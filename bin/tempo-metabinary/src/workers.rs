//! Lazily started, shared, idle-reaped `rpc-only` workers, one per frozen era.

use crate::{
    catalog::FrozenEra,
    handshake::{WorkerIdentity, wait_for_worker},
    process::{shutdown_children, spawn_child},
    routing::{RpcParams, UNSUPPORTED_CODE},
};
use alloy_primitives::{B256, U64};
use eyre::{OptionExt as _, WrapErr as _, bail, ensure, eyre};
use futures::Stream;
use jsonrpsee::{
    core::{
        ClientError, RpcResult,
        client::{ClientT, Subscription, SubscriptionClientT},
    },
    http_client::{HttpClient, HttpClientBuilder},
    types::{
        ErrorObjectOwned,
        error::{CALL_EXECUTION_FAILED_CODE, METHOD_NOT_FOUND_CODE},
    },
    ws_client::{WsClient, WsClientBuilder},
};
use serde_json::value::RawValue;
use std::{
    io,
    net::{Ipv4Addr, TcpListener},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    process::{Child, Command},
    runtime::Handle,
    sync::Mutex,
    time::Instant,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::warn;

/// Time a worker may stay unused before it is stopped.
const IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Interval of the idle check.
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Time after a failed start before the era is retried.
const FAILURE_COOLDOWN: Duration = Duration::from_secs(30);

/// Default [`WorkerContext::startup_timeout`].
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(120);

/// Node configuration workers inherit.
#[derive(Debug, Clone)]
pub struct WorkerContext {
    /// Path of the genesis JSON the live node runs.
    pub chain: String,
    /// The node's datadir.
    pub datadir: PathBuf,
    /// Custom static files directory, if configured.
    pub static_files_path: Option<PathBuf>,
    /// Custom RocksDB directory, if configured.
    pub rocksdb_path: Option<PathBuf>,
    /// Serialized RPC configuration passed through `--rpc-config`.
    pub rpc_config: PathBuf,
    /// Chain ID workers must serve.
    pub chain_id: U64,
    /// Genesis hash workers must serve.
    pub genesis_hash: B256,
    /// Time a worker may take to answer the handshake.
    pub startup_timeout: Duration,
}

/// The frozen-era workers of one node.
pub struct HistoricalWorkers {
    context: WorkerContext,
    eras: Vec<Era>,
    runtime: Handle,
    shutdown: CancellationToken,
    /// Background stops and the idle reaper.
    tasks: TaskTracker,
}

impl HistoricalWorkers {
    /// Creates dormant workers for `eras` and starts the idle reaper. Requires a Tokio runtime.
    pub fn new(context: WorkerContext, eras: Vec<FrozenEra>) -> eyre::Result<Arc<Self>> {
        let runtime = Handle::try_current().wrap_err("historical workers need a Tokio runtime")?;
        ensure!(
            !context.startup_timeout.is_zero(),
            "worker startup timeout must be positive"
        );
        let this = Arc::new(Self {
            context,
            eras: eras
                .into_iter()
                .map(|era| Era {
                    name: era.to_string(),
                    era,
                    state: Mutex::new(State::Dormant),
                })
                .collect(),
            runtime,
            shutdown: CancellationToken::new(),
            tasks: TaskTracker::new(),
        });
        this.tasks
            .spawn_on(reap_idle_workers(Arc::downgrade(&this)), &this.runtime);
        Ok(this)
    }

    /// Calls `method` on `era`'s worker. `-32000` if unavailable, `-32004` if it lacks `method`.
    pub async fn request(
        self: &Arc<Self>,
        era: usize,
        method: &str,
        params: RpcParams,
    ) -> RpcResult<Box<RawValue>> {
        let worker = self.get(era).await.map_err(unavailable)?;
        worker
            .client
            .request::<Box<RawValue>, _>(method, params)
            .await
            .map_err(|err| self.call_error(era, method, err))
    }

    /// Opens a `debug_subscribe` subscription on `era`'s worker over a dedicated WebSocket.
    pub async fn subscribe(
        self: &Arc<Self>,
        era: usize,
        params: RpcParams,
    ) -> RpcResult<WorkerSubscription> {
        const METHOD: &str = "debug_subscribe";
        let worker = self.get(era).await.map_err(unavailable)?;
        let client = WsClientBuilder::default()
            .max_request_size(u32::MAX)
            .max_response_size(u32::MAX)
            .request_timeout(Duration::MAX)
            .build(format!("ws://{}:{}", Ipv4Addr::LOCALHOST, worker.port))
            .await
            .map_err(|err| self.call_error(era, METHOD, err))?;
        let subscription = client
            .subscribe::<Box<RawValue>, _>(METHOD, params, "debug_unsubscribe")
            .await
            .map_err(|err| self.call_error(era, METHOD, err))?;
        Ok(WorkerSubscription {
            subscription,
            _client: client,
            _worker: worker,
        })
    }

    /// Stops every worker so later requests fail. Retriable, as children stay owned until reaped.
    pub async fn shutdown(&self) -> eyre::Result<()> {
        self.shutdown.cancel();
        let mut states = Vec::with_capacity(self.eras.len());
        for era in &self.eras {
            states.push(era.state.lock().await);
        }
        let stopped = shutdown_children(states.iter_mut().zip(&self.eras).filter_map(
            |(state, era)| match &mut **state {
                State::Running(process) => Some((era.name.as_str(), &mut process.child)),
                _ => None,
            },
        ))
        .await;
        let mut cleaned = Ok(());
        for state in &mut states {
            if let State::Running(process) = std::mem::replace(&mut **state, State::Dormant)
                && let Err(err) = remove_secondary(&process.secondary)
            {
                cleaned = Err(err);
            }
        }
        drop(states);
        self.tasks.close();
        self.tasks.wait().await;
        stopped.and(cleaned)
    }

    /// Returns `era`'s ready worker, starting it or resuming an abandoned handshake if needed.
    async fn get(self: &Arc<Self>, era: usize) -> eyre::Result<Arc<HistoricalWorker>> {
        let slot = self.eras.get(era).ok_or_eyre("unknown historical era")?;
        let mut state = slot.state.lock().await;
        if self.shutdown.is_cancelled() {
            bail!("historical workers are shutting down");
        }
        if let State::Failed { message, retry_at } = &*state {
            if Instant::now() < *retry_at {
                bail!("{message}");
            }
            *state = State::Dormant;
        }
        match self.start(slot, &mut state).await {
            Ok(worker) => Ok(worker),
            Err(err) => {
                let message = format!("historical era {} unavailable: {err:#}", slot.name);
                let failed = State::Failed {
                    message: message.clone(),
                    retry_at: Instant::now() + FAILURE_COOLDOWN,
                };
                if let State::Running(process) = std::mem::replace(&mut *state, failed) {
                    self.stop_in_background(slot.name.clone(), process);
                }
                warn!(era = %slot.name, %err, "historical worker failed");
                Err(eyre!(message))
            }
        }
    }

    async fn start(&self, slot: &Era, state: &mut State) -> eyre::Result<Arc<HistoricalWorker>> {
        if matches!(state, State::Dormant) {
            *state = State::Running(Box::new(self.spawn(&slot.era)?));
        }
        let State::Running(process) = state else {
            bail!("historical era {} is not running", slot.name);
        };
        let Process {
            child,
            client,
            port,
            ready,
            deadline,
            last_used,
            ..
        } = &mut **process;
        if let Some(status) = child.try_wait()? {
            bail!("historical era {} exited with {status}", slot.name);
        }
        *last_used = Instant::now();
        if let Some(ready) = ready {
            return Ok(ready.clone());
        }

        let pid = child.id().ok_or_eyre("worker was already reaped")?;
        let identity = WorkerIdentity {
            chain_id: self.context.chain_id,
            genesis_hash: self.context.genesis_hash,
        };
        let check_alive = || match child.try_wait()? {
            Some(status) => Err(eyre!("historical era {} exited with {status}", slot.name)),
            None => Ok(()),
        };
        tokio::select! {
            biased;
            () = self.shutdown.cancelled() => bail!("historical workers are shutting down"),
            info = wait_for_worker(client, &identity, pid, *deadline, check_alive) => info?,
        };
        let worker = Arc::new(HistoricalWorker {
            client: client.clone(),
            port: *port,
        });
        *ready = Some(worker.clone());
        Ok(worker)
    }

    fn spawn(&self, era: &FrozenEra) -> eyre::Result<Process> {
        let context = &self.context;
        let port = {
            // Released just before spawning so the worker can bind it.
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .wrap_err("failed to reserve a worker port")?;
            listener.local_addr()?.port()
        };
        let client = HttpClientBuilder::default()
            .max_request_size(u32::MAX)
            .max_response_size(u32::MAX)
            // Execution timeouts belong to the native RPC.
            .request_timeout(Duration::MAX)
            .build(format!("http://{}:{port}", Ipv4Addr::LOCALHOST))?;

        let mut cmd = Command::new(&era.binary);
        cmd.arg("rpc-only")
            .arg("--chain")
            .arg(&context.chain)
            .arg("--datadir")
            .arg(&context.datadir)
            .arg("--port")
            .arg(port.to_string());
        if let Some(path) = &context.static_files_path {
            cmd.arg("--datadir.static-files").arg(path);
        }
        if let Some(path) = &context.rocksdb_path {
            cmd.arg("--datadir.rocksdb").arg(path);
        }
        cmd.arg("--rpc-config").arg(&context.rpc_config);
        let child = spawn_child(&mut cmd)
            .wrap_err_with(|| format!("failed to spawn {}", era.binary.display()))?;
        let pid = child
            .id()
            .ok_or_eyre("worker exited before it was tracked")?;

        // Reth's read-only RocksDB secondary lives beside the primary, named by the reader's PID.
        let rocksdb = context
            .rocksdb_path
            .clone()
            .unwrap_or_else(|| context.datadir.join("rocksdb"));
        let secondary = rocksdb
            .parent()
            .unwrap_or(&rocksdb)
            .join(format!("rocksdb-secondary-tmp-{pid}"));

        let now = Instant::now();
        Ok(Process {
            child,
            client,
            port,
            ready: None,
            deadline: now + context.startup_timeout,
            last_used: now,
            secondary,
        })
    }

    /// Stops idle workers, keeping those whose handle is held by a caller.
    fn reap_idle(&self) {
        let now = Instant::now();
        for slot in &self.eras {
            // A locked state is in use.
            let Ok(mut state) = slot.state.try_lock() else {
                continue;
            };
            let State::Running(process) = &mut *state else {
                continue;
            };
            if process
                .ready
                .as_ref()
                .is_some_and(|ready| Arc::strong_count(ready) > 1)
            {
                process.last_used = now;
                continue;
            }
            if now.duration_since(process.last_used) < IDLE_TIMEOUT {
                continue;
            }
            if let State::Running(process) = std::mem::replace(&mut *state, State::Dormant) {
                self.stop_in_background(slot.name.clone(), process);
            }
        }
    }

    fn stop_in_background(&self, name: String, mut process: Box<Process>) {
        self.tasks.spawn_on(
            async move {
                let stopped = shutdown_children([(name.as_str(), &mut process.child)]).await;
                if let Err(err) = stopped.and(remove_secondary(&process.secondary)) {
                    warn!(era = %name, %err, "failed to stop historical worker");
                }
            },
            &self.runtime,
        );
    }

    fn call_error(&self, era: usize, method: &str, err: ClientError) -> ErrorObjectOwned {
        match err {
            ClientError::Call(err) if err.code() == METHOD_NOT_FOUND_CODE => {
                let era = self.eras.get(era).map_or("?", |slot| slot.name.as_str());
                ErrorObjectOwned::owned(
                    UNSUPPORTED_CODE,
                    format!("{method} is unavailable in historical era {era}"),
                    None::<()>,
                )
            }
            ClientError::Call(err) => err,
            err => ErrorObjectOwned::owned(
                CALL_EXECUTION_FAILED_CODE,
                format!("era RPC unavailable: {err}"),
                None::<()>,
            ),
        }
    }
}

/// A ready worker. Holding it keeps the worker from being reaped as idle.
pub struct HistoricalWorker {
    client: HttpClient,
    port: u16,
}

/// Raw `debug_subscribe` notification results. Holds the worker and unsubscribes on drop.
pub struct WorkerSubscription {
    subscription: Subscription<Box<RawValue>>,
    _client: WsClient,
    _worker: Arc<HistoricalWorker>,
}

impl Stream for WorkerSubscription {
    type Item = Box<RawValue>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.subscription).poll_next(cx) {
            Poll::Ready(Some(Ok(result))) => Poll::Ready(Some(result)),
            Poll::Ready(Some(Err(err))) => {
                warn!(%err, "invalid worker notification");
                Poll::Ready(None)
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct Era {
    era: FrozenEra,
    /// Display name, for example `pre-T12`.
    name: String,
    state: Mutex<State>,
}

enum State {
    Dormant,
    Running(Box<Process>),
    /// Start failed, so requests fail with `message` until `retry_at`.
    Failed {
        message: String,
        retry_at: Instant,
    },
}

struct Process {
    child: Child,
    client: HttpClient,
    port: u16,
    /// Set once the handshake succeeded.
    ready: Option<Arc<HistoricalWorker>>,
    deadline: Instant,
    last_used: Instant,
    /// The worker's RocksDB secondary directory, removed after it stops.
    secondary: PathBuf,
}

async fn reap_idle_workers(workers: Weak<HistoricalWorkers>) {
    let Some(shutdown) = workers.upgrade().map(|workers| workers.shutdown.clone()) else {
        return;
    };
    let mut interval = tokio::time::interval(IDLE_CHECK_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            _ = interval.tick() => {}
        }
        let Some(workers) = workers.upgrade() else {
            return;
        };
        workers.reap_idle();
    }
}

fn remove_secondary(path: &Path) -> eyre::Result<()> {
    match std::fs::remove_dir_all(path) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => {
            Err(err).wrap_err_with(|| format!("failed to remove {}", path.display()))
        }
        _ => Ok(()),
    }
}

fn unavailable(err: eyre::Report) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(CALL_EXECUTION_FAILED_CODE, format!("{err:#}"), None::<()>)
}

#[cfg(all(test, unix))]
mod tests;
