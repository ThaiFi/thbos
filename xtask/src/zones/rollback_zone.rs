//! Offline rollback of a Zone's persisted canonical chain.

use alloy_eips::BlockHashOrNumber;
use alloy_primitives::B256;
use eyre::{Context as _, OptionExt as _, ensure};
use reth_chainspec::EthChainSpec as _;
use reth_cli_commands::common::{AccessRights, Environment, EnvironmentArgs};
use reth_provider::{
    BlockExecutionWriter as _, BlockHashReader as _, BlockNumReader as _,
    ChainStateBlockReader as _, ChainStateBlockWriter as _, PruneCheckpointReader as _,
    StaticFileProviderFactory as _, providers::RocksDBProvider,
};
use reth_tasks::{Runtime, RuntimeBuilder, RuntimeConfig, TokioConfig};
use zone_chainspec::ZoneChainSpecParser;
use zone_node::ZoneNode;

/// Rewind a stopped Zone node, retaining the selected block. Defaults to a dry run.
#[derive(Debug, clap::Parser)]
pub(crate) struct RollbackZone {
    #[command(flatten)]
    env: EnvironmentArgs<ZoneChainSpecParser>,

    /// Canonical Zone block number or hash to retain; all descendants are removed.
    #[arg(long, value_name = "NUMBER_OR_HASH")]
    to_block: BlockHashOrNumber,

    /// Apply the rollback to disk. Stop the node and back up its data first.
    #[arg(long)]
    execute: bool,
}

impl RollbackZone {
    /// Preview or apply a local rollback without contacting L1 or changing the Portal.
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let runtime = RuntimeBuilder::new(RuntimeConfig::default().with_tokio(
            TokioConfig::existing_handle(tokio::runtime::Handle::current()),
        ))
        .build()
        .wrap_err("failed building rollback runtime")?;
        tokio::task::spawn_blocking(move || self.rollback(runtime))
            .await
            .wrap_err("rollback task panicked")?
    }

    fn rollback(self, runtime: Runtime) -> eyre::Result<()> {
        let data_dir = self
            .env
            .datadir
            .clone()
            .resolve_datadir(self.env.chain.chain());
        // EnvironmentArgs otherwise creates a missing RocksDB even for read-only access.
        for path in [data_dir.db(), data_dir.static_files()] {
            ensure!(
                path.is_dir(),
                "missing Zone storage directory: {}",
                path.display()
            );
        }
        ensure!(
            RocksDBProvider::exists(data_dir.rocksdb()),
            "missing Zone RocksDB database: {}",
            data_dir.rocksdb().display()
        );
        let environment = self
            .env
            .init::<ZoneNode>(AccessRights::RoInconsistent, runtime.clone())
            .wrap_err("failed opening Zone storage for rollback preview")?;
        let plan = self.plan(&environment)?;
        println!("Zone data: {}", data_dir.data_dir().display());
        println!("Current head: {} ({})", plan.head, plan.head_hash);
        println!("Retain block: {} ({})", plan.target, plan.target_hash);
        println!("Remove {} blocks", plan.head - plan.target);
        drop(environment);
        if !self.execute {
            println!("Dry run; pass --execute to apply the rollback.");
            return Ok(());
        }
        if plan.target == plan.head {
            println!("Already at the requested block.");
            return Ok(());
        }

        // Acquire Reth's writer lock and repeat the checks before any unwind. Do not let
        // environment initialization automatically heal storage to a different target.
        let environment = self
            .env
            .init::<ZoneNode>(AccessRights::RwInconsistent, runtime)
            .wrap_err("failed opening Zone storage for rollback; stop the node first")?;
        ensure!(
            self.plan(&environment)? == plan,
            "Zone chain changed after rollback preview"
        );
        let provider = environment
            .provider_factory
            .provider_rw()
            .wrap_err("failed opening rollback transaction")?;
        provider
            .remove_block_and_execution_above(plan.target)
            .wrap_err("failed unwinding Zone blocks and execution state")?;
        // Zone forkchoice uses instant finality: head, safe, and finalized are identical.
        provider.save_safe_block_number(plan.target)?;
        provider.save_finalized_block_number(plan.target)?;
        provider
            .commit()
            .wrap_err("failed committing Zone rollback")?;

        let provider = environment.provider_factory.provider()?;
        ensure!(
            provider.last_block_number()? == plan.target
                && provider.block_hash(plan.target)? == Some(plan.target_hash)
                && provider.last_safe_block_number()? == Some(plan.target)
                && provider.last_finalized_block_number()? == Some(plan.target),
            "rollback committed but persisted head verification failed"
        );
        println!(
            "Rolled back to Zone block {} ({})",
            plan.target, plan.target_hash
        );
        Ok(())
    }

    fn plan(&self, environment: &Environment<ZoneNode>) -> eyre::Result<RollbackPlan> {
        let provider = environment.provider_factory.provider()?;
        ensure!(
            provider.block_hash(0)? == Some(self.env.chain.genesis_hash()),
            "Zone genesis does not match the database"
        );
        ensure!(
            environment
                .provider_factory
                .static_file_provider()
                .check_consistency(&provider)?
                .is_none(),
            "Zone storage is inconsistent; repair it before rolling back"
        );
        let head = provider.last_block_number()?;
        let target = match self.to_block {
            BlockHashOrNumber::Number(number) => number,
            BlockHashOrNumber::Hash(hash) => provider
                .block_number(hash)?
                .ok_or_eyre(format!("Zone block {hash} was not found"))?,
        };
        ensure!(
            target <= head,
            "target Zone block {target} is above current head {head}"
        );
        let target_hash = provider
            .block_hash(target)?
            .ok_or_eyre(format!("Zone block {target} has no canonical hash"))?;
        if let BlockHashOrNumber::Hash(hash) = self.to_block {
            ensure!(target_hash == hash, "Zone block {hash} is not canonical");
        }
        provider
            .prune_modes_ref()
            .ensure_unwind_target_unpruned(head, target, &provider.get_prune_checkpoints()?)
            .wrap_err("rollback target requires pruned data")?;
        Ok(RollbackPlan {
            head,
            head_hash: provider
                .block_hash(head)?
                .ok_or_eyre("Zone head has no canonical hash")?,
            target,
            target_hash,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RollbackPlan {
    head: u64,
    head_hash: B256,
    target: u64,
    target_hash: B256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{path::Path, sync::Arc};

    use alloy_consensus::Header;
    use alloy_primitives::{Address, U256};
    use clap::Parser as _;
    use reth_chain_state::ExecutedBlock;
    use reth_db_api::{tables, transaction::DbTxMut as _};
    use reth_evm::execute::BlockExecutionOutput;
    use reth_primitives_traits::RecoveredBlock;
    use reth_provider::{
        HeaderProvider as _, PruneCheckpointWriter as _, SaveBlocksInput,
        StageCheckpointWriter as _,
    };
    use reth_prune_types::{PruneCheckpoint, PruneSegment};
    use reth_trie_common::{HashedPostState, KeccakKeyHasher, SortedTrieData};
    use revm::{database::states::BundleState, state::AccountInfo};
    use tempo_primitives::{Block, TempoHeader, TempoPrimitives};

    const ACCOUNT: Address = Address::repeat_byte(0x11);

    fn command(directory: &Path, target: &str, execute: bool) -> RollbackZone {
        let mut args = vec![
            "rollback-zone".to_owned(),
            "--chain".to_owned(),
            directory.join("genesis.json").display().to_string(),
            "--datadir".to_owned(),
            directory.join("data").display().to_string(),
            "--to-block".to_owned(),
            target.to_owned(),
        ];
        if execute {
            args.push("--execute".to_owned());
        }
        RollbackZone::try_parse_from(args).unwrap()
    }

    fn fixture(storage_v2: bool) -> (tempfile::TempDir, Runtime, Vec<B256>) {
        let directory = tempfile::tempdir().unwrap();
        let chain_id = zone_primitives::constants::zone_chain_id(1337, 11).unwrap();
        std::fs::write(
            directory.path().join("genesis.json"),
            serde_json::json!({"config": {"chainId": chain_id}, "alloc": {}}).to_string(),
        )
        .unwrap();
        let runtime = Runtime::test();
        let mut args = command(directory.path(), "0", false);
        args.env.storage.v2 = storage_v2;
        let environment = args
            .env
            .init::<ZoneNode>(AccessRights::RW, runtime.clone())
            .unwrap();
        let mut parent_hash = args.env.chain.genesis_hash();
        let mut hashes = vec![parent_hash];
        let mut previous = None;
        for number in 1..=3 {
            let account = AccountInfo {
                balance: U256::from(number * 100),
                nonce: number,
                ..Default::default()
            };
            let mut builder = BundleState::builder(0..=0)
                .state_present_account_info(ACCOUNT, account.clone())
                .revert_account_info(0, ACCOUNT, Some(previous.clone()))
                .state_storage(
                    ACCOUNT,
                    [(
                        U256::from(1),
                        (U256::from((number - 1) * 1000), U256::from(number * 1000)),
                    )]
                    .into_iter()
                    .collect(),
                )
                .revert_storage(
                    0,
                    ACCOUNT,
                    vec![(U256::from(1), U256::from((number - 1) * 1000))],
                );
            if let Some(original) = previous {
                builder = builder.state_original_account_info(ACCOUNT, original);
            }
            let state = builder.build();
            let hashed_state = HashedPostState::from_bundle_state::<KeccakKeyHasher>(&state.state);
            let (state_root, trie_updates) = environment
                .provider_factory
                .latest()
                .unwrap()
                .state_root_with_updates(hashed_state.clone())
                .unwrap();
            let trie_data = SortedTrieData::new(
                Arc::new(hashed_state.into_sorted()),
                Arc::new(trie_updates.into_sorted()),
            );
            let header = TempoHeader {
                inner: Header {
                    number,
                    parent_hash,
                    timestamp: number,
                    state_root,
                    ..Default::default()
                },
                ..Default::default()
            };
            let block =
                RecoveredBlock::new_unhashed(Block::new(header, Default::default()), vec![]);
            parent_hash = block.hash();
            hashes.push(parent_hash);
            let executed = ExecutedBlock::<TempoPrimitives>::new(
                Arc::new(block),
                Arc::new(BlockExecutionOutput {
                    state,
                    ..Default::default()
                }),
                trie_data,
            );
            let provider = environment.provider_factory.provider_rw().unwrap();
            provider
                .save_blocks(&SaveBlocksInput::new(
                    vec![executed],
                    number - 1,
                    number - 1,
                    number,
                    number,
                ))
                .unwrap();
            provider.save_safe_block_number(number).unwrap();
            provider.save_finalized_block_number(number).unwrap();
            provider.commit().unwrap();
            previous = Some(account);
        }
        drop(environment);
        (directory, runtime, hashes)
    }

    fn assert_head(directory: &Path, runtime: Runtime, number: u64, hash: B256) {
        let args = command(directory, "0", false);
        let environment = args
            .env
            .init::<ZoneNode>(AccessRights::RO, runtime)
            .unwrap();
        let provider = environment.provider_factory.provider().unwrap();
        assert_eq!(provider.last_block_number().unwrap(), number);
        assert_eq!(provider.block_hash(number).unwrap(), Some(hash));
        assert_eq!(
            environment
                .provider_factory
                .latest()
                .unwrap()
                .state_root(Default::default())
                .unwrap(),
            provider
                .header_by_number(number)
                .unwrap()
                .unwrap()
                .inner
                .state_root
        );
        assert_eq!(provider.header_by_number(number + 1).unwrap(), None);
        assert_eq!(provider.last_safe_block_number().unwrap(), Some(number));
        assert_eq!(
            provider.last_finalized_block_number().unwrap(),
            Some(number)
        );
        let account = environment
            .provider_factory
            .latest()
            .unwrap()
            .basic_account(&ACCOUNT)
            .unwrap();
        assert_eq!(
            environment
                .provider_factory
                .latest()
                .unwrap()
                .storage(ACCOUNT, B256::with_last_byte(1))
                .unwrap()
                .unwrap_or_default(),
            U256::from(number * 1000)
        );
        if number == 0 {
            assert_eq!(account, None);
        } else {
            let account = account.unwrap();
            assert_eq!(account.balance, U256::from(number * 100));
            assert_eq!(account.nonce, number);
        }
    }

    #[test]
    fn rollback_restores_state_and_finality_in_both_storage_modes() {
        for storage_v2 in [false, true] {
            let (directory, runtime, hashes) = fixture(storage_v2);
            command(directory.path(), "1", false)
                .rollback(runtime.clone())
                .unwrap();
            assert_head(directory.path(), runtime.clone(), 3, hashes[3]);

            command(directory.path(), &hashes[1].to_string(), true)
                .rollback(runtime.clone())
                .unwrap();
            assert_head(directory.path(), runtime.clone(), 1, hashes[1]);
            command(directory.path(), "1", true)
                .rollback(runtime.clone())
                .unwrap();
            assert_head(directory.path(), runtime.clone(), 1, hashes[1]);

            command(directory.path(), "0", true)
                .rollback(runtime.clone())
                .unwrap();
            assert_head(directory.path(), runtime, 0, hashes[0]);
        }
    }

    #[test]
    fn invalid_targets_leave_the_chain_unchanged() {
        let (directory, runtime, hashes) = fixture(true);
        for execute in [false, true] {
            let unknown = B256::repeat_byte(0xff);
            for (target, expected) in [
                (
                    "4".to_owned(),
                    "target Zone block 4 is above current head 3".to_owned(),
                ),
                (
                    unknown.to_string(),
                    format!("Zone block {unknown} was not found"),
                ),
            ] {
                let error = command(directory.path(), &target, execute)
                    .rollback(runtime.clone())
                    .unwrap_err();
                assert_eq!(error.to_string(), expected);
                assert_head(directory.path(), runtime.clone(), 3, hashes[3]);
            }
        }
        let mut args = command(directory.path(), "1", true);
        let mut genesis = args.env.chain.genesis().clone();
        genesis.timestamp = 1;
        args.env.chain = Arc::new(zone_chainspec::ZoneChainSpec::from_genesis(genesis).unwrap());
        assert_eq!(
            args.rollback(runtime.clone()).unwrap_err().to_string(),
            "Zone genesis does not match the database"
        );
        assert_head(directory.path(), runtime, 3, hashes[3]);
    }

    #[test]
    fn noncanonical_hash_is_rejected() {
        let (directory, runtime, hashes) = fixture(true);
        let hash = B256::repeat_byte(0xfe);
        let args = command(directory.path(), &hash.to_string(), true);
        let environment = args
            .env
            .init::<ZoneNode>(AccessRights::RW, runtime.clone())
            .unwrap();
        let provider = environment.provider_factory.provider_rw().unwrap();
        provider
            .tx_ref()
            .put::<tables::HeaderNumbers>(hash, 1)
            .unwrap();
        provider.commit().unwrap();
        drop(environment);
        assert_eq!(
            args.rollback(runtime.clone()).unwrap_err().to_string(),
            format!("Zone block {hash} is not canonical")
        );
        assert_head(directory.path(), runtime, 3, hashes[3]);
    }

    #[test]
    fn pruned_and_inconsistent_storage_are_rejected() {
        let (directory, runtime, hashes) = fixture(true);
        let args = command(directory.path(), "1", true);
        let environment = args
            .env
            .init::<ZoneNode>(AccessRights::RW, runtime.clone())
            .unwrap();
        let provider = environment.provider_factory.provider_rw().unwrap();
        provider
            .save_prune_checkpoint(
                PruneSegment::AccountHistory,
                PruneCheckpoint::pruned_through(2),
            )
            .unwrap();
        provider.commit().unwrap();
        drop(environment);
        assert_eq!(
            args.rollback(runtime.clone()).unwrap_err().to_string(),
            "rollback target requires pruned data"
        );
        assert_head(directory.path(), runtime.clone(), 3, hashes[3]);

        let args = command(directory.path(), "2", true);
        let environment = args
            .env
            .init::<ZoneNode>(AccessRights::RW, runtime.clone())
            .unwrap();
        let provider = environment.provider_factory.provider_rw().unwrap();
        provider.update_pipeline_stages(4, true).unwrap();
        provider.commit().unwrap();
        drop(environment);
        assert_eq!(
            args.rollback(runtime.clone()).unwrap_err().to_string(),
            "Zone storage is inconsistent; repair it before rolling back"
        );
        assert_head(directory.path(), runtime, 3, hashes[3]);
    }

    #[test]
    fn missing_storage_is_not_created() {
        let (directory, runtime, _) = fixture(true);
        let rocksdb = directory.path().join("data/rocksdb");
        std::fs::remove_dir_all(&rocksdb).unwrap();
        std::fs::create_dir(&rocksdb).unwrap();
        assert_eq!(
            command(directory.path(), "0", false)
                .rollback(runtime.clone())
                .unwrap_err()
                .to_string(),
            format!("missing Zone RocksDB database: {}", rocksdb.display())
        );
        assert_eq!(std::fs::read_dir(&rocksdb).unwrap().count(), 0);
        std::fs::remove_dir_all(directory.path().join("data")).unwrap();
        let error = command(directory.path(), "0", true)
            .rollback(runtime)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "missing Zone storage directory: {}",
                directory.path().join("data/db").display()
            )
        );
        assert!(!directory.path().join("data").exists());
    }
}
