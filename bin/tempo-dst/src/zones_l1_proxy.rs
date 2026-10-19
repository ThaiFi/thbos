// SPDX-License-Identifier: GPL-2.0

//! A byzantine L1 JSON-RPC proxy for the zones load's L1-fault family
//! (`zones_l1_faults`). It sits between the batch prover and the Tempo L1: it
//! forwards every JSON-RPC request to the real node, but for one chosen
//! [`L1Fault`] kind it tampers the matching responses, so the L1 reports state
//! that disagrees with the truth (a stale head, a wrong block hash or state
//! root, an altered storage value or proof, dropped or fabricated deposit
//! logs, an altered `eth_call`).
//!
//! The prover points a single `generate-input` run's `--tempo-rpc-url` at a
//! proxy instance, so the fault is scoped to that one witness build and never
//! reaches the honest sequencer or the honest oracle (the prover's real-L1
//! replay is a separate call). A witness built from a lying L1 must not
//! validate against the real chain: `generate-input`'s own SPF check and anchor
//! binding reject it, which the oracle reads as `S/zones-l1-fault-detected`. A
//! prover that accepted it would be trusting falsified L1 state
//! (`E12/zones-trusted-bad-l1-accepted`).
//!
//! The server is sync and single-connection (`Connection: close`), so its
//! behaviour is a pure function of the requests it sees, deterministic under
//! Bedrock. It is a separate mechanism from the network-fault proxy in
//! `dst/net-zones` (which cuts connections rather than altering payloads).

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use serde_json::Value;

use crate::zones::{L1Fault, PORTAL};

/// What one proxy instance tampers: the fault kind and, for
/// [`L1Fault::StaleHead`], the L1 block the head is reported below (the probed
/// batch's submission block). A head merely some blocks behind is immaterial
/// when the batch is older than that: every L1 read is then honest and a
/// correct prover rightly succeeds. A head below the submission block hides
/// the batch, so a correct prover must fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyFault {
    pub kind: L1Fault,
    pub stale_below: u64,
}

/// A running proxy: its listen address, and a flag to stop it.
pub struct Proxy {
    pub addr: String,
    stop: Arc<AtomicBool>,
    /// Set once the proxy has tampered at least one response.
    applied: Arc<AtomicBool>,
}

impl Proxy {
    /// Whether the proxy actually tampered a response (the faulted method was
    /// requested at least once).
    pub fn applied(&self) -> bool {
        self.applied.load(Ordering::SeqCst)
    }

    /// Stops the accept loop.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock the accept() by connecting once.
        let _ = TcpStream::connect(&self.addr);
    }
}

/// Starts a byzantine proxy to `upstream` (e.g. `http://127.0.0.1:8545`) on an
/// ephemeral localhost port, faulting `fault`. Returns the running proxy.
pub fn start(upstream: &str, fault: ProxyFault) -> std::io::Result<Proxy> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = format!("http://{}", listener.local_addr()?);
    let stop = Arc::new(AtomicBool::new(false));
    let applied = Arc::new(AtomicBool::new(false));
    let upstream = upstream.trim_end_matches('/').to_string();
    let (s, a) = (stop.clone(), applied.clone());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            if s.load(Ordering::SeqCst) {
                break;
            }
            if let Ok(stream) = conn {
                let _ = serve(stream, &upstream, fault, &a);
            }
        }
    });
    Ok(Proxy {
        addr,
        stop,
        applied,
    })
}

/// Reads one JSON-RPC request from `stream`, forwards it, tampers the response
/// if it matches `fault`, and writes the result back.
fn serve(
    mut stream: TcpStream,
    upstream: &str,
    fault: ProxyFault,
    applied: &AtomicBool,
) -> std::io::Result<()> {
    let body = match read_request_body(&mut stream)? {
        Some(b) => b,
        None => return Ok(()),
    };
    let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let mut response = forward(upstream, &body);
    if let Value::Object(_) = &request {
        if tamper(&request, &mut response, fault) {
            applied.store(true, Ordering::SeqCst);
        }
    } else if let Value::Array(reqs) = &request {
        // JSON-RPC batch: tamper each sub-response by id.
        if let Value::Array(resps) = &mut response {
            for req in reqs {
                if let Some(resp) = resps.iter_mut().find(|r| r["id"] == req["id"]) {
                    if tamper(req, resp, fault) {
                        applied.store(true, Ordering::SeqCst);
                    }
                }
            }
        }
    }
    let payload = serde_json::to_vec(&response).unwrap_or_default();
    write_response(&mut stream, &payload)
}

/// Reads an HTTP/1.1 request and returns its body by `Content-Length`.
fn read_request_body(stream: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut len = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(v) = trimmed.strip_prefix("Content-Length:") {
            len = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = trimmed.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_response(stream: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}

/// Forwards the raw JSON-RPC body to the upstream node and returns the parsed
/// response (or a null value on transport error).
fn forward(upstream: &str, body: &[u8]) -> Value {
    let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    match ureq::post(upstream)
        .timeout(Duration::from_secs(30))
        .send_json(value)
    {
        Ok(resp) => resp.into_json().unwrap_or(Value::Null),
        Err(_) => Value::Null,
    }
}

/// Tampers one JSON-RPC `response` to `request` for `fault`. Returns whether a
/// change was made (the method matched and there was something to alter).
fn tamper(request: &Value, response: &mut Value, fault: ProxyFault) -> bool {
    let method = request["method"].as_str().unwrap_or("");
    let result = &mut response["result"];
    if result.is_null() {
        return false;
    }
    match fault.kind {
        L1Fault::StaleHead if method == "eth_blockNumber" => {
            // Report a head below the probed batch's submission block, so the
            // batch "has not been submitted yet" as far as the prover can tell.
            if let Some(n) = hex_u64(result) {
                let stale = n.min(fault.stale_below).saturating_sub(1);
                *result = Value::String(format!("0x{stale:x}"));
                return true;
            }
            false
        }
        L1Fault::WrongBlockHash
            if matches!(method, "eth_getBlockByNumber" | "eth_getBlockByHash") =>
        {
            flip_hex_field(result, "hash")
        }
        L1Fault::WrongStateRoot
            if matches!(method, "eth_getBlockByNumber" | "eth_getBlockByHash") =>
        {
            flip_hex_field(result, "stateRoot")
        }
        L1Fault::AlterStorage if method == "eth_getStorageAt" => flip_hex_value(result),
        L1Fault::AlterStorage if method == "eth_getProof" => {
            // Alter the first storage proof's value.
            flip_hex_field(&mut result["storageProof"][0], "value")
        }
        L1Fault::AlterCall if method == "eth_call" => flip_hex_value(result),
        L1Fault::DropDepositLogs if method == "eth_getLogs" => {
            let before = result.as_array().map(|a| a.len()).unwrap_or(0);
            if let Some(logs) = result.as_array_mut() {
                logs.retain(|l| !is_portal_log(l));
            }
            result.as_array().map(|a| a.len()).unwrap_or(0) != before
        }
        L1Fault::FabricateDepositLog if method == "eth_getLogs" => {
            if let Some(logs) = result.as_array_mut() {
                if let Some(mut fake) = logs.iter().find(|l| is_portal_log(l)).cloned() {
                    // A duplicate deposit log with a bumped index: a deposit
                    // the real chain never emitted.
                    fake["logIndex"] = Value::String("0xffff".into());
                    logs.push(fake);
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

fn is_portal_log(log: &Value) -> bool {
    log["address"]
        .as_str()
        .and_then(|a| a.parse::<alloy_primitives::Address>().ok())
        == Some(PORTAL)
}

fn hex_u64(v: &Value) -> Option<u64> {
    u64::from_str_radix(v.as_str()?.trim_start_matches("0x"), 16).ok()
}

/// Flips the last nibble of a `0x` hex string field of `v`.
fn flip_hex_field(v: &mut Value, field: &str) -> bool {
    match v.get_mut(field) {
        Some(f) => flip_hex_value(f),
        None => false,
    }
}

/// Flips the last nibble of a `0x` hex string value, keeping it valid hex.
fn flip_hex_value(v: &mut Value) -> bool {
    let Some(s) = v.as_str() else { return false };
    let Some(hex) = s.strip_prefix("0x").filter(|h| !h.is_empty()) else {
        return false;
    };
    let mut chars: Vec<char> = hex.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == '0' { '1' } else { '0' };
    *v = Value::String(format!("0x{}", chars.into_iter().collect::<String>()));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(result: Value) -> Value {
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result})
    }
    fn req(method: &str) -> Value {
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": []})
    }

    /// A fault spec with no stale-head target.
    fn pf(kind: L1Fault) -> ProxyFault {
        ProxyFault {
            kind,
            stale_below: u64::MAX,
        }
    }

    #[test]
    fn stale_head_is_reported_below_the_batch_submission() {
        // Head 0x100, batch submitted at 0x40: the reported head hides it,
        // however far behind the real head the batch is.
        let spec = ProxyFault {
            kind: L1Fault::StaleHead,
            stale_below: 0x40,
        };
        let mut r = resp(Value::String("0x100".into()));
        assert!(tamper(&req("eth_blockNumber"), &mut r, spec));
        assert_eq!(r["result"], "0x3f");
        // Another method is untouched.
        let mut r = resp(Value::String("0x100".into()));
        assert!(!tamper(&req("eth_chainId"), &mut r, spec));
    }

    #[test]
    fn wrong_hash_and_root_flip_one_nibble() {
        let block = serde_json::json!({"hash": "0xabc0", "stateRoot": "0xdef0"});
        let mut r = resp(block.clone());
        assert!(tamper(
            &req("eth_getBlockByNumber"),
            &mut r,
            pf(L1Fault::WrongBlockHash)
        ));
        assert_eq!(r["result"]["hash"], "0xabc1");
        assert_eq!(r["result"]["stateRoot"], "0xdef0");
        let mut r = resp(block);
        assert!(tamper(
            &req("eth_getBlockByNumber"),
            &mut r,
            pf(L1Fault::WrongStateRoot)
        ));
        assert_eq!(r["result"]["stateRoot"], "0xdef1");
    }

    #[test]
    fn drop_and_fabricate_target_portal_logs() {
        let portal = format!("{PORTAL:?}");
        let logs = serde_json::json!([
            {"address": portal, "logIndex": "0x1"},
            {"address": "0x0000000000000000000000000000000000000000", "logIndex": "0x2"},
        ]);
        let mut r = resp(logs.clone());
        assert!(tamper(
            &req("eth_getLogs"),
            &mut r,
            pf(L1Fault::DropDepositLogs)
        ));
        assert_eq!(r["result"].as_array().unwrap().len(), 1);
        assert_eq!(
            r["result"][0]["address"].as_str().unwrap().to_lowercase(),
            "0x0000000000000000000000000000000000000000"
        );
        let mut r = resp(logs);
        assert!(tamper(
            &req("eth_getLogs"),
            &mut r,
            pf(L1Fault::FabricateDepositLog)
        ));
        assert_eq!(r["result"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn a_null_result_is_never_tampered() {
        let mut r = resp(Value::Null);
        for f in L1Fault::ALL {
            assert!(!tamper(&req("eth_getLogs"), &mut r, pf(f)));
        }
    }
}
