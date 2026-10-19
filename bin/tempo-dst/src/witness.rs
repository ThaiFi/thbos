// SPDX-License-Identifier: GPL-2.0

//! Reference for the execution-witness oracle (E6/witness-*), on alloy-trie.
//!
//! `debug_executionWitness` returns the flat set of state-trie nodes (and
//! contract codes) touched while executing a block, proving the block's
//! **pre-execution** state. This module re-derives ordered Merkle proofs from
//! that unordered node set and checks them against the parent block's state
//! root, independently of `eth_getProof`:
//!
//! - [`node_map`]: `{keccak256(node) -> node}` over `witness.state`, so a child
//!   referenced by hash can be looked up.
//! - [`extract_path`]: walks the partial trie from a root hash along a key's
//!   nibbles, collecting the hashed nodes along the way in the order
//!   [`verify_proof`] expects (inline nodes stay embedded in their parent).
//! - [`check_account`]: for one account, verifies the witness-derived account
//!   proof (and each witness-covered storage slot) against the parent state
//!   root, using the node's own `eth_getProof` at the parent block as the
//!   expected values. Paths the witness does not cover (untouched this block)
//!   are skipped, not failed.
//!
//! reth has serialized `state`/`codes`/`keys` as either a JSON array of hex
//! strings or an object map `{hash: node}` across versions; [`from_value`]
//! normalizes both, ignoring any keys since every node is re-hashed.
//!
//! [`from_value`]: ExecutionWitness::from_value

use std::collections::{HashMap, HashSet};

use alloy_primitives::{keccak256, Bytes, B256};
use alloy_rlp::Decodable;
use alloy_trie::{nodes::TrieNode, proof::verify_proof, Nibbles, TrieAccount};
use serde_json::Value;

use crate::trie_ref::AccountProof;

/// Outcome of `debug_executionWitness`, distinguishing a node that lacks the
/// method (capability-gated coverage) from a transient failure (skip).
#[derive(Debug, Clone)]
pub enum WitnessRpc {
    Ok(ExecutionWitness),
    /// `method not found` (`-32601`): the node's debug namespace is off.
    Unsupported,
    /// The node is down or the call failed transiently; skip this tick.
    Unavailable,
}

/// Whether a JSON-RPC error string is a "method not found"/unknown-method
/// error, so the witness oracle treats the node as capability-gated rather
/// than failing. reth replies `the method ... does not exist/is not available`.
pub fn is_method_not_found(err: &str) -> bool {
    if err.contains("-32601") {
        return true;
    }
    let lower = err.to_lowercase();
    [
        "method not found",
        "does not exist",
        "is not available",
        "not supported",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// reth's `debug_executionWitness` response (hand-rolled: the fields are
/// serialized as either arrays or `{hash: node}` maps across reth versions).
#[derive(Debug, Clone, Default)]
pub struct ExecutionWitness {
    /// State-trie nodes (branch/extension/leaf RLP) touched by the block.
    pub state: Vec<Bytes>,
    /// Bytecode of contracts touched by the block.
    pub codes: Vec<Bytes>,
    /// Trie-key preimages (parsed for schema fidelity; unused: we re-hash).
    #[allow(dead_code)]
    pub keys: Vec<Bytes>,
    /// Ancestor block headers (parsed for schema fidelity; unused here).
    #[allow(dead_code)]
    pub headers: Vec<Bytes>,
}

impl ExecutionWitness {
    /// Normalizes a `debug_executionWitness` result, tolerating each field
    /// being an array of hex strings, a `{hash: node}` map, or absent.
    pub fn from_value(v: &Value) -> ExecutionWitness {
        ExecutionWitness {
            state: bytes_collection(v.get("state")),
            codes: bytes_collection(v.get("codes")),
            keys: bytes_collection(v.get("keys")),
            headers: bytes_collection(v.get("headers")),
        }
    }
}

/// Hex strings in an array or in a map's values, as `Bytes`; unparseable
/// entries and other shapes yield an empty vector.
fn bytes_collection(v: Option<&Value>) -> Vec<Bytes> {
    let items: Box<dyn Iterator<Item = &Value>> = match v {
        Some(Value::Array(a)) => Box::new(a.iter()),
        Some(Value::Object(m)) => Box::new(m.values()),
        _ => return Vec::new(),
    };
    items
        .filter_map(|e| serde_json::from_value::<Bytes>(e.clone()).ok())
        .collect()
}

/// `{keccak256(node) -> node}` over every witness state node.
pub fn node_map(witness: &ExecutionWitness) -> HashMap<B256, Bytes> {
    witness
        .state
        .iter()
        .map(|node| (keccak256(node), node.clone()))
        .collect()
}

/// `{keccak256(code)}` over every witness code.
pub fn code_hashes(witness: &ExecutionWitness) -> HashSet<B256> {
    witness.codes.iter().map(keccak256).collect()
}

/// keccak256 of empty code (an account with no code).
fn empty_code_hash() -> B256 {
    keccak256([])
}

/// Where a trie walk stopped.
#[derive(Debug, PartialEq, Eq)]
enum PathEnd {
    /// The walk reached a leaf, an exclusion, or a diverging extension: the
    /// collected path is a complete (inclusion or exclusion) proof.
    Complete,
    /// A child referenced by hash (or the root) was absent from the witness,
    /// so the path is truncated: the key is not covered by this witness.
    Missing,
}

/// The hashed nodes from `root` along `key`, in the order [`verify_proof`]
/// expects, plus whether the path is complete or truncated. Inline children
/// stay embedded in their parent and are not separate entries.
fn extract_path(nodes: &HashMap<B256, Bytes>, root: B256, key: &Nibbles) -> (Vec<Bytes>, PathEnd) {
    let mut path = Vec::new();
    let mut walked = Nibbles::new();
    let mut next = Some(root);
    while let Some(hash) = next {
        let Some(node_bytes) = nodes.get(&hash) else {
            return (path, PathEnd::Missing);
        };
        path.push(node_bytes.clone());
        let Ok(node) = TrieNode::decode(&mut &node_bytes[..]) else {
            return (path, PathEnd::Missing);
        };
        next = descend(node, &mut walked, key);
    }
    (path, PathEnd::Complete)
}

/// The hash of the next node to visit for `key`, resolving inline children in
/// place; `None` at a terminal node (leaf, exclusion, or exhausted key),
/// mirroring alloy-trie's own `process_trie_node`.
fn descend(node: TrieNode, walked: &mut Nibbles, key: &Nibbles) -> Option<B256> {
    match node {
        TrieNode::Branch(branch) => {
            let next = key.get(walked.len())?;
            let mut ptr = branch.as_ref().first_child_index();
            for index in 0u8..16 {
                if branch.state_mask.is_bit_set(index) {
                    if index == next {
                        walked.push(next);
                        let child = &branch.stack[ptr];
                        return if child.is_hash() {
                            child.as_hash()
                        } else {
                            TrieNode::decode(&mut &child[..])
                                .ok()
                                .and_then(|n| descend(n, walked, key))
                        };
                    }
                    ptr += 1;
                }
            }
            None
        }
        TrieNode::Extension(ext) => {
            walked.extend(&ext.key);
            if ext.child.is_hash() {
                ext.child.as_hash()
            } else {
                TrieNode::decode(&mut &ext.child[..])
                    .ok()
                    .and_then(|n| descend(n, walked, key))
            }
        }
        TrieNode::Leaf(leaf) => {
            walked.extend(&leaf.key);
            None
        }
        TrieNode::EmptyRoot => None,
    }
}

/// One account's witness-verification result.
#[derive(Debug, Default)]
pub struct WitnessReport {
    /// The account proof verified against the parent state root.
    pub verified: bool,
    /// `(signature, detail)` failures (account, storage, or code).
    pub failures: Vec<(String, String)>,
}

/// Checks that `witness` proves `proof` (the node's `eth_getProof` at the
/// **parent** block) against `parent_state_root`:
///
/// - the account proof derived from the witness verifies, and proves the same
///   account `eth_getProof` reports (else `E6/witness-account-mismatch`);
/// - each witness-covered storage slot proves the same value (else
///   `E6/witness-proof-invalid`); slots the witness does not cover are skipped;
/// - a contract account's code is present in `witness.codes` (else
///   `E6/witness-code-unreferenced`); extra codes are ignored.
///
/// An account the witness does not cover (untouched this block) yields an empty
/// report (not verified, no failure).
pub fn check_account(
    nodes: &HashMap<B256, Bytes>,
    parent_state_root: B256,
    proof: &AccountProof,
    codes: &HashSet<B256>,
) -> WitnessReport {
    let mut report = WitnessReport::default();
    let account = TrieAccount {
        nonce: proof.nonce.to(),
        balance: proof.balance,
        storage_root: proof.storage_hash,
        code_hash: proof.code_hash,
    };
    let expected = (account != TrieAccount::default()).then(|| alloy_rlp::encode(account));
    let key = Nibbles::unpack(keccak256(proof.address));
    let (path, end) = extract_path(nodes, parent_state_root, &key);
    if end == PathEnd::Missing {
        // The account's path is not in this block's witness: untouched.
        return report;
    }
    if let Err(e) = verify_proof(parent_state_root, key, expected, &path) {
        report.failures.push((
            "E6/witness-account-mismatch".to_string(),
            format!(
                "state root {parent_state_root}, storage hash {}: {e}",
                proof.storage_hash
            ),
        ));
        return report;
    }
    report.verified = true;

    for sp in &proof.storage_proof {
        let skey = Nibbles::unpack(keccak256(B256::from(sp.key)));
        let (spath, send) = extract_path(nodes, proof.storage_hash, &skey);
        if send == PathEnd::Missing {
            // The slot's subtree is not in the witness: skip as uncovered.
            continue;
        }
        let expected = (!sp.value.is_zero()).then(|| alloy_rlp::encode(sp.value));
        if let Err(e) = verify_proof(proof.storage_hash, skey, expected, &spath) {
            report.failures.push((
                "E6/witness-proof-invalid".to_string(),
                format!("slot {}, storage hash {}: {e}", sp.key, proof.storage_hash),
            ));
        }
    }

    // A verified contract account's code should be present in the witness.
    if proof.code_hash != empty_code_hash()
        && !proof.code_hash.is_zero()
        && !codes.contains(&proof.code_hash)
    {
        report.failures.push((
            "E6/witness-code-unreferenced".to_string(),
            format!("code hash {} absent from witness.codes", proof.code_hash),
        ));
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trie_ref;
    use alloy_primitives::U256;
    use serde_json::json;

    const ADDR: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
    const SLOTS: [u64; 2] = [544, 646];

    /// A witness whose `state` holds every node of an honest proof of `addr`
    /// over `storage`, and the proof itself (the parent-block ground truth).
    fn honest_witness(storage: &[(u64, u64)]) -> (B256, AccountProof, ExecutionWitness) {
        let (root, proof) = trie_ref::tests::honest_proof(ADDR, storage, &SLOTS);
        let mut state: Vec<Bytes> = proof.account_proof.clone();
        for sp in &proof.storage_proof {
            state.extend(sp.proof.iter().cloned());
        }
        let witness = ExecutionWitness {
            state,
            codes: vec![Bytes::from_static(b"code")],
            ..Default::default()
        };
        (root, proof, witness)
    }

    #[test]
    fn deserializes_array_and_map_state() {
        let array = json!({
            "state": ["0x1234", "0xabcd"],
            "codes": ["0x00"],
            "keys": ["0xdead"],
        });
        let w = ExecutionWitness::from_value(&array);
        assert_eq!(w.state.len(), 2);
        assert_eq!(w.state[0], Bytes::from_static(&[0x12, 0x34]));
        assert_eq!(w.codes, vec![Bytes::from_static(&[0x00])]);
        assert_eq!(w.keys, vec![Bytes::from_static(&[0xde, 0xad])]);

        let map = json!({
            "state": {"0xaa": "0x1234", "0xbb": "0xabcd"},
            "codes": {"0xcc": "0x00"},
        });
        let w = ExecutionWitness::from_value(&map);
        // Keys are ignored; the node bytes are collected in some order.
        let mut got: Vec<_> = w.state.iter().map(|b| b.to_vec()).collect();
        got.sort();
        assert_eq!(got, vec![vec![0x12, 0x34], vec![0xab, 0xcd]]);
        assert_eq!(w.codes, vec![Bytes::from_static(&[0x00])]);

        // A missing field, or a non-collection, is empty.
        let w = ExecutionWitness::from_value(&json!({"state": "0x00"}));
        assert!(w.state.is_empty() && w.codes.is_empty());
    }

    #[test]
    fn method_not_found_detected() {
        assert!(is_method_not_found(
            r#"{"code":-32601,"message":"Method not found"}"#
        ));
        assert!(is_method_not_found(
            "the method debug_executionWitness does not exist/is not available"
        ));
        assert!(!is_method_not_found("execution reverted"));
    }

    #[test]
    fn extracts_and_verifies_honest_witness() {
        for storage in [&[][..], &[(544, 1)], &[(544, 7), (646, 3)]] {
            let (root, proof, witness) = honest_witness(storage);
            let nodes = node_map(&witness);
            let codes = code_hashes(&witness);
            // The parent state root node is present (Check A).
            assert!(nodes.contains_key(&root), "storage {storage:?}");
            // The witness-derived account path matches eth_getProof's.
            let key = Nibbles::unpack(keccak256(proof.address));
            let (path, end) = extract_path(&nodes, root, &key);
            assert_eq!(end, PathEnd::Complete, "storage {storage:?}");
            assert_eq!(path, proof.account_proof, "storage {storage:?}");

            let report = check_account(&nodes, root, &proof, &codes);
            assert!(report.verified, "storage {storage:?}");
            assert!(report.failures.is_empty(), "{:?}", report.failures);
        }
    }

    #[test]
    fn uncovered_account_is_skipped_not_failed() {
        let (root, proof, witness) = honest_witness(&[(544, 1)]);
        // Drop the account's nodes: the account is no longer covered.
        let empty = ExecutionWitness {
            state: witness
                .state
                .iter()
                .filter(|n| keccak256(n) != root)
                .cloned()
                .collect(),
            ..witness
        };
        let nodes = node_map(&empty);
        // Root is gone, so even extraction reports Missing.
        let (_, end) = extract_path(&nodes, root, &Nibbles::unpack(keccak256(proof.address)));
        assert_eq!(end, PathEnd::Missing);
        let report = check_account(&nodes, root, &proof, &code_hashes(&empty));
        assert!(!report.verified);
        assert!(report.failures.is_empty());
    }

    #[test]
    fn tampered_account_value_is_reported() {
        let (root, mut proof, witness) = honest_witness(&[(544, 1)]);
        let nodes = node_map(&witness);
        let codes = code_hashes(&witness);
        // Claim a different balance than the witness proves.
        proof.balance = U256::from(999);
        let report = check_account(&nodes, root, &proof, &codes);
        assert!(!report.verified);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].0, "E6/witness-account-mismatch");
    }

    #[test]
    fn tampered_storage_value_is_reported() {
        let (root, mut proof, witness) = honest_witness(&[(544, 1), (646, 2)]);
        let nodes = node_map(&witness);
        let codes = code_hashes(&witness);
        // The account still verifies, but a storage value is wrong.
        proof.storage_proof[0].value = U256::from(42);
        let report = check_account(&nodes, root, &proof, &codes);
        assert!(report.verified);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].0, "E6/witness-proof-invalid");
    }

    #[test]
    fn missing_code_is_reported() {
        let (root, proof, mut witness) = honest_witness(&[(544, 1)]);
        // honest_proof's code hash is keccak("code"); drop it from the witness.
        witness.codes.clear();
        let nodes = node_map(&witness);
        let codes = code_hashes(&witness);
        let report = check_account(&nodes, root, &proof, &codes);
        assert!(report.verified);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].0, "E6/witness-code-unreferenced");
    }
}
