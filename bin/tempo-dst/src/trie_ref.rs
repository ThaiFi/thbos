// SPDX-License-Identifier: GPL-2.0

//! Storage-trie references for the E5 and E6 oracles, on alloy-trie.
//!
//! - [`storage_root`]: a contract's storage root rebuilt from scratch from its
//!   slot values (`HashBuilder` over the sorted hashed slots). The node computes
//!   roots incrementally (sparse trie, persisted trie updates), so a from-scratch
//!   build is an independent path even though reth also links alloy-trie.
//! - [`verify`]: an `eth_getProof` response checked against the block's state
//!   root: the account proof, then each storage proof against `storageHash`,
//!   both over [`hashed_path`] so that in-place nodes are not walked.

use alloy_primitives::{keccak256, Address, Bytes, B256, U256, U64};
use alloy_trie::{proof::verify_proof, root::storage_root_unhashed, Nibbles, TrieAccount};
use serde::Deserialize;

/// `(slot, value)` pairs.
pub type Storage = Vec<(u64, U256)>;

/// Storage root of `storage`; zero values are absent from the trie.
pub fn storage_root(storage: &[(u64, U256)]) -> B256 {
    storage_root_unhashed(
        storage
            .iter()
            .filter(|(_, v)| !v.is_zero())
            .map(|(slot, v)| (B256::from(U256::from(*slot)), *v)),
    )
}

/// `eth_getProof` response (EIP-1186).
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountProof {
    pub address: Address,
    pub nonce: U64,
    pub balance: U256,
    pub code_hash: B256,
    pub storage_hash: B256,
    pub account_proof: Vec<Bytes>,
    pub storage_proof: Vec<StorageProof>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct StorageProof {
    pub key: U256,
    pub value: U256,
    pub proof: Vec<Bytes>,
}

#[derive(Debug, PartialEq)]
pub enum ProofError {
    /// The account proof does not prove the reported account fields.
    Account(String),
    /// A storage proof does not prove the reported value under `storageHash`.
    Storage { slot: U256, error: String },
}

/// The steps of the Merkle path in `proof`: its leading nodes, up to (not
/// including) the first in-place (inlined) node.
///
/// A trie node whose RLP is shorter than 32 bytes is embedded in its parent
/// rather than referenced by hash, so it is not a step of the path. This is the
/// same rule [`crate::witness::extract_path`] already follows when it rebuilds a
/// path from the witness node set ("inline children stay embedded in their
/// parent and are not separate entries"); `eth_getProof` needs it too, because
/// reth hands `ProofNodes::matching_nodes_sorted(path)` through unfiltered and
/// that set retains the in-place node under its own (full) path. Left in,
/// `verify_proof` resolves the parent branch's in-place child to a value, finds
/// one more proof element, and rejects a correct, well-formed proof.
///
/// Trailing-only is exact: an inlined extension or branch is too short to hold
/// a 32-byte child hash, so an in-place node's whole subtree is in place too and
/// no hashed node can follow one. The root is referenced by hash whatever its
/// length (it *is* the root hash), so index 0 is always kept.
fn hashed_path(proof: &[Bytes]) -> &[Bytes] {
    let inline = proof.iter().skip(1).position(|node| node.len() < 32);
    &proof[..inline.map_or(proof.len(), |i| i + 1)]
}

/// Checks `proof` against `state_root`. An account with all-default fields
/// must be proven absent.
pub fn verify(proof: &AccountProof, state_root: B256) -> Result<(), ProofError> {
    let account = TrieAccount {
        nonce: proof.nonce.to(),
        balance: proof.balance,
        storage_root: proof.storage_hash,
        code_hash: proof.code_hash,
    };
    let expected = (account != TrieAccount::default()).then(|| alloy_rlp::encode(account));
    verify_proof(
        state_root,
        Nibbles::unpack(keccak256(proof.address)),
        expected,
        hashed_path(&proof.account_proof),
    )
    .map_err(|e| ProofError::Account(e.to_string()))?;
    for sp in &proof.storage_proof {
        let expected = (!sp.value.is_zero()).then(|| alloy_rlp::encode(sp.value));
        verify_proof(
            proof.storage_hash,
            Nibbles::unpack(keccak256(B256::from(sp.key))),
            expected,
            hashed_path(&sp.proof),
        )
        .map_err(|e| ProofError::Storage {
            slot: sp.key,
            error: e.to_string(),
        })?;
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use alloy_trie::{proof::ProofRetainer, HashBuilder};
    use serde_json::Value;

    fn root_hex(pairs: &[(u64, u64)]) -> String {
        let storage: Vec<_> = pairs.iter().map(|(s, v)| (*s, U256::from(*v))).collect();
        storage_root(&storage).to_string()
    }

    /// Proof of `nodes`' leaves, retained for `targets`, as `(root, proof per target)`.
    fn build(leaves: &[(B256, Vec<u8>)], targets: &[B256]) -> (B256, Vec<Vec<Bytes>>) {
        let mut leaves = leaves.to_vec();
        leaves.sort();
        let retainer = ProofRetainer::from_iter(targets.iter().map(|t| Nibbles::unpack(*t)));
        let mut hb = HashBuilder::default().with_proof_retainer(retainer);
        for (key, value) in &leaves {
            hb.add_leaf(Nibbles::unpack(*key), value);
        }
        let root = hb.root();
        let nodes = hb.take_proof_nodes();
        let proofs = targets
            .iter()
            .map(|t| {
                nodes
                    .matching_nodes_sorted(&Nibbles::unpack(*t))
                    .into_iter()
                    .map(|(_, n)| n)
                    .collect()
            })
            .collect();
        (root, proofs)
    }

    /// An honest node's `(state_root, eth_getProof)` for a contract at
    /// `address` holding `storage`, proving `slots`.
    pub fn honest_proof(
        address: &str,
        storage: &[(u64, u64)],
        slots: &[u64],
    ) -> (B256, AccountProof) {
        let (root, mut proofs) = honest_state(&[(address, storage, slots)]);
        (root, proofs.remove(0))
    }

    /// `(address, storage, proven slots)`.
    pub type Contract<'a> = (&'a str, &'a [(u64, u64)], &'a [u64]);

    /// An honest node's state root and `eth_getProof` per contract, for a
    /// state holding each `(address, storage)`, proving `slots`.
    pub fn honest_state(contracts: &[Contract<'_>]) -> (B256, Vec<AccountProof>) {
        let parts: Vec<_> = contracts
            .iter()
            .map(|(a, storage, slots)| account_part(a, storage, slots))
            .collect();
        let leaves: Vec<_> = parts
            .iter()
            .map(|(key, leaf, _)| (*key, leaf.clone()))
            .collect();
        let keys: Vec<_> = parts.iter().map(|(key, _, _)| *key).collect();
        let (state_root, account_proofs) = build(&leaves, &keys);
        let proofs = parts
            .into_iter()
            .zip(account_proofs)
            .map(|((_, _, mut proof), account_proof)| {
                proof.account_proof = account_proof;
                proof
            })
            .collect();
        (state_root, proofs)
    }

    /// One contract's account-trie key and leaf, and its proof without the
    /// account part.
    fn account_part(
        address: &str,
        storage: &[(u64, u64)],
        slots: &[u64],
    ) -> (B256, Vec<u8>, AccountProof) {
        let address: Address = address.parse().unwrap();
        let value = |s: u64| storage.iter().find(|(k, _)| *k == s).map_or(0, |(_, v)| *v);
        let leaves: Vec<_> = storage
            .iter()
            .filter(|(_, v)| *v != 0)
            .map(|(s, v)| {
                (
                    keccak256(B256::from(U256::from(*s))),
                    alloy_rlp::encode(U256::from(*v)),
                )
            })
            .collect();
        let targets: Vec<_> = slots
            .iter()
            .map(|s| keccak256(B256::from(U256::from(*s))))
            .collect();
        let (storage_hash, storage_proofs) = build(&leaves, &targets);
        let account = TrieAccount {
            nonce: 1,
            balance: U256::ZERO,
            storage_root: storage_hash,
            code_hash: keccak256(b"code"),
        };
        let key = keccak256(address);
        let proof = AccountProof {
            address,
            nonce: U64::from(1),
            balance: U256::ZERO,
            code_hash: account.code_hash,
            storage_hash,
            account_proof: Vec::new(),
            storage_proof: slots
                .iter()
                .zip(storage_proofs)
                .map(|(s, proof)| StorageProof {
                    key: U256::from(*s),
                    value: U256::from(value(*s)),
                    proof,
                })
                .collect(),
        };
        (key, alloy_rlp::encode(account), proof)
    }

    /// Real `eth_getProof` responses from a Tempo dev node (reth 42fa3c5)
    /// for the RawStorage contract, with the block's header `stateRoot`.
    fn fixture(block: u64) -> (B256, AccountProof, Vec<U256>) {
        let path = format!(
            "{}/testdata/proof_block{block}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        (
            v["state_root"].as_str().unwrap().parse().unwrap(),
            serde_json::from_value(v["proof"].clone()).unwrap(),
            serde_json::from_value(v["storage_at"].clone()).unwrap(),
        )
    }

    #[test]
    fn slot_paths_share_the_intended_prefixes() {
        let prefix = |s: u64| keccak256(B256::from(U256::from(s))).to_string()[2..5].to_string();
        assert_eq!(prefix(544), "120");
        assert_eq!(prefix(646), "121");
        assert_eq!(&prefix(131)[..2], "13");
        assert_eq!(&prefix(0)[..1], "2");
    }

    /// storageHash values reported by a Tempo dev node (reth 42fa3c5) for
    /// RawStorage blocks 21..29 running the collapse_abcd sequence.
    #[test]
    fn matches_node_roots_through_collapse_sequence() {
        let cases: &[(&[(u64, u64)], &str)] = &[
            (
                &[(544, 1)],
                "0x9c1bc8c6765b46c895c98d38aa670890e839c5d554c818d13cd0a61f2199193f",
            ),
            (
                &[(544, 1), (646, 1)],
                "0xdad20cc093ebc92d483c79fc4d80d6d10a91197dab5ab6314d9c52815f8d8ce7",
            ),
            (
                &[(544, 1), (646, 1), (131, 1)],
                "0x011bab17dd93212035bf2de0c571dead56386d42b3b4ed77b19b5d3dcdd7afed",
            ),
            (
                &[(544, 1), (646, 1), (131, 1), (0, 1)],
                "0x1daa48d84592389ab7fdbce646b4928231c028856284fda4bc04e4ad713c1bfc",
            ),
            (
                &[(544, 2), (646, 1), (131, 1), (0, 1)],
                "0x4c910ca842fa9193d277bb3c3ed573b7db52a6742ee703c14621ecf4d149670c",
            ),
            (
                &[(544, 2), (646, 1), (131, 1)],
                "0x669b39a03372fa136716aefbca5f41fd480a087c19dfbc455d81d799e8f56ae4",
            ),
            (
                &[(544, 2), (646, 1)],
                "0x8350eef39e704e8c7d0c7edc83173c39128ac37b1813b7f4669742a5de36b624",
            ),
            (
                &[(544, 2)],
                "0x138f24efcf384c1626fd3b56c309a77f467b63cdd40cc62a2de4641443895d07",
            ),
            (
                &[],
                "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            ),
        ];
        for (pairs, want) in cases {
            assert_eq!(&root_hex(pairs), want, "storage {pairs:?}");
        }
    }

    #[test]
    fn zero_values_are_absent() {
        assert_eq!(root_hex(&[(544, 1), (646, 0)]), root_hex(&[(544, 1)]));
        assert_eq!(root_hex(&[(0, 0)]), root_hex(&[]));
    }

    #[test]
    fn order_independent() {
        assert_eq!(
            root_hex(&[(646, 7), (0, 7), (131, 7)]),
            "0x5dc82150a47e75b4c75a9636ce883582e517b4451ec6f17520c433a6cd4648fe"
        );
    }

    /// Blocks 20 (empty storage), 21 (A only: three absence proofs) and 24
    /// (A, B, C, D live).
    #[test]
    fn node_proofs_verify() {
        for block in [20, 21, 24] {
            let (state_root, proof, storage_at) = fixture(block);
            assert_eq!(verify(&proof, state_root), Ok(()), "block {block}");
            let values: Vec<_> = proof.storage_proof.iter().map(|p| p.value).collect();
            assert_eq!(values, storage_at, "block {block}");
            let storage: Vec<_> = [544, 646, 131, 0].into_iter().zip(storage_at).collect();
            assert_eq!(storage_root(&storage), proof.storage_hash, "block {block}");
        }
    }

    /// The same block from reth's `eth_getMultiProof` (proof v2 path).
    #[test]
    fn node_multiproof_verifies() {
        let (state_root, proof, _) = fixture(24);
        let path = format!(
            "{}/testdata/multiproof_block24.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let multi: AccountProof =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(verify(&multi, state_root), Ok(()));
        assert_eq!(multi.storage_hash, proof.storage_hash);
    }

    #[test]
    fn tampered_node_proofs_fail() {
        let (state_root, proof, _) = fixture(24);
        assert!(matches!(
            verify(&proof, B256::ZERO),
            Err(ProofError::Account(_))
        ));

        let mut p = proof.clone();
        p.storage_hash = fixture(21).1.storage_hash;
        assert!(matches!(
            verify(&p, state_root),
            Err(ProofError::Account(_))
        ));

        let mut p = proof.clone();
        p.storage_proof[0].value = U256::from(2);
        assert!(matches!(
            verify(&p, state_root),
            Err(ProofError::Storage { .. })
        ));

        // Claiming a live slot is absent.
        let mut p = proof.clone();
        p.storage_proof[3].value = U256::ZERO;
        assert!(matches!(
            verify(&p, state_root),
            Err(ProofError::Storage { .. })
        ));

        // A storage proof with its leaf dropped.
        let mut p = proof.clone();
        p.storage_proof[1].proof.pop();
        assert!(matches!(
            verify(&p, state_root),
            Err(ProofError::Storage { .. })
        ));

        // Claiming an absent slot is live (block 21: only A is live).
        let (state_root, mut p, _) = fixture(21);
        p.storage_proof[1].value = U256::from(1);
        assert!(matches!(
            verify(&p, state_root),
            Err(ProofError::Storage { .. })
        ));
    }

    #[test]
    fn honest_proofs_verify() {
        let addr = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
        for storage in [
            &[][..],
            &[(544, 1)],
            &[(544, 1), (646, 3), (131, 1), (0, 9)],
        ] {
            let (root, p) = honest_proof(addr, storage, &[544, 646, 131, 0]);
            assert_eq!(verify(&p, root), Ok(()), "storage {storage:?}");
        }
    }

    const ADDR: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
    /// Seed 21's trie shape, and the slot it puts at an in-place leaf.
    const INLINE_SEED: u64 = 21;
    const INLINE_SLOT: u64 = 50541;

    /// Seed 21's storage, with a value class 1 ("small (< 0x80: inline-sized
    /// leaves)") value under [`INLINE_SLOT`] and wider values elsewhere.
    fn inline_storage() -> (Vec<u64>, Vec<(u64, u64)>) {
        let slots = crate::trie_gen::slots(INLINE_SEED);
        let storage = slots
            .iter()
            .map(|s| (*s, if *s == INLINE_SLOT { 0x69 } else { 0x4242 }))
            .collect();
        (slots, storage)
    }

    /// Seed 21 puts slots 50541 and 125299 at paths sharing 8 nibbles, so a
    /// one-byte value under 50541 makes a 31-byte leaf: short enough to live
    /// in place in its parent branch rather than be referenced by hash.
    /// `eth_getProof` returns it as a trailing proof element all the same, and
    /// walking it rejected correct proofs (false E13 and E6 findings).
    #[test]
    fn in_place_leaf_proof_verifies() {
        let (slots, storage) = inline_storage();
        assert!(
            slots.contains(&INLINE_SLOT) && slots.contains(&125299),
            "{slots:?}"
        );
        let (root, p) = honest_proof(ADDR, &storage, &slots);

        // The slot's proof really does carry a trailing in-place node, and it
        // is the only one: everything above it is referenced by hash.
        let sp = &p.storage_proof[slots.iter().position(|s| *s == INLINE_SLOT).unwrap()];
        assert_eq!(sp.key, U256::from(INLINE_SLOT));
        let tail = sp.proof.last().unwrap();
        assert!(tail.len() < 32, "no in-place node: {:?}", sp.proof);
        assert_eq!(hashed_path(&sp.proof).len(), sp.proof.len() - 1);
        assert!(hashed_path(&sp.proof).iter().all(|n| n.len() >= 32));
        // It is the leaf itself: its last byte is the value it holds.
        assert_eq!(*tail.last().unwrap(), 0x69);

        assert_eq!(verify(&p, root), Ok(()));
    }

    /// The trim must not turn the oracle into one that accepts anything: a
    /// proof of the in-place slot that is genuinely wrong is still rejected.
    #[test]
    fn in_place_leaf_proof_still_catches_lies() {
        let (slots, storage) = inline_storage();
        let (root, proof) = honest_proof(ADDR, &storage, &slots);
        let at = slots.iter().position(|s| *s == INLINE_SLOT).unwrap();

        let bad = |p: &AccountProof| {
            assert!(
                matches!(verify(p, root), Err(ProofError::Storage { slot, .. }) if slot == U256::from(INLINE_SLOT)),
                "accepted: {:?}",
                verify(p, root)
            )
        };

        // A different value under the in-place leaf.
        let mut p = proof.clone();
        p.storage_proof[at].value = U256::from(0x6a);
        bad(&p);

        // Claiming the live in-place slot is absent.
        let mut p = proof.clone();
        p.storage_proof[at].value = U256::ZERO;
        bad(&p);

        // The in-place leaf's parent branch dropped: the path no longer
        // reaches the value, and the trailing in-place node cannot stand in
        // for it.
        let mut p = proof.clone();
        let parent = hashed_path(&p.storage_proof[at].proof).len() - 1;
        p.storage_proof[at].proof.remove(parent);
        bad(&p);

        // A tampered in-place leaf: trimming it is sound only because the
        // parent branch's embedded copy is what verify_proof reads.
        let mut p = proof.clone();
        let last = p.storage_proof[at].proof.len() - 1;
        let mut leaf = p.storage_proof[at].proof[last].to_vec();
        *leaf.last_mut().unwrap() = 0x6a;
        p.storage_proof[at].proof[last] = Bytes::from(leaf);
        assert_eq!(
            verify(&p, root),
            Ok(()),
            "value comes from the parent branch"
        );
        // ... and claiming that tampered value does not verify.
        p.storage_proof[at].value = U256::from(0x6a);
        bad(&p);

        // The whole state root is wrong.
        assert!(matches!(
            verify(&proof, B256::ZERO),
            Err(ProofError::Account(_))
        ));
    }

    #[test]
    fn hashed_path_keeps_the_root_and_drops_the_in_place_tail() {
        let long = |b: u8| Bytes::from(vec![b; 40]);
        let short = |b: u8| Bytes::from(vec![b; 20]);
        let path = |p: &[Bytes]| hashed_path(p).len();

        assert_eq!(path(&[]), 0);
        assert_eq!(path(&[long(1), long(2), long(3)]), 3);
        assert_eq!(path(&[long(1), long(2), short(3)]), 2);
        // An in-place subtree can be several nodes deep; all of it goes.
        assert_eq!(path(&[long(1), short(2), short(3)]), 1);
        // The root is referenced by hash whatever its length.
        assert_eq!(path(&[short(1)]), 1);
        assert_eq!(path(&[short(1), short(2)]), 1);
    }
}
