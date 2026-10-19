// SPDX-License-Identifier: GPL-2.0

//! Generated state-mutation load (`load=statemix`): a pure function of the run
//! seed, driving the [`Mutator`] contract (contrib/bedrock-dst/statemix) so one
//! contract exercises every tx-level state-mutation path. It is the generic
//! workload behind the generic valid-state-root invariant ([`crate::state_root`]):
//! a seed-weighted rotating mix of plain transfers, `SSTORE` set/update/
//! clear-to-zero, `CREATE`, `CREATE2` at a reused (previously self-destructed)
//! address, `SELFDESTRUCT`, same-tx create+selfdestruct, empty-account
//! touch/delete (EIP-161), max/edge values, and bulk-write-then-clear.
//!
//! Determinism: the whole plan ([`mutations`]) is a function of `(seed,
//! generation, steps)` only — no wall-clock, no unseeded RNG. The plan is also
//! the per-block tx set a later build-differential strand can replay (each
//! [`Mutation`] records its `(op, key, val)` and its [`MutationKind`]).
//!
//! Mutation keys that write the contract's own storage (`SET`, `CREATE`,
//! `CREATE2`, `DESTROY`) are drawn from a fixed per-seed [`slots`] pool, so the
//! valid-root oracle can rebuild the contract's storage root from exactly those
//! slots. `EMPTY_TOUCH` and `TRANSFER` keys are account addresses and write no
//! contract storage.

use alloy_primitives::{keccak256, U256};

/// Mutator's CREATE address (dev account 0, nonce 0 on a fresh chain), the same
/// slot-0 CREATE address RawStorage uses; only one load runs at a time.
pub const CONTRACT: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

/// Contract storage slots the load writes (a per-seed pool). The valid-root
/// oracle rebuilds the storage root from exactly these.
const POOL_SIZE: usize = 12;

/// Bulk-write-then-clear runs write a contiguous slot range `base..base+n`,
/// `base` in `[0, BULK_BASE_RANGE)` and `n` in
/// `[BULK_MIN_N, BULK_MIN_N + BULK_N_SPREAD)`, drawn fresh per generation. These
/// keys are NOT in the per-seed [`slots`] pool, so the valid-root oracle's
/// candidate set must union them in ([`written_slots`]); otherwise a block
/// captured mid-bulk-write (its range still set, the pool slots not yet written)
/// reads an empty pool and recomputes the empty storage root — the
/// `state-root-recomputed` false positive.
const BULK_BASE_RANGE: u64 = 0x400;
const BULK_MIN_N: u64 = 3;
const BULK_N_SPREAD: u64 = 5;

/// `exec`'s `op` selector (must match Mutator.sol).
pub mod op {
    pub const SET: u64 = 0;
    pub const CREATE: u64 = 1;
    pub const CREATE2: u64 = 2;
    pub const DESTROY: u64 = 3;
    pub const CREATE_DIE: u64 = 4;
    pub const EMPTY_TOUCH: u64 = 5;
    pub const TRANSFER: u64 = 6;
}

/// The distinct mutation behaviours a run rotates through. Every one must be
/// emitted by a long-enough plan (the generator forces one of each early), so
/// each state-mutation path is exercised.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MutationKind {
    /// A plain value transfer to a derived address (op TRANSFER).
    Transfer,
    /// `SSTORE` of a fresh non-zero value to a pool slot (op SET).
    Set,
    /// `SSTORE` overwriting a pool slot that already held a value (op SET).
    Update,
    /// `SSTORE` of zero to a pool slot, clearing it (op SET, val 0).
    ClearToZero,
    /// `SSTORE` of a max/edge value (op SET, val in {MAX, MAX-1, 1<<255}).
    MaxEdge,
    /// `CREATE` a child, recording it in a pool slot (op CREATE).
    Create,
    /// `CREATE2` a child at a (possibly reused) salt address (op CREATE2).
    Create2Reuse,
    /// `SELFDESTRUCT` the child recorded in a pool slot (op DESTROY).
    Destroy,
    /// Create and self-destruct a child in the same tx (op CREATE_DIE).
    CreateDie,
    /// Touch an empty account, created then pruned (op EMPTY_TOUCH, EIP-161).
    EmptyTouch,
    /// Part of a bulk-write-then-clear run (op SET; written then later zeroed).
    BulkWrite,
    /// Part of the clear phase of a bulk-write-then-clear run (op SET, val 0).
    BulkClear,
}

impl MutationKind {
    /// Every kind, for coverage assertions in tests.
    #[cfg(test)]
    pub const ALL: [MutationKind; 12] = [
        MutationKind::Transfer,
        MutationKind::Set,
        MutationKind::Update,
        MutationKind::ClearToZero,
        MutationKind::MaxEdge,
        MutationKind::Create,
        MutationKind::Create2Reuse,
        MutationKind::Destroy,
        MutationKind::CreateDie,
        MutationKind::EmptyTouch,
        MutationKind::BulkWrite,
        MutationKind::BulkClear,
    ];

    /// A short stable tag (recorded in events / details).
    pub fn tag(self) -> &'static str {
        match self {
            MutationKind::Transfer => "transfer",
            MutationKind::Set => "set",
            MutationKind::Update => "update",
            MutationKind::ClearToZero => "clear",
            MutationKind::MaxEdge => "max-edge",
            MutationKind::Create => "create",
            MutationKind::Create2Reuse => "create2-reuse",
            MutationKind::Destroy => "destroy",
            MutationKind::CreateDie => "create-die",
            MutationKind::EmptyTouch => "empty-touch",
            MutationKind::BulkWrite => "bulk-write",
            MutationKind::BulkClear => "bulk-clear",
        }
    }
}

/// One generated mutation: the `exec(op, key, val)` call it sends and the
/// behaviour it stands for. `(op, key, val)` is exactly the tx a replay sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mutation {
    pub kind: MutationKind,
    pub op: u64,
    pub key: U256,
    pub val: U256,
}

const SLOT_SALT: u64 = 0x7374_6d78_736c_6f74; // "stmxslot"
const OPS_SALT: u64 = 0x7374_6d78_6f70_7300; // "stmxops\0"
const WEIGHT_SALT: u64 = 0x7374_6d78_7767_7400; // "stmxwgt\0"

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// A small splitmix64 stream.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = splitmix64(self.0);
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
}

/// The run's contract storage slots (a per-seed pool), sorted and distinct.
/// Includes the hot low slots and a spread of pseudo-random ones, so writes,
/// clears, creates and destroys land across the storage trie. A pure function
/// of the seed.
pub fn slots(seed: u64) -> Vec<u64> {
    let mut rng = Rng::new(seed ^ SLOT_SALT);
    let mut out = vec![0u64, 1, 2];
    while out.len() < POOL_SIZE {
        // A mix of near-zero slots (deep shared prefixes) and full-range ones.
        let s = if rng.below(3) == 0 {
            rng.below(64)
        } else {
            rng.next()
        };
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out.sort_unstable();
    out
}

/// The complete set of contract-storage slots the load can ever write for
/// `seed`, across every generation: the per-seed [`slots`] pool PLUS the whole
/// bulk-write range (`0..BULK_BASE_RANGE + BULK_MIN_N + BULK_N_SPREAD`, which
/// covers every `base..base+n` any generation can draw). Sorted and distinct.
///
/// This is the candidate set the generic valid-state-root oracle
/// ([`crate::state_root`]) reads to rebuild the Mutator's storage root from
/// scratch. The bulk bases are drawn per generation, so unlike [`slots`] this
/// set is deliberately generation-independent (the union over all generations):
/// a pure function of the seed, analogous to `trie_gen::slots`.
pub fn written_slots(seed: u64) -> Vec<u64> {
    let mut set: std::collections::BTreeSet<u64> = slots(seed).into_iter().collect();
    // `base` in [0, BULK_BASE_RANGE), `n` in [BULK_MIN_N, BULK_MIN_N + BULK_N_SPREAD),
    // so the largest key is (BULK_BASE_RANGE - 1) + (BULK_MIN_N + BULK_N_SPREAD - 1).
    let bulk_end = BULK_BASE_RANGE + BULK_MIN_N + BULK_N_SPREAD - 1;
    set.extend(0..bulk_end);
    set.into_iter().collect()
}

/// Weights of the seven `exec` ops, each at least one so every op can appear.
struct Weights([u64; 7]);

fn weights(seed: u64) -> Weights {
    let mut rng = Rng::new(seed ^ WEIGHT_SALT);
    let mut w = [0u64; 7];
    for x in &mut w {
        *x = 1 + rng.below(4);
    }
    Weights(w)
}

impl Weights {
    fn pick(&self, rng: &mut Rng) -> u64 {
        let total: u64 = self.0.iter().sum();
        let mut pick = rng.below(total);
        for (op, &w) in self.0.iter().enumerate() {
            if pick < w {
                return op as u64;
            }
            pick -= w;
        }
        0
    }
}

/// A full/edge value by class.
fn edge_value(rng: &mut Rng) -> U256 {
    match rng.below(4) {
        0 => U256::MAX,
        1 => U256::MAX - U256::from(1u64),
        2 => U256::from(1u64) << 255,
        _ => (U256::from(1u64) << 128) - U256::from(1u64),
    }
}

/// A fresh non-zero value, varied across encoding classes.
fn fresh_value(rng: &mut Rng, step: usize) -> U256 {
    match rng.below(4) {
        0 => U256::from(1 + rng.below(0x7f)),
        1 => U256::from(0x80 + rng.below(u64::MAX - 0x80)),
        2 => edge_value(rng),
        // A keccak-derived full word that is unique per step, so an update
        // always changes the slot's value (and the root).
        _ => U256::from_be_bytes(keccak256((step as u64).to_be_bytes()).0),
    }
}

/// The run's mutation plan for load generation `generation`: `steps` mutations,
/// a seed-weighted rotating mix of every [`MutationKind`]. A pure function of
/// `(seed, generation, steps)`; the first mutations force one of every kind so
/// even a short run covers them all.
pub fn mutations(seed: u64, generation: u64, steps: usize) -> Vec<Mutation> {
    let pool = slots(seed);
    let weights = weights(seed);
    let gen_seed = seed ^ OPS_SALT ^ generation.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut rng = Rng::new(gen_seed);
    let mut out: Vec<Mutation> = Vec::with_capacity(steps);
    // Track which pool slots currently hold a value / a child, so updates,
    // clears and destroys act on live slots.
    let mut set_slots: Vec<u64> = Vec::new();
    let mut child_slots: Vec<u64> = Vec::new();

    let slot = |rng: &mut Rng| pool[rng.below(pool.len() as u64) as usize];
    let address_key = |rng: &mut Rng| {
        // A 160-bit address, outside the slot pool (writes no contract storage).
        let hi = rng.next();
        let lo = rng.next();
        (U256::from(hi) << 64) | U256::from(lo) | (U256::from(1u64) << 159)
    };

    // A short forced prologue: one of every kind, so coverage never depends on
    // chance in a short run. bulk-write-then-clear is scheduled as a run below.
    let prologue = [
        MutationKind::Set,
        MutationKind::Transfer,
        MutationKind::Create,
        MutationKind::Create2Reuse,
        MutationKind::Destroy,
        MutationKind::CreateDie,
        MutationKind::EmptyTouch,
        MutationKind::MaxEdge,
        MutationKind::Update,
        MutationKind::ClearToZero,
    ];

    let mut forced = prologue.iter().copied();
    let mut did_bulk = false;
    while out.len() < steps {
        // Every so often, a bulk-write-then-clear run over a contiguous slot
        // range, which stresses many trie leaves appearing then disappearing.
        if (!did_bulk && out.len() + 8 <= steps) || (rng.below(40) == 0 && out.len() + 8 <= steps) {
            did_bulk = true;
            let base = rng.below(BULK_BASE_RANGE);
            let n = BULK_MIN_N + rng.below(BULK_N_SPREAD);
            for i in 0..n {
                let key = U256::from(base + i);
                out.push(Mutation {
                    kind: MutationKind::BulkWrite,
                    op: op::SET,
                    key,
                    val: fresh_value(&mut rng, out.len()),
                });
            }
            for i in 0..n {
                out.push(Mutation {
                    kind: MutationKind::BulkClear,
                    op: op::SET,
                    key: U256::from(base + i),
                    val: U256::ZERO,
                });
            }
            continue;
        }
        let kind = forced
            .next()
            .unwrap_or_else(|| match weights.pick(&mut rng) {
                x if x == op::CREATE => MutationKind::Create,
                x if x == op::CREATE2 => MutationKind::Create2Reuse,
                x if x == op::DESTROY => MutationKind::Destroy,
                x if x == op::CREATE_DIE => MutationKind::CreateDie,
                x if x == op::EMPTY_TOUCH => MutationKind::EmptyTouch,
                x if x == op::TRANSFER => MutationKind::Transfer,
                // op::SET: set / update / clear / max-edge, by sub-draw.
                _ => match rng.below(4) {
                    0 if !set_slots.is_empty() => MutationKind::Update,
                    1 if !set_slots.is_empty() => MutationKind::ClearToZero,
                    2 => MutationKind::MaxEdge,
                    _ => MutationKind::Set,
                },
            });
        let m = match kind {
            MutationKind::Set => {
                let k = slot(&mut rng);
                if !set_slots.contains(&k) {
                    set_slots.push(k);
                }
                Mutation {
                    kind,
                    op: op::SET,
                    key: U256::from(k),
                    val: fresh_value(&mut rng, out.len()),
                }
            }
            MutationKind::MaxEdge => {
                let k = slot(&mut rng);
                if !set_slots.contains(&k) {
                    set_slots.push(k);
                }
                Mutation {
                    kind,
                    op: op::SET,
                    key: U256::from(k),
                    val: edge_value(&mut rng),
                }
            }
            MutationKind::Update => {
                let k = if set_slots.is_empty() {
                    slot(&mut rng)
                } else {
                    set_slots[rng.below(set_slots.len() as u64) as usize]
                };
                if !set_slots.contains(&k) {
                    set_slots.push(k);
                }
                Mutation {
                    kind,
                    op: op::SET,
                    key: U256::from(k),
                    val: fresh_value(&mut rng, out.len()),
                }
            }
            MutationKind::ClearToZero => {
                let (k, pos) = if set_slots.is_empty() {
                    (slot(&mut rng), None)
                } else {
                    let i = rng.below(set_slots.len() as u64) as usize;
                    (set_slots[i], Some(i))
                };
                if let Some(i) = pos {
                    set_slots.remove(i);
                }
                Mutation {
                    kind,
                    op: op::SET,
                    key: U256::from(k),
                    val: U256::ZERO,
                }
            }
            MutationKind::Create => {
                let k = slot(&mut rng);
                if !child_slots.contains(&k) {
                    child_slots.push(k);
                }
                if !set_slots.contains(&k) {
                    set_slots.push(k);
                }
                Mutation {
                    kind,
                    op: op::CREATE,
                    key: U256::from(k),
                    val: U256::ZERO,
                }
            }
            MutationKind::Create2Reuse => {
                let k = slot(&mut rng);
                if !child_slots.contains(&k) {
                    child_slots.push(k);
                }
                if !set_slots.contains(&k) {
                    set_slots.push(k);
                }
                Mutation {
                    kind,
                    op: op::CREATE2,
                    key: U256::from(k),
                    val: U256::ZERO,
                }
            }
            MutationKind::Destroy => {
                let (k, cpos) = if child_slots.is_empty() {
                    (slot(&mut rng), None)
                } else {
                    let i = rng.below(child_slots.len() as u64) as usize;
                    (child_slots[i], Some(i))
                };
                if let Some(i) = cpos {
                    child_slots.remove(i);
                }
                if let Some(i) = set_slots.iter().position(|s| *s == k) {
                    set_slots.remove(i);
                }
                Mutation {
                    kind,
                    op: op::DESTROY,
                    key: U256::from(k),
                    val: U256::ZERO,
                }
            }
            MutationKind::CreateDie => Mutation {
                kind,
                op: op::CREATE_DIE,
                key: U256::ZERO,
                val: U256::ZERO,
            },
            MutationKind::EmptyTouch => Mutation {
                kind,
                op: op::EMPTY_TOUCH,
                key: address_key(&mut rng),
                val: U256::ZERO,
            },
            MutationKind::Transfer => Mutation {
                kind,
                op: op::TRANSFER,
                key: address_key(&mut rng),
                val: U256::ZERO,
            },
            // Bulk kinds are only produced by the run above.
            MutationKind::BulkWrite | MutationKind::BulkClear => continue,
        };
        out.push(m);
    }
    out.truncate(steps);
    out
}

/// The per-generation mutation mix, recorded with the run (events.jsonl) so a
/// later build-differential strand can see — and replay via [`mutations`] — the
/// exact deterministic tx set this generation sent: the contract, the slot pool,
/// and the count of each [`MutationKind`].
pub fn summary(seed: u64, generation: u64, steps: usize) -> serde_json::Value {
    let muts = mutations(seed, generation, steps);
    let mut counts: std::collections::BTreeMap<&str, u64> = std::collections::BTreeMap::new();
    for m in &muts {
        *counts.entry(m.kind.tag()).or_default() += 1;
    }
    serde_json::json!({
        "contract": CONTRACT,
        "generation": generation,
        "steps": muts.len(),
        "slots": slots(seed),
        "kinds": counts,
    })
}

/// txgen spec for load generation `generation` with spec seed `seed`: `steps`
/// `exec(op, key, val)` calls over the [`Mutator`] contract, in one sequence
/// from dev account 0 (nonce order). Deterministic per generation.
pub fn spec(seed: u64, generation: u64, steps: usize) -> String {
    let muts = mutations(seed, generation, steps);
    let mut out = format!(
        "# Generated by tempo-dst (statemix_gen) for seed {seed}, load generation {generation}.\n\
         chain_id: 1337\n\
         accounts:\n  mix:\n    mnemonic: \"test test test test test test test test test test test junk\"\n    range: [0, 1]\n\
         artifacts:\n  Mutator:\n    abi: mutator.json\n    bytecode: mutator.json\n\
         templates:\n  exec:\n    type: tempo\n    from: {{ pool: mix, select: {{ index: 0 }} }}\n    gas_limit: 2000000\n\
         \x20   max_fee_per_gas: 100000000000\n    max_priority_fee_per_gas: 1000000000\n\
         \x20   fee_token: \"0x20c0000000000000000000000000000000000000\"\n\
         \x20   call:\n      abi: Mutator\n      function: exec\n      args: []\n\
         sequences:\n  mutate:\n    steps:\n"
    );
    for (i, m) in muts.iter().enumerate() {
        out.push_str(&format!(
            "      - {{ name: m{i}, template: exec, with: {{ call: {{ to: \"{CONTRACT}\", args: [{}, \"{}\", \"{}\"] }} }} }}\n",
            m.op, m.key, m.val
        ));
    }
    out.push_str("mix:\n  - { sequence: mutate, weight: 1 }\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn slots_are_deterministic_and_distinct() {
        for seed in 0..32 {
            let s = slots(seed);
            assert_eq!(s, slots(seed));
            let set: BTreeSet<_> = s.iter().copied().collect();
            assert_eq!(set.len(), s.len(), "distinct");
            assert_eq!(s.len(), POOL_SIZE);
            assert!(s.windows(2).all(|w| w[0] < w[1]), "sorted");
        }
        assert_ne!(slots(1), slots(2));
    }

    #[test]
    fn mutations_are_deterministic_per_generation() {
        let a = mutations(7, 0, 200);
        assert_eq!(a, mutations(7, 0, 200));
        assert_ne!(a, mutations(7, 1, 200));
        assert_ne!(a, mutations(8, 0, 200));
        assert_eq!(a.len(), 200);
        // A prefix of a longer plan is not required, but the first forced
        // prologue mutations are stable across lengths.
        let short = mutations(7, 0, 40);
        assert_eq!(&a[..short.len().min(10)], &short[..short.len().min(10)]);
    }

    #[test]
    fn every_mutation_kind_is_emitted() {
        // Over a modest run, every kind appears (forced prologue + bulk run +
        // weighted mix).
        let muts = mutations(3, 0, 300);
        let kinds: BTreeSet<MutationKind> = muts.iter().map(|m| m.kind).collect();
        for k in MutationKind::ALL {
            assert!(kinds.contains(&k), "missing {:?}", k);
        }
        // And across several seeds.
        for seed in 0..8 {
            let kinds: BTreeSet<MutationKind> =
                mutations(seed, 0, 400).iter().map(|m| m.kind).collect();
            for k in MutationKind::ALL {
                assert!(kinds.contains(&k), "seed {seed} missing {:?}", k);
            }
        }
    }

    #[test]
    fn ops_are_in_range_and_keys_consistent() {
        let pool: BTreeSet<u64> = slots(5).into_iter().collect();
        for m in mutations(5, 0, 500) {
            assert!(m.op <= op::TRANSFER);
            match m.kind {
                // Contract-storage writers use a pool slot (or a small bulk key).
                MutationKind::Set
                | MutationKind::Update
                | MutationKind::ClearToZero
                | MutationKind::MaxEdge
                | MutationKind::Create
                | MutationKind::Create2Reuse
                | MutationKind::Destroy => {
                    let k = m.key.to::<u64>();
                    assert!(pool.contains(&k), "key {k} not in pool for {:?}", m.kind);
                }
                MutationKind::BulkWrite | MutationKind::BulkClear => {
                    assert!(m.key < U256::from(0x800u64));
                }
                MutationKind::CreateDie => assert_eq!(m.op, op::CREATE_DIE),
                MutationKind::EmptyTouch => assert_eq!(m.op, op::EMPTY_TOUCH),
                MutationKind::Transfer => assert_eq!(m.op, op::TRANSFER),
            }
            // Clears (including bulk clears) write zero.
            if matches!(m.kind, MutationKind::ClearToZero | MutationKind::BulkClear) {
                assert_eq!(m.val, U256::ZERO);
            }
        }
    }

    #[test]
    fn written_slots_cover_every_storage_write_across_generations() {
        // Every slot any storage-writing mutation touches, over several seeds and
        // generations, must be in the candidate set the valid-root oracle reads.
        // CREATE_DIE / EMPTY_TOUCH / TRANSFER write no Mutator storage.
        for seed in 0..16 {
            let candidate_vec = written_slots(seed);
            assert!(
                candidate_vec.windows(2).all(|w| w[0] < w[1]),
                "sorted distinct"
            );
            let candidate: BTreeSet<u64> = candidate_vec.into_iter().collect();
            for generation in 0..6 {
                for m in mutations(seed, generation, 400) {
                    let writes_storage = matches!(
                        m.kind,
                        MutationKind::Set
                            | MutationKind::Update
                            | MutationKind::ClearToZero
                            | MutationKind::MaxEdge
                            | MutationKind::Create
                            | MutationKind::Create2Reuse
                            | MutationKind::Destroy
                            | MutationKind::BulkWrite
                            | MutationKind::BulkClear
                    );
                    if writes_storage {
                        let k = m.key.to::<u64>();
                        assert!(
                            candidate.contains(&k),
                            "seed {seed} gen {generation}: slot {k} ({:?}) not in written_slots",
                            m.kind
                        );
                    }
                }
            }
        }
        // The pool is a subset of the complete candidate set.
        let candidate: BTreeSet<u64> = written_slots(7).into_iter().collect();
        for s in slots(7) {
            assert!(candidate.contains(&s));
        }
    }

    #[test]
    fn spec_is_deterministic_and_well_formed() {
        let a = spec(4, 0, 50);
        assert_eq!(a, spec(4, 0, 50));
        assert_ne!(a, spec(4, 1, 50));
        assert_eq!(a.matches("template: exec").count(), 50);
        assert!(a.contains("sequences:\n  mutate:"));
        assert!(a.contains(CONTRACT));
    }
}
