# Tempo DST: finding reth bugs under Bedrock

Run one Tempo dev node (reth-based) inside a Bedrock guest and perturb it
deterministically. One boot is shared by every seed; each seed then runs as its
own branch from a warm checkpoint, with different perturbations:

- **Thread schedules**: the node runs under `thread-fuzz` (sched_ext
  concurrency-fuzz), so the schedule is drawn from Bedrock's getrandom stream.
  A seccomp filter keeps every node thread in SCHED_EXT: reth's
  `deprioritize_background_threads` asks for SCHED_IDLE and gets EPERM, since a
  thread that left sched_ext would run in the fair class ahead of every other
  node thread and could starve them all. Set `THREAD_FUZZ_SECCOMP=0` in the
  node's environment to turn the filter off for debugging.
- **Crash/restart**: `tempo-dst nemesis` SIGKILLs and restarts the node at
  seed-derived times. With `storage_faults=true` it also crashes the *machine*
  (un-synced writes are lost) and tears writes; see
  [Storage faults](#storage-faults-storage_faultstrue). With `process_faults=true`
  it also pauses, CPU-throttles and gracefully stops the node; see
  [Process faults](#process-faults-process_faultstrue).
- **Load**: the selected txgen revision sends pathUSD transfers (fixed seed 99).
- **Forced preemption** (swarm): each seed draws a preemption period (off,
  200k, 2M or 20M guest instructions) from a host-side PRNG of the seed;
  the driver applies it to the branch (`Branch::set_preempt`) for every load,
  with or without `reference=true`. `--no-preempt` turns it off and never calls
  the ioctl. A `bedrock.ko` without `SET_PREEMPT_CONFIG` is rejected before
  boot when any seed would use it.

Every run is a timeline (the World plus the tape of inputs served to it), so a
failure replays exactly from its tape: `bedrock-dst replay <out>/seed-N` (see
[Timelines and replay](#timelines-and-replay)). Each seed's swarm record
(`{"preempt": {"period", "seed"}, "load", "reference", "nemesis"}`, plus
`"storage_faults": true` and `"process_faults": true` when on) is under
`"swarm"` in its `config.json`, `verdict.json` and `summary.json` entry, so
failures can be grouped by feature (`regressions/hunt.sh` prints that table).

## Running from Bedrock

This directory is the workload bundle consumed by
`tempoxyz/bedrock`'s `workloads/dst/run.sh`. `bedrock.yaml` selects the
preparation hooks, generated Compose file, host planner and guest controller.
Set `BEDROCK_ROOT` to a Bedrock checkout to use this directory's thin `run.sh`
wrapper, or invoke the generic runner directly:

```sh
RUN_DIR=/tmp/tempo-dst-inputs "$BEDROCK_ROOT/workloads/dst/run.sh" \
  --harness "$PWD/contrib/bedrock-dst" --seeds 20 --out dst-out
```

The manifest defaults to two consensus validators. For a dev node, override
`validators=1` and `consensus=false`. For zones, use those same overrides with
`load=zones`; zones supplies its own four-validator topology.
`--prepare-only` creates frozen inputs; `--prepared` runs them without building.
Supply workload settings during preparation, not again with `--prepared`.
Node and txgen revisions remain preparation arguments, for example
`--prepare-args '["--node-revisions","origin/main","--txgen-rev","origin/main"]'`
on the generic runner. The wrapper also accepts the original revision flags.

## Components

| Piece | Where | Role |
|---|---|---|
| `bedrock-dst` | `tempoxyz/bedrock:crates/bedrock-dst` | Workload-agnostic host driver: boot, warm checkpoint, branch per seed, collect, verdict, replay ([contract](#workload-contract)) |
| `tempo-dst` | `bin/tempo-dst` | The workload: in-guest warmup, nemesis and oracles (in a controller container), and the host-side planner |
| `workload-monitor` | `tempoxyz/bedrock:guest/workload-monitor` | Forwards assertions and excuses container SIGKILL deaths that the nemesis logged (kills, and graceful stops' SIGKILL fallback, which the stopper reports itself) |
| compose / run | `contrib/bedrock-dst` | Node config, variants, campaign entry point |

Guest contract: each writer appends serialized `bedrock_assertions::Assertion`
records to its own `/bedrock/assertions/<writer>.jsonl` file. Records include a
`timestamp_unix_nano` and a message of `<signature>: <detail>`. Guest init
forwards complete lines to the serial log; at the end of each seed, `finalize`
merges all files by timestamp into `/bedrock/out/assertions.jsonl`, the host's
`assertions.jsonl` and verdict. Control events go to `/bedrock/events.jsonl`
(`{source, kind, container, guest_time_ns, detail}`). The `start` hook
installs its config as `/bedrock/in/config.json`.

## Workload contract

`bedrock-dst` runs workloads through the typed hooks documented in
[`bedrock-dst-contract`](https://github.com/tempoxyz/bedrock/blob/main/crates/bedrock-dst-contract/src/lib.rs).
The Tempo implementation is in `bin/tempo-dst`; configs and scenarios
retain the workload's JSON payloads for replay.

Beyond them, `bedrock-dst explore` uses the optional `progress` guest hook
(the run's new assertion records since the previous call, in
`/bedrock/out/progress.jsonl`), and `minimize` the plan's typed
`host_decisions` (`{id, kind, at_secs, detail}`: each scheduled fault, kind
as the canonical `Fault` names it) with `PlanRequest.drop` (recorded
decisions without those faults, and without the load generation a dropped
restart would have started).


`bedrock-dst campaign` takes `--workload-cmd` (default `tempo-dst`),
`--workload-planner` (default: the command on PATH; replay, branch and
moments take an override), `--workload-arg key=value` (repeatable) and
`--workload-config file.json`; the parsed arguments are recorded as
`workload_args` in campaign.json and world.json. Here the planner is
the same `tempo-dst` binary packaged in the guest controller image;
`run.sh` passes it. Recorded arguments in any earlier format (before the
contract, or with the removed `kernel_rng`/`no_tape`) are refused.

`TempoArgs` (defaults in parentheses): `load`
(`transfers`|`trie`|`tip20`|`chain`|`statemix`|`zones`),
`txgen_count` (20000), `txgen_tps` (100), `trie_tps` (5), `tip20_tps` (50),
`chain_tps` (10), `statemix_tps` (10), `verify_state_root` (false; see
"Generic valid-state-root invariant"; auto-on with `load=statemix`),
`reference` (false), `no_nemesis` (false), `max_kills` (3),
`min_gap_secs` (30), `liveness_secs` (60), `workload_seed` (99), `decisions`
(`explicit`, the only mode: the planner draws the fault plan and
per-generation seeds; `guest` is refused), `storage_faults`
(false), `storage_fault_kinds` (all; a list or `crash,torn`), `process_faults`
(false), `process_fault_kinds` (all; a list or `pause,stop`),
`finalize_stop_timeout_secs` (120), `zones_witness_faults` (false; see "Witness faults"), `zones_l1_faults` (false; see "Byzantine L1"), `zones_policy` (false; see "TIP-403 policy"), `zone_sequencers` (1; 3 with
`load=zones`), `network_faults` (false), `network_fault_kinds` (the load's),
`max_network_faults` (3), `network_min_gap_secs` (30), `validators` (1),
`consensus` (false), `follower` (false; alias `certified_follower`; see
[Certified follower](#certified-follower-followertrue)); see
[Network nemesis](#network-nemesis-network_faultstrue) and
[Multi-sequencer zones](#multi-sequencer-zones-zone_sequencers3).
Fault fields are left out of configs, scenarios and swarm records while off.
`bin/tempo-dst/testdata/planner-golden.json`, generated by the driver
before the contract, pins the planner's configs, decisions and required
coverage byte for byte (cases of the removed `decisions=guest` and
`spec_seeds_from_getrandom` modes keep only their replay and re-draw
checks); `planner-golden-faults.json` pins the fault modes the
same way (snapshots of the planner, regenerated only for new modes:
`TEMPO_DST_REGENERATE_GOLDEN=1 cargo test regenerate_fault_golden --
--ignored`).

## Oracles

| Signature | Checks |
|---|---|
| `E1/panic`, `E1/*-mismatch`, `E1/trie-diff-*`, `E1/persistence-*`, `E1/engine-fatal`, `E1/bad-block`, ... | Node log line matching a reth failure message (pinned reth `42fa3c5`; see `LOG_PATTERNS` in `bin/tempo-dst/src/oracle.rs`) |
| `E1/error-log/<target>` | Any ERROR-level node log line. Noisy by design; triage by target |
| `E1/trie-diff-*` | `--engine.state-root-task-compare-updates`: sparse-trie task vs. regular state-root updates differ |
| `E2/head-stalled` | Head did not advance for `liveness_secs` while the node was up and not paused or CPU-throttled by the nemesis (the clock restarts when such a window ends, so a node that never recovers still fails) |
| `E3/finalized-block-changed`, `E3/head-below-finalized` | The block the node reported finalized (`eth_getBlockByNumber("finalized")`) before a kill keeps its hash after the restart, and the head gets back to it. Unfinalized blocks may legitimately be rebuilt: reth unwinds to its persisted state-trie frontier, which trails the `Saved range of blocks` frontier (observed: saved 318, unwound to 308, finalized 269) |
| `E5/storage-root-mismatch`, `E5/{multiproof,untargeted}-storage-root-mismatch` | `load=trie`: at every checked block, a RawStorage contract's `storageHash` (`eth_getProof`, `eth_getProof` without targets, `eth_getMultiProof`) equals a root rebuilt from scratch from its slot values (`eth_getStorageAt`) with alloy-trie's `HashBuilder`, not the node's incremental trie |
| `E6/account-proof-invalid`, `E6/storage-proof-invalid`, `E6/proof-value-mismatch` (and `multiproof-`/`untargeted-` forms) | `load=trie`: each proof response verifies (`alloy_trie::proof::verify_proof`): the account proof against the header `stateRoot`, each slot's proof against `storageHash`, and the proven values equal `eth_getStorageAt` |
| `E8/tip20-supply-changed`, `E8/tip20-balances-not-conserved`, `E8/tip20-balance-exceeds-supply` | `load=tip20`: at every checked block, the token's `totalSupply` is the minted supply, the holders' `balanceOf` sum to it, and none exceeds it (all reads `eth_call` at that block's hash, EIP-1898) |
| `E8/tip20-transfers-unexplained` | `load=tip20`: a block's balances are exactly its parent's plus the token's `Transfer` logs in the block's receipts (`eth_getBlockReceipts`; reverted transfers must leave none): catches partially applied blocks and reads that mix two versions of the state |
| `E8/tip20-snapshot-changed` | `load=tip20`: pinned blocks' balances, re-read every tick while the block stays canonical (after more blocks, persistence of the block, node restarts), are unchanged |
| `E9/chain-link-broken` | `load=chain`: in canonical receipt order, each ChainOfBlocks `Appended` log has the next index and link `keccak(prev, payload, index)`: the node never executed an append against the wrong pre-state |
| `E9/chain-state-mismatch` | `load=chain`: at every checked block B, the stored `length`, `head` and `links[length-1]` (`eth_getStorageAt` at B) equal the chain rebuilt from the receipts of blocks `..=B`; one swept old link per tick at the head too |
| `E9/chain-shrunk` | `load=chain`: the stored length never decreases between checked canonical blocks |
| `E9/chain-not-prefix` | `load=chain`: the chain stored at an older block (depths 2-48 and 49-250, like E5) is a prefix of the chain stored at the head; state against state, no receipts |
| `E9/chain-entry-lost` | `load=chain`: after a restart, the head still holds the chain stored at the block finalized before the kill |
| `E9/chain-history-changed` | `load=chain`: re-reading a pinned finalized block's stored chain (one pin per kill, re-read round-robin) gives the value read when it was pinned, across persistence cycles and restarts |
| `E7/reference-<E1 pattern>`, `E7/reference-rejected` | `reference=true`: the reference node logs one of E1's patterns (e.g. `E7/reference-bad-block`, `E7/reference-state-root-mismatch`) or rejects a block (`Invalid block error on new payload`, pipeline validation/execution error) the primary produced |
| `E7/reference-stalled` | `reference=true`: the reference's head stays more than 32 blocks behind the primary's for `liveness_secs` while the primary is up and not paused (clock restarts at each primary restart and resume) |
| `E7/block-hash-differs`, `E7/state-root-differs` | `reference=true`: at the highest block both nodes have, they disagree for `liveness_secs` (a crash may rebuild unfinalized blocks; the reference must reorg onto them), named by whether the state roots differ too; or the same header hash comes with different `stateRoot`s |
| `E7/proof-differs` | `reference=true load=trie`: on blocks both nodes agree on (new ones, plus E5/E6's depth sweep; contracts as in E5/E6), RawStorage's `eth_getProof` `storageHash` and proven values, `eth_getMultiProof` `storageHash`, and `eth_getStorageAt` values are equal on both |
| `E7/reference-graceful-stop`, `E7/reference-repair-trie` | `reference=true`: the reference stops cleanly at the end of the run (as `E4/graceful-stop`) and `tempo db repair-trie --dry-run` finds no trie inconsistencies in its datadir |
| `E11/tx-lookup-missing`, `E11/tx-lookup-wrong-block`, `E11/receipt-missing`, `E11/receipt-wrong-block` | `storage_faults=true`: after a crash and cold reopen, every transaction of a recorded block that is still canonical with its recorded hash resolves to it (`eth_getTransactionByHash`, `eth_getTransactionReceipt`): a kept block with missing index entries is a hole |
| `E11/block-body-changed` | `storage_faults=true`: a kept block (same hash) serves the transaction list recorded before the crash |
| `E11/history-account-mismatch`, `E11/history-storage-mismatch`, `E11/history-proof-invalid`, `E11/history-proof-mismatch`, `E11/history-read-error` | `storage_faults=true`: historical reads recorded before the crash at a kept block (a sender's nonce via `eth_getTransactionCount`, its pathUSD `balanceOf` via `eth_call` at the block hash, its `eth_getProof` against the header state root) read the same after it, and do not error |
| `E11/tx-lookup-stale` | `storage_faults=true`: a transaction of a block lost with the un-synced suffix (and rebuilt) resolves nowhere or to a canonical block, never to the replaced one |
| `H/lazyfs-unavailable`, `H/lazyfs-crash-failed`, `H/node-inspect-failed` | Harness integrity: a LazyFS control command (crash, arming a torn write, mount) failed or timed out, writing the kept blocks of a crash to the backing directory failed, or `podman inspect` could not tell whether the node was still running in a torn-write window. Not node bugs |
| `E12/zones-outbox-insolvent` | `load=zones`: at every L1 block `B`, paired with the newest zone block `Z` that imported only L1 blocks `<= B`, the portal's pathUSD escrow (`balanceOf(portal)` at `B`) covers the zone's `totalSupply` at `Z` plus deposits made by `B` that `Z` has not processed, withdrawals requested by `Z` and not yet paid, re-minted or refunded by `B`, and parked refunds (zones' `zone-portal-backing` accounting). The pairing makes the snapshot consistent: `Z` only processed deposits on L1 by `B`, and every withdrawal paid by `B` was settled from a zone block `<= Z` |
| `E12/zones-withdrawal-unbacked`, `E12/zones-deposit-unbacked`, `E12/zones-refund-overclaimed` | `load=zones`: at a consistent `(Z, B)` pair, L1 paid out more than the outbox burned, the zone processed deposits the portal never recorded, or more refunds were claimed than parked |
| `E12/zones-double-withdrawal`, `E12/zones-withdrawal-unrequested`, `E12/zones-withdrawal-mismatch`, `E12/zones-withdrawal-unproven` | `load=zones`: each L1 `WithdrawalProcessed` matches exactly one outbox `WithdrawalRequested` by `senderTag = keccak256(sender, txHash, fallbackNonce)`, with the same recipient, token and amount, requested in a zone block that a batch submitted by then had settled; no tag is paid twice |
| `E12/zones-batch-index-gap`, `E12/zones-batch-replayed`, `E12/zones-portal-state-mismatch` | `load=zones`: `BatchSubmitted` indices go 1, 2, 3, ... in canonical L1 order, and the portal's `blockHash()`/`withdrawalBatchIndex()` at the submitting block are the last batch's |
| `E12/zones-batch-unknown-block`, `E12/zones-batch-commitment-mismatch`, `E12/zones-batch-not-advancing`, `E12/zones-settled-block-lost` | `load=zones`: each batch's `nextBlockHash` is a canonical zone block once the zone has imported the submitting L1 block; that block's outbox `lastBatch()` (withdrawal queue hash, index) and inbox `processedDepositNumber()` are what the sequencer's signed batch committed to, and it imported an L1 block before the submission; settled blocks advance and stay canonical (e.g. across zone restarts) |
| `E12/zones-invalid-batch-submitted` | `load=zones`: a batch the portal settled, whose own witness the prover's honest SPF replay (`tempo-zone-prover-utils generate-input --block <nextBlockHash>`) rejects: it should never have been submittable |
| `E12/zones-invalid-state-advanced` | `load=zones`: the honest SPF replay of a settled batch produces another `nextBlockHash` than the portal recorded: the L1 advanced to a root an honest replay disagrees with. Batches settle in `NoProof` mode, so the L1 itself never rejects; this replay is the check |
| `E12/zones-proof-replay-failed` | `load=zones`: the prover and the oracle saw different committed hashes for one batch index (a harness inconsistency) |
| `E12/zones-invalid-witness-accepted` | `zones_witness_faults=true`: the SPF replayed a mutated witness (see "Witness faults") to the batch's committed hash; a prover used as a settlement gate would let an invalid batch through |
| `E12/zones-trusted-bad-l1-accepted` | `zones_l1_faults=true`: the prover built a witness over an L1 that lied about its state (see "Byzantine L1") and still replayed the committed hash; the zone would advance or settle state from falsified L1 data |
| `E12/zones-policy-not-enforced` | `zones_policy=true`: a zone TIP-20 transfer the active TIP-403 policy forbids (recipient blacklisted) landed anyway |
| `E12/zones-transfer-unconserved` | `zones_policy=true`: an allowed transfer did not credit the recipient exactly the sent amount, or changed `totalSupply` (a transfer mints/burns nothing), or a rejected transfer moved funds |
| `E12/zones-batch-stalled`, `E12/zones-withdrawal-stuck`, `E12/zones-deposit-stuck`, `E12/zones-batch-unproven` | `load=zones` liveness, each clock restarted at every nemesis restart and paused while the L1, zone or prover is down: a batch lands every `liveness_secs`; a settled withdrawal is paid within `liveness_secs`; a deposit the zone imported is processed within `liveness_secs`; the prover replays each batch within 3 x `liveness_secs` |
| `E12/zone-<E1 pattern>` | `load=zones`: the zone node logs one of E1's named patterns (e.g. `E12/zone-panic`); its ERROR lines alone are not findings (it logs L1 connection errors while the L1 is down) |
| `E12/zones-cluster-fork` | `zone_sequencers=3`: two sequencers hold different blocks at one height, at once at or below the portal's settled height, else for 20 s |
| `E12/zones-cluster-leader-mismatch`, `E12/zones-cluster-double-leader` | `zone_sequencers=3`: a zone block's beneficiary is not the leader of an epoch active over the L1 anchors it applied (portal `LeaderUpdated` history); two nodes report the leader role for the same locally applied epoch in consecutive samples |
| `E12/zones-cluster-anchor-regressed`, `E12/zones-cluster-anchor-mismatch` | `zone_sequencers=3`: a node's `TempoBlockFinalized` L1 numbers go backwards, or a finalized hash is not the L1's canonical block (TempoState links headers by parent hash, so canonical forward jumps skip nothing) |
| `E12/zones-cluster-production-stalled` | `zone_sequencers=3`: the cluster's height does not advance for `liveness_secs` while no fault or kill stops the leader (clock restarted at each heal/restart) |
| `E12/zones-cluster-not-caught-up` | `network_faults=true`: within `liveness_secs` of a fault healing, a node it hit has not reached the cluster height (and, after an L1 cut, the L1 head) at the heal |
| `E12/zones-cluster-handoff-incomplete` | `network_faults=true`: within `liveness_secs` of a handoff fault healing, the portal does not name the target, or it has not built a block at/after its activation |
| `E12/zones-cluster-quorum-settlement-stalled`, `E12/zones-cluster-settlement-not-resumed` | `network_faults=true`: E12's batch liveness under a fault that leaves a 2-of-3 quorum with the leader (not excused), or after a heal (clock restarted at the heal) |
| `E12/zones-cluster-outage-deposit-stuck`, `E12/zones-cluster-outage-withdrawal-stuck`, `E12/zones-deposit-processed-twice` | E12's deposit/withdrawal liveness for ones made during a fault (judged from the heal); a zone `DepositProcessed` deposit hash processed twice |
| `D/network-fault-failed` | The network nemesis could not apply or heal a planned fault (iptables, ss, tc or `zone_setLeader` error) |
| `E12/txgen-portal-underbacked` | `load=zones`: txgen's zone-backing campaign reports its own solvency audit failing (`[zone-property] FAIL ... underbacked`) |
| `E4/graceful-stop`, `E4/re-execute` | At the end of the run, the node stops cleanly, and `tempo re-execute` over `[1, head]` from its datadir agrees |
| `E4/graceful-stop`, `E4/repair-trie`, `E4/re-execute` | At the end of the run, the node stops cleanly within `finalize_stop_timeout_secs` (120): `podman stop` succeeds without falling back to SIGKILL (podman still exits 0 then; the container exits 137) or using up the timeout; `tempo db repair-trie --dry-run` finds no trie inconsistencies in its datadir; and `tempo re-execute` over `[1, head]` from its datadir agrees |
| `E4/stop-timeout` | `process_faults=true`: a mid-run graceful stop (`podman stop -t <10-30 s>`) ended the same way: the node did not shut down cleanly within the drawn timeout |
| `H/pause-failed`, `H/throttle-failed` | Harness integrity: `podman pause`/`unpause`, or the node's cgroup files, did not work. Not node bugs |
| `H/storage-layer-enoent` | `storage=lazyfs`: a commonware blob resize/sync on an open file failed with ENOENT, which a kernel file system cannot return for `ftruncate`/`fsync` on a descriptor: the storage layer, not the node. Its known cause, an uninitialized return code in LazyFS's `lfs_truncate` (bedrock#43), is fixed in `nix/lazyfs/bedrock.patch`; the check stays as a guard |
| `H/storage-crash-failed` | `storage=lazyfs`: a planned machine crash could not be carried out (a harness failure: the run did not test what it planned) |
| `container <name> exit code is zero` | workload-monitor: no unexplained container death |
| `D/guest-exited` | The guest VM stopped mid-run (kernel panic, shutdown) |
| `S/multi-contract-block` | `trie_contracts=auto`: a block changed two or more contracts' storage roots (vs. its parent; untargeted `eth_getProof`) |
| `S/trie-all-contracts-checked` | `trie_contracts=auto` with two or more contracts: a tick's newest block was checked for every contract (per-contract check counts go to `oracle.log` every 30 ticks) |
| `S/kill`, `S/recovered`, `S/rewound-unfinalized`, `S/re-executed`, `S/load-included`, `S/trie-checked`, `S/trie-all-slots-live`, `S/chain-appended`, `S/chain-survived-restart`, `S/chain-history-reread` | Coverage (Sometimes): the fault, crash-recovery unwind, recovery, and load paths actually ran |
| `S/tip20-checked`, `S/tip20-transfers-in-block`, `S/tip20-pinned-read-survived-persistence`, `S/tip20-pinned-read-survived-restart` | Coverage for E8: a block passed; a block with 2+ transfers passed; a block pinned before it was persisted (newer than the last `Saved range of blocks`) read the same after a save covered it; a block pinned before a node restart read the same after it |
| `S/storage-discarded`, `S/storage-fault-surfaced`, `S/durable-history-checked`, `S/durable-block-rebuilt`, `S/durable-sweep-complete` | Coverage with `storage_faults=true`: a machine crash discarded un-synced data (or a torn write fired); the node reacted (E1 line) inside a torn-write window; E11 re-checked a block that kept its hash, saw one that was rebuilt, and finished a post-crash sweep |
| `S/reference-compared`, `S/reference-synced`, `S/reference-followed-restart` | Coverage with `reference=true`: a common block was compared, the reference reached the primary's head, and after a primary restart (or resume) it followed past the pre-kill head |
| `S/paused-recovered`, `S/throttled-recovered`, `S/graceful-stop`, `S/graceful-restart` | Coverage with `process_faults=true`: the head passed its pre-pause head after a resume, passed its head at a throttle's end, a graceful stop ran, and the node got past its pre-stop head after the restart |
| `S/zones-witness-mutated`, `S/zones-mutated-witness-rejected` | Coverage with `zones_witness_faults=true`: a settled batch's witness was mutated and replayed, and the SPF rejected (or diverged from) it; `-rejected` is emitted once per mutation kind |
| `S/zones-l1-response-faulted`, `S/zones-l1-fault-detected` | Coverage with `zones_l1_faults=true`: the byzantine L1 proxy tampered a response, and the prover rejected the witness built on it; `-detected` is emitted once per fault kind |
| `S/zones-policy-changed`, `S/zones-transfer-allowed`, `S/zones-transfer-rejected` | Coverage with `zones_policy=true`: pathUSD's TIP-403 policy was changed on L1, an allowed zone transfer landed and conserved, and a forbidden one did not land |
| `S/zones-batch-submitted`, `S/zones-batch-proven`, `S/zones-deposit-credited`, `S/zones-withdrawal-finalized`, `S/zones-solvency-checked`, `S/zones-batch-after-restart`, `S/zones-batch-with-withdrawals`, `S/txgen-deposit-processed`, `S/txgen-withdrawal-paid` | Coverage for E12: a batch landed during the run, the prover replayed one, a deposit was credited on the zone, a withdrawal was paid on L1 and matched its request, solvency passed with non-zero zone supply, a batch landed after a nemesis restart, a batch carried withdrawals; and txgen's own lifecycle reached a processed deposit and a paid withdrawal |
| `E13/finalized-conflict`, `E13/finalized-not-prefix`, `E13/finalized-reverted` | `validators=4`: every validator's finalized blocks (`eth_getBlockByNumber("finalized")` and each block below it) have one hash per height across validators, each links to the block finalized below it, and none changes on the validator that served it (height going back without a restart, or another hash/finalization digest after a restart); a finalization's digest is the validator's own block at that height |
| `E13/validator-state-root-differs`, `E13/validator-proof-differs` | `validators>=2` with `validator_engine_diff=true`: at every block the validators AGREE on (same finalized/canonical hash — E13 above), their EXECUTION must match too. Across the agreeing validators, the header `stateRoot` is the same, and on the same deterministic `(address, slots)` sample E5/E6 use (`Config::tries()`) each validator's `eth_getProof` verifies against its own state root (`trie_ref::verify`) and proves the same storage hash and values as its peers. A divergence means one engine's state DB diverged from the header it finalized (the #16-class detector). Running the validators on different engine profiles (`EngineProfile`: sparse-trie `Optimized` vs the `Simple` sequential engine, plus `Compare`/`Race`/`NoPrune`) makes this the sparse-trie-vs-simple execution differential the old E7 dev-node reference provided, on real consensus nodes with no `--follow` |
| `E14/finalization-lost`, `E14/finalized-block-lost`, `E14/finalized-height-regressed`, `E14/certificate-invalid` | `validators=4`: after a restart, a validator still serves the finalizations (`consensus_getFinalization`) and finalized blocks it served before the crash (its own last reads; never compared with peers, since a node lacks certificates for heights it finalized while catching up); its `finalized` height never goes back within one process; certificates for one height are byte-identical across validators (threshold BLS: unique per message) |
| `E15/reopen-failed`, `E15/consensus-storage-error` | `validators=4`: a restarted validator answers RPC within the catch-up budget; no ERROR line about journal/archive/freezer/metadata/checksum/replay while it recovers |
| `E16/stalled`, `E16/node-stuck`, `E16/mesh-timeout` | `validators=4`: the cluster's finalized height advances within `stall_secs` while at most f=1 validator is down (the clock restarts when the cluster gets back within budget); an up validator gets within 5 blocks of the cluster within `catch_up_secs`; the full mesh re-forms within `mesh_secs` of the last restart. Budgets scale with `cooldown` (1s: 60/90/60 s; default: 180/200/200 s) |
| `E17/honest-peer-blocked` | `validators=4`: no validator blocks a peer (all are honest): a commonware `block!` WARN, a `consensus_network_tracker_directory_blocked{peer}` series, or rising `consensus_network_listener_handshakes_blocked_total` |
| `E18/dkg-failed` | `validators=4`: `consensus_engine_dkg_manager_ceremony_failures_total` never rises |
| `S/dkg-duplicate-ack-rejected` | `validators=4`: a DKG dealer rejected an ACK it already held (`failed to process ACK, already received an ack`), logged by Tempo at ERROR. A player re-delivers an ACK after a restart or a healed partition; the dealer rejects it before storing anything (`Dealer::receive_ack`), so the ceremony is unaffected. Coverage, not an E1 failure; any other DKG error is still E1 |
| `S/mesh-formed`, `S/epoch-transition`, `S/nullification`, `S/leader-skip`, `S/resolver-fetch`, `S/archive-sparse`, `S/validator-caught-up`, `S/finalized-during-fault`, `S/full-restart-recovered` | Coverage with `validators=4`: full mesh; an epoch changed; a view nullified; a leader skipped (timeout reason `LeaderTimeout`/`MissingProposal`/`LeaderNullify`); a resolver fetch succeeded; a restarted validator lacked a certificate for a height it finalized while catching up; a restarted validator reached the cluster's pre-restart height; the cluster finalized with a validator down; it finalized past its height after every validator was down |
| `S/validator-engine-diff-checked` | Coverage with `validator_engine_diff=true` (required): the cross-validator execution differential compared at least one block across validators running at least two distinct engine profiles |
| `E6/state-root-recomputed` | `verify_state_root=true` (auto-on with `load=statemix`): for every new canonical block, on every node (the dev node and each validator), the block's touched set — its tx senders/recipients, receipt-created contracts, the generic workload's Mutator contract, and the known finalize-time system writers (pathUSD; extend `SYSTEM_WRITERS`) — is read by block hash (EIP-1898). The workload contract's storage root, rebuilt from scratch from its slot values (`trie_ref::storage_root`, independent of the node's trie), equals the node's `storageHash` (`storage-root-mismatch`), and every touched account's `eth_getProof` verifies against the header `stateRoot` (`account-proof-invalid`/`storage-proof-invalid`). Catches any path that produces a block whose state root != the true post-execution state (the #16/#62/reth#27679 class) even on a lone self-accepting producer, since the oracle's ground truth is the recompute, not the node's trie |
| `E13/same-height-state-root-differs` | `verify_state_root=true` with `validators>=2` (Strand C): at a height every validator has settled on (lowest head minus a small lag), the validators' canonical blocks must share one state root. A producer that self-accepts a block with a wrong root diverges from its honest peers at that height, so this reports it promptly rather than only as an E16 liveness stall. Reuses the engine-diff per-validator `ExecView`; distinct from `E13/validator-state-root-differs`, which compares only validators that already agree on the block hash |
| `S/state-root-recomputed-checked`, `S/state-root-verified`, `S/same-height-root-checked` | Coverage with `verify_state_root` (required): a storage root was rebuilt from scratch and matched (with `load=statemix`/`trie`); a block's touched-set proofs verified against the header state root; and, with the cluster, the same-height probe compared validators |
| `E/follower-catch-up-stalled`, `E/follower-canonical-diverged`, `E/follower-persistence-stalled` | `follower=true` (and `load=zones`): the certified L1 follower, driven behind by an offline-window fault and rejoining, must resolve a `SYNCING` forkchoice to execution, canonicalization and advancing persistence within `liveness_secs` — the tempo#8263 class ("canonicalize follower catch-up after syncing forkchoice"). `-catch-up-stalled`: its head never caught back up to the validators' finalized height; `-canonical-diverged`: head and finality matched but its canonical hash differs from the validators'; `-persistence-stalled`: head/finality caught up but persistence never passed the previous incarnation's watermark (the exact stall the fix prevents). Trigger-agnostic: a snapshot restore, a kill-and-hold, a pause or a healed partition all arm the same check |
| `S/follower-snapshot-restored`, `S/follower-syncing-observed`, `S/follower-executed-after-syncing`, `S/follower-caught-up` | Coverage with `follower=true` (the first, second and fourth required): the pre-warm follower datadir was restored (the deepest gap), a `SYNCING` forkchoice was observed on rejoin, a block executed after it, and the follower caught back up to the validators' finalized chain with persistence advancing |
| `C/missing/<signature>` | Required coverage never satisfied: `S/load-included` always, plus `S/trie-checked` with `load=trie` (and `S/multi-contract-block` for `trie_contracts=auto` seeds that draw two or more contracts); with `load=tip20` all four `S/tip20-*` above; with `load=chain` `S/chain-appended` and `S/chain-survived-restart` (the `-survived-restart` signatures only when every seed's nemesis plan has a kill); with `load=zones` `S/zones-batch-submitted`, `S/zones-batch-proven`, `S/zones-deposit-credited`, `S/zones-withdrawal-finalized` and `S/zones-solvency-checked`, plus `S/zones-batch-after-restart` when every plan has a kill, plus `S/zones-witness-mutated` and `S/zones-mutated-witness-rejected` with `zones_witness_faults=true`, plus `S/zones-l1-response-faulted` and `S/zones-l1-fault-detected` with `zones_l1_faults=true`, plus `S/zones-policy-changed`, `S/zones-transfer-allowed` and `S/zones-transfer-rejected` with `zones_policy=true`; plus `S/reference-compared` and `S/reference-synced` with `reference=true`; with `zone_sequencers=3` `S/cluster-converged` and `S/cluster-blocks-checked`; with an explicit network plan, per fault `S/net-fault-<family>` (plus `S/net-connections-reset` / `S/net-netem-applied` for reset / netem steps) and, in the zone cluster, its family's effect (`zones_cluster::required_effects`: `S/net-partition-healed` for partitions; `S/net-l1-cut-restored` for L1 cuts, plus `S/cluster-l1-backfilled`, `S/net-leader-isolated` and `S/net-quorum-lost-and-regained` when the leader is cut, `S/net-quorum-lost-and-regained` for both followers, `S/net-quorum-settled-during-fault` for one; `S/net-handoff-completed` for handoffs); plus `S/durable-history-checked` with `storage_faults=true` when the plan has a kill; with `validators=4` `S/mesh-formed`, and `S/validator-caught-up` when the seed's plan has a fault, plus `S/validator-engine-diff-checked` with `validator_engine_diff=true`; with `follower=true` (any cluster load, and always with `load=zones`) `S/follower-snapshot-restored`, `S/follower-syncing-observed` and `S/follower-caught-up`. Restart-dependent signatures are not required with `process_faults=true` (a plan may be all pauses and throttles); its own `S/*` signatures are coverage only. A run whose load never landed proves nothing |
| `S/cluster-*`, `S/net-*` | Coverage for E12's cluster checks and the network nemesis (above), plus `S/net-outage-deposit-processed`, `S/net-outage-withdrawal-paid`, `S/net-degraded-kept-up` |

## Trie load (`load=trie`)

`trie/RawStorage.sol` writes exactly `sstore(slot, value)`, so its storage trie
is shaped only by the workload. `trie/deploy.yaml` deploys it from dev account 0
before the warm checkpoint (address `0x5FbDB2315678afecb367f032d93F642f64180aa3`).

Each run's writes are generated from its seed (`bin/tempo-dst/src/trie_gen.rs`,
`tempo-dst trie-spec <seed> <generation> <steps>` prints one), with no
hand-picked trigger for any particular bug:

- **Slots** form a random trie shape: an anchor, a stack of slots sharing 1, 2,
  3, ... leading keccak nibbles with it (nested branches and extensions),
  sometimes a pair sharing 7+ nibbles (leaves small enough to be inlined in
  their parent), and a few unrelated slots.
- **Writes** are random inserts, updates and deletes over those slots, with
  values from every encoding class (zero, < 0x80, u64, full 256-bit), and
  no-op holds of random length so changes land at every distance from the
  node's persistence cycles. Stack depth, the value mix and holds vary per seed.
- Each node restart starts a new load generation: a fresh write stream over the
  same slots, from nonces re-read from the node.

E5/E6 check every new block plus two older ones per tick (depths 2-48 and
49-250), with `eth_getProof`, `eth_getProof` without storage targets, and
`eth_getMultiProof`.

### Many contracts, many senders (`trie_contracts=auto`)

The workload arg `trie_contracts` is `1` or `auto`. `1` (the default) is the load above: one contract, one
sender, so old campaigns' seeds keep meaning the same runs. `auto` exercises
the account trie and reth's per-account storage-proof workers, multiproof
chunking across accounts and prefix sets spanning several storage tries:

- **Pool**: `trie/deploy-pool.yaml` (run by `tempo-dst warmup`) deploys
  16 RawStorage contracts before the warm checkpoint (so the boot prefix
  differs from `1`'s). Contract `c` is writer `c mod 8`'s CREATE at nonce
  `c div 8` (`trie_gen::pool_address`; the deploy waits for `eth_getCode` at
  each). Writer 0 is dev account 0, so contract 0 is the single-contract
  address; writers 1-7 are dev accounts 10-16, outside every other load's
  accounts. The dev genesis only gives pathUSD to accounts 0-9, so dev
  account 0 funds them first.
- **Per seed** (the planner, `trie_gen::draw`; recorded as `swarm.trie` in
  scenario.json and delivered as the trie config's `contracts`/`senders`;
  the guest also logs a `trie-plan` event with the addresses and writer
  assignment): N contracts
  (1/8 of seeds one, 1/2 two to four, 1/4 five to eight, 1/8 nine to
  sixteen) and S senders (1 with one contract, else 2..=min(N, 8)). The
  first N pool contracts each get their own slot shape (`trie_gen` with a
  per-contract sub-seed; contract 0 keeps the run seed). Contract `c` is
  written by writer `c mod S`, and a quarter of the time by one more.
- **Writes**: one generated spec per writer, each one sequence from one
  sender (nonce order, one write per block per writer), generated
  separately and interleaved by the trie image's `run-multi.sh`, so blocks
  carry several writers' writes (`trie_tps` is per writer). Before the
  streams, every load generation (branch start and each restart) opens with
  a burst: each writer writes a fresh full-word value to its own contract,
  all sent back to back and drained, so the generation's first block
  changes several contracts' roots (`S/multi-contract-block` does not
  depend on the streams overlapping by chance). N = 1, S = 1 produces
  exactly the single-contract spec, with no burst.
- **Oracle cost**: each tick checks every contract at its newest block
  (E5/E6, and E7 at the newest common block); each other block it checks
  (new blocks below the newest, and the two swept older ones) is checked for
  one contract, round-robin. A tick costs about N + 11 contract checks
  instead of 12 N; each contract's depth sweep covers its ranges about N
  times slower. Failure details name the contract (`contract 0x...`).
  Until `S/multi-contract-block` is seen, every new block's contract roots
  are compared with its parent's (N untargeted `eth_getProof`s per block).

## TIP-20 load (`load=tip20`)

A bank-transfer workload: a closed set of holders of a fresh TIP-20 token
whose whole supply they hold, so transfers among them conserve it.
`tip20/deploy.yaml` runs before the warm checkpoint (`tempo-dst deploy-tip20`):
dev account 9 creates the token through the TIP20Factory precompile
(`createToken`, salt `0xb1d`, at `0x20C0000000000000000000008a34063c54ebdca3`),
grants itself `ISSUER_ROLE`, and mints `k * 10^24` to holder `k`, dev accounts
1-8 (supply `36 * 10^24`). Nothing mints or burns afterwards, and fees are paid
in pathUSD, so the token's supply never moves.

Each run's transfers are generated from its seed (`bin/tempo-dst/src/tip20.rs`,
`tempo-dst tip20-spec <seed> <generation> <steps>`): a per-seed subset of 2-8
holders sends, interleaved, so each block holds several concurrent transfers;
amounts mix zero, small, large and overdrawn (more than the supply: the
transfer reverts and must move nothing), with some self-transfers. Each node
restart starts a fresh transfer stream from nonces re-read from the node.

E8 (`Tip20Oracle`) reads every block by hash: the holders' balances and the
supply (conservation), checked against the parent's balances plus the block's
`Transfer` logs (one generation per block), plus the E5/E6 historical depth
sweep. It pins the run's first block and the latest few multiples of 25, and
re-reads them every tick; a pin whose block is rewound by crash recovery is
dropped (unfinalized blocks may be rebuilt; E3 covers finalized ones).

## Chain load (`load=chain`)

The [chain of blocks](https://antithesis.com/docs/resources/chain-of-blocks/)
workload, against one node's own history instead of replicas.
`chain/ChainOfBlocks.sol` keeps `(length, head)` and every link, with
`append(payload)` computing `links[i] = head = keccak256(head, payload, i)`
from its *stored* head, and logs each append. `chain/deploy.yaml` deploys it
from dev account 9 before the warm checkpoint (address
`0x700b6A60ce7EaaEA56F065753d8dcB9653dbAD35`) and appends entry 0.

- The writer is one sender in nonce order (`bin/tempo-dst/src/cob_gen.rs`,
  `tempo-dst chain-spec <seed> <generation> <steps>`), payloads
  `keccak(seed, generation, step)`. Linking in the contract means it never
  needs the on-chain head: after a crash drops the pool, the next generation
  extends whatever chain the node kept.
- E9 (`bin/tempo-dst/src/cob.rs`) rebuilds the chain from `eth_getLogs`
  (receipts) and recomputes every link from its payload, then holds the
  node's state to it at explicit block numbers. `head` commits to the whole
  history, so one slot read checks every earlier append; `length`/`head` are
  rewritten every append (changeset history), `links[i]` is written once
  (old, cold slots).
- Rebuilt unfinalized blocks are legal: when a synced block's hash changes,
  E9 drops the replaced blocks' appends and re-reads their logs.
- Outside Bedrock: `TEMPO_DST_RPC=http://127.0.0.1:8545 tempo-dst chain-check
  [block]` checks every append block once; `tempo-dst chain-watch <secs>` runs
  the stateful oracle and treats RPC loss/return as kill/restart.

## State-mix load (`load=statemix`)

The generic state-mutation workload behind the generic valid-state-root
invariant. It deploys one `Mutator` contract (`contrib/bedrock-dst/statemix`,
at the slot-0 CREATE address) whose `exec(op, key, val)` calldata selects the
mutation, so one contract exercises every tx-level state-mutation path. Each
run's plan (`bin/tempo-dst/src/statemix_gen.rs`) is a pure function of
`(seed, generation, steps)` — a seed-weighted rotating mix, with a forced
prologue so even a short run covers each kind:

- plain transfer (forward value to a derived address);
- `SSTORE` set / update / clear-to-zero, and max/edge values (`U256::MAX`,
  `MAX-1`, `1<<255`, `2^128-1`);
- `CREATE`, `CREATE2` at a reused (previously self-destructed) salt address,
  `SELFDESTRUCT`, and same-tx create+selfdestruct;
- empty-account touch/delete (EIP-161);
- bulk-write-then-clear over a contiguous slot range.

Notes:
- Slots that write the contract's own storage (`SET`/`CREATE`/`CREATE2`/
  `DESTROY`) are drawn from a fixed per-seed pool (`statemix_gen::slots`), so
  the valid-root oracle can rebuild the contract's storage root from exactly
  those slots; `EMPTY_TOUCH`/`TRANSFER` keys are account addresses that write no
  contract storage.
- EIP-7702 set-code authorizations are not emitted: txgen's `tempo` template
  sends plain EIP-1559 `exec` calls and has no set-code-auth path here; skipped.
- A run crosses an epoch boundary with T8 active (so the recurring committee
  finalize-time write is exercised): the cluster's `EPOCH_LENGTH=100` is crossed
  by any run over ~20 s, and the single-node run (`statemix_tps` over
  `run_secs`) is sized to cross it too.
- The generation-0 mutation mix is recorded (deterministically) in a
  `statemix-plan` event, and the whole plan is replayable via
  `statemix_gen::mutations(seed, generation, steps)` — the per-block tx set a
  later build-differential strand can rebuild and feed into a build request.
- `tempo-dst statemix-spec <seed> <generation> <steps>` prints a generated spec.

## Generic valid-state-root invariant (`verify_state_root=true`)

Auto-on with `load=statemix`; also enabled on any load with
`verify_state_root=true`. Off by default, so existing goldens are byte-identical
(`bin/tempo-dst/src/state_root.rs`, Strand A; and Strand C in
`consensus.rs`). For every new canonical block, on every node (the dev node and
each validator independently), it recomputes the affected state from scratch and
asserts consistency with the block's header `stateRoot` — see
`E6/state-root-recomputed` and `E13/same-height-state-root-differs` above. The
oracle's ground truth is the independent `trie_ref` recompute, never the node's
own trie, so a wrong root is caught even on a lone, self-accepting producer. It
reuses the historical-RPC by-hash (EIP-1898) query infra, and the cluster probe
(Strand C) reuses the engine-diff per-validator plumbing. This generalizes the
`load=trie` E5/E6 checks (fixed RawStorage contracts) to the dynamic per-block
touched set on every node, and complements the finalize-time `E4/re-execute`,
the cross-engine `E13` differential, and the `E1/state-root-mismatch` log scan
(this strand is the per-block / per-proposal / historical recompute those lack).

Note (follow-up, not this change): the reth-dst side with
`--engine.share-sparse-trie-with-payload-builder` and withdrawals would
reproduce reth#27679 directly; that needs the reth-dst harness fixed and is
tracked separately.

## Zones load (`load=zones`)

A [Tempo zone](https://github.com/tempoxyz/zones) settling through a certified
Tempo L1 follower. `load=zones` always brings up four Commonware validators
(`v1..v4`) from the existing deterministic `tempo-xtask generate-localnet`
genesis/key builder, plus the independent `tempo` follower using that same
`/net/genesis.json` and `--follow ws://10.89.77.11:8546`. The follower runs
under thread-fuzz and exposes the existing HTTP/WS endpoints on 8545/8546,
with a 4096-block proof window and persistence every three blocks. Zone
sequencers, provisioning, load and SPF replay all use those endpoints.

Zones scenarios now use version 2; replay rejects older zones scenarios
instead of silently interpreting them with the new topology.

There is no dev-mode L1 or uncertified reference fallback. Omit `validators`,
`consensus`, `reference` and `storage`: zones owns its upstream topology;
`storage_faults` still applies to the follower. Upstream validators stay
running while the zones nemesis faults the follower, sequencers and prover.
The factory's genesis owner is set to dev account 0 with the same packed
configuration used by Tempo's zones `L1TestNode` fixture; consensus DKG,
validator keys, contract runtimes and funded mnemonic accounts are preserved.

Before the warm checkpoint, warmup waits for upstream finality, the follower
and batch 1, then gracefully stops the follower and copies its complete
execution/consensus datadir. The first ordinary process kill targets the
follower. Every follower restart restores this immutable snapshot while
upstream validators keep finalizing. Other kill slots rotate over the zone
sequencers and prover. Recovery is measured against upstream finality at
restart, and requires matching canonical hashes, finalized height and a
persisted watermark beyond the previous incarnation's.

A zones campaign with guaranteed kills requires `S/follower-snapshot-restored`,
`S/follower-fcu-syncing`, `S/follower-executed-after-syncing` and
`S/follower-caught-up`. Missing trigger coverage is a coverage failure, even
if ordinary zone operation succeeds. `E19/follower-catch-up-stalled` detects
stuck head/persistence or an unavailable follower; `E19/follower-hash-mismatch`
detects recovery onto the wrong history. Run for long enough to leave a full
`liveness_secs` recovery budget after snapshot restoration. `no_nemesis=true`
disables snapshot fault injection and does not require its coverage.

```sh
./contrib/bedrock-dst/run.sh --workload-arg validators=1 --workload-arg consensus=false --workload-arg load=zones \
  --workload-arg zone_sequencers=3 --workload-arg decisions=explicit \
  --memory-mb 8192 --seeds 4 --run-secs 300 --out dst-zones
```

The zone sequencer and replay services come from `bedrock/tempo-dst-zones` (`zones/Dockerfile`: tempoxyz/zones
`24a51dd4` and txgen `0d62b7db` built from source, release, debuginfo
stripped, on the txgen image so the layers are shared):

- **`zone`** (`zones/zone.sh`): the zone node and its sequencer. Its first
  start provisions zone 1 with `tempo-zone dev`: `ZoneFactory.createZone`
  (TIP-1091 precompile `0x5aF2..`; dev account 0 owns it in the generated consensus
  genesis) with dev account 0 as admin and sole sequencer (threshold 1),
  portal `0x5ad0000000000000000000000000000000000001`, pathUSD as the initial
  token, `setSequencerEncryptionKey`, and an L1-anchored zone genesis
  (chain ID `(1337 << 32) | 1`). Restarts rerun `tempo-zone node` on the same
  datadir. The sequencer builds one zone block per finalized L1 block
  (`advanceTempo` first: imports the L1 header and the portal's deposits),
  finalizes a withdrawal batch every 25 blocks (`ZONE_BATCH_INTERVAL_BLOCKS`,
  sooner with deposits or withdrawals), signs each batch's EIP-712
  `SettlementAttestation` with the sequencer key and submits it
  (`submitBatch`), and pays out settled withdrawals (`processWithdrawals`).
- **`zone-prover`** (`tempo-dst zone-prover`, packaged in the zones image):
  for every `BatchSubmitted` on the portal, `tempo-zone-prover-utils
  generate-input --block <nextBlockHash>` builds the batch witness and replays
  it through the zone's stateless proof function (SPF), the code the
  production prover runs, and prints one JSON result line (status, replayed
  hash, seconds, peak RSS) that E12 reads from the journal.
- **`zones-load`** (started per branch like txgen): txgen's zone-backing
  property campaign (`txgen-tempo-property`, branch
  `fuzz/zones-property-generator`): from dev account 1, encrypted portal
  deposits (ECIES to the sequencer key) and outbox `requestWithdrawal`s with
  amounts from its swarm (random/Echidna uint128, raw or spendable), each
  awaited to settlement, auditing portal solvency after each. Seeded per run
  (`--seed` from the run seed and load generation; restarts with the next
  seed whenever a campaign ends). Its key randomness (ECIES ephemeral keys,
  GCM nonces) and clock reads are the guest's, so Bedrock controls them.

**What is real and what is not.** The L1, zone node, sequencer, settlement
(signatures, portal checks, deposit and withdrawal queues) and the SPF
re-execution are the real code. The production prover runs the same SPF in an
AWS Nitro enclave and attaches an NSM attestation that the L1's
`ZoneVerifier` checks against approved PCRs; that needs Nitro hardware, so
there is no attestation: the sequencer settles in the portal's `NoProof` mode
(`verifierConfig = 0x02`, empty proof, accepted by the pinned L1 as a
"temporary rollout fallback"), and the `zone-prover` replay is checked by E12
instead of on chain. There is no SNARK in zones to run.

**Warmup** (the `warmup` hook, `warmup.rs`, before the warm checkpoint): runs
`zones/deploy.yaml` from dev account 9 (`TIP403Registry.migrateTransferPolicyIds([pathUSD])`;
`createZone` reverts with `TokenTransferPolicyNotSet` until pathUSD has a
registry binding, and `zone.sh` retries it), then reports not ready until the portal
has code, the zone serves blocks and batch 1 has settled. Every branch starts
from that zone. `tempo-dst deploy-zones` does the same in one blocking call.

**Witness faults** (`--workload-arg zones_witness_faults=true`). Checks that
an invalid batch witness cannot pass the SPF. For every settled batch the
`zone-prover` writes the honest witness (`generate-input --output`), applies
one mutation kind drawn from Bedrock's getrandom (on the input tape), and
replays the result offline through the SPF with `tempo-zone-prover-utils
replay-witness`. That subcommand is added by `zones/replay-witness.patch` at
image build; it is read-only (no RPC, no settlement). The existing `prove`
subcommand cannot stand in: it requires a remote Nitro prover (mandatory
`--target HOST:PORT` and `--attestation-policy`, authenticated against the
hard-coded AWS Nitro root), never runs `prove_zone_batch` locally, so there is
no local SPF entry point for an arbitrary witness without this patch. Mutated witnesses are
never submitted to L1. The mutation kinds (`zones::WitnessMutation`) change
values only, so the JSON still deserializes as a `BatchWitness` but describes
an invalid transition:

- an altered Zone or Tempo state trie node (a changed account balance or
  storage slot) or a dropped Zone state node (a missing read);
- an off-by-one `anchorBlockNumber`, `tempoBlockNumber` or
  `expectedWithdrawalBatchIndex`;
- a tampered `anchorBlockHash` or RLP parent header;
- a dropped last Zone block, or a bumped first block timestamp.

An SPF error or a different replayed hash counts as rejected. A kind that does
not apply (e.g. dropping the only block of a one-block batch) is skipped.
Reproducing the committed hash is `E12/zones-invalid-witness-accepted` only for
a mutation that provably invalidates the transition (the public-input,
anchor-hash, parent-header, dropped-block and timestamp kinds). The witness
over-provides state nodes, so a corrupted or dropped node the batch never reads
leaves the committed hash unchanged; such an acceptance is inconclusive, not a
finding, while a rejection still covers it (observed live: most node mutations
reject, a few are accepted inconclusively).

**The sequencer does not self-check.** `tempo-zone` runs SPF before
submitting only with `--sequencer.enable-prover`, which a sequencer accepts
only together with Nitro `--sequencer.prover-address`es. Even then, a failed
proof only logs a warning and settles through the portal's `NoProof`
fallback (`ZoneMonitor::prepare_artifacts`). So with this harness's NoProof
setup, nothing between building a batch and calling `submitBatch`
re-executes it. A pre-submit gate has no injection point; the mutation
family therefore tests the prover's SPF, and
`E12/zones-invalid-state-advanced` / `-invalid-batch-submitted` replay every
settled batch honestly.

**Byzantine L1** (`--workload-arg zones_l1_faults=true`). Checks that the
prover does not trust an L1 that lies about its state. For a settled batch the
`zone-prover` rebuilds the witness with `generate-input` pointed at a byzantine
L1 proxy (`zones_l1_proxy`): the proxy forwards every JSON-RPC request to the
real node but, for one drawn [`zones::L1Fault`] kind, tampers the matching
responses -- an `eth_blockNumber` below the batch's submission block (a head merely behind is immaterial for an older batch, so it is set below the submission), a wrong block `hash` or `stateRoot`, an
altered `eth_getStorageAt`/`eth_getProof`/`eth_call` value, or dropped or
fabricated portal `DepositMade` logs. This is a separate probe: the honest
replay above uses the real L1 and is never affected, and nothing built on the
faulted L1 is submitted. A witness built over a lying L1 does not validate
against the real chain (its anchor, state root or deposits disagree), so
`generate-input`'s own SPF and hash checks reject it: `S/zones-l1-fault-detected`
(once per fault kind) and `S/zones-l1-response-faulted` cover it. If the prover
instead built a witness that replayed the committed hash from falsified L1,
that is `E12/zones-trusted-bad-l1-accepted` (except a fabricated extra log,
which a correct prover ignores, so its acceptance is inconclusive). The
prover reads few L1 methods, so the kinds that reliably apply to its witness
build are the stale head, dropped portal logs and the altered `eth_call`
(observed live); the block/storage kinds are inert here and report as not
applied. The proxy is sync and
single-connection, so it is deterministic under Bedrock; it alters response
payloads and is a distinct mechanism from the connection-level L1 chaos proxy
in the network-fault work. This faults the prover's L1 view; faulting the zone
node's own WebSocket L1 subscriber (to test deposit crediting) needs a
WebSocket proxy and is not done here.

**TIP-403 policy** (`--workload-arg zones_policy=true`). Checks that zone
TIP-20 transfers honour the L1-inherited TIP-403 policy and conserve balances.
The policy driver (`policy.sh`, container `zones-policy`, `cast`-based) runs
once per branch: it funds a dedicated account (dev account 2) on the zone with
one txgen bootstrap deposit (so it never races the zones-load sender, dev
account 1); on L1 it creates a BLACKLIST policy, blacklists a fresh test
recipient (dev account 7 -- never the fee manager, portal, inbox or outbox),
and switches pathUSD's transfer policy to it; it waits until the zone imports
that L1 block (`TempoState.tempoBlockNumber`); then it sends a forbidden
transfer (dev 2 to the blacklisted address, which must not land) and an
allowed one (dev 2 to dev 3, which must), snapshotting balances and supply
around each. Each step prints a `tempo-dst-policy:` line the oracle reads.

Transfers run on the zone only after `zones/enable-transfers.patch` (applied
at image build): upstream disables user TIP-20 transfers during the
permissioned phase (`TIP20Rules::admit` reverts `Unauthorized`), so without
it a zone transfer always reverts and nothing could be exercised; the patch
lets `TIP20Token` run and enforce the policy, which stays set on L1 and
read-only on the zone. The oracle fails with `E12/zones-policy-not-enforced`
if a forbidden transfer lands and `E12/zones-transfer-unconserved` if an
allowed transfer does not credit the recipient exactly the amount or changes
supply; the normal solvency check is unaffected (a transfer mints/burns
nothing). Because pathUSD is also the fee token, only a fresh recipient is
blacklisted, never a payer or a system account.

**Nemesis.** With `load=zones`, kill `i` targets (`planner::kill_target`) `tempo`, `zone` and
`zone-prover` in turn from an offset of the run seed (a function of the
config, so explicit plans replay the same targets); each kill also restarts
the driver (a new load generation).

E12 (`bin/tempo-dst/src/zones.rs`) follows both chains block by block
(blocks rebuilt after a crash are dropped and re-read), see the oracle table.
Outside Bedrock: `TEMPO_DST_RPC=http://127.0.0.1:8545 tempo-dst zones-watch
<secs>` runs it against live nodes (zone RPC on 9545), reading prover and
driver lines from stdin.

The images tar must hold `bedrock/tempo-dst-zones:latest` (`build.sh`
builds it; `regressions/hunt.sh` saves it only with `--workload-arg
load=zones`). Guest memory: L1 + zone node + prover + driver. Measured at the warm checkpoint with the stripped `known-fixes` node: ~1.6 GB used (1.25 GB of it the image tmpfs), zone node RSS ~290 MB, SPF replay ~33 MB peak RSS and 0.1-2 s per batch; `--memory-mb 3072` passes.

## Network nemesis (`network_faults=true`)

A generic nemesis for loads with a network topology
(`bin/tempo-dst/src/netfault.rs`, plan entries in `planner.rs`). It runs
in `tempo-dst nemesis` on one timeline with the kills, never overlapping a
kill (5 s before / 20 s after it) or another fault, and heals everything
when each fault ends.

**Interface.** A load declares a `NetTopology` (in config.json
`network.topology`, built by `planner::network_topology`):

| Field | Meaning |
|---|---|
| `nodes: [{name, ip}]` | Containers the nemesis may fault, each in its own network namespace at a fixed IP |
| `endpoints: [{name, ip, ports}]` | Named things outside the nodes they connect to (e.g. a forwarder in front of a host-network service) |
| `fault_ports` | Ports generic families are scoped to (e.g. consensus P2P), leaving the rest (RPC, other P2P) alone; empty: all |
| `oracle: {ip, ports}` | Where the oracles reach the nodes from and the node ports they use; a fault that blocks this path is logged as `oracle_path_cut` |

A plan entry is a `NetFault {at_secs, dur_secs, family, steps}`; each
`NetStep {after_secs, action}` is one of:

| `action` | Effect (inside the node's namespace, via `nsenter -t <pid> -n`) |
|---|---|
| `partition {sides, ports, one_way, mode}` | every link between nodes of different sides (1\|3, 2\|2, ... or more sides pairwise) blocked with `iptables` in a `BEDROCK_NET` chain; `one_way`: only what the first side sends |
| `cut {from, to, ports, mode}` | each `from` node's links to each peer (a node or an endpoint) blocked |
| `reset {from, to, ports, at_offsets}` | established TCP connections killed with `ss -K` at each offset; listeners and new connections untouched |
| `netem {from, to, ports, shape}` | delay/jitter/loss/rate on what each `from` node sends to each peer only (asymmetric per link): a `prio` qdisc, `netem` on a fourth band, `u32` filters by peer IP and port |
| `set-leader {target}` | (zones) `zone_setLeader` through an operator RPC |

`mode` is `reset` (TCP RST: established connections die on their next
segment and new ones are refused, no process restarts) or `drop` (a silent
stall). `ports` match either side of a connection (whoever dialed); empty
means all ports (or an endpoint's own). Nodes are named (`{"node":
"v1"}`) or roles (`{"role": "leader", "pick": 0}`) that the load's
`NetWorkload` resolves when the fault starts (`all` is built in);
restoring flushes the chain and deletes the qdisc, so clients reconnect to
the same endpoints through their normal path.

**Families** (`network_fault_kinds`, default: the load's): generic ones over
the topology's nodes by name on its fault ports, `partition` (1|n-1 up to
an even split, mode drawn), `one-way-partition`, `link-cut` (one directed
pair), `link-reset` (2-6 resets), `link-netem` (one node to 1..n-1 peers,
latency 20-500 ms, jitter, loss 0/1/5 %, rate cap); plus the load's own
(zones below). Timing, family, sides, peers, modes, shapes and reset
offsets are drawn from Bedrock randomness (`decisions=guest`) or by the
planner from the seed (`decisions=explicit`), recorded in the plan, the
scenario (`network.plan`) and a `network`/`plan` event; branch re-draws
keep the faults that started and re-draw the rest. Other args:
`max_network_faults` (3), `network_min_gap_secs` (30).

**Events.** `network`/`fault-start` (`kind`, the fault, the `nodes` it
hits, plus whatever the load's `NetWorkload::describe` adds, e.g. roles and
`excuse`: which oracle clocks stop), `network`/`step` (iptables rules and
`oracle_path_cut`, resets with sockets killed, netem arguments), and
`network`/`fault-end` (with `error` if applying or healing failed, which
also fails `D/network-fault-failed`). Coverage: `S/net-fault-<family>`,
`S/net-connections-reset`, `S/net-netem-applied`; the load's oracles add
effect coverage per family.

The guest kernel needs `NET_SCH_NETEM`, `NET_SCH_PRIO`, `NET_CLS_U32`,
`IP_NF_TARGET_REJECT` and `INET_DIAG_DESTROY`, now enabled in
`nix/guest-kernel.nix` (this changes the guest kernel, hence every
workload's boot prefix). netem's per-packet draws come from the guest
kernel's RNG (seeded by Bedrock, on the tape); its timers run on the
emulated clock.

## Multi-sequencer zones (`zone_sequencers=3`)

`--workload-arg validators=1 --workload-arg consensus=false --workload-arg load=zones --workload-arg zone_sequencers=3` replaces the
single `tempo-zone dev` sequencer with three `tempo-zone node`s in
tempoxyz/zones' multi-sequencer mode (same pin, `24a51dd4`, which already
contains zones PRs #1261 and #1278; nothing needed a bump):

- **Provisioning** (warmup, `zones/zone-provision.sh` run by `tempo-dst
  warmup` from a host-network container): `tempo-xtask create-zone` with the
  three sequencers (dev accounts 5, 6, 7) and a **2-of-3** settlement
  threshold (the first is the bootstrap leader, epoch 1), then
  `set-encryption-key`; it writes the genesis, the manifest, fixed Ed25519
  P2P keys and the individual secp256k1 keys to the shared volume. Each node
  signs its blocks with its own key (also its `--sequencer-key-file`, as in
  zones' real P2P fixture), so a block's beneficiary names its producer;
  nodes 1 and 2 load node 0's key as an extra deposit-decryption key. The
  warm checkpoint waits for batch 1 and all three heads.
- **Topology** (compose `# >>> zones-multi`, `zones_cluster::topology`):
  `zone-N` at `10.90.10.(11+N)` on network `zseq`, Commonware P2P on 9200
  directly between them; the host-network L1 WebSocket through `l1-forward`
  (`tempo-dst tcp-forward`) on the gateway `10.90.10.1`, port `18600+N`
  (endpoint `l1`). Fault ports: 9200. Oracle path: from the gateway to RPC
  9545/8544. E12, the prover and the driver use node 0's RPC.
- **Kills** rotate over `tempo`, `zone-0..2` and `zone-prover`.
- **Families** (`zones_cluster::draw_family`, roles `leader`, `follower`
  (`followers[pick % 2]`), `other-follower`, `followers`, `all`, resolved
  from the portal's `leader()` when the fault starts):

| Family | zones test it replicates | Steps |
|---|---|---|
| `l1-cut-all`, `l1-cut-followers`, `l1-cut-leader`, `l1-cut-follower` | `test_three_sequencers_reconnect_and_catch_up_after_l1_network_outage`, `test_asymmetric_l1_fault_matrix` | cut (reset or drop) of the group's L1 link, restored on the same endpoint |
| `l1-resets` | `test_three_sequencers_tolerate_random_active_l1_connection_resets` | every sequencer's established L1 connections reset 2-6 times |
| `l1-netem` | `test_follower_keeps_up_with_high_l1_latency` | netem on the L1 links of all, the leader or a follower |
| generic `partition`, `one-way-partition`, `link-cut`, `link-netem` | `test_followers_catch_up_after_{leader,their}_p2p_disconnect`, `test_follower_keeps_up_with_high_p2p_latency` | on the P2P port, by name |
| `handoff-follower-cut`, `-incoming-isolated`, `-outgoing-isolated`, `-incoming-p2p-isolated`, `-latency`, `-loss` | `network_chaos_p2p_e2e` leadership cases | `set-leader` to a follower 2 s into the fault while the other follower / the incoming leader and the other follower (both planes) / the outgoing leader after the rotation / the incoming leader's P2P links are cut, or under 400 ms P2P + 500 ms L1 latency, or P2P loss |

The zones `describe` logs the leader, the nodes hit (`hit`), a handoff's
`target` and the `excuse`: `settlement` when the leader's side has fewer
than 2 of 3, `production` when the leader cannot build, `observer` when
node 0 is cut off from the leader. E12's zones and cluster checks stop those clocks during the
fault and restart them at its end (see the oracle table).

Use `--memory-mb 8192` as an initial budget for zones: it now includes four
upstream validators, the certified follower and its clean datadir snapshot,
in addition to the zone sequencers and SPF replay. Measure peak memory on
the Bedrock host before increasing concurrency.

## Reference node (`reference=true`, E7)

`run.sh ... --workload-arg validators=1 --workload-arg consensus=false --workload-arg reference=true` keeps compose.yaml's `# >>> reference` blocks: a
second node, `tempo-ref` (same image, RPC on 8547, own `tempo-ref-data`
volume), that re-executes every primary block on reth's simplest paths:
`--engine.disable-prewarming --engine.disable-precompile-cache
--engine.state-root-fallback --engine.disable-state-cache
--engine.num-state-masking-blocks 0 --engine.persistence-threshold 3`. It
runs plain `tempo` (no thread-fuzz) and the nemesis never kills it, so it is
the baseline the primary is compared against.

- It follows the primary with `--follow http://127.0.0.1:8545
  --follow.nocertify`, Tempo's switch for reth's `--debug.rpc-consensus-url`
  (fetch blocks over RPC, drive the engine with newPayload/FCU) that skips the
  commonware consensus stack. `--debug.rpc-consensus-url` alone fails outside
  `--dev`: Tempo then requires `--consensus.signing-key`. Chain: `--chain
  dev` (same genesis as `--dev`).
- The RPC follower only sees blocks produced while it polls. Blocks from
  before it started, or the ones a primary crash unwinds and rebuilds, come
  over p2p: the primary gets a fixed `--p2p-secret-key-hex` and the reference
  names it in `--trusted-peers` (discovery stays off). While the primary is
  down the follower logs `alloy_rpc_client::poller` errors, so ERROR lines on
  the reference are not findings; only E1's named patterns are.
- Verified outside Bedrock on the pinned image: a reference started 450
  blocks late backfills, then matches every header hash and state root; after
  a SIGKILL that made the primary unwind 637 to 627 and rebuild, the
  reference reorgs onto the rebuilt blocks within ~15 s; proofs match.

Off by default until validated in campaigns.

## Storage faults (`storage_faults=true`)

A SIGKILL keeps the guest page cache, so every write the node made survives
it, synced or not. A real machine crash loses what was never synced. Off by
default; with the flag:

**LazyFS** ([dsrhaslab/lazyfs](https://github.com/dsrhaslab/lazyfs), the
FUSE file system Jepsen uses to lose un-fsynced data; pinned in
`nix/lazyfs.nix`, patched by `nix/lazyfs/bedrock.patch`, driven by
`storage.rs`). LazyFS keeps written data in its own page cache until the
application syncs the file; a power loss drops what was never synced. During
warmup, before the checkpoint, the warmup hook (`storage::attach`, also
`tempo-dst storage-attach`) SIGKILLs the node, bind-mounts its datadir
volume's backing directory privately at `/run/lazyfs/root`, mounts LazyFS
over the backing directory itself (reaching the files through the bind, so
compose, `podman start` and E4's re-execute are unchanged), and restarts the
node. Everything on disk at that point is durable. From then on:

- data is volatile until `fsync`/`fdatasync` of the file; shared writable
  mappings work (not `direct_io`), so MDBX's write map reaches LazyFS through
  kernel writeback, and `msync(MS_SYNC)` and `O_DSYNC` writes arrive as
  `fsync`. A file's size changes are volatile with its data;
- creates, links, removals and renames reach the backing directory at once
  (durable immediately: a state ext4 can reach, but not every one it can;
  directory `fsync` is not modeled);
- crash: `sync -f` pushes the kernel's dirty pages of the mount to LazyFS
  (still volatile), LazyFS writes the drawn subset of its un-synced blocks to
  the backing files (none for `all`; for `subset` each dirty 4 KiB block and
  each file's un-synced size kept with the drawn probability, blocks past the
  durable size only with the size) and exits, dropping the rest; the mount is
  dropped (with every kernel cache) and a fresh LazyFS mounted; the node
  reopens cold. Durable bytes are never touched;
- torn write: LazyFS's own `torn-op` (the n-th write to a file split into
  parts, a strict subset of them persisted) or `torn-seq` (of the n-th run of
  writes to a file without an `fsync`, only a subset persisted, possibly out
  of order), armed on a drawn datadir file (`db/mdbx.dat`, the headers static
  file and its offsets, the account and storage change-set static files).
  When it fires, LazyFS writes the persisted part and SIGKILLs itself under
  the running node: every other un-synced write is lost. If it has not fired
  by the window's end, the window ends in a crash that discards everything.

The patch (`nix/lazyfs/bedrock.patch`, 242 added lines of C++) fixes one
LazyFS bug and adds the control commands. The bug: `lfs_truncate` left its
return code uninitialized on the cache-only paths (a new file's `set_len(0)`,
a cached shrink or same-size truncate), so `ftruncate(fd)` failed with a
stale `errno` (seen as `ENOENT` in commonware's blob resize) whenever the
stack slot happened to hold -1: deterministic under Bedrock, gone with any
change to the stack (e.g. LazyFS's op logging). The commands are the
`bedrock <id> <command>` control commands on LazyFS's fault FIFO, with
replies (`<id> <json>`) on the completion FIFO, opened read-write so LazyFS
never waits for a reader: `crash <keep_permille> <seed>` (the subset crash),
`torn-op <file> <parts> <persist> <occurrence>` and `torn-seq <file>
<persist> <occurrence>` (LazyFS's torn faults, acknowledged, armed under its
command lock), and `stats` (liveness). LazyFS's cache is 128 MiB,
preallocated, with LRU eviction: when it is full, a dirty block can be
written back early, a state Linux writeback can also reach. The mount source
is named `lazyfs`: libmdbx refuses sources named `fuse*` unless opened
exclusively. The guest kernel has `CONFIG_FUSE_FS=y` for this. LazyFS runs
single-threaded (`-s`) plus its FIFO thread; its only clock reads are file
times from the guest's emulated clock, and its only randomness is seeds and
fault parameters from the nemesis's Bedrock-controlled draws.

**Fault families** (`nemesis.rs`), one per planned kill, drawn per seed:
process kill (as without the flag); machine crash with discard all or subset
(twice as likely); a torn write armed for a 2-10 s window ending in a machine
crash. Inside a torn-write window (`storage-fault` to `storage-fault-end`
events) the node may die when the fault fires: workload-monitor excuses its
death (any exit code) and E1 findings become `S/storage-fault-surfaced`,
until the restart. Without the flag nothing extra is drawn, so old seeds mean
the same. `storage_fault_kinds=crash,torn` (any of `kill`, `crash`, `torn`;
other names are rejected) restricts the families. Each planned fault, with
its family and parameters, is part of the nemesis plan: in the `plan` event,
in scenario.json, in config.json with `decisions=explicit` (drawn by the
planner), and in a branch's re-drawn plan; a kill whose fault window is still
open when a branch re-decides is finished with a restart (after a crash that
discards everything, for a torn write that may have fired).

**E11** (`durable.rs`) records, outside the node, every canonical block's hash
and transaction hashes and every fourth block's historical reads, freezes them
at each kill, and after the reopen re-checks the newest 48 blocks before the
crash and a stride of 32 older ones (see the oracle table). Losing an un-synced
suffix of unfinalized blocks is allowed (E3 still covers finalized ones);
serving a kept block with holes is not. E4's re-execute runs over the LazyFS
mount at the end.

Runs (180 s seeds, transfers load, 3 GB guests): reth-23603 buggy 4/4 E11
and pinned 0/4 with `storage_fault_kinds=crash` (see regressions/); torn
writes alone (`storage_fault_kinds=torn decisions=explicit`, seeds 0-2) 3/3
pass with 4 of 9 armed faults firing (`torn-op` on `mdbx.dat` and on the
headers offsets; the drawn `torn-seq` runs never reached their write), the
node recovering each time, and `replay` of seed 0 (two fired) identical.
LazyFS stays at ~170 MB resident. faultfs, the hand-written FUSE model LazyFS
replaced, needed 16 GB guests (a ~4.5 GB transient while MDBX reopened its
4 GiB sparse datafile) and also modeled directory `fsync`, storage errors and
slow syncs; below 3 GB the guest runs out loading the images either way.

Not modeled (follow-ups): volatile namespace changes (directory `fsync`),
`EIO`/`ENOSPC` and slow syncs (dropped to keep the LazyFS patch minimal; the
first faultfs version had them), bit corruption, and `sync_file_range` as a
durability point (it is not one). LazyFS fills a file grown by `ftruncate`
with zeros in its cache, so a large growth (MDBX's datafile past its initial
4 GiB) would evict and write back early; runs stay far below it.

Outside Bedrock (any Linux host with FUSE, as root): `nix build .#lazyfs`,
then mount it as `storage::mount` does (a config with `fifo_path` and
`fifo_path_completed`, `-o modules=subdir -o subdir=ROOT -f -s`) and send
`bedrock 1 crash 0 0` to the fault FIFO; `tempo-dst storage-ctl` does this
against `/run/lazyfs` (`storage-ctl crash all`, `storage-ctl torn
'{"mode":"op","file":"headers","parts":3,"persist":5,"occurrence":2}'`).

## Process faults (`process_faults=true`)

Faults on the node process rather than its storage, after upstream
oss-garage/bedrock#26 ("Node faults"). Off by default; with the flag each
planned fault is drawn (Bedrock-controlled randomness, `nemesis.rs`) from:

- **kill**: SIGKILL and restart, as without the flag;
- **pause**: `podman pause` (cgroup v2 freezer) for 1-20 s, then `podman
  unpause`. The node keeps its memory and sockets but answers nothing: RPC
  clients time out, the E7 reference's follower and p2p session see it
  vanish and come back. No restart, so the txpool and in-memory blocks
  survive;
- **throttle**: 10-30% of one CPU for 5-30 s (`process.rs`). The quota is
  written to the container cgroup's `cpu.max`, but that is CFS bandwidth and
  the node's threads are `SCHED_EXT` (thread-fuzz; scx-fuzz implements no
  `cgroup_set_bandwidth`), so it is enforced with the freezer too:
  `cgroup.freeze` duty-cycled in guest time, thawed for the quota of every
  100 ms. `cpu.stat` before and after is in the `throttle-end` event;
- **stop**: `podman stop -t <10-30 s>`, a downtime, then `podman start`:
  clean shutdown and startup mid-load, distinct from SIGKILL and from
  finalize's stop. A stop that falls back to SIGKILL (container exit 137,
  podman's "resorting to SIGKILL") or uses up the timeout is
  `E4/stop-timeout`. The restart then runs like a kill's (E3, E9, E11 and
  the load's new generation).

Events, each logged before acting: `pause`/`resume`, `throttle`/`throttle-end`
(always logged, so excusal always ends), `stop`/`stopped`/`restart`. E2 is
excused inside pause and throttle windows and its clock restarts at their
end; other oracles keep checking a throttled node; a paused node is treated
like a down one (no checks). workload-monitor charges each `stop` with the
container's next death: a clean exit is recorded as usual, a SIGKILL fallback
is left to `E4/stop-timeout`, any other code is still asserted. The E7
reference keeps running throughout; its stall clock restarts at the
primary's resume. `process_fault_kinds=pause,stop` (any of `kill`, `pause`,
`throttle`, `stop`) restricts the families; with `storage_faults=true` too, the
process families are added to the storage table (which keeps its own
`kill`). Without the flag nothing extra is drawn, so old seeds mean the same.
The flags are `TempoArgs` (`process_faults`, `process_fault_kinds`,
`finalize_stop_timeout_secs`, plain workload args); the planner draws the
families for `decisions=explicit` and branch re-draws like the guest, and
records `process_faults` in the swarm record. A branch that re-decides
inside a pause or throttle ends it at once. Pauses and throttles restart
nothing, so with `process_faults=true` no restart-dependent coverage is
required.

## Validators (`validators=2..20`, or `validators=1 consensus=true`)

`--workload-arg validators=N` replaces Tempo's single dev node with N real
commonware validators: compose services `v1`-`vN`
(`# >>> validators` blocks; run.sh drops the dev node's `# >>> single`
blocks) on a podman bridge, validator `i` at `10.89.77.(10+i)` (consensus p2p
8000, devp2p 8001, metrics 8002, RPC 8545), each under thread-fuzz with its
own data volume. `validators=1 consensus=true` runs a single real consensus
validator. Without `consensus=true`, default `validators=1` is the dev node.

- **Artifacts.** The builder compiles `tempo-xtask` from the first requested
  Tempo revision. `validators/build.sh` adds one shared `/net` to each node
  image as `bedrock/tempo-validators:<N>-<node tag>`, containing the
  genesis and keys from Tempo's `tempo-xtask generate-localnet --seed 0
  --accounts 64 --epoch-length 100 --validators 10.89.77.11:8000,...`,
  patched (`xtask-signing-key-hex.patch`) to also write
  each signing key unencrypted (the encrypted one costs ~512 MiB and seconds
  of scrypt per start). The IPs are part of the genesis. Revisions are
  assigned to validators in round robin order; all revisions must accept
  the first revision's genesis.
- **Variants** (compose-time, so they change the boot prefix):
  `cooldown=1s` (default; `--consensus.connection-per-peer-min-period 1s`,
  full mesh in 4-10 s) or `default` (Tempo's 60 s: 95-123 s);
  `timeouts=tuned` (default; 1 s target block time, 3 s proposal and 5 s
  notarization waits, one consensus worker thread, leader skip at Tempo's
  default, for Bedrock's instruction-count clock) or `prod`.
- **Engine differential** (`validator_engine_diff=true`, compose-time, needs
  `validators>=2`): each validator runs a different reth engine profile
  (`cluster.rs` `EngineProfile`), so the consensus cluster is an N-way
  execution differential (E13/validator-state-root-differs,
  E13/validator-proof-differs; coverage `S/validator-engine-diff-checked`).
  `Optimized` is today's default (`--engine.state-root-task-compare-updates`),
  `Simple` the old E7 reference's sequential engine
  (`--engine.state-root-fallback` with prewarming/precompile-cache/state-cache
  and state masking off), plus `Compare`/`Race`/`NoPrune`. The `{Optimized,
  Simple}` pair is always present (v1/v2). The assignment is a pure function of
  the campaign-fixed `workload_seed` (the validators boot once, before the
  shared warm checkpoint), recorded in `swarm.cluster.engine_diff` and
  `cluster.engine_profiles`; run.sh replicates the draw to template the compose
  file. Off by default (every validator keeps today's flags; existing goldens
  unchanged).
- **Warmup** gates the warm checkpoint on every validator having finalized
  `--warm-blocks` and the full mesh (each validator connected to the other
  N-1), then deploys the load through v1.
- **Load.** Generation `g` sends to validator `first_load_target + g`
  (rotating; `first_load_target` drawn per seed), and a new generation starts
  after every fault, so the load's oracles (E5/E6/E8/E9, `S/load-included`)
  check several nodes per seed. The generated genesis sets every account's
  fee token to AlphaUSD, so the TIP-20 load's token still never pays fees.
- **Faults** (`cluster.rs` `ClusterFault`, always planner-made and delivered
  in config.json, so `replay --scenario` is exact): typed entries that SIGKILL
  and restart `targets` (`order`: `together`, or `rolling` with `gap_ms`),
  `down_ms` later, each fired by a trigger after `not_before_secs`: `now`,
  `finalization` (the cluster's finalized height grows by `min_jump` between
  100 ms polls: 1 lands mid-finalization, 2+ in a catch-up burst) or
  `epoch-boundary` (the next multiple of 100 plus `offset`), or at
  `deadline_secs`. Families (`faults=`, else drawn per seed, recorded in
  the swarm): `single`, `quick` (<1 s down), `simultaneous` (2-3 validators:
  beyond the fault budget for small clusters), `rolling` (all nodes in
  turn), `whole-cluster` (all nodes at once). `max_kills` bounds the faults
  per seed; `min_gap_secs` (at least the cooldown's mesh budget) separates
  them. Faults are process crashes (data volumes and the guest page cache
  survive) unless `storage=lazyfs`: then each validator's datadir is on its
  own LazyFS instance (attached during warmup; `node_storage.rs`, LazyFS and
  its patch from the single-node storage-fault work), half the faults are
  machine crashes (`crash: {"kind": "machine", "discard": ...}`: SIGKILL,
  then drop all or a seeded subset of the un-synced writes, remount cold),
  and the `power-loss` family (every validator's machine at once) joins the
  draw. A crash that fails is `H/storage-crash-failed`;
  `S/machine-crash-discarded` shows one dropped data. Liveness oracles excuse windows with more than f validators down
  and restart their clocks when the cluster is back within budget; a later
  fault family (network faults) reports `impair`/`heal` events over
  `targets`, which count against the same budget.
- **Oracles**: E1 on every validator's log, E13-E18 (table above),
  `cluster_live.rs`/`consensus.rs`; finalize stops every validator
  together (`podman stop`) and re-executes each datadir against
  `/net/genesis.json` (E4). Each stop must exit 0, or exit 1 from exactly
  Tempo's deliberate executor fail-stop: on SIGTERM reth stops its engine
  before consensus, and the executor's next engine call fails with "beacon
  consensus engine task stopped" (`S/shutdown-executor-fail-stop`); finalize
  announces these stops (`finalize`/`stop` events) so workload-monitor
  leaves their exit codes to E4. The consensus oracle applies nemesis events
  right before each validator's reads, so a validator killed and restarted
  mid-tick is never judged against its previous incarnation.
- `tempo-dst cluster-watch <secs>` runs E13-E18 against a live cluster at
  the genesis IPs outside Bedrock.

```sh
DOCKER='sudo docker' ./contrib/bedrock-dst/validators/build.sh bedrock/tempo-localnet:known-fixes
./contrib/bedrock-dst/run.sh --node-image bedrock/tempo-localnet:known-fixes \
  --workload-arg validators=4 --workload-arg faults=rolling --memory-mb 6144 \
  --seeds 4 --run-secs 300 --out dst-validators
```

Not yet: network faults,
`branch --vary decisions` for cluster plans (refused), the reference node
with validators (refused).

## Certified follower (`follower=true`)

`--workload-arg follower=true` attaches one independent certified L1 consensus
follower to the consensus cluster (`validators=N consensus=true`) under **any**
load — the generic detector for the tempo#8263 class ("canonicalize follower
catch-up after syncing forkchoice"). It is off by default and incompatible with
the dev node; `load=zones` always implies it (through its own four-upstream
topology). The same mechanism that was bound to zones in #66 (decofe) is lifted
out here so it runs on `trie`/`tip20`/`chain`/`transfers`/`statemix`/`zones`.

**The bug class.** A follower that follows the validators' certified consensus,
falls behind, and catches up sends a forkchoice *ahead of execution*; reth
answers `SYNCING`, and the buggy path stalls canonicalization and persistence —
the follower never makes the block canonical or advances persistence. The
[merged fix](https://github.com/tempoxyz/tempo) gates the catch-up forkchoice on
reth's live finality and tolerates a racing `TooDeepReorg` only below finality.

- **Topology.** An extra `tempo` container (compose `# >>> zones-follower`
  block; `render-compose.py` keeps it for `follower=true` or zones) runs the
  built validators image on the generated chain, follows `v1`'s certified
  consensus over `ws://10.89.77.11:8546`, and trusts `v1`'s execution p2p so it
  catches up through execution-layer sync. It is **not** a validator: `v1..vN`
  produce blocks (driven by the load), and the follower follows. Its datadir is
  an independent volume (`tempo-data`). `topology::Role::Follower`.
- **The fall-behind/catch-up fault (an offline-window family, drawn from the
  seed).** Warmup saves a clean pre-warm follower datadir before the warm
  checkpoint (`follower::snapshot`). During the run the cluster nemesis drives
  the follower behind on a planner-made, replayable schedule
  (`scenario.follower`, `config.follower_plan`; `planner::follower_plan_for`
  under `FOLLOWER_SALT`) whose windows cross the persistence/finality frontier:
  - **snapshot-restore** — restore the pre-warm datadir (the deepest gap and the
    strongest #8263 trigger); always the first window;
  - **kill-and-hold** — SIGKILL and hold the follower down past the persistence
    frontier before restart;
  - **pause** — `podman pause`/`unpause` for a window.
  (A healed network partition also arms the catch-up check.)
- **The catch-up oracle (`follower::FollowerOracle`), trigger-agnostic.** On any
  rejoin it asserts, within `liveness_secs`: a `SYNCING` forkchoice is observed
  (`S/follower-syncing-observed`), a block executes after it
  (`S/follower-executed-after-syncing`), and the follower's head and finality
  reconverge on the validators' finalized chain with persistence advancing past
  the previous incarnation's watermark (`S/follower-caught-up`). A stall is the
  finding: `E/follower-catch-up-stalled`, `E/follower-canonical-diverged`,
  `E/follower-persistence-stalled` (see Oracles). The oracle is
  container-parameterized, so the same invariant can judge a validator that fell
  behind and rejoined. The follower's datadir is re-executed alongside the
  validators' at finalize.

```sh
./contrib/bedrock-dst/run.sh --node-image bedrock/tempo-localnet:known-fixes \
  --workload-arg validators=4 --workload-arg consensus=true \
  --workload-arg follower=true --workload-arg load=trie --memory-mb 6144 \
  --seeds 4 --run-secs 300 --out dst-follower
```

Required coverage when on: `S/follower-snapshot-restored`,
`S/follower-syncing-observed`, `S/follower-caught-up`. Off by default, so
existing configs, scenarios and goldens are byte-identical; follower-on cases
are pinned in `planner-golden-cluster.ndjson`.

## Checking the zones topology

```sh
cargo test -p tempo-dst
uv run --with pyyaml python -m unittest discover -s contrib/bedrock-dst -p test_topology.py
```

The topology tests parse the actual renderer output with duplicate YAML keys
rejected, check both zone layouts and ordinary dev/reference/validator
layouts, and check that the fixture factory override preserves consensus
metadata and every other allocation. Unit tests cover stalled recovery,
RPC outages, hash divergence and head recovery without persistence. These
checks do not replace a campaign on a host with `/dev/bedrock`.

## Running

On a bare-metal Intel host with EPT-friendly PEBS and `bedrock.ko` loaded
(`/dev/bedrock`). Nested VMs don't work: KVM hides `PEBS_BASELINE` from guests,
and without precise exits guests that spin in user code (e.g. podman's Go
runtime) never receive timer interrupts.

```sh
DOCKER='sudo docker' ./contrib/bedrock-dst/run.sh --seeds 20 --run-secs 180 --out dst-out
./contrib/bedrock-dst/run.sh --variant no-prewarm --seeds 20 --out dst-out-noprewarm
./contrib/bedrock-dst/run.sh --workload-arg load=trie --seeds 20 --out dst-out-trie
./contrib/bedrock-dst/run.sh --workload-arg load=trie --workload-arg trie_contracts=auto \
  --seeds 20 --out dst-out-trie-multi
./contrib/bedrock-dst/run.sh --workload-arg load=tip20 --seeds 20 --out dst-out-tip20
./contrib/bedrock-dst/run.sh --workload-arg load=chain --seeds 20 --out dst-out-chain
./contrib/bedrock-dst/run.sh --workload-arg validators=1 --workload-arg consensus=false --workload-arg load=zones --memory-mb 3072 --seeds 20 --out dst-out-zones
./contrib/bedrock-dst/run.sh --workload-arg validators=1 --workload-arg consensus=false --workload-arg load=zones --workload-arg zone_sequencers=3 \
  --workload-arg network_faults=true --workload-arg decisions=explicit \
  --memory-mb 4096 --run-secs 300 --seeds 20 --out dst-out-netzones
./contrib/bedrock-dst/run.sh --workload-arg load=trie --workload-arg validators=1 --workload-arg consensus=false --workload-arg reference=true \
  --seeds 20 --out dst-out-ref
./contrib/bedrock-dst/run.sh --workload-arg storage_faults=true --seeds 20 --out dst-out-storage
./contrib/bedrock-dst/run.sh --workload-arg load=trie --workload-arg process_faults=true \
  --seeds 20 --out dst-out-process
bedrock-dst replay dst-out/seed-3
```

Results: `dst-out/summary.json`, plus a `verdict.json` per seed.

`prepare.sh` builds the selected Tempo and txgen revisions (both default to
freshly fetched `origin/main`) with Tempo's `profiling` profile and `dst`
feature, debug assertions and overflow checks. It also builds the static musl
`tempo-dst` planner/controller and ready signaler. Persistent Cargo targets and
sccache live under `$TEMPO_BUILD_CACHE` (default
`~/.cache/bedrock-tempo-dst`). It packages the node, controller, generators and
load contracts into a content-keyed image archive and renders the selected
topology. Bedrock builds its own driver, kernel and initrd separately.

Use `--node-revisions REV[,REV...]` or `--txgen-rev` on the wrapper to choose
source revisions; revisions are assigned round robin across validators.
`--prepare-only` builds inputs, then `--prepared` with the same `RUN_DIR` runs
without rebuilding. Supply workload settings only during preparation.

The [DST workflow](https://github.com/tempoxyz/bedrock/blob/main/.github/workflows/tempo-e2e.yml)
selects a harness repository, revision and directory. For this harness, use
`workload_config` to set validators/consensus/load and `prepare_args` for node
and txgen revisions. `memory_mb` selects guest RAM; `parallel_seeds` and
`seed_loops` control seed streams. Active guests are limited by free RAM,
reserving 32 GiB for the host; remaining streams are queued. A single `seed`
can be selected instead. Summaries and verdict uploads retain the existing
assertion signatures.

## Timelines and replay

Every run is a **timeline**: the World (an immutable boot plus warm
checkpoint, `world.json`) plus the decision tape that was served to it
(`tape.bin`). A run is a pure function of those two, so the tape is the replay
unit, not the seed: a seed number only names a root timeline together with the
World and this driver version.

| File | Holds |
|---|---|
| `<out>/world.json` | the World: `world_id` (sha256 of the vmlinux, initrd, images.tar and compose file by content, `bedrock.ko` identity, the planner's sha256, cmdline, memory, TSC frequency, boot seed, the exact warmup command and the warm checkpoint's virtual time), the same files with their paths, and the boot arguments |
| `tape.bin` | every input of the run with its virtual time: randomness (RDRAND, RDSEED, getrandom with the requesting pid), host actions (`tempo-dst start/finalize`, artifact fetches, a branch's `redecide`) and control actions (forced-preemption settings, the run's horizon) |
| `timeline.json` | the timeline's id (`tl-` + tape sha256 prefix), World, parent (`{timeline, cut}` for a branch), tape summary (sha256, counts, per-consumer draws) and `segments`: how each stretch of the tape was generated (`rand`: per-consumer streams `{base, overrides, skip}` or the parent's suffix; `plan`: the plan seed, a re-draw or dropped decisions; `preempt`) |
| `actions.jsonl` | each host action's command, exit code and output sha256, at its response time |
| `scenario.json` | the plan's decisions with what the guest reported (derived, for reading) |

**Tape format** (`bedrock_lab::Tape`, version 2, little-endian): magic
`BDRKTAPE`, version, flags, body length, body, FNV-1a checksum. The body is
the TSC frequency, start/end virtual time, the randomness inputs (`at`,
source, pid, bytes), the host actions (`at`, target, command,
record_output) and the control actions (`at`, `set_preempt {period, seed}` |
`end`). Version-1 tapes (no control actions) still read. A branch applies a
control action when it is halted at exactly the recorded time; a replay that
only halts later fails (`LabError::CtlDiverged`) instead of drifting.

**Randomness** comes from per-consumer streams (`bedrock_lab::StreamSource`):
one xorshift64 stream per consumer (`insn` for RDRAND/RDSEED, `getrandom:<pid>`),
each seeded from the timeline's base seed and the consumer key. How many values
one consumer draws never shifts another's, so a fork can re-roll exactly one
consumer (the scheduler's pool, Tempo's RNG) or drop a nemesis kill and keep
every other consumer's draws. A campaign seed's root timeline uses plan seed
= seed, randomness base `splitmix64(seed ^ "randstr1")` and the seed's own
forced-preemption draw, each its own consumer. Every draw exits to userspace,
exactly as when a tape replays (the in-kernel PRNG, the removed
`--kernel-rng`, did not replay exactly: an interrupt pending at a randomness
exit lands on the other side of the draw).

**`replay <timeline-dir>`** is the one replay path. It boots the World again
and refuses (unless `--force`) if anything in `world.json` differs (binaries,
module, boot arguments, warm checkpoint time), then forks the warm checkpoint
with a `RecordedInputSource` over the tape: randomness comes from the tape,
the lab queues each recorded host action at its recorded time and applies
each control action at its time. It never re-derives anything from a seed.
The replay must consume exactly the tape's inputs, every host action must
answer the same bytes (`actions.jsonl`; all artifacts are such answers), and
it must end where the tape ends. A replay that asks for randomness the tape
does not have stops with an error naming the input index; it never invents
bytes. Runs recorded before timelines (`manifest.json`, `--scenario`,
`decisions=guest`) are not replayable by this driver.

`run.sh` builds `tempoInitrd` through Nix. The prepared initrd is cached in the
store and reused across invocations. The controller binary is built with the
other host binaries and packaged in the `bedrock/tempo-dst` image, which the
guest runs through `podman exec`; the World pins the inputs by sha256.

**Decisions.** The planner makes every semantic decision (kill plan,
per-generation load seeds) from the plan seed before the run and delivers it
in `config.json`; `decisions=guest` and `spec_seeds_from_getrandom` were
removed. Guest randomness is left to the guest's own consumers (thread-fuzz,
Tempo, the kernel), which the tape covers.

## Branching from a moment

One recorded timeline can be turned into many nearby runs, Antithesis-style:
re-execute it exactly to a moment `T`, checkpoint there, and fork `K`
timelines that continue from `T` with other randomness and/or other
decisions. Each branch is a full run (oracles, artifacts, verdict) and a
timeline of its own (`tape.bin`, `timeline.json` with `parent: {timeline,
cut}`), so it replays with `replay` and can itself be branched. `branch` is
the fork preset of the multiverse engine.

```sh
bedrock-dst moments dst-out/seed-7               # pick T
bedrock-dst branch dst-out/seed-7 --at 31.2 --seeds 50          # fresh randomness
bedrock-dst branch dst-out/seed-7 --at 31.2 --seeds 8 --vary both --horizon-secs 60
bedrock-dst branch dst-out/seed-7 --at input:812 --vary none --seeds 1  # = the original
bedrock-dst replay dst-out/seed-7/branches-31.2s/branch-3
```

**How.** `branch` boots the World and checks it like `replay`, then
re-executes the tape strictly up to `T` (`bedrock_lab::PrefixSource`:
randomness in order, host and control actions at their recorded times),
checkpoints where the run actually halted (the first exit at or after `T`),
and forks each branch from that in-memory checkpoint with its own source.
A branch's tape is therefore the parent's prefix followed by what its own
segment served. Each branch runs to the parent's end (or `--horizon-secs`
after `T`, recorded on its tape as an `end` control action), finalizes and is
judged like a campaign seed.

**`--at`** takes virtual seconds since the run forked from the warm
checkpoint (`31.2`; what `moments` prints), absolute virtual time
(`vt:110.5`, as `console.log` stamps it), or "just before randomness input
`n`" (`input:812`). `T` must lie after the start action and before the run's
end; the branch's `timeline.json` records the exact cut.

**`moments <timeline-dir>`** lists moments to branch from: the start action,
each nemesis kill and restart, each later load generation, and, per Always
signature, its first failure, the last pass before it, and 5 s before it.
Guest event times are mapped to virtual time through the run's first event,
so they are good to a few hundred ms (`input:<n>` is exact).

**`--vary`** (what changes after `T`):

| `--vary` | Randomness after `T` | Decisions after `T` |
|---|---|---|
| `none` | the rest of the tape | the original's: a playback of the parent's suffix that must reproduce every input and host-action answer |
| `rng` (default) | fresh per-consumer streams per branch | the original's |
| `decisions` | every consumer's stream continued where the parent left it | re-drawn |
| `both` | fresh | re-drawn |

Re-drawing keeps every kill that fired before `T` and every load generation
started before it; the rest of the kill plan is drawn from the branch seed,
and later generations get fresh seeds. The driver delivers them at `T` with
`tempo-dst redecide '<json>'` (a host action on the branch's tape): the guest
waits until the nemesis is between faults, keeps whatever already happened,
and resumes the nemesis with the merged plan.

**Determinism.** Branch `i`'s seed is `branch_seed(parent tape sha256, T, i)`,
so a branch is a pure function of the parent tape, the moment and the branch
seed; its segment records the streams and plan operation that seed made.

**Output** (default `<timeline-dir>/branches-<at>/`): `world.json`,
`boot-console.log`, `prefix-console.log`, `branch-<i>/` (timeline
directories), and `summary.json`; the driver prints signatures × branches,
plus how many branches are distinct runs and how many equal the parent.

**Use cases.**

- *Explore around a failure.* For a seed that hits #16 (a wrong block), branch
  50 ways from 5 s before the first wrong block. How many branches still
  fail, and with which signatures, says whether the bug needs that exact
  schedule or just that state.
- *Find siblings*: `--vary both` from a kill shortly before the failure
  re-rolls the later kills and loads.
- *Minimize*: the engine's fork-late minimizer automates "branch from later
  and later moments" (see the multiverse docs).

**Limitations.** A branch needs the parent's World (it re-executes the
tape). `--vary decisions` changes guest timing at `T` by the host action
itself. Moments derived from guest events are approximate. Branches run
sequentially in one process from one in-memory checkpoint.

## Multiverse exploration

`bedrock-dst explore` is the multiverse engine (design: `docs/multiverse.md`
on `dst/multiverse-design`). It grows a corpus of snapshots of timelines and
repeatedly asks a weighted policy mix what to run next:

| Policy | Picks | Then |
|---|---|---|
| `breadth` | the World | a new root timeline (plan seed, its preemption draw, fresh per-consumer streams): what `campaign` runs |
| `rarity` | the snapshot with the largest Σ 1/df(feature) + interest, ÷ (1 + expansions) | fresh or re-rolled randomness, sometimes a plan re-draw or a preemption change |
| `libafl` (primary) | LibAFL's own prioritization: its MaxMapFeedback admits fork points (snapshots) by their slice's feature map, and its stock `IndexesLenTimeMinimizerScheduler` over `StdWeightedScheduler` with `PowerSchedule::fast()` (AFLFast) picks one | the same operators |

```sh
DST_CMD=explore ./contrib/bedrock-dst/run.sh --workload-arg load=trie \
  --policy libafl --fresh-floor 0.25 --hours 8 --slice-secs 10 --out explore-out
bedrock-dst replay explore-out/timelines/000042
bedrock-dst minimize explore-out/timelines/000042 --k 4 --step-secs 10
POLICY=libafl HOURS=8 SHARDS=8 ./contrib/bedrock-dst/regressions/hunt.sh ...
```

Every timeline runs to its end in slices of `--slice-secs`. After each slice
the engine observes it: the workload's `progress` hook (`tempo-dst progress`:
the assertion records written since the previous call, its state kept in
the guest so forks continue it), the new lines of `/bedrock/events.jsonl`,
and pc-guard edge maps (`cov-*` feedback buffers) when the image has them.
Observations become features keyed by kind, name and epoch: the slice's
stretch of virtual time *and its phase* (kills and restarts seen, a fault
window open, derived from the events), so a signal first reached in a new
phase is novel: `S/x` satisfied Sometimes, `A/x` Always with an
AFL hitcount bucket of its evaluations (aggregate counts from PR #32 when
records carry them; Always and Sometimes never merge, contradictory counts
count as failing), near misses, `M/<source>/<kind>` moments, edges. A slice
boundary becomes a snapshot when the slice was novel or every
`--snapshot-every` slices; snapshots are taken right after the observation's
host actions answered, an exact halt point, and only when its state
fingerprint (phase, failing set, event kinds) is new: equivalent states are
not forked twice. `--fresh-floor` (default 0.25) forces that share of
timelines to start fresh from the World, so late-horizon breadth never
starves; every child runs to the end of the horizon.

Snapshots hold live CoW checkpoints under `--max-snapshot-mb` of private
pages (and `--max-live`); only leaves are evicted (least expanded, then least
recently used), and an evicted snapshot restores by re-executing its tape
from its nearest live ancestor. Policies never look at liveness, so the
search order is a pure function of `--engine-seed` and what timelines
observed; only `--hours` decides where it stops.

A timeline whose observations show a failing Always signature (other than
the `E1/error-log/*` noise class) is an objective: it is finalized
(end-of-run oracles: graceful stop, E4 re-execute), as is a deterministic
`--finalize-sample` fraction (default 15%) of the others; the rest are
judged on what they observed. Each objective gets a triage key (normalized
first failing signature + sorted failing set, noise excluded).

Output: `world.json`, `explore.json`, `runs.jsonl` (one line per timeline:
policy, parent snapshot, failures, triage key, engine totals),
`summary.json` (first hit and hit count per signature, triage keys, corpus
and memory stats), and `timelines/<n>/` timeline directories (each replays
with `replay`). `--shard i --shards N` partitions root plan seeds and salts
the engine seed (single-host shards, no shared corpus).

**`minimize <timeline>`** probes cuts every `--step-secs` up to the
objective's first failure: at each, `--k` children continue with fresh
randomness only. It probes the latest cut first (no child fails: the bug
needs the exact schedule) and binary-searches the earliest cut that still
reproduces, reporting hit rates; on a root timeline it then drops each
host decision (kills; the planner's typed `host_decisions`) while the run,
with the same per-consumer streams and preemption, still fails, tries
preemption off, and replays the minimized timeline. `minimize/minimize.json`
has the result.

## Task board

Ticked items exist in code and have unit tests. Claim a task by opening a
draft PR that names it.

### Prerequisites
- [x] **P1** Bare-metal host with a Rust-enabled 6.18 kernel and EPT-friendly PEBS
- [ ] **P2** First end-to-end smoke run: `run.sh --seeds 2 --run-secs 120`, then fix whatever breaks

### A: Driver (`tempoxyz/bedrock:crates/bedrock-dst`)
- [x] **A1** Boot, wait for `--warm-blocks`, warm checkpoint
- [x] **A2** Branch per seed, reseeding the in-VM PRNG (`Branch::reseed_rng`); deliver config; start oracle, nemesis, load; finalize; collect
- [x] **A3** Per-seed artifacts and `verdict.json` (Always failures deduped by signature, Sometimes coverage)
- [x] **A4** `replay <out>/seed-N` compares assertions, events, finalize and verdict byte-for-byte
- [ ] **A4b** Also compare exit-record streams (reuse `compare-traces.py`) for divergence localization
- [ ] **A5** Parallel seeds. A `Branch` is single-driver: shard seeds across processes, each booting its own prefix, or add multi-branch driving. Watch fork memory (oss-garage/bedrock#28)
- [x] **A6** Timelines: tape v2 (control actions), per-consumer randomness streams, `world.json` + `timeline.json`, one tape-only `replay`; explicit decisions only
- [ ] **A6b** Validate `replay` across loads and many seeds
- [x] **A6c** Branching from a moment of a recorded run: `bedrock-dst branch --at T --vary none|rng|decisions|both` (`PrefixSource`, `tempo-dst redecide`), `bedrock-dst moments`

### B: Crash faults
- [ ] **B1** Verify on host that the `tempo-data` volume survives `podman kill` + `start`
- [x] **B2** `tempo-dst nemesis`: seed-derived kill/restart plan, logged before each kill
- [x] **B3** Kill and restart events in `events.jsonl`
- [x] **B4** workload-monitor excuses nemesis SIGKILLs; panics and unexplained kills are still asserted
- [x] **B6** Storage faults (`storage_faults=true`): datadir on LazyFS; machine crashes discarding all or a subset of un-synced writes, torn writes; E11 durable history
- [ ] **B7** Bit corruption, `EIO`/`ENOSPC` and slow syncs; fault windows targeted at persistence (`Saving range of blocks`)
- [x] **B5** Process faults (`process_faults=true`): pause/resume, CPU throttling, graceful stop/start (`E4/stop-timeout`)
- [ ] **B5b** Kill-during-persistence targeting (kill right after a `Saving range of blocks` line)

### C: Schedules
- [x] **C1** Node wrapped in `thread-fuzz` (compose `entrypoint`)
- [ ] **C2** Measure perturbation: across seeds, how much do block timing and tx inclusion actually vary? Decides whether oss-garage/bedrock#20 is needed
- [ ] **C3** Confirm `replay` is identical with thread-fuzz on

### D: Workload
- [x] **D0** txgen load per branch (pathUSD transfers; load only, not an oracle)
- [ ] **D1** Spike: tuner (`tempoxyz/tuner`) `StructureTxGenerator` → serializable tx program
- [ ] **D2** Genesis/fixture mapping: tuner fixture EOAs to dev accounts (mnemonic `test … junk`)
- [ ] **D3** Lowering + in-guest submitter: resolve nonces at submit time, sign Tempo AA and EVM envelopes, record accepted/rejected/unknown
- [x] **D4** Trie-shaping load (`load=trie`): raw-storage writes over per-seed generated slot shapes and values, checked by E5 and E6
- [x] **D6** TIP-20 bank-transfer load (`load=tip20`): per-seed transfers among a closed set of holders of a fresh token, checked by E8
- [x] **D7** Chain-of-blocks load (`load=chain`): hash-chained appends from one sender, checked by E9
- [x] **D8** Zones load (`load=zones`): a zone sequencer and batch prover settling to the node, driven by txgen's zone-backing campaign, checked by E12
- [ ] **D8b** Zone-internal transfers (txgen's campaign only deposits and withdraws), withdrawal callbacks (`gasLimit > 0`), and a second token
- [ ] **D5** Coverage-guided mutation with tuner's mutator (needs G3)
- [ ] **D5** Coverage-guided mutation with tuner's mutator (needs G3)

### E: Oracles (`bin/tempo-dst`)
- [x] **E1** Log scanner over `journalctl CONTAINER_NAME=tempo` (survives restarts)
- [x] **E2** Liveness
- [x] **E3** Durability of finalized blocks across crash/restart (the `Saved range` frontier is not durable: reth unwinds to its state-trie frontier)
- [x] **E4** Graceful stop + trie repair dry run + `tempo re-execute`. Verify on host that `--chain dev` matches the dev node's chain spec (override with `TEMPO_DST_CHAIN`)
- [ ] **E4b** Independent state-root check: rebuild the trie from the final state, separate from the sparse trie
- [x] **E7** Reference-node differential oracle (`reference=true`): a vanilla-flags follower re-executes every block; logs, lag, header/state-root and proof answers compared (`bin/tempo-dst/src/reference.rs`)
- [ ] **E7b** First campaign with `reference=true`; then consider defaulting it on
- [x] **E8** TIP-20 ledger: conservation, per-block explanation by `Transfer` logs, pinned snapshots stable across persistence and restarts
- [ ] **E8b** Run `load=tip20` under Bedrock and tune the pin cadence and required coverage from real runs
- [x] **E9** Chain of blocks: receipts-rebuilt hash chain vs. state at every block, prefix/monotonic history, finalized entries and pinned history across restarts
- [x] **E12b** Multi-sequencer zones (`E12/zones-cluster-*`): no fork, one leader per term, L1 backfill, recovery/handoff after network faults, 2-of-3 settlement with a healthy quorum
- [x] **B6** Network nemesis: generic topology, partitions/cuts (iptables reset or drop), connection resets (`ss -K`), per-link netem, port scoping; zones families and leadership handoffs under faults
- [x] **E12** Zones: portal solvency at every L1 block, exactly-once withdrawals, batch order/commitments/settled-block durability, SPF replay of every batch, liveness
- [ ] **E5** Triage: tune `E1/error-log/*` noise from real runs and promote recurring targets to named signatures

### F: Negative controls (one per oracle, env-gated patches on Tempo `d3f3b28f`)
- [ ] **F1** Panic in a sparse-trie update → `E1/panic`
- [ ] **F2** Skip a persistence commit → `E3/*`
- [ ] **F3** Corrupt a receipt or state root that the producing node accepts → `E4/re-execute`
- [ ] **F4** Stall the engine after a restart → `E2/head-stalled`

### G: Variants and feedback
- [x] **G1** `run.sh --variant default|no-prewarm|parallel`
- [ ] **G1b** `bedrock_ncpus=1` vs 5 campaigns (pass `--cmdline`)
- [ ] **G2** Point the harness at upstream `reth --dev` so findings can go upstream directly
- [ ] **G3** sancov-instrumented Tempo build + `libpcguard` coverage collection per seed
- [x] **G4** Multiverse engine (`explore`): snapshot corpus, LibAFL power-scheduled fork points (feature `libafl`, primary) plus breadth/rarity arms, phase-keyed features, fresh-run floor, state-fingerprint dedupe; fork-late `minimize`

**Milestone:** a campaign of thousands of seeds per day on one host; F1 to F4
are each caught; every failing seed replays exactly.
