# Regressions: rediscovering known reth bugs

Each entry rebuilds the Tempo node with one historical reth fix undone (or, for
an unmerged fix, uses the pinned node as the buggy build and the fix as the
control), then runs the **generic** campaign on both with identical seeds. The
entry names no trigger: it reproduces when the ordinary load, faults and
oracles find the bug on their own, which is the claim worth making about the
harness. Hit rate over seeds is the measure.

```sh
DOCKER='sudo docker' ./contrib/bedrock-dst/regressions/run.sh reth-27267 --seeds 20 --run-secs 180
```

`<name>/regression.env`:

| Variable | Meaning |
|---|---|
| `RETH_REVERT` | Merged fix in the pinned reth; buggy = pinned with it reverted, fixed = pinned |
| `RETH_PATCH` | As `RETH_REVERT`, for fixes that no longer revert cleanly: a patch in the entry's directory |
| `RETH_FIX_PR`, `RETH_FIX_HEAD` | Unmerged fix; buggy = pinned, fixed = pinned with the PR applied |
| `BASE_RETH_PRS` | `"<pr>:<head> ..."`: unmerged fixes for other bugs, applied to both images so a known bug with the same signature can't fire on either side |
| `VARIANT` | `run.sh --variant` (node flags; part of the boot prefix) |
| `CAMPAIGN_ARGS` | Extra `bedrock-dst campaign` arguments (normally just the load, `--workload-arg load=trie`) |
| `EXPECT` | Signature prefix a buggy-image seed must fail with, and no fixed-image seed may |

`build.sh <name>` builds `bedrock/tempo-localnet:<name>-{buggy,fixed}` (Tempo
`d3f3b28f`, reth `42fa3c5`, every reth crate patched to a local checkout).

| Entry | Bug | Status |
|---|---|---|
| `reth-27267` | #27267: proof v2 emits inlined leaves as standalone proof nodes (`eth_getMultiProof`) | First run (pinned base, 8 seeds) inconclusive: #27615 hit both sides (1/8 each). Now on a #27615 base |
| `reth-26843` | #26843: proof v2 drops a clean sibling on branch collapse under a prefix set (historical `eth_getMultiProof`) | Defined, on a #27615 base; not run yet. Patch also reverts #27634 and rolls back four later proof v2 commits |
| `reth-27615` | #27615: range trie changesets miss nodes created and deleted while the trie frontier lags (historical proofs, disk unwinds) | **Reproduced generically** (8 seeds, `load=trie`, default flags): buggy (pinned) 6/8 seeds hit E5/*, fixed (pinned + PR) 0/8. First found organically by the generated load on the pinned node |
| `reth-23603` | #23603: RocksDB commits (storage v2: tx-hash and history indices) with `sync=false` while MDBX commits are synced; a machine crash keeps blocks whose lookups and history are gone (`storage_faults=true`, E11) | **Reproduced generically** (4 seeds, `storage_faults=true storage_fault_kinds=crash`, transfers load, 180 s): buggy 4/4 seeds hit E11/tx-lookup-missing, receipt-missing, history-account/storage-mismatch (and E4/re-execute); fixed (pinned) 0/4, all seeds pass. Same on LazyFS (`--memory-mb 3072`): buggy 4/4, fixed 0/4 |
| #27270 | Sparse-trie reuse across forks with identical state roots; publishing abandoned jobs' tries | Not defined: needs forks. Tempo disables the engine API, so this needs a fork driver |
| #27614 | Missing prefix invalidation for in-memory fork keys | Not defined: unreachable at the pin since #27634 (every overlay uses trie changesets); needs that reverted plus a fork driver. Not what the generated load hits: the reth unit test still fails with only #27614 applied and passes with only #27615's own changes |

#27615's branch is stacked on #27614's, so applying it (as `RETH_FIX_PR` or
in `BASE_RETH_PRS`) also brings #27614's `storage-overlay/src/builder.rs`
change. That change only affects the overlay path without trie changesets,
which is unused at the pin.
