# Tempo Fuzz Harness

A stateless Tempo block executor, built as a cdylib for differential fuzzing
and for replaying blocks taken from a node.

An input is a chain, a pre-state and blocks; the outcome is the receipts, the
resulting state, what changed, and which protocol invariants broke. The types
and their contracts are in [`tempo-fuzz-types`](../fuzz-types).

```bash
cargo build -p tempo-fuzz-harness --release
```

The library exports two C ABI functions, both bincode-encoded:

- `tempo_fuzz_execute_with_result_v1`: a `TempoHarnessInput` in, a
  `TempoHarnessOutcome` out.
- `tempo_fuzz_capabilities_v1`: the harness's `TempoHarnessCapabilities`, with
  its schema version and the hardforks it executes, so a runner that loads
  several revisions can generate inputs all of them support.

The pre-state is either the dev genesis plus fuzzed accounts, or an exact
state such as a block's pre-state from a node, where reading anything the
input does not list is reported instead of read as empty. A block header is
either a context the harness completes, or an RLP header executed as given.
