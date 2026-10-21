# THBOS — Thai Baht OS

**THBOS is a fork of [Tempo](https://github.com/tempoxyz/tempo) maintained by [ThaiFi](https://thaifi.com).** It is the node software for the ThaiFi chain (chain ID 17), built to power the **Thai Baht stablecoin** (pathUSD / THCFI — 1 THB = 1 token, 6 decimals).

We keep the fork as small as possible: everything except the base-fee schedule follows upstream Tempo. Protocol docs: [docs.tempo.xyz](https://docs.tempo.xyz/).

## What's different from upstream

One feature — an optional `thbosTime` genesis field that switches the T7 base-fee schedule (TIP-1067 mechanics unchanged):

- Before `thbosTime`: upstream values (floor 600,000,000 / cap 12,000,000,000 attodollars)
- From `thbosTime` onward: `THBOS_BASE_FEE_CAP` = 4,757,147,605,420 → floor = CAP/20 = 237,857,380,271 → a standard TIP-20 transfer (42,042 gas) costs **exactly 0.01 USD**
- Under congestion the base fee rises toward the cap (0.20 USD per transfer, 20×) and decays back to the floor automatically
- Because the switch is timestamp-gated in consensus, nodes can sync from genesis across it and operators can upgrade rolling — no coordinated stop

Everything else follows upstream Tempo.

## Images

Multi-arch (`linux/amd64`, `linux/arm64`), built from `main`:

```
ghcr.io/thaifi/thbos:v1.16.1-fee0.01
ghcr.io/thaifi/thbos:latest
```

Binaries are compiled with default x86-64 target flags (no AVX2 requirement — runs on older CPUs such as Intel Xeon X5650).

## ThaiFi chain (chain ID 17)

| | |
|---|---|
| RPC | https://rpc.thaifi.com |
| WS | wss://ws.thaifi.com |
| Explorer | https://exp.thaifi.com |
| Snapshots | https://snapshots.thaifi.com |
| Contracts / verify | https://contracts.thaifi.com |
| Fee token | pathUSD `0x20c0000000000000000000000000000000000000` (6 decimals) — gas is paid in the fee token, not ETH |
| Block time | 250 ms |

Operator docs (compose, genesis, snapshots): [github.com/ThaiFi/node](https://github.com/ThaiFi/node).

## License

Same as upstream Tempo.
