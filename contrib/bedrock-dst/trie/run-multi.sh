#!/bin/bash
# Multi-sender trie load (S >= 2 writers; see bin/tempo-dst/src/trie_gen.rs).
# TXGEN_SPECS lists one generated spec per writer, each a single sequence
# from one sender, so each writer's writes keep their nonce order and land one
# per block. Generated separately (txgen draws mix entries with replacement, so
# one spec with several sequences could repeat one and skip another) and
# interleaved round-robin into one stream: bench send then runs the writers'
# sequences concurrently, so a block carries several writers' writes.
# TXGEN_COUNT is per writer; TXGEN_TPS is the total rate.
set -euo pipefail
rpc=${TEMPO_RPC_URL:-http://127.0.0.1:8545}
count=${TXGEN_COUNT:-1000}
tps=${TXGEN_TPS:-100}
seed=${TXGEN_SEED:-99}
mkdir -p /results
for attempt in $(seq 1 300); do
  chain=$(curl -fsS --max-time 5 -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' "$rpc" | jq -er '.result') && break
  sleep 1
done
test "${chain:-}" = 0x539
sleep 2
# Burst: TXGEN_BURST_SPECS holds one single-write spec per writer, each to a
# different contract. Sent back to back (no rate limit) and drained before the
# streams are generated (their nonces follow the burst's), so the generation's
# first block changes several contracts' storage roots.
if [ -n "${TXGEN_BURST_SPECS:-}" ]; then
  bursts=()
  i=0
  for spec in $TXGEN_BURST_SPECS; do
    txgen-tempo generate -s "$spec" -n 1 --seed "$seed" --rpc "$rpc" \
      -o "/results/burst-$i.ndjson"
    bursts+=("/results/burst-$i.ndjson")
    i=$((i + 1))
  done
  cat "${bursts[@]}" > /results/burst.ndjson
  bench send -i /results/burst.ndjson --rpc-url "$rpc" --tps 10000 \
    --max-concurrent 16 --max-pending 200 --retries 0 \
    --timeout 10s --drain-timeout 30 --report json:/results/burst-report.json
  echo 'TXGEN_BURST_SUMMARY:'
  jq -c '{sent,success,failed,run_stats}' /results/burst-report.json || true
fi
streams=()
i=0
for spec in $TXGEN_SPECS; do
  txgen-tempo generate -s "$spec" -n "$count" --seed "$seed" --rpc "$rpc" \
    -o "/results/transactions-$i.ndjson"
  streams+=("/results/transactions-$i.ndjson")
  i=$((i + 1))
done
paste -d '\n' "${streams[@]}" | grep -v '^$' > /results/transactions.ndjson
echo "Txgen: $i writers, $(wc -l < /results/transactions.ndjson) transactions; target_tps=$tps"
bench send -i /results/transactions.ndjson --rpc-url "$rpc" --tps "$tps" \
  --max-concurrent 16 --max-pending 200 --retries 0 \
  --timeout 10s --drain-timeout 30 --collect-latencies \
  --report json:/results/report.json
echo 'TXGEN_REPORT_SUMMARY:'
jq -c '{sent,success,failed,elapsed_secs,tps,success_rate,latency,run_stats,receipt_metrics,block_composition: .block_composition.summary}' /results/report.json
