#!/bin/bash
set -euo pipefail
rpc=${TEMPO_RPC_URL:-http://127.0.0.1:8545}
count=${TXGEN_COUNT:-1000}
tps=${TXGEN_TPS:-100}
seed=${TXGEN_SEED:-99}
mkdir -p /results
finish() {
  status=$?
  echo "TXGEN_EXIT_STATUS=$status"
  if [ "${BEDROCK:-1}" = 1 ]; then
    if [ -f /results/report.json ]; then
      bedrock-file-store /results/report.json /tmp/tempo-workload/txgen-report.json || true
    fi
    if [ -f /results/transactions.ndjson ]; then
      bedrock-file-store /results/transactions.ndjson /tmp/tempo-workload/transactions.ndjson || true
    fi
    sleep 1
    bedrock-shutdown
  fi
}
trap finish EXIT
cpus=$(nproc)
echo "Txgen: reported CPUs=$cpus; count=$count; target_tps=$tps"
if [ "${BEDROCK:-1}" = 1 ]; then test "$cpus" = 5; fi
for attempt in $(seq 1 300); do
  chain=$(curl -fsS --max-time 5 -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' "$rpc" | jq -er '.result') && break
  sleep 1
done
test "${chain:-}" = 0x539
# Wait for the first produced block so setup is outside the benchmark window.
sleep 2
txgen-tempo generate -s "${TXGEN_SPEC:-/workload/workload.yaml}" -n "$count" --seed "$seed" --rpc "$rpc" \
  -o /results/transactions.ndjson
bench send -i /results/transactions.ndjson --rpc-url "$rpc" --tps "$tps" \
  --max-concurrent 16 --max-pending 200 --retries 0 \
  --timeout 10s --drain-timeout 30 --collect-latencies \
  --report json:/results/report.json
echo 'TXGEN_REPORT_SUMMARY:'
jq -c '{sent,success,failed,elapsed_secs,tps,success_rate,latency,run_stats,receipt_metrics,block_composition: .block_composition.summary}' /results/report.json
jq -e --argjson count "$count" '.sent == $count and .success == $count and .failed == 0 and .run_stats.total_txs >= $count and (.block_composition.summary.kinds | all(.reverted_tx_count == 0))' /results/report.json >/dev/null
echo 'TEMPO_TXGEN_PASS: all transactions admitted and included'
