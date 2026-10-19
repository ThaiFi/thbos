#!/usr/bin/env bash
# Convenience entry point; all VM lifecycle logic lives in Bedrock.
set -euo pipefail
: "${BEDROCK_ROOT:?Set BEDROCK_ROOT to a checkout of tempoxyz/bedrock}"
here=$(cd "$(dirname "$0")" && pwd)
prepare=()
while true; do
  case "${1:-}" in
    --variant|--node-image|--tempo-rev|--node-revisions|--txgen-rev)
      prepare+=("$1" "$2"); shift 2 ;;
    *) break ;;
  esac
done
prepare_json=$(python3 - "${prepare[@]}" <<'PY'
import json, sys
print(json.dumps(sys.argv[1:]))
PY
)
exec "$BEDROCK_ROOT/workloads/dst/run.sh" --harness "$here" \
  --prepare-args "$prepare_json" "$@"
