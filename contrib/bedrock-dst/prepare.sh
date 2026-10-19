#!/usr/bin/env bash
# Prepare Tempo images, planner and topology for the generic Bedrock runner.
set -euo pipefail
cd "$(dirname "$0")/../.."
variant=default
node_image=
node_revisions=origin/main
txgen_rev=origin/main
config=
while true; do
  case "${1:-}" in
    --variant) variant=$2; shift 2 ;;
    --node-image) node_image=$2; shift 2 ;;
    --tempo-rev|--node-revisions) node_revisions=$2; shift 2 ;;
    --txgen-rev) txgen_rev=$2; shift 2 ;;
    --workload-config) config=$2; shift 2 ;;
    "") break ;;
    *) echo "Unknown preparation argument: $1" >&2; exit 1 ;;
  esac
done
root=contrib/bedrock-dst
mkdir -p "${RUN_DIR:-$root}"
run_dir=$(cd "${RUN_DIR:-$root}" && pwd)
read -r validator_count cluster_mode zones_mode < <(python3 - "$config" <<'PY'
import json, sys
args = json.load(open(sys.argv[1])) if sys.argv[1] else {}
zones = args.get("load") == "zones"
count = 4 if zones else int(args.get("validators", 1))
if zones and (str(args.get("reference", False)).lower() == "true" or int(args.get("validators", 1)) != 1 or str(args.get("consensus", False)).lower() == "true"):
    sys.exit("load=zones owns four upstream validators and a certified follower; omit validators, consensus and reference")
if not 1 <= count <= 20:
    sys.exit(f"validators={count}: expected 1-20")
print(count, int(count > 1 or str(args.get("consensus", False)).lower() == "true"), int(zones))
PY
)
node_revisions=$(python3 - "$node_revisions" "$validator_count" <<'PY'
import sys
refs = [ref.strip() for ref in sys.argv[1].split(',')]
count = int(sys.argv[2])
if any(not ref for ref in refs) or len(refs) > count:
    sys.exit('node_revisions must contain 1 to validators nonempty revisions')
print(','.join(refs))
PY
)
cache=${TEMPO_BUILD_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/bedrock-tempo-dst}
mkdir -p "$cache"
cache=$(cd "$cache" && pwd)
read -r -a docker <<<"${DOCKER:-docker}"
"${docker[@]}" build -q -t bedrock/dst-builder:rust1.96-musl-sccache0.14 "$root/builder" >&2
socket=${DOCKER_SOCKET:-/var/run/docker.sock}
key=$("${docker[@]}" run --rm --user "$(id -u):$(id -g)" \
  --group-add "$(stat -c %g "$socket")" \
  --mount "type=bind,src=$socket,dst=/var/run/docker.sock" \
  --mount "type=bind,src=$PWD,dst=/workspace,readonly" \
  --mount "type=bind,src=$cache,dst=/cache" \
  --mount "type=bind,src=$run_dir,dst=/out" \
  -e TEMPO_REVISIONS="$node_revisions" -e TXGEN_REV="$txgen_rev" \
  -e TEMPO_DST_VALIDATORS="$validator_count" -e TEMPO_DST_CONSENSUS="$cluster_mode" \
  -e SCCACHE_CACHE_SIZE="${SCCACHE_CACHE_SIZE:-10G}" \
  bedrock/dst-builder:rust1.96-musl-sccache0.14)
images=${IMAGES:-$cache/images/$key.tar}
source "$run_dir/build-info.env"
node_image=${node_image:-bedrock/tempo-runtime:rev-${tempo_rev:0:12}}
mapfile -t node_images < "$run_dir/node-images"
if [ "$cluster_mode" = 1 ] && [ -z "${IMAGES:-}" ]; then
  VALIDATOR_RUN_DIR="$run_dir" VALIDATOR_COUNT="$validator_count" VALIDATOR_ZONES="$zones_mode" \
    DOCKER="${DOCKER:-docker}" "$root/validators/build.sh" "${node_images[@]}" >&2
fi
# Render from the same resolved settings delivered to the planner and guest.
python3 "$root/render-compose.py" "$variant" "$node_image" "$run_dir" "$validator_count" "$cluster_mode" "$config"
if [ -z "${IMAGES:-}" ]; then
  extra=()
  if grep -q 'image: bedrock/tempo-dst-zones:latest' "$run_dir/compose-run.yaml"; then
    DOCKER_BUILDKIT=1 "${docker[@]}" build -q -t bedrock/tempo-dst-zones:latest "$root/zones" >&2
    extra+=(bedrock/tempo-dst-zones:latest)
  fi
  if grep -q 'image: bedrock/tempo-validators:' "$run_dir/compose-run.yaml"; then
    for image in "${node_images[@]}"; do
      extra+=("bedrock/tempo-validators:$validator_count-${image##*:}")
    done
  fi
  if [ ${#extra[@]} -gt 0 ]; then
    images="$run_dir/images.tar"
    "${docker[@]}" save "${node_images[@]}" bedrock/tempo-dst:latest \
      bedrock/tempo-txgen:latest bedrock/tempo-dst-ready:latest \
      bedrock/tempo-dst-trie:latest bedrock/tempo-dst-tip20:latest \
      bedrock/tempo-dst-chain:latest bedrock/tempo-dst-statemix:latest \
      "${extra[@]}" > "$images.tmp"
    mv "$images.tmp" "$images"
  fi
fi
printf '%s\n' "$images" > "$run_dir/images.path"
