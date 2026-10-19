#!/usr/bin/env bash
# Adds one deterministic validator genesis and key set to each Tempo image.
set -euo pipefail
read -r -a docker <<<"${DOCKER:-docker}"
run_dir=${VALIDATOR_RUN_DIR:?set VALIDATOR_RUN_DIR to the prepared input directory}
count=${VALIDATOR_COUNT:?set VALIDATOR_COUNT}
(( count >= 1 && count <= 20 )) || { echo 'VALIDATOR_COUNT must be 1-20' >&2; exit 1; }
(( $# > 0 )) || { echo 'pass at least one node image' >&2; exit 1; }
work=$(mktemp -d "${TMPDIR:-/tmp}/tempo-validators.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/ctx"
validators=()
for ((i=1; i<=count; i++)); do
  validators+=("10.89.77.$((10+i)):8000")
done
validator_csv=$(IFS=,; echo "${validators[*]}")
"${docker[@]}" run --rm --user "$(id -u):$(id -g)" \
  -v "$run_dir:/inputs:ro" -v "$work/ctx:/out" \
  --entrypoint /inputs/tempo-xtask bedrock/dst-builder:rust1.96-musl-sccache0.14 \
  generate-localnet --output /out/net --seed 0 --accounts 64 \
  --epoch-length 100 --validators "$validator_csv" > "$work/generate.log" 2>&1 ||
  { cat "$work/generate.log" >&2; exit 1; }
if [ "${VALIDATOR_ZONES:-0}" = 1 ]; then
  python3 "$(dirname "$0")/zones-genesis.py" "$work/ctx/net/genesis.json"
fi
rm -f "$work"/ctx/net/*/signing.key
peers=()
for ((i=1; i<=count; i++)); do
  ip="10.89.77.$((10+i))"
  identity=$(cat "$work/ctx/net/$ip:8000/enode.identity")
  peers+=("enode://$identity@$ip:8001")
done
(IFS=,; echo "${peers[*]}") > "$run_dir/validator-peers"
for node_image in "$@"; do
  tag="bedrock/tempo-validators:$count-${node_image##*:}"
  cat > "$work/ctx/Dockerfile" <<DF
FROM $node_image
COPY net /net
LABEL org.bedrock.validators.node-image="$node_image"
DF
  DOCKER_BUILDKIT=1 "${docker[@]}" build -q -t "$tag" "$work/ctx" >/dev/null
  echo "Built $tag" >&2
done
