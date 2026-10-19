#!/usr/bin/env bash
# Hunts for new bugs on the known-fixes node (see known-fixes/regression.env):
# builds the images, then launches SHARDS processes, every shard its own boot.
# Failures on this image are novel-bug candidates.
#
#   DOCKER='sudo docker' SHARDS=8 SEEDS=25 ./contrib/bedrock-dst/regressions/hunt.sh \
#     [--variant masking] [bedrock-dst campaign args, e.g.
#      --workload-arg load=trie --run-secs 180]
#
# Without POLICY each shard is a campaign of SEEDS seeds. With POLICY (e.g.
# breadth=0.3,rarity=0.7) each shard is `bedrock-dst explore --shard i
# --shards SHARDS` (the multiverse engine) for HOURS hours or TIMELINES
# timelines.
#
# Every load's image (trie, tip20, chain) is in the shards' images tar, so any
# `--workload-arg load=...` works; the zones image (~210 MB beyond txgen) is
# added only with `--workload-arg load=zones`. `--workload-arg reference=true`
# adds the E7 reference node, which runs the known-fixes image too.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
read -r -a docker <<<"${DOCKER:-docker}"
out=${OUT:-$PWD/hunt-$(date +%Y%m%d-%H%M%S)}
shards=${SHARDS:-8} seeds=${SEEDS:-25} start=${SEED_START:-0}
variant=default
if [ "${1:-}" = --variant ]; then variant=$2; shift 2; fi
# NODE: the regressions/ entry whose image to hunt on (e.g. known-fixes-debug).
node=${NODE:-known-fixes}
image=bedrock/tempo-localnet:$node
mkdir -p "$out"
# Builds log to $out/build.log; a failure stops the hunt with a pointer to it.
build_failed() { echo "hunt: image build failed; see $out/build.log" >&2; exit 1; }
"${docker[@]}" image inspect "$image" >/dev/null 2>&1 ||
  "$here/build.sh" "$node" >>"$out/build.log" 2>&1 || build_failed
DOCKER="${DOCKER:-docker}" RUN_DIR="$out/inputs" "$here/../run.sh" --prepare-only --workload-arg validators=1 --workload-arg consensus=false \
  >>"$out/build.log" 2>&1 || build_failed
extra=()
prev=
for arg in "$@"; do
  case "$prev/$arg" in
    --workload-arg/load=zones | */--workload-arg=load=zones) extra=(bedrock/tempo-dst-zones:latest) ;;
  esac
  prev=$arg
done
if [ ${#extra[@]} -gt 0 ]; then
  DOCKER_BUILDKIT=1 "${docker[@]}" build -t "${extra[0]}" "$here/../zones" \
    >>"$out/build.log" 2>&1 || build_failed
fi
"${docker[@]}" save "$image" bedrock/tempo-dst:latest \
  bedrock/tempo-txgen:latest bedrock/tempo-dst-ready:latest \
  bedrock/tempo-dst-trie:latest bedrock/tempo-dst-tip20:latest \
  bedrock/tempo-dst-chain:latest "${extra[@]}" > "$out/images.tar"
for i in $(seq 0 $((shards - 1))); do
  if [ -n "${POLICY:-}" ]; then
    DST_CMD=explore RUN_DIR="$out/shard-$i-inputs" IMAGES="$out/images.tar" "$here/../run.sh" \
      --variant "$variant" --node-image "$image" --workload-arg validators=1 --workload-arg consensus=false --seed-start "$start" --shard "$i" --shards "$shards" \
      --policy "$POLICY" ${HOURS:+--hours "$HOURS"} ${TIMELINES:+--timelines "$TIMELINES"} \
      --out "$out/shard-$i" "$@" > "$out/shard-$i.log" 2>&1 &
  else
    first=$((start + i * seeds))
    RUN_DIR="$out/shard-$i-inputs" IMAGES="$out/images.tar" "$here/../run.sh" --variant "$variant" --node-image "$image" --workload-arg validators=1 --workload-arg consensus=false \
      --seed-start "$first" --seeds "$seeds" --out "$out/shard-$i" "$@" > "$out/shard-$i.log" 2>&1 &
  fi
done
wait || true
python3 - "$out" <<'PY'
import collections, json, pathlib, sys
out = pathlib.Path(sys.argv[1])
by_sig, total = collections.defaultdict(list), 0
# (feature, value) -> [seeds, failed], from each seed's swarm record.
by_feature = collections.defaultdict(lambda: [0, 0])
def runs():
    """(name, failures, pass, swarm) of every finished run."""
    for summary in sorted(out.glob("shard-*/summary.json")):
        for seed, v in json.loads(summary.read_text()).get("seeds", {}).items():
            yield f"{summary.parent.name}/seed-{seed}", v.get("failures", []), v.get("pass", False), v.get("swarm")
    for runs_file in sorted(out.glob("shard-*/runs.jsonl")):
        for line in runs_file.read_text().splitlines():
            r = json.loads(line)
            yield f"{runs_file.parent.name}/{r['dir'].rsplit('/', 1)[-1]}", r["failures"], r["pass"], None
for name, failures, passed, swarm in runs():
        total += 1
        for sig in failures:
            by_sig[sig].append(name)
        swarm = swarm or {}
        features = {"preempt.period": (swarm.get("preempt") or {}).get("period")}
        features.update({k: swarm.get(k) for k in ("load", "reference", "nemesis")})
        for k, val in features.items():
            if val is not None:
                by_feature[(k, val)][0] += 1
                by_feature[(k, val)][1] += not passed
print(f"{total} seeds; {len(by_sig)} failing signatures")
for sig, seeds in sorted(by_sig.items(), key=lambda kv: -len(kv[1])):
    print(f"{len(seeds):4d}  {sig}  e.g. {', '.join(seeds[:3])}")
if by_feature:
    print("failed/seeds by swarm feature:")
    for (k, val), (n, failed) in sorted(by_feature.items(), key=lambda kv: str(kv[0])):
        print(f"  {k}={val}: {failed}/{n}")
PY
