#!/usr/bin/env bash
# Builds the buggy and fixed node images for regression <name> (see README.md):
# bedrock/tempo-localnet:<name>-buggy and bedrock/tempo-localnet:<name>-fixed.
# One of them is the pinned image (bedrock/tempo-localnet:pinned), retagged:
#
# - RETH_REVERT=<commit>: a fix in the pinned reth. buggy = pinned reth with
#   the commit reverted; fixed = pinned.
# - RETH_PATCH=<file in the regression dir>: as RETH_REVERT, for fixes that no
#   longer revert cleanly; buggy = pinned reth with the patch applied.
# - RETH_FIX_PR=<number> RETH_FIX_HEAD=<commit>: an unmerged fix. buggy =
#   pinned; fixed = pinned reth with the PR's changes applied.
#
# BASE_TEMPO_PRS="<number>:<head commit> ..." applies unmerged Tempo fixes to
# both images the same way (e.g. tempo#8189 for bedrock#13).
#
# BASE_RETH_PRS="<number>:<head commit> ..." applies unmerged fixes for other
# bugs to BOTH images, so a known bug that shares this regression's signature
# can't fire on either side. Neither image is then the pinned one; both are
# built. BASE_RETH_PATCHES="<file in the entry dir> ..." does the same with
# patches.
#
# DEBUG_ASSERTIONS=1 builds with `-C debug-assertions=on`, enabling reth's and
# Tempo's internal debug_assert! invariants (trie, sparse trie, persistence);
# a violation panics and E1/panic reports it. It uses its own chef image.
#
# STRIP_DEBUG=1 strips debuginfo from the built node binaries (see strip_debug).
#
# An entry with only base fixes (no RETH_REVERT/RETH_PATCH/RETH_FIX_PR) builds
# one image, bedrock/tempo-localnet:<name>: e.g. known-fixes, the pinned node
# with every known bug fixed, for campaigns hunting new ones.
#
#   DOCKER='sudo docker' ./contrib/bedrock-dst/regressions/build.sh reth-27267
#
# The chef stage (all dependencies, ~17 GB) is built from unpatched reth once
# and shared by every regression; the final stage recompiles only the reverted
# reth crates and their dependents. CHEF_IMAGE overrides it with any cooked
# Tempo chef image at the same revisions.
set -euo pipefail
# Concurrent builds of the same images (parallel hunt.sh / run.sh) collide;
# serialize them host-wide.
exec 9>"${BUILD_LOCK:-/tmp/bedrock-dst-build.lock}"
flock 9
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tempo-tree.sh
. "$here/tempo-tree.sh"
name=${1:?usage: build.sh <regression>}
# shellcheck source=/dev/null
. "$here/$name/regression.env"
read -r -a docker <<<"${DOCKER:-docker}"
# Tempo and reth as in the pinned image (bedrock/tempo-localnet:pinned).
# Pins; an entry may override them (e.g. to build from fix or DST-profile PR
# heads based on newer upstream).
tempo_rev=${TEMPO_REV:-d3f3b28f102946dcdca1a5beb12f328f2f1bbdbd}
reth_rev=${RETH_REV:-42fa3c569ad182914d26db410919d6a10c7b4859}
# RUST_PROFILE / RUST_FEATURES: Tempo's Dockerfile build args (defaults
# profiling / asm-keccak,jemalloc,otlp), e.g. profile `dst` with feature `dst`
# from tempo#8198 (opt-level 3 + debug assertions + overflow checks).
profile=${RUST_PROFILE:-profiling}
features=${RUST_FEATURES:-asm-keccak,jemalloc,otlp}
rustflags=""
chef_suffix=""
if [ "${DEBUG_ASSERTIONS:-0}" = 1 ]; then
  rustflags="-C debug-assertions=on"
  chef_suffix="-debug-assertions"
fi
profile_suffix=""
[ "$profile" = profiling ] || profile_suffix="-$profile"
chef=${CHEF_IMAGE:-bedrock/tempo-chef:${tempo_rev:0:8}-${reth_rev:0:8}$profile_suffix$chef_suffix}

work=$(mktemp -d "${TMPDIR:-/tmp}/tempo-regression.XXXXXX")
trap 'rm -rf "$work"' EXIT
# Applies unmerged PR <number> at <head> of the repo at <dir> and commits it:
# only the PR's own commits (diffed from its merge-base with upstream main,
# which may be newer or older than our pin). Fails unless the tree changed.
apply_pr() {
  local dir=$1 label=$2 pr=$3 head=$4 before base
  local g=(git -C "$dir" -c user.name=regression -c user.email=regression@localhost)
  "${g[@]}" fetch -q origin main "pull/$pr/head"
  test "$("${g[@]}" rev-parse "$head^{commit}" 2>/dev/null)" = "$head" ||
    { echo "PR $label#$pr head $head not found" >&2; return 1; }
  base=$("${g[@]}" merge-base origin/main "$head")
  before=$("${g[@]}" rev-parse HEAD)
  "${g[@]}" diff "$base" "$head" | "${g[@]}" apply --index
  "${g[@]}" commit -q -m "apply $label#$pr at $head"
  test -n "$("${g[@]}" diff --name-only "$before" HEAD)"
  echo "applied $label#$pr: $("${g[@]}" diff --shortstat "$before" HEAD)"
}

tempo_tree_clone "$work/tempo" "$tempo_rev"
for base in ${BASE_TEMPO_PRS:-}; do
  apply_pr "$work/tempo" tempoxyz/tempo "${base%%:*}" "${base#*:}"
done
tempo_tree_local_reth "$work/tempo" "$reth_rev"

if ! "${docker[@]}" image inspect "$chef" >/dev/null 2>&1; then
  DOCKER_BUILDKIT=1 "${docker[@]}" build --target builder -f "$work/tempo/Dockerfile.chef" \
    --build-arg EXTRA_RUSTFLAGS="$rustflags" --build-arg RUST_PROFILE="$profile" \
    --build-arg RUST_FEATURES="$features" -t "$chef" "$work/tempo"
fi

reth=(git -C "$work/tempo/reth" -c user.name=regression -c user.email=regression@localhost)
for base in ${BASE_RETH_PRS:-}; do
  apply_pr "$work/tempo/reth" paradigmxyz/reth "${base%%:*}" "${base#*:}"
done
for patch in ${BASE_RETH_PATCHES:-}; do
  "${reth[@]}" apply --index "$here/$name/$patch"
  "${reth[@]}" commit -q -m "apply $patch"
  echo "applied $patch"
done

build() {
  local tag=$name${1:+-$1}
  DOCKER_BUILDKIT=1 "${docker[@]}" build --target tempo-localnet -f "$work/tempo/Dockerfile" \
    --build-arg CHEF_IMAGE="$chef" --build-arg EXTRA_RUSTFLAGS="$rustflags" \
    --build-arg RUST_PROFILE="$profile" --build-arg RUST_FEATURES="$features" \
    -t "bedrock/tempo-localnet:$tag" "$work/tempo"
  [ "${STRIP_DEBUG:-0}" = 1 ] && strip_debug "bedrock/tempo-localnet:$tag"
  echo "Built bedrock/tempo-localnet:$tag (reth $("${reth[@]}" log --oneline -1 | cut -c1-80))"
}
# STRIP_DEBUG=1 drops DWARF debuginfo (~1.1 GB) from the node binaries. The
# guest holds the image in RAM, so this sets the guest's memory floor. The
# symbol table stays (backtraces still name functions) and panic messages
# carry their own file:line.
strip_debug() {
  local image=$1 dir
  dir=$(mktemp -d)
  # Flat image: a layer on top of $image would keep the unstripped binaries
  # in the lower layer, and the guest loads every layer. Mirrors Tempo's
  # tempo-localnet stage (same base digest, ca-certificates, metadata).
  cat > "$dir/Dockerfile" <<DF
FROM $image AS src
FROM debian:bookworm-slim@sha256:4724b8cc51e33e398f0e2e15e18d5ec2851ff0c2280647e1310bc1642182655d AS strip
RUN apt-get update && apt-get install -y --no-install-recommends binutils && rm -rf /var/lib/apt/lists/*
COPY --from=src /usr/local/bin/tempo /usr/local/bin/tempo-localnet /out/
RUN strip --strip-debug /out/tempo /out/tempo-localnet
FROM debian:bookworm-slim@sha256:4724b8cc51e33e398f0e2e15e18d5ec2851ff0c2280647e1310bc1642182655d
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /data
COPY --from=strip /out/tempo /out/tempo-localnet /usr/local/bin/
EXPOSE 8545
VOLUME ["/data"]
HEALTHCHECK --interval=2s --timeout=2s --start-period=120s --retries=5 CMD ["/usr/local/bin/tempo-localnet", "--health"]
ENTRYPOINT ["/usr/local/bin/tempo-localnet"]
DF
  DOCKER_BUILDKIT=1 "${docker[@]}" build -q -t "$image" "$dir" >/dev/null
  rm -rf "$dir"
  echo "stripped debuginfo: $image ($("${docker[@]}" image inspect -f '{{.Size}}' "$image" | numfmt --to=iec))"
}
# The regression's other side: built from the same base when there is one,
# else the pinned image.
other() {
  if [ -n "${BASE_RETH_PRS:-}${BASE_RETH_PATCHES:-}${BASE_TEMPO_PRS:-}" ]; then
    "${reth[@]}" checkout -q "$1"
    build "$2"
  else
    if ! "${docker[@]}" image inspect bedrock/tempo-localnet:pinned >/dev/null 2>&1; then
      pinned=ghcr.io/tempoxyz/tempo-localnet@sha256:9ab8e4ffe86cd397106d7462657b41a2723374f2ed554d0aac3afb1b54f24aa6
      "${docker[@]}" pull "$pinned"
      "${docker[@]}" tag "$pinned" bedrock/tempo-localnet:pinned
    fi
    "${docker[@]}" tag bedrock/tempo-localnet:pinned "bedrock/tempo-localnet:$name-$2"
    echo "bedrock/tempo-localnet:$name-$2 is the pinned image"
  fi
}
base=$("${reth[@]}" rev-parse HEAD)
if [ -n "${RETH_REVERT:-}" ]; then
  "${reth[@]}" revert --no-edit "$RETH_REVERT"
  build buggy
  other "$base" fixed
elif [ -n "${RETH_PATCH:-}" ]; then
  "${reth[@]}" apply --index "$here/$name/$RETH_PATCH"
  "${reth[@]}" commit -q -m "regression $name"
  build buggy
  other "$base" fixed
elif [ -n "${RETH_FIX_PR:-}" ]; then
  apply_pr "$work/tempo/reth" paradigmxyz/reth "$RETH_FIX_PR" "$RETH_FIX_HEAD"
  build fixed
  other "$base" buggy
else
  build ""
fi
