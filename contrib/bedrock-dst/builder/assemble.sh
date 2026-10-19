#!/usr/bin/env bash
# Runs inside the build container. /workspace is the harness Tempo checkout, /cache survives runs,
# and /out is this campaign's input directory.
set -euo pipefail
exec 9>/cache/build.lock
flock 9
export HOME=/cache CARGO_HOME=/cache/cargo SCCACHE_DIR=/cache/sccache
export SCCACHE_CACHE_SIZE=${SCCACHE_CACHE_SIZE:-10G} RUSTC_WRAPPER=sccache CARGO_INCREMENTAL=0
mkdir -p "$CARGO_HOME" "$SCCACHE_DIR" /cache/target /cache/images /out

checkout() {
    local name=$1 url=$2 rev=$3 repo=/cache/git/$1 source=/cache/source/$1 sha
    if [ ! -d "$repo/.git" ]; then
        mkdir -p /cache/git /cache/source
        git clone -q --filter=blob:none "$url" "$repo"
    fi
    git -C "$repo" fetch -q --prune "$url" '+refs/heads/*:refs/remotes/origin/*' --tags
    if ! sha=$(git -C "$repo" rev-parse --verify "$rev^{commit}" 2>/dev/null); then
        git -C "$repo" fetch -q "$url" "$rev"
        sha=$(git -C "$repo" rev-parse --verify 'FETCH_HEAD^{commit}')
    fi
    if [ -d "$source" ]; then
        if [ "$(git -C "$source" rev-parse HEAD)" != "$sha" ]; then
            git -C "$source" checkout -q --detach --force "$sha"
        fi
    else
        git -C "$repo" worktree add -q --detach "$source" "$sha"
    fi
    printf '%s\n' "$sha"
}

IFS=, read -r -a tempo_refs <<< "${TEMPO_REVISIONS:-${TEMPO_REV:-origin/main}}"
tempo_shas=()
for ref in "${tempo_refs[@]}"; do
    tempo_shas+=("$(checkout tempo https://github.com/tempoxyz/tempo.git "$ref")")
done
tempo_sha=${tempo_shas[0]}
txgen_sha=$(checkout txgen https://github.com/tempoxyz/txgen.git "${TXGEN_REV:-origin/main}")
tempo_revs=$(IFS=,; echo "${tempo_shas[*]}")
printf 'tempo_rev=%s\ntempo_revs=%s\ntxgen_rev=%s\n' "$tempo_sha" "$tempo_revs" "$txgen_sha" > /out/build-info.env
for sha in "${tempo_shas[@]}"; do
    printf 'bedrock/tempo-runtime:rev-%s\n' "${sha:0:12}"
done | awk '!seen[$0]++' > /out/node-images

cargo_jobs=$(( $(nproc) / 4 ))
export CARGO_BUILD_JOBS=$(( cargo_jobs > 0 ? cargo_jobs : 1 ))
stage=$(mktemp -d /cache/stage.XXXXXX)
trap 'rm -rf "$stage"' EXIT
pids=()
(
    export CARGO_TARGET_DIR=/cache/target/tempo-dst-musl
    RUSTFLAGS='-C target-feature=+crt-static' \
        cargo build --manifest-path /workspace/Cargo.toml --locked --profile profiling \
        --target x86_64-unknown-linux-musl -p tempo-dst >&2
    if readelf -l "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/profiling/tempo-dst" | grep -q INTERP; then
        echo 'tempo-dst must be static for the guest host namespace' >&2
        exit 1
    fi
    install -m 755 "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/profiling/tempo-dst" /out/tempo-dst
) & pids+=($!)
(
    export CARGO_TARGET_DIR=/cache/target/tempo
    for sha in "${tempo_shas[@]}"; do
        [ -s "$stage/tempo-${sha:0:12}/tempo" ] && continue
        checkout tempo https://github.com/tempoxyz/tempo.git "$sha" >/dev/null
        RUSTFLAGS='-C link-arg=-fuse-ld=mold -C debug-assertions=on -C overflow-checks=on' \
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=clang \
            cargo build --manifest-path /cache/source/tempo/Cargo.toml --locked \
            --profile profiling --bin tempo --features asm-keccak,jemalloc,otlp,localnet,dst >&2
        mkdir -p "$stage/tempo-${sha:0:12}"
        install -m 755 "$CARGO_TARGET_DIR/profiling/tempo" "$stage/tempo-${sha:0:12}/tempo"
        strip --strip-debug "$stage/tempo-${sha:0:12}/tempo"
    done
    if [ "${TEMPO_DST_VALIDATORS:-1}" -gt 1 ] || [ "${TEMPO_DST_CONSENSUS:-0}" = 1 ]; then
        checkout tempo https://github.com/tempoxyz/tempo.git "$tempo_sha" >/dev/null
        (
            git -C /cache/source/tempo apply /workspace/contrib/bedrock-dst/validators/xtask-signing-key-hex.patch
            trap 'git -C /cache/source/tempo apply -R /workspace/contrib/bedrock-dst/validators/xtask-signing-key-hex.patch' EXIT
            RUSTFLAGS='-C link-arg=-fuse-ld=mold -C debug-assertions=on -C overflow-checks=on' \
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=clang \
                cargo build --manifest-path /cache/source/tempo/Cargo.toml --locked \
                --profile profiling --bin tempo-xtask >&2
            install -m 755 "$CARGO_TARGET_DIR/profiling/tempo-xtask" /out/tempo-xtask
        )
    fi
) & pids+=($!)
(
    export CARGO_TARGET_DIR=/cache/target/txgen
    cargo build --manifest-path /cache/source/txgen/Cargo.toml --locked --release \
        --bin txgen-tempo --bin bench >&2
) & pids+=($!)
failed=0
for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
[ "$failed" = 0 ] || exit 1

mkdir -p "$stage"/{tempo-dst,ready,txgen}
install -m 755 /out/tempo-dst "$stage/tempo-dst/tempo-dst"
strip --strip-debug "$stage/tempo-dst/tempo-dst"
sccache gcc -O2 -I/workspace/contrib/bedrock-dst/ready -c \
    /workspace/contrib/bedrock-dst/ready/ready.c -o "$stage/ready/ready.o"
gcc -static "$stage/ready/ready.o" -o "$stage/ready/bedrock-ready"
rm "$stage/ready/ready.o"
cp /workspace/contrib/bedrock-dst/ready/wait-and-ready.sh "$stage/ready/"
install -m 755 /cache/target/txgen/release/txgen-tempo "$stage/txgen/txgen-tempo"
install -m 755 /cache/target/txgen/release/bench "$stage/txgen/bench"
cp /workspace/contrib/bedrock-dst/txgen/{run.sh,workload.yaml,tip20.abi.json} "$stage/txgen/"

images=/workspace/contrib/bedrock-dst/builder/images
key=$({
    (cd "$stage" && find . -type f -print0 | sort -z | xargs -0 sha256sum)
    for file in "$images"/*/Dockerfile /workspace/contrib/bedrock-dst/{trie,tip20,chain,statemix}/*; do
        sha256sum "$file"
    done
} | sha256sum | cut -d' ' -f1)
archive=/cache/images/$key.tar
if [ ! -s "$archive" ]; then
    pids=()
    while read -r image; do
        docker build -q -t "$image" -f "$images/tempo/Dockerfile" "$stage/tempo-${image##*rev-}" >&2 & pids+=($!)
    done < /out/node-images
    docker build -q -t bedrock/tempo-dst:latest -f "$images/tempo-dst/Dockerfile" "$stage/tempo-dst" >&2 & pids+=($!)
    docker build -q -t bedrock/tempo-dst-ready:latest -f "$images/ready/Dockerfile" "$stage/ready" >&2 & pids+=($!)
    docker build -q -t bedrock/tempo-txgen:latest -f "$images/txgen/Dockerfile" "$stage/txgen" >&2 & pids+=($!)
    for kind in trie tip20 chain statemix; do
        docker build -q -t "bedrock/tempo-dst-$kind:latest" \
            "/workspace/contrib/bedrock-dst/$kind" >&2 & pids+=($!)
    done
    failed=0
    for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
    [ "$failed" = 0 ] || exit 1
    mapfile -t node_images < /out/node-images
    docker save "${node_images[@]}" bedrock/tempo-dst:latest \
        bedrock/tempo-dst-ready:latest bedrock/tempo-txgen:latest \
        bedrock/tempo-dst-trie:latest bedrock/tempo-dst-tip20:latest \
        bedrock/tempo-dst-chain:latest bedrock/tempo-dst-statemix:latest > "$archive.tmp"
    mv "$archive.tmp" "$archive"
else
    docker load -i "$archive" >&2
fi
printf '%s\n' "$key"
