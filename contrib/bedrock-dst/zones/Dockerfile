# syntax=docker/dockerfile:1
#
# Zones load (`--load zones`): one image for the zone sequencer, the batch
# prover and the deposit/withdrawal driver, so the guest holds their shared
# layers once.
#
# - tempo-zone (tempoxyz/zones): the zone node. With --sequencer it builds
#   zone blocks from finalized L1 blocks, signs each batch's
#   SettlementAttestation (EIP-712, sequencer key), submits it to the portal
#   (`submitBatch`), and processes withdrawals on L1.
# - tempo-zone-prover-utils (tempoxyz/zones): `generate-input --block` builds
#   a submitted batch's witness and replays it through the stateless proof
#   function (SPF), the code the Nitro enclave runs. The enclave's attestation
#   needs AWS Nitro hardware, so batches settle in the portal's NoProof mode
#   and the replay is the prover (see README "Zones load").
# - tempo-xtask (tempoxyz/zones): `create-zone` with a 3-sequencer, 2-of-3
#   settlement set and `set-encryption-key`, the operator path that
#   provisions the multi-sequencer zone (`zone_sequencers=3`,
#   zone-provision.sh).
# - txgen-tempo-property (tempoxyz/txgen fuzz/zones-property-generator): the
#   zone-backing property campaign (encrypted portal deposits, outbox
#   withdrawals, portal solvency audit).
#
# Release builds with debuginfo stripped (symbols kept), in a flat final
# stage: the guest holds the image in RAM. Pins: keep in sync with README.
ARG ZONES_REV=24a51dd432682596c55ba82186804f7af848fc81
ARG TXGEN_REV=0d62b7dbf14f338e0fc51750053d2cafe3d55bde

FROM rust:1.96-bookworm@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc AS zones
ARG ZONES_REV
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev build-essential clang libclang-dev mold git \
    && rm -rf /var/lib/apt/lists/*
# vergen reads git metadata, so build from a real checkout.
RUN git clone -q --filter=blob:none https://github.com/tempoxyz/zones.git /src \
    && git -C /src checkout -q --detach "$ZONES_REV"
WORKDIR /src
# A read-only `replay-witness` subcommand for tempo-zone-prover-utils: offline
# SPF replay of a saved witness JSON (no RPC, no settlement). The zones witness-
# fault family (`--workload-arg zones_witness_faults=true`) replays a mutated
# witness with it and checks the SPF rejects it. Not a production path.
COPY replay-witness.patch enable-transfers.patch /tmp/
# enable-transfers.patch lets user TIP-20 transfers run on the zone (upstream
# disables them during the permissioned phase) so the DST policy family can
# exercise TIP-403 enforcement and balance conservation; the policy itself is
# still the L1-inherited one. Not a production path.
RUN git -c user.name=bedrock -c user.email=bedrock@localhost apply --index /tmp/replay-witness.patch /tmp/enable-transfers.patch \
    && git -c user.name=bedrock -c user.email=bedrock@localhost commit -q -m "bedrock: prover-utils replay-witness + zone transfers"
ENV CARGO_PROFILE_RELEASE_STRIP=debuginfo CARGO_INCREMENTAL=0 CARGO_NET_GIT_FETCH_WITH_CLI=true
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=bedrock-zones-registry \
    --mount=type=cache,target=/usr/local/cargo/git,id=bedrock-zones-git \
    RUSTFLAGS="-C link-arg=-fuse-ld=mold" \
    cargo build --locked --release --bin tempo-zone --features jemalloc \
    && RUSTFLAGS="-C link-arg=-fuse-ld=mold" \
    cargo build --locked --release -p tempo-zone-prover-utils \
    && RUSTFLAGS="-C link-arg=-fuse-ld=mold" \
    cargo build --locked --release -p tempo-xtask \
    && mkdir /out && cp target/release/tempo-zone target/release/tempo-zone-prover-utils \
       target/release/tempo-xtask /out/

FROM rust:1.95.0-bookworm AS txgen
ARG TXGEN_REV
RUN apt-get update && apt-get install -y --no-install-recommends libfontconfig1-dev git \
    && rm -rf /var/lib/apt/lists/*
RUN git clone -q --filter=blob:none https://github.com/tempoxyz/txgen.git /src \
    && git -C /src checkout -q --detach "$TXGEN_REV"
WORKDIR /src
ENV CARGO_PROFILE_RELEASE_STRIP=debuginfo CARGO_NET_GIT_FETCH_WITH_CLI=true
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=bedrock-txgen-registry \
    --mount=type=cache,target=/usr/local/cargo/git,id=bedrock-txgen-git \
    cargo build --locked --release --bin txgen-tempo-property \
    && mkdir /out && cp target/release/txgen-tempo-property /out/

# `cast` for the policy driver (`policy.sh`): the same Foundry nightly the
# zones repo pins. It sends plain L1/zone transactions (create/edit a TIP-403
# policy, switch pathUSD's policy, zone transfers).
FROM debian:bookworm-slim AS foundry
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup --install nightly-fc14f674bd853bc817c308a5202faa5be8df05e7

# On the txgen load image (already in the images tar, so its layers are
# shared): its txgen runs the setup spec (deploy.yaml) during warmup.
FROM bedrock/tempo-txgen:latest
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 libfontconfig1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=bedrock/tempo-dst:latest /usr/local/bin/tempo-dst /usr/local/bin/tempo-dst
COPY --from=zones /out/ /usr/local/bin/
COPY --from=txgen /out/ /usr/local/bin/
COPY --from=foundry /root/.foundry/bin/cast /usr/local/bin/cast
COPY deploy.yaml tip403.abi.json /workload/zones/
COPY zone.sh policy.sh zone-multi.sh zone-provision.sh /usr/local/bin/
WORKDIR /data
ENTRYPOINT ["/bin/sh", "/usr/local/bin/zone.sh"]
