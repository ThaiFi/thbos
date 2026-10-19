FROM rust:1.96-bookworm@sha256:19817ead3289c8c631c73df281e18b59b172f6a31f4f563290f69cddd06c30e9
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev libfontconfig1-dev build-essential clang libclang-dev \
    mold musl-tools docker.io git python3 \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo install sccache --version 0.14.0 --locked
COPY assemble.sh /usr/local/bin/assemble-tempo-dst
ENTRYPOINT ["/usr/local/bin/assemble-tempo-dst"]
