FROM bedrock/tempo-check:latest AS helpers
FROM ghcr.io/tempoxyz/txgen@sha256:5a13376e67209c218375ec42ae21e83dfca2998491b2c83292a0c722f4a96fbf
RUN apt-get update && apt-get install -y --no-install-recommends curl jq && rm -rf /var/lib/apt/lists/*
COPY --from=helpers /usr/local/bin/bedrock-shutdown /usr/local/bin/
COPY bedrock-file-store /usr/local/bin/
COPY workload.yaml tip20.abi.json /workload/
COPY run.sh /workload/run.sh
ENTRYPOINT ["/bin/bash", "/workload/run.sh"]
