# TIP-20 load: the txgen image plus the token's ABI and its deploy spec
# (deploy.yaml, run before the warm checkpoint). tempo-dst generates each
# run's transfer spec and mounts it at /workload/tip20/generated.yaml.
FROM bedrock/tempo-txgen:latest
COPY deploy.yaml tip20.abi.json /workload/tip20/
