# Chain-of-blocks load: the txgen image plus the ChainOfBlocks artifact and its
# deploy spec (deploy.yaml, run before the warm checkpoint). tempo-dst
# generates each run's append spec and mounts it at
# /workload/chain/generated.yaml.
FROM bedrock/tempo-txgen:latest
COPY deploy.yaml chain-of-blocks.json /workload/chain/
