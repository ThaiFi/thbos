# State-mix load: the txgen image plus the Mutator artifact and its deploy spec
# (deploy.yaml, run before the warm checkpoint). tempo-dst generates each run's
# mutation spec (statemix_gen) and mounts it under /workload/statemix/.
FROM bedrock/tempo-txgen:latest
COPY deploy.yaml mutator.json /workload/statemix/
