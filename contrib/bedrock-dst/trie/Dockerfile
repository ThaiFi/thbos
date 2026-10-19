# Trie load: the txgen image plus the RawStorage artifact and its deploy specs
# (deploy.yaml for one contract, deploy-pool.yaml for the multi-contract pool;
# run before the warm checkpoint) and the multi-writer runner. tempo-dst
# generates each run's write specs and mounts them under /workload/trie/.
FROM bedrock/tempo-txgen:latest
COPY deploy.yaml deploy-pool.yaml raw-storage.json run-multi.sh /workload/trie/
# pathUSD's ABI (deploy-pool.yaml funds the extra writers with it).
RUN cp /workload/tip20.abi.json /workload/trie/
