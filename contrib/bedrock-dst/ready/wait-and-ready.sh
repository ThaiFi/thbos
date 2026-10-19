#!/bin/sh
# Waits until the node's head reaches block 1, signals ready, then idles: the
# lab owns the VM's lifetime.
rpc='{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'
until wget -qO- --header 'Content-Type: application/json' --post-data "$rpc" \
    http://127.0.0.1:8545 2>/dev/null | grep -q '"result":"0x[1-9a-f]'; do
  sleep 1
done
echo "tempo-dst: node producing blocks, signaling ready"
/usr/local/bin/bedrock-ready
exec sleep infinity
