#!/bin/sh
# Multi-sequencer zone node `zone-N` (compose services zone-0..2,
# `zone_sequencers=3`): waits until the warmup hook has provisioned the zone
# (zone-provision.sh writes /shared), then runs `tempo-zone node` in
# multi-sequencer mode (`--sequencer.manifest`). Restarts (nemesis kills) rerun
# it on the same datadir.
#
# The node sits in its own network namespace on network zseq at 10.90.10.(11+N)
# and talks to its peers directly (Commonware P2P on 9200, the manifest's
# addresses); it reaches the host-network L1 WebSocket through `l1-forward`
# on the gateway, port 18600+N (keep in sync with zones_cluster.rs
# `topology()`).
set -u
N=$1
S=/shared
until [ -f "$S/provisioned" ]; do sleep 1; done
portal=$(sed -n 's/.*"portal": *"\(0x[0-9a-fA-F]*\)".*/\1/p' "$S/zone.json")
GW=10.90.10.1
EXTRA=""
[ "$N" != 0 ] && EXTRA="--deposit-decryption-keys-file $S/decryption.keys"
echo "zone-multi.sh: node $N (portal $portal)"
# shellcheck disable=SC2086
exec /usr/local/bin/tempo-zone node --chain "$S/genesis.json" \
  --l1.rpc-url "ws://$GW:$((18600 + N))" --l1.portal-address "$portal" \
  --http --http.addr 0.0.0.0 --http.port 9545 --http.api all \
  --ws --ws.addr 0.0.0.0 --ws.port 9546 --ws.api all \
  --port 9547 --redacted-rpc.port 8544 --authrpc.port 8553 \
  --datadir /data/node --log.file.directory /data/logs \
  --sequencer.manifest "$S/manifest-$N.toml" --p2p.key "$S/p2p-$N.key" \
  --secp256k1.key "$S/seq-$N.key" --sequencer-key-file "$S/seq-$N.key" \
  --p2p.listen 0.0.0.0:9200 \
  --disable-discovery --ipcdisable --color never $EXTRA
