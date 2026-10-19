#!/bin/sh
# Zone sequencer (compose service `zone`, `--load zones`). The first start
# provisions a fresh zone against the certified Tempo L1 follower (`tempo-zone dev`:
# ZoneFactory.createZone from dev account 0, the factory owner in the generated consensus
# genesis, then setSequencerEncryptionKey and an L1-anchored zone genesis) and
# runs the node; restarts (nemesis kills) rerun the node on the same datadir.
# Runs during warmup, before the warm checkpoint, so every branch starts with
# the zone in place: zone 1, portal 0x5ad0000000000000000000000000000000000001.
#
# Ports (host network): HTTP 9545, WS 9546, P2P 9547, redacted RPC 8544,
# auth RPC 8553 (the L1 has 8551).
set -u
D=/data/zone
L1=ws://127.0.0.1:8546
# Not reth defaults that collide with the L1 in the shared host network.
EXTRA="--authrpc.port 8553 --disable-discovery --ipcdisable --color never"
while true; do
  if [ -f "$D/zone.json" ]; then
    portal=$(sed -n 's/.*"portal": *"\(0x[0-9a-fA-F]*\)".*/\1/p' "$D/zone.json")
    echo "zone.sh: restarting zone node (portal $portal)"
    # shellcheck disable=SC2086
    exec /usr/local/bin/tempo-zone node --chain "$D/genesis.json" \
      --l1.rpc-url "$L1" --l1.portal-address "$portal" \
      --http --http.addr 127.0.0.1 --http.port 9545 --http.api all \
      --ws --ws.addr 127.0.0.1 --ws.port 9546 --ws.api all \
      --port 9547 --redacted-rpc.port 8544 \
      --datadir "$D/node" --log.file.directory "$D/logs" \
      --sequencer --sequencer-key-file "$D/sequencer.key" $EXTRA
  fi
  # A provisioning attempt that died before writing zone.json leaves a
  # datadir `dev` refuses to wipe.
  rm -rf "$D"
  echo "zone.sh: provisioning zone"
  # shellcheck disable=SC2086
  /usr/local/bin/tempo-zone dev --l1.rpc-url "$L1" --datadir "$D" \
    --http.addr 127.0.0.1 --http.port 9545 --redacted-rpc.port 8544 -- $EXTRA
  echo "zone.sh: tempo-zone dev exited ($?), retrying"
  sleep 2
done
