#!/bin/sh
# Provisions the multi-sequencer zone (`zone_sequencers=3`) on the local Tempo
# certified L1 follower, the operator way: `tempo-xtask create-zone` with three sequencers and
# a 2-of-3 settlement threshold (the first is the bootstrap leader), then
# `set-encryption-key`. Writes everything the sequencers need to /shared
# (the guest's /bedrock/zone-shared, bind-mounted into every zone-N):
# genesis.json, zone.json, per-node manifest, Ed25519 P2P key and individual
# secp256k1 key, the shared decryption key file, and finally `provisioned`.
#
# Run once by the warmup hook (`tempo-dst warmup`, before the warm checkpoint)
# from a host-network container; idempotent (does nothing once provisioned).
#
# Keys are fixed (deterministic runs; never real funds): individual sequencer
# keys are dev accounts 5, 6, 7 of the `test ... junk` mnemonic (pathUSD-funded by
# the generated consensus genesis, so they pay their own settlement and setLeader gas), the portal admin and ZoneFactory owner is dev account 0, and the
# portal's deposit encryption key is node 0's individual key (the zones e2e
# fixture's choice); nodes 1 and 2 load it as an extra decryption key.
#
# Topology (keep in sync with bin/tempo-dst/src/zones_cluster.rs
# `topology()`): node i is 10.90.10.(11+i) on network zseq, Commonware P2P on
# 9200; it reaches the L1 WebSocket through `l1-forward` on the gateway
# 10.90.10.1, port 18600+i.
set -eu
S=/shared
L1_HTTP=http://127.0.0.1:8545
[ -f "$S/provisioned" ] && { echo "zone-provision: already provisioned"; exit 0; }
mkdir -p "$S"
DEV0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ADMIN=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEYS="0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba 0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e 0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356"
ADDRS="0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc 0x976EA74026E726554dB657fA54763abd0C3a0aa9 0x14dC79964da2C08b23698B3D3cc7Ca32193d9955"
P2P_KEYS="0x1111111111111111111111111111111111111111111111111111111111111111 0x2222222222222222222222222222222222222222222222222222222222222222 0x3333333333333333333333333333333333333333333333333333333333333333"
P2P_PUBS="0xd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737 0xa09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0 0x17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"
nth() { echo "$2" | tr ' ' '\n' | sed -n "$(($1 + 1))p"; }

rm -rf "$S/xtask"
seqs=""
for a in $ADDRS; do seqs="$seqs --sequencer $a"; done
# shellcheck disable=SC2086
ZONE_FACTORY_OWNER_KEY=$DEV0 tempo-xtask create-zone --output "$S/xtask" \
  --l1-rpc-url "$L1_HTTP" --zone-factory 0x5aF2000000000000000000000000000000000000 \
  $seqs --threshold 2 --admin "$ADMIN" --rpc-url http://10.90.10.11:9545
portal=$(sed -n 's/.*"portal": *"\(0x[0-9a-fA-F]*\)".*/\1/p' "$S/xtask/zone.json")
zone_id=$(sed -n 's/.*"zoneId": *\([0-9]*\).*/\1/p' "$S/xtask/zone.json")
echo "zone-provision: zone $zone_id portal $portal"
PRIVATE_KEY=$(nth 0 "$KEYS") TRANSACTION_PRIVATE_KEY=$(nth 0 "$KEYS") \
  tempo-xtask set-encryption-key --l1-rpc-url "$L1_HTTP" --portal "$portal"
cp "$S/xtask/genesis.json" "$S/genesis.json"
cp "$S/xtask/zone.json" "$S/zone.json"
nth 0 "$KEYS" > "$S/decryption.keys"
for i in 0 1 2; do
  nth $i "$KEYS" > "$S/seq-$i.key"
  nth $i "$P2P_KEYS" > "$S/p2p-$i.key"
  m="$S/manifest-$i.toml"
  {
    echo "zone_id = $zone_id"
    echo "sequencer_set_version = 0"
    echo "leader_ed25519_public_key = \"$(nth 0 "$P2P_PUBS")\""
    for j in 0 1 2; do
      addr="10.90.10.$((11 + j)):9200"
      echo ""
      echo "[[nodes]]"
      echo "name = \"node-$j\""
      echo "ed25519_public_key = \"$(nth $j "$P2P_PUBS")\""
      echo "secp256k1_address = \"$(nth $j "$ADDRS")\""
      echo "address = \"$addr\""
    done
  } > "$m"
done
chmod 600 "$S"/*.key "$S/decryption.keys"
touch "$S/provisioned"
echo "zone-provision: done"
