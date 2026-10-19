#!/bin/bash
# Zones TIP-403 policy driver (`--workload-arg zones_policy=true`, container
# `zones-policy`). It exercises, on the running dev zone, that zone TIP-20
# transfers honour the L1-inherited TIP-403 policy and conserve balances:
#
#   1. fund a dedicated policy account (dev account 2) on the zone with one
#      txgen bootstrap deposit (encrypted); dev account 1 stays the zones-load
#      sender, so there is no nonce race;
#   2. on L1, create a BLACKLIST policy, blacklist a fresh test recipient
#      (dev account 7 -- never the fee manager, portal, inbox or outbox), and
#      switch pathUSD's transfer policy to it;
#   3. wait until the zone imports the L1 block that switched the policy
#      (TempoState.tempoBlockNumber);
#   4. send a forbidden zone transfer (dev2 -> blacklisted) -- it must not
#      land -- and an allowed one (dev2 -> dev3) -- it must -- snapshotting
#      balances and supply around each.
#
# Each step prints a `tempo-dst-policy: {json}` line the E12 oracle reads.
# Transfers run on the zone only after enable-transfers.patch; the policy is
# set on L1 and read-only on the zone.
#
# `policy.sh fund` runs only step 1, in warmup (before the warm checkpoint, so
# dev 2 is funded in every branch and no nemesis kill interrupts the slow
# deposit). `policy.sh` (per branch) skips funding and runs steps 2-4, retrying
# the whole sequence so a nemesis kill mid-flow does not abort it.
set -u
MODE=${1:-run}
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1
emit() { printf 'tempo-dst-policy: %s\n' "$1"; }
log() { echo "zones-policy: $*" >&2; }
# An error step; the detail is JSON-escaped (it may hold cast output).
emit_error() {
  emit "$(jq -cn --arg d "$1" '{step: "error", detail: ($d | .[0:300])}')"
  log "error: $1"
  [ "$MODE" = fund ] && exit 1
  exec sleep infinity
}
# Sends an L1 transaction from dev 0 and prints its receipt JSON; retries until
# a receipt with status 1 lands (dev 0 is also the sequencer, so transient
# submission errors are possible).
l1_send() {
  local out status
  for _ in $(seq 1 10); do
    out=$(cast send --rpc-url "$L1" --private-key "$DEV0_KEY" --json --timeout 60 "$@" 2>&1)
    status=$(echo "$out" | jq -r '.status // empty' 2>/dev/null)
    if [ "$status" = 0x1 ] || [ "$status" = 1 ]; then
      echo "$out"
      return 0
    fi
    log "L1 send $2 failed (status ${status:-none}): $(echo "$out" | tail -c 200)"
    sleep 3
  done
  echo "$out"
  return 1
}

L1=http://127.0.0.1:8545
ZONE=http://127.0.0.1:9545
ZONE_PRIV=http://127.0.0.1:8544
PORTAL=0x5ad0000000000000000000000000000000000001
PATHUSD=0x20c0000000000000000000000000000000000000
REG=0x403c000000000000000000000000000000000000
TEMPOSTATE=0x1c00000000000000000000000000000000000000
ZONE_ID=1
ZONE_CHAIN=5742371274753

# Dev accounts (mnemonic test ... junk).
DEV0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
DEV0_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
DEV2=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
DEV2_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
DEV3=0x90F79bf6EB2c4f870365E785982E1f101E93b906
# Fresh blacklist target: dev account 7, used nowhere else.
BLACK=0x14dC79964da2C08b23698B3d3cc7Ca32193d9955

bal() { # account -> balance (decimal), 0 on error
  cast call --rpc-url "$ZONE" --from "$1" "$PATHUSD" 'balanceOf(address)(uint256)' "$1" 2>/dev/null | sed 's/ .*//' | grep -E '^[0-9]+$' || echo 0
}
supply() {
  cast call --rpc-url "$ZONE" "$PATHUSD" 'totalSupply()(uint256)' 2>/dev/null | sed 's/ .*//' | grep -E '^[0-9]+$' || echo 0
}
# Sends a zone transfer; prints the receipt status (1 landed, 0 reverted or
# rejected at the pool).
zone_transfer() {
  local to=$1 amt=$2 out
  out=$(cast send --rpc-url "$ZONE" --legacy --gas-limit 400000 --timeout 60 \
    --private-key "$DEV2_KEY" --json "$PATHUSD" 'transfer(address,uint256)' "$to" "$amt" 2>/dev/null)
  echo "$out" | sed -n 's/.*"status":"\?\(0x[0-9a-fA-F]*\)"\?.*/\1/p' | head -1 | grep -q '0x1' && echo 1 || echo 0
}
transfer_report() { # kind to amount
  local kind=$1 to=$2 amt=$3
  local sb rb sup sa ra sup2 landed
  sb=$(bal "$DEV2"); rb=$(bal "$to"); sup=$(supply)
  landed=$(zone_transfer "$to" "$amt")
  sleep 1
  sa=$(bal "$DEV2"); ra=$(bal "$to"); sup2=$(supply)
  emit "{\"step\":\"transfer\",\"kind\":\"$kind\",\"to\":\"$to\",\"amount\":\"$amt\",\"landed\":$landed,\"sender_before\":\"$sb\",\"sender_after\":\"$sa\",\"recipient_before\":\"$rb\",\"recipient_after\":\"$ra\",\"supply_before\":\"$sup\",\"supply_after\":\"$sup2\"}"
  log "$kind transfer to $to: landed=$landed sender $sb->$sa recipient $rb->$ra"
}

counter() { cast call --rpc-url "$L1" "$REG" 'policyIdCounter()(uint64)' 2>/dev/null | sed 's/ .*//'; }

# 1. Fund dev2 on the zone with one txgen bootstrap deposit.
fund_dev2() {
  [ "$(bal "$DEV2")" != 0 ] && return 0
  log "funding dev2 on the zone"
  for attempt in $(seq 1 6); do
    PRIVATE_KEY=$DEV2_KEY ZONE_TOKEN=$PATHUSD RUST_LOG=warn timeout 180 \
      txgen-tempo-property --l1-rpc-url "$L1" --zone-rpc-url "$ZONE" \
      --zone-private-rpc-url "$ZONE_PRIV" --zone-id "$ZONE_ID" --zone-chain-id "$ZONE_CHAIN" \
      --portal "$PORTAL" --token "$PATHUSD" --cases 1 --max-steps 1 \
      --settlement-timeout-secs 120 --failure-directory /tmp/pf >&2
    [ "$(bal "$DEV2")" != 0 ] && break
    log "dev2 still unfunded (attempt $attempt)"
    sleep 3
  done
  [ "$(bal "$DEV2")" != 0 ]
}

# Steps 2-4, as one retryable sequence (each failure returns 1 to the caller's
# retry loop, so a nemesis kill mid-flow is recovered).
run_flow() {
  # 2. Create a BLACKLIST policy and blacklist the test recipient on L1. The
  #    new id is policyIdCounter before the create; nothing else creates
  #    policies, confirmed with policyExists.
  local PID RC AFTER EXISTS SW L1BLK_HEX L1BLK ZPID TB
  PID=$(counter)
  [ -n "${PID:-}" ] || { log "no policyIdCounter"; return 1; }
  RC=$(l1_send "$REG" 'createPolicy(address,uint8)' "$DEV0" 1) ||
    { log "createPolicy failed: $(echo "$RC" | tail -c 200)"; return 1; }
  AFTER=$(counter)
  EXISTS=$(cast call --rpc-url "$L1" "$REG" 'policyExists(uint64)(bool)' "$PID" 2>/dev/null)
  log "created policy id=$PID (counter now $AFTER, exists=$EXISTS)"
  [ "$EXISTS" = true ] && [ "${AFTER:-0}" -gt "$PID" ] 2>/dev/null ||
    { log "policy $PID not created"; return 1; }
  emit "{\"step\":\"policy-created\",\"id\":$PID}"
  l1_send "$REG" 'modifyPolicyBlacklist(uint64,address,bool)' "$PID" "$BLACK" true >/dev/null ||
    { log "modifyPolicyBlacklist failed"; return 1; }

  # 3. Switch pathUSD's policy and wait for the zone to adopt it.
  SW=$(l1_send "$PATHUSD" 'changeTransferPolicyId(uint64)' "$PID") ||
    { log "changeTransferPolicyId failed: $(echo "$SW" | tail -c 200)"; return 1; }
  L1BLK_HEX=$(echo "$SW" | jq -r '.blockNumber' 2>/dev/null)
  L1BLK=$(cast to-dec "$L1BLK_HEX" 2>/dev/null | grep -E '^[0-9]+$' || echo 0)
  emit "{\"step\":\"policy-switched\",\"id\":$PID,\"l1_block\":$L1BLK}"
  log "pathUSD policy -> $PID at L1 block $L1BLK; awaiting zone import"
  ZPID=""
  for _ in $(seq 1 60); do
    TB=$(cast call --rpc-url "$ZONE" "$TEMPOSTATE" 'tempoBlockNumber()(uint64)' 2>/dev/null | sed 's/ .*//')
    ZPID=$(cast call --rpc-url "$ZONE" "$PATHUSD" 'transferPolicyId()(uint64)' 2>/dev/null | sed 's/ .*//')
    [ "${ZPID:-}" = "$PID" ] && [ -n "${TB:-}" ] && [ "$TB" -ge "$L1BLK" ] 2>/dev/null && break
    sleep 2
  done
  log "zone sees pathUSD policy id=$ZPID (want $PID)"
  [ "${ZPID:-}" = "$PID" ] || { log "zone did not adopt policy $PID (sees $ZPID)"; return 1; }

  # 4. Forbidden then allowed transfer.
  transfer_report forbidden "$BLACK" 1
  transfer_report allowed "$DEV3" 1
  log "policy flow complete"
  return 0
}

if [ "$MODE" = fund ]; then
  fund_dev2 || emit_error "dev2 funding failed"
  log "dev2 zone balance: $(bal "$DEV2")"
  exit 0
fi

# Per branch: dev2 is funded in warmup; verify (fund as a fallback), then run
# the flow with retries so a nemesis kill does not abort it.
fund_dev2 || true
[ "$(bal "$DEV2")" != 0 ] || emit_error "dev2 not funded (warmup funding missing)"
for attempt in $(seq 1 25); do
  run_flow && break
  log "policy flow attempt $attempt failed; retrying"
  sleep 5
done
exec sleep infinity
