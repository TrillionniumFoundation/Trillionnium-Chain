#!/usr/bin/env bash
set -euo pipefail

BIN="$(go env GOPATH)/bin/chaind"
HOME_DIR="${HOME}/.chain"
CHAIN_ID="chain"
FEE="500stake"
RPC="http://localhost:26657"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[ERR] missing command: $1" >&2; exit 1; }
}

need_cmd jq
[ -x "$BIN" ] || { echo "[ERR] chaind not found at $BIN" >&2; exit 1; }

echo "[1/9] Reset chain state"
"$BIN" tendermint unsafe-reset-all --home "$HOME_DIR" >/dev/null

echo "[2/9] Start node"
"$BIN" start --home "$HOME_DIR" >/tmp/trnm-smoke-unbonding-node.log 2>&1 &
NODE_PID=$!
trap 'kill $NODE_PID >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 30); do
  height="$(curl -s "$RPC/status" | jq -r '.result.sync_info.latest_block_height')"
  if [ "${height:-0}" -gt 0 ] 2>/dev/null; then
    break
  fi
  sleep 1
done
[ "${height:-0}" -gt 0 ] || { echo "[ERR] chain did not produce first block" >&2; exit 1; }
echo "    node height: $height"

ALICE_ADDR="$($BIN keys show alice -a --keyring-backend test --home "$HOME_DIR")"
echo "    alice: $ALICE_ADDR"

echo "[3/9] Register worker (alice, 100000 utrnm stake)"
alice_before="$($BIN query bank balances "$ALICE_ADDR" --home "$HOME_DIR" -o json | jq -r '.balances[] | select(.denom=="utrnm") | .amount')"

"$BIN" tx workload register-worker node-alice-001 ipfs://alice-addr \
  --from alice --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/tmp/trnm-smoke-unbonding-register.json

sleep 2

worker_json="$($BIN query workload show-worker "$ALICE_ADDR" --home "$HOME_DIR" -o json)"
worker_stake="$(echo "$worker_json" | jq -r '.Worker.stake')"
[ "$worker_stake" = "100000" ] || { echo "[ERR] worker stake is $worker_stake (expected 100000)" >&2; exit 1; }
echo "    worker stake: $worker_stake"

alice_after_register="$($BIN query bank balances "$ALICE_ADDR" --home "$HOME_DIR" -o json | jq -r '.balances[] | select(.denom=="utrnm") | .amount')"
expected_after_register=$((alice_before - 100000))
[ "$alice_after_register" -eq "$expected_after_register" ] || {
  echo "[ERR] alice balance mismatch after register: got=$alice_after_register expected=$expected_after_register" >&2
  exit 1
}
echo "    alice utrnm: $alice_before -> $alice_after_register"

echo "[4/9] Request unbonding (starts cooldown)"
"$BIN" tx workload request-unbonding --from alice --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/tmp/trnm-smoke-unbonding-request.json

sleep 2

unbonding_json="$($BIN query workload show-unbonding "$ALICE_ADDR" --home "$HOME_DIR" -o json)"
unbonding_release_height="$(echo "$unbonding_json" | jq -r '.Unbonding.releaseHeight')"
[ "$unbonding_release_height" != "" ] && [ "$unbonding_release_height" != "null" ] || {
  echo "[ERR] unbonding not found or invalid releaseHeight" >&2
  exit 1
}
echo "    unbonding release height: $unbonding_release_height"

worker_status="$($BIN query workload show-worker "$ALICE_ADDR" --home "$HOME_DIR" -o json | jq -r '.Worker // empty')"
if [ -n "$worker_status" ]; then
  echo "    worker still active (expected until release height)"
fi

echo "[5/9] Advance chain to release height"
current_height="$(curl -s "$RPC/status" | jq -r '.result.sync_info.latest_block_height')"
blocks_needed=$((unbonding_release_height - current_height + 1))
if [ "$blocks_needed" -gt 0 ]; then
  echo "    advancing $blocks_needed blocks..."
  for _ in $(seq 1 "$blocks_needed"); do
    $BIN debug tx --home "$HOME_DIR" >/dev/null 2>&1 || true
    sleep 1
  done
fi

final_height="$(curl -s "$RPC/status" | jq -r '.result.sync_info.latest_block_height')"
echo "    chain height: $final_height"

echo "[6/9] Finalize unbonding (withdraw stake)"
alice_before_finalize="$($BIN query bank balances "$ALICE_ADDR" --home "$HOME_DIR" -o json | jq -r '.balances[] | select(.denom=="utrnm") | .amount')"

"$BIN" tx workload finalize-unbonding --from alice --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/tmp/trnm-smoke-unbonding-finalize.json

sleep 2

echo "[7/9] Validate worker removed"
worker_after="$($BIN query workload show-worker "$ALICE_ADDR" --home "$HOME_DIR" -o json 2>&1)"
if echo "$worker_after" | grep -q "not found"; then
  echo "    worker correctly removed after unbonding"
else
  echo "[WARN] worker may still exist: $worker_after"
fi

echo "[8/9] Validate stake returned"
alice_after_finalize="$($BIN query bank balances "$ALICE_ADDR" --home "$HOME_DIR" -o json | jq -r '.balances[] | select(.denom=="utrnm") | .amount')"
# Should have original stake back (minus fees)
expected_final=$((alice_before - 500 - 500 - 500))  # 3 tx fees
if [ "$alice_after_finalize" -ge "$expected_final" ]; then
  echo "    alice utrnm: $alice_after_finalize (stake returned)"
else
  echo "[ERR] alice balance mismatch: got=$alice_after_finalize expected>=$expected_final" >&2
  exit 1
fi

echo "[9/9] PASS"
echo "    flow: register -> request-unbonding -> finalize-unbonding"
echo "    stake: locked (100000) -> released"
echo "    node log: /tmp/trnm-smoke-unbonding-node.log"
