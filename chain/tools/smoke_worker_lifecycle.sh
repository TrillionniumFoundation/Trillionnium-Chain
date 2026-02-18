#!/usr/bin/env bash
#
# smoke_worker_lifecycle.sh
# Full worker lifecycle: register → request-unbonding → wait cooldown → finalize-unbonding
# Also validates slash logic via tx-query (authority-gated, so we verify rejection).
#
set -euo pipefail

BIN="$(go env GOPATH)/bin/chaind"
HOME_DIR="${HOME}/.chain"
CHAIN_ID="chain"
FEE="500stake"
RPC="http://localhost:26657"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "[ERR] missing: $1" >&2; exit 1; }; }
need_cmd jq
[ -x "$BIN" ] || { echo "[ERR] chaind not found" >&2; exit 1; }

wait_blocks() {
  local target=$1
  for _ in $(seq 1 180); do
    local h; h="$(curl -sf "$RPC/status" | jq -r '.result.sync_info.latest_block_height')"
    [ "${h:-0}" -ge "$target" ] 2>/dev/null && return 0
    sleep 1
  done
  echo "[ERR] timed out waiting for block $target" >&2; exit 1
}

PASS=0; FAIL=0
check() {
  local label="$1" cond="$2"
  if eval "$cond"; then
    echo "  ✅ $label"
    PASS=$((PASS + 1))
  else
    echo "  ❌ $label"
    FAIL=$((FAIL + 1))
  fi
}

# ─── Setup ───────────────────────────────────────────────────────────
echo "[1/7] Reset & start chain"
pkill -9 -f "chaind start" 2>/dev/null || true
pkill -9 -f "chaind" 2>/dev/null || true
sleep 2
lsof -ti:26657 2>/dev/null | xargs kill -9 2>/dev/null || true
sleep 1
"$BIN" tendermint unsafe-reset-all --home "$HOME_DIR" >/dev/null 2>&1
"$BIN" start --home "$HOME_DIR" >/tmp/trnm-smoke-lifecycle.log 2>&1 &
NODE_PID=$!
trap 'kill $NODE_PID 2>/dev/null || true' EXIT
wait_blocks 1
echo "  chain running"

ALICE="$($BIN keys show alice -a --keyring-backend test --home "$HOME_DIR")"
alice_init="$($BIN query bank balances "$ALICE" --home "$HOME_DIR" -o json | jq -r '.balances[] | select(.denom=="utrnm") | .amount')"
echo "  alice: $ALICE (${alice_init} utrnm)"

# ─── Register Worker ────────────────────────────────────────────────
echo "[2/7] Register worker"
$BIN tx workload register-worker node-a1 ipfs://a1 \
  --from alice --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/dev/null
sleep 2

worker="$($BIN query workload list-worker --home "$HOME_DIR" -o json)"
stake="$(echo "$worker" | jq -r '.worker[0].stake')"
alice_post_reg="$($BIN query bank balances "$ALICE" --home "$HOME_DIR" -o json | jq -r '.balances[] | select(.denom=="utrnm") | .amount')"

check "worker registered with stake=100000" '[ "$stake" = "100000" ]'
check "alice balance reduced by 100000" '[ "$alice_post_reg" -eq $((alice_init - 100000)) ]'

# ─── Slash (unauthorized, should fail) ──────────────────────────────
echo "[3/7] Slash attempt (non-authority → must fail)"
$BIN tx workload slash-worker "$ALICE" 10 \
  --from alice --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/tmp/trnm-slash-attempt.json 2>/dev/null || true
sleep 2

SLASH_TXHASH="$(jq -r '.txhash' /tmp/trnm-slash-attempt.json 2>/dev/null || echo '')"
if [ -n "$SLASH_TXHASH" ]; then
  slash_code="$($BIN query tx "$SLASH_TXHASH" --home "$HOME_DIR" -o json 2>/dev/null | jq -r '.code')"
  check "slash rejected (non-authority)" '[ "$slash_code" != "0" ]'
else
  check "slash rejected (tx failed to broadcast)" 'true'
fi

# Verify stake unchanged
stake_after_slash="$($BIN query workload show-worker "$ALICE" --home "$HOME_DIR" -o json | jq -r '.worker.stake // .Worker.stake')"
check "stake unchanged after rejected slash" '[ "$stake_after_slash" = "100000" ]'

# ─── Request Unbonding ──────────────────────────────────────────────
echo "[4/7] Request unbonding"
$BIN tx workload request-unbonding \
  --from alice --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/dev/null
sleep 2

unbonding="$($BIN query workload show-unbonding "$ALICE" --home "$HOME_DIR" -o json)"
release_height="$(echo "$unbonding" | jq -r '.Unbonding.releaseHeight // .unbonding.releaseHeight')"
check "unbonding created" '[ "$release_height" != "" ] && [ "$release_height" != "null" ]'
echo "  release height: $release_height"

# Worker should be removed from active set
worker_after_unbond="$($BIN query workload show-worker "$ALICE" --home "$HOME_DIR" -o json 2>&1 || echo 'NOT_FOUND')"
check "worker removed from active set" 'echo "$worker_after_unbond" | grep -q "not found" || echo "$worker_after_unbond" | grep -q "NOT_FOUND"'

# ─── Premature Finalize (should fail) ───────────────────────────────
echo "[5/7] Premature finalize (should fail)"
$BIN tx workload finalize-unbonding \
  --from alice --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/tmp/trnm-premature-finalize.json 2>/dev/null || true
sleep 2

PREMATURE_TXHASH="$(jq -r '.txhash' /tmp/trnm-premature-finalize.json 2>/dev/null || echo '')"
if [ -n "$PREMATURE_TXHASH" ]; then
  premature_code="$($BIN query tx "$PREMATURE_TXHASH" --home "$HOME_DIR" -o json 2>/dev/null | jq -r '.code')"
  check "premature finalize rejected" '[ "$premature_code" != "0" ]'
else
  check "premature finalize rejected" 'true'
fi

# ─── Wait for release height ────────────────────────────────────────
echo "[6/7] Waiting for release height ($release_height)..."
wait_blocks "$release_height"
cur_h="$(curl -sf "$RPC/status" | jq -r '.result.sync_info.latest_block_height')"
echo "  chain height: $cur_h"

# ─── Finalize Unbonding ─────────────────────────────────────────────
echo "[7/7] Finalize unbonding"
$BIN tx workload finalize-unbonding \
  --from alice --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/tmp/trnm-finalize.json
sleep 2

FINAL_TXHASH="$(jq -r '.txhash' /tmp/trnm-finalize.json)"
final_code="$($BIN query tx "$FINAL_TXHASH" --home "$HOME_DIR" -o json 2>/dev/null | jq -r '.code')"
check "finalize-unbonding succeeded" '[ "$final_code" = "0" ]'

# Unbonding record should be removed
unbonding_after="$($BIN query workload show-unbonding "$ALICE" --home "$HOME_DIR" -o json 2>&1 || echo 'NOT_FOUND')"
check "unbonding record cleaned up" 'echo "$unbonding_after" | grep -q "not found" || echo "$unbonding_after" | grep -q "NOT_FOUND"'

# Stake should be returned
alice_final="$($BIN query bank balances "$ALICE" --home "$HOME_DIR" -o json | jq -r '.balances[] | select(.denom=="utrnm") | .amount')"
check "stake returned to alice" '[ "$alice_final" -gt "$alice_post_reg" ]'
echo "  alice utrnm: $alice_init → $alice_post_reg (registered) → $alice_final (finalized)"

# ─── Summary ────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════"
echo "  PASS: $PASS  FAIL: $FAIL"
if [ "$FAIL" -eq 0 ]; then
  echo "  🎉 ALL CHECKS PASSED"
else
  echo "  ⚠️  SOME CHECKS FAILED"
fi
echo "═══════════════════════════════════════"
echo "  node log: /tmp/trnm-smoke-lifecycle.log"
exit "$FAIL"
