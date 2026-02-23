#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_DIR="${RUN_DIR:-$ROOT/run/product-smoke/$(date +%Y%m%d-%H%M%S)}"
WALLET_STORE="${WALLET_STORE:-$RUN_DIR/wallets}"
CLI_BIN="${CLI_BIN:-cargo run -q -p trnm-cli --}"

mkdir -p "$RUN_DIR" "$WALLET_STORE"

ALICE_NAME="${ALICE_NAME:-smoke-alice}"
BOB_NAME="${BOB_NAME:-smoke-bob}"
TRANSFER_AMOUNT="${TRANSFER_AMOUNT:-1}"
DENOM="${DENOM:-trnm}"

ALICE_ADDR=""
TX_HASH=""
TX_STATUS=""

fail() {
  local msg="$1"
  echo "[SMOKE][FAIL] $msg"
  if [[ -n "$ALICE_ADDR" ]]; then
    echo "address=$ALICE_ADDR"
  fi
  if [[ -n "$TX_HASH" ]]; then
    echo "tx_hash=$TX_HASH"
  fi
  if [[ -n "$TX_STATUS" ]]; then
    echo "status=$TX_STATUS"
  fi
  exit 1
}

extract_kv() {
  local key="$1"
  local file="$2"
  sed -n "s/^${key}=//p" "$file" | head -n1
}

run_cli() {
  local quoted=""
  local arg
  for arg in "$@"; do
    quoted+=" $(printf '%q' "$arg")"
  done
  (cd "$ROOT/trillionnium-rust" && eval "$CLI_BIN$quoted")
}

# 1) wallet create
ALICE_OUT="$RUN_DIR/alice.create.out"
BOB_OUT="$RUN_DIR/bob.create.out"

run_cli wallet create --name "$ALICE_NAME" --out "$WALLET_STORE" > "$ALICE_OUT"
run_cli wallet create --name "$BOB_NAME" --out "$WALLET_STORE" > "$BOB_OUT"

ALICE_ADDR="$(extract_kv "address" "$ALICE_OUT")"
BOB_ADDR="$(extract_kv "address" "$BOB_OUT")"

[[ -n "$ALICE_ADDR" ]] || fail "wallet create missing ALICE address"
[[ -n "$BOB_ADDR" ]] || fail "wallet create missing BOB address"

echo "[STEP][PASS] wallet create address=$ALICE_ADDR"

# 2) query balance
BALANCE_JSON="$RUN_DIR/alice.balance.json"
run_cli query balance --name "$ALICE_NAME" --store "$WALLET_STORE" --denom "$DENOM" > "$BALANCE_JSON"

BALANCE_VALUE="$(python3 - "$BALANCE_JSON" "$ALICE_ADDR" <<'PY'
import json,sys
p,expect = sys.argv[1], sys.argv[2]
obj = json.load(open(p))
addr = obj.get('address','')
bal = str(obj.get('balance',''))
if not addr or not bal:
    raise SystemExit(2)
if addr != expect:
    raise SystemExit(3)
print(bal)
PY
)" || fail "query balance parse/validation failed"

echo "[STEP][PASS] query balance address=$ALICE_ADDR balance=$BALANCE_VALUE"

# 3) tx transfer
TRANSFER_JSON="$RUN_DIR/transfer.json"
run_cli tx transfer \
  --from "$ALICE_NAME" \
  --to "$BOB_ADDR" \
  --amount "$TRANSFER_AMOUNT" \
  --denom "$DENOM" \
  --store "$WALLET_STORE" > "$TRANSFER_JSON"

TX_HASH="$(python3 - "$TRANSFER_JSON" <<'PY'
import json,sys
obj = json.load(open(sys.argv[1]))
tx = obj.get('tx_hash','')
if not tx:
    raise SystemExit(2)
print(tx)
PY
)" || fail "tx transfer missing tx_hash"

echo "[STEP][PASS] tx transfer tx_hash=$TX_HASH"

# 4) getTx
TX_QUERY_OUT="$RUN_DIR/gettx.out"
run_cli tx query "$TX_HASH" > "$TX_QUERY_OUT"

TX_STATUS="$(extract_kv "status" "$TX_QUERY_OUT")"
[[ -n "$TX_STATUS" ]] || fail "getTx missing status"

echo "[STEP][PASS] getTx tx_hash=$TX_HASH status=$TX_STATUS"

echo "[SMOKE][PASS] product-layer smoke"
echo "address=$ALICE_ADDR"
echo "tx_hash=$TX_HASH"
echo "status=$TX_STATUS"
echo "artifacts=$RUN_DIR"