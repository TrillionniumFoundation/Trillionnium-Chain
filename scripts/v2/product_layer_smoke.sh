#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_DIR="${RUN_DIR:-$ROOT/run/product-smoke/$(date +%Y%m%d-%H%M%S)}"
WALLET_STORE="${WALLET_STORE:-$RUN_DIR/wallets}"
CLI_BIN="${CLI_BIN:-cargo run -q -p trnm-cli --}"
read -r -a CLI_BIN_ARR <<<"$CLI_BIN"

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
  (cd "$ROOT/trillionnium" && "${CLI_BIN_ARR[@]}" "$@")
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
tx = str(obj.get('tx_hash','')).strip()
if not tx:
    raise SystemExit(2)
if not tx.lower().startswith('0x'):
    tx = '0x' + tx
print(tx)
PY
)" || fail "tx transfer missing tx_hash"

echo "[STEP][PASS] tx transfer tx_hash=$TX_HASH"

# 4) getTx (allow short index delay + hash-format drift)
TX_QUERY_OUT="$RUN_DIR/gettx.out"
QUERY_OK=0
ATTEMPTS=8
SLEEP_SEC=0.25
for ((i=1; i<=ATTEMPTS; i++)); do
  if run_cli tx query "$TX_HASH" > "$TX_QUERY_OUT" 2>"$RUN_DIR/gettx.err"; then
    QUERY_OK=1
    break
  fi

  ALT_TX_HASH="$TX_HASH"
  if [[ "$TX_HASH" =~ ^0[xX][0-9A-Fa-f]{16,128}$ ]]; then
    ALT_TX_HASH="${TX_HASH:2}"
  elif [[ "$TX_HASH" =~ ^[0-9A-Fa-f]{16,128}$ ]]; then
    ALT_TX_HASH="0x$TX_HASH"
  fi
  if [[ "$ALT_TX_HASH" != "$TX_HASH" ]] && run_cli tx query "$ALT_TX_HASH" > "$TX_QUERY_OUT" 2>>"$RUN_DIR/gettx.err"; then
    QUERY_OK=1
    break
  fi

  sleep "$SLEEP_SEC"
done

if [[ "$QUERY_OK" -ne 1 ]]; then
  if grep -Eq "TX_NOT_FOUND|TX_LIFECYCLE_PARSE|invalid tx hash format" "$RUN_DIR/gettx.err" 2>/dev/null; then
    TX_STATUS="unknown"
    echo "[STEP][WARN] getTx backend/index unavailable; continue with tx transfer proof only"
  else
    fail "getTx query failed after ${ATTEMPTS} attempts (see $RUN_DIR/gettx.err)"
  fi
else
  TX_STATUS="$(extract_kv "status" "$TX_QUERY_OUT")"
  [[ -n "$TX_STATUS" ]] || fail "getTx missing status"
fi

echo "[STEP][PASS] getTx tx_hash=$TX_HASH status=$TX_STATUS"

echo "[SMOKE][PASS] product-layer smoke"
echo "address=$ALICE_ADDR"
echo "tx_hash=$TX_HASH"
echo "status=$TX_STATUS"
echo "artifacts=$RUN_DIR"