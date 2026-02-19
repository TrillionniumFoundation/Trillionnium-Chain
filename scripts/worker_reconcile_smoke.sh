#!/usr/bin/env bash
set -euo pipefail

ROOT="/Users/qianqi/.openclaw/workspace/TrillionniumChain"
BIN="$ROOT/build/chaind"
HOME_DIR="${HOME_DIR:-/Users/qianqi/.chain}"
CHAIN_ID="${CHAIN_ID:-trillionnium}"
NODE="${NODE:-tcp://127.0.0.1:26657}"
WORKER_DIR="$ROOT/worker"
STATE_FILE="$WORKER_DIR/worker_state.json"
JOB_ID="999999"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1"; exit 1; }; }
need jq
need python3

wait_tx_commit() {
  local txh="$1"
  for _ in $(seq 1 120); do
    if "$BIN" query tx "$txh" --home "$HOME_DIR" --node "$NODE" -o json >/tmp/trnm-reconcile-tx.json 2>/dev/null; then
      local code
      code="$(jq -r '.code // .tx_response.code // 0' /tmp/trnm-reconcile-tx.json)"
      [[ "$code" == "0" ]] && return 0
      echo "[ERR] tx committed with non-zero code=$code"
      jq -r '.raw_log // .tx_response.raw_log // ""' /tmp/trnm-reconcile-tx.json
      return 1
    fi
    sleep 1
  done
  echo "[ERR] tx not committed in time: $txh"
  return 1
}

echo "[1/6] ensure chain up (auto-start if needed)"
NODE_PID=""
if ! "$BIN" status --home "$HOME_DIR" --node "$NODE" >/dev/null 2>&1; then
  "$BIN" start --home "$HOME_DIR" --minimum-gas-prices 0stake >/tmp/trnm-reconcile-node.log 2>&1 &
  NODE_PID=$!
  for _ in $(seq 1 40); do
    if "$BIN" status --home "$HOME_DIR" --node "$NODE" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  "$BIN" status --home "$HOME_DIR" --node "$NODE" >/dev/null
fi

cleanup() {
  if [[ -n "${BACKUP:-}" && -f "$BACKUP" ]]; then
    mv "$BACKUP" "$STATE_FILE"
  else
    rm -f "$STATE_FILE"
  fi
  if [[ -n "$NODE_PID" ]]; then
    kill "$NODE_PID" >/dev/null 2>&1 || true
    wait "$NODE_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

tx_create_with_retry() {
  local out rc tries=0
  while (( tries < 20 )); do
    set +e
    out="$($BIN tx workload create-task ipfs://reconcile-smoke 500 0 none none \
      --from alice --keyring-backend test --chain-id "$CHAIN_ID" --home "$HOME_DIR" --node "$NODE" \
      --yes --broadcast-mode sync --gas auto --gas-adjustment 1.5 -o json 2>&1)"
    rc=$?
    set -e

    if [[ $rc -eq 0 ]] && grep -q '"txhash"' <<<"$out"; then
      echo "$out" >/tmp/trnm-reconcile-create.json
      return 0
    fi

    if grep -qi "account sequence mismatch" <<<"$out"; then
      ((tries++))
      sleep 1.2
      continue
    fi

    echo "$out"
    return 1
  done

  echo "$out"
  return 1
}

echo "[2/6] create one tx for reconcile probe"
tx_create_with_retry

TXH="$(jq -r '.txhash // empty' /tmp/trnm-reconcile-create.json)"
[[ -n "$TXH" ]] || { echo "[ERR] no txhash from create-task"; cat /tmp/trnm-reconcile-create.json; exit 1; }
wait_tx_commit "$TXH"

echo "[3/6] seed worker_state with committed phase"
BACKUP=""
if [[ -f "$STATE_FILE" ]]; then
  BACKUP="$STATE_FILE.bak.$(date +%s)"
  cp "$STATE_FILE" "$BACKUP"
fi
cat > "$STATE_FILE" <<EOF
{
  "seen_jobs": [],
  "sequence": null,
  "job_phases": {"$JOB_ID": "committed"},
  "job_txs": {"$JOB_ID": "$TXH"}
}
EOF

echo "[4/6] run reconciler"
(
  cd "$WORKER_DIR"
  python3 - <<'PY'
import json
import yaml
from listener import ChainListener

cfg = yaml.safe_load(open('config.yaml', 'r'))
l = ChainListener(cfg)
l.reconcile_local_state()
state = json.load(open('worker_state.json', 'r'))
phase = state.get('job_phases', {}).get('999999')
seen = state.get('seen_jobs', [])
print('phase=', phase)
print('seen_contains=', '999999' in [str(x) for x in seen])
if phase != 'finalized' or '999999' not in [str(x) for x in seen]:
    raise SystemExit(2)
PY
)

echo "[5/6] verify done"
echo "[6/6] cleanup by trap"
echo "SMOKE PASS ✅ worker reconcile local-state works"