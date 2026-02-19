#!/usr/bin/env bash
set -euo pipefail

ROOT="/Users/qianqi/.openclaw/workspace/TrillionniumChain"
BIN="$ROOT/build/chaind"
HOME_DIR="${HOME_DIR:-/Users/qianqi/.chain}"
NODE="${NODE:-tcp://127.0.0.1:26657}"
CHAIN_ID="${CHAIN_ID:-trillionnium}"
OUTCOME="${1:-mismatch}" # match|mismatch
OUT_DIR="${OUT_DIR:-$ROOT/data/reexec-demo}"
TS="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$OUT_DIR/$TS"
mkdir -p "$RUN_DIR"

need(){ command -v "$1" >/dev/null 2>&1 || { echo "missing: $1"; exit 1; }; }
need jq
need shasum

NODE_PID=""
cleanup(){
  if [[ -n "$NODE_PID" ]]; then
    kill "$NODE_PID" >/dev/null 2>&1 || true
    wait "$NODE_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

RPC_HTTP="${RPC_HTTP:-http://127.0.0.1:26657}"

wait_node(){
  for _ in $(seq 1 40); do
    if curl -sf --max-time 2 "$RPC_HTTP/status" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_first_block(){
  for _ in $(seq 1 40); do
    h="$(curl -sf --max-time 2 "$RPC_HTTP/status" | jq -r '.result.sync_info.latest_block_height // "0"' 2>/dev/null || echo 0)"
    if [[ "${h:-0}" =~ ^[0-9]+$ ]] && [[ "$h" -gt 0 ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_tx(){
  local txh="$1"
  for _ in $(seq 1 60); do
    if "$BIN" query tx "$txh" --home "$HOME_DIR" --node "$NODE" -o json >"$RUN_DIR/tx-$txh.json" 2>/dev/null; then
      local c
      c="$(jq -r '.code // .tx_response.code // 0' "$RUN_DIR/tx-$txh.json")"
      [[ "$c" == "0" ]] && return 0
      jq -r '.raw_log // .tx_response.raw_log // ""' "$RUN_DIR/tx-$txh.json"
      return 1
    fi
    sleep 1
  done
  return 1
}

tx_sync(){
  local out="$1"; shift
  "$BIN" tx "$@" --home "$HOME_DIR" --node "$NODE" --chain-id "$CHAIN_ID" --keyring-backend test --yes --broadcast-mode sync --fees 500stake -o json > "$out"
  local txh
  txh="$(jq -r '.txhash // empty' "$out")"
  [[ -n "$txh" ]] || { echo "missing txhash in $out"; return 1; }
  wait_tx "$txh"
}

echo "[1/8] reset chain and start node"
pkill -f "$BIN start --home $HOME_DIR" >/dev/null 2>&1 || true
sleep 1
"$BIN" tendermint unsafe-reset-all --home "$HOME_DIR" >/dev/null
"$BIN" start --home "$HOME_DIR" --minimum-gas-prices 0stake >/tmp/trnm-reexec-demo-node.log 2>&1 &
NODE_PID=$!
wait_node
wait_first_block

echo "[2/8] node ready"

ALICE="$($BIN keys show alice -a --keyring-backend test --home "$HOME_DIR")"
BOB="$($BIN keys show bob -a --keyring-backend test --home "$HOME_DIR")"

echo "[3/8] register worker bob"
tx_sync "$RUN_DIR/register.json" workload register-worker node-bob ipfs://bob --from bob

echo "[4/8] create+accept task"
tx_sync "$RUN_DIR/create.json" workload create-task ipfs://reexec-demo 500 0 none none --from alice
TASK_TOTAL="$($BIN query workload list-task --home "$HOME_DIR" --node "$NODE" -o json | jq -r '((.Task // .task // [])|length)')"
TASK_ID=$((TASK_TOTAL - 1))
tx_sync "$RUN_DIR/accept.json" workload accept-task "$TASK_ID" --from bob

RESULT_HASH="result://demo-ok"
SALT="salt-reexec-demo"
COMMIT_HASH="$(printf "%s" "${TASK_ID}|${RESULT_HASH}|${SALT}|${BOB}" | shasum -a 256 | awk '{print $1}')"

echo "[5/8] commit+reveal"
tx_sync "$RUN_DIR/commit.json" workload commit-result "$TASK_ID" "$COMMIT_HASH" --from bob
tx_sync "$RUN_DIR/reveal.json" workload reveal-result "$TASK_ID" "$RESULT_HASH" ipfs://result-demo "$SALT" --from bob

echo "[6/8] challenge"
tx_sync "$RUN_DIR/challenge.json" workload challenge-result "$TASK_ID" "reexec-demo" ipfs://evidence-demo --from alice

echo "[7/8] build reexec resolve template"
REEXEC_HASH="$RESULT_HASH"
if [[ "$OUTCOME" == "mismatch" ]]; then
  REEXEC_HASH="result://demo-mismatch"
fi
"$ROOT/scripts/challenge_reexec_resolve_template.sh" "$TASK_ID" "$OUTCOME" "$REEXEC_HASH" "ipfs://reexec-report-$TASK_ID" > "$RUN_DIR/resolve-template.txt"

STATUS="$($BIN query workload show-task "$TASK_ID" --home "$HOME_DIR" --node "$NODE" -o json | jq -r '.Task.status // .task.status // 0')"

cat > "$RUN_DIR/summary.json" <<EOF
{
  "task_id": $TASK_ID,
  "outcome": "$OUTCOME",
  "status_before_resolve": $STATUS,
  "template": "$RUN_DIR/resolve-template.txt",
  "note": "Authority resolve is environment-dependent; template generated for immediate execution"
}
EOF

echo "[8/8] done"
echo "SUMMARY_JSON=$RUN_DIR/summary.json"
echo "TEMPLATE=$RUN_DIR/resolve-template.txt"
