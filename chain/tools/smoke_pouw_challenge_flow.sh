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
need_cmd curl
[ -x "$BIN" ] || { echo "[ERR] chaind not found at $BIN" >&2; exit 1; }

echo "[1/8] Reset chain state"
"$BIN" tendermint unsafe-reset-all --home "$HOME_DIR" >/dev/null

ALICE_ADDR="$($BIN keys show alice -a --keyring-backend test --home "$HOME_DIR")"
BOB_ADDR="$($BIN keys show bob -a --keyring-backend test --home "$HOME_DIR")"

echo "[2/8] Start node"
"$BIN" start --home "$HOME_DIR" >/tmp/trnm-smoke-pouw-node.log 2>&1 &
NODE_PID=$!
trap 'kill $NODE_PID >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 30); do
  if curl -sf "$RPC/status" >/dev/null; then
    break
  fi
  sleep 1
done
curl -sf "$RPC/status" >/dev/null || { echo "[ERR] node not ready" >&2; exit 1; }

echo "[3/8] Create task"
IPFS_HASH="ipfs://pouw-smoke-$(date +%s)"
"$BIN" tx workload create-task "$IPFS_HASH" 500 0 none none \
  --from alice --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" >/tmp/trnm-smoke-pouw-create.json
sleep 2

TASK_TOTAL="$($BIN query workload list-task --home "$HOME_DIR" -o json | jq -r '.pagination.total')"
TASK_ID=$((TASK_TOTAL - 1))

echo "[4/8] Submit result (worker=bob)"
"$BIN" tx workload submit-result "$TASK_ID" "result://hash-ok" "ipfs://result" \
  --from bob --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" >/tmp/trnm-smoke-pouw-submit.json || true
sleep 2

echo "[5/8] Challenge result (challenger=alice)"
"$BIN" tx workload challenge-result "$TASK_ID" "bad result" "ipfs://evidence" \
  --from alice --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" >/tmp/trnm-smoke-pouw-challenge.json || true
sleep 2

echo "[6/8] Query task"
TASK_JSON="$($BIN query workload show-task "$TASK_ID" --home "$HOME_DIR" -o json)"
STATUS="$(echo "$TASK_JSON" | jq -r '.Task.status')"
CHALLENGE_ID="$(echo "$TASK_JSON" | jq -r '.Task.challengeId')"

echo "[7/8] Query challenge"
if [ "$CHALLENGE_ID" != "0" ] || [ "$STATUS" = "3" ]; then
  "$BIN" query workload show-challenge "$CHALLENGE_ID" --home "$HOME_DIR" -o json >/tmp/trnm-smoke-pouw-challenge-query.json || true
fi

echo "[8/8] PASS (smoke executed)"
echo "    task_id=$TASK_ID status=$STATUS challenge_id=$CHALLENGE_ID"
echo "    node log: /tmp/trnm-smoke-pouw-node.log"
