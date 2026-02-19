#!/usr/bin/env bash
set -euo pipefail

BIN="$(go env GOPATH)/bin/chaind"
HOME_DIR="${HOME}/.chain"
CHAIN_ID="trillionnium"
FEE="500stake"
RPC="http://localhost:26657"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[ERR] missing command: $1" >&2; exit 1; }
}

need_cmd jq
need_cmd curl
need_cmd shasum
[ -x "$BIN" ] || { echo "[ERR] chaind not found at $BIN" >&2; exit 1; }

assert_tx_ok() {
  local f="$1"
  local c
  c="$(jq -r '.code // 0' "$f")"
  if [ "$c" != "0" ]; then
    echo "[ERR] tx failed: $f (code=$c)" >&2
    jq -r '.raw_log // .logs // .tx_response.raw_log // ""' "$f" >&2 || true
    exit 1
  fi
}

wait_tx_commit() {
  local txfile="$1"
  local txh
  txh="$(jq -r '.txhash // empty' "$txfile")"
  [ -n "$txh" ] || { echo "[ERR] txhash missing in $txfile" >&2; exit 1; }

  for _ in $(seq 1 50); do
    if "$BIN" query tx "$txh" --home "$HOME_DIR" -o json >/tmp/trnm-last-tx-query.json 2>/dev/null; then
      local committed_code
      committed_code="$(jq -r '.code // .tx_response.code // 0' /tmp/trnm-last-tx-query.json)"
      if [ "$committed_code" != "0" ]; then
        echo "[ERR] committed tx failed: $txh (code=$committed_code)" >&2
        jq -r '.raw_log // .tx_response.raw_log // ""' /tmp/trnm-last-tx-query.json >&2 || true
        exit 1
      fi
      return 0
    fi
    sleep 1
  done

  echo "[ERR] tx not committed in time: $txh" >&2
  exit 1
}

echo "[1/11] Reset chain"
pkill -f "$BIN start --home $HOME_DIR" >/dev/null 2>&1 || true
sleep 1
"$BIN" tendermint unsafe-reset-all --home "$HOME_DIR" >/dev/null

echo "[2/11] Start node"
"$BIN" start --home "$HOME_DIR" --minimum-gas-prices 0stake >/tmp/trnm-smoke-cli-node.log 2>&1 &
NODE_PID=$!
trap 'kill $NODE_PID >/dev/null 2>&1 || true; wait $NODE_PID >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 40); do
  if curl -sf "$RPC/status" >/dev/null; then
    break
  fi
  sleep 1
done
curl -sf "$RPC/status" >/dev/null || { echo "[ERR] node not ready" >&2; exit 1; }

for _ in $(seq 1 40); do
  H="$(curl -s "$RPC/status" | jq -r '.result.sync_info.latest_block_height')"
  if [ "${H:-0}" -gt 0 ] 2>/dev/null; then
    break
  fi
  sleep 1
done
[ "${H:-0}" -gt 0 ] || { echo "[ERR] first block not produced" >&2; exit 1; }

ALICE="$($BIN keys show alice -a --keyring-backend test --home "$HOME_DIR")"
BOB="$($BIN keys show bob -a --keyring-backend test --home "$HOME_DIR")"

echo "[3/11] Register worker (bob)"
"$BIN" tx workload register-worker node-bob ipfs://bob \
  --from bob --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/tmp/trnm-smoke-cli-register.json
assert_tx_ok /tmp/trnm-smoke-cli-register.json
wait_tx_commit /tmp/trnm-smoke-cli-register.json

echo "[4/11] Create task (alice)"
"$BIN" tx workload create-task ipfs://task-cli 500 0 none none \
  --from alice --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/tmp/trnm-smoke-cli-create.json
assert_tx_ok /tmp/trnm-smoke-cli-create.json
wait_tx_commit /tmp/trnm-smoke-cli-create.json
TASK_TOTAL="$($BIN query workload list-task --home "$HOME_DIR" -o json | jq -r '((.Task // .task // [])|length)')"
TASK_ID=$((TASK_TOTAL - 1))

echo "[5/11] Accept task (bob)"
"$BIN" tx workload accept-task "$TASK_ID" \
  --from bob --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/tmp/trnm-smoke-cli-accept.json
assert_tx_ok /tmp/trnm-smoke-cli-accept.json
wait_tx_commit /tmp/trnm-smoke-cli-accept.json

RESULT_HASH="result://ok"
REVEAL_SALT="salt-cli"
COMMIT_HASH="$(printf "%s" "${TASK_ID}|${RESULT_HASH}|${REVEAL_SALT}|${BOB}" | shasum -a 256 | awk '{print $1}')"

echo "[6/11] Commit result (bob)"
"$BIN" tx workload commit-result "$TASK_ID" "$COMMIT_HASH" \
  --from bob --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/tmp/trnm-smoke-cli-commit.json
assert_tx_ok /tmp/trnm-smoke-cli-commit.json
wait_tx_commit /tmp/trnm-smoke-cli-commit.json

echo "[7/11] Reveal result (bob)"
"$BIN" tx workload reveal-result "$TASK_ID" "$RESULT_HASH" ipfs://result-cli "$REVEAL_SALT" \
  --from bob --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/tmp/trnm-smoke-cli-reveal.json
assert_tx_ok /tmp/trnm-smoke-cli-reveal.json
wait_tx_commit /tmp/trnm-smoke-cli-reveal.json

echo "[8/11] Challenge result (alice)"
"$BIN" tx workload challenge-result "$TASK_ID" "challenge-cli" ipfs://evidence-cli \
  --from alice --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/tmp/trnm-smoke-cli-challenge.json
assert_tx_ok /tmp/trnm-smoke-cli-challenge.json
wait_tx_commit /tmp/trnm-smoke-cli-challenge.json

echo "[9/11] Query task/challenge"
TASK_JSON="$($BIN query workload show-task "$TASK_ID" --home "$HOME_DIR" -o json)"
STATUS="$(echo "$TASK_JSON" | jq -r '(.Task.status // .task.status // 0)')"
CHALLENGE_LIST_JSON="$($BIN query workload list-challenge --home "$HOME_DIR" -o json)"
CHALLENGE_COUNT="$(echo "$CHALLENGE_LIST_JSON" | jq -r '((.challenge // .Challenge // []) | length)')"
CHALLENGE_ID="$(echo "$CHALLENGE_LIST_JSON" | jq -r '((.challenge // .Challenge // [])[0].id // 0)')"
CHALLENGER="$(echo "$CHALLENGE_LIST_JSON" | jq -r '((.challenge // .Challenge // [])[0].challenger // "")')"

[ "$STATUS" = "4" ] || { echo "[ERR] expected challenged status=4 got=$STATUS" >&2; exit 1; }
[ "$CHALLENGE_COUNT" -gt 0 ] || { echo "[ERR] no challenge found in list-challenge" >&2; exit 1; }
[ "$CHALLENGER" = "$ALICE" ] || { echo "[ERR] challenger mismatch" >&2; exit 1; }

echo "[10/11] Resolve attempt by non-authority (expected fail)"
"$BIN" tx workload resolve-challenge "$TASK_ID" true result://final "manual" \
  --from alice --chain-id "$CHAIN_ID" --home "$HOME_DIR" --keyring-backend test \
  --yes --broadcast-mode sync --fees "$FEE" -o json >/tmp/trnm-smoke-cli-resolve.json
assert_tx_ok /tmp/trnm-smoke-cli-resolve.json

RESOLVE_TXH="$(jq -r '.txhash // empty' /tmp/trnm-smoke-cli-resolve.json)"
[ -n "$RESOLVE_TXH" ] || { echo "[ERR] resolve txhash missing" >&2; exit 1; }

for _ in $(seq 1 50); do
  if "$BIN" query tx "$RESOLVE_TXH" --home "$HOME_DIR" -o json >/tmp/trnm-smoke-cli-resolve-committed.json 2>/dev/null; then
    break
  fi
  sleep 1
done

RESOLVE_CODE="$(jq -r '.code // .tx_response.code // 0' /tmp/trnm-smoke-cli-resolve-committed.json)"
if [ "$RESOLVE_CODE" = "0" ]; then
  echo "[ERR] resolve unexpectedly succeeded from non-authority" >&2
  cat /tmp/trnm-smoke-cli-resolve-committed.json >&2
  exit 1
fi

echo "[11/11] PASS"
echo "    task_id=$TASK_ID status=$STATUS challenge_id=$CHALLENGE_ID"
echo "    resolve non-authority rejected as expected"
echo "    node log: /tmp/trnm-smoke-cli-node.log"
