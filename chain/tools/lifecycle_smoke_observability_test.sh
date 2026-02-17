#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT_DIR/tools/lifecycle_smoke.sh"

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat >"$TMP_DIR/chaind" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="${MOCK_STATE_DIR:?}"
HEIGHT_FILE="$STATE_DIR/height"
FINALIZED_FILE="$STATE_DIR/finalized"

cmd="${1:-}"
if [[ "$cmd" == "status" ]]; then
  h="$(cat "$HEIGHT_FILE")"
  echo $((h + 1)) >"$HEIGHT_FILE"
  cat <<JSON
{"SyncInfo":{"latest_block_height":"$h","catching_up":false}}
JSON
  exit 0
fi

if [[ "$cmd" == "keys" && "${2:-}" == "show" ]]; then
  echo "cosmos1workeraddr"
  exit 0
fi

if [[ "$cmd" == "tx" && "${2:-}" == "workload" && "${3:-}" == "register-worker" ]]; then
  echo '{"txhash":"txreg","code":0}'
  exit 0
fi
if [[ "$cmd" == "tx" && "${2:-}" == "workload" && "${3:-}" == "request-unbonding" ]]; then
  echo '{"txhash":"txreq","code":0}'
  exit 0
fi
if [[ "$cmd" == "tx" && "${2:-}" == "workload" && "${3:-}" == "finalize-unbonding" ]]; then
  if [[ "${MOCK_FAIL_FINALIZE:-0}" == "1" ]]; then
    echo '{"txhash":"txfin","code":1106,"raw_log":"mock cooldown not reached"}'
    exit 0
  fi
  echo 1 >"$FINALIZED_FILE"
  echo '{"txhash":"txfin","code":0}'
  exit 0
fi

if [[ "$cmd" == "q" && "${2:-}" == "tx" ]]; then
  tx="${3:-}"
  case "$tx" in
    txreg)
      cat <<JSON
{"events":[{"type":"workload_register_worker","attributes":[{"key":"worker","value":"cosmos1workeraddr"}]}]}
JSON
      ;;
    txreq)
      cat <<JSON
{"events":[{"type":"workload_request_unbonding","attributes":[{"key":"worker","value":"cosmos1workeraddr"},{"key":"amount","value":"100stake"}]}]}
JSON
      ;;
    txfin)
      cat <<JSON
{"events":[{"type":"workload_finalize_unbonding","attributes":[{"key":"worker","value":"cosmos1workeraddr"},{"key":"amount","value":"100stake"}]}]}
JSON
      ;;
    *)
      exit 1
      ;;
  esac
  exit 0
fi

if [[ "$cmd" == "q" && "${2:-}" == "workload" && "${3:-}" == "show-unbonding" ]]; then
  finalized="$(cat "$FINALIZED_FILE")"
  if [[ "$finalized" == "1" ]]; then
    exit 1
  fi
  cat <<JSON
{"unbonding":{"releaseHeight":"103"}}
JSON
  exit 0
fi

echo "unsupported mock command: $*" >&2
exit 1
EOF
chmod +x "$TMP_DIR/chaind"

echo 100 >"$TMP_DIR/height"
echo 0 >"$TMP_DIR/finalized"

OUT_FILE="$TMP_DIR/out.log"
MOCK_STATE_DIR="$TMP_DIR" BIN="$TMP_DIR/chaind" SLEEP_SECONDS=0 MAX_WAIT_BLOCKS=20 TX_WAIT_SECONDS=2 SUMMARY_JSON=1 \
  "$SCRIPT" chain alice http://127.0.0.1:26657 >"$OUT_FILE" 2>&1

grep -q "summary: duration_s=" "$OUT_FILE"
grep -q "SUMMARY_JSON:" "$OUT_FILE"
grep -q "tx_register=txreg" "$OUT_FILE"
grep -q "OK: lifecycle smoke completed" "$OUT_FILE"

SUCCESS_SUMMARY_LINE="$(grep 'SUMMARY_JSON:' "$OUT_FILE" | tail -n1)"
SUCCESS_SUMMARY_JSON="${SUCCESS_SUMMARY_LINE#*SUMMARY_JSON: }"

echo "$SUCCESS_SUMMARY_JSON" | jq -e '
  (keys | sort) == [
    "catching_up","cooldown_stagnant_rounds","cooldown_waited_blocks","duration_s","end_height",
    "height_delta","last_step","last_tx","node_height","reason","release_height","start_height",
    "status","tx_finalize_unbonding","tx_register","tx_request_unbonding","worker"
  ] and
  .status == "ok" and
  .reason == "" and
  .worker == "cosmos1workeraddr" and
  .tx_register == "txreg" and
  .tx_request_unbonding == "txreq" and
  .tx_finalize_unbonding == "txfin" and
  (.start_height | type) == "number" and
  (.end_height | type) == "number" and
  (.height_delta | type) == "number" and
  (.duration_s | type) == "number" and
  (.release_height | type) == "number" and
  (.cooldown_waited_blocks | type) == "number" and
  (.cooldown_stagnant_rounds | type) == "number"
' >/dev/null

# failure path: ensure key diagnostics snapshot is emitted for CI triage
echo 100 >"$TMP_DIR/height"
echo 0 >"$TMP_DIR/finalized"
OUT_FAIL_FILE="$TMP_DIR/out_fail.log"
set +e
MOCK_STATE_DIR="$TMP_DIR" MOCK_FAIL_FINALIZE=1 BIN="$TMP_DIR/chaind" SLEEP_SECONDS=0 MAX_WAIT_BLOCKS=20 TX_WAIT_SECONDS=2 SUMMARY_JSON=1 \
  "$SCRIPT" chain alice http://127.0.0.1:26657 >"$OUT_FAIL_FILE" 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]]
grep -q "failure_snapshot: reason=finalize-unbonding broadcast failed" "$OUT_FAIL_FILE"
grep -q '"status":"failed"' "$OUT_FAIL_FILE"
grep -q '"last_step":"finalize-unbonding"' "$OUT_FAIL_FILE"

FAIL_SUMMARY_LINE="$(grep 'SUMMARY_JSON:' "$OUT_FAIL_FILE" | tail -n1)"
FAIL_SUMMARY_JSON="${FAIL_SUMMARY_LINE#*SUMMARY_JSON: }"

echo "$FAIL_SUMMARY_JSON" | jq -e '
  (keys | sort) == [
    "catching_up","cooldown_stagnant_rounds","cooldown_waited_blocks","duration_s","end_height",
    "height_delta","last_step","last_tx","node_height","reason","release_height","start_height",
    "status","tx_finalize_unbonding","tx_register","tx_request_unbonding","worker"
  ] and
  .status == "failed" and
  (.reason | startswith("finalize-unbonding broadcast failed")) and
  .last_step == "finalize-unbonding" and
  .last_tx == "txfin" and
  .worker == "cosmos1workeraddr" and
  (.start_height | type) == "number" and
  (.release_height | type) == "number"
' >/dev/null

echo "PASS: lifecycle_smoke observability regression"
