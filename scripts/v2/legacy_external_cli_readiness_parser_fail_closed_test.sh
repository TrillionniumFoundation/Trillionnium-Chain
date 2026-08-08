#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP_DIR="$(mktemp -d /tmp/trnm-readiness-fail-closed.XXXXXX)"
FAKE_CLI="$TMP_DIR/fake-cli.sh"
trap 'rm -rf "$TMP_DIR"' EXIT

cat > "$FAKE_CLI" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-}:${2:-}" in
  tx:--help)
    exit 0
    ;;
  tx:commit-result)
    echo 'transaction_hash=0xABCDEF0123456789'
    exit 0
    ;;
  tx:query)
    case "${READINESS_FIXTURE_CASE:?}" in
      rejected|failed|pending|error)
        printf '{"transactionHash":"0xABCDEF0123456789","status":"%s"}\n' \
          "$READINESS_FIXTURE_CASE"
        ;;
      scalar_false)
        echo '{"transactionHash":"0xABCDEF0123456789","transactionState":false}'
        ;;
      scalar_one)
        echo '{"transactionHash":"0xABCDEF0123456789","transactionState":1}'
        ;;
      scalar_zero)
        echo '{"transactionHash":"0xABCDEF0123456789","transactionState":0}'
        ;;
      decoy_snake)
        echo '{"decoy_tx_hash":"0xABCDEF0123456789","status":"confirmed"}'
        ;;
      decoy_camel)
        echo '{"decoy_transactionHash":"0xABCDEF0123456789","status":"confirmed"}'
        ;;
      envelope_status_conflict)
        echo '{"status":"ok","result":{"transactionHash":"0xABCDEF0123456789","transactionStatus":"rejected"}}'
        ;;
      envelope_status_only)
        echo '{"status":"ok","result":{"transactionHash":"0xABCDEF0123456789"}}'
        ;;
      hash_conflict)
        echo '{"transactionHash":"0xABCDEF0123456789","status":"confirmed","result":{"tx_hash":"0x1111111111111111","transactionStatus":"confirmed"}}'
        ;;
      duplicate_json_key)
        echo '{"transactionHash":"0xABCDEF0123456789","status":"rejected","status":"ok"}'
        ;;
      malformed_json_array)
        echo '[{"transactionHash":"0xABCDEF0123456789","status":"committed"},BROKEN]'
        ;;
      stale_retry)
        count=0
        if [[ -f "$READINESS_QUERY_COUNT_FILE" ]]; then
          count="$(sed -n '1p' "$READINESS_QUERY_COUNT_FILE")"
        fi
        count=$((count + 1))
        printf '%s\n' "$count" > "$READINESS_QUERY_COUNT_FILE"
        if [[ "$count" -eq 1 ]]; then
          echo '{"transactionHash":"0xABCDEF0123456789","status":"unknown"}'
        else
          echo '{"transactionHash":"0x1111111111111111","status":"confirmed"}'
        fi
        ;;
      *)
        echo "unknown fixture case" >&2
        exit 2
        ;;
    esac
    exit 0
    ;;
esac

exit 2
EOF
chmod +x "$FAKE_CLI"

run_case() {
  local name="$1"
  local expected_rc="$2"
  local expected_status="$3"
  local case_dir="$TMP_DIR/$name"
  local counter="$case_dir/query-count"
  local stderr_log="$case_dir/stderr.log"
  local output=""
  local rc=0
  local report=""

  mkdir -p "$case_dir"
  set +e
  output=$(OUT_DIR="$case_dir/out" \
    TRNM_TX_CLI="$FAKE_CLI" \
    REQUIRE_REAL_TX_CLI=1 \
    TRNM_REALCLI_QUERY_RETRIES=2 \
    TRNM_REALCLI_QUERY_RETRY_SLEEP_SEC=0 \
    READINESS_FIXTURE_CASE="$name" \
    READINESS_QUERY_COUNT_FILE="$counter" \
    ./scripts/v2/worker_real_cli_readiness.sh 2>"$stderr_log")
  rc=$?
  set -e

  if [[ "$rc" -ne "$expected_rc" ]]; then
    echo "[FAIL] readiness case $name expected rc=$expected_rc got rc=$rc" >&2
    sed -n '1,160p' "$stderr_log" >&2 || true
    exit 1
  fi

  report="$(printf '%s\n' "$output" | tail -n1)"
  if [[ ! -f "$report" ]]; then
    echo "[FAIL] readiness case $name did not produce a report" >&2
    exit 1
  fi
  if ! grep -Fq -- "status: **$expected_status**" "$report"; then
    echo "[FAIL] readiness case $name expected report status $expected_status" >&2
    sed -n '1,160p' "$report" >&2
    exit 1
  fi
}

for negative in \
  rejected failed pending error scalar_false scalar_one decoy_snake decoy_camel \
  envelope_status_conflict envelope_status_only hash_conflict duplicate_json_key \
  malformed_json_array stale_retry; do
  run_case "$negative" 18 NOT_READY
done
run_case scalar_zero 0 READY

echo "[OK] legacy external CLI readiness parser fails closed on negative, decoy, and cross-retry evidence"
