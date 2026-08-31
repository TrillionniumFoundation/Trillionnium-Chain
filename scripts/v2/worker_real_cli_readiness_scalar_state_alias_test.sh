#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP_DIR="$(mktemp -d /tmp/trnm-readiness-scalar-state.XXXXXX)"
TMP_LOG="$TMP_DIR/readiness.log"
FAKE_CLI="$TMP_DIR/fake-cli.sh"
trap 'rm -rf "$TMP_DIR"' EXIT

cat >"$FAKE_CLI" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "tx" && "${2:-}" == "--help" ]]; then
  exit 0
fi
if [[ "${1:-}" == "tx" && "${2:-}" == "commit-result" ]]; then
  echo 'txHash=0xABCDEF0123456789'
  exit 0
fi
if [[ "${1:-}" == "tx" && "${2:-}" == "query" ]]; then
  echo '{"transactionHash":"0xABCDEF0123456789","transactionState":true}'
  exit 0
fi
exit 2
EOF
chmod +x "$FAKE_CLI"

OUT_PATH=""
set +e
OUT_PATH=$(OUT_DIR="$TMP_DIR/out" TRNM_TX_CLI="$FAKE_CLI" ./scripts/v2/worker_real_cli_readiness.sh 2>"$TMP_LOG")
rc=$?
set -e

if [[ "$rc" -ne 0 ]]; then
  echo "[FAIL] readiness script should accept transactionState boolean aliases (rc=$rc)" >&2
  sed -n '1,160p' "$TMP_LOG" >&2 || true
  exit 1
fi

REPORT_PATH="$(printf '%s\n' "$OUT_PATH" | tail -n1)"
if [[ ! -f "$REPORT_PATH" ]]; then
  echo "[FAIL] readiness script did not return a readable report path" >&2
  printf 'OUT_PATH=%s\n' "$OUT_PATH" >&2
  sed -n '1,160p' "$TMP_LOG" >&2 || true
  exit 1
fi

if ! grep -q 'status: \*\*READY\*\*' "$REPORT_PATH"; then
  echo "[FAIL] readiness report did not mark adapter READY" >&2
  sed -n '1,160p' "$REPORT_PATH" >&2 || true
  exit 1
fi

if ! grep -q 'probe query hash match: yes' "$REPORT_PATH"; then
  echo "[FAIL] readiness report did not confirm query hash match" >&2
  sed -n '1,160p' "$REPORT_PATH" >&2 || true
  exit 1
fi

if ! grep -q 'probe query status: committed' "$REPORT_PATH"; then
  echo "[FAIL] readiness report did not normalize scalar lifecycle status evidence" >&2
  sed -n '1,160p' "$REPORT_PATH" >&2 || true
  exit 1
fi

echo "[OK] worker_real_cli_readiness_scalar_state_alias_test passed"
