#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TX_CLI="${TRNM_TX_CLI:-trnm-cli}"
REQUIRE_REAL_TX_CLI="${REQUIRE_REAL_TX_CLI:-0}"
OUT_DIR="${OUT_DIR:-$ROOT/data/worker-cli-readiness}"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
REPORT="$OUT_DIR/worker-real-cli-readiness-$TS.md"

status="NOT_READY"
reason=""
cmd_exists="no"
supports_tx="no"

if command -v "$TX_CLI" >/dev/null 2>&1; then
  cmd_exists="yes"
  if "$TX_CLI" tx --help >/dev/null 2>&1; then
    supports_tx="yes"
    status="READY"
    reason="tx subcommand detected"
  else
    reason="tx subcommand missing: '$TX_CLI tx --help' failed"
  fi
else
  reason="tx cli not found in PATH: $TX_CLI"
fi

cat > "$REPORT" <<EOF
# Worker Real CLI Readiness

- ts: \
  $(date '+%F %T %Z')
- tx_cli: \
  \
  \
  $TX_CLI
- status: **$status**
- reason: $reason

## Checks
- command exists: $cmd_exists
- supports \`tx\` subcommand: $supports_tx
- require real tx cli: $REQUIRE_REAL_TX_CLI

## Next Action
- If status is NOT_READY: provide a tx-capable CLI implementation (or wrapper) that supports:
  - \`tx commit-result <task_id> <worker> <commit_hash> <nonce>\`
  - \`tx reveal-result <task_id> <result_hash> <salt_hex>\`
- Then run:
  - \`TRNM_TX_CLI=<your-cli> ./scripts/v2/run_worker_receipt_gates.sh\`
EOF

echo "$REPORT"

if [[ "$REQUIRE_REAL_TX_CLI" == "1" && "$status" != "READY" ]]; then
  echo "[FAIL] real tx cli required but not ready: $reason" >&2
  exit 18
fi
