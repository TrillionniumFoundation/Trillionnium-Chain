#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TX_CLI="${TRNM_TX_CLI:-trnm-node}"
OUT_DIR="${OUT_DIR:-$ROOT/data/worker-cli-readiness}"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
REPORT="$OUT_DIR/worker-real-cli-readiness-$TS.md"

status="NOT_READY"
reason=""

if ! command -v "$TX_CLI" >/dev/null 2>&1; then
  reason="tx cli not found in PATH: $TX_CLI"
else
  if "$TX_CLI" tx --help >/dev/null 2>&1; then
    status="READY"
    reason="tx subcommand detected"
  else
    reason="tx subcommand missing: '$TX_CLI tx --help' failed"
  fi
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
- command exists: $(command -v "$TX_CLI" >/dev/null 2>&1 && echo yes || echo no)
- supports \`tx\` subcommand: $("$TX_CLI" tx --help >/dev/null 2>&1 && echo yes || echo no)

## Next Action
- If status is NOT_READY: provide a tx-capable CLI implementation (or wrapper) that supports:
  - \`tx commit-result <task_id> <worker> <commit_hash> <nonce>\`
  - \`tx reveal-result <task_id> <result_hash> <salt_hex>\`
- Then run:
  - \`TRNM_TX_CLI=<your-cli> ./scripts/v2/run_worker_receipt_gates.sh\`
EOF

echo "$REPORT"
