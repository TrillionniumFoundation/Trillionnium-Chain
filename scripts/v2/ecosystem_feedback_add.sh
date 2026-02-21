#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LOG="$ROOT/docs/ecosystem/alpha-feedback-log.md"

FEEDBACK_ID="${1:-}"
SOURCE="${2:-}"
COMPONENT="${3:-}"
SEVERITY="${4:-S2}"
STATUS="${5:-open}"
OWNER="${6:-tbd}"
LINKED="${7:-n/a}"

if [[ -z "$FEEDBACK_ID" || -z "$SOURCE" || -z "$COMPONENT" ]]; then
  echo "usage: $0 <feedback_id> <source> <component> [severity] [status] [owner] [linked_issue]" >&2
  exit 2
fi

cat >> "$LOG" <<EOF

### $FEEDBACK_ID
- source: $SOURCE
- component: $COMPONENT
- severity: $SEVERITY
- repro_steps: TODO
- expected: TODO
- actual: TODO
- status: $STATUS
- owner: $OWNER
- linked_issue: $LINKED
- updated_at: $(date +%F)
EOF

echo "[OK] feedback appended: $FEEDBACK_ID"
