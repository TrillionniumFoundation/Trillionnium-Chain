#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/audit.log"
OUT="$TMP_DIR/report.json"

cat > "$LOG" <<'EOF'
2026-03-02T03:30:00Z [event] event_schema=v1 event_type=slash challenger_delta=1_000 treasury_delta=2_000 note="underscore should be ignored"
2026-03-02T03:30:01Z [event] event_schema=v1 event_type=slash challenger_delta=-3 treasury_delta=3 note="canonical"
EOF

python3 "$ROOT/scripts/v2/audit_report_generator.py" "$LOG" > "$OUT"

python3 - "$OUT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
summary = report.get('summary', {})
impact = summary.get('financial_impact', {})

if summary.get('total_audit_events') != 2:
    print('[FAIL] expected both v1 events to remain in audit log', file=sys.stderr)
    sys.exit(1)

if impact.get('challenger_delta_total') != -3:
    print('[FAIL] challenger_delta_total should ignore underscore numeric token', file=sys.stderr)
    sys.exit(1)

if impact.get('treasury_delta_total') != 3:
    print('[FAIL] treasury_delta_total should ignore underscore numeric token', file=sys.stderr)
    sys.exit(1)

print('[PASS] e2_audit_report_generator_ignore_underscore_numeric_delta_test')
PY
