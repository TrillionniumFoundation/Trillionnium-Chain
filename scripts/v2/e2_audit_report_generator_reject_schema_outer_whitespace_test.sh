#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/audit.log"
OUT="$TMP_DIR/report.json"

cat > "$LOG" <<'EOF'
2026-03-02T06:00:00Z [event] event_schema=" v1 " event_type=challenge challenger_delta=-4 treasury_delta=4 note="schema token padded with whitespace must be rejected"
2026-03-02T06:00:01Z [event] event_schema=v1 event_type=resolve challenger_delta=1 treasury_delta=-1 note="canonical"
EOF

python3 "$ROOT/scripts/v2/audit_report_generator.py" "$LOG" > "$OUT"

python3 - "$OUT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
summary = report.get('summary', {})
counts = summary.get('event_counts', {})

if summary.get('total_audit_events') != 1:
    print('[FAIL] expected exactly one canonical audit event after padded schema filtering', file=sys.stderr)
    sys.exit(1)

if counts.get('challenge', 0) != 0:
    print('[FAIL] whitespace-padded event_schema token must not count as challenge event', file=sys.stderr)
    sys.exit(1)

if counts.get('resolve') != 1:
    print('[FAIL] canonical resolve event missing after filtering', file=sys.stderr)
    sys.exit(1)

if summary.get('financial_impact', {}).get('challenger_delta_total') != 1:
    print('[FAIL] challenger_delta_total should only include canonical resolve event', file=sys.stderr)
    sys.exit(1)

if summary.get('financial_impact', {}).get('treasury_delta_total') != -1:
    print('[FAIL] treasury_delta_total should only include canonical resolve event', file=sys.stderr)
    sys.exit(1)

print('[PASS] e2_audit_report_generator_reject_schema_outer_whitespace_test')
PY
