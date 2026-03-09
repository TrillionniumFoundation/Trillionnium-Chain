#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/audit.log"
OUT="$TMP_DIR/report.json"

cat > "$LOG" <<'EOF'
2026-03-02T01:30:00Z [event] event_schema=llm2 event_type=challenge challenger_delta=-5 treasury_delta=5 note="llm2 schema"
2026-03-02T01:30:01Z [event] event_schema=compact event_type=resolve challenger_delta=2 treasury_delta=-2 note="compact schema"
2026-03-02T01:30:02Z [event] event_schema=v2 event_type=slash challenger_delta=-9 treasury_delta=9 note="non-canonical"
EOF

python3 "$ROOT/scripts/v2/audit_report_generator.py" "$LOG" > "$OUT"

python3 - "$OUT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
summary = report.get('summary', {})
counts = summary.get('event_counts', {})

if summary.get('total_audit_events') != 2:
    print('[FAIL] expected llm2 + compact events to be accepted and v2 rejected', file=sys.stderr)
    sys.exit(1)

if counts.get('challenge') != 1 or counts.get('resolve') != 1:
    print('[FAIL] expected challenge/resolve counts from llm2+compact events', file=sys.stderr)
    sys.exit(1)

if summary.get('financial_impact', {}).get('challenger_delta_total') != -3:
    print('[FAIL] challenger_delta_total should sum llm2+compact events only', file=sys.stderr)
    sys.exit(1)

if summary.get('financial_impact', {}).get('treasury_delta_total') != 3:
    print('[FAIL] treasury_delta_total should sum llm2+compact events only', file=sys.stderr)
    sys.exit(1)

print('[PASS] e2_audit_report_generator_llm2_compact_schema_test')
PY
