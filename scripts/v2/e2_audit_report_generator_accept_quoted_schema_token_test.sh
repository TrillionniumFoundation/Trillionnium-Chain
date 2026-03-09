#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/audit.log"
OUT="$TMP_DIR/report.json"

cat > "$LOG" <<'EOF'
2026-03-02T07:00:00Z [event] event_schema="v1" event_type=challenge challenger_delta=-6 treasury_delta=6 note="quoted canonical schema token"
2026-03-02T07:00:01Z [event] event_schema=v1 event_type=resolve challenger_delta=2 treasury_delta=-2 note="plain canonical schema token"
2026-03-02T07:00:02Z [event] event_schema="v1." event_type=slash challenger_delta=-9 treasury_delta=9 note="quoted punctuation-suffixed schema must still be rejected"
EOF

python3 "$ROOT/scripts/v2/audit_report_generator.py" "$LOG" > "$OUT"

python3 - "$OUT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
summary = report.get('summary', {})
counts = summary.get('event_counts', {})
audit_log = report.get('audit_log', [])

if summary.get('total_audit_events') != 2:
    print('[FAIL] expected quoted v1 + plain v1 events accepted and quoted v1. rejected', file=sys.stderr)
    sys.exit(1)

if counts.get('challenge') != 1 or counts.get('resolve') != 1:
    print('[FAIL] expected exactly one challenge and one resolve event', file=sys.stderr)
    sys.exit(1)

if counts.get('slash', 0) != 0:
    print('[FAIL] quoted punctuation-suffixed schema token must not count as slash event', file=sys.stderr)
    sys.exit(1)

if len(audit_log) != 2:
    print('[FAIL] audit log should contain only accepted canonical schema events', file=sys.stderr)
    sys.exit(1)

if summary.get('financial_impact', {}).get('challenger_delta_total') != -4:
    print('[FAIL] challenger_delta_total should include only accepted canonical schema events', file=sys.stderr)
    sys.exit(1)

if summary.get('financial_impact', {}).get('treasury_delta_total') != 4:
    print('[FAIL] treasury_delta_total should include only accepted canonical schema events', file=sys.stderr)
    sys.exit(1)

print('[PASS] e2_audit_report_generator_accept_quoted_schema_token_test')
PY
