#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/audit.log"
OUT="$TMP_DIR/report.json"

cat > "$LOG" <<'EOF'
2026-03-03T02:10:00Z [event] event_schema=llm.v2 event_type=challenge challenger_delta=-3 treasury_delta=3 note="dot alias"
2026-03-03T02:10:01Z [event] event_schema=llm_v2 event_type=resolve challenger_delta=2 treasury_delta=-2 note="underscore alias"
2026-03-03T02:10:02Z [event] event_schema=llm-v2 event_type=slash challenger_delta=-9 treasury_delta=9 note="hyphen alias should stay rejected"
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
    print('[FAIL] expected llm.v2 and llm_v2 accepted while llm-v2 rejected', file=sys.stderr)
    sys.exit(1)

if counts.get('challenge') != 1 or counts.get('resolve') != 1:
    print('[FAIL] expected exactly one challenge and one resolve event from llm.v2 aliases', file=sys.stderr)
    sys.exit(1)

if counts.get('slash', 0) != 0:
    print('[FAIL] non-canonical llm-v2 alias must not count as slash event', file=sys.stderr)
    sys.exit(1)

if any(e.get('event_schema') != 'llm2' for e in audit_log):
    print('[FAIL] accepted llm v2 aliases must canonicalize to event_schema=llm2', file=sys.stderr)
    sys.exit(1)

if summary.get('financial_impact', {}).get('challenger_delta_total') != -1:
    print('[FAIL] challenger_delta_total should include only accepted llm.v2 aliases', file=sys.stderr)
    sys.exit(1)

if summary.get('financial_impact', {}).get('treasury_delta_total') != 1:
    print('[FAIL] treasury_delta_total should include only accepted llm.v2 aliases', file=sys.stderr)
    sys.exit(1)

print('[PASS] e2_audit_report_generator_accept_llm_v2_alias_schema_test')
PY
