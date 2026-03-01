#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/audit.log"
OUT="$TMP_DIR/report.json"

cat > "$LOG" <<'EOF'
2026-03-02T01:20:00Z [event] event_schema=v2 event_type=slash challenger_delta=-9 treasury_delta=9 note="legacy marker event_schema=v1"
2026-03-02T01:20:01Z [event] event_schema=v1 event_type=slash challenger_delta=-3 treasury_delta=3 note="canonical"
EOF

python3 "$ROOT/scripts/v2/audit_report_generator.py" "$LOG" > "$OUT"

python3 - "$OUT" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
summary = report.get('summary', {})

if summary.get('total_audit_events') != 1:
    print('[FAIL] expected exactly one v1 audit event after schema-token spoof filtering', file=sys.stderr)
    sys.exit(1)

if summary.get('financial_impact', {}).get('challenger_delta_total') != -3:
    print('[FAIL] challenger_delta_total should only aggregate canonical v1 event', file=sys.stderr)
    sys.exit(1)

if summary.get('financial_impact', {}).get('treasury_delta_total') != 3:
    print('[FAIL] treasury_delta_total should only aggregate canonical v1 event', file=sys.stderr)
    sys.exit(1)

print('[PASS] e2_audit_report_generator_schema_token_spoof_test')
PY
