#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GEN="$ROOT/scripts/v2/audit_report_generator.py"

tmp_log="$(mktemp)"
tmp_json="$(mktemp)"
trap 'rm -f "$tmp_log" "$tmp_json"' EXIT

cat >"$tmp_log" <<'LOG'
2026-03-03T02:20:00Z [event] event_schema=LLM_V2 event_type=challenge challenger_delta=-8 treasury_delta=8 note="uppercase alias must be rejected"
2026-03-03T02:20:01Z [event] event_schema=llm_v2 event_type=resolve challenger_delta=3 treasury_delta=-3 note="canonical alias"
LOG

python3 "$GEN" "$tmp_log" >"$tmp_json"

python3 - "$tmp_json" <<'PY'
import json
import sys

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    report = json.load(f)

rows = report.get('audit_log', [])
if len(rows) != 1:
    print('[FAIL] expected exactly one canonical audit event after uppercase alias filtering', file=sys.stderr)
    sys.exit(1)

if rows[0].get('event_schema') != 'llm2':
    print('[FAIL] expected canonical llm2 schema in retained event', file=sys.stderr)
    sys.exit(1)

if rows[0].get('event_type') != 'resolve':
    print('[FAIL] expected lowercase canonical resolve event to remain', file=sys.stderr)
    sys.exit(1)

summary = report.get('summary', {})
counts = summary.get('event_counts', {})
if counts.get('challenge', 0) != 0:
    print('[FAIL] uppercase alias event_schema token must not count as challenge event', file=sys.stderr)
    sys.exit(1)

if counts.get('resolve', 0) != 1:
    print('[FAIL] expected one resolve event after filtering', file=sys.stderr)
    sys.exit(1)

print('[PASS] e2_audit_report_generator_reject_uppercase_llm_v2_alias_schema_test')
PY
