#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

LOG="$TMP_DIR/events.log"
OUT="$TMP_DIR/report.json"

cat > "$LOG" <<'LOGEOF'
2026-03-01T07:00:00Z [event] event_schema=v1 event_type=challenge challenger_delta=-2 treasury_delta=1
2026-03-01T07:00:04Z [event] event_schema=v1 event_type=resolve challenger_delta=3 treasury_delta=-1
LOGEOF

python3 "$ROOT/scripts/v2/audit_report_generator.py" "$LOG" > "$OUT"

python3 - "$OUT" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, 'r', encoding='utf-8') as f:
    report = json.load(f)

rows = report["audit_log"]
assert [r.get("event_ts") for r in rows] == [
    "2026-03-01T07:00:00Z",
    "2026-03-01T07:00:04Z",
], rows
print("[PASS] e2_audit_report_generator_event_ts_test")
PY
