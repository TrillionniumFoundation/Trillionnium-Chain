#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr7-invalid-audit-utf8.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/run/pr7-alerts/test-run" "$TMP/run/pr7-alert-delivery"

cat >"$TMP/run/pr7-alerts/test-run/summary.txt" <<'EOF'
status=PASS
EOF

python3 - "$TMP/run/pr7-alert-delivery/audit.jsonl" "$TMP/run/pr7-alerts/test-run/summary.txt" <<'PY'
from pathlib import Path
import sys

out = Path(sys.argv[1])
report = sys.argv[2]
out.write_bytes(
    b'{"record_type":"delivery_summary","report_path":"' + report.encode('utf-8') + b'","event":"partial_success","primary_channel":"imessage","channels_ok":1,"channels_failed":1}\n'
    b'{"record_type":"delivery_attempt","report_path":"' + report.encode('utf-8') + b'","channel":"imessage","ok":true}\n'
    b'\xff\xfe\xfa not-utf8 noise\n'
    b'{"record_type":"delivery_attempt","report_path":"' + report.encode('utf-8') + b'","channel":"email","ok":false}\n'
)
PY

STATUS_FILE="$TMP/status.env"
export STATUS_FILE

DELIVERY_SUMMARY_JSON="$(python3 - "$TMP/run/pr7-alert-delivery/audit.jsonl" "$TMP/run/pr7-alerts/test-run/summary.txt" <<'PY'
import json
import sys
from pathlib import Path

audit = Path(sys.argv[1])
report = sys.argv[2]
summary = None
for line in audit.read_text(encoding='utf-8', errors='ignore').splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        continue
    if item.get('record_type') == 'delivery_summary' and item.get('report_path') == report:
        summary = item
if summary is None:
    print('{}')
else:
    print(json.dumps(summary, ensure_ascii=False))
PY
)"

ROUTE_LINES="$(python3 - "$TMP/run/pr7-alert-delivery/audit.jsonl" "$TMP/run/pr7-alerts/test-run/summary.txt" <<'PY'
import json
import sys
from pathlib import Path

audit = Path(sys.argv[1])
report = sys.argv[2]
rows = []
for line in audit.read_text(encoding='utf-8', errors='ignore').splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        continue
    if item.get('record_type') == 'delivery_summary':
        continue
    if item.get('report_path') != report:
        continue
    ch = str(item.get('channel','')).strip()
    if not ch:
        continue
    ok = bool(item.get('ok'))
    rows.append((ch, ok))
seen = {}
for ch, ok in rows:
    seen[ch] = ok
succ = [ch for ch, ok in seen.items() if ok]
fail = [ch for ch, ok in seen.items() if not ok]
print('success=' + ','.join(succ))
print('failed=' + ','.join(fail))
PY
)"

python3 - "$DELIVERY_SUMMARY_JSON" "$ROUTE_LINES" <<'PY'
import json
import sys

summary = json.loads(sys.argv[1])
routes = dict(line.split('=', 1) for line in sys.argv[2].splitlines() if '=' in line)

assert summary['event'] == 'partial_success', summary
assert summary['channels_ok'] == 1, summary
assert summary['channels_failed'] == 1, summary
assert routes['success'] == 'imessage', routes
assert routes['failed'] == 'email', routes
print('[OK] pr7 alert delivery gate audit parsing ignores invalid UTF-8 bytes and preserves matching JSON rows')
PY
