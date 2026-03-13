#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr7-gate-skip-min-level.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

MOCK_PR6="$TMP/mock_pr6.sh"
RUN_DIR="$TMP/run"
AUDIT_FILE="$TMP/audit.jsonl"
STATE_FILE="$TMP/state.json"
STATUS_FILE="$TMP/status.env"

cat >"$MOCK_PR6" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "${RUN_DIR:?}"
cat >"${RUN_DIR}/summary.txt" <<'EOR'
status=PASS
alert_code=PR6_TEST
alert_message=below min-level skip observability
alert_level=INFO
generated_at_utc=2026-03-11T00:00:00Z
EOR
exit 0
EOS
chmod +x "$MOCK_PR6"

RUN_DIR="$RUN_DIR" \
PR6_GATE_CMD="$MOCK_PR6" \
PR7_STATUS_FILE="$STATUS_FILE" \
ALERT_NOTIFY_AUDIT_FILE="$AUDIT_FILE" \
ALERT_NOTIFY_STATE_FILE="$STATE_FILE" \
ALERT_NOTIFY_DEAD_LETTER_FILE="$TMP/dead.jsonl" \
ALERT_NOTIFY_CHANNEL=imessage \
ALERT_NOTIFY_PRIMARY_CHANNEL=imessage \
ALERT_NOTIFY_MIN_LEVEL=WARN \
IMESSAGE_TO=test@example.com \
"$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >/dev/null

grep -q '^delivery_event=skipped_min_level$' "$STATUS_FILE"
grep -q '^primary_channel=imessage$' "$STATUS_FILE"
grep -q '^channels_ok=0$' "$STATUS_FILE"
grep -q '^channels_failed=0$' "$STATUS_FILE"
grep -q '^partial_success=0$' "$STATUS_FILE"
python3 - "$AUDIT_FILE" "$RUN_DIR/summary.txt" <<'PY'
import json
import sys
from pathlib import Path

audit_path = Path(sys.argv[1])
report_path = sys.argv[2]
rows = []
for line in audit_path.read_text(encoding='utf-8').splitlines():
    if not line.strip():
        continue
    rows.append(json.loads(line))
summary = [
    r for r in rows
    if r.get('record_type') == 'delivery_summary'
    and Path(str(r.get('report_path', ''))).resolve() == Path(report_path).resolve()
]
assert len(summary) == 1, summary
row = summary[0]
assert row['event'] == 'skipped_min_level', row
assert row['channels_total'] == 0, row
assert row['channels_ok'] == 0, row
assert row['channels_failed'] == 0, row
assert row['attempts'] == 0, row
assert row['reason'] == 'level=INFO below min_level=WARN', row
PY

echo "[OK] pr7 gate records skipped_min_level delivery summaries for status observability"
