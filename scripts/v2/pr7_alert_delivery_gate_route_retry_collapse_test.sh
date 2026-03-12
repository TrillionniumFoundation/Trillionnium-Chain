#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr7-gate-route-retry.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

MOCK_PR6="$TMP/mock_pr6.sh"
MOCK_PR7="$TMP/mock_pr7.py"
RUN_DIR="$TMP/run"
AUDIT_FILE="$TMP/audit.jsonl"
STATE_FILE="$TMP/state.json"
STATUS_FILE="$TMP/status.env"

cat >"$MOCK_PR6" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "${RUN_DIR:?}"
cat >"${RUN_DIR}/summary.txt" <<'EOR'
status=FAIL
alert_code=PR6_TEST
alert_message=route retry collapse
alert_level=CRITICAL
generated_at_utc=2026-03-11T00:00:00Z
EOR
exit 4
EOS
chmod +x "$MOCK_PR6"

cat >"$MOCK_PR7" <<'EOS'
#!/usr/bin/env python3
import argparse, json
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument('--report', required=True)
p.add_argument('--channel', required=True)
p.add_argument('--primary-channel', required=True)
p.add_argument('--backup-channel', default='')
p.add_argument('--audit-file', required=True)
p.add_argument('--state-file', required=True)
p.add_argument('--dead-letter-file', required=True)
p.add_argument('--min-level')
p.add_argument('--dedup-seconds')
p.add_argument('--aggregate-seconds')
p.add_argument('--max-retries')
p.add_argument('--base-backoff-ms')
p.add_argument('--max-backoff-ms')
p.add_argument('--cooldown-info')
p.add_argument('--cooldown-warn')
p.add_argument('--cooldown-critical')
p.add_argument('--warn-escalate-count')
p.add_argument('--warn-escalate-window-seconds')
p.add_argument('--quiet-hours-start')
p.add_argument('--quiet-hours-end')
p.add_argument('--quiet-hours-tz')
p.add_argument('--dry-run', action='store_true')
p.add_argument('--quiet-hours-enabled', action='store_true')
args = p.parse_args()
audit = Path(args.audit_file)
audit.parent.mkdir(parents=True, exist_ok=True)
entries = [
    {
        'at_utc': '2026-03-11T00:00:01Z',
        'fingerprint': 'abc',
        'class_fingerprint': 'abc',
        'level': 'CRITICAL',
        'report_path': args.report,
        'channel': args.primary_channel,
        'reason': 'retry-1',
        'ok': False,
        'attempts': 1,
        'error': 'temporary failure',
        'dry_run': False,
    },
    {
        'at_utc': '2026-03-11T00:00:02Z',
        'fingerprint': 'abc',
        'class_fingerprint': 'abc',
        'level': 'CRITICAL',
        'report_path': args.report,
        'channel': args.primary_channel,
        'reason': 'retry-2',
        'ok': True,
        'attempts': 2,
        'error': '',
        'dry_run': False,
    },
    {
        'at_utc': '2026-03-11T00:00:03Z',
        'fingerprint': 'abc',
        'class_fingerprint': 'abc',
        'level': 'CRITICAL',
        'report_path': args.report,
        'channel': args.backup_channel,
        'reason': 'retry-1',
        'ok': True,
        'attempts': 1,
        'error': '',
        'dry_run': False,
    },
    {
        'at_utc': '2026-03-11T00:00:04Z',
        'fingerprint': 'abc',
        'class_fingerprint': 'abc',
        'level': 'CRITICAL',
        'report_path': args.report,
        'channel': args.backup_channel,
        'reason': 'retry-2',
        'ok': False,
        'attempts': 2,
        'error': 'final failure',
        'dry_run': False,
    },
]
with audit.open('a', encoding='utf-8') as f:
    for item in entries:
        f.write(json.dumps(item) + '\n')
print('[MOCK_PR7] wrote retrying per-channel audit rows without delivery_summary')
raise SystemExit(0)
EOS
chmod +x "$MOCK_PR7"

RUN_DIR="$RUN_DIR" \
PR6_GATE_CMD="$MOCK_PR6" \
PR7_DELIVERY_CMD="$MOCK_PR7" \
PR7_STATUS_FILE="$STATUS_FILE" \
ALERT_NOTIFY_AUDIT_FILE="$AUDIT_FILE" \
ALERT_NOTIFY_STATE_FILE="$STATE_FILE" \
ALERT_NOTIFY_DEAD_LETTER_FILE="$TMP/dead.jsonl" \
ALERT_NOTIFY_CHANNEL=imessage \
ALERT_NOTIFY_PRIMARY_CHANNEL=imessage \
ALERT_NOTIFY_BACKUP_CHANNEL=telegram \
"$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >/dev/null || test $? -eq 4

grep -q '^delivery_event=unknown$' "$STATUS_FILE"
grep -q '^success_channels=imessage$' "$STATUS_FILE"
grep -q '^failed_channels=telegram$' "$STATUS_FILE"
grep -q '^channels_ok=1$' "$STATUS_FILE"
grep -q '^channels_failed=1$' "$STATUS_FILE"
grep -q '^partial_success=1$' "$STATUS_FILE"

echo "[OK] pr7 gate collapses retried route rows to the final per-channel outcome"
