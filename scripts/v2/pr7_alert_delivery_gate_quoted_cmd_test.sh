#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d /tmp/trnm-pr7-gate-quoted-cmd.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

MOCK_PR6="$TMP/mock_pr6.sh"
MOCK_PR7="$TMP/mock_pr7.py"
RUN_DIR="$TMP/run"
LOG_FILE="$TMP/argv.log"
STATUS_FILE="$TMP/status.env"

cat >"$MOCK_PR6" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "${RUN_DIR:?}"
cat >"${RUN_DIR}/summary.txt" <<'EOR'
status=FAIL
alert_code=PR6_TEST
alert_message=quoted argv preserved
alert_level=CRITICAL
generated_at_utc=2026-03-12T00:00:00Z
EOR
exit 4
EOS
chmod +x "$MOCK_PR6"

cat >"$MOCK_PR7" <<'EOS'
#!/usr/bin/env python3
import argparse
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--report', required=True)
p.add_argument('--channel', required=True)
p.add_argument('--primary-channel', required=True)
p.add_argument('--backup-channel', default='')
p.add_argument('--audit-file', required=True)
p.add_argument('--state-file', required=True)
p.add_argument('--dead-letter-file', required=True)
p.add_argument('--tag', required=True)
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
Path(__import__('os').environ['LOG_FILE']).write_text(args.tag + '\n', encoding='utf-8')
raise SystemExit(0)
EOS
chmod +x "$MOCK_PR7"

RUN_DIR="$RUN_DIR" \
LOG_FILE="$LOG_FILE" \
PR6_GATE_CMD="$MOCK_PR6" \
PR7_DELIVERY_CMD="python3 '$MOCK_PR7' --tag 'alpha beta'" \
PR7_STATUS_FILE="$STATUS_FILE" \
ALERT_NOTIFY_AUDIT_FILE="$TMP/audit.jsonl" \
ALERT_NOTIFY_STATE_FILE="$TMP/state.json" \
ALERT_NOTIFY_DEAD_LETTER_FILE="$TMP/dead.jsonl" \
ALERT_NOTIFY_CHANNEL=imessage \
ALERT_NOTIFY_PRIMARY_CHANNEL=imessage \
"$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >/dev/null || test $? -eq 4

if [[ "$(cat "$LOG_FILE")" != "alpha beta" ]]; then
  echo "[FAIL] quoted PR7_DELIVERY_CMD argument was not preserved"
  cat "$LOG_FILE"
  exit 1
fi

echo "[OK] pr7 gate preserves quoted PR7_DELIVERY_CMD arguments"
