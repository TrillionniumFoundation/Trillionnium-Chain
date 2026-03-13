#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr7-gate-min-level-alias-route.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

RUN_DIR="$TMP/run"
mkdir -p "$RUN_DIR"

MOCK_PR6="$TMP/mock-pr6.sh"
cat >"$MOCK_PR6" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$RUN_DIR"
cat >"$RUN_DIR/summary.txt" <<'EOF'
status=FAIL
alert_level=CRITICAL
alert_code=PR6_ALERT_RULES
alert_message=critical alias routing regression
rule.unresolved_challenges.status=FAIL
rule.unresolved_challenges.value=9
rule.forfeits_daily_increase.status=PASS
rule.forfeits_daily_increase.value=0
rule.escrow_nonzero_hours.status=PASS
rule.escrow_nonzero_hours.value=0
EOF
SH
chmod +x "$MOCK_PR6"

MOCK_PR7="$TMP/mock-pr7.py"
cat >"$MOCK_PR7" <<'PY'
#!/usr/bin/env python3
import argparse
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--report')
p.add_argument('--channel')
p.add_argument('--primary-channel')
p.add_argument('--backup-channel')
p.add_argument('--audit-file')
p.add_argument('--state-file')
p.add_argument('--dead-letter-file')
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
Path(args.audit_file).parent.mkdir(parents=True, exist_ok=True)
Path(args.audit_file).write_text('', encoding='utf-8')
print(f"channel={args.channel}")
print(f"primary_channel={args.primary_channel}")
print(f"min_level={args.min_level}")
PY
chmod +x "$MOCK_PR7"

OUT="$TMP/out.txt"
RUN_DIR="$RUN_DIR" \
PR6_GATE_CMD="$MOCK_PR6" \
PR7_DELIVERY_CMD="python3 $MOCK_PR7" \
ALERT_NOTIFY_MIN_LEVEL=FAIL \
ALERT_NOTIFY_CHANNEL_INFO=telegram \
ALERT_NOTIFY_CHANNEL_WARN=slack \
ALERT_NOTIFY_CHANNEL_CRITICAL=imessage \
"$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$OUT" 2>&1

grep -q '^channel=imessage$' "$OUT"
grep -q '^primary_channel=imessage$' "$OUT"
grep -q '^min_level=FAIL$' "$OUT"

echo "[OK] pr7 gate maps ALERT_NOTIFY_MIN_LEVEL=FAIL alias to the critical fallback route"
