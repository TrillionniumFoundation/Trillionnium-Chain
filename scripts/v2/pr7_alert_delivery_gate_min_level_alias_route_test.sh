#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/trnm-pr7-gate-effective-level-route.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

MOCK_PR6="$TMP/mock-pr6.sh"
cat >"$MOCK_PR6" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$RUN_DIR"

case "${MOCK_REPORT_MODE:-critical}" in
  critical)
    cat >"$RUN_DIR/summary.txt" <<'EOF'
status=FAIL
alert_level=CRITICAL
alert_code=PR6_ALERT_RULES
alert_message=critical effective-level routing regression
rule.unresolved_challenges.status=FAIL
rule.unresolved_challenges.value=9
rule.forfeits_daily_increase.status=PASS
rule.forfeits_daily_increase.value=0
rule.escrow_nonzero_hours.status=PASS
rule.escrow_nonzero_hours.value=0
EOF
    ;;
  warn)
    cat >"$RUN_DIR/summary.txt" <<'EOF'
status=WARN
alert_level=WARN
alert_code=PR6_ALERT_RULES
alert_message=warn escalation routing regression
rule.unresolved_challenges.status=WARN
rule.unresolved_challenges.value=4
rule.forfeits_daily_increase.status=PASS
rule.forfeits_daily_increase.value=0
rule.escrow_nonzero_hours.status=PASS
rule.escrow_nonzero_hours.value=0
EOF
    ;;
  *)
    echo "unknown MOCK_REPORT_MODE=${MOCK_REPORT_MODE:-}" >&2
    exit 2
    ;;
esac
SH
chmod +x "$MOCK_PR6"

assert_delivery_summary() {
  local audit_file="$1"
  local expected_channel="$2"
  local expected_level="$3"

  python3 - "$audit_file" "$expected_channel" "$expected_level" <<'PY'
import json
import sys
from pathlib import Path

audit_path = Path(sys.argv[1])
expected_channel = sys.argv[2]
expected_level = sys.argv[3]
summaries = []
for raw in audit_path.read_text(encoding="utf-8").splitlines():
    item = json.loads(raw)
    if item.get("record_type") == "delivery_summary":
        summaries.append(item)
if len(summaries) != 1:
    raise SystemExit(f"expected one delivery summary, got {len(summaries)}")
summary = summaries[0]
if summary.get("primary_channel") != expected_channel:
    raise SystemExit(
        f"expected primary_channel={expected_channel}, got {summary.get('primary_channel')}"
    )
if summary.get("level") != expected_level:
    raise SystemExit(f"expected level={expected_level}, got {summary.get('level')}")
PY
}

run_case() {
  local name="$1"
  local report_mode="$2"
  local escalate_count="$3"
  local override_kind="$4"
  local expected_channel="$5"
  local expected_level="$6"
  local case_dir="$TMP/$name"
  local run_dir="$case_dir/run"
  local audit_file="$case_dir/audit.jsonl"
  local state_file="$case_dir/state.json"
  local dead_file="$case_dir/dead-letter.jsonl"
  local out_file="$case_dir/out.txt"

  mkdir -p "$case_dir"

  case "$override_kind" in
    none)
      env -u ALERT_NOTIFY_PRIMARY_CHANNEL -u ALERT_NOTIFY_CHANNEL \
        ALERT_POLICY_FILE="$case_dir/missing-policy.json" \
        RUN_DIR="$run_dir" \
        PR6_GATE_CMD="$MOCK_PR6" \
        MOCK_REPORT_MODE="$report_mode" \
        PR7_GATE_LOCK_DIR="$case_dir/gate.lock" \
        ALERT_NOTIFY_AUDIT_FILE="$audit_file" \
        ALERT_NOTIFY_STATE_FILE="$state_file" \
        ALERT_NOTIFY_DEAD_LETTER_FILE="$dead_file" \
        ALERT_NOTIFY_MIN_LEVEL=WARN \
        ALERT_NOTIFY_CHANNEL_INFO=slack \
        ALERT_NOTIFY_CHANNEL_WARN=imessage \
        ALERT_NOTIFY_CHANNEL_CRITICAL=telegram \
        ALERT_NOTIFY_WARN_ESCALATE_COUNT="$escalate_count" \
        ALERT_NOTIFY_QUIET_HOURS_ENABLED=0 \
        DRY_RUN=1 \
        "$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$out_file" 2>&1
      ;;
    primary)
      env -u ALERT_NOTIFY_CHANNEL \
        ALERT_POLICY_FILE="$case_dir/missing-policy.json" \
        RUN_DIR="$run_dir" \
        PR6_GATE_CMD="$MOCK_PR6" \
        MOCK_REPORT_MODE="$report_mode" \
        PR7_GATE_LOCK_DIR="$case_dir/gate.lock" \
        ALERT_NOTIFY_AUDIT_FILE="$audit_file" \
        ALERT_NOTIFY_STATE_FILE="$state_file" \
        ALERT_NOTIFY_DEAD_LETTER_FILE="$dead_file" \
        ALERT_NOTIFY_MIN_LEVEL=WARN \
        ALERT_NOTIFY_CHANNEL_INFO=slack \
        ALERT_NOTIFY_CHANNEL_WARN=imessage \
        ALERT_NOTIFY_CHANNEL_CRITICAL=telegram \
        ALERT_NOTIFY_PRIMARY_CHANNEL=slack \
        ALERT_NOTIFY_WARN_ESCALATE_COUNT="$escalate_count" \
        ALERT_NOTIFY_QUIET_HOURS_ENABLED=0 \
        DRY_RUN=1 \
        "$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$out_file" 2>&1
      ;;
    legacy)
      env -u ALERT_NOTIFY_PRIMARY_CHANNEL \
        ALERT_POLICY_FILE="$case_dir/missing-policy.json" \
        RUN_DIR="$run_dir" \
        PR6_GATE_CMD="$MOCK_PR6" \
        MOCK_REPORT_MODE="$report_mode" \
        PR7_GATE_LOCK_DIR="$case_dir/gate.lock" \
        ALERT_NOTIFY_AUDIT_FILE="$audit_file" \
        ALERT_NOTIFY_STATE_FILE="$state_file" \
        ALERT_NOTIFY_DEAD_LETTER_FILE="$dead_file" \
        ALERT_NOTIFY_MIN_LEVEL=WARN \
        ALERT_NOTIFY_CHANNEL_INFO=slack \
        ALERT_NOTIFY_CHANNEL_WARN=imessage \
        ALERT_NOTIFY_CHANNEL_CRITICAL=telegram \
        ALERT_NOTIFY_CHANNEL=slack \
        ALERT_NOTIFY_WARN_ESCALATE_COUNT="$escalate_count" \
        ALERT_NOTIFY_QUIET_HOURS_ENABLED=0 \
        DRY_RUN=1 \
        "$ROOT/scripts/v2/pr7_alert_delivery_gate.sh" >"$out_file" 2>&1
      ;;
    *)
      echo "unknown override kind: $override_kind" >&2
      exit 2
      ;;
  esac

  grep -q "^primary_channel=${expected_channel}$" "$run_dir/pr7-delivery-status.env"
  assert_delivery_summary "$audit_file" "$expected_channel" "$expected_level"
}

# The threshold remains WARN, but a CRITICAL report must use the canonical
# critical route instead of the WARN route.
run_case critical_report critical 0 none telegram CRITICAL

# Route selection happens after WARN escalation, so an escalated WARN also uses
# the CRITICAL route.
run_case warn_escalation warn 1 none telegram CRITICAL

# Both explicit override contracts remain authoritative for every level.
run_case explicit_primary critical 0 primary slack CRITICAL
run_case legacy_channel critical 0 legacy slack CRITICAL

echo "[OK] pr7 gate routes by effective level and preserves explicit channel overrides"
