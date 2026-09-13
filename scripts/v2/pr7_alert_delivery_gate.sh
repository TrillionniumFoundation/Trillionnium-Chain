#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
now_utc_compact() {
  date -u +%Y%m%d-%H%M%S
}
if [[ -z "${RUN_DIR:-}" ]]; then
  TS="$(now_utc_compact)"
  RUN_DIR="$ROOT/run/pr7-alerts/${TS}-pid$$"
fi
mkdir -p "$RUN_DIR"

PR6_GATE_CMD="${PR6_GATE_CMD:-$ROOT/scripts/v2/pr6_alert_rules_gate.sh}"
PR7_DELIVERY_CMD="${PR7_DELIVERY_CMD:-python3 $ROOT/scripts/v2/pr7_alert_delivery.py}"
PR7_DELIVERY_FAIL_MODE="${PR7_DELIVERY_FAIL_MODE:-ignore}" # ignore|warn|escalate
STATUS_FILE="${PR7_STATUS_FILE:-$RUN_DIR/pr7-delivery-status.env}"
LOCK_DIR="${PR7_GATE_LOCK_DIR:-$ROOT/run/pr7-alert-delivery/.gate-lock}"
LOCK_WAIT_SECONDS="${PR7_GATE_LOCK_WAIT_SECONDS:-30}"
LOCK_JITTER_MIN_MS="${PR7_GATE_LOCK_JITTER_MIN_MS:-100}"
LOCK_JITTER_MAX_MS="${PR7_GATE_LOCK_JITTER_MAX_MS:-299}"

require_non_negative_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "[PR7][FAIL] invalid $name='$value' (expect non-negative integer)" >&2
    exit 2
  fi
}

require_enum() {
  local name="$1"
  local value="$2"
  shift 2
  local candidate
  for candidate in "$@"; do
    if [[ "$value" == "$candidate" ]]; then
      return 0
    fi
  done
  echo "[PR7][FAIL] invalid $name='$value' (allowed: $*)" >&2
  exit 2
}

split_shell_words() {
  local text="$1"
  python3 - "$text" <<'PY'
import shlex
import sys

try:
    for item in shlex.split(sys.argv[1]):
        print(item)
except ValueError as exc:
    print(f"[PR7][FAIL] invalid PR7_DELIVERY_CMD: {exc}", file=sys.stderr)
    raise SystemExit(2)
PY
}

require_non_negative_integer "PR7_GATE_LOCK_WAIT_SECONDS" "$LOCK_WAIT_SECONDS"
require_non_negative_integer "PR7_GATE_LOCK_JITTER_MIN_MS" "$LOCK_JITTER_MIN_MS"
require_non_negative_integer "PR7_GATE_LOCK_JITTER_MAX_MS" "$LOCK_JITTER_MAX_MS"
if (( LOCK_JITTER_MAX_MS < LOCK_JITTER_MIN_MS )); then
  echo "[PR7][FAIL] PR7_GATE_LOCK_JITTER_MAX_MS must be >= PR7_GATE_LOCK_JITTER_MIN_MS" >&2
  exit 2
fi
require_enum "PR7_DELIVERY_FAIL_MODE" "$PR7_DELIVERY_FAIL_MODE" ignore warn escalate
if [[ ! -x "$PR6_GATE_CMD" ]]; then
  echo "[PR7][FAIL] PR6_GATE_CMD not executable: $PR6_GATE_CMD" >&2
  exit 2
fi
if [[ -z "${PR7_DELIVERY_CMD// }" ]]; then
  echo "[PR7][FAIL] PR7_DELIVERY_CMD is empty" >&2
  exit 2
fi

if ! PR7_DELIVERY_CMD_LINES="$(split_shell_words "$PR7_DELIVERY_CMD")"; then
  exit 2
fi
PR7_DELIVERY_CMD_ARR=()
while IFS= read -r cmd_arg; do
  PR7_DELIVERY_CMD_ARR[${#PR7_DELIVERY_CMD_ARR[@]}]="$cmd_arg"
done <<<"$PR7_DELIVERY_CMD_LINES"
if (( ${#PR7_DELIVERY_CMD_ARR[@]} == 0 )); then
  echo "[PR7][FAIL] PR7_DELIVERY_CMD resolved to zero argv entries" >&2
  exit 2
fi
if [[ -z "${PR7_DELIVERY_CMD_ARR[0]}" ]]; then
  echo "[PR7][FAIL] PR7_DELIVERY_CMD resolved to an empty command token" >&2
  exit 2
fi

# Optional: resolve versioned policy config (without overriding explicit env)
POLICY_FILE="${ALERT_POLICY_FILE:-$ROOT/config/alert-policy/current.json}"
if [[ -f "$POLICY_FILE" ]]; then
  POLICY_ENV="$RUN_DIR/policy.env"
  python3 "$ROOT/scripts/v2/alert_policy_resolve.py" \
    --policy "$POLICY_FILE" \
    --profile "${ALERT_POLICY_PROFILE:-default}" \
    --out-env "$POLICY_ENV" \
    --only-missing \
    --audit
  # shellcheck disable=SC1090
  source "$POLICY_ENV"
fi

require_enum "ALERT_NOTIFY_MIN_LEVEL" "${ALERT_NOTIFY_MIN_LEVEL:-WARN}" INFO WARN CRITICAL PASS FAIL

# Preserve the legacy single-channel override contract while allowing the
# delivery implementation to choose a policy route from the *effective* alert
# level after normalization and WARN escalation. Policy resolution populates
# only the per-level route variables, so capture explicit overrides separately.
EXPLICIT_PRIMARY_CHANNEL="${ALERT_NOTIFY_PRIMARY_CHANNEL:-}"
EXPLICIT_LEGACY_CHANNEL="${ALERT_NOTIFY_CHANNEL:-}"
ROUTE_BY_EFFECTIVE_LEVEL=1
if [[ -n "$EXPLICIT_PRIMARY_CHANNEL" || -n "$EXPLICIT_LEGACY_CHANNEL" ]]; then
  ROUTE_BY_EFFECTIVE_LEVEL=0
fi

ROUTE_CHANNEL_INFO="${ALERT_NOTIFY_CHANNEL_INFO:-imessage}"
ROUTE_CHANNEL_WARN="${ALERT_NOTIFY_CHANNEL_WARN:-imessage}"
ROUTE_CHANNEL_CRITICAL="${ALERT_NOTIFY_CHANNEL_CRITICAL:-imessage}"

write_status_file() {
  mkdir -p "$(dirname "$STATUS_FILE")"
  cat >"$STATUS_FILE" <<EOF
status=$1
pr6_rc=$2
pr7_rc=$3
final_rc=$4
fail_mode=${PR7_DELIVERY_FAIL_MODE}
delivery_event=$5
primary_channel=${ALERT_NOTIFY_PRIMARY_CHANNEL:-${ALERT_NOTIFY_CHANNEL:-}}
backup_channel=${ALERT_NOTIFY_BACKUP_CHANNEL:-}
success_channels=
failed_channels=
channels_ok=0
channels_failed=0
partial_success=0
run_dir=${RUN_DIR}
lock_dir=${LOCK_DIR}
report=${6:-}
audit_file=${ALERT_NOTIFY_AUDIT_FILE:-$ROOT/run/pr7-alert-delivery/audit.jsonl}
generated_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
}

acquire_lock() {
  local start now elapsed jitter_range jitter
  mkdir -p "$(dirname "$LOCK_DIR")"
  start="$(date +%s)"
  while ! mkdir "$LOCK_DIR" 2>/dev/null; do
    now="$(date +%s)"
    elapsed=$(( now - start ))
    if (( elapsed >= LOCK_WAIT_SECONDS )); then
      echo "[PR7][FAIL] lock timeout after ${LOCK_WAIT_SECONDS}s lock_dir=$LOCK_DIR" >&2
      return 1
    fi
    if (( LOCK_JITTER_MAX_MS == LOCK_JITTER_MIN_MS )); then
      jitter="$LOCK_JITTER_MIN_MS"
    else
      jitter_range=$(( LOCK_JITTER_MAX_MS - LOCK_JITTER_MIN_MS + 1 ))
      jitter=$(( (RANDOM % jitter_range) + LOCK_JITTER_MIN_MS ))
    fi
    sleep "0.$jitter"
  done
  echo "$$" >"$LOCK_DIR/pid"
}

release_lock() {
  rm -rf "$LOCK_DIR" || true
}

if ! acquire_lock; then
  write_status_file "LOCK_TIMEOUT" 0 5 5 "lock_timeout"
  echo "[PR7][alert-delivery] status=LOCK_TIMEOUT pr6_rc=0 pr7_rc=5 final_rc=5 fail_mode=$PR7_DELIVERY_FAIL_MODE report= status_file=$STATUS_FILE"
  exit 5
fi
trap release_lock EXIT

# 1) Generate PR6 report first (do not stop immediately on WARN/FAIL exit code)
set +e
RUN_DIR="$RUN_DIR" "$PR6_GATE_CMD"
pr6_rc=$?
set -e

REPORT="$RUN_DIR/summary.txt"
if [[ ! -f "$REPORT" ]]; then
  echo "[PR7][FAIL] missing PR6 report: $REPORT" >&2
  exit 2
fi

# 2) Deliver WARN/FAIL alerts with dedup window
# Backward-compatible CLI arguments for custom delivery commands and existing
# mocks. The canonical Python delivery command receives the full route map via
# environment and, when no explicit override exists, ignores this threshold-
# based fallback in favor of the effective post-escalation severity.
if [[ -n "$EXPLICIT_LEGACY_CHANNEL" ]]; then
  ALERT_NOTIFY_CHANNEL="$EXPLICIT_LEGACY_CHANNEL"
elif [[ -n "$EXPLICIT_PRIMARY_CHANNEL" ]]; then
  ALERT_NOTIFY_CHANNEL="$EXPLICIT_PRIMARY_CHANNEL"
else
  case "${ALERT_NOTIFY_MIN_LEVEL:-WARN}" in
    CRITICAL|FAIL) ALERT_NOTIFY_CHANNEL="$ROUTE_CHANNEL_CRITICAL" ;;
    WARN) ALERT_NOTIFY_CHANNEL="$ROUTE_CHANNEL_WARN" ;;
    INFO|PASS) ALERT_NOTIFY_CHANNEL="$ROUTE_CHANNEL_INFO" ;;
    *) ALERT_NOTIFY_CHANNEL="$ROUTE_CHANNEL_INFO" ;;
  esac
fi

DELIVERY_PRIMARY_CHANNEL="${EXPLICIT_PRIMARY_CHANNEL:-$ALERT_NOTIFY_CHANNEL}"

# Keep the argv vector non-empty before expanding it. macOS still ships Bash
# 3.2, where expanding an empty array under `set -u` aborts the script. Building
# one mandatory vector and conditionally appending optional flags is portable
# across Bash 3 and newer shells.
DELIVERY_ARGS=(
  --report "$REPORT"
  --channel "$ALERT_NOTIFY_CHANNEL"
  --primary-channel "$DELIVERY_PRIMARY_CHANNEL"
  --audit-file "${ALERT_NOTIFY_AUDIT_FILE:-$ROOT/run/pr7-alert-delivery/audit.jsonl}"
  --state-file "${ALERT_NOTIFY_STATE_FILE:-$ROOT/run/pr7-alert-delivery/state.json}"
  --dead-letter-file "${ALERT_NOTIFY_DEAD_LETTER_FILE:-$ROOT/run/pr7-alert-delivery/dead-letter.jsonl}"
  --min-level "${ALERT_NOTIFY_MIN_LEVEL:-WARN}"
  --dedup-seconds "${ALERT_NOTIFY_DEDUP_SECONDS:-1800}"
  --aggregate-seconds "${ALERT_NOTIFY_AGGREGATE_SECONDS:-${ALERT_NOTIFY_DEDUP_SECONDS:-1800}}"
  --max-retries "${ALERT_NOTIFY_MAX_RETRIES:-3}"
  --base-backoff-ms "${ALERT_NOTIFY_BASE_BACKOFF_MS:-500}"
  --max-backoff-ms "${ALERT_NOTIFY_MAX_BACKOFF_MS:-8000}"
  --cooldown-info "${ALERT_NOTIFY_COOLDOWN_INFO:-${ALERT_NOTIFY_DEDUP_SECONDS:-1800}}"
  --cooldown-warn "${ALERT_NOTIFY_COOLDOWN_WARN:-${ALERT_NOTIFY_DEDUP_SECONDS:-1800}}"
  --cooldown-critical "${ALERT_NOTIFY_COOLDOWN_CRITICAL:-300}"
  --warn-escalate-count "${ALERT_NOTIFY_WARN_ESCALATE_COUNT:-0}"
  --warn-escalate-window-seconds "${ALERT_NOTIFY_WARN_ESCALATE_WINDOW_SECONDS:-3600}"
  --quiet-hours-start "${ALERT_NOTIFY_QUIET_HOURS_START:-23:00}"
  --quiet-hours-end "${ALERT_NOTIFY_QUIET_HOURS_END:-08:00}"
  --quiet-hours-tz "${ALERT_NOTIFY_QUIET_HOURS_TZ:-Asia/Shanghai}"
)
if [[ -n "${ALERT_NOTIFY_BACKUP_CHANNEL:-}" ]]; then
  DELIVERY_ARGS+=(--backup-channel "$ALERT_NOTIFY_BACKUP_CHANNEL")
fi
if [[ "${ALERT_NOTIFY_QUIET_HOURS_ENABLED:-0}" == "1" ]]; then
  DELIVERY_ARGS+=(--quiet-hours-enabled)
fi
if [[ "${DRY_RUN:-0}" == "1" ]]; then
  DELIVERY_ARGS+=(--dry-run)
fi

set +e
IMESSAGE_TO="${IMESSAGE_TO:-qiqianpkugsm@gmail.com}" \
  PR7_ROUTE_BY_EFFECTIVE_LEVEL="$ROUTE_BY_EFFECTIVE_LEVEL" \
  ALERT_NOTIFY_CHANNEL_INFO="$ROUTE_CHANNEL_INFO" \
  ALERT_NOTIFY_CHANNEL_WARN="$ROUTE_CHANNEL_WARN" \
  ALERT_NOTIFY_CHANNEL_CRITICAL="$ROUTE_CHANNEL_CRITICAL" \
  "${PR7_DELIVERY_CMD_ARR[@]}" \
  "${DELIVERY_ARGS[@]}"
pr7_rc=$?
set -e

status="$(sed -n 's/^status=//p' "$REPORT" | head -n1)"
if [[ -z "$status" ]]; then
  status="UNKNOWN"
  echo "[PR7][WARN] missing status field in report: $REPORT" >&2
fi

final_rc="$pr6_rc"
if [[ "$PR7_DELIVERY_FAIL_MODE" == "escalate" && "$pr7_rc" -ne 0 ]]; then
  final_rc=4
elif [[ "$PR7_DELIVERY_FAIL_MODE" == "warn" && "$pr7_rc" -ne 0 ]]; then
  echo "[PR7][WARN] delivery failed with rc=$pr7_rc (mode=warn, preserving pr6 rc=$pr6_rc)" >&2
fi

AUDIT_FILE="${ALERT_NOTIFY_AUDIT_FILE:-$ROOT/run/pr7-alert-delivery/audit.jsonl}"
DELIVERY_EVENT="unknown"
PRIMARY_CHANNEL="$DELIVERY_PRIMARY_CHANNEL"
BACKUP_CHANNEL="${ALERT_NOTIFY_BACKUP_CHANNEL:-}"
SUCCESS_CHANNELS=""
FAILED_CHANNELS=""
CHANNELS_OK="0"
CHANNELS_FAILED="0"
PARTIAL_SUCCESS="0"
if [[ -f "$AUDIT_FILE" ]]; then
  DELIVERY_SUMMARY_JSON="$(python3 - "$AUDIT_FILE" "$REPORT" <<'PY'
import json
import sys
from pathlib import Path

audit = Path(sys.argv[1])
report = Path(sys.argv[2]).resolve()
summary = None
for line in audit.read_text(encoding='utf-8', errors='ignore').splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        continue
    try:
        item_report = Path(str(item.get('report_path', ''))).resolve()
    except Exception:
        continue
    if item.get('record_type') == 'delivery_summary' and item_report == report:
        summary = item
if summary is None:
    print('{}')
else:
    print(json.dumps(summary, ensure_ascii=False))
PY
)"
  if [[ -n "$DELIVERY_SUMMARY_JSON" && "$DELIVERY_SUMMARY_JSON" != "{}" ]]; then
    DELIVERY_EVENT="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("event","unknown"))' <<<"$DELIVERY_SUMMARY_JSON")"
    PRIMARY_CHANNEL="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("primary_channel",""))' <<<"$DELIVERY_SUMMARY_JSON")"
    CHANNELS_OK="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("channels_ok",0))' <<<"$DELIVERY_SUMMARY_JSON")"
    CHANNELS_FAILED="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("channels_failed",0))' <<<"$DELIVERY_SUMMARY_JSON")"
    if [[ "$DELIVERY_EVENT" == "partial_success" ]]; then
      PARTIAL_SUCCESS="1"
    fi
  fi

  ROUTE_LINES="$(python3 - "$AUDIT_FILE" "$REPORT" <<'PY'
import json
import sys
from pathlib import Path

audit = Path(sys.argv[1])
report = Path(sys.argv[2]).resolve()
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
    try:
        item_report = Path(str(item.get('report_path', ''))).resolve()
    except Exception:
        continue
    if item_report != report:
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
  SUCCESS_CHANNELS="$(printf '%s\n' "$ROUTE_LINES" | sed -n 's/^success=//p' | head -n1)"
  FAILED_CHANNELS="$(printf '%s\n' "$ROUTE_LINES" | sed -n 's/^failed=//p' | head -n1)"

  if [[ "$DELIVERY_EVENT" == "unknown" ]]; then
    if [[ -n "$SUCCESS_CHANNELS" ]]; then
      CHANNELS_OK="$(python3 -c 'import sys; s=sys.argv[1].strip(); print(0 if not s else len([p for p in s.split(",") if p]))' "$SUCCESS_CHANNELS")"
    fi
    if [[ -n "$FAILED_CHANNELS" ]]; then
      CHANNELS_FAILED="$(python3 -c 'import sys; s=sys.argv[1].strip(); print(0 if not s else len([p for p in s.split(",") if p]))' "$FAILED_CHANNELS")"
    fi
    if [[ -n "$SUCCESS_CHANNELS" && -n "$FAILED_CHANNELS" ]]; then
      PARTIAL_SUCCESS="1"
    fi
  fi
fi

cat >"$STATUS_FILE" <<EOF
status=${status}
pr6_rc=${pr6_rc}
pr7_rc=${pr7_rc}
final_rc=${final_rc}
fail_mode=${PR7_DELIVERY_FAIL_MODE}
delivery_event=${DELIVERY_EVENT}
primary_channel=${PRIMARY_CHANNEL}
backup_channel=${BACKUP_CHANNEL}
success_channels=${SUCCESS_CHANNELS}
failed_channels=${FAILED_CHANNELS}
channels_ok=${CHANNELS_OK}
channels_failed=${CHANNELS_FAILED}
partial_success=${PARTIAL_SUCCESS}
run_dir=${RUN_DIR}
lock_dir=${LOCK_DIR}
report=${REPORT}
audit_file=${AUDIT_FILE}
generated_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

echo "[PR7][alert-delivery] status=$status pr6_rc=$pr6_rc pr7_rc=$pr7_rc final_rc=$final_rc fail_mode=$PR7_DELIVERY_FAIL_MODE report=$REPORT status_file=$STATUS_FILE"

# Optional non-blocking regression self-test for quiet-hours + WARN escalation bypass.
if [[ "${ALERT_NOTIFY_SELFTEST_QUIET_HOURS:-0}" == "1" ]]; then
  if ! "$ROOT/scripts/v2/pr7_quiet_hours_warn_escalation_bypass_test.sh"; then
    echo "[PR7][WARN] quiet-hours self-test failed (non-blocking)" >&2
  fi
fi

exit "$final_rc"
