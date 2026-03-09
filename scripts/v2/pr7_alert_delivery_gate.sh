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
DRY_RUN_ARG=()
if [[ "${DRY_RUN:-0}" == "1" ]]; then
  DRY_RUN_ARG=(--dry-run)
fi

QUIET_HOURS_ARG=()
if [[ "${ALERT_NOTIFY_QUIET_HOURS_ENABLED:-0}" == "1" ]]; then
  QUIET_HOURS_ARG=(--quiet-hours-enabled)
fi

# Backward-compatible routing:
# - if ALERT_NOTIFY_CHANNEL is explicitly set, use it
# - else derive channel from min-level route
if [[ -z "${ALERT_NOTIFY_CHANNEL:-}" ]]; then
  case "${ALERT_NOTIFY_MIN_LEVEL:-WARN}" in
    CRITICAL) ALERT_NOTIFY_CHANNEL="${ALERT_NOTIFY_CHANNEL_CRITICAL:-imessage}" ;;
    WARN) ALERT_NOTIFY_CHANNEL="${ALERT_NOTIFY_CHANNEL_WARN:-imessage}" ;;
    *) ALERT_NOTIFY_CHANNEL="${ALERT_NOTIFY_CHANNEL_INFO:-imessage}" ;;
  esac
fi

BACKUP_CHANNEL_ARG=()
if [[ -n "${ALERT_NOTIFY_BACKUP_CHANNEL:-}" ]]; then
  BACKUP_CHANNEL_ARG=(--backup-channel "$ALERT_NOTIFY_BACKUP_CHANNEL")
fi

read -r -a PR7_DELIVERY_CMD_ARR <<<"$PR7_DELIVERY_CMD"
set +e
IMESSAGE_TO="${IMESSAGE_TO:-qiqianpkugsm@gmail.com}" \
  "${PR7_DELIVERY_CMD_ARR[@]}" \
  --report "$REPORT" \
  --channel "${ALERT_NOTIFY_CHANNEL:-imessage}" \
  --primary-channel "${ALERT_NOTIFY_PRIMARY_CHANNEL:-${ALERT_NOTIFY_CHANNEL:-imessage}}" \
  "${BACKUP_CHANNEL_ARG[@]}" \
  --audit-file "${ALERT_NOTIFY_AUDIT_FILE:-$ROOT/run/pr7-alert-delivery/audit.jsonl}" \
  --state-file "${ALERT_NOTIFY_STATE_FILE:-$ROOT/run/pr7-alert-delivery/state.json}" \
  --dead-letter-file "${ALERT_NOTIFY_DEAD_LETTER_FILE:-$ROOT/run/pr7-alert-delivery/dead-letter.jsonl}" \
  --min-level "${ALERT_NOTIFY_MIN_LEVEL:-WARN}" \
  --dedup-seconds "${ALERT_NOTIFY_DEDUP_SECONDS:-1800}" \
  --aggregate-seconds "${ALERT_NOTIFY_AGGREGATE_SECONDS:-${ALERT_NOTIFY_DEDUP_SECONDS:-1800}}" \
  --max-retries "${ALERT_NOTIFY_MAX_RETRIES:-3}" \
  --base-backoff-ms "${ALERT_NOTIFY_BASE_BACKOFF_MS:-500}" \
  --max-backoff-ms "${ALERT_NOTIFY_MAX_BACKOFF_MS:-8000}" \
  --cooldown-info "${ALERT_NOTIFY_COOLDOWN_INFO:-${ALERT_NOTIFY_DEDUP_SECONDS:-1800}}" \
  --cooldown-warn "${ALERT_NOTIFY_COOLDOWN_WARN:-${ALERT_NOTIFY_DEDUP_SECONDS:-1800}}" \
  --cooldown-critical "${ALERT_NOTIFY_COOLDOWN_CRITICAL:-300}" \
  --warn-escalate-count "${ALERT_NOTIFY_WARN_ESCALATE_COUNT:-0}" \
  --warn-escalate-window-seconds "${ALERT_NOTIFY_WARN_ESCALATE_WINDOW_SECONDS:-3600}" \
  --quiet-hours-start "${ALERT_NOTIFY_QUIET_HOURS_START:-23:00}" \
  --quiet-hours-end "${ALERT_NOTIFY_QUIET_HOURS_END:-08:00}" \
  --quiet-hours-tz "${ALERT_NOTIFY_QUIET_HOURS_TZ:-Asia/Shanghai}" \
  "${QUIET_HOURS_ARG[@]}" \
  "${DRY_RUN_ARG[@]}"
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

cat >"$STATUS_FILE" <<EOF
status=${status}
pr6_rc=${pr6_rc}
pr7_rc=${pr7_rc}
final_rc=${final_rc}
fail_mode=${PR7_DELIVERY_FAIL_MODE}
run_dir=${RUN_DIR}
lock_dir=${LOCK_DIR}
report=${REPORT}
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
