#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_DIR="${RUN_DIR:-$ROOT/run/pr6-alerts/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$RUN_DIR"

# 1) Generate PR6 report first (do not stop immediately on WARN/FAIL exit code)
set +e
RUN_DIR="$RUN_DIR" "$ROOT/scripts/v2/pr6_alert_rules_gate.sh"
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

IMESSAGE_TO="${IMESSAGE_TO:-qiqianpkugsm@gmail.com}" \
python3 "$ROOT/scripts/v2/pr7_alert_delivery.py" \
  --report "$REPORT" \
  --channel "${ALERT_NOTIFY_CHANNEL:-imessage}" \
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

status="$(sed -n 's/^status=//p' "$REPORT" | head -n1)"
echo "[PR7][alert-delivery] status=$status pr6_rc=$pr6_rc pr7_rc=$pr7_rc report=$REPORT"

# Keep upstream gate semantics
exit "$pr6_rc"
