#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_DIR="${RUN_DIR:-$ROOT/run/pr6-alerts/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$RUN_DIR"

EVENT_LOG="${EVENT_LOG:-$ROOT/trillionnium-rust/run/event-field-check.log}"
REPORT="$RUN_DIR/summary.txt"

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

CI_WARN_ARG=()
if [[ "${CI_HARD_FAIL_ON_WARN:-0}" == "1" ]]; then
  CI_WARN_ARG=(--ci-hard-fail-on-warn)
fi

python3 "$ROOT/scripts/v2/pr6_challenge_alert_rules.py" \
  --event-log "$EVENT_LOG" \
  --window-hours "${WINDOW_HOURS:-48}" \
  --fail-unresolved-challenges "${FAIL_UNRESOLVED_CHALLENGES:-5}" \
  --warn-unresolved-challenges "${WARN_UNRESOLVED_CHALLENGES:--1}" \
  --fail-forfeits-daily-increase "${FAIL_FORFEITS_DAILY_INCREASE:-100}" \
  --warn-forfeits-daily-increase "${WARN_FORFEITS_DAILY_INCREASE:--1}" \
  --fail-escrow-nonzero-hours "${FAIL_ESCROW_NONZERO_HOURS:-24}" \
  --warn-escrow-nonzero-hours "${WARN_ESCROW_NONZERO_HOURS:--1}" \
  "${CI_WARN_ARG[@]}" \
  --report "$REPORT"

status="$(sed -n 's/^status=//p' "$REPORT" | head -n1)"
echo "[PR6][alert-rules] status=$status report=$REPORT"
