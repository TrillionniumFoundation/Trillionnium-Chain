#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_DIR="${RUN_DIR:-$ROOT/run/pr6-alerts/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$RUN_DIR"

EVENT_LOG="${EVENT_LOG:-$ROOT/trillionnium-rust/run/event-field-check.log}"
REPORT="$RUN_DIR/summary.txt"

require_non_negative_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "[PR6][FAIL] invalid $name='$value' (expect non-negative integer)" >&2
    exit 2
  fi
}

require_number_or_auto() {
  local name="$1"
  local value="$2"
  if [[ "$value" == "-1" ]]; then
    return 0
  fi
  if [[ ! "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "[PR6][FAIL] invalid $name='$value' (expect number or -1 for auto)" >&2
    exit 2
  fi
}

WINDOW_HOURS_VAL="${WINDOW_HOURS:-48}"
FAIL_UNRESOLVED_CHALLENGES_VAL="${FAIL_UNRESOLVED_CHALLENGES:-5}"
WARN_UNRESOLVED_CHALLENGES_VAL="${WARN_UNRESOLVED_CHALLENGES:--1}"
FAIL_FORFEITS_DAILY_INCREASE_VAL="${FAIL_FORFEITS_DAILY_INCREASE:-100}"
WARN_FORFEITS_DAILY_INCREASE_VAL="${WARN_FORFEITS_DAILY_INCREASE:--1}"
FAIL_ESCROW_NONZERO_HOURS_VAL="${FAIL_ESCROW_NONZERO_HOURS:-24}"
WARN_ESCROW_NONZERO_HOURS_VAL="${WARN_ESCROW_NONZERO_HOURS:--1}"

require_non_negative_integer "WINDOW_HOURS" "$WINDOW_HOURS_VAL"
require_non_negative_integer "FAIL_UNRESOLVED_CHALLENGES" "$FAIL_UNRESOLVED_CHALLENGES_VAL"
require_number_or_auto "WARN_UNRESOLVED_CHALLENGES" "$WARN_UNRESOLVED_CHALLENGES_VAL"
require_non_negative_integer "FAIL_FORFEITS_DAILY_INCREASE" "$FAIL_FORFEITS_DAILY_INCREASE_VAL"
require_number_or_auto "WARN_FORFEITS_DAILY_INCREASE" "$WARN_FORFEITS_DAILY_INCREASE_VAL"
require_number_or_auto "FAIL_ESCROW_NONZERO_HOURS" "$FAIL_ESCROW_NONZERO_HOURS_VAL"
require_number_or_auto "WARN_ESCROW_NONZERO_HOURS" "$WARN_ESCROW_NONZERO_HOURS_VAL"

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

CI_WARN_ARG=""
if [[ "${CI_HARD_FAIL_ON_WARN:-0}" == "1" ]]; then
  CI_WARN_ARG="--ci-hard-fail-on-warn"
fi

python3 "$ROOT/scripts/v2/pr6_challenge_alert_rules.py" \
  --event-log "$EVENT_LOG" \
  --window-hours "$WINDOW_HOURS_VAL" \
  --fail-unresolved-challenges "$FAIL_UNRESOLVED_CHALLENGES_VAL" \
  --warn-unresolved-challenges "$WARN_UNRESOLVED_CHALLENGES_VAL" \
  --fail-forfeits-daily-increase "$FAIL_FORFEITS_DAILY_INCREASE_VAL" \
  --warn-forfeits-daily-increase "$WARN_FORFEITS_DAILY_INCREASE_VAL" \
  --fail-escrow-nonzero-hours "$FAIL_ESCROW_NONZERO_HOURS_VAL" \
  --warn-escrow-nonzero-hours "$WARN_ESCROW_NONZERO_HOURS_VAL" \
  ${CI_WARN_ARG:+$CI_WARN_ARG} \
  --report "$REPORT"

status="$(sed -n 's/^status=//p' "$REPORT" | head -n1)"
echo "[PR6][alert-rules] status=$status report=$REPORT"
