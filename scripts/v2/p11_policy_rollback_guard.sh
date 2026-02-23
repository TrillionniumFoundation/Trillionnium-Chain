#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

OUT="${P11_ROLLBACK_GUARD_OUT:-run/pr11/policy-rollback-guard.txt}"
JSON_OUT="${P11_ROLLBACK_GUARD_JSON_OUT:-run/pr11/policy-rollback-guard.json}"
LOOKBACK_SECONDS="${P11_ROLLBACK_GUARD_LOOKBACK_SECONDS:-3600}"
FAILED_RATE_THRESHOLD_PCT="${P11_ROLLBACK_GUARD_FAILED_RATE_THRESHOLD_PCT:-20}"
CONSECUTIVE_FAILURES_THRESHOLD="${P11_ROLLBACK_GUARD_CONSECUTIVE_FAILURES_THRESHOLD:-10}"
POLICY_TAG="${P11_ROLLBACK_GUARD_POLICY_TAG:-alert-policy/current}"

python3 ./scripts/v2/p11_policy_rollback_guard.py \
  --state-file "${P11_ROLLBACK_GUARD_STATE_FILE:-run/pr7-alert-delivery/state.json}" \
  --dead-letter-file "${P11_ROLLBACK_GUARD_DEAD_LETTER_FILE:-run/pr7-alert-delivery/dead-letter.jsonl}" \
  --audit-file "${P11_ROLLBACK_GUARD_AUDIT_FILE:-run/pr7-alert-delivery/audit.jsonl}" \
  --lookback-seconds "$LOOKBACK_SECONDS" \
  --failed-rate-threshold-pct "$FAILED_RATE_THRESHOLD_PCT" \
  --consecutive-failures-threshold "$CONSECUTIVE_FAILURES_THRESHOLD" \
  --policy-tag "$POLICY_TAG" \
  --out "$OUT" \
  --json-out "$JSON_OUT"

echo "[P11] rollback guard report: $OUT"
echo "[P11] rollback guard json:   $JSON_OUT"
