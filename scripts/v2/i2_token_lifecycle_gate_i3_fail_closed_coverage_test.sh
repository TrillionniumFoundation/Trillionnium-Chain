#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$ROOT/scripts/v2/i2_token_lifecycle_gate.sh"

required_tests=(
  "revoke_dominates_issue_renew_revoke_competition_at_same_height"
  "renew_at_revocation_boundary_is_fail_closed_when_revoke_lands_first"
  "verify_at_revocation_boundary_is_fail_closed_after_same_height_renew_revoke_race"
  "verify_before_revocation_boundary_stays_active_after_same_height_renew_revoke_race"
  "same_height_revoke_replay_after_renew_then_revoke_is_idempotent_without_side_effects"
  "nonexpiring_same_height_renew_then_revoke_still_fails_closed_at_boundary"
  "revoked_token_with_scope_mismatch_returns_inactive_fail_closed"
  "revoked_token_with_unauthorized_actor_returns_inactive_fail_closed"
  "revoked_did_with_scope_mismatch_returns_did_revoked_fail_closed"
  "revoked_did_with_unauthorized_actor_still_returns_did_revoked_fail_closed"
)

for test_name in "${required_tests[@]}"; do
  if ! grep -Fq "$test_name" "$GATE"; then
    echo "[FAIL] i2 gate missing I3 fail-closed coverage test: $test_name" >&2
    exit 1
  fi
done

echo "[PASS] i2 token lifecycle gate keeps I3 race + fail-closed precedence anchors"
