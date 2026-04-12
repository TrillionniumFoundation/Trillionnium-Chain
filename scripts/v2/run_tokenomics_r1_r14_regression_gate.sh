#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"

export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
export CARGO_TERM_COLOR=never

run_test() {
  local pkg="$1"
  local test_name="$2"
  echo "[gate][run] cargo test -q -p ${pkg} ${test_name}"
  cargo test -q -p "$pkg" "$test_name"
}

run_integration_test() {
  local pkg="$1"
  local target="$2"
  echo "[gate][run] cargo test -q -p ${pkg} --test ${target}"
  cargo test -q -p "$pkg" --test "$target"
}

start_ts="$(date +%s)"

echo "[gate] tokenomics regression gate (R1-R24 core) start (script: run_tokenomics_r1_r14_regression_gate.sh)"

# R1/R11: liveness (reveal deadline + revealed timeout scan)
run_test trnm-pouw challenge_rejected_after_reveal_deadline_window
run_test trnm-pouw revealed_timeout_auto_completes_without_challenge

# R2/R8: resolve authority + signer binding
run_test trnm-pouw resolve_rejects_when_payload_resolver_matches_but_signer_is_attacker
run_test trnm-pouw resolve_accepts_when_signer_is_authority_even_if_payload_resolver_is_arbitrary

# R3/R4: worker slash + challenger bounty flow
run_test trnm-pouw committed_timeout_slashes_worker_economically_and_credits_treasury
run_test trnm-pouw resolve_success_gives_challenger_more_than_bond_refund_baseline

# R5: dynamic challenge bond floor anti-spam
run_test trnm-pouw challenge_rejects_spam_like_low_bond_under_dynamic_bounty_floor
run_test trnm-pouw challenge_dynamic_floor_boundary_ceil_passes_and_fails

# R5b/R5c/R5d: admission hard-stop + sponsor boundary + drain-only duplicate retention
run_integration_test trnm-mempool lane_zero_capacity_public_contract_bound
run_integration_test trnm-mempool lane_borrowed_last_slot_backpressured_retry_reuse_bound
run_integration_test trnm-mempool lane_qos_snapshot_reserve_only_drain_only_duplicate_retention_bound
run_integration_test trnm-mempool lane_reserve_clamp_borrow_policy_bound

# R6/R14: governance timelock + sensitive-key rate-limit (incl. resolve_authority)
run_test trnm-state governance_sensitive_update_rejected_before_timelock_expiry
run_test trnm-state governance_sensitive_update_excessive_step_change_rejected
run_test trnm-state governance_resolve_authority_rejected_before_timelock_expiry
run_test trnm-state governance_resolve_authority_applied_after_timelock
run_test trnm-state governance_timelock_classification_merge_gate_keeps_emergency_pause_immediate

# R7: event accounting deltas
run_test trnm-rpc summarize_challenge_treasury_tracks_balances_and_forfeits

# R9/R10: governance key integrity + deterministic lookup
run_test trnm-state governance_same_key_different_id_shadow_attempt_rejected
run_test trnm-state governance_readers_use_deterministic_current_value

# R13: overflow fail-fast in state/rpc transfer paths
run_test trnm-state balance_credit_overflow_rejected
run_test trnm-rpc reject_amount_plus_fee_overflow
run_test trnm-rpc reject_receiver_credit_overflow

# R15: pending sensitive governance update operational controls (replace/cancel)
run_test trnm-state governance_sensitive_pending_replace_before_activation_resets_timelock
run_test trnm-state governance_sensitive_pending_cancel_before_activation_removes_pending

# R16: reveal-time challenge window snapshot invariants under mid-flight governance changes
run_test trnm-pouw challenge_window_is_snapshotted_at_reveal_even_if_governance_changes_after
run_test trnm-pouw challenge_boundary_stays_correct_at_and_after_deadline_with_snapshot

# R17/R18: signer-bound resolve auth + legacy fallback window freeze on first challenge
run_test trnm-pouw legacy_fallback_asymmetry_keeps_challenge_deadline_and_signer_auth_intact
run_test trnm-pouw legacy_revealed_snapshot_freezes_resolve_timing_after_challenge_despite_later_gov_change

# R19-R24: unresolved-timeout refund + challenge signer binding + invariant/preflight hardening + delta observability
run_test trnm-pouw challenge_rejects_when_payload_challenger_matches_but_signer_is_attacker
run_test trnm-pouw challenged_timeout_refunds_bond_and_keeps_forfeit_bucket_unchanged
run_test trnm-pouw malformed_challenged_invariant_failure_rejects_early_without_status_or_balance_mutation
run_test trnm-pouw resolve_preflight_overflow_rejects_without_status_or_balance_mutation
run_test trnm-pouw accept_preflight_rejects_lock_credit_overflow_without_mutation
run_test trnm-node event_delta_fallback_is_deterministic_for_large_balances

end_ts="$(date +%s)"
elapsed="$((end_ts - start_ts))"
echo "[OK] tokenomics regression gate (R1-R24 core) passed in ${elapsed}s"
