#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
MANIFEST="$ROOT/trillionnium/Cargo.toml"
LEGACY_APP_MANIFEST="$ROOT/trillionnium/crates/trnm-consensus-app/Cargo.toml"

require_one_executed_test() {
  local scope="$1"
  local output="$2"
  if ! grep -Fq -- 'test result: ok. 1 passed; 0 failed; 0 ignored;' <<<"$output"; then
    printf 'recovery smoke did not execute exactly one passing, non-ignored test: %s\n' \
      "$scope" >&2
    exit 2
  fi
}

run_unit_filter() {
  local package="$1"
  local filter="$2"
  local manifest="$MANIFEST"
  local listed
  local output

  if [[ "$package" == "trnm-consensus-app" ]]; then
    manifest="$LEGACY_APP_MANIFEST"
  fi

  listed="$(cargo test --manifest-path "$manifest" --locked \
    -p "$package" --lib "$filter" -- --list)"
  if [[ "$(grep -Fc -- "$filter: test" <<<"$listed" || true)" != 1 ]]; then
    printf 'recovery smoke filter did not match exactly one test: package=%s filter=%s\n' \
      "$package" "$filter" >&2
    exit 2
  fi
  output="$(cargo test --manifest-path "$manifest" --locked \
    -p "$package" --lib "$filter" -- --test-threads=1 2>&1)" || {
    printf '%s\n' "$output"
    exit 1
  }
  printf '%s\n' "$output"
  require_one_executed_test "package=$package filter=$filter" "$output"
}

run_feature_unit_filter() {
  local package="$1"
  local feature="$2"
  local filter="$3"
  local listed
  local output

  listed="$(cargo test --manifest-path "$MANIFEST" --locked \
    -p "$package" --lib --features "$feature" "$filter" -- --list)"
  if [[ "$(grep -Fc -- "$filter: test" <<<"$listed" || true)" != 1 ]]; then
    printf 'recovery smoke filter did not match exactly one test: package=%s feature=%s filter=%s\n' \
      "$package" "$feature" "$filter" >&2
    exit 2
  fi
  output="$(cargo test --manifest-path "$MANIFEST" --locked \
    -p "$package" --lib --features "$feature" "$filter" -- --test-threads=1 2>&1)" || {
    printf '%s\n' "$output"
    exit 1
  }
  printf '%s\n' "$output"
  require_one_executed_test \
    "package=$package feature=$feature filter=$filter" "$output"
}

run_feature_integration_filter() {
  local package="$1"
  local feature="$2"
  local target="$3"
  local filter="$4"
  local listed
  local output

  listed="$(cargo test --manifest-path "$MANIFEST" --locked \
    -p "$package" --features "$feature" --test "$target" "$filter" -- --list)"
  if [[ "$(grep -Fc -- "$filter: test" <<<"$listed" || true)" != 1 ]]; then
    printf 'recovery smoke filter did not match exactly one test: package=%s feature=%s target=%s filter=%s\n' \
      "$package" "$feature" "$target" "$filter" >&2
    exit 2
  fi
  output="$(cargo test --manifest-path "$MANIFEST" --locked \
    -p "$package" --features "$feature" --test "$target" "$filter" -- \
    --test-threads=1 2>&1)" || {
    printf '%s\n' "$output"
    exit 1
  }
  printf '%s\n' "$output"
  require_one_executed_test \
    "package=$package feature=$feature target=$target filter=$filter" "$output"
}

run_integration_filter() {
  local package="$1"
  local target="$2"
  local filter="$3"
  local listed
  local output

  listed="$(cargo test --manifest-path "$MANIFEST" --locked \
    -p "$package" --test "$target" "$filter" -- --list)"
  if [[ "$(grep -Fc -- "$filter: test" <<<"$listed" || true)" != 1 ]]; then
    printf 'recovery smoke filter did not match exactly one test: package=%s target=%s filter=%s\n' \
      "$package" "$target" "$filter" >&2
    exit 2
  fi
  output="$(cargo test --manifest-path "$MANIFEST" --locked \
    -p "$package" --test "$target" "$filter" -- --test-threads=1 2>&1)" || {
    printf '%s\n' "$output"
    exit 1
  }
  printf '%s\n' "$output"
  require_one_executed_test \
    "package=$package target=$target filter=$filter" "$output"
}

run_unit_filter trnm-consensus-core \
  recovery_with_a_claimed_durable_validation_fails_closed_without_reopening_it
run_unit_filter trnm-consensus-core \
  proposal_obligation_recovery_rebuilds_the_exact_target_before_invalid_callback
run_unit_filter trnm-consensus-core \
  synced_obligation_recovery_rebuilds_the_exact_route_and_witness
run_unit_filter trnm-consensus-core \
  recovered_invalid_completion_ack_releases_the_fence_back_to_safety_replay
run_unit_filter trnm-consensus-core \
  obligation_recovery_never_exposes_a_core_when_reconciliation_is_omitted
run_unit_filter trnm-consensus-core \
  obligation_recovery_rejects_tampered_duplicate_and_concurrent_records
run_unit_filter trnm-consensus-core \
  persisted_sign_intent_is_re_requested_after_recovery
run_unit_filter trnm-consensus-core \
  callback_persistence_preserves_exact_sign_intent_across_crash_resume
run_unit_filter trnm-consensus-core \
  synced_callback_persistence_preserves_exact_vote_intent_across_crash_resume
run_unit_filter trnm-consensus-core \
  durable_valid_fact_still_requires_body_and_context_readiness_after_recovery
run_integration_filter trnm-consensus-safety-store sqlite_store \
  initializes_reads_head_and_reopens_exactly
run_integration_filter trnm-consensus-safety-store sqlite_store \
  exact_retries_preserve_two_revision_retention_and_reopen_head
run_integration_filter trnm-consensus-safety-store sqlite_store \
  persistence_requires_the_one_designated_core_affinity
run_integration_filter trnm-consensus-safety-store sqlite_store \
  same_revision_different_valid_context_durably_halts
run_integration_filter trnm-consensus-safety-store sqlite_store \
  revision_gap_durably_halts_and_survives_reopen
run_integration_filter trnm-consensus-safety-store sqlite_store \
  raw_sqlite_accounting_head_and_record_tampering_is_rejected_on_reopen
run_unit_filter trnm-consensus-safety-store \
  torn_halt_latch_is_fail_closed_without_damaging_the_head_slots
run_integration_filter trnm-consensus-safety-store sqlite_store \
  deleting_persistent_wal_or_shm_after_close_fails_reopen_closed
run_integration_filter trnm-consensus-safety-store sqlite_store \
  tampered_only_valid_lock_watermark_slot_is_rejected_on_reopen
run_integration_filter trnm-consensus-signer-journal sqlite_journal \
  signature_is_persisted_before_return_and_exact_replay_skips_producer
run_integration_filter trnm-consensus-signer-journal sqlite_journal \
  external_watermark_recovers_each_local_first_commit_window
run_integration_filter trnm-consensus-signer-journal sqlite_journal \
  whole_namespace_rollback_is_detected_by_external_watermark
run_unit_filter trnm-poco-node \
  bounded_timeout_signing_persists_before_broadcast_and_replays_exactly
run_unit_filter trnm-poco-node \
  unavailable_producer_leaves_exact_prepared_tail_for_same_intent_retry
run_unit_filter trnm-poco-node \
  signer_revision_ahead_of_authenticated_safety_head_fails_startup
run_feature_integration_filter trnm-poco-node recovery-process-test-support \
  timeout_signing_process_kill_matrix \
  real_process_sigkill_matrix_replays_exact_bounded_timeout_signing

# The excluded trnm-consensus-app workspace remains useful for archive
# inspection. It is excluded from the active native workspace and runs only
# through its own manifest when a local reviewer explicitly opts in. The old
# Node recovery feature and process-kill target are non-buildable archive
# source; they are never invoked here. An opt-in pass remains archive evidence,
# never native release or readiness authority.
if [[ "${TRNM_RUN_LEGACY_APP_ARCHIVE_TESTS:-0}" == "1" ]]; then
run_unit_filter trnm-consensus-app \
  durable_reservation_is_unique_across_independent_stores_and_reopen
run_unit_filter trnm-consensus-app \
  invalid_artifact_and_callback_v0_frozen_vectors
run_unit_filter trnm-consensus-app \
  durable_complete_body_invalid_seals_one_callback_pending_record_and_recovers_it
run_unit_filter trnm-consensus-app \
  live_durable_invalid_callbacks_cross_real_core_barriers_for_both_routes_and_reasons
run_unit_filter trnm-consensus-app \
  live_invalid_postwrite_safety_uncertainty_confirms_exact_before_core_release
run_unit_filter trnm-consensus-app \
  live_invalid_binding_refuses_completion_only_core_state_without_artifact_binding
run_unit_filter trnm-consensus-app \
  live_invalid_safety_conflict_quarantines_without_ack_or_core_release
run_unit_filter trnm-consensus-app \
  live_invalid_storage_ack_releases_exact_safety_halt_without_state_change
run_unit_filter trnm-consensus-app \
  callback_driver_is_store_nested_and_raw_journal_transitions_are_private
run_unit_filter trnm-consensus-app \
  callback_driver_source_keeps_safety_sink_explicitly_non_production
run_unit_filter trnm-consensus-app \
  durable_complete_body_invalid_precommit_failpoints_roll_back_and_return_owner
run_unit_filter trnm-consensus-app \
  durable_complete_body_invalid_restart_rejects_artifact_and_outbox_splices
run_unit_filter trnm-consensus-app \
  recovery_scanner_orders_reserved_jobs_and_fails_closed_on_checksum_drift
run_unit_filter trnm-consensus-app \
  restart_rejects_checksum_consistent_canonical_header_splice
run_unit_filter trnm-consensus-app \
  restart_rejects_checksum_consistent_positive_parent_downgrade
run_unit_filter trnm-consensus-app \
  exact_reopen_and_restart_reject_nonempty_inactive_outbox
run_unit_filter trnm-consensus-app \
  exact_reopen_stays_inert_but_restart_rejects_a_different_non_reserved_job
run_unit_filter trnm-consensus-app \
  restart_rejects_validation_journal_accounting_drift
run_unit_filter trnm-consensus-app \
  schema_v5_nonempty_migration_fails_closed_and_preserves_rows
run_unit_filter trnm-consensus-app \
  schema_v6_reserved_jobs_migrate_atomically_through_v7_to_v8
run_unit_filter trnm-consensus-app \
  schema_v6_active_state_outbox_and_accounting_drift_migrations_roll_back
run_unit_filter trnm-consensus-app \
  schema_v7_reserved_and_callback_pending_rows_migrate_byte_exactly_to_v8
run_unit_filter trnm-consensus-app \
  schema_v7_delivery_state_activation_fails_closed_and_preserves_rows
run_unit_filter trnm-consensus-app \
  schema_v8_recovers_delivered_and_acked_with_retired_outbox_accounting
run_unit_filter trnm-consensus-app \
  schema_v8_restart_rejects_evaluated_applied_and_valid_rows
run_unit_filter trnm-consensus-app \
  native_validation_jobs_and_outbox_remain_source_local_across_snapshot_install
printf '%s\n' \
  'poco_bft_recovery_evidence_mode=LEGACY_APP_ARCHIVE_OPT_IN' \
  'validation_recovery=legacy_deterministic_invalid_existing_only' \
  'validation_recovery_process_kill_matrix=UNAVAILABLE_NON_BUILDABLE_ARCHIVE_SOURCE' \
  'validation_recovery_process_kill_scope=none' \
  'validation_recovery_process_kill_checkpoint_count=0' \
  'validation_recovery_process_kill_checkpoint_origin=none' \
  'bounded_timeout_signing_effect_loop=EVALUATED_DEFAULT_BUILD' \
  'bounded_timeout_signature_replay=EVALUATED' \
  'bounded_timeout_process_sigkill_matrix=EVALUATED_ACTIVE_NATIVE' \
  'bounded_timeout_process_sigkill_scope=local_linux_test_only_safety_ack_signer_journal_producer_signature_ready_broadcast' \
  'bounded_timeout_process_sigkill_checkpoint_count=6' \
  'bounded_timeout_process_sigkill_checkpoint_origin=official_host_four_boundaries_feature_producer_two_boundaries' \
  'legacy_app_archive_tests=EVALUATED_STANDALONE_ARCHIVE_NOT_ACTIVE_NATIVE_EVIDENCE' \
  'legacy_node_recovery_feature_tests=UNAVAILABLE_NON_BUILDABLE_ARCHIVE_SOURCE' \
  'legacy_process_sigkill_feature_tests=UNAVAILABLE_NON_BUILDABLE_ARCHIVE_SOURCE' \
  'vote_signing_effect_loop=NOT_IMPLEMENTED' \
  'power_loss_fsync_matrix=NOT_EVALUATED' \
  'valid_recovery=not_implemented' \
  'unavailable_recovery=not_implemented' \
  'poco_bft_recovery_smoke=passed scope=standalone-legacy-app-archive-plus-active-native-timeout-not-release-evidence'
else
printf '%s\n' \
  'legacy_app_archive_tests=SKIPPED_NO_ACTIVE_NATIVE_WORKFLOW_AUTHORITY' \
  'legacy_node_recovery_feature_tests=SKIPPED_NO_ACTIVE_NATIVE_WORKFLOW_AUTHORITY' \
  'legacy_process_sigkill_feature_tests=SKIPPED_NO_ACTIVE_NATIVE_WORKFLOW_AUTHORITY' \
  'poco_bft_recovery_evidence_mode=ACTIVE_NATIVE_DEFAULT_ONLY' \
  'bounded_timeout_signing_effect_loop=EVALUATED_DEFAULT_BUILD' \
  'bounded_timeout_signature_replay=EVALUATED' \
  'bounded_timeout_process_sigkill_matrix=EVALUATED_ACTIVE_NATIVE' \
  'vote_signing_effect_loop=NOT_IMPLEMENTED' \
  'power_loss_fsync_matrix=NOT_EVALUATED' \
  'valid_recovery=not_implemented' \
  'unavailable_recovery=not_implemented' \
  'poco_bft_recovery_smoke=passed scope=core-sign-safety-journal-torn-halt-latch-wal-shm-watermark-bounded-timeout-signing-replay-active-native-default'
fi
