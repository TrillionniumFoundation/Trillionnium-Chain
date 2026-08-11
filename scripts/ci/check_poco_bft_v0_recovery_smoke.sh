#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
MANIFEST="$ROOT/trillionnium/Cargo.toml"

run_unit_filter() {
  local package="$1"
  local filter="$2"
  local listed

  listed="$(cargo test --manifest-path "$MANIFEST" --locked \
    -p "$package" --lib "$filter" -- --list)"
  if ! grep -Fq -- "$filter" <<<"$listed"; then
    printf 'recovery smoke filter matched no test: package=%s filter=%s\n' \
      "$package" "$filter" >&2
    exit 2
  fi
  cargo test --manifest-path "$MANIFEST" --locked \
    -p "$package" --lib "$filter" -- --test-threads=1
}

run_integration_filter() {
  local package="$1"
  local target="$2"
  local filter="$3"
  local listed

  listed="$(cargo test --manifest-path "$MANIFEST" --locked \
    -p "$package" --test "$target" "$filter" -- --list)"
  if ! grep -Fq -- "$filter" <<<"$listed"; then
    printf 'recovery smoke filter matched no test: package=%s target=%s filter=%s\n' \
      "$package" "$target" "$filter" >&2
    exit 2
  fi
  cargo test --manifest-path "$MANIFEST" --locked \
    -p "$package" --test "$target" "$filter" -- --test-threads=1
}

run_unit_filter trnm-consensus-core \
  recovery_with_a_claimed_durable_validation_fails_closed_without_reopening_it
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
  'poco_bft_recovery_smoke=passed scope=core-sign-safety-journal-torn-halt-latch-wal-shm-watermark-validation-job-recovery-integrity-outbox-delivery-states-snapshot'
