#!/usr/bin/env bash
set -euo pipefail
for case in \
 store::storage_service::tests::cache_quota::cache_deletion_and_cache_quota_failure_cannot_release_actual_paid_retention \
 store::storage_service::tests::native_cell_failed_initial_copy_needs_a_separate_funded_repair_and_preserves_unknown_cost \
 store::storage_service::tests::native_cell_repair_cpu_owner_cannot_move_threads_or_resume_after_exhaustion \
 store::storage_service::tests::native_cell_retirement_cannot_release_a_pending_effect_before_reconciliation \
 store::storage_service::tests::native_cell_retirement_rejects_another_chain_and_reconciles_orphaned_funding \
 store::storage_service::tests::native_cell_storage_escrow_replay_and_reorg_keep_physical_obligation \
 store::storage_service::tests::native_cell_storage_subject_and_real_byte_block_capacity_are_required_before_effect \
 store::legacy_reorg_observation_tests::legacy_observation_opt_in_is_local_and_keeps_unentered_unknown \
 store::legacy_reorg_observation_tests::legacy_observation_preserves_cancelled_and_failed_reorg_outcomes \
 store::legacy_reorg_observation_tests::legacy_observation_preserves_signed_reorg_state_and_progress \
 store::storage_service::tests::native_cell_expired_storage_request_creates_no_budget_or_physical_obligation \
 store::storage_service::tests::native_cell_physical_writer_wait_spends_original_storage_deadline
do
 name=${case##*::}
 cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib "$case" -- --exact --nocapture 2>&1 | tee "/workspace/scratch/73305aff6ced/observations/composed-final/node-qualified/$name.log"
 python3 scripts/ci/check_required_native_test.py "/workspace/scratch/73305aff6ced/observations/composed-final/node-qualified/$name.log" --test "$case"
done
