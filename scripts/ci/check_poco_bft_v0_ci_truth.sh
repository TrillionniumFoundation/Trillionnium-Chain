#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
POCO_WORKFLOW="$ROOT/.github/workflows/trnm-poco-bft-v0.yml"
LEGACY_WORKFLOW="$ROOT/.github/workflows/rust-l1-testnet-preflight.yml"
RECOVERY_GATE="$ROOT/scripts/ci/check_poco_bft_v0_recovery_smoke.sh"
LEGACY_PREFLIGHT="$ROOT/trillionnium/scripts/testnet_preflight.sh"
CORE_SOURCE="$ROOT/trillionnium/crates/trnm-consensus-core/src/core.rs"
CORE_TESTS="$ROOT/trillionnium/crates/trnm-consensus-core/src/tests.rs"
APP_RECOVERY="$ROOT/trillionnium/crates/trnm-consensus-app/src/native_validation_recovery.rs"
APP_STORE_SOURCE="$ROOT/trillionnium/crates/trnm-consensus-app/src/store.rs"
SAFETY_STORE_SOURCE="$ROOT/trillionnium/crates/trnm-consensus-safety-store/src/sqlite.rs"
NODE_SOURCE="$ROOT/trillionnium/crates/trnm-poco-node/src/lib.rs"
NODE_RECOVERY_TESTS="$ROOT/trillionnium/crates/trnm-poco-node/src/recovery_tests.rs"
NODE_CARGO="$ROOT/trillionnium/crates/trnm-poco-node/Cargo.toml"
G1C_TRUTH="$ROOT/docs/protocol/poco-bft-v0/IMPLEMENTATION_GAP_REGISTER.md"
ROOT_README="$ROOT/README.md"
PROTOCOL_README="$ROOT/docs/protocol/poco-bft-v0/README.md"
WIRE_DOC="$ROOT/docs/protocol/poco-bft-v0/03-wire-crypto-and-domain-separation.md"
INVARIANTS_DOC="$ROOT/docs/protocol/poco-bft-v0/07-invariants-and-conformance.md"
DELIVERY_PLAN="$ROOT/docs/development/TRNM_POCO_BFT_DELIVERY_PLAN_2026-08-04.md"

fail() {
  printf 'PoCO-BFT CI/readiness truth gate failed: %s\n' "$*" >&2
  exit 1
}

require_file() {
  local path="$1"
  [[ -f "$path" ]] || fail "missing file: $path"
}

require_literal() {
  local path="$1"
  local literal="$2"
  grep -Fq -- "$literal" "$path" \
    || fail "missing required literal in ${path#$ROOT/}: $literal"
}

require_literal_count() {
  local path="$1"
  local literal="$2"
  local expected="$3"
  local actual
  actual="$(grep -Fc -- "$literal" "$path" || true)"
  [[ "$actual" = "$expected" ]] \
    || fail "expected $expected occurrences in ${path#$ROOT/}, found $actual: $literal"
}

reject_literal() {
  local path="$1"
  local literal="$2"
  if grep -Fq -- "$literal" "$path"; then
    fail "forbidden readiness claim in ${path#$ROOT/}: $literal"
  fi
}

for required in \
  "$POCO_WORKFLOW" \
  "$LEGACY_WORKFLOW" \
  "$RECOVERY_GATE" \
  "$LEGACY_PREFLIGHT" \
  "$CORE_SOURCE" \
  "$CORE_TESTS" \
  "$APP_RECOVERY" \
  "$APP_STORE_SOURCE" \
  "$SAFETY_STORE_SOURCE" \
  "$NODE_SOURCE" \
  "$NODE_RECOVERY_TESTS" \
  "$NODE_CARGO" \
  "$G1C_TRUTH" \
  "$ROOT_README" \
  "$PROTOCOL_README" \
  "$WIRE_DOC" \
  "$INVARIANTS_DOC" \
  "$DELIVERY_PLAN"; do
  require_file "$required"
done

# A SafetyStore change must trigger both pull-request and main-push PoCO gates.
require_literal_count "$POCO_WORKFLOW" \
  '      - "trillionnium/crates/trnm-consensus-safety-store/**"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - "trillionnium/crates/trnm-consensus-signer-journal/**"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - ".github/workflows/rust-l1-testnet-preflight.yml"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - "trillionnium/scripts/testnet_preflight.sh"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - "RELEASE_READINESS.md"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - "docs/architecture/TRNM_CONSENSUS_DELIVERY_DUAL_TRACK_DECISION_2026-08-11.md"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - "trillionnium/crates/trnm-poco-node/**"' 2

# SafetyStore is a first-class package in the complete test, strict lint,
# recovery, and release-profile compilation boundaries.
require_literal "$POCO_WORKFLOW" \
  'cargo test --locked -p trnm-consensus-safety-store --lib --tests'
require_literal "$POCO_WORKFLOW" \
  'cargo clippy --locked -p trnm-consensus-safety-store --all-targets -- -D warnings'
require_literal "$POCO_WORKFLOW" \
  '            -p trnm-consensus-safety-store \'
require_literal "$POCO_WORKFLOW" \
  'cargo test --locked -p trnm-consensus-signer-journal --all-targets'
require_literal "$POCO_WORKFLOW" \
  'cargo clippy --locked -p trnm-consensus-signer-journal --all-targets -- -D warnings'
require_literal "$POCO_WORKFLOW" \
  '            -p trnm-consensus-signer-journal \'
require_literal "$POCO_WORKFLOW" \
  'run: bash ./scripts/ci/check_poco_bft_v0_recovery_smoke.sh'
require_literal "$POCO_WORKFLOW" \
  'run: bash ./scripts/ci/check_poco_bft_v0_ci_truth.sh'
require_literal "$RECOVERY_GATE" \
  'torn_halt_latch_is_fail_closed_without_damaging_the_head_slots'
require_literal "$RECOVERY_GATE" \
  'deleting_persistent_wal_or_shm_after_close_fails_reopen_closed'
require_literal "$RECOVERY_GATE" \
  'tampered_only_valid_lock_watermark_slot_is_rejected_on_reopen'
require_literal "$RECOVERY_GATE" \
  'callback_persistence_preserves_exact_sign_intent_across_crash_resume'
require_literal "$RECOVERY_GATE" \
  'synced_callback_persistence_preserves_exact_vote_intent_across_crash_resume'
require_literal "$RECOVERY_GATE" \
  'external_watermark_recovers_each_local_first_commit_window'
require_literal "$RECOVERY_GATE" \
  'whole_namespace_rollback_is_detected_by_external_watermark'
require_literal "$RECOVERY_GATE" \
  'proposal_obligation_recovery_rebuilds_the_exact_target_before_invalid_callback'
require_literal "$RECOVERY_GATE" \
  'synced_obligation_recovery_rebuilds_the_exact_route_and_witness'
require_literal "$RECOVERY_GATE" \
  'obligation_recovery_rejects_tampered_duplicate_and_concurrent_records'
require_literal "$RECOVERY_GATE" \
  'strict_three_store_recovery_matrix_closes_o_p_o_d_c_d_and_c_k'
require_literal "$RECOVERY_GATE" \
  'validation_recovery=deterministic_invalid_existing_only'
require_literal "$RECOVERY_GATE" 'process_kill_matrix=NOT_EVALUATED'
require_literal "$RECOVERY_GATE" 'valid_recovery=not_implemented'
require_literal "$RECOVERY_GATE" 'unavailable_recovery=not_implemented'

# G1c is a bounded recovery join, not a relaxation of ordinary Core recovery.
# Keep the implementation/test anchors and exact claim boundary machine-checked.
require_literal "$CORE_SOURCE" \
  'pub fn begin_payload_validation_obligation_recovery_v0<V: SignatureVerifier>('
require_literal "$CORE_TESTS" \
  'fn recovery_with_a_claimed_durable_validation_fails_closed_without_reopening_it()'
require_literal "$CORE_TESTS" \
  'fn proposal_obligation_recovery_rebuilds_the_exact_target_before_invalid_callback()'
require_literal "$CORE_TESTS" \
  'fn obligation_recovery_rejects_tampered_duplicate_and_concurrent_records()'
require_literal "$APP_RECOVERY" 'pub fn open_existing_v8('
require_literal "$APP_RECOVERY" 'NativeValidationRecoveryUnsupportedV0::Reserved'
require_literal "$APP_RECOVERY" 'NativeValidationRecoveryUnsupportedV0::Evaluated'
require_literal "$APP_RECOVERY" 'NativeValidationRecoveryUnsupportedV0::Applied'
require_literal "$APP_RECOVERY" 'NativeValidationRecoveryUnsupportedV0::Valid'
require_literal "$APP_RECOVERY" 'NativeValidationRecoveryUnsupportedV0::Unavailable'
require_literal "$APP_RECOVERY" 'struct NativeValidationRecoveryNamespacePinV0 {'
require_literal "$APP_RECOVERY" 'let mut active_recovery_job_count = 0_usize;'
require_literal "$APP_RECOVERY" \
  'expected_safety_journal_id: [u8; 32],'
require_literal "$APP_RECOVERY" \
  'expected_safety_verifier_profile_ref: [u8; 32],'
require_literal "$APP_RECOVERY" \
  'confirmed: &ConfirmedNativeDeterministicInvalidHeadV0,'
require_literal "$APP_RECOVERY" \
  'bootstrap_native_validation_safety_binding_manifest_v0('
require_literal "$APP_RECOVERY" \
  'open_and_pin_native_validation_safety_binding_manifest_v0('
require_literal "$APP_RECOVERY" 'file_name.push(".safety-binding-v0");'
reject_literal "$APP_RECOVERY" \
  'pub trait NativeValidationConfirmedInvalidTransitionV0'
require_literal "$APP_STORE_SOURCE" 'ApplicationStoreOwnerModeV0::OrdinaryShared => {'
require_literal "$APP_STORE_SOURCE" 'FileExt::try_lock_shared(&lock_handle)'
require_literal "$APP_STORE_SOURCE" 'ApplicationStoreOwnerModeV0::RecoveryExclusive => {'
require_literal "$APP_STORE_SOURCE" 'FileExt::try_lock_exclusive(&lock_handle)'
require_literal "$APP_STORE_SOURCE" \
  'pub(super) fn validate_secure_native_validation_recovery_namespace_v0('
require_literal "$SAFETY_STORE_SOURCE" \
  'pub struct ConfirmedNativeDeterministicInvalidHeadV0 {'
require_literal "$SAFETY_STORE_SOURCE" \
  'pub fn confirmed_native_deterministic_invalid_head_v0('
require_literal "$SAFETY_STORE_SOURCE" 'pub const fn journal_id_v0(&self) -> [u8; 32] {'
require_literal "$SAFETY_STORE_SOURCE" \
  'pub const fn verifier_profile_ref_v0(&self) -> [u8; 32] {'
reject_literal "$SAFETY_STORE_SOURCE" \
  'impl NativeValidationConfirmedInvalidTransitionV0 for ConfirmedNativeDeterministicInvalidHeadV0'
reject_literal "$NODE_SOURCE" 'NativeValidationConfirmedInvalidTransitionV0'
reject_literal "$NODE_SOURCE" 'struct ConfirmedNativeInvalidSafetyHeadV0 {'
require_literal "$NODE_SOURCE" \
  'safety_store.journal_id_v0(),'
require_literal "$NODE_SOURCE" \
  'safety_store.verifier_profile_ref_v0(),'
require_literal "$NODE_SOURCE" \
  'left.starts_with(right) || right.starts_with(left)'
require_literal "$NODE_RECOVERY_TESTS" \
  'fn strict_three_store_recovery_matrix_closes_o_p_o_d_c_d_and_c_k()'
require_literal "$NODE_CARGO" 'production_candidate = false'
require_literal "$NODE_CARGO" 'production_consensus_activation = false'
require_literal "$NODE_CARGO" 'incomplete = true'
require_literal "$NODE_CARGO" 'effect_driver = false'
require_literal "$NODE_SOURCE" 'pub const PRODUCTION_CANDIDATE_V0: bool = false;'
require_literal "$NODE_SOURCE" \
  'pub const HOST_IMPLEMENTATION_COMPLETE_V0: bool = false;'
require_literal "$G1C_TRUTH" \
  'the admitted matrix is `O+P`, `O+D`, `C+D`, and `C+K`'
require_literal "$G1C_TRUTH" \
  'outside this local Linux contract, and no real process kill-point matrix,'
require_literal "$G1C_TRUTH" \
  'general network/effect driver, or state-sync recovery join has been completed.'

# Keep the ordinary recovery rejection distinct from the one-obligation G1c
# session, and describe the concrete Safety token as bounded joint provenance
# rather than either standalone authority or comparison-only data.
require_literal "$ROOT_README" \
  'The G1c validation-recovery slice is intentionally narrow. Ordinary'
require_literal "$ROOT_README" \
  'grants no callback, Core, or general application transition authority by'
require_literal "$PROTOCOL_README" \
  'Ordinary `Core::recover` validates every schema-v8 obligation and inert'
require_literal "$PROTOCOL_README" \
  'The token is not standalone or general transition authority.'
require_literal "$WIRE_DOC" \
  'Ordinary `Core::recover` validates schema-v8 obligations and inert completions'
require_literal "$INVARIANTS_DOC" \
  '- ordinary `Core::recover` MUST validate every schema-v8 obligation and inert'
require_literal "$INVARIANTS_DOC" \
  'capability MUST NOT implement an authority trait or authorize any callback,'
require_literal "$DELIVERY_PLAN" \
  'recovery session is the only bounded authenticated-ticket exception and'
require_literal "$G1C_TRUTH" \
  'native-invalid exact-readback token grants no detached or general'
reject_literal "$PROTOCOL_README" \
  'Recovery validates every schema-v8 obligation and inert completion and then rejects'
reject_literal "$WIRE_DOC" \
  'Recovery validates schema-v8 obligations and inert completions and then rejects'
reject_literal "$INVARIANTS_DOC" \
  '- recovery MUST validate every schema-v8 obligation and inert completion and then'
reject_literal "$DELIVERY_PLAN" \
  'of a pending SignIntent across unrelated callback persistence. Recovery first'
reject_literal "$ROOT_README" \
  'grants no public callback, Core, or application transition authority'
reject_literal "$G1C_TRUTH" 'grants only authenticated comparison facts'

# The fail-closed node scaffold must compile and lint wherever its source can
# trigger this workflow, while remaining explicitly incomplete and outside the
# uploaded library archive.
require_literal "$POCO_WORKFLOW" \
  'cargo test --locked -p trnm-poco-node --all-targets --features recovery-test-support'
require_literal "$POCO_WORKFLOW" \
  'cargo clippy --locked -p trnm-poco-node --all-targets --features recovery-test-support --no-deps -- -D warnings'
require_literal_count "$POCO_WORKFLOW" '--features recovery-test-support' 2
require_literal "$POCO_WORKFLOW" \
  '            -p trnm-poco-node \'
require_literal "$POCO_WORKFLOW" \
  'name: Core, application, SafetyStore, signer, and inert-node G1c recovery gate'

# Release-profile libraries are useful integration artifacts, not a node or a
# production-readiness decision. Keep that boundary machine-readable both in
# the workflow UI and in the uploaded archive metadata.
require_literal "$POCO_WORKFLOW" \
  'name: Development-only integration library artifact build'
require_literal "$POCO_WORKFLOW" \
  'cargo build --locked --release --no-default-features \'
require_literal "$POCO_WORKFLOW" \
  'name: trnm-poco-bft-v0-development-libs-${{ github.run_id }}-${{ github.run_attempt }}'
require_literal "$POCO_WORKFLOW" 'artifact_class=development_only'
require_literal "$POCO_WORKFLOW" 'build_profile=release'
require_literal "$POCO_WORKFLOW" 'development_only=true'
require_literal "$POCO_WORKFLOW" 'production_consensus_activation=false'
require_literal "$POCO_WORKFLOW" 'deployable_node=false'
require_literal "$POCO_WORKFLOW" 'production_candidate=false'
require_literal "$POCO_WORKFLOW" 'incomplete=true'
require_literal "$POCO_WORKFLOW" 'effect_driver=false'
require_literal "$POCO_WORKFLOW" 'poco_node_binary_included=false'
require_literal "$POCO_WORKFLOW" 'production_ready=false'
require_literal "$POCO_WORKFLOW" 'test_features_included=false'
require_literal "$POCO_WORKFLOW" 'recovery_test_support_included=false'
require_literal "$POCO_WORKFLOW" 'recovery_only_core_step=true'
require_literal "$POCO_WORKFLOW" \
  'validation_recovery_scope=deterministic_invalid_existing_only_v0'
require_literal "$POCO_WORKFLOW" 'validation_recovery_process_kill_matrix=false'
require_literal "$POCO_WORKFLOW" 'application_safety_binding_manifest=true'
require_literal "$POCO_WORKFLOW" \
  'application_safety_binding_initializer=fixture_only_not_in_artifact'
require_literal "$POCO_WORKFLOW" 'application_recovery_secure_namespace=true'
require_literal "$POCO_WORKFLOW" \
  'application_recovery_secure_namespace_scope=local_linux_non_same_euid_v0'
require_literal "$POCO_WORKFLOW" 'application_recovery_sqlite_main_fd_identity=false'
require_literal "$POCO_WORKFLOW" 'application_recovery_wal_shm_inode_pinning=false'
require_literal "$POCO_WORKFLOW" 'block_id_speculative_overlay=false'
require_literal "$POCO_WORKFLOW" 'ordered_finalization_queue=false'
require_literal "$POCO_WORKFLOW" 'whole_node_namespace_rollback_protection=false'
require_literal "$POCO_WORKFLOW" 'includes_trnm_consensus_safety_store=true'
require_literal "$POCO_WORKFLOW" 'includes_trnm_consensus_signer_journal=true'
require_literal "$POCO_WORKFLOW" 'external_monotonic_signer_watermark_bound=false'
require_literal "$POCO_WORKFLOW" \
  '${{ runner.temp }}/trnm-poco-bft-v0-development-libs.metadata.txt'
require_literal "$POCO_WORKFLOW" \
  'name: Verify development-only artifact boundary'
reject_literal "$POCO_WORKFLOW" 'name: Release library artifact build'
reject_literal "$POCO_WORKFLOW" \
  'name: trnm-poco-bft-v0-libs-${{ github.run_id }}-${{ github.run_attempt }}'

# The retained Rust-L1 script executes the legacy simulator and loopback
# devnet. A pass is only a development rehearsal pass; it must never emit a
# PoCO, public-testnet, or production GO decision.
require_literal "$LEGACY_WORKFLOW" 'name: legacy-local-harness-preflight'
require_literal "$LEGACY_WORKFLOW" \
  'name: Legacy local harness rehearsal (development only)'
require_literal "$LEGACY_WORKFLOW" \
  'name: legacy-local-harness-preflight-${{ github.run_id }}'
require_literal "$LEGACY_WORKFLOW" 'name: Record non-readiness boundary'
require_literal "$LEGACY_WORKFLOW" \
  'poco_bft_readiness=NOT_EVALUATED'
require_literal "$LEGACY_WORKFLOW" \
  'public_testnet_readiness=NOT_EVALUATED'
require_literal "$LEGACY_WORKFLOW" 'production_ready=false'
require_literal "$LEGACY_PREFLIGHT" 'trnm_legacy_local_harness_preflight'
require_literal "$LEGACY_PREFLIGHT" \
  'evaluation_scope=legacy_local_harness_rehearsal'
require_literal "$LEGACY_PREFLIGHT" 'pass_semantics=local_rehearsal_only'
require_literal "$LEGACY_PREFLIGHT" 'readiness_decision=NOT_EVALUATED'
require_literal "$LEGACY_PREFLIGHT" 'development_only=true'
require_literal "$LEGACY_PREFLIGHT" 'legacy_harness=true'
require_literal "$LEGACY_PREFLIGHT" 'poco_bft_evaluated=false'
require_literal "$LEGACY_PREFLIGHT" 'poco_bft_readiness=NOT_EVALUATED'
require_literal "$LEGACY_PREFLIGHT" 'public_testnet_evaluated=false'
require_literal "$LEGACY_PREFLIGHT" 'public_testnet_readiness=NOT_EVALUATED'
require_literal "$LEGACY_PREFLIGHT" 'production_ready=false'
require_literal "$LEGACY_PREFLIGHT" \
  'truth_source=$GIT_TOPLEVEL/RELEASE_READINESS.md'
require_literal "$LEGACY_PREFLIGHT" 'status=PASS'
require_literal "$LEGACY_PREFLIGHT" 'result=PASS'
reject_literal "$LEGACY_PREFLIGHT" 'status=GO'
reject_literal "$LEGACY_PREFLIGHT" 'result=GO'
reject_literal "$LEGACY_PREFLIGHT" '[OK] testnet preflight passed'
reject_literal "$LEGACY_PREFLIGHT" \
  'truth_source=$ROOT/RELEASE_READINESS.md'

printf '%s\n' \
  'poco_bft_ci_truth=passed safety_store=triggered,tested,clippy,recovery,artifact signer_journal=triggered,tested,clippy,recovery,artifact,incomplete node_scaffold=triggered,tested,clippy,release-built,incomplete readiness=development_only,no_legacy_go'
