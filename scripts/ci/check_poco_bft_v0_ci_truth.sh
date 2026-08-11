#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
POCO_WORKFLOW="$ROOT/.github/workflows/trnm-poco-bft-v0.yml"
LEGACY_WORKFLOW="$ROOT/.github/workflows/rust-l1-testnet-preflight.yml"
RECOVERY_GATE="$ROOT/scripts/ci/check_poco_bft_v0_recovery_smoke.sh"
LEGACY_PREFLIGHT="$ROOT/trillionnium/scripts/testnet_preflight.sh"

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
  "$LEGACY_PREFLIGHT"; do
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

# The fail-closed node scaffold must compile and lint wherever its source can
# trigger this workflow, while remaining explicitly incomplete and outside the
# uploaded library archive.
require_literal "$POCO_WORKFLOW" \
  'cargo test --locked -p trnm-poco-node --all-targets'
require_literal "$POCO_WORKFLOW" \
  'cargo clippy --locked -p trnm-poco-node --all-targets -- -D warnings'
require_literal "$POCO_WORKFLOW" \
  '            -p trnm-poco-node \'

# Release-profile libraries are useful integration artifacts, not a node or a
# production-readiness decision. Keep that boundary machine-readable both in
# the workflow UI and in the uploaded archive metadata.
require_literal "$POCO_WORKFLOW" \
  'name: Development-only integration library artifact build'
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
