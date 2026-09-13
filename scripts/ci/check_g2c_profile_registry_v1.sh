#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"

bash scripts/ci/check_deterministic_reexecution_model_v1.sh

cargo test \
  --manifest-path trillionnium/Cargo.toml \
  --locked --offline \
  -p trnm-poco-verify-challenge-v1 \
  --test profile_registry_v1

cargo clippy \
  --manifest-path trillionnium/Cargo.toml \
  --locked --offline \
  -p trnm-poco-verify-challenge-v1 \
  --test profile_registry_v1 \
  -- -D warnings

cargo fmt \
  --manifest-path trillionnium/Cargo.toml \
  --package trnm-poco-verify-challenge-v1 \
  -- --check

python3 - <<'PY'
from pathlib import Path
source = Path('trillionnium/crates/trnm-poco-verify-challenge-v1/src/profile_registry_v1.rs').read_text()
test = Path('trillionnium/crates/trnm-poco-verify-challenge-v1/tests/profile_registry_v1.rs').read_text()
compiled_surface = source + '\n' + test

# Every closed profile kind must be exercised through the public integration
# surface. The implementation intentionally uses `Self::...` internally, so a
# source-only spelling check would reject equivalent, compiled Rust.
for token in (
    'VerificationProfileKindV1::DeterministicReexecution',
    'VerificationProfileKindV1::ReproducibleMachineLearning',
    'VerificationProfileKindV1::ZeroKnowledge',
    'VerificationProfileKindV1::TrustedExecutionEnvironment',
    'VerificationProfileKindV1::StakeQuorum',
    'VerificationProfileKindV1::Optimistic',
    'VerificationProfileKindV1::Subjective',
):
    assert token in compiled_surface, token

# Non-authority constants remain source-owned and may not be satisfied by a
# test-only shadow declaration.
for token in (
    'VERIFICATION_PROFILE_FALLBACK_ALLOWED_V1: bool = false',
    'VERIFICATION_DECISION_ECONOMIC_AUTHORITY_V1: bool = false',
    'VERIFICATION_DECISION_ORDER_REORG_AUTHORITY_V1: bool = false',
    'VERIFICATION_DECISION_POCO_WEIGHT_AUTHORITY_V1: bool = false',
):
    assert token in source, token

for token in (
    'exact_resolution_and_evidence_precede_backend',
    'verified_rejected_and_unavailable_are_distinct_and_non_authoritative',
    'disabled_expired_revoked_and_unknown_profiles_do_not_fallback',
    'subjective_profiles_cannot_escalate_objective_authority',
    'duplicate_challenge_is_rejected_and_lifecycle_is_forward_only',
    'withdrawal_and_expiry_close_without_economic_or_order_authority',
):
    assert token in test, token
print('G2C closed profile registry and challenge lifecycle: ok')
PY

git diff --check
