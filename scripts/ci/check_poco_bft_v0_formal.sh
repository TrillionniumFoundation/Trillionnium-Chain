#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
model="$repo_root/formal/quint/poco-bft-v0/poco_bft.qnt"
journal_model="$repo_root/formal/quint/poco-bft-v0/persist_before_sign.qnt"
weighted_model="$repo_root/formal/quint/poco-bft-v0/weighted_quorum.qnt"
tc_model="$repo_root/formal/quint/poco-bft-v0/tc_lock.qnt"
tc_selection_model="$repo_root/formal/quint/poco-bft-v0/tc_high_qc_selection.qnt"
anchor_view_change_model="$repo_root/formal/quint/poco-bft-v0/anchor_view_change.qnt"
partition_heal_model="$repo_root/formal/quint/poco-bft-v0/partition_heal.qnt"
upgrade_model="$repo_root/formal/quint/poco-bft-v0/upgrade_atomicity.qnt"
weight_snapshot_model="$repo_root/formal/quint/poco-bft-v0/poco_weight_snapshot.qnt"
handoff_model="$repo_root/formal/quint/poco-bft-v0/joint_handoff.qnt"
light_client_model="$repo_root/formal/quint/poco-bft-v0/light_client_handoff.qnt"
application_atomicity_model="$repo_root/formal/quint/poco-bft-v0/poco_application_atomicity.qnt"
sign_before_persist_mutant="$repo_root/formal/quint/poco-bft-v0/mutants/sign_before_persist.qnt"
duplicate_signer_mutant="$repo_root/formal/quint/poco-bft-v0/mutants/duplicate_signer_weight.qnt"
tc_unlock_mutant="$repo_root/formal/quint/poco-bft-v0/mutants/tc_clears_lock.qnt"
tc_omitted_reference_mutant="$repo_root/formal/quint/poco-bft-v0/mutants/tc_omits_referenced_qc.qnt"
premature_upgrade_mutant="$repo_root/formal/quint/poco-bft-v0/mutants/premature_upgrade_activation.qnt"
duplicate_certificate_mutant="$repo_root/formal/quint/poco-bft-v0/mutants/duplicate_certificate_counted.qnt"
one_sided_handoff_mutant="$repo_root/formal/quint/poco-bft-v0/mutants/one_sided_handoff.qnt"
self_signed_uncommitted_mutant="$repo_root/formal/quint/poco-bft-v0/mutants/self_signed_uncommitted_set.qnt"
quint_toolchain_dir="$repo_root/formal/quint/poco-bft-v0"
quint_bin="${QUINT_BIN:-$quint_toolchain_dir/node_modules/.bin/quint}"
if [[ ! -x "$quint_bin" ]]; then
  echo "ERROR: lock-pinned Quint is not installed; run npm ci --ignore-scripts --no-audit --no-fund in $quint_toolchain_dir" >&2
  exit 1
fi

"$quint_bin" typecheck "$model"
"$quint_bin" typecheck "$journal_model"
"$quint_bin" typecheck "$weighted_model"
"$quint_bin" typecheck "$tc_model"
"$quint_bin" typecheck "$tc_selection_model"
"$quint_bin" typecheck "$anchor_view_change_model"
"$quint_bin" typecheck "$partition_heal_model"
"$quint_bin" typecheck "$upgrade_model"
"$quint_bin" typecheck "$weight_snapshot_model"
"$quint_bin" typecheck "$handoff_model"
"$quint_bin" typecheck "$light_client_model"
"$quint_bin" typecheck "$application_atomicity_model"
"$quint_bin" typecheck "$sign_before_persist_mutant"
"$quint_bin" typecheck "$duplicate_signer_mutant"
"$quint_bin" typecheck "$tc_unlock_mutant"
"$quint_bin" typecheck "$tc_omitted_reference_mutant"
"$quint_bin" typecheck "$premature_upgrade_mutant"
"$quint_bin" typecheck "$duplicate_certificate_mutant"
"$quint_bin" typecheck "$one_sided_handoff_mutant"
"$quint_bin" typecheck "$self_signed_uncommitted_mutant"

for invariant in \
  noConflictingFinality \
  quorumContainsHonest \
  durableNonEquivocation \
  journalCoversVotes \
  certifiedLocks
do
  "$quint_bin" run "$model" \
    --invariant="$invariant" \
    --max-samples=10000 \
    --max-steps=30 \
    --seed=0x54524e4d \
    --verbosity=1
done

for invariant in \
  signatureCoveredByJournal \
  durableNonEquivocationAcrossCrash \
  journalCoveredByViewWatermark
do
  "$quint_bin" run "$journal_model" \
    --invariant="$invariant" \
    --max-samples=10000 \
    --max-steps=30 \
    --seed=0x54524e4d \
    --verbosity=1
done

for invariant in \
  noConflictingWeightedQcs \
  weightedQcContainsHonest \
  uniqueSignerAccounting
do
  "$quint_bin" run "$weighted_model" \
    --invariant="$invariant" \
    --max-samples=10000 \
    --max-steps=20 \
    --seed=0x54524e4d \
    --verbosity=1
done

for invariant in tcDoesNotUnlock tcStateMonotonic
do
  "$quint_bin" run "$tc_model" \
    --invariant="$invariant" \
    --max-samples=10000 \
    --max-steps=20 \
    --seed=0x54524e4d \
    --verbosity=1
done

for invariant in \
  completeUniqueQcReferences \
  acceptedSelectsCanonicalHighQc \
  sameViewConflictFailsClosed \
  acceptedOnlyWithTimeoutQuorum \
  haltedReceiverCannotAccept \
  qcDigestBreaksEqualViewBlockTie
do
  "$quint_bin" run "$tc_selection_model" \
    --invariant="$invariant" \
    --max-samples=10000 \
    --max-steps=20 \
    --seed=0x54524e4d \
    --verbosity=1
done

for invariant in \
  anchorViewChangeSafety \
  anchorsAreViewZeroAndUnsigned \
  onlyContextAuthorizedAnchorsCanProgress \
  tcRequiresQuorumAndExactAnchor \
  firstProposalKeepsActivationHeight \
  skippedViewProposalRequiresExactTc \
  ordinaryQcRequiresOrdinaryVoteQuorum \
  candidateValidationFailsClosed \
  anchorHasNoCertificationOrFinalityPower \
  missingHandoffAuthorizationCannotProgress
do
  "$quint_bin" run "$anchor_view_change_model" \
    --invariant="$invariant" \
    --max-samples=10000 \
    --max-steps=12 \
    --seed=0x54524e4d \
    --verbosity=1
done

# The network model has a substantially larger message-state surface than the
# other kernels. Its separately named review invariants are combined into one
# predicate so they inspect the same fixed corpus without repeating it seven
# times. The fair finite progress trace is checked independently below.
"$quint_bin" run "$partition_heal_model" \
  --invariant=partitionHealSafety \
  --max-samples=3000 \
  --max-steps=20 \
  --seed=0x54524e4d \
  --verbosity=1

for invariant in \
  upgradeAtomicitySafety \
  activationRequiresAllPrerequisites \
  unsupportedPlanCannotActivate \
  conflictingFinalizedPlansFailClosed \
  oneConfigurationPerHeight
do
  "$quint_bin" run "$upgrade_model" \
    --invariant="$invariant" \
    --max-samples=10000 \
    --max-steps=30 \
    --seed=0x54524e4d \
    --verbosity=1
done

for invariant in \
  pocoWeightSnapshotSafety \
  maturityAgeDecayAndPerCertificateCap \
  hierarchicalCapsHitInFrozenOrder \
  identicalInputProducesUniqueSnapshot \
  deterministicRawThenIdSelectionOrder \
  duplicateCertificateFailsClosed \
  errorAndOverflowFailClosed \
  candidateAndCommittedPowerBounds
do
  "$quint_bin" run "$weight_snapshot_model" \
    --invariant="$invariant" \
    --max-samples=10000 \
    --max-steps=4 \
    --seed=0x54524e4d \
    --verbosity=1
done

for invariant in \
  activationRequiresCheckpoint \
  activationRequiresBothQuorums \
  oneJointDescriptor
do
  "$quint_bin" run "$handoff_model" \
    --invariant="$invariant" \
    --max-samples=10000 \
    --max-steps=30 \
    --seed=0x54524e4d \
    --verbosity=1
done

for invariant in \
  acceptedOnlyCommittedJointTransition \
  acceptedWithinTrustingPeriod \
  uncertainFreshnessFailsClosed \
  trustingPeriodBoundary \
  atMostOneAcceptedLink
do
  "$quint_bin" run "$light_client_model" \
    --invariant="$invariant" \
    --max-samples=10000 \
    --max-steps=30 \
    --seed=0x54524e4d \
    --verbosity=1
done

for invariant in \
  allOrNothingCommit \
  targetBoundFieldsEqualCommittedHeight \
  acceptedCertificateHasAllAuthorities \
  nonceAndRegistrationHistoryMonotonic \
  decisionAndNullifierAtMostOnce \
  pruneRequiresAtomicSparseNullifierInsertion \
  replayRejectedAfterPrune \
  failedOperationLeavesHeadUnchanged
do
  "$quint_bin" run "$application_atomicity_model" \
    --invariant="$invariant" \
    --max-samples=10000 \
    --max-steps=8 \
    --seed=0x54524e4d \
    --verbosity=1
done

mutant_dir="$(mktemp -d)"
trap 'rm -r "$mutant_dir"' EXIT

expect_reachable() {
  local label="$1"
  local witness_model="$2"
  local init_action="$3"
  local step_action="$4"
  local not_reached_invariant="$5"
  local max_steps="$6"
  local output="$mutant_dir/$label.log"

  if "$quint_bin" run "$witness_model" \
    --init="$init_action" \
    --step="$step_action" \
    --invariant="$not_reached_invariant" \
    --max-samples=1 \
    --max-steps="$max_steps" \
    --seed=0x54524e4d \
    --verbosity=1 >"$output" 2>&1
  then
    echo "$label bounded witness was not reached" >&2
    cat "$output" >&2
    exit 1
  fi

  if ! grep -Eq 'Invariant.*violated|violation|counterexample' "$output"; then
    echo "$label witness check failed without a recognizable trace" >&2
    cat "$output" >&2
    exit 1
  fi

  echo "[ok] $label bounded witness was reached"
}

expect_violation() {
  local label="$1"
  local mutant_model="$2"
  local invariant="$3"
  local max_steps="$4"
  local output="$mutant_dir/$label.log"

  if "$quint_bin" run "$mutant_model" \
    --invariant="$invariant" \
    --max-samples=10000 \
    --max-steps="$max_steps" \
    --seed=0x54524e4d \
    --verbosity=1 >"$output" 2>&1
  then
    echo "$label mutant unexpectedly satisfied $invariant" >&2
    cat "$output" >&2
    exit 1
  fi

  if ! grep -Eq 'Invariant.*violated|violation|counterexample' "$output"; then
    echo "$label mutant failed without a recognizable counterexample" >&2
    cat "$output" >&2
    exit 1
  fi

  echo "[ok] $label mutant was rejected"
}

expect_scoped_violation() {
  local label="$1"
  local mutation_model="$2"
  local init_action="$3"
  local step_action="$4"
  local invariant="$5"
  local max_steps="$6"
  local output="$mutant_dir/$label.log"

  if "$quint_bin" run "$mutation_model" \
    --init="$init_action" \
    --step="$step_action" \
    --invariant="$invariant" \
    --max-samples=1 \
    --max-steps="$max_steps" \
    --seed=0x54524e4d \
    --verbosity=1 >"$output" 2>&1
  then
    echo "$label mutation unexpectedly satisfied $invariant" >&2
    cat "$output" >&2
    exit 1
  fi

  if ! grep -Eq 'Invariant.*violated|violation|counterexample' "$output"; then
    echo "$label mutation failed without a recognizable counterexample" >&2
    cat "$output" >&2
    exit 1
  fi

  echo "[ok] $label in-model mutation was rejected"
}

expect_reachable \
  legal-three-chain-finality "$model" init \
  legalFinalityStep legalFinalityNotReached 4
expect_scoped_violation \
  lock-rule-bypass-conflicting-finality "$model" init \
  unsafeForkStep noConflictingFinality 8
expect_reachable \
  heterogeneous-tc-selection "$tc_selection_model" initHeterogeneous \
  validateTc heterogeneousSelectionNotReached 1
expect_reachable \
  conflicting-tc-halt "$tc_selection_model" initConflicting \
  validateTc conflictingQcHaltNotReached 1
expect_reachable \
  same-view-block-digest-selection "$tc_selection_model" \
  initSameViewBlockDifferentDigests validateTc \
  sameViewBlockDigestSelectionNotReached 1
expect_reachable \
  genesis-anchor-view-change "$anchor_view_change_model" \
  initGenesisAuthorized authorizedViewChangeStep \
  authorizedViewChangeNotReached 7
expect_reachable \
  epoch-anchor-view-change "$anchor_view_change_model" \
  initEpochAuthorized authorizedViewChangeStep \
  authorizedViewChangeNotReached 7
expect_reachable \
  wrong-anchor-tc-rejection "$anchor_view_change_model" \
  initEpochAuthorized wrongTcRejectionStep wrongTcRejectionNotReached 4
expect_reachable \
  missing-handoff-anchor-rejection "$anchor_view_change_model" \
  initEpochMissingHandoff missingHandoffRejectionStep \
  missingHandoffRejectionNotReached 2
expect_reachable \
  unauthorized-empty-qc-rejection "$anchor_view_change_model" \
  initGenesisUntrusted unauthorizedContextRejectionStep \
  unauthorizedEmptyRejectionNotReached 2
expect_reachable \
  wrong-empty-qc-rejection "$anchor_view_change_model" \
  initEpochAuthorized wrongEmptyQcRejectionStep \
  unauthorizedEmptyRejectionNotReached 2
expect_reachable \
  anchor-certification-rejection "$anchor_view_change_model" \
  initEpochAuthorized anchorCertificationRejectionStep \
  anchorCertificationRejectionNotReached 2
expect_reachable \
  anchor-finality-rejection "$anchor_view_change_model" \
  initEpochAuthorized anchorFinalityRejectionStep \
  anchorFinalityRejectionNotReached 2
expect_reachable \
  valid-certifying-qc-acceptance "$anchor_view_change_model" \
  initEpochAuthorized certifyingQcAcceptanceStep \
  validCertifyingQcAcceptanceNotReached 2
expect_reachable \
  valid-direct-finality-acceptance "$anchor_view_change_model" \
  initEpochAuthorized finalityAcceptanceStep \
  validFinalityAcceptanceNotReached 2
expect_reachable \
  fair-heal-progress "$partition_heal_model" init \
  fairHealStep fairHealProgressNotReached 4
expect_reachable \
  legal-upgrade "$upgrade_model" init \
  legalUpgradeStep legalUpgradeNotReached 7
expect_reachable \
  legal-weight-snapshot "$weight_snapshot_model" initValid \
  step legalSnapshotNotReached 2
expect_reachable \
  duplicate-certificate-fallback "$weight_snapshot_model" initDuplicate \
  step duplicateFallbackNotReached 2
expect_reachable \
  arithmetic-overflow-fallback "$weight_snapshot_model" initOverflow \
  step overflowFallbackNotReached 2
expect_reachable \
  malformed-state-fallback "$weight_snapshot_model" initMalformed \
  step overflowFallbackNotReached 2
expect_reachable \
  poco-application-acceptance "$application_atomicity_model" \
  initAcceptance acceptanceWitnessStep acceptanceNotReached 1
expect_reachable \
  poco-application-challenge-resolution "$application_atomicity_model" \
  initChallenge challengeWitnessStep challengeNotReached 2
expect_reachable \
  poco-application-governance-approval "$application_atomicity_model" \
  initGovernance governanceWitnessStep governanceNotReached 2
expect_reachable \
  poco-application-registration-rotation "$application_atomicity_model" \
  initRotation rotationWitnessStep rotationNotReached 1
expect_reachable \
  poco-application-prune-replay-rejection "$application_atomicity_model" \
  initPrune pruneReplayWitnessStep pruneReplayRejectNotReached 2
expect_reachable \
  poco-application-failure-rollback "$application_atomicity_model" \
  initFailure failureRollbackWitnessStep failureRollbackNotReached 1

expect_violation \
  sign-before-persist "$sign_before_persist_mutant" signatureCoveredByJournal 10
expect_violation \
  duplicate-signer "$duplicate_signer_mutant" noConflictingWeightedQcs 20
expect_violation tc-unlock "$tc_unlock_mutant" tcDoesNotUnlock 10
expect_violation \
  tc-omitted-reference "$tc_omitted_reference_mutant" \
  completeUniqueQcReferences 1
expect_scoped_violation \
  anchor-certifies "$anchor_view_change_model" \
  initEpochAuthorized anchorCertificationMutantStep \
  anchorHasNoCertificationOrFinalityPower 2
expect_scoped_violation \
  anchor-finalizes "$anchor_view_change_model" \
  initEpochAuthorized anchorFinalityMutantStep \
  anchorHasNoCertificationOrFinalityPower 2
expect_violation \
  premature-upgrade "$premature_upgrade_mutant" \
  activationRequiresAllPrerequisites 1
expect_violation \
  duplicate-certificate-counted "$duplicate_certificate_mutant" \
  duplicateCertificateFailsClosed 1
expect_violation \
  one-sided-handoff "$one_sided_handoff_mutant" activationRequiresBothQuorums 30
expect_violation \
  self-signed-uncommitted-set "$self_signed_uncommitted_mutant" \
  acceptedOnlyCommittedJointTransition 5
expect_scoped_violation \
  partial-cross-entry-commit "$application_atomicity_model" \
  initAcceptance partialCrossEntryCommitMutantStep \
  allOrNothingCommit 1
expect_scoped_violation \
  prune-without-nullifier "$application_atomicity_model" \
  initPrune pruneWithoutNullifierMutantStep \
  pruneRequiresAtomicSparseNullifierInsertion 1
