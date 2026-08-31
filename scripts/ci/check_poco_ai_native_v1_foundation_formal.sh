#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
formal_root="$repo_root/formal/quint/poco-ai-native-v1"
toolchain_root="$repo_root/formal/quint/poco-bft-v0"
quint_bin="${QUINT_BIN:-$toolchain_root/node_modules/.bin/quint}"
max_samples="${QUINT_MAX_SAMPLES:-2500}"
seed="0x54524e4d"

fail() {
  printf 'PoCO AI-native v1 foundation formal gate failed: %s\n' "$*" >&2
  exit 1
}

[[ -x "$quint_bin" ]] || fail \
  "lock-pinned Quint is missing; install the existing v0 toolchain exactly"

order_model="$formal_root/weighted_order_kernel.qnt"
timeout_model="$formal_root/timeout_lock.qnt"
handoff_model="$formal_root/epoch_handoff_activation.qnt"

mutants=(
  "$formal_root/mutants/duplicate_signer_weight.qnt"
  "$formal_root/mutants/unsafe_lock_vote.qnt"
  "$formal_root/mutants/tc_unlocks.qnt"
  "$formal_root/mutants/tc_finalizes.qnt"
  "$formal_root/mutants/two_chain_finality.qnt"
  "$formal_root/mutants/single_quorum_handoff.qnt"
  "$formal_root/mutants/wrong_activation_anchor.qnt"
)

for required in \
  "$formal_root/README.md" \
  "$order_model" \
  "$timeout_model" \
  "$handoff_model" \
  "${mutants[@]}"
do
  [[ -f "$required" ]] || fail "missing ${required#$repo_root/}"
done

# Bind the bounded abstraction to the current candidate schema/vector facts
# and preserve every repository-wide negative evidence claim.
python3 - "$repo_root" <<'PY'
from __future__ import annotations

import json
import pathlib
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
schema = json.loads((root / "docs/protocol/poco-ai-native-v1/schema/cev1-foundation-order-kernel-v1.json").read_text())
vectors = json.loads((root / "docs/protocol/poco-ai-native-v1/vectors/cev1-foundation-order-kernel-v1.json").read_text())
with (root / "docs/protocol/poco-ai-native-v1/status.toml").open("rb") as source:
    status = tomllib.load(source)

issues: list[str] = []

if schema.get("status", {}).get("classification") != "candidate_non_normative":
    issues.append("schema must remain candidate_non_normative")
for key in (
    "normative_freeze",
    "global_wire_schema_complete",
    "semantic_consistency_proven",
    "implementation_or_activation_evidence",
    "cryptographic_interoperability_evidence",
):
    if schema.get("status", {}).get(key) is not False:
        issues.append(f"schema.status.{key} must remain false")

constraint_ids = {entry.get("id") for entry in schema.get("constraints", [])}
for expected in (
    "validator-quorum",
    "certificate-order",
    "certificate-quorum",
    "tc-view",
    "handoff-monotonic",
):
    if expected not in constraint_ids:
        issues.append(f"candidate schema is missing constraint {expected}")

fixtures = vectors.get("fixtures", {})
source_definition = fixtures.get("source_validator_set_descriptor", {}).get("definition", {})
target_definition = fixtures.get("target_validator_set_descriptor", {}).get("definition", {})
for label, definition in (
    ("source", source_definition),
    ("target", target_definition),
):
    weights = [member.get("voting_weight") for member in definition.get("members", [])]
    if weights != [1, 1, 1, 1]:
        issues.append(f"{label} vector weights changed from the modeled [1,1,1,1]")
    if definition.get("total_weight") != 4 or definition.get("quorum_threshold") != 3:
        issues.append(f"{label} vector W/threshold changed from modeled 4/3")

positive_by_id = {
    case.get("case_id"): case for case in vectors.get("positive_cases", [])
}
handoff = positive_by_id.get("epoch_handoff_body", {}).get("value", {})
expected_handoff = {
    "old_epoch": 7,
    "new_epoch": 8,
    "terminal_height": 99,
    "activation_height": 100,
    "initial_new_view": 1,
}
for key, expected in expected_handoff.items():
    if handoff.get(key) != expected:
        issues.append(f"handoff fixture {key}={handoff.get(key)!r}, expected {expected}")

tc = positive_by_id.get("timeout_certificate", {}).get("value", {})
if tc.get("target_view") != tc.get("timed_out_view", -2) + 1:
    issues.append("timeout fixture no longer has target_view=timed_out_view+1")

if status.get("normative_freeze") is not False:
    issues.append("status.normative_freeze must remain false")
if status.get("implementation_status") != "not-implemented":
    issues.append("status.implementation_status must remain not-implemented")
if status.get("evidence", {}).get("formal_model_complete") is not False:
    issues.append("status.evidence.formal_model_complete must remain false")

readme = (root / "formal/quint/poco-ai-native-v1/README.md").read_text()
for literal in (
    "candidate evidence only",
    "formal_model_complete=false",
    "ValidatorSetDefinitionV1",
    "TimeoutCertificateBodyV1",
    "EpochHandoffSignatureEntryV1",
    "old_epoch=7",
    "terminal_height=99",
):
    if literal not in readme:
        issues.append(f"formal README is missing required mapping literal {literal!r}")

if issues:
    for issue in issues:
        print(f"ERROR: {issue}", file=sys.stderr)
    raise SystemExit(1)
PY

models=("$order_model" "$timeout_model" "$handoff_model" "${mutants[@]}")
for model in "${models[@]}"; do
  "$quint_bin" typecheck "$model"
done

run_invariant() {
  local model="$1"
  local invariant="$2"
  local max_steps="$3"
  "$quint_bin" run "$model" \
    --invariant="$invariant" \
    --max-samples="$max_samples" \
    --max-steps="$max_steps" \
    --seed="$seed" \
    --verbosity=1
}

for invariant in \
  thresholdMatchesCommittedWeights \
  everyQcHasUniqueWeightedQuorum \
  honestVoteNonEquivocation \
  certifiedLocks \
  finalityRequiresDirectThreeChain \
  noConflictingOrderFinality
do
  run_invariant "$order_model" "$invariant" 12
done

for invariant in \
  tcTargetIsImmediateSuccessor \
  tcNeverUnlocks \
  tcNeverCertifiesOrFinalizes \
  tcViewStateIsMonotonic
do
  run_invariant "$timeout_model" "$invariant" 10
done

for invariant in \
  handoffRolesAreSeparated \
  activationRequiresFinalizedCheckpoint \
  activationRequiresDualWeightedQuorum \
  activationAnchorIsExact \
  activationCoordinatesAreMonotonic
do
  run_invariant "$handoff_model" "$invariant" 8
done

evidence_dir="$(mktemp -d)"
trap 'rm -rf "$evidence_dir"' EXIT

expect_counterexample() {
  local label="$1"
  local model="$2"
  local init_action="$3"
  local step_action="$4"
  local invariant="$5"
  local max_steps="$6"
  local output="$evidence_dir/$label.log"

  if "$quint_bin" run "$model" \
    --init="$init_action" \
    --step="$step_action" \
    --invariant="$invariant" \
    --max-samples=1 \
    --max-steps="$max_steps" \
    --seed="$seed" \
    --verbosity=1 >"$output" 2>&1
  then
    cat "$output" >&2
    fail "$label unexpectedly satisfied $invariant"
  fi

  grep -Eq 'Invariant.*violated|violation|counterexample' "$output" || {
    cat "$output" >&2
    fail "$label failed without a recognizable Quint counterexample"
  }
  printf '[ok] %s produced the required bounded counterexample\n' "$label"
}

# Positive reachability witnesses deliberately violate a "not reached"
# invariant when the legal trace completes.
expect_counterexample \
  legal-three-chain "$order_model" init legalFinalityStep \
  legalFinalityNotReached 4
expect_counterexample \
  legal-timeout "$timeout_model" init legalTimeoutStep \
  legalTimeoutNotReached 1
expect_counterexample \
  legal-dual-quorum-handoff "$handoff_model" init legalActivationStep \
  legalActivationNotReached 4

expect_counterexample \
  duplicate-signer-weight "${mutants[0]}" init step \
  noConflictingWeightedQcs 2
expect_counterexample \
  unsafe-lock-vote "${mutants[1]}" init step \
  noConflictingOrderFinality 6
expect_counterexample \
  tc-unlocks "${mutants[2]}" init step tcNeverUnlocks 1
expect_counterexample \
  tc-finalizes "${mutants[3]}" init step tcNeverFinalizes 1
expect_counterexample \
  two-chain-finality "${mutants[4]}" init step \
  finalityRequiresThreeChain 2
expect_counterexample \
  single-quorum-handoff "${mutants[5]}" init step \
  activationRequiresDualWeightedQuorum 2
expect_counterexample \
  wrong-activation-anchor "${mutants[6]}" init step \
  activationAnchorIsExact 4

printf 'PoCO AI-native v1 foundation formal candidate gate passed (Quint %s; samples=%s).\n' \
  "$($quint_bin --version)" "$max_samples"
