#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"

package_doc=docs/development/packages/TRNM_G1_R2B_REAL_CORE_ADAPTER_EXECUTION_PACKAGE_V1.md
target_doc=docs/development/packages/TRNM_G1_R2B_NEXT_IMPLEMENTATION_TARGET_V1.md
manifest_path=docs/development/packages/trnm-g1-r2b-manifest-v1.toml
parent_manifest=docs/development/packages/trnm-g1-r2-manifest-v1.toml
source=trillionnium/crates/trnm-poco-node/src/bin/trnm-poco-replay-to-core-coordinator-v1.rs
cargo_manifest=trillionnium/crates/trnm-poco-node/Cargo.toml
workflow=.github/workflows/trnm-replay-to-core-coordinator-v1.yml
truth=config/consensus-mainline.json

for required in "$package_doc" "$target_doc" "$manifest_path" "$parent_manifest" \
  "$source" "$cargo_manifest" "$workflow" "$truth"; do
  [[ -f "$required" && ! -L "$required" ]] || {
    printf 'G1-R2B contract truth gate failed: missing regular file: %s\n' "$required" >&2
    exit 1
  }
done

python3 - "$package_doc" "$target_doc" "$manifest_path" "$parent_manifest" \
  "$source" "$cargo_manifest" "$workflow" "$truth" <<'PY'
from __future__ import annotations

import json
import pathlib
import re
import sys
import tomllib

package_path, target_path, manifest_path, parent_manifest_path, source_path, cargo_path, workflow_path, truth_path = map(pathlib.Path, sys.argv[1:])

def fail(message: str) -> None:
    raise SystemExit(f"G1-R2B contract truth gate failed: {message}")

try:
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    parent = tomllib.loads(parent_manifest_path.read_text(encoding="utf-8"))
except Exception as error:  # pragma: no cover - parser diagnostics
    fail(f"manifest TOML is invalid: {error}")

expected = {
    "manifest_version": 1,
    "package_id": "trnm-g1-r2b-real-core-adapter-v1",
    "classification": "candidate-non-normative-planned",
    "parent_plan_id": "trnm-ai-native-blockchain-development-plan-v1",
    "parent_package_id": "trnm-g1-r2-replay-to-core-durable-ack-v1",
    "canonical_ref": "refs/heads/docs/chain-poco-bft-mainline-20260825",
    "implementation_ref": "refs/heads/feature/chain-g1-r2b-real-core-adapter-20260828",
    "implementation_commit": "UNBOUND_UNTIL_NORMALIZED_SOURCE_COMMIT",
    "source_commit": "UNBOUND_UNTIL_NORMALIZED_SOURCE_COMMIT",
    "source_tree": "UNBOUND_UNTIL_NORMALIZED_SOURCE_TREE",
    "status": "r2-b-contract-only",
    "scope": "candidate-process-boundary-contract",
    "authority": "sealed-test-or-private-review-only",
    "data_scope": "synthetic-local-only",
    "observed_worktree_probe": "CandidateCoreIngressV1-candidate-and-unbound",
    "production_candidate": False,
    "production_consensus_activation": False,
    "g1_exit": False,
    "g1_r2_exit": False,
}
for key, value in expected.items():
    if manifest.get(key) != value:
        fail(f"manifest {key}={manifest.get(key)!r}, expected {value!r}")
if parent.get("package_id") != "trnm-g1-r2-replay-to-core-durable-ack-v1":
    fail("R2B parent manifest does not identify the R2 package")

capabilities = manifest.get("capabilities", {})
required_true = (
    "exact_replay_request_binding",
    "authenticated_body_resolution_required",
    "real_core_ingress_required",
    "safety_state_persistence_readback_required",
    "whole_node_predecessor_cas_required",
)
for key in required_true:
    if capabilities.get(key) is not True:
        fail(f"capabilities.{key} must remain true")
required_false = (
    "sealed_receipt_constructor_authorized",
    "candidate_probe_source_bound",
    "live_core_adapter",
    "core_ack_generated_by_core",
    "core_ack_atomic_with_core",
    "node_process_integration",
    "process_kill_matrix_complete",
    "whole_node_anti_rollback",
    "independent_review",
    "production_activation",
)
for key in required_false:
    if capabilities.get(key) is not False:
        fail(f"capabilities.{key} must remain false")

fault_cuts = manifest.get("fault_cuts", {})
for key in (
    "before_core_input",
    "core_accepted_before_persistence",
    "persistence_before_readback",
    "readback_before_replay_ack",
    "replay_ack_before_completion",
    "completion_before_response",
):
    if fault_cuts.get(key) is not True:
        fail(f"fault_cuts.{key} must be specified")
if fault_cuts.get("process_sigkill_evidence") is not False:
    fail("process SIGKILL evidence must remain false until real evidence exists")

package = package_path.read_text(encoding="utf-8")
target = target_path.read_text(encoding="utf-8")
source = source_path.read_text(encoding="utf-8")
cargo = cargo_path.read_text(encoding="utf-8")
workflow = workflow_path.read_text(encoding="utf-8")
truth = json.loads(truth_path.read_text(encoding="utf-8"))

required_package = (
    "candidate-only contract",
    "CandidateCoreIngressV1",
    "UNBOUND_UNTIL_NORMALIZED_SOURCE",
    "CoreReplayRequestV1",
    "SafetyStatePersistenceV0",
    "whole-node predecessor checkpoint",
    "R2B-01",
    "R2B-02",
    "R2B-03",
    "R2B-04",
    "R2B-05",
    "R2B-06",
    "contract-only",
    "production_candidate=false",
    "production_consensus_activation=false",
    "live_core_adapter=false",
    "core_ack_generated_by_core=false",
    "core_ack_atomic_with_core=false",
    "node_process_integration=false",
)
for literal in required_package:
    if literal not in package:
        fail(f"R2B package is missing required boundary: {literal}")
for forbidden in (
    "production-ready",
    "G1-R2 exit achieved",
    "G1 exit achieved",
    "core_ack_atomic_with_core=true",
    "production_candidate=true",
    "production_consensus_activation=true",
):
    if forbidden.lower() in package.lower():
        fail(f"R2B package contains forbidden promotion claim: {forbidden}")

for literal in (
    "TRNM_G1_R2B_REAL_CORE_ADAPTER_EXECUTION_PACKAGE_V1.md",
    "trnm-g1-r2b-manifest-v1.toml",
    "check_replay_to_core_r2b_contract_v1.sh",
    "candidate `CandidateCoreIngressV1` probe",
    "production_candidate=false",
    "live_core_adapter=false",
):
    if literal not in target:
        fail(f"R2B target is missing status/link marker: {literal}")

for literal in (
    "REPLAY_TO_CORE_REAL_CORE_INGRESS_CANDIDATE_V1: bool = true",
    "REPLAY_TO_CORE_FAULT_CUT_MATRIX_CANDIDATE_V1: bool = true",
    "REPLAY_TO_CORE_LIVE_CORE_ADAPTER_V1: bool = false",
    "REPLAY_TO_CORE_ACK_GENERATED_BY_CORE_V1: bool = false",
    "REPLAY_TO_CORE_ACK_ATOMIC_WITH_CORE_V1: bool = false",
    "REPLAY_TO_CORE_NODE_PROCESS_INTEGRATION_V1: bool = false",
    "REPLAY_TO_CORE_PRODUCTION_ACTIVATION_V1: bool = false",
):
    if literal not in source:
        fail(f"coordinator source is missing negative truth marker: {literal}")
for forbidden in (
    "pub fn new_after_durable_core",
    "pub(crate) fn new_after_durable_core",
    "REPLAY_TO_CORE_LIVE_CORE_ADAPTER_V1: bool = true",
    "REPLAY_TO_CORE_ACK_GENERATED_BY_CORE_V1: bool = true",
    "REPLAY_TO_CORE_ACK_ATOMIC_WITH_CORE_V1: bool = true",
    "REPLAY_TO_CORE_NODE_PROCESS_INTEGRATION_V1: bool = true",
    "REPLAY_TO_CORE_PRODUCTION_ACTIVATION_V1: bool = true",
):
    if forbidden in source:
        fail(f"coordinator source contains forbidden authority claim: {forbidden}")

if re.search(r"name\s*=\s*\"trnm-poco-replay-to-core-(?:adapter|r2b)", cargo):
    fail("a separate R2B production binary target is not authorized")

for literal in (
    "TRNM_G1_R2B_REAL_CORE_ADAPTER_EXECUTION_PACKAGE_V1.md",
    "trnm-g1-r2b-manifest-v1.toml",
    "scripts/ci/check_replay_to_core_r2b_contract_v1.sh",
    "bash ./scripts/ci/check_replay_to_core_r2b_contract_v1.sh",
):
    if literal not in workflow:
        fail(f"workflow is missing R2B contract hook: {literal}")

if truth.get("stage") != "G1-native-host-incomplete":
    fail(f"machine truth stage changed unexpectedly: {truth.get('stage')!r}")
for key in ("production_candidate", "production_consensus_activation"):
    if truth.get(key) is not False:
        fail(f"machine truth {key} must remain false")

print(
    "G1-R2B contract truth gate: PASS "
    "(contract-only; source binding, real Core process evidence and promotion remain absent)"
)
PY
