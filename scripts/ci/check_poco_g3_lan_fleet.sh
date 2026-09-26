#!/usr/bin/env bash
set -euo pipefail

# This Stage0 contract self-test is deliberately local and read-only. It
# compiles Python into a temporary directory and runs fixture/self-test
# contracts only by default. Explicit --material-builder and --validator-binary
# inputs additionally run native material parity against already-built binaries;
# their prerequisite is the existing locked/offline lab-validator binary build.
# This gate never invokes Cargo or SSH. Strict Clippy, live fleet execution and
# evidence production remain separate gates and are not represented as green.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FLEET="$ROOT/scripts/poco-fleet"
LAB_VALIDATOR="$ROOT/trillionnium/crates/trnm-poco-lab-validator"

umask 077
export PYTHONDONTWRITEBYTECODE=1
export PYTHONNOUSERSITE=1
unset PYTHONHOME PYTHONPATH

fail() {
  printf 'PoCO G3 LAN fleet Stage0 contract self-test gate failed: %s\n' "$*" >&2
  exit 1
}

# Both paths are required together. There is no implicit Cargo build, PATH
# fallback or dummy-binary success when the Python-only gate is selected.
native_material_builder=""
native_validator_binary=""
while (( $# )); do
  case "$1" in
    --material-builder)
      (( $# >= 2 )) || fail "--material-builder requires a path"
      [[ -n "$2" ]] || fail "empty --material-builder"
      [[ -z "$native_material_builder" ]] || fail "duplicate --material-builder"
      native_material_builder="$2"
      shift 2
      ;;
    --validator-binary)
      (( $# >= 2 )) || fail "--validator-binary requires a path"
      [[ -n "$2" ]] || fail "empty --validator-binary"
      [[ -z "$native_validator_binary" ]] || fail "duplicate --validator-binary"
      native_validator_binary="$2"
      shift 2
      ;;
    *) fail "unsupported argument $1" ;;
  esac
done
if [[ -n "$native_material_builder" || -n "$native_validator_binary" ]]; then
  [[ -n "$native_material_builder" && -n "$native_validator_binary" ]] \
    || fail "native material parity requires both prebuilt binary paths"
fi

readonly -a REQUIRED_FILES=(
  "scripts/poco-fleet/inventory.toml"
  "scripts/poco-fleet/assemble_reproducible_build_report.py"
  "scripts/poco-fleet/assemble_reproducible_build_report_test.py"
  "scripts/poco-fleet/assemble_run_bundle_v1.py"
  "scripts/poco-fleet/assemble_run_bundle_v1_test.py"
  "scripts/poco-fleet/assemble_stage0_direct_seven_bundle_v1.py"
  "scripts/poco-fleet/build_reproducible_lab_candidate.py"
  "scripts/poco-fleet/build_reproducible_lab_candidate_test.py"
  "scripts/poco-fleet/build_reproducible_lab_candidate_v2.py"
  "scripts/poco-fleet/build_reproducible_lab_candidate_v2_test.py"
  "scripts/poco-fleet/source_candidate_doc_alias_v1.py"
  "scripts/poco-fleet/source_candidate_doc_alias_v1_test.py"
  "scripts/poco-fleet/native_client_campaign_v1.py"
  "scripts/poco-fleet/native_client_campaign_v1_test.py"
  "scripts/poco-fleet/check_native_client_campaign_v1.py"
  "scripts/poco-fleet/check_native_client_material_test.py"
  "scripts/poco-fleet/check_baseline.py"
  "scripts/poco-fleet/check_baseline_test.py"
  "scripts/poco-fleet/check_raw_run_artifacts.py"
  "scripts/poco-fleet/check_run_bundle.py"
  "scripts/poco-fleet/check_run_bundle_test.py"
  "scripts/poco-fleet/check_run_evidence.py"
  "scripts/poco-fleet/check_run_evidence_test.py"
  "scripts/poco-fleet/check_run_material.py"
  "scripts/poco-fleet/check_run_material_test.py"
  "scripts/poco-fleet/check_run_readiness_evidence.py"
  "scripts/poco-fleet/check_run_readiness_evidence_test.py"
  "scripts/poco-fleet/check_signed_runtime_evidence.py"
  "scripts/poco-fleet/check_signed_runtime_evidence_test.py"
  "scripts/poco-fleet/check_source_candidate.py"
  "scripts/poco-fleet/check_source_candidate_test.py"
  "scripts/poco-fleet/check_stage0_observation_status.py"
  "scripts/poco-fleet/check_stage0_observation_status_test.py"
  "scripts/poco-fleet/check_stage0_direct_seven_bundle_v1.py"
  "scripts/poco-fleet/check_stage0_reproducible_build_evidence.py"
  "scripts/poco-fleet/check_stage0_reproducible_build_evidence_test.py"
  "scripts/poco-fleet/check_topology.py"
  "scripts/poco-fleet/check_validator_deployments.py"
  "scripts/poco-fleet/check_validator_deployments_test.py"
  "scripts/poco-fleet/collect_no_fault_run_bundle_v1.py"
  "scripts/poco-fleet/collect_no_fault_run_bundle_v1_test.py"
  "scripts/poco-fleet/evidence_bundle_profiles_v1.py"
  "scripts/poco-fleet/fault_evidence_semantics_v1.py"
  "scripts/poco-fleet/fault_evidence_semantics_v1_test.py"
  "scripts/poco-fleet/mesh_resource_preflight_v1.py"
  "scripts/poco-fleet/mesh_resource_preflight_v1_test.py"
  "scripts/poco-fleet/plan_topology.py"
  "scripts/poco-fleet/planned_p2p_connectivity_admission_v1.py"
  "scripts/poco-fleet/planned_p2p_connectivity_admission_v1_test.py"
  "scripts/poco-fleet/poco_consensus_contract.py"
  "scripts/poco-fleet/poco_consensus_contract_test.py"
  "scripts/poco-fleet/prepare_run_material.py"
  "scripts/poco-fleet/prepare_source_candidate.py"
  "scripts/poco-fleet/prepare_validator_deployments.py"
  "scripts/poco-fleet/probe_fleet.py"
  "scripts/poco-fleet/probe_run_readiness.py"
  "scripts/poco-fleet/run_consensus_fleet.py"
  "scripts/poco-fleet/run_consensus_fleet_test.py"
  "scripts/poco-fleet/run_fault_restart_fleet_v1.py"
  "scripts/poco-fleet/run_fault_restart_fleet_v1_test.py"
  "scripts/poco-fleet/run_fault_selection_v1_test.py"
  "scripts/poco-fleet/run_fault_restart_handoff_v1_test.py"
  "scripts/poco-fleet/run_isolated_startup_rejection_v1.py"
  "scripts/poco-fleet/run_isolated_startup_rejection_v1_test.py"
  "scripts/poco-fleet/run_network_smoke_fleet.py"
  "scripts/poco-fleet/run_network_smoke_fleet_test.py"
  "scripts/poco-fleet/run_local_fault_performance_campaign_v1.py"
  "scripts/poco-fleet/run_local_fault_performance_campaign_v1_test.py"
  "scripts/poco-fleet/sealed_artifact_transport_v1.py"
  "scripts/poco-fleet/sealed_artifact_transport_v1_test.py"
  "scripts/poco-fleet/stage0_direct_seven_bundle_v1_test.py"
  "scripts/poco-fleet/validate_inventory.py"
  "trillionnium/crates/trnm-poco-lab-validator/Cargo.toml"
  "trillionnium/crates/trnm-poco-lab-validator/src/bin/trnm-poco-lab-material-builder.rs"
  "trillionnium/crates/trnm-poco-lab-validator/src/consensus_mesh.rs"
  "trillionnium/crates/trnm-poco-lab-validator/src/consensus_runtime.rs"
  "trillionnium/crates/trnm-poco-lab-validator/src/main.rs"
  "trillionnium/crates/trnm-poco-lab-validator/src/startup_rejection.rs"
)

readonly -a PYTHON_FILES=(
  "scripts/poco-fleet/assemble_reproducible_build_report.py"
  "scripts/poco-fleet/assemble_reproducible_build_report_test.py"
  "scripts/poco-fleet/assemble_run_bundle_v1.py"
  "scripts/poco-fleet/assemble_run_bundle_v1_test.py"
  "scripts/poco-fleet/assemble_stage0_direct_seven_bundle_v1.py"
  "scripts/poco-fleet/build_reproducible_lab_candidate.py"
  "scripts/poco-fleet/build_reproducible_lab_candidate_test.py"
  "scripts/poco-fleet/build_reproducible_lab_candidate_v2.py"
  "scripts/poco-fleet/build_reproducible_lab_candidate_v2_test.py"
  "scripts/poco-fleet/source_candidate_doc_alias_v1.py"
  "scripts/poco-fleet/source_candidate_doc_alias_v1_test.py"
  "scripts/poco-fleet/native_client_campaign_v1.py"
  "scripts/poco-fleet/native_client_campaign_v1_test.py"
  "scripts/poco-fleet/check_native_client_campaign_v1.py"
  "scripts/poco-fleet/check_native_client_material_test.py"
  "scripts/poco-fleet/check_baseline.py"
  "scripts/poco-fleet/check_baseline_test.py"
  "scripts/poco-fleet/check_raw_run_artifacts.py"
  "scripts/poco-fleet/check_run_bundle.py"
  "scripts/poco-fleet/check_run_bundle_test.py"
  "scripts/poco-fleet/check_run_evidence.py"
  "scripts/poco-fleet/check_run_evidence_test.py"
  "scripts/poco-fleet/check_run_material.py"
  "scripts/poco-fleet/check_run_material_test.py"
  "scripts/poco-fleet/check_run_readiness_evidence.py"
  "scripts/poco-fleet/check_run_readiness_evidence_test.py"
  "scripts/poco-fleet/check_signed_runtime_evidence.py"
  "scripts/poco-fleet/check_signed_runtime_evidence_test.py"
  "scripts/poco-fleet/check_source_candidate.py"
  "scripts/poco-fleet/check_source_candidate_test.py"
  "scripts/poco-fleet/check_stage0_observation_status.py"
  "scripts/poco-fleet/check_stage0_observation_status_test.py"
  "scripts/poco-fleet/check_stage0_direct_seven_bundle_v1.py"
  "scripts/poco-fleet/check_stage0_reproducible_build_evidence.py"
  "scripts/poco-fleet/check_stage0_reproducible_build_evidence_test.py"
  "scripts/poco-fleet/check_topology.py"
  "scripts/poco-fleet/check_validator_deployments.py"
  "scripts/poco-fleet/check_validator_deployments_test.py"
  "scripts/poco-fleet/collect_no_fault_run_bundle_v1.py"
  "scripts/poco-fleet/collect_no_fault_run_bundle_v1_test.py"
  "scripts/poco-fleet/evidence_bundle_profiles_v1.py"
  "scripts/poco-fleet/fault_evidence_semantics_v1.py"
  "scripts/poco-fleet/fault_evidence_semantics_v1_test.py"
  "scripts/poco-fleet/mesh_resource_preflight_v1.py"
  "scripts/poco-fleet/mesh_resource_preflight_v1_test.py"
  "scripts/poco-fleet/plan_topology.py"
  "scripts/poco-fleet/planned_p2p_connectivity_admission_v1.py"
  "scripts/poco-fleet/planned_p2p_connectivity_admission_v1_test.py"
  "scripts/poco-fleet/poco_consensus_contract.py"
  "scripts/poco-fleet/poco_consensus_contract_test.py"
  "scripts/poco-fleet/prepare_run_material.py"
  "scripts/poco-fleet/prepare_source_candidate.py"
  "scripts/poco-fleet/prepare_validator_deployments.py"
  "scripts/poco-fleet/probe_fleet.py"
  "scripts/poco-fleet/probe_run_readiness.py"
  "scripts/poco-fleet/run_consensus_fleet.py"
  "scripts/poco-fleet/run_consensus_fleet_test.py"
  "scripts/poco-fleet/run_fault_restart_fleet_v1.py"
  "scripts/poco-fleet/run_fault_restart_fleet_v1_test.py"
  "scripts/poco-fleet/run_fault_selection_v1_test.py"
  "scripts/poco-fleet/run_fault_restart_handoff_v1_test.py"
  "scripts/poco-fleet/run_isolated_startup_rejection_v1.py"
  "scripts/poco-fleet/run_isolated_startup_rejection_v1_test.py"
  "scripts/poco-fleet/run_network_smoke_fleet.py"
  "scripts/poco-fleet/run_network_smoke_fleet_test.py"
  "scripts/poco-fleet/run_local_fault_performance_campaign_v1.py"
  "scripts/poco-fleet/run_local_fault_performance_campaign_v1_test.py"
  "scripts/poco-fleet/sealed_artifact_transport_v1.py"
  "scripts/poco-fleet/sealed_artifact_transport_v1_test.py"
  "scripts/poco-fleet/stage0_direct_seven_bundle_v1_test.py"
  "scripts/poco-fleet/validate_inventory.py"
)

readonly -a NO_CARGO_SELF_TESTS=(
  "scripts/poco-fleet/poco_consensus_contract_test.py"
  "scripts/poco-fleet/check_baseline_test.py"
  "scripts/poco-fleet/check_run_readiness_evidence_test.py"
  "scripts/poco-fleet/check_source_candidate_test.py"
  "scripts/poco-fleet/build_reproducible_lab_candidate_test.py"
  "scripts/poco-fleet/build_reproducible_lab_candidate_v2_test.py"
  "scripts/poco-fleet/check_stage0_observation_status_test.py"
  "scripts/poco-fleet/check_stage0_reproducible_build_evidence_test.py"
  "scripts/poco-fleet/assemble_reproducible_build_report_test.py"
  "scripts/poco-fleet/assemble_run_bundle_v1_test.py"
  "scripts/poco-fleet/check_run_material_test.py"
  "scripts/poco-fleet/run_network_smoke_fleet_test.py"
  "scripts/poco-fleet/run_local_fault_performance_campaign_v1_test.py"
  "scripts/poco-fleet/mesh_resource_preflight_v1_test.py"
  "scripts/poco-fleet/run_consensus_fleet_test.py"
  "scripts/poco-fleet/sealed_artifact_transport_v1_test.py"
  "scripts/poco-fleet/fault_evidence_semantics_v1_test.py"
  "scripts/poco-fleet/run_isolated_startup_rejection_v1_test.py"
  "scripts/poco-fleet/run_fault_restart_fleet_v1_test.py"
  "scripts/poco-fleet/run_fault_selection_v1_test.py"
  "scripts/poco-fleet/run_fault_restart_handoff_v1_test.py"
  "scripts/poco-fleet/check_run_evidence_test.py"
  "scripts/poco-fleet/check_run_bundle_test.py"
  "scripts/poco-fleet/check_signed_runtime_evidence_test.py"
  "scripts/poco-fleet/collect_no_fault_run_bundle_v1_test.py"
  "scripts/poco-fleet/planned_p2p_connectivity_admission_v1_test.py"
  "scripts/poco-fleet/stage0_direct_seven_bundle_v1_test.py"
  "scripts/poco-fleet/source_candidate_doc_alias_v1_test.py"
  "scripts/poco-fleet/native_client_campaign_v1_test.py"
)

readonly -a NO_CARGO_STABLE_MARKERS=(
  'poco_consensus_contract_self_test=passed'
  'poco_g3_current_fleet_observation_self_test=passed'
  'poco_g3_current_run_readiness_self_test=passed'
  'poco_g3_source_candidate_test=passed'
  'poco_g3_reproducible_builder_boundary_test=passed'
  'poco_g3_reproducible_builder_v2_boundary_test=passed'
  'poco_g3_stage0_observation_status_test=passed'
  'poco_g3_stage0_reproducible_build_evidence_test=passed'
  'poco_g3_reproducible_build_report_test=passed'
  'poco_g3_run_bundle_assembler_v1_test=passed'
  'poco_g3_run_material_self_test=passed'
  'poco_g3_network_smoke_fleet_test=passed'
  'trnm_local_fault_performance_campaign_v1_test=passed'
  'poco_g3_mesh_resource_preflight_v1_test=passed'
  'poco_g3_consensus_fleet_test=passed'
  'sealed_artifact_transport_v1_test=passed'
  'poco_g3_fault_evidence_semantics_v1_test=passed'
  'isolated startup rejection runner:'
  'poco_g3_fault_restart_fleet_v1_test=passed'
  'poco_fault_selection_v1_test=passed'
  'poco_fault_restart_handoff_v1_test=passed'
  'poco_g3_run_evidence_self_test=passed'
  'poco_g3_run_bundle_self_test=passed'
  'poco_g3_signed_runtime_evidence_tests=passed'
  'poco_g3_no_fault_bundle_collector_v1_test=passed'
  'planned_p2p_connectivity_admission_v1_test=passed'
  'poco_g3_stage0_direct_seven_bundle_v1_test=passed'
  'source_doc_alias_tests=passed'
  'native_campaign_structural_tests=passed'
)

for relative in "${REQUIRED_FILES[@]}"; do
  [[ -f "$ROOT/$relative" ]] || fail "missing required file $relative"
done

compile_paths=()
for relative in "${PYTHON_FILES[@]}"; do
  compile_paths+=("$ROOT/$relative")
done
python3 - "${compile_paths[@]}" <<'PY'
import pathlib
import py_compile
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="poco-g3-stage0-pycompile-") as temporary:
    destination = pathlib.Path(temporary)
    for index, source in enumerate(sys.argv[1:]):
        py_compile.compile(
            source,
            cfile=str(destination / f"stage0-{index}.pyc"),
            doraise=True,
        )
PY

# This static contract check intentionally reads no historical evidence or
# documentation.  It binds the current source/build chain and false truth
# boundaries without producing an archive, build report, or run artifact.
python3 - "$ROOT" <<'PY'
import importlib.util
import pathlib
import re
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
fleet = root / "scripts/poco-fleet"
lab = root / "trillionnium/crates/trnm-poco-lab-validator"


def source(relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8")


def require_all(relative: str, literals: tuple[str, ...]) -> None:
    text = source(relative)
    missing = [literal for literal in literals if literal not in text]
    if missing:
        raise SystemExit(f"{relative} lost Stage0 literal {missing[0]!r}")


gate_source = source("scripts/ci/check_poco_g3_lan_fleet.sh")
for forbidden in ("docs/" + "evidence/", "2026-" + "08-13.json"):
    if forbidden in gate_source:
        raise SystemExit(
            f"Stage0 contract self-test gate regained forbidden historical input {forbidden!r}"
        )
if re.search(r"(?m)^[ \t]*(?:cargo|ssh)(?:[ \t]|$)", gate_source):
    raise SystemExit("Stage0 contract self-test gate must not execute Cargo or SSH")

require_all(
    "scripts/poco-fleet/prepare_source_candidate.py",
    (
        "STRICT_SCHEMA_VERSION = 2",
        'parser.add_argument("--require-clean", action="store_true")',
        '"profile": "clean-commit-v1"',
        '"HEAD^{commit}"',
        '"HEAD^{tree}"',
        '"git_blob_oid"',
        '"git_commit_payload_base64"',
        'CARGO_LOCK_PATH = "trillionnium/Cargo.lock"',
    ),
)
require_all(
    "scripts/poco-fleet/check_source_candidate.py",
    (
        "def validate(path: pathlib.Path, *, require_clean: bool = False)",
        "strict source candidate must use clean-commit-v1",
        'record_keys = {"path", "sha256", "bytes", "mode", "git_blob_oid"}',
        'git_object_oid(object_format, "commit", commit_payload)',
        "compute_git_tree_oid(records, object_format)",
        "cargo_lock binding differs from its exact file record",
        'parser.add_argument("--require-clean", action="store_true")',
    ),
)

strict_report_fields = (
    '"schema_version": 3',
    '"source_candidate_profile"',
    '"source_base_commit"',
    '"source_git_object_format"',
    '"source_git_tree_oid"',
    '"source_git_status_sha256"',
    '"cargo_lock_path"',
    '"cargo_lock_sha256"',
    '"cargo_lock_bytes"',
)
require_all(
    "scripts/poco-fleet/build_reproducible_lab_candidate.py",
    (
        '[sys.executable, str(CHECK), str(candidate), "--require-clean"]',
        'value.get("source_profile") != "clean-commit-v1"',
        "verify_cargo_lock(left_source, candidate_report)",
        *strict_report_fields,
    ),
)
require_all(
    "scripts/poco-fleet/assemble_reproducible_build_report.py",
    (
        "check_source_candidate.validate(path, require_clean=True)",
        'report.get("source_profile") != "clean-commit-v1"',
        'report.get("schema_version") != 3',
        *strict_report_fields,
    ),
)
require_all(
    "scripts/poco-fleet/check_stage0_direct_seven_bundle_v1.py",
    (
        'PROFILE = "poco-g3-stage0-direct-seven-observation-bundle-v1"',
        '"validator_run_7_completed_observed": True',
        '"runner_legacy_validator_run_completed": False',
        "validate_raw_replay_archives(",
        "def bind_pinned_bundle_root(",
        "held bundle directory inventory is not the exact required closure",
        "manifest_bytes != canonical_manifest",
        "signed_evidence.verify_ed25519(",
        "REPLAY_TERMINAL_SIGNATURE_DOMAIN",
        '"stage0_deep_reverification_bundle_available": True',
        '"validator_run_7_completed": True',
        '"fault_matrix_completed": False',
        '"performance_evidence": False',
        '"g3_lan_multihost_evidence": False',
        '"geo_wan_evidence": False',
        '"production_activation": False',
        '"production_candidate": False',
    ),
)
require_all(
    "scripts/poco-fleet/assemble_stage0_direct_seven_bundle_v1.py",
    (
        "lock = checker.cargo_lock_bytes(candidate_source)",
        "checker.validate_source_coordinator_inventory(",
        "output_tree = OutputTree.create(output)",
        "planned bundle crosses its X230 file-count or aggregate-byte envelope",
        "validate_output_capacity(output, planned_bytes)",
        "private_keys_bundled=false runner_truth_bits_changed=false",
        "proposal_qc_finality_semantics_independently_decoded=false",
        "runner_generic_512m_compatibility_claim=false",
        "output_tree.verify()",
        "output_tree.publish()",
        "renameat2",
        "RENAME_NOREPLACE",
        "Failure handling is deliberately close-only",
        "checker.bind_pinned_bundle_root(self.descriptor, manifest)",
        "cryptographic_content_equivalence_binding=true",
        "checker_itself_fd_rooted=false",
    ),
)

with (fleet / "inventory.toml").open("rb") as handle:
    inventory = tomllib.load(handle)
if inventory.get("network_scope") != "single-lan":
    raise SystemExit("fleet inventory must remain single-lan")
if inventory.get("geo_wan_evidence") is not False:
    raise SystemExit("fleet inventory must keep geo_wan_evidence=false")

with (lab / "Cargo.toml").open("rb") as handle:
    metadata = tomllib.load(handle)["package"]["metadata"]["trnm"]
false_metadata = (
    "authenticated_fresh_session_multihost_observed",
    "production_candidate",
    "production_consensus_activation",
    "geo_wan_evidence",
    "g3_evidence_complete",
    "validator_runtime_started",
)
for field in false_metadata:
    if metadata.get(field) is not False:
        raise SystemExit(f"lab-validator metadata must keep {field}=false")

for relative in (
    "scripts/poco-fleet/run_network_smoke_fleet.py",
    "scripts/poco-fleet/run_consensus_fleet.py",
):
    require_all(
        relative,
        tuple(
            f'"{field}": False'
            for field in (
                "validator_run_completed",
                "fault_matrix_completed",
                "performance_evidence",
                "geo_wan_evidence",
                "production_activation",
            )
        ),
    )

inert = (
    "continuous consensus process2 reached the durable zero-delta caught-up cut; "
    "RecoveryReady, RecoveryStart, pacemaker, mesh, and ordinary ingress remain "
    "unavailable"
)
require_all(
    "trillionnium/crates/trnm-poco-lab-validator/src/consensus_runtime.rs",
    (inert,),
)
spec = importlib.util.spec_from_file_location(
    "stage0_fault_restart_fleet", fleet / "run_fault_restart_fleet_v1.py"
)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load fault/restart runner for Stage0 boundary check")
sys.path.insert(0, str(fleet))
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
if module.PROCESS2_INERT_BOUNDARY_MESSAGE_V1 != inert:
    raise SystemExit("fault/restart supervisor lost the exact process2 inert boundary")
PY

# Each Python self-test owns its semantic assertions and exits nonzero on failure.
# This shell checks only one stable summary marker; changing diagnostic counts,
# adding truthful fields, or emitting nested passed summaries must not create a
# second handwritten acceptance contract.
run_exact_python() {
  local relative="$1"
  local marker="$2"
  shift 2
  local output
  if ! output="$(python3 "$ROOT/$relative" "$@")"; then
    fail "self-test failed: $relative"
  fi
  [[ -n "$output" ]] || fail "self-test emitted no summary: $relative"
  local matched=0
  local line
  while IFS= read -r line; do
    [[ -n "$line" ]] || fail "self-test emitted an empty summary line: $relative"
    if [[ "$line" == "$marker" || "$line" == "$marker "* ]]; then
      matched=$((matched + 1))
    fi
  done <<< "$output"
  [[ "$matched" == 1 ]] \
    || fail "self-test stable marker is missing or duplicated: $relative"
  printf '%s\n' "$output"
}

run_exact_python \
  "scripts/poco-fleet/validate_inventory.py" \
  'poco_g3_lan_inventory=passed' \
  "$FLEET/inventory.toml"
run_exact_python \
  "scripts/poco-fleet/check_topology.py" \
  'poco_g3_topology_planner=passed'

[[ "${#NO_CARGO_SELF_TESTS[@]}" == "${#NO_CARGO_STABLE_MARKERS[@]}" ]] \
  || fail "self-test path and stable-marker tables differ in length"
for index in "${!NO_CARGO_SELF_TESTS[@]}"; do
  run_exact_python \
    "${NO_CARGO_SELF_TESTS[$index]}" \
    "${NO_CARGO_STABLE_MARKERS[$index]}"
done

native_material_parity="not_run_requires_prebuilt_binaries"
if [[ -n "$native_material_builder" ]]; then
  run_exact_python \
    "scripts/poco-fleet/check_native_client_material_test.py" \
    'native_client_material=passed' \
    --material-builder "$native_material_builder" \
    --validator-binary "$native_validator_binary"
  native_material_parity="passed_prebuilt_binaries"
fi
printf 'native_material_parity=%s cargo_build_invoked=false live_campaign_invoked=false\n' "$native_material_parity"

printf '%s\n' \
  "poco_g3_lan_fleet_contract_self_test_gate=passed stage0_observation_complete=false observation_status_evaluated=false required_files=${#REQUIRED_FILES[@]} python_compile=${#PYTHON_FILES[@]} no_cargo_self_tests=${#NO_CARGO_SELF_TESTS[@]} readiness=current_fixture_self_tests_only strict_candidate=clean-commit-v1 strict_builder_schema=3 strict_aggregate_schema=3 commit_tree_blob_cargo_lock_bound=true cargo_executed=false ssh_executed=false evidence_generated=false validator_run=false multihost_observed=false fault_matrix_completed=false performance_evidence=false geo_wan=false production_activation=false strict_clippy_gate_closed=false dormant_clippy_warning_baseline=31_normal,13_test"
