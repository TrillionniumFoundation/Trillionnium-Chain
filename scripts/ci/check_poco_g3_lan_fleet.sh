#!/usr/bin/env bash
set -euo pipefail

# This Stage0 contract self-test is deliberately local and read-only. It
# compiles Python into a temporary directory and runs fixture/self-test
# contracts only. Cargo/Rust integration, strict Clippy, SSH fleet execution,
# and evidence production are later gates and are not represented as green
# here.

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
  "scripts/poco-fleet/run_fault_restart_handoff_v1_test.py"
  "scripts/poco-fleet/run_isolated_startup_rejection_v1.py"
  "scripts/poco-fleet/run_isolated_startup_rejection_v1_test.py"
  "scripts/poco-fleet/run_network_smoke_fleet.py"
  "scripts/poco-fleet/run_network_smoke_fleet_test.py"
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
  "scripts/poco-fleet/run_fault_restart_handoff_v1_test.py"
  "scripts/poco-fleet/run_isolated_startup_rejection_v1.py"
  "scripts/poco-fleet/run_isolated_startup_rejection_v1_test.py"
  "scripts/poco-fleet/run_network_smoke_fleet.py"
  "scripts/poco-fleet/run_network_smoke_fleet_test.py"
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
  "scripts/poco-fleet/mesh_resource_preflight_v1_test.py"
  "scripts/poco-fleet/run_consensus_fleet_test.py"
  "scripts/poco-fleet/sealed_artifact_transport_v1_test.py"
  "scripts/poco-fleet/fault_evidence_semantics_v1_test.py"
  "scripts/poco-fleet/run_isolated_startup_rejection_v1_test.py"
  "scripts/poco-fleet/run_fault_restart_fleet_v1_test.py"
  "scripts/poco-fleet/run_fault_restart_handoff_v1_test.py"
  "scripts/poco-fleet/check_run_evidence_test.py"
  "scripts/poco-fleet/check_run_bundle_test.py"
  "scripts/poco-fleet/check_signed_runtime_evidence_test.py"
  "scripts/poco-fleet/collect_no_fault_run_bundle_v1_test.py"
  "scripts/poco-fleet/stage0_direct_seven_bundle_v1_test.py"
)

readonly -a NO_CARGO_EXPECTED_SUMMARIES=(
  'poco_consensus_contract_self_test=passed vectors=2 mutations=4 deployment_inputs_absent=true'
  'poco_g3_current_fleet_observation_self_test=passed producer_positive=1 bounded_memory_positives=3 negatives=25 inventory_alignment_negatives=2 linux_memtotal_tolerance_bytes=32768 linux_page_bytes=4096 macos_memory_exact=true historical_gate=false build=false validator_run=false multihost_run=false geo_wan=false production=false'
  'poco_g3_current_run_readiness_self_test=passed producer_positive=1 negatives=23 historical_gate=false build=false validator_run=false multihost_run=false geo_wan=false production=false'
  'poco_g3_source_candidate_test=passed strict_profile=clean-commit-v1 fresh_clone_byte_identity=true git_tree_blob_binding=true commit_tree_binding=true cargo_lock_bound=true dirty_worktrees_rejected=true legacy_v1_audit_only=true actual_build_executed=false production_activation=false geo_wan=false'
  'poco_g3_reproducible_builder_boundary_test=passed ambient_overrides=12 git_authority_overrides=5 all_cargo_configs_rejected=true closed_build_environment=true cargo_home_and_environment_paths_remapped=true candidate_inode_pinned=true strict_checker_required=true cargo_lock_verified_before_build=true schema3_provenance=true binary_inode_pinned=true output_inode_pinned=true unowned_replacement_preserved=true actual_build_executed=false production_activation=false geo_wan=false'
  'poco_g3_reproducible_builder_v2_boundary_test=passed v1_evidence_bytes_unchanged=true rust_src_canonical_remap=true absent_rust_src_compatible=true malformed_and_duplicate_commit=fail-closed relative_sysroot=fail-closed symlink_rust_src=fail-closed unexpected_stderr=fail-closed actual_build_executed=false production_activation=false geo_wan=false'
  'poco_g3_stage0_observation_status_test=passed positives=2 negatives=7 structured_incomplete=true require_complete_fail_closed=true contract_self_tests_not_observations=true production_activation_blocked=true report_hash_bound=true cross_time_control_bound=true rust_src_drift_not_reproducible=true committed_v2_remap_control=true committed_clean_tool_boundary_fail_closed=true initial_cache_miss_preserved=true'
  'poco_g3_stage0_reproducible_build_evidence_test=passed positives=3 negatives=51 shallow_binary_bytes_rehashed=false deep_binary_bytes_rehashed=true operator_recorded_execution=true cryptographic_execution_attestation=false duplicate_json=fail-closed unchecked_pyc=ignored unsafe_paths=fail-closed symlinks=fail-closed actual_build_executed=false production_activation=false geo_wan=false'
  'poco_g3_reproducible_build_report_test=passed strict_candidate=true schema3_provenance=true both_architectures_bound=true legacy_candidate_rejected=true schema2_local_rejected=true validator_binary_bytes_rehashed=true material_builder_bytes_rehashed=true input_inode_pinned=true output_inode_pinned=true unique_json=true actual_build_executed=false production_activation=false geo_wan=false'
  'poco_g3_run_bundle_assembler_v1_test=passed positives=13 negatives=14 no_fault_active_assembly=true mixed_plan_only=true mixed_active_assembly=fail-closed no_partial_output=true creates_runtime_evidence=false g3_complete=false geo_wan=false production_activation=false'
  'poco_g3_run_material_self_test=passed positives=3 negatives=36 validator_hosts=5 mac_observer=true ephemeral_role_keys=three pop=true public_workload=true ordinary_start_height=4 ordinal_height_mapping=true content_addressed=true application_private_keys=false builder_inode_pinned=true builder_path_substitution_rejected=true material_builder_validator_binary_distinct=true same_binary_fallback_rejected=true material_author_hash_bound=true material_author_runtime_deployed=false run_root_symlink_rejected=true generator_output_symlink_rejected=true public_bootstrap_bundle=true bootstrap_runtime_closed=false role_reopen=true production_activation=false geo_wan=false'
  'poco_g3_network_smoke_fleet_test=passed positives=6 negatives=7 unique_json=true safe_remote_paths=true input_symlinks_rejected=true file_backed_process_io=true partial_cleanup=true local_stage_directories=true remote_binary_hash=true observer_stage_cleanup_registered=true validator_run_completed=false g3_complete=false geo_wan=false'
  'poco_g3_mesh_resource_preflight_v1_test=passed positives=18 negatives=11 topology=100 per_process_rlimit=distinct host_file_capacity=system-wide uid_threads=bounded system_threads=bounded rss=bounded coordinator_capture_fds=per-process-bounded inherited_rlimit=true pre_effect_runners=consensus,fault ulimit_elevation=false validator_run=false g3_complete=false'
  'poco_g3_consensus_fleet_test=passed positives=24 negatives=44 parallel_process_contract=true signed_journal_required=true fleet_start_certificate_required=true signed_report_required=true signed_metrics_required=true signed_final_state_required=true macos_independent_verifier_required=true sealed_replay_archive_export_required=true macos_replay_archive_verifier_required=true fault_matrix_completed=false performance_evidence=false g3_complete=false geo_wan=false production_activation=false'
  'sealed_artifact_transport_v1_test=passed positives=5 negatives=13 nofollow=true o_excl=true double_hash=true fixed_frames=true observer_receipt=true source_mutation_fail_closed=true runtime_evidence_observed=false g3_complete=false'
  'poco_g3_fault_evidence_semantics_v1_test=passed positives=25 negatives=5 connectivity_primary_signed=3 restart_catchup=distinct negative_startup_isolated=2 bounded_delay_degraded=required epoch_handoff_signed=required active_campaign=fail-closed active_bundle_assembly=fail-closed g3_complete=false'
  'isolated startup rejection runner: positives=3 negatives=5'
  'poco_g3_fault_restart_fleet_v1_test=passed positives=36 negatives=19 fault_order=fixed-8 restart=exactly-1 runtime_control=exact mixed_fault_authority=exact active_campaign=fail-closed driver_not_evidence=true fault_driver_pinned=true safe_remote_paths=true file_backed_io=true plan_only_no_effect=true reverse_failure_cleanup=true fleet_start_certificate_required=true signed_journal_report_metrics_final_state_required=true fault_matrix_completed=false g3_complete=false geo_wan=false production_activation=false'
  'poco_fault_restart_handoff_v1_test=passed target_only=true exit75_exact=true exit75_ssh_preserved=true schema2_exact=true p1_locator_digest_unlink=true peer_liveness=true single_p2_launch=true normal_artifacts_absent=true truth_bits_unchanged=true'
  'poco_g3_run_evidence_self_test=passed positives=3 negatives=33 topologies=7,31,100 geo_wan=false production_activation=false'
  'poco_g3_run_bundle_self_test=passed positives=3 negatives=58 topologies=7,31,100 content_addressed=true raw_summary_derived=true unique_json_keys=true exact_validator_set_hash=true ordered_recovery_state_machines=true'
  'poco_g3_signed_runtime_evidence_tests=passed positives=1 negatives=27 unsigned_observation_authority=false g3_complete=false'
  'poco_g3_no_fault_bundle_collector_v1_test=passed positive_fixture_only=true production_active=blocked plan_only=no_outputs signed_observer_profile=plan-only external_load_profile=plan-only independent_anchor=required active_bounds=exact prestart_schema=exact real_public_inventory=exact symlink_ancestor=blocked input_overlap=blocked missing_pid=blocked external_window=blocked qc_n=blocked invalid_signature_control=blocked nonempty_workload=blocked mac_signature_fact=blocked validator_signature=blocked missing_artifact=blocked replay_export=required replay_observer=required replay_hash_join=exact truth_bits_changed=false fault_gate_released=false'
  'poco_g3_stage0_direct_seven_bundle_v1_test=passed cargo_executed=false fixture_only=true deep_candidate=true cargo_lock_member=true dual_arch_binaries=4 symlink=blocked duplicate_json=blocked trailing=blocked toctou_pinned=true manifest_complete=true roles_unique=true failure=blocked cleanup=blocked observer_set=7 replay_sets=7 raw_replay_substitution=blocked raw_replay_hash_chain=blocked terminal_seal_signature=verified terminal_seal_signature_mutation=blocked terminal_agreement=exact runner_validator_run_completed=false stage0_direct_seven_observed=scoped validator_run_7_completed_observed=true fault_matrix=false performance=false g3_lan=false geo_wan=false production=false'
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
        "checker.cargo_lock_bytes(output / \"candidate/source.tar\")",
        "private_keys_bundled=false runner_truth_bits_changed=false",
        "checker.validate(output, emit=False)",
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
    "continuous consensus RestartCut/RestartPark/RestartParkedAck-joined "
    "process2 is inert; authenticated start-catchup, RecoveryReady, and "
    "RecoveryStart remain unavailable"
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

run_exact_python() {
  local relative="$1"
  local expected="$2"
  shift 2
  local output
  if ! output="$(python3 "$ROOT/$relative" "$@")"; then
    fail "self-test failed: $relative"
  fi
  [[ "$output" == "$expected" ]] \
    || fail "self-test summary differs from the exact contract: $relative"
  printf '%s\n' "$output"
}

run_exact_python \
  "scripts/poco-fleet/validate_inventory.py" \
  'poco_g3_lan_inventory=passed hosts=6 topology=7,31,100 validator_hosts=5 observer_hosts=1 observer_role=load-generator,evidence-collector,crypto-cross-verifier network_scope=single-lan geo_wan_evidence=false heterogeneous=true linux_x86_64_memory_reference_page_aligned=true' \
  "$FLEET/inventory.toml"
run_exact_python \
  "scripts/poco-fleet/check_topology.py" \
  'poco_g3_topology_planner=passed counts=7,31,100 profiles=equal,bounded-unequal five_linux_validator_hosts=true mac_observer=true all_six_hosts_participate=true unique_ports=true deterministic=true test_keys=false'

[[ "${#NO_CARGO_SELF_TESTS[@]}" == "${#NO_CARGO_EXPECTED_SUMMARIES[@]}" ]] \
  || fail "self-test path and exact-summary tables differ in length"
for index in "${!NO_CARGO_SELF_TESTS[@]}"; do
  run_exact_python \
    "${NO_CARGO_SELF_TESTS[$index]}" \
    "${NO_CARGO_EXPECTED_SUMMARIES[$index]}"
done

printf '%s\n' \
  "poco_g3_lan_fleet_contract_self_test_gate=passed stage0_observation_complete=false observation_status_evaluated=false required_files=${#REQUIRED_FILES[@]} python_compile=${#PYTHON_FILES[@]} no_cargo_self_tests=${#NO_CARGO_SELF_TESTS[@]} readiness=current_fixture_self_tests_only strict_candidate=clean-commit-v1 strict_builder_schema=3 strict_aggregate_schema=3 commit_tree_blob_cargo_lock_bound=true cargo_executed=false ssh_executed=false evidence_generated=false validator_run=false multihost_observed=false fault_matrix_completed=false performance_evidence=false geo_wan=false production_activation=false strict_clippy_gate_closed=false dormant_clippy_warning_baseline=31_normal,13_test"
