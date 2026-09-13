#!/usr/bin/env python3
"""Self-test the typed Stage0 observation status reporter."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
CHECKER = HERE / "check_stage0_observation_status.py"

OBSERVATIONS = (
    "reproducible_builder_invocation_executed",
    "within_invocation_binary_identity_observed",
    "native_cross_architecture_build_observed",
    "aggregate_build_report_emitted",
    "native_cross_time_reproducible_build_observed",
    "committed_candidate_rust_src_remap_fix_observed",
    "current_fleet_probe_observed",
    "current_run_readiness_observed",
    "fresh_clone_gates_observed",
    "fresh_clone_source_candidates_byte_identical_observed",
    "fresh_clone_fmt_observed",
    "fresh_clone_check_observed",
    "key_tests_observed",
    "stage0_deep_reverification_bundle_available",
    "validator_run_7_completed",
)


def write_report(path: pathlib.Path) -> str:
    report = {
        "classification": "unsigned-manual-ssh-operator-observation",
        "evidence_profile": "poco-g3-stage0-x230-fresh-clone-gates-observation-v1",
        "gates": {
            "fresh_clone_check_observed": True,
            "fresh_clone_fmt_observed": True,
            "key_tests_observed": True,
            "production_activation": False,
            "production_candidate": False,
            "validator_run_7_completed": False,
        },
        "logs": {"bundled": False},
        "runner": {
            "formal_rerun_offline": True,
            "initial_offline_cache_ready": False,
            "paid_ci_used": False,
            "public_dependency_fetch_used": True,
            "runner_identity_cryptographically_attested": False,
            "transport": "manual-ssh",
        },
        "schema_version": 1,
        "source": {"source_candidates_byte_identical": True},
    }
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def write_json(path: pathlib.Path, value: object) -> str:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def write_cross_time_reports(
    root: pathlib.Path, prefix: str, *, complete: bool
) -> tuple[pathlib.Path, str]:
    source = {
        "source_base_commit": "d" * 40,
        "source_git_tree_oid": "e" * 40,
        "source_candidate_sha256": "1" * 64,
        "cargo_lock_sha256": "2" * 64,
        "cargo_lock_bytes": 123,
        "rustc_vv_sha256": "3" * 64,
    }
    historical = {
        "committed_builder_sha256": "8" * 64,
        "validator_binary_sha256": "4" * 64,
        "validator_binary_bytes": 100,
        "material_builder_binary_sha256": "5" * 64,
        "material_builder_binary_bytes": 50,
    }
    drift_outputs = {
        "validator_binary_sha256": "6" * 64,
        "validator_binary_bytes": 101,
        "material_builder_binary_sha256": "7" * 64,
        "material_builder_binary_bytes": 51,
    }

    def raw_report(outputs: dict[str, object]) -> dict[str, object]:
        return {
            **source,
            **outputs,
            "schema_version": 3,
            "independent_build_count": 2,
            "reproducible_build": True,
            "production_activation": False,
            "geo_wan_evidence": False,
            "source_candidate_profile": "clean-commit-v1",
            "source_git_object_format": "sha1",
            "source_git_status_sha256": hashlib.sha256(b"").hexdigest(),
            "host_triple": "x86_64-unknown-linux-gnu",
        }

    drift_path = root / f"{prefix}-drift.json"
    control_path = root / f"{prefix}-control.json"
    drift_hash = write_json(drift_path, raw_report(drift_outputs))
    control_hash = write_json(control_path, raw_report(historical))
    wrapper = {
        "classification": (
            "unsigned-manual-ssh-cross-time-reproducibility-committed-tool-control"
        ),
        "evidence_profile": "poco-g3-stage0-rust-src-cross-time-control-v3",
        "schema_version": 1,
        "runner": {
            "host_triple": "x86_64-unknown-linux-gnu",
            "paid_ci_used": False,
            "runner_identity_cryptographically_attested": False,
            "transport": "manual-ssh",
        },
        "source_candidate": {
            "base_commit": source["source_base_commit"],
            "git_tree_oid": source["source_git_tree_oid"],
            "source_candidate_sha256": source["source_candidate_sha256"],
            "cargo_lock_sha256": source["cargo_lock_sha256"],
            "cargo_lock_bytes": source["cargo_lock_bytes"],
        },
        "rustc": {
            "commit_hash": "9" * 40,
            "rustc_vv_sha256": source["rustc_vv_sha256"],
        },
        "historical_2026_08_20_baseline": historical,
        "frozen_candidate_v1_baseline": {
            **source,
            **historical,
        },
        "unpatched_rust_src_drift_observation": {
            **drift_outputs,
            "committed_builder_sha256": historical["committed_builder_sha256"],
            "raw_report_path": drift_path.name,
            "raw_report_sha256": drift_hash,
            "physical_rust_src_sysroot_path_present_in_rodata": True,
            "report_claims_reproducible_build": True,
        },
        "committed_v2_remap_control_observation": {
            **historical,
            "builder_tool_bundle_bundled_in_evidence": False,
            "builder_tool_bundle_bytes": 456,
            "builder_tool_bundle_complete_history": True,
            "builder_tool_bundle_sha256": "a" * 64,
            "builder_tool_checkout_clone_no_local": True,
            "builder_tool_checkout_detached_exact_commit": True,
            "builder_tool_checkout_fresh": True,
            "builder_tool_checkout_status_empty": True,
            "builder_tool_checkout_status_sha256": hashlib.sha256(b"").hexdigest(),
            "builder_tool_commit": "a" * 40,
            "builder_tool_commit_parent": "b" * 40,
            "builder_tool_commit_tree_oid": "c" * 40,
            "canonical_remap_target": f"/rustc/{'9' * 40}",
            "raw_report_path": control_path.name,
            "raw_report_sha256": control_hash,
            "report_claims_reproducible_build": True,
            "code_under_test_committed": True,
            "committed_builder_control_observed": True,
            "candidate_contains_remap_fix": complete,
            "observation_input_candidate_contains_remap_fix": complete,
            "restores_frozen_candidate_v1_hashes": True,
            "restores_historical_baseline_hashes": False,
            "stage0_truth_base_contains_remap_fix": complete,
            "tool_source_cryptographically_bound_to_raw_report": False,
            "control_exit_code": 0,
            "frozen_v1_builder_sha256": historical["committed_builder_sha256"],
            "v1_evidence_bound_builder_unchanged": True,
            "v2_wrapper_path": (
                "scripts/poco-fleet/build_reproducible_lab_candidate_v2.py"
            ),
            "v2_wrapper_sha256": "b" * 64,
            "v2_wrapper_test_path": (
                "scripts/poco-fleet/build_reproducible_lab_candidate_v2_test.py"
            ),
            "v2_wrapper_test_sha256": "c" * 64,
            "v2_wrapper_tracked": True,
        },
        "claims": {
            "committed_candidate_contains_remap_fix": complete,
            "committed_tool_control_native_linux_cross_time_reproducible": True,
            "cross_time_drift_observed": True,
            "remap_tool_fix_committed": True,
            "remap_control_restores_historical_hashes": False,
            "remap_control_restores_frozen_candidate_v1_hashes": True,
            "control_observation_promotes_native_linux_cross_time_reproducibility": True,
            "stage0_observation_complete": complete,
        },
        "artifacts_bundled": False,
        "production_activation": False,
        "production_candidate": False,
        "validator_run_7_completed": False,
    }
    wrapper_path = root / f"{prefix}-wrapper.json"
    return wrapper_path, write_json(wrapper_path, wrapper)


def write_status(
    path: pathlib.Path,
    values: dict[str, object],
    report_relative: str,
    report_sha256: str,
    cross_time_relative: str,
    cross_time_sha256: str,
) -> None:
    merged: dict[str, object] = {
        "schema_version": 1,
        "source_candidate_clean_commit_contract": True,
        "current_fresh_clone_gates_evidence_profile": (
            "poco-g3-stage0-x230-fresh-clone-gates-observation-v1"
        ),
        "current_fresh_clone_gates_evidence_path": report_relative,
        "current_fresh_clone_gates_evidence_sha256": report_sha256,
        "current_rust_src_cross_time_control_profile": (
            "poco-g3-stage0-rust-src-cross-time-control-v3"
        ),
        "current_rust_src_cross_time_control_path": cross_time_relative,
        "current_rust_src_cross_time_control_sha256": cross_time_sha256,
        "reproducible_build_executed": True,
        "native_linux_x86_64_reproducible_build_observed": True,
        "build_execution_cryptographically_attested": False,
        "rust_src_cross_time_drift_observed": True,
        "rust_src_physical_sysroot_path_in_rodata_observed": True,
        "rust_src_drift_report_claims_reproducible_build": True,
        "rust_src_remap_control_observed": True,
        "committed_rust_src_remap_builder_control_observed": True,
        "rust_src_remap_control_restored_historical_hashes": False,
        "rust_src_remap_control_restored_frozen_candidate_v1_hashes": True,
        "rust_src_remap_control_exit_zero": True,
        "rust_src_remap_control_report_claims_reproducible_build": True,
        "rust_src_remap_code_under_test_committed": True,
        "rust_src_remap_in_d6bb_candidate": False,
        "rust_src_remap_in_stage0_truth_base": False,
        "rust_src_remap_tool_source_bound_to_raw_report": False,
        "rust_src_remap_runner_identity_cryptographically_attested": False,
        "validator_runtime_started": False,
        "validator_run_completed": False,
        "validator_run_31_completed": False,
        "validator_run_100_completed": False,
        "signed_runtime_evidence_multihost_observed": False,
        "multihost_consensus_observed": False,
        "fault_restart_fleet_multihost_observed": False,
        "fault_matrix_completed": False,
        "performance_evidence": False,
        "g3_lan_multihost_evidence": False,
        "successful_process2_restart_observed": False,
        "authenticated_process2_catchup_operational": False,
        "recovery_ready_operational": False,
        "recovery_start_operational": False,
        "production_activation": False,
        "production_candidate": False,
        "g3_geo_wan_evidence": False,
        "fresh_clone_gates_initial_offline_cache_ready": False,
        "fresh_clone_gates_public_dependency_fetch_used": True,
        "fresh_clone_gates_formal_rerun_offline": True,
        "fresh_clone_gates_paid_ci_used": False,
        "fresh_clone_gates_runner_identity_cryptographically_attested": False,
        "fresh_clone_gates_logs_bundled": False,
        **{field: False for field in OBSERVATIONS},
        **values,
    }
    lines = []
    for key, value in merged.items():
        if type(value) is bool:
            rendered = str(value).lower()
        elif type(value) is int:
            rendered = str(value)
        else:
            rendered = f'"{value}"'
        lines.append(f"{key} = {rendered}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(
    path: pathlib.Path, evidence_root: pathlib.Path, *arguments: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CHECKER),
            str(path),
            "--evidence-root",
            str(evidence_root),
            *arguments,
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="poco-stage0-observation-status-") as raw:
        root = pathlib.Path(raw)
        report_path = root / "fresh-clone-report.json"
        report_sha256 = write_report(report_path)
        cross_time_path, cross_time_sha256 = write_cross_time_reports(
            root, "incomplete", complete=False
        )
        complete_cross_time_path, complete_cross_time_sha256 = write_cross_time_reports(
            root, "complete", complete=True
        )
        current_observations = {
            "reproducible_builder_invocation_executed": True,
            "within_invocation_binary_identity_observed": True,
            "native_cross_architecture_build_observed": True,
            "aggregate_build_report_emitted": True,
            "native_cross_time_reproducible_build_observed": True,
            "fresh_clone_gates_observed": True,
            "fresh_clone_source_candidates_byte_identical_observed": True,
            "fresh_clone_fmt_observed": True,
            "fresh_clone_check_observed": True,
            "key_tests_observed": True,
        }
        incomplete = root / "incomplete.toml"
        write_status(
            incomplete,
            current_observations,
            report_path.name,
            report_sha256,
            cross_time_path.name,
            cross_time_sha256,
        )
        report = run(incomplete, root)
        assert report.returncode == 0, report.stderr
        assert "stage0_observation_complete=false" in report.stdout
        assert "native_build_records_present=true" in report.stdout
        assert "native_reproducible_build=true" in report.stdout
        assert "rust_src_cross_time_control_bound=true" in report.stdout
        assert "rust_src_drift_observed=true" in report.stdout
        assert "rust_src_remap_code_under_test_committed=true" in report.stdout
        assert "committed_rust_src_remap_builder_control_observed=true" in report.stdout
        assert "rust_src_remap_control_restored_historical_hashes=false" in report.stdout
        assert "rust_src_remap_control_restored_frozen_candidate_v1_hashes=true" in report.stdout
        assert "committed_candidate_rust_src_remap_fix_observed=false" in report.stdout
        assert "rust_src_remap_in_d6bb_candidate=false" in report.stdout
        assert "fresh_clone_report_bound=true" in report.stdout
        assert "fresh_clone_fmt_observed=true" in report.stdout
        assert "initial_offline_cache_ready=false" in report.stdout
        assert "public_dependency_fetch_used=true" in report.stdout
        assert "deep_reverification_bundle_available=false" in report.stdout
        assert "contract_self_tests_are_observations=false" in report.stdout

        required = run(incomplete, root, "--require-complete")
        assert required.returncode == 1, required
        assert required.stdout == report.stdout

        complete = root / "complete.toml"
        write_status(
            complete,
            {
                **{field: True for field in OBSERVATIONS},
                "rust_src_remap_in_d6bb_candidate": True,
                "rust_src_remap_in_stage0_truth_base": True,
            },
            report_path.name,
            report_sha256,
            complete_cross_time_path.name,
            complete_cross_time_sha256,
        )
        accepted = run(complete, root, "--require-complete")
        # A descriptive report and a recomputed status hash are not runtime
        # evidence.  Until an independently bound seven-validator receipt is
        # admitted by this checker, the completion bit is immutable-false.
        assert accepted.returncode == 2
        assert "validator_run_7_completed=false" in accepted.stderr

        missing = root / "missing.toml"
        write_status(
            missing,
            current_observations,
            report_path.name,
            report_sha256,
            cross_time_path.name,
            cross_time_sha256,
        )
        text = missing.read_text(encoding="utf-8")
        missing.write_text(
            text.replace("fresh_clone_fmt_observed = true\n", ""),
            encoding="utf-8",
        )
        absent = run(missing, root)
        assert absent.returncode == 2
        assert "fresh_clone_fmt_observed must be an explicit boolean" in absent.stderr

        malformed = root / "malformed.toml"
        write_status(
            malformed,
            {**current_observations, "key_tests_observed": "false"},
            report_path.name,
            report_sha256,
            cross_time_path.name,
            cross_time_sha256,
        )
        wrong_type = run(malformed, root)
        assert wrong_type.returncode == 2
        assert "key_tests_observed must be an explicit boolean" in wrong_type.stderr

        activated = root / "activated.toml"
        write_status(
            activated,
            {**current_observations, "production_activation": True},
            report_path.name,
            report_sha256,
            cross_time_path.name,
            cross_time_sha256,
        )
        forbidden = run(activated, root)
        assert forbidden.returncode == 2
        assert "production_activation=false" in forbidden.stderr

        forged_runtime = root / "forged-runtime-boundary.toml"
        write_status(
            forged_runtime,
            {**current_observations, "validator_runtime_started": True},
            report_path.name,
            report_sha256,
            cross_time_path.name,
            cross_time_sha256,
        )
        forged_runtime_result = run(forged_runtime, root)
        assert forged_runtime_result.returncode == 2
        assert "validator_runtime_started=false" in forged_runtime_result.stderr

        wrong_hash = root / "wrong-hash.toml"
        write_status(
            wrong_hash,
            current_observations,
            report_path.name,
            "0" * 64,
            cross_time_path.name,
            cross_time_sha256,
        )
        unbound = run(wrong_hash, root)
        assert unbound.returncode == 2
        assert "fresh-clone report sha256 differs from its binding" in unbound.stderr

        wrong_cross_hash = root / "wrong-cross-hash.toml"
        write_status(
            wrong_cross_hash,
            current_observations,
            report_path.name,
            report_sha256,
            cross_time_path.name,
            "0" * 64,
        )
        unbound_cross_time = run(wrong_cross_hash, root)
        assert unbound_cross_time.returncode == 2
        assert "cross-time control report sha256 differs" in unbound_cross_time.stderr

        invalid_v2_path = root / "invalid-v2-boundary.json"
        invalid_v2 = json.loads(cross_time_path.read_text(encoding="utf-8"))
        invalid_v2["committed_v2_remap_control_observation"][
            "v2_wrapper_tracked"
        ] = False
        invalid_v2_hash = write_json(invalid_v2_path, invalid_v2)
        invalid_v2_status = root / "invalid-v2-boundary.toml"
        write_status(
            invalid_v2_status,
            current_observations,
            report_path.name,
            report_sha256,
            invalid_v2_path.name,
            invalid_v2_hash,
        )
        invalid_v2_result = run(invalid_v2_status, root)
        assert invalid_v2_result.returncode == 2
        assert "committed v2 control must use a tracked wrapper" in invalid_v2_result.stderr

    print(
        "poco_g3_stage0_observation_status_test=passed positives=1 negatives=9 "
        "structured_incomplete=true require_complete_fail_closed=true "
        "contract_self_tests_not_observations=true production_activation_blocked=true "
        "report_hash_bound=true cross_time_control_bound=true "
        "rust_src_drift_not_reproducible=true committed_v2_remap_control=true "
        "committed_clean_tool_boundary_fail_closed=true "
        "initial_cache_miss_preserved=true"
    )


if __name__ == "__main__":
    main()
