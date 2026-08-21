#!/usr/bin/env python3
"""Report Stage0 observation truth without treating self-tests as evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import tomllib
from collections.abc import Mapping
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_STATUS = ROOT / "docs/evidence/poco-g3/status.toml"
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX40 = re.compile(r"[0-9a-f]{40}")

BUILD_RECORD_FIELDS = (
    "reproducible_builder_invocation_executed",
    "within_invocation_binary_identity_observed",
    "native_cross_architecture_build_observed",
    "aggregate_build_report_emitted",
)

# These are observations required by the current Stage0 closure plan. Contract
# and fixture self-test booleans are deliberately absent from this list.
REQUIRED_OBSERVATION_FIELDS = (
    *BUILD_RECORD_FIELDS,
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

MUST_REMAIN_FALSE_FIELDS = (
    "production_activation",
    "production_candidate",
    "g3_geo_wan_evidence",
)

REPORT_BOOLEAN_FIELDS = (
    "reproducible_build_executed",
    "native_linux_x86_64_reproducible_build_observed",
    "build_execution_cryptographically_attested",
    "rust_src_cross_time_drift_observed",
    "rust_src_physical_sysroot_path_in_rodata_observed",
    "rust_src_drift_report_claims_reproducible_build",
    "rust_src_remap_control_observed",
    "committed_rust_src_remap_builder_control_observed",
    "rust_src_remap_control_restored_historical_hashes",
    "rust_src_remap_control_exit_zero",
    "rust_src_remap_control_report_claims_reproducible_build",
    "rust_src_remap_code_under_test_committed",
    "rust_src_remap_in_d6bb_candidate",
    "rust_src_remap_in_stage0_truth_base",
    "rust_src_remap_tool_source_bound_to_raw_report",
    "rust_src_remap_runner_identity_cryptographically_attested",
    "fresh_clone_gates_initial_offline_cache_ready",
    "fresh_clone_gates_public_dependency_fetch_used",
    "fresh_clone_gates_formal_rerun_offline",
    "fresh_clone_gates_paid_ci_used",
    "fresh_clone_gates_runner_identity_cryptographically_attested",
    "fresh_clone_gates_logs_bundled",
)


class ObservationStatusError(ValueError):
    """The typed observation status is absent, malformed, or contradictory."""


def boolean(status: Mapping[str, Any], field: str) -> bool:
    value = status.get(field)
    if type(value) is not bool:
        raise ObservationStatusError(f"{field} must be an explicit boolean")
    return value


def text(status: Mapping[str, Any], field: str) -> str:
    value = status.get(field)
    if not isinstance(value, str) or not value:
        raise ObservationStatusError(f"{field} must be a non-empty string")
    return value


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ObservationStatusError(f"fresh-clone report repeats JSON key {key!r}")
        result[key] = value
    return result


def report_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ObservationStatusError(f"fresh-clone report {field} must be an object")
    return value


def resolve_report_path(evidence_root: pathlib.Path, relative: str) -> pathlib.Path:
    logical = pathlib.PurePosixPath(relative)
    if logical.is_absolute() or ".." in logical.parts:
        raise ObservationStatusError("fresh-clone evidence path must be repository-relative")
    resolved_root = evidence_root.resolve()
    resolved = (resolved_root / logical).resolve()
    if not resolved.is_relative_to(resolved_root):
        raise ObservationStatusError("fresh-clone evidence path escapes evidence root")
    return resolved


def load_json_report(
    evidence_root: pathlib.Path,
    relative: str,
    expected_hash: str,
    label: str,
) -> Mapping[str, Any]:
    if HEX64.fullmatch(expected_hash) is None:
        raise ObservationStatusError(f"{label} sha256 must be canonical")
    report_path = resolve_report_path(evidence_root, relative)
    try:
        report_bytes = report_path.read_bytes()
        report = json.loads(report_bytes, object_pairs_hook=unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ObservationStatusError(f"cannot read {label}: {error}") from error
    if hashlib.sha256(report_bytes).hexdigest() != expected_hash:
        raise ObservationStatusError(f"{label} sha256 differs from its binding")
    return report_mapping(report, "root")


def load_status_bound_report(
    status: Mapping[str, Any],
    evidence_root: pathlib.Path,
    path_field: str,
    hash_field: str,
    label: str,
) -> Mapping[str, Any]:
    return load_json_report(
        evidence_root,
        text(status, path_field),
        text(status, hash_field),
        label,
    )


def validate_fresh_clone_report(
    status: Mapping[str, Any], evidence_root: pathlib.Path
) -> None:
    report = load_status_bound_report(
        status,
        evidence_root,
        "current_fresh_clone_gates_evidence_path",
        "current_fresh_clone_gates_evidence_sha256",
        "fresh-clone report",
    )
    if report.get("schema_version") != 1:
        raise ObservationStatusError("fresh-clone report must use schema_version=1")
    if report.get("evidence_profile") != text(
        status, "current_fresh_clone_gates_evidence_profile"
    ):
        raise ObservationStatusError("fresh-clone evidence profile differs from status")
    if report.get("classification") != "unsigned-manual-ssh-operator-observation":
        raise ObservationStatusError("fresh-clone report lost unsigned manual-SSH boundary")

    gates = report_mapping(report.get("gates"), "gates")
    runner = report_mapping(report.get("runner"), "runner")
    logs = report_mapping(report.get("logs"), "logs")
    source = report_mapping(report.get("source"), "source")
    expected_facts = (
        (gates, "fresh_clone_fmt_observed", "fresh_clone_fmt_observed"),
        (gates, "fresh_clone_check_observed", "fresh_clone_check_observed"),
        (gates, "key_tests_observed", "key_tests_observed"),
        (
            runner,
            "initial_offline_cache_ready",
            "fresh_clone_gates_initial_offline_cache_ready",
        ),
        (
            runner,
            "public_dependency_fetch_used",
            "fresh_clone_gates_public_dependency_fetch_used",
        ),
        (
            runner,
            "formal_rerun_offline",
            "fresh_clone_gates_formal_rerun_offline",
        ),
        (runner, "paid_ci_used", "fresh_clone_gates_paid_ci_used"),
        (
            runner,
            "runner_identity_cryptographically_attested",
            "fresh_clone_gates_runner_identity_cryptographically_attested",
        ),
        (logs, "bundled", "fresh_clone_gates_logs_bundled"),
        (
            source,
            "source_candidates_byte_identical",
            "fresh_clone_source_candidates_byte_identical_observed",
        ),
    )
    for report_parent, report_field, status_field in expected_facts:
        if report_parent.get(report_field) is not boolean(status, status_field):
            raise ObservationStatusError(
                f"fresh-clone report {report_field} differs from {status_field}"
            )
    for field in (
        "production_activation",
        "production_candidate",
        "validator_run_7_completed",
    ):
        if gates.get(field) is not False:
            raise ObservationStatusError(
                f"fresh-clone report must keep its own {field}=false boundary"
            )
    if runner.get("transport") != "manual-ssh":
        raise ObservationStatusError("fresh-clone report transport must remain manual-ssh")
    if boolean(status, "fresh_clone_gates_observed") is not True:
        raise ObservationStatusError("tracked fresh-clone report must remain observed=true")


def validate_rust_src_cross_time_control(
    status: Mapping[str, Any], evidence_root: pathlib.Path
) -> None:
    report = load_status_bound_report(
        status,
        evidence_root,
        "current_rust_src_cross_time_control_path",
        "current_rust_src_cross_time_control_sha256",
        "rust-src cross-time control report",
    )
    if report.get("schema_version") != 1:
        raise ObservationStatusError(
            "rust-src cross-time control report must use schema_version=1"
        )
    if report.get("evidence_profile") != text(
        status, "current_rust_src_cross_time_control_profile"
    ):
        raise ObservationStatusError("rust-src control profile differs from status")
    if (
        report.get("classification")
        != "unsigned-manual-ssh-cross-time-reproducibility-committed-tool-control"
    ):
        raise ObservationStatusError("rust-src control lost unsigned manual-SSH boundary")

    runner = report_mapping(report.get("runner"), "runner")
    source = report_mapping(report.get("source_candidate"), "source_candidate")
    historical = report_mapping(
        report.get("historical_2026_08_20_baseline"), "historical baseline"
    )
    drift = report_mapping(
        report.get("unpatched_rust_src_drift_observation"), "drift observation"
    )
    control = report_mapping(
        report.get("committed_v2_remap_control_observation"),
        "committed v2 remap control",
    )
    claims = report_mapping(report.get("claims"), "claims")

    status_facts = (
        (claims, "committed_tool_control_native_linux_cross_time_reproducible", "native_cross_time_reproducible_build_observed"),
        (claims, "committed_tool_control_native_linux_cross_time_reproducible", "native_linux_x86_64_reproducible_build_observed"),
        (claims, "cross_time_drift_observed", "rust_src_cross_time_drift_observed"),
        (claims, "committed_candidate_contains_remap_fix", "committed_candidate_rust_src_remap_fix_observed"),
        (claims, "remap_tool_fix_committed", "rust_src_remap_code_under_test_committed"),
        (claims, "remap_control_restores_historical_hashes", "rust_src_remap_control_restored_historical_hashes"),
        (drift, "physical_rust_src_sysroot_path_present_in_rodata", "rust_src_physical_sysroot_path_in_rodata_observed"),
        (drift, "report_claims_reproducible_build", "rust_src_drift_report_claims_reproducible_build"),
        (control, "report_claims_reproducible_build", "rust_src_remap_control_report_claims_reproducible_build"),
        (control, "code_under_test_committed", "rust_src_remap_code_under_test_committed"),
        (control, "committed_builder_control_observed", "committed_rust_src_remap_builder_control_observed"),
        (control, "committed_builder_control_observed", "reproducible_build_executed"),
        (control, "candidate_contains_remap_fix", "rust_src_remap_in_d6bb_candidate"),
        (control, "stage0_truth_base_contains_remap_fix", "rust_src_remap_in_stage0_truth_base"),
        (control, "tool_source_cryptographically_bound_to_raw_report", "rust_src_remap_tool_source_bound_to_raw_report"),
        (runner, "runner_identity_cryptographically_attested", "rust_src_remap_runner_identity_cryptographically_attested"),
    )
    for report_parent, report_field, status_field in status_facts:
        if report_parent.get(report_field) is not boolean(status, status_field):
            raise ObservationStatusError(
                f"rust-src control {report_field} differs from {status_field}"
            )
    if boolean(status, "rust_src_remap_control_observed") is not True:
        raise ObservationStatusError("tracked rust-src remap control must be observed=true")
    if (control.get("control_exit_code") == 0) is not boolean(
        status, "rust_src_remap_control_exit_zero"
    ):
        raise ObservationStatusError("rust-src control exit truth differs from status")
    if (
        claims.get(
            "control_observation_promotes_native_linux_cross_time_reproducibility"
        )
        is not True
    ):
        raise ObservationStatusError(
            "committed clean-tool control must support its scoped cross-time claim"
        )

    complete = all(boolean(status, field) for field in REQUIRED_OBSERVATION_FIELDS)
    if claims.get("stage0_observation_complete") is not complete:
        raise ObservationStatusError(
            "rust-src control Stage0 completion bit differs from typed status"
        )
    for parent, field in (
        (report, "artifacts_bundled"),
        (report, "production_activation"),
        (report, "production_candidate"),
        (report, "validator_run_7_completed"),
    ):
        if parent.get(field) is not False:
            raise ObservationStatusError(
                f"rust-src control must keep its own {field}=false boundary"
            )
    if (
        runner.get("transport") != "manual-ssh"
        or runner.get("paid_ci_used") is not False
        or runner.get("runner_identity_cryptographically_attested") is not False
    ):
        raise ObservationStatusError("rust-src control runner boundary changed")
    if control.get("v1_evidence_bound_builder_unchanged") is not True:
        raise ObservationStatusError("v2 control must preserve the evidence-bound v1 builder")
    if control.get("v2_wrapper_tracked") is not True:
        raise ObservationStatusError("committed v2 control must use a tracked wrapper")
    if control.get("code_under_test_committed") is not True:
        raise ObservationStatusError("committed v2 control lost its tool commit boundary")
    for field in (
        "builder_tool_bundle_complete_history",
        "builder_tool_checkout_clone_no_local",
        "builder_tool_checkout_detached_exact_commit",
        "builder_tool_checkout_fresh",
        "builder_tool_checkout_status_empty",
    ):
        if control.get(field) is not True:
            raise ObservationStatusError(f"committed v2 control requires {field}=true")
    if control.get("builder_tool_bundle_bundled_in_evidence") is not False:
        raise ObservationStatusError("tool bundle must remain recorded but unbundled")
    if control.get("builder_tool_checkout_status_sha256") != hashlib.sha256(b"").hexdigest():
        raise ObservationStatusError("committed v2 control checkout status is not empty")
    if (
        control.get("frozen_v1_builder_sha256")
        != historical.get("committed_builder_sha256")
        or drift.get("committed_builder_sha256")
        != historical.get("committed_builder_sha256")
    ):
        raise ObservationStatusError("v2 control lost the frozen v1 builder binding")
    rustc = report_mapping(report.get("rustc"), "rustc")
    if control.get("canonical_remap_target") != f"/rustc/{text(rustc, 'commit_hash')}":
        raise ObservationStatusError("v2 control canonical remap target differs from rustc")
    expected_v2_paths = {
        "v2_wrapper_path": "scripts/poco-fleet/build_reproducible_lab_candidate_v2.py",
        "v2_wrapper_test_path": (
            "scripts/poco-fleet/build_reproducible_lab_candidate_v2_test.py"
        ),
    }
    for field, expected in expected_v2_paths.items():
        if control.get(field) != expected:
            raise ObservationStatusError(f"v2 control {field} differs from its boundary")
    for field in (
        "builder_tool_bundle_sha256",
        "builder_tool_checkout_status_sha256",
        "frozen_v1_builder_sha256",
        "v2_wrapper_sha256",
        "v2_wrapper_test_sha256",
    ):
        if HEX64.fullmatch(text(control, field)) is None:
            raise ObservationStatusError(f"v2 control {field} must be canonical")
    for field in (
        "builder_tool_commit",
        "builder_tool_commit_parent",
        "builder_tool_commit_tree_oid",
    ):
        if HEX40.fullmatch(text(control, field)) is None:
            raise ObservationStatusError(f"v2 control {field} must be canonical")
    if type(control.get("builder_tool_bundle_bytes")) is not int or control.get(
        "builder_tool_bundle_bytes"
    ) <= 0:
        raise ObservationStatusError("v2 control tool bundle bytes must be positive")

    raw_reports = (
        (drift, "rust-src drift raw report"),
        (control, "rust-src remapped v2 raw report"),
    )
    raw_values: list[Mapping[str, Any]] = []
    for observation, label in raw_reports:
        raw = load_json_report(
            evidence_root,
            text(observation, "raw_report_path"),
            text(observation, "raw_report_sha256"),
            label,
        )
        raw_values.append(raw)
        if (
            raw.get("schema_version") != 3
            or raw.get("independent_build_count") != 2
            or raw.get("reproducible_build") is not True
            or raw.get("production_activation") is not False
            or raw.get("host_triple") != runner.get("host_triple")
        ):
            raise ObservationStatusError(f"{label} lost its schema-3 build boundary")
        source_pairs = (
            ("source_base_commit", "base_commit"),
            ("source_git_tree_oid", "git_tree_oid"),
            ("source_candidate_sha256", "source_candidate_sha256"),
            ("cargo_lock_sha256", "cargo_lock_sha256"),
            ("cargo_lock_bytes", "cargo_lock_bytes"),
        )
        for raw_field, source_field in source_pairs:
            if raw.get(raw_field) != source.get(source_field):
                raise ObservationStatusError(
                    f"{label} {raw_field} differs from the control source"
                )
        if raw.get("rustc_vv_sha256") != rustc.get("rustc_vv_sha256"):
            raise ObservationStatusError(f"{label} rustc differs from the control")
        for output_field in (
            "validator_binary_sha256",
            "validator_binary_bytes",
            "material_builder_binary_sha256",
            "material_builder_binary_bytes",
        ):
            if raw.get(output_field) != observation.get(output_field):
                raise ObservationStatusError(
                    f"{label} {output_field} differs from the typed control"
                )

    drift_raw, control_raw = raw_values
    output_fields = (
        "validator_binary_sha256",
        "validator_binary_bytes",
        "material_builder_binary_sha256",
        "material_builder_binary_bytes",
    )
    if all(drift_raw.get(field) == historical.get(field) for field in output_fields):
        raise ObservationStatusError("rust-src drift unexpectedly matches the historical baseline")
    if any(control_raw.get(field) != historical.get(field) for field in output_fields):
        raise ObservationStatusError("rust-src remap control did not restore the baseline")
    for field in (
        "builder_tool_commit",
        "builder_tool_bundle_sha256",
        "v2_wrapper_sha256",
        "v2_wrapper_test_sha256",
    ):
        if field in control_raw:
            raise ObservationStatusError(
                f"raw schema-3 control unexpectedly self-binds tool field {field}"
            )


def load_status(path: pathlib.Path, evidence_root: pathlib.Path) -> dict[str, Any]:
    with path.open("rb") as source:
        status = tomllib.load(source)
    if status.get("schema_version") != 1:
        raise ObservationStatusError("status must use schema_version=1")
    for field in (
        *REQUIRED_OBSERVATION_FIELDS,
        *MUST_REMAIN_FALSE_FIELDS,
        *REPORT_BOOLEAN_FIELDS,
    ):
        boolean(status, field)
    for field in MUST_REMAIN_FALSE_FIELDS:
        if boolean(status, field):
            raise ObservationStatusError(f"Stage0 status must keep {field}=false")
    validate_fresh_clone_report(status, evidence_root)
    validate_rust_src_cross_time_control(status, evidence_root)
    return status


def render_status(status: Mapping[str, Any]) -> tuple[str, bool]:
    missing = tuple(
        field for field in REQUIRED_OBSERVATION_FIELDS if not boolean(status, field)
    )
    complete = not missing
    native_build_records_present = all(
        boolean(status, field) for field in BUILD_RECORD_FIELDS
    )
    missing_text = ",".join(missing) if missing else "none"
    summary = (
        "poco_g3_stage0_observation_status=reported "
        f"stage0_observation_complete={str(complete).lower()} "
        f"native_build_records_present={str(native_build_records_present).lower()} "
        "within_invocation_binary_identity_observed="
        f"{str(boolean(status, 'within_invocation_binary_identity_observed')).lower()} "
        "native_reproducible_build="
        f"{str(boolean(status, 'native_cross_time_reproducible_build_observed')).lower()} "
        "native_build_cryptographically_attested="
        f"{str(boolean(status, 'build_execution_cryptographically_attested')).lower()} "
        "rust_src_cross_time_control_bound=true "
        "rust_src_cross_time_control_sha256="
        f"{text(status, 'current_rust_src_cross_time_control_sha256')} "
        "rust_src_drift_observed="
        f"{str(boolean(status, 'rust_src_cross_time_drift_observed')).lower()} "
        "rust_src_remap_control_restored_historical_hashes="
        f"{str(boolean(status, 'rust_src_remap_control_restored_historical_hashes')).lower()} "
        "rust_src_remap_code_under_test_committed="
        f"{str(boolean(status, 'rust_src_remap_code_under_test_committed')).lower()} "
        "committed_rust_src_remap_builder_control_observed="
        f"{str(boolean(status, 'committed_rust_src_remap_builder_control_observed')).lower()} "
        "committed_candidate_rust_src_remap_fix_observed="
        f"{str(boolean(status, 'committed_candidate_rust_src_remap_fix_observed')).lower()} "
        "rust_src_remap_in_d6bb_candidate="
        f"{str(boolean(status, 'rust_src_remap_in_d6bb_candidate')).lower()} "
        "rust_src_remap_tool_source_bound_to_raw_report="
        f"{str(boolean(status, 'rust_src_remap_tool_source_bound_to_raw_report')).lower()} "
        "fresh_clone_report_bound=true "
        "fresh_clone_report_sha256="
        f"{text(status, 'current_fresh_clone_gates_evidence_sha256')} "
        f"fresh_clone_fmt_observed={str(boolean(status, 'fresh_clone_fmt_observed')).lower()} "
        f"fresh_clone_check_observed={str(boolean(status, 'fresh_clone_check_observed')).lower()} "
        f"key_tests_observed={str(boolean(status, 'key_tests_observed')).lower()} "
        "initial_offline_cache_ready="
        f"{str(boolean(status, 'fresh_clone_gates_initial_offline_cache_ready')).lower()} "
        "public_dependency_fetch_used="
        f"{str(boolean(status, 'fresh_clone_gates_public_dependency_fetch_used')).lower()} "
        "formal_rerun_offline="
        f"{str(boolean(status, 'fresh_clone_gates_formal_rerun_offline')).lower()} "
        "fresh_clone_runner_cryptographically_attested="
        f"{str(boolean(status, 'fresh_clone_gates_runner_identity_cryptographically_attested')).lower()} "
        "fresh_clone_logs_bundled="
        f"{str(boolean(status, 'fresh_clone_gates_logs_bundled')).lower()} "
        "deep_reverification_bundle_available="
        f"{str(boolean(status, 'stage0_deep_reverification_bundle_available')).lower()} "
        f"validator_run_7_completed={str(boolean(status, 'validator_run_7_completed')).lower()} "
        "contract_self_tests_are_observations=false "
        f"missing={missing_text}"
    )
    return summary, complete


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "status",
        nargs="?",
        type=pathlib.Path,
        default=DEFAULT_STATUS,
        help="typed Stage0 status TOML (default: docs/evidence/poco-g3/status.toml)",
    )
    parser.add_argument(
        "--evidence-root",
        type=pathlib.Path,
        default=ROOT,
        help="root used to resolve repository-relative evidence paths",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="exit 1 when the typed observation status is incomplete",
    )
    args = parser.parse_args(argv)

    try:
        status = load_status(args.status, args.evidence_root)
        summary, complete = render_status(status)
    except (OSError, tomllib.TOMLDecodeError, ObservationStatusError) as error:
        print(f"Stage0 observation status invalid: {error}", file=sys.stderr)
        return 2

    print(summary)
    if args.require_complete and not complete:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
