#!/usr/bin/env python3
"""Plan-only boundary for a future PoCO G3 no-fault runner-to-bundle bridge.

Production collection is deliberately unavailable.  The CLI only validates a
read-only envelope and reports the missing authority contracts.  A private
module capability retains the old projection path solely so repository fixtures
can exercise downstream schemas; it is not reachable from the CLI and is never
real run evidence.

The mixed-authority fault profile is intentionally unsupported here.
"""

from __future__ import annotations

import argparse
import datetime
import json
import math
import pathlib
import re
import shutil
import stat
import sys
import tempfile
import types
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import assemble_run_bundle_v1 as assembler  # noqa: E402
import check_run_evidence  # noqa: E402
import check_signed_runtime_evidence  # noqa: E402
import evidence_bundle_profiles_v1 as evidence_profiles  # noqa: E402
import run_consensus_fleet as consensus_runner  # noqa: E402


PROFILE = evidence_profiles.NO_FAULT_V1
PLANNABLE_PROFILES = {
    evidence_profiles.NO_FAULT_V1,
    evidence_profiles.NO_FAULT_SIGNED_RUNTIME_OBSERVER_V1,
    evidence_profiles.NO_FAULT_SIGNED_RUNTIME_EXTERNAL_LOAD_V1,
}
VALID_COUNTS = {7, 31, 100}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

COORDINATOR_KEYS = {
    "schema_version",
    "run_id",
    "fleet_id",
    "validator_count",
    "weight_profile",
    "network_scope",
    "geo_wan_evidence",
    "candidate",
    "material_author",
    "validator_set_sha256",
    "public_files",
    "secret_files",
    "production_activation",
}
RUNNER_SUMMARY_KEYS = {
    "schema_version",
    "profile",
    "run_id",
    "validator_count",
    "transport",
    "signed_report_count",
    "signed_runtime_journal_count",
    "fleet_start_certificate_count",
    "signed_runtime_metrics_count",
    "signed_runtime_final_state_count",
    "signed_replay_archive_set_count",
    "observer_verified_report_count",
    "observer_verified_journal_count",
    "observer_verified_fleet_start_certificate_count",
    "observer_verified_metrics_count",
    "observer_verified_final_state_count",
    "observer_verified_replay_archive_count",
    "all_six_hosts_participated",
    "elapsed_monotonic_ns",
    "observed_fleet_launch_skew_ns",
    "fleet_launch_skew_within_allowance",
    "fleet_launch_skew_capacity_authority",
    "coordinator_manifest_sha256",
    "processes",
    "terminal_agreement",
    "failure",
    "cleanup_failures",
    "validator_run_completed",
    "fault_matrix_completed",
    "performance_evidence",
    "g3_lan_multihost_evidence",
    "geo_wan_evidence",
    "production_activation",
}
RUNNER_PROCESS_KEYS = {
    "validator_id",
    "host_id",
    "signed_report_sha256",
    "signed_runtime_journal_sha256",
    "fleet_start_certificate_sha256",
    "signed_runtime_metrics_sha256",
    "signed_runtime_final_state_sha256",
    "replay_archive_context_sha256",
    "replay_archive_entries_sha256",
    "replay_archive_head_sha256",
    "replay_archive_terminal_seal_sha256",
    "observer_journal_verification",
    "observer_fleet_start_certificate_verification",
    "observer_report_verification",
    "observer_metrics_verification",
    "observer_final_state_verification",
    "observer_replay_archive_verification",
}
PRESTART_PLAN_KEYS = {
    "schema_version",
    "profile",
    "evidence_profile",
    "run_id",
    "validator_count",
    "linux_validator_host_count",
    "observer_host_id",
    "coordinator_manifest_sha256",
    "duration_seconds",
    "max_blocks",
    "runtime_topology_supported",
    "transport",
    "signer_lifetime",
    "signed_replay_archive_lifetime",
    "commissioning_allowance_seconds",
    "fleet_launch_skew_allowance_seconds",
    "fleet_launch_skew_capacity_authority",
    "mesh_setup_allowance_seconds",
    "startup_allowance_seconds",
    "terminal_drain_allowance_seconds",
    "timeout_view_budget_allowance_seconds",
    "process_completion_allowance_seconds",
    "validators",
    "requires_signed_terminal_evidence_chain_per_validator",
    "requires_macos_independent_verification",
    "requires_macos_full_fleet_certificate_verification",
    "requires_macos_full_runtime_journal_replay",
    "requires_post_success_replay_archive_export",
    "requires_macos_full_replay_archive_verification",
    "mesh_resource_preflight_required_before_effects",
    "mesh_resource_preflight",
    "validator_run_completed",
    "fault_matrix_completed",
    "performance_evidence",
    "g3_lan_multihost_evidence",
    "geo_wan_evidence",
    "production_activation",
}
PRESTART_SIGNER_LIFETIME_KEYS = {
    "journal_capacity",
    "maximum_timeout_view_advances",
    "maximum_local_vote_intents",
    "maximum_local_timeout_intents",
    "maximum_total_intents",
}
PRESTART_ARCHIVE_LIFETIME_KEYS = {
    "archive_capacity",
    "maximum_proposal_entries",
    "maximum_quorum_certificate_entries",
    "maximum_total_entries",
}
PRESTART_VALIDATOR_KEYS = {
    "validator_id",
    "host_id",
    "management",
    "deployment",
    "config_relative",
}
MESH_PREFLIGHT_KEYS = {
    "schema_version",
    "profile",
    "validator_count",
    "peer_degree",
    "per_validator_threads",
    "per_validator_socket_fds",
    "per_validator_open_file_fds",
    "per_validator_rss_bytes",
    "coordinator_capture_fds",
    "observed_epoch_spread_seconds",
    "hosts",
    "capacity_passed",
    "validator_run_completed",
    "g3_lan_multihost_evidence",
    "geo_wan_evidence",
    "production_activation",
}
MESH_PREFLIGHT_HOST_KEYS = {
    "host_id",
    "management",
    "hostname",
    "validator_processes",
    "cpu_threads",
    "memory_bytes",
    "memory_available_bytes",
    "per_process_nofile_soft",
    "per_process_nofile_hard",
    "uid_nproc_soft",
    "uid_nproc_hard",
    "uid_threads_observed",
    "system_threads_observed",
    "system_threads_max",
    "system_file_handles_allocated",
    "system_file_handles_max",
    "system_file_handles_available",
    "host_threads_required",
    "host_open_file_fds_required",
    "coordinator_capture_fds_required",
    "host_rss_bytes_required",
    "capacity_passed",
}
OBSERVER_REPORT_KEYS = {
    "schema_version",
    "run_id",
    "host_id",
    "process_id",
    "config_sha256",
    "binary_sha256",
    "load_submitted_nonempty_blocks",
    "verified_qc_signatures",
    "rejected_invalid_signature_controls",
    "started_at",
    "ended_at",
}
AGGREGATE_BUILD_REPORT_KEYS = {
    "schema_version",
    "source_tree_sha256",
    "linux_first_sha256",
    "linux_second_sha256",
    "linux_material_builder_first_sha256",
    "linux_material_builder_second_sha256",
    "macos_first_sha256",
    "macos_second_sha256",
    "macos_material_builder_first_sha256",
    "macos_material_builder_second_sha256",
    "independent_build_roots",
    "production_activation",
} | check_run_evidence.SOURCE_PROVENANCE_KEYS


class _FixtureTestOnlyCapability:
    """Unexported capability for repository fixture tests only."""

    __slots__ = ()


_FIXTURE_TEST_ONLY_CAPABILITY = _FixtureTestOnlyCapability()


def fail(message: str) -> None:
    raise SystemExit(f"PoCO G3 no-fault bundle collector failed: {message}")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            fail(f"duplicate JSON object name {key!r}")
        value[key] = child
    return value


def exact(value: object, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{field} keys must be exactly {sorted(keys)!r}")
    return value


def regular_file(raw: pathlib.Path | str, field: str) -> pathlib.Path:
    try:
        return assembler.require_regular_file(pathlib.Path(raw), field)
    except SystemExit as error:
        fail(str(error))


def real_directory(raw: pathlib.Path | str, field: str) -> pathlib.Path:
    path = pathlib.Path(raw).absolute()
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve {field}: {error}")
    if resolved != path or stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail(f"{field} must be one real, non-symlink directory")
    return path


def read_json(raw: pathlib.Path | str, field: str) -> dict[str, Any]:
    path = regular_file(raw, field)
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"{field} is not one exact UTF-8 JSON document: {error}")
    if not isinstance(value, dict):
        fail(f"{field} must be one JSON object")
    return value


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path: pathlib.Path) -> str:
    return assembler.sha256_file(regular_file(path, str(path)))


def positive_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"{field} must be a positive integer")
    return value


def nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(f"{field} must be a non-negative integer")
    return value


def positive_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{field} must be a finite positive number")
    result = float(value)
    if not math.isfinite(result) or result <= 0.0:
        fail(f"{field} must be a finite positive number")
    return result


def utc(value: object, field: str) -> datetime.datetime:
    if not isinstance(value, str) or RFC3339_UTC.fullmatch(value) is None:
        fail(f"{field} must be second-precision RFC3339 UTC")
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc
        )
    except ValueError:
        fail(f"{field} must be second-precision RFC3339 UTC")


def canonical_sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        fail(f"{field} must be canonical lowercase SHA-256")
    return value


def paths_overlap(left: pathlib.Path, right: pathlib.Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def validate_output_root(
    raw: pathlib.Path,
    field: str,
    *,
    input_roots: tuple[pathlib.Path, ...] = (),
) -> pathlib.Path:
    """Project one fresh output through only real, non-symlink ancestors."""

    output = pathlib.Path(raw).absolute()
    if output.exists() or output.is_symlink():
        fail(f"{field} already exists")
    for ancestor in output.parents:
        try:
            metadata = ancestor.lstat()
        except OSError as error:
            fail(f"cannot inspect {field} ancestor {ancestor}: {error}")
        if stat.S_ISLNK(metadata.st_mode):
            fail(f"{field} must not traverse a symbolic-link ancestor")
        if not stat.S_ISDIR(metadata.st_mode):
            fail(f"{field} ancestor must be a real directory")
        try:
            if ancestor.resolve(strict=True) != ancestor:
                fail(f"{field} must not traverse a substituted ancestor")
        except OSError as error:
            fail(f"cannot resolve {field} ancestor {ancestor}: {error}")

    source_root = assembler.SOURCE_ROOT.resolve(strict=True)
    if output == source_root or source_root in output.parents:
        fail(f"{field} must remain outside the source tree")
    for input_root in input_roots:
        resolved_input = input_root.resolve(strict=True)
        if paths_overlap(output, resolved_input):
            fail(f"{field} must remain disjoint from every input root")
    return output


def artifact_source(
    role: str,
    subject: str,
    source: pathlib.Path,
    destination: str,
) -> dict[str, str]:
    return {
        "role": role,
        "subject": subject,
        "source": regular_file(source, f"{role}[{subject or 'singleton'}]").as_posix(),
        "path": destination,
    }


def validate_build_report(
    path: pathlib.Path,
    *,
    candidate_source: pathlib.Path,
    linux_binary: pathlib.Path,
    macos_binary: pathlib.Path,
    material_builder_binary: pathlib.Path,
) -> dict[str, Any]:
    report = exact(
        read_json(path, "aggregate build report"),
        AGGREGATE_BUILD_REPORT_KEYS,
        "aggregate build report",
    )
    check_run_evidence.validate_source_provenance(
        report,
        "aggregate build report",
        fail_fn=fail,
    )
    source_sha256 = sha256_file(candidate_source)
    linux_sha256 = sha256_file(linux_binary)
    macos_sha256 = sha256_file(macos_binary)
    material_builder_sha256 = sha256_file(material_builder_binary)
    macos_builder_first = canonical_sha256(
        report["macos_material_builder_first_sha256"],
        "aggregate build report macOS material-builder hash",
    )
    macos_builder_second = canonical_sha256(
        report["macos_material_builder_second_sha256"],
        "aggregate build report macOS material-builder hash",
    )
    if (
        report["schema_version"] != 3
        or report["source_tree_sha256"] != source_sha256
        or report["linux_first_sha256"] != linux_sha256
        or report["linux_second_sha256"] != linux_sha256
        or report["linux_material_builder_first_sha256"]
        != material_builder_sha256
        or report["linux_material_builder_second_sha256"]
        != material_builder_sha256
        or report["macos_first_sha256"] != macos_sha256
        or report["macos_second_sha256"] != macos_sha256
        or macos_builder_first != macos_builder_second
        or macos_builder_first == "0" * 64
        or report["independent_build_roots"] is not True
        or report["production_activation"] is not False
        or material_builder_sha256
        in {source_sha256, linux_sha256, macos_sha256}
    ):
        fail("aggregate build report differs from the strict schema-3 candidate")
    return report


def validate_coordinator(
    root: pathlib.Path,
    validator_count: int,
    candidate_source: pathlib.Path,
    linux_binary: pathlib.Path,
    macos_binary: pathlib.Path,
    material_builder_binary: pathlib.Path,
) -> dict[str, Any]:
    manifest_path = root / "manifest.json"
    manifest = exact(read_json(manifest_path, "coordinator manifest"), COORDINATOR_KEYS, "coordinator manifest")
    if (
        manifest["schema_version"] != 2
        or manifest["validator_count"] != validator_count
        or manifest["network_scope"] != "single-lan"
        or manifest["geo_wan_evidence"] is not False
        or manifest["production_activation"] is not False
        or not isinstance(manifest["run_id"], str)
        or check_run_evidence.RUN_ID.fullmatch(manifest["run_id"]) is None
    ):
        fail("coordinator manifest crosses the frozen no-fault LAN identity")
    candidate = exact(
        manifest["candidate"],
        {"source_tree_sha256", "linux_x86_64_sha256", "macos_arm64_sha256"},
        "coordinator candidate",
    )
    material_author = exact(
        manifest["material_author"],
        {"binary_sha256", "runtime_deployed"},
        "coordinator material_author",
    )
    observed = {
        "source_tree_sha256": sha256_file(candidate_source),
        "linux_x86_64_sha256": sha256_file(linux_binary),
        "macos_arm64_sha256": sha256_file(macos_binary),
    }
    if candidate != observed:
        fail("candidate artifact bytes differ from the pre-run coordinator manifest")
    if (
        material_author["binary_sha256"] != sha256_file(material_builder_binary)
        or material_author["runtime_deployed"] is not False
    ):
        fail("material-author artifact differs or was runtime-deployed")

    validator_set = read_json(
        root / "public/validator-set.json", "coordinator validator set"
    )
    raw_validators = validator_set.get("validators")
    if not isinstance(raw_validators, list):
        fail("coordinator validator set validators must be a list")
    validator_ids = sorted(
        item.get("validator_id")
        for item in raw_validators
        if isinstance(item, dict) and isinstance(item.get("validator_id"), str)
    )
    if len(validator_ids) != validator_count or len(set(validator_ids)) != validator_count:
        fail("coordinator validator set cardinality differs from its manifest")
    expected_public_paths = {
        *evidence_profiles.COORDINATOR_PUBLIC_SINGLETON_PATHS.values(),
        *(f"public/configs/{validator_id}.json" for validator_id in validator_ids),
        "public/observer-configs/mac.json",
    }
    public_files = manifest["public_files"]
    if not isinstance(public_files, list):
        fail("coordinator public_files must be a list")
    public_by_path: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(public_files):
        reference = exact(
            raw,
            {"path", "sha256", "bytes"},
            f"coordinator public_files[{index}]",
        )
        relative = reference["path"]
        if not isinstance(relative, str) or not relative or "\\" in relative:
            fail("coordinator public file path must be one POSIX relative path")
        path = pathlib.PurePosixPath(relative)
        if path.is_absolute() or any(
            part in {"", ".", ".."} for part in path.parts
        ):
            fail("coordinator public file path escapes the run root")
        if relative in public_by_path:
            fail("coordinator public_files contains a duplicate path")
        canonical_sha256(
            reference["sha256"], f"coordinator public_files[{index}].sha256"
        )
        expected_bytes = positive_int(
            reference["bytes"], f"coordinator public_files[{index}].bytes"
        )
        source = regular_file(
            root.joinpath(*path.parts), f"coordinator public file {relative}"
        )
        if (
            source.stat().st_size != expected_bytes
            or sha256_file(source) != reference["sha256"]
        ):
            fail("coordinator public reference differs from its exact file bytes")
        public_by_path[relative] = reference
    if set(public_by_path) != expected_public_paths:
        fail(
            "coordinator public inventory must exactly cover topology, validator "
            "set, workload corpus/policy, five bootstrap files, validator configs, "
            "and the mac observer config"
        )
    return manifest


def require_observer_verification(
    value: object,
    *,
    field: str,
    status: str,
    run_id: str,
    validator_id: str,
    selected_id: bool = False,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{field} must be the macOS verifier result object")
    identity_field = "selected_validator_id" if selected_id else "validator_id"
    if (
        value.get("status") != status
        or value.get("run_id") != run_id
        or value.get(identity_field) != validator_id
        or value.get("signature_verified") is not True
        or value.get("semantics_verified") is not True
        or value.get("g3_evidence_complete") is not False
        or value.get("geo_wan_evidence") is not False
        or value.get("production_activation") is not False
    ):
        fail(f"{field} is not a successful, non-production macOS verification")
    return value


def signed_runner_sources(
    runner_root: pathlib.Path,
    validator_ids: set[str],
) -> dict[str, dict[str, pathlib.Path]]:
    layouts = {
        "validator_consensus_run_report": ("signed-reports", ".json"),
        "validator_runtime_event_journal": ("signed-runtime-journals", ".jsonl"),
        "validator_fleet_start_certificate": ("fleet-start-certificates", ".bin"),
        "validator_runtime_metrics": ("signed-runtime-metrics", ".json"),
        "validator_runtime_final_state": ("signed-runtime-final-states", ".json"),
        "validator_replay_archive_context": ("signed-replay-archive-contexts", ".json"),
        "validator_replay_archive_entries": ("signed-replay-archive-entries", ".jsonl"),
        "validator_replay_archive_head": ("signed-replay-archive-heads", ".json"),
        "validator_replay_archive_terminal_seal": (
            "signed-replay-archive-terminal-seals",
            ".json",
        ),
    }
    result: dict[str, dict[str, pathlib.Path]] = {}
    for role, (directory_name, suffix) in layouts.items():
        directory = real_directory(runner_root / directory_name, directory_name)
        expected_names = {f"{validator_id}{suffix}" for validator_id in validator_ids}
        try:
            observed_names = {item.name for item in directory.iterdir()}
        except OSError as error:
            fail(f"cannot enumerate {directory_name}: {error}")
        if observed_names != expected_names:
            fail(f"{directory_name} must contain exactly one artifact per validator")
        result[role] = {
            validator_id: regular_file(
                directory / f"{validator_id}{suffix}", f"{role}[{validator_id}]"
            )
            for validator_id in validator_ids
        }
    return result


def validate_mesh_preflight(
    value: object,
    *,
    validator_count: int,
    planned_hosts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    preflight = exact(value, MESH_PREFLIGHT_KEYS, "mesh resource preflight")
    resources = consensus_runner.mesh_resources
    peer_degree = 6 if validator_count == 7 else 8
    expected_threads = peer_degree * 2 + 1
    expected_socket_fds = peer_degree * 4 + 2
    expected_open_fds = expected_socket_fds + resources.PROCESS_FD_RESERVE
    expected_rss = (
        resources.BASE_PROCESS_RSS_BYTES
        + resources.GLOBAL_QUEUE_BYTES
        + expected_threads * resources.WORKER_STACK_BYTES
        + peer_degree * 2 * resources.FRAME_SCRATCH_BYTES
    )
    expected_coordinator_fds = (
        validator_count * 2 + resources.COORDINATOR_FD_RESERVE
    )
    if (
        preflight["schema_version"] != 1
        or preflight["profile"]
        != "poco-g3-mesh-host-resource-preflight-v1"
        or preflight["validator_count"] != validator_count
        or preflight["peer_degree"] != peer_degree
        or preflight["per_validator_threads"] != expected_threads
        or preflight["per_validator_socket_fds"] != expected_socket_fds
        or preflight["per_validator_open_file_fds"] != expected_open_fds
        or preflight["per_validator_rss_bytes"] != expected_rss
        or preflight["coordinator_capture_fds"] != expected_coordinator_fds
        or nonnegative_int(
            preflight["observed_epoch_spread_seconds"],
            "mesh preflight observed_epoch_spread_seconds",
        )
        > 30
        or preflight["capacity_passed"] is not True
        or preflight["validator_run_completed"] is not False
        or preflight["g3_lan_multihost_evidence"] is not False
        or preflight["geo_wan_evidence"] is not False
        or preflight["production_activation"] is not False
    ):
        fail("mesh resource preflight differs from the active runner contract")

    raw_hosts = preflight["hosts"]
    if not isinstance(raw_hosts, list) or len(raw_hosts) != len(planned_hosts):
        fail("mesh resource preflight host inventory differs")
    observed_hosts: set[str] = set()
    integer_fields = (
        "validator_processes",
        "cpu_threads",
        "memory_bytes",
        "memory_available_bytes",
        "uid_threads_observed",
        "system_threads_observed",
        "system_threads_max",
        "system_file_handles_allocated",
        "system_file_handles_max",
        "system_file_handles_available",
        "host_threads_required",
        "host_open_file_fds_required",
        "host_rss_bytes_required",
    )
    limit_fields = (
        "per_process_nofile_soft",
        "per_process_nofile_hard",
        "uid_nproc_soft",
        "uid_nproc_hard",
    )
    for index, raw_host in enumerate(raw_hosts):
        host = exact(raw_host, MESH_PREFLIGHT_HOST_KEYS, f"mesh preflight hosts[{index}]")
        host_id = host["host_id"]
        expected = planned_hosts.get(host_id) if isinstance(host_id, str) else None
        if expected is None or host_id in observed_hosts:
            fail("mesh resource preflight has a missing, duplicate, or foreign host")
        observed_hosts.add(host_id)
        if (
            host["management"] != expected["management"]
            or host["validator_processes"] != expected["validator_processes"]
            or not isinstance(host["hostname"], str)
            or not host["hostname"]
            or host["capacity_passed"] is not True
        ):
            fail(f"mesh resource preflight host {host_id} differs from placement")
        for field in integer_fields:
            positive_int(host[field], f"mesh preflight {host_id}.{field}")
        nonnegative_int(
            host["coordinator_capture_fds_required"],
            f"mesh preflight {host_id}.coordinator_capture_fds_required",
        )
        for field in limit_fields:
            limit = host[field]
            if not isinstance(limit, str) or (
                limit != "unlimited" and (not limit.isascii() or not limit.isdigit())
            ):
                fail(f"mesh preflight {host_id}.{field} is not one frozen limit")
        if (
            host["memory_available_bytes"] > host["memory_bytes"]
            or host["system_file_handles_allocated"]
            >= host["system_file_handles_max"]
            or host["system_file_handles_available"]
            != host["system_file_handles_max"]
            - host["system_file_handles_allocated"]
            or host["host_threads_required"]
            != expected_threads * expected["validator_processes"]
            or host["host_open_file_fds_required"]
            != expected_open_fds * expected["validator_processes"]
            or host["coordinator_capture_fds_required"]
            != (
                expected_coordinator_fds
                if expected["management"] == "local"
                else 0
            )
            or host["host_rss_bytes_required"]
            != expected_rss * expected["validator_processes"]
        ):
            fail(f"mesh resource preflight host {host_id} capacity arithmetic differs")
    if observed_hosts != set(planned_hosts):
        fail("mesh resource preflight host inventory differs")
    return preflight


def validate_prestart_plan(
    runner_root: pathlib.Path,
    coordinator_manifest: dict[str, Any],
    coordinator_anchor: str,
    validator_ids: set[str],
    validator_count: int,
) -> dict[str, Any]:
    plan = exact(
        read_json(runner_root / "prestart-plan.json", "runner prestart plan"),
        PRESTART_PLAN_KEYS,
        "runner prestart plan",
    )
    duration_seconds = positive_int(
        plan["duration_seconds"], "prestart duration_seconds"
    )
    max_blocks = positive_int(plan["max_blocks"], "prestart max_blocks")
    try:
        bounds = consensus_runner.validated_run_bounds(duration_seconds, max_blocks)
    except SystemExit as error:
        fail(f"runner prestart bounds are invalid: {error}")

    signer_lifetime = exact(
        plan["signer_lifetime"],
        PRESTART_SIGNER_LIFETIME_KEYS,
        "prestart signer_lifetime",
    )
    archive_lifetime = exact(
        plan["signed_replay_archive_lifetime"],
        PRESTART_ARCHIVE_LIFETIME_KEYS,
        "prestart signed_replay_archive_lifetime",
    )
    expected_signer_lifetime = {
        "journal_capacity": bounds["journal_capacity"],
        "maximum_timeout_view_advances": bounds[
            "maximum_timeout_view_advances"
        ],
        "maximum_local_vote_intents": bounds["maximum_local_vote_intents"],
        "maximum_local_timeout_intents": bounds[
            "maximum_local_timeout_intents"
        ],
        "maximum_total_intents": bounds["maximum_total_intents"],
    }
    expected_archive_lifetime = {
        "archive_capacity": bounds["signed_replay_archive_capacity"],
        "maximum_proposal_entries": bounds["maximum_proposal_archive_entries"],
        "maximum_quorum_certificate_entries": bounds[
            "maximum_quorum_certificate_archive_entries"
        ],
        "maximum_total_entries": bounds[
            "maximum_signed_replay_archive_entries"
        ],
    }
    constant_fields = {
        "commissioning_allowance_seconds": "commissioning_allowance_seconds",
        "fleet_launch_skew_allowance_seconds": (
            "fleet_launch_skew_allowance_seconds"
        ),
        "mesh_setup_allowance_seconds": "mesh_setup_allowance_seconds",
        "startup_allowance_seconds": "startup_allowance_seconds",
        "terminal_drain_allowance_seconds": "terminal_drain_allowance_seconds",
        "timeout_view_budget_allowance_seconds": (
            "timeout_view_budget_allowance_seconds"
        ),
        "process_completion_allowance_seconds": (
            "process_completion_allowance_seconds"
        ),
    }
    if (
        plan["schema_version"] != 1
        or plan["profile"] != "frozen-v0-continuous-consensus-candidate"
        or plan["evidence_profile"] != evidence_profiles.NO_FAULT_V1
        or plan["run_id"] != coordinator_manifest["run_id"]
        or plan["validator_count"] != validator_count
        or plan["observer_host_id"] != "mac"
        or plan["coordinator_manifest_sha256"] != coordinator_anchor
        or plan["runtime_topology_supported"] is not True
        or plan["transport"]
        != consensus_runner.runtime_transport_profile(validator_count)
        or signer_lifetime != expected_signer_lifetime
        or archive_lifetime != expected_archive_lifetime
        or any(plan[field] != bounds[bound] for field, bound in constant_fields.items())
        or plan["fleet_launch_skew_capacity_authority"] is not False
        or plan["requires_signed_terminal_evidence_chain_per_validator"] is not True
        or plan["requires_macos_independent_verification"] is not True
        or plan["requires_macos_full_fleet_certificate_verification"] is not True
        or plan["requires_macos_full_runtime_journal_replay"] is not True
        or plan["requires_post_success_replay_archive_export"] is not True
        or plan["requires_macos_full_replay_archive_verification"] is not True
        or plan["mesh_resource_preflight_required_before_effects"] is not True
        or plan["validator_run_completed"] is not False
        or plan["fault_matrix_completed"] is not False
        or plan["performance_evidence"] is not False
        or plan["g3_lan_multihost_evidence"] is not False
        or plan["geo_wan_evidence"] is not False
        or plan["production_activation"] is not False
    ):
        fail("runner prestart plan differs from the exact active runner contract")

    raw_validators = plan["validators"]
    if not isinstance(raw_validators, list) or len(raw_validators) != validator_count:
        fail("runner prestart plan validator inventory differs")
    planned_by_id: dict[str, dict[str, Any]] = {}
    planned_hosts: dict[str, dict[str, Any]] = {}
    for index, raw_validator in enumerate(raw_validators):
        validator = exact(
            raw_validator,
            PRESTART_VALIDATOR_KEYS,
            f"prestart validators[{index}]",
        )
        validator_id = validator["validator_id"]
        host_id = validator["host_id"]
        management = validator["management"]
        if (
            validator_id not in validator_ids
            or validator_id in planned_by_id
            or not isinstance(host_id, str)
            or not host_id
            or not isinstance(management, str)
            or not management
            or not isinstance(validator["deployment"], str)
            or not pathlib.Path(validator["deployment"]).is_absolute()
            or validator["config_relative"]
            != f"public/configs/{validator_id}.json"
        ):
            fail("runner prestart plan validator entry is not canonical")
        planned_by_id[validator_id] = validator
        host = planned_hosts.setdefault(
            host_id, {"management": management, "validator_processes": 0}
        )
        if host["management"] != management:
            fail("runner prestart plan has conflicting host management routes")
        host["validator_processes"] += 1
    if (
        set(planned_by_id) != validator_ids
        or len(planned_hosts) != 5
        or plan["linux_validator_host_count"] != len(planned_hosts)
        or sum(
            host["management"] == "local" for host in planned_hosts.values()
        )
        != 1
    ):
        fail("runner prestart plan physical host placement differs")
    validate_mesh_preflight(
        plan["mesh_resource_preflight"],
        validator_count=validator_count,
        planned_hosts=planned_hosts,
    )
    return plan


def validate_runner_output(
    runner_root: pathlib.Path,
    coordinator_manifest: dict[str, Any],
    coordinator_anchor: str,
    validator_ids: set[str],
    validator_count: int,
) -> tuple[dict[str, dict[str, pathlib.Path]], dict[str, Any], dict[str, Any]]:
    try:
        anchor_bytes = regular_file(
            runner_root / "coordinator-anchor.txt", "runner coordinator anchor"
        ).read_bytes()
    except OSError as error:
        fail(f"cannot read runner coordinator anchor: {error}")
    if anchor_bytes != f"{coordinator_anchor}\n".encode("ascii"):
        fail("runner coordinator anchor differs from the exact pre-run manifest bytes")

    plan = validate_prestart_plan(
        runner_root,
        coordinator_manifest,
        coordinator_anchor,
        validator_ids,
        validator_count,
    )
    planned_by_id = {
        item["validator_id"]: item for item in plan["validators"]
    }

    launch = exact(
        read_json(runner_root / "fleet-launch-observation.json", "fleet launch observation"),
        {
            "schema_version",
            "validator_count",
            "allowance_seconds",
            "observed_launch_skew_ns",
            "within_allowance",
        },
        "fleet launch observation",
    )
    if (
        launch["schema_version"] != 1
        or launch["validator_count"] != validator_count
        or positive_int(launch["allowance_seconds"], "launch allowance_seconds")
        != consensus_runner.FLEET_LAUNCH_SKEW_ALLOWANCE_SECONDS
        or launch["within_allowance"] is not True
    ):
        fail("fleet launch observation crosses its frozen bound")
    launch_skew = nonnegative_int(
        launch["observed_launch_skew_ns"], "observed_launch_skew_ns"
    )
    if launch_skew > launch["allowance_seconds"] * 1_000_000_000:
        fail("fleet launch observation exceeds its allowance")

    summary = exact(
        read_json(runner_root / "consensus-run-summary.json", "runner summary"),
        RUNNER_SUMMARY_KEYS,
        "runner summary",
    )
    count_fields = (
        "signed_report_count",
        "signed_runtime_journal_count",
        "fleet_start_certificate_count",
        "signed_runtime_metrics_count",
        "signed_runtime_final_state_count",
        "observer_verified_report_count",
        "observer_verified_journal_count",
        "observer_verified_fleet_start_certificate_count",
        "observer_verified_metrics_count",
        "observer_verified_final_state_count",
        "signed_replay_archive_set_count",
        "observer_verified_replay_archive_count",
    )
    if (
        summary["schema_version"] != 1
        or summary["profile"] != "frozen-v0-continuous-consensus-candidate"
        or summary["run_id"] != coordinator_manifest["run_id"]
        or summary["validator_count"] != validator_count
        or summary["transport"] != consensus_runner.runtime_transport_profile(validator_count)
        or any(summary[field] != validator_count for field in count_fields)
        or summary["all_six_hosts_participated"] is not False
        or positive_int(summary["elapsed_monotonic_ns"], "runner elapsed_monotonic_ns") <= 0
        or summary["observed_fleet_launch_skew_ns"] != launch_skew
        or summary["fleet_launch_skew_within_allowance"] is not True
        or summary["fleet_launch_skew_capacity_authority"] is not False
        or summary["coordinator_manifest_sha256"] != coordinator_anchor
        or summary["failure"] is not None
        or summary["cleanup_failures"] != []
        or summary["validator_run_completed"] is not False
        or summary["fault_matrix_completed"] is not False
        or summary["performance_evidence"] is not False
        or summary["g3_lan_multihost_evidence"] is not False
        or summary["geo_wan_evidence"] is not False
        or summary["production_activation"] is not False
        or not isinstance(summary["terminal_agreement"], dict)
        or not summary["terminal_agreement"]
    ):
        fail(
            "runner summary is not one successful no-fault execution with all "
            "evidence-completion claims false"
        )

    sources = signed_runner_sources(runner_root, validator_ids)
    processes = summary["processes"]
    if not isinstance(processes, list) or len(processes) != validator_count:
        fail("runner summary must contain exactly one process result per validator")
    process_by_id: dict[str, dict[str, Any]] = {}
    expected_hash_fields = {
        "signed_report_sha256": "validator_consensus_run_report",
        "signed_runtime_journal_sha256": "validator_runtime_event_journal",
        "fleet_start_certificate_sha256": "validator_fleet_start_certificate",
        "signed_runtime_metrics_sha256": "validator_runtime_metrics",
        "signed_runtime_final_state_sha256": "validator_runtime_final_state",
        "replay_archive_context_sha256": "validator_replay_archive_context",
        "replay_archive_entries_sha256": "validator_replay_archive_entries",
        "replay_archive_head_sha256": "validator_replay_archive_head",
        "replay_archive_terminal_seal_sha256": (
            "validator_replay_archive_terminal_seal"
        ),
    }
    statuses = {
        "observer_journal_verification": (
            "runtime-journal-signature-and-semantics-verified",
            False,
        ),
        "observer_fleet_start_certificate_verification": (
            "fleet-start-certificate-signature-and-semantics-verified",
            True,
        ),
        "observer_report_verification": (
            "consensus-run-report-signature-and-semantics-verified",
            False,
        ),
        "observer_metrics_verification": (
            "runtime-metrics-signature-and-semantics-verified",
            False,
        ),
        "observer_final_state_verification": (
            "runtime-final-state-signature-and-semantics-verified",
            False,
        ),
    }
    for index, raw in enumerate(processes):
        process = exact(raw, RUNNER_PROCESS_KEYS, f"runner processes[{index}]")
        validator_id = process["validator_id"]
        if validator_id not in validator_ids or validator_id in process_by_id:
            fail("runner process results have a missing, duplicate, or foreign validator")
        if process["host_id"] != planned_by_id[validator_id]["host_id"]:
            fail(f"runner process {validator_id} differs from its planned physical host")
        for hash_field, role in expected_hash_fields.items():
            if process[hash_field] != sha256_file(sources[role][validator_id]):
                fail(f"runner process {validator_id} {hash_field} differs from artifact bytes")
        for verification_field, (status, selected_id) in statuses.items():
            require_observer_verification(
                process[verification_field],
                field=f"runner process {validator_id} {verification_field}",
                status=status,
                run_id=summary["run_id"],
                validator_id=validator_id,
                selected_id=selected_id,
            )
        replay_artifact_facts = {
            "context": types.SimpleNamespace(
                path=sources["validator_replay_archive_context"][validator_id],
                sha256=process["replay_archive_context_sha256"],
                bytes=sources["validator_replay_archive_context"][validator_id]
                .stat()
                .st_size,
            ),
            "entries": types.SimpleNamespace(
                path=sources["validator_replay_archive_entries"][validator_id],
                sha256=process["replay_archive_entries_sha256"],
                bytes=sources["validator_replay_archive_entries"][validator_id]
                .stat()
                .st_size,
            ),
            "head": types.SimpleNamespace(
                path=sources["validator_replay_archive_head"][validator_id],
                sha256=process["replay_archive_head_sha256"],
                bytes=sources["validator_replay_archive_head"][validator_id]
                .stat()
                .st_size,
            ),
            "terminal_seal": types.SimpleNamespace(
                path=sources[
                    "validator_replay_archive_terminal_seal"
                ][validator_id],
                sha256=process["replay_archive_terminal_seal_sha256"],
                bytes=sources[
                    "validator_replay_archive_terminal_seal"
                ][validator_id]
                .stat()
                .st_size,
            ),
        }
        consensus_runner.exact_replay_archive_verified_summary_v1(
            process["observer_replay_archive_verification"],
            run_id=summary["run_id"],
            validator_id=validator_id,
            validator_ids=validator_ids,
            artifact_facts=replay_artifact_facts,
            certificate=process[
                "observer_fleet_start_certificate_verification"
            ],
            journal=process["observer_journal_verification"],
            final_state=process["observer_final_state_verification"],
            run_bounds=consensus_runner.validated_run_bounds(
                plan["duration_seconds"], plan["max_blocks"]
            ),
        )
        process_by_id[validator_id] = process
    if set(process_by_id) != validator_ids:
        fail("runner process result inventory differs from the validator set")
    consensus_runner.validate_runner_output_manifest(
        runner_root,
        expected_run_id=coordinator_manifest["run_id"],
        expected_validator_count=validator_count,
        expected_coordinator_anchor=coordinator_anchor,
    )
    return sources, plan, summary


def copied_artifact(
    root: pathlib.Path,
    records: list[dict[str, Any]],
    *,
    role: str,
    subject: str,
    source: pathlib.Path,
    relative: str,
) -> None:
    target = root.joinpath(*pathlib.PurePosixPath(relative).parts)
    reference = assembler.copy_exact(regular_file(source, f"{role}[{subject}]"), target)
    reference["path"] = relative
    records.append({"role": role, "subject": subject, **reference})


def verify_signed_inputs(
    coordinator_root: pathlib.Path,
    candidate_source: pathlib.Path,
    linux_binary: pathlib.Path,
    macos_binary: pathlib.Path,
    material_builder_binary: pathlib.Path,
    build_report: pathlib.Path,
    signed_sources: dict[str, dict[str, pathlib.Path]],
    validator_ids: set[str],
    run_id: str,
    validator_count: int,
    coordinator_anchor: str,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="poco-g3-no-fault-signed-view-") as raw:
        root = pathlib.Path(raw)
        records: list[dict[str, Any]] = []
        singleton_sources = [
            ("candidate_source", candidate_source, "candidate/source.artifact"),
            ("linux_binary", linux_binary, "candidate/linux.bin"),
            ("macos_binary", macos_binary, "candidate/macos.bin"),
            (
                "material_builder_binary",
                material_builder_binary,
                "candidate/material-builder-linux.bin",
            ),
            ("build_report", build_report, "candidate/build-report.json"),
            (
                "coordinator_manifest",
                coordinator_root / "manifest.json",
                "coordinator-manifest.json",
            ),
        ]
        singleton_sources.extend(
            (
                role,
                coordinator_root.joinpath(*pathlib.PurePosixPath(relative).parts),
                relative,
            )
            for role, relative in evidence_profiles.COORDINATOR_PUBLIC_SINGLETON_PATHS.items()
        )
        for role, source, relative in singleton_sources:
            copied_artifact(
                root,
                records,
                role=role,
                subject="",
                source=source,
                relative=relative,
            )
        copied_artifact(
            root,
            records,
            role="observer_config",
            subject="mac",
            source=coordinator_root / "public/observer-configs/mac.json",
            relative="observer/mac/config.json",
        )
        for validator_id in sorted(validator_ids):
            copied_artifact(
                root,
                records,
                role="validator_config",
                subject=validator_id,
                source=coordinator_root / f"public/configs/{validator_id}.json",
                relative=f"validators/{validator_id}/config.json",
            )
            for role, suffix in (
                ("validator_fleet_start_certificate", "fleet-start-certificate.bin"),
                ("validator_runtime_event_journal", "runtime-events.jsonl"),
                ("validator_consensus_run_report", "consensus-report.json"),
                ("validator_runtime_metrics", "runtime-metrics.json"),
                ("validator_runtime_final_state", "runtime-final-state.json"),
            ):
                copied_artifact(
                    root,
                    records,
                    role=role,
                    subject=validator_id,
                    source=signed_sources[role][validator_id],
                    relative=f"validators/{validator_id}/signed/{suffix}",
                )
        manifest = {
            "schema_version": 1,
            "evidence_profile": PROFILE,
            "run_id": run_id,
            "validator_count": validator_count,
            "network_scope": "single-lan",
            "geo_wan_evidence": False,
            "artifacts": records,
        }
        assembler.write_new(root / "manifest.json", canonical_json(manifest))
        return check_signed_runtime_evidence.validate(
            root,
            validator_count,
            coordinator_anchor,
            profile=PROFILE,
            emit=False,
        )


def validate_observer_report(
    path: pathlib.Path,
    *,
    run_id: str,
    validator_count: int,
    observer_config_sha256: str,
    macos_binary_sha256: str,
    submitted_count: int,
    started_at: str,
    ended_at: str,
) -> dict[str, Any]:
    report = exact(read_json(path, "macOS observer/load report"), OBSERVER_REPORT_KEYS, "macOS observer/load report")
    if (
        report["schema_version"] != 1
        or report["run_id"] != run_id
        or report["host_id"] != "mac"
        or report["config_sha256"] != observer_config_sha256
        or report["binary_sha256"] != macos_binary_sha256
    ):
        fail("macOS observer/load report differs from its run/config/binary")
    positive_int(report["process_id"], "observer report process_id")
    load_count = positive_int(
        report["load_submitted_nonempty_blocks"],
        "observer report load_submitted_nonempty_blocks",
    )
    if load_count != submitted_count:
        fail("observer workload count differs from all validator-signed reports")
    if positive_int(
        report["verified_qc_signatures"], "observer report verified_qc_signatures"
    ) < validator_count:
        fail("observer report verified fewer QC signatures than validators")
    positive_int(
        report["rejected_invalid_signature_controls"],
        "observer report rejected_invalid_signature_controls",
    )
    start = utc(report["started_at"], "observer report started_at")
    end = utc(report["ended_at"], "observer report ended_at")
    if start >= end:
        fail("observer report external time window is empty")
    if report["started_at"] != started_at or report["ended_at"] != ended_at:
        fail("observer report external time window differs from signed metrics")
    return report


def nearest_rank(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def derive_documents(
    *,
    coordinator_root: pathlib.Path,
    coordinator: dict[str, Any],
    candidate_source: pathlib.Path,
    linux_binary: pathlib.Path,
    macos_binary: pathlib.Path,
    build_report: dict[str, Any],
    observer_report_path: pathlib.Path,
    signed_runtime: dict[str, Any],
    prestart_plan: dict[str, Any],
    runner_summary: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    run_id = coordinator["run_id"]
    validator_count = coordinator["validator_count"]
    topology = read_json(coordinator_root / "topology.json", "topology")
    signed_validators: dict[str, dict[str, Any]] = signed_runtime["validators"]
    validator_ids = sorted(signed_validators)

    report_counts = {
        (
            value["report"]["submitted_ordinary_block_count"],
            value["report"]["committed_ordinary_block_count"],
            value["report"]["finalized_ordinary_block_count"],
        )
        for value in signed_validators.values()
    }
    if len(report_counts) != 1:
        fail("validator-signed reports disagree on workload counts")
    submitted_count, committed_count, finalized_count = next(iter(report_counts))
    positive_int(submitted_count, "signed submitted ordinary block count")
    positive_int(committed_count, "signed committed ordinary block count")
    positive_int(finalized_count, "signed finalized ordinary block count")

    intervals = {
        (
            value["metrics"]["measurement_started_at"],
            value["metrics"]["measurement_ended_at"],
        )
        for value in signed_validators.values()
    }
    if len(intervals) != 1:
        fail("validator-signed metrics do not share one external time window")
    started_at, ended_at = next(iter(intervals))
    started = utc(started_at, "signed metrics measurement_started_at")
    ended = utc(ended_at, "signed metrics measurement_ended_at")
    if started >= ended:
        fail("validator-signed external time window is empty")
    measurement_seconds = int((ended - started).total_seconds())
    positive_int(measurement_seconds, "measurement_seconds")

    requested_bounds = {
        (
            value["report"]["requested_duration_seconds"],
            value["report"]["requested_max_blocks"],
        )
        for value in signed_validators.values()
    }
    if requested_bounds != {
        (prestart_plan["duration_seconds"], prestart_plan["max_blocks"])
    }:
        fail("validator-signed requested bounds differ from the prestart plan")

    observer_config_path = coordinator_root / "public/observer-configs/mac.json"
    observer_config_sha256 = sha256_file(observer_config_path)
    observer_report = validate_observer_report(
        observer_report_path,
        run_id=run_id,
        validator_count=validator_count,
        observer_config_sha256=observer_config_sha256,
        macos_binary_sha256=sha256_file(macos_binary),
        submitted_count=submitted_count,
        started_at=started_at,
        ended_at=ended_at,
    )

    raw_events: dict[str, list[dict[str, Any]]] = {}
    raw_metrics: dict[str, dict[str, Any]] = {}
    raw_final_states: dict[str, dict[str, Any]] = {}
    derived_validators: list[dict[str, Any]] = []
    finality_samples: list[float] = []
    cpu_seconds = 0.0
    peak_rss_bytes = 0
    disk_bytes = 0
    fsync_count = 0
    network_tx_bytes = 0
    network_rx_bytes = 0
    ordinary_starts: set[int] = set()
    tips: set[tuple[int, str, str, str]] = set()
    submission_owner = validator_ids[0]

    for validator_id in validator_ids:
        signed = signed_validators[validator_id]
        report = signed["report"]
        metrics = signed["metrics"]
        final_state = signed["final_state"]
        config_path = coordinator_root / f"public/configs/{validator_id}.json"
        config = read_json(config_path, f"validator config[{validator_id}]")
        if (
            config.get("run_id") != run_id
            or config.get("validator_id") != validator_id
            or config.get("production_activation") is not False
        ):
            fail(f"validator config[{validator_id}] identity differs")
        ordinary_starts.add(final_state["ordinary_start_height"])
        tips.add(
            (
                final_state["finalized_height"],
                final_state["finalized_block_id"],
                final_state["finalized_state_root"],
                final_state["finalized_chain_root"],
            )
        )
        process_id = positive_int(final_state["process_id"], f"signed PID[{validator_id}]")
        derived_validators.append(
            {
                "validator_id": validator_id,
                "host_id": config["host_id"],
                "lan_ip": config["lan_ip"],
                "p2p_port": config["p2p_port"],
                "metrics_port": config["metrics_port"],
                "weight": config["weight"],
                "process_id": process_id,
                "binary_sha256": config["binary_sha256"],
                "config_sha256": sha256_file(config_path),
            }
        )
        events = [
            {
                "schema_version": 1,
                "run_id": run_id,
                "validator_id": validator_id,
                "sequence": 0,
                "observed_at": started_at,
                "kind": "process_start",
                "subject": "instance-1",
                "value": process_id,
            }
        ]
        if validator_id == submission_owner:
            events.append(
                {
                    "schema_version": 1,
                    "run_id": run_id,
                    "validator_id": validator_id,
                    "sequence": len(events),
                    "observed_at": observer_report["started_at"],
                    "kind": "submitted_nonempty_blocks",
                    "subject": "",
                    "value": submitted_count,
                }
            )
        events.append(
            {
                "schema_version": 1,
                "run_id": run_id,
                "validator_id": validator_id,
                "sequence": len(events),
                "observed_at": ended_at,
                "kind": "finalized_tip",
                "subject": ":".join(
                    (
                        final_state["finalized_block_id"],
                        final_state["finalized_state_root"],
                        final_state["finalized_chain_root"],
                    )
                ),
                "value": final_state["finalized_height"],
            }
        )
        raw_events[validator_id] = events
        raw_metrics[validator_id] = {
            "schema_version": 1,
            "run_id": run_id,
            "validator_id": validator_id,
            "measurement_started_at": metrics["measurement_started_at"],
            "measurement_ended_at": metrics["measurement_ended_at"],
            "finality_samples_ms": metrics["finality_samples_ms"],
            "cpu_seconds": metrics["cpu_seconds"],
            "peak_rss_bytes": metrics["peak_rss_bytes"],
            "disk_bytes": metrics["disk_bytes"],
            "fsync_count": metrics["fsync_count"],
            "network_tx_bytes": metrics["network_tx_bytes"],
            "network_rx_bytes": metrics["network_rx_bytes"],
        }
        raw_final_states[validator_id] = {
            "schema_version": 2,
            "run_id": run_id,
            "validator_id": validator_id,
            "process_id": process_id,
            "process_instance_count": final_state["process_instance_count"],
            "ordinary_start_height": final_state["ordinary_start_height"],
            "finalized_height": final_state["finalized_height"],
            "finalized_ordinary_block_count": final_state[
                "finalized_ordinary_block_count"
            ],
            "finalized_block_id": final_state["finalized_block_id"],
            "finalized_state_root": final_state["finalized_state_root"],
            "finalized_chain_root": final_state["finalized_chain_root"],
            "applied_height": final_state["applied_height"],
            "all_finalized_ordinary_blocks_nonempty": final_state[
                "finalized_nonempty_ordinary_block_count"
            ]
            == final_state["finalized_ordinary_block_count"],
            "double_sign_events": final_state["double_sign_events"],
            "duplicate_apply_events": final_state["duplicate_apply_events"],
            "state_drift_events": final_state["state_drift_events"],
            "safety_halt_violations": final_state["safety_halt_violations"],
        }
        finality_samples.extend(
            positive_number(value, f"finality sample[{validator_id}]")
            for value in metrics["finality_samples_ms"]
        )
        cpu_seconds += positive_number(metrics["cpu_seconds"], "signed cpu_seconds")
        peak_rss_bytes = max(
            peak_rss_bytes,
            positive_int(metrics["peak_rss_bytes"], "signed peak_rss_bytes"),
        )
        disk_bytes += positive_int(metrics["disk_bytes"], "signed disk_bytes")
        fsync_count += positive_int(metrics["fsync_count"], "signed fsync_count")
        network_tx_bytes += positive_int(
            metrics["network_tx_bytes"], "signed network_tx_bytes"
        )
        network_rx_bytes += positive_int(
            metrics["network_rx_bytes"], "signed network_rx_bytes"
        )

    if len(ordinary_starts) != 1 or len(tips) != 1:
        fail("validator-signed ordinary start or final tip does not agree")
    ordinary_start = next(iter(ordinary_starts))
    finalized_height, final_block, final_state_root, final_chain_root = next(iter(tips))
    if (
        finalized_height - ordinary_start + 1 != finalized_count
        or committed_count != finalized_count
    ):
        fail("signed committed/finalized workload does not map to the terminal height")
    if not raw_final_states or any(
        value["all_finalized_ordinary_blocks_nonempty"] is not True
        for value in raw_final_states.values()
    ):
        fail("signed final states do not prove a non-empty workload")

    terminal = runner_summary["terminal_agreement"]
    terminal_expected = {
        "finalized_height": finalized_height,
        "finalized_ordinary_block_count": finalized_count,
        "finalized_block_id": final_block,
        "finalized_state_root": final_state_root,
        "finalized_chain_root": final_chain_root,
        "fleet_start_certificate_sha256": signed_runtime[
            "fleet_start_certificate_sha256"
        ],
    }
    if any(terminal.get(key) != value for key, value in terminal_expected.items()):
        fail("runner terminal agreement differs from independently verified signed facts")

    validators_by_host: dict[str, list[dict[str, Any]]] = {}
    for validator in derived_validators:
        validators_by_host.setdefault(validator["host_id"], []).append(validator)
    participants: list[dict[str, Any]] = []
    planned_participants = topology.get("participants")
    if not isinstance(planned_participants, list):
        fail("topology omits the six physical participants")
    for plan in sorted(planned_participants, key=lambda item: item.get("host_id", "")):
        host_id = plan.get("host_id")
        if host_id == "mac":
            participants.append(
                {
                    "host_id": "mac",
                    "lan_ip": plan["lan_ip"],
                    "run_roles": plan["run_roles"],
                    "process_ids": [observer_report["process_id"]],
                    "binary_sha256": sha256_file(macos_binary),
                    "config_set_sha256": check_run_evidence.observer_configuration_set_digest(
                        observer_config_sha256
                    ),
                }
            )
            continue
        hosted = validators_by_host.get(host_id, [])
        if not hosted:
            fail(f"validator host {host_id!r} has no signed process")
        participants.append(
            {
                "host_id": host_id,
                "lan_ip": plan["lan_ip"],
                "run_roles": plan["run_roles"],
                "process_ids": sorted(item["process_id"] for item in hosted),
                "binary_sha256": sha256_file(linux_binary),
                "config_set_sha256": check_run_evidence.host_validator_configuration_set_digest(
                    hosted
                ),
            }
        )

    safety_fields = (
        "double_sign_events",
        "duplicate_apply_events",
        "state_drift_events",
        "safety_halt_violations",
    )
    safety_counts = {
        field: sum(value[field] for value in raw_final_states.values())
        for field in safety_fields
    }
    summary = {
        "schema_version": 3,
        "evidence_profile": PROFILE,
        "run_id": run_id,
        "fleet_id": coordinator["fleet_id"],
        "candidate": {
            "source_tree_sha256": sha256_file(candidate_source),
            **{
                field: build_report[field]
                for field in check_run_evidence.SOURCE_PROVENANCE_KEYS
            },
            "linux_x86_64_sha256": sha256_file(linux_binary),
            "macos_arm64_sha256": sha256_file(macos_binary),
            "configuration_set_sha256": check_run_evidence.configuration_set_digest(
                derived_validators
            ),
            "reproducible_build": True,
            "production_activation": False,
        },
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "validator_run_completed": True,
        "topology": {
            "validator_count": validator_count,
            "weight_profile": topology["weight_profile"],
            "peer_degree": topology["peer_degree"],
            "ephemeral_test_keys": True,
        },
        "started_at": started_at,
        "ended_at": ended_at,
        "validators": sorted(derived_validators, key=lambda item: item["validator_id"]),
        "participants": participants,
        "consensus": {
            "ordinary_start_height": ordinary_start,
            "submitted_nonempty_blocks": submitted_count,
            "committed_nonempty_blocks": committed_count,
            "finalized_height": finalized_height,
            "state_root_agreement": True,
            **safety_counts,
            "restart_catchup_passed": False,
            "heal_convergence_passed": False,
        },
        "faults": [],
        "performance": {
            "measurement_seconds": measurement_seconds,
            "committed_goodput_tps": committed_count / measurement_seconds,
            "finality_ms_p50": nearest_rank(finality_samples, 0.50),
            "finality_ms_p95": nearest_rank(finality_samples, 0.95),
            "finality_ms_p99": nearest_rank(finality_samples, 0.99),
            "cpu_seconds": cpu_seconds,
            "peak_rss_bytes": peak_rss_bytes,
            "disk_bytes": disk_bytes,
            "fsync_count": fsync_count,
            "network_tx_bytes": network_tx_bytes,
            "network_rx_bytes": network_rx_bytes,
        },
    }
    return summary, raw_events, raw_metrics, raw_final_states


def write_collector_inputs(
    *,
    root: pathlib.Path,
    summary: dict[str, Any],
    raw_events: dict[str, list[dict[str, Any]]],
    raw_metrics: dict[str, dict[str, Any]],
    raw_final_states: dict[str, dict[str, Any]],
    observer_report_source: pathlib.Path,
) -> dict[str, pathlib.Path]:
    paths: dict[str, pathlib.Path] = {}
    summary_path = root / "completed-run-summary.json"
    assembler.write_new(summary_path, canonical_json(summary))
    paths["summary"] = summary_path
    observer_target = root / "observer/mac/report.json"
    assembler.copy_exact(regular_file(observer_report_source, "observer report"), observer_target)
    paths["observer_report"] = observer_target
    for validator_id in sorted(raw_events):
        validator_root = root / "validators" / validator_id
        events_path = validator_root / "events.jsonl"
        event_bytes = b"".join(canonical_json(event) + b"\n" for event in raw_events[validator_id])
        assembler.write_new(events_path, event_bytes)
        metrics_path = validator_root / "metrics.json"
        assembler.write_new(metrics_path, canonical_json(raw_metrics[validator_id]))
        final_path = validator_root / "final-state.json"
        assembler.write_new(final_path, canonical_json(raw_final_states[validator_id]))
        paths[f"events:{validator_id}"] = events_path
        paths[f"metrics:{validator_id}"] = metrics_path
        paths[f"final:{validator_id}"] = final_path
    return paths


def assembly_spec(
    *,
    summary: dict[str, Any],
    generated: dict[str, pathlib.Path],
    coordinator_root: pathlib.Path,
    candidate_source: pathlib.Path,
    linux_binary: pathlib.Path,
    macos_binary: pathlib.Path,
    material_builder_binary: pathlib.Path,
    build_report: pathlib.Path,
    signed_sources: dict[str, dict[str, pathlib.Path]],
) -> dict[str, Any]:
    artifacts = [
        artifact_source("candidate_source", "", candidate_source, "candidate/source.artifact"),
        artifact_source("linux_binary", "", linux_binary, "candidate/linux.bin"),
        artifact_source("macos_binary", "", macos_binary, "candidate/macos.bin"),
        artifact_source(
            "material_builder_binary",
            "",
            material_builder_binary,
            "candidate/material-builder-linux.bin",
        ),
        artifact_source("build_report", "", build_report, "candidate/build-report.json"),
        artifact_source(
            "coordinator_manifest",
            "",
            coordinator_root / "manifest.json",
            "coordinator-manifest.json",
        ),
        artifact_source(
            "observer_config",
            "mac",
            coordinator_root / "public/observer-configs/mac.json",
            "observer/mac/config.json",
        ),
        artifact_source(
            "observer_report",
            "mac",
            generated["observer_report"],
            "observer/mac/report.json",
        ),
    ]
    artifacts.extend(
        artifact_source(
            role,
            "",
            coordinator_root.joinpath(*pathlib.PurePosixPath(relative).parts),
            relative,
        )
        for role, relative in evidence_profiles.COORDINATOR_PUBLIC_SINGLETON_PATHS.items()
    )
    for validator in summary["validators"]:
        validator_id = validator["validator_id"]
        artifacts.extend(
            (
                artifact_source(
                    "validator_config",
                    validator_id,
                    coordinator_root / f"public/configs/{validator_id}.json",
                    f"validators/{validator_id}/config.json",
                ),
                artifact_source(
                    "validator_event_log",
                    validator_id,
                    generated[f"events:{validator_id}"],
                    f"validators/{validator_id}/events.jsonl",
                ),
                artifact_source(
                    "validator_metrics",
                    validator_id,
                    generated[f"metrics:{validator_id}"],
                    f"validators/{validator_id}/metrics.json",
                ),
                artifact_source(
                    "validator_final_state",
                    validator_id,
                    generated[f"final:{validator_id}"],
                    f"validators/{validator_id}/final-state.json",
                ),
            )
        )
        for role, name in (
            ("validator_fleet_start_certificate", "fleet-start-certificate.bin"),
            ("validator_runtime_event_journal", "runtime-events.jsonl"),
            ("validator_consensus_run_report", "consensus-report.json"),
            ("validator_runtime_metrics", "runtime-metrics.json"),
            ("validator_runtime_final_state", "runtime-final-state.json"),
        ):
            artifacts.append(
                artifact_source(
                    role,
                    validator_id,
                    signed_sources[role][validator_id],
                    f"validators/{validator_id}/signed/{name}",
                )
            )
    return {
        "schema_version": 1,
        "evidence_profile": PROFILE,
        "run_id": summary["run_id"],
        "validator_count": summary["topology"]["validator_count"],
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "completed_run_summary": {
            "source": generated["summary"].as_posix(),
            "path": "completed-run-summary.json",
        },
        "artifacts": artifacts,
    }


def validate_collection_envelope(
    *,
    coordinator_root: pathlib.Path,
    runner_output: pathlib.Path,
    validator_count: int,
    coordinator_manifest_sha256: str,
    candidate_source: pathlib.Path,
    linux_binary: pathlib.Path,
    macos_binary: pathlib.Path,
    material_builder_binary: pathlib.Path,
    build_report: pathlib.Path,
    observer_report: pathlib.Path,
    collector_output: pathlib.Path,
    bundle_output: pathlib.Path,
    require_observer_report: bool,
) -> dict[str, Any]:
    if validator_count not in VALID_COUNTS:
        fail("validator count must be 7, 31, or 100")
    independent_anchor = canonical_sha256(
        coordinator_manifest_sha256, "independent coordinator manifest anchor"
    )
    coordinator_root = real_directory(coordinator_root, "coordinator root")
    runner_output = real_directory(runner_output, "runner output")
    candidate_source = regular_file(candidate_source, "candidate source artifact")
    linux_binary = regular_file(linux_binary, "Linux candidate binary")
    macos_binary = regular_file(macos_binary, "macOS candidate binary")
    material_builder_binary = regular_file(
        material_builder_binary, "material-builder binary"
    )
    build_report = regular_file(build_report, "aggregate build report")
    build_report_document = validate_build_report(
        build_report,
        candidate_source=candidate_source,
        linux_binary=linux_binary,
        macos_binary=macos_binary,
        material_builder_binary=material_builder_binary,
    )
    if require_observer_report:
        observer_report = regular_file(observer_report, "macOS observer/load report")
    else:
        observer_report = pathlib.Path(observer_report).absolute()
        if observer_report.is_symlink():
            fail("proposed macOS observer/load report must not be a symbolic link")
        if observer_report.exists():
            observer_report = regular_file(
                observer_report, "proposed macOS observer/load report"
            )
    input_roots = (coordinator_root, runner_output)
    collector_root = validate_output_root(
        collector_output, "collector output", input_roots=input_roots
    )
    bundle_root = validate_output_root(
        bundle_output, "bundle output", input_roots=input_roots
    )
    if paths_overlap(collector_root, bundle_root):
        fail("collector output and bundle output must be disjoint")

    coordinator_anchor = sha256_file(coordinator_root / "manifest.json")
    if coordinator_anchor != independent_anchor:
        fail("current coordinator manifest differs from the independent pre-run anchor")
    coordinator = validate_coordinator(
        coordinator_root,
        validator_count,
        candidate_source,
        linux_binary,
        macos_binary,
        material_builder_binary,
    )
    validator_set = read_json(
        coordinator_root / "public/validator-set.json", "validator set"
    )
    raw_validator_set = validator_set.get("validators")
    if not isinstance(raw_validator_set, list):
        fail("validator set validators must be a list")
    validator_ids = {
        item.get("validator_id") for item in raw_validator_set if isinstance(item, dict)
    }
    if (
        len(validator_ids) != validator_count
        or any(not isinstance(value, str) or HEX64.fullmatch(value) is None for value in validator_ids)
    ):
        fail("validator set inventory differs from the requested cardinality")
    typed_validator_ids = {str(value) for value in validator_ids}
    signed_sources, prestart_plan, runner_summary = validate_runner_output(
        runner_output,
        coordinator,
        coordinator_anchor,
        typed_validator_ids,
        validator_count,
    )
    return {
        "coordinator_root": coordinator_root,
        "runner_output": runner_output,
        "candidate_source": candidate_source,
        "linux_binary": linux_binary,
        "macos_binary": macos_binary,
        "material_builder_binary": material_builder_binary,
        "build_report": build_report,
        "build_report_document": build_report_document,
        "observer_report": observer_report,
        "collector_root": collector_root,
        "bundle_root": bundle_root,
        "coordinator": coordinator,
        "coordinator_anchor": coordinator_anchor,
        "validator_ids": typed_validator_ids,
        "signed_sources": signed_sources,
        "prestart_plan": prestart_plan,
        "runner_summary": runner_summary,
    }


def plan_only(*, profile: str = PROFILE, **arguments: Any) -> dict[str, Any]:
    """Read-only envelope validation for the only production-supported mode."""

    try:
        selected_profile = evidence_profiles.require_known(profile)
    except ValueError as error:
        fail(str(error))
    if selected_profile not in PLANNABLE_PROFILES:
        fail("the no-fault collector does not plan mixed-authority fault profiles")
    envelope = validate_collection_envelope(
        **arguments, require_observer_report=False
    )
    blockers = list(
        evidence_profiles.authority_blockers(
            evidence_profiles.NO_FAULT_SIGNED_RUNTIME_OBSERVER_V1
            if selected_profile == PROFILE
            else selected_profile
        )
    )
    return {
        "schema_version": 1,
        "profile": selected_profile,
        "run_id": envelope["coordinator"]["run_id"],
        "validator_count": envelope["coordinator"]["validator_count"],
        "coordinator_manifest_sha256": envelope["coordinator_anchor"],
        "mode": "plan-only",
        "active_campaign_supported": False,
        "outputs_created": False,
        "blockers": blockers,
        "g3_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }


def collect(
    *,
    coordinator_root: pathlib.Path,
    runner_output: pathlib.Path,
    validator_count: int,
    coordinator_manifest_sha256: str,
    candidate_source: pathlib.Path,
    linux_binary: pathlib.Path,
    macos_binary: pathlib.Path,
    material_builder_binary: pathlib.Path,
    build_report: pathlib.Path,
    observer_report: pathlib.Path,
    collector_output: pathlib.Path,
    bundle_output: pathlib.Path,
    profile: str = PROFILE,
    fixture_test_only: object | None = None,
) -> tuple[pathlib.Path, pathlib.Path]:
    """Exercise obsolete projection schemas under the private fixture capability."""

    try:
        selected_profile = evidence_profiles.require_known(profile)
    except ValueError as error:
        fail(str(error))
    if selected_profile != PROFILE:
        fail(
            f"{selected_profile} is plan-only and cannot collect: "
            + ", ".join(evidence_profiles.authority_blockers(selected_profile))
        )
    if fixture_test_only is not _FIXTURE_TEST_ONLY_CAPABILITY:
        fail(
            "active collection is unavailable; production mode is plan-only until "
            "the real macOS observer producer, signed-runtime-only profile, and "
            "content-addressed per-host provenance producer exists"
        )
    envelope = validate_collection_envelope(
        coordinator_root=coordinator_root,
        runner_output=runner_output,
        validator_count=validator_count,
        coordinator_manifest_sha256=coordinator_manifest_sha256,
        candidate_source=candidate_source,
        linux_binary=linux_binary,
        macos_binary=macos_binary,
        material_builder_binary=material_builder_binary,
        build_report=build_report,
        observer_report=observer_report,
        collector_output=collector_output,
        bundle_output=bundle_output,
        require_observer_report=True,
    )
    coordinator_root = envelope["coordinator_root"]
    candidate_source = envelope["candidate_source"]
    linux_binary = envelope["linux_binary"]
    macos_binary = envelope["macos_binary"]
    material_builder_binary = envelope["material_builder_binary"]
    build_report = envelope["build_report"]
    build_report_document = envelope["build_report_document"]
    observer_report = envelope["observer_report"]
    collector_root = envelope["collector_root"]
    bundle_root = envelope["bundle_root"]
    coordinator = envelope["coordinator"]
    coordinator_anchor = envelope["coordinator_anchor"]
    typed_validator_ids = envelope["validator_ids"]
    signed_sources = envelope["signed_sources"]
    prestart_plan = envelope["prestart_plan"]
    runner_summary = envelope["runner_summary"]
    signed_runtime = verify_signed_inputs(
        coordinator_root,
        candidate_source,
        linux_binary,
        macos_binary,
        material_builder_binary,
        build_report,
        signed_sources,
        typed_validator_ids,
        coordinator["run_id"],
        validator_count,
        coordinator_anchor,
    )
    summary, raw_events, raw_metrics, raw_final_states = derive_documents(
        coordinator_root=coordinator_root,
        coordinator=coordinator,
        candidate_source=candidate_source,
        linux_binary=linux_binary,
        macos_binary=macos_binary,
        build_report=build_report_document,
        observer_report_path=observer_report,
        signed_runtime=signed_runtime,
        prestart_plan=prestart_plan,
        runner_summary=runner_summary,
    )

    collector_root.mkdir(parents=True, mode=0o700)
    collector_root.chmod(0o700)
    try:
        generated = write_collector_inputs(
            root=collector_root,
            summary=summary,
            raw_events=raw_events,
            raw_metrics=raw_metrics,
            raw_final_states=raw_final_states,
            observer_report_source=observer_report,
        )
        spec = assembly_spec(
            summary=summary,
            generated=generated,
            coordinator_root=coordinator_root,
            candidate_source=candidate_source,
            linux_binary=linux_binary,
            macos_binary=macos_binary,
            material_builder_binary=material_builder_binary,
            build_report=build_report,
            signed_sources=signed_sources,
        )
        spec_path = collector_root / "assembly-spec.json"
        assembler.write_new(spec_path, canonical_json(spec))
        normalized = assembler.normalize_spec(spec_path, profile=PROFILE)
        assembler.assemble(normalized, bundle_root, coordinator_anchor)
    except BaseException:
        shutil.rmtree(collector_root, ignore_errors=True)
        raise
    return collector_root, bundle_root


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only plan validation for the unavailable no-fault runner-to-bundle "
            "bridge; this CLI never assembles evidence"
        )
    )
    parser.add_argument("coordinator_root", type=pathlib.Path)
    parser.add_argument("runner_output", type=pathlib.Path)
    parser.add_argument("--validators", required=True, type=int, choices=(7, 31, 100))
    parser.add_argument(
        "--profile",
        default=PROFILE,
        choices=sorted(PLANNABLE_PROFILES),
        help="known no-fault contract to inspect; every production path is plan-only",
    )
    parser.add_argument("--coordinator-manifest-sha256", required=True)
    parser.add_argument("--candidate-source", required=True, type=pathlib.Path)
    parser.add_argument("--linux-binary", required=True, type=pathlib.Path)
    parser.add_argument("--macos-binary", required=True, type=pathlib.Path)
    parser.add_argument("--material-builder-binary", required=True, type=pathlib.Path)
    parser.add_argument("--build-report", required=True, type=pathlib.Path)
    parser.add_argument(
        "--observer-report",
        required=True,
        type=pathlib.Path,
        help=(
            "proposed external observer-report path; no real authenticated producer "
            "is wired yet and plan-only mode never treats it as authority"
        ),
    )
    parser.add_argument("--collector-output", required=True, type=pathlib.Path)
    parser.add_argument("--bundle-output", required=True, type=pathlib.Path)
    parser.add_argument(
        "--plan-only",
        action="store_true",
        default=True,
        help="the only supported mode; it is also the default and creates no outputs",
    )
    args = parser.parse_args()
    if args.plan_only is not True:
        fail("the collector CLI supports plan-only mode exclusively")
    plan = plan_only(
        profile=args.profile,
        coordinator_root=args.coordinator_root,
        runner_output=args.runner_output,
        validator_count=args.validators,
        coordinator_manifest_sha256=args.coordinator_manifest_sha256,
        candidate_source=args.candidate_source,
        linux_binary=args.linux_binary,
        macos_binary=args.macos_binary,
        material_builder_binary=args.material_builder_binary,
        build_report=args.build_report,
        observer_report=args.observer_report,
        collector_output=args.collector_output,
        bundle_output=args.bundle_output,
    )
    print(json.dumps(plan, indent=2, sort_keys=True))
    print(
        "poco_g3_no_fault_bundle_collector_v1=plan-only "
        f"profile={args.profile} validators={args.validators} "
        "active_campaign_supported=false outputs_created=false "
        "mac_observer_producer=false replay_qc_verifier=false "
        "runner_host_provenance_roles=false truth_bits_changed=false "
        "g3_complete=false geo_wan=false production=false"
    )


if __name__ == "__main__":
    main()
