#!/usr/bin/env python3
"""Run the frozen seven-validator PoCO fault/restart campaign, fail closed.

This coordinator owns ordering, least-authority deployment, exact runtime-
control requests, file-backed process I/O, cleanup, and collection.  A separate
bounded fault driver performs host-specific effects, but its output is never
accepted as fault evidence.  Only the three connectivity faults may use the
runtime's signed FaultApplied/FaultRecovered projection.  Restart/catch-up,
isolated negative startup, signed degraded recovery, and epoch handoff each
require their own authority and must never be relabelled as that projection.

The default full matrix remains rejected before effects. Explicit closed
connectivity selections require their real signed transitions and seven-node
terminal verification, without promoting full-matrix or external acceptance.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
SOURCE_ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import run_consensus_fleet as consensus  # noqa: E402
import run_network_smoke_fleet as base  # noqa: E402
import fault_evidence_semantics_v1 as fault_semantics  # noqa: E402
import mesh_resource_preflight_v1 as mesh_resources  # noqa: E402


SCHEMA_VERSION = 1
PROFILE = fault_semantics.FULL_CAMPAIGN_PROFILE
SELECTED_PROFILE = fault_semantics.CONNECTIVITY_PROFILE
RESTART_PROFILE = fault_semantics.RESTART_PROFILE
FAULT_ORDER = fault_semantics.FAULT_ORDER
RESTART_FAULT = "validator_process_kill"
CONTROL_STATUS_FILE = "runtime-control-status.json"
MAX_CONTROL_BYTES = 64 * 1024
MAX_DRIVER_BYTES = 1024 * 1024
MAX_DRIVER_BINARY_BYTES = 16 * 1024 * 1024
MAX_PROCESS_IO_BYTES = 16 * 1024 * 1024
MAX_FAULT_WINDOW_SECONDS = 15 * 60
MIN_FAULT_WINDOW_SECONDS = 2
CONTROL_POLL_SECONDS = 1.0
RESTART_FRONTIER_STABLE_POLLS_V1 = 2
PROCESS1_TARGET_PARKED_EXIT_STATUS_V1 = 75
PROCESS2_INERT_EXIT_STATUS_V1 = 2
PROCESS2_INERT_BOUNDARY_MESSAGE_V1 = (
    "continuous consensus process2 reached the durable zero-delta caught-up cut; "
    "RecoveryReady, RecoveryStart, pacemaker, mesh, and ordinary ingress remain "
    "unavailable"
)
MANAGEMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
STATUS_KEYS = {
    "schema_version",
    "run_id",
    "validator_id",
    "process_id",
    "process_instance",
    "generation",
    "socket_basename",
    "journal_event_sequence",
    "journal_event_sha256",
    "production_activation",
}
RESPONSE_KEYS = {
    "schema_version",
    "run_id",
    "validator_id",
    "process_instance",
    "generation",
    "nonce",
    "verb",
    "status",
    "expected_fault",
    "barrier_phase",
    "fleet_ready_set_sha256",
    "fleet_start_certificate_sha256",
    "journal_event_sequence",
    "journal_event_sha256",
    "finalized_height",
    "application_height",
    "restart_quiesce_requested",
    "restart_pending_catchup",
    "restart_completed",
    "active_faults",
    "recovered_faults",
    "final_tip_recorded",
    "clean_stop_recorded",
    "safety_halted",
    "production_activation",
}
DRIVER_KEYS = {
    "schema_version",
    "phase",
    "kind",
    "target_validator_id",
    "status",
    "effect_id",
    "production_activation",
}
TARGET_HANDOFF_KEYS = {
    "schema_version",
    "status",
    "run_id",
    "validator_id",
    "process1_pid",
    "process1_instance",
    "process2_instance",
    "restart_park_event_sequence",
    "restart_park_event_sha256",
    "restart_parked_ack_event_sequence",
    "restart_parked_ack_event_sha256",
    "restart_cut_artifact_sha256",
    "restart_park_artifact_sha256",
    "restart_parked_ack_artifact_sha256",
    "restart_parked_ack_admission_set_sha256",
    "local_restart_parked_ack_statement_sha256",
    "protocol_authority",
    "production_activation",
}


@dataclasses.dataclass(frozen=True)
class FaultStepV1:
    ordinal: int
    kind: str
    target_validator_id: str
    target_host_id: str
    restart: bool


@dataclasses.dataclass
class FileResultV1:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_path: pathlib.Path
    stderr_path: pathlib.Path


@dataclasses.dataclass
class RuntimeProcessV1:
    process: base.ValidatorProcess
    command: list[str]
    child: subprocess.Popen[bytes]
    capture: base.ProcessCapture
    report_source: str
    journal_source: str
    metrics_source: str
    final_state_source: str
    fleet_start_certificate_source: str
    process_instance: int


@dataclasses.dataclass(frozen=True)
class SavedControlLocatorV1:
    """One canonical observation of an exact runtime-control locator."""

    status: dict[str, Any]
    raw_sha256: str


@dataclasses.dataclass(frozen=True)
class Process2ResumeArtifactsV1:
    ready_set_artifact_sha256: str
    start_certificate_artifact_sha256: str
    fence_token_digest: str


def validate_process2_resume_artifacts_v1(
    value: Process2ResumeArtifactsV1,
) -> Process2ResumeArtifactsV1:
    for field in dataclasses.fields(value):
        digest = getattr(value, field.name)
        if (
            not isinstance(digest, str)
            or HEX64.fullmatch(digest) is None
            or digest == "0" * 64
        ):
            fail(f"process2 {field.name} is not one nonzero SHA-256")
    return value


def process2_resume_arguments_v1(value: Process2ResumeArtifactsV1) -> list[str]:
    value = validate_process2_resume_artifacts_v1(value)
    return [
        "--resume-process2",
        "--recovery-ready-set-sha256",
        value.ready_set_artifact_sha256,
        "--recovery-start-certificate-sha256",
        value.start_certificate_artifact_sha256,
        "--recovery-fence-token-sha256",
        value.fence_token_digest,
    ]


def fail(message: str) -> None:
    raise SystemExit(f"PoCO G3 fault/restart fleet v1 failed: {message}")


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_management(value: str) -> str:
    if MANAGEMENT.fullmatch(value) is None or value.startswith("-"):
        fail("management route is unsafe")
    return value


def exact_remote_root(value: str) -> str:
    # shell_path checks the frozen stage prefix and its complete character set.
    base.shell_path(value)
    return value


def validator_root(process: base.ValidatorProcess, stage: base.HostStage) -> str:
    return exact_remote_root(base.validator_stage_root(process, stage))


def validator_config(process: base.ValidatorProcess, stage: base.HostStage) -> str:
    return exact_remote_root(
        f"{validator_root(process, stage)}/{process.config_relative.as_posix()}"
    )


def require_fault_driver(path: pathlib.Path) -> pathlib.Path:
    unresolved = path.absolute()
    try:
        metadata = unresolved.lstat()
        resolved = unresolved.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve fault driver: {error}")
    if (
        resolved != unresolved
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or not os.access(unresolved, os.X_OK)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
    ):
        fail("fault driver must be one executable regular non-symlink file")
    return resolved


def pin_fault_driver(
    source: pathlib.Path,
    target: pathlib.Path,
    expected_sha256: str,
) -> pathlib.Path:
    """Freeze the reviewed driver bytes before the first fleet effect."""

    before = source.stat()
    descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        with os.fdopen(descriptor, "rb") as stream:
            payload = stream.read(MAX_DRIVER_BINARY_BYTES + 1)
            after = os.fstat(stream.fileno())
    except BaseException:
        raise
    if (
        not payload
        or len(payload) > MAX_DRIVER_BINARY_BYTES
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(payload) != before.st_size
        or hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        fail("fault driver changed after its prestart plan was frozen")
    base.write_new(target, payload, mode=0o500)
    if base.sha256_file(target) != expected_sha256:
        target.unlink(missing_ok=True)
        fail("pinned fault driver fresh readback differs")
    return target


def fixed_fault_plan(processes: list[base.ValidatorProcess]) -> list[FaultStepV1]:
    if len(processes) != 7:
        fail("fault/restart campaign requires exactly seven validators")
    validator_ids = [process.validator_id for process in processes]
    if len(set(validator_ids)) != 7 or any(
        base.VALIDATOR_ID.fullmatch(validator_id) is None
        for validator_id in validator_ids
    ):
        fail("fault/restart validator inventory is invalid or duplicated")
    steps = [
        FaultStepV1(
            ordinal=index + 1,
            kind=kind,
            target_validator_id=processes[index % 7].validator_id,
            target_host_id=processes[index % 7].host_id,
            restart=kind == RESTART_FAULT,
        )
        for index, kind in enumerate(FAULT_ORDER)
    ]
    if tuple(step.kind for step in steps) != FAULT_ORDER or sum(
        step.restart for step in steps
    ) != 1:
        raise AssertionError("frozen fault/restart plan construction regressed")
    return steps


def selected_fault_plan(
    processes: list[base.ValidatorProcess], campaign: str,
) -> list[FaultStepV1]:
    kinds = fault_semantics.campaign_faults(campaign)
    # Keep the original observer assignment even for a single selected fault.
    return [dataclasses.replace(step, ordinal=index + 1)
            for index, step in enumerate(
                step for step in fixed_fault_plan(processes) if step.kind in kinds)]


def selected_placement_facts(
    topology: dict[str, Any], processes: list[base.ValidatorProcess],
) -> dict[str, Any]:
    base.placement_report_fields_v1(topology)  # closed schema/profile
    profile = topology.get("placement_profile", base.CANONICAL_PLACEMENT)
    inventory = mesh_resources._validated_host_inventory_v1(processes, 7, profile)
    if {row["validator_id"]: row["host_id"] for row in topology["validators"]} != {
        process.validator_id: process.host_id for process in processes
    } or len(topology["validators"]) != 7:
        fail("selected campaign topology differs from exact process inventory")
    observers = [row for row in topology["participants"] if row["host_id"] == "mac"]
    if len(observers) != 1 or not observers[0].get("management"):
        fail("selected campaign requires the actual Mac observer")
    return {
        "placement_profile": profile,
        "linux_validator_host_count": len(inventory),
        "validator_host_allocations": {
            host: entry["validator_processes"] for host, entry in sorted(inventory.items())
        },
        "planned_participant_host_count": len(inventory) + 1,
        "observer": {"host_id": "mac", "management": observers[0]["management"]},
        "whole_host_failure_tolerance": False,
    }


def campaign_plan(
    *,
    manifest: dict[str, Any],
    processes: list[base.ValidatorProcess],
    coordinator_anchor: str,
    driver_sha256: str,
    duration_seconds: int,
    max_blocks: int,
    fault_window_seconds: int,
    campaign: str = "all",
    topology: dict[str, Any] | None = None,
) -> dict[str, Any]:
    kinds = fault_semantics.campaign_faults(campaign)
    consensus.validated_run_bounds(duration_seconds, max_blocks)
    if (
        isinstance(fault_window_seconds, bool)
        or not MIN_FAULT_WINDOW_SECONDS
        <= fault_window_seconds
        <= MAX_FAULT_WINDOW_SECONDS
    ):
        fail("fault window crosses the frozen bound")
    if duration_seconds < len(kinds) * fault_window_seconds:
        fail("consensus duration cannot contain the complete ordered fault matrix")
    if HEX64.fullmatch(coordinator_anchor) is None or HEX64.fullmatch(driver_sha256) is None:
        fail("campaign content address is non-canonical")
    steps = selected_fault_plan(processes, campaign)
    plan = {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "run_id": manifest["run_id"],
        "validator_count": 7,
        "network_scope": "single-lan",
        "coordinator_manifest_sha256": coordinator_anchor,
        "fault_driver_sha256": driver_sha256,
        "duration_seconds": duration_seconds,
        "max_blocks": max_blocks,
        "fault_window_seconds": fault_window_seconds,
        "fault_order": [dataclasses.asdict(step) for step in steps],
        "fault_evidence_policy": fault_semantics.plan_matrix(),
        "active_campaign_supported": not fault_semantics.active_campaign_blockers(),
        "authority_blockers": fault_semantics.active_campaign_blockers(),
        "restart_count": 1,
        "requires_runtime_control": True,
        "requires_signed_runtime_journal": True,
        "requires_fleet_start_certificate": True,
        "requires_signed_terminal_report": True,
        "requires_signed_runtime_metrics": True,
        "requires_signed_runtime_final_state": True,
        "requires_macos_independent_replay": True,
        "driver_output_is_runtime_evidence": False,
        "vocabulary_membership_is_runtime_authority": False,
        "legacy_exact_eight_primary_signed_transitions_allowed": False,
        "mesh_resource_preflight_required_before_effects": True,
        "mesh_resource_preflight": None,
        "fault_matrix_completed": False,
        "validator_run_completed": False,
        "g3_lan_multihost_evidence": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    if campaign != "all":
        if topology is None:
            fail("selected campaign requires the validated topology")
        facts = selected_placement_facts(topology, processes)
        candidate = manifest.get("candidate")
        if (not isinstance(candidate, dict)
            or set(candidate) != {"source_tree_sha256", "linux_x86_64_sha256", "macos_arm64_sha256"}
            or any(not isinstance(value, str) or HEX64.fullmatch(value) is None for value in candidate.values())):
            fail("selected campaign lacks source-bound candidate identity")
        plan.update(
            schema_version=2,
            profile=fault_semantics.campaign_profile(campaign),
            campaign=campaign,
            candidate=dict(candidate),
            topology_sha256=hashlib.sha256(base.canonical_json(topology)).hexdigest(),
            fault_evidence_policy=[fault_semantics.policy_for(kind).plan_record() for kind in kinds],
            active_campaign_supported=True,
            authority_blockers=[],
            restart_count=1 if campaign == "restart" else 0,
            full_matrix_authority_blockers=fault_semantics.active_campaign_blockers(),
            selected_campaign_completed=False, fault_restart_profile_completed=False,
            **facts,
        )
    return plan


def safe_label(value: str) -> str:
    if not value or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for character in value):
        fail("file-backed command label is unsafe")
    return value


def read_bounded(path: pathlib.Path, bound: int, field: str) -> bytes:
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file() or metadata.st_size > bound:
        fail(f"{field} crosses its file-backed bound")
    return path.read_bytes()


def run_file_backed(
    arguments: list[str],
    *,
    io_root: pathlib.Path,
    label: str,
    timeout: int,
    bound: int = MAX_CONTROL_BYTES,
    check: bool = True,
) -> FileResultV1:
    """Run without PIPE so a slow coordinator cannot deadlock a child."""

    label = safe_label(label)
    stdout_path = io_root / f"{label}.stdout"
    stderr_path = io_root / f"{label}.stderr"
    stdout_fd = os.open(
        stdout_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    stderr_fd = os.open(
        stderr_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(stdout_fd, "wb") as stdout, os.fdopen(stderr_fd, "wb") as stderr:
            completed = subprocess.run(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                check=False,
                timeout=timeout,
            )
            stdout.flush()
            stderr.flush()
            os.fsync(stdout.fileno())
            os.fsync(stderr.fileno())
    except BaseException:
        # The caller owns one fresh observation root. Preserve exact partial
        # command output for diagnosis; stage/effect cleanup is handled by the
        # campaign's finally block.
        raise
    result = FileResultV1(
        completed.returncode,
        read_bounded(stdout_path, bound, f"{label} stdout"),
        read_bounded(stderr_path, bound, f"{label} stderr"),
        stdout_path,
        stderr_path,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command {label} exited {result.returncode}: "
            f"{result.stderr.decode('utf-8', errors='replace')[:400]}"
        )
    return result


def strict_object(raw: bytes, field: str) -> dict[str, Any]:
    value = base.strict_json_bytes(raw, field)
    if not isinstance(value, dict):
        fail(f"{field} is not one JSON object")
    canonical = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if canonical != raw:
        fail(f"{field} is not canonical JSON")
    return value


def strict_stdout_object(raw: bytes, field: str) -> dict[str, Any]:
    if len(raw) < 3 or not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\r" in raw:
        fail(f"{field} must be one exact JSON line")
    return strict_object(raw[:-1], field)


def exact_status(
    value: object,
    *,
    run_id: str,
    validator_id: str,
    process_instance: int | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != STATUS_KEYS:
        fail("runtime-control status keys differ from contract")
    instance = value["process_instance"]
    generation = value["generation"]
    if (
        value["schema_version"] != 1
        or value["run_id"] != run_id
        or value["validator_id"] != validator_id
        or isinstance(value["process_id"], bool)
        or not isinstance(value["process_id"], int)
        or value["process_id"] <= 0
        or isinstance(instance, bool)
        or not isinstance(instance, int)
        or instance not in {1, 2}
        or (process_instance is not None and instance != process_instance)
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 1 <= generation <= 1024
        or value["socket_basename"]
        != f"runtime-control.instance-{instance}.generation-{generation}.sock"
        or isinstance(value["journal_event_sequence"], bool)
        or not isinstance(value["journal_event_sequence"], int)
        or value["journal_event_sequence"] < 0
        or not isinstance(value["journal_event_sha256"], str)
        or HEX64.fullmatch(value["journal_event_sha256"]) is None
        or value["journal_event_sha256"] == "0" * 64
        or value["production_activation"] is not False
    ):
        fail("runtime-control status crosses its exact context")
    return value


def valid_barrier_projection_v1(value: dict[str, Any], allow_pre_start: bool) -> bool:
    ready, started = value["fleet_ready_set_sha256"], value["fleet_start_certificate_sha256"]
    nonzero = lambda text: isinstance(text, str) and HEX64.fullmatch(text) is not None and text != "0" * 64
    phase = value["barrier_phase"]
    if phase == "started":
        return nonzero(ready) and nonzero(started)
    if allow_pre_start and phase == "preparing":
        return ready == "" and started == ""
    if allow_pre_start and phase == "ready":
        return nonzero(ready) and started == ""
    return False


def exact_response(
    value: object,
    *,
    status: dict[str, Any],
    nonce: int,
    verb: str,
    allow_pre_start: bool = False,
) -> dict[str, Any]:
    if allow_pre_start and verb != "status":
        fail("pre-start observation is only available to status reads")
    if not isinstance(value, dict) or set(value) != RESPONSE_KEYS:
        fail("runtime-control response keys differ from contract")
    active = value["active_faults"]
    recovered = value["recovered_faults"]
    if (
        value["schema_version"] != 1
        or value["run_id"] != status["run_id"]
        or value["validator_id"] != status["validator_id"]
        or value["process_instance"] != status["process_instance"]
        or value["generation"] != status["generation"]
        or value["nonce"] != nonce
        or value["verb"] != verb
        or value["status"] != "ok"
        or value["expected_fault"] not in {"", *FAULT_ORDER}
        or not valid_barrier_projection_v1(value, allow_pre_start)
        or not isinstance(active, list)
        or not isinstance(recovered, list)
        or active != sorted(set(active))
        or recovered != sorted(set(recovered))
        or any(fault not in FAULT_ORDER for fault in active + recovered)
        or any(
            isinstance(value[field], bool)
            or not isinstance(value[field], int)
            or value[field] < 0
            for field in (
                "journal_event_sequence",
                "finalized_height",
                "application_height",
            )
        )
        or not isinstance(value["journal_event_sha256"], str)
        or HEX64.fullmatch(value["journal_event_sha256"]) is None
        or value["journal_event_sha256"] == "0" * 64
        or any(
            not isinstance(value[field], bool)
            for field in (
                "restart_quiesce_requested",
                "restart_pending_catchup",
                "restart_completed",
                "final_tip_recorded",
                "clean_stop_recorded",
                "safety_halted",
                "production_activation",
            )
        )
        or value["production_activation"] is not False
    ):
        fail("runtime-control response crosses its exact context")
    return value


def exact_target_handoff(
    value: object,
    *,
    run_id: str,
    validator_id: str,
    process1_pid: int,
) -> dict[str, Any]:
    """Authenticate the data-only status-75 handoff descriptor."""

    if not isinstance(value, dict) or set(value) != TARGET_HANDOFF_KEYS:
        fail("process-1 target handoff keys differ from contract")
    digest_fields = (
        "restart_park_event_sha256",
        "restart_parked_ack_event_sha256",
        "restart_cut_artifact_sha256",
        "restart_park_artifact_sha256",
        "restart_parked_ack_artifact_sha256",
        "restart_parked_ack_admission_set_sha256",
        "local_restart_parked_ack_statement_sha256",
    )
    park_sequence = value["restart_park_event_sequence"]
    ack_sequence = value["restart_parked_ack_event_sequence"]
    if (
        value["schema_version"] != 2
        or value["status"] != "process1-target-parked-ack-handoff"
        or value["run_id"] != run_id
        or value["validator_id"] != validator_id
        or isinstance(value["process1_pid"], bool)
        or not isinstance(value["process1_pid"], int)
        or value["process1_pid"] != process1_pid
        or isinstance(value["process1_instance"], bool)
        or not isinstance(value["process1_instance"], int)
        or value["process1_instance"] != 1
        or isinstance(value["process2_instance"], bool)
        or not isinstance(value["process2_instance"], int)
        or value["process2_instance"] != 2
        or isinstance(park_sequence, bool)
        or not isinstance(park_sequence, int)
        or park_sequence <= 0
        or isinstance(ack_sequence, bool)
        or not isinstance(ack_sequence, int)
        or ack_sequence != park_sequence + 1
        or any(
            not isinstance(value[field], str)
            or HEX64.fullmatch(value[field]) is None
            or value[field] == "0" * 64
            for field in digest_fields
        )
        or value["protocol_authority"] is not False
        or value["production_activation"] is not False
    ):
        fail("process-1 target handoff crosses its exact durable context")
    return value


def exact_driver_response(
    value: object,
    *,
    step: FaultStepV1,
    phase: str,
) -> dict[str, Any]:
    expected_status = "applied" if phase == "apply" else "restored"
    if not isinstance(value, dict) or set(value) != DRIVER_KEYS:
        fail("fault-driver response keys differ from contract")
    if (
        value["schema_version"] != 1
        or value["phase"] != phase
        or value["kind"] != step.kind
        or value["target_validator_id"] != step.target_validator_id
        or value["status"] != expected_status
        or not isinstance(value["effect_id"], str)
        or HEX64.fullmatch(value["effect_id"]) is None
        or value["effect_id"] == "0" * 64
        or value["production_activation"] is not False
    ):
        fail("fault-driver response crosses its exact request")
    return value


def remote_or_local_command(
    process: base.ValidatorProcess,
    stage: base.HostStage,
    arguments: list[str],
) -> list[str]:
    if not stage.remote:
        return arguments
    validate_management(process.management)
    command = " ".join(shlex.quote(argument) for argument in arguments)
    return [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=15",
        process.management,
        f"set -eu; exec {command}",
    ]


RECOVERY_MATERIAL_RESULT_KEYS = {
    "schema_version",
    "status",
    "run_id",
    "validator_id",
    "validator_set_id",
    "path",
    "artifact_sha256",
    "context_digest",
    "predecessor_artifact_sha256",
    "candidate_only",
    "production_activation",
}
PEER_LEASE_BINDING_RESULT_KEYS = {
    "schema_version",
    "status",
    "binding_digest",
    "candidate_only",
    "production_activation",
}


def recovery_material_root_v1(
    process: base.ValidatorProcess, stage: base.HostStage
) -> str:
    return exact_remote_root(f"{validator_root(process, stage)}/recovery-material-v1")


def recovery_material_path_v1(
    process: base.ValidatorProcess,
    stage: base.HostStage,
    name: str,
) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,126}", name):
        fail("recovery material file name is unsafe")
    return exact_remote_root(f"{recovery_material_root_v1(process, stage)}/{name}")


def create_recovery_material_root_v1(
    *,
    process: base.ValidatorProcess,
    stage: base.HostStage,
    io_root: pathlib.Path,
    label: str,
) -> str:
    root = recovery_material_root_v1(process, stage)
    if stage.remote:
        validate_management(process.management)
        quoted = base.shell_path(root)
        run_file_backed(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=15",
                process.management,
                (
                    f"set -eu; test ! -e {quoted}; test ! -L {quoted}; "
                    f"mkdir -m 700 -- {quoted}; test -d {quoted}; test ! -L {quoted}; "
                    f'test "$(stat -c %a -- {quoted})" = 700'
                ),
            ],
            io_root=io_root,
            label=label,
            timeout=30,
        )
    else:
        path = pathlib.Path(root)
        path.mkdir(mode=0o700, parents=False, exist_ok=False)
        metadata = path.lstat()
        if path.is_symlink() or not path.is_dir() or metadata.st_mode & 0o7777 != 0o700:
            raise RuntimeError("local recovery material root is not one private directory")
    return root


def copy_to_validator_v1(
    *,
    process: base.ValidatorProcess,
    stage: base.HostStage,
    source: pathlib.Path,
    target: str,
    io_root: pathlib.Path,
    label: str,
) -> None:
    source_metadata = source.lstat()
    if (
        source.is_symlink()
        or not source.is_file()
        or source_metadata.st_nlink != 1
        or source_metadata.st_size <= 0
        or source_metadata.st_size > MAX_CONTROL_BYTES
    ):
        raise RuntimeError("recovery material source is not one bounded regular file")
    source_sha256 = base.sha256_file(source)
    exact_remote_root(target)
    if stage.remote:
        validate_management(process.management)
        quoted = base.shell_path(target)
        run_file_backed(
            [
                "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                process.management,
                f"set -eu; test ! -e {quoted}; test ! -L {quoted}",
            ],
            io_root=io_root,
            label=f"{label}-preflight",
            timeout=30,
        )
        run_file_backed(
            ["scp", "-q", str(source), f"{process.management}:{target}"],
            io_root=io_root,
            label=f"{label}-copy",
            timeout=60,
        )
        verify = run_file_backed(
            [
                "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                process.management,
                (
                    f"set -eu; chmod 600 -- {quoted}; test -f {quoted}; "
                    f'test ! -L {quoted}; test "$(stat -c %h -- {quoted})" = 1; '
                    f'test "$(stat -c %a -- {quoted})" = 600; sha256sum -- {quoted}'
                ),
            ],
            io_root=io_root,
            label=f"{label}-verify",
            timeout=30,
        )
        observed = verify.stdout.decode("ascii", errors="strict").split()[0]
        if observed != source_sha256:
            raise RuntimeError("remote recovery material digest differs after copy")
        return
    target_path = pathlib.Path(target)
    if target_path.exists() or target_path.is_symlink():
        raise RuntimeError("local recovery material target already exists")
    shutil.copyfile(source, target_path)
    target_path.chmod(0o600)
    metadata = target_path.lstat()
    if (
        target_path.is_symlink()
        or not target_path.is_file()
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o7777 != 0o600
        or base.sha256_file(target_path) != source_sha256
    ):
        raise RuntimeError("local recovery material differs after copy")


def run_validator_cli_v1(
    *,
    process: base.ValidatorProcess,
    stage: base.HostStage,
    binary: str,
    command: str,
    arguments: list[str],
    io_root: pathlib.Path,
    label: str,
    timeout: int = 60,
) -> FileResultV1:
    base.shell_path(binary)
    return run_file_backed(
        remote_or_local_command(
            process,
            stage,
            [
                binary,
                command,
                validator_root(process, stage),
                validator_config(process, stage),
                *arguments,
            ],
        ),
        io_root=io_root,
        label=label,
        timeout=timeout,
        bound=MAX_CONTROL_BYTES,
    )


def exact_recovery_material_result_v1(
    value: object,
    *,
    command: str,
    process: base.ValidatorProcess,
    run_id: str,
    expected_path: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != RECOVERY_MATERIAL_RESULT_KEYS:
        fail("recovery material result keys differ from contract")
    optional_digests = ("context_digest", "predecessor_artifact_sha256")
    if (
        value["schema_version"] != 1
        or value["status"] != command
        or value["run_id"] != run_id
        or value["validator_id"] != process.validator_id
        or not isinstance(value["validator_set_id"], str)
        or HEX64.fullmatch(value["validator_set_id"]) is None
        or value["validator_set_id"] == "0" * 64
        or value["path"] != expected_path
        or not isinstance(value["artifact_sha256"], str)
        or HEX64.fullmatch(value["artifact_sha256"]) is None
        or value["artifact_sha256"] == "0" * 64
        or any(
            digest is not None
            and (
                not isinstance(digest, str)
                or HEX64.fullmatch(digest) is None
                or digest == "0" * 64
            )
            for digest in (value[field] for field in optional_digests)
        )
        or value["candidate_only"] is not True
        or value["production_activation"] is not False
    ):
        fail("recovery material result crosses its exact request")
    return value


def exact_peer_lease_binding_v1(value: object) -> str:
    if not isinstance(value, dict) or set(value) != PEER_LEASE_BINDING_RESULT_KEYS:
        fail("peer-lease binding result keys differ from contract")
    digest = value["binding_digest"]
    if (
        value["schema_version"] != 1
        or value["status"] != "peer-lease-binding"
        or not isinstance(digest, str)
        or HEX64.fullmatch(digest) is None
        or digest == "0" * 64
        or value["candidate_only"] is not True
        or value["production_activation"] is not False
    ):
        fail("peer-lease binding result crosses its exact endpoint")
    return digest


def query_peer_lease_binding_v1(
    *,
    process: base.ValidatorProcess,
    stage: base.HostStage,
    binary: str,
    socket: str,
    io_root: pathlib.Path,
    label: str,
) -> str:
    result = run_file_backed(
        remote_or_local_command(
            process,
            stage,
            [binary, "peer-lease-binding", "--socket", socket],
        ),
        io_root=io_root,
        label=label,
        timeout=30,
        bound=MAX_CONTROL_BYTES,
    )
    return exact_peer_lease_binding_v1(
        strict_stdout_object(result.stdout, "peer-lease binding result")
    )


def commission_process2_recovery_material_v1(
    *,
    processes: list[base.ValidatorProcess],
    stages: dict[str, base.HostStage],
    linux_paths: dict[str, str],
    target: base.ValidatorProcess,
    peer_lease_socket: str,
    run_id: str,
    io_root: pathlib.Path,
) -> tuple[Process2ResumeArtifactsV1, dict[str, Any]]:
    if (
        len(processes) != 7
        or target.validator_id not in {process.validator_id for process in processes}
        or len(stages) < 1
    ):
        raise RuntimeError("process2 recovery material requires one exact seven-validator fleet")
    material_io = io_root / "process2-recovery-material-v1"
    material_io.mkdir(mode=0o700, parents=False, exist_ok=False)
    target_stage = stages[target.host_id]
    target_binary = linux_paths[target.host_id]
    binding_before = query_peer_lease_binding_v1(
        process=target,
        stage=target_stage,
        binary=target_binary,
        socket=peer_lease_socket,
        io_root=io_root,
        label="process2-fence-binding-before-material",
    )

    material_roots: dict[str, str] = {}
    for process in processes:
        material_roots[process.validator_id] = create_recovery_material_root_v1(
            process=process,
            stage=stages[process.host_id],
            io_root=io_root,
            label=f"process2-material-root-{process.validator_id}",
        )

    target_context = recovery_material_path_v1(target, target_stage, "context.bin")
    context_result_raw = run_validator_cli_v1(
        process=target,
        stage=target_stage,
        binary=target_binary,
        command="recovery-context",
        arguments=[target_context],
        io_root=io_root,
        label="process2-recovery-context",
    )
    context_result = exact_recovery_material_result_v1(
        strict_stdout_object(context_result_raw.stdout, "process2 recovery context"),
        command="recovery-context",
        process=target,
        run_id=run_id,
        expected_path=target_context,
    )
    context_digest = context_result["context_digest"]
    if context_digest is None:
        raise RuntimeError("recovery context command omitted its typed context digest")
    coordinator_context = material_io / "context.bin"
    copy_remote_or_local(
        process=target,
        stage=target_stage,
        source=target_context,
        target=coordinator_context,
        io_root=io_root,
        label="process2-context-to-coordinator",
    )
    if base.sha256_file(coordinator_context) != context_result["artifact_sha256"]:
        raise RuntimeError("copied recovery context differs from target result")

    context_paths: dict[str, str] = {target.validator_id: target_context}
    for process in processes:
        if process.validator_id == target.validator_id:
            continue
        stage = stages[process.host_id]
        destination = recovery_material_path_v1(process, stage, "context.bin")
        copy_to_validator_v1(
            process=process,
            stage=stage,
            source=coordinator_context,
            target=destination,
            io_root=io_root,
            label=f"process2-context-to-{process.validator_id}",
        )
        context_paths[process.validator_id] = destination

    ready_results: dict[str, dict[str, Any]] = {}
    ready_coordinator_paths: dict[str, pathlib.Path] = {}
    for process in processes:
        stage = stages[process.host_id]
        output = recovery_material_path_v1(
            process, stage, f"ready-{process.validator_id}.bin"
        )
        raw = run_validator_cli_v1(
            process=process,
            stage=stage,
            binary=linux_paths[process.host_id],
            command="recovery-ready",
            arguments=[context_paths[process.validator_id], output],
            io_root=io_root,
            label=f"process2-ready-{process.validator_id}",
        )
        result = exact_recovery_material_result_v1(
            strict_stdout_object(raw.stdout, f"RecoveryReady {process.validator_id}"),
            command="recovery-ready",
            process=process,
            run_id=run_id,
            expected_path=output,
        )
        if result["context_digest"] != context_digest:
            raise RuntimeError("RecoveryReady statement changed the recovery context")
        ready_results[process.validator_id] = result
        coordinator_path = material_io / f"ready-{process.validator_id}.bin"
        copy_remote_or_local(
            process=process,
            stage=stage,
            source=output,
            target=coordinator_path,
            io_root=io_root,
            label=f"process2-ready-to-coordinator-{process.validator_id}",
        )
        if base.sha256_file(coordinator_path) != result["artifact_sha256"]:
            raise RuntimeError("copied RecoveryReady statement differs")
        ready_coordinator_paths[process.validator_id] = coordinator_path

    target_ready_inputs: list[str] = []
    for process in processes:
        if process.validator_id == target.validator_id:
            destination = recovery_material_path_v1(
                target, target_stage, f"ready-{target.validator_id}.bin"
            )
        else:
            destination = recovery_material_path_v1(
                target, target_stage, f"ready-{process.validator_id}.bin"
            )
            copy_to_validator_v1(
                process=target,
                stage=target_stage,
                source=ready_coordinator_paths[process.validator_id],
                target=destination,
                io_root=io_root,
                label=f"process2-ready-to-target-{process.validator_id}",
            )
        target_ready_inputs.append(destination)

    ready_set_path = exact_remote_root(
        f"{validator_root(target, target_stage)}/recovery-ready-set-v1.bin"
    )
    raw_ready_set = run_validator_cli_v1(
        process=target,
        stage=target_stage,
        binary=target_binary,
        command="recovery-ready-set",
        arguments=[target_context, *target_ready_inputs],
        io_root=io_root,
        label="process2-ready-set",
    )
    ready_set_result = exact_recovery_material_result_v1(
        strict_stdout_object(raw_ready_set.stdout, "RecoveryReady set"),
        command="recovery-ready-set",
        process=target,
        run_id=run_id,
        expected_path=ready_set_path,
    )
    if ready_set_result["context_digest"] != context_digest:
        raise RuntimeError("RecoveryReady set changed the recovery context")
    ready_set_coordinator = material_io / "recovery-ready-set-v1.bin"
    copy_remote_or_local(
        process=target,
        stage=target_stage,
        source=ready_set_path,
        target=ready_set_coordinator,
        io_root=io_root,
        label="process2-ready-set-to-coordinator",
    )
    if base.sha256_file(ready_set_coordinator) != ready_set_result["artifact_sha256"]:
        raise RuntimeError("copied RecoveryReady set differs")

    ready_set_paths: dict[str, str] = {target.validator_id: ready_set_path}
    for process in processes:
        if process.validator_id == target.validator_id:
            continue
        stage = stages[process.host_id]
        destination = recovery_material_path_v1(process, stage, "ready-set.bin")
        copy_to_validator_v1(
            process=process,
            stage=stage,
            source=ready_set_coordinator,
            target=destination,
            io_root=io_root,
            label=f"process2-ready-set-to-{process.validator_id}",
        )
        ready_set_paths[process.validator_id] = destination

    start_results: dict[str, dict[str, Any]] = {}
    start_coordinator_paths: dict[str, pathlib.Path] = {}
    for process in processes:
        stage = stages[process.host_id]
        output = recovery_material_path_v1(
            process, stage, f"start-{process.validator_id}.bin"
        )
        raw = run_validator_cli_v1(
            process=process,
            stage=stage,
            binary=linux_paths[process.host_id],
            command="recovery-start",
            arguments=[ready_set_paths[process.validator_id], output],
            io_root=io_root,
            label=f"process2-start-{process.validator_id}",
        )
        result = exact_recovery_material_result_v1(
            strict_stdout_object(raw.stdout, f"RecoveryStart {process.validator_id}"),
            command="recovery-start",
            process=process,
            run_id=run_id,
            expected_path=output,
        )
        if result["context_digest"] != context_digest:
            raise RuntimeError("RecoveryStart statement changed the recovery context")
        start_results[process.validator_id] = result
        coordinator_path = material_io / f"start-{process.validator_id}.bin"
        copy_remote_or_local(
            process=process,
            stage=stage,
            source=output,
            target=coordinator_path,
            io_root=io_root,
            label=f"process2-start-to-coordinator-{process.validator_id}",
        )
        if base.sha256_file(coordinator_path) != result["artifact_sha256"]:
            raise RuntimeError("copied RecoveryStart statement differs")
        start_coordinator_paths[process.validator_id] = coordinator_path

    target_start_inputs: list[str] = []
    for process in processes:
        if process.validator_id == target.validator_id:
            destination = recovery_material_path_v1(
                target, target_stage, f"start-{target.validator_id}.bin"
            )
        else:
            destination = recovery_material_path_v1(
                target, target_stage, f"start-{process.validator_id}.bin"
            )
            copy_to_validator_v1(
                process=target,
                stage=target_stage,
                source=start_coordinator_paths[process.validator_id],
                target=destination,
                io_root=io_root,
                label=f"process2-start-to-target-{process.validator_id}",
            )
        target_start_inputs.append(destination)

    start_certificate_path = exact_remote_root(
        f"{validator_root(target, target_stage)}/recovery-start-certificate-v1.bin"
    )
    raw_certificate = run_validator_cli_v1(
        process=target,
        stage=target_stage,
        binary=target_binary,
        command="recovery-start-certificate",
        arguments=[ready_set_path, *target_start_inputs],
        io_root=io_root,
        label="process2-start-certificate",
    )
    start_certificate_result = exact_recovery_material_result_v1(
        strict_stdout_object(raw_certificate.stdout, "RecoveryStart certificate"),
        command="recovery-start-certificate",
        process=target,
        run_id=run_id,
        expected_path=start_certificate_path,
    )
    if (
        start_certificate_result["context_digest"] != context_digest
        or start_certificate_result["predecessor_artifact_sha256"]
        != ready_set_result["artifact_sha256"]
    ):
        raise RuntimeError("RecoveryStart certificate changed its context or ReadySet")

    peer_artifacts: dict[str, str] = {}
    for name, expected in (
        ("recovery-zero-delta-cut-v1.bin", None),
        ("recovery-ready-set-v1.bin", ready_set_result["artifact_sha256"]),
        ("recovery-start-certificate-v1.bin", start_certificate_result["artifact_sha256"]),
    ):
        coordinator_file = material_io / ("peer-" + name)
        copy_remote_or_local(
            process=target, stage=target_stage,
            source=exact_remote_root(f"{validator_root(target, target_stage)}/{name}"),
            target=coordinator_file, io_root=io_root, label=f"peer-artifact-{name}",
        )
        digest = base.sha256_file(coordinator_file)
        if expected is not None and digest != expected:
            raise RuntimeError("resident peer artifact differs from target certificate")
        peer_artifacts[name] = digest
        for peer in processes:
            if peer.validator_id == target.validator_id:
                continue
            peer_stage = stages[peer.host_id]
            copy_to_validator_v1(
                process=peer, stage=peer_stage, source=coordinator_file,
                target=exact_remote_root(f"{validator_root(peer, peer_stage)}/{name}"),
                io_root=io_root, label=f"peer-artifact-{peer.validator_id}-{name}",
            )

    binding_after = query_peer_lease_binding_v1(
        process=target,
        stage=target_stage,
        binary=target_binary,
        socket=peer_lease_socket,
        io_root=io_root,
        label="process2-fence-binding-after-material",
    )
    if binding_after != binding_before:
        raise RuntimeError("external peer-fence identity changed during recovery material exchange")
    artifacts = validate_process2_resume_artifacts_v1(
        Process2ResumeArtifactsV1(
            ready_set_artifact_sha256=ready_set_result["artifact_sha256"],
            start_certificate_artifact_sha256=start_certificate_result["artifact_sha256"],
            fence_token_digest=binding_after,
        )
    )
    summary = {
        "schema_version": 1,
        "status": "process2-recovery-material-complete",
        "run_id": run_id,
        "target_validator_id": target.validator_id,
        "context_sha256": context_result["artifact_sha256"],
        "context_digest": context_digest,
        "ready_statement_sha256": {
            validator_id: result["artifact_sha256"]
            for validator_id, result in sorted(ready_results.items())
        },
        "ready_set_sha256": artifacts.ready_set_artifact_sha256,
        "start_statement_sha256": {
            validator_id: result["artifact_sha256"]
            for validator_id, result in sorted(start_results.items())
        },
        "start_certificate_sha256": artifacts.start_certificate_artifact_sha256,
        "fence_token_digest": artifacts.fence_token_digest,
        "candidate_only": True,
        "production_activation": False,
    }
    base.write_new(
        material_io / "summary.json",
        json.dumps(summary, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        mode=0o600,
    )
    return artifacts, summary


def wait_control_locator(
    *,
    process: base.ValidatorProcess,
    stage: base.HostStage,
    run_id: str,
    process_instance: int,
    io_root: pathlib.Path,
    label: str,
    timeout_seconds: int,
) -> SavedControlLocatorV1:
    root = validator_root(process, stage)
    status_path = exact_remote_root(f"{root}/{CONTROL_STATUS_FILE}")
    if stage.remote:
        validate_management(process.management)
        quoted = base.shell_path(status_path)
        attempts = max(1, timeout_seconds * 4)
        remote = (
            "set -eu; attempts="
            f"{attempts}; while test ! -f {quoted}; do "
            'attempts=$((attempts-1)); test "$attempts" -gt 0; sleep 0.25; '
            f"done; test ! -L {quoted}; exec cat -- {quoted}"
        )
        result = run_file_backed(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=15",
                process.management,
                remote,
            ],
            io_root=io_root,
            label=label,
            timeout=timeout_seconds + 20,
        )
        raw = result.stdout
    else:
        path = pathlib.Path(status_path)
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                metadata = path.lstat()
                if path.is_symlink() or not path.is_file() or metadata.st_size > MAX_CONTROL_BYTES:
                    fail("local runtime-control status is not one bounded regular file")
                raw = path.read_bytes()
                break
            except FileNotFoundError:
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        f"validator {process.validator_id} omitted runtime-control status"
                    )
                time.sleep(0.25)
    status = exact_status(
        strict_object(raw, f"runtime-control status {process.validator_id}"),
        run_id=run_id,
        validator_id=process.validator_id,
        process_instance=process_instance,
    )
    return SavedControlLocatorV1(
        status=dict(status), raw_sha256=hashlib.sha256(raw).hexdigest()
    )


def wait_control_status(
    *,
    process: base.ValidatorProcess,
    stage: base.HostStage,
    run_id: str,
    process_instance: int,
    io_root: pathlib.Path,
    label: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    return wait_control_locator(
        process=process,
        stage=stage,
        run_id=run_id,
        process_instance=process_instance,
        io_root=io_root,
        label=label,
        timeout_seconds=timeout_seconds,
    ).status


def exact_post_handoff_control_locator(
    current: SavedControlLocatorV1,
    *,
    saved: SavedControlLocatorV1,
    handoff: dict[str, Any],
) -> SavedControlLocatorV1:
    current_status = current.status
    saved_status = saved.status
    if (
        current_status != saved_status
        or current.raw_sha256 != saved.raw_sha256
        or saved_status["run_id"] != handoff["run_id"]
        or saved_status["validator_id"] != handoff["validator_id"]
        or saved_status["process_id"] != handoff["process1_pid"]
        or saved_status["process_instance"] != handoff["process1_instance"]
        or HEX64.fullmatch(saved.raw_sha256) is None
        or saved.raw_sha256 == "0" * 64
    ):
        fail("post-handoff runtime-control locator differs from its saved incarnation")
    return current


def remove_exact_control_locator(
    *,
    process: base.ValidatorProcess,
    stage: base.HostStage,
    locator: SavedControlLocatorV1,
    io_root: pathlib.Path,
    label: str,
) -> None:
    status_path = exact_remote_root(
        f"{validator_root(process, stage)}/{CONTROL_STATUS_FILE}"
    )
    if stage.remote:
        validate_management(process.management)
        remote_unlink = """
import hashlib
import os
import stat
import sys

path, expected_sha256, maximum = sys.argv[1], sys.argv[2], int(sys.argv[3])
parent, name = os.path.split(path)
parent_fd = os.open(parent, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
        dir_fd=parent_fd,
    )
    try:
        before = os.fstat(descriptor)
        payload = bytearray()
        while len(payload) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        stat.S_IMODE(value.st_mode),
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if (
        identity(before) != identity(after)
        or identity(after) != identity(named)
        or not stat.S_ISREG(after.st_mode)
        or after.st_uid != os.geteuid()
        or stat.S_IMODE(after.st_mode) != 0o600
        or after.st_nlink != 1
        or after.st_size <= 0
        or after.st_size > maximum
        or len(payload) != after.st_size
        or hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        raise SystemExit("runtime-control locator changed before exact unlink")
    os.unlink(name, dir_fd=parent_fd)
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
""".strip()
        command = shlex.join(
            [
                "python3",
                "-c",
                remote_unlink,
                status_path,
                locator.raw_sha256,
                str(MAX_CONTROL_BYTES),
            ]
        )
        run_file_backed(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                process.management,
                f"set -eu; exec {command}",
            ],
            io_root=io_root,
            label=label,
            timeout=30,
        )
    else:
        path = pathlib.Path(status_path)
        parent = path.parent
        parent_fd = os.open(
            parent, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_fd,
            )
            try:
                before = os.fstat(descriptor)
                payload = bytearray()
                while len(payload) <= MAX_CONTROL_BYTES:
                    chunk = os.read(
                        descriptor,
                        min(65536, MAX_CONTROL_BYTES + 1 - len(payload)),
                    )
                    if not chunk:
                        break
                    payload.extend(chunk)
                after = os.fstat(descriptor)
                named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            finally:
                os.close(descriptor)
            identity = lambda value: (
                value.st_dev,
                value.st_ino,
                value.st_uid,
                stat.S_IMODE(value.st_mode),
                value.st_nlink,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )
            if (
                identity(before) != identity(after)
                or identity(after) != identity(named)
                or not stat.S_ISREG(after.st_mode)
                or after.st_uid != os.geteuid()
                or stat.S_IMODE(after.st_mode) != 0o600
                or after.st_nlink != 1
                or after.st_size <= 0
                or after.st_size > MAX_CONTROL_BYTES
                or len(payload) != after.st_size
                or hashlib.sha256(payload).hexdigest() != locator.raw_sha256
            ):
                fail("runtime-control locator changed before exact unlink")
            os.unlink(path.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)


def send_control(
    *,
    process: base.ValidatorProcess,
    stage: base.HostStage,
    binary: str,
    status: dict[str, Any],
    nonce: int,
    verb: str,
    fault: str,
    io_root: pathlib.Path,
    label: str,
    allow_pre_start: bool = False,
) -> dict[str, Any]:
    arguments = [
        binary,
        "runtime-control",
        validator_root(process, stage),
        validator_config(process, stage),
        str(status["process_instance"]),
        str(status["generation"]),
        str(nonce),
        verb,
        fault,
    ]
    result = run_file_backed(
        remote_or_local_command(process, stage, arguments),
        io_root=io_root,
        label=label,
        timeout=30,
    )
    return exact_response(
        strict_stdout_object(result.stdout, f"runtime-control {verb} response"),
        status=status,
        nonce=nonce,
        verb=verb, allow_pre_start=allow_pre_start,
    )


def invoke_fault_driver(
    *,
    driver: pathlib.Path,
    step: FaultStepV1,
    phase: str,
    process: base.ValidatorProcess,
    stage: base.HostStage,
    status: dict[str, Any],
    fault_window_seconds: int,
    io_root: pathlib.Path,
    label: str,
) -> tuple[dict[str, Any], FileResultV1]:
    arguments = [
        str(driver),
        "--schema-version",
        "1",
        "--phase",
        phase,
        "--kind",
        step.kind,
        "--target-validator-id",
        step.target_validator_id,
        "--target-host-id",
        step.target_host_id,
        "--management",
        validate_management(process.management),
        "--remote-run-root",
        validator_root(process, stage),
        "--process-id",
        str(status["process_id"]),
        "--process-instance",
        str(status["process_instance"]),
        "--window-seconds",
        str(fault_window_seconds),
    ]
    result = run_file_backed(
        arguments,
        io_root=io_root,
        label=label,
        timeout=fault_window_seconds + 30,
        bound=MAX_DRIVER_BYTES,
    )
    response = exact_driver_response(
        strict_stdout_object(result.stdout, f"fault driver {phase} response"),
        step=step,
        phase=phase,
    )
    return response, result


def wait_for_started_fleet_v1(
    processes: list[base.ValidatorProcess], stages: dict[str, base.HostStage],
    linux_paths: dict[str, str], statuses: dict[str, dict[str, Any]],
    read_nonces: dict[str, int], io_root: pathlib.Path,
) -> None:
    deadline = time.monotonic() + consensus.STARTUP_ALLOWANCE_SECONDS
    remaining = {process.validator_id: process for process in processes}
    while remaining:
        for validator_id, process in list(remaining.items()):
            nonce = read_nonces[validator_id]
            value = send_control(
                process=process, stage=stages[process.host_id], binary=linux_paths[process.host_id],
                status=statuses[validator_id], nonce=nonce, verb="status", fault="",
                io_root=io_root, label=f"fleet-started-{validator_id}-{nonce}",
                allow_pre_start=True,
            )
            read_nonces[validator_id] += 1
            if value["safety_halted"] or value["clean_stop_recorded"]:
                raise RuntimeError("runtime halted or stopped before fault campaign start")
            if value["barrier_phase"] == "started":
                remaining.pop(validator_id)
            if time.monotonic() >= deadline:
                raise RuntimeError("fault campaign did not observe all seven started runtimes")
        if remaining:
            time.sleep(CONTROL_POLL_SECONDS)


def restart_target_frontier_v1(
    observations: dict[str, dict[str, Any]], target_validator_id: str
) -> tuple[int, int] | None:
    """Return a safe planned-restart frontier only when target is not behind.

    Heights are a precondition, not restart authority. The signed RestartPrepare
    and every peer's exact cut/projection checks remain authoritative.
    """

    if len(observations) != 7 or target_validator_id not in observations:
        fail("restart frontier does not contain the exact direct-seven set")
    coordinates: dict[str, tuple[int, int]] = {}
    for validator_id, value in observations.items():
        finalized = value.get("finalized_height")
        application = value.get("application_height")
        if (
            isinstance(finalized, bool)
            or not isinstance(finalized, int)
            or finalized < 0
            or isinstance(application, bool)
            or not isinstance(application, int)
            or application < 0
        ):
            fail(f"restart frontier has invalid coordinates for {validator_id}")
        coordinates[validator_id] = (finalized, application)
    target = coordinates[target_validator_id]
    if target[0] != target[1]:
        return None
    for validator_id, (finalized, application) in coordinates.items():
        if finalized != application:
            return None
        if validator_id != target_validator_id and (
            finalized > target[0] or application > target[1]
        ):
            return None
    return target


def advance_restart_frontier_stability_v1(
    prior_frontier: tuple[int, int] | None,
    stable_polls: int,
    frontier: tuple[int, int] | None,
) -> tuple[tuple[int, int] | None, int]:
    """Advance consecutive safe-frontier evidence without requiring a frozen chain.

    A pre-quiesced fleet may continue applying finite authenticated peer progress
    between observations. Requiring byte-identical heights therefore rejects a healthy
    live chain. Each accepted observation still proves the exact direct-seven
    not-behind predicate; this helper additionally rejects coordinate regression.
    """

    if frontier is None:
        return None, 0
    if prior_frontier is not None and (
        frontier[0] < prior_frontier[0] or frontier[1] < prior_frontier[1]
    ):
        fail("restart frontier regressed across consecutive safe observations")
    return frontier, stable_polls + 1


def restart_prequiesce_order_v1(
    processes: list[base.ValidatorProcess], target_validator_id: str
) -> list[base.ValidatorProcess]:
    if (
        len(processes) != 7
        or len({process.validator_id for process in processes}) != 7
        or target_validator_id not in {process.validator_id for process in processes}
    ):
        fail("restart pre-quiesce requires one exact direct-seven target")
    return [
        process for process in processes if process.validator_id != target_validator_id
    ] + [
        next(process for process in processes if process.validator_id == target_validator_id)
    ]


def exact_restart_quiesce_response_v1(
    value: dict[str, Any], *, requested: bool, validator_id: str
) -> dict[str, Any]:
    if (
        value["barrier_phase"] != "started"
        or value["restart_quiesce_requested"] is not requested
        or value["expected_fault"] != ""
        or value["active_faults"]
        or value["restart_pending_catchup"]
        or value["restart_completed"]
        or value["final_tip_recorded"]
        or value["clean_stop_recorded"]
        or value["safety_halted"]
    ):
        state = "set" if requested else "cleared"
        raise RuntimeError(
            f"validator {validator_id} restart pre-quiesce was not cleanly {state}"
        )
    return value


def send_restart_quiesce_control_v1(
    *,
    process: base.ValidatorProcess,
    stage: base.HostStage,
    binary: str,
    status: dict[str, Any],
    nonce: int,
    verb: str,
    io_root: pathlib.Path,
    label: str,
) -> dict[str, Any]:
    if verb not in {"quiesce_restart", "clear_restart_quiesce"}:
        raise RuntimeError("restart pre-quiesce helper received a foreign verb")
    errors: list[str] = []
    for attempt in (1, 2):
        try:
            return send_control(
                process=process,
                stage=stage,
                binary=binary,
                status=status,
                nonce=nonce,
                verb=verb,
                fault="",
                io_root=io_root,
                label=f"{label}-attempt-{attempt}",
            )
        except (OSError, subprocess.SubprocessError, RuntimeError, SystemExit) as error:
            errors.append(str(error))
    raise RuntimeError(
        f"validator {process.validator_id} {verb} omitted an exact response after retry: "
        + " | ".join(errors)
    )


def clear_restart_prequiesce_v1(
    *,
    processes: list[base.ValidatorProcess],
    stages: dict[str, base.HostStage],
    linux_paths: dict[str, str],
    statuses: dict[str, dict[str, Any]],
    command_nonces: dict[str, int],
    io_root: pathlib.Path,
    label_prefix: str,
) -> list[dict[str, Any]]:
    cleared: list[dict[str, Any]] = []
    failures: list[str] = []
    if len({process.validator_id for process in processes}) != len(processes):
        raise RuntimeError("restart pre-quiesce clear contains duplicate validators")
    for process in reversed(processes):
        nonce = command_nonces[process.validator_id]
        try:
            value = send_restart_quiesce_control_v1(
                process=process,
                stage=stages[process.host_id],
                binary=linux_paths[process.host_id],
                status=statuses[process.validator_id],
                nonce=nonce,
                verb="clear_restart_quiesce",
                io_root=io_root,
                label=f"{label_prefix}-{process.validator_id}",
            )
            command_nonces[process.validator_id] += 1
            exact_restart_quiesce_response_v1(
                value, requested=False, validator_id=process.validator_id
            )
            cleared.append({"validator_id": process.validator_id, "response": value})
        except (OSError, subprocess.SubprocessError, RuntimeError, SystemExit) as error:
            failures.append(f"{process.validator_id}: {error}")
    if failures:
        raise RuntimeError(
            "restart pre-quiesce clear failed for: " + "; ".join(failures)
        )
    return cleared


def resume_resident_peers_v1(
    *, processes: list[base.ValidatorProcess], stages: dict[str, base.HostStage],
    linux_paths: dict[str, str], statuses: dict[str, dict[str, Any]],
    command_nonces: dict[str, int], read_nonces: dict[str, int],
    io_root: pathlib.Path, timeout_seconds: int,
) -> dict[str, dict[str, Any]]:
    if len(processes) != 6 or len({p.validator_id for p in processes}) != 6:
        raise RuntimeError("resident recovery requires six distinct non-target peers")
    deadline = time.monotonic() + timeout_seconds
    for peer in processes:
        if statuses[peer.validator_id]["process_instance"] != 1:
            raise RuntimeError("resident recovery cannot replace a peer process instance")
        send_control(
            process=peer, stage=stages[peer.host_id], binary=linux_paths[peer.host_id],
            status=statuses[peer.validator_id], nonce=command_nonces[peer.validator_id],
            verb="resume_restart_peer", fault="", io_root=io_root,
            label=f"resident-peer-resume-{peer.validator_id}",
        )
        command_nonces[peer.validator_id] += 1
    completed: dict[str, dict[str, Any]] = {}
    while time.monotonic() < deadline:
        for peer in processes:
            if peer.validator_id in completed:
                continue
            nonce = read_nonces[peer.validator_id]
            response = send_control(
                process=peer, stage=stages[peer.host_id], binary=linux_paths[peer.host_id],
                status=statuses[peer.validator_id], nonce=nonce, verb="status", fault="",
                io_root=io_root, label=f"resident-peer-status-{peer.validator_id}-{nonce}",
            )
            read_nonces[peer.validator_id] += 1
            if response["safety_halted"] or response["clean_stop_recorded"]:
                raise RuntimeError("resident peer halted before authenticated recovery")
            if (response["restart_completed"] and not response["restart_pending_catchup"]
                    and not response["restart_quiesce_requested"]):
                completed[peer.validator_id] = response
        if len(completed) == 6:
            return completed
        time.sleep(CONTROL_POLL_SECONDS)
    raise RuntimeError("resident peer recovery did not complete within the original window")


def quiesce_restart_fleet_v1(
    *,
    processes: list[base.ValidatorProcess],
    target_validator_id: str,
    stages: dict[str, base.HostStage],
    linux_paths: dict[str, str],
    statuses: dict[str, dict[str, Any]],
    command_nonces: dict[str, int],
    io_root: pathlib.Path,
) -> tuple[list[base.ValidatorProcess], list[dict[str, Any]]]:
    ordered = restart_prequiesce_order_v1(processes, target_validator_id)
    quiesced: list[base.ValidatorProcess] = []
    observations: list[dict[str, Any]] = []
    try:
        for process in ordered:
            nonce = command_nonces[process.validator_id]
            value = send_restart_quiesce_control_v1(
                process=process,
                stage=stages[process.host_id],
                binary=linux_paths[process.host_id],
                status=statuses[process.validator_id],
                nonce=nonce,
                verb="quiesce_restart",
                io_root=io_root,
                label=f"restart-prequiesce-{process.validator_id}",
            )
            command_nonces[process.validator_id] += 1
            quiesced.append(process)
            exact_restart_quiesce_response_v1(
                value, requested=True, validator_id=process.validator_id
            )
            observations.append({"validator_id": process.validator_id, "response": value})
    except (OSError, subprocess.SubprocessError, RuntimeError, SystemExit) as error:
        try:
            clear_restart_prequiesce_v1(
                processes=quiesced,
                stages=stages,
                linux_paths=linux_paths,
                statuses=statuses,
                command_nonces=command_nonces,
                io_root=io_root,
                label_prefix="restart-prequiesce-rollback",
            )
        except (OSError, subprocess.SubprocessError, RuntimeError, SystemExit) as rollback:
            raise RuntimeError(
                f"fleet restart pre-quiesce failed and rollback was incomplete: {rollback}"
            ) from error
        raise RuntimeError(
            "fleet restart pre-quiesce failed and all accepted pauses were cleared"
        ) from error
    return ordered, observations


def wait_for_restart_target_frontier_v1(
    *,
    processes: list[base.ValidatorProcess],
    target: base.ValidatorProcess,
    runtimes: dict[str, RuntimeProcessV1],
    stages: dict[str, base.HostStage],
    linux_paths: dict[str, str],
    statuses: dict[str, dict[str, Any]],
    read_nonces: dict[str, int],
    io_root: pathlib.Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    """Observe a stable target-at-frontier window before signed restart prepare.

    Non-targets are read first and the selected target last. Two consecutive
    safe target frontiers are required. The target coordinates may advance while
    authenticated peer drain continues, but they may not regress and no clean peer
    may be ahead in either observation. No read response can construct a cut,
    signature, or lifecycle transition.
    """

    if len(processes) != 7 or target.validator_id not in {p.validator_id for p in processes}:
        fail("restart frontier requires the exact selected direct-seven target")
    deadline = time.monotonic() + timeout_seconds
    ordered = [p for p in processes if p.validator_id != target.validator_id] + [target]
    prior_frontier: tuple[int, int] | None = None
    stable_polls = 0
    attempt = 0
    while True:
        attempt += 1
        require_non_target_processes_live(runtimes, target.validator_id)
        observations: dict[str, dict[str, Any]] = {}
        for process in ordered:
            validator_id = process.validator_id
            nonce = read_nonces[validator_id]
            value = send_control(
                process=process,
                stage=stages[process.host_id],
                binary=linux_paths[process.host_id],
                status=statuses[validator_id],
                nonce=nonce,
                verb="status",
                fault="",
                io_root=io_root,
                label=f"restart-frontier-{attempt:04d}-{validator_id}-{nonce}",
            )
            read_nonces[validator_id] += 1
            if (
                value["barrier_phase"] != "started"
                or value["safety_halted"]
                or value["clean_stop_recorded"]
                or value["restart_quiesce_requested"] is not True
                or value["restart_pending_catchup"]
                or value["restart_completed"]
                or value["active_faults"]
                or value["expected_fault"] != ""
            ):
                raise RuntimeError(
                    f"validator {validator_id} is not clean at restart frontier"
                )
            observations[validator_id] = value
        frontier = restart_target_frontier_v1(observations, target.validator_id)
        prior_frontier, stable_polls = advance_restart_frontier_stability_v1(
            prior_frontier, stable_polls, frontier
        )
        if stable_polls >= RESTART_FRONTIER_STABLE_POLLS_V1:
            require_non_target_processes_live(runtimes, target.validator_id)
            return {
                "schema_version": 1,
                "profile": "poco-g3-planned-restart-frontier-v1",
                "target_validator_id": target.validator_id,
                "finalized_height": frontier[0],
                "application_height": frontier[1],
                "stable_polls": stable_polls,
                "poll_attempts": attempt,
                "validator_heights": {
                    validator_id: {
                        "finalized_height": value["finalized_height"],
                        "application_height": value["application_height"],
                        "journal_event_sequence": value["journal_event_sequence"],
                        "journal_event_sha256": value["journal_event_sha256"],
                    }
                    for validator_id, value in sorted(observations.items())
                },
                "production_activation": False,
            }
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "selected restart target never held two consecutive not-behind frontiers"
            )
        time.sleep(CONTROL_POLL_SECONDS)


def wait_for_signed_fault_state(
    *,
    process: base.ValidatorProcess,
    stage: base.HostStage,
    binary: str,
    status: dict[str, Any],
    step: FaultStepV1,
    phase: str,
    read_nonce: int,
    io_root: pathlib.Path,
    label_prefix: str,
    timeout_seconds: int,
) -> tuple[dict[str, Any], int]:
    fault_semantics.require_primary_signed_transition(step.kind)
    deadline = time.monotonic() + timeout_seconds
    attempt = 0
    while True:
        attempt += 1
        response = send_control(
            process=process,
            stage=stage,
            binary=binary,
            status=status,
            nonce=read_nonce,
            verb="status",
            fault="",
            io_root=io_root,
            label=f"{label_prefix}-{attempt:04d}",
        )
        read_nonce += 1
        if response["safety_halted"]:
            raise RuntimeError(
                f"validator {process.validator_id} safety-halted during {step.kind}"
            )
        if phase == "applied":
            satisfied = (
                step.kind in response["active_faults"]
                and step.kind not in response["recovered_faults"]
            )
        elif phase == "recovered":
            satisfied = (
                step.kind not in response["active_faults"]
                and step.kind in response["recovered_faults"]
                and (
                    not step.restart
                    or (
                        response["process_instance"] == 2
                        and response["restart_completed"] is True
                        and response["restart_pending_catchup"] is False
                    )
                )
            )
        else:
            raise AssertionError("unknown signed fault phase")
        if satisfied:
            return response, read_nonce
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"validator {process.validator_id} omitted signed {phase} for {step.kind}"
            )
        time.sleep(CONTROL_POLL_SECONDS)


def fault_journal_summary(
    value: object,
    *,
    certificate: dict[str, Any],
    run_id: str,
    validator_id: str,
    coordinator_anchor: str,
    expected_faults: set[str],
    restarted: bool,
) -> dict[str, Any]:
    if not expected_faults <= fault_semantics.CONNECTIVITY_FAULTS:
        fail(
            "primary runtime journal fault count may contain only signed "
            "connectivity Applied/Recovered transitions"
        )
    if not isinstance(value, dict):
        fail("observer runtime-journal verification is not an object")
    expected_keys = {
        "schema_version",
        "status",
        "run_id",
        "validator_id",
        "validator_set_sha256",
        "coordinator_manifest_sha256",
        "candidate_source_sha256",
        "binary_sha256",
        "config_sha256",
        "barrier_round",
        "fleet_ready_event_sequence",
        "fleet_ready_event_sha256",
        "fleet_ready_previous_event_sequence",
        "fleet_ready_previous_event_sha256",
        "fleet_ready_set_sha256",
        "fleet_start_certificate_sha256",
        "process_instance_count",
        "event_count",
        "runtime_event_sequence",
        "runtime_event_sha256",
        "finalized_height",
        "finalized_block_id",
        "finalized_state_root",
        "finalized_chain_root",
        "recovered_fault_count",
        "restart_completed",
        "clean_stop",
        "signature_verified",
        "semantics_verified",
        "g3_evidence_complete",
        "geo_wan_evidence",
        "production_activation",
    }
    if set(value) != expected_keys:
        fail("observer fault-journal verification keys differ from contract")
    process_count = 2 if restarted else 1
    if (
        value["schema_version"] != 1
        or value["status"] != "runtime-journal-signature-and-semantics-verified"
        or value["run_id"] != run_id
        or value["validator_id"] != validator_id
        or value["coordinator_manifest_sha256"] != coordinator_anchor
        or isinstance(value["process_instance_count"], bool)
        or not isinstance(value["process_instance_count"], int)
        or value["process_instance_count"] != process_count
        or isinstance(value["recovered_fault_count"], bool)
        or not isinstance(value["recovered_fault_count"], int)
        or value["recovered_fault_count"] != len(expected_faults)
        or value["restart_completed"] is not restarted
        or value["clean_stop"] is not True
        or value["signature_verified"] is not True
        or value["semantics_verified"] is not True
        or value["g3_evidence_complete"] is not False
        or value["geo_wan_evidence"] is not False
        or value["production_activation"] is not False
        or any(
            isinstance(value[field], bool)
            or not isinstance(value[field], int)
            or value[field] <= 0
            for field in (
                "event_count",
                "runtime_event_sequence",
                "finalized_height",
                "barrier_round",
                "fleet_ready_event_sequence",
                "fleet_ready_previous_event_sequence",
            )
        )
        or value["event_count"] != value["runtime_event_sequence"] + 1
        or value["barrier_round"] != 1
        or value["fleet_ready_previous_event_sequence"] + 1
        != value["fleet_ready_event_sequence"]
        or any(
            not isinstance(value[field], str) or HEX64.fullmatch(value[field]) is None
            for field in (
                "validator_set_sha256",
                "coordinator_manifest_sha256",
                "candidate_source_sha256",
                "binary_sha256",
                "config_sha256",
                "fleet_ready_event_sha256",
                "fleet_ready_previous_event_sha256",
                "fleet_ready_set_sha256",
                "fleet_start_certificate_sha256",
                "runtime_event_sha256",
                "finalized_block_id",
                "finalized_state_root",
                "finalized_chain_root",
            )
        )
    ):
        fail("observer fault-journal verification crosses the campaign profile")
    if (
        certificate.get("selected_validator_id") != validator_id
        or certificate.get("barrier_round") != value["barrier_round"]
        or certificate.get("ready_set_sha256") != value["fleet_ready_set_sha256"]
        or certificate.get("fleet_start_certificate_sha256")
        != value["fleet_start_certificate_sha256"]
        or certificate.get("selected_fleet_ready_event_sequence")
        != value["fleet_ready_event_sequence"]
        or certificate.get("selected_fleet_ready_event_sha256")
        != value["fleet_ready_event_sha256"]
        or certificate.get("selected_pre_ready_journal_sequence")
        != value["fleet_ready_previous_event_sequence"]
        or certificate.get("selected_pre_ready_journal_sha256")
        != value["fleet_ready_previous_event_sha256"]
    ):
        fail("observer fleet certificate does not join the fault journal")
    return value


def launch_runtime(
    *,
    process: base.ValidatorProcess,
    stage: base.HostStage,
    binary: str,
    duration_seconds: int,
    max_blocks: int,
    process_io: pathlib.Path,
    process_instance: int,
    peer_lease_socket: str | None = None,
    process2_resume: Process2ResumeArtifactsV1 | None = None,
) -> RuntimeProcessV1:
    command, report, journal, metrics, final_state, certificate = consensus.command_for(
        process, stage, binary, duration_seconds, max_blocks, peer_lease_socket
    )
    resume_arguments: list[str] = []
    if process2_resume is not None:
        if process_instance != 2 or peer_lease_socket is None:
            raise RuntimeError(
                "process2 resume requires process instance 2 and an external peer fence"
            )
        resume_arguments = process2_resume_arguments_v1(process2_resume)
        if not stage.remote:
            command.extend(resume_arguments)
    if stage.remote:
        # `wait` returning the dedicated successful handoff status must not be
        # consumed by `set -e`. Preserve every child status, including 75,
        # through the SSH process observed by the supervisor.
        arguments = [
            binary,
            "run-consensus",
            validator_root(process, stage),
            validator_config(process, stage),
            str(duration_seconds),
            str(max_blocks),
            report,
        ]
        if peer_lease_socket is not None:
            arguments.extend(("--peer-lease-socket", peer_lease_socket))
        arguments.extend(resume_arguments)
        child_command = shlex.join(arguments)
        remote = (
            "set -eu; child=''; "
            "cleanup() { if test -n \"$child\"; then "
            "kill \"$child\" 2>/dev/null || true; "
            "wait \"$child\" 2>/dev/null || true; fi; }; "
            "trap cleanup EXIT HUP INT TERM; "
            f"{child_command} & child=$!; "
            "if wait \"$child\"; then status=0; else status=$?; fi; "
            "child=''; exit \"$status\""
        )
        command = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
            process.management,
            remote,
        ]
    capture = base.open_process_capture(
        process_io,
        process.validator_id
        if process_instance == 1
        else f"{process.validator_id}.instance-{process_instance}",
    )
    try:
        child = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=capture.stdout,
            stderr=capture.stderr,
        )
    except BaseException:
        base.close_process_capture(capture)
        raise
    return RuntimeProcessV1(
        process,
        command,
        child,
        capture,
        report,
        journal,
        metrics,
        final_state,
        certificate,
        process_instance,
    )


def stop_runtime(runtime: RuntimeProcessV1) -> None:
    if runtime.child.poll() is None:
        runtime.child.kill()
        try:
            runtime.child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
    try:
        base.close_process_capture(runtime.capture)
    except OSError:
        pass


def require_non_target_processes_live(
    runtimes: dict[str, RuntimeProcessV1], target_validator_id: str
) -> None:
    for validator_id, runtime in runtimes.items():
        if validator_id == target_validator_id:
            continue
        returncode = runtime.child.poll()
        if returncode is not None:
            raise RuntimeError(
                f"non-target validator {validator_id} exited {returncode} during target handoff"
            )


def wait_for_exact_target_handoff_exit(
    *,
    runtime: RuntimeProcessV1,
    runtimes: dict[str, RuntimeProcessV1],
    timeout_seconds: int,
) -> int:
    deadline = time.monotonic() + timeout_seconds
    while True:
        require_non_target_processes_live(runtimes, runtime.process.validator_id)
        returncode = runtime.child.poll()
        if returncode is not None:
            require_non_target_processes_live(runtimes, runtime.process.validator_id)
            return returncode
        if time.monotonic() >= deadline:
            raise RuntimeError("selected target omitted its bounded process-1 handoff exit")
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))


def require_target_handoff_exit_status(returncode: int) -> None:
    if returncode != PROCESS1_TARGET_PARKED_EXIT_STATUS_V1:
        raise RuntimeError(
            f"selected process-1 target exited {returncode}, not exact handoff status 75"
        )


def exact_process2_inert_exit(
    returncode: int, stdout: bytes, stderr: bytes
) -> dict[str, Any]:
    expected_stderr = (
        "trnm-poco-lab-validator failed: "
        f"{PROCESS2_INERT_BOUNDARY_MESSAGE_V1}\n"
    ).encode("utf-8")
    if (
        returncode != PROCESS2_INERT_EXIT_STATUS_V1
        or stdout != b"\n"
        or stderr != expected_stderr
    ):
        raise RuntimeError(
            "process 2 did not stop at the exact authenticated inert-recovery boundary"
        )
    return {
        "returncode": returncode,
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "authenticated_inert_boundary": True,
    }


def require_no_target_normal_terminal_artifacts(
    *,
    runtime: RuntimeProcessV1,
    stage: base.HostStage,
    io_root: pathlib.Path,
    label: str,
) -> None:
    paths = (
        runtime.report_source,
        runtime.metrics_source,
        runtime.final_state_source,
        exact_remote_root(
            f"{validator_root(runtime.process, stage)}/archive-terminal-seal.json"
        ),
    )
    if stage.remote:
        validate_management(runtime.process.management)
        predicates = " ".join(
            f"test ! -e {base.shell_path(path)}; test ! -L {base.shell_path(path)};"
            for path in paths
        )
        run_file_backed(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                runtime.process.management,
                f"set -eu; {predicates}",
            ],
            io_root=io_root,
            label=label,
            timeout=30,
        )
        return
    for raw_path in paths:
        path = pathlib.Path(raw_path)
        if path.exists() or path.is_symlink():
            raise RuntimeError(
                f"target handoff produced forbidden normal terminal artifact {path.name}"
            )


def supervise_target_process1_handoff(
    *,
    runtimes: dict[str, RuntimeProcessV1],
    process: base.ValidatorProcess,
    stage: base.HostStage,
    binary: str,
    run_id: str,
    duration_seconds: int,
    max_blocks: int,
    process_io: pathlib.Path,
    control_io: pathlib.Path,
    command_nonce: int,
    timeout_seconds: int,
    peer_lease_socket: str | None = None,
) -> tuple[RuntimeProcessV1, dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Perform the sole exact P1-target status-75 to P2 supervisor handoff.

    This is process orchestration only. It does not make the handoff a
    `validator_process_kill` observation and grants no recovery or G3 truth.
    """

    runtime = runtimes.get(process.validator_id)
    if (
        runtime is None
        or runtime.process is not process
        or runtime.process_instance != 1
        or len(runtimes) != 7
        or set(runtimes)
        != {candidate.process.validator_id for candidate in runtimes.values()}
        or command_nonce <= 0
    ):
        raise RuntimeError("target handoff does not own one exact process-1 runtime")
    require_non_target_processes_live(runtimes, process.validator_id)
    saved_locator = wait_control_locator(
        process=process,
        stage=stage,
        run_id=run_id,
        process_instance=1,
        io_root=control_io,
        label=f"handoff-save-control-{process.validator_id}",
        timeout_seconds=timeout_seconds,
    )
    prepare = send_control(
        process=process,
        stage=stage,
        binary=binary,
        status=saved_locator.status,
        nonce=command_nonce,
        verb="prepare_restart",
        fault="",
        io_root=control_io,
        label=f"handoff-prepare-{process.validator_id}",
    )
    if (
        prepare["expected_fault"] != ""
        or prepare["active_faults"]
        or prepare["restart_quiesce_requested"] is not True
        or prepare["restart_pending_catchup"] is not False
        or prepare["restart_completed"] is not False
        or prepare["final_tip_recorded"] is not False
        or prepare["clean_stop_recorded"] is not False
        or prepare["safety_halted"] is not False
    ):
        raise RuntimeError("prepare_restart response is not one clean process-1 intent")

    returncode = wait_for_exact_target_handoff_exit(
        runtime=runtime,
        runtimes=runtimes,
        timeout_seconds=timeout_seconds,
    )
    stdout, _stderr = base.finish_process_capture(runtime.capture)
    require_target_handoff_exit_status(returncode)
    handoff = exact_target_handoff(
        strict_stdout_object(stdout, "process-1 target handoff"),
        run_id=run_id,
        validator_id=process.validator_id,
        process1_pid=saved_locator.status["process_id"],
    )
    require_no_target_normal_terminal_artifacts(
        runtime=runtime,
        stage=stage,
        io_root=control_io,
        label=f"handoff-no-terminal-artifacts-{process.validator_id}",
    )
    current_locator = wait_control_locator(
        process=process,
        stage=stage,
        run_id=run_id,
        process_instance=1,
        io_root=control_io,
        label=f"handoff-reread-control-{process.validator_id}",
        timeout_seconds=1,
    )
    exact_post_handoff_control_locator(
        current_locator, saved=saved_locator, handoff=handoff
    )
    remove_exact_control_locator(
        process=process,
        stage=stage,
        locator=current_locator,
        io_root=control_io,
        label=f"handoff-remove-control-{process.validator_id}",
    )
    require_non_target_processes_live(runtimes, process.validator_id)

    successor = launch_runtime(
        process=process,
        stage=stage,
        binary=binary,
        duration_seconds=duration_seconds,
        max_blocks=max_blocks,
        process_io=process_io,
        process_instance=2,
        peer_lease_socket=peer_lease_socket,
    )
    runtimes[process.validator_id] = successor
    if successor.command != runtime.command:
        raise RuntimeError("process 2 was not launched with the exact process-1 command")
    process2_returncode = wait_for_exact_target_handoff_exit(
        runtime=successor,
        runtimes=runtimes,
        timeout_seconds=max(timeout_seconds, consensus.STARTUP_ALLOWANCE_SECONDS),
    )
    process2_stdout, process2_stderr = base.finish_process_capture(successor.capture)
    process2_exit = exact_process2_inert_exit(
        process2_returncode, process2_stdout, process2_stderr
    )
    require_no_target_normal_terminal_artifacts(
        runtime=successor,
        stage=stage,
        io_root=control_io,
        label=f"handoff-no-process2-terminal-artifacts-{process.validator_id}",
    )
    require_non_target_processes_live(runtimes, process.validator_id)
    return successor, process2_exit, prepare, handoff


def copy_remote_or_local(
    *,
    process: base.ValidatorProcess,
    stage: base.HostStage,
    source: str,
    target: pathlib.Path,
    io_root: pathlib.Path,
    label: str,
) -> None:
    if target.exists() or target.is_symlink():
        raise RuntimeError(f"evidence target already exists: {target}")
    if stage.remote:
        validate_management(process.management)
        exact_remote_root(source)
        run_file_backed(
            ["scp", "-q", f"{process.management}:{source}", str(target)],
            io_root=io_root,
            label=label,
            timeout=60,
            bound=MAX_CONTROL_BYTES,
        )
    else:
        source_path = pathlib.Path(source)
        metadata = source_path.lstat()
        if source_path.is_symlink() or not source_path.is_file() or metadata.st_size <= 0:
            raise RuntimeError("local runtime evidence is not one regular file")
        shutil.copyfile(source_path, target)
    metadata = target.lstat()
    if target.is_symlink() or not target.is_file() or metadata.st_size <= 0:
        target.unlink(missing_ok=True)
        raise RuntimeError("copied runtime evidence is empty or non-regular")
    target.chmod(0o600)


def observer_verify(
    *,
    process: base.ValidatorProcess,
    source: pathlib.Path,
    kind: str,
    mac_binary: str,
    observer_root: str,
    observer_stage: base.HostStage,
    coordinator_anchor: str,
    run_id: str,
    io_root: pathlib.Path,
    label: str,
) -> dict[str, Any]:
    validate_management(observer_stage.management)
    suffix = {
        "runtime-journal": "journal.jsonl",
        "consensus-report": "consensus.json",
        "runtime-metrics": "metrics.json",
        "runtime-final-state": "final-state.json",
    }[kind]
    remote_source = exact_remote_root(
        f"{observer_stage.root}/reports/{process.validator_id}.{suffix}"
    )
    remote_source = f"{consensus.observer_sealed_reports_root_v1(observer_stage)}/{pathlib.PurePosixPath(remote_source).name}"
    run_file_backed(
        [
            "scp",
            "-q",
            str(source),
            f"{observer_stage.management}:{remote_source}",
        ],
        io_root=io_root,
        label=f"{label}-copy",
        timeout=60,
    )
    run_file_backed(
        ["ssh", "-o", "BatchMode=yes", observer_stage.management,
         f"chmod 600 {shlex.quote(remote_source)}"],
        io_root=io_root, label=f"{label}-mode", timeout=30,
    )
    observer_config = exact_remote_root(
        f"{observer_root}/public/configs/{process.validator_id}.json"
    )
    arguments = [
        mac_binary,
        f"verify-{kind}",
        observer_root,
        observer_config,
        remote_source,
        coordinator_anchor,
    ]
    command = " ".join(shlex.quote(argument) for argument in arguments)
    result = run_file_backed(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            observer_stage.management,
            f"set -eu; exec {command}",
        ],
        io_root=io_root,
        label=f"{label}-verify",
        timeout=60,
    )
    value = strict_stdout_object(result.stdout, f"observer {kind} verification")
    if kind == "consensus-report":
        return consensus.exact_verified_summary(
            value,
            run_id=run_id,
            validator_id=process.validator_id,
            coordinator_anchor=coordinator_anchor,
        )
    if kind in {"runtime-metrics", "runtime-final-state"}:
        return consensus.exact_runtime_verified_summary(
            value,
            kind=kind,
            run_id=run_id,
            validator_id=process.validator_id,
        )
    return value


def observer_verify_fleet_start_certificate(
    *,
    process: base.ValidatorProcess,
    source: pathlib.Path,
    mac_binary: str,
    observer_root: str,
    observer_stage: base.HostStage,
    coordinator_anchor: str,
    run_id: str,
    duration_seconds: int,
    max_blocks: int,
    validator_count: int,
    io_root: pathlib.Path,
    label: str,
) -> dict[str, Any]:
    """Copy, permission-pin, and independently verify one raw N/N certificate."""

    validate_management(observer_stage.management)
    remote_source = exact_remote_root(
        f"{observer_stage.root}/reports/{process.validator_id}.fleet-start-certificate.bin"
    )
    remote_source = f"{consensus.observer_sealed_reports_root_v1(observer_stage)}/{pathlib.PurePosixPath(remote_source).name}"
    run_file_backed(
        [
            "scp",
            "-q",
            str(source),
            f"{observer_stage.management}:{remote_source}",
        ],
        io_root=io_root,
        label=f"{label}-copy",
        timeout=60,
    )
    run_file_backed(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            observer_stage.management,
            f"chmod 600 {shlex.quote(remote_source)}",
        ],
        io_root=io_root,
        label=f"{label}-chmod",
        timeout=60,
    )
    observer_config = exact_remote_root(
        f"{observer_root}/public/configs/{process.validator_id}.json"
    )
    arguments = [
        mac_binary,
        "verify-fleet-start-certificate",
        observer_root,
        observer_config,
        remote_source,
        coordinator_anchor,
        str(duration_seconds),
        str(max_blocks),
    ]
    command = " ".join(shlex.quote(argument) for argument in arguments)
    result = run_file_backed(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            observer_stage.management,
            f"set -eu; exec {command}",
        ],
        io_root=io_root,
        label=f"{label}-verify",
        timeout=60,
    )
    return consensus.exact_fleet_start_certificate_summary(
        strict_stdout_object(
            result.stdout,
            f"observer fleet StartCertificate verification {process.validator_id}",
        ),
        run_id=run_id,
        validator_id=process.validator_id,
        coordinator_anchor=coordinator_anchor,
        duration_seconds=duration_seconds,
        max_blocks=max_blocks,
        validator_count=validator_count,
        artifact_sha256=base.sha256_file(source),
    )


def exact_selected_journal_faults_v1(
    raw: bytes, verified: dict[str, Any], expected: set[str],
) -> None:
    """Join labels in the SAME Mac-verified raw artifact, not merely its count.

    This is a projection check after strict crypto replay, never a verifier.
    The caller pins raw bytes before transport and compares them afterward.
    """
    if not raw or len(raw) > 32 * 1024 * 1024 or not raw.endswith(b"\n"):
        fail("fault journal bytes exceed the original bounded artifact contract")
    applied: set[str] = set()
    recovered: set[str] = set()
    count = 0
    last = None
    for line in raw.splitlines():
        event = base.strict_json_bytes(line, "Mac-verified runtime journal event")
        if not isinstance(event, dict):
            fail("fault journal event is not an object")
        if any(event.get(field) != verified[field] for field in (
            "run_id", "validator_id", "coordinator_manifest_sha256", "candidate_source_sha256",
            "binary_sha256", "config_sha256", "validator_set_sha256",
        )) or event.get("sequence") != count:
            fail("fault journal raw artifact differs from verified identity/sequence")
        kind, subject = event.get("kind"), event.get("subject")
        if kind == "fault_applied":
            if subject not in expected or subject in applied:
                fail("fault journal contains an unexpected or duplicate applied label")
            applied.add(subject)
        elif kind == "fault_recovered":
            if subject not in applied or subject in recovered:
                fail("fault journal contains an unmatched or duplicate recovered label")
            recovered.add(subject)
        count += 1
        last = event
    if (applied != expected or recovered != expected or count != verified["event_count"]
        or last is None or last.get("event_sha256") != verified["runtime_event_sha256"]
        or last.get("sequence") != verified["runtime_event_sequence"]):
        fail("fault journal selected labels/tip differ from independently verified evidence")


def collect_terminal_evidence(
    *,
    runtimes: dict[str, RuntimeProcessV1],
    stages: dict[str, base.HostStage],
    mac_binary: str,
    observer_root: str,
    observer_stage: base.HostStage,
    coordinator_anchor: str,
    run_id: str,
    output: pathlib.Path,
    process_io: pathlib.Path,
    expected_faults: dict[str, set[str]],
    restarted_validator_id: str | None,
    duration_seconds: int,
    max_blocks: int,
    validator_count: int,
    deadline: float,
) -> list[dict[str, Any]]:
    directories = {
        "journal": output / "signed-runtime-journals",
        "report": output / "signed-reports",
        "metrics": output / "signed-runtime-metrics",
        "final": output / "signed-runtime-final-states",
        "certificate": output / "fleet-start-certificates",
    }
    for directory in directories.values():
        directory.mkdir(mode=0o700)
    results: list[dict[str, Any]] = []
    for validator_id, runtime in runtimes.items():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("fault campaign exceeded its terminal deadline")
        try:
            runtime.child.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                f"validator {validator_id} exceeded the fault-campaign deadline"
            ) from error
        _stdout, stderr = base.finish_process_capture(runtime.capture)
        if runtime.child.returncode != 0:
            raise RuntimeError(
                f"validator {validator_id} exited {runtime.child.returncode}: "
                f"{stderr.decode('utf-8', errors='replace')[:400]}"
            )
        process = runtime.process
        stage = stages[process.host_id]
        paths = {
            "journal": directories["journal"] / f"{validator_id}.jsonl",
            "report": directories["report"] / f"{validator_id}.json",
            "metrics": directories["metrics"] / f"{validator_id}.json",
            "final": directories["final"] / f"{validator_id}.json",
            "certificate": directories["certificate"] / f"{validator_id}.bin",
        }
        for key, source in (
            ("journal", runtime.journal_source),
            ("report", runtime.report_source),
            ("metrics", runtime.metrics_source),
            ("final", runtime.final_state_source),
            ("certificate", runtime.fleet_start_certificate_source),
        ):
            copy_remote_or_local(
                process=process,
                stage=stage,
                source=source,
                target=paths[key],
                io_root=process_io,
                label=f"collect-{validator_id}-{key}",
            )
        certificate = observer_verify_fleet_start_certificate(
            process=process,
            source=paths["certificate"],
            mac_binary=mac_binary,
            observer_root=observer_root,
            observer_stage=observer_stage,
            coordinator_anchor=coordinator_anchor,
            run_id=run_id,
            duration_seconds=duration_seconds,
            max_blocks=max_blocks,
            validator_count=validator_count,
            io_root=process_io,
            label=f"observe-{validator_id}-certificate",
        )
        journal_bytes = read_bounded(paths["journal"], 32 * 1024 * 1024, "runtime journal")
        raw_journal_verification = observer_verify(
            process=process,
            source=paths["journal"],
            kind="runtime-journal",
            mac_binary=mac_binary,
            observer_root=observer_root,
            observer_stage=observer_stage,
            coordinator_anchor=coordinator_anchor,
            run_id=run_id,
            io_root=process_io,
            label=f"observe-{validator_id}-journal",
        )
        journal = fault_journal_summary(
            raw_journal_verification,
            certificate=certificate,
            run_id=run_id,
            validator_id=validator_id,
            coordinator_anchor=coordinator_anchor,
            expected_faults=expected_faults[validator_id],
            restarted=validator_id == restarted_validator_id,
        )
        if read_bounded(paths["journal"], 32 * 1024 * 1024, "runtime journal") != journal_bytes:
            fail("runtime journal changed during independent Mac verification")
        exact_selected_journal_faults_v1(journal_bytes, journal, expected_faults[validator_id])
        report = observer_verify(
            process=process,
            source=paths["report"],
            kind="consensus-report",
            mac_binary=mac_binary,
            observer_root=observer_root,
            observer_stage=observer_stage,
            coordinator_anchor=coordinator_anchor,
            run_id=run_id,
            io_root=process_io,
            label=f"observe-{validator_id}-report",
        )
        metrics = observer_verify(
            process=process,
            source=paths["metrics"],
            kind="runtime-metrics",
            mac_binary=mac_binary,
            observer_root=observer_root,
            observer_stage=observer_stage,
            coordinator_anchor=coordinator_anchor,
            run_id=run_id,
            io_root=process_io,
            label=f"observe-{validator_id}-metrics",
        )
        final_state = observer_verify(
            process=process,
            source=paths["final"],
            kind="runtime-final-state",
            mac_binary=mac_binary,
            observer_root=observer_root,
            observer_stage=observer_stage,
            coordinator_anchor=coordinator_anchor,
            run_id=run_id,
            io_root=process_io,
            label=f"observe-{validator_id}-final",
        )
        report_document = base.strict_json_bytes(
            paths["report"].read_bytes(), f"signed report {validator_id}"
        )
        consensus.exact_process_evidence_chain(
            certificate=certificate,
            journal=journal,
            report_document=report_document,
            report=report,
            metrics=metrics,
            final_state=final_state,
        )
        results.append(
            {
                "validator_id": validator_id,
                "host_id": process.host_id,
                "faults": sorted(expected_faults[validator_id]),
                "restarted": validator_id == restarted_validator_id,
                "signed_runtime_journal_sha256": base.sha256_file(paths["journal"]),
                "signed_report_sha256": base.sha256_file(paths["report"]),
                "signed_runtime_metrics_sha256": base.sha256_file(paths["metrics"]),
                "signed_runtime_final_state_sha256": base.sha256_file(paths["final"]),
                "fleet_start_certificate_sha256": base.sha256_file(
                    paths["certificate"]
                ),
                "observer_journal_verification": journal,
                "observer_fleet_start_certificate_verification": certificate,
                "observer_report_verification": report,
                "observer_metrics_verification": metrics,
                "observer_final_state_verification": final_state,
            }
        )
    consensus.exact_terminal_agreement(results, 7)
    return results


def write_restart_artifacts_v1(
    *,
    output: pathlib.Path,
    step: FaultStepV1,
    run_id: str,
    started_at: str,
    ended_at: str,
    transcript: list[dict[str, Any]],
) -> dict[str, Any]:
    if (
        not step.restart
        or fault_semantics.policy_for(step.kind).evidence_mode
        != fault_semantics.SIGNED_RESTART_CATCHUP
    ):
        raise RuntimeError("restart artifact writer received a non-restart step")
    if ended_at <= started_at or len(transcript) != 5:
        raise RuntimeError("restart transcript is incomplete or lacks wall-clock duration")
    required_surfaces = (
        "process1-handoff",
        "process2-inert-cut",
        "recovery-material",
        "process2-control",
        "process2-catchup",
    )
    if tuple(item.get("surface") for item in transcript) != required_surfaces:
        raise RuntimeError("restart transcript surfaces differ from the exact recovery order")
    fault_root = output / "faults"
    fault_root.mkdir(exist_ok=True, mode=0o700)
    log_path = fault_root / f"{step.ordinal:02d}-{step.kind}.commands.jsonl"
    log_bytes = b"".join(
        json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        for item in transcript
    )
    base.write_new(log_path, log_bytes, mode=0o600)
    schedule = {
        "schema_version": 1,
        "run_id": run_id,
        "kind": step.kind,
        "evidence_mode": fault_semantics.SIGNED_RESTART_CATCHUP,
        "target_validator_id": step.target_validator_id,
        "started_at": started_at,
        "ended_at": ended_at,
        "action": "status75-process1-park+exact-process2-zero-delta",
        "restore_action": "direct7-ready+direct7-start+live-fence-bound-process2-resume",
        "command_stdout_sha256": base.sha256_file(log_path),
        "applied": True,
        "restored": True,
    }
    schedule_path = fault_root / f"{step.ordinal:02d}-{step.kind}.schedule.json"
    base.write_new(schedule_path, base.canonical_json(schedule), mode=0o600)
    return {
        "ordinal": step.ordinal,
        "kind": step.kind,
        "target_validator_id": step.target_validator_id,
        "target_host_id": step.target_host_id,
        "restart": True,
        "schedule_path": str(schedule_path.relative_to(output)),
        "schedule_sha256": base.sha256_file(schedule_path),
        "command_log_path": str(log_path.relative_to(output)),
        "command_log_sha256": base.sha256_file(log_path),
        "signed_transition_observed": True,
        "evidence_mode": fault_semantics.SIGNED_RESTART_CATCHUP,
    }


def write_fault_artifacts(
    *,
    output: pathlib.Path,
    step: FaultStepV1,
    run_id: str,
    started_at: str,
    ended_at: str,
    transcript: list[dict[str, Any]],
    fault_driver_sha256: str,
) -> dict[str, Any]:
    fault_semantics.require_primary_signed_transition(step.kind)
    if HEX64.fullmatch(fault_driver_sha256) is None:
        raise RuntimeError("fault schedule lacks the pinned driver hash")
    fault_root = output / "faults"
    fault_root.mkdir(exist_ok=True, mode=0o700)
    log_path = fault_root / f"{step.ordinal:02d}-{step.kind}.commands.jsonl"
    log_bytes = b"".join(
        json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        for item in transcript
    )
    if not log_bytes:
        raise RuntimeError("fault command transcript is empty")
    base.write_new(log_path, log_bytes)
    log_sha256 = base.sha256_file(log_path)
    schedule = {
        "schema_version": 1,
        "run_id": run_id,
        "kind": step.kind,
        "evidence_mode": fault_semantics.policy_for(step.kind).evidence_mode,
        "target_validator_id": step.target_validator_id,
        "started_at": started_at,
        "ended_at": ended_at,
        "action": f"external-fault-driver-v1:{fault_driver_sha256}:apply",
        "restore_action": (
            "coordinator-exact-process-relaunch+external-fault-driver-v1:"
            f"{fault_driver_sha256}:restore"
            if step.restart
            else f"external-fault-driver-v1:{fault_driver_sha256}:restore"
        ),
        "command_stdout_sha256": log_sha256,
        "applied": True,
        "restored": True,
    }
    schedule_path = fault_root / f"{step.ordinal:02d}-{step.kind}.schedule.json"
    base.write_new(schedule_path, base.canonical_json(schedule))
    return {
        "ordinal": step.ordinal,
        "kind": step.kind,
        "target_validator_id": step.target_validator_id,
        "target_host_id": step.target_host_id,
        "restart": step.restart,
        "schedule_path": str(schedule_path.relative_to(output)),
        "schedule_sha256": base.sha256_file(schedule_path),
        "command_log_path": str(log_path.relative_to(output)),
        "command_log_sha256": log_sha256,
        "signed_transition_observed": True,
        "evidence_mode": fault_semantics.policy_for(step.kind).evidence_mode,
    }


def cleanup_fault_effects(
    active: list[
        tuple[
            FaultStepV1,
            base.ValidatorProcess,
            base.HostStage,
            dict[str, Any],
        ]
    ],
    *,
    driver: pathlib.Path,
    fault_window_seconds: int,
    io_root: pathlib.Path,
) -> list[str]:
    failures: list[str] = []
    for step, process, stage, status in reversed(active):
        try:
            invoke_fault_driver(
                driver=driver,
                step=step,
                phase="restore",
                process=process,
                stage=stage,
                status=status,
                fault_window_seconds=fault_window_seconds,
                io_root=io_root,
                label=f"cleanup-{step.ordinal:02d}-{step.kind}",
            )
        except (OSError, subprocess.SubprocessError, RuntimeError, SystemExit) as error:
            failures.append(f"{step.kind}: {error}")
    active.clear()
    return failures


def execute_campaign(
    *,
    coordinator: pathlib.Path,
    deployments: pathlib.Path,
    manifest: dict[str, Any],
    processes: list[base.ValidatorProcess],
    linux_binary: pathlib.Path,
    macos_binary: pathlib.Path,
    fault_driver: pathlib.Path,
    output: pathlib.Path,
    duration_seconds: int,
    max_blocks: int,
    fault_window_seconds: int,
    plan: dict[str, Any],
    stage_plan: dict[str, base.HostStage],
    campaign: str = "all",
    topology: dict[str, Any] | None = None,
    anchor_snapshot: consensus.CoordinatorAnchorSnapshot | None = None,
) -> None:
    expected_stage_plan = base.preflight_runtime_layout(
        processes, manifest["run_id"], output
    )
    if stage_plan != expected_stage_plan:
        fail("fault runner stage plan differs from the frozen runtime layout")
    # This check deliberately precedes output creation, deployment, process
    # launch, and driver pinning.  A vocabulary entry is not permission to
    # inject a fault whose authoritative observation path does not yet exist.
    try:
        fault_semantics.require_campaign_supported(campaign)
    except RuntimeError as error:
        fail(str(error))
    expected_plan = campaign_plan(
        manifest=manifest, processes=processes,
        coordinator_anchor=plan["coordinator_manifest_sha256"],
        driver_sha256=plan["fault_driver_sha256"], duration_seconds=duration_seconds,
        max_blocks=max_blocks, fault_window_seconds=fault_window_seconds,
        campaign=campaign, topology=topology,
    )
    if base.canonical_json(plan) != base.canonical_json(expected_plan):
        fail("campaign plan differs from the exact selected source and topology")
    if campaign != "all":
        if anchor_snapshot is None or anchor_snapshot.sha256 != plan["coordinator_manifest_sha256"]:
            fail("selected campaign requires an independent coordinator anchor")
        consensus.verify_coordinator_anchor(anchor_snapshot)
    try:
        plan["mesh_resource_preflight"] = (
            mesh_resources.preflight_mesh_fleet_resources_v1(
                processes, 7, placement_profile=plan.get("placement_profile", base.CANONICAL_PLACEMENT)
            )
        )
    except RuntimeError as error:
        fail(str(error))
    candidate = manifest["candidate"]
    run_id = manifest["run_id"]
    coordinator_anchor = plan["coordinator_manifest_sha256"]
    output.mkdir(parents=True, mode=0o700)
    output.chmod(0o700)
    base.write_new(output / "prestart-plan.json", base.canonical_json(plan))
    base.write_new(
        output / "coordinator-anchor.txt", f"{coordinator_anchor}\n".encode("ascii")
    )
    fault_driver = pin_fault_driver(
        fault_driver,
        output / "fault-driver-v1",
        plan["fault_driver_sha256"],
    )
    process_io = output / "process-io"
    control_io = output / "control-io"
    driver_io = output / "fault-driver-io"
    for directory in (process_io, control_io, driver_io):
        directory.mkdir(mode=0o700)

    stages: dict[str, base.HostStage] = {}
    runtimes: dict[str, RuntimeProcessV1] = {}
    statuses: dict[str, dict[str, Any]] = {}
    read_nonces = {process.validator_id: 1 for process in processes}
    command_nonces = {process.validator_id: 1 for process in processes}
    expected_faults = {process.validator_id: set() for process in processes}
    active_effects: list[
        tuple[
            FaultStepV1,
            base.ValidatorProcess,
            base.HostStage,
            dict[str, Any],
        ]
    ] = []
    fault_results: list[dict[str, Any]] = []
    process_by_id = {process.validator_id: process for process in processes}
    failure: str | None = None
    cleanup_failures: list[str] = []
    terminal_results: list[dict[str, Any]] = []
    terminal_agreement: dict[str, Any] | None = None
    restart_launch_count = 0
    peer_lease_daemons: list[consensus.RunningPeerLeaseDaemon] = []
    restarted_validator_id = next(
        (step["target_validator_id"] for step in plan["fault_order"] if step["restart"]),
        None,
    )
    started_ns = time.monotonic_ns()
    try:
        if anchor_snapshot is not None:
            consensus.verify_coordinator_anchor(anchor_snapshot)
        stages = base.create_stages(
            stage_plan, processes=processes, run_id=run_id, output=output
        )
        linux_paths, mac_binary, observer_root = base.deploy(
            stages,
            processes,
            deployments,
            linux_binary,
            macos_binary,
            candidate["linux_x86_64_sha256"],
            candidate["macos_arm64_sha256"],
        )
        observer_stage = stages["mac"]
        if campaign != "all" and (
            observer_stage.host_id != plan["observer"]["host_id"]
            or observer_stage.management != plan["observer"]["management"]
        ):
            fail("deployed Mac observer differs from the frozen placement")
        peer_lease_paths, peer_lease_daemons = consensus.start_peer_lease_daemons(
            stages, processes, linux_paths
        )
        for process in processes:
            stage = stages[process.host_id]
            runtimes[process.validator_id] = launch_runtime(
                process=process,
                stage=stage,
                binary=linux_paths[process.host_id],
                duration_seconds=duration_seconds,
                max_blocks=max_blocks,
                process_io=process_io,
                process_instance=1,
                peer_lease_socket=peer_lease_paths[process.host_id].socket,
            )
        for process in processes:
            statuses[process.validator_id] = wait_control_status(
                process=process,
                stage=stages[process.host_id],
                run_id=run_id,
                process_instance=1,
                io_root=control_io,
                label=f"status-initial-{process.validator_id}",
                timeout_seconds=consensus.STARTUP_ALLOWANCE_SECONDS,
            )

        wait_for_started_fleet_v1(processes, stages, linux_paths, statuses, read_nonces, control_io)
        steps = selected_fault_plan(processes, campaign)
        for step in steps:
            policy = fault_semantics.policy_for(step.kind)
            process = process_by_id[step.target_validator_id]
            stage = stages[process.host_id]
            binary = linux_paths[process.host_id]
            if step.restart:
                if (
                    policy.evidence_mode != fault_semantics.SIGNED_RESTART_CATCHUP
                    or restart_launch_count != 0
                ):
                    raise RuntimeError(
                        "restart handoff differs from the sole signed-catchup slot"
                    )
                restart_started_at = utc_now()
                quiesced_processes, fleet_quiesce = quiesce_restart_fleet_v1(
                    processes=processes,
                    target_validator_id=process.validator_id,
                    stages=stages,
                    linux_paths=linux_paths,
                    statuses=statuses,
                    command_nonces=command_nonces,
                    io_root=control_io,
                )
                target_quiesce = next(
                    item["response"]
                    for item in fleet_quiesce
                    if item["validator_id"] == process.validator_id
                )
                try:
                    restart_frontier = wait_for_restart_target_frontier_v1(
                        processes=processes,
                        target=process,
                        runtimes=runtimes,
                        stages=stages,
                        linux_paths=linux_paths,
                        statuses=statuses,
                        read_nonces=read_nonces,
                        io_root=control_io,
                        timeout_seconds=fault_window_seconds,
                    )
                except Exception as frontier_error:
                    try:
                        clear_restart_prequiesce_v1(
                            processes=quiesced_processes,
                            stages=stages,
                            linux_paths=linux_paths,
                            statuses=statuses,
                            command_nonces=command_nonces,
                            io_root=control_io,
                            label_prefix="restart-frontier-prequiesce-clear",
                        )
                    except Exception as clear_error:
                        raise RuntimeError(
                            "restart frontier failed and direct-seven pre-quiesce "
                            f"rollback was incomplete: {clear_error}"
                        ) from frontier_error
                    for validator_id, runtime in runtimes.items():
                        returncode = runtime.child.poll()
                        if returncode is not None:
                            raise RuntimeError(
                                f"validator {validator_id} exited {returncode} during "
                                "restart pre-quiesce rollback"
                            ) from frontier_error
                    raise RuntimeError(
                        "restart frontier failed; direct-seven pre-quiesce was "
                        "explicitly cleared"
                    ) from frontier_error

                inert_runtime, process2_exit, prepare, handoff = supervise_target_process1_handoff(
                    runtimes=runtimes,
                    process=process,
                    stage=stage,
                    binary=binary,
                    run_id=run_id,
                    duration_seconds=duration_seconds,
                    max_blocks=max_blocks,
                    process_io=process_io,
                    control_io=control_io,
                    command_nonce=command_nonces[process.validator_id],
                    timeout_seconds=fault_window_seconds,
                    peer_lease_socket=peer_lease_paths[process.host_id].socket,
                )
                command_nonces[process.validator_id] += 1
                if runtimes[process.validator_id] is not inert_runtime:
                    raise RuntimeError("target inert process-2 owner was not retained")
                require_non_target_processes_live(runtimes, process.validator_id)
                artifacts, material_summary = commission_process2_recovery_material_v1(
                    processes=processes,
                    stages=stages,
                    linux_paths=linux_paths,
                    target=process,
                    peer_lease_socket=peer_lease_paths[process.host_id].socket,
                    run_id=run_id,
                    io_root=control_io,
                )
                require_non_target_processes_live(runtimes, process.validator_id)
                resumed_runtime = launch_runtime(
                    process=process,
                    stage=stage,
                    binary=binary,
                    duration_seconds=duration_seconds,
                    max_blocks=max_blocks,
                    process_io=process_io,
                    process_instance=2,
                    peer_lease_socket=peer_lease_paths[process.host_id].socket,
                    process2_resume=artifacts,
                )
                runtimes[process.validator_id] = resumed_runtime
                statuses[process.validator_id] = wait_control_status(
                    process=process,
                    stage=stage,
                    run_id=run_id,
                    process_instance=2,
                    io_root=control_io,
                    label=f"status-process2-{process.validator_id}",
                    timeout_seconds=consensus.STARTUP_ALLOWANCE_SECONDS,
                )
                peer_recovery_resume = resume_resident_peers_v1(
                    processes=[p for p in quiesced_processes if p.validator_id != process.validator_id],
                    stages=stages, linux_paths=linux_paths, statuses=statuses,
                    command_nonces=command_nonces, read_nonces=read_nonces,
                    io_root=control_io, timeout_seconds=fault_window_seconds,
                )
                read_nonces[process.validator_id] = 1
                command_nonces[process.validator_id] = 1
                wait_for_started_fleet_v1(
                    processes,
                    stages,
                    linux_paths,
                    statuses,
                    read_nonces,
                    control_io,
                )
                catchup = send_control(
                    process=process,
                    stage=stage,
                    binary=binary,
                    status=statuses[process.validator_id],
                    nonce=read_nonces[process.validator_id],
                    verb="status",
                    fault="",
                    io_root=control_io,
                    label=f"process2-catchup-{process.validator_id}",
                    allow_pre_start=False,
                )
                read_nonces[process.validator_id] += 1
                if (
                    catchup["barrier_phase"] != "started"
                    or catchup["restart_quiesce_requested"]
                    or catchup["restart_pending_catchup"]
                    or not catchup["restart_completed"]
                    or catchup["safety_halted"]
                    or catchup["clean_stop_recorded"]
                ):
                    raise RuntimeError("process2 did not reach exact started/caught-up state")
                restart_ended_at = utc_now()
                fault_results.append(
                    write_restart_artifacts_v1(
                        output=output,
                        step=step,
                        run_id=run_id,
                        started_at=restart_started_at,
                        ended_at=restart_ended_at,
                        transcript=[
                            {
                                "surface": "process1-handoff",
                                "quiesce": target_quiesce,
                                "fleet_quiesce": fleet_quiesce,
                                "frontier": restart_frontier,
                                "prepare": prepare,
                                "handoff": handoff,
                                "peer_recovery_resume": peer_recovery_resume,
                            },
                            {"surface": "process2-inert-cut", **process2_exit},
                            {"surface": "recovery-material", **material_summary},
                            {"surface": "process2-control", **statuses[process.validator_id]},
                            {"surface": "process2-catchup", **catchup},
                        ],
                    )
                )
                restart_launch_count += 1
                continue
            if policy.evidence_mode != fault_semantics.SIGNED_CONNECTIVITY_TRANSITION:
                raise RuntimeError(
                    f"{step.kind} requires {policy.evidence_mode}; the live runner "
                    "must not project it through primary FaultApplied/FaultRecovered"
                )
            status = statuses[process.validator_id]
            transcript: list[dict[str, Any]] = []
            started_at = utc_now()

            command_nonce = command_nonces[process.validator_id]
            expectation = send_control(
                process=process,
                stage=stage,
                binary=binary,
                status=status,
                nonce=command_nonce,
                verb="expect_fault",
                fault=step.kind,
                io_root=control_io,
                label=f"fault-{step.ordinal:02d}-expect",
            )
            command_nonces[process.validator_id] += 1
            if expectation["expected_fault"] != step.kind:
                raise RuntimeError("runtime did not retain the exact fault expectation")
            transcript.append({"surface": "runtime-control", **expectation})

            # Register the exact owned restoration obligation before invoking
            # a driver that can fail after a partial external effect.
            active_effects.append((step, process, stage, status))
            driver_applied, _ = invoke_fault_driver(
                driver=fault_driver,
                step=step,
                phase="apply",
                process=process,
                stage=stage,
                status=status,
                fault_window_seconds=fault_window_seconds,
                io_root=driver_io,
                label=f"fault-{step.ordinal:02d}-apply",
            )
            transcript.append(
                {
                    "surface": "fault-driver",
                    "fault_driver_sha256": plan["fault_driver_sha256"],
                    **driver_applied,
                }
            )

            applied, next_nonce = wait_for_signed_fault_state(
                process=process,
                stage=stage,
                binary=binary,
                status=status,
                step=step,
                phase="applied",
                read_nonce=read_nonces[process.validator_id],
                io_root=control_io,
                label_prefix=f"fault-{step.ordinal:02d}-wait-applied",
                timeout_seconds=fault_window_seconds,
            )
            read_nonces[process.validator_id] = next_nonce
            transcript.append({"surface": "runtime-control", **applied})

            driver_restored, _ = invoke_fault_driver(
                driver=fault_driver,
                step=step,
                phase="restore",
                process=process,
                stage=stage,
                status=status,
                fault_window_seconds=fault_window_seconds,
                io_root=driver_io,
                label=f"fault-{step.ordinal:02d}-restore",
            )
            transcript.append(
                {
                    "surface": "fault-driver",
                    "fault_driver_sha256": plan["fault_driver_sha256"],
                    **driver_restored,
                }
            )
            if driver_restored["effect_id"] != driver_applied["effect_id"]:
                raise RuntimeError("restored fault effect differs from the exact applied effect")
            active_effects.pop()

            recovered, next_nonce = wait_for_signed_fault_state(
                process=process,
                stage=stage,
                binary=binary,
                status=status,
                step=step,
                phase="recovered",
                read_nonce=read_nonces[process.validator_id],
                io_root=control_io,
                label_prefix=f"fault-{step.ordinal:02d}-wait-recovered",
                timeout_seconds=fault_window_seconds,
            )
            read_nonces[process.validator_id] = next_nonce
            transcript.append({"surface": "runtime-control", **recovered})

            command_nonce = command_nonces[process.validator_id]
            cleared = send_control(
                process=process,
                stage=stage,
                binary=binary,
                status=status,
                nonce=command_nonce,
                verb="clear_fault_expectation",
                fault=step.kind,
                io_root=control_io,
                label=f"fault-{step.ordinal:02d}-clear",
            )
            command_nonces[process.validator_id] += 1
            if cleared["expected_fault"] != "":
                raise RuntimeError("runtime did not clear the recovered fault expectation")
            transcript.append({"surface": "runtime-control", **cleared})
            expected_faults[process.validator_id].add(step.kind)
            ended_at = utc_now()
            if ended_at <= started_at:
                raise RuntimeError("fault schedule lacks a positive external wall-clock interval")
            fault_results.append(
                write_fault_artifacts(
                    output=output,
                    step=step,
                    run_id=run_id,
                    started_at=started_at,
                    ended_at=ended_at,
                    transcript=transcript,
                    fault_driver_sha256=plan["fault_driver_sha256"],
                )
            )

        terminal_deadline = (
            time.monotonic()
            + duration_seconds
            + consensus.PROCESS_COMPLETION_ALLOWANCE_SECONDS
        )
        terminal_results = collect_terminal_evidence(
            runtimes=runtimes,
            stages=stages,
            mac_binary=mac_binary,
            observer_root=observer_root,
            observer_stage=observer_stage,
            coordinator_anchor=coordinator_anchor,
            run_id=run_id,
            output=output,
            process_io=control_io,
            expected_faults=expected_faults,
            restarted_validator_id=restarted_validator_id,
            duration_seconds=duration_seconds,
            max_blocks=max_blocks,
            validator_count=7,
            deadline=terminal_deadline,
        )
        terminal_agreement = consensus.exact_terminal_agreement(terminal_results, 7)
        if anchor_snapshot is not None:
            consensus.verify_coordinator_anchor(anchor_snapshot)
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError, SystemExit) as error:
        failure = str(error)
    finally:
        cleanup_failures.extend(
            cleanup_fault_effects(
                active_effects,
                driver=fault_driver,
                fault_window_seconds=fault_window_seconds,
                io_root=driver_io,
            )
        )
        for runtime in runtimes.values():
            stop_runtime(runtime)
        cleanup_failures.extend(consensus.stop_peer_lease_daemons(peer_lease_daemons))
        cleanup_failures.extend(base.clean_stages(stages))

    success = (
        failure is None
        and not cleanup_failures
        and [result["kind"] for result in fault_results] == list(fault_semantics.campaign_faults(campaign))
        and len(terminal_results) == 7
        and terminal_agreement is not None
        and restart_launch_count == plan["restart_count"]
        and sum(result["restarted"] for result in terminal_results) == plan["restart_count"]
    )
    summary = {
        "schema_version": 1,
        "profile": PROFILE,
        "run_id": run_id,
        "validator_count": 7,
        "network_scope": "single-lan",
        "elapsed_monotonic_ns": time.monotonic_ns() - started_ns,
        "coordinator_manifest_sha256": coordinator_anchor,
        "fault_order": list(fault_semantics.campaign_faults(campaign)),
        "faults": fault_results,
        "restart_count": restart_launch_count,
        "restarted_validator_id": (
            restarted_validator_id if restart_launch_count == 1 else None
        ),
        "validators": terminal_results,
        "terminal_agreement": terminal_agreement,
        "failure": failure,
        "cleanup_failures": cleanup_failures,
        "fault_restart_profile_completed": success and campaign == "all",
        # The campaign result still requires the independent raw/signed bundle
        # gates before any repository truth bit can move.
        "validator_run_completed": False,
        "fault_matrix_completed": False,
        "performance_evidence": False,
        "g3_lan_multihost_evidence": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    if campaign != "all":
        summary.update(
            schema_version=2,
            profile=fault_semantics.campaign_profile(campaign),
            campaign=campaign,
            selected_campaign_completed=success,
            candidate=plan["candidate"], topology_sha256=plan["topology_sha256"],
            fault_driver_sha256=plan["fault_driver_sha256"],
            prestart_plan_sha256=base.sha256_file(output / "prestart-plan.json"),
            participant_host_count=len({row["host_id"] for row in terminal_results} | {"mac"}) if terminal_results else 0,
            **selected_placement_facts(topology, processes),
        )
    base.write_new(output / "fault-restart-run-summary.json", base.canonical_json(summary))
    if not success:
        fail(
            f"campaign failed; preserved observations at {output}: "
            f"{failure or cleanup_failures}"
        )
    print(
        f"poco_g3_fault_restart_fleet_v1=passed validators=7 faults={len(fault_results)} restart={restart_launch_count} campaign={campaign} "
        "fault_driver_pinned=true signed_transitions=true "
        "signed_terminal_chain=true macos_cross_verified=true "
        "bundle_verification_required=true fault_matrix_completed=false "
        "g3_complete=false geo_wan=false production_activation=false "
        f"output={output}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("coordinator_root", type=pathlib.Path)
    parser.add_argument("deployment_root", type=pathlib.Path)
    parser.add_argument("--validators", required=True, type=int, choices=(7,))
    parser.add_argument("--linux-binary", required=True, type=pathlib.Path)
    parser.add_argument("--macos-binary", required=True, type=pathlib.Path)
    parser.add_argument("--fault-driver", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--duration-seconds", required=True, type=int)
    parser.add_argument("--max-blocks", required=True, type=int)
    parser.add_argument("--fault-window-seconds", type=int, default=30)
    parser.add_argument("--campaign", choices=tuple(fault_semantics.CAMPAIGN_FAULTS), default="all")
    parser.add_argument("--coordinator-manifest-sha256")
    parser.add_argument("--plan-only", action="store_true")
    args = parser.parse_args()

    coordinator = base.require_private_directory(args.coordinator_root, "coordinator root")
    deployments = base.require_private_directory(args.deployment_root, "deployment root")
    anchor_snapshot = None
    if args.campaign != "all":
        anchor_snapshot = consensus.checked_coordinator_anchor(coordinator, args.coordinator_manifest_sha256)
    manifest, topology, processes = base.load_contract(coordinator, deployments, 7)
    output = pathlib.Path(os.path.abspath(args.output))
    stage_plan = base.preflight_runtime_layout(processes, manifest["run_id"], output)
    candidate = manifest["candidate"]
    linux_binary = base.require_binary(
        args.linux_binary, candidate["linux_x86_64_sha256"], "Linux binary"
    )
    macos_binary = base.require_binary(
        args.macos_binary, candidate["macos_arm64_sha256"], "macOS binary"
    )
    fault_driver = require_fault_driver(args.fault_driver)
    if anchor_snapshot is not None:
        consensus.verify_coordinator_anchor(anchor_snapshot)
    coordinator_anchor = anchor_snapshot.sha256 if anchor_snapshot is not None else base.sha256_file(coordinator / "manifest.json")
    plan = campaign_plan(
        manifest=manifest,
        processes=processes,
        coordinator_anchor=coordinator_anchor,
        driver_sha256=base.sha256_file(fault_driver),
        duration_seconds=args.duration_seconds,
        max_blocks=args.max_blocks,
        fault_window_seconds=args.fault_window_seconds,
        campaign=args.campaign, topology=topology,
    )
    if args.plan_only:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return
    if output.exists() or output.is_symlink():
        fail("output root already exists; fault observations are immutable")
    try:
        output.relative_to(SOURCE_ROOT)
    except ValueError:
        pass
    else:
        fail("output root must remain outside the source tree")
    if args.campaign != "all":
        consensus.validate_output_root(output, input_paths=(coordinator, deployments, linux_binary, macos_binary, fault_driver))
    execute_campaign(
        coordinator=coordinator,
        deployments=deployments,
        manifest=manifest,
        processes=processes,
        linux_binary=linux_binary,
        macos_binary=macos_binary,
        fault_driver=fault_driver,
        output=output,
        duration_seconds=args.duration_seconds,
        max_blocks=args.max_blocks,
        fault_window_seconds=args.fault_window_seconds,
        plan=plan,
        stage_plan=stage_plan, campaign=args.campaign, topology=topology,
        anchor_snapshot=anchor_snapshot,
    )


if __name__ == "__main__":
    main()
