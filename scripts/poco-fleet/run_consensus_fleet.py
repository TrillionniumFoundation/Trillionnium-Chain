#!/usr/bin/env python3
"""Run one closed PoCO G3 consensus profile on the six-host LAN fleet.

This runner accepts success only when every Linux validator process exits
cleanly, creates one new fleet-certificate/journal/report/metrics/final-state
chain plus one terminal replay-archive set, and the secret-free macOS observer
independently verifies those signed facts against the frozen coordinator anchor.
It never synthesizes runtime
events, measurements, final state, or fault evidence. The deployed runtime
uses the frozen seven-validator direct mesh. The independently origin-signed
31/100-validator sparse relay layouts remain plan-only until their durable
Core/store capacity profiles have been independently verified.
"""

from __future__ import annotations

import argparse
import dataclasses
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

import evidence_bundle_profiles_v1 as evidence_profiles
import mesh_resource_preflight_v1 as mesh_resources
import run_network_smoke_fleet as base
import sealed_artifact_transport_v1 as sealed_transport


MAX_DURATION_SECONDS = 7 * 24 * 60 * 60
# Must equal the deployed Rust Core capacity.  The broader report/workload
# formats remain able to describe larger future profiles, but this runner
# rejects them before any fleet effect until their durable store envelopes are
# implemented and independently verified.
MAX_BLOCKS = 128
MIN_FINALIZABLE_BLOCKS = 3
MAX_SIGNER_INTENTS = 4_096
MAX_SIGNED_REPLAY_ARCHIVE_ENTRIES = 8_192
MAX_BUNDLE_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_REPLAY_ARCHIVE_CONTEXT_BYTES = 64 * 1024
MAX_REPLAY_ARCHIVE_HEAD_BYTES = 16 * 1024
MAX_REPLAY_ARCHIVE_TERMINAL_SEAL_BYTES = 256 * 1024
TERMINAL_DRAIN_ALLOWANCE_SECONDS = 30
PACEMAKER_BASE_TIMEOUT_SECONDS = 2
COMMISSIONING_ALLOWANCE_SECONDS = 300
FLEET_LAUNCH_SKEW_ALLOWANCE_SECONDS = 30
PEER_LEASE_DAEMON_READY_TIMEOUT_SECONDS = 30
PEER_LEASE_DAEMON_POLL_SECONDS = 0.1
PEER_LEASE_SOCKET_MAX_BYTES = 103
# Sizing input for the enforced timeout-view cap. This is deliberately
# separate from the observed process-launch skew: independent host clocks and
# an asynchronous start protocol cannot make that observation a safety fact.
TIMEOUT_VIEW_BUDGET_ALLOWANCE_SECONDS = 30
MESH_SETUP_ALLOWANCE_SECONDS = (
    COMMISSIONING_ALLOWANCE_SECONDS + FLEET_LAUNCH_SKEW_ALLOWANCE_SECONDS
)
STARTUP_ALLOWANCE_SECONDS = (
    COMMISSIONING_ALLOWANCE_SECONDS + MESH_SETUP_ALLOWANCE_SECONDS
)
PROCESS_COMPLETION_ALLOWANCE_SECONDS = (
    STARTUP_ALLOWANCE_SECONDS + TERMINAL_DRAIN_ALLOWANCE_SECONDS
)
HEX32 = re.compile(r"^[0-9a-f]{64}$")
RUNNER_LIFECYCLE_PROFILE = "frozen-v0-continuous-consensus-runner-lifecycle-v1"
RUNNER_OUTPUT_PROFILE = "frozen-v0-continuous-consensus-runner-output-v1"
RUNNER_EVIDENCE_PROFILE = evidence_profiles.NO_FAULT_V1
RUNNER_OUTPUT_MANIFEST = "runner-output-manifest.json"
RUNNER_LIFECYCLE_KINDS = (
    "anchor_checked",
    "contract_loaded",
    "preflight_completed",
    "output_initialized",
    "deployment_started",
    "deployment_completed",
    "validator_launch_started",
    "validator_launch_completed",
    "validator_processes_exited",
    "replay_archives_exported",
    "replay_archives_observer_verified",
    "signed_artifacts_sealed",
    "cleanup_finished",
    "summary_sealed",
)
RUNNER_SINGLETON_ARTIFACTS = {
    "coordinator-anchor.txt": "coordinator_anchor_record",
    "prestart-plan.json": "runner_prestart_plan",
    "mesh-resource-preflight.json": "runner_resource_preflight",
    "runner-lifecycle.json": "runner_lifecycle",
    "fleet-launch-observation.json": "runner_launch_observation",
    "consensus-run-summary.json": "runner_summary",
}
RUNNER_VALIDATOR_ARTIFACT_PATTERNS = (
    (re.compile(r"^signed-reports/([0-9a-f]{64})\.json$"), "validator_consensus_run_report"),
    (re.compile(r"^signed-runtime-journals/([0-9a-f]{64})\.jsonl$"), "validator_runtime_event_journal"),
    (re.compile(r"^fleet-start-certificates/([0-9a-f]{64})\.bin$"), "validator_fleet_start_certificate"),
    (re.compile(r"^signed-runtime-metrics/([0-9a-f]{64})\.json$"), "validator_runtime_metrics"),
    (re.compile(r"^signed-runtime-final-states/([0-9a-f]{64})\.json$"), "validator_runtime_final_state"),
    (re.compile(r"^signed-replay-archive-contexts/([0-9a-f]{64})\.json$"), "validator_replay_archive_context"),
    (re.compile(r"^signed-replay-archive-entries/([0-9a-f]{64})\.jsonl$"), "validator_replay_archive_entries"),
    (re.compile(r"^signed-replay-archive-heads/([0-9a-f]{64})\.json$"), "validator_replay_archive_head"),
    (re.compile(r"^signed-replay-archive-terminal-seals/([0-9a-f]{64})\.json$"), "validator_replay_archive_terminal_seal"),
    (re.compile(r"^process-io/([0-9a-f]{64})\.stdout$"), "validator_process_stdout"),
    (re.compile(r"^process-io/([0-9a-f]{64})\.stderr$"), "validator_process_stderr"),
)
RUNNER_REQUIRED_SINGLETON_ROLES = {
    "coordinator_anchor_record",
    "runner_prestart_plan",
    "runner_resource_preflight",
    "runner_lifecycle",
    "runner_summary",
}
RUNNER_REQUIRED_SUCCESS_VALIDATOR_ROLES = {
    role for _pattern, role in RUNNER_VALIDATOR_ARTIFACT_PATTERNS
}

REPLAY_ARCHIVE_ARTIFACTS = (
    (
        "context",
        "signed-replay-archive-v1/context.json",
        "signed-replay-archive-contexts",
        ".json",
        MAX_REPLAY_ARCHIVE_CONTEXT_BYTES,
    ),
    (
        "entries",
        "signed-replay-archive-v1/entries.jsonl",
        "signed-replay-archive-entries",
        ".jsonl",
        MAX_BUNDLE_ARTIFACT_BYTES,
    ),
    (
        "head",
        "signed-replay-archive-v1/head.json",
        "signed-replay-archive-heads",
        ".json",
        MAX_REPLAY_ARCHIVE_HEAD_BYTES,
    ),
    (
        "terminal_seal",
        "archive-terminal-seal.json",
        "signed-replay-archive-terminal-seals",
        ".json",
        MAX_REPLAY_ARCHIVE_TERMINAL_SEAL_BYTES,
    ),
)


@dataclasses.dataclass(frozen=True)
class CoordinatorAnchorSnapshot:
    path: pathlib.Path
    sha256: str
    device: int
    inode: int
    size: int
    modified_ns: int
    checked_monotonic_ns: int


@dataclasses.dataclass(frozen=True)
class PeerLeasePaths:
    """Private, host-scoped paths for the candidate external fence daemon."""

    socket: str
    journal: str
    ready: str


@dataclasses.dataclass
class RunningPeerLeaseDaemon:
    host_id: str
    stage: base.HostStage
    paths: PeerLeasePaths
    child: subprocess.Popen[bytes]


def exact_object(value: object, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        base.fail(f"{field} keys must be exactly {sorted(keys)!r}")
    return value


def safe_runner_relative(value: object, field: str) -> pathlib.PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        base.fail(f"{field} must be one non-empty POSIX relative path")
    path = pathlib.PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        base.fail(f"{field} escapes the runner output root")
    return path


def sealed_file_facts(
    path: pathlib.Path,
    field: str,
    *,
    allow_empty: bool = False,
) -> tuple[str, int, os.stat_result]:
    """Hash one inode-pinned regular file without following symbolic links."""

    absolute = path.absolute()
    try:
        before_path = absolute.lstat()
        descriptor = os.open(
            absolute,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        base.fail(f"cannot open {field}: {error}")
    digest = hashlib.sha256()
    size = 0
    try:
        before = os.fstat(descriptor)
        if (
            stat.S_ISLNK(before_path.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before_path.st_dev != before.st_dev
            or before_path.st_ino != before.st_ino
        ):
            base.fail(f"{field} must be one singly-linked regular non-symlink file")
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after_path = absolute.lstat()
    except OSError as error:
        base.fail(f"cannot re-read {field}: {error}")
    identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    if (
        identity
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or identity
        != (
            after_path.st_dev,
            after_path.st_ino,
            after_path.st_size,
            after_path.st_mtime_ns,
        )
        or size != before.st_size
        or (size == 0 and not allow_empty)
    ):
        base.fail(f"{field} changed while it was sealed or is unexpectedly empty")
    return digest.hexdigest(), size, before


def checked_coordinator_anchor(
    coordinator: pathlib.Path, expected_sha256: object
) -> CoordinatorAnchorSnapshot:
    """Compare the independent anchor before any output or fleet effect."""

    if not isinstance(expected_sha256, str) or HEX32.fullmatch(expected_sha256) is None:
        base.fail("coordinator manifest independent anchor must be canonical SHA-256")
    manifest_path = coordinator / "manifest.json"
    observed, size, metadata = sealed_file_facts(
        manifest_path, "coordinator manifest", allow_empty=False
    )
    if observed != expected_sha256:
        base.fail(
            "current coordinator manifest differs from the independent pre-run anchor"
        )
    return CoordinatorAnchorSnapshot(
        path=manifest_path,
        sha256=observed,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=size,
        modified_ns=metadata.st_mtime_ns,
        checked_monotonic_ns=time.monotonic_ns(),
    )


def verify_coordinator_anchor(snapshot: CoordinatorAnchorSnapshot) -> None:
    observed, size, metadata = sealed_file_facts(
        snapshot.path, "coordinator manifest anchor recheck", allow_empty=False
    )
    if (
        observed != snapshot.sha256
        or metadata.st_dev != snapshot.device
        or metadata.st_ino != snapshot.inode
        or size != snapshot.size
        or metadata.st_mtime_ns != snapshot.modified_ns
    ):
        base.fail("coordinator manifest mutated after its independent anchor check")


def paths_overlap(left: pathlib.Path, right: pathlib.Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def validate_output_root(
    raw: pathlib.Path,
    *,
    input_paths: tuple[pathlib.Path, ...],
) -> pathlib.Path:
    output = pathlib.Path(os.path.abspath(raw))
    if output.exists() or output.is_symlink():
        base.fail("output root already exists; run observations are immutable")
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as error:
        base.fail(f"cannot resolve output parent: {error}")
    if parent != output.parent:
        base.fail("output root must not traverse a symbolic-link ancestor")
    output = parent / output.name
    source_root = pathlib.Path(__file__).resolve().parents[2]
    if paths_overlap(output, source_root):
        base.fail("output root must be outside and disjoint from the source tree")
    for raw_input in input_paths:
        candidate = raw_input.resolve(strict=True)
        if paths_overlap(output, candidate):
            base.fail("output root must remain disjoint from every input path")
    return output


def record_lifecycle_event(
    events: list[dict[str, Any]],
    kind: str,
    *,
    monotonic_ns: int | None = None,
) -> None:
    if kind not in RUNNER_LIFECYCLE_KINDS:
        base.fail(f"runner lifecycle kind {kind!r} is outside the frozen vocabulary")
    if any(event.get("kind") == kind for event in events):
        base.fail(f"runner lifecycle kind {kind!r} is duplicated")
    position = RUNNER_LIFECYCLE_KINDS.index(kind)
    if events and position <= RUNNER_LIFECYCLE_KINDS.index(events[-1]["kind"]):
        base.fail("runner lifecycle events are out of frozen program order")
    observed = time.monotonic_ns() if monotonic_ns is None else monotonic_ns
    if isinstance(observed, bool) or not isinstance(observed, int) or observed < 0:
        base.fail("runner lifecycle monotonic value is invalid")
    if events and observed <= events[-1]["monotonic_ns"]:
        if monotonic_ns is not None:
            base.fail("runner lifecycle monotonic values are not strictly increasing")
        while observed <= events[-1]["monotonic_ns"]:
            observed = time.monotonic_ns()
    events.append(
        {"sequence": len(events), "kind": kind, "monotonic_ns": observed}
    )


def validate_runner_lifecycle(
    document: object,
    *,
    run_id: str,
    validator_count: int,
    coordinator_anchor: str,
) -> dict[str, Any]:
    lifecycle = exact_object(
        document,
        {
            "schema_version",
            "profile",
            "evidence_profile",
            "run_id",
            "validator_count",
            "coordinator_manifest_sha256",
            "events",
            "observer_process_started",
            "observer_report_received",
            "validator_run_completed",
            "fault_matrix_completed",
            "performance_evidence",
            "g3_lan_multihost_evidence",
            "geo_wan_evidence",
            "production_activation",
        },
        "runner lifecycle",
    )
    if (
        lifecycle["schema_version"] != 1
        or lifecycle["profile"] != RUNNER_LIFECYCLE_PROFILE
        or lifecycle["evidence_profile"] != RUNNER_EVIDENCE_PROFILE
        or lifecycle["run_id"] != run_id
        or lifecycle["validator_count"] != validator_count
        or lifecycle["coordinator_manifest_sha256"] != coordinator_anchor
        or lifecycle["observer_process_started"] is not False
        or lifecycle["observer_report_received"] is not False
        or lifecycle["validator_run_completed"] is not False
        or lifecycle["fault_matrix_completed"] is not False
        or lifecycle["performance_evidence"] is not False
        or lifecycle["g3_lan_multihost_evidence"] is not False
        or lifecycle["geo_wan_evidence"] is not False
        or lifecycle["production_activation"] is not False
    ):
        base.fail("runner lifecycle crosses its legacy non-completion boundary")
    raw_events = lifecycle["events"]
    if not isinstance(raw_events, list) or len(raw_events) < 6:
        base.fail("runner lifecycle omits mandatory real local stages")
    observed_kinds: list[str] = []
    prior_ns = -1
    for index, raw_event in enumerate(raw_events):
        event = exact_object(
            raw_event,
            {"sequence", "kind", "monotonic_ns"},
            f"runner lifecycle events[{index}]",
        )
        kind = event["kind"]
        value = event["monotonic_ns"]
        if (
            event["sequence"] != index
            or kind not in RUNNER_LIFECYCLE_KINDS
            or kind in observed_kinds
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value <= prior_ns
        ):
            base.fail("runner lifecycle sequence/order/monotonic contract differs")
        if observed_kinds and RUNNER_LIFECYCLE_KINDS.index(kind) <= (
            RUNNER_LIFECYCLE_KINDS.index(observed_kinds[-1])
        ):
            base.fail("runner lifecycle sequence/order/monotonic contract differs")
        observed_kinds.append(kind)
        prior_ns = value
    mandatory = {
        "anchor_checked",
        "contract_loaded",
        "preflight_completed",
        "output_initialized",
        "cleanup_finished",
        "summary_sealed",
    }
    if (
        not mandatory.issubset(observed_kinds)
        or observed_kinds[0] != "anchor_checked"
        or observed_kinds[-2:] != ["cleanup_finished", "summary_sealed"]
    ):
        base.fail("runner lifecycle omits mandatory real local stages")
    return lifecycle


def runner_lifecycle_document(
    *,
    run_id: str,
    validator_count: int,
    coordinator_anchor: str,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    document = {
        "schema_version": 1,
        "profile": RUNNER_LIFECYCLE_PROFILE,
        "evidence_profile": RUNNER_EVIDENCE_PROFILE,
        "run_id": run_id,
        "validator_count": validator_count,
        "coordinator_manifest_sha256": coordinator_anchor,
        "events": events,
        "observer_process_started": False,
        "observer_report_received": False,
        "validator_run_completed": False,
        "fault_matrix_completed": False,
        "performance_evidence": False,
        "g3_lan_multihost_evidence": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    return validate_runner_lifecycle(
        document,
        run_id=run_id,
        validator_count=validator_count,
        coordinator_anchor=coordinator_anchor,
    )


def runner_artifact_identity(relative: str) -> tuple[str, str]:
    if relative in RUNNER_SINGLETON_ARTIFACTS:
        return RUNNER_SINGLETON_ARTIFACTS[relative], ""
    for pattern, role in RUNNER_VALIDATOR_ARTIFACT_PATTERNS:
        match = pattern.fullmatch(relative)
        if match is not None:
            return role, match.group(1)
    base.fail(f"runner output contains unowned artifact path {relative!r}")


def ordered_runner_artifact_root(
    *,
    run_id: str,
    validator_count: int,
    coordinator_anchor: str,
    artifacts: list[dict[str, Any]],
) -> str:
    digest = hashlib.sha256()
    digest.update(b"TRNM/PoCO/G3/RunnerOutputManifest/v1\0")
    for value in (
        RUNNER_OUTPUT_PROFILE,
        RUNNER_EVIDENCE_PROFILE,
        run_id,
        coordinator_anchor,
    ):
        encoded = value.encode("ascii")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    digest.update(validator_count.to_bytes(4, "big"))
    digest.update(len(artifacts).to_bytes(8, "big"))
    for artifact in sorted(
        artifacts,
        key=lambda item: (item["role"], item["subject"], item["path"]),
    ):
        for field in ("role", "subject", "path"):
            encoded = artifact[field].encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
        digest.update(bytes.fromhex(artifact["sha256"]))
        digest.update(artifact["bytes"].to_bytes(8, "big"))
    return digest.hexdigest()


def runner_output_files(root: pathlib.Path) -> dict[str, pathlib.Path]:
    if root.is_symlink() or not root.is_dir() or root.resolve(strict=True) != root:
        base.fail("runner output root must be one real non-symlink directory")
    files: dict[str, pathlib.Path] = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            base.fail(f"runner output contains symbolic link {relative!r}")
        if stat.S_ISREG(metadata.st_mode):
            files[relative] = path
        elif not stat.S_ISDIR(metadata.st_mode):
            base.fail(f"runner output contains a non-file entry {relative!r}")
    return files


def validate_runner_output_manifest(
    root: pathlib.Path,
    *,
    expected_run_id: str,
    expected_validator_count: int,
    expected_coordinator_anchor: str,
) -> dict[str, Any]:
    root = root.absolute()
    files = runner_output_files(root)
    manifest_path = files.get(RUNNER_OUTPUT_MANIFEST)
    if manifest_path is None:
        base.fail("runner output manifest is missing")
    document = exact_object(
        base.read_json(manifest_path, "runner output manifest"),
        {
            "schema_version",
            "profile",
            "evidence_profile",
            "run_id",
            "validator_count",
            "coordinator_manifest_sha256",
            "artifacts",
            "ordered_artifact_root",
            "observer_process_started",
            "observer_report_received",
            "validator_run_completed",
            "fault_matrix_completed",
            "performance_evidence",
            "g3_lan_multihost_evidence",
            "geo_wan_evidence",
            "production_activation",
        },
        "runner output manifest",
    )
    if (
        document["schema_version"] != 1
        or document["profile"] != RUNNER_OUTPUT_PROFILE
        or document["evidence_profile"] != RUNNER_EVIDENCE_PROFILE
        or document["run_id"] != expected_run_id
        or document["validator_count"] != expected_validator_count
        or document["coordinator_manifest_sha256"] != expected_coordinator_anchor
        or document["observer_process_started"] is not False
        or document["observer_report_received"] is not False
        or document["validator_run_completed"] is not False
        or document["fault_matrix_completed"] is not False
        or document["performance_evidence"] is not False
        or document["g3_lan_multihost_evidence"] is not False
        or document["geo_wan_evidence"] is not False
        or document["production_activation"] is not False
    ):
        base.fail("runner output manifest crosses its legacy non-completion boundary")
    artifacts = document["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        base.fail("runner output manifest artifacts must be a non-empty list")
    sorted_artifacts = sorted(
        artifacts,
        key=lambda item: (
            item.get("role", "") if isinstance(item, dict) else "",
            item.get("subject", "") if isinstance(item, dict) else "",
            item.get("path", "") if isinstance(item, dict) else "",
        ),
    )
    if artifacts != sorted_artifacts:
        base.fail("runner output manifest artifacts are not canonically ordered")
    seen_pairs: set[tuple[str, str]] = set()
    seen_paths: set[str] = set()
    role_subjects: dict[str, set[str]] = {}
    for index, raw in enumerate(artifacts):
        artifact = exact_object(
            raw,
            {"role", "subject", "path", "sha256", "bytes"},
            f"runner output manifest artifacts[{index}]",
        )
        role = artifact["role"]
        subject = artifact["subject"]
        relative = safe_runner_relative(
            artifact["path"], f"runner output manifest artifacts[{index}].path"
        ).as_posix()
        if relative == RUNNER_OUTPUT_MANIFEST:
            base.fail("runner output manifest must not reference itself")
        if not isinstance(role, str) or not isinstance(subject, str):
            base.fail("runner output manifest role/subject must be strings")
        expected_role, expected_subject = runner_artifact_identity(relative)
        if (role, subject) != (expected_role, expected_subject):
            base.fail("runner output manifest role/subject/path binding differs")
        pair = (role, subject)
        if pair in seen_pairs or relative in seen_paths:
            base.fail("runner output manifest contains a duplicate role/subject or path")
        seen_pairs.add(pair)
        seen_paths.add(relative)
        role_subjects.setdefault(role, set()).add(subject)
        expected_hash = artifact["sha256"]
        expected_bytes = artifact["bytes"]
        if (
            not isinstance(expected_hash, str)
            or HEX32.fullmatch(expected_hash) is None
            or isinstance(expected_bytes, bool)
            or not isinstance(expected_bytes, int)
            or expected_bytes < 0
        ):
            base.fail("runner output manifest content reference is not canonical")
        allow_empty = role in {"validator_process_stdout", "validator_process_stderr"}
        observed_hash, observed_bytes, _metadata = sealed_file_facts(
            root.joinpath(*pathlib.PurePosixPath(relative).parts),
            f"runner output artifact {relative}",
            allow_empty=allow_empty,
        )
        if (observed_hash, observed_bytes) != (expected_hash, expected_bytes):
            base.fail("runner output artifact content address differs")
    actual_paths = set(files) - {RUNNER_OUTPUT_MANIFEST}
    if seen_paths != actual_paths:
        base.fail("runner output manifest omits a file or output contains an extra file")
    if not RUNNER_REQUIRED_SINGLETON_ROLES.issubset(role_subjects):
        base.fail("runner output manifest omits a mandatory runner singleton")
    if any(role_subjects[role] != {""} for role in RUNNER_REQUIRED_SINGLETON_ROLES):
        base.fail("runner output singleton subject differs")

    plan = base.read_json(root / "prestart-plan.json", "manifest-bound prestart plan")
    if (
        not isinstance(plan, dict)
        or plan.get("profile") != "frozen-v0-continuous-consensus-candidate"
        or plan.get("evidence_profile") != RUNNER_EVIDENCE_PROFILE
        or plan.get("run_id") != expected_run_id
        or plan.get("validator_count") != expected_validator_count
        or plan.get("coordinator_manifest_sha256")
        != expected_coordinator_anchor
        or plan.get("mesh_resource_preflight_required_before_effects") is not True
        or plan.get("requires_post_success_replay_archive_export") is not True
        or plan.get("requires_macos_full_replay_archive_verification") is not True
        or plan.get("validator_run_completed") is not False
        or plan.get("fault_matrix_completed") is not False
        or plan.get("performance_evidence") is not False
        or plan.get("g3_lan_multihost_evidence") is not False
        or plan.get("geo_wan_evidence") is not False
        or plan.get("production_activation") is not False
    ):
        base.fail("runner output prestart plan crosses its legacy boundary")
    raw_validators = plan.get("validators")
    if not isinstance(raw_validators, list) or len(raw_validators) != (
        expected_validator_count
    ):
        base.fail("runner output prestart validator inventory differs")
    validator_ids: set[str] = set()
    for item in raw_validators:
        validator_id = item.get("validator_id") if isinstance(item, dict) else None
        if (
            not isinstance(validator_id, str)
            or HEX32.fullmatch(validator_id) is None
            or validator_id in validator_ids
        ):
            base.fail("runner output prestart validator inventory differs")
        validator_ids.add(validator_id)
    for role in RUNNER_REQUIRED_SUCCESS_VALIDATOR_ROLES:
        if not role_subjects.get(role, set()).issubset(validator_ids):
            base.fail("runner output artifact subject is outside the planned validators")
    preflight = base.read_json(
        root / "mesh-resource-preflight.json", "manifest-bound mesh preflight"
    )
    if plan.get("mesh_resource_preflight") != preflight:
        base.fail("prestart plan and sealed mesh preflight differ")
    if (
        not isinstance(preflight, dict)
        or preflight.get("validator_run_completed") is not False
        or preflight.get("g3_lan_multihost_evidence") is not False
        or preflight.get("geo_wan_evidence") is not False
        or preflight.get("production_activation") is not False
    ):
        base.fail("sealed mesh preflight crosses its non-completion boundary")
    anchor_bytes = (root / "coordinator-anchor.txt").read_bytes()
    if anchor_bytes != f"{expected_coordinator_anchor}\n".encode("ascii"):
        base.fail("runner coordinator anchor record differs")
    lifecycle = base.read_json(
        root / "runner-lifecycle.json", "manifest-bound runner lifecycle"
    )
    validate_runner_lifecycle(
        lifecycle,
        run_id=expected_run_id,
        validator_count=expected_validator_count,
        coordinator_anchor=expected_coordinator_anchor,
    )
    summary = base.read_json(
        root / "consensus-run-summary.json", "manifest-bound runner summary"
    )
    if (
        not isinstance(summary, dict)
        or summary.get("profile")
        != "frozen-v0-continuous-consensus-candidate"
        or summary.get("run_id") != expected_run_id
        or summary.get("validator_count") != expected_validator_count
        or summary.get("coordinator_manifest_sha256") != expected_coordinator_anchor
        or summary.get("all_six_hosts_participated") is not False
        or summary.get("fleet_launch_skew_capacity_authority") is not False
        or summary.get("validator_run_completed") is not False
        or summary.get("fault_matrix_completed") is not False
        or summary.get("performance_evidence") is not False
        or summary.get("g3_lan_multihost_evidence") is not False
        or summary.get("geo_wan_evidence") is not False
        or summary.get("production_activation") is not False
    ):
        base.fail("manifest-bound runner summary crosses its non-completion boundary")
    if summary.get("failure") is None:
        successful_lifecycle_kinds = {
            event.get("kind") for event in lifecycle.get("events", [])
            if isinstance(event, dict)
        }
        if not {
            "validator_processes_exited",
            "replay_archives_exported",
            "replay_archives_observer_verified",
            "signed_artifacts_sealed",
        }.issubset(successful_lifecycle_kinds):
            base.fail("successful runner execution omits replay archive lifecycle stages")
        if role_subjects.get("runner_launch_observation") != {""}:
            base.fail("successful runner execution omits its launch observation")
        for role in RUNNER_REQUIRED_SUCCESS_VALIDATOR_ROLES:
            if role_subjects.get(role) != validator_ids:
                base.fail(f"successful runner execution omits one {role}")
    expected_root = ordered_runner_artifact_root(
        run_id=expected_run_id,
        validator_count=expected_validator_count,
        coordinator_anchor=expected_coordinator_anchor,
        artifacts=artifacts,
    )
    if document["ordered_artifact_root"] != expected_root:
        base.fail("runner output manifest ordered artifact root differs")
    return document


def write_runner_output_manifest(
    root: pathlib.Path,
    *,
    run_id: str,
    validator_count: int,
    coordinator_anchor: str,
) -> pathlib.Path:
    root = root.absolute()
    if (root / RUNNER_OUTPUT_MANIFEST).exists() or (
        root / RUNNER_OUTPUT_MANIFEST
    ).is_symlink():
        base.fail("runner output manifest already exists")
    files = runner_output_files(root)
    artifacts: list[dict[str, Any]] = []
    for relative, path in files.items():
        role, subject = runner_artifact_identity(relative)
        allow_empty = role in {"validator_process_stdout", "validator_process_stderr"}
        digest, size, _metadata = sealed_file_facts(
            path, f"runner output artifact {relative}", allow_empty=allow_empty
        )
        artifacts.append(
            {
                "role": role,
                "subject": subject,
                "path": relative,
                "sha256": digest,
                "bytes": size,
            }
        )
    artifacts.sort(key=lambda item: (item["role"], item["subject"], item["path"]))
    document = {
        "schema_version": 1,
        "profile": RUNNER_OUTPUT_PROFILE,
        "evidence_profile": RUNNER_EVIDENCE_PROFILE,
        "run_id": run_id,
        "validator_count": validator_count,
        "coordinator_manifest_sha256": coordinator_anchor,
        "artifacts": artifacts,
        "ordered_artifact_root": ordered_runner_artifact_root(
            run_id=run_id,
            validator_count=validator_count,
            coordinator_anchor=coordinator_anchor,
            artifacts=artifacts,
        ),
        "observer_process_started": False,
        "observer_report_received": False,
        "validator_run_completed": False,
        "fault_matrix_completed": False,
        "performance_evidence": False,
        "g3_lan_multihost_evidence": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    path = root / RUNNER_OUTPUT_MANIFEST
    base.write_new(path, base.canonical_json(document))
    try:
        validate_runner_output_manifest(
            root,
            expected_run_id=run_id,
            expected_validator_count=validator_count,
            expected_coordinator_anchor=coordinator_anchor,
        )
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


def validated_run_bounds(duration_seconds: int, max_blocks: int) -> dict[str, int]:
    """Mirror the Rust pre-effect runtime and append-only signer bounds."""

    if (
        isinstance(duration_seconds, bool)
        or not isinstance(duration_seconds, int)
        or not 1 <= duration_seconds <= MAX_DURATION_SECONDS
    ):
        base.fail("duration crosses the bounded consensus profile")
    if (
        isinstance(max_blocks, bool)
        or not isinstance(max_blocks, int)
        or not MIN_FINALIZABLE_BLOCKS <= max_blocks <= MAX_BLOCKS
    ):
        base.fail(
            "max-blocks cannot produce one ordinary three-chain finality or "
            "crosses the bounded consensus profile"
        )
    timeout_view_budget_horizon_seconds = (
        duration_seconds
        + TERMINAL_DRAIN_ALLOWANCE_SECONDS
        + TIMEOUT_VIEW_BUDGET_ALLOWANCE_SECONDS
    )
    maximum_timeout_view_advances = (
        timeout_view_budget_horizon_seconds + PACEMAKER_BASE_TIMEOUT_SECONDS - 1
    ) // PACEMAKER_BASE_TIMEOUT_SECONDS
    maximum_local_timeout_intents = maximum_timeout_view_advances
    maximum_local_vote_intents = max_blocks + maximum_timeout_view_advances
    maximum_total_intents = (
        maximum_local_vote_intents + maximum_local_timeout_intents
    )
    if maximum_total_intents > MAX_SIGNER_INTENTS:
        base.fail(
            "bounded consensus lifetime exceeds the append-only signer "
            f"capacity ({maximum_local_vote_intents} Vote + "
            f"{maximum_local_timeout_intents} TimeoutVote > "
            f"{MAX_SIGNER_INTENTS})"
        )
    maximum_proposal_archive_entries = maximum_local_vote_intents
    maximum_quorum_certificate_archive_entries = (
        maximum_proposal_archive_entries + 1
    )
    maximum_signed_replay_archive_entries = (
        maximum_proposal_archive_entries
        + maximum_quorum_certificate_archive_entries
    )
    if maximum_signed_replay_archive_entries > MAX_SIGNED_REPLAY_ARCHIVE_ENTRIES:
        base.fail(
            "bounded consensus lifetime exceeds the signed replay archive "
            f"capacity ({maximum_proposal_archive_entries} Proposal + "
            f"{maximum_quorum_certificate_archive_entries} QC > "
            f"{MAX_SIGNED_REPLAY_ARCHIVE_ENTRIES})"
        )
    return {
        "journal_capacity": MAX_SIGNER_INTENTS,
        "maximum_timeout_view_advances": maximum_timeout_view_advances,
        "maximum_local_vote_intents": maximum_local_vote_intents,
        "maximum_local_timeout_intents": maximum_local_timeout_intents,
        "maximum_total_intents": maximum_total_intents,
        "signed_replay_archive_capacity": MAX_SIGNED_REPLAY_ARCHIVE_ENTRIES,
        "maximum_proposal_archive_entries": maximum_proposal_archive_entries,
        "maximum_quorum_certificate_archive_entries": (
            maximum_quorum_certificate_archive_entries
        ),
        "maximum_signed_replay_archive_entries": (
            maximum_signed_replay_archive_entries
        ),
        "terminal_drain_allowance_seconds": TERMINAL_DRAIN_ALLOWANCE_SECONDS,
        "timeout_view_budget_allowance_seconds": (
            TIMEOUT_VIEW_BUDGET_ALLOWANCE_SECONDS
        ),
        "commissioning_allowance_seconds": COMMISSIONING_ALLOWANCE_SECONDS,
        "fleet_launch_skew_allowance_seconds": FLEET_LAUNCH_SKEW_ALLOWANCE_SECONDS,
        "mesh_setup_allowance_seconds": MESH_SETUP_ALLOWANCE_SECONDS,
        "startup_allowance_seconds": STARTUP_ALLOWANCE_SECONDS,
        "process_completion_allowance_seconds": PROCESS_COMPLETION_ALLOWANCE_SECONDS,
    }


def validated_launch_skew_ns(first_launch_ns: int, last_launch_ns: int) -> int:
    """Reject a fleet whose measured sequential process launch exceeds its bound."""

    if (
        isinstance(first_launch_ns, bool)
        or isinstance(last_launch_ns, bool)
        or not isinstance(first_launch_ns, int)
        or not isinstance(last_launch_ns, int)
        or first_launch_ns < 0
        or last_launch_ns < first_launch_ns
    ):
        base.fail("fleet launch monotonic interval is invalid")
    observed = last_launch_ns - first_launch_ns
    if observed > FLEET_LAUNCH_SKEW_ALLOWANCE_SECONDS * 1_000_000_000:
        base.fail("fleet process launch skew exceeds its enforced allowance")
    return observed


def validate_runtime_topology(validators: int, *, plan_only: bool) -> bool:
    """Keep 31/100 visible for planning but fail closed for active effects."""

    if isinstance(validators, bool) or validators not in {7, 31, 100}:
        base.fail("continuous consensus topology is outside the frozen 7/31/100 profiles")
    active_supported = validators == 7
    if not plan_only and not active_supported:
        base.fail(
            "active consensus is frozen to the direct seven-validator Stage0 profile"
        )
    return active_supported


def runtime_transport_profile(validators: int) -> dict[str, int | str]:
    validate_runtime_topology(validators, plan_only=True)
    if validators == 7:
        return {"mode": "direct", "peer_degree": 6, "relay_hop_budget": 0}
    return {
        "mode": "origin-signed-sparse-relay",
        "peer_degree": 8,
        "relay_hop_budget": 4 if validators == 31 else 13,
    }


def exact_terminal_agreement(
    process_results: list[dict[str, Any]], expected_count: int
) -> dict[str, Any]:
    """Require one exact finalized block/state/chain cut across all validators."""

    if len(process_results) != expected_count:
        base.fail("terminal agreement set has the wrong validator count")
    validator_ids = [value.get("validator_id") for value in process_results]
    if (
        any(not isinstance(value, str) or HEX32.fullmatch(value) is None for value in validator_ids)
        or len(set(validator_ids)) != expected_count
    ):
        base.fail("terminal agreement set has invalid or duplicate validator IDs")
    fields = (
        "finalized_height",
        "finalized_ordinary_block_count",
        "finalized_block_id",
        "finalized_state_root",
        "finalized_chain_root",
    )
    cuts: set[tuple[Any, ...]] = set()
    for result in process_results:
        verification = result.get("observer_final_state_verification")
        if not isinstance(verification, dict) or any(
            field not in verification for field in fields
        ):
            base.fail("terminal agreement set lacks an independently verified final state")
        cuts.add(tuple(verification[field] for field in fields))
    if len(cuts) != 1:
        base.fail("validator terminal finality or state-root divergence observed")
    certificate_digests = {
        result.get("fleet_start_certificate_sha256") for result in process_results
    }
    if (
        len(certificate_digests) != 1
        or not isinstance(next(iter(certificate_digests)), str)
        or HEX32.fullmatch(next(iter(certificate_digests))) is None
    ):
        base.fail("validators do not share one exact fleet StartCertificate")
    observer_certificates = [
        result.get("observer_fleet_start_certificate_verification")
        for result in process_results
    ]
    if any(
        not isinstance(verified, dict)
        or verified.get("selected_validator_id") != result.get("validator_id")
        or verified.get("validator_count") != expected_count
        or verified.get("fleet_start_certificate_sha256")
        != result.get("fleet_start_certificate_sha256")
        for result, verified in zip(process_results, observer_certificates, strict=True)
    ):
        base.fail("terminal agreement lacks observer-verified fleet certificates")
    semantic_fields = (
        "fleet_start_certificate_digest",
        "ready_set_sha256",
        "context_sha256",
    )
    if any(
        any(
            not isinstance(verified.get(field), str)
            or HEX32.fullmatch(verified[field]) is None
            for field in semantic_fields
        )
        for verified in observer_certificates
        if isinstance(verified, dict)
    ):
        base.fail("observer-verified fleet certificate semantics are malformed")
    typed_certificate_digests = {
        verified["fleet_start_certificate_digest"]
        for verified in observer_certificates
        if isinstance(verified, dict)
    }
    ready_set_digests = {
        verified["ready_set_sha256"]
        for verified in observer_certificates
        if isinstance(verified, dict)
    }
    context_digests = {
        verified["context_sha256"]
        for verified in observer_certificates
        if isinstance(verified, dict)
    }
    if (
        len(typed_certificate_digests) != 1
        or len(ready_set_digests) != 1
        or len(context_digests) != 1
    ):
        base.fail("observer-verified fleet certificate semantics diverge")
    cut = next(iter(cuts))
    return {
        **dict(zip(fields, cut, strict=True)),
        "fleet_start_certificate_sha256": next(iter(certificate_digests)),
        "fleet_start_certificate_digest": next(iter(typed_certificate_digests)),
        "fleet_ready_set_sha256": next(iter(ready_set_digests)),
        "fleet_context_sha256": next(iter(context_digests)),
    }


def peer_lease_paths(stage: base.HostStage) -> PeerLeasePaths:
    """Derive one private external-fence endpoint for a validator host.

    The authority is host-scoped rather than validator-scoped.  This matters
    on the two hosts carrying two validators: both processes must share one
    durable CAS/journal namespace so an overlapping lease cannot be hidden by
    starting a second authority.  The stage ``bin`` directory is materialized
    mode 0700 before this function is called, and the daemon itself enforces
    the 0600 socket/regular-file boundaries.
    """

    prefix = f"{stage.root}/bin"
    paths = PeerLeasePaths(
        socket=f"{prefix}/peer-lease.sock",
        journal=f"{prefix}/peer-lease.journal",
        ready=f"{prefix}/peer-lease.ready",
    )
    for value in (paths.socket, paths.journal, paths.ready):
        # shell_path validates the frozen stage spelling and rejects traversal
        # before any local or remote effect.  The socket bound is the smaller
        # Linux/macOS sockaddr_un limit used by the fleet.
        base.shell_path(value)
    if len(paths.socket.encode("utf-8")) > PEER_LEASE_SOCKET_MAX_BYTES:
        base.fail("peer-lease socket path exceeds the portable Unix bound")
    if len({paths.socket, paths.journal, paths.ready}) != 3:
        base.fail("peer-lease daemon paths collide")
    return paths


def peer_lease_daemon_command(
    stage: base.HostStage,
    binary: str,
    paths: PeerLeasePaths,
) -> list[str]:
    """Build the candidate-only daemon command for one host stage.

    A remote daemon remains a child of its SSH shell and is killed by the
    shell trap when the coordinator closes the channel.  Its output is not
    mixed with validator evidence; the validator's signed journal remains the
    authoritative runtime artifact.
    """

    arguments = [
        binary,
        "peer-lease-daemon",
        "--socket",
        paths.socket,
        "--journal",
        paths.journal,
        "--ready-file",
        paths.ready,
    ]
    if not stage.remote:
        return arguments
    command = " ".join(shlex.quote(value) for value in arguments)
    remote = (
        "set -eu; daemon=''; "
        "cleanup() { if test -n \"$daemon\"; then kill \"$daemon\" 2>/dev/null || true; "
        "wait \"$daemon\" 2>/dev/null || true; fi; }; "
        "trap cleanup EXIT HUP INT TERM; "
        f"{command} >/dev/null 2>&1 & daemon=$!; "
        "wait \"$daemon\"; status=$?; daemon=''; exit \"$status\""
    )
    return [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=15",
        stage.management,
        remote,
    ]


def peer_lease_ready_probe(stage: base.HostStage, paths: PeerLeasePaths) -> None:
    """Check the daemon's private readiness contract without granting a lease."""

    if stage.remote:
        command = "set -eu; test -S {socket}; test -f {ready}; test ! -L {ready}".format(
            socket=shlex.quote(paths.socket),
            ready=shlex.quote(paths.ready),
        )
        base.run_checked(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=2",
                stage.management,
                command,
            ],
            timeout=4,
        )
        return
    socket_path = pathlib.Path(paths.socket)
    ready_path = pathlib.Path(paths.ready)
    socket_metadata = socket_path.lstat()
    ready_metadata = ready_path.lstat()
    if (
        not stat.S_ISSOCK(socket_metadata.st_mode)
        or socket_metadata.st_mode & 0o7777 != 0o600
        or stat.S_ISLNK(ready_metadata.st_mode)
        or not stat.S_ISREG(ready_metadata.st_mode)
        or ready_metadata.st_mode & 0o7777 != 0o600
    ):
        raise RuntimeError("peer-lease daemon readiness files are not private")


def wait_for_peer_lease_ready(
    daemon: RunningPeerLeaseDaemon,
    *,
    timeout_seconds: int = PEER_LEASE_DAEMON_READY_TIMEOUT_SECONDS,
) -> None:
    """Wait on the daemon's ready socket with one bounded wall-clock budget."""

    deadline = time.monotonic() + timeout_seconds
    last_error: BaseException | None = None
    while True:
        if daemon.child.poll() is not None:
            raise RuntimeError(
                f"peer-lease daemon on {daemon.host_id} exited "
                f"{daemon.child.returncode} before readiness"
            )
        try:
            peer_lease_ready_probe(daemon.stage, daemon.paths)
            return
        except (OSError, subprocess.SubprocessError, RuntimeError) as error:
            last_error = error
        if time.monotonic() >= deadline:
            detail = f": {last_error}" if last_error is not None else ""
            raise RuntimeError(
                f"peer-lease daemon on {daemon.host_id} did not become ready{detail}"
            )
        time.sleep(PEER_LEASE_DAEMON_POLL_SECONDS)


def start_peer_lease_daemons(
    stages: dict[str, base.HostStage],
    processes: list[base.ValidatorProcess],
    linux_paths: dict[str, str],
) -> tuple[dict[str, PeerLeasePaths], list[RunningPeerLeaseDaemon]]:
    """Start exactly one candidate authority per validator host."""

    paths_by_host: dict[str, PeerLeasePaths] = {}
    running: list[RunningPeerLeaseDaemon] = []
    try:
        for host_id in sorted({process.host_id for process in processes}):
            stage = stages[host_id]
            paths = peer_lease_paths(stage)
            daemon = RunningPeerLeaseDaemon(
                host_id=host_id,
                stage=stage,
                paths=paths,
                child=subprocess.Popen(
                    peer_lease_daemon_command(stage, linux_paths[host_id], paths),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ),
            )
            running.append(daemon)
            wait_for_peer_lease_ready(daemon)
            paths_by_host[host_id] = paths
    except BaseException:
        stop_peer_lease_daemons(running)
        raise
    return paths_by_host, running


def stop_peer_lease_daemons(daemons: list[RunningPeerLeaseDaemon]) -> list[str]:
    """Terminate/reap authorities before their stage roots are removed."""

    failures: list[str] = []
    for daemon in reversed(daemons):
        child = daemon.child
        try:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=10)
        except (OSError, subprocess.SubprocessError) as error:
            failures.append(f"peer-lease daemon {daemon.host_id}: {error}")
    return failures


def command_for(
    process: base.ValidatorProcess,
    stage: base.HostStage,
    binary: str,
    duration_seconds: int,
    max_blocks: int,
    peer_lease_socket: str | None = None,
) -> tuple[list[str], str, str, str, str, str]:
    root = base.validator_stage_root(process, stage)
    config = f"{root}/{process.config_relative.as_posix()}"
    report = f"{root}/consensus-report.json"
    journal = f"{root}/runtime-events.jsonl"
    metrics = f"{root}/runtime-metrics.json"
    final_state = f"{root}/runtime-final-state.json"
    fleet_start_certificate = f"{root}/fleet-start-certificate.bin"
    arguments = [
        binary,
        "run-consensus",
        root,
        config,
        str(duration_seconds),
        str(max_blocks),
        report,
    ]
    if peer_lease_socket is not None:
        base.shell_path(peer_lease_socket)
        if len(peer_lease_socket.encode("utf-8")) > PEER_LEASE_SOCKET_MAX_BYTES:
            base.fail("peer-lease socket path exceeds the portable Unix bound")
        arguments.extend(("--peer-lease-socket", peer_lease_socket))
    if not stage.remote:
        return (
            arguments,
            report,
            journal,
            metrics,
            final_state,
            fleet_start_certificate,
        )
    command = " ".join(shlex.quote(value) for value in arguments)
    remote = (
        "set -eu; child=''; "
        "cleanup() { if test -n \"$child\"; then kill \"$child\" 2>/dev/null || true; "
        "wait \"$child\" 2>/dev/null || true; fi; }; "
        "trap cleanup EXIT HUP INT TERM; "
        f"{command} & child=$!; wait \"$child\"; status=$?; child=''; exit \"$status\""
    )
    return (
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
            process.management,
            remote,
        ],
        report,
        journal,
        metrics,
        final_state,
        fleet_start_certificate,
    )


def copy_observation_file(
    process: base.ValidatorProcess,
    stage: base.HostStage,
    source: str,
    target: pathlib.Path,
) -> bool:
    try:
        if stage.remote:
            base.run_checked(
                ["scp", "-q", f"{process.management}:{source}", str(target)],
                timeout=60,
            )
        else:
            shutil.copyfile(source, target)
        metadata = target.lstat()
        if target.is_symlink() or not target.is_file() or metadata.st_size <= 0:
            target.unlink(missing_ok=True)
            return False
        target.chmod(0o600)
        return True
    except (OSError, subprocess.SubprocessError):
        target.unlink(missing_ok=True)
        return False


def replay_archive_sources_v1(
    process: base.ValidatorProcess,
    stage: base.HostStage,
) -> dict[str, str]:
    validator_root = base.validator_stage_root(process, stage)
    return {
        label: f"{validator_root}/{source_relative}"
        for label, source_relative, _directory, _suffix, _maximum in (
            REPLAY_ARCHIVE_ARTIFACTS
        )
    }


def copy_replay_archive_set_v1(
    *,
    process: base.ValidatorProcess,
    stage: base.HostStage,
    output: pathlib.Path,
) -> dict[str, Any]:
    sources = replay_archive_sources_v1(process, stage)
    copied: dict[str, Any] = {}
    for label, _source_relative, directory, suffix, maximum in REPLAY_ARCHIVE_ARTIFACTS:
        target = output / directory / f"{process.validator_id}{suffix}"
        copied[label] = sealed_transport.copy_sealed_stage_artifact_v1(
            management=process.management,
            remote=stage.remote,
            source=sources[label],
            target=target,
            maximum_bytes=maximum,
        )
    return copied


def observer_sealed_reports_root_v1(observer_stage: base.HostStage) -> str:
    """Return the no-follow canonical path to the frozen Mac stage.

    The common fleet runner intentionally creates stages below ``/tmp``. On
    macOS that name is a system symlink to ``/private/tmp``; the sealed
    transport must not weaken its component-wise no-follow walk to traverse
    it, so the fixed Mac observer uses the equivalent canonical spelling.
    """

    root = f"{observer_stage.root}/reports"
    if observer_stage.host_id != "mac":
        return root
    prefix = f"{base.REMOTE_STAGE_PREFIX}-"
    if not observer_stage.remote or not observer_stage.root.startswith(prefix):
        base.fail("Mac observer stage is not the frozen remote /tmp stage")
    return f"/private{root}"


def exact_verified_summary(
    value: object,
    *,
    run_id: str,
    validator_id: str,
    coordinator_anchor: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        base.fail("observer consensus verification is not an object")
    expected_keys = {
        "schema_version",
        "status",
        "run_id",
        "validator_id",
        "validator_set_id",
        "validator_set_sha256",
        "topology_sha256",
        "coordinator_manifest_sha256",
        "candidate_source_sha256",
        "binary_sha256",
        "config_sha256",
        "process_instance",
        "ordinary_start_height",
        "submitted_height",
        "committed_height",
        "finalized_height",
        "submitted_ordinary_block_count",
        "committed_ordinary_block_count",
        "finalized_ordinary_block_count",
        "application_state_root",
        "safety_revision",
        "application_store_sequence",
        "whole_node_checkpoint_generation",
        "signer_watermark_sequence",
        "safety_halt_count",
        "double_vote_count",
        "double_timeout_count",
        "conflicting_certificate_count",
        "unresolved_obligation_count",
        "clean_stop",
        "validator_run_completed",
        "continuous_consensus_runtime",
        "signature_verified",
        "semantics_verified",
        "g3_evidence_complete",
        "geo_wan_evidence",
        "production_activation",
    }
    if set(value) != expected_keys:
        base.fail("observer consensus verification keys differ from contract")
    if (
        value["schema_version"] != 2
        or value["status"]
        != "consensus-run-report-signature-and-semantics-verified"
        or value["run_id"] != run_id
        or value["validator_id"] != validator_id
        or value["coordinator_manifest_sha256"] != coordinator_anchor
        or value["signature_verified"] is not True
        or value["semantics_verified"] is not True
        or value["clean_stop"] is not True
        or value["validator_run_completed"] is not True
        or value["continuous_consensus_runtime"] is not True
        or value["g3_evidence_complete"] is not False
        or value["geo_wan_evidence"] is not False
        or value["production_activation"] is not False
        or any(
            value[field] != 0
            for field in (
                "safety_halt_count",
                "double_vote_count",
                "double_timeout_count",
                "conflicting_certificate_count",
                "unresolved_obligation_count",
            )
        )
        or any(
            isinstance(value[field], bool)
            or not isinstance(value[field], int)
            or value[field] <= 0
            for field in (
                "process_instance",
                "ordinary_start_height",
                "submitted_height",
                "committed_height",
                "finalized_height",
                "submitted_ordinary_block_count",
                "committed_ordinary_block_count",
                "finalized_ordinary_block_count",
                "safety_revision",
                "application_store_sequence",
                "whole_node_checkpoint_generation",
                "signer_watermark_sequence",
            )
        )
        or value["submitted_height"] < value["committed_height"]
        or value["committed_height"] < value["finalized_height"]
        or value["submitted_ordinary_block_count"]
        < value["committed_ordinary_block_count"]
        or value["committed_ordinary_block_count"]
        < value["finalized_ordinary_block_count"]
        or value["submitted_height"]
        != value["ordinary_start_height"]
        + value["submitted_ordinary_block_count"]
        - 1
        or value["committed_height"]
        != value["ordinary_start_height"]
        + value["committed_ordinary_block_count"]
        - 1
        or value["finalized_height"]
        != value["ordinary_start_height"]
        + value["finalized_ordinary_block_count"]
        - 1
    ):
        base.fail("observer consensus verification crosses the accepted profile")
    return value


def exact_fleet_start_certificate_summary(
    value: object,
    *,
    run_id: str,
    validator_id: str,
    coordinator_anchor: str,
    duration_seconds: int,
    max_blocks: int,
    validator_count: int,
    artifact_sha256: str,
) -> dict[str, Any]:
    """Accept only the Rust observer's exact N/N fleet certificate summary."""

    if not isinstance(value, dict):
        base.fail("observer fleet StartCertificate verification is not an object")
    expected_keys = {
        "schema_version",
        "status",
        "run_id",
        "selected_validator_id",
        "validator_count",
        "validator_set_id",
        "validator_set_sha256",
        "topology_sha256",
        "coordinator_manifest_sha256",
        "candidate_source_sha256",
        "binary_sha256",
        "workload_corpus_sha256",
        "workload_policy_sha256",
        "ordinary_start_height",
        "duration_seconds",
        "max_blocks",
        "target_height",
        "barrier_round",
        "transport",
        "relay_hop_budget",
        "context_sha256",
        "ready_set_sha256",
        "fleet_start_certificate_digest",
        "fleet_start_certificate_sha256",
        "ready_statement_count",
        "start_statement_count",
        "mesh_session_count",
        "selected_pre_ready_journal_sequence",
        "selected_pre_ready_journal_sha256",
        "selected_fleet_ready_event_sequence",
        "selected_fleet_ready_event_sha256",
        "initial_current_view",
        "initial_high_qc_height",
        "initial_finalized_height",
        "initial_application_height",
        "initial_proposal_parent_height",
        "maximum_timeout_view_advances",
        "maximum_local_vote_intents",
        "maximum_local_timeout_intents",
        "maximum_total_signer_intents",
        "maximum_signed_replay_archive_entries",
        "relay_admission_capacity",
        "signature_verified",
        "semantics_verified",
        "exact_session_topology_verified",
        "g3_evidence_complete",
        "geo_wan_evidence",
        "production_activation",
    }
    if set(value) != expected_keys:
        base.fail("observer fleet StartCertificate verification keys differ from contract")
    bounds = validated_run_bounds(duration_seconds, max_blocks)
    expected_transport = runtime_transport_profile(validator_count)
    expected_mesh_sessions = validator_count * (12 if validator_count == 7 else 16)
    integer_fields = (
        "ordinary_start_height",
        "duration_seconds",
        "max_blocks",
        "target_height",
        "barrier_round",
        "ready_statement_count",
        "start_statement_count",
        "mesh_session_count",
        "selected_pre_ready_journal_sequence",
        "selected_fleet_ready_event_sequence",
        "initial_current_view",
        "initial_high_qc_height",
        "initial_finalized_height",
        "initial_application_height",
        "initial_proposal_parent_height",
        "maximum_timeout_view_advances",
        "maximum_local_vote_intents",
        "maximum_local_timeout_intents",
        "maximum_total_signer_intents",
        "maximum_signed_replay_archive_entries",
        "relay_admission_capacity",
    )
    if any(
        isinstance(value[field], bool)
        or not isinstance(value[field], int)
        or value[field] <= 0
        for field in integer_fields
    ) or (
        isinstance(value["relay_hop_budget"], bool)
        or not isinstance(value["relay_hop_budget"], int)
        or value["relay_hop_budget"] < 0
    ):
        base.fail("observer fleet StartCertificate integer profile differs")
    if (
        value["schema_version"] != 1
        or value["status"]
        != "fleet-start-certificate-signature-and-semantics-verified"
        or value["run_id"] != run_id
        or value["selected_validator_id"] != validator_id
        or value["validator_count"] != validator_count
        or value["coordinator_manifest_sha256"] != coordinator_anchor
        or value["duration_seconds"] != duration_seconds
        or value["max_blocks"] != max_blocks
        or value["barrier_round"] != 1
        or value["transport"] != expected_transport["mode"]
        or value["relay_hop_budget"] != expected_transport["relay_hop_budget"]
        or value["fleet_start_certificate_sha256"] != artifact_sha256
        or value["ready_statement_count"] != validator_count
        or value["start_statement_count"] != validator_count
        or value["mesh_session_count"] != expected_mesh_sessions
        or value["maximum_timeout_view_advances"]
        != bounds["maximum_timeout_view_advances"]
        or value["maximum_local_vote_intents"]
        != bounds["maximum_local_vote_intents"]
        or value["maximum_local_timeout_intents"]
        != bounds["maximum_local_timeout_intents"]
        or value["maximum_total_signer_intents"]
        != bounds["maximum_total_intents"]
        or value["maximum_signed_replay_archive_entries"]
        != bounds["maximum_signed_replay_archive_entries"]
        or value["relay_admission_capacity"] != (2 * validator_count + 4) * 6
        or value["signature_verified"] is not True
        or value["semantics_verified"] is not True
        or value["exact_session_topology_verified"] is not True
        or value["g3_evidence_complete"] is not False
        or value["geo_wan_evidence"] is not False
        or value["production_activation"] is not False
        or value["target_height"]
        != value["ordinary_start_height"] + max_blocks - 1
        or value["initial_proposal_parent_height"] + 1
        != value["ordinary_start_height"]
        or value["initial_high_qc_height"]
        != value["initial_proposal_parent_height"]
        or value["selected_pre_ready_journal_sequence"] + 1
        != value["selected_fleet_ready_event_sequence"]
    ):
        base.fail("observer fleet StartCertificate verification crosses accepted profile")
    digest_fields = (
        "validator_set_id",
        "validator_set_sha256",
        "topology_sha256",
        "coordinator_manifest_sha256",
        "candidate_source_sha256",
        "binary_sha256",
        "workload_corpus_sha256",
        "workload_policy_sha256",
        "context_sha256",
        "ready_set_sha256",
        "fleet_start_certificate_digest",
        "fleet_start_certificate_sha256",
        "selected_pre_ready_journal_sha256",
        "selected_fleet_ready_event_sha256",
    )
    if any(
        not isinstance(value[field], str) or HEX32.fullmatch(value[field]) is None
        for field in digest_fields
    ):
        base.fail("observer fleet StartCertificate digest profile differs")
    return value


def exact_journal_verified_summary(
    value: object,
    *,
    run_id: str,
    validator_id: str,
    coordinator_anchor: str,
) -> dict[str, Any]:
    """Accept only the Rust observer's exact full-journal replay summary."""

    if not isinstance(value, dict):
        base.fail("observer runtime-journal verification is not an object")
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
        base.fail("observer runtime-journal verification keys differ from contract")
    if (
        value["schema_version"] != 1
        or value["status"]
        != "runtime-journal-signature-and-semantics-verified"
        or value["run_id"] != run_id
        or value["validator_id"] != validator_id
        or value["coordinator_manifest_sha256"] != coordinator_anchor
        or value["clean_stop"] is not True
        or value["signature_verified"] is not True
        or value["semantics_verified"] is not True
        or value["g3_evidence_complete"] is not False
        or value["geo_wan_evidence"] is not False
        or value["production_activation"] is not False
        or isinstance(value["process_instance_count"], bool)
        or not isinstance(value["process_instance_count"], int)
        or value["process_instance_count"] != 1
        or isinstance(value["event_count"], bool)
        or not isinstance(value["event_count"], int)
        or value["event_count"] <= 0
        or isinstance(value["runtime_event_sequence"], bool)
        or not isinstance(value["runtime_event_sequence"], int)
        or value["runtime_event_sequence"] <= 0
        or value["event_count"] != value["runtime_event_sequence"] + 1
        or isinstance(value["finalized_height"], bool)
        or not isinstance(value["finalized_height"], int)
        or value["finalized_height"] <= 0
        or isinstance(value["recovered_fault_count"], bool)
        or not isinstance(value["recovered_fault_count"], int)
        or value["recovered_fault_count"] != 0
        or value["restart_completed"] is not False
        or isinstance(value["barrier_round"], bool)
        or not isinstance(value["barrier_round"], int)
        or value["barrier_round"] != 1
        or isinstance(value["fleet_ready_event_sequence"], bool)
        or not isinstance(value["fleet_ready_event_sequence"], int)
        or value["fleet_ready_event_sequence"] <= 0
        or isinstance(value["fleet_ready_previous_event_sequence"], bool)
        or not isinstance(value["fleet_ready_previous_event_sequence"], int)
        or value["fleet_ready_previous_event_sequence"] <= 0
        or value["fleet_ready_previous_event_sequence"] + 1
        != value["fleet_ready_event_sequence"]
        or any(
            not isinstance(value[field], str) or HEX32.fullmatch(value[field]) is None
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
        base.fail("observer runtime-journal verification crosses the accepted profile")
    return value


def exact_runtime_verified_summary(
    value: object,
    *,
    kind: str,
    run_id: str,
    validator_id: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        base.fail(f"observer {kind} verification is not an object")
    common = {
        "schema_version",
        "status",
        "run_id",
        "validator_id",
        "process_instance_count",
        "ordinary_start_height",
        "runtime_event_sequence",
        "runtime_event_sha256",
        "consensus_report_sha256",
        "body_sha256",
        "signature_verified",
        "semantics_verified",
        "g3_evidence_complete",
        "geo_wan_evidence",
        "production_activation",
    }
    if kind == "runtime-metrics":
        expected_keys = common | {"finality_sample_count", "fsync_count"}
        schema_version = 2
        status = "runtime-metrics-signature-and-semantics-verified"
    elif kind == "runtime-final-state":
        expected_keys = common | {
            "finalized_height",
            "finalized_ordinary_block_count",
            "finalized_nonempty_ordinary_block_count",
            "finalized_block_id",
            "finalized_state_root",
            "finalized_chain_root",
            "runtime_metrics_sha256",
        }
        schema_version = 3
        status = "runtime-final-state-signature-and-semantics-verified"
    else:
        raise AssertionError(f"unknown runtime verification kind {kind}")
    if set(value) != expected_keys:
        base.fail(f"observer {kind} verification keys differ from contract")
    if (
        value["schema_version"] != schema_version
        or value["status"] != status
        or value["run_id"] != run_id
        or value["validator_id"] != validator_id
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
                "process_instance_count",
                "ordinary_start_height",
                "runtime_event_sequence",
            )
        )
        or any(
            not isinstance(value[field], str) or HEX32.fullmatch(value[field]) is None
            for field in (
                "runtime_event_sha256",
                "consensus_report_sha256",
                "body_sha256",
            )
        )
    ):
        base.fail(f"observer {kind} verification crosses the accepted profile")
    if kind == "runtime-metrics":
        if any(
            isinstance(value[field], bool)
            or not isinstance(value[field], int)
            or value[field] <= 0
            for field in ("finality_sample_count", "fsync_count")
        ):
            base.fail("observer runtime-metrics cardinality differs")
    else:
        for field in (
            "finalized_height",
            "finalized_ordinary_block_count",
            "finalized_nonempty_ordinary_block_count",
        ):
            if (
                isinstance(value[field], bool)
                or not isinstance(value[field], int)
                or value[field] <= 0
            ):
                base.fail(f"observer runtime-final-state {field} differs")
        if (
            value["finalized_nonempty_ordinary_block_count"]
            != value["finalized_ordinary_block_count"]
            or value["finalized_height"]
            != value["ordinary_start_height"]
            + value["finalized_ordinary_block_count"]
            - 1
            or any(
                not isinstance(value[field], str)
                or HEX32.fullmatch(value[field]) is None
                for field in (
                    "finalized_block_id",
                    "finalized_state_root",
                    "finalized_chain_root",
                    "runtime_metrics_sha256",
                )
            )
        ):
            base.fail("observer runtime-final-state tip/count binding differs")
    return value


def exact_process_evidence_chain(
    *,
    certificate: dict[str, Any],
    journal: dict[str, Any],
    report_document: object,
    report: dict[str, Any],
    metrics: dict[str, Any],
    final_state: dict[str, Any],
) -> None:
    """Bind the independently verified journal head before and after report."""

    if not isinstance(report_document, dict):
        raise ValueError("signed consensus report is not an object")
    event_sequences = (
        journal["runtime_event_sequence"],
        report_document.get("runtime_event_sequence"),
        metrics["runtime_event_sequence"],
        final_state["runtime_event_sequence"],
    )
    event_hashes = (
        journal["runtime_event_sha256"],
        report_document.get("runtime_event_sha256"),
        metrics["runtime_event_sha256"],
        final_state["runtime_event_sha256"],
    )
    process_instances = (
        journal["process_instance_count"],
        report_document.get("process_instance"),
        report["process_instance"],
        metrics["process_instance_count"],
        final_state["process_instance_count"],
    )
    if len(set(event_sequences)) != 1 or len(set(event_hashes)) != 1:
        raise ValueError("verified runtime-journal head differs across terminal evidence")
    if len(set(process_instances)) != 1:
        raise ValueError("verified process instance differs across terminal evidence")
    if any(
        journal[field] != report[field]
        for field in (
            "validator_set_sha256",
            "coordinator_manifest_sha256",
            "candidate_source_sha256",
            "binary_sha256",
            "config_sha256",
        )
    ):
        raise ValueError("verified runtime-journal deployment context differs from report")
    if (
        certificate["selected_validator_id"] != journal["validator_id"]
        or certificate["barrier_round"] != journal["barrier_round"]
        or certificate["ready_set_sha256"] != journal["fleet_ready_set_sha256"]
        or certificate["fleet_start_certificate_sha256"]
        != journal["fleet_start_certificate_sha256"]
        or certificate["selected_fleet_ready_event_sequence"]
        != journal["fleet_ready_event_sequence"]
        or certificate["selected_fleet_ready_event_sha256"]
        != journal["fleet_ready_event_sha256"]
        or certificate["selected_pre_ready_journal_sequence"]
        != journal["fleet_ready_previous_event_sequence"]
        or certificate["selected_pre_ready_journal_sha256"]
        != journal["fleet_ready_previous_event_sha256"]
    ):
        raise ValueError(
            "observer-verified fleet certificate does not join the signed runtime journal"
        )
    if (
        metrics["consensus_report_sha256"] != report_document.get("report_sha256")
        or final_state["consensus_report_sha256"]
        != report_document.get("report_sha256")
        or final_state["runtime_metrics_sha256"] != metrics["body_sha256"]
        or journal["finalized_height"] != report["finalized_height"]
        or journal["finalized_height"] != final_state["finalized_height"]
        or final_state["finalized_ordinary_block_count"]
        != report["finalized_ordinary_block_count"]
        or journal["finalized_block_id"]
        != report_document.get("application_head_block_id")
        or journal["finalized_block_id"] != final_state["finalized_block_id"]
        or journal["finalized_state_root"] != report["application_state_root"]
        or journal["finalized_state_root"] != final_state["finalized_state_root"]
        or journal["finalized_chain_root"] != final_state["finalized_chain_root"]
    ):
        raise ValueError("verified terminal evidence chain differs")


def exact_replay_archive_verified_summary_v1(
    value: object,
    *,
    run_id: str,
    validator_id: str,
    validator_ids: set[str],
    artifact_facts: dict[str, Any],
    certificate: dict[str, Any],
    journal: dict[str, Any],
    final_state: dict[str, Any],
    run_bounds: dict[str, int],
) -> dict[str, Any]:
    expected_keys = {
        "schema_version",
        "status",
        "run_id",
        "validator_id",
        "fleet_start_certificate_sha256",
        "clean_stop_journal_sequence",
        "clean_stop_journal_sha256",
        "finalized_height",
        "finalized_block_id",
        "finalized_state_root",
        "finalized_chain_root",
        "archive_covers_signed_final_tip",
        "finality_proof_id",
        "finality_child_block_id",
        "finality_grandchild_block_id",
        "archive_context_sha256",
        "archive_context_file_sha256",
        "archive_entries_file_sha256",
        "archive_head_file_sha256",
        "terminal_archive_sequence",
        "terminal_archive_record_sha256",
        "proposal_count",
        "quorum_certificate_count",
        "quorum_certificate_signature_share_count",
        "unique_quorum_certificates",
        "negative_control_certificate_id",
        "negative_control_signer_id",
        "invalid_signature_control_rejected",
        "input_sha256_unchanged",
        "observer_verified_nonempty_workload",
        "observer_verified_finality",
        "validator_run_completed",
        "g3_evidence_complete",
        "geo_wan_evidence",
        "production_activation",
    }
    replay = exact_object(value, expected_keys, "observer replay archive verification")
    hex_fields = {
        "fleet_start_certificate_sha256",
        "clean_stop_journal_sha256",
        "finalized_block_id",
        "finalized_state_root",
        "finalized_chain_root",
        "finality_proof_id",
        "finality_child_block_id",
        "finality_grandchild_block_id",
        "archive_context_sha256",
        "archive_context_file_sha256",
        "archive_entries_file_sha256",
        "archive_head_file_sha256",
        "terminal_archive_record_sha256",
        "negative_control_certificate_id",
        "negative_control_signer_id",
    }
    count_fields = {
        "clean_stop_journal_sequence",
        "finalized_height",
        "terminal_archive_sequence",
        "proposal_count",
        "quorum_certificate_count",
        "quorum_certificate_signature_share_count",
    }
    if (
        replay["schema_version"] != 1
        or replay["status"]
        != "validator-signed-terminal-replay-archive-verified"
        or replay["run_id"] != run_id
        or replay["validator_id"] != validator_id
        or any(
            not isinstance(replay[field], str)
            or HEX32.fullmatch(replay[field]) is None
            or replay[field] == "0" * 64
            for field in hex_fields
        )
        or any(
            isinstance(replay[field], bool)
            or not isinstance(replay[field], int)
            or replay[field] <= 0
            for field in count_fields
        )
        or replay["archive_covers_signed_final_tip"] is not True
        or replay["invalid_signature_control_rejected"] is not True
        or replay["input_sha256_unchanged"] is not True
        or replay["observer_verified_nonempty_workload"] is not False
        or replay["observer_verified_finality"] is not False
        or replay["validator_run_completed"] is not False
        or replay["g3_evidence_complete"] is not False
        or replay["geo_wan_evidence"] is not False
        or replay["production_activation"] is not False
    ):
        base.fail("observer replay archive verification crosses its inert profile")

    raw_certificates = replay["unique_quorum_certificates"]
    if not isinstance(raw_certificates, list) or not raw_certificates:
        base.fail("observer replay archive verification has no unique QCs")
    certificate_shares: dict[str, int] = {}
    for index, raw in enumerate(raw_certificates):
        certificate_record = exact_object(
            raw,
            {"certificate_id", "signature_share_count"},
            f"observer replay archive unique QCs[{index}]",
        )
        certificate_id = certificate_record["certificate_id"]
        shares = certificate_record["signature_share_count"]
        if (
            not isinstance(certificate_id, str)
            or HEX32.fullmatch(certificate_id) is None
            or certificate_id in certificate_shares
            or isinstance(shares, bool)
            or not isinstance(shares, int)
            or shares <= 0
            or shares > len(validator_ids)
        ):
            base.fail("observer replay archive unique QC inventory differs")
        certificate_shares[certificate_id] = shares
    if (
        replay["quorum_certificate_count"] != len(certificate_shares)
        or replay["terminal_archive_sequence"]
        != replay["proposal_count"] + replay["quorum_certificate_count"]
        or replay["quorum_certificate_signature_share_count"]
        != sum(certificate_shares.values())
        or replay["negative_control_certificate_id"] not in certificate_shares
        or replay["negative_control_signer_id"] not in validator_ids
        or replay["proposal_count"]
        > run_bounds["maximum_proposal_archive_entries"]
        or replay["quorum_certificate_count"]
        > run_bounds["maximum_quorum_certificate_archive_entries"]
        or replay["proposal_count"] + replay["quorum_certificate_count"]
        > run_bounds["maximum_signed_replay_archive_entries"]
    ):
        base.fail("observer replay archive counts or negative control differ")

    expected_artifact_hashes = {
        "archive_context_file_sha256": getattr(artifact_facts["context"], "sha256"),
        "archive_entries_file_sha256": getattr(artifact_facts["entries"], "sha256"),
        "archive_head_file_sha256": getattr(artifact_facts["head"], "sha256"),
    }
    if (
        any(replay[field] != digest for field, digest in expected_artifact_hashes.items())
        or replay["fleet_start_certificate_sha256"]
        != certificate["fleet_start_certificate_sha256"]
        or replay["clean_stop_journal_sequence"] != journal["runtime_event_sequence"]
        or replay["clean_stop_journal_sha256"] != journal["runtime_event_sha256"]
        or replay["finalized_height"] != journal["finalized_height"]
        or replay["finalized_height"] != final_state["finalized_height"]
        or replay["finalized_block_id"] != journal["finalized_block_id"]
        or replay["finalized_block_id"] != final_state["finalized_block_id"]
        or replay["finalized_state_root"] != journal["finalized_state_root"]
        or replay["finalized_state_root"] != final_state["finalized_state_root"]
        or replay["finalized_chain_root"] != journal["finalized_chain_root"]
        or replay["finalized_chain_root"] != final_state["finalized_chain_root"]
    ):
        base.fail("observer replay archive verification differs from terminal evidence")
    return replay


def verify_replay_archive_on_observer_v1(
    *,
    process: base.ValidatorProcess,
    artifact_facts: dict[str, Any],
    mac_binary: str,
    observer_root: str,
    observer_stage: base.HostStage,
    coordinator_anchor: str,
    run_id: str,
    validator_ids: set[str],
    certificate: dict[str, Any],
    journal: dict[str, Any],
    final_state: dict[str, Any],
    run_bounds: dict[str, int],
) -> dict[str, Any]:
    remote_paths: dict[str, str] = {}
    observer_reports_root = observer_sealed_reports_root_v1(observer_stage)
    for label, _source_relative, _directory, suffix, maximum in REPLAY_ARCHIVE_ARTIFACTS:
        facts = artifact_facts[label]
        sealed_transport.revalidate_local_sealed_artifact_v1(
            pathlib.Path(getattr(facts, "path")), facts
        )
        remote = sealed_transport.stage_sealed_artifact_on_observer_v1(
            management=observer_stage.management,
            source=pathlib.Path(getattr(facts, "path")),
            remote_reports_root=observer_reports_root,
            remote_name=f"{process.validator_id}.replay-{label.replace('_', '-')}{suffix}",
            maximum_bytes=maximum,
        )
        remote_paths[label] = str(getattr(remote, "path"))

    observer_config = f"{observer_root}/public/configs/{process.validator_id}.json"
    command = " ".join(
        shlex.quote(value)
        for value in (
            mac_binary,
            "verify-replay-archive",
            observer_root,
            observer_config,
            remote_paths["context"],
            remote_paths["entries"],
            remote_paths["head"],
            remote_paths["terminal_seal"],
            coordinator_anchor,
        )
    )
    verified = base.run_checked(
        ["ssh", "-o", "BatchMode=yes", observer_stage.management, command],
        timeout=600,
    )
    if len(verified.stdout) > 1024 * 1024:
        base.fail("observer replay archive verification output is oversized")
    replay = exact_replay_archive_verified_summary_v1(
        base.strict_json_bytes(
            verified.stdout,
            f"observer replay archive verification {process.validator_id}",
        ),
        run_id=run_id,
        validator_id=process.validator_id,
        validator_ids=validator_ids,
        artifact_facts=artifact_facts,
        certificate=certificate,
        journal=journal,
        final_state=final_state,
        run_bounds=run_bounds,
    )
    for facts in artifact_facts.values():
        sealed_transport.revalidate_local_sealed_artifact_v1(
            pathlib.Path(getattr(facts, "path")), facts
        )
    return replay


def verify_on_observer(
    *,
    process: base.ValidatorProcess,
    report_path: pathlib.Path,
    mac_binary: str,
    observer_root: str,
    observer_stage: base.HostStage,
    coordinator_anchor: str,
    run_id: str,
) -> dict[str, Any]:
    remote_report = f"{observer_stage.root}/reports/{process.validator_id}.consensus.json"
    base.run_checked(
        ["scp", "-q", str(report_path), f"{observer_stage.management}:{remote_report}"],
        timeout=60,
    )
    observer_config = f"{observer_root}/public/configs/{process.validator_id}.json"
    command = " ".join(
        shlex.quote(value)
        for value in (
            mac_binary,
            "verify-consensus-report",
            observer_root,
            observer_config,
            remote_report,
            coordinator_anchor,
        )
    )
    verified = base.run_checked(
        ["ssh", "-o", "BatchMode=yes", observer_stage.management, command],
        timeout=60,
    )
    return exact_verified_summary(
        base.strict_json_bytes(
            verified.stdout,
            f"observer consensus verification {process.validator_id}",
        ),
        run_id=run_id,
        validator_id=process.validator_id,
        coordinator_anchor=coordinator_anchor,
    )


def verify_journal_on_observer(
    *,
    process: base.ValidatorProcess,
    journal_path: pathlib.Path,
    mac_binary: str,
    observer_root: str,
    observer_stage: base.HostStage,
    coordinator_anchor: str,
    run_id: str,
) -> dict[str, Any]:
    remote_journal = f"{observer_stage.root}/reports/{process.validator_id}.journal.jsonl"
    base.run_checked(
        ["scp", "-q", str(journal_path), f"{observer_stage.management}:{remote_journal}"],
        timeout=60,
    )
    observer_config = f"{observer_root}/public/configs/{process.validator_id}.json"
    command = " ".join(
        shlex.quote(value)
        for value in (
            mac_binary,
            "verify-runtime-journal",
            observer_root,
            observer_config,
            remote_journal,
            coordinator_anchor,
        )
    )
    verified = base.run_checked(
        ["ssh", "-o", "BatchMode=yes", observer_stage.management, command],
        timeout=60,
    )
    return exact_journal_verified_summary(
        base.strict_json_bytes(
            verified.stdout,
            f"observer runtime-journal verification {process.validator_id}",
        ),
        run_id=run_id,
        validator_id=process.validator_id,
        coordinator_anchor=coordinator_anchor,
    )


def verify_fleet_start_certificate_on_observer(
    *,
    process: base.ValidatorProcess,
    certificate_path: pathlib.Path,
    mac_binary: str,
    observer_root: str,
    observer_stage: base.HostStage,
    coordinator_anchor: str,
    run_id: str,
    duration_seconds: int,
    max_blocks: int,
    validator_count: int,
) -> dict[str, Any]:
    remote_certificate = (
        f"{observer_stage.root}/reports/{process.validator_id}.fleet-start-certificate.bin"
    )
    base.run_checked(
        [
            "scp",
            "-q",
            str(certificate_path),
            f"{observer_stage.management}:{remote_certificate}",
        ],
        timeout=60,
    )
    base.run_checked(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            observer_stage.management,
            f"chmod 600 -- {shlex.quote(remote_certificate)}",
        ],
        timeout=60,
    )
    observer_config = f"{observer_root}/public/configs/{process.validator_id}.json"
    command = " ".join(
        shlex.quote(value)
        for value in (
            mac_binary,
            "verify-fleet-start-certificate",
            observer_root,
            observer_config,
            remote_certificate,
            coordinator_anchor,
            str(duration_seconds),
            str(max_blocks),
        )
    )
    verified = base.run_checked(
        ["ssh", "-o", "BatchMode=yes", observer_stage.management, command],
        timeout=60,
    )
    return exact_fleet_start_certificate_summary(
        base.strict_json_bytes(
            verified.stdout,
            f"observer fleet StartCertificate verification {process.validator_id}",
        ),
        run_id=run_id,
        validator_id=process.validator_id,
        coordinator_anchor=coordinator_anchor,
        duration_seconds=duration_seconds,
        max_blocks=max_blocks,
        validator_count=validator_count,
        artifact_sha256=base.sha256_file(certificate_path),
    )


def verify_runtime_on_observer(
    *,
    process: base.ValidatorProcess,
    evidence_path: pathlib.Path,
    kind: str,
    mac_binary: str,
    observer_root: str,
    observer_stage: base.HostStage,
    coordinator_anchor: str,
    run_id: str,
) -> dict[str, Any]:
    suffix = "metrics" if kind == "runtime-metrics" else "final-state"
    remote_evidence = (
        f"{observer_stage.root}/reports/{process.validator_id}.{suffix}.json"
    )
    base.run_checked(
        ["scp", "-q", str(evidence_path), f"{observer_stage.management}:{remote_evidence}"],
        timeout=60,
    )
    observer_config = f"{observer_root}/public/configs/{process.validator_id}.json"
    command = " ".join(
        shlex.quote(value)
        for value in (
            mac_binary,
            f"verify-{kind}",
            observer_root,
            observer_config,
            remote_evidence,
            coordinator_anchor,
        )
    )
    verified = base.run_checked(
        ["ssh", "-o", "BatchMode=yes", observer_stage.management, command],
        timeout=60,
    )
    return exact_runtime_verified_summary(
        base.strict_json_bytes(
            verified.stdout,
            f"observer {kind} verification {process.validator_id}",
        ),
        kind=kind,
        run_id=run_id,
        validator_id=process.validator_id,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("coordinator_root", type=pathlib.Path)
    parser.add_argument("deployment_root", type=pathlib.Path)
    parser.add_argument("--validators", required=True, type=int, choices=(7, 31, 100))
    parser.add_argument("--linux-binary", required=True, type=pathlib.Path)
    parser.add_argument("--macos-binary", required=True, type=pathlib.Path)
    parser.add_argument(
        "--coordinator-manifest-sha256",
        required=True,
        help="independent SHA-256 recorded before any runner effect",
    )
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--duration-seconds", required=True, type=int)
    parser.add_argument("--max-blocks", required=True, type=int)
    parser.add_argument("--plan-only", action="store_true")
    args = parser.parse_args()
    run_bounds = validated_run_bounds(args.duration_seconds, args.max_blocks)
    runtime_topology_supported = validate_runtime_topology(
        args.validators, plan_only=args.plan_only
    )
    transport = runtime_transport_profile(args.validators)

    coordinator = base.require_private_directory(args.coordinator_root, "coordinator root")
    anchor_snapshot = checked_coordinator_anchor(
        coordinator, args.coordinator_manifest_sha256
    )
    coordinator_anchor = anchor_snapshot.sha256
    lifecycle_events: list[dict[str, Any]] = []
    record_lifecycle_event(
        lifecycle_events,
        "anchor_checked",
        monotonic_ns=anchor_snapshot.checked_monotonic_ns,
    )
    deployments = base.require_private_directory(args.deployment_root, "deployment root")
    manifest, _topology, processes = base.load_contract(
        coordinator, deployments, args.validators
    )
    verify_coordinator_anchor(anchor_snapshot)
    record_lifecycle_event(lifecycle_events, "contract_loaded")
    candidate = manifest["candidate"]
    linux_binary = base.require_binary(
        args.linux_binary, candidate["linux_x86_64_sha256"], "Linux binary"
    )
    macos_binary = base.require_binary(
        args.macos_binary, candidate["macos_arm64_sha256"], "macOS binary"
    )
    run_id = manifest["run_id"]
    planned_output = pathlib.Path(os.path.abspath(args.output))
    stage_plan = base.preflight_runtime_layout(processes, run_id, planned_output)
    plan = {
        "schema_version": 1,
        "profile": "frozen-v0-continuous-consensus-candidate",
        "evidence_profile": RUNNER_EVIDENCE_PROFILE,
        "run_id": run_id,
        "validator_count": args.validators,
        "linux_validator_host_count": len({item.host_id for item in processes}),
        "observer_host_id": "mac",
        "coordinator_manifest_sha256": coordinator_anchor,
        "duration_seconds": args.duration_seconds,
        "max_blocks": args.max_blocks,
        "runtime_topology_supported": runtime_topology_supported,
        "transport": transport,
        "signer_lifetime": {
            "journal_capacity": run_bounds["journal_capacity"],
            "maximum_timeout_view_advances": run_bounds[
                "maximum_timeout_view_advances"
            ],
            "maximum_local_vote_intents": run_bounds[
                "maximum_local_vote_intents"
            ],
            "maximum_local_timeout_intents": run_bounds[
                "maximum_local_timeout_intents"
            ],
            "maximum_total_intents": run_bounds["maximum_total_intents"],
        },
        "signed_replay_archive_lifetime": {
            "archive_capacity": run_bounds["signed_replay_archive_capacity"],
            "maximum_proposal_entries": run_bounds[
                "maximum_proposal_archive_entries"
            ],
            "maximum_quorum_certificate_entries": run_bounds[
                "maximum_quorum_certificate_archive_entries"
            ],
            "maximum_total_entries": run_bounds[
                "maximum_signed_replay_archive_entries"
            ],
        },
        "commissioning_allowance_seconds": run_bounds[
            "commissioning_allowance_seconds"
        ],
        "fleet_launch_skew_allowance_seconds": run_bounds[
            "fleet_launch_skew_allowance_seconds"
        ],
        "fleet_launch_skew_capacity_authority": False,
        "mesh_setup_allowance_seconds": run_bounds["mesh_setup_allowance_seconds"],
        "startup_allowance_seconds": run_bounds["startup_allowance_seconds"],
        "terminal_drain_allowance_seconds": run_bounds[
            "terminal_drain_allowance_seconds"
        ],
        "timeout_view_budget_allowance_seconds": run_bounds[
            "timeout_view_budget_allowance_seconds"
        ],
        "process_completion_allowance_seconds": run_bounds[
            "process_completion_allowance_seconds"
        ],
        "validators": [base.public_process_projection(value) for value in processes],
        "requires_signed_terminal_evidence_chain_per_validator": True,
        "requires_macos_independent_verification": True,
        "requires_macos_full_fleet_certificate_verification": True,
        "requires_macos_full_runtime_journal_replay": True,
        "requires_post_success_replay_archive_export": True,
        "requires_macos_full_replay_archive_verification": True,
        "mesh_resource_preflight_required_before_effects": True,
        "mesh_resource_preflight": None,
        "validator_run_completed": False,
        "fault_matrix_completed": False,
        "performance_evidence": False,
        "g3_lan_multihost_evidence": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    if args.plan_only:
        verify_coordinator_anchor(anchor_snapshot)
        print(json.dumps(plan, indent=2, sort_keys=True))
        return

    output = validate_output_root(
        planned_output,
        input_paths=(coordinator, deployments, linux_binary, macos_binary),
    )
    if output != planned_output:
        base.fail("validated output root differs from the frozen runtime layout")
    try:
        plan["mesh_resource_preflight"] = (
            mesh_resources.preflight_mesh_fleet_resources_v1(
                processes, args.validators
            )
        )
    except RuntimeError as error:
        base.fail(str(error))
    record_lifecycle_event(lifecycle_events, "preflight_completed")
    verify_coordinator_anchor(anchor_snapshot)
    output.mkdir(parents=True, mode=0o700)
    output.chmod(0o700)
    record_lifecycle_event(lifecycle_events, "output_initialized")
    base.write_new(output / "prestart-plan.json", base.canonical_json(plan))
    base.write_new(
        output / "mesh-resource-preflight.json",
        base.canonical_json(plan["mesh_resource_preflight"]),
    )
    base.write_new(
        output / "coordinator-anchor.txt",
        f"{coordinator_anchor}\n".encode("ascii"),
    )

    reports = output / "signed-reports"
    journals = output / "signed-runtime-journals"
    fleet_start_certificates = output / "fleet-start-certificates"
    metrics_values = output / "signed-runtime-metrics"
    final_states = output / "signed-runtime-final-states"
    replay_archive_contexts = output / "signed-replay-archive-contexts"
    replay_archive_entries = output / "signed-replay-archive-entries"
    replay_archive_heads = output / "signed-replay-archive-heads"
    replay_archive_terminal_seals = output / "signed-replay-archive-terminal-seals"
    process_io = output / "process-io"
    for directory in (
        reports,
        journals,
        fleet_start_certificates,
        metrics_values,
        final_states,
        replay_archive_contexts,
        replay_archive_entries,
        replay_archive_heads,
        replay_archive_terminal_seals,
        process_io,
    ):
        directory.mkdir(mode=0o700)

    stages: dict[str, base.HostStage] = {}
    peer_lease_paths_by_host: dict[str, PeerLeasePaths] = {}
    peer_lease_daemons: list[RunningPeerLeaseDaemon] = []
    running: list[
        tuple[
            base.ValidatorProcess,
            subprocess.Popen[bytes],
            base.ProcessCapture,
            str,
            str,
            str,
            str,
            str,
        ]
    ] = []
    process_results: list[dict[str, Any]] = []
    replay_archive_sets: dict[str, dict[str, Any]] = {}
    observer_verified_replay_archive_count = 0
    terminal_agreement: dict[str, Any] | None = None
    failure: str | None = None
    cleanup_failures: list[str] = []
    observed_launch_skew_ns: int | None = None
    started_ns = time.monotonic_ns()
    try:
        record_lifecycle_event(lifecycle_events, "deployment_started")
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
        (
            peer_lease_paths_by_host,
            peer_lease_daemons,
        ) = start_peer_lease_daemons(stages, processes, linux_paths)
        record_lifecycle_event(lifecycle_events, "deployment_completed")
        observer_stage = stages["mac"]
        first_launch_ns: int | None = None
        last_launch_ns: int | None = None
        record_lifecycle_event(lifecycle_events, "validator_launch_started")
        for process in processes:
            (
                command,
                report_source,
                journal_source,
                metrics_source,
                final_state_source,
                fleet_start_certificate_source,
            ) = command_for(
                process,
                stages[process.host_id],
                linux_paths[process.host_id],
                args.duration_seconds,
                args.max_blocks,
                peer_lease_paths_by_host[process.host_id].socket,
            )
            capture = base.open_process_capture(process_io, process.validator_id)
            try:
                launch_ns = time.monotonic_ns()
                if first_launch_ns is None:
                    first_launch_ns = launch_ns
                child = subprocess.Popen(
                    command,
                    stdout=capture.stdout,
                    stderr=capture.stderr,
                )
                last_launch_ns = time.monotonic_ns()
            except BaseException:
                base.close_process_capture(capture)
                raise
            running.append(
                (
                    process,
                    child,
                    capture,
                    report_source,
                    journal_source,
                    metrics_source,
                    final_state_source,
                    fleet_start_certificate_source,
                )
            )
        if first_launch_ns is None or last_launch_ns is None:
            raise RuntimeError("fleet launched no validator process")
        observed_launch_skew_ns = validated_launch_skew_ns(
            first_launch_ns, last_launch_ns
        )
        base.write_new(
            output / "fleet-launch-observation.json",
            base.canonical_json(
                {
                    "schema_version": 1,
                    "validator_count": args.validators,
                    "allowance_seconds": FLEET_LAUNCH_SKEW_ALLOWANCE_SECONDS,
                    "observed_launch_skew_ns": observed_launch_skew_ns,
                    "within_allowance": True,
                }
            ),
        )
        record_lifecycle_event(lifecycle_events, "validator_launch_completed")
        deadline = (
            time.monotonic()
            + args.duration_seconds
            + run_bounds["process_completion_allowance_seconds"]
        )
        for (
            process,
            child,
            capture,
            report_source,
            journal_source,
            metrics_source,
            final_state_source,
            fleet_start_certificate_source,
        ) in running:
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(child.args, 0)
                child.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                child.kill()
                try:
                    child.wait(timeout=10)
                finally:
                    base.finish_process_capture(capture)
                raise RuntimeError(
                    f"validator {process.validator_id} exceeded fleet deadline"
                )
            _stdout, stderr = base.finish_process_capture(capture)
            stage = stages[process.host_id]
            if child.returncode != 0:
                raise RuntimeError(
                    f"validator {process.validator_id} exited {child.returncode}: "
                    f"{stderr.decode('utf-8', errors='replace')[:400]}"
                )
            journal_path = journals / f"{process.validator_id}.jsonl"
            journal_copied = copy_observation_file(
                process, stage, journal_source, journal_path
            )
            if not journal_copied:
                raise RuntimeError(
                    f"validator {process.validator_id} omitted its signed runtime journal"
                )
            fleet_start_certificate_path = (
                fleet_start_certificates / f"{process.validator_id}.bin"
            )
            if not copy_observation_file(
                process,
                stage,
                fleet_start_certificate_source,
                fleet_start_certificate_path,
            ):
                raise RuntimeError(
                    f"validator {process.validator_id} omitted its fleet StartCertificate"
                )
            fleet_start_certificate_verification = (
                verify_fleet_start_certificate_on_observer(
                    process=process,
                    certificate_path=fleet_start_certificate_path,
                    mac_binary=mac_binary,
                    observer_root=observer_root,
                    observer_stage=observer_stage,
                    coordinator_anchor=coordinator_anchor,
                    run_id=run_id,
                    duration_seconds=args.duration_seconds,
                    max_blocks=args.max_blocks,
                    validator_count=args.validators,
                )
            )
            journal_verification = verify_journal_on_observer(
                process=process,
                journal_path=journal_path,
                mac_binary=mac_binary,
                observer_root=observer_root,
                observer_stage=observer_stage,
                coordinator_anchor=coordinator_anchor,
                run_id=run_id,
            )
            report_path = reports / f"{process.validator_id}.json"
            if not copy_observation_file(process, stage, report_source, report_path):
                raise RuntimeError(
                    f"validator {process.validator_id} omitted its signed terminal report"
                )
            metrics_path = metrics_values / f"{process.validator_id}.json"
            if not copy_observation_file(process, stage, metrics_source, metrics_path):
                raise RuntimeError(
                    f"validator {process.validator_id} omitted its signed runtime metrics"
                )
            final_state_path = final_states / f"{process.validator_id}.json"
            if not copy_observation_file(
                process, stage, final_state_source, final_state_path
            ):
                raise RuntimeError(
                    f"validator {process.validator_id} omitted its signed runtime final state"
                )
            report_verification = verify_on_observer(
                process=process,
                report_path=report_path,
                mac_binary=mac_binary,
                observer_root=observer_root,
                observer_stage=observer_stage,
                coordinator_anchor=coordinator_anchor,
                run_id=run_id,
            )
            metrics_verification = verify_runtime_on_observer(
                process=process,
                evidence_path=metrics_path,
                kind="runtime-metrics",
                mac_binary=mac_binary,
                observer_root=observer_root,
                observer_stage=observer_stage,
                coordinator_anchor=coordinator_anchor,
                run_id=run_id,
            )
            final_state_verification = verify_runtime_on_observer(
                process=process,
                evidence_path=final_state_path,
                kind="runtime-final-state",
                mac_binary=mac_binary,
                observer_root=observer_root,
                observer_stage=observer_stage,
                coordinator_anchor=coordinator_anchor,
                run_id=run_id,
            )
            report_document = base.strict_json_bytes(
                report_path.read_bytes(),
                f"signed report {process.validator_id}",
            )
            exact_process_evidence_chain(
                certificate=fleet_start_certificate_verification,
                journal=journal_verification,
                report_document=report_document,
                report=report_verification,
                metrics=metrics_verification,
                final_state=final_state_verification,
            )
            process_results.append(
                {
                    "validator_id": process.validator_id,
                    "host_id": process.host_id,
                    "signed_report_sha256": base.sha256_file(report_path),
                    "signed_runtime_journal_sha256": base.sha256_file(journal_path),
                    "fleet_start_certificate_sha256": base.sha256_file(
                        fleet_start_certificate_path
                    ),
                    "signed_runtime_metrics_sha256": base.sha256_file(metrics_path),
                    "signed_runtime_final_state_sha256": base.sha256_file(
                        final_state_path
                    ),
                    "observer_journal_verification": journal_verification,
                    "observer_fleet_start_certificate_verification": (
                        fleet_start_certificate_verification
                    ),
                    "observer_report_verification": report_verification,
                    "observer_metrics_verification": metrics_verification,
                    "observer_final_state_verification": final_state_verification,
                }
            )
        record_lifecycle_event(lifecycle_events, "validator_processes_exited")
        for process in processes:
            replay_archive_sets[process.validator_id] = copy_replay_archive_set_v1(
                process=process,
                stage=stages[process.host_id],
                output=output,
            )
        record_lifecycle_event(lifecycle_events, "replay_archives_exported")

        validator_ids = {process.validator_id for process in processes}
        process_results_by_id = {
            result["validator_id"]: result for result in process_results
        }
        for process in processes:
            result = process_results_by_id[process.validator_id]
            facts = replay_archive_sets[process.validator_id]
            replay_verification = verify_replay_archive_on_observer_v1(
                process=process,
                artifact_facts=facts,
                mac_binary=mac_binary,
                observer_root=observer_root,
                observer_stage=observer_stage,
                coordinator_anchor=coordinator_anchor,
                run_id=run_id,
                validator_ids=validator_ids,
                certificate=result["observer_fleet_start_certificate_verification"],
                journal=result["observer_journal_verification"],
                final_state=result["observer_final_state_verification"],
                run_bounds=run_bounds,
            )
            result.update(
                {
                    "replay_archive_context_sha256": getattr(
                        facts["context"], "sha256"
                    ),
                    "replay_archive_entries_sha256": getattr(
                        facts["entries"], "sha256"
                    ),
                    "replay_archive_head_sha256": getattr(facts["head"], "sha256"),
                    "replay_archive_terminal_seal_sha256": getattr(
                        facts["terminal_seal"], "sha256"
                    ),
                    "observer_replay_archive_verification": replay_verification,
                }
            )
            observer_verified_replay_archive_count += 1
        record_lifecycle_event(
            lifecycle_events, "replay_archives_observer_verified"
        )
        terminal_agreement = exact_terminal_agreement(process_results, args.validators)
        record_lifecycle_event(lifecycle_events, "signed_artifacts_sealed")
    except (
        OSError,
        subprocess.SubprocessError,
        RuntimeError,
        ValueError,
        SystemExit,
    ) as error:
        failure = str(error)
    finally:
        for (
            _process,
            child,
            capture,
            _report,
            _journal,
            _metrics,
            _final,
            _fleet_start_certificate,
        ) in running:
            if child.poll() is None:
                child.kill()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
            try:
                base.close_process_capture(capture)
            except OSError:
                pass
        cleanup_failures.extend(stop_peer_lease_daemons(peer_lease_daemons))
        cleanup_failures.extend(base.clean_stages(stages))
        try:
            verify_coordinator_anchor(anchor_snapshot)
        except SystemExit as error:
            if failure is None:
                failure = str(error)
            else:
                cleanup_failures.append(str(error))
        record_lifecycle_event(lifecycle_events, "cleanup_finished")

    elapsed_ns = time.monotonic_ns() - started_ns
    success = (
        failure is None
        and not cleanup_failures
        and len(process_results) == args.validators
        and len(replay_archive_sets) == args.validators
        and observer_verified_replay_archive_count == args.validators
        and terminal_agreement is not None
    )
    summary = {
        "schema_version": 1,
        "profile": "frozen-v0-continuous-consensus-candidate",
        "run_id": run_id,
        "validator_count": args.validators,
        "transport": transport,
        "signed_report_count": len(process_results),
        "signed_runtime_journal_count": len(process_results),
        "fleet_start_certificate_count": len(process_results),
        "signed_runtime_metrics_count": len(process_results),
        "signed_runtime_final_state_count": len(process_results),
        "signed_replay_archive_set_count": len(replay_archive_sets),
        "observer_verified_report_count": len(process_results),
        "observer_verified_journal_count": len(process_results),
        "observer_verified_fleet_start_certificate_count": len(process_results),
        "observer_verified_metrics_count": len(process_results),
        "observer_verified_final_state_count": len(process_results),
        "observer_verified_replay_archive_count": (
            observer_verified_replay_archive_count
        ),
        "all_six_hosts_participated": False,
        "elapsed_monotonic_ns": elapsed_ns,
        "observed_fleet_launch_skew_ns": observed_launch_skew_ns,
        "fleet_launch_skew_within_allowance": (
            observed_launch_skew_ns is not None
            and observed_launch_skew_ns
            <= FLEET_LAUNCH_SKEW_ALLOWANCE_SECONDS * 1_000_000_000
        ),
        "fleet_launch_skew_capacity_authority": False,
        "coordinator_manifest_sha256": coordinator_anchor,
        "processes": process_results,
        "terminal_agreement": terminal_agreement,
        "failure": failure,
        "cleanup_failures": cleanup_failures,
        "validator_run_completed": False,
        "fault_matrix_completed": False,
        "performance_evidence": False,
        "g3_lan_multihost_evidence": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    base.write_new(output / "consensus-run-summary.json", base.canonical_json(summary))
    record_lifecycle_event(lifecycle_events, "summary_sealed")
    lifecycle = runner_lifecycle_document(
        run_id=run_id,
        validator_count=args.validators,
        coordinator_anchor=coordinator_anchor,
        events=lifecycle_events,
    )
    base.write_new(
        output / "runner-lifecycle.json", base.canonical_json(lifecycle)
    )
    write_runner_output_manifest(
        output,
        run_id=run_id,
        validator_count=args.validators,
        coordinator_anchor=coordinator_anchor,
    )
    if not success:
        base.fail(
            f"run failed; preserved evidence at {output}: {failure or cleanup_failures}"
        )
    print(
        f"poco_g3_consensus_fleet_runner_execution=passed validators={args.validators} "
        "all_six_hosts_attested=false signed_runtime_journals=true "
        "fleet_start_certificate=common "
        "signed_terminal_reports=true signed_runtime_metrics=true "
        "signed_runtime_final_states=true replay_archive_sets=true "
        "macos_replay_archive_verified=true macos_cross_verified=true "
        "validator_run_completed=false fault_matrix_completed=false "
        "performance_evidence=false "
        "g3_complete=false geo_wan=false "
        f"output={output}"
    )


if __name__ == "__main__":
    main()
