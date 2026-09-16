#!/usr/bin/env python3
"""Validate source-bound runtime semantic evidence envelopes.

This module deliberately sits between a runtime command's exit status and the
semantic-gate result. A zero exit code is only process execution evidence. A P0
semantic claim additionally needs a source-bound evidence envelope, required
claim fields, and immutable artifacts whose digests are independently checked.

The envelope is still repository-side engineering evidence, not production or
independent audit authority. External qualification remains a separate gate.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import subprocess
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA = "trnm-runtime-semantic-evidence-v1"


class EvidenceError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def git_output(*arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise EvidenceError(
            f"git {' '.join(arguments)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def current_source_identity() -> tuple[str, str]:
    return git_output("rev-parse", "HEAD"), git_output("rev-parse", "HEAD^{tree}")


def _unsigned(value: object, field: str, *, minimum: int = 0) -> int:
    require(
        isinstance(value, int) and not isinstance(value, bool) and value >= minimum,
        f"{field} must be an integer >= {minimum}",
    )
    return value


def _positive_number(value: object, field: str) -> float:
    require(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and float(value) > 0,
        f"{field} must be a positive number",
    )
    return float(value)


def _true(claims: dict[str, Any], *fields: str) -> None:
    for field in fields:
        require(claims.get(field) is True, f"claims.{field} must be true")


def _validate_claims(check_id: str, claims: object) -> set[str]:
    require(isinstance(claims, dict), "claims must be an object")
    values: dict[str, Any] = claims

    if check_id == "P0.1-multinode-persistence":
        _unsigned(values.get("validator_processes"), "claims.validator_processes", minimum=7)
        _unsigned(values.get("independent_run_roots"), "claims.independent_run_roots", minimum=7)
        require(
            values["independent_run_roots"] >= values["validator_processes"],
            "independent_run_roots must cover every validator process",
        )
        _true(
            values,
            "four_node_phase",
            "seven_node_phase",
            "kill_restart_rejoin",
            "partition_heal",
            "lost_reply_recovery",
            "durable_state_replay_verified",
            "finality_agreement",
        )
        return {"process_logs", "signed_final_state", "replay_verification"}

    if check_id == "P0.2-epoch-transition":
        _unsigned(values.get("completed_transitions"), "claims.completed_transitions", minimum=2)
        _unsigned(values.get("distinct_epochs"), "claims.distinct_epochs", minimum=3)
        _true(
            values,
            "checkpoint_committed",
            "seal1_finalized",
            "seal2_finalized",
            "joint_handoff_authorized",
            "first_new_block_executed",
            "persist_before_sign_cuts_replayed",
            "cold_restart_rejoin",
            "proof_replay_verified",
        )
        return {"epoch_transition_trace", "signer_journal", "finality_proof"}

    if check_id == "P0.3-signer-rollback":
        _true(
            values,
            "device_backed_custody",
            "independent_administration",
            "external_monotonic_anchor",
            "persist_before_sign",
            "rollback_rejected",
            "anchor_replacement_rejected",
            "lost_response_replay_safe",
        )
        return {"device_attestation", "monotonic_anchor_trace", "rollback_trace"}

    if check_id == "P0.4-finalized-goodput":
        events = _unsigned(values.get("event_count"), "claims.event_count", minimum=1)
        finalized = _unsigned(
            values.get("replay_verified_finalized_count"),
            "claims.replay_verified_finalized_count",
            minimum=1,
        )
        require(finalized <= events, "replay_verified_finalized_count exceeds event_count")
        _positive_number(values.get("finalized_goodput_tps"), "claims.finalized_goodput_tps")
        p50 = _positive_number(values.get("finality_p50_ms"), "claims.finality_p50_ms")
        p95 = _positive_number(values.get("finality_p95_ms"), "claims.finality_p95_ms")
        p99 = _positive_number(values.get("finality_p99_ms"), "claims.finality_p99_ms")
        require(p50 <= p95 <= p99, "finality percentiles must be monotonic")
        _true(values, "workload_bound", "topology_bound", "durability_bound", "confidence_bounds")
        return {
            "raw_tx_telemetry",
            "goodput_measurement",
            "workload_manifest",
            "topology_manifest",
            "durability_profile",
        }

    raise EvidenceError(f"unknown runtime semantic check id: {check_id}")


def _sealed_file_facts(path: pathlib.Path, field: str) -> tuple[str, int]:
    absolute = pathlib.Path(os.path.abspath(path))
    try:
        before_path = absolute.lstat()
        descriptor = os.open(
            absolute,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise EvidenceError(f"cannot open {field}: {error}") from error
    digest = hashlib.sha256()
    size = 0
    try:
        before = os.fstat(descriptor)
        require(
            not stat.S_ISLNK(before_path.st_mode)
            and stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before_path.st_dev == before.st_dev
            and before_path.st_ino == before.st_ino,
            f"{field} must be one singly-linked regular non-symlink file",
        )
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after_path = absolute.lstat()
    except OSError as error:
        raise EvidenceError(f"cannot re-read {field}: {error}") from error
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    require(
        identity == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        and identity
        == (after_path.st_dev, after_path.st_ino, after_path.st_size, after_path.st_mtime_ns)
        and size == before.st_size
        and size > 0,
        f"{field} changed while hashing or is empty",
    )
    return digest.hexdigest(), size


def verify_evidence(path: pathlib.Path, expected_check_id: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"cannot read evidence envelope {path}: {error}") from error
    require(raw, "evidence envelope is empty")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise EvidenceError(f"invalid evidence envelope JSON: {error}") from error
    require(isinstance(document, dict), "evidence envelope must be an object")
    require(document.get("schema") == SCHEMA, f"evidence schema must be {SCHEMA}")
    require(document.get("check_id") == expected_check_id, "evidence check_id mismatch")
    require(document.get("status") == "PASS", "evidence status must be PASS")
    require(document.get("production_authority") is False, "evidence cannot hold production authority")

    source_commit, source_tree = current_source_identity()
    require(document.get("source_commit") == source_commit, "evidence source_commit does not match HEAD")
    require(document.get("source_tree") == source_tree, "evidence source_tree does not match HEAD tree")

    required_roles = _validate_claims(expected_check_id, document.get("claims"))
    artifacts = document.get("artifacts")
    require(isinstance(artifacts, list) and artifacts, "evidence artifacts must be non-empty")
    seen_roles: set[str] = set()
    seen_paths: set[pathlib.Path] = set()
    envelope_absolute = pathlib.Path(os.path.abspath(path))
    for index, row in enumerate(artifacts):
        require(isinstance(row, dict), f"artifacts[{index}] must be an object")
        require(
            set(row) == {"role", "path", "sha256", "bytes"},
            f"artifacts[{index}] keys drift",
        )
        role = row["role"]
        raw_path = row["path"]
        expected_digest = row["sha256"]
        expected_bytes = row["bytes"]
        require(isinstance(role, str) and role, f"artifacts[{index}].role missing")
        require(role not in seen_roles, f"duplicate artifact role {role}")
        require(isinstance(raw_path, str) and raw_path, f"artifacts[{index}].path missing")
        artifact_path = pathlib.Path(raw_path)
        if not artifact_path.is_absolute():
            artifact_path = path.parent / artifact_path
        artifact_path = pathlib.Path(os.path.abspath(artifact_path))
        require(artifact_path != envelope_absolute, "evidence envelope cannot cite itself as an artifact")
        require(artifact_path not in seen_paths, "duplicate artifact path")
        require(
            isinstance(expected_digest, str)
            and len(expected_digest) == 64
            and all(character in "0123456789abcdef" for character in expected_digest),
            f"artifacts[{index}].sha256 must be canonical lowercase hex",
        )
        _unsigned(expected_bytes, f"artifacts[{index}].bytes", minimum=1)
        observed_digest, observed_bytes = _sealed_file_facts(
            artifact_path, f"artifact {role}"
        )
        require(observed_digest == expected_digest, f"artifact {role} digest mismatch")
        require(observed_bytes == expected_bytes, f"artifact {role} size mismatch")
        seen_roles.add(role)
        seen_paths.add(artifact_path)

    missing_roles = sorted(required_roles - seen_roles)
    require(not missing_roles, f"evidence is missing required artifact roles: {missing_roles}")
    return document
