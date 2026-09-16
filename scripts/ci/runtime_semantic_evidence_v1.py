#!/usr/bin/env python3
"""Verify source-bound runtime evidence with fixed repository verifiers.

The evidence envelope is only a content-addressed manifest. It contains no
self-authoritative PASS bit and no boolean claim fields. A semantic check passes
only when this module invokes the repository-owned verifier for that check over
the sealed raw artifacts and recomputes the claimed result.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA = "trnm-runtime-semantic-evidence-v2"
HEX64 = set("0123456789abcdef")


class EvidenceError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def git_output(*arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments], cwd=ROOT, check=False, text=True, capture_output=True
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


def _sealed_file_facts(path: pathlib.Path, field: str) -> tuple[str, int]:
    absolute = pathlib.Path(os.path.abspath(path))
    try:
        before_path = absolute.lstat()
        descriptor = os.open(
            absolute, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
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


def _strict_json(path: pathlib.Path, field: str) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
        value = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{field} is not one strict UTF-8 JSON object: {error}") from error
    require(isinstance(value, dict), f"{field} must be a JSON object")
    return value


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON member {key!r}")
        value[key] = child
    return value


def _run_fixed_verifier(command: list[str], label: str) -> str:
    completed = subprocess.run(
        command, cwd=ROOT, check=False, text=True, capture_output=True
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise EvidenceError(f"{label} rejected evidence: {detail}")
    return completed.stdout.strip()


def _verify_p01(artifacts: dict[str, pathlib.Path]) -> dict[str, Any]:
    required = {
        "four_node_bundle_manifest",
        "four_node_coordinator_manifest",
        "seven_node_bundle_manifest",
        "seven_node_coordinator_manifest",
    }
    require(set(artifacts) == required, f"P0.1 artifact roles must be exactly {sorted(required)}")
    results: dict[str, Any] = {"verified_validator_counts": []}
    for count, prefix in ((4, "four_node"), (7, "seven_node")):
        manifest = artifacts[f"{prefix}_bundle_manifest"]
        coordinator = artifacts[f"{prefix}_coordinator_manifest"]
        require(manifest.name == "manifest.json", f"P0.1 {count}-node bundle artifact must be manifest.json")
        document = _strict_json(manifest, f"P0.1 {count}-node manifest")
        require(document.get("validator_count") == count, f"P0.1 {count}-node manifest validator_count mismatch")
        profile = document.get("evidence_profile")
        require(isinstance(profile, str) and profile, f"P0.1 {count}-node manifest evidence_profile missing")
        coordinator_digest, _ = _sealed_file_facts(coordinator, f"P0.1 {count}-node coordinator manifest")
        output = _run_fixed_verifier(
            [
                sys.executable,
                str(ROOT / "scripts/poco-fleet/check_run_bundle.py"),
                str(manifest.parent),
                "--validators",
                str(count),
                "--profile",
                profile,
                "--coordinator-manifest-sha256",
                coordinator_digest,
            ],
            f"P0.1 {count}-node fixed bundle verifier",
        )
        require("poco_g3_run_bundle=passed" in output, f"P0.1 {count}-node verifier did not emit pass marker")
        results["verified_validator_counts"].append(count)
    return results


def _verify_p04(artifacts: dict[str, pathlib.Path]) -> dict[str, Any]:
    required = {
        "raw_tx_telemetry",
        "goodput_measurement",
        "workload_manifest",
        "topology_manifest",
        "durability_profile",
    }
    require(set(artifacts) == required, f"P0.4 artifact roles must be exactly {sorted(required)}")
    bindings: dict[str, str] = {}
    for role in ("workload_manifest", "topology_manifest", "durability_profile"):
        document = _strict_json(artifacts[role], f"P0.4 {role}")
        require(document.get("production_authority") is False, f"P0.4 {role} cannot hold production authority")
        digest, _ = _sealed_file_facts(artifacts[role], f"P0.4 {role}")
        bindings[f"{role}_sha256"] = digest

    # Every raw event must bind the exact workload/topology/durability inputs.
    raw_path = artifacts["raw_tx_telemetry"]
    event_count = 0
    for lineno, line in enumerate(raw_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line, object_pairs_hook=_unique_pairs)
        except (json.JSONDecodeError, ValueError) as error:
            raise EvidenceError(f"P0.4 telemetry line {lineno} invalid: {error}") from error
        require(isinstance(event, dict), f"P0.4 telemetry line {lineno} must be an object")
        for field, expected in bindings.items():
            require(event.get(field) == expected, f"P0.4 telemetry line {lineno} {field} mismatch")
        event_count += 1
    require(event_count > 0, "P0.4 telemetry is empty")

    with tempfile.TemporaryDirectory(prefix="trnm-p04-recompute-") as directory:
        recomputed = pathlib.Path(directory) / "measurement.json"
        _run_fixed_verifier(
            [
                sys.executable,
                str(ROOT / "trillionnium/scripts/measure_finalized_goodput.py"),
                str(raw_path),
                "-o",
                str(recomputed),
            ],
            "P0.4 fixed goodput verifier",
        )
        observed = _strict_json(artifacts["goodput_measurement"], "P0.4 supplied measurement")
        expected = _strict_json(recomputed, "P0.4 recomputed measurement")

    # generated_at/environment are observation metadata; semantic values must be exact.
    for transient in ("generated_at_utc", "environment"):
        observed.pop(transient, None)
        expected.pop(transient, None)
    require(observed == expected, "P0.4 supplied measurement differs from fixed-verifier recomputation")
    metrics = expected.get("metrics")
    counts = expected.get("counts")
    require(isinstance(metrics, dict) and isinstance(counts, dict), "P0.4 recomputation lacks metrics/counts")
    require(_unsigned(counts.get("replay_verified_finalized"), "P0.4 replay_verified_finalized", minimum=1) >= 1, "P0.4 has no replay-verified finality")
    goodput = metrics.get("finalized_goodput_tps")
    require(isinstance(goodput, (int, float)) and not isinstance(goodput, bool) and goodput > 0, "P0.4 finalized goodput must be positive")
    return {"event_count": event_count, "finalized_goodput_tps": goodput}


def _verify_semantics(check_id: str, artifacts: dict[str, pathlib.Path]) -> dict[str, Any]:
    if check_id == "P0.1-multinode-persistence":
        return _verify_p01(artifacts)
    if check_id == "P0.4-finalized-goodput":
        return _verify_p04(artifacts)
    if check_id == "P0.2-epoch-transition":
        raise EvidenceError("P0.2 has no fixed two-transition runtime verifier yet; fail closed")
    if check_id == "P0.3-signer-rollback":
        raise EvidenceError("P0.3 has no fixed device/anti-rollback verifier yet; fail closed")
    raise EvidenceError(f"unknown runtime semantic check id: {check_id}")


def verify_evidence(path: pathlib.Path, expected_check_id: str) -> dict[str, Any]:
    document = _strict_json(path, "evidence envelope")
    require(
        set(document)
        == {"schema", "check_id", "production_authority", "source_commit", "source_tree", "artifacts"},
        "evidence envelope keys drift; self-authored status/claims fields are forbidden",
    )
    require(document.get("schema") == SCHEMA, f"evidence schema must be {SCHEMA}")
    require(document.get("check_id") == expected_check_id, "evidence check_id mismatch")
    require(document.get("production_authority") is False, "evidence cannot hold production authority")

    source_commit, source_tree = current_source_identity()
    require(document.get("source_commit") == source_commit, "evidence source_commit does not match HEAD")
    require(document.get("source_tree") == source_tree, "evidence source_tree does not match HEAD tree")

    rows = document.get("artifacts")
    require(isinstance(rows, list) and rows, "evidence artifacts must be non-empty")
    envelope_absolute = pathlib.Path(os.path.abspath(path))
    artifacts: dict[str, pathlib.Path] = {}
    seen_paths: set[pathlib.Path] = set()
    for index, row in enumerate(rows):
        require(isinstance(row, dict), f"artifacts[{index}] must be an object")
        require(set(row) == {"role", "path", "sha256", "bytes"}, f"artifacts[{index}] keys drift")
        role = row["role"]
        raw_path = row["path"]
        expected_digest = row["sha256"]
        expected_bytes = row["bytes"]
        require(isinstance(role, str) and role and role not in artifacts, f"artifacts[{index}].role invalid or duplicate")
        require(isinstance(raw_path, str) and raw_path, f"artifacts[{index}].path missing")
        artifact_path = pathlib.Path(raw_path)
        if not artifact_path.is_absolute():
            artifact_path = path.parent / artifact_path
        artifact_path = pathlib.Path(os.path.abspath(artifact_path))
        require(artifact_path != envelope_absolute, "evidence envelope cannot cite itself")
        require(artifact_path not in seen_paths, "duplicate artifact path")
        require(
            isinstance(expected_digest, str)
            and len(expected_digest) == 64
            and all(character in HEX64 for character in expected_digest),
            f"artifacts[{index}].sha256 must be canonical lowercase hex",
        )
        _unsigned(expected_bytes, f"artifacts[{index}].bytes", minimum=1)
        observed_digest, observed_bytes = _sealed_file_facts(artifact_path, f"artifact {role}")
        require(observed_digest == expected_digest, f"artifact {role} digest mismatch")
        require(observed_bytes == expected_bytes, f"artifact {role} size mismatch")
        artifacts[role] = artifact_path
        seen_paths.add(artifact_path)

    semantic = _verify_semantics(expected_check_id, artifacts)
    return {"check_id": expected_check_id, "semantic_verifier": semantic}
