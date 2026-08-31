#!/usr/bin/env python3
"""Assemble, then strictly verify, one immutable PoCO G3 LAN run bundle.

The assembler is intentionally mechanical.  It accepts an explicit inventory
of already-existing raw artifacts, copies their exact bytes into a new private
directory, derives only content addresses and the collector input root, and
then invokes the independent run-bundle verifier.  It never creates validator
events, metrics, final state, fault outcomes, or a completed-run summary.
Active assembly is available only for the explicit no-fault profile. The
mixed-authority fault profile remains plan-only until its distinct artifact
roles and authorities exist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import stat
import sys
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
SOURCE_ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import check_run_bundle as checker  # noqa: E402
import evidence_bundle_profiles_v1 as evidence_profiles  # noqa: E402
import fault_evidence_semantics_v1 as fault_semantics  # noqa: E402


MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_BUNDLE_BYTES = 8 * 1024 * 1024 * 1024
SPEC_KEYS = {
    "schema_version",
    "evidence_profile",
    "run_id",
    "validator_count",
    "network_scope",
    "geo_wan_evidence",
    "completed_run_summary",
    "artifacts",
}
SUMMARY_KEYS = {"source", "path"}
ARTIFACT_KEYS = {"role", "subject", "source", "path"}
SUMMARY_CANDIDATE_KEYS = {
    "source_tree_sha256",
    "linux_x86_64_sha256",
    "macos_arm64_sha256",
    "configuration_set_sha256",
    "reproducible_build",
    "production_activation",
} | checker.check_run_evidence.SOURCE_PROVENANCE_KEYS


def fail(message: str) -> None:
    raise SystemExit(f"PoCO G3 run-bundle assembler failed: {message}")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            fail(f"duplicate JSON object name {key!r}")
        value[key] = child
    return value


def read_json(path: pathlib.Path, field: str) -> dict[str, Any]:
    source = require_regular_file(path, field)
    try:
        value = json.loads(
            source.read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"{field} is not one exact UTF-8 JSON document: {error}")
    if not isinstance(value, dict):
        fail(f"{field} must be one JSON object")
    return value


def exact(value: object, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{field} keys must be exactly {sorted(keys)!r}")
    return value


def safe_relative(value: object, field: str) -> pathlib.PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        fail(f"{field} must be a non-empty POSIX relative path")
    relative = pathlib.PurePosixPath(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        fail(f"{field} must remain inside the new bundle")
    return relative


def require_regular_file(raw: pathlib.Path | str, field: str) -> pathlib.Path:
    path = pathlib.Path(raw).absolute()
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve {field}: {error}")
    if (
        resolved != path
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > MAX_ARTIFACT_BYTES
    ):
        fail(f"{field} must be one bounded, regular, non-symlink file")
    return path


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def write_new(path: pathlib.Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def copy_exact(source: pathlib.Path, target: pathlib.Path) -> dict[str, object]:
    """Copy one inode-pinned regular file and return its exact reference."""

    before = source.stat()
    source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target_fd = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(source_fd, "rb", closefd=True) as input_stream:
            source_fd = -1
            with os.fdopen(target_fd, "wb", closefd=True) as output_stream:
                target_fd = -1
                while chunk := input_stream.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_ARTIFACT_BYTES:
                        fail("artifact changed across its bounded copy")
                    digest.update(chunk)
                    output_stream.write(chunk)
                output_stream.flush()
                os.fsync(output_stream.fileno())
            after = os.fstat(input_stream.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if target_fd >= 0:
            os.close(target_fd)
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or size != before.st_size
        or size <= 0
    ):
        target.unlink(missing_ok=True)
        fail("artifact identity changed while it was copied")
    return {
        "path": target.as_posix(),
        "sha256": digest.hexdigest(),
        "bytes": size,
    }


def normalize_spec(path: pathlib.Path, *, profile: str) -> dict[str, Any]:
    document = exact(read_json(path, "assembly spec"), SPEC_KEYS, "assembly spec")
    try:
        selected_profile = evidence_profiles.require_known(profile)
    except ValueError as error:
        fail(str(error))
    vocabulary = checker.role_vocabulary(selected_profile)
    if document["evidence_profile"] != selected_profile:
        fail("assembly spec evidence_profile differs from the explicit CLI profile")
    count = document["validator_count"]
    if (
        document["schema_version"] != 1
        or count not in {7, 31, 100}
        or document["network_scope"] != "single-lan"
        or document["geo_wan_evidence"] is not False
        or not isinstance(document["run_id"], str)
        or checker.check_run_evidence.RUN_ID.fullmatch(document["run_id"]) is None
    ):
        fail("assembly spec identity crosses the frozen LAN profile")
    summary = exact(
        document["completed_run_summary"], SUMMARY_KEYS, "completed_run_summary"
    )
    summary_source = require_regular_file(summary["source"], "completed-run summary")
    summary_document = checker.read_json(summary_source, "completed-run summary")
    if summary_document.get("run_id") != document["run_id"]:
        fail("completed-run summary differs from the assembly run_id")
    if summary_document.get("evidence_profile") != selected_profile:
        fail("completed-run summary evidence_profile differs from the assembly spec")
    if summary_document.get("schema_version") != 3:
        fail("completed-run summary schema_version must be 3")
    summary_candidate = exact(
        summary_document.get("candidate"),
        SUMMARY_CANDIDATE_KEYS,
        "completed-run summary candidate",
    )
    checker.check_run_evidence.validate_source_provenance(
        summary_candidate,
        "completed-run summary candidate",
        fail_fn=fail,
    )
    if selected_profile == evidence_profiles.NO_FAULT_V1:
        checker.check_run_evidence.validate(
            summary_source, count, profile=selected_profile, emit=False
        )
    validator_ids = {
        item.get("validator_id")
        for item in summary_document.get("validators", [])
        if isinstance(item, dict)
    }
    if len(validator_ids) != count or any(not isinstance(item, str) for item in validator_ids):
        fail("completed-run summary validator inventory is invalid")
    summary_path = safe_relative(summary["path"], "completed_run_summary.path")
    if summary_path.as_posix() in {"manifest.json", "collector-report.json"}:
        fail("completed-run summary uses a reserved output path")

    artifacts = document["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        fail("artifacts must be a non-empty list")
    normalized: list[dict[str, Any]] = []
    paths = {"manifest.json", "collector-report.json", summary_path.as_posix()}
    pairs: set[tuple[str, str]] = set()
    total = summary_source.stat().st_size
    allowed_roles = vocabulary.all_roles - {"collector_report"}
    for index, raw in enumerate(artifacts):
        item = exact(raw, ARTIFACT_KEYS, f"artifacts[{index}]")
        role = item["role"]
        subject = item["subject"]
        if role not in allowed_roles or not isinstance(subject, str):
            fail(f"artifacts[{index}] role/subject is outside the bundle vocabulary")
        if role in vocabulary.fault:
            fail("legacy primary fault artifacts are forbidden in every v1 profile")
        pair = (role, subject)
        if pair in pairs:
            fail("artifact role/subject pairs must be unique")
        pairs.add(pair)
        source = require_regular_file(item["source"], f"artifacts[{index}].source")
        relative = safe_relative(item["path"], f"artifacts[{index}].path")
        if relative.as_posix() in paths:
            fail("bundle destination paths must be unique and non-reserved")
        paths.add(relative.as_posix())
        total += source.stat().st_size
        if total > MAX_BUNDLE_BYTES:
            fail("bundle input bytes exceed the frozen bound")
        normalized.append(
            {"role": role, "subject": subject, "source": source, "path": relative}
        )
    role_subjects: dict[str, set[str]] = {}
    for role, subject in pairs:
        role_subjects.setdefault(role, set()).add(subject)
    for role in vocabulary.singleton - {"collector_report"}:
        if role_subjects.get(role) != {""}:
            fail(f"assembly spec requires exactly one {role}")
    for role in vocabulary.validator:
        if role_subjects.get(role) != validator_ids:
            fail(f"assembly spec requires one {role} per validator")
    for role in vocabulary.host:
        if role_subjects.get(role) != vocabulary.host_subjects:
            fail(f"assembly spec requires one {role} per frozen physical host")
    for role in vocabulary.observer:
        if role_subjects.get(role) != {"mac"}:
            fail(f"assembly spec requires exactly one {role} for mac")
    if any(role_subjects.get(role) for role in vocabulary.fault):
        fail("assembly spec forbids legacy fault artifacts")
    return {
        **document,
        "completed_run_summary": {"source": summary_source, "path": summary_path},
        "artifacts": normalized,
        "input_bytes": total,
    }


def plan(document: dict[str, Any], coordinator_anchor: str) -> dict[str, Any]:
    if checker.HEX64.fullmatch(coordinator_anchor) is None:
        fail("coordinator manifest anchor must be canonical SHA-256")
    summary = document["completed_run_summary"]
    artifacts = [
        {
            "role": item["role"],
            "subject": item["subject"],
            "path": item["path"].as_posix(),
            "source_sha256": sha256_file(item["source"]),
            "bytes": item["source"].stat().st_size,
        }
        for item in document["artifacts"]
    ]
    return {
        "schema_version": 1,
        "profile": "poco-g3-run-bundle-assembly-plan-v2",
        "evidence_profile": document["evidence_profile"],
        "run_id": document["run_id"],
        "validator_count": document["validator_count"],
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "coordinator_manifest_sha256": coordinator_anchor,
        "completed_run_summary": {
            "path": summary["path"].as_posix(),
            "source_sha256": sha256_file(summary["source"]),
            "bytes": summary["source"].stat().st_size,
        },
        "artifacts": artifacts,
        "input_bytes": document["input_bytes"],
        "fault_evidence_policy": (
            fault_semantics.plan_matrix()
            if document["evidence_profile"]
            == evidence_profiles.MIXED_AUTHORITY_FAULT_MATRIX_V1
            else []
        ),
        "active_assembly_supported": document["evidence_profile"]
        in evidence_profiles.ACTIVE_BUNDLE_PROFILES,
        "authority_blockers": (
            fault_semantics.bundle_assembly_blockers()
            if document["evidence_profile"]
            == evidence_profiles.MIXED_AUTHORITY_FAULT_MATRIX_V1
            else list(
                evidence_profiles.authority_blockers(
                    document["evidence_profile"]
                )
            )
        ),
        "legacy_exact_eight_primary_signed_transitions_allowed": False,
        "creates_runtime_evidence": False,
        "requires_independent_bundle_verification": True,
        "g3_evidence_complete": False,
        "geo_wan_evidence_complete": False,
        "production_activation": False,
    }


def validate_output_root(path: pathlib.Path) -> pathlib.Path:
    output = path.absolute()
    if output.exists() or output.is_symlink():
        fail("output root already exists")
    try:
        output.relative_to(SOURCE_ROOT)
    except ValueError:
        return output
    fail("output root must remain outside the source tree")


def assemble(
    document: dict[str, Any],
    output: pathlib.Path,
    coordinator_anchor: str,
) -> pathlib.Path:
    if (
        document["evidence_profile"]
        == evidence_profiles.MIXED_AUTHORITY_FAULT_MATRIX_V1
    ):
        try:
            fault_semantics.require_bundle_assembly_supported()
        except RuntimeError as error:
            fail(str(error))
    try:
        evidence_profiles.require_active(document["evidence_profile"])
    except (ValueError, RuntimeError) as error:
        fail(str(error))
    if checker.HEX64.fullmatch(coordinator_anchor) is None:
        fail("coordinator manifest anchor must be canonical SHA-256")
    root = validate_output_root(output)
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    try:
        summary = document["completed_run_summary"]
        summary_target = root.joinpath(*summary["path"].parts)
        summary_ref = copy_exact(summary["source"], summary_target)
        summary_ref["path"] = summary["path"].as_posix()
        records: list[dict[str, Any]] = []
        for item in document["artifacts"]:
            target = root.joinpath(*item["path"].parts)
            reference = copy_exact(item["source"], target)
            reference["path"] = item["path"].as_posix()
            records.append(
                {
                    "role": item["role"],
                    "subject": item["subject"],
                    **reference,
                }
            )
        collector = {
            "schema_version": 1,
            "evidence_profile": document["evidence_profile"],
            "run_id": document["run_id"],
            "validator_count": document["validator_count"],
            "summary_sha256": summary_ref["sha256"],
            "ordered_input_root": checker.ordered_input_root(
                document["evidence_profile"], records
            ),
            "derived_from_raw_artifacts": True,
        }
        collector_path = root / "collector-report.json"
        write_new(
            collector_path,
            json.dumps(collector, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
        records.append(
            {
                "role": "collector_report",
                "subject": "",
                "path": "collector-report.json",
                "sha256": sha256_file(collector_path),
                "bytes": collector_path.stat().st_size,
            }
        )
        manifest = {
            "schema_version": 1,
            "evidence_profile": document["evidence_profile"],
            "run_id": document["run_id"],
            "validator_count": document["validator_count"],
            "network_scope": "single-lan",
            "geo_wan_evidence": False,
            "completed_run_summary": summary_ref,
            "artifacts": records,
        }
        write_new(
            root / "manifest.json",
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
        checker.validate(
            root,
            document["validator_count"],
            profile=document["evidence_profile"],
            coordinator_manifest_sha256=coordinator_anchor,
            emit=False,
        )
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        raise
    return root


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("spec", type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--coordinator-manifest-sha256", required=True)
    parser.add_argument(
        "--profile", required=True, choices=sorted(evidence_profiles.KNOWN_PROFILES)
    )
    parser.add_argument("--plan-only", action="store_true")
    args = parser.parse_args()
    document = normalize_spec(args.spec, profile=args.profile)
    assembly_plan = plan(document, args.coordinator_manifest_sha256)
    if args.plan_only:
        print(json.dumps(assembly_plan, indent=2, sort_keys=True))
        return
    root = assemble(document, args.output, args.coordinator_manifest_sha256)
    print(
        "poco_g3_run_bundle_assembler_v1=passed "
        f"profile={document['evidence_profile']} "
        f"validators={document['validator_count']} artifacts={len(document['artifacts']) + 1} "
        "raw_artifacts_copied=true independent_verifier=passed "
        "created_runtime_evidence=false geo_wan=false production_activation=false "
        f"output={root}"
    )


if __name__ == "__main__":
    main()
