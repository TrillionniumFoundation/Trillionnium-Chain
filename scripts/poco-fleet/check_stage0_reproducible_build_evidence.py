#!/usr/bin/env python3
"""Verify the bounded Stage0 Linux/x86_64 reproducible-build observation.

Shallow verification checks the two content-addressed raw builder reports for
internal consistency and enforces their closed truth boundary. Deep
verification additionally rehashes the exact strict source candidate and the
two common output binaries.
Neither mode executes Cargo or upgrades this observation into cross-
architecture, validator-run, multihost, or production evidence.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import tarfile
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
REPOSITORY_ROOT = HERE.parent.parent


PROFILE = "poco-g3-stage0-linux-x86_64-reproducible-build-observation-v1"
EVIDENCE_ID = re.compile(
    r"^trnm-poco-g3-stage0-linux-x86_64-repro-([0-9a-f]{8})-([0-9]{8})$"
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
LINUX_X86_64_HOST = re.compile(r"^x86_64-[A-Za-z0-9_.-]+-linux-gnu$")
MAX_JSON_BYTES = 1024 * 1024
MAX_BINARY_BYTES = 1024 * 1024 * 1024
MAX_SOURCE_CANDIDATE_BYTES = 1024 * 1024 * 1024
MAX_SOURCE_FILE_COUNT = 1_000_000
MAX_CARGO_LOCK_BYTES = 16 * 1024 * 1024
EMPTY_STATUS_SHA256 = hashlib.sha256(b"").hexdigest()
CARGO_LOCK_PATH = "trillionnium/Cargo.lock"

EXPECTED_TOOLS: list[dict[str, object]] = [
    {
        "role": "reproducible_builder",
        "path": "scripts/poco-fleet/build_reproducible_lab_candidate.py",
        "sha256": (
            "f6e86e72934d29a3f7015be4ca5b3d5c595941aef4c7aa75cb712f4c0cc80bde"
        ),
        "bytes": 31_428,
    },
    {
        "role": "source_candidate_checker",
        "path": "scripts/poco-fleet/check_source_candidate.py",
        "sha256": (
            "2c9222dd65448fa89558c8c25873adf6ca6f1ad157a90655539c14da0864d4e6"
        ),
        "bytes": 19_570,
    },
]

MANIFEST_KEYS = {
    "schema_version",
    "evidence_id",
    "evidence_profile",
    "source_candidate",
    "operator_recorded_tools",
    "operator_recorded_offline_dependency_cache",
    "runner_record",
    "build_reports",
    "binary_outputs",
    "claims",
}
SOURCE_CANDIDATE_KEYS = {
    "archive_bytes",
    "base_commit",
    "cargo_lock_bytes",
    "cargo_lock_path",
    "cargo_lock_sha256",
    "file_count",
    "geo_wan_evidence",
    "git_object_format",
    "git_status_sha256",
    "git_tree_oid",
    "production_activation",
    "source_bytes",
    "source_candidate_sha256",
    "source_profile",
}
CACHE_KEYS = {"format", "sha256", "bytes", "bundled"}
RUNNER_KEYS = {
    "runner_label",
    "transport",
    "paid_ci_used",
    "cryptographic_host_attestation",
    "tool_and_cache_use_cryptographically_attested",
    "builder_invocation_count",
    "independent_cargo_build_count",
    "host_triple",
    "rustc_vv_sha256",
}
REPORT_REF_KEYS = {"subject", "path", "sha256", "bytes"}
BINARY_OUTPUT_KEYS = {"role", "sha256", "bytes", "bundled"}
REPORT_KEYS = {
    "schema_version",
    "source_candidate_sha256",
    "source_candidate_profile",
    "source_base_commit",
    "source_git_object_format",
    "source_git_tree_oid",
    "source_git_status_sha256",
    "cargo_lock_path",
    "cargo_lock_sha256",
    "cargo_lock_bytes",
    "validator_binary_sha256",
    "validator_binary_bytes",
    "material_builder_binary_sha256",
    "material_builder_binary_bytes",
    "host_triple",
    "rustc_vv_sha256",
    "reproducible_build",
    "independent_build_count",
    "output_validator_binary",
    "output_material_builder_binary",
    "production_activation",
    "geo_wan_evidence",
}
CLAIM_VALUES: dict[str, bool] = {
    "builder_reports_claim_reproducible_build": True,
    "operator_records_native_linux_x86_64_build_execution": True,
    "build_execution_cryptographically_attested": False,
    "native_cross_architecture_build_observed": False,
    "aggregate_build_report_emitted": False,
    "fresh_clone_fmt_observed": False,
    "fresh_clone_check_observed": False,
    "key_tests_observed": False,
    "validator_runtime_started": False,
    "validator_run_7_completed": False,
    "signed_runtime_evidence_multihost_observed": False,
    "multihost_consensus_observed": False,
    "fault_matrix_completed": False,
    "performance_evidence": False,
    "g3_lan_multihost_evidence": False,
    "g3_geo_wan_evidence": False,
    "production_activation": False,
    "production_candidate": False,
}


def fail(message: str) -> None:
    raise SystemExit(f"PoCO G3 Stage0 reproducible-build evidence invalid: {message}")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            fail(f"duplicate JSON object name {key!r}")
        value[key] = child
    return value


def exact_keys(value: object, expected: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{field} keys must be exactly {sorted(expected)!r}")
    return value


def exact_typed_mapping(
    value: object,
    expected: dict[str, object],
    field: str,
) -> dict[str, Any]:
    observed = exact_keys(value, set(expected), field)
    for key, expected_value in expected.items():
        actual = observed[key]
        if type(actual) is not type(expected_value) or actual != expected_value:
            fail(f"{field}.{key} differs from its exact typed value")
    return observed


def positive_integer(value: object, field: str, maximum: int | None = None) -> int:
    if type(value) is not int or value <= 0 or (maximum is not None and value > maximum):
        fail(f"{field} must be one bounded positive integer")
    return value


def sha256_text(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not HEX64.fullmatch(value)
        or value == "0" * 64
    ):
        fail(f"{field} must be one canonical nonzero lowercase SHA-256")
    return value


def git_oid(value: object, object_format: str, field: str) -> str:
    pattern = HEX40 if object_format == "sha1" else HEX64 if object_format == "sha256" else None
    if (
        pattern is None
        or not isinstance(value, str)
        or pattern.fullmatch(value) is None
        or set(value) == {"0"}
    ):
        fail(f"{field} is not one canonical {object_format} Git object ID")
    return value


def validate_source_candidate_record(value: object) -> dict[str, Any]:
    candidate = exact_keys(value, SOURCE_CANDIDATE_KEYS, "source_candidate")
    object_format = candidate["git_object_format"]
    if not isinstance(object_format, str) or object_format not in {"sha1", "sha256"}:
        fail("source_candidate.git_object_format must be sha1 or sha256")
    git_oid(candidate["base_commit"], object_format, "source_candidate.base_commit")
    git_oid(candidate["git_tree_oid"], object_format, "source_candidate.git_tree_oid")
    positive_integer(
        candidate["archive_bytes"],
        "source_candidate.archive_bytes",
        MAX_SOURCE_CANDIDATE_BYTES,
    )
    positive_integer(
        candidate["file_count"],
        "source_candidate.file_count",
        MAX_SOURCE_FILE_COUNT,
    )
    positive_integer(
        candidate["source_bytes"],
        "source_candidate.source_bytes",
        MAX_SOURCE_CANDIDATE_BYTES,
    )
    positive_integer(
        candidate["cargo_lock_bytes"],
        "source_candidate.cargo_lock_bytes",
        MAX_CARGO_LOCK_BYTES,
    )
    sha256_text(
        candidate["source_candidate_sha256"],
        "source_candidate.source_candidate_sha256",
    )
    sha256_text(candidate["cargo_lock_sha256"], "source_candidate.cargo_lock_sha256")
    if (
        candidate["source_profile"] != "clean-commit-v1"
        or candidate["git_status_sha256"] != EMPTY_STATUS_SHA256
        or candidate["cargo_lock_path"] != CARGO_LOCK_PATH
        or candidate["production_activation"] is not False
        or candidate["geo_wan_evidence"] is not False
    ):
        fail("source_candidate differs from the strict clean-commit truth boundary")
    return candidate


def validate_cache_record(value: object) -> dict[str, Any]:
    field = "operator_recorded_offline_dependency_cache"
    cache = exact_keys(value, CACHE_KEYS, field)
    if (
        cache["format"] != "cargo-home-registry-tar-gzip-v1"
        or cache["bundled"] is not False
    ):
        fail(f"{field} differs from the unbundled input record")
    sha256_text(cache["sha256"], f"{field}.sha256")
    positive_integer(
        cache["bytes"],
        f"{field}.bytes",
        MAX_BINARY_BYTES,
    )
    return cache


def validate_evidence_id(value: object, base_commit: str) -> str:
    if not isinstance(value, str):
        fail("evidence_id must be one canonical string")
    matched = EVIDENCE_ID.fullmatch(value)
    if matched is None or matched.group(1) != base_commit[:8]:
        fail("evidence_id must bind the source commit prefix and UTC date")
    try:
        datetime.datetime.strptime(matched.group(2), "%Y%m%d")
    except ValueError as error:
        fail(f"evidence_id has an invalid UTC calendar date: {error}")
    return value


def physical_regular_path(
    raw: pathlib.Path,
    field: str,
    *,
    executable: bool = False,
) -> pathlib.Path:
    path = raw if raw.is_absolute() else pathlib.Path.cwd() / raw
    unresolved = path.absolute()
    try:
        metadata = unresolved.lstat()
        resolved = unresolved.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve {field}: {error}")
    if (
        unresolved != resolved
        or unresolved.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or (executable and metadata.st_mode & 0o111 == 0)
    ):
        fail(f"{field} must be one physical regular non-symlink file")
    return resolved


def physical_directory(raw: pathlib.Path, field: str) -> pathlib.Path:
    path = raw if raw.is_absolute() else pathlib.Path.cwd() / raw
    unresolved = path.absolute()
    try:
        metadata = unresolved.lstat()
        resolved = unresolved.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve {field}: {error}")
    if unresolved != resolved or unresolved.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        fail(f"{field} must be one physical directory with no symlink ancestors")
    return resolved


def safe_relative(value: object, field: str) -> pathlib.PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        fail(f"{field} must be one non-empty POSIX relative path")
    relative = pathlib.PurePosixPath(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        fail(f"{field} must remain inside the evidence root")
    return relative


def referenced_regular(root: pathlib.Path, value: object, field: str) -> pathlib.Path:
    relative = safe_relative(value, field)
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as error:
            fail(f"cannot inspect {field} ancestor: {error}")
        if current.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            fail(f"{field} has a non-directory or symlink ancestor")
    return physical_regular_path(root.joinpath(*relative.parts), field)


def pinned_hash_and_size(
    raw: pathlib.Path,
    field: str,
    maximum: int,
    *,
    executable: bool = False,
) -> tuple[str, int, bytes]:
    path = physical_regular_path(raw, field, executable=executable)
    before = path.lstat()
    size = positive_integer(before.st_size, f"{field} bytes", maximum)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
            or opened.st_mtime_ns != before.st_mtime_ns
            or opened.st_ctime_ns != before.st_ctime_ns
            or opened.st_mode != before.st_mode
            or (executable and opened.st_mode & 0o111 == 0)
        ):
            fail(f"{field} changed identity while opening")
        digest = hashlib.sha256()
        prefix = bytearray()
        remaining = size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"{field} truncated during pinned read")
            digest.update(chunk)
            if len(prefix) < 64:
                prefix.extend(chunk[: 64 - len(prefix)])
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail(f"{field} grew during pinned read")
        after = os.fstat(descriptor)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
            or after.st_mode != opened.st_mode
        ):
            fail(f"{field} changed during pinned read")
    finally:
        os.close(descriptor)
    return digest.hexdigest(), size, bytes(prefix)


def pinned_bytes(raw: pathlib.Path, field: str, maximum: int) -> bytes:
    path = physical_regular_path(raw, field)
    before = path.lstat()
    size = positive_integer(before.st_size, f"{field} bytes", maximum)
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
            or opened.st_mtime_ns != before.st_mtime_ns
            or opened.st_ctime_ns != before.st_ctime_ns
            or opened.st_mode != before.st_mode
        ):
            fail(f"{field} changed identity while opening")
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"{field} truncated during pinned read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail(f"{field} grew during pinned read")
        after = os.fstat(descriptor)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
            or after.st_mode != opened.st_mode
        ):
            fail(f"{field} changed during pinned read")
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def parse_json(raw: bytes, field: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot decode {field}: {error}")
    if not isinstance(value, dict):
        fail(f"{field} must be one JSON object")
    return value


def canonical_manifest(path: pathlib.Path) -> dict[str, Any]:
    raw = pinned_bytes(path, "manifest.json", MAX_JSON_BYTES)
    value = parse_json(raw, "manifest.json")
    canonical = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if raw != canonical:
        fail("manifest.json must use canonical sorted, indented JSON")
    return value


def canonical_builder_report(path: pathlib.Path, field: str) -> tuple[dict[str, Any], str, int]:
    raw = pinned_bytes(path, field, MAX_JSON_BYTES)
    value = parse_json(raw, field)
    canonical = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
    if raw != canonical:
        fail(f"{field} is not exact canonical builder stdout JSON")
    return value, hashlib.sha256(raw).hexdigest(), len(raw)


def report_output_path(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
        or "\n" in value
        or "\r" in value
    ):
        fail(f"{field} must be one absolute POSIX output path")
    path = pathlib.PurePosixPath(value)
    if (
        not path.is_absolute()
        or path.anchor != "/"
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        fail(f"{field} must be one normalized absolute POSIX output path")
    return value


def validate_report(
    report: object,
    candidate: dict[str, Any],
    field: str,
) -> dict[str, Any]:
    value = exact_keys(report, REPORT_KEYS, field)
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 3
        or value["source_candidate_sha256"] != candidate["source_candidate_sha256"]
        or value["source_candidate_profile"] != candidate["source_profile"]
        or value["source_base_commit"] != candidate["base_commit"]
        or value["source_git_object_format"] != candidate["git_object_format"]
        or value["source_git_tree_oid"] != candidate["git_tree_oid"]
        or value["source_git_status_sha256"] != candidate["git_status_sha256"]
        or value["cargo_lock_path"] != candidate["cargo_lock_path"]
        or value["cargo_lock_sha256"] != candidate["cargo_lock_sha256"]
        or type(value["cargo_lock_bytes"]) is not int
        or value["cargo_lock_bytes"] != candidate["cargo_lock_bytes"]
        or not isinstance(value["host_triple"], str)
        or LINUX_X86_64_HOST.fullmatch(value["host_triple"]) is None
        or value["reproducible_build"] is not True
        or type(value["independent_build_count"]) is not int
        or value["independent_build_count"] != 2
        or value["production_activation"] is not False
        or value["geo_wan_evidence"] is not False
    ):
        fail(f"{field} differs from the exact schema-3 Linux build contract")
    for role in ("validator", "material_builder"):
        sha256_text(value[f"{role}_binary_sha256"], f"{field}.{role}_binary_sha256")
        positive_integer(
            value[f"{role}_binary_bytes"],
            f"{field}.{role}_binary_bytes",
            MAX_BINARY_BYTES,
        )
    sha256_text(value["rustc_vv_sha256"], f"{field}.rustc_vv_sha256")
    validator_output = report_output_path(
        value["output_validator_binary"], f"{field}.output_validator_binary"
    )
    material_output = report_output_path(
        value["output_material_builder_binary"],
        f"{field}.output_material_builder_binary",
    )
    if validator_output == material_output:
        fail(f"{field} output roles must use distinct paths")
    if value["validator_binary_sha256"] == value["material_builder_binary_sha256"]:
        fail(f"{field} output roles must have distinct binary hashes")
    return value


def verify_tools(value: object) -> bytes:
    if value != EXPECTED_TOOLS:
        fail("operator_recorded_tools must name the exact builder and source checker")
    source_checker_bytes: bytes | None = None
    for index, tool in enumerate(EXPECTED_TOOLS):
        relative = safe_relative(tool["path"], f"tools[{index}].path")
        path = referenced_regular(
            REPOSITORY_ROOT,
            str(relative),
            f"tools[{index}]",
        )
        payload = pinned_bytes(path, f"tools[{index}]", MAX_JSON_BYTES)
        digest = hashlib.sha256(payload).hexdigest()
        size = len(payload)
        if digest != tool["sha256"] or size != tool["bytes"]:
            fail(f"tools[{index}] bytes differ from the profile-bound tool")
        if tool["role"] == "source_candidate_checker":
            source_checker_bytes = payload
    if source_checker_bytes is None:
        fail("operator_recorded_tools omitted the pinned source checker bytes")
    return source_checker_bytes


def load_pinned_source_candidate_validator(source: bytes):
    filename = str(REPOSITORY_ROOT / EXPECTED_TOOLS[1]["path"])
    namespace: dict[str, Any] = {
        "__name__": "_trnm_pinned_check_source_candidate",
        "__file__": filename,
        "__package__": None,
    }
    try:
        code = compile(source, filename, "exec", dont_inherit=True)
        exec(code, namespace)
    except Exception as error:
        fail(f"cannot execute the exact pinned source checker bytes: {error}")
    validator = namespace.get("validate")
    if not callable(validator):
        fail("exact pinned source checker bytes omitted validate()")
    return validator


def verify_external_binary(
    path: pathlib.Path,
    field: str,
    expected: dict[str, Any],
) -> None:
    digest, size, header = pinned_hash_and_size(
        path,
        field,
        MAX_BINARY_BYTES,
        executable=True,
    )
    if digest != expected["sha256"] or size != expected["bytes"]:
        fail(f"{field} differs from the exact report-bound binary")
    if (
        len(header) < 64
        or header[:4] != b"\x7fELF"
        or header[4] != 2
        or header[5] != 1
        or header[6] != 1
        or int.from_bytes(header[16:18], "little") not in {2, 3}
        or int.from_bytes(header[18:20], "little") != 62
        or int.from_bytes(header[20:24], "little") != 1
    ):
        fail(f"{field} lacks the expected ELF64 little-endian x86_64 header")


def validate(
    evidence_root: pathlib.Path,
    *,
    source_candidate: pathlib.Path | None = None,
    validator_binary: pathlib.Path | None = None,
    material_builder: pathlib.Path | None = None,
    emit: bool = True,
) -> dict[str, Any]:
    deep_values = (source_candidate, validator_binary, material_builder)
    deep = all(value is not None for value in deep_values)
    if any(value is not None for value in deep_values) and not deep:
        fail("deep mode requires source candidate, validator binary, and material builder together")

    root = physical_directory(evidence_root, "evidence root")
    manifest_path = referenced_regular(root, "manifest.json", "manifest.json")
    manifest = exact_keys(canonical_manifest(manifest_path), MANIFEST_KEYS, "manifest")
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or manifest["evidence_profile"] != PROFILE
    ):
        fail("manifest identity differs")
    candidate = validate_source_candidate_record(manifest["source_candidate"])
    evidence_id = validate_evidence_id(manifest["evidence_id"], candidate["base_commit"])
    validate_cache_record(manifest["operator_recorded_offline_dependency_cache"])
    source_checker_bytes = verify_tools(manifest["operator_recorded_tools"])

    exact_typed_mapping(manifest["claims"], CLAIM_VALUES, "claims")

    runner = exact_keys(manifest["runner_record"], RUNNER_KEYS, "runner_record")
    if (
        runner["runner_label"] != "x230-self-hosted"
        or runner["transport"] != "manual-ssh"
        or runner["paid_ci_used"] is not False
        or runner["cryptographic_host_attestation"] is not False
        or runner["tool_and_cache_use_cryptographically_attested"] is not False
        or type(runner["builder_invocation_count"]) is not int
        or runner["builder_invocation_count"] != 2
        or type(runner["independent_cargo_build_count"]) is not int
        or runner["independent_cargo_build_count"] != 4
        or not isinstance(runner["host_triple"], str)
        or LINUX_X86_64_HOST.fullmatch(runner["host_triple"]) is None
    ):
        fail("runner_record differs from the unsigned bounded X230 operator record")
    sha256_text(runner["rustc_vv_sha256"], "runner_record.rustc_vv_sha256")

    refs = manifest["build_reports"]
    if not isinstance(refs, list) or len(refs) != 2:
        fail("build_reports must contain exactly build-a and build-b")
    reports: list[dict[str, Any]] = []
    report_hashes: list[str] = []
    report_paths: list[str] = []
    for index, subject in enumerate(("build-a", "build-b")):
        ref = exact_keys(refs[index], REPORT_REF_KEYS, f"build_reports[{index}]")
        if ref["subject"] != subject or ref["path"] != f"{subject}.json":
            fail(f"build_reports[{index}] must bind {subject}.json")
        expected_hash = sha256_text(ref["sha256"], f"build_reports[{index}].sha256")
        expected_bytes = positive_integer(
            ref["bytes"], f"build_reports[{index}].bytes", MAX_JSON_BYTES
        )
        path = referenced_regular(root, ref["path"], f"build_reports[{index}].path")
        report, observed_hash, observed_bytes = canonical_builder_report(
            path, f"build report {subject}"
        )
        if observed_hash != expected_hash or observed_bytes != expected_bytes:
            fail(f"build report {subject} content address mismatch")
        reports.append(validate_report(report, candidate, f"build report {subject}"))
        report_hashes.append(observed_hash)
        report_paths.append(str(path))
    if len(set(report_paths)) != 2 or len(set(report_hashes)) != 2:
        fail("build-a and build-b must be distinct content-addressed reports")

    first, second = reports
    shared_fields = (
        "host_triple",
        "rustc_vv_sha256",
        "validator_binary_sha256",
        "validator_binary_bytes",
        "material_builder_binary_sha256",
        "material_builder_binary_bytes",
    )
    for field in shared_fields:
        if first[field] != second[field]:
            fail(f"build-a and build-b disagree on {field}")
    output_paths = {
        first["output_validator_binary"],
        first["output_material_builder_binary"],
        second["output_validator_binary"],
        second["output_material_builder_binary"],
    }
    if len(output_paths) != 4:
        fail("builder invocations must use four distinct role output paths")
    if (
        runner["host_triple"] != first["host_triple"]
        or runner["rustc_vv_sha256"] != first["rustc_vv_sha256"]
    ):
        fail("runner_record differs from the two raw reports")

    outputs = manifest["binary_outputs"]
    if not isinstance(outputs, list) or len(outputs) != 2:
        fail("binary_outputs must contain exactly the two common role binaries")
    expected_outputs: dict[str, dict[str, Any]] = {}
    for index, role in enumerate(("validator", "material_builder")):
        output = exact_keys(outputs[index], BINARY_OUTPUT_KEYS, f"binary_outputs[{index}]")
        if output["role"] != role or output["bundled"] is not False:
            fail(f"binary_outputs[{index}] must be the unbundled {role} role")
        digest = sha256_text(output["sha256"], f"binary_outputs[{index}].sha256")
        size = positive_integer(
            output["bytes"], f"binary_outputs[{index}].bytes", MAX_BINARY_BYTES
        )
        if (
            digest != first[f"{role}_binary_sha256"]
            or size != first[f"{role}_binary_bytes"]
        ):
            fail(f"binary_outputs[{index}] differs from both raw reports")
        expected_outputs[role] = output
    if outputs[0]["sha256"] == outputs[1]["sha256"]:
        fail("validator and material-builder output hashes must differ")

    if deep:
        assert source_candidate is not None
        assert validator_binary is not None
        assert material_builder is not None
        physical_regular_path(source_candidate, "source candidate")
        source_candidate_validate = load_pinned_source_candidate_validator(
            source_checker_bytes
        )
        try:
            candidate_report = source_candidate_validate(source_candidate, require_clean=True)
        except (SystemExit, OSError, tarfile.TarError, ValueError) as error:
            fail(f"source candidate failed strict deep verification: {error}")
        if candidate_report != candidate:
            fail("deep source-candidate result differs from the manifest")
        verify_external_binary(
            validator_binary,
            "validator binary",
            expected_outputs["validator"],
        )
        verify_external_binary(
            material_builder,
            "material-builder binary",
            expected_outputs["material_builder"],
        )

    result: dict[str, Any] = {
        "binary_bytes_rehashed": deep,
        "build_execution_cryptographically_attested": False,
        "builder_reports_claim_reproducible_build": True,
        "evidence_id": evidence_id,
        "evidence_profile": PROFILE,
        "operator_recorded_independent_cargo_build_count": 4,
        "native_cross_architecture_build_observed": False,
        "operator_records_native_linux_x86_64_build_execution": True,
        "production_activation": False,
        "report_set_consistent": True,
        "runner_identity_cryptographically_attested": False,
        "report_bound_elf64_le_x86_64_header_rehashed": deep,
        "source_candidate_bytes_rehashed": deep,
        "tool_and_cache_use_cryptographically_attested": False,
        "validator_run_7_completed": False,
    }
    if emit:
        print(json.dumps(result, sort_keys=True))
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_root", type=pathlib.Path)
    parser.add_argument("--source-candidate", type=pathlib.Path)
    parser.add_argument("--validator-binary", type=pathlib.Path)
    parser.add_argument("--material-builder", type=pathlib.Path)
    args = parser.parse_args()
    validate(
        args.evidence_root,
        source_candidate=args.source_candidate,
        validator_binary=args.validator_binary,
        material_builder=args.material_builder,
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        fail(str(error))
