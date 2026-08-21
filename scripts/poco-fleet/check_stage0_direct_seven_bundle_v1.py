#!/usr/bin/env python3
"""Deep-check one scoped Stage0 direct-seven observation bundle.

This profile does not reinterpret the legacy runner completion bits.  The
runner deliberately seals ``validator_run_completed=false``.  A much narrower
``stage0_direct_seven_observed`` fact is derived independently from the exact
seven-validator signed-runtime chains, the macOS verification results, the
terminal agreement, and the complete replay-archive sets.

The bundle contains public coordinator material only.  The coordinator
manifest's secret references are checked, but private validator keys are both
unnecessary for verification and forbidden from the evidence bundle.
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
import sys
import tarfile
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, NoReturn


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import check_baseline  # noqa: E402
import check_run_readiness_evidence  # noqa: E402
import check_signed_runtime_evidence as signed_evidence  # noqa: E402
import check_source_candidate  # noqa: E402
import collect_no_fault_run_bundle_v1 as runner_bridge  # noqa: E402
import evidence_bundle_profiles_v1 as evidence_profiles  # noqa: E402
import run_consensus_fleet as consensus_runner  # noqa: E402


PROFILE = "poco-g3-stage0-direct-seven-observation-bundle-v1"
SCHEMA_VERSION = 1
VALIDATOR_COUNT = 7
MAXIMUM_PREFLIGHT_AGE_SECONDS = 3_600
MAXIMUM_FILE_COUNT = 1_000
MAXIMUM_BUNDLE_BYTES = 4 * 1024 * 1024 * 1024
MAXIMUM_FILE_BYTES = 1024 * 1024 * 1024
MAXIMUM_JSON_BYTES = 16 * 1024 * 1024
MAXIMUM_JSONL_BYTES = 256 * 1024 * 1024
MAXIMUM_REPLAY_CONTEXT_BYTES = 64 * 1024
MAXIMUM_REPLAY_HEAD_BYTES = 16 * 1024
MAXIMUM_REPLAY_TERMINAL_SEAL_BYTES = 256 * 1024
MAXIMUM_REPLAY_ENTRIES = 8_192
MAXIMUM_REPLAY_PAYLOAD_BYTES = 6 * 1024 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
VALIDATOR_CONFIG = re.compile(r"^public/configs/([0-9a-f]{64})\.json$")
OBSERVER_CONFIG = re.compile(r"^public/observer-configs/(mac)\.json$")
SECRET_PATH = re.compile(
    r"^secrets/(consensus|p2p-identity|operator-recovery)/([0-9a-f]{64})\.pk8$"
)

MANIFEST_KEYS = {
    "schema_version",
    "evidence_profile",
    "run_id",
    "validator_count",
    "network_scope",
    "candidate",
    "preflight",
    "coordinator_manifest_sha256",
    "runner_ordered_artifact_root",
    "artifacts",
    "ordered_artifact_root",
    "derived_observation",
    "stage0_status_projection",
    "claims",
}
ARTIFACT_KEYS = {"role", "subject", "path", "sha256", "bytes"}
CANDIDATE_KEYS = {
    "source_candidate_sha256",
    "source_candidate_profile",
    "source_base_commit",
    "source_git_object_format",
    "source_git_tree_oid",
    "source_git_status_sha256",
    "cargo_lock_path",
    "cargo_lock_sha256",
    "cargo_lock_bytes",
    "aggregate_build_report_sha256",
    "linux_validator_sha256",
    "linux_material_builder_sha256",
    "macos_validator_sha256",
    "macos_material_builder_sha256",
}
PREFLIGHT_KEYS = {
    "inventory_sha256",
    "probe_fleet_sha256",
    "readiness_sha256",
    "probe_observed_at_epoch_ns",
    "readiness_completed_at_epoch",
    "run_started_at",
    "maximum_preflight_age_seconds",
}
DERIVED_KEYS = {
    "validator_ids",
    "validator_host_ids",
    "signed_process_count",
    "signed_artifact_chain_count",
    "observer_verified_process_count",
    "observer_verified_replay_archive_count",
    "fleet_barrier_round",
    "fleet_ready_set_sha256",
    "fleet_start_certificate_sha256",
    "terminal_agreement",
    "runner_legacy_validator_run_completed",
    "stage0_direct_seven_observed",
}
TERMINAL_KEYS = {
    "finalized_height",
    "finalized_ordinary_block_count",
    "finalized_block_id",
    "finalized_state_root",
    "finalized_chain_root",
    "fleet_start_certificate_sha256",
}
CLAIMS = {
    "stage0_direct_seven_observed": True,
    "validator_run_7_completed_observed": True,
    "fault_matrix_completed": False,
    "performance_evidence": False,
    "g3_lan_multihost_evidence": False,
    "geo_wan_evidence": False,
    "production_activation": False,
    "production_candidate": False,
}
STAGE0_STATUS_PROJECTION = {
    "current_fleet_probe_observed": True,
    "current_run_readiness_observed": True,
    "stage0_deep_reverification_bundle_available": True,
    "validator_run_7_completed": True,
}
FIXED_PATH_IDENTITIES = {
    "candidate/source.tar": ("source_candidate", ""),
    "candidate/Cargo.lock": ("cargo_lock", ""),
    "candidate/aggregate-build-report.json": ("aggregate_build_report", ""),
    "candidate/linux-x86_64/trnm-poco-lab-validator": (
        "linux_validator_binary",
        "",
    ),
    "candidate/linux-x86_64/trnm-poco-lab-material-builder": (
        "linux_material_builder_binary",
        "",
    ),
    "candidate/macos-arm64/trnm-poco-lab-validator": (
        "macos_validator_binary",
        "",
    ),
    "candidate/macos-arm64/trnm-poco-lab-material-builder": (
        "macos_material_builder_binary",
        "",
    ),
    "preflight/inventory.toml": ("fleet_inventory", ""),
    "preflight/probe-fleet-v1.json": ("probe_fleet_v1", ""),
    "preflight/run-readiness-v2.json": ("run_readiness_v2", ""),
    "coordinator/manifest.json": ("coordinator_manifest", ""),
    "runner/runner-output-manifest.json": ("runner_output_manifest", ""),
}
AGGREGATE_KEYS = {
    "schema_version",
    "source_tree_sha256",
    "source_candidate_profile",
    "source_base_commit",
    "source_git_object_format",
    "source_git_tree_oid",
    "source_git_status_sha256",
    "cargo_lock_path",
    "cargo_lock_sha256",
    "cargo_lock_bytes",
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
}
REPLAY_CONTEXT_KEYS = (
    "schema_version",
    "run_id",
    "chain_id",
    "genesis_hash",
    "validator_set_id",
    "local_validator_id",
    "local_consensus_public_key",
    "coordinator_manifest_sha256",
    "validator_set_sha256",
    "topology_sha256",
    "config_sha256",
    "candidate_source_sha256",
    "binary_sha256",
    "workload_corpus_sha256",
    "workload_policy_sha256",
    "ordinary_start_height",
    "maximum_timeout_view_advances",
    "maximum_proposal_entries",
    "maximum_quorum_certificate_entries",
    "maximum_archive_entries",
    "context_sha256",
)
REPLAY_ENTRY_KEYS = (
    "schema_version",
    "sequence",
    "context_sha256",
    "previous_record_sha256",
    "kind",
    "height",
    "view",
    "block_id",
    "content_sha256",
    "payload_hex",
    "record_sha256",
)
REPLAY_HEAD_KEYS = (
    "schema_version",
    "sequence",
    "context_sha256",
    "record_sha256",
)
REPLAY_TERMINAL_SEAL_KEYS = (
    "schema_version",
    "run_id",
    "validator_id",
    "validator_set_id",
    "validator_set_sha256",
    "topology_sha256",
    "coordinator_manifest_sha256",
    "candidate_source_sha256",
    "binary_sha256",
    "config_sha256",
    "fleet_start_certificate_sha256",
    "process_instance",
    "clean_stop_journal_sequence",
    "clean_stop_journal_sha256",
    "finalized_height",
    "finalized_block_id",
    "finalized_state_root",
    "finalized_chain_root",
    "finality_proof_id",
    "finality_child_block_id",
    "finality_grandchild_block_id",
    "archive_context_sha256",
    "archive_context_file_sha256",
    "archive_context_file_bytes",
    "archive_entries_file_sha256",
    "archive_entries_file_bytes",
    "archive_head_file_sha256",
    "archive_head_file_bytes",
    "terminal_archive_sequence",
    "terminal_archive_record_sha256",
    "proposal_count",
    "quorum_certificate_count",
    "body_sha256",
    "signature",
)
REPLAY_CONTEXT_DOMAIN = b"trnm.poco-g3.signed-replay-archive.context.v1"
REPLAY_GENESIS_DOMAIN = b"trnm.poco-g3.signed-replay-archive.genesis.v1"
REPLAY_CONTENT_DOMAIN = b"trnm.poco-g3.signed-replay-archive.content.v1"
REPLAY_RECORD_DOMAIN = b"trnm.poco-g3.signed-replay-archive.record.v1"
REPLAY_TERMINAL_BODY_DOMAIN = b"trnm.poco-g3.replay-archive-terminal-seal.body.v1"
REPLAY_TERMINAL_SIGNATURE_DOMAIN = (
    b"trnm.poco-g3.replay-archive-terminal-seal.signature.v1"
)


@dataclass(frozen=True)
class FileFact:
    path: pathlib.Path
    sha256: str
    bytes: int
    device: int
    inode: int
    mode: int
    links: int
    modified_ns: int
    changed_ns: int


def fail(message: str) -> NoReturn:
    raise SystemExit(f"PoCO G3 Stage0 direct-seven bundle invalid: {message}")


def exact(value: object, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{field} keys must be exactly {sorted(keys)!r}")
    return value


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON object name {key!r}")
        result[key] = value
    return result


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def compact_ordered_json(value: dict[str, Any], keys: tuple[str, ...]) -> bytes:
    return json.dumps(
        {key: value[key] for key in keys},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def hash_parts(domain: bytes, parts: tuple[bytes, ...]) -> bytes:
    digest = hashlib.sha256()
    digest.update(b"trnm.domain.hash.v1")
    digest.update(len(domain).to_bytes(8, "big"))
    digest.update(domain)
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def exact_hex(value: object, length: int, field: str, *, nonzero: bool = False) -> bytes:
    pattern = HEX64 if length == 32 else HEX128 if length == 64 else None
    if not isinstance(value, str) or pattern is None or pattern.fullmatch(value) is None:
        fail(f"{field} must be canonical lowercase {length}-byte hex")
    decoded = bytes.fromhex(value)
    if nonzero and decoded == bytes(length):
        fail(f"{field} must be nonzero")
    return decoded


def exact_u64(value: object, field: str, *, positive: bool = False) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < (1 if positive else 0)
        or value > (1 << 64) - 1
    ):
        fail(f"{field} must be one bounded {'positive ' if positive else ''}u64")
    return value


def strict_json_bytes(raw: bytes, field: str) -> dict[str, Any]:
    """Accept one JSON object with no prefix and at most its producer LF."""

    if raw.endswith(b"\n"):
        payload = raw[:-1]
    else:
        payload = raw
    if not payload or payload[:1] != b"{" or payload[-1:] != b"}":
        fail(f"{field} is not one exact JSON object without trailing bytes")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda token: fail(
                f"{field} contains non-finite JSON number {token!r}"
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(f"{field} is not exact UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{field} must be one JSON object")
    return value


def strict_rust_json(
    path: pathlib.Path,
    field: str,
    keys: tuple[str, ...],
    *,
    maximum: int,
) -> tuple[dict[str, Any], FileFact]:
    raw, fact = read_pinned(
        path,
        field,
        allow_empty=False,
        maximum=maximum,
        capture=True,
    )
    value = exact(strict_json_bytes(raw, field), set(keys), field)
    if raw != compact_ordered_json(value, keys) + b"\n":
        fail(f"{field} is not canonical Rust JSON")
    return value, fact


def strict_json(path: pathlib.Path, field: str) -> dict[str, Any]:
    return strict_json_bytes(
        read_pinned(
            path,
            field,
            allow_empty=False,
            maximum=MAXIMUM_JSON_BYTES,
            capture=True,
        )[0],
        field,
    )


def safe_relative(value: object, field: str) -> pathlib.PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        fail(f"{field} must be one non-empty POSIX relative path")
    relative = pathlib.PurePosixPath(value)
    if (
        relative.is_absolute()
        or relative.as_posix() != value
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        fail(f"{field} escapes its bundle root")
    return relative


def read_pinned(
    path: pathlib.Path,
    field: str,
    *,
    allow_empty: bool,
    maximum: int = MAXIMUM_FILE_BYTES,
    capture: bool = False,
) -> tuple[bytes, FileFact]:
    path = path.absolute()
    try:
        before = path.lstat()
    except OSError as error:
        fail(f"cannot inspect {field}: {error}")
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > maximum
        or (not allow_empty and before.st_size <= 0)
    ):
        fail(f"{field} must be one bounded regular non-symlink, non-hardlinked file")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    try:
        opened = os.fstat(descriptor)
        identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        expected = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if identity != expected:
            fail(f"{field} changed identity while opening")
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"{field} truncated during its pinned read")
            if capture:
                chunks.append(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail(f"{field} grew during its pinned read")
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != identity:
            fail(f"{field} changed during its pinned read")
    finally:
        os.close(descriptor)
    fact = FileFact(
        path=path,
        sha256=digest.hexdigest(),
        bytes=before.st_size,
        device=before.st_dev,
        inode=before.st_ino,
        mode=before.st_mode,
        links=before.st_nlink,
        modified_ns=before.st_mtime_ns,
        changed_ns=before.st_ctime_ns,
    )
    return b"".join(chunks), fact


def visit_jsonl_pinned(
    path: pathlib.Path,
    field: str,
    *,
    maximum: int,
    maximum_line: int,
    visitor: Callable[[bytes, int], None],
) -> tuple[FileFact, int]:
    """Stream one pinned JSONL file with bounded per-record memory."""

    path = path.absolute()
    try:
        before = path.lstat()
    except OSError as error:
        fail(f"cannot inspect {field}: {error}")
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum
        or maximum_line <= 0
    ):
        fail(f"{field} must be one bounded regular non-symlink JSONL file")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    digest = hashlib.sha256()
    pending = bytearray()
    line_count = 0
    total = 0
    try:
        opened = os.fstat(descriptor)
        identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        expected = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if identity != expected:
            fail(f"{field} changed identity while opening")
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"{field} truncated during its pinned stream")
            digest.update(chunk)
            pending.extend(chunk)
            remaining -= len(chunk)
            total += len(chunk)
            while True:
                newline = pending.find(b"\n")
                if newline < 0:
                    break
                if newline + 1 > maximum_line:
                    fail(f"{field} contains an oversized JSONL record")
                line = bytes(pending[: newline + 1])
                del pending[: newline + 1]
                visitor(line, line_count)
                line_count += 1
            if len(pending) > maximum_line:
                fail(f"{field} contains an oversized or unterminated JSONL record")
        if os.read(descriptor, 1):
            fail(f"{field} grew during its pinned stream")
        if pending:
            fail(f"{field} ends in an unterminated JSONL record")
        if line_count == 0:
            fail(f"{field} contains no JSONL records")
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != identity:
            fail(f"{field} changed during its pinned stream")
    finally:
        os.close(descriptor)
    return (
        FileFact(
            path=path,
            sha256=digest.hexdigest(),
            bytes=total,
            device=before.st_dev,
            inode=before.st_ino,
            mode=before.st_mode,
            links=before.st_nlink,
            modified_ns=before.st_mtime_ns,
            changed_ns=before.st_ctime_ns,
        ),
        line_count,
    )


def real_root(path: pathlib.Path, field: str) -> pathlib.Path:
    path = path.absolute()
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve {field}: {error}")
    if (
        resolved != path
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        fail(f"{field} must be one real non-symlink directory")
    return path


def tree_files(root: pathlib.Path) -> dict[str, pathlib.Path]:
    root = real_root(root, "bundle root")
    files: dict[str, pathlib.Path] = {}
    total = 0
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            fail(f"bundle contains symbolic link {relative!r}")
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                fail(f"bundle contains hardlinked file {relative!r}")
            files[relative] = path
            total += metadata.st_size
        elif not stat.S_ISDIR(metadata.st_mode):
            fail(f"bundle contains non-file entry {relative!r}")
        if len(files) > MAXIMUM_FILE_COUNT or total > MAXIMUM_BUNDLE_BYTES:
            fail("bundle crosses its file-count or byte bound")
    return files


def verify_ref(
    root: pathlib.Path,
    value: object,
    field: str,
    *,
    allow_empty: bool,
) -> tuple[pathlib.Path, FileFact]:
    reference = exact(value, ARTIFACT_KEYS, field)
    relative = safe_relative(reference["path"], f"{field}.path")
    path = root.joinpath(*relative.parts)
    expected_hash = reference["sha256"]
    expected_bytes = reference["bytes"]
    if not isinstance(expected_hash, str) or HEX64.fullmatch(expected_hash) is None:
        fail(f"{field}.sha256 must be canonical lowercase SHA-256")
    if (
        isinstance(expected_bytes, bool)
        or not isinstance(expected_bytes, int)
        or expected_bytes < (0 if allow_empty else 1)
    ):
        fail(f"{field}.bytes crosses its exact bound")
    _payload, fact = read_pinned(path, field, allow_empty=allow_empty)
    if (fact.sha256, fact.bytes) != (expected_hash, expected_bytes):
        fail(f"{field} content address differs from exact bytes")
    return path, fact


def ordered_artifact_root(artifacts: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    digest.update(b"TRNM/PoCO/G3/Stage0DirectSevenBundle/v1\0")
    for artifact in artifacts:
        for field in ("role", "subject", "path"):
            encoded = artifact[field].encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
        digest.update(bytes.fromhex(artifact["sha256"]))
        digest.update(artifact["bytes"].to_bytes(8, "big"))
    return digest.hexdigest()


def sha256(path: pathlib.Path, field: str, *, allow_empty: bool = False) -> str:
    return read_pinned(path, field, allow_empty=allow_empty)[1].sha256


def cargo_lock_bytes(candidate: pathlib.Path) -> bytes:
    try:
        with tarfile.open(candidate, "r:") as archive:
            member = archive.getmember("source/trillionnium/Cargo.lock")
            if not member.isfile() or member.size <= 0 or member.size > MAXIMUM_JSON_BYTES:
                fail("source candidate Cargo.lock crosses its extraction bound")
            stream = archive.extractfile(member)
            if stream is None:
                fail("source candidate Cargo.lock has no regular byte stream")
            payload = stream.read(MAXIMUM_JSON_BYTES + 1)
    except (OSError, KeyError, tarfile.TarError) as error:
        fail(f"cannot reopen source candidate Cargo.lock: {error}")
    if len(payload) != member.size:
        fail("source candidate Cargo.lock length differs from its bounded member")
    return payload


def validate_aggregate(
    path: pathlib.Path,
    *,
    candidate_report: dict[str, Any],
    candidate_path: pathlib.Path,
    cargo_lock_path: pathlib.Path,
    linux_validator: pathlib.Path,
    linux_builder: pathlib.Path,
    macos_validator: pathlib.Path,
    macos_builder: pathlib.Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    aggregate = exact(strict_json(path, "aggregate build report"), AGGREGATE_KEYS, "aggregate build report")
    binaries = {
        "linux_validator_sha256": sha256(linux_validator, "Linux validator binary"),
        "linux_material_builder_sha256": sha256(linux_builder, "Linux material-builder binary"),
        "macos_validator_sha256": sha256(macos_validator, "macOS validator binary"),
        "macos_material_builder_sha256": sha256(macos_builder, "macOS material-builder binary"),
    }
    if len(set(binaries.values())) != 4:
        fail("the four architecture/role binaries must have distinct exact bytes")
    for binary_path, field in (
        (linux_validator, "Linux validator binary"),
        (linux_builder, "Linux material-builder binary"),
        (macos_validator, "macOS validator binary"),
        (macos_builder, "macOS material-builder binary"),
    ):
        if stat.S_IMODE(binary_path.stat().st_mode) & 0o111 == 0:
            fail(f"{field} is not executable")
    provenance = {
        "source_tree_sha256": candidate_report["source_candidate_sha256"],
        "source_candidate_profile": candidate_report["source_profile"],
        "source_base_commit": candidate_report["base_commit"],
        "source_git_object_format": candidate_report["git_object_format"],
        "source_git_tree_oid": candidate_report["git_tree_oid"],
        "source_git_status_sha256": candidate_report["git_status_sha256"],
        "cargo_lock_path": candidate_report["cargo_lock_path"],
        "cargo_lock_sha256": candidate_report["cargo_lock_sha256"],
        "cargo_lock_bytes": candidate_report["cargo_lock_bytes"],
    }
    expected = {
        **aggregate,
        "schema_version": 3,
        **provenance,
        "linux_first_sha256": binaries["linux_validator_sha256"],
        "linux_second_sha256": binaries["linux_validator_sha256"],
        "linux_material_builder_first_sha256": binaries[
            "linux_material_builder_sha256"
        ],
        "linux_material_builder_second_sha256": binaries[
            "linux_material_builder_sha256"
        ],
        "macos_first_sha256": binaries["macos_validator_sha256"],
        "macos_second_sha256": binaries["macos_validator_sha256"],
        "macos_material_builder_first_sha256": binaries[
            "macos_material_builder_sha256"
        ],
        "macos_material_builder_second_sha256": binaries[
            "macos_material_builder_sha256"
        ],
        "independent_build_roots": True,
        "production_activation": False,
    }
    if aggregate != expected:
        fail("aggregate build report differs from candidate and all four binaries")
    exact_lock = cargo_lock_bytes(candidate_path)
    bundled_lock, bundled_fact = read_pinned(
        cargo_lock_path,
        "bundled Cargo.lock",
        allow_empty=False,
        maximum=16 * 1024 * 1024,
        capture=True,
    )
    if (
        bundled_lock != exact_lock
        or bundled_fact.sha256 != candidate_report["cargo_lock_sha256"]
        or bundled_fact.bytes != candidate_report["cargo_lock_bytes"]
    ):
        fail("bundled Cargo.lock differs from the clean-commit candidate member")
    return aggregate, binaries


def load_inventory(path: pathlib.Path) -> dict[str, Any]:
    payload, _fact = read_pinned(
        path,
        "fleet inventory",
        allow_empty=False,
        maximum=1024 * 1024,
        capture=True,
    )
    try:
        value = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        fail(f"fleet inventory is not exact UTF-8 TOML: {error}")
    if not isinstance(value, dict):
        fail("fleet inventory must be one TOML table")
    return value


def validate_preflight(
    inventory_path: pathlib.Path,
    probe_path: pathlib.Path,
    readiness_path: pathlib.Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    inventory = load_inventory(inventory_path)
    probe = strict_json(probe_path, "probe-fleet-v1")
    readiness = strict_json(readiness_path, "run-readiness-v2")
    try:
        check_baseline.validate(probe, inventory)
        check_run_readiness_evidence.validate(readiness, inventory)
    except SystemExit as error:
        fail(f"fresh fleet preflight failed independent validation: {error}")
    if probe["fleet_id"] != readiness["fleet_id"]:
        fail("probe-fleet-v1 and run-readiness-v2 fleet IDs differ")
    return inventory, probe, readiness


def coordinator_public_identities(manifest: dict[str, Any]) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    singleton_by_path = {
        value: key
        for key, value in evidence_profiles.COORDINATOR_PUBLIC_SINGLETON_PATHS.items()
    }
    public_files = manifest.get("public_files")
    if not isinstance(public_files, list):
        fail("coordinator manifest public_files must be a list")
    for index, raw in enumerate(public_files):
        reference = exact(
            raw,
            {"path", "sha256", "bytes"},
            f"coordinator public_files[{index}]",
        )
        relative = safe_relative(reference["path"], f"coordinator public_files[{index}].path").as_posix()
        if relative in result:
            fail("coordinator public file paths must be unique")
        if relative in singleton_by_path:
            identity = (singleton_by_path[relative], "")
        elif (matched := VALIDATOR_CONFIG.fullmatch(relative)) is not None:
            identity = ("validator_config", matched.group(1))
        elif (matched := OBSERVER_CONFIG.fullmatch(relative)) is not None:
            identity = ("observer_config", matched.group(1))
        else:
            fail(f"coordinator public path {relative!r} is outside the closed profile")
        result[f"coordinator/{relative}"] = identity
    return result


def validate_secret_references(
    coordinator: dict[str, Any], validator_ids: set[str]
) -> None:
    values = coordinator.get("secret_files")
    if not isinstance(values, list) or len(values) != VALIDATOR_COUNT * 3:
        fail("coordinator secret-reference inventory must contain three roles per validator")
    observed: set[tuple[str, str]] = set()
    for index, raw in enumerate(values):
        reference = exact(raw, {"path", "sha256", "bytes"}, f"secret_files[{index}]")
        path = safe_relative(reference["path"], f"secret_files[{index}].path").as_posix()
        match = SECRET_PATH.fullmatch(path)
        if match is None or match.group(2) not in validator_ids:
            fail("coordinator secret reference is outside the closed role/validator set")
        pair = (match.group(1), match.group(2))
        if pair in observed:
            fail("coordinator secret role/validator references must be unique")
        observed.add(pair)
        if (
            not isinstance(reference["sha256"], str)
            or HEX64.fullmatch(reference["sha256"]) is None
            or isinstance(reference["bytes"], bool)
            or not isinstance(reference["bytes"], int)
            or reference["bytes"] <= 0
        ):
            fail("coordinator secret reference content address is invalid")
    expected = {
        (role, validator_id)
        for role in ("consensus", "p2p-identity", "operator-recovery")
        for validator_id in validator_ids
    }
    if observed != expected:
        fail("coordinator secret role/validator references are incomplete")


def validate_topology_inventory_join(
    coordinator_root: pathlib.Path,
    coordinator: dict[str, Any],
    inventory: dict[str, Any],
    plan: dict[str, Any],
) -> list[str]:
    topology = strict_json(coordinator_root / "topology.json", "coordinator topology")
    raw_hosts = inventory.get("hosts")
    if not isinstance(raw_hosts, list) or len(raw_hosts) != 6:
        fail("fleet inventory must contain exactly six physical hosts")
    inventory_hosts = {
        item.get("id"): item for item in raw_hosts if isinstance(item, dict)
    }
    if len(inventory_hosts) != 6 or coordinator["fleet_id"] != inventory.get("fleet_id"):
        fail("coordinator and preflight inventory fleet identities differ")
    participants = topology.get("participants")
    if not isinstance(participants, list) or len(participants) != 6:
        fail("direct-seven topology must retain all six physical participants")
    participant_ids: set[str] = set()
    for participant in participants:
        host_id = participant.get("host_id") if isinstance(participant, dict) else None
        inventory_host = inventory_hosts.get(host_id)
        if (
            inventory_host is None
            or host_id in participant_ids
            or participant.get("lan_ip") != inventory_host.get("lan_ip")
        ):
            fail("topology participant differs from the preflight inventory")
        participant_ids.add(host_id)
    validators = topology.get("validators")
    if (
        topology.get("validator_count") != VALIDATOR_COUNT
        or topology.get("peer_degree") != 6
        or not isinstance(validators, list)
        or len(validators) != VALIDATOR_COUNT
    ):
        fail("Stage0 direct-seven requires a seven-validator full mesh")
    validator_ids = {
        item.get("validator_id") for item in validators if isinstance(item, dict)
    }
    if len(validator_ids) != VALIDATOR_COUNT:
        fail("direct-seven topology validator identities are incomplete")
    for item in validators:
        validator_id = item.get("validator_id")
        peers = item.get("peers")
        if (
            item.get("host_id") not in participant_ids - {"mac"}
            or not isinstance(peers, list)
            or len(peers) != 6
            or set(peers) != validator_ids - {validator_id}
        ):
            fail("direct-seven topology is not the canonical all-to-all mesh")
    planned_hosts: set[str] = set()
    for item in plan["validators"]:
        host = inventory_hosts.get(item["host_id"])
        if host is None or item["management"] != host.get("management"):
            fail("runner prestart placement differs from inventory management authority")
        planned_hosts.add(item["host_id"])
    if len(planned_hosts) != 5 or "mac" in planned_hosts:
        fail("direct-seven validators must span the five Linux validator hosts")
    return sorted(planned_hosts)


def expected_artifact_identities(root: pathlib.Path) -> dict[str, tuple[str, str]]:
    coordinator = strict_json(root / "coordinator/manifest.json", "coordinator manifest")
    runner_manifest = strict_json(
        root / "runner/runner-output-manifest.json", "runner output manifest"
    )
    expected = dict(FIXED_PATH_IDENTITIES)
    for path, identity in coordinator_public_identities(coordinator).items():
        if path in expected:
            fail("coordinator path collides with a fixed bundle path")
        expected[path] = identity
    artifacts = runner_manifest.get("artifacts")
    if not isinstance(artifacts, list):
        fail("runner output manifest artifacts must be a list")
    for index, item in enumerate(artifacts):
        artifact = exact(item, ARTIFACT_KEYS, f"runner artifacts[{index}]")
        relative = safe_relative(artifact["path"], f"runner artifacts[{index}].path").as_posix()
        path = f"runner/{relative}"
        if path in expected:
            fail("runner output path collides with a fixed bundle path")
        if not isinstance(artifact["role"], str) or not isinstance(artifact["subject"], str):
            fail("runner role/subject must be strings")
        expected[path] = (artifact["role"], artifact["subject"])
    return expected


def validate_all_json_artifacts(root: pathlib.Path, expected_paths: set[str]) -> None:
    for relative in sorted(expected_paths):
        path = root.joinpath(*pathlib.PurePosixPath(relative).parts)
        if path.suffix == ".json":
            strict_json(path, relative)
        elif path.suffix == ".jsonl":
            visit_jsonl_pinned(
                path,
                relative,
                maximum=MAXIMUM_JSONL_BYTES,
                maximum_line=MAXIMUM_JSON_BYTES,
                visitor=lambda line, index: strict_json_bytes(
                    line, f"{relative}[{index}]"
                ),
            )


def parse_utc(value: object, field: str) -> datetime.datetime:
    if not isinstance(value, str):
        fail(f"{field} must be RFC3339 UTC")
    try:
        parsed = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        fail(f"{field} must be second-precision RFC3339 UTC")
    return parsed.replace(tzinfo=datetime.timezone.utc)


def validate_raw_replay_archive(
    *,
    coordinator_root: pathlib.Path,
    signed_sources: dict[str, dict[str, pathlib.Path]],
    signed_validator: dict[str, Any],
    process: dict[str, Any],
    plan: dict[str, Any],
    validator_set: dict[str, Any],
    validator_id: str,
    coordinator_anchor: str,
    candidate_sha256: str,
) -> None:
    """Authenticate and hash-chain one exported replay archive from raw bytes.

    The legacy collector checks an unsigned observer summary.  This additional
    verifier treats that summary only as a projection: the validator-signed
    terminal seal must authenticate the exact context/entries/head files, and
    those raw files are parsed and hash-chained here before the projection can
    contribute to the scoped Stage0 claim.
    """

    context_path = signed_sources["validator_replay_archive_context"][validator_id]
    entries_path = signed_sources["validator_replay_archive_entries"][validator_id]
    head_path = signed_sources["validator_replay_archive_head"][validator_id]
    seal_path = signed_sources["validator_replay_archive_terminal_seal"][validator_id]
    config_path = coordinator_root / f"public/configs/{validator_id}.json"
    validator_set_path = coordinator_root / "public/validator-set.json"
    topology_path = coordinator_root / "topology.json"

    config = strict_json(config_path, f"validator config {validator_id}")
    context, context_fact = strict_rust_json(
        context_path,
        f"replay context {validator_id}",
        REPLAY_CONTEXT_KEYS,
        maximum=MAXIMUM_REPLAY_CONTEXT_BYTES,
    )
    validator_records = validator_set.get("validators")
    if not isinstance(validator_records, list):
        fail("validator set has no replay-verifier inventory")
    selected = [
        item
        for item in validator_records
        if isinstance(item, dict) and item.get("validator_id") == validator_id
    ]
    if len(selected) != 1:
        fail(f"replay validator {validator_id} is absent or duplicated")
    validator = selected[0]
    archive_lifetime = plan["signed_replay_archive_lifetime"]
    signer_lifetime = plan["signer_lifetime"]
    if type(context["schema_version"]) is not int or context["schema_version"] != 1:
        fail(f"replay context {validator_id} has the wrong exact schema version")
    context_numbers = (
        exact_u64(context["ordinary_start_height"], "replay ordinary_start_height", positive=True),
        exact_u64(
            context["maximum_timeout_view_advances"],
            "replay maximum_timeout_view_advances",
            positive=True,
        ),
        exact_u64(
            context["maximum_proposal_entries"],
            "replay maximum_proposal_entries",
            positive=True,
        ),
        exact_u64(
            context["maximum_quorum_certificate_entries"],
            "replay maximum_quorum_certificate_entries",
            positive=True,
        ),
        exact_u64(
            context["maximum_archive_entries"],
            "replay maximum_archive_entries",
            positive=True,
        ),
    )
    if (
        context_numbers[3] != context_numbers[2] + 1
        or context_numbers[4] != context_numbers[2] + context_numbers[3]
        or context_numbers[4] > MAXIMUM_REPLAY_ENTRIES
    ):
        fail(f"replay context {validator_id} has inconsistent capacity bounds")
    try:
        set_id = signed_evidence.validator_set_id(validator_set)
    except SystemExit as error:
        fail(f"cannot reconstruct replay validator-set ID: {error}")
    context_digest = hash_parts(
        REPLAY_CONTEXT_DOMAIN,
        (
            str(context["run_id"]).encode("utf-8"),
            str(context["chain_id"]).encode("utf-8"),
            exact_hex(context["genesis_hash"], 32, "replay context genesis"),
            exact_hex(context["validator_set_id"], 32, "replay context validator-set ID"),
            exact_hex(context["local_validator_id"], 32, "replay context validator ID"),
            exact_hex(
                context["local_consensus_public_key"],
                32,
                "replay context consensus public key",
            ),
            exact_hex(
                context["coordinator_manifest_sha256"],
                32,
                "replay context coordinator manifest",
            ),
            exact_hex(context["validator_set_sha256"], 32, "replay context validator set"),
            exact_hex(context["topology_sha256"], 32, "replay context topology"),
            exact_hex(context["config_sha256"], 32, "replay context config"),
            exact_hex(context["candidate_source_sha256"], 32, "replay context source"),
            exact_hex(context["binary_sha256"], 32, "replay context binary"),
            exact_hex(context["workload_corpus_sha256"], 32, "replay context workload"),
            exact_hex(context["workload_policy_sha256"], 32, "replay context policy"),
            *(number.to_bytes(8, "big") for number in context_numbers),
        ),
    )
    expected_context = {
        **context,
        "schema_version": 1,
        "run_id": config["run_id"],
        "chain_id": validator_set["chain_id"],
        "genesis_hash": validator_set["genesis_hash"],
        "validator_set_id": set_id,
        "local_validator_id": validator_id,
        "local_consensus_public_key": validator["consensus_public_key"],
        "coordinator_manifest_sha256": coordinator_anchor,
        "validator_set_sha256": sha256(validator_set_path, "validator set"),
        "topology_sha256": sha256(topology_path, "topology"),
        "config_sha256": sha256(config_path, f"validator config {validator_id}"),
        "candidate_source_sha256": candidate_sha256,
        "binary_sha256": config["binary_sha256"],
        "workload_corpus_sha256": config["workload_corpus_sha256"],
        "workload_policy_sha256": config["workload_policy_sha256"],
        "ordinary_start_height": config["ordinary_start_height"],
        "maximum_timeout_view_advances": signer_lifetime[
            "maximum_timeout_view_advances"
        ],
        "maximum_proposal_entries": archive_lifetime[
            "maximum_proposal_entries"
        ],
        "maximum_quorum_certificate_entries": archive_lifetime[
            "maximum_quorum_certificate_entries"
        ],
        "maximum_archive_entries": archive_lifetime["maximum_total_entries"],
        "context_sha256": context_digest.hex(),
    }
    if context != expected_context:
        fail(f"replay context {validator_id} differs from authenticated public inputs")

    prior_record = hash_parts(REPLAY_GENESIS_DOMAIN, (context_digest,))
    coordinates: set[tuple[str, int, int, str]] = set()
    proposal_count = 0
    quorum_certificate_count = 0

    def verify_entry(line: bytes, zero_based_index: int) -> None:
        nonlocal prior_record, proposal_count, quorum_certificate_count
        index = zero_based_index + 1
        if index > context_numbers[4]:
            fail(f"replay entries {validator_id} cross the context entry bound")
        entry = exact(
            strict_json_bytes(line, f"replay entry {validator_id}[{index}]"),
            set(REPLAY_ENTRY_KEYS),
            f"replay entry {validator_id}[{index}]",
        )
        if line != compact_ordered_json(entry, REPLAY_ENTRY_KEYS) + b"\n":
            fail(f"replay entry {validator_id}[{index}] is not canonical Rust JSON")
        sequence = exact_u64(entry["sequence"], "replay entry sequence", positive=True)
        height = exact_u64(entry["height"], "replay entry height", positive=True)
        view = exact_u64(entry["view"], "replay entry view", positive=True)
        if (
            type(entry["schema_version"]) is not int
            or entry["schema_version"] != 1
            or sequence != index
        ):
            fail(f"replay entry {validator_id}[{index}] has a discontinuous sequence")
        kind = entry["kind"]
        if kind == "proposal":
            kind_code = b"\x01"
            proposal_count += 1
        elif kind == "quorum-certificate":
            kind_code = b"\x02"
            quorum_certificate_count += 1
        else:
            fail(f"replay entry {validator_id}[{index}] has an unknown kind")
        block_id = exact_hex(entry["block_id"], 32, "replay entry block ID")
        if entry["context_sha256"] != context_digest.hex():
            fail(f"replay entry {validator_id}[{index}] has a foreign context")
        predecessor = exact_hex(
            entry["previous_record_sha256"], 32, "replay entry predecessor"
        )
        if predecessor != prior_record:
            fail(f"replay entry {validator_id}[{index}] forks its record chain")
        payload_hex = entry["payload_hex"]
        if (
            not isinstance(payload_hex, str)
            or len(payload_hex) == 0
            or len(payload_hex) % 2 != 0
            or len(payload_hex) > MAXIMUM_REPLAY_PAYLOAD_BYTES * 2
            or re.fullmatch(r"[0-9a-f]+", payload_hex) is None
        ):
            fail(f"replay entry {validator_id}[{index}] payload is not bounded canonical hex")
        payload = bytes.fromhex(payload_hex)
        content_digest = hash_parts(REPLAY_CONTENT_DOMAIN, (kind_code, payload))
        if entry["content_sha256"] != content_digest.hex():
            fail(f"replay entry {validator_id}[{index}] content digest differs")
        record_digest = hash_parts(
            REPLAY_RECORD_DOMAIN,
            (
                context_digest,
                sequence.to_bytes(8, "big"),
                prior_record,
                kind_code,
                height.to_bytes(8, "big"),
                view.to_bytes(8, "big"),
                block_id,
                content_digest,
            ),
        )
        if entry["record_sha256"] != record_digest.hex():
            fail(f"replay entry {validator_id}[{index}] record digest differs")
        coordinate = (kind, height, view, entry["block_id"])
        if coordinate in coordinates:
            fail(f"replay entries {validator_id} repeat one logical coordinate")
        coordinates.add(coordinate)
        prior_record = record_digest

    entries_fact, entry_count = visit_jsonl_pinned(
        entries_path,
        f"replay entries {validator_id}",
        maximum=MAXIMUM_JSONL_BYTES,
        maximum_line=MAXIMUM_REPLAY_PAYLOAD_BYTES * 2 + 4_096,
        visitor=verify_entry,
    )
    if (
        proposal_count <= 0
        or quorum_certificate_count <= 0
        or proposal_count > context_numbers[2]
        or quorum_certificate_count > context_numbers[3]
    ):
        fail(f"replay entries {validator_id} cross the non-empty context inventory")

    head, head_fact = strict_rust_json(
        head_path,
        f"replay head {validator_id}",
        REPLAY_HEAD_KEYS,
        maximum=MAXIMUM_REPLAY_HEAD_BYTES,
    )
    exact_u64(head["sequence"], "replay head sequence", positive=True)
    if type(head["schema_version"]) is not int or head["schema_version"] != 1:
        fail(f"replay head {validator_id} has the wrong exact schema version")
    expected_head = {
        "schema_version": 1,
        "sequence": entry_count,
        "context_sha256": context_digest.hex(),
        "record_sha256": prior_record.hex(),
    }
    if head != expected_head:
        fail(f"replay head {validator_id} differs from the full raw log")

    seal, seal_fact = strict_rust_json(
        seal_path,
        f"replay terminal seal {validator_id}",
        REPLAY_TERMINAL_SEAL_KEYS,
        maximum=MAXIMUM_REPLAY_TERMINAL_SEAL_BYTES,
    )
    if type(seal["schema_version"]) is not int or seal["schema_version"] != 1:
        fail(f"replay terminal seal {validator_id} has the wrong exact schema version")
    unsigned_seal = dict(seal)
    unsigned_seal["body_sha256"] = ""
    unsigned_seal["signature"] = ""
    seal_body = hash_parts(
        REPLAY_TERMINAL_BODY_DOMAIN,
        (compact_ordered_json(unsigned_seal, REPLAY_TERMINAL_SEAL_KEYS),),
    )
    if seal["body_sha256"] != seal_body.hex():
        fail(f"replay terminal seal {validator_id} body digest differs")
    exact_hex(seal["signature"], 64, f"replay terminal seal {validator_id} signature")
    try:
        signed_evidence.verify_ed25519(
            validator["consensus_public_key"],
            hash_parts(REPLAY_TERMINAL_SIGNATURE_DOMAIN, (seal_body,)),
            seal["signature"],
            f"replay terminal seal {validator_id}",
        )
    except SystemExit as error:
        fail(f"replay terminal seal {validator_id} signature failed: {error}")

    replay = process["observer_replay_archive_verification"]
    last_event = signed_validator["last_event"]
    final_state = signed_validator["final_state"]
    seal_numbers = (
        "process_instance",
        "clean_stop_journal_sequence",
        "finalized_height",
        "archive_context_file_bytes",
        "archive_entries_file_bytes",
        "archive_head_file_bytes",
        "terminal_archive_sequence",
        "proposal_count",
        "quorum_certificate_count",
    )
    for field in seal_numbers:
        exact_u64(seal[field], f"replay terminal seal {field}", positive=True)
    expected_seal = {
        **seal,
        "schema_version": 1,
        "run_id": context["run_id"],
        "validator_id": validator_id,
        "validator_set_id": set_id,
        "validator_set_sha256": context["validator_set_sha256"],
        "topology_sha256": context["topology_sha256"],
        "coordinator_manifest_sha256": coordinator_anchor,
        "candidate_source_sha256": candidate_sha256,
        "binary_sha256": config["binary_sha256"],
        "config_sha256": context["config_sha256"],
        "fleet_start_certificate_sha256": process[
            "fleet_start_certificate_sha256"
        ],
        "process_instance": final_state["process_instance_count"],
        "clean_stop_journal_sequence": last_event["sequence"],
        "clean_stop_journal_sha256": last_event["event_sha256"],
        "finalized_height": final_state["finalized_height"],
        "finalized_block_id": final_state["finalized_block_id"],
        "finalized_state_root": final_state["finalized_state_root"],
        "finalized_chain_root": final_state["finalized_chain_root"],
        "finality_proof_id": replay["finality_proof_id"],
        "finality_child_block_id": replay["finality_child_block_id"],
        "finality_grandchild_block_id": replay["finality_grandchild_block_id"],
        "archive_context_sha256": context_digest.hex(),
        "archive_context_file_sha256": context_fact.sha256,
        "archive_context_file_bytes": context_fact.bytes,
        "archive_entries_file_sha256": entries_fact.sha256,
        "archive_entries_file_bytes": entries_fact.bytes,
        "archive_head_file_sha256": head_fact.sha256,
        "archive_head_file_bytes": head_fact.bytes,
        "terminal_archive_sequence": entry_count,
        "terminal_archive_record_sha256": prior_record.hex(),
        "proposal_count": proposal_count,
        "quorum_certificate_count": quorum_certificate_count,
    }
    if seal != expected_seal:
        fail(
            f"replay terminal seal {validator_id} differs from raw and signed terminal facts"
        )
    replay_fields = (
        "fleet_start_certificate_sha256",
        "clean_stop_journal_sequence",
        "clean_stop_journal_sha256",
        "finalized_height",
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
        "terminal_archive_sequence",
        "terminal_archive_record_sha256",
        "proposal_count",
        "quorum_certificate_count",
    )
    if any(replay[field] != seal[field] for field in replay_fields):
        fail(f"observer replay projection {validator_id} differs from the signed raw seal")
    if process["replay_archive_terminal_seal_sha256"] != seal_fact.sha256:
        fail(f"runner replay terminal-seal hash {validator_id} differs from raw bytes")


def validate_raw_replay_archives(
    *,
    coordinator_root: pathlib.Path,
    signed_sources: dict[str, dict[str, pathlib.Path]],
    signed_runtime: dict[str, Any],
    plan: dict[str, Any],
    runner_summary: dict[str, Any],
    validator_set: dict[str, Any],
    validator_ids: set[str],
    coordinator_anchor: str,
    candidate_sha256: str,
) -> None:
    processes = {
        process["validator_id"]: process for process in runner_summary["processes"]
    }
    if set(processes) != validator_ids:
        fail("runner process set differs before raw replay verification")
    for validator_id in sorted(validator_ids):
        validate_raw_replay_archive(
            coordinator_root=coordinator_root,
            signed_sources=signed_sources,
            signed_validator=signed_runtime["validators"][validator_id],
            process=processes[validator_id],
            plan=plan,
            validator_set=validator_set,
            validator_id=validator_id,
            coordinator_anchor=coordinator_anchor,
            candidate_sha256=candidate_sha256,
        )


def derive(root: pathlib.Path) -> dict[str, Any]:
    candidate_path = root / "candidate/source.tar"
    cargo_lock_path = root / "candidate/Cargo.lock"
    aggregate_path = root / "candidate/aggregate-build-report.json"
    linux_validator = root / "candidate/linux-x86_64/trnm-poco-lab-validator"
    linux_builder = root / "candidate/linux-x86_64/trnm-poco-lab-material-builder"
    macos_validator = root / "candidate/macos-arm64/trnm-poco-lab-validator"
    macos_builder = root / "candidate/macos-arm64/trnm-poco-lab-material-builder"
    inventory_path = root / "preflight/inventory.toml"
    probe_path = root / "preflight/probe-fleet-v1.json"
    readiness_path = root / "preflight/run-readiness-v2.json"
    coordinator_root = root / "coordinator"
    runner_root = root / "runner"

    try:
        candidate_report = check_source_candidate.validate(
            candidate_path, require_clean=True
        )
    except (SystemExit, OSError, tarfile.TarError, ValueError) as error:
        fail(f"clean-commit-v1 source candidate failed deep verification: {error}")
    aggregate, binaries = validate_aggregate(
        aggregate_path,
        candidate_report=candidate_report,
        candidate_path=candidate_path,
        cargo_lock_path=cargo_lock_path,
        linux_validator=linux_validator,
        linux_builder=linux_builder,
        macos_validator=macos_validator,
        macos_builder=macos_builder,
    )
    inventory, probe, readiness = validate_preflight(
        inventory_path, probe_path, readiness_path
    )
    coordinator_anchor = sha256(
        coordinator_root / "manifest.json", "coordinator manifest"
    )
    coordinator = runner_bridge.validate_coordinator(
        coordinator_root,
        VALIDATOR_COUNT,
        candidate_path,
        linux_validator,
        macos_validator,
        linux_builder,
    )
    validator_set = strict_json(
        coordinator_root / "public/validator-set.json", "validator set"
    )
    raw_validators = validator_set.get("validators")
    validator_ids = (
        {
            item.get("validator_id")
            for item in raw_validators
            if isinstance(item, dict)
        }
        if isinstance(raw_validators, list)
        else set()
    )
    if (
        not isinstance(raw_validators, list)
        or len(validator_ids) != VALIDATOR_COUNT
        or any(not isinstance(item, str) or HEX64.fullmatch(item) is None for item in validator_ids)
    ):
        fail("validator set must contain exactly seven canonical identities")
    typed_validator_ids = {str(item) for item in validator_ids}
    validate_secret_references(coordinator, typed_validator_ids)
    signed_sources, plan, runner_summary = runner_bridge.validate_runner_output(
        runner_root,
        coordinator,
        coordinator_anchor,
        typed_validator_ids,
        VALIDATOR_COUNT,
    )
    validator_host_ids = validate_topology_inventory_join(
        coordinator_root, coordinator, inventory, plan
    )
    signed_runtime = runner_bridge.verify_signed_inputs(
        coordinator_root,
        candidate_path,
        linux_validator,
        macos_validator,
        linux_builder,
        aggregate_path,
        signed_sources,
        typed_validator_ids,
        coordinator["run_id"],
        VALIDATOR_COUNT,
        coordinator_anchor,
    )
    signed_validators = signed_runtime.get("validators")
    if not isinstance(signed_validators, dict) or set(signed_validators) != typed_validator_ids:
        fail("signed-runtime verifier did not return the exact seven-validator set")
    validate_raw_replay_archives(
        coordinator_root=coordinator_root,
        signed_sources=signed_sources,
        signed_runtime=signed_runtime,
        plan=plan,
        runner_summary=runner_summary,
        validator_set=validator_set,
        validator_ids=typed_validator_ids,
        coordinator_anchor=coordinator_anchor,
        candidate_sha256=candidate_report["source_candidate_sha256"],
    )

    starts: set[str] = set()
    terminal_tips: set[tuple[int, int, str, str, str]] = set()
    for validator_id, evidence in signed_validators.items():
        report = evidence["report"]
        metrics = evidence["metrics"]
        final_state = evidence["final_state"]
        starts.add(metrics["measurement_started_at"])
        finalized_count = final_state["finalized_ordinary_block_count"]
        if (
            isinstance(finalized_count, bool)
            or not isinstance(finalized_count, int)
            or finalized_count <= 0
            or report["committed_ordinary_block_count"] != finalized_count
            or report["finalized_ordinary_block_count"] != finalized_count
            or final_state["finalized_nonempty_ordinary_block_count"] != finalized_count
            or final_state["process_instance_count"] != 1
            or any(
                final_state[field] != 0
                for field in (
                    "double_sign_events",
                    "duplicate_apply_events",
                    "state_drift_events",
                    "safety_halt_violations",
                )
            )
        ):
            fail(f"validator {validator_id} lacks one safe non-empty terminal chain")
        terminal_tips.add(
            (
                final_state["finalized_height"],
                finalized_count,
                final_state["finalized_block_id"],
                final_state["finalized_state_root"],
                final_state["finalized_chain_root"],
            )
        )
    if len(starts) != 1 or len(terminal_tips) != 1:
        fail("seven signed processes disagree on run start or terminal state")
    run_started_at = next(iter(starts))
    run_start = parse_utc(run_started_at, "signed run start")
    probe_ns = probe["observed_at_epoch_ns"]
    readiness_epoch = readiness["probe_completed_at_epoch"]
    if (
        isinstance(probe_ns, bool)
        or not isinstance(probe_ns, int)
        or isinstance(readiness_epoch, bool)
        or not isinstance(readiness_epoch, int)
    ):
        fail("preflight timestamps must be exact integers")
    run_start_epoch = int(run_start.timestamp())
    if not (
        probe_ns <= readiness_epoch * 1_000_000_000
        <= run_start_epoch * 1_000_000_000
        and run_start_epoch * 1_000_000_000 - probe_ns
        <= MAXIMUM_PREFLIGHT_AGE_SECONDS * 1_000_000_000
    ):
        fail("probe/readiness observations are not fresh and pre-run")

    tip = next(iter(terminal_tips))
    expected_terminal = {
        "finalized_height": tip[0],
        "finalized_ordinary_block_count": tip[1],
        "finalized_block_id": tip[2],
        "finalized_state_root": tip[3],
        "finalized_chain_root": tip[4],
        "fleet_start_certificate_sha256": signed_runtime[
            "fleet_start_certificate_sha256"
        ],
    }
    terminal = exact(
        runner_summary["terminal_agreement"],
        TERMINAL_KEYS,
        "runner terminal agreement",
    )
    if terminal != expected_terminal:
        fail("runner terminal agreement differs from seven signed terminal states")
    processes = runner_summary["processes"]
    if (
        len(processes) != VALIDATOR_COUNT
        or runner_summary["failure"] is not None
        or runner_summary["cleanup_failures"] != []
        or runner_summary["validator_run_completed"] is not False
    ):
        fail("runner does not expose one clean seven-process scoped observation")
    for process in processes:
        verification_fields = (
            "observer_journal_verification",
            "observer_fleet_start_certificate_verification",
            "observer_report_verification",
            "observer_metrics_verification",
            "observer_final_state_verification",
        )
        if any(
            process[field].get("signature_verified") is not True
            or process[field].get("semantics_verified") is not True
            for field in verification_fields
        ):
            fail("runner process lacks complete macOS signature/semantics verification")

    candidate = {
        "source_candidate_sha256": candidate_report["source_candidate_sha256"],
        "source_candidate_profile": candidate_report["source_profile"],
        "source_base_commit": candidate_report["base_commit"],
        "source_git_object_format": candidate_report["git_object_format"],
        "source_git_tree_oid": candidate_report["git_tree_oid"],
        "source_git_status_sha256": candidate_report["git_status_sha256"],
        "cargo_lock_path": candidate_report["cargo_lock_path"],
        "cargo_lock_sha256": candidate_report["cargo_lock_sha256"],
        "cargo_lock_bytes": candidate_report["cargo_lock_bytes"],
        "aggregate_build_report_sha256": sha256(
            aggregate_path, "aggregate build report"
        ),
        **binaries,
    }
    preflight = {
        "inventory_sha256": sha256(inventory_path, "fleet inventory"),
        "probe_fleet_sha256": sha256(probe_path, "probe-fleet-v1"),
        "readiness_sha256": sha256(readiness_path, "run-readiness-v2"),
        "probe_observed_at_epoch_ns": probe_ns,
        "readiness_completed_at_epoch": readiness_epoch,
        "run_started_at": run_started_at,
        "maximum_preflight_age_seconds": MAXIMUM_PREFLIGHT_AGE_SECONDS,
    }
    derived = {
        "validator_ids": sorted(typed_validator_ids),
        "validator_host_ids": validator_host_ids,
        "signed_process_count": VALIDATOR_COUNT,
        "signed_artifact_chain_count": VALIDATOR_COUNT,
        "observer_verified_process_count": VALIDATOR_COUNT,
        "observer_verified_replay_archive_count": VALIDATOR_COUNT,
        "fleet_barrier_round": signed_runtime["fleet_barrier_round"],
        "fleet_ready_set_sha256": signed_runtime["fleet_ready_set_sha256"],
        "fleet_start_certificate_sha256": signed_runtime[
            "fleet_start_certificate_sha256"
        ],
        "terminal_agreement": terminal,
        "runner_legacy_validator_run_completed": False,
        "stage0_direct_seven_observed": True,
    }
    return {
        "run_id": coordinator["run_id"],
        "candidate": candidate,
        "preflight": preflight,
        "coordinator_manifest_sha256": coordinator_anchor,
        "runner_ordered_artifact_root": strict_json(
            runner_root / "runner-output-manifest.json", "runner output manifest"
        )["ordered_artifact_root"],
        "derived_observation": derived,
    }


def validate(root: pathlib.Path, *, emit: bool = True) -> dict[str, Any]:
    root = real_root(root, "bundle root")
    files_before = tree_files(root)
    manifest_path = files_before.get("manifest.json")
    if manifest_path is None:
        fail("manifest.json is missing")
    manifest_raw, manifest_fact = read_pinned(
        manifest_path,
        "manifest.json",
        allow_empty=False,
        maximum=MAXIMUM_JSON_BYTES,
        capture=True,
    )
    manifest = exact(
        strict_json_bytes(manifest_raw, "manifest.json"), MANIFEST_KEYS, "manifest"
    )
    if manifest_raw != canonical_json(manifest):
        fail("manifest.json is not canonical or has trailing bytes")
    if (
        manifest["schema_version"] != SCHEMA_VERSION
        or manifest["evidence_profile"] != PROFILE
        or manifest["validator_count"] != VALIDATOR_COUNT
        or manifest["network_scope"] != "single-lan"
    ):
        fail("manifest crosses the scoped direct-seven identity")
    exact(manifest["candidate"], CANDIDATE_KEYS, "candidate")
    exact(manifest["preflight"], PREFLIGHT_KEYS, "preflight")
    exact(manifest["derived_observation"], DERIVED_KEYS, "derived_observation")
    if manifest["claims"] != CLAIMS:
        fail("claims cross the exact scoped Stage0 non-production boundary")
    if manifest["stage0_status_projection"] != STAGE0_STATUS_PROJECTION:
        fail("typed Stage0 status projection differs from independently authorized facts")

    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        fail("manifest artifacts must be one non-empty list")
    if artifacts != sorted(
        artifacts, key=lambda item: (item.get("role", ""), item.get("subject", ""), item.get("path", ""))
    ):
        fail("manifest artifacts must be canonically ordered")
    expected_identities = expected_artifact_identities(root)
    seen_paths = {"manifest.json"}
    seen_pairs: set[tuple[str, str]] = set()
    facts_before: dict[str, FileFact] = {"manifest.json": manifest_fact}
    for index, artifact in enumerate(artifacts):
        exact(artifact, ARTIFACT_KEYS, f"artifacts[{index}]")
        role = artifact["role"]
        subject = artifact["subject"]
        if not isinstance(role, str) or not role or not isinstance(subject, str):
            fail("artifact role must be non-empty and subject must be a string")
        pair = (role, subject)
        relative = safe_relative(artifact["path"], f"artifacts[{index}].path").as_posix()
        if pair in seen_pairs or relative in seen_paths:
            fail("artifact role/subject and path identities must be unique")
        if expected_identities.get(relative) != pair:
            fail("artifact role/subject/path differs from the closed source inventory")
        seen_pairs.add(pair)
        seen_paths.add(relative)
        allow_empty = role in {"validator_process_stdout", "validator_process_stderr"}
        _path, fact = verify_ref(
            root, artifact, f"artifacts[{index}]", allow_empty=allow_empty
        )
        facts_before[relative] = fact
    if set(expected_identities) != seen_paths - {"manifest.json"}:
        fail("manifest omits one required coordinator/runner/candidate artifact")
    if set(files_before) != seen_paths:
        fail("bundle contains an unreferenced, missing, or substituted file")
    if manifest["ordered_artifact_root"] != ordered_artifact_root(artifacts):
        fail("manifest ordered_artifact_root differs from every exact input")
    validate_all_json_artifacts(root, seen_paths - {"manifest.json"})

    observed = derive(root)
    expected_projection = {
        "run_id": manifest["run_id"],
        "candidate": manifest["candidate"],
        "preflight": manifest["preflight"],
        "coordinator_manifest_sha256": manifest["coordinator_manifest_sha256"],
        "runner_ordered_artifact_root": manifest["runner_ordered_artifact_root"],
        "derived_observation": manifest["derived_observation"],
    }
    if observed != expected_projection:
        fail("manifest projection differs from independently derived exact facts")

    files_after = tree_files(root)
    if set(files_after) != set(files_before):
        fail("bundle file inventory changed during verification")
    for relative, prior in facts_before.items():
        allow_empty = relative.endswith((".stdout", ".stderr"))
        _raw, after = read_pinned(
            files_after[relative], relative, allow_empty=allow_empty
        )
        if after != prior:
            fail(f"bundle artifact {relative!r} changed during verification")
    if emit:
        print(
            "poco_g3_stage0_direct_seven_bundle=passed validators=7 "
            "clean_commit=true cargo_lock_rehashed=true dual_arch_binaries=4 "
            "probe_fleet=fresh readiness=fresh signed_chains=7 "
            "observer_verifications=7 replay_archive_sets=7 terminal_agreement=true "
            "runner_validator_run_completed=false stage0_direct_seven_observed=true "
            "validator_run_7_completed_observed=true "
            "fault_matrix=false performance=false g3_lan=false geo_wan=false "
            "production_activation=false production_candidate=false"
        )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=pathlib.Path)
    args = parser.parse_args()
    validate(args.bundle)


if __name__ == "__main__":
    main()
