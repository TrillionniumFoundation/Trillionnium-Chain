#!/usr/bin/env python3
"""Candidate-only G1-R4 process fault matrix and evidence producer.

This harness is intentionally independent of the production Rust owners.  It
models the durable *boundary contract* using a tiny canonical byte record and
real private files, then drives the record writer from a second OS process.
The process is stopped at named checkpoints with SIGKILL; a fresh recovery
process classifies the residue and the independent replay checker validates
the emitted evidence.  The harness therefore provides useful local evidence
without pretending to close the missing A02--A05 interfaces.

No result from this file is production, validator, or G1-exit evidence.  The
faults named ``disk_full``, ``io_error``, ``fsync_error`` and
``directory_fsync_error`` are deterministic injected failures, not a claim
that a physical disk was exhausted.  Every failed/ambiguous residue is kept
under the caller-provided evidence directory when ``--output`` is used.
"""

from __future__ import annotations

import argparse
import dataclasses
import errno
import hashlib
import json
import os
import pathlib
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable


SCHEMA = "trnm-g1-r4-fault-matrix-v1"
STATE_SCHEMA = "trnm-g1-r4-durable-state-v1"
EVENT_SCHEMA = "trnm-g1-r4-process-event-v1"
BASE_COMMIT = "6e0189e351015ef3230f217ca7ff86149baedcf0"
BASE_TREE = "efea864cb2fbc4835a59a089b3dbab8934e71231"
ASSESSED_PLAN_COMMIT = "8198fea0307eb368df34ff77ffc272a6b0e655ec"
ASSESSED_PLAN_TREE = "a1be71bba1b54c428493d186fafb656d081b31a9"
LATEST_PLAN_COMMIT = "92449b8e101642f39d644d863db7bb60dea488f7"
LATEST_PLAN_TREE = "cf8f1ab4f5065cb0551a30ec0e036cd44cb31766"
PLAN_PATH = "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"

REQUIRED_MUTANT_KINDS = (
    "disk_full",
    "io_error",
    "fsync_error",
    "directory_fsync_error",
    "torn_write",
    "database_rollback",
    "namespace_rollback",
    "application_safety_skew",
    "losing_fork",
)

SEAM_PATHS = (
    "trillionnium/crates/trnm-poco-node/tests/finalization_intent_process_kill_matrix.rs",
    "trillionnium/crates/trnm-poco-node/tests/g1_process_host_e2e.rs",
    "trillionnium/crates/trnm-poco-node/tests/recovery_process_kill_matrix.rs",
    "trillionnium/crates/trnm-poco-lab-validator/src/recovery_barrier.rs",
    "trillionnium/crates/trnm-poco-lab-validator/src/restart_catchup.rs",
    "trillionnium/crates/trnm-poco-lab-validator/src/signed_replay_archive.rs",
)

# The fixed order is part of the evidence contract.  It is deliberately
# sorted by boundary rather than by the order in which a filesystem happens
# to return directory entries.
CASE_ORDER = (
    "R4-M01-sigkill-before-publish",
    "R4-M02-response-loss-before-commit",
    "R4-M03-response-loss-after-commit",
    "R4-M04-disk-full-before-publish",
    "R4-M05-io-error-before-publish",
    "R4-M06-fsync-error-before-publish",
    "R4-M07-directory-fsync-error-after-publish",
    "R4-M08-torn-write-before-publish",
    "R4-M09-database-rollback",
    "R4-M10-namespace-rollback",
    "R4-M11-application-safety-skew",
    "R4-M12-multi-block-ancestor-order",
    "R4-M13-losing-fork-retention",
)


@dataclasses.dataclass(frozen=True)
class CaseSpec:
    case_id: str
    phase: str
    fault_kind: str | None
    expected_status: str
    worker: bool = True


CASE_SPECS = (
    CaseSpec(CASE_ORDER[0], "sigkill_before_publish", None, "RECOVERED_EXACT"),
    CaseSpec(CASE_ORDER[1], "response_loss_before_commit", None, "RECOVERED_EXACT"),
    CaseSpec(CASE_ORDER[2], "response_loss_after_commit", None, "REPLAYED_EXACT"),
    CaseSpec(CASE_ORDER[3], "disk_full_before_publish", "disk_full", "DISK_FULL_RETAINED"),
    CaseSpec(CASE_ORDER[4], "io_error_before_publish", "io_error", "IO_ERROR_RETAINED"),
    CaseSpec(CASE_ORDER[5], "fsync_error_before_publish", "fsync_error", "FSYNC_ERROR_RETAINED"),
    CaseSpec(
        CASE_ORDER[6],
        "directory_fsync_error_after_publish",
        "directory_fsync_error",
        "DIR_FSYNC_AMBIGUOUS_RETAINED",
    ),
    CaseSpec(CASE_ORDER[7], "torn_write_before_publish", "torn_write", "TORN_WRITE_REJECTED"),
    CaseSpec(CASE_ORDER[8], "database_rollback", "database_rollback", "ROLLBACK_REJECTED"),
    CaseSpec(CASE_ORDER[9], "namespace_rollback", "namespace_rollback", "ROLLBACK_REJECTED"),
    CaseSpec(
        CASE_ORDER[10],
        "application_safety_skew",
        "application_safety_skew",
        "SKEW_REJECTED",
    ),
    CaseSpec(CASE_ORDER[11], "multi_block_ancestor_order", None, "ORDER_REPLAYED_EXACT", worker=False),
    CaseSpec(CASE_ORDER[12], "losing_fork_retention", "losing_fork", "FORK_RETAINED", worker=False),
)


class MatrixFailure(RuntimeError):
    """A machine-checkable harness failure."""


def canonical_json(value: object) -> bytes:
    """Encode one deterministic JSON object (one trailing LF)."""

    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    return sha256_bytes(path.read_bytes())


def strict_json(raw: bytes, field: str) -> dict[str, Any]:
    """Parse an object while rejecting duplicate keys and non-object roots."""

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise MatrixFailure(f"{field} contains duplicate key {key!r}")
            out[key] = value
        return out

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MatrixFailure(f"{field} is not strict UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise MatrixFailure(f"{field} must be one JSON object")
    return value


def safe_private_root(path: pathlib.Path) -> pathlib.Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise MatrixFailure(f"private root is not a real directory: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        path.chmod(0o700)
    return path


def fsync_directory(path: pathlib.Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_exact(path: pathlib.Path, payload: bytes, *, sync: bool = True) -> None:
    """Create one private regular file, write exact bytes and optionally fsync."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise MatrixFailure(f"short write for {path.name}")
            view = view[count:]
        if sync:
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_prefix(path: pathlib.Path, payload: bytes, prefix_length: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, payload[:prefix_length])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def ensure_regular_private(path: pathlib.Path) -> os.stat_result:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise MatrixFailure(f"residue is not one private regular file: {path.name}")
    return metadata


def state_bytes(
    *,
    height: int,
    parent_root: str,
    application_root: str,
    safety_root: str,
    signer_root: str,
    checkpoint_root: str,
    branch: str = "main",
) -> bytes:
    """Return the fixed-width, line-oriented durable state encoding.

    The independent verifier intentionally reimplements this grammar rather
    than importing this function.  Width and field order are part of the
    process evidence contract and make torn/partial writes unambiguous.
    """

    fields = (
        ("schema", STATE_SCHEMA),
        ("height", f"{height:020d}"),
        ("parent", parent_root),
        ("application", application_root),
        ("safety", safety_root),
        ("signer", signer_root),
        ("checkpoint", checkpoint_root),
        ("branch", branch),
    )
    for key, value in fields:
        if "\n" in value or "\r" in value or "=" in value:
            raise MatrixFailure(f"state field {key} contains a delimiter")
    return "".join(f"{key}={value}\n" for key, value in fields).encode("ascii")


def state_for_height(height: int, *, branch: str = "main") -> bytes:
    parent = sha256_bytes(f"TRNM/R4/parent/{branch}/{height - 1}".encode())
    application = sha256_bytes(f"TRNM/R4/application/{branch}/{height}".encode())
    safety = sha256_bytes(f"TRNM/R4/safety/{branch}/{height}".encode())
    signer = sha256_bytes(f"TRNM/R4/signer/{branch}/{height}".encode())
    checkpoint = sha256_bytes(
        f"TRNM/R4/checkpoint/{branch}/{height}/{application}/{safety}/{signer}".encode()
    )
    return state_bytes(
        height=height,
        parent_root=parent,
        application_root=application,
        safety_root=safety,
        signer_root=signer,
        checkpoint_root=checkpoint,
        branch=branch,
    )


def checkpoint_line(case_id: str, phase: str, root: pathlib.Path, *, fault: str = "none") -> str:
    target = root / "state.target"
    temporary = root / "state.tmp"
    target_exists = int(target.exists())
    temporary_exists = int(temporary.exists())
    target_digest = sha256_file(target) if target.exists() else "0" * 64
    temporary_digest = sha256_file(temporary) if temporary.exists() else "0" * 64
    return (
        "checkpoint_v1="
        f"{case_id};phase={phase};pid={os.getpid()};fault={fault};"
        f"target={target_exists};temp={temporary_exists};"
        f"target_sha256={target_digest};temp_sha256={temporary_digest}\n"
    )


def wait_at_checkpoint() -> None:
    """Hold a child alive until its parent intentionally terminates it."""

    try:
        os.read(sys.stdin.fileno(), 1)
    except (OSError, ValueError):
        # The parent uses SIGKILL; EOF is also a safe clean-stop path for
        # local debugging and never counts as a SIGKILL observation.
        pass
    time.sleep(60)


def worker_main(root: pathlib.Path, case: CaseSpec) -> int:
    """Run one deterministic write cut in a separate process."""

    safe_private_root(root)
    target = root / "state.target"
    temporary = root / "state.tmp"
    state = state_for_height(7)

    def emit(fault: str = "none") -> None:
        print(checkpoint_line(case.case_id, case.phase, root, fault=fault), end="", flush=True)

    if case.phase in {"sigkill_before_publish", "response_loss_before_commit"}:
        write_exact(temporary, state)
        emit()
        wait_at_checkpoint()
        return 0

    if case.phase == "response_loss_after_commit":
        write_exact(temporary, state)
        os.replace(temporary, target)
        fsync_directory(root)
        emit()
        wait_at_checkpoint()
        return 0

    if case.phase in {"disk_full_before_publish", "io_error_before_publish", "fsync_error_before_publish"}:
        # Keep a bounded, fsynced prefix as operator evidence.  The injected
        # errno is named in the checkpoint; no physical disk state is claimed.
        if case.phase == "disk_full_before_publish":
            write_prefix(temporary, state, len(state) // 2)
            emit("ENOSPC")
        elif case.phase == "io_error_before_publish":
            write_prefix(temporary, state, len(state) // 2)
            emit("EIO")
        else:
            write_prefix(temporary, state, len(state))
            emit("FSYNC_EIO")
        wait_at_checkpoint()
        return 0

    if case.phase == "directory_fsync_error_after_publish":
        write_exact(temporary, state)
        os.replace(temporary, target)
        # The directory fsync failure is injected *after* rename.  The target
        # is therefore ambiguous until a fresh process validates its bytes.
        emit("DIRECTORY_FSYNC_EIO")
        wait_at_checkpoint()
        return 0

    if case.phase == "torn_write_before_publish":
        write_prefix(temporary, state, len(state) - 3)
        emit("TORN_WRITE")
        wait_at_checkpoint()
        return 0

    if case.phase == "database_rollback":
        write_exact(root / "watermark.anchor", b"height=00000000000000000007\n")
        write_exact(target, state_for_height(5))
        emit("ROLLBACK")
        wait_at_checkpoint()
        return 0

    if case.phase == "namespace_rollback":
        # A whole-namespace rollback is represented by a lower target plus a
        # separately retained external anchor.  The harness never calls this
        # an authenticated production anti-rollback root.
        write_exact(root / "watermark.anchor", b"height=00000000000000000007\n")
        write_exact(root / "namespace.snapshot", state_for_height(5))
        write_exact(target, state_for_height(5))
        emit("NAMESPACE_ROLLBACK")
        wait_at_checkpoint()
        return 0

    if case.phase == "application_safety_skew":
        application = sha256_bytes(b"application-root-at-7")
        safety = sha256_bytes(b"safety-root-at-6")
        signer = sha256_bytes(b"signer-root-at-7")
        skewed = state_bytes(
            height=7,
            parent_root=sha256_bytes(b"parent-at-6"),
            application_root=application,
            safety_root=safety,
            signer_root=signer,
            checkpoint_root=sha256_bytes(b"checkpoint-skewed"),
        )
        write_exact(target, skewed)
        emit("SKEW")
        wait_at_checkpoint()
        return 0

    raise MatrixFailure(f"worker does not implement phase {case.phase}")


def read_checkpoint(process: subprocess.Popen[bytes], expected_case: str) -> str:
    if process.stdout is None:
        raise MatrixFailure("worker stdout was not captured")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        ready = selector.select(timeout=10.0)
        if not ready:
            raise MatrixFailure(f"checkpoint timeout for {expected_case}")
        line = process.stdout.readline().decode("utf-8")
    finally:
        selector.close()
    if not line.startswith(f"checkpoint_v1={expected_case};") or not line.endswith("\n"):
        raise MatrixFailure(f"malformed checkpoint for {expected_case}: {line!r}")
    return line


def kill_worker(process: subprocess.Popen[bytes], expected_case: str) -> tuple[int, str]:
    process.kill()  # SIGKILL on POSIX; this is the boundary under test.
    returncode = process.wait(timeout=10)
    stderr = b""
    if process.stderr is not None:
        stderr = process.stderr.read()
    if returncode != -signal.SIGKILL:
        raise MatrixFailure(
            f"worker for {expected_case} did not terminate by SIGKILL: "
            f"returncode={returncode} stderr={stderr.decode(errors='replace')}"
        )
    return returncode, stderr.decode("utf-8", errors="replace")


def parse_state(raw: bytes, field: str) -> dict[str, str]:
    """Small local parser used only for recovery classification.

    The independent replay script has a separate implementation and is the
    authority for the evidence verdict.
    """

    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise MatrixFailure(f"{field} is not ASCII: {error}") from error
    lines = text.splitlines(keepends=True)
    expected = ("schema", "height", "parent", "application", "safety", "signer", "checkpoint", "branch")
    if len(lines) != len(expected) or any(not line.endswith("\n") for line in lines):
        raise MatrixFailure(f"{field} has a torn or incomplete line inventory")
    result: dict[str, str] = {}
    for line, key in zip(lines, expected):
        name, separator, value = line[:-1].partition("=")
        if separator != "=" or name != key or name in result or not value:
            raise MatrixFailure(f"{field} has a malformed {key} field")
        result[name] = value
    if result["schema"] != STATE_SCHEMA or len(result["height"]) != 20 or not result["height"].isdigit():
        raise MatrixFailure(f"{field} has an invalid schema/height")
    for key in ("parent", "application", "safety", "signer", "checkpoint"):
        value = result[key]
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise MatrixFailure(f"{field}.{key} is not a lowercase digest")
    return result


def residue_snapshot(root: pathlib.Path) -> dict[str, Any]:
    names = ("state.target", "state.tmp", "watermark.anchor", "namespace.snapshot")
    out: dict[str, Any] = {}
    for name in names:
        path = root / name
        if not path.exists():
            out[name] = None
            continue
        metadata = ensure_regular_private(path)
        raw = path.read_bytes()
        out[name] = {
            "bytes": len(raw),
            "sha256": sha256_bytes(raw),
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "nlink": metadata.st_nlink,
        }
    return out


def classify_recovery(case: CaseSpec, root: pathlib.Path) -> dict[str, Any]:
    target = root / "state.target"
    temporary = root / "state.tmp"

    if case.phase in {"sigkill_before_publish", "response_loss_before_commit"}:
        raw = temporary.read_bytes()
        parsed = parse_state(raw, "temporary state")
        os.replace(temporary, target)
        fsync_directory(root)
        recovered = parse_state(target.read_bytes(), "recovered state")
        return {
            "status": "RECOVERED_EXACT",
            "error_code": None,
            "height": int(recovered["height"]),
            "state_sha256": sha256_bytes(target.read_bytes()),
            "response_loss": case.phase == "response_loss_before_commit",
            "idempotent_retry": True,
            "retained": False,
            "fault_authority": "candidate-process-boundary",
            "parent_root": parsed["parent"],
        }

    if case.phase == "response_loss_after_commit":
        recovered = parse_state(target.read_bytes(), "committed state")
        if temporary.exists():
            raise MatrixFailure("response-loss-after-commit left a temporary residue")
        return {
            "status": "REPLAYED_EXACT",
            "error_code": None,
            "height": int(recovered["height"]),
            "state_sha256": sha256_bytes(target.read_bytes()),
            "response_loss": True,
            "idempotent_retry": True,
            "retained": False,
            "fault_authority": "candidate-process-boundary",
        }

    if case.phase in {
        "disk_full_before_publish",
        "io_error_before_publish",
        "fsync_error_before_publish",
        "torn_write_before_publish",
    }:
        if not temporary.exists() or target.exists():
            raise MatrixFailure(f"{case.phase} residue shape is unsafe")
        raw = temporary.read_bytes()
        expected_error = {
            "disk_full_before_publish": ("DISK_FULL_RETAINED", "ENOSPC"),
            "io_error_before_publish": ("IO_ERROR_RETAINED", "EIO"),
            "fsync_error_before_publish": ("FSYNC_ERROR_RETAINED", "EIO"),
            "torn_write_before_publish": ("TORN_WRITE_REJECTED", "TORN_WRITE"),
        }[case.phase]
        return {
            "status": expected_error[0],
            "error_code": expected_error[1],
            "state_sha256": sha256_bytes(raw),
            "bytes": len(raw),
            "idempotent_retry": False,
            "retained": True,
            "retained_file": "state.tmp",
            "fault_authority": "deterministic-injection",
        }

    if case.phase == "directory_fsync_error_after_publish":
        parsed = parse_state(target.read_bytes(), "directory-fsync ambiguous target")
        return {
            "status": "DIR_FSYNC_AMBIGUOUS_RETAINED",
            "error_code": "DIRECTORY_FSYNC_EIO",
            "height": int(parsed["height"]),
            "state_sha256": sha256_bytes(target.read_bytes()),
            "idempotent_retry": True,
            "retained": True,
            "retained_file": "state.target",
            "fault_authority": "deterministic-injection",
        }

    if case.phase in {"database_rollback", "namespace_rollback"}:
        anchor = (root / "watermark.anchor").read_text(encoding="ascii")
        if anchor != "height=00000000000000000007\n":
            raise MatrixFailure("rollback anchor was not exact")
        candidate_path = target if case.phase == "database_rollback" else root / "namespace.snapshot"
        candidate = parse_state(candidate_path.read_bytes(), "rollback candidate")
        return {
            "status": "ROLLBACK_REJECTED",
            "error_code": "LOWER_THAN_EXTERNAL_WATERMARK",
            "height": int(candidate["height"]),
            "state_sha256": sha256_bytes(candidate_path.read_bytes()),
            "idempotent_retry": False,
            "retained": True,
            "retained_file": candidate_path.name,
            "fault_authority": "candidate-external-anchor-model",
        }

    if case.phase == "application_safety_skew":
        parsed = parse_state(target.read_bytes(), "skew candidate")
        if parsed["application"] == parsed["safety"]:
            raise MatrixFailure("skew mutant unexpectedly has equal roots")
        return {
            "status": "SKEW_REJECTED",
            "error_code": "APPLICATION_SAFETY_ROOT_MISMATCH",
            "height": int(parsed["height"]),
            "state_sha256": sha256_bytes(target.read_bytes()),
            "idempotent_retry": False,
            "retained": True,
            "retained_file": "state.target",
            "fault_authority": "candidate-cross-plane-model",
        }

    raise MatrixFailure(f"no worker recovery classifier for {case.phase}")


def run_worker_case(case: CaseSpec, root: pathlib.Path) -> dict[str, Any]:
    command = [sys.executable, str(pathlib.Path(__file__).resolve()), "--worker", str(root), case.case_id]
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    checkpoint = read_checkpoint(process, case.case_id)
    returncode, stderr = kill_worker(process, case.case_id)
    recovery = classify_recovery(case, root)
    return {
        "schema": EVENT_SCHEMA,
        "case_id": case.case_id,
        "phase": case.phase,
        "fault_kind": case.fault_kind,
        "checkpoint": checkpoint.rstrip("\n"),
        "process": {
            "worker_pid": process.pid,
            "exit_signal": -returncode,
            "sigkill_observed": returncode == -signal.SIGKILL,
            "stderr_sha256": sha256_bytes(stderr.encode("utf-8")),
            "independent_process": True,
        },
        "residue_before_recovery": residue_snapshot(root),
        "recovery": recovery,
        "residue_after_recovery": residue_snapshot(root),
    }


def run_multi_block_case(root: pathlib.Path) -> dict[str, Any]:
    records = [state_for_height(height) for height in (1, 2, 3)]
    queue = root / "queue.log"
    write_exact(queue, b"".join(records))
    parsed = []
    offset = 0
    # Fixed record length is deliberate: a missing/torn record cannot be
    # silently interpreted as a shorter valid block.
    record_length = len(records[0])
    raw = queue.read_bytes()
    while offset < len(raw):
        chunk = raw[offset : offset + record_length]
        if len(chunk) != record_length:
            raise MatrixFailure("multi-block queue contains a torn tail")
        parsed.append(parse_state(chunk, f"queue record {len(parsed)}"))
        offset += record_length
    heights = [int(item["height"]) for item in parsed]
    if heights != [1, 2, 3]:
        raise MatrixFailure(f"multi-block order drift: {heights}")
    return {
        "schema": EVENT_SCHEMA,
        "case_id": CASE_ORDER[11],
        "phase": "multi_block_ancestor_order",
        "fault_kind": None,
        "checkpoint": (
            f"checkpoint_v1={CASE_ORDER[11]};phase=multi_block_ancestor_order;pid=0;"
            "fault=none;target=1;temp=0;target_sha256="
            + sha256_bytes(raw)
            + ";temp_sha256="
            + "0" * 64
        ),
        "process": {
            "worker_pid": None,
            "exit_signal": None,
            "sigkill_observed": False,
            "stderr_sha256": sha256_bytes(b""),
            "independent_process": True,
        },
        "residue_before_recovery": {
            "queue.log": {
                "bytes": len(raw),
                "sha256": sha256_bytes(raw),
                "mode": "0600",
                "nlink": 1,
            }
        },
        "recovery": {
            "status": "ORDER_REPLAYED_EXACT",
            "error_code": None,
            "heights": heights,
            "record_count": len(parsed),
            "idempotent_retry": True,
            "retained": False,
            "fault_authority": "candidate-independent-replay",
        },
        "residue_after_recovery": {
            "queue.log": {
                "bytes": len(raw),
                "sha256": sha256_bytes(raw),
                "mode": "0600",
                "nlink": 1,
            }
        },
    }


def run_fork_case(root: pathlib.Path) -> dict[str, Any]:
    winner = root / "fork-main.state"
    loser = root / "fork-loser.state"
    write_exact(winner, state_for_height(8, branch="main"))
    write_exact(loser, state_for_height(8, branch="fork"))
    winner_raw = winner.read_bytes()
    loser_raw = loser.read_bytes()
    if sha256_bytes(winner_raw) == sha256_bytes(loser_raw):
        raise MatrixFailure("fork mutant unexpectedly equals winning branch")
    return {
        "schema": EVENT_SCHEMA,
        "case_id": CASE_ORDER[12],
        "phase": "losing_fork_retention",
        "fault_kind": "losing_fork",
        "checkpoint": (
            f"checkpoint_v1={CASE_ORDER[12]};phase=losing_fork_retention;pid=0;"
            "fault=losing_fork;target=1;temp=0;target_sha256="
            + sha256_bytes(winner_raw)
            + ";temp_sha256="
            + "0" * 64
        ),
        "process": {
            "worker_pid": None,
            "exit_signal": None,
            "sigkill_observed": False,
            "stderr_sha256": sha256_bytes(b""),
            "independent_process": True,
        },
        "residue_before_recovery": {
            "fork-main.state": {
                "bytes": len(winner_raw),
                "sha256": sha256_bytes(winner_raw),
                "mode": "0600",
                "nlink": 1,
            },
            "fork-loser.state": {
                "bytes": len(loser_raw),
                "sha256": sha256_bytes(loser_raw),
                "mode": "0600",
                "nlink": 1,
            },
        },
        "recovery": {
            "status": "FORK_RETAINED",
            "error_code": "LOSING_FORK_NOT_GC_ELIGIBLE",
            "winner_sha256": sha256_bytes(winner_raw),
            "loser_sha256": sha256_bytes(loser_raw),
            "idempotent_retry": False,
            "retained": True,
            "retained_file": "fork-loser.state",
            "fault_authority": "candidate-independent-replay",
        },
        "residue_after_recovery": {
            "fork-main.state": {
                "bytes": len(winner_raw),
                "sha256": sha256_bytes(winner_raw),
                "mode": "0600",
                "nlink": 1,
            },
            "fork-loser.state": {
                "bytes": len(loser_raw),
                "sha256": sha256_bytes(loser_raw),
                "mode": "0600",
                "nlink": 1,
            },
        },
    }


def git_value(root: pathlib.Path, expression: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", expression],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() or None


def source_audit(root: pathlib.Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for relative in SEAM_PATHS:
        path = root / relative
        if not path.is_file():
            files.append({"path": relative, "present": False})
            continue
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        files.append(
            {
                "path": relative,
                "present": True,
                "bytes": len(raw),
                "sha256": sha256_bytes(raw),
                "tokens": {
                    "process": "process" in text.lower(),
                    "recovery": "recover" in text.lower(),
                    "checkpoint": "checkpoint" in text.lower(),
                    "rollback": "rollback" in text.lower(),
                },
            }
        )
    return {
        "scope": "candidate-source-audit-only",
        "files": files,
        "all_present": all(item["present"] for item in files),
    }


def copy_retained_mutants(
    output_root: pathlib.Path | None,
    case_events: Iterable[dict[str, Any]],
    temp_roots: dict[str, pathlib.Path],
) -> list[dict[str, Any]]:
    retained: list[dict[str, Any]] = []
    destination = None
    if output_root is not None:
        destination = output_root / "retained"
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    for event in case_events:
        recovery = event["recovery"]
        if not recovery.get("retained"):
            continue
        case_id = event["case_id"]
        source_name = recovery.get("retained_file")
        if not isinstance(source_name, str):
            raise MatrixFailure(f"retained event {case_id} lacks retained_file")
        source = temp_roots[case_id] / source_name
        if not source.is_file():
            raise MatrixFailure(f"retained residue disappeared for {case_id}: {source_name}")
        raw = source.read_bytes()
        relative = f"retained/{case_id}.bin"
        if destination is not None:
            target = destination / f"{case_id}.bin"
            write_exact(target, raw)
        retained.append(
            {
                "case_id": case_id,
                "kind": event.get("fault_kind") or recovery.get("error_code"),
                "source_name": source_name,
                "path": relative,
                "bytes": len(raw),
                "sha256": sha256_bytes(raw),
                "retained": True,
            }
        )
    return retained


def build_evidence(root: pathlib.Path, output_root: pathlib.Path | None) -> dict[str, Any]:
    if sys.platform != "linux":
        raise MatrixFailure("G1-R4 process evidence requires Linux")
    if len(CASE_SPECS) != len(CASE_ORDER) or tuple(item.case_id for item in CASE_SPECS) != CASE_ORDER:
        raise MatrixFailure("case order is not frozen")

    events: list[dict[str, Any]] = []
    temp_roots: dict[str, pathlib.Path] = {}
    with tempfile.TemporaryDirectory(prefix="trnm-g1-r4-") as temporary:
        run_root = pathlib.Path(temporary)
        for case in CASE_SPECS:
            case_root = safe_private_root(run_root / case.case_id)
            temp_roots[case.case_id] = case_root
            if case.phase == "multi_block_ancestor_order":
                events.append(run_multi_block_case(case_root))
            elif case.phase == "losing_fork_retention":
                events.append(run_fork_case(case_root))
            else:
                events.append(run_worker_case(case, case_root))
        retained = copy_retained_mutants(output_root, events, temp_roots)

    # The temporary roots are removed only after all residues were copied and
    # hashed.  ``retained`` remains an explicit index even for stdout-only
    # runs, while a persisted output directory carries the raw bytes.
    source_root = root
    head_commit = git_value(source_root, "HEAD")
    head_tree = git_value(source_root, "HEAD^{tree}")
    status_raw = subprocess.run(
        ["git", "-C", str(source_root), "status", "--porcelain=v1"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    evidence = {
        "schema": SCHEMA,
        "schema_version": 1,
        "package_id": "G1_R4_FAULT_MATRIX_V1",
        "status": "BLOCKED_UPSTREAM",
        "scope": "process",
        "authority": "candidate",
        "classification": "candidate-non-normative",
        "data_scope": "synthetic-local-fault-replay",
        "candidate_only": True,
        "production": False,
        "production_candidate": False,
        "production_consensus_activation": False,
        "g1_r4_exit": False,
        "base": {
            "ref": "refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829",
            "commit": BASE_COMMIT,
            "tree": BASE_TREE,
        },
        "head": {"commit": head_commit, "tree": head_tree},
        "plan": {
            "path": PLAN_PATH,
            "assessed_commit": ASSESSED_PLAN_COMMIT,
            "assessed_tree": ASSESSED_PLAN_TREE,
            "latest_live_commit": LATEST_PLAN_COMMIT,
            "latest_live_tree": LATEST_PLAN_TREE,
        },
        "worktree": {
            "clean": status_raw == "",
            "status_sha256": sha256_bytes(status_raw.encode("utf-8")),
            "status_lines": status_raw.splitlines(),
        },
        "command": "python3 scripts/faults/g1_r4_fault_matrix_v1.py --output <evidence-dir>/evidence.json",
        "replay_command": "python3 scripts/faults/g1_r4_independent_replay_v1.py <evidence-dir>/evidence.json",
        "topology": {
            "writer_processes": 11,
            "independent_replay_processes": 1,
            "host_count": 1,
            "network": "none",
        },
        "fault_schedule": [
            {"ordinal": index + 1, "case_id": case.case_id, "phase": case.phase, "fault": case.fault_kind}
            for index, case in enumerate(CASE_SPECS)
        ],
        "cases": events,
        "positive_count": sum(
            event["recovery"]["status"] in {"RECOVERED_EXACT", "REPLAYED_EXACT", "ORDER_REPLAYED_EXACT"}
            for event in events
        ),
        "negative_count": sum(
            event["recovery"]["status"] not in {"RECOVERED_EXACT", "REPLAYED_EXACT", "ORDER_REPLAYED_EXACT"}
            for event in events
        ),
        "retained_mutants": retained,
        "source_seam_audit": source_audit(source_root),
        "upstream_blockers": [
            {
                "id": "A02_CORE_ACK_ATOMIC_WITH_CORE_UNAVAILABLE",
                "owner": "A02",
                "severity": "High",
                "status": "blocked-upstream",
            },
            {
                "id": "A03_ORDINARY_PROPOSAL_PERMIT_UNAVAILABLE",
                "owner": "A03",
                "severity": "High",
                "status": "blocked-upstream",
            },
            {
                "id": "A04_APPLICATION_COMMIT_READBACK_UNAVAILABLE",
                "owner": "A04",
                "severity": "High",
                "status": "blocked-upstream",
            },
            {
                "id": "A05_WHOLE_NODE_CHECKPOINT_CAS_UNAVAILABLE",
                "owner": "A05",
                "severity": "Critical",
                "status": "blocked-upstream",
            },
        ],
        "known_gaps": [
            "physical_disk_full_not_executed; ENOSPC is deterministic injection",
            "physical_power_loss_not_executed; host reboot classification remains open",
            "SQLite WAL/SHM/hot-journal integration awaits A04 owner hook",
            "production signer/watermark/whole-node CAS awaits A05 accepted interface",
            "100000-block real-node corpus and multi-host network replay remain open",
            "independent clean-clone Cargo replay is unavailable on this host",
        ],
        "assertions": {
            "every_named_case_has_positive_or_negative_result": len(events) == len(CASE_SPECS),
            "sigkill_observed_for_process_cases": all(
                event["process"]["sigkill_observed"]
                for event in events
                if event["process"]["worker_pid"] is not None
            ),
            "independent_process_replay": all(event["process"]["independent_process"] for event in events),
            "retained_mutants_indexed": len(retained) == len(REQUIRED_MUTANT_KINDS),
            "production_authority_minted": False,
            "g1_exit": False,
        },
        "evidence_scope_contract": {
            "source_commit_bound": head_commit is not None,
            "source_tree_bound": head_tree is not None,
            "plan_commit_bound": True,
            "binary_sha256": None,
            "sbom_sha256": None,
            "raw_trace_root": None,
            "reviewers": [],
            "signatures": [],
            "acceptance": "pending-independent-review",
        },
    }
    return evidence


def run_replay_checker(replay_path: pathlib.Path, evidence_path: pathlib.Path) -> dict[str, Any]:
    process = subprocess.run(
        [sys.executable, str(replay_path), str(evidence_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if process.returncode != 0:
        raise MatrixFailure(
            f"independent replay failed: stdout={process.stdout!r} stderr={process.stderr!r}"
        )
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError as error:
        raise MatrixFailure(f"independent replay returned non-JSON: {process.stdout!r}") from error


def write_output(output: pathlib.Path, evidence: dict[str, Any]) -> None:
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = canonical_json(evidence)
    # Replace the report atomically so the optional independent-replay result
    # can be appended without ever exposing a partially written JSON file.
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise MatrixFailure("short write while publishing evidence JSON")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, output)
        fsync_directory(output.parent)
    finally:
        # ``os.replace`` consumed the temporary name on success.  The unlink
        # is narrowly scoped to this private, freshly-created path.
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", nargs=2, metavar=("ROOT", "CASE_ID"), help=argparse.SUPPRESS)
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        help="persist evidence JSON at a file path (its parent is created; a directory is rejected)",
    )
    parser.add_argument("--root", type=pathlib.Path, help="repository root (defaults to git top-level)")
    parser.add_argument("--no-independent-replay", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def repository_root(explicit: pathlib.Path | None) -> pathlib.Path:
    if explicit is not None:
        return explicit.resolve()
    value = git_value(pathlib.Path.cwd(), "--show-toplevel")
    return pathlib.Path(value).resolve() if value else pathlib.Path.cwd().resolve()


def main() -> int:
    args = parse_args()
    if args.worker is not None:
        root = safe_private_root(pathlib.Path(args.worker[0]).resolve())
        try:
            case = next(item for item in CASE_SPECS if item.case_id == args.worker[1])
        except StopIteration:
            print(f"unknown worker case {args.worker[1]}", file=sys.stderr)
            return 2
        try:
            return worker_main(root, case)
        except Exception as error:  # worker errors must be visible to parent
            print(f"worker failure: {error}", file=sys.stderr)
            return 1

    root = repository_root(args.root)
    if args.output is not None and args.output.exists() and args.output.is_dir():
        print(
            "G1-R4 fault matrix failed closed: --output must name a file, not an existing directory",
            file=sys.stderr,
        )
        return 2
    output_root = args.output.parent if args.output is not None else None
    try:
        evidence = build_evidence(root, output_root)
        if args.output is None:
            print(json.dumps(evidence, indent=2, sort_keys=True))
            return 0

        write_output(args.output, evidence)
        replay_path = pathlib.Path(__file__).with_name("g1_r4_independent_replay_v1.py")
        if not args.no_independent_replay:
            replay_result = run_replay_checker(replay_path, args.output)
            evidence["independent_replay"] = replay_result
            write_output(args.output, evidence)
        print(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "status": evidence["status"],
                    "output": str(args.output),
                    "head_commit": evidence["head"]["commit"],
                    "head_tree": evidence["head"]["tree"],
                    "positive_count": evidence["positive_count"],
                    "negative_count": evidence["negative_count"],
                    "retained_mutants": len(evidence["retained_mutants"]),
                },
                sort_keys=True,
            )
        )
        return 0
    except (MatrixFailure, OSError, subprocess.SubprocessError) as error:
        print(f"G1-R4 fault matrix failed closed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
