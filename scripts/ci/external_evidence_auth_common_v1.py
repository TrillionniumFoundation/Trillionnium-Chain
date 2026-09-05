"""Bounded canonical data helpers for external evidence authentication v1."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
from typing import Any

PROFILE = "ed25519-trnm-evidence-v1"
BODY_DOMAIN = b"trnm.external-evidence.body.v1\x00"
SIGN_DOMAIN = b"trnm.external-evidence.signature.v1\x00"
ED25519_SPKI = bytes.fromhex("302a300506032b6570032100")
MAX_JSON_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_ARTIFACTS = 64
MAX_KEYS = 128
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}\Z")
UTC_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
BODY_FIELDS = {
    "schema", "evidence_id", "blocker_id", "source_commit", "source_tree",
    "producer", "independent_reviewer", "independence_declaration", "scope",
    "result", "started_at", "ended_at", "wall_clock_seconds", "artifacts", "claims",
}
KEY_FIELDS = {
    "signer", "public_key_hex", "role", "independence_domain", "blocker_ids",
    "valid_from", "valid_until", "revoked",
}


class AuthenticationError(RuntimeError):
    pass


def require(condition: Any, message: str) -> None:
    if not condition:
        raise AuthenticationError(message)


def exact_fields(value: Any, required: set[str], optional: set[str] | None = None) -> None:
    require(isinstance(value, dict), "object required")
    require(required <= set(value) <= required | (optional or set()), "closed field set mismatch")


def hex_bytes(value: Any, count: int, label: str) -> bytes:
    require(isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{count * 2}}}", value),
            f"invalid {label}")
    return bytes.fromhex(value)


def identity(value: Any) -> str:
    require(isinstance(value, str) and ID.fullmatch(value), "invalid authority identity")
    return value


def timestamp(value: Any) -> dt.datetime:
    require(isinstance(value, str) and UTC_TIME.fullmatch(value), "UTC whole-second time required")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError as error:
        raise AuthenticationError("invalid UTC time") from error


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON member")
        value[key] = item
    return value


def no_float(value: str) -> Any:
    raise AuthenticationError("floating-point and non-finite JSON numbers are forbidden")


def validate_json_tree(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [100000]
    budget[0] -= 1
    require(budget[0] >= 0 and depth <= 32, "JSON work/depth limit exceeded")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        require(-(2**63) <= value < 2**128, "JSON integer bound exceeded")
    elif isinstance(value, str):
        require(len(value) <= 16384 and not any(0xD800 <= ord(c) <= 0xDFFF for c in value),
                "JSON string bound or Unicode scalar violation")
    elif isinstance(value, list):
        for child in value:
            validate_json_tree(child, depth + 1, budget)
    elif isinstance(value, dict):
        for key, child in value.items():
            require(isinstance(key, str), "JSON object keys must be strings")
            validate_json_tree(key, depth + 1, budget)
            validate_json_tree(child, depth + 1, budget)
    else:
        raise AuthenticationError("unsupported JSON value")


def decode_json(raw: bytes) -> dict[str, Any]:
    require(len(raw) <= MAX_JSON_BYTES, "JSON byte limit exceeded")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object,
                           parse_float=no_float, parse_constant=no_float)
        validate_json_tree(value)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise AuthenticationError("invalid JSON") from error
    require(isinstance(value, dict), "top-level object required")
    return value


def file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def open_regular(path: str | pathlib.Path, *, dir_fd: int | None = None) -> int:
    require(hasattr(os, "O_NOFOLLOW"), "no-follow file opens are required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "regular file required")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_document(path: pathlib.Path) -> bytes:
    fd = open_regular(path)
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        require(before.st_size <= MAX_JSON_BYTES, "JSON byte limit exceeded")
        raw = handle.read(MAX_JSON_BYTES + 1)
        require(file_identity(before) == file_identity(os.fstat(handle.fileno())),
                "document changed during read")
        require(len(raw) == before.st_size, "document size mismatch")
    return raw


def canonical_body(row: dict[str, Any]) -> bytes:
    exact_fields(row, BODY_FIELDS | {"signatures"}, {"notes"})
    validate_json_tree(row)
    body = {key: value for key, value in row.items() if key != "signatures"}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    require(len(encoded) <= MAX_JSON_BYTES, "canonical body byte limit exceeded")
    return encoded


def body_digest(row: dict[str, Any]) -> str:
    body = canonical_body(row)
    return hashlib.sha256(BODY_DOMAIN + len(body).to_bytes(8, "big") + body).hexdigest()


def signature_message(digest: str, policy_sha256: str, signer: str, role: str) -> bytes:
    require(role in {"producer", "reviewer"}, "invalid signer role")
    name = identity(signer).encode("ascii")
    return (SIGN_DOMAIN + hex_bytes(policy_sha256, 32, "policy digest")
            + hex_bytes(digest, 32, "body digest")
            + (b"\x00" if role == "producer" else b"\x01")
            + len(name).to_bytes(2, "big") + name)
