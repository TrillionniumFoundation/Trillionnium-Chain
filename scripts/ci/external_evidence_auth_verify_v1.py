"""Pinned trust-policy and content-addressed artifact verification."""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import pathlib
from typing import Any

import check_external_evidence_v1 as intake
from external_evidence_auth_common_v1 import (
    AuthenticationError, KEY_FIELDS, MAX_ARTIFACT_BYTES, MAX_TOTAL_ARTIFACT_BYTES, MAX_KEYS,
    exact_fields, file_identity, hex_bytes, identity, open_regular, require,
    timestamp, decode_json,
)

def load_policy(raw: bytes, expected_sha256: str, as_of: dt.datetime) -> dict[str, dict[str, Any]]:
    hex_bytes(expected_sha256, 32, "policy digest")
    require(hashlib.sha256(raw).hexdigest() == expected_sha256, "trust policy pin mismatch")
    policy = decode_json(raw)
    exact_fields(policy, {"schema", "valid_from", "valid_until", "keys"})
    require(policy["schema"] == "trnm-external-evidence-trust-v1", "trust policy schema mismatch")
    require(timestamp(policy["valid_from"]) <= as_of <= timestamp(policy["valid_until"]),
            "trust policy outside validity interval")
    keys = policy["keys"]
    require(isinstance(keys, list) and 2 <= len(keys) <= MAX_KEYS, "trust key count out of bounds")
    by_signer: dict[str, dict[str, Any]] = {}
    public_keys: set[bytes] = set()
    for key in keys:
        exact_fields(key, KEY_FIELDS)
        name = identity(key["signer"])
        public = hex_bytes(key["public_key_hex"], 32, "public key")
        require(public not in {bytes(32), b"\x01" + bytes(31)}, "degenerate public key")
        require(name not in by_signer and public not in public_keys, "duplicate trust identity/key")
        require(isinstance(key["role"], str) and key["role"] in {"producer", "reviewer"}, "invalid trust role")
        identity(key["independence_domain"])
        blockers = key["blocker_ids"]
        require(isinstance(blockers, list) and blockers and len(blockers) <= len(intake.SCOPES)
                and all(isinstance(b, str) and b in intake.SCOPES for b in blockers),
                "invalid trust blocker scope")
        require(len(set(blockers)) == len(blockers), "duplicate trust blocker scope")
        require(type(key["revoked"]) is bool, "revoked must be boolean")
        require(timestamp(key["valid_from"]) <= timestamp(key["valid_until"]), "key interval reversed")
        by_signer[name] = key
        public_keys.add(public)
    return by_signer


def verify_artifacts(
    artifacts: list[dict[str, Any]],
    directory: pathlib.Path,
    *,
    max_total_artifact_bytes: int = MAX_TOTAL_ARTIFACT_BYTES,
    identity_fn=file_identity,
) -> list[dict[str, Any]]:
    require(hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"), "POSIX directory opens required")
    root_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    verified = []
    total = 0
    try:
        for artifact in artifacts:
            digest = artifact["sha256"]  # validated hex; never a caller-selected path
            fd = open_regular(digest, dir_fd=root_fd)
            with os.fdopen(fd, "rb") as handle:
                before = os.fstat(handle.fileno())
                require(before.st_size <= MAX_ARTIFACT_BYTES, "artifact byte limit exceeded")
                require(total + before.st_size <= max_total_artifact_bytes, "total artifact byte limit exceeded")
                actual = hashlib.sha256()
                observed = 0
                while True:
                    chunk = handle.read(min(1024 * 1024, MAX_ARTIFACT_BYTES - observed + 1))
                    if not chunk:
                        break
                    observed += len(chunk)
                    require(observed <= MAX_ARTIFACT_BYTES, "artifact grew beyond bound")
                    actual.update(chunk)
                require(observed == before.st_size and
                        identity_fn(before) == identity_fn(os.fstat(handle.fileno())),
                        "artifact changed during read")
                require(actual.hexdigest() == digest, "artifact content digest mismatch")
                total += observed
            verified.append({"name": artifact["name"], "sha256": digest, "bytes": observed})
    finally:
        os.close(root_fd)
    return verified
