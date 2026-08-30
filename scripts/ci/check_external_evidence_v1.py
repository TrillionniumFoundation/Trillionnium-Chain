#!/usr/bin/env python3
"""Validate external blocker evidence without converting absence into a claim."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any, Mapping
from urllib.parse import parse_qsl, unquote, urlsplit

ROOT = pathlib.Path(__file__).resolve().parents[2]
SUBMISSIONS = ROOT / "docs/evidence/external/submissions"
SIGNER_REGISTRY = ROOT / "docs/evidence/external/SIGNER_KEY_REGISTRY_V1.json"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
URI_DIGEST = re.compile(r"^urn:trnm:artifact:sha256:([0-9a-f]{64})$")
SIGNATURE_DOMAIN = b"trnm.external-evidence.signature.v1\0"
EVIDENCE_DIGEST_DOMAIN = b"trnm.external-evidence.envelope.v1\0"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
REGISTRY_SCHEMA = "trnm-external-evidence-signer-registry-v1"
REGISTRY_ROLES = {
    "producer",
    "independent_reviewer",
    "operator",
    "custodian",
    "auditor",
    "governance",
}

COMMON_KEYS = {
    "schema",
    "evidence_id",
    "blocker_id",
    "source_commit",
    "source_tree",
    "producer",
    "independent_reviewer",
    "independence_declaration",
    "scope",
    "result",
    "started_at",
    "ended_at",
    "wall_clock_seconds",
    "artifacts",
    "signatures",
    "claims",
    "evidence_digest",
    "signer_registry_sha256",
    "notes",
}


class EvidenceError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def display_path(path: pathlib.Path, root: pathlib.Path = ROOT) -> str:
    """Render a path without assuming that tests keep it under ``ROOT``."""

    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate names instead of silently accepting the last value."""

    value: dict[str, object] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key {key!r}")
        value[key] = child
    return value


def reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r} is forbidden")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_json_object,
            parse_constant=reject_json_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise EvidenceError(f"{display_path(path)}: invalid JSON: {exc}") from exc
    require(isinstance(value, dict), f"{display_path(path)}: top level must be object")
    return value


def canonical_json(value: object, label: str) -> bytes:
    """Encode one deterministic, finite JSON value for digest/signature use."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise EvidenceError(f"{label}: cannot canonicalize JSON: {exc}") from exc


def envelope_digest(row: Mapping[str, Any]) -> str:
    """Return the digest signed by every external-evidence signer.

    Signatures and the digest field itself are excluded from the preimage so
    that multiple independent signers can attest to one stable envelope.
    The domain prefix prevents a digest from being replayed as another TRNM
    object or protocol signature.
    """

    unsigned = {
        key: value
        for key, value in row.items()
        if key not in {"signatures", "evidence_digest"}
    }
    return hashlib.sha256(EVIDENCE_DIGEST_DOMAIN + canonical_json(unsigned, "evidence envelope")).hexdigest()


def git_output(git_root: pathlib.Path, *arguments: str) -> str:
    """Run a read-only Git query and fail closed on any ambiguity."""

    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=git_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvidenceError(f"Git source-object verification unavailable: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown Git error"
        raise EvidenceError(f"Git source-object verification failed: {detail}")
    return result.stdout.strip()


def validate_source_binding(
    path: pathlib.Path,
    row: Mapping[str, Any],
    *,
    git_root: pathlib.Path = ROOT,
) -> None:
    """Prove that the advertised commit and tree are real matching Git objects."""

    prefix = display_path(path)
    commit = row.get("source_commit")
    tree = row.get("source_tree")
    require(isinstance(commit, str) and HEX40.fullmatch(commit),
            f"{prefix}: source_commit must be 40 lowercase hex")
    require(isinstance(tree, str) and HEX40.fullmatch(tree),
            f"{prefix}: source_tree must be 40 lowercase hex")

    validate_source_pair(commit, tree, prefix=prefix, git_root=git_root)


def validate_source_pair(
    commit: str,
    tree: str,
    *,
    prefix: str,
    git_root: pathlib.Path = ROOT,
) -> None:
    """Validate a source tuple supplied on the command line."""

    require(HEX40.fullmatch(commit) is not None,
            f"{prefix}: source_commit must be 40 lowercase hex")
    require(HEX40.fullmatch(tree) is not None,
            f"{prefix}: source_tree must be 40 lowercase hex")
    resolved_commit = git_output(git_root, "rev-parse", "--verify", f"{commit}^{{commit}}")
    require(resolved_commit == commit,
            f"{prefix}: source_commit is not an exact local commit object")
    resolved_tree = git_output(git_root, "rev-parse", "--verify", f"{commit}^{{tree}}")
    require(resolved_tree == tree,
            f"{prefix}: source_tree does not match source_commit tree")
    tree_type = git_output(git_root, "cat-file", "-t", tree)
    require(tree_type == "tree", f"{prefix}: source_tree is not a Git tree object")


def parse_uri_digest(uri: str, prefix: str) -> str:
    """Extract the required SHA-256 binding from an immutable artifact URI.

    A bare URL is intentionally not enough: the server may replace its bytes.
    We accept a canonical TRNM URN, a ``/sha256/<digest>`` path component, or
    one unambiguous ``sha256=<digest>`` query/fragment parameter on an HTTPS,
    IPFS, or file URI.
    """

    require(isinstance(uri, str) and uri and "REPLACE" not in uri,
            f"{prefix}: immutable_uri invalid")
    require(uri == uri.strip() and not any(ord(ch) < 0x20 for ch in uri),
            f"{prefix}: immutable_uri contains whitespace/control bytes")
    urn_match = URI_DIGEST.fullmatch(uri)
    if urn_match:
        return urn_match.group(1)

    try:
        parsed = urlsplit(uri)
    except ValueError as exc:
        raise EvidenceError(f"{prefix}: immutable_uri is malformed") from exc
    require(parsed.scheme in {"https", "ipfs", "file"},
            f"{prefix}: immutable_uri must use HTTPS, IPFS, file, or TRNM URN")
    require(parsed.netloc or parsed.scheme == "file",
            f"{prefix}: immutable_uri authority is required")
    require(parsed.username is None and parsed.password is None,
            f"{prefix}: immutable_uri credentials are forbidden")

    candidates: list[str] = []
    segments = [unquote(part) for part in parsed.path.split("/") if part]
    for index, segment in enumerate(segments[:-1]):
        if segment.lower() == "sha256" and HEX64.fullmatch(segments[index + 1]):
            candidates.append(segments[index + 1])

    for component_name, component in (("query", parsed.query), ("fragment", parsed.fragment)):
        if not component:
            continue
        try:
            pairs = parse_qsl(component, keep_blank_values=True, strict_parsing=True)
        except ValueError as exc:
            raise EvidenceError(f"{prefix}: immutable_uri {component_name} is malformed") from exc
        values = [value for key, value in pairs if key.lower() == "sha256"]
        require(len(values) <= 1,
                f"{prefix}: immutable_uri has duplicate sha256 bindings")
        if values:
            require(HEX64.fullmatch(values[0]) is not None,
                    f"{prefix}: immutable_uri sha256 binding is invalid")
            candidates.append(values[0])

    require(candidates, f"{prefix}: immutable_uri must carry a SHA-256 binding")
    require(len(set(candidates)) == 1,
            f"{prefix}: immutable_uri carries conflicting SHA-256 bindings")
    return candidates[0]


def safe_local_path(value: object, prefix: str, *, root: pathlib.Path = ROOT) -> pathlib.Path:
    """Resolve an optional artifact path without permitting workspace escape."""

    require(isinstance(value, str) and value and "\\" not in value,
            f"{prefix}: local_path must be a POSIX relative path")
    candidate = pathlib.PurePosixPath(value)
    require(not candidate.is_absolute() and all(part not in {"", ".", ".."} for part in candidate.parts),
            f"{prefix}: local_path escapes repository root")
    root_resolved = root.resolve()
    try:
        path = (root / pathlib.Path(candidate.as_posix())).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise EvidenceError(f"{prefix}: local_path cannot be resolved: {exc}") from exc
    require(path.is_relative_to(root_resolved),
            f"{prefix}: local_path resolves outside repository root")
    require(path.is_file(), f"{prefix}: local_path must reference a regular file")
    return path


def sha256_file(path: pathlib.Path, prefix: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                size += len(chunk)
                require(size <= MAX_ARTIFACT_BYTES,
                        f"{prefix}: local artifact exceeds size limit")
                digest.update(chunk)
    except OSError as exc:
        raise EvidenceError(f"{prefix}: cannot read local artifact: {exc}") from exc
    return digest.hexdigest(), size


def load_signer_registry(path: pathlib.Path) -> tuple[dict[str, dict[str, Any]], str]:
    """Load the explicit external signer allow-list and its canonical digest."""

    document = read_json(path)
    prefix = display_path(path)
    require(set(document) == {"schema", "version", "signers"},
            f"{prefix}: signer registry keys must be exactly ['schema', 'signers', 'version']")
    require(document.get("schema") == REGISTRY_SCHEMA,
            f"{prefix}: signer registry schema drift")
    require(document.get("version") == 1,
            f"{prefix}: signer registry version must be 1")
    signers = document.get("signers")
    require(isinstance(signers, list), f"{prefix}: signers must be an array")
    by_key: dict[str, dict[str, Any]] = {}
    identities: set[str] = set()
    for index, entry in enumerate(signers):
        field = f"{prefix}: signers[{index}]"
        require(isinstance(entry, dict), f"{field} must be an object")
        required = {"signer", "key_id", "algorithm", "public_key", "roles", "active"}
        require(set(entry) == required,
                f"{field} keys must be exactly {sorted(required)!r}")
        signer = entry["signer"]
        key_id = entry["key_id"]
        require(isinstance(signer, str) and signer,
                f"{field}.signer is required")
        require(isinstance(key_id, str) and KEY_ID.fullmatch(key_id),
                f"{field}.key_id is invalid")
        require(key_id not in by_key, f"{field}.key_id is duplicated")
        require(signer not in identities, f"{field}.signer is duplicated")
        require(entry["algorithm"] == "ed25519-sha256-v1",
                f"{field}.algorithm must be ed25519-sha256-v1")
        public_key = entry["public_key"]
        require(isinstance(public_key, str) and HEX64.fullmatch(public_key),
                f"{field}.public_key must be 32-byte lowercase hex")
        require(public_key != "0" * 64,
                f"{field}.public_key must not be all zeroes")
        roles = entry["roles"]
        require(isinstance(roles, list) and roles and all(isinstance(role, str) for role in roles),
                f"{field}.roles must be a non-empty string array")
        require(set(roles) <= REGISTRY_ROLES and len(set(roles)) == len(roles),
                f"{field}.roles contains an unknown or duplicate role")
        require(isinstance(entry["active"], bool), f"{field}.active must be boolean")
        by_key[key_id] = entry
        identities.add(signer)
    digest = hashlib.sha256(
        b"trnm.external-evidence.signer-registry.v1\0"
        + canonical_json(document, "signer registry")
    ).hexdigest()
    return by_key, digest


def verify_ed25519(public_key: str, message: bytes, signature: str, field: str) -> None:
    """Verify one raw Ed25519 signature using the pinned OpenSSL interface."""

    require(HEX64.fullmatch(public_key) is not None,
            f"{field}: public key must be 32-byte lowercase hex")
    require(HEX128.fullmatch(signature) is not None,
            f"{field}: signature must be 64-byte lowercase hex")
    try:
        with tempfile.TemporaryDirectory(prefix="trnm-external-evidence-") as temporary:
            root = pathlib.Path(temporary)
            (root / "public.der").write_bytes(ED25519_SPKI_PREFIX + bytes.fromhex(public_key))
            (root / "message.bin").write_bytes(message)
            (root / "signature.bin").write_bytes(bytes.fromhex(signature))
            result = subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                    "-keyform", "DER", "-inkey", str(root / "public.der"),
                    "-in", str(root / "message.bin"), "-sigfile", str(root / "signature.bin"),
                ],
                check=False,
                capture_output=True,
                timeout=10,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvidenceError(f"{field}: Ed25519 verifier unavailable: {exc}") from exc
    require(result.returncode == 0, f"{field}: Ed25519 signature is invalid")


def parse_time(value: Any, label: str) -> dt.datetime:
    require(isinstance(value, str), f"{label}: expected RFC3339 string")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{label}: invalid RFC3339 time") from exc
    require(parsed.tzinfo is not None, f"{label}: timezone required")
    return parsed


def validate_common(
    path: pathlib.Path,
    row: dict[str, Any],
    allowed: set[str],
    *,
    signer_registry: Mapping[str, dict[str, Any]] | None = None,
    signer_registry_digest: str | None = None,
    git_root: pathlib.Path = ROOT,
) -> None:
    """Validate fields shared by every external evidence submission.

    The caller supplies the parsed signer registry so a single immutable
    allow-list is used for the complete scan.  Source-object and signature
    checks are deliberately performed for rejected records too: a rejected
    report is still an externally attributable observation, not an unsigned
    escape hatch.
    """

    prefix = display_path(path)
    if signer_registry is None or signer_registry_digest is None:
        signer_registry, signer_registry_digest = load_signer_registry(
            SIGNER_REGISTRY if git_root == ROOT else git_root / "docs/evidence/external/SIGNER_KEY_REGISTRY_V1.json"
        )
    unknown = set(row) - COMMON_KEYS
    require(not unknown, f"{prefix}: unknown top-level fields: {sorted(unknown)!r}")
    require(row.get("schema") == "trnm-external-evidence-v1", f"{prefix}: schema drift")
    require(row.get("blocker_id") in allowed, f"{prefix}: unknown blocker_id")
    require(isinstance(row.get("evidence_id"), str) and len(row["evidence_id"]) >= 8,
            f"{prefix}: invalid evidence_id")
    validate_source_binding(path, row, git_root=git_root)
    evidence_digest = row.get("evidence_digest")
    require(isinstance(evidence_digest, str) and HEX64.fullmatch(evidence_digest),
            f"{prefix}: evidence_digest must be 32-byte lowercase hex")
    require(evidence_digest == envelope_digest(row),
            f"{prefix}: evidence_digest does not match canonical envelope")
    registry_digest = row.get("signer_registry_sha256")
    require(isinstance(registry_digest, str) and HEX64.fullmatch(registry_digest),
            f"{prefix}: signer_registry_sha256 must be 32-byte lowercase hex")
    require(registry_digest == signer_registry_digest,
            f"{prefix}: signer registry digest does not match the checked registry")

    producer = row.get("producer")
    reviewer = row.get("independent_reviewer")
    require(isinstance(producer, str) and producer, f"{prefix}: producer required")
    require(isinstance(reviewer, str) and reviewer, f"{prefix}: independent reviewer required")
    require(producer != reviewer, f"{prefix}: producer and independent reviewer must differ")
    require(row.get("independence_declaration") is True,
            f"{prefix}: reviewer independence declaration required")
    require(row.get("result") in {"accepted", "rejected"}, f"{prefix}: invalid result")
    started = parse_time(row.get("started_at"), f"{prefix}: started_at")
    ended = parse_time(row.get("ended_at"), f"{prefix}: ended_at")
    require(ended >= started, f"{prefix}: ended_at precedes started_at")
    wall = row.get("wall_clock_seconds")
    require(isinstance(wall, int) and not isinstance(wall, bool) and wall >= 0,
            f"{prefix}: invalid wall_clock_seconds")
    actual = int((ended - started).total_seconds())
    require(abs(actual - wall) <= 1, f"{prefix}: wall clock does not match timestamps")

    artifacts = row.get("artifacts")
    require(isinstance(artifacts, list) and artifacts, f"{prefix}: immutable artifacts required")
    artifact_names: set[str] = set()
    for index, artifact in enumerate(artifacts):
        field = f"{prefix}: artifact {index}"
        require(isinstance(artifact, dict), f"{field} must be object")
        allowed_artifact_keys = {"name", "sha256", "immutable_uri", "local_path", "bytes"}
        require(set(artifact) <= allowed_artifact_keys,
                f"{field} has unknown fields: {sorted(set(artifact) - allowed_artifact_keys)!r}")
        name = artifact.get("name")
        require(isinstance(name, str) and name, f"{field} name required")
        require(name not in artifact_names, f"{prefix}: duplicate artifact name {name!r}")
        artifact_names.add(name)
        digest = artifact.get("sha256")
        require(isinstance(digest, str) and HEX64.fullmatch(digest),
                f"{field} sha256 invalid")
        uri = artifact.get("immutable_uri")
        uri_digest = parse_uri_digest(uri, f"{field}.immutable_uri")
        require(uri_digest == digest,
                f"{field}: immutable_uri digest does not match sha256")
        if "local_path" in artifact:
            local = safe_local_path(artifact["local_path"], f"{field}.local_path", root=git_root)
            observed_digest, observed_bytes = sha256_file(local, field)
            require(observed_digest == digest,
                    f"{field}: local_path bytes do not match sha256")
            if "bytes" in artifact:
                size = artifact["bytes"]
                require(isinstance(size, int) and not isinstance(size, bool) and size >= 0,
                        f"{field}.bytes must be a non-negative integer")
                require(size == observed_bytes, f"{field}: bytes does not match local_path")
        elif "bytes" in artifact:
            size = artifact["bytes"]
            require(isinstance(size, int) and not isinstance(size, bool) and size >= 0,
                    f"{field}.bytes must be a non-negative integer")

    signatures = row.get("signatures")
    require(isinstance(signatures, list) and len(signatures) >= 2,
            f"{prefix}: producer and reviewer signatures required")
    signer_ids: set[str] = set()
    key_ids: set[str] = set()
    signed_digests: set[str] = set()
    signature_message = SIGNATURE_DOMAIN + bytes.fromhex(evidence_digest)
    for index, signature in enumerate(signatures):
        field = f"{prefix}: signature {index}"
        require(isinstance(signature, dict), f"{field} must be object")
        expected_keys = {"signer", "key_id", "algorithm", "signature", "signed_digest"}
        require(set(signature) == expected_keys,
                f"{field} keys must be exactly {sorted(expected_keys)!r}")
        signer = signature["signer"]
        key_id = signature["key_id"]
        require(isinstance(signer, str) and signer, f"{field}.signer required")
        require(isinstance(key_id, str) and KEY_ID.fullmatch(key_id),
                f"{field}.key_id invalid")
        require(signer not in signer_ids, f"{prefix}: duplicate signer {signer!r}")
        require(key_id not in key_ids, f"{prefix}: duplicate signer key_id {key_id!r}")
        signer_ids.add(signer)
        key_ids.add(key_id)
        registry_entry = signer_registry.get(key_id)
        require(registry_entry is not None,
                f"{field}: key_id is not present in the active signer registry")
        require(registry_entry["active"] is True,
                f"{field}: signer key is inactive or revoked")
        require(registry_entry["signer"] == signer,
                f"{field}: signer does not match registry key_id")
        require(signature["algorithm"] == "ed25519-sha256-v1",
                f"{field}.algorithm must be ed25519-sha256-v1")
        require(registry_entry["algorithm"] == signature["algorithm"],
                f"{field}: algorithm differs from signer registry")
        digest = signature["signed_digest"]
        require(isinstance(digest, str) and HEX64.fullmatch(digest),
                f"{field}.signed_digest invalid")
        require(digest == evidence_digest,
                f"{field}: signature covers a different evidence digest")
        signed_digests.add(digest)
        signature_bytes = signature["signature"]
        require(isinstance(signature_bytes, str) and HEX128.fullmatch(signature_bytes),
                f"{field}.signature must be 64-byte lowercase hex")
        verify_ed25519(registry_entry["public_key"], signature_message, signature_bytes, field)
    require(producer in signer_ids and reviewer in signer_ids,
            f"{prefix}: both producer and reviewer must sign")
    require(len(signed_digests) == 1, f"{prefix}: signatures do not cover one digest")
    producer_key_ids = {signature["key_id"] for signature in signatures if signature["signer"] == producer}
    reviewer_key_ids = {signature["key_id"] for signature in signatures if signature["signer"] == reviewer}
    require(len(producer_key_ids) == 1 and len(reviewer_key_ids) == 1,
            f"{prefix}: producer/reviewer signature identity is ambiguous")
    producer_entry = signer_registry[next(iter(producer_key_ids))]
    reviewer_entry = signer_registry[next(iter(reviewer_key_ids))]
    require("producer" in producer_entry["roles"],
            f"{prefix}: producer key is not registered for producer role")
    require("independent_reviewer" in reviewer_entry["roles"],
            f"{prefix}: reviewer key is not registered for independent_reviewer role")
    require(producer_key_ids.isdisjoint(reviewer_key_ids),
            f"{prefix}: producer and reviewer key IDs must differ")
    claims = row.get("claims")
    require(isinstance(claims, dict), f"{prefix}: claims must be object")
    if "notes" in row:
        require(isinstance(row["notes"], str), f"{prefix}: notes must be a string")


def validate_specific(path: pathlib.Path, row: dict[str, Any]) -> None:
    prefix = display_path(path)
    claims = row["claims"]
    blocker = row["blocker_id"]

    if blocker == "EXT-REVIEW-001":
        require(row.get("scope") == "review", f"{prefix}: review evidence scope mismatch")
        require(isinstance(claims.get("package_digest"), str) and
                HEX64.fullmatch(claims["package_digest"]),
                f"{prefix}: package_digest required")
        require(isinstance(claims.get("interface_digest"), str) and
                HEX64.fullmatch(claims["interface_digest"]),
                f"{prefix}: interface_digest required")
        require(isinstance(claims.get("replayed_p0_mutants"), int) and
                not isinstance(claims["replayed_p0_mutants"], bool) and
                claims["replayed_p0_mutants"] > 0,
                f"{prefix}: independently replayed P0 mutant count required")
        require(isinstance(claims.get("downstream_invalidation"), list),
                f"{prefix}: downstream invalidation set required")

    elif blocker == "EXT-G1-CAMPAIGN-001":
        require(row.get("scope") == "network", f"{prefix}: campaign scope mismatch")
        node_counts = claims.get("node_counts", [])
        require(isinstance(node_counts, list) and
                all(isinstance(value, int) and not isinstance(value, bool) for value in node_counts) and
                set(node_counts) >= {4, 7, 31, 100},
                f"{prefix}: real 4/7/31/100 process runs required")
        require(isinstance(claims.get("physical_hosts"), int) and
                not isinstance(claims["physical_hosts"], bool) and claims["physical_hosts"] >= 3,
                f"{prefix}: at least three physical hosts")
        require(isinstance(claims.get("operators"), int) and
                not isinstance(claims["operators"], bool) and claims["operators"] >= 2,
                f"{prefix}: multiple operators required")
        require(isinstance(claims.get("custody_domains"), int) and
                not isinstance(claims["custody_domains"], bool) and claims["custody_domains"] >= 2,
                f"{prefix}: multiple custody domains required")
        require(claims.get("real_processes") is True, f"{prefix}: real processes required")
        require(claims.get("signed_raw_traces") is True, f"{prefix}: signed raw traces required")
        for key in ("partition_heal", "restart_recovery", "state_sync", "epoch_key_rotation"):
            require(claims.get(key) is True, f"{prefix}: {key} campaign required")
        require(claims.get("conflicting_finality_count") == 0,
                f"{prefix}: conflicting finality observed")
        require(claims.get("double_sign_count") == 0, f"{prefix}: double-sign observed")

    elif blocker == "EXT-ANCHOR-HSM-001":
        require(row.get("scope") == "custody", f"{prefix}: custody scope mismatch")
        require(claims.get("device_backed") is True, f"{prefix}: device-backed key required")
        require(claims.get("private_key_non_exportable") is True,
                f"{prefix}: non-exportable key required")
        require(claims.get("external_monotonic_anchor") is True,
                f"{prefix}: external monotonic anchor required")
        require(claims.get("quorum_custody") is True, f"{prefix}: quorum custody required")
        require(claims.get("rotation_rehearsed") is True, f"{prefix}: rotation required")
        require(claims.get("revocation_rehearsed") is True, f"{prefix}: revocation required")
        require(isinstance(claims.get("rollback_mutants_rejected"), int) and
                not isinstance(claims["rollback_mutants_rejected"], bool) and
                claims["rollback_mutants_rejected"] > 0,
                f"{prefix}: rollback mutants required")
        require(isinstance(claims.get("cloned_namespace_mutants_rejected"), int) and
                not isinstance(claims["cloned_namespace_mutants_rejected"], bool) and
                claims["cloned_namespace_mutants_rejected"] > 0,
                f"{prefix}: cloned-namespace mutants required")
        require(isinstance(claims.get("device_attestation_sha256"), str) and
                HEX64.fullmatch(claims["device_attestation_sha256"]),
                f"{prefix}: device attestation digest required")

    elif blocker == "EXT-POWERLOSS-001":
        require(row.get("scope") == "host", f"{prefix}: power-loss scope mismatch")
        require(claims.get("physical_power_interruption") is True,
                f"{prefix}: physical power interruption required")
        require(claims.get("host_reboot") is True, f"{prefix}: host reboot required")
        require(claims.get("controller_cache_loss") is True,
                f"{prefix}: controller-cache loss required")
        require(claims.get("independent_recovery_process") is True,
                f"{prefix}: independent recovery process required")
        require(claims.get("exact_root_readback") is True,
                f"{prefix}: exact root readback required")
        require(claims.get("sigkill_only") is False,
                f"{prefix}: SIGKILL-only evidence is insufficient")

    elif blocker == "EXT-AUDIT-001":
        require(row.get("scope") == "audit", f"{prefix}: audit scope mismatch")
        for key in ("consensus_audit", "cryptography_audit", "economic_audit", "red_team"):
            require(claims.get(key) is True, f"{prefix}: {key} required")
        require(claims.get("open_critical") == 0, f"{prefix}: open Critical finding")
        require(claims.get("open_high") == 0, f"{prefix}: open High finding")
        require(claims.get("all_findings_source_bound") is True,
                f"{prefix}: findings must be source-bound")

    elif blocker == "EXT-SOAK-ACTIVATION-001":
        require(row.get("scope") == "production", f"{prefix}: soak scope mismatch")
        require(isinstance(claims.get("chaos_72h_seconds"), int) and
                not isinstance(claims["chaos_72h_seconds"], bool) and
                claims["chaos_72h_seconds"] >= 72 * 60 * 60,
                f"{prefix}: 72-hour chaos duration not met")
        require(isinstance(claims.get("public_testnet_7d_seconds"), int) and
                not isinstance(claims["public_testnet_7d_seconds"], bool) and
                claims["public_testnet_7d_seconds"] >= 7 * 24 * 60 * 60,
                f"{prefix}: 7-day public-testnet duration not met")
        require(isinstance(claims.get("production_candidate_30d_seconds"), int) and
                not isinstance(claims["production_candidate_30d_seconds"], bool) and
                claims["production_candidate_30d_seconds"] >= 30 * 24 * 60 * 60,
                f"{prefix}: 30-day candidate duration not met")
        require(claims.get("simulated_time") is False,
                f"{prefix}: simulated time cannot satisfy soak")
        for key in ("incident_drill", "restore_drill", "key_rotation_drill",
                    "state_sync_drill", "authorized_governance_record"):
            require(claims.get(key) is True, f"{prefix}: {key} required")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-all", action="store_true")
    parser.add_argument("--source-commit")
    parser.add_argument("--source-tree")
    parser.add_argument(
        "--signer-registry",
        type=pathlib.Path,
        default=SIGNER_REGISTRY,
        help="explicit Ed25519 signer allow-list (default: repository registry)",
    )
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()

    policy = read_json(ROOT / "config/repository-policy-v1.json")
    allowed = set(policy["external_blockers"])
    require(allowed, "external blocker policy is empty")

    registry_path = args.signer_registry
    if not registry_path.is_absolute():
        registry_path = ROOT / registry_path
    signer_registry, registry_digest = load_signer_registry(registry_path)

    if args.require_all:
        require(args.source_commit and HEX40.fullmatch(args.source_commit),
                "--require-all needs a 40-hex --source-commit")
        require(args.source_tree and HEX40.fullmatch(args.source_tree),
                "--require-all needs a 40-hex --source-tree")
        validate_source_pair(
            args.source_commit,
            args.source_tree,
            prefix="--require-all source tuple",
        )

    files = sorted(SUBMISSIONS.glob("*.json")) if SUBMISSIONS.exists() else []
    accepted: dict[str, str] = {}
    rejected: dict[str, str] = {}
    seen_ids: set[str] = set()

    for path in files:
        row = read_json(path)
        validate_common(
            path,
            row,
            allowed,
            signer_registry=signer_registry,
            signer_registry_digest=registry_digest,
        )
        validate_specific(path, row)
        evidence_id = row["evidence_id"]
        require(evidence_id not in seen_ids, f"duplicate evidence_id {evidence_id}")
        seen_ids.add(evidence_id)
        blocker = row["blocker_id"]
        if args.require_all:
            require(row["source_commit"] == args.source_commit,
                    f"{display_path(path)}: stale source commit")
            require(row["source_tree"] == args.source_tree,
                    f"{display_path(path)}: stale source tree")
        if row["result"] == "accepted":
            require(blocker not in accepted, f"multiple accepted evidence files for {blocker}")
            accepted[blocker] = evidence_id
        else:
            rejected[blocker] = evidence_id

    open_blockers = sorted(allowed - set(accepted))
    report = {
        "schema": "trnm-external-evidence-validation-v1",
        "submission_count": len(files),
        "accepted": dict(sorted(accepted.items())),
        "rejected_latest": dict(sorted(rejected.items())),
        "open_blockers": open_blockers,
        "all_external_blockers_closed": not open_blockers,
        "production_candidate": False if open_blockers else
            policy["release_truth"]["production_candidate"],
        "production_consensus_activation": False if open_blockers else
            policy["release_truth"]["production_consensus_activation"],
    }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = args.output if args.output.is_absolute() else ROOT / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")

    if args.require_all and open_blockers:
        print("external evidence gate remains open: " + ", ".join(open_blockers),
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvidenceError as exc:
        print(f"external evidence validation failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
