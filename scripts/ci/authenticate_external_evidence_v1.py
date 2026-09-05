#!/usr/bin/env python3
"""Offline, pinned-policy Ed25519 authentication of external evidence v1.

This verifies a signed envelope and local content, NOT the truth of a physical
campaign, policy enrollment, independent acceptance, or permission to release.
No trust keys or production acceptance defaults are bundled with this tool.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
from typing import Any

import check_external_evidence_v1 as intake
from external_evidence_auth_common_v1 import (
    AuthenticationError, ED25519_SPKI, MAX_ARTIFACTS, MAX_ARTIFACT_BYTES,
    MAX_TOTAL_ARTIFACT_BYTES,
    MAX_JSON_BYTES, PROFILE, body_digest, decode_json, exact_fields,
    file_identity, hex_bytes, identity, read_document, require,
    signature_message, timestamp, validate_json_tree,
)
from external_evidence_auth_verify_v1 import load_policy, verify_artifacts


from external_evidence_auth_crypto_v1 import verify_ed25519

def authenticate(row: dict[str, Any], policy_raw: bytes, policy_sha256: str,
                 artifact_directory: pathlib.Path, source_commit: str, source_tree: str,
                 as_of: str) -> dict[str, Any]:
    """Return authentication facts only; policy enrollment remains a trusted input."""
    hex_bytes(source_commit, 20, "source commit")
    hex_bytes(source_tree, 20, "source tree")
    now = timestamp(as_of)
    keys = load_policy(policy_raw, policy_sha256, now)
    digest = body_digest(row)
    require(row["source_commit"] == source_commit and row["source_tree"] == source_tree,
            "evidence source identity mismatch")
    require(timestamp(row["started_at"]) <= timestamp(row["ended_at"]) <= now,
            "evidence time interval invalid or in the future")
    require(type(row["wall_clock_seconds"]) is int, "wall clock must be an integer")
    if "notes" in row:
        require(isinstance(row["notes"], str), "notes must be a string")
    # Reuse the existing declaration contract; the path is a diagnostic label only.
    label = intake.ROOT / "offline-authentication-input.json"
    try:
        intake.validate_common(label, row, set(intake.SCOPES))
        if row["result"] == "accepted":
            intake.validate_specific(label, row)
    except (intake.EvidenceError, TypeError, ValueError, KeyError) as error:
        raise AuthenticationError(f"invalid evidence declaration: {error}") from error
    numeric_claims = {
        "replayed_p0_mutants", "physical_hosts", "operators", "custody_domains",
        "conflicting_finality_count", "double_sign_count", "rollback_mutants_rejected",
        "cloned_namespace_mutants_rejected", "open_critical", "open_high",
        "chaos_72h_seconds", "public_testnet_7d_seconds", "production_candidate_30d_seconds",
    }
    for name in numeric_claims & set(row["claims"]):
        require(type(row["claims"][name]) is int and row["claims"][name] >= 0,
                "claim counter must be a nonnegative integer")
    if "node_counts" in row["claims"]:
        counts = row["claims"]["node_counts"]
        require(isinstance(counts, list) and len(counts) <= 256
                and all(type(count) is int and count > 0 for count in counts), "invalid node counts")
        require(len(counts) == len(set(counts)), "duplicate node count")
    artifacts = row["artifacts"]
    require(len(artifacts) <= MAX_ARTIFACTS, "artifact count out of bounds")
    names, digests = set(), set()
    for artifact in artifacts:
        exact_fields(artifact, {"name", "sha256", "immutable_uri"})
        hex_bytes(artifact["sha256"], 32, "artifact digest")
        require(artifact["name"] not in names and artifact["sha256"] not in digests,
                "duplicate artifact name/content")
        require(artifact["immutable_uri"] == "urn:sha256:" + artifact["sha256"],
                "authentication requires content-addressed artifact URNs")
        names.add(artifact["name"])
        digests.add(artifact["sha256"])
    signatures = row["signatures"]
    require(len(signatures) == 2, "exactly two role signatures required")
    expected = {identity(row["producer"]): "producer", identity(row["independent_reviewer"]): "reviewer"}
    require(len(expected) == 2, "producer and reviewer must differ")
    observed: set[str] = set()
    domains: set[str] = set()
    for signature in signatures:
        exact_fields(signature, {"signer", "algorithm", "signature", "signed_digest"})
        name = identity(signature["signer"])
        require(name in expected and name not in observed and name in keys, "unknown/duplicate signer")
        key = keys[name]
        role = expected[name]
        require(key["role"] == role and row["blocker_id"] in key["blocker_ids"], "signer role/scope mismatch")
        require(not key["revoked"], "signing key revoked")
        require(timestamp(key["valid_from"]) <= timestamp(row["ended_at"]) <= now <= timestamp(key["valid_until"]),
                "signing key outside validity interval")
        require(key["independence_domain"] not in domains, "producer/reviewer trust domains overlap")
        require(signature["algorithm"] == PROFILE, "unsupported signature profile")
        require(signature["signed_digest"] == digest, "signed body digest mismatch")
        verify_ed25519(hex_bytes(key["public_key_hex"], 32, "public key"),
                       hex_bytes(signature["signature"], 64, "signature"),
                       signature_message(digest, policy_sha256, name, role))
        observed.add(name)
        domains.add(key["independence_domain"])
    verified_artifacts = verify_artifacts(
        artifacts, artifact_directory,
        max_total_artifact_bytes=MAX_TOTAL_ARTIFACT_BYTES,
        identity_fn=file_identity,
    )
    return {
        "schema": "trnm-external-evidence-authentication-v1", "evidence_id": row["evidence_id"],
        "blocker_id": row["blocker_id"], "declared_result": row["result"],
        "source_commit": source_commit, "source_tree": source_tree, "body_digest": digest,
        "trust_policy_sha256": policy_sha256, "verification_time": as_of,
        "signature_profile": PROFILE, "verified_signers": sorted(observed),
        "signatures_verified": True, "artifact_content_verified": True,
        "artifacts": verified_artifacts, "trust_policy_enrollment": "caller-trusted-not-verified",
        "physical_claims_verified": False, "independent_acceptance": "not-assessed",
        "accepted": {}, "all_external_blockers_closed": False,
        "production_candidate": False, "production_consensus_activation": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--submission", type=pathlib.Path, required=True)
    parser.add_argument("--trust-policy", type=pathlib.Path, required=True)
    parser.add_argument("--trust-policy-sha256", required=True)
    parser.add_argument("--artifact-directory", type=pathlib.Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--as-of", required=True)
    args = parser.parse_args()
    try:
        result = authenticate(decode_json(read_document(args.submission)), read_document(args.trust_policy),
                              args.trust_policy_sha256, args.artifact_directory,
                              args.source_commit, args.source_tree, args.as_of)
    except (AuthenticationError, OSError) as error:
        print(f"external evidence authentication failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
