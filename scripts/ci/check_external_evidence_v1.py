#!/usr/bin/env python3
"""Validate external blocker evidence without converting absence into a claim."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
SUBMISSIONS = ROOT / "docs/evidence/external/submissions"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class EvidenceError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{path.relative_to(ROOT)}: invalid JSON: {exc}") from exc
    require(isinstance(value, dict), f"{path.relative_to(ROOT)}: top level must be object")
    return value


def parse_time(value: Any, label: str) -> dt.datetime:
    require(isinstance(value, str), f"{label}: expected RFC3339 string")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{label}: invalid RFC3339 time") from exc
    require(parsed.tzinfo is not None, f"{label}: timezone required")
    return parsed


def validate_common(path: pathlib.Path, row: dict[str, Any], allowed: set[str]) -> None:
    prefix = str(path.relative_to(ROOT))
    require(row.get("schema") == "trnm-external-evidence-v1", f"{prefix}: schema drift")
    require(row.get("blocker_id") in allowed, f"{prefix}: unknown blocker_id")
    require(isinstance(row.get("evidence_id"), str) and len(row["evidence_id"]) >= 8,
            f"{prefix}: invalid evidence_id")
    require(isinstance(row.get("source_commit"), str) and HEX40.fullmatch(row["source_commit"]),
            f"{prefix}: source_commit must be 40 lowercase hex")
    require(isinstance(row.get("source_tree"), str) and HEX40.fullmatch(row["source_tree"]),
            f"{prefix}: source_tree must be 40 lowercase hex")
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
    require(isinstance(wall, int) and wall >= 0, f"{prefix}: invalid wall_clock_seconds")
    actual = int((ended - started).total_seconds())
    require(abs(actual - wall) <= 1, f"{prefix}: wall clock does not match timestamps")

    artifacts = row.get("artifacts")
    require(isinstance(artifacts, list) and artifacts, f"{prefix}: immutable artifacts required")
    for index, artifact in enumerate(artifacts):
        require(isinstance(artifact, dict), f"{prefix}: artifact {index} must be object")
        require(isinstance(artifact.get("name"), str) and artifact["name"],
                f"{prefix}: artifact {index} name required")
        require(isinstance(artifact.get("sha256"), str) and HEX64.fullmatch(artifact["sha256"]),
                f"{prefix}: artifact {index} sha256 invalid")
        uri = artifact.get("immutable_uri")
        require(isinstance(uri, str) and uri and "REPLACE" not in uri,
                f"{prefix}: artifact {index} immutable_uri invalid")

    signatures = row.get("signatures")
    require(isinstance(signatures, list) and len(signatures) >= 2,
            f"{prefix}: producer and reviewer signatures required")
    signers: set[str] = set()
    digests: set[str] = set()
    for index, signature in enumerate(signatures):
        require(isinstance(signature, dict), f"{prefix}: signature {index} must be object")
        signer = signature.get("signer")
        require(isinstance(signer, str) and signer, f"{prefix}: signature signer required")
        signers.add(signer)
        require(isinstance(signature.get("algorithm"), str) and signature["algorithm"],
                f"{prefix}: signature algorithm required")
        require(isinstance(signature.get("signature"), str) and
                len(signature["signature"]) >= 16 and "REPLACE" not in signature["signature"],
                f"{prefix}: signature bytes missing")
        digest = signature.get("signed_digest")
        require(isinstance(digest, str) and HEX64.fullmatch(digest),
                f"{prefix}: signed digest invalid")
        digests.add(digest)
    require(producer in signers and reviewer in signers,
            f"{prefix}: both producer and reviewer must sign")
    require(len(digests) == 1, f"{prefix}: signatures do not cover one digest")
    claims = row.get("claims")
    require(isinstance(claims, dict), f"{prefix}: claims must be object")


def validate_specific(path: pathlib.Path, row: dict[str, Any]) -> None:
    prefix = str(path.relative_to(ROOT))
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
                claims["replayed_p0_mutants"] > 0,
                f"{prefix}: independently replayed P0 mutant count required")
        require(isinstance(claims.get("downstream_invalidation"), list),
                f"{prefix}: downstream invalidation set required")

    elif blocker == "EXT-G1-CAMPAIGN-001":
        require(row.get("scope") == "network", f"{prefix}: campaign scope mismatch")
        require(set(claims.get("node_counts", [])) >= {4, 7, 31, 100},
                f"{prefix}: real 4/7/31/100 process runs required")
        require(claims.get("physical_hosts", 0) >= 3, f"{prefix}: at least three physical hosts")
        require(claims.get("operators", 0) >= 2, f"{prefix}: multiple operators required")
        require(claims.get("custody_domains", 0) >= 2,
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
        require(claims.get("rollback_mutants_rejected", 0) > 0,
                f"{prefix}: rollback mutants required")
        require(claims.get("cloned_namespace_mutants_rejected", 0) > 0,
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
        require(claims.get("chaos_72h_seconds", 0) >= 72 * 60 * 60,
                f"{prefix}: 72-hour chaos duration not met")
        require(claims.get("public_testnet_7d_seconds", 0) >= 7 * 24 * 60 * 60,
                f"{prefix}: 7-day public-testnet duration not met")
        require(claims.get("production_candidate_30d_seconds", 0) >= 30 * 24 * 60 * 60,
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
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()

    policy = read_json(ROOT / "config/repository-policy-v1.json")
    allowed = set(policy["external_blockers"])
    require(allowed, "external blocker policy is empty")

    files = sorted(SUBMISSIONS.glob("*.json")) if SUBMISSIONS.exists() else []
    accepted: dict[str, str] = {}
    rejected: dict[str, str] = {}
    seen_ids: set[str] = set()

    for path in files:
        row = read_json(path)
        validate_common(path, row, allowed)
        validate_specific(path, row)
        evidence_id = row["evidence_id"]
        require(evidence_id not in seen_ids, f"duplicate evidence_id {evidence_id}")
        seen_ids.add(evidence_id)
        blocker = row["blocker_id"]
        if args.require_all:
            require(args.source_commit and HEX40.fullmatch(args.source_commit),
                    "--require-all needs a 40-hex --source-commit")
            require(args.source_tree and HEX40.fullmatch(args.source_tree),
                    "--require-all needs a 40-hex --source-tree")
            require(row["source_commit"] == args.source_commit,
                    f"{path.relative_to(ROOT)}: stale source commit")
            require(row["source_tree"] == args.source_tree,
                    f"{path.relative_to(ROOT)}: stale source tree")
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
