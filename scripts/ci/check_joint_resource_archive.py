#!/usr/bin/env python3
"""Verify the unchanged joint-resource observation after archiving its containers.

Every original SHA256SUMS entry is checked. Only the explicitly indexed archive
containers and original README resolve from reachable Git objects; all other
original files must remain present and byte-identical. Archive/member summaries
remain historical records. No archive is extracted or executed, no observation
is repeated, and no work, service or production qualification is granted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

import check_historical_archive as history
from check_sealed_ci_archive import checksum_rows, digest


SCHEMA = "pon-joint-resource-evidence-index-v1"
QUALIFICATION_FLAGS = (
    "evidence_child_inherits_native_qualification",
    "all_legal_algorithm_cost_lower_bound_proved",
    "joint_classical_quantum_consensus_security_proved",
    "original_public_resource_acceptance_passed",
    "production_activation",
)
HISTORICAL_MANIFESTS = frozenset({"README.md", "SHA256SUMS", "artifacts.json"})


def validate(root: Path, index: Path):
    root = root.resolve()
    index = index.absolute()
    index_name = history.canonical(index.relative_to(root).as_posix())
    captured = history.local_file(root, index_name).read_bytes()
    archived_report, _ = history.validate(root, index)
    history.require(history.local_file(root, index_name).read_bytes() == captured,
                    "archive index changed while validating")
    data = json.loads(captured, object_pairs_hook=history.unique)
    package = history.canonical(index.parent.relative_to(root).as_posix())
    prefix = package + "/"
    history.require(data["scopes"] == [prefix + "archives"],
                    "joint-resource archive must cover the complete archives directory")
    original = history.tree_rows(root, data["source_commit"], [package])
    archived = {row["path"]: row for row in data["files"]}
    manifests = {row["path"]: row for row in data["historical_manifests"]}
    preserved = {row["path"] for row in data["preserved_files"]}
    history.require(set(manifests) == {prefix + name for name in HISTORICAL_MANIFESTS},
                    "original README, checksum list and artifact index must be bound")
    history.require(preserved == set(original) - set(archived) - {prefix + "README.md"},
                    "every original retained file must remain byte-identical")
    history.require(data["retained_copies"] == [], "unexpected replacement copies")
    history.require(all(name.endswith((".tar.gz", ".tar.xz", ".zip")) for name in archived),
                    "unsupported original archive container")
    observed = set()
    for path in (root / package).rglob("*"):
        history.require(not path.is_symlink(), "symlink in current joint-resource package")
        if path.is_file():
            observed.add(path.relative_to(root).as_posix())
    history.require(observed == ((set(original) - set(archived)) | {index_name}),
                    "current joint-resource package has missing or extra files")

    def current(name):
        full = prefix + name
        raw = history.local_file(root, full).read_bytes()
        source = original.get(full)
        history.require(source is not None, "unbound retained original file: " + name)
        oid = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        history.require(len(raw) == source["bytes"] and oid == source["blob"],
                        "retained original bytes differ: " + name)
        return raw

    sums_raw = current("SHA256SUMS")
    checksums = checksum_rows(sums_raw)
    expected = {name[len(prefix):] for name in original} - {"SHA256SUMS"}
    history.require(set(checksums) == expected, "original checksum roster is incomplete")
    payload_bytes = 0
    for name, expected_sha in checksums.items():
        full = prefix + name
        if full in archived:
            row = archived[full]
            observed_identity = row["bytes"], row["sha256"]
        elif name == "README.md":
            row = manifests[full]
            observed_identity = row["bytes"], row["sha256"]
        else:
            raw = current(name)
            observed_identity = len(raw), digest(raw)
        history.require(observed_identity == (original[full]["bytes"], expected_sha),
                        "original payload checksum differs: " + name)
        payload_bytes += observed_identity[0]

    artifacts = json.loads(current("artifacts.json"), object_pairs_hook=history.unique)
    history.require(artifacts["schema"] == SCHEMA, "wrong original artifact-index schema")
    for flag in QUALIFICATION_FLAGS:
        history.require(artifacts[flag] is False, "original artifact index promotes " + flag)
    records = artifacts["archives"]
    history.require(isinstance(records, list) and len(records) == len(archived)
                    and type(artifacts["archive_count"]) is int
                    and artifacts["archive_count"] == len(archived)
                    and type(artifacts["total_archive_bytes"]) is int
                    and artifacts["total_archive_bytes"] == sum(row["bytes"] for row in archived.values()),
                    "original archive denominator differs")
    seen, declared_members = set(), 0
    for record in records:
        name = history.canonical(record["path"])
        full = prefix + name
        history.require(full in archived and name not in seen,
                        "duplicate or unbound original artifact")
        seen.add(name)
        row = archived[full]
        history.require(name == "archives/" + record["file"]
                        and (record["bytes"], record["sha256"]) == (row["bytes"], row["sha256"]),
                        "original artifact identity differs")
        metadata_name = history.canonical(record["metadata"])
        history.require(metadata_name.startswith("inventories/") and metadata_name in checksums,
                        "unbound original archive metadata")
        metadata = json.loads(current(metadata_name), object_pairs_hook=history.unique)
        expected_metadata = {key: value for key, value in record.items()
                             if key not in {"path", "metadata", "scope"}}
        history.require(metadata == expected_metadata, "original artifact/metadata binding differs")
        history.require(type(record["file_count"]) is int and record["file_count"] > 0,
                        "invalid original member denominator")
        declared_members += record["file_count"]
    original_readme = history.git(root, "cat-file", "blob", manifests[prefix + "README.md"]["blob"])
    history.require(b"**HOLD / NO-GO.**" in original_readme, "original HOLD outcome is missing")
    crosscheck = json.loads(current("original-campaign-root-crosscheck.json"),
                           object_pairs_hook=history.unique)
    history.require(crosscheck["failure"] == "ORIGINAL_THREE_RUN_CAMPAIGN_FAILED"
                    and type(crosscheck["complete_campaigns"]) is int
                    and crosscheck["complete_campaigns"] == 0
                    and crosscheck["actual_campaigns"] == crosscheck["planned_campaigns"] == 3,
                    "original campaign failure or denominator differs")
    history.require(history.local_file(root, index_name).read_bytes() == captured,
                    "archive index changed during package validation")
    return dict(archived_report, original_checksums_verified=True,
                original_sealed_payload_files=len(checksums), original_sealed_payload_bytes=payload_bytes,
                original_artifact_bindings=len(records), original_declared_members=declared_members,
                original_gate_verdict="HOLD / NO-GO", original_complete_campaigns=0,
                original_planned_campaigns=3, archives_extracted=False,
                archive_members_rehashed=False, archived_helpers_executed=False,
                current_business_qualification=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.root, args.manifest), sort_keys=True))
        return 0
    except (history.Invalid, KeyError, TypeError, OSError, UnicodeError, ValueError) as error:
        print("Joint-resource archive check failed: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
