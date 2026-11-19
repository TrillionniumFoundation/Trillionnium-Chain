#!/usr/bin/env python3
"""Verify the original sealed CI package after its ZIPs move to Git history.

The original SHA256SUMS, SEAL, artifact index, outcomes and retained payloads
remain unchanged. This reader checks every original checksum entry, resolving
only explicitly archived ZIPs and the original storage README from the pinned
Git snapshot. Missing current files are errors, never an archive fallback.
No files are restored, archives extracted, helpers run or observations rerun.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

import check_historical_archive as history


CONTROL_FILES = frozenset({
    "ARTIFACT_INDEX.json", "FILES.json", "GATE_CORE.json", "OBSERVER_NOTES.json",
    "SEAL.json", "SHA256SUMS",
})
SEAL_SCHEMA = "trnm-final819-core-evidence-seal-v1"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def checksum_rows(raw):
    result = {}
    for line in raw.decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        history.require(match is not None, "invalid original checksum line")
        sha, name = match.groups()
        history.canonical(name)
        history.require(name not in result, "duplicate original checksum path")
        result[name] = sha
    history.require(result, "empty original checksum list")
    return result


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
                    "sealed CI archive must cover the complete archives directory")
    original = history.tree_rows(root, data["source_commit"], [package])
    archived = {row["path"]: row for row in data["files"]}
    manifests = {row["path"]: row for row in data["historical_manifests"]}
    preserved = {row["path"] for row in data["preserved_files"]}
    history.require({prefix + name for name in CONTROL_FILES} <= preserved,
                    "original sealed controls must remain byte-identical")
    history.require(prefix + "README.md" in manifests,
                    "original storage README must be indexed")
    history.require(all(name.endswith(".zip") for name in archived),
                    "sealed CI archive includes a non-ZIP payload")

    observed = set()
    for path in (root / package).rglob("*"):
        history.require(not path.is_symlink(), "symlink in current sealed package")
        if path.is_file():
            observed.add(path.relative_to(root).as_posix())
    history.require(observed == (set(original) - set(archived)) | {index_name},
                    "current sealed package has missing or extra files")

    def current(name):
        full = prefix + name
        raw = history.local_file(root, full).read_bytes()
        source = original.get(full)
        history.require(source is not None, "unbound retained original file: " + name)
        oid = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        history.require(len(raw) == source["bytes"] and oid == source["blob"],
                        "retained original bytes differ: " + name)
        return raw

    seal_raw = current("SEAL.json")
    seal = json.loads(seal_raw, object_pairs_hook=history.unique)
    history.require(seal.get("schema") == SEAL_SCHEMA and seal.get("verdict") == "HOLD",
                    "unsupported or promoted original CI seal")
    sums_raw = current("SHA256SUMS")
    history.require((len(sums_raw), digest(sums_raw))
                    == (seal["sha256sums_bytes"], seal["sha256sums_sha256"]),
                    "original seal/checksum binding differs")
    checksums = checksum_rows(sums_raw)
    expected = {name[len(prefix):] for name in original} - {"SEAL.json", "SHA256SUMS"}
    history.require(set(checksums) == expected, "original checksum roster is incomplete")
    verified = {}
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
        verified[name] = observed_identity
    history.require(type(seal["payload_files"]) is int
                    and seal["payload_files"] == len(verified)
                    and type(seal["payload_bytes"]) is int
                    and seal["payload_bytes"] == sum(size for size, _ in verified.values()),
                    "original sealed payload totals differ")
    history.require(seal["archives"] == seal["core_lane_count"] == len(archived)
                    and seal["archive_bytes"] == sum(row["bytes"] for row in archived.values()),
                    "original archive/lane denominator differs")

    core_raw = current("GATE_CORE.json")
    history.require((len(core_raw), digest(core_raw))
                    == (seal["gate_core_bytes"], seal["gate_core_sha256"]),
                    "original gate core binding differs")
    core = json.loads(core_raw, object_pairs_hook=history.unique)
    history.require(core["verdict"] == "HOLD" and core["candidate"] == seal["candidate"]
                    and core["workflow_jobs"]["total"] == seal["workflow_jobs"]
                    and core["native_lanes"]["total"] == seal["native_lanes"],
                    "original outcome identity or denominators differ")
    artifacts = json.loads(current("ARTIFACT_INDEX.json"), object_pairs_hook=history.unique)
    history.require(isinstance(artifacts, list) and len(artifacts) == len(archived),
                    "original artifact roster differs")
    seen = set()
    for item in artifacts:
        name = history.canonical(item["archive"])
        full = prefix + name
        history.require(full in archived and name not in seen, "unbound or duplicate original artifact")
        seen.add(name)
        metadata = item["github_metadata"]
        history.require(type(item["artifact_id"]) is int
                        and metadata["id"] == item["artifact_id"]
                        and name == "archives/" + str(item["artifact_id"]) + ".zip"
                        and metadata["size_in_bytes"] == archived[full]["bytes"]
                        and metadata["digest"] == "sha256:" + archived[full]["sha256"]
                        and metadata["workflow_run"]["head_sha"] == seal["candidate"],
                        "original GitHub artifact binding differs")
        history.require(history.canonical(item["readback"]) in checksums,
                        "original artifact readback missing from sealed roster")
    history.require(history.local_file(root, index_name).read_bytes() == captured,
                    "archive index changed during package validation")
    return dict(archived_report, original_sealed_payload_files=len(verified),
                original_sealed_payload_bytes=seal["payload_bytes"],
                original_artifact_bindings=len(artifacts), original_gate_verdict=core["verdict"],
                original_workflow_jobs=core["workflow_jobs"], original_native_lanes=core["native_lanes"],
                original_checksums_verified=True, archived_helpers_executed=False,
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
        print("Sealed CI archive check failed: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
