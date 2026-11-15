#!/usr/bin/env python3
"""Check every original PQ-authority file hash after archiving one old CI capture.

The complete capture is indexed in Git; all its smaller records remain as exact
retained copies. Four large byte streams are history-only. The original package
index, compression mappings, failed observations and live corpus pins are not
rewritten. No historical collector, native executable or campaign is executed.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import sys

import check_historical_archive as history


CAPTURE = "hosted-ci-native-triage-01/native-campaign-artifact-13610289272"
RETAINED = "hosted-ci-native-triage-01/retained-native-campaign-13610289272"
LARGE = frozenset({"original-artifact-13610289272.zip",
                   *(f"selected/run-{number}-raw/report.json" for number in (1, 2, 3))})
MANIFESTS = frozenset({"README.md", "artifact-index.json", "followup-archive-inventory.json"})
PRESERVED = frozenset({"artifact-index.json", "followup-archive-inventory.json", "external-artifacts.json",
                       "authority-final-validation-runner.py", "authority-integrated-validation-runner.py",
                       "authority-validation-runner.py", "quorum-red/receipt.json", "quorum-green/receipt.json",
                       "hosted-ci-native-triage-01/receipt.json", "hosted-ci-native-triage-01/findings.json",
                       "hosted-ci-final-readback-01/receipt.json"})
CORPUS = "config/pon/pq-cross-branch-corpus-v1.json"
HASH_ONLY_GZIP = frozenset({"root-quorum-research/commands.jsonl.gz",
                            "root-quorum-research/observations.jsonl.gz"})


def identity(row):
    history.require(isinstance(row, dict) and set(row) == {"bytes", "sha256"}
                    and type(row["bytes"]) is int and row["bytes"] >= 0
                    and isinstance(row["sha256"], str)
                    and re.fullmatch("[0-9a-f]{64}", row["sha256"]), "invalid original file identity")
    return row["bytes"], row["sha256"]


def validate(root: Path, index: Path):
    root = root.resolve()
    index = index.absolute()
    index_name = history.canonical(index.relative_to(root).as_posix())
    index_raw = history.local_file(root, index_name).read_bytes()
    report, _ = history.validate(root, index)
    history.require(history.local_file(root, index_name).read_bytes() == index_raw, "archive index changed")
    data = json.loads(index_raw, object_pairs_hook=history.unique)
    package = history.canonical(index.parent.relative_to(root).as_posix())
    prefix = package + "/"
    capture_prefix = prefix + CAPTURE + "/"
    history.require(data["scopes"] == [prefix + CAPTURE], "wrong original capture scope")
    original = history.tree_rows(root, data["source_commit"], [package])
    archived = {row["path"]: row for row in data["files"]}
    manifests = {row["path"]: row for row in data["historical_manifests"]}
    history.require(set(manifests) == {prefix + name for name in MANIFESTS}, "original indexes must be bound")
    large = {capture_prefix + name for name in LARGE}
    history.require(large <= set(archived), "missing original large capture files")
    copies = {row["archive_path"]: row["path"] for row in data["retained_copies"]}
    expected_copies = {name: prefix + RETAINED + "/" + name[len(capture_prefix):]
                       for name in set(archived) - large}
    history.require(copies == expected_copies, "all smaller capture records must remain as exact copies")
    history.require({prefix + name for name in PRESERVED}
                    <= {row["path"] for row in data["preserved_files"]}, "missing preserved controls")
    corpus = json.loads(history.local_file(root, CORPUS).read_bytes(), object_pairs_hook=history.unique)
    history.require(isinstance(corpus["pinned_blobs"], dict) and isinstance(corpus["required_paths"], list),
                    "invalid live PQ corpus")
    live = set(corpus["pinned_blobs"]) | set(corpus["required_paths"])
    history.require(not live.intersection(archived), "live PQ corpus consumes the archived capture")
    observed = set()
    for path in (root / package).rglob("*"):
        history.require(not path.is_symlink(), "symlink in current PQ-authority package")
        if path.is_file(): observed.add(path.relative_to(root).as_posix())
    history.require(observed == ((set(original) - set(archived)) | set(copies.values()) | {index_name}),
                    "missing or extra current PQ-authority files")

    def raw(name):
        full = prefix + history.canonical(name)
        if full in copies:
            value = history.local_file(root, copies[full]).read_bytes()
        elif full in archived or name == "README.md":
            value = history.git(root, "cat-file", "blob", original[full]["blob"])
        else:
            value = history.local_file(root, full).read_bytes()
        oid = hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest()
        history.require((len(value), oid) == (original[full]["bytes"], original[full]["blob"]),
                        "original bytes changed: " + name)
        return value

    artifact_index = json.loads(raw("artifact-index.json"), object_pairs_hook=history.unique)
    history.require(artifact_index["schema"] == "trnm-pq-authority-artifacts-v1"
                    and artifact_index["whole_chain_pq_qualified"] is False
                    and artifact_index["production_activation"] is False, "original PQ scope changed")
    files = artifact_index["files"]
    history.require(isinstance(files, dict)
                    and set(files) == {n[len(prefix):] for n in original} - {"artifact-index.json"},
                    "original package checksum roster is incomplete")
    checked = {}
    for name, expected in files.items():
        full = prefix + history.canonical(name)
        if full in archived:
            actual = archived[full]["bytes"], archived[full]["sha256"]
        elif name == "README.md":
            actual = manifests[full]["bytes"], manifests[full]["sha256"]
        else:
            value = raw(name)
            actual = len(value), hashlib.sha256(value).hexdigest()
        history.require(actual == identity(expected), "original file checksum differs: " + name)
        checked[name] = actual

    compression = artifact_index["compression"]
    history.require(isinstance(compression, dict), "invalid original compression map")
    decoded = {}
    for name, row in compression.items():
        history.require(name in checked and checked[name] == (row["compressed_bytes"], row["compressed_sha256"]),
                        "original compressed-file binding differs")
        source = row["uncompressed"]
        if "relative_path" in source:
            history.require(set(source) == {"bytes", "sha256", "relative_path"},
                            "unexpected original compression source fields")
            source_name = history.canonical(source["relative_path"])
            history.require(source_name not in decoded and source_name not in checked,
                            "duplicate or shadowed original compression source")
        else:
            history.require(name in HASH_ONLY_GZIP and set(source) == {"bytes", "sha256"},
                            "missing original compression source path")
            # These two original records bind uncompressed bytes only. Do not
            # invent a source pathname that their frozen index did not record.
            source_name = None
        expected_size, expected_sha = identity({"bytes": source["bytes"], "sha256": source["sha256"]})
        total, sha = 0, hashlib.sha256()
        with gzip.GzipFile(fileobj=io.BytesIO(raw(name)), mode="rb") as stream:
            while block := stream.read(1024 * 1024):
                total += len(block)
                history.require(total <= expected_size, "original decompressed byte limit exceeded")
                sha.update(block)
        history.require((total, sha.hexdigest()) == (expected_size, expected_sha),
                        "original decompressed SHA-256 differs")
        if source_name is not None:
            decoded[source_name] = total, sha.hexdigest()
    followup = json.loads(raw("followup-archive-inventory.json"), object_pairs_hook=history.unique)
    history.require(followup["schema"] == "trnm-pq-authority-followup-archives-v1"
                    and followup["capture_bytes_trimmed"] is False
                    and followup["source_receipts_rewritten"] is False
                    and followup["hosted_ci_passed"] is False, "original follow-up scope changed")
    accounted = 0
    for directory, row in followup["directories"].items():
        history.canonical(directory)
        for name, expected in row["copied_original_files"].items():
            full = history.canonical(directory + "/" + name)
            history.require(checked.get(full, decoded.get(full)) == identity(expected),
                            "original follow-up file accounting differs: " + full)
            accounted += 1
    external = json.loads(raw("external-artifacts.json"), object_pairs_hook=history.unique)
    history.require(external["files"] == [] and external["silent_omissions"] is False,
                    "original external-file accounting changed")
    history.require(history.local_file(root, index_name).read_bytes() == index_raw, "archive index changed")
    return dict(report, original_checksums_verified=True, original_package_files=len(files),
                original_package_payload_bytes=sum(size for size, _ in checked.values()),
                original_compression_bindings_verified=len(compression),
                original_compression_source_paths_named=len(decoded),
                original_followup_file_bindings_verified=accounted,
                history_only_large_files=len(large), history_only_large_bytes=sum(archived[n]["bytes"] for n in large),
                retained_capture_records=len(copies), live_corpus_archived_paths=0,
                original_hosted_ci_passed=False, whole_chain_pq_qualified=False,
                archived_helpers_executed=False, new_campaign_execution=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.root, args.manifest), sort_keys=True))
        return 0
    except (history.Invalid, KeyError, TypeError, OSError, UnicodeError, ValueError, EOFError) as error:
        print("PQ triage archive check failed: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
