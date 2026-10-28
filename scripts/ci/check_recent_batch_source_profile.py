#!/usr/bin/env python3
"""Check one explicitly selected, reviewed source identity; execute no native test."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "config/pon-recent-batch-source-profiles-v1.json"
SCHEMA = "pon-recent-batch-source-profiles-v1"
PROFILES = {"original-reviewed-v1", "native-pq-quota-v3-reviewed-v1"}
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def load_manifest(path):
    raw = path.read_bytes()
    document = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(document, dict) or set(document) != {
        "schema", "review_basis_commit", "original_workflow_blob", "profiles"
    }:
        raise ValueError("unexpected source-profile manifest shape")
    if document["schema"] != SCHEMA:
        raise ValueError("unknown source-profile manifest schema")
    for field in ("review_basis_commit", "original_workflow_blob"):
        if not isinstance(document[field], str) or not HEX40.fullmatch(document[field]):
            raise ValueError(f"invalid {field}")
    profiles = document["profiles"]
    if not isinstance(profiles, dict) or set(profiles) != PROFILES:
        raise ValueError("source profiles must retain both explicit reviewed identities")
    for name, profile in profiles.items():
        if not isinstance(profile, dict) or set(profile) != {"review", "git_blobs"}:
            raise ValueError(f"unexpected profile shape: {name}")
        if not isinstance(profile["review"], str) or not profile["review"]:
            raise ValueError(f"missing source review: {name}")
        pins = profile["git_blobs"]
        if not isinstance(pins, dict) or not pins:
            raise ValueError(f"empty source identity: {name}")
        for relative, expected in pins.items():
            path = PurePosixPath(relative)
            if (not relative or not path.parts or path.is_absolute() or ".." in path.parts
                    or "." in path.parts or str(path) != relative or "\\" in relative):
                raise ValueError(f"noncanonical relative source path: {relative}")
            if not isinstance(expected, str) or not HEX40.fullmatch(expected):
                raise ValueError(f"invalid Git blob identity: {relative}")
    return document, hashlib.sha256(raw).hexdigest()


def verify(root, document, profile):
    if profile not in PROFILES or profile not in document["profiles"]:
        raise ValueError(f"unknown explicit source profile: {profile}")
    rows = []
    for relative, expected in sorted(document["profiles"][profile]["git_blobs"].items()):
        path = root / relative
        cursor = root
        for component in PurePosixPath(relative).parts:
            cursor = cursor / component
            if cursor.is_symlink():
                raise ValueError(f"symlink source component refused: {relative}")
        try:
            mode = path.stat().st_mode
        except FileNotFoundError as error:
            raise ValueError(f"missing pinned source: {relative}") from error
        if not stat.S_ISREG(mode):
            raise ValueError(f"nonregular pinned source: {relative}")
        data = path.read_bytes()
        actual = git_blob(data)
        rows.append({"path": relative, "expected_git_blob": expected,
                     "actual_git_blob": actual, "bytes": len(data), "matches": actual == expected})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {"schema": "pon-recent-batch-source-observation-v1", "profile": args.profile,
              "result": "FAIL", "native_tests_executed": False,
              "native_compatibility_qualified": False, "production_activation": False}
    try:
        document, digest = load_manifest(args.manifest or args.root / MANIFEST)
        report["manifest_sha256"] = digest
        report["review_basis_commit"] = document["review_basis_commit"]
        report["files"] = verify(args.root, document, args.profile)
        if not all(row["matches"] for row in report["files"]):
            raise ValueError("selected reviewed source identity differs; no alternate profile tried")
        report["result"] = "PASS"
    except (OSError, ValueError, TypeError) as error:
        report["error"] = f"{type(error).__name__}: {error}"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
