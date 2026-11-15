#!/usr/bin/env python3
"""Read-only proof for one literal evidence child of the frozen Z commit.

Prepared for later execution under the existing per-command recorder. This
program does not run native tests or replace scripts/ci/verify_ci_source.py.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

BASE = "cdd984808a088e6c2e13b1e1ae6630a94d500c89"
BASE_TREE = "1ed39b6ebe55cb00c238f26f6bfc9361ab93faec"
ADDITION = "evidence/pon-account-authorization-boundary-20261111"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
GENERATED_INDEXES = {"record-index.json", "binary-identities.json"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key: " + key)
        value[key] = item
    return value


def load(path: Path):
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def canonical(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(
        ["git", "--no-replace-objects", *args], cwd=root,
        env=dict(os.environ, GIT_NO_LAZY_FETCH="1"), stderr=subprocess.PIPE)


def tree_entries(root: Path, commit: str, recursive: bool):
    args = ["ls-tree", "-z", "--full-tree"]
    if recursive:
        args.append("-r")
    output = git(root, *args, commit)
    entries = {}
    for row in output.split(b"\0"):
        if not row:
            continue
        header, name = row.split(b"\t", 1)
        mode, kind, oid = header.split(b" ")
        require(name not in entries, "duplicate Git tree path")
        entries[name] = (mode, kind, oid)
    return entries


def identity_clean(root: Path, expected: str):
    require(git(root, "rev-parse", "HEAD").strip().decode() == expected,
            "actual HEAD differs from literal expected child")
    require(not git(root, "status", "--porcelain=v1", "--untracked-files=all"),
            "source must be committed and clean")


def payload_proof(root: Path, added: dict, expected_payload: str, expected_manifest: str):
    directory = root / ADDITION
    manifest_path = directory / "manifest.json"
    require(sha(manifest_path) == expected_manifest,
            "manifest differs from the explicitly reviewed manifest bytes")
    manifest = load(manifest_path)
    require(manifest.get("schema") == "trnm-account-authorization-delivery-manifest-v1",
            "unexpected delivery manifest schema")
    require(manifest.get("current_source_commit") == BASE,
            "historical observation cohort must remain Z")
    flags = manifest.get("interpretation")
    require(isinstance(flags, dict) and flags and all(v is False for v in flags.values()),
            "manifest must not grant qualification")
    require(manifest.get("reviewed_payload_sha256") == expected_payload,
            "manifest differs from explicitly reviewed payload hash")
    require((directory / "manifest.sha256").read_bytes()
            == (sha(manifest_path) + "  manifest.json\n").encode(),
            "manifest sidecar mismatch")
    rows = manifest.get("files")
    require(isinstance(rows, list) and bool(rows), "empty manifest file table")
    seen = set()
    total = 0
    for row in rows:
        name = row.get("path")
        require(isinstance(name, str) and name and "\\" not in name
                and not PurePosixPath(name).is_absolute()
                and all(x not in ("", ".", "..") for x in name.split("/")),
                "unsafe manifest relative path")
        require(name not in seen and name not in ("manifest.json", "manifest.sha256"),
                "duplicate/self-referential manifest member")
        seen.add(name)
        file = directory / name
        require(file.is_file() and not file.is_symlink(), "payload member is not a regular file")
        require(file.stat().st_size == row.get("bytes") and sha(file) == row.get("sha256"),
                "payload bytes/hash differ: " + name)
        total += row["bytes"]
    tracked = {name.decode("utf-8")[len(ADDITION) + 1:] for name in added}
    require(tracked == seen | {"manifest.json", "manifest.sha256"},
            "tracked evidence additions differ from the complete manifest")
    require(manifest.get("file_count") == len(rows) and manifest.get("total_file_bytes") == total,
            "manifest size/count differs")
    payload_rows = [{key: row[key] for key in ("path", "bytes", "sha256")}
                    for row in sorted(rows, key=lambda item: item["path"])
                    if row["path"] not in GENERATED_INDEXES]
    require(hashlib.sha256(canonical(payload_rows)).hexdigest() == expected_payload,
            "actual payload differs from reviewed assembly payload")
    index = load(directory / "record-index.json")
    require(index.get("current_source_commit") == BASE
            and index.get("payload_sha256") == expected_payload,
            "record index must preserve its original Z source/payload binding")
    require(index.get("interpretation") == flags, "record-index qualification flags differ")
    records = index.get("records", [])
    def one(identifier):
        matches = [r for r in records if r.get("host") == "desktop"
                   and r.get("source_commit") == BASE and r.get("id") == identifier]
        require(len(matches) == 1, "missing/duplicate preserved observation: " + identifier)
        return matches[0]
    failed = one("rust-baseline")
    require(failed.get("classification") == "FAIL" and failed.get("returncode") == 101
            and failed.get("completed_result") is True and failed.get("recorded_pass") is False,
            "original full-Rust failure was not preserved")
    incomplete = one("node-retained-all-targets")
    require(incomplete.get("classification") == "INCOMPLETE_EMPTY_RESULT"
            and incomplete.get("completed_result") is False
            and all(incomplete.get(k) is None for k in (
                "computed_pass", "recorded_pass", "returncode", "finished_utc", "source_identity_intact")),
            "original unknown Node outcome was reclassified")
    require(manifest.get("all_selected_records_terminal") is False,
            "incomplete observation must not become a terminal receipt")
    return {"manifest_sha256": sha(manifest_path), "reviewed_payload_sha256": expected_payload,
            "tracked_new_files": len(added), "manifest_members": len(rows),
            "original_full_rust_failure_preserved": True,
            "original_node_incomplete_preserved": True,
            "observation_source_commit": BASE, "qualification_granted": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--expected-self-sha256", required=True)
    parser.add_argument("--expected-payload-sha256", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--expected-runner-sha256", required=True)
    parser.add_argument("--environment", type=Path, required=True)
    parser.add_argument("--expected-environment-sha256", required=True)
    args = parser.parse_args()
    require(bool(HEX40.fullmatch(args.head)) and args.head != BASE,
            "head must be an explicit full new commit SHA; Z is not E")
    for value in (args.expected_self_sha256, args.expected_payload_sha256, args.expected_manifest_sha256,
                  args.expected_runner_sha256, args.expected_environment_sha256):
        require(bool(HEX64.fullmatch(value)), "hash must be an explicit full SHA-256")
    root = args.repo
    require(root.is_absolute() and root.resolve() == root, "repository path must be exact and unsymlinked")
    require(sha(Path(__file__)) == args.expected_self_sha256, "proof helper bytes changed")
    require(sha(args.runner) == args.expected_runner_sha256, "original recorder bytes changed")
    require(sha(args.environment) == args.expected_environment_sha256, "recorded environment bytes changed")
    identity_clean(root, args.head)
    require(git(root, "rev-parse", BASE + "^{tree}").strip().decode() == BASE_TREE,
            "frozen base tree mismatch")
    headers = git(root, "cat-file", "-p", args.head).split(b"\n\n", 1)[0].splitlines()
    parents = [line[7:].decode() for line in headers if line.startswith(b"parent ")]
    require(parents == [BASE], "E must have exactly one direct parent: Z")
    old = tree_entries(root, BASE, True)
    new = tree_entries(root, args.head, True)
    prefix = (ADDITION + "/").encode()
    require(not any(name.startswith(prefix) for name in old), "evidence directory already existed in Z")
    require(all(new.get(name) == entry for name, entry in old.items()),
            "an old tracked path, mode, type or object changed/deleted")
    added = {name: entry for name, entry in new.items() if name not in old}
    require(bool(added) and all(name.startswith(prefix) for name in added),
            "E may only add files under the specified evidence directory")
    require(all(entry[0] in (b"100644", b"100755") and entry[1] == b"blob" for entry in added.values()),
            "new evidence must contain only regular tracked files")
    old_top, new_top = tree_entries(root, BASE, False), tree_entries(root, args.head, False)
    require(all(new_top.get(name) == entry for name, entry in old_top.items() if name != b"evidence"),
            "an existing top-level object outside evidence changed")
    unchanged_trees = {}
    for name in ("trillionnium", "config", "scripts", ".github", "tests", "docs"):
        entry = old_top[name.encode()]
        require(entry == new_top[name.encode()] and entry[1] == b"tree", "required tree changed: " + name)
        unchanged_trees[name] = entry[2].decode()
    payload = payload_proof(root, added, args.expected_payload_sha256, args.expected_manifest_sha256)
    identity_clean(root, args.head)
    report = {"schema": "trnm-evidence-child-relation-v1", "source_commit": args.head,
              "source_tree": git(root, "rev-parse", args.head + "^{tree}").strip().decode(),
              "parent_commit": BASE, "parent_tree": BASE_TREE,
              "all_old_tracked_paths_modes_types_and_objects_identical": True,
              "old_tracked_entries": len(old), "permitted_addition": ADDITION,
              "unchanged_top_level_tree_objects": unchanged_trees, "payload": payload,
              "helper_sha256": sha(Path(__file__)), "runner_sha256": sha(args.runner),
              "environment_sha256": sha(args.environment),
              "complete_raw_source_guard_is_a_separate_required_command": True,
              "runtime_binary_equivalence_claimed": False, "native_test_execution_claimed": False,
              "full_ci_acceptance_granted": False, "qualification_granted": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print("evidence child relation refused: " + str(error), file=sys.stderr)
        raise SystemExit(1)
