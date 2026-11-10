#!/usr/bin/env python3
"""Prepare a strictly reviewed corpus refresh from a real staged Git candidate.

This external integration helper never edits the checkout or stages/commits it.
The code checkpoint, staged final bytes and later committed validation source
remain separate identities. No execution or qualification is inferred.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

BASE = "da1374a200022bc14dc2bd325cc9ba29dbcd24ab"
BASE_TREE = "00479a98dabc6b1fd91a0ceef82ffbdbffb78067"
CORPUS = "config/pon/pq-cross-branch-corpus-v1.json"
CHECKER = "scripts/ci/check_pq_research_integration.py"
BASE_CORPUS_BLOB = "e8f863a9988aed86797f923864631dac60b5a0b0"
BASE_CORPUS_SHA256 = "8b04622f2dd117ec137dc5995ba4ee00730ae41d6c0ba75b43d0aa2d34abd552"
BASE_CHECKER_BLOB = "250454d67b984e5b7784a27e7a326a2d91f4205a"
CANDIDATE_CHECKER_BLOB = "21094a39eb15525663925ac2d258deae40502990"
NEW_REQUIRED = (
    "config/pon/w1-qrom-current-required-tests-v1.json",
    "docs/research/PON_FRESH_REJECTION_COST_V1.md",
    "evidence/pon-w1-lifetime-current-20261110-685a/README.md",
    "evidence/pon-w1-lifetime-current-20261110-685a/project-input.json",
    "evidence/pon-w1-lifetime-current-20261110-685a/project-report.json",
    "scripts/ci/prepare_artifact_upload.py",
    "scripts/ci/test_fresh_rejection_report.py",
    "scripts/ci/test_prepare_artifact_upload.py",
    "scripts/ci/test_w1_qrom_current_ci.py",
    "scripts/ci/w1_native_controls.py",
    "scripts/ci/w1_qrom_current_ci.py",
    "scripts/pon_fresh_rejection_report.py",
    "trillionnium/crates/trnm-crypto-primitives/examples/pon_fresh_rejection_cost.rs",
    "trillionnium/crates/trnm-pon-node/src/store/confirmation_chainwork_tests.rs",
    "evidence/pon-w1-qrom-current-20261110-685a/README.md",
    "evidence/pon-w1-qrom-current-20261110-685a/source-binding.json",
    "evidence/pon-w1-qrom-current-20261110-685a/current-report.json",
    "evidence/pon-w1-qrom-current-20261110-685a/prior-v2-on-c2.command.json",
    "evidence/pon-w1-qrom-current-20261110-685a/prior-v2-on-c2.stdout.log",
    "evidence/pon-w1-qrom-current-20261110-685a/prior-v2-on-c2.stderr.log",
    "evidence/pon-w1-qrom-current-20261110-685a/historical/current-v2.json",
    "evidence/pon-w1-qrom-current-20261110-685a/historical/current-auditor.py",
    "evidence/pon-w1-qrom-current-20261110-685a/historical/current-tests.py",
    "evidence/pon-w1-qrom-current-20261110-685a/historical/current-mapping.md.txt",
)
HISTORICAL_PREFIXES = ("evidence/", "qualification/")
REGULAR_MODES = ("100644", "100755")
FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW


class Refusal(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(Refusal("nonfinite JSON")))


def git(root, *args, data=None):
    result = subprocess.run(["git", "-C", str(root), *args], input=data, capture_output=True)
    require(result.returncode == 0, "git command refused: " + " ".join(args)
            + ": " + result.stderr.decode(errors="replace").strip())
    return result.stdout


def oid(value):
    require(type(value) is str and re.fullmatch("[0-9a-f]{40}", value), "full SHA-1 identity required")
    return value


def safe_path(value):
    require(type(value) is str and value and not value.startswith("/")
            and not any(c in value for c in "\\\0\r\n\t")
            and all(p not in ("", ".", "..") for p in value.split("/")), "unsafe repository path")
    return value


def tree(root, identity):
    rows = {}
    for record in git(root, "ls-tree", "-r", "-l", "-z", "--full-tree", oid(identity)).split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode, kind, blob, size = metadata.decode("ascii").split()
        name = path.decode("utf-8")
        rows[name] = {"mode": mode, "type": kind, "blob": blob,
                      "bytes": int(size) if size != "-" else None}
    return rows


def file_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def actual_blob(root, relative, expected):
    """Hash the real bytes with Git through a checked nonblocking descriptor."""
    safe_path(relative)
    require(expected["mode"] in REGULAR_MODES and expected["type"] == "blob", "nonregular Git input: " + relative)
    root = Path(root).absolute()
    require(root.anchor == "/" and ".." not in root.parts, "unsafe checkout root")
    fds, held = [], []
    process = None
    try:
        parent = None
        components = [root.anchor, *root.parts[1:], *relative.split("/")[:-1]]
        for component in components:
            fd = os.open(component, FLAGS | os.O_DIRECTORY, dir_fd=parent)
            fds.append(fd)
            metadata = os.fstat(fd)
            held.append((parent, component, fd, metadata.st_dev, metadata.st_ino, metadata.st_mode))
            parent = fd
        leaf = relative.split("/")[-1]
        fd = os.open(leaf, FLAGS, dir_fd=parent)
        fds.append(fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size == expected["bytes"], "nonregular or wrong-size current input: " + relative)
        require(bool(before.st_mode & 0o111) == (expected["mode"] == "100755"), "Git executable mode differs: " + relative)
        process = subprocess.Popen(["git", "-C", str(root), "hash-object", "--stdin"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            require(bool(chunk), "truncated current input: " + relative)
            process.stdin.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        require(not os.read(fd, 1), "growing current input: " + relative)
        process.stdin.close()
        process.stdin = None
        stdout, stderr = process.communicate(timeout=30)
        require(process.returncode == 0, "git hash-object refused: " + relative)
        require(stdout.decode().strip() == expected["blob"], "actual Git blob differs from staged tree: " + relative)
        require(file_identity(before) == file_identity(os.fstat(fd))
                == file_identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)), "changed current input: " + relative)
        for parent_fd, component, directory_fd, dev, ino, mode in reversed(held):
            for metadata in (os.fstat(directory_fd), os.stat(component, dir_fd=parent_fd, follow_symlinks=False)):
                require((metadata.st_dev, metadata.st_ino, metadata.st_mode) == (dev, ino, mode), "changed current ancestor: " + relative)
        return {"bytes": before.st_size, "sha256": digest.hexdigest(), "git_blob": expected["blob"]}
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()
        for fd in reversed(fds):
            os.close(fd)


def validate_base(raw, entries):
    require(hashlib.sha256(raw).hexdigest() == BASE_CORPUS_SHA256, "old corpus bytes differ from exact da1374a")
    old = strict_json(raw)
    require(old["schema"] == "trnm-pq-cross-branch-corpus-v1"
            and old["status"] == "research-only-hold-no-go", "historical corpus header changed")
    pins, required = old["pinned_blobs"], old["required_paths"]
    require(type(pins) is dict and len(pins) == 1079 and len(required) == len(set(required)) == 987,
            "old corpus denominator changed")
    require(set(required).issubset(pins), "old required input lacks pin")
    for path, blob in pins.items():
        safe_path(path)
        require(entries.get(path, {}).get("blob") == blob, "old corpus/Git binding mismatch: " + path)
    return old


def verify_index(root, candidate_tree):
    require(git(root, "write-tree").decode().strip() == candidate_tree, "staged candidate tree changed")
    require(not git(root, "diff", "--name-only", "-z"), "unstaged tracked inputs remain")
    require(not git(root, "ls-files", "--others", "--exclude-standard", "-z"), "untracked inputs remain; stage the explicit final candidate first")
    flags = git(root, "ls-files", "-v", "-z").split(b"\0")
    require(all(not row or row.startswith(b"H ") for row in flags), "sparse, hidden or nonordinary index entry")


def candidate_plan(root, checkpoint, checkpoint_tree, candidate_tree):
    require(git(root, "rev-parse", BASE + "^{tree}").decode().strip() == BASE_TREE, "baseline tree differs")
    require(git(root, "rev-parse", oid(checkpoint) + "^{commit}").decode().strip() == checkpoint, "checkpoint is not the requested commit")
    require(git(root, "rev-parse", checkpoint + "^{tree}").decode().strip() == oid(checkpoint_tree), "checkpoint tree differs")
    require(git(root, "cat-file", "-t", oid(candidate_tree)).strip() == b"tree", "candidate must be a real Git tree")
    git(root, "merge-base", "--is-ancestor", BASE, checkpoint)
    git(root, "merge-base", "--is-ancestor", checkpoint, "HEAD")
    verify_index(root, candidate_tree)
    before, at_checkpoint, final = tree(root, BASE_TREE), tree(root, checkpoint_tree), tree(root, candidate_tree)
    require(before[CORPUS]["blob"] == final[CORPUS]["blob"] == BASE_CORPUS_BLOB, "refresh requires the untouched original corpus")
    require(before[CHECKER]["blob"] == BASE_CHECKER_BLOB and final[CHECKER]["blob"] == CANDIDATE_CHECKER_BLOB,
            "exact reviewed required-path guard is missing or changed")
    raw = git(root, "show", BASE + ":" + CORPUS)
    old = validate_base(raw, before)
    require(set(before).issubset(final), "the final candidate deletes an existing tracked path")
    for path, entry in before.items():
        if path.startswith(HISTORICAL_PREFIXES):
            require(final[path] == entry, "historical evidence changed: " + path)
    for path in set(final) - set(before):
        safe_path(path)
        if not path.startswith(HISTORICAL_PREFIXES):
            require(path in NEW_REQUIRED, "unreviewed new implementation dependency: " + path)
    require(not set(NEW_REQUIRED) & set(before), "new dependency unexpectedly existed in the baseline")
    require(set(NEW_REQUIRED).issubset(final), "one or more new required inputs are missing")
    changes = []
    for path in sorted(path for path in final if final[path] != before.get(path)):
        actual = actual_blob(root, path, final[path])
        changes.append({"path": path, "status": "modified" if path in before else "added",
                        "baseline": before.get(path), "checkpoint": at_checkpoint.get(path),
                        "candidate": final[path], "actual": actual,
                        "differs_from_code_checkpoint": final[path] != at_checkpoint.get(path)})
    verify_index(root, candidate_tree)
    plan = {"schema": "trnm-corpus-candidate-paths-v1", "baseline_commit": BASE,
            "checkpoint_commit": checkpoint, "checkpoint_tree": checkpoint_tree,
            "observed_head": git(root, "rev-parse", "HEAD").decode().strip(),
            "candidate_index_tree": candidate_tree, "changes": changes,
            "new_required_paths": list(NEW_REQUIRED),
            "scope": "actual tracked and staged bytes; checkpoint is not relabeled as final validation source"}
    return plan, old, before, final


def refreshed_corpus(old, before, final):
    require(set(NEW_REQUIRED).issubset(final), "new required input missing from final tree")
    updated = copy.deepcopy(old)
    changed = []
    for path, previous in old["pinned_blobs"].items():
        require(path in final, "old pin missing from final tree: " + path)
        current = final[path]["blob"]
        if current != previous:
            require(before[path]["blob"] == previous, "unreviewed old blob: " + path)
            updated["pinned_blobs"][path] = current
            changed.append({"path": path, "before": previous, "after": current})
    for path in NEW_REQUIRED:
        require(path not in updated["pinned_blobs"] and path not in updated["required_paths"], "new dependency already present")
        updated["pinned_blobs"][path] = final[path]["blob"]
        updated["required_paths"].append(path)
    require(set(updated) == set(old), "unexpected corpus top-level field")
    require(all(updated[key] == value for key, value in old.items() if key not in ("pinned_blobs", "required_paths")),
            "historical scope, status, claims or source composition changed")
    require(updated["required_paths"][:987] == old["required_paths"]
            and set(old["pinned_blobs"]).issubset(updated["pinned_blobs"])
            and len(updated["pinned_blobs"]) == 1103 and len(updated["required_paths"]) == 1011,
            "old source coverage was lost or new denominator differs")
    return updated, changed


def write_new(path, raw, root):
    path = Path(path).absolute()
    require(path.anchor == "/" and ".." not in path.parts
            and path != root and root not in path.parents, "outputs must be outside the measured checkout")
    parent = os.open("/", FLAGS | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, FLAGS | os.O_DIRECTORY, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    finally:
        os.close(parent)


def read_plan(path):
    fd = os.open(path, FLAGS)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= 16 * 1024 * 1024,
                "plan is not a bounded regular file")
        raw = stream.read(16 * 1024 * 1024 + 1)
        require(len(raw) == before.st_size and file_identity(before) == file_identity(os.fstat(stream.fileno())),
                "explicit path plan changed while reading")
        return raw


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("inventory", "update"))
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--checkpoint-tree", required=True)
    parser.add_argument("--candidate-tree", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args(argv)
    root = args.repo_root.absolute()
    try:
        plan, old, before, final = candidate_plan(root, args.checkpoint, args.checkpoint_tree, args.candidate_tree)
        if args.mode == "inventory":
            write_new(args.plan, encoded(plan), root)
            print(json.dumps({"inventory_written": str(args.plan), "changed_paths": len(plan["changes"]), "tests_executed": False}))
            return 0
        require(args.output is not None and args.receipt is not None, "update requires --output and --receipt")
        retained = read_plan(args.plan)
        require(strict_json(retained) == plan, "explicit final path plan or actual file bytes changed")
        updated, changes = refreshed_corpus(old, before, final)
        # Every old and new pinned path is read as an actual checked fd and
        # passed through Git hash-object, including unchanged historical pins.
        for path in sorted(updated["pinned_blobs"]):
            actual_blob(root, path, final[path])
        actual_blob(root, CORPUS, final[CORPUS])
        verify_index(root, args.candidate_tree)
        raw = encoded(updated)
        receipt = {"schema": "trnm-corpus-refresh-observation-v1", "status": "HOLD_NO_GO",
                   "checkpoint_commit": args.checkpoint, "checkpoint_tree": args.checkpoint_tree,
                   "candidate_index_tree_before_corpus_refresh": args.candidate_tree,
                   "candidate_plan_sha256": hashlib.sha256(retained).hexdigest(),
                   "old_corpus_sha256": BASE_CORPUS_SHA256, "updated_corpus_sha256": hashlib.sha256(raw).hexdigest(),
                   "retained_original_required_paths": 987, "retained_original_pin_paths": 1079,
                   "required_paths": 1011, "pinned_blobs": 1103, "changed_existing_pins": changes,
                   "new_required_paths": list(NEW_REQUIRED), "historical_fields_unchanged": True,
                   "historical_evidence_unchanged": True, "tests_executed": False,
                   "native_executed": False, "production_qualified": False,
                   "scope": "source binding preparation only; no final commit or acceptance is claimed"}
        write_new(args.output, raw, root)
        write_new(args.receipt, encoded(receipt), root)
        print(json.dumps({"updated_corpus": str(args.output), "receipt": str(args.receipt),
                          "required_paths": 1011, "pinned_blobs": 1103, "status": "HOLD_NO_GO"}))
        return 0
    except (Refusal, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("CORPUS_REFRESH_REFUSED: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
