#!/usr/bin/env python3
"""Review/apply a bounded authority/PQ128 source binding in a real full worktree.

No commits, pushes, network calls, corpus edits, W1-ledger edits or historical
evidence rewrites. The default prepares a diff; --apply writes seven files.
The selected code checkpoint and the later executed candidate remain distinct.
"""
from __future__ import annotations

import argparse
import ast
from copy import deepcopy
from datetime import datetime, timezone
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import sys
import uuid


BASE = "da1374a200022bc14dc2bd325cc9ba29dbcd24ab"
AUTH_REV = "893738947a50dc42819b56e632192de4f9f24fa0"
LIFETIME_REV = "66b7064be597039ce871b5b12ad5568850a2dd46"
AUTH_TABLE_SHA = "a3c5483479d5217c13946e173e4103316069eb42b43c335c6f7b44e783b73f1c"
AUTH = "config/pon/pq-authority-effects-v1.json"
AUTH_CHECK = "scripts/ci/pq_authority_effect_register.py"
AUTH_TEST = "scripts/ci/test_pq_authority_effect_register.py"
LOCK = "config/pon/pq128-source-lock-v1.json"
BUDGET = "config/pon/pq128-lifetime-budget-v1.json"
AUTH_DOC = "docs/security/PQ_AUTHORITY_EFFECT_REGISTER_V1.md"
BUDGET_DOC = "docs/security/PQ128_LIFETIME_BUDGET_V1.md"
STORE = "trillionnium/crates/trnm-pon-node/src/store.rs"
NATIVE_BUDGET = "trillionnium/crates/trnm-service-settlement/src/native_budget.rs"
MAX_BYTES = 4 * 1024 * 1024

# Independently retrieved exact baseline Git blobs, including both documents.
# Updating these pins to accept another input is a separate review, not a mode.
BASELINE_BLOBS = {
    AUTH: "adbce9a7866f1b9edfbbb3b556873c509d12228d",
    AUTH_CHECK: "5ed3512c9289df5043ef1c95013567fe54d22c5e",
    AUTH_TEST: "c3d12d5d5433d79c1d0d592aae5584ecf2c1731b",
    LOCK: "7644527dccaf4f8559ac2ca94334b658ca1d7438",
    BUDGET: "c36fc3e9d904c6e9b634425a1784f96280305951",
    AUTH_DOC: "32d760fc0e5fd89588a0281b731db3bb803420f6",
    BUDGET_DOC: "0459757b4b8d94c64ec7a825f598012e524d9213",
}


class BindingError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise BindingError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git_blob_id(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw,
                        usedforsecurity=False).hexdigest()


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def safe_parts(relative):
    require(type(relative) is str and "\\" not in relative and "\0" not in relative,
            "unsafe relative path")
    parts = relative.split("/")
    require(parts and all(part not in ("", ".", "..") for part in parts)
            and not PurePosixPath(relative).is_absolute(), "unsafe relative path")
    return parts


def parent_descriptor(root, relative):
    parts = safe_parts(relative)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(root, flags)
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def read_regular(root, relative):
    parent, name = parent_descriptor(root, relative)
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_BYTES,
                    "nonregular/oversized file: " + relative)
            chunks, size = [], 0
            while True:
                part = os.read(descriptor, min(65536, MAX_BYTES + 1 - size))
                if not part:
                    break
                chunks.append(part)
                size += len(part)
                require(size <= MAX_BYTES, "file exceeds bound: " + relative)
            after = os.fstat(descriptor)
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            require(all(getattr(before, key) == getattr(after, key) for key in fields)
                    and size == before.st_size, "file changed during read: " + relative)
            return b"".join(chunks), stat.S_IMODE(before.st_mode)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def git(root, *arguments, allow_failure=False):
    result = subprocess.run(["git", "--no-replace-objects", "--literal-pathspecs",
                             "-C", str(root), *arguments], capture_output=True,
                            timeout=30, check=False)
    require(allow_failure or result.returncode == 0,
            "Git command refused: " + " ".join(arguments))
    return result


def commit_file(root, commit, relative):
    safe_parts(relative)
    entry = git(root, "ls-tree", "-l", "-z", commit, "--", relative).stdout
    require(entry.endswith(b"\0") and entry.count(b"\0") == 1,
            "missing/ambiguous Git path: " + relative)
    metadata, name = entry[:-1].split(b"\t", 1)
    mode, kind, object_id, size = metadata.decode("ascii").split()
    require(name.decode("utf-8") == relative and mode in ("100644", "100755")
            and kind == "blob" and size.isdecimal() and int(size) <= MAX_BYTES,
            "Git source is not a bounded regular blob: " + relative)
    raw = git(root, "show", commit + ":" + relative).stdout
    require(len(raw) == int(size) and git_blob_id(raw) == object_id,
            "Git blob bytes differ: " + relative)
    return raw, {"git_blob": object_id, "git_mode": mode, "bytes": len(raw),
                 "sha256": sha(raw)}


def validate_baseline_bytes(baseline):
    require(set(baseline) == set(BASELINE_BLOBS), "baseline file set differs")
    for path, expected in BASELINE_BLOBS.items():
        require(git_blob_id(baseline[path]) == expected, "unreviewed baseline: " + path)
    authority, lock, budget = map(strict_json, (baseline[AUTH], baseline[LOCK], baseline[BUDGET]))
    require(authority["source_revision"] == AUTH_REV
            and len(authority["source_files_sha256"]) == 44
            and len(authority["routes"]) == 7, "authority baseline roster/revision differs")
    require(canonical_table(AUTH_REV, authority["source_files_sha256"]) == AUTH_TABLE_SHA,
            "authority original canonical table differs")
    require(lock["source_revision"] == budget["experiment"]["source_revision"] == LIFETIME_REV
            and len(lock["files"]) == 15, "lifetime baseline roster/revision differs")
    paths = {path for event in budget["events"] for path in event["source_paths"]}
    require(paths == set(lock["files"]), "lifetime event path union differs")
    return authority, lock, budget


def canonical_table(revision, files):
    raw = json.dumps({"source_revision": revision, "files": files},
                     sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha(raw)


def verify_table_changes(original, current, allowed, label):
    require(set(current) == set(original), label + " roster changed")
    changed = {path for path in original if original[path] != current[path]}
    require(changed == set(allowed), label + " unexpected changed pin set: "
            + repr(sorted(changed)))


def bind_sources(root, checkpoint, original, allowed, label, cache):
    current, records = {}, []
    for path, prior in sorted(original.items()):
        if path not in cache:
            cache[path] = commit_file(root, checkpoint, path)
        raw, record = cache[path]
        observed, _ = read_regular(root, path)
        require(observed == raw, "working source differs from checkpoint: " + path)
        current[path] = record["sha256"]
        records.append({"path": path, "prior_sha256": prior,
                        "changed": prior != current[path], **record})
    verify_table_changes(original, current, allowed, label)
    return current, records


def replace_once(raw, before, after):
    before, after = before.encode("utf-8"), after.encode("utf-8")
    require(raw.count(before) == 1, "expected source anchor is not unique: " + before.decode())
    return raw.replace(before, after, 1)


def replace_revision(raw, before, after):
    return replace_once(raw, '"source_revision": "' + before + '"',
                        '"source_revision": "' + after + '"')


def replace_pin(raw, path, before, after):
    return replace_once(raw, json.dumps(path) + ": " + json.dumps(before),
                        json.dumps(path) + ": " + json.dumps(after))


def test_names(raw):
    return [node.name for node in ast.walk(ast.parse(raw))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")]


def render_changes(baseline, checkpoint, tree, authority_files, lifetime_files):
    authority, lock, budget = validate_baseline_bytes(baseline)
    verify_table_changes(authority["source_files_sha256"], authority_files, {STORE}, "authority")
    verify_table_changes(lock["files"], lifetime_files, {STORE, NATIVE_BUDGET}, "lifetime")
    new = dict(baseline)
    new[AUTH] = replace_revision(new[AUTH], AUTH_REV, checkpoint)
    new[AUTH] = replace_pin(new[AUTH], STORE, authority["source_files_sha256"][STORE], authority_files[STORE])
    digest = canonical_table(checkpoint, authority_files)
    new[AUTH_CHECK] = replace_once(new[AUTH_CHECK], "SOURCE_REVISION = '" + AUTH_REV + "'",
                                    "SOURCE_REVISION = '" + checkpoint + "'")
    new[AUTH_CHECK] = replace_once(new[AUTH_CHECK], "REVIEWED_SOURCE_LOCK_SHA256 = '" + AUTH_TABLE_SHA + "'",
                                    "REVIEWED_SOURCE_LOCK_SHA256 = '" + digest + "'")
    positive = "        self.assertEqual(result['source_revision'],\n                         '" + AUTH_REV + "')"
    new[AUTH_TEST] = replace_once(new[AUTH_TEST], positive, positive.replace(AUTH_REV, checkpoint))
    stale = "                             ('source_revision', '44e96b1a841a50613d0b93484c5e576caec9f81f'),\n"
    new[AUTH_TEST] = replace_once(new[AUTH_TEST], stale, stale
        + "                             ('source_revision', '" + AUTH_REV + "'),\n")
    new[LOCK] = replace_revision(new[LOCK], LIFETIME_REV, checkpoint)
    for path in (STORE, NATIVE_BUDGET):
        new[LOCK] = replace_pin(new[LOCK], path, lock["files"][path], lifetime_files[path])
    new[BUDGET] = replace_revision(new[BUDGET], LIFETIME_REV, checkpoint)

    expected = deepcopy(authority)
    expected["source_revision"], expected["source_files_sha256"] = checkpoint, authority_files
    require(strict_json(new[AUTH]) == expected, "authority changed beyond revision/store pin")
    expected = deepcopy(lock)
    expected["source_revision"], expected["files"] = checkpoint, lifetime_files
    require(strict_json(new[LOCK]) == expected, "lifetime lock changed beyond reviewed pins")
    expected = deepcopy(budget)
    expected["experiment"]["source_revision"] = checkpoint
    require(strict_json(new[BUDGET]) == expected, "lifetime experiment changed beyond revision")
    require(test_names(new[AUTH_TEST]) == test_names(baseline[AUTH_TEST]), "authority test roster changed")
    ast.parse(new[AUTH_CHECK]); ast.parse(new[AUTH_TEST])

    heading = "\n## Reviewed source binding to code checkpoint `" + checkpoint + "`\n\n"
    common = ("This is a selected-source consistency review. All named regular Git blobs were read with\n"
              "`git show " + checkpoint + ":<path>` and matched against the working files.\n"
              "The code checkpoint is `" + checkpoint + "`, tree `" + tree + "`.\n"
              "The later binding, reader, test and documentation edits are not claimed to exist in that\n"
              "checkpoint. The final executed candidate and binary require their own observations.\n\n")
    authority_note = (heading + common
        + "All 44 curated paths retain their roster. Forty-three source hashes are unchanged; only\n"
        + "`trillionnium/crates/trnm-pon-node/src/store.rs` changes:\n\n"
        + "```text\nprior:    " + authority["source_files_sha256"][STORE]
        + "\nreviewed: " + authority_files[STORE] + "\n```\n\n"
        + "The prior active revision `" + AUTH_REV + "` and its canonical table digest\n"
        + "`" + AUTH_TABLE_SHA + "` remain historical records. The new canonical table digest is\n"
        + "`" + digest + "`. The independent positive revision is updated, and the prior\n"
        + "revision is added to the existing stale-context refusal control. No test is removed.\n\n"
        + "The seven routes, exact effect scopes and all false qualification fields are unchanged.\n"
        + "The old reader's actual source-lock refusal is retained separately before rebinding;\n"
        + "the new Python checks and their outcomes belong to this mapping and cannot relabel an\n"
        + "earlier failure or native run. Neither these pins nor the checks establish complete\n"
        + "dependency coverage, call-graph reachability, provenance authentication, native behavior,\n"
        + "external-effect acceptance or production activation.\n")
    lifetime_note = (heading + common
        + "All 15 declared event paths retain their roster. Thirteen source hashes are unchanged.\n"
        + "The two changed source pins are:\n\n| Source | Prior SHA-256 | Reviewed SHA-256 |\n| --- | --- | --- |\n"
        + "".join("| `" + path + "` | `" + lock["files"][path] + "` | `"
                  + lifetime_files[path] + "` |\n" for path in (STORE, NATIVE_BUDGET))
        + "\nThe prior mapping remains `" + LIFETIME_REV + "`, with lock-byte SHA-256\n"
        + "`" + sha(baseline[LOCK]) + "`. The new lock-byte SHA-256 is\n"
        + "`" + sha(new[LOCK]) + "`. The research manifest changes only\n"
        + "`experiment.source_revision`; no source is added to an event or removed from one.\n\n"
        + "All eight unknown event terms, four unknown shared-primitive query budgets, allocations,\n"
        + "assumptions, null actual lifetime failure bound and false qualification/activation\n"
        + "fields are preserved. The prior guard's source-lock refusal remains a failed observation.\n"
        + "This reviewed mapping and its separate Python controls do not replace native execution,\n"
        + "complete reduction/coverage work, cryptographic provenance or an instantiated PQ128 bound.\n"
        + "Earlier reports and evidence remain unchanged and retain their original source attribution.\n")
    new[AUTH_DOC] += authority_note.encode("utf-8")
    new[BUDGET_DOC] += lifetime_note.encode("utf-8")
    require(set(new) == set(BASELINE_BLOBS), "output file set differs")
    return new


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def run_logged(root, output, name, argv, timeout=180):
    with (output / (name + ".stdout.log")).open("xb") as stdout, \
            (output / (name + ".stderr.log")).open("xb") as stderr:
        result = subprocess.run(argv, cwd=root, stdout=stdout, stderr=stderr,
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
                                timeout=timeout, check=False)
    record = {"argv": argv, "exit_code": result.returncode}
    write_json(output / (name + ".command.json"), record)
    return record


def verify_old_refusal(root, output, name, path):
    record = run_logged(root, output, name, [sys.executable, "-B", str(root / path), "--root", str(root)])
    require(record["exit_code"] == 2, "old guard did not return its required exit-2 refusal: " + name)
    require((output / (name + ".stdout.log")).read_bytes() == b"", "old guard emitted unexpected stdout")
    report = strict_json((output / (name + ".stderr.log")).read_bytes())
    require(report.get("status") == "REFUSE"
            and report.get("reason") == "source lock hash mismatch: " + STORE,
            "old guard failed for an unrelated reason: " + name)


def replace_regular(root, relative, before, after):
    observed, mode = read_regular(root, relative)
    require(observed == before, "target changed before replacement: " + relative)
    parent, name = parent_descriptor(root, relative)
    temporary = ".source-binding-" + uuid.uuid4().hex
    created = False
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             mode, dir_fd=parent)
        created = True
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(after); stream.flush(); os.fchmod(stream.fileno(), mode); os.fsync(stream.fileno())
        require(read_regular(root, relative)[0] == before, "target changed while staging: " + relative)
        os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        created = False
        os.fsync(parent)
    finally:
        if created:
            os.unlink(temporary, dir_fd=parent)
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--output", type=Path, help="fresh review/log directory outside the worktree")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--defer-validation", action="store_true",
                        help="after --apply, print the four exact commands for the integrating controller")
    args = parser.parse_args()
    output, applied = None, []
    try:
        root = args.root.absolute()
        checkpoint = args.checkpoint
        require(not args.defer_validation or args.apply, "--defer-validation requires --apply")
        require(re.fullmatch(r"[0-9a-f]{40}", checkpoint) is not None, "checkpoint must be an exact commit ID")
        for path in (root, *root.parents):
            require(not path.is_symlink() and path.is_dir(), "worktree ancestry is not regular")
        require(git(root, "rev-parse", "--show-toplevel").stdout.decode().strip() == str(root), "root is not the worktree root")
        require(git(root, "rev-parse", "--is-shallow-repository").stdout.strip() == b"false", "shallow worktree refused")
        sparse = git(root, "config", "--bool", "core.sparseCheckout", allow_failure=True)
        require(sparse.returncode in (0, 1) and sparse.stdout.strip() in (b"", b"false"), "sparse worktree refused")
        require(git(root, "cat-file", "-t", checkpoint).stdout.strip() == b"commit", "checkpoint is not a commit")
        git(root, "merge-base", "--is-ancestor", BASE, checkpoint)
        git(root, "merge-base", "--is-ancestor", checkpoint, "HEAD")
        head = git(root, "rev-parse", "HEAD").stdout.decode().strip()
        tree = git(root, "rev-parse", checkpoint + "^{tree}").stdout.decode().strip()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = (args.output or root.parent / ("source-binding-" + checkpoint[:12] + "-" + stamp + "-" + uuid.uuid4().hex[:6])).absolute()
        require(not output.is_relative_to(root) and not output.exists(), "output must be fresh and outside the worktree")
        output.mkdir(parents=True, exist_ok=False)
        preflight = run_logged(root, output, "project-preflight", ["bash", "scripts/project-preflight.sh"])
        require(preflight["exit_code"] == 0, "project preflight failed; no binding files changed")

        baseline = {}
        for path, expected in BASELINE_BLOBS.items():
            raw, record = commit_file(root, BASE, path)
            require(record["git_blob"] == expected, "baseline Git pin differs: " + path)
            require(read_regular(root, path)[0] == raw, "current binding/document bytes are not the reviewed baseline: " + path)
            baseline[path] = raw
        authority, lock, _budget = validate_baseline_bytes(baseline)
        cache = {}
        authority_files, authority_records = bind_sources(root, checkpoint, authority["source_files_sha256"], {STORE}, "authority", cache)
        lifetime_files, lifetime_records = bind_sources(root, checkpoint, lock["files"], {STORE, NATIVE_BUDGET}, "lifetime", cache)
        verify_old_refusal(root, output, "prior-authority-refusal", AUTH_CHECK)
        verify_old_refusal(root, output, "prior-pq128-refusal", "scripts/ci/pq_lifetime_budget.py")
        updated = render_changes(baseline, checkpoint, tree, authority_files, lifetime_files)
        patch = []
        for path in BASELINE_BLOBS:
            patch.append("diff --git a/" + path + " b/" + path + "\n")
            patch.extend(difflib.unified_diff(baseline[path].decode().splitlines(keepends=True),
                         updated[path].decode().splitlines(keepends=True), fromfile="a/" + path, tofile="b/" + path))
        with (output / "review.patch").open("x", encoding="utf-8") as stream:
            stream.write("".join(patch))
        commands = [[sys.executable, "-B", str(root / path)] for path in (
            AUTH_TEST, AUTH_CHECK, "scripts/ci/test_pq_lifetime_budget.py", "scripts/ci/pq_lifetime_budget.py")]
        review = {"schema": "trnm-authority-pq128-source-binding-review-v1", "baseline": BASE,
                  "code_checkpoint": checkpoint, "code_checkpoint_tree": tree, "head_before": head,
                  "authority_sources": authority_records, "lifetime_sources": lifetime_records,
                  "files": [{"path": p, "before_sha256": sha(baseline[p]), "after_sha256": sha(updated[p])} for p in BASELINE_BLOBS],
                  "validation_commands": commands, "native_tests_executed": False,
                  "whole_chain_pq_qualified": False, "production_activation": False}
        write_json(output / "review.json", review)
        for path, (raw, _record) in cache.items():
            require(read_regular(root, path)[0] == raw, "selected source changed before application: " + path)
        for path in BASELINE_BLOBS:
            require(read_regular(root, path)[0] == baseline[path], "binding target changed before application: " + path)
        results = []
        if args.apply:
            for path in BASELINE_BLOBS:
                replace_regular(root, path, baseline[path], updated[path]); applied.append(path)
            for path, (raw, _record) in cache.items():
                require(read_regular(root, path)[0] == raw, "selected source changed after application: " + path)
            if not args.defer_validation:
                for index, command in enumerate(commands, 1):
                    result = run_logged(root, output, "updated-check-" + str(index), command)
                    results.append(result)
                require(all(result["exit_code"] == 0 for result in results),
                        "updated Python validation failed; all four outputs retained, no automatic rollback")
                auth_result = strict_json((output / "updated-check-2.stdout.log").read_bytes())
                require(auth_result.get("status") == "HOLD"
                        and auth_result.get("source_consistency") == "PASS"
                        and auth_result.get("source_revision") == checkpoint
                        and auth_result.get("source_files_sha256") == authority_files
                        and auth_result.get("reviewed_source_lock_sha256") == canonical_table(checkpoint, authority_files)
                        and all(auth_result.get(flag) is False for flag in (
                            "coverage_complete", "provenance_authenticated", "native_tests_executed",
                            "whole_chain_pq_qualified", "production_activation")),
                        "updated authority checker identity or limited scope differs")
                lifetime_result = strict_json((output / "updated-check-4.stdout.log").read_bytes())
                require(lifetime_result.get("status") == "HOLD"
                        and lifetime_result.get("experiment", {}).get("source_revision") == checkpoint
                        and lifetime_result.get("source_files_sha256") == lifetime_files
                        and lifetime_result.get("source_lock_sha256") == sha(updated[LOCK])
                        and lifetime_result.get("source_revision_bound") is True
                        and lifetime_result.get("actual_lifetime_failure_bound") is None
                        and all(lifetime_result.get(flag) is False for flag in (
                            "whole_chain_pq_qualified", "pq_128_qualified", "production_activation",
                            "composition_coverage_proved", "theorem_applicability_verified")),
                        "updated lifetime checker identity or limited scope differs")
            for path, (raw, _record) in cache.items():
                require(read_regular(root, path)[0] == raw, "selected source changed during validation: " + path)
            for path in BASELINE_BLOBS:
                require(read_regular(root, path)[0] == updated[path], "updated binding target changed: " + path)
        require(git(root, "rev-parse", "HEAD").stdout.decode().strip() == head, "HEAD changed during source binding")
        status = "PREPARED_NO_WRITES" if not args.apply else ("APPLIED_VALIDATION_DEFERRED" if args.defer_validation else "APPLIED_PYTHON_CHECKS_PASSED_SECURITY_HOLD")
        write_json(output / "result.json", {"status": status, "applied": applied,
                   "validation": results, "native_tests_executed": False, "production_activation": False})
        print(json.dumps({"status": status, "output": str(output), "changed_files": len(applied)}, sort_keys=True))
        for command in commands:
            print(shlex.join(command))
        return 0
    except (BindingError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        failure = {"status": "REFUSE", "reason": str(error), "applied": applied,
                   "automatic_rollback_performed": False, "native_tests_executed": False}
        if output is not None and output.is_dir() and not (output / "failure.json").exists():
            write_json(output / "failure.json", failure)
        print(json.dumps(failure, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
