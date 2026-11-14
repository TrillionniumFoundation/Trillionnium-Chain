#!/usr/bin/env python3
"""Restore one owned checkout's visibility only after original physical checks.

No checkout/reset, existing-file replacement, global configuration change, source
edit, qualification run, push, or PR creation belongs to this helper. Optional
recovery materializes only absent skip-worktree files from their exact HEAD blob.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import traceback
import types

if not __debug__ or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE"):
    raise RuntimeError("optimized Python is refused")

ROOT = Path("/home/qian-qi/work/chain-pon-outcome-7612-final")
HEAD = "04f5b5515774aab6663bb80cf7831fe07367ba81"
BRANCH = "fix/chain-pon-learning-outcome-composition-20261111-7612"
EXPECTED_ENTRIES = 29041
GIT = "/usr/bin/git"
GUARD = "scripts/ci/verify_ci_source.py"
GUARD_SHA = "0ddfd07719eae98913348c82b06d3e4522d721c353d9b01d6deac0dfda619946"
RUNNER_SHA = "01fcfb229fba3f6dae4d8709e18a23992c472b2eb3844880b5d301ee904d2ba6"
OUT_NAME = "chain-pon-outcome-7612-checkout-visibility"
CONFIG_PATTERN = (
    r"^(core\.(ignorestat|filemode|ignorecase|symlinks|trustctime|checkstat|"
    r"fsmonitor|preloadindex|sparsecheckout|sparsecheckoutcone|splitindex|"
    r"untrackedcache|repositoryformatversion|worktree|bare)|"
    r"extensions\.(worktreeconfig|objectformat)|index\.(version|sparse))$"
)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def path_record(path):
    return {"path": os.fsdecode(path), "path_base64": base64.b64encode(path).decode()}


def fingerprint(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def exact_file(path):
    """Read a canonical regular metadata file without following its final link."""
    require(path.is_absolute() and path.resolve(strict=True) == path,
            "noncanonical metadata path: " + str(path))
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), "nonregular metadata file: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before),
                "metadata file changed before read")
        raw = stream.read()
        require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before),
                "metadata file changed during read")
    require(fingerprint(path.lstat()) == fingerprint(before),
            "metadata path changed during read")
    return raw


def write_json(path, value):
    with path.open("x") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


class Journal:
    def __init__(self, out, environment):
        self.out, self.env, self.rows = out, environment, []

    def save(self):
        value = {"schema": "chain-checkout-visibility-command-observation-v1",
                 "source_head": HEAD, "source_root": str(ROOT), "commands": self.rows}
        temporary = self.out / "commands.json.tmp"
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        temporary.replace(self.out / "commands.json")

    def run(self, label, command, *, data=None, accepted=(0,), timeout=600,
            environment=None):
        started = now()
        print("BEGIN", label, started, flush=True)
        if data is not None:
            (self.out / (label + ".stdin")).write_bytes(data)
        code, output, errors, problem = None, b"", b"", None
        try:
            process = subprocess.run(command, cwd=ROOT, env=environment or self.env,
                                     input=data, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=timeout)
            code, output, errors = process.returncode, process.stdout, process.stderr
        except subprocess.TimeoutExpired as error:
            output, errors = error.stdout or b"", error.stderr or b""
            problem = "TimeoutExpired"
        except OSError as error:
            problem = repr(error)
        (self.out / (label + ".stdout")).write_bytes(output)
        (self.out / (label + ".stderr")).write_bytes(errors)
        self.rows.append({"label": label, "command": command, "cwd": str(ROOT),
                          "started_at": started, "finished_at": now(),
                          "exit_code": code, "execution_error": problem,
                          "stdout_sha256": digest(output), "stdout_bytes": len(output),
                          "stderr_sha256": digest(errors), "stderr_bytes": len(errors),
                          "stdin_sha256": None if data is None else digest(data)})
        self.save()
        print("END", label, code, flush=True)
        require(problem is None and code in accepted, "command failed: " + label)
        return output, code

    def git(self, label, *args, **kwargs):
        return self.run(label, [GIT, "--no-replace-objects", *args], **kwargs)


def parse_tree(raw):
    require(raw.endswith(b"\0"), "incomplete HEAD tree listing")
    entries = {}
    for record in raw.split(b"\0")[:-1]:
        metadata, path = record.split(b"\t", 1)
        mode, kind, oid, size = metadata.split()
        require(path and path not in entries and kind == b"blob" and size.isdigit()
                and re.fullmatch(rb"[0-9a-f]{40}", oid) is not None,
                "unsupported, duplicate or malformed HEAD entry")
        require(all(part not in (b"", b".", b"..") for part in path.split(b"/")),
                "noncanonical HEAD path")
        entries[path] = (mode, oid, int(size))
    return entries


def check_index(raw, entries):
    require(raw.endswith(b"\0"), "incomplete index listing")
    actual, problems = {}, []
    for record in raw.split(b"\0")[:-1]:
        metadata, path = record.split(b"\t", 1)
        mode, oid, stage = metadata.split()
        expected = entries.get(path)
        if path in actual or stage != b"0" or expected is None or (mode, oid) != expected[:2]:
            problems.append(dict(path_record(path), stage=os.fsdecode(stage),
                                 index_mode=os.fsdecode(mode), index_oid=os.fsdecode(oid)))
        actual[path] = (mode, oid, stage)
    for path in set(entries) - set(actual):
        problems.append(dict(path_record(path), error="HEAD path absent from index"))
    return problems


def parse_flags(raw, entries):
    require(raw.endswith(b"\0"), "incomplete index visibility listing")
    flags = {}
    for record in raw.split(b"\0")[:-1]:
        require(len(record) > 2 and record[1:2] == b" " and record[2:] not in flags,
                "malformed or duplicate visibility entry")
        flags[record[2:]] = record[:1]
    require(set(flags) == set(entries), "visibility/index/HEAD path rosters differ")
    return flags


def secure_parent(root_fd, path, *, create=False):
    parts = path.split(b"/")
    require(all(part not in (b"", b".", b"..") for part in parts), "unsafe tracked path")
    parent = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, 0o755, dir_fd=parent)
                except FileExistsError:
                    pass
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=parent)
            os.close(parent)
            parent = following
        return parent, parts[-1]
    except BaseException:
        os.close(parent)
        raise


def really_absent(root_fd, path):
    """An existing symlink, directory or inaccessible parent is never a missing file."""
    try:
        parent, name = secure_parent(root_fd, path)
    except FileNotFoundError:
        return True
    try:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
            return False
        except FileNotFoundError:
            return True
    finally:
        os.close(parent)


def physical_scan(out, label, guard, root_fd, entries, flags):
    missing, problems, count, total = [], [], 0, 0
    with (out / (label + ".jsonl")).open("x") as stream:
        for path, (mode, oid, size) in entries.items():
            row = dict(path_record(path), mode=mode.decode(), expected_oid=oid.decode(),
                       expected_bytes=size)
            try:
                actual = guard._tracked_blob(root_fd, path, mode, size)
                require(actual == oid.decode(), "physical blob differs from HEAD")
                row.update(result="MATCH", actual_oid=actual)
                count, total = count + 1, total + size
            except (OSError, ValueError, RuntimeError) as error:
                absent = isinstance(error, FileNotFoundError) and really_absent(root_fd, path)
                recoverable = absent and flags[path].upper() == b"S" and mode in (b"100644", b"100755")
                row.update(result="MISSING_SKIPPED" if recoverable else "REFUSED",
                           error=type(error).__name__ + ": " + str(error))
                if recoverable:
                    missing.append(path)
                else:
                    problems.append(row)
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    summary = {"schema": "chain-original-physical-blob-scan-v1", "head": HEAD,
               "expected_entries": len(entries), "matching_entries": count,
               "matching_bytes": total, "missing_skipped": [path_record(p) for p in missing],
               "refused": problems, "guard_sha256": GUARD_SHA,
               "original_function": "_tracked_blob(root_fd, path, mode, size)"}
    write_json(out / (label + ".json"), summary)
    return missing, problems, summary


def recover_blob(journal, directory, root_fd, path, entry, number):
    """Hash a fresh Git blob before publishing an exclusive, no-overwrite link."""
    mode, oid, size = entry
    label = "restore-" + str(number).zfill(3)
    temporary = directory / (label + ".blob")
    errors = journal.out / (label + ".stderr")
    command = [GIT, "--no-replace-objects", "cat-file", "blob", oid.decode()]
    started = now()
    record = dict(path_record(path), command=command, started_at=started,
                  expected_oid=oid.decode(), expected_bytes=size, source_head=HEAD,
                  result="NOT_PUBLISHED", entry_created=False, existing_path_replaced=False)
    try:
        with temporary.open("xb") as output, errors.open("xb") as diagnostics:
            process = subprocess.run(command, cwd=ROOT, env=journal.env,
                                     stdin=subprocess.DEVNULL, stdout=output,
                                     stderr=diagnostics, timeout=600)
        record["exit_code"] = process.returncode
        record["stderr_sha256"] = digest(errors.read_bytes())
        require(process.returncode == 0, "exact HEAD blob could not be read")
        require(temporary.stat().st_size == size, "restored blob size differs from HEAD")
        value = hashlib.sha1(b"blob " + str(size).encode() + b"\0", usedforsecurity=False)
        content = hashlib.sha256()
        with temporary.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                value.update(chunk)
                content.update(chunk)
        record.update(actual_oid=value.hexdigest(), sha256=content.hexdigest(), bytes=size)
        require(value.hexdigest() == oid.decode(), "restored blob is not the exact HEAD object")
        os.chmod(temporary, 0o755 if mode == b"100755" else 0o644)
        parent, name = secure_parent(root_fd, path, create=True)
        try:
            # link() has exclusive destination semantics: an intervening existing
            # file, symlink or directory is refused; no rename/replace fallback.
            os.link(temporary, name, dst_dir_fd=parent, follow_symlinks=False)
            record.update(result="LINK_CREATED_UNVERIFIED", entry_created=True)
            os.fsync(parent)
        finally:
            os.close(parent)
        record["result"] = "RESTORED_EXACT_HEAD_BLOB"
    except BaseException as error:
        record["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        record["finished_at"] = now()
        if errors.exists():
            record["stderr_sha256"] = digest(errors.read_bytes())
        write_json(journal.out / (label + ".json"), record)
        if temporary.exists():
            temporary.unlink()  # Only this invocation's external staging link.
    return record


def snapshot_metadata(journal, label):
    paths = {}
    for name, relative in (("index", "index"), ("HEAD", "HEAD")):
        raw, _ = journal.git(label + "-locate-" + name, "rev-parse",
                             "--path-format=absolute", "--git-path", relative)
        path = Path(os.fsdecode(raw).strip())
        data = exact_file(path)
        (journal.out / (label + "-" + name + ".original")).write_bytes(data)
        paths[name] = {"path": str(path), "bytes": len(data), "sha256": digest(data)}
    shared, _ = journal.git(label + "-shared-index", "rev-parse", "--shared-index-path")
    if shared.strip():
        path = Path(os.fsdecode(shared).strip())
        if not path.is_absolute():
            path = ROOT / path
        data = exact_file(path)
        (journal.out / (label + "-shared-index.original")).write_bytes(data)
        paths["shared_index"] = {"path": str(path), "bytes": len(data), "sha256": digest(data)}
    write_json(journal.out / (label + "-metadata.json"), paths)
    return paths


def finish(out, result):
    write_json(out / "summary.json", result)
    with (out / "SHA256SUMS").open("x") as output:
        for path in sorted(out.rglob("*")):
            require(not path.is_symlink(), "symlink in visibility observations")
            if path.is_file() and path.name != "SHA256SUMS":
                output.write(digest(path.read_bytes()) + "  " + path.relative_to(out).as_posix() + "\n")
    print("CHECKOUT_VISIBILITY_FINISHED", json.dumps(result, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restore-missing-skipped", action="store_true",
                        help="recover only absent skip-worktree regular files from exact HEAD blobs")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    require(ROOT.is_absolute() and ROOT.resolve(strict=True) == ROOT, "noncanonical owned checkout")
    out = args.out or ROOT.parent / OUT_NAME
    require(out.is_absolute() and out.parent == ROOT.parent and
            out.name.startswith(OUT_NAME) and out.parent.resolve(strict=True) == out.parent,
            "observations must be a fresh owned sibling directory")
    out.mkdir(mode=0o700)
    (out / "repair-runner.py").write_bytes(Path(__file__).read_bytes())
    environment = os.environ.copy()
    removed = sorted(key for key in environment if key.startswith("GIT_"))
    for key in removed:
        environment.pop(key)
    environment.update(PYTHONDONTWRITEBYTECODE="1", GIT_NO_REPLACE_OBJECTS="1",
                       GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    journal = Journal(out, environment)
    write_json(out / "invocation.json", {
        "source_root": str(ROOT), "source_head": HEAD, "expected_entries": EXPECTED_ENTRIES,
        "restore_missing_skipped": args.restore_missing_skipped,
        "removed_inherited_git_variable_names": removed, "started_at": now(),
        "frozen_runner_sha256": RUNNER_SHA, "next_provider_run_started": False,
        "source_file_overwrites_allowed": False, "global_config_changes_allowed": False})
    result = {"schema": "chain-checkout-visibility-result-v1", "result": "FAIL",
              "source_head": HEAD, "source_root": str(ROOT), "restored_files": [],
              "hidden_paths_cleared": 0, "local_ignorestat_changed": False,
              "native_tests_executed": 0, "provider_preparation_executed": False,
              "next_provider_run_started": False, "frozen_runner_sha256": RUNNER_SHA,
              "production_activation": False}
    root_fd = None
    try:
        top, _ = journal.git("source-root", "rev-parse", "--show-toplevel")
        require(Path(os.fsdecode(top).strip()).resolve(strict=True) == ROOT, "wrong Git source root")
        head, _ = journal.git("head-before", "rev-parse", "HEAD")
        require(head.decode().strip() == HEAD, "unexpected HEAD")
        branch, _ = journal.git("branch-before", "branch", "--show-current")
        require(branch.decode().strip() == BRANCH, "unexpected owned branch")
        commit, _ = journal.git("head-commit-original", "cat-file", "commit", HEAD)
        require(hashlib.sha1(b"commit " + str(len(commit)).encode() + b"\0" + commit,
                            usedforsecurity=False).hexdigest() == HEAD, "HEAD object identity differs")
        replacements, _ = journal.git("replacement-refs", "for-each-ref", "--format=%(refname)", "refs/replace/")
        require(not replacements.strip(), "replacement refs are refused")
        grafts, _ = journal.git("grafts-path", "rev-parse", "--path-format=absolute", "--git-path", "info/grafts")
        require(not Path(os.fsdecode(grafts).strip()).exists(), "grafted history is refused")
        metadata_before = snapshot_metadata(journal, "before")
        flags_raw, _ = journal.git("visibility-before", "ls-files", "-v", "-z")
        index_raw, _ = journal.git("index-stage-before", "ls-files", "--stage", "-z")
        tree_raw, _ = journal.git("head-tree-original", "ls-tree", "-r", "-l", "-z", "--full-tree", HEAD)
        entries = parse_tree(tree_raw)
        require(len(entries) == EXPECTED_ENTRIES, "unexpected fixed-HEAD tracked inventory")
        index_problems = check_index(index_raw, entries)
        write_json(out / "index-head-comparison.json", {"entries": len(entries), "problems": index_problems})
        require(not index_problems, "index stage/mode/OID differs from HEAD")
        flags = parse_flags(flags_raw, entries)
        hidden = {path: tag for path, tag in flags.items() if tag.islower() or tag == b"S"}
        write_json(out / "visibility-before.json", {"entries": len(flags),
            "hidden": [dict(path_record(p), tag=t.decode()) for p, t in hidden.items()]})
        journal.git("related-core-config-before", "config", "--show-origin", "--show-scope",
                    "--get-regexp", CONFIG_PATTERN, accepted=(0, 1))
        ignore, code = journal.git("ignorestat-before", "config", "--bool", "--get", "core.ignoreStat", accepted=(0, 1))
        require(code == 1 or ignore.strip() in (b"true", b"false"), "unexpected effective core.ignoreStat")

        guard_bytes, _ = journal.git("original-source-guard", "show", HEAD + ":" + GUARD)
        require(digest(guard_bytes) == GUARD_SHA and exact_file(ROOT / GUARD) == guard_bytes,
                "original source guard bytes differ")
        guard = types.ModuleType("chain_original_source_guard")
        guard.__file__ = str(ROOT / GUARD)
        exec(compile(guard_bytes, str(ROOT / GUARD), "exec"), guard.__dict__)
        require(list(inspect.signature(guard._tracked_blob).parameters) == ["root_fd", "path", "mode", "size"],
                "original physical-blob function signature differs")
        root_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for path in (b"scripts/project-preflight.sh", b"scripts/ci/project_boundary.py", GUARD.encode()):
            mode, oid, size = entries[path]
            require(guard._tracked_blob(root_fd, path, mode, size) == oid.decode(),
                    "original executable source differs before preflight")
        journal.run("project-preflight-original", ["bash", "scripts/project-preflight.sh"])

        missing, problems, scan = physical_scan(out, "physical-before", guard, root_fd, entries, flags)
        require(not problems, "existing bytes/modes or non-skipped missing files differ; no restoration or flags changed")
        require(not missing or args.restore_missing_skipped,
                "missing skip-worktree files require explicit --restore-missing-skipped; flags unchanged")
        if missing:
            with tempfile.TemporaryDirectory(prefix=OUT_NAME + "-blob-", dir=ROOT.parent) as directory:
                for number, path in enumerate(missing, 1):
                    result["restored_files"].append(
                        recover_blob(journal, Path(directory), root_fd, path, entries[path], number))
        missing_after, problems_after, scan_after = physical_scan(
            out, "physical-before-metadata-change", guard, root_fd, entries, flags)
        require(not missing_after and not problems_after and scan_after["matching_entries"] == len(entries),
                "full original physical verification did not pass; flags unchanged")
        current_head, _ = journal.git("head-before-metadata-change", "rev-parse", "HEAD")
        require(current_head.decode().strip() == HEAD, "HEAD changed during physical verification")
        current_index, _ = journal.git("index-before-metadata-change", "ls-files", "--stage", "-z")
        current_flags, _ = journal.git("flags-before-metadata-change", "ls-files", "-v", "-z")
        require(current_index == index_raw and current_flags == flags_raw,
                "index changed during physical verification")
        require(digest(exact_file(Path(metadata_before["index"]["path"]))) == metadata_before["index"]["sha256"],
                "raw index changed during physical verification")
        current_ignore, current_code = journal.git("ignorestat-before-change", "config", "--bool", "--get",
                                                  "core.ignoreStat", accepted=(0, 1))
        require((current_ignore, current_code) == (ignore, code), "core.ignoreStat changed during validation")

        if code == 0 and ignore.strip() == b"true":
            journal.git("set-local-ignorestat-false", "config", "--local", "core.ignoreStat", "false")
            result["local_ignorestat_changed"] = True
            effective, status = journal.git("ignorestat-after-change", "config", "--bool", "--get",
                                            "core.ignoreStat", accepted=(0, 1))
            require(status == 0 and effective.strip() == b"false", "local core.ignoreStat false is not effective")
        for label, option, paths in (
            ("clear-assume-unchanged", "--no-assume-unchanged", [p for p, t in hidden.items() if t.islower()]),
            ("clear-skip-worktree", "--no-skip-worktree", [p for p, t in hidden.items() if t.upper() == b"S"]),
        ):
            if paths:
                journal.git(label, "update-index", option, "-z", "--stdin",
                            data=b"\0".join(sorted(paths)) + b"\0")
        result["hidden_paths_cleared"] = len(hidden)

        # The original complete gate runs with normal optional locking semantics.
        gate_environment = dict(environment)
        gate_environment.pop("GIT_OPTIONAL_LOCKS", None)
        receipt_raw, _ = journal.run("original-source-after",
            [sys.executable, "-B", GUARD, "--kind", "head", "--expected-head", HEAD,
             "--output", str(out / "original-source-after.json")], environment=gate_environment)
        require(receipt_raw == (out / "original-source-after.json").read_bytes(), "original source receipt bytes differ")
        receipt = json.loads(receipt_raw)
        require(receipt["tested_commit"] == receipt["candidate"] == HEAD and
                receipt["tracked_worktree_verified"] is True and receipt["tracked_entries"] == EXPECTED_ENTRIES and
                receipt["tests_executed_by_identity_check"] is False, "original source gate did not verify full fixed HEAD")
        final_flags, _ = journal.git("visibility-after", "ls-files", "-v", "-z")
        require(not any(tag.islower() or tag == b"S" for tag in parse_flags(final_flags, entries).values()),
                "index still hides tracked files")
        final_index, _ = journal.git("index-stage-after", "ls-files", "--stage", "-z")
        require(not check_index(final_index, entries), "index content changed while clearing visibility flags")
        status, _ = journal.git("status-after", "status", "--porcelain=v1",
                                "--untracked-files=all", "--ignore-submodules=none")
        require(not status, "source is not actually clean")
        final_head, _ = journal.git("head-after", "rev-parse", "HEAD")
        require(final_head.decode().strip() == HEAD, "HEAD changed")
        snapshot_metadata(journal, "after")
        journal.git("related-core-config-after", "config", "--show-origin", "--show-scope",
                    "--get-regexp", CONFIG_PATTERN, accepted=(0, 1))
        result.update(result="PASS", tested_tree=receipt["tested_tree"],
                      physical_entries_verified=receipt["tracked_entries"],
                      physical_bytes_verified=receipt["tracked_bytes"],
                      original_source_gate="PASS", frozen_runner_may_be_started=True)
    except BaseException as error:
        (out / "failure.txt").write_text(traceback.format_exc())
        result.update(error=type(error).__name__ + ": " + str(error),
                      frozen_runner_may_be_started=False)
    finally:
        if root_fd is not None:
            os.close(root_fd)
        journal.save()
    result["finished_at"] = now()
    finish(out, result)
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
