#!/usr/bin/env python3
"""Prepare only the owned final checkout, preserving its three evidence folders.

The frozen helper changes only its fixed ROOT. This wrapper never starts a build,
qualification runner, commit, push, or PR. Original source qualification runs
inside that helper only while the three verified untracked folders are outside
the checkout. They are restored before its successful observations are archived.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import traceback
import types

if not __debug__ or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE"):
    raise RuntimeError("optimized Python is refused")

ROOT = Path("/home/qian-qi/work/chain-pon-outcome-7612-final")
HEAD = "04f5b5515774aab6663bb80cf7831fe07367ba81"
BRANCH = "fix/chain-pon-learning-outcome-composition-20261111-7612"
EVIDENCE = "evidence/pon-learning-outcome-composition-20261111"
AUDIT = ROOT.parent / "chain-pon-outcome-7612-final-checkout-preparation"
HELPER_OUT = ROOT.parent / "chain-pon-outcome-7612-checkout-visibility-final"
FROZEN_SHA = "6c8ae308445f6b42078be33fd3fc133db4984fa024e4012ec785f60677911fec"
DERIVED_SHA = "9c42662fa4f4ffa53860e3593b754f6ca2de4a81cffdf2342e4711711e969d3e"
GUARD_SHA = "0ddfd07719eae98913348c82b06d3e4522d721c353d9b01d6deac0dfda619946"
OLD_ROOT = b'ROOT = Path("/home/qian-qi/work/chain-pon-outcome-7612-publish")'
NEW_ROOT = b'ROOT = Path("/home/qian-qi/work/chain-pon-outcome-7612-final")'
OWNED = ("native-c2-attempt1", "native-c2-attempt2", "checkout-visibility")
FAILED_PINS = (
    "bd84f0e75104d5bbc27ce9ea02aa281fd0c731c29572b0ceee41cb6c5a7b93b5",
    "8671856a9ab7f0a33b6729894527a3a451e1d866627da4587d2ed9dfaf0312de",
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    with path.open("x") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def inventory(directory):
    require(directory.resolve(strict=True) == directory and directory.is_dir(),
            "noncanonical evidence directory")
    rows = []
    for path in sorted(directory.rglob("*")):
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode), "symlink in owned evidence")
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),
                "special file in owned evidence")
        if stat.S_ISREG(info.st_mode):
            raw = path.read_bytes()
            require(len(raw) == info.st_size, "evidence file changed during inventory")
            rows.append({"path": path.relative_to(directory).as_posix(),
                         "bytes": len(raw), "sha256": sha(raw)})
    return rows


def directory_identity(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and not path.is_symlink(), "owned path is not an ordinary directory")
    return {"device": info.st_dev, "inode": info.st_ino}


def rename_noreplace(source, destination):
    """Linux atomic rename with an exclusive destination; never overwrite."""
    require(source.parent.resolve(strict=True) == source.parent and
            destination.parent.resolve(strict=True) == destination.parent,
            "noncanonical move parent")
    libc = ctypes.CDLL(None, use_errno=True)
    operation = getattr(libc, "renameat2", None)
    require(operation is not None, "atomic no-overwrite rename is unavailable")
    operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint]
    operation.restype = ctypes.c_int
    source_fd = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    target_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        require(os.fstat(source_fd).st_dev == os.fstat(target_fd).st_dev,
                "atomic staging crosses filesystems")
        if operation(source_fd, os.fsencode(source.name), target_fd,
                     os.fsencode(destination.name), 1) != 0:  # RENAME_NOREPLACE
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(destination))
    finally:
        os.close(source_fd)
        os.close(target_fd)


class Journal:
    def __init__(self, environment):
        self.env, self.commands, self.moves = environment, [], []

    def save(self):
        temporary = AUDIT / "journal.json.tmp"
        temporary.write_text(json.dumps({"commands": self.commands, "moves": self.moves},
                                        indent=2, sort_keys=True) + "\n")
        temporary.replace(AUDIT / "journal.json")

    def run(self, label, command, *, accepted=(0,), timeout=600):
        stdout, stderr = AUDIT / (label + ".stdout"), AUDIT / (label + ".stderr")
        started, code, failure, child = now(), None, None, None
        print("BEGIN", label, started, flush=True)
        with stdout.open("xb") as output, stderr.open("xb") as diagnostics:
            try:
                child = subprocess.Popen(command, cwd=ROOT, env=self.env,
                                         stdin=subprocess.DEVNULL, stdout=output,
                                         stderr=diagnostics, start_new_session=True)
                code = child.wait(timeout=timeout)
            except BaseException as error:
                failure = type(error).__name__ + ": " + str(error)
                if child is not None and child.poll() is None:
                    try:
                        os.killpg(child.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        code = child.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        code = child.wait(timeout=15)
        row = {"label": label, "command": command, "cwd": str(ROOT), "started_at": started,
               "finished_at": now(), "exit_code": code, "execution_error": failure,
               "stdout": stdout.name, "stderr": stderr.name,
               "stdout_bytes": stdout.stat().st_size, "stderr_bytes": stderr.stat().st_size,
               "stdout_sha256": sha(stdout.read_bytes()), "stderr_sha256": sha(stderr.read_bytes())}
        self.commands.append(row)
        self.save()
        print("END", label, code, flush=True)
        require(failure is None and code in accepted, "preparation command failed: " + label)
        return stdout.read_bytes(), row

    def git(self, label, *args):
        return self.run(label, ["/usr/bin/git", "--no-replace-objects", *args])[0]


def verify_owned(directory, name, pin):
    manifest_raw = (directory / "ARCHIVE_MANIFEST.json").read_bytes()
    require(sha(manifest_raw) == pin, "owned archive manifest pin differs: " + name)
    manifest = json.loads(manifest_raw)
    require(manifest["source_head"] == HEAD, "owned archive source differs")
    if name == "checkout-visibility":
        require(manifest["schema"] == "chain-checkout-visibility-archive-v1" and manifest["result"] == "PASS",
                "published-checkout visibility archive is not complete PASS")
        summary = json.loads((directory / "summary.json").read_text())
        require(summary["result"] == "PASS" and summary["source_head"] == HEAD and
                summary["source_root"] == "/home/qian-qi/work/chain-pon-outcome-7612-publish" and
                summary["physical_entries_verified"] == 29041 and summary["original_source_gate"] == "PASS" and
                summary["native_tests_executed"] == 0 and summary["provider_preparation_executed"] is False,
                "published-checkout visibility result differs")
        require(sha((directory / "repair-runner.py").read_bytes()) == FROZEN_SHA,
                "published-checkout repair helper differs")
    else:
        failed = ["workspace-strict-clippy"] if name == OWNED[0] else ["source-before", "source-after"]
        require(manifest["schema"] == "pon-learning-outcome-archive-manifest-v1" and
                manifest["original_summary_result"] == "FAIL" and manifest["failed_commands"] == failed,
                "historical failure was relabeled")
    rows = manifest["files"]
    expected = {row["path"]: row for row in rows}
    require(len(expected) == len(rows), "duplicate owned archive member")
    for path in expected:
        require(path and not Path(path).is_absolute() and ".." not in Path(path).parts,
                "unsafe owned archive member")
    actual = {row["path"]: row for row in inventory(directory) if row["path"] != "ARCHIVE_MANIFEST.json"}
    require(actual == expected, "owned archive bytes or inventory differ: " + name)
    return {"name": name, "manifest_sha256": pin, "files": inventory(directory),
            "identity": directory_identity(directory)}


def require_only_owned_untracked(journal, label):
    raw = journal.git(label + "-status", "status", "--porcelain=v1", "-z", "--untracked-files=all")
    prefixes = tuple((EVIDENCE + "/" + name + "/").encode() for name in OWNED)
    for entry in raw.split(b"\0"):
        if entry:
            require(entry[:3] == b"?? " and entry[3:].startswith(prefixes),
                    "unexpected tracked change or unowned untracked path")
    # Ignored raw logs are also checked; no other untracked directory is moved.
    for suffix, options in (("visible", ("--others", "--exclude-standard")),
                            ("ignored", ("--others", "--ignored", "--exclude-standard"))):
        listing = journal.git(label + "-" + suffix, "ls-files", *options, "-z")
        require(all(not path or path.startswith(prefixes) for path in listing.split(b"\0")),
                "unowned untracked/ignored file is present")
    tracked = journal.git(label + "-owned-not-tracked", "ls-files", "-z", "--",
                          *[EVIDENCE + "/" + name for name in OWNED])
    require(not tracked, "an owned staging directory contains tracked source")


def verify_helper_output(directory):
    files = {row["path"]: row for row in inventory(directory)}
    sums = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        require(re.fullmatch(r"[0-9a-f]{64}", digest) and name in files and name not in sums,
                "invalid or duplicate original helper checksum")
        require(files[name]["sha256"] == digest, "original helper checksum differs")
        sums[name] = digest
    require(set(sums) == set(files) - {"SHA256SUMS"}, "original helper checksum inventory incomplete")
    summary = json.loads((directory / "summary.json").read_text())
    require(summary["result"] == "PASS" and summary["source_head"] == HEAD and
            summary["source_root"] == str(ROOT) and summary["original_source_gate"] == "PASS" and
            summary["physical_entries_verified"] == 29041 and summary["native_tests_executed"] == 0 and
            summary["provider_preparation_executed"] is False and summary["next_provider_run_started"] is False,
            "final checkout helper did not finish original source verification")
    require(sha((directory / "repair-runner.py").read_bytes()) == DERIVED_SHA, "derived helper bytes differ")
    return files, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frozen-helper", type=Path, required=True)
    parser.add_argument("--visibility-manifest-sha", required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{64}", args.visibility_manifest_sha) is not None,
            "visibility manifest SHA must be canonical")
    require(ROOT.resolve(strict=True) == ROOT and AUDIT.parent.resolve(strict=True) == AUDIT.parent,
            "noncanonical final checkout")
    require(not HELPER_OUT.exists(), "final helper output already exists; inspect before retrying")
    require(not (ROOT / EVIDENCE / "checkout-visibility-final").exists(), "final visibility archive already exists")
    AUDIT.mkdir(mode=0o700)
    staging = AUDIT / "staged-owned-evidence"
    staging.mkdir(mode=0o700)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(PYTHONDONTWRITEBYTECODE="1", GIT_NO_REPLACE_OBJECTS="1",
                       GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    journal = Journal(environment)
    records, failures, helper_summary = [], [], None
    result = {"schema": "chain-final-checkout-preparation-v1", "result": "FAIL",
              "source_head": HEAD, "source_root": str(ROOT),
              "frozen_helper_sha256": FROZEN_SHA, "derived_helper_sha256": DERIVED_SHA,
              "source_change": "only missing exact HEAD blobs restored by the unchanged helper",
              "build_or_gate_runner_started": False, "commit_or_remote_write_performed": False,
              "production_activation": False}
    (AUDIT / "preparation-wrapper.py").write_bytes(Path(__file__).read_bytes())
    try:
        original = args.frozen_helper.read_bytes()
        require(sha(original) == FROZEN_SHA and original.count(OLD_ROOT) == 1, "frozen helper differs")
        derived = original.replace(OLD_ROOT, NEW_ROOT)
        require(sha(derived) == DERIVED_SHA, "helper derivation changed more than its fixed ROOT")
        derived_path = AUDIT / "helper-final.py"
        with derived_path.open("xb") as output:
            output.write(derived)
        write_json(AUDIT / "helper-derivation.json", {
            "original_sha256": FROZEN_SHA, "derived_sha256": DERIVED_SHA,
            "only_replacement": {"before": OLD_ROOT.decode(), "after": NEW_ROOT.decode()},
            "expected_head": HEAD, "expected_entries": 29041, "output_directory": str(HELPER_OUT)})
        require(journal.git("head-before", "rev-parse", "HEAD").decode().strip() == HEAD, "unexpected final HEAD")
        require(journal.git("branch-before", "branch", "--show-current").decode().strip() == BRANCH, "unexpected branch")
        require(Path(journal.git("root-before", "rev-parse", "--show-toplevel").decode().strip()).resolve() == ROOT,
                "wrong Git checkout")
        # Execute only the original byte-bound preflight and physical helper.
        guard_raw = journal.git("guard-original", "show", HEAD + ":scripts/ci/verify_ci_source.py")
        require(sha(guard_raw) == GUARD_SHA, "original source verifier differs")
        guard = types.ModuleType("original_final_preparation_guard")
        guard.__file__ = str(ROOT / "scripts/ci/verify_ci_source.py")
        exec(compile(guard_raw, guard.__file__, "exec"), guard.__dict__)
        root_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for path in ("scripts/project-preflight.sh", "scripts/ci/project_boundary.py",
                         "scripts/ci/verify_ci_source.py"):
                tree = journal.git("bind-" + Path(path).stem, "ls-tree", "-l", "-z", HEAD, "--", path)
                items = tree.split(b"\0")
                require(len(items) == 2 and items[1] == b"", "preflight source entry differs")
                metadata, name = items[0].split(b"\t", 1)
                mode, kind, oid, size = metadata.split()
                require(kind == b"blob" and name == path.encode() and size.isdigit() and
                        guard._tracked_blob(root_fd, name, mode, int(size)) == oid.decode(),
                        "preflight source bytes or mode differ")
        finally:
            os.close(root_fd)
        journal.run("project-preflight-original", ["bash", "scripts/project-preflight.sh"])
        require_only_owned_untracked(journal, "before")
        pins = (*FAILED_PINS, args.visibility_manifest_sha)
        for name, pin in zip(OWNED, pins):
            records.append(verify_owned(ROOT / EVIDENCE / name, name, pin))
        write_json(AUDIT / "owned-evidence-before.json", records)
        for record in records:
            name = record["name"]
            source, target = ROOT / EVIDENCE / name, staging / name
            move = {"name": name, "source": str(source), "staging": str(target),
                    "original_identity": record["identity"], "state": "PLANNED"}
            journal.moves.append(move)
            journal.save()
            rename_noreplace(source, target)
            move["state"] = "STAGED"
            journal.save()
            require(directory_identity(target) == record["identity"] and inventory(target) == record["files"],
                    "staged evidence differs from original")
        require(not journal.git("clean-while-staged", "status", "--porcelain=v1", "--untracked-files=all"),
                "unexpected untracked source remains while owned archives are staged")
        helper_stdout, invocation = journal.run("helper-invocation",
            [sys.executable, "-I", "-B", str(derived_path), "--restore-missing-skipped", "--out", str(HELPER_OUT)],
            timeout=7200)
        write_json(AUDIT / "helper-invocation.json", invocation)
        _, helper_summary = verify_helper_output(HELPER_OUT)
        marker = [line for line in helper_stdout.splitlines() if line.startswith(b"CHECKOUT_VISIBILITY_FINISHED ")]
        require(len(marker) == 1 and json.loads(marker[0].split(b" ", 1)[1]) == helper_summary,
                "original helper completion marker differs")
    except BaseException as error:
        failures.append(type(error).__name__ + ": " + str(error))
        (AUDIT / "preparation-failure.txt").write_text(traceback.format_exc())
    finally:
        # Reconcile actual paths and original inode identities even if an error
        # occurred immediately after rename and before its journal update.
        for record in records:
            source, staged = ROOT / EVIDENCE / record["name"], staging / record["name"]
            try:
                if staged.exists():
                    require(directory_identity(staged) == record["identity"], "staged ownership identity changed")
                    rename_noreplace(staged, source)
                require(directory_identity(source) == record["identity"], "restored directory identity differs")
                require(inventory(source) == record["files"], "restored evidence bytes differ")
                for move in journal.moves:
                    if move["name"] == record["name"]:
                        move["state"] = "RESTORED_AND_BYTE_VERIFIED"
                journal.save()
            except BaseException as error:
                failures.append("restore " + record["name"] + ": " + type(error).__name__ + ": " + str(error))
        write_json(AUDIT / "owned-evidence-restoration.json", {
            "all_restored_and_byte_identical": not any(item.startswith("restore ") for item in failures),
            "records": records, "failures": failures})
    if not failures:
        try:
            require(helper_summary is not None, "successful helper result is missing")
            require_only_owned_untracked(journal, "restored")
            require(journal.git("head-after", "rev-parse", "HEAD").decode().strip() == HEAD, "HEAD changed")
            raw_files, _ = verify_helper_output(HELPER_OUT)
            archive_staging = AUDIT / "completed-helper-archive"
            shutil.copytree(HELPER_OUT, archive_staging)
            require({row["path"]: row for row in inventory(archive_staging)} == raw_files,
                    "copied final helper original bytes differ")
            for name in ("helper-invocation.json", "helper-invocation.stdout", "helper-invocation.stderr",
                         "helper-derivation.json", "owned-evidence-before.json",
                         "owned-evidence-restoration.json", "preparation-wrapper.py"):
                data = (AUDIT / name).read_bytes()
                with (archive_staging / name).open("xb") as output:
                    output.write(data)
            write_json(archive_staging / "ARCHIVE_MANIFEST.json", {
                "schema": "chain-checkout-visibility-final-archive-v1", "source_head": HEAD,
                "result": "PASS", "derived_helper_sha256": DERIVED_SHA,
                "original_three_archives_restored_byte_identically": True,
                "files": inventory(archive_staging)})
            snapshot = inventory(archive_staging)
            destination = ROOT / EVIDENCE / "checkout-visibility-final"
            rename_noreplace(archive_staging, destination)
            require(inventory(destination) == snapshot, "published final-helper archive bytes differ")
            result.update(result="PASS", original_three_archives_restored_byte_identically=True,
                          helper_original_source_gate="PASS", helper_exit_code=0,
                          archive=str(destination),
                          archive_manifest_sha256=sha((destination / "ARCHIVE_MANIFEST.json").read_bytes()),
                          current_worktree_has_owned_untracked_evidence=True,
                          c3_source_after_commit_check_still_required=True)
        except BaseException as error:
            failures.append("archive: " + type(error).__name__ + ": " + str(error))
            (AUDIT / "archive-failure.txt").write_text(traceback.format_exc())
    result.update(failures=failures, finished_at=now())
    journal.save()
    write_json(AUDIT / "summary.json", result)
    with (AUDIT / "SHA256SUMS").open("x") as output:
        for row in inventory(AUDIT):
            if row["path"] != "SHA256SUMS":
                output.write(row["sha256"] + "  " + row["path"] + "\n")
    print("FINAL_CHECKOUT_PREPARATION_FINISHED", json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    def interrupted(_number, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
