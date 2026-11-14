#!/usr/bin/python3
"""Package the closed M6 repository-truth execution after an exact terminal handoff.
This program must not run against a live receipt directory. It does not run Git,
source verification, tests, builds, network requests, or the original lane.
"""
import argparse
import datetime
import hashlib
import json
import math
import os
import pathlib
import re
import stat
import sys
import zipfile

BASE = pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root")
RECEIPTS = BASE / "final-repository-truth-offline-2a6206-v1"
OUTPUT = BASE / "package-original-repository-truth-2a6206-v1-prci"
DRIVER = BASE / "run_final_rog_repository_truth_offline_v4.py"
SOURCE = BASE / "source"
CONFORMANCE = BASE / "final-python312-env/bin/python"
RUNTIME = BASE / "final-runtime-release-env/bin/python"
TOOLCHAIN = pathlib.Path("/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin")
BUNDLE_ROOT = BASE / "offline-source-bundles-v3"
HEAD = "2a62061177852dc3ebd200fa8d7c66c661a119a1"
TREE = "f8d170ff75990e879e93888a95e5408f36b36f6c"
START_HEAD = "08c9becab740ab2c375b970f376a7638f44c9e8e"
DRIVER_BYTES = 15187
DRIVER_SHA256 = "bbc62032fcb58443ee36cd59408c49d2d9694c5f709c48a30b6daf714a5ddd38"
SOURCE_BYTES = 423
SOURCE_SHA256 = "056b49f3825e2ca45533311fae3f6939782a1a29af41993bce1932ec3fc547bd"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
LABELS = [
    "initial-head", "initial-status", "pre-update-preflight",
    "local-bundle-verify", "local-bundle-list-heads", "fetch-exact-local-bundle",
    "fetched-commit", "fetched-tree", "fast-forward-ancestry", "fast-forward",
    "preflight-audit", "rust-version", "cargo-version", "conformance-environment",
    "runtime-environment", "verify-source-before", "repository-truth", "verify-source-after",
]

def require(ok, message):
    if not ok:
        raise ValueError(message)

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def signature(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns]

def open_regular(path):
    pure = pathlib.PurePosixPath(str(path))
    require(pure.is_absolute() and ".." not in pure.parts, "unsafe absolute input path")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in pure.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(pure.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=directory)
    finally:
        os.close(directory)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise ValueError("input is not a regular single-link file: " + str(path))
    return fd, info

def file_info(path):
    fd, before = open_regular(path)
    try:
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(before.st_size + 1)
        require(signature(os.fstat(fd)) == signature(before) and len(raw) == before.st_size,
                "output changed during readback")
        return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    finally:
        os.close(fd)

def save_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    observed = file_info(path)
    require(observed["bytes"] == len(raw) and observed["sha256"] == hashlib.sha256(raw).hexdigest(),
            "output readback differs")

def inventory():
    require(RECEIPTS.resolve(strict=True) == RECEIPTS, "receipt path is not canonical")
    files, directories = {}, []
    for base, names, filenames in os.walk(RECEIPTS, followlinks=False):
        for name in names:
            path = pathlib.Path(base) / name
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                    "non-directory/symlink in receipt directory")
            directories.append(str(path.relative_to(RECEIPTS)))
        for name in filenames:
            path = pathlib.Path(base) / name
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                    "non-regular or multiply-linked receipt")
            files[str(path.relative_to(RECEIPTS))] = signature(info)
    return {"files": files, "directories": sorted(directories)}

def expected_commands(bundle):
    prefix = ["git", "--no-replace-objects"]
    commands = {
        "initial-head": prefix + ["rev-parse", "HEAD"],
        "initial-status": prefix + ["status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"],
        "pre-update-preflight": ["bash", "scripts/project-preflight.sh", "--audit"],
        "local-bundle-verify": prefix + ["bundle", "verify", bundle],
        "local-bundle-list-heads": prefix + ["bundle", "list-heads", bundle],
        "fetch-exact-local-bundle": prefix + ["fetch", "--no-tags", "--no-recurse-submodules",
            "--no-write-fetch-head", "--no-auto-maintenance", bundle, "HEAD"],
        "fetched-commit": prefix + ["rev-parse", HEAD + "^{commit}"],
        "fetched-tree": prefix + ["rev-parse", HEAD + "^{tree}"],
        "fast-forward-ancestry": prefix + ["merge-base", "--is-ancestor", START_HEAD, HEAD],
        "fast-forward": prefix + ["merge", "--ff-only", "--no-edit", HEAD],
        "preflight-audit": ["bash", "scripts/project-preflight.sh", "--audit"],
        "rust-version": [str(TOOLCHAIN / "rustc"), "--version"],
        "cargo-version": [str(TOOLCHAIN / "cargo"), "--version"],
        "repository-truth": ["bash", "scripts/ci/ci_job.sh", "repository-truth"],
    }
    for label, python, wanted in (
        ("conformance", CONFORMANCE, {"numpy": "1.26.4", "cryptography": "50.0.2"}),
        ("runtime", RUNTIME, {"packaging": "26.3"}),
    ):
        program = ("import importlib.metadata as m,json,sys; expected=" + repr(wanted)
                   + "; actual={k:m.version(k) for k in expected}; "
                   + "assert actual==expected and sys.version_info[:2]==(3,12); "
                   + "print(json.dumps({'actual':actual,'python':sys.version,'executable':sys.executable}))")
        commands[label + "-environment"] = [str(python), "-B", "-c", program]
    for label, name in (("verify-source-before", "source-before.json"),
                        ("verify-source-after", "source-after.json")):
        commands[label] = [str(CONFORMANCE), "-B", "scripts/ci/verify_ci_source.py",
            "--kind", "head", "--expected-head", HEAD, "--output", str(RECEIPTS / name)]
    require(set(commands) == set(LABELS), "internal command roster differs")
    return commands

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terminal-summary-sha256", required=True)
    parser.add_argument("--terminal-exit-code", type=int, choices=(0, 1), required=True)
    args = parser.parse_args()
    require(not sys.flags.optimize, "optimized interpreter forbidden")
    require(re.fullmatch(r"[0-9a-f]{64}", args.terminal_summary_sha256) is not None,
            "a real operator-provided terminal summary SHA256 is required")
    require(pathlib.Path(__file__).resolve(strict=True).parent == OUTPUT,
            "packager must run only from the fixed new external package directory")
    require(OUTPUT.resolve(strict=True) == OUTPUT, "non-canonical package directory")
    require(set(path.name for path in OUTPUT.iterdir()) == {pathlib.Path(__file__).name},
            "package directory is not unused; do not retry/overwrite it")
    started = now()
    held, data, rows = [], {}, []

    def retain(path, member, role, expected_bytes=None, expected_sha=None):
        require(member not in data and re.fullmatch(r"[A-Za-z0-9._/-]+", member)
                and ".." not in pathlib.PurePosixPath(member).parts,
                "unsafe or duplicate member")
        fd, before = open_regular(path)
        held.append((fd, signature(before), str(path)))
        require(0 <= before.st_size <= MAX_FILE_BYTES, "input exceeds bounded packaging size")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(before.st_size + 1)
        require(signature(os.fstat(fd)) == signature(before) and len(raw) == before.st_size,
                "input changed during descriptor read")
        digest = hashlib.sha256(raw).hexdigest()
        if expected_bytes is not None:
            require(type(expected_bytes) is int and len(raw) == expected_bytes, "input size differs: " + str(path))
        if expected_sha is not None:
            require(re.fullmatch(r"[0-9a-f]{64}", expected_sha) is not None and digest == expected_sha,
                    "input SHA differs: " + str(path))
        data[member] = raw
        require(sum(len(value) for value in data.values()) <= MAX_TOTAL_BYTES, "package exceeds bounded total")
        rows.append({"path": member, "bytes": len(raw), "sha256": digest,
                     "origin": {"host": "rog", "path": str(path)},
                     "role": role, "source_version": signature(before)})
        return raw

    try:
        summary_raw = retain(RECEIPTS / "summary.json", "original/summary.json", "original-execution",
                             expected_sha=args.terminal_summary_sha256)
        original = json.loads(summary_raw)
        require(original["schema"] == "trnm-final-linux-repository-truth-offline-source-v4",
                "wrong original execution schema")
        require(original["head"] == HEAD and original["tree"] == TREE
                and original["expected_start_head"] == START_HEAD
                and original["source"] == str(SOURCE), "wrong exact original source")
        require(original["status"] in ("passed", "failed")
                and isinstance(original["finished_at"], str)
                and datetime.datetime.fromisoformat(original["finished_at"]).tzinfo is not None,
                "original receipt is not explicitly terminal")
        require(datetime.datetime.fromisoformat(original["finished_at"])
                >= datetime.datetime.fromisoformat(original["started_at"]), "invalid original timestamps")
        require(original["driver"] == {"path": str(DRIVER), "sha256": DRIVER_SHA256},
                "original producer differs")
        require(original["hosted_ci_qualification"] is False
                and original["host_provisioning_performed"] is False
                and original["remote_mutations_performed"] is False
                and original["local_bundle_source"] is True
                and original["remote_publication_verified"] is False
                and original["source_acquisition"] == "fixed-local-bundle", "qualification/source flags differ")
        bundle = original["bundle_input"]
        require(set(bundle) == {"path", "bytes", "sha256"} and type(bundle["bytes"]) is int
                and bundle["bytes"] > 0 and re.fullmatch(r"[0-9a-f]{64}", bundle["sha256"]),
                "invalid recorded local bundle identity")
        bundle_path = pathlib.PurePosixPath(bundle["path"])
        require(bundle_path.parent == BUNDLE_ROOT
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.bundle", bundle_path.name),
                "unsafe recorded bundle path")
        invocation = original["invocation"]
        argv = invocation["argv"]
        require(invocation["executable"] == str(CONFORMANCE) and invocation["optimize"] == 0,
                "original interpreter identity differs")
        require(isinstance(argv, list) and len(argv) == 15 and argv[0] == str(DRIVER),
                "original invocation arity differs")
        arguments = {}
        for pos in range(1, len(argv), 2):
            require(argv[pos] not in arguments, "duplicate original argument")
            arguments[argv[pos]] = argv[pos + 1]
        require(arguments == {
            "--head": HEAD, "--tree": TREE, "--evidence-dir": str(RECEIPTS),
            "--expected-start-head": START_HEAD, "--bundle-path": bundle["path"],
            "--bundle-bytes": str(bundle["bytes"]), "--bundle-sha256": bundle["sha256"],
        }, "original invocation values differ")
        require(original["bundle_before"] == original["bundle_after_fetch"]
                and {key: original["bundle_before"][key] for key in ("path", "bytes", "sha256")} == bundle,
                "recorded bundle identity/fence differs")
        commands = expected_commands(bundle["path"])
        steps = original["steps"]
        require(isinstance(steps, list) and [step["label"] for step in steps] == LABELS,
                "original full 18-step roster differs; preserve irregular failure separately")
        initial_inventory = inventory()
        names = {"summary.json", "source-before.json", "source-after.json"}
        for step in steps:
            label = step["label"]
            require(step["argv"] == commands[label] and step["cwd"] == str(SOURCE)
                    and step["timeout_seconds"] == (2700 if label == "repository-truth" else 300),
                    "original command/budget differs: " + label)
            require(type(step["exit"]) is int and isinstance(step["elapsed_seconds"], (int, float))
                    and not isinstance(step["elapsed_seconds"], bool) and math.isfinite(step["elapsed_seconds"])
                    and step["elapsed_seconds"] >= 0, "invalid original completion field")
            if label != "repository-truth":
                require(step["exit"] == 0, "original non-lane stage failed; preserve separately without normalization")
            for channel in ("stdout", "stderr"):
                name = label + "." + channel
                require(step[channel + "_path"] == str(RECEIPTS / name), "raw path differs")
                require(name not in names, "duplicate original raw path")
                names.add(name)
                retain(RECEIPTS / name, "original/" + name, "original-execution",
                       step[channel + "_bytes"], step[channel + "_sha256"])
        require(set(initial_inventory["files"]) == names and len(names) == 39,
                "unexpected/missing original files; notify operator before any exclusions: "
                + json.dumps({"unexpected": sorted(set(initial_inventory["files"]) - names),
                              "missing": sorted(names - set(initial_inventory["files"]))}))
        for name in ("source-before.json", "source-after.json"):
            retain(RECEIPTS / name, "original/" + name, "original-execution", SOURCE_BYTES, SOURCE_SHA256)
        require(len(rows) == 39, "original file count differs")
        original_bytes = sum(row["bytes"] for row in rows)
        source_raw = data["original/source-before.json"]
        require(source_raw == data["original/source-after.json"]
                == data["original/verify-source-before.stdout"]
                == data["original/verify-source-after.stdout"], "original source identities differ")
        identity = json.loads(source_raw)
        require(identity["tested_commit"] == HEAD and identity["tested_tree"] == TREE
                and identity["kind"] == "head" and identity["tracked_worktree_verified"] is True,
                "source sidecar fields differ")
        require(data["original/initial-head.stdout"].decode().strip() == START_HEAD
                and data["original/initial-status.stdout"] == b""
                and data["original/fetched-commit.stdout"].decode().strip() == HEAD
                and data["original/fetched-tree.stdout"].decode().strip() == TREE,
                "original recorded Git/source readback differs")
        require([line.split() for line in data["original/local-bundle-list-heads.stdout"].decode("ascii").splitlines()]
                == [[HEAD, "HEAD"]], "original bundle advertisement differs")
        lane = steps[LABELS.index("repository-truth")]
        require(type(original["lane_exit"]) is int and original["lane_exit"] == lane["exit"]
                and original["source_before_after_verified"] is True
                and isinstance(original["errors"], list)
                and all(isinstance(value, str) for value in original["errors"]), "original terminal fields disagree")
        derived = "passed" if not original["errors"] and lane["exit"] == 0 else "failed"
        require(original["status"] == derived and args.terminal_exit_code == (0 if derived == "passed" else 1),
                "actual terminal/status/lane mismatch; never relabel failure")
        retain(DRIVER, "driver/" + DRIVER.name, "original-driver", DRIVER_BYTES, DRIVER_SHA256)
        retain(pathlib.Path(__file__), "producer/" + pathlib.Path(__file__).name, "packaging-producer")
        require(len(rows) == 41, "payload count differs")

        def fence():
            require(inventory() == initial_inventory, "closed receipt directory changed")
            for fd, version, path in held:
                require(signature(os.fstat(fd)) == version, "held original changed: " + path)
                other, info = open_regular(path)
                try:
                    require(signature(info) == version, "original path changed: " + path)
                finally:
                    os.close(other)

        fence()
        index = {
            "schema": "trnm-M6-original-repository-truth-package-index-v1",
            "source_head": HEAD, "source_tree": TREE, "expected_start_head": START_HEAD,
            "original_schema": original["schema"], "original_status": original["status"],
            "original_lane_exit": lane["exit"], "original_errors": original["errors"],
            "operator_terminal_exit_code": args.terminal_exit_code,
            "operator_terminal_summary_sha256": args.terminal_summary_sha256,
            "original_file_count": 39, "original_bytes": original_bytes,
            "original_driver": original["driver"], "original_invocation": invocation,
            "original_bundle_input": bundle, "original_environment": original["environment"],
            "original_steps": [{key: step[key] for key in
                ("label", "argv", "cwd", "exit", "timeout_seconds", "elapsed_seconds")} for step in steps],
            "source_before_after_equal": True,
            "source_identity": identity,
            "independently_pinned_source_identity": {
                "bytes": SOURCE_BYTES, "sha256": SOURCE_SHA256,
                "expected_entries": 41671, "expected_raw_bytes": 3994766803,
            },
            "files": rows, "receipt_directories": initial_inventory["directories"],
            "unexpected_nested_files_excluded": [],
            "original_record_bytes_preserved": True,
            "tests_rerun": False, "source_or_git_objects_modified": False,
            "network_actions_by_packager": False, "hosted_ci_qualification": False,
            "remote_publication_verified": False, "future_revision_qualification": False,
        }
        index_raw = (json.dumps(index, indent=2) + "\n").encode()
        index_path = OUTPUT / "EVIDENCE_INDEX.json"
        save_new(index_path, index_raw)
        zip_path = OUTPUT / "original-repository-truth-2a6206-v1.zip"
        with zipfile.ZipFile(zip_path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for row in rows:
                archive.writestr(row["path"], data[row["path"]])
            archive.writestr("EVIDENCE_INDEX.json", index_raw)
        by_path = {row["path"]: row for row in rows}
        with zipfile.ZipFile(zip_path, "r") as archive:
            members = archive.infolist()
            require(len(members) == 42 and {item.filename for item in members} == set(data) | {"EVIDENCE_INDEX.json"},
                    "ZIP roster differs")
            for item in members:
                raw = archive.read(item)
                expected = index_raw if item.filename == "EVIDENCE_INDEX.json" else data[item.filename]
                require(raw == expected, "ZIP member bytes/CRC differ")
                if item.filename != "EVIDENCE_INDEX.json":
                    row = by_path[item.filename]
                    require(len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"],
                            "ZIP member identity differs")
        fence()
        completion = {
            "schema": "trnm-M6-original-repository-truth-package-completion-v1",
            "packaging_status": "verified", "started_at": started, "finished_at": now(),
            "original_status": original["status"], "original_lane_exit": lane["exit"],
            "original_errors": original["errors"], "original_lane_elapsed_seconds": lane["elapsed_seconds"],
            "original_head": HEAD, "original_tree": TREE, "expected_start_head": START_HEAD,
            "original_terminal_summary_sha256": args.terminal_summary_sha256,
            "operator_terminal_exit_code": args.terminal_exit_code,
            "original_file_count": 39, "original_bytes": original_bytes,
            "original_step_count": 18, "payload_file_count": 41, "zip_member_count": 42,
            "original_lane_argv": commands["repository-truth"], "original_lane_timeout_seconds": 2700,
            "original_invocation": invocation,
            "zip": file_info(zip_path), "index": file_info(index_path),
            "producer": file_info(pathlib.Path(__file__)),
            "all_member_crc_size_sha_verified": True,
            "original_source_versions_unchanged": True, "source_before_after_equal": True,
            "raw_flat_originals_required_for_mac_copy": 39,
            "original_driver_flat_required_for_mac_copy": True,
            "unexpected_nested_files_excluded": [],
            "tests_rerun": False, "source_or_git_objects_modified": False,
            "network_actions_by_packager": False, "hosted_ci_qualification": False,
            "remote_publication_verified": False, "future_revision_qualification": False,
        }
        completion_path = OUTPUT / "package-summary.json"
        save_new(completion_path, (json.dumps(completion, indent=2) + "\n").encode())
        print(json.dumps({"packaging_status": "verified", "original_status": original["status"],
              "original_lane_exit": lane["exit"], "summary": file_info(completion_path),
              "zip": completion["zip"], "index": completion["index"], "producer": completion["producer"],
              "original_files": 39, "zip_members": 42, "tests_rerun": False}), flush=True)
        return 0
    finally:
        for fd, _, _ in held:
            os.close(fd)

if __name__ == "__main__":
    sys.exit(main())
