#!/usr/bin/env python3
"""Observe current ELF bytes at Cargo Running paths in completed source receipts.

This reads files only. It never executes a test, Cargo, an ELF, or a dependency
inspector. The result is a post-command artifact observation, not an exec-time
attestation, a test-pass gate, or an independent deployment qualification.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
RUNNING = re.compile(r"^\s*Running (.+?) \((.+)\)\s*$")
TEST = re.compile(r"^test ([A-Za-z_][A-Za-z0-9_:]*) \.\.\. (.+)$")


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def observe_elf(path):
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111:
            raise ValueError(f"not a regular executable: {path}")
        header = stream.read(64)
        if (len(header) < 20 or header[:4] != b"\x7fELF"
                or header[4] not in (1, 2) or header[5] not in (1, 2)):
            raise ValueError(f"not a supported ELF header: {path}")
        stream.seek(0)
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    if signature(before) != signature(after) or signature(after) != signature(path.stat()):
        raise ValueError(f"executable changed during observation: {path}")
    endian = "little" if header[5] == 1 else "big"
    machine = int.from_bytes(header[18:20], endian)
    return {
        "path": str(path), "sha256": digest, "bytes": after.st_size,
        "elf_class_bits": 32 if header[4] == 1 else 64,
        "elf_endian": endian, "elf_machine": machine,
        "elf_machine_name": {62: "x86_64", 183: "aarch64"}.get(machine, "other"),
        "device": after.st_dev, "inode": after.st_ino,
        "mode": oct(stat.S_IMODE(after.st_mode)),
        "mtime_ns": after.st_mtime_ns, "ctime_ns": after.st_ctime_ns,
    }


def observe_receipt(path, expected_commit, expected_tree):
    receipt_bytes = path.read_bytes()
    receipt = json.loads(receipt_bytes)
    if receipt.get("schema") != "trnm-pq-native-command-v1":
        raise ValueError(f"unknown receipt schema: {path}")
    status, code = receipt.get("status"), receipt.get("exit_code")
    if (status not in ("command_succeeded", "command_failed")
            or type(code) is not int or (status == "command_succeeded") != (code == 0)):
        raise ValueError(f"receipt is not a completed command observation: {path}")
    source = receipt.get("before")
    if (not isinstance(source, dict) or source != receipt.get("after")
            or source.get("tested_commit") != expected_commit
            or source.get("tested_tree") != expected_tree
            or source.get("tracked_worktree_verified") is not True):
        raise ValueError(f"receipt source does not match requested fixed source: {path}")
    name = receipt.get("log_file")
    if not isinstance(name, str) or Path(name).name != name:
        raise ValueError(f"invalid receipt log filename: {path}")
    log_path = path.parent / name
    raw_log = log_path.read_bytes()
    log_hash = hashlib.sha256(raw_log).hexdigest()
    if (log_hash != receipt.get("log_sha256")
            or len(raw_log) != receipt.get("log_bytes")):
        raise ValueError(f"receipt log bytes/hash mismatch: {path}")
    cwd = Path(receipt["cwd"]).resolve(strict=True)
    target_value = receipt.get("environment", {}).get("CARGO_TARGET_DIR")
    target = None
    if target_value:
        target = Path(target_value)
        target = (target if target.is_absolute() else cwd / target).resolve(strict=True)
    executions = []
    for number, raw_line in enumerate(raw_log.decode("utf-8", errors="replace").splitlines(), 1):
        line = ANSI.sub("", raw_line)
        match = RUNNING.fullmatch(line)
        if match:
            if target is None:
                raise ValueError(f"Running path has no recorded target directory: {path}")
            logged_path = Path(match[2])
            resolved = (logged_path if logged_path.is_absolute() else cwd / logged_path).resolve(strict=True)
            if not resolved.is_relative_to(target):
                raise ValueError(f"Running path escapes recorded target directory: {resolved}")
            executions.append({
                "cargo_target": match[1], "cargo_running_line": number,
                "cargo_logged_path": match[2], "elf": observe_elf(resolved),
                "observed_test_lines": [], "observed_summary_lines": [],
            })
        elif executions:
            test = TEST.fullmatch(line)
            if test:
                executions[-1]["observed_test_lines"].append({
                    "line": number, "name": test[1], "outcome_text": test[2],
                })
            elif line.startswith("test result:"):
                executions[-1]["observed_summary_lines"].append({"line": number, "text": line})
    argv = receipt["argv"]
    if code == 0 and argv and Path(argv[0]).name == "cargo" and "test" in argv[:3] and not executions:
        raise ValueError(f"successful direct Cargo test has no Running paths: {path}")
    return {
        "receipt_path": str(path), "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "log_path": str(log_path), "log_sha256": log_hash, "log_bytes": len(raw_log),
        "source": source, "status": status, "exit_code": code,
        "argv": argv, "cwd": str(cwd), "environment": receipt.get("environment"),
        "executions": executions,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", action="append", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (args.expected_commit, args.expected_tree)):
        raise ValueError("expected source identities must be full lowercase Git object IDs")
    receipts = [observe_receipt(path.resolve(strict=True), args.expected_commit, args.expected_tree)
                for path in args.receipt]
    output = args.output.resolve()
    if any(output.is_relative_to(Path(row["cwd"])) for row in receipts):
        raise ValueError("write observations outside source worktrees")
    result = {
        "schema": "chain-post-command-executable-observation-v1",
        "observed_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "current bytes at actual Cargo Running paths; original receipt/log hashes verified",
        "exec_time_attestation": False, "independent_deployment_qualified": False,
        "whole_chain_quantum_security_qualified": False,
        "source_commit": args.expected_commit, "source_tree": args.expected_tree,
        "receipts": receipts,
    }
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"output": str(output), "receipts": len(receipts),
                      "logged_executable_invocations": sum(len(r["executions"]) for r in receipts)}))


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"chain-executable-observation: {error}", file=sys.stderr)
        sys.exit(1)
