#!/usr/bin/env python3
"""Observe three fixed-source test ELFs after the original --no-run command.

Invoke only after the build owner confirms compilation is complete. This reads
the completed receipt, its original log, and exactly the three logged Executable
paths. It performs no build, test, cache mutation, or binary execution.
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


EXPECTED_ARGV = [
    "cargo", "+1.95.0", "test", "--locked", "--offline",
    "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-pon-node",
    "--lib", "--test", "pool_mining", "--test", "architecture_delivery_compare",
    "--all-features", "--no-run",
]
EXPECTED_TARGETS = {
    "unittests src/lib.rs",
    "tests/pool_mining.rs",
    "tests/architecture_delivery_compare.rs",
}
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
EXECUTABLE = re.compile(r"^\s*Executable (.+?) \((.+)\)\s*$")


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (args.expected_commit, args.expected_tree)):
        raise ValueError("expected source identities must be full lowercase Git object IDs")
    receipt_path = args.receipt.resolve(strict=True)
    receipt_bytes = receipt_path.read_bytes()
    receipt = json.loads(receipt_bytes)
    if (receipt.get("schema") != "trnm-pq-native-command-v1"
            or receipt.get("status") != "command_succeeded"
            or type(receipt.get("exit_code")) is not int or receipt["exit_code"] != 0):
        raise ValueError("build-only receipt must be complete and successful before any ELF observation")
    if receipt.get("argv") != EXPECTED_ARGV:
        raise ValueError("build-only command differs from the original exact three-target argv")
    source = receipt.get("before")
    if (not isinstance(source, dict) or source != receipt.get("after")
            or source.get("tested_commit") != args.expected_commit
            or source.get("tested_tree") != args.expected_tree
            or source.get("tracked_worktree_verified") is not True):
        raise ValueError("build-only source identity does not match the fixed source")
    name = receipt.get("log_file")
    if not isinstance(name, str) or Path(name).name != name:
        raise ValueError("invalid receipt log filename")
    log_path = receipt_path.parent / name
    raw_log = log_path.read_bytes()
    log_sha256 = hashlib.sha256(raw_log).hexdigest()
    if log_sha256 != receipt.get("log_sha256") or len(raw_log) != receipt.get("log_bytes"):
        raise ValueError("build-only original log bytes/hash mismatch")
    cwd = Path(receipt["cwd"]).resolve(strict=True)
    target_value = receipt.get("environment", {}).get("CARGO_TARGET_DIR")
    if not isinstance(target_value, str) or not target_value:
        raise ValueError("missing recorded target directory")
    target = Path(target_value)
    target = (target if target.is_absolute() else cwd / target).resolve(strict=True)
    output = args.output.resolve()
    if output.is_relative_to(cwd):
        raise ValueError("write observations outside the source worktree")
    logged = []
    for number, raw_line in enumerate(raw_log.decode("utf-8", errors="replace").splitlines(), 1):
        line = ANSI.sub("", raw_line)
        if (re.match(r"^\s*Running\s", line) or re.match(r"^running [0-9]+ tests?", line)
                or line.startswith("test result:")):
            raise ValueError("build-only transcript unexpectedly contains test execution markers")
        match = EXECUTABLE.fullmatch(line)
        if match:
            path = Path(match[2])
            path = (path if path.is_absolute() else cwd / path).resolve(strict=True)
            if not path.is_relative_to(target):
                raise ValueError("Executable path escapes the recorded target directory")
            logged.append({"cargo_target": match[1], "cargo_executable_line": number,
                           "cargo_logged_path": match[2], "resolved_path": str(path)})
    if (len(logged) != 3 or {row["cargo_target"] for row in logged} != EXPECTED_TARGETS
            or len({row["resolved_path"] for row in logged}) != 3):
        raise ValueError("expected exactly the original three distinct Executable targets")
    started = datetime.now(timezone.utc).isoformat()
    for row in logged:
        row["elf"] = observe_elf(Path(row.pop("resolved_path")))
    result = {
        "schema": "chain-pre-execution-executable-observation-v1",
        "observed_started_utc": started,
        "observed_finished_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "current bytes at original completed --no-run Executable paths; no test execution",
        "source_commit": args.expected_commit, "source_tree": args.expected_tree,
        "source": source, "argv": receipt["argv"], "cwd": str(cwd),
        "environment": receipt["environment"],
        "receipt_path": str(receipt_path),
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "log_path": str(log_path), "log_sha256": log_sha256, "log_bytes": len(raw_log),
        "build_status": receipt["status"], "build_exit_code": receipt["exit_code"],
        "executed_tests": 0, "native_tests_passed_by_build_only": 0,
        "exec_time_attestation": False, "independent_deployment_qualified": False,
        "whole_chain_quantum_security_qualified": False,
        "executables": logged,
        "observer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps({"output": str(output), "executables_observed": len(logged),
                      "executed_tests": 0}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"chain-pre-execution-observation: {error}", file=sys.stderr)
        sys.exit(1)
