#!/usr/bin/env python3
"""Verify the exact frozen-profile source and paired engineering exports."""

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import traceback
import xml.etree.ElementTree as ET


def digest(path):
    path = Path(path)
    before = path.stat()
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    after = path.stat()
    identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    if identity(before) != identity(after):
        raise RuntimeError(f"artifact changed during hash: {path}")
    return {"path": str(path), "bytes": after.st_size, "sha256": h.hexdigest(),
            "mtime_ns": after.st_mtime_ns, "inode": after.st_ino, "device": after.st_dev}


def write_new(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--tests", required=True)
    parser.add_argument("--seed-target", required=True)
    args = parser.parse_args()
    root, out, target = Path(args.source), Path(args.output), Path(args.target)
    seed_target = Path(args.seed_target)
    tests = json.loads(Path(args.tests).read_text())
    if not isinstance(tests, list) or not tests or len(tests) != len(set(tests)):
        raise ValueError("expected exact, nonempty, unique test names")
    out.mkdir(mode=0o700, parents=False, exist_ok=False)

    def git(*values):
        return subprocess.check_output(["git", *values], cwd=root, text=True).strip()

    def source():
        return {"head": git("rev-parse", "HEAD"),
                "tree": git("rev-parse", "HEAD^{tree}"),
                "index_tree": git("write-tree"),
                "status": git("status", "--porcelain"),
                "native_tree": git("rev-parse", "HEAD:codex-rs"),
                "runner_sha256": digest(__file__)["sha256"]}

    def resources():
        result = subprocess.run(["systemctl", "--user", "show", args.unit,
                                 "-p", "MemoryMax", "-p", "CPUQuotaPerSecUSec",
                                 "-p", "Nice", "-p", "ControlGroup",
                                 "-p", "RuntimeMaxUSec"], capture_output=True,
                                text=True, check=True)
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        group = Path("/sys/fs/cgroup") / values["ControlGroup"].lstrip("/")
        for name in ["memory.max", "memory.peak", "memory.swap.max", "memory.swap.peak",
                     "cpu.max", "cpu.stat", "pids.max", "pids.peak"]:
            path = group / name
            if path.exists():
                values[name] = path.read_text().strip()
        return values

    def binaries():
        return [digest(path) for pattern in ["codex_hepta_agentd-*", "codex_hepta_learning_artifacts-*"]
                for path in sorted((target / "debug/deps").glob(pattern))
                if path.is_file() and os.access(path, os.X_OK)]

    baseline = source()
    start_ns = time.time_ns()
    envelope = resources()
    if envelope.get("memory.max") != "8589934592":
        raise RuntimeError("engineering memory envelope differs before cache copy")
    quota, period = envelope["cpu.max"].split()
    if quota == "max" or int(quota) != 2 * int(period):
        raise RuntimeError("engineering CPU envelope differs before cache copy")
    if target.exists():
        raise RuntimeError("private target already exists; reconcile instead of replacing")
    target.mkdir(mode=0o700)
    copy_start = time.monotonic()
    cache_log = out / "cache-copy.log"
    with cache_log.open("x") as stream:
        copied = subprocess.run(["cp", "-a", "--reflink=auto", str(seed_target) + "/.", str(target)], stdout=stream, stderr=subprocess.STDOUT)
    cache = {"seed_target": str(seed_target), "private_target": str(target),
             "seed_was_read_only": True, "copy_command_exit": copied.returncode,
             "copy_wall_seconds": time.monotonic() - copy_start, "copy_log": digest(cache_log),
             "cache_is_not_provenance": True}
    write_new(out / "cache-copy.json", cache)
    if copied.returncode:
        raise RuntimeError("cache copy failed; no native tests ran")
    machine = {"configured_host": "rog", "sysname": os.uname().sysname,
               "release": os.uname().release, "version": os.uname().version,
               "machine": os.uname().machine}
    for key, path in [("machine_id_sha256", "/etc/machine-id"),
                      ("boot_id_sha256", "/proc/sys/kernel/random/boot_id")]:
        if Path(path).is_file():
            machine[key] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    scopes = ["codex-rs/hepta-agentd", "codex-rs/hepta-learning-artifacts",
              "codex-rs/hepta-neuron", "codex-rs/hepta-types", "codex-rs/Cargo.lock",
              "codex-rs/Cargo.toml", "codex-rs/.config/nextest.toml",
              "scripts/run-nextest.py", "justfile", "codex-rs/rust-toolchain.toml", "AGENTS.md"]
    filter_expression = " | ".join("test(=" + name + ")" for name in tests)
    command = ["just", "test", "--locked", "-p", "codex-hepta-learning-artifacts",
               "-p", "codex-hepta-agentd", "--lib",
               "-E", filter_expression, "--success-output", "final", "--failure-output", "final"]
    toolchain = {"rustc": subprocess.check_output(["/home/qian-qi/.rustup/toolchains/1.96.0-x86_64-unknown-linux-gnu/bin/rustc", "--version", "--verbose"], text=True),
                 "cargo": subprocess.check_output(["/home/qian-qi/.rustup/toolchains/1.96.0-x86_64-unknown-linux-gnu/bin/cargo", "--version"], text=True),
                 "just": subprocess.check_output(["/home/qian-qi/work/chain-hepta-native-1f3ba4601505/tools/bin/just", "--version"], text=True)}
    initial = {"source": baseline, "resources": envelope, "machine": machine, "toolchain": toolchain,
               "expected_head": args.expected_head, "cache": cache, "command": command,
               "exact_test_names": tests, "started_ns": start_ns,
               "engineering_controls_only": True, "actual_model_execution": False,
               "production_final_use_qualified": False,
               "owner_readback_files_exported_by_driver": False, "stdout_readback_opt_in": True,
               "paired_checkpoint_stdout_opt_in": True, "pins_are_fixture_derived": True,
               "binary_before": binaries()}
    write_new(out / "start.json", initial)
    steps = []
    error = None
    exit_code = 99
    junit_paths = [root / "codex-rs/target/nextest/local/junit.xml", target / "nextest/local/junit.xml"]
    try:
        if baseline["head"] != args.expected_head or baseline["status"] or baseline["tree"] != baseline["index_tree"]:
            raise RuntimeError("expected exact clean source was not present")
        if envelope["memory.max"] != "8589934592":
            raise RuntimeError("engineering memory envelope differs")
        quota, period = envelope["cpu.max"].split()
        if quota == "max" or int(quota) != 2 * int(period):
            raise RuntimeError("engineering CPU envelope differs")
        subprocess.run(["git", "diff", "--exit-code", "HEAD", "--", *scopes], cwd=root,
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with (out / "source-snapshot.tar").open("xb") as archive:
            subprocess.run(["git", "archive", "--format=tar", args.expected_head, *scopes],
                           cwd=root, stdout=archive, check=True)
        (out / "source-files.git-index").write_bytes(subprocess.check_output(
            ["git", "ls-files", "--stage", "-z", "--", *scopes], cwd=root))
        paths = subprocess.check_output(["git", "ls-files", "-z", "--", *scopes], cwd=root).decode().split("\0")
        source_files = [{"relative": name, **digest(root / name)} for name in paths if name]
        write_new(out / "source-files.sha256.json", source_files)
        for index, path in enumerate(junit_paths):
            if path.exists():
                shutil.copy2(path, out / f"prior-excluded-{index}-junit.xml")
        env = os.environ.copy()
        env.update({"CARGO_TARGET_DIR": str(target), "CARGO_BUILD_JOBS": "2",
                    "CARGO_INCREMENTAL": "0", "CARGO_PROFILE_DEV_DEBUG": "0",
                    "HEPTA_GENERATION_LEARNING_READBACK_STDOUT": "1",
                    "CARGO_PROFILE_TEST_DEBUG": "0", "LIBCLANG_PATH": "/usr/lib/llvm-21/lib",
                    "NEXTEST_PROFILE": "local", "NEXTEST_TEST_THREADS": "2",
                    "RUSTUP_TOOLCHAIN": "1.96.0", "RUST_MIN_STACK": "8388608",
                    "PATH": "/home/qian-qi/.rustup/toolchains/1.96.0-x86_64-unknown-linux-gnu/bin:/home/qian-qi/work/chain-hepta-native-1f3ba4601505/tools/bin:/home/qian-qi/.cargo/bin:/usr/local/bin:/usr/bin:/bin"})
        started = time.monotonic()
        execution_started_ns = time.time_ns()
        log = out / "native-controls.log"
        with log.open("x") as stream:
            process = subprocess.run(command, cwd=root / "codex-rs", env=env,
                                     stdout=stream, stderr=subprocess.STDOUT)
        step = {"command": command, "exit_code": process.returncode,
                "wall_seconds": time.monotonic() - started,
                "log": digest(log), "source_after": source(),
                "resources_after": resources(), "binary_after": binaries()}
        steps.append(step)
        if step["source_after"] != baseline:
            raise RuntimeError("source changed during native controls")
        if process.returncode:
            exit_code = process.returncode
            raise RuntimeError("native controls failed")
        matches = re.findall(r"Nextest run ID ([0-9a-f-]{36})", log.read_text())
        if len(matches) != 1:
            raise RuntimeError("expected exactly one original nextest run ID")
        selected = []
        for path in junit_paths:
            if path.exists():
                xml = ET.parse(path).getroot()
                if xml.attrib.get("uuid") == matches[0] and path.stat().st_mtime_ns >= execution_started_ns:
                    selected.append((path, xml))
        if len(selected) != 1:
            raise RuntimeError("missing or ambiguous fresh original JUnit")
        path, xml = selected[0]
        cases = xml.findall(".//testcase")
        names = [case.attrib.get("name") for case in cases]
        if collections.Counter(names) != collections.Counter(tests):
            raise RuntimeError("actual native test denominator differs")
        if any(case.find(tag) is not None for case in cases for tag in ["error", "failure", "skipped"]):
            raise RuntimeError("native tests contain failure/error/skips")
        shutil.copy2(path, out / "native-controls.junit.xml")
        step["junit"] = {**digest(out / "native-controls.junit.xml"), "attributes": xml.attrib,
                         "run_id": matches[0], "testcases": names}
        exit_code = 0
    except Exception as exc:
        error = {"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}
    finally:
        result = {"source_before": baseline, "source_after": source(),
                  "source_unchanged": source() == baseline, "steps": steps, "cache": cache,
                  "machine": machine, "toolchain": toolchain, "resources_before": envelope,
                  "resources_after": resources(), "error": error, "exit_code": exit_code,
                  "engineering_controls_only": True, "actual_model_execution": False,
                  "production_final_use_qualified": False,
                  "owner_readback_files_exported_by_driver": False, "stdout_readback_opt_in": True,
                  "paired_checkpoint_stdout_opt_in": True, "pins_are_fixture_derived": True}
        write_new(out / "result.json", result)
        print(json.dumps(result, sort_keys=True), flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
