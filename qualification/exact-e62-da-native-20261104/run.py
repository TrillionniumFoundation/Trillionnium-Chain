#!/usr/bin/env python3
"""Execute the complete frozen DA library and strict package lint on exact e62.

This is a scoped native qualification. It does not replace the original
workspace feature-unification, Host, protocol or business-performance gates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

from transcript import observations, reader_controls

RECIPE = Path(__file__).resolve().parents[2]
MAX_LOG_READ_BYTES = 16 * 1024 * 1024


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(path):
    value = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            count += len(block)
            value.update(block)
    return {"bytes": count, "sha256": value.hexdigest()}


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def read_log(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_LOG_READ_BYTES + 1)
    require(len(raw) <= MAX_LOG_READ_BYTES, "QUALIFICATION_LOG_READ_LIMIT")
    return raw.decode("utf-8")


def run(argv, log, timeout, root):
    started = time.monotonic_ns()
    timed_out = False
    with log.open("wb") as stream:
        child = subprocess.Popen(argv, cwd=root, stdout=stream, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            code = child.wait()
    return {"argv": list(map(str, argv)), "cwd": str(root), "exit_code": code,
            "timed_out": timed_out, "outer_timeout_seconds": timeout,
            "elapsed_ns": time.monotonic_ns() - started,
            "log": log.name, "log_digest": digest(log)}


def source(root, expected, output):
    observed = run(["python3", "scripts/ci/verify_ci_source.py", "--kind", "head",
                    "--expected-head", expected["source"], "--output", str(output)],
                   output.with_suffix(".command.log"), 120, root)
    require(observed["exit_code"] == 0 and not observed["timed_out"], "SOURCE_COMMAND")
    value = json.loads(output.read_text())
    require(value["candidate"] == value["tested_commit"] == expected["source"]
            and value["tested_tree"] == expected["tree"]
            and value["tracked_worktree_verified"] is True, "SOURCE_IDENTITY")
    return value


def input_files(root, expected):
    values = []
    for row in expected["source_inputs"]:
        path = root / row["path"]
        require(path.is_file() and not path.is_symlink(), "REGULAR_SOURCE_INPUT")
        raw = path.read_bytes()
        require(git_blob(raw) == row["git_blob"], "EXACT_SOURCE_INPUT")
        values.append({**row, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    return values


def extra_reader_controls():
    names = ["fixture::case_" + str(i) for i in range(180)]
    full = "\n".join("test " + name + " ... ok" for name in names)
    full += "\ntest result: ok. 180 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n"
    require(observations(full, False, names)["passed"] is True, "COUNT_180_POSITIVE")
    require(observations(full.replace("180 passed", "179 passed"), False, names)["passed"]
            is False, "COUNT_180_NEGATIVE")
    require(observations(full.replace("test fixture::case_179 ... ok\n", ""), False, names)["passed"]
            is False, "COUNT_180_MISSING_CASE")
    return {"synthetic_parser_cases_passed": 3, "native_tests_executed": 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    out = args.out.resolve()
    require(root.is_dir() and not root.is_symlink(), "SOURCE_DIRECTORY")
    require(not out.is_relative_to(root) and not out.is_relative_to(RECIPE), "OUTPUT_OUTSIDE_SOURCE")
    out.mkdir(parents=True, exist_ok=False)
    expected = json.loads(Path(__file__).with_name("inputs.json").read_text())
    require(expected["source"] == "e62eb3a4f35cf9fc5bf7f3092f86d441d0c4cd29"
            and expected["tree"] == "e61e1542d983e780c96a39e5785d3b4efc46ed60"
            and expected["registry_count"] == 180
            and expected["toolchain"] == "1.95.0", "FROZEN_QUALIFICATION_INPUT")
    receipt = {"schema": "trnm-exact-e62-da-native-v1", "commands": [],
               "source_before": None, "source_after": None, "failure": None,
               "native_module": None, "strict_clippy_passed": False,
               "format_passed": False, "complete": False, "passed": False,
               "original_full_workspace_qualified": False, "host_qualified": False,
               "performance_qualified": False, "production_activation": False,
               "scope": "All 180 registered DA library tests in the package-selected all-feature test profile, original 300-second module ceiling, plus strict package Clippy. No diagnostic Rust overlay or changed fixture deadline."}
    binary = None
    try:
        recipe_head = subprocess.check_output(
            ["git", "--no-replace-objects", "rev-parse", "HEAD"], cwd=RECIPE, text=True).strip()
        require(recipe_head == os.environ["GITHUB_SHA"], "RECIPE_HEAD")
        receipt["recipe_head"] = recipe_head
        receipt["reader_controls"] = [reader_controls(), extra_reader_controls()]
        receipt["source_before"] = source(root, expected, out / "source-before.json")
        receipt["inputs_before"] = input_files(root, expected)
        for argv, label in [
                (["rustc", "+1.95.0", "-Vv"], "rustc"),
                (["cargo", "+1.95.0", "-V"], "cargo")]:
            observed = run(argv, out / (label + ".log"), 60, root)
            receipt["commands"].append(observed)
            require(observed["exit_code"] == 0 and not observed["timed_out"], "TOOLCHAIN_COMMAND")
        require(read_log(out / "rustc.log").startswith("rustc 1.95.0 ")
                and read_log(out / "cargo.log").startswith("cargo 1.95.0 "), "TOOLCHAIN_VERSION")
        argv = ["cargo", "+1.95.0", "test", "--locked", "--manifest-path",
                "trillionnium/Cargo.toml", "-p", "trnm-data-availability",
                "--all-features", "--lib", "--no-run", "--message-format=json"]
        build = run(argv, out / "build.log", 600, root)
        receipt["commands"].append(build)
        require(build["exit_code"] == 0 and not build["timed_out"], "NATIVE_BUILD")
        paths = set()
        for line in read_log(out / "build.log").splitlines():
            if not line.startswith("{"):
                continue
            row = json.loads(line)
            if (row.get("reason") == "compiler-artifact"
                    and row.get("target", {}).get("name") == "trnm_data_availability"
                    and row.get("profile", {}).get("test") is True
                    and row.get("executable")):
                paths.add(Path(row["executable"]))
        require(len(paths) == 1, "EXACT_LIBRARY_BINARY")
        binary = paths.pop()
        require(binary.is_file() and not binary.is_symlink(), "REGULAR_LIBRARY_BINARY")
        receipt["binary_before"] = digest(binary)
        crate = root / "trillionnium/crates/trnm-data-availability"
        registry = run([str(binary), "--list", "--format", "terse"], out / "registry.log", 60, crate)
        receipt["commands"].append(registry)
        require(registry["exit_code"] == 0 and not registry["timed_out"], "REGISTRY_COMMAND")
        names = re.findall(r"^([A-Za-z_][A-Za-z0-9_:]*): test$", read_log(out / "registry.log"), re.M)
        require(len(names) == len(set(names)) == 180, "EXACT_180_REGISTRY")
        require(set(expected["required_tests"]).issubset(set(names)), "REQUIRED_REGRESSION_NAMES")
        receipt["registered_tests"] = names
        execution = run([str(binary), "--test-threads=1"], out / "all-library.log", 300, crate)
        observed = observations(read_log(out / "all-library.log"), False, names)
        observed["passed"] = (observed["passed"] and execution["exit_code"] == 0
                              and not execution["timed_out"])
        receipt["native_module"] = {"execution": execution, **observed}
        lint = run(["cargo", "+1.95.0", "clippy", "--locked", "--manifest-path",
                    "trillionnium/Cargo.toml", "-p", "trnm-data-availability",
                    "--all-targets", "--all-features", "--", "-D", "warnings"],
                   out / "clippy.log", 600, root)
        receipt["commands"].append(lint)
        receipt["strict_clippy_passed"] = lint["exit_code"] == 0 and not lint["timed_out"]
        formatted = run(["cargo", "+1.95.0", "fmt", "--manifest-path",
                         "trillionnium/Cargo.toml", "--all", "--", "--check"],
                        out / "format.log", 120, root)
        receipt["commands"].append(formatted)
        receipt["format_passed"] = formatted["exit_code"] == 0 and not formatted["timed_out"]
        receipt["complete"] = True
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        receipt["failure"] = {"type": type(error).__name__,
                              "message_sha256": hashlib.sha256(str(error).encode()).hexdigest()}
    finally:
        try:
            if binary is not None:
                receipt["binary_after"] = digest(binary)
            receipt["inputs_after"] = input_files(root, expected)
            receipt["source_after"] = source(root, expected, out / "source-after.json")
            receipt["source_unchanged"] = receipt["source_before"] == receipt["source_after"]
            receipt["inputs_unchanged"] = receipt.get("inputs_before") == receipt["inputs_after"]
            receipt["binary_unchanged"] = (binary is not None
                and receipt.get("binary_before") == receipt.get("binary_after"))
        except (OSError, RuntimeError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
            receipt["finalization_failure"] = {"type": type(error).__name__,
                "message_sha256": hashlib.sha256(str(error).encode()).hexdigest()}
        receipt["passed"] = (receipt["complete"] and receipt["failure"] is None
            and "finalization_failure" not in receipt
            and receipt.get("source_unchanged") is True and receipt.get("inputs_unchanged") is True
            and receipt.get("binary_unchanged") is True
            and (receipt.get("native_module") or {}).get("passed") is True
            and receipt["strict_clippy_passed"] and receipt["format_passed"])
        (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print("EXACT_DA_NATIVE " + json.dumps(receipt, sort_keys=True), flush=True)
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
