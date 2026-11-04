#!/usr/bin/env python3
"""Bounded package-selected DA reproduction; never a replacement baseline gate."""
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

ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / "trillionnium/crates/trnm-data-availability"
SELECTOR = "cell::discovery::sequence_tests::tcp_two_bootstraps_newer_owner_sequence_never_dials_superseded_endpoint"
MAX_LOG_BYTES = 16 * 1024 * 1024


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(path):
    total = 0
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            total += len(block)
            value.update(block)
    return {"bytes": total, "sha256": value.hexdigest()}


def read_log(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_LOG_BYTES + 1)
    require(len(raw) <= MAX_LOG_BYTES, "DIAGNOSTIC_LOG_READ_LIMIT")
    return raw.decode("utf-8")


def run(command, path, timeout, cwd=ROOT):
    started = time.monotonic_ns()
    timed_out = False
    with path.open("wb") as stream:
        process = subprocess.Popen(command, cwd=cwd, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            code = process.wait()
    return {"argv": list(map(str, command)), "cwd": str(cwd), "exit_code": code,
            "timed_out": timed_out, "outer_timeout_seconds": timeout,
            "elapsed_ns": time.monotonic_ns() - started, "log": path.name,
            "log_digest": digest(path)}


def source(path):
    expected = os.environ["GITHUB_SHA"]
    result = run(["python3", "scripts/ci/verify_ci_source.py", "--kind", "head",
                  "--expected-head", expected, "--output", str(path)],
                 path.with_suffix(".command.log"), 120)
    require(result["exit_code"] == 0 and not result["timed_out"], "SOURCE_CHECK_FAILED")
    value = json.loads(path.read_text())
    require(value["tested_commit"] == expected
            and value["candidate"] == expected
            and value["tracked_worktree_verified"] is True, "EXACT_SOURCE_REQUIRED")
    return value


def observations(log, selected, registered_names):
    summaries = [tuple(map(int, row)) for row in re.findall(
        r"^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
        r"(\d+) measured; (\d+) filtered out;", log, re.M)]
    success = re.findall(r"^test ([A-Za-z_][A-Za-z0-9_:]*) \.\.\. ok$", log, re.M)
    # Exact-selector --nocapture may put fixed diagnostics after the test name.
    selected_present = re.search(r"^test " + re.escape(SELECTOR) + r" \.\.\.", log, re.M) is not None
    expected = (1, 0, 0, 0, 173) if selected else (174, 0, 0, 0, 0)
    passed = summaries == [expected] and (selected_present if selected else
              len(success) == 174 and set(success) == set(registered_names))
    return {"passed": passed, "native_summaries": summaries,
            "selected_case_present": selected_present,
            "completed_plain_success_rows": len(success),
            "exchange_diagnostic_lines": [line for line in log.splitlines()
                if "cell_discovery_exchange " in line],
            "scope": "Diagnostic case/module observations only; no original full-workspace or Host qualification."}



def reader_controls():
    names = [SELECTOR] + [f"fixture::case_{number}" for number in range(173)]
    full = "\n".join(f"test {name} ... ok" for name in names) + (
        "\ntest result: ok. 174 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n")
    selected = (f"test {SELECTOR} ... cell_discovery_exchange round=0\nok\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 173 filtered out;\n")
    cases = [
        (observations(full, False, names)["passed"], True),
        (observations(selected, True, names)["passed"], True),
        (observations(full.replace(f"test {names[0]} ... ok\n", ""), False, names)["passed"], False),
        (observations(full.replace(names[1], names[2]), False, names)["passed"], False),
        (observations(full.replace(names[1], "fixture::foreign"), False, names)["passed"], False),
        (observations(full.replace("174 passed", "173 passed"), False, names)["passed"], False),
        (observations(selected.replace(SELECTOR, "fixture::foreign"), True, names)["passed"], False),
        (observations(selected.replace("0 failed", "1 failed"), True, names)["passed"], False),
    ]
    require(all(actual is expected for actual, expected in cases), "READER_CONTROL_FAILED")
    return {"synthetic_parser_cases_passed": len(cases), "native_tests_executed": 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    require(out.is_absolute() and not out.is_relative_to(ROOT), "OUTSIDE_CHECKOUT")
    out.mkdir(parents=True, exist_ok=False)
    receipt = {"schema": "trnm-da-original-sequence-diagnostic-v1",
               "source_before": None, "source_after": None, "commands": [],
               "native_cases": [], "complete": False, "diagnostic_all_passed": False,
               "original_baseline_qualified": False, "host_qualified": False,
               "performance_qualified": False, "production_activation": False,
               "scope": "Package-selected test-profile build; not the whole-workspace feature-unification denominator. Repetitions are bounded observations; any failure remains failure."}
    binary = None
    try:
        receipt["reader_controls"] = reader_controls()
        receipt["source_before"] = source(out / "source-before.json")
        for command, name in [
                (["rustc", "+1.95.0", "-Vv"], "rustc.log"),
                (["cargo", "+1.95.0", "-V"], "cargo.log")]:
            observed = run(command, out / name, 60)
            receipt["commands"].append(observed)
            require(observed["exit_code"] == 0, "TOOLCHAIN_QUERY_FAILED")
        require(read_log(out / "rustc.log").startswith("rustc 1.95.0 "), "RUSTC_VERSION")
        require(read_log(out / "cargo.log").startswith("cargo 1.95.0 "), "CARGO_VERSION")
        command = ["cargo", "+1.95.0", "test", "--locked", "--manifest-path",
                   "trillionnium/Cargo.toml", "-p", "trnm-data-availability",
                   "--lib", "--no-run", "--message-format=json"]
        built = run(command, out / "build.log", 600)
        receipt["commands"].append(built)
        require(built["exit_code"] == 0 and not built["timed_out"], "DIAGNOSTIC_BUILD_FAILED")
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
        require(len(paths) == 1, "EXACT_DA_TEST_BINARY")
        binary = paths.pop()
        require(binary.is_file() and not binary.is_symlink(), "REGULAR_NATIVE_BINARY")
        receipt["binary_before"] = digest(binary)
        listed = run([str(binary), "--list", "--format", "terse"], out / "registry.log", 60, CRATE)
        receipt["commands"].append(listed)
        require(listed["exit_code"] == 0 and not listed["timed_out"], "REGISTRY_COMMAND")
        names = re.findall(r"^([A-Za-z_][A-Za-z0-9_:]*): test$", read_log(out / "registry.log"), re.M)
        require(len(names) == 174 and len(set(names)) == 174 and SELECTOR in names, "EXACT_174_REGISTRY")
        receipt["registered_test_count"] = 174
        # Every outcome is retained. No failed repetition is replaced by a later pass.
        for ordinal in range(4):
            selected = ordinal != 0
            name = "original-module" if not selected else f"sequence-observation-{ordinal}"
            command = [str(binary)]
            if selected:
                command.extend([SELECTOR, "--exact", "--nocapture"])
            command.append("--test-threads=1")
            execution = run(command, out / (name + ".log"), 300 if not selected else 60, CRATE)
            observed = observations(read_log(out / (name + ".log")), selected, names)
            observed["passed"] = (observed["passed"] and execution["exit_code"] == 0
                                  and not execution["timed_out"])
            receipt["native_cases"].append({"name": name, "execution": execution, **observed})
        receipt["complete"] = True
        receipt["diagnostic_all_passed"] = all(row["passed"] for row in receipt["native_cases"])
    finally:
        if binary is not None:
            receipt["binary_after"] = digest(binary)
        receipt["source_after"] = source(out / "source-after.json")
        receipt["source_unchanged"] = receipt["source_before"] == receipt["source_after"]
        receipt["binary_unchanged"] = (binary is not None
            and receipt.get("binary_before") == receipt.get("binary_after"))
        receipt["diagnostic_all_passed"] = (receipt["diagnostic_all_passed"]
            and receipt["source_unchanged"] and receipt["binary_unchanged"])
        (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print("DA_DIAGNOSTIC " + json.dumps(receipt, sort_keys=True), flush=True)
    return 0 if receipt["complete"] and receipt["diagnostic_all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
