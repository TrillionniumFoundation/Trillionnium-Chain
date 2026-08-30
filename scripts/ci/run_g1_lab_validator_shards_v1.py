#!/usr/bin/env python3
"""Run every non-ignored trnm-poco-lab-validator unit test in bounded shards.

The ordinary `cargo test --lib` invocation exceeded the single-job integration
budget because hundreds of process/recovery tests were serialized behind one
job. This runner preserves the complete discovered test set, executes every
non-ignored test exactly once in isolated test-binary processes, and fails if a
test disappears, is selected zero times, times out, or returns non-zero.

Tests that own process, socket, or filesystem lifecycle state can be assigned
to an explicit serial phase. This avoids cross-test resource contention without
ignoring, retrying around, or weakening any test.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from typing import Iterable


REPOSITORY_MINIMUM_DISCOVERED_TESTS = 398


def run_checked(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        raise SystemExit(
            f"command failed with exit {result.returncode}: {' '.join(command)}"
        )
    return result


def discover_test_binary(repository: Path) -> Path:
    command = [
        "cargo",
        "test",
        "--manifest-path",
        "trillionnium/Cargo.toml",
        "-p",
        "trnm-poco-lab-validator",
        "--lib",
        "--locked",
        "--no-run",
        "--message-format=json",
    ]
    result = run_checked(command, cwd=repository)
    executables: list[Path] = []
    for raw_line in result.stdout.splitlines():
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if event.get("reason") != "compiler-artifact" or not event.get("executable"):
            continue
        target = event.get("target") or {}
        name = str(target.get("name", "")).replace("_", "-")
        kinds = set(target.get("kind") or [])
        if name == "trnm-poco-lab-validator" and "lib" in kinds:
            executables.append(Path(event["executable"]))
    unique = sorted(set(executables))
    if len(unique) != 1:
        raise SystemExit(f"expected one laboratory test binary, got {unique!r}")
    binary = unique[0]
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit(f"test binary is not executable: {binary}")
    return binary


def parse_test_list(output: str) -> list[str]:
    tests: list[str] = []
    for line in output.splitlines():
        if line.endswith(": test"):
            tests.append(line[: -len(": test")])
    if len(tests) != len(set(tests)):
        raise SystemExit("duplicate test names discovered")
    return sorted(tests)


def list_tests(binary: Path, *, ignored_only: bool) -> list[str]:
    command = [str(binary), "--list", "--format", "terse"]
    if ignored_only:
        command.append("--ignored")
    result = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        raise SystemExit(f"test discovery failed with exit {result.returncode}")
    return parse_test_list(result.stdout)


def terminate_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    process.wait(timeout=5)


def run_one_test(binary: Path, test_name: str, timeout_seconds: int) -> dict[str, object]:
    started = time.monotonic()
    process = subprocess.Popen(
        [
            str(binary),
            test_name,
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    timed_out = False
    try:
        output, _ = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        terminate_process_group(process)
        output = process.stdout.read() if process.stdout is not None else ""
    elapsed = round(time.monotonic() - started, 6)
    returncode = process.returncode if process.returncode is not None else -signal.SIGKILL
    selected_once = "running 1 test" in output
    passed = not timed_out and returncode == 0 and selected_once
    return {
        "test": test_name,
        "passed": passed,
        "timed_out": timed_out,
        "selected_once": selected_once,
        "returncode": returncode,
        "elapsed_seconds": elapsed,
        "output": output,
    }


def canonical_result_projection(
    results: Iterable[dict[str, object]],
) -> list[dict[str, object]]:
    return [
        {
            "test": result["test"],
            "passed": result["passed"],
            "timed_out": result["timed_out"],
            "selected_once": result["selected_once"],
            "returncode": result["returncode"],
        }
        for result in sorted(results, key=lambda item: str(item["test"]))
    ]


def emit_progress(
    result: dict[str, object],
    *,
    completed: int,
    total: int,
    phase: str,
) -> None:
    print(
        "g1_lab_progress "
        f"completed={completed}/{total} "
        f"phase={phase} "
        f"passed={str(bool(result['passed'])).lower()} "
        f"elapsed_seconds={result['elapsed_seconds']} "
        f"test={result['test']}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default=".")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--per-test-timeout-seconds", type=int, default=1800)
    parser.add_argument(
        "--minimum-discovered-tests",
        type=int,
        default=REPOSITORY_MINIMUM_DISCOVERED_TESTS,
    )
    parser.add_argument(
        "--serial-prefix",
        action="append",
        default=[],
        help=(
            "Run matching test-name prefixes sequentially after all parallel "
            "tests. May be supplied more than once."
        ),
    )
    args = parser.parse_args()

    if args.workers < 1 or args.workers > 32:
        raise SystemExit("workers must be in 1..32")
    if args.per_test_timeout_seconds < 60:
        raise SystemExit("per-test timeout must be at least 60 seconds")
    serial_prefixes = tuple(dict.fromkeys(args.serial_prefix))
    if any(not prefix for prefix in serial_prefixes):
        raise SystemExit("serial prefixes must be non-empty")

    repository = Path(args.repository).resolve()
    binary = discover_test_binary(repository)
    all_tests = list_tests(binary, ignored_only=False)
    ignored_tests = set(list_tests(binary, ignored_only=True))
    if len(all_tests) < args.minimum_discovered_tests:
        raise SystemExit(
            f"test-set shrinkage: discovered {len(all_tests)}, "
            f"minimum is {args.minimum_discovered_tests}"
        )
    if not ignored_tests.issubset(set(all_tests)):
        raise SystemExit("ignored test set is not a subset of all discovered tests")
    runnable = [test for test in all_tests if test not in ignored_tests]
    if not runnable:
        raise SystemExit("no runnable laboratory tests discovered")

    unmatched_prefixes = [
        prefix
        for prefix in serial_prefixes
        if not any(test.startswith(prefix) for test in runnable)
    ]
    if unmatched_prefixes:
        raise SystemExit(
            f"serial test-prefix drift: no tests matched {unmatched_prefixes!r}"
        )

    serial_tests = [
        test
        for test in runnable
        if any(test.startswith(prefix) for prefix in serial_prefixes)
    ]
    serial_set = set(serial_tests)
    parallel_tests = [test for test in runnable if test not in serial_set]
    scheduled = parallel_tests + serial_tests
    if len(scheduled) != len(runnable) or set(scheduled) != set(runnable):
        raise SystemExit("resource-aware schedule is not an exact runnable-test partition")
    if len(scheduled) != len(set(scheduled)):
        raise SystemExit("resource-aware schedule selects a test more than once")

    print(
        "g1_lab_discovery "
        f"binary={binary} discovered={len(all_tests)} "
        f"ignored={len(ignored_tests)} runnable={len(runnable)} "
        f"parallel={len(parallel_tests)} serial={len(serial_tests)} "
        f"workers={args.workers} serial_prefixes={','.join(serial_prefixes) or '-'}"
    )

    results: list[dict[str, object]] = []
    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_test = {
            executor.submit(
                run_one_test,
                binary,
                test_name,
                args.per_test_timeout_seconds,
            ): test_name
            for test_name in parallel_tests
        }
        for future in concurrent.futures.as_completed(future_to_test):
            result = future.result()
            results.append(result)
            completed += 1
            emit_progress(
                result,
                completed=completed,
                total=len(runnable),
                phase="parallel",
            )

    for test_name in serial_tests:
        result = run_one_test(binary, test_name, args.per_test_timeout_seconds)
        results.append(result)
        completed += 1
        emit_progress(
            result,
            completed=completed,
            total=len(runnable),
            phase="serial",
        )

    if completed != len(runnable) or len(results) != len(runnable):
        raise SystemExit("not every runnable laboratory test completed exactly once")

    projection = canonical_result_projection(results)
    encoded = json.dumps(
        {
            "schema": "trnm-g1-lab-validator-sharded-result-v1",
            "discovered": len(all_tests),
            "ignored": sorted(ignored_tests),
            "parallel_tests": sorted(parallel_tests),
            "serial_prefixes": list(serial_prefixes),
            "serial_tests": sorted(serial_tests),
            "results": projection,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    report_path = Path(tempfile.gettempdir()) / "trnm-g1-lab-validator-result-v1.json"
    report_path.write_bytes(encoded + b"\n")

    failures = [result for result in results if not bool(result["passed"])]
    for result in sorted(failures, key=lambda item: str(item["test"])):
        print(f"--- failure: {result['test']} ---", file=sys.stderr)
        print(result["output"], file=sys.stderr)
    print(
        "g1_lab_result "
        f"passed={len(results) - len(failures)} failed={len(failures)} "
        f"ignored={len(ignored_tests)} parallel={len(parallel_tests)} "
        f"serial={len(serial_tests)} sha256={digest} report={report_path}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
