#!/usr/bin/env python3
"""Run every non-ignored trnm-poco-lab-validator unit test with hard bounds.

The runner discovers the canonical Rust test binary, partitions resource-owning
modules into a serial phase, and executes each runnable test exactly once. Every
child process, pipe read, and whole-run wall clock is bounded. Timeout handling
never performs an unbounded read from a pipe that may still be held by a
detached grandchild.
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
import threading
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
    tests = [line[: -len(": test")] for line in output.splitlines() if line.endswith(": test")]
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
        timeout=120,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        raise SystemExit(f"test discovery failed with exit {result.returncode}")
    return parse_test_list(result.stdout)


def normalize_output(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def bound_output(output: str, maximum_bytes: int) -> str:
    encoded = output.encode("utf-8", errors="replace")
    if len(encoded) <= maximum_bytes:
        return output
    half = max(1, maximum_bytes // 2)
    omitted = len(encoded) - (2 * half)
    prefix = encoded[:half].decode("utf-8", errors="replace")
    suffix = encoded[-half:].decode("utf-8", errors="replace")
    return f"{prefix}\n... <{omitted} bytes omitted> ...\n{suffix}"


def terminate_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def skipped_result(test_name: str, reason: str) -> dict[str, object]:
    return {
        "test": test_name,
        "passed": False,
        "timed_out": reason in {"global_timeout", "not_started_global_timeout"},
        "timeout_kind": reason,
        "selected_once": False,
        "returncode": -signal.SIGKILL,
        "elapsed_seconds": 0.0,
        "output": reason,
    }


def run_one_test(
    binary: Path,
    test_name: str,
    timeout_seconds: int,
    deadline: float,
    output_limit: int,
    active: dict[str, float],
    active_lock: threading.Lock,
) -> dict[str, object]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return skipped_result(test_name, "not_started_global_timeout")

    effective_timeout = min(float(timeout_seconds), remaining)
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
    with active_lock:
        active[test_name] = started

    timed_out = False
    timeout_kind = "none"
    output = ""
    try:
        output, _ = process.communicate(timeout=effective_timeout)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        timeout_kind = (
            "global_timeout"
            if deadline - time.monotonic() <= 0.5
            else "per_test_timeout"
        )
        # TimeoutExpired already carries bytes drained by communicate(). Never
        # call stdout.read(): detached descendants can retain the write end and
        # turn a bounded timeout into an unbounded hang.
        output = normalize_output(error.output)
        terminate_process_group(process)
        if process.stdout is not None:
            process.stdout.close()
    finally:
        with active_lock:
            active.pop(test_name, None)

    elapsed = round(time.monotonic() - started, 6)
    returncode = process.returncode if process.returncode is not None else -signal.SIGKILL
    output = bound_output(normalize_output(output), output_limit)
    selected_once = "running 1 test" in output
    passed = not timed_out and returncode == 0 and selected_once
    return {
        "test": test_name,
        "passed": passed,
        "timed_out": timed_out,
        "timeout_kind": timeout_kind,
        "selected_once": selected_once,
        "returncode": returncode,
        "elapsed_seconds": elapsed,
        "output": output,
    }


def canonical_result_projection(results: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {
            "test": result["test"],
            "passed": result["passed"],
            "timed_out": result["timed_out"],
            "timeout_kind": result["timeout_kind"],
            "selected_once": result["selected_once"],
            "returncode": result["returncode"],
        }
        for result in sorted(results, key=lambda item: str(item["test"]))
    ]


def emit_progress(
    result: dict[str, object], *, completed: int, total: int, phase: str
) -> None:
    print(
        "g1_lab_progress "
        f"completed={completed}/{total} phase={phase} "
        f"passed={str(bool(result['passed'])).lower()} "
        f"timed_out={str(bool(result['timed_out'])).lower()} "
        f"elapsed_seconds={result['elapsed_seconds']} test={result['test']}",
        flush=True,
    )


def heartbeat(
    stop: threading.Event,
    active: dict[str, float],
    active_lock: threading.Lock,
    interval_seconds: int,
    started: float,
    deadline: float,
) -> None:
    while not stop.wait(interval_seconds):
        now = time.monotonic()
        with active_lock:
            snapshot = sorted(
                (name, round(now - test_started, 3))
                for name, test_started in active.items()
            )
        print(
            "g1_lab_heartbeat "
            f"elapsed_seconds={round(now - started, 3)} "
            f"remaining_seconds={max(0, round(deadline - now, 3))} "
            f"active={json.dumps(snapshot, separators=(',', ':'))}",
            flush=True,
        )


def run_parallel_phase(
    *,
    binary: Path,
    tests: list[str],
    workers: int,
    timeout_seconds: int,
    deadline: float,
    output_limit: int,
    active: dict[str, float],
    active_lock: threading.Lock,
    results: list[dict[str, object]],
    completed: int,
    total: int,
) -> int:
    iterator = iter(tests)
    futures: dict[concurrent.futures.Future[dict[str, object]], str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for _ in range(workers):
            try:
                test_name = next(iterator)
            except StopIteration:
                break
            futures[
                executor.submit(
                    run_one_test,
                    binary,
                    test_name,
                    timeout_seconds,
                    deadline,
                    output_limit,
                    active,
                    active_lock,
                )
            ] = test_name

        while futures:
            done, _ = concurrent.futures.wait(
                futures,
                timeout=max(1.0, min(30.0, deadline - time.monotonic() + 1.0)),
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if not done:
                continue
            for future in done:
                futures.pop(future)
                result = future.result()
                results.append(result)
                completed += 1
                emit_progress(result, completed=completed, total=total, phase="parallel")
                try:
                    test_name = next(iterator)
                except StopIteration:
                    continue
                futures[
                    executor.submit(
                        run_one_test,
                        binary,
                        test_name,
                        timeout_seconds,
                        deadline,
                        output_limit,
                        active,
                        active_lock,
                    )
                ] = test_name
    return completed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default=".")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--parallel-test-timeout-seconds", type=int, default=300)
    parser.add_argument("--serial-test-timeout-seconds", type=int, default=900)
    parser.add_argument("--global-timeout-seconds", type=int, default=14_400)
    parser.add_argument("--heartbeat-seconds", type=int, default=60)
    parser.add_argument("--max-captured-output-bytes", type=int, default=262_144)
    parser.add_argument(
        "--minimum-discovered-tests",
        type=int,
        default=REPOSITORY_MINIMUM_DISCOVERED_TESTS,
    )
    parser.add_argument("--serial-prefix", action="append", default=[])
    args = parser.parse_args()

    if args.workers < 1 or args.workers > 16:
        raise SystemExit("workers must be in 1..16")
    if args.parallel_test_timeout_seconds < 30:
        raise SystemExit("parallel-test timeout must be at least 30 seconds")
    if args.serial_test_timeout_seconds < 30:
        raise SystemExit("serial-test timeout must be at least 30 seconds")
    if args.global_timeout_seconds < 300:
        raise SystemExit("global timeout must be at least 300 seconds")
    if args.heartbeat_seconds < 10 or args.heartbeat_seconds > 600:
        raise SystemExit("heartbeat interval must be in 10..600 seconds")
    if args.max_captured_output_bytes < 4096:
        raise SystemExit("captured output bound must be at least 4096 bytes")

    serial_prefixes = tuple(dict.fromkeys(args.serial_prefix))
    if any(not prefix for prefix in serial_prefixes):
        raise SystemExit("serial prefixes must be non-empty")

    repository = Path(args.repository).resolve()
    binary = discover_test_binary(repository)
    all_tests = list_tests(binary, ignored_only=False)
    ignored_tests = set(list_tests(binary, ignored_only=True))
    if len(all_tests) < args.minimum_discovered_tests:
        raise SystemExit(
            f"test-set shrinkage: discovered {len(all_tests)}, minimum is "
            f"{args.minimum_discovered_tests}"
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
        raise SystemExit(f"serial test-prefix drift: no tests matched {unmatched_prefixes!r}")

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

    started = time.monotonic()
    deadline = started + args.global_timeout_seconds
    active: dict[str, float] = {}
    active_lock = threading.Lock()
    stop_heartbeat = threading.Event()
    heartbeat_thread = threading.Thread(
        target=heartbeat,
        args=(
            stop_heartbeat,
            active,
            active_lock,
            args.heartbeat_seconds,
            started,
            deadline,
        ),
        daemon=True,
    )
    heartbeat_thread.start()

    print(
        "g1_lab_discovery "
        f"binary={binary} discovered={len(all_tests)} ignored={len(ignored_tests)} "
        f"runnable={len(runnable)} parallel={len(parallel_tests)} "
        f"serial={len(serial_tests)} workers={args.workers} "
        f"parallel_timeout={args.parallel_test_timeout_seconds} "
        f"serial_timeout={args.serial_test_timeout_seconds} "
        f"global_timeout={args.global_timeout_seconds} "
        f"serial_prefixes={','.join(serial_prefixes) or '-'}",
        flush=True,
    )

    results: list[dict[str, object]] = []
    completed = 0
    try:
        completed = run_parallel_phase(
            binary=binary,
            tests=parallel_tests,
            workers=args.workers,
            timeout_seconds=args.parallel_test_timeout_seconds,
            deadline=deadline,
            output_limit=args.max_captured_output_bytes,
            active=active,
            active_lock=active_lock,
            results=results,
            completed=completed,
            total=len(runnable),
        )
        for test_name in serial_tests:
            result = run_one_test(
                binary,
                test_name,
                args.serial_test_timeout_seconds,
                deadline,
                args.max_captured_output_bytes,
                active,
                active_lock,
            )
            results.append(result)
            completed += 1
            emit_progress(result, completed=completed, total=len(runnable), phase="serial")
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=2)

    if completed != len(runnable) or len(results) != len(runnable):
        raise SystemExit("not every runnable laboratory test completed exactly once")

    projection = canonical_result_projection(results)
    encoded = json.dumps(
        {
            "schema": "trnm-g1-lab-validator-bounded-result-v2",
            "discovered": len(all_tests),
            "ignored": sorted(ignored_tests),
            "parallel_tests": sorted(parallel_tests),
            "serial_prefixes": list(serial_prefixes),
            "serial_tests": sorted(serial_tests),
            "limits": {
                "workers": args.workers,
                "parallel_test_timeout_seconds": args.parallel_test_timeout_seconds,
                "serial_test_timeout_seconds": args.serial_test_timeout_seconds,
                "global_timeout_seconds": args.global_timeout_seconds,
                "max_captured_output_bytes": args.max_captured_output_bytes,
            },
            "results": projection,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    report_path = Path(tempfile.gettempdir()) / "trnm-g1-lab-validator-result-v2.json"
    report_path.write_bytes(encoded + b"\n")

    failures = [result for result in results if not bool(result["passed"])]
    for result in sorted(failures, key=lambda item: str(item["test"])):
        print(f"--- failure: {result['test']} ---", file=sys.stderr)
        print(result["output"], file=sys.stderr)
    print(
        "g1_lab_result "
        f"passed={len(results) - len(failures)} failed={len(failures)} "
        f"ignored={len(ignored_tests)} parallel={len(parallel_tests)} "
        f"serial={len(serial_tests)} sha256={digest} report={report_path}",
        flush=True,
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
