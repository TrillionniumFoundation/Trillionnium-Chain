#!/usr/bin/env python3
"""Run every non-ignored trnm-poco-lab-validator unit test with hard bounds.

The runner discovers the canonical Rust test binary, partitions resource-owning
modules into a serial phase, and executes each runnable test exactly once.

Unlike the predecessor implementation, test output is written to bounded
temporary files instead of pipes. Detached descendants therefore cannot retain
a pipe writer and turn a process timeout into an unbounded runner hang. The
scheduler is single-threaded and owns every child process group directly.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from typing import Iterable, Sequence


REPOSITORY_MINIMUM_DISCOVERED_TESTS = 398
COMMAND_OUTPUT_LIMIT_BYTES = 64 * 1024 * 1024


def normalize_output(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def read_bounded_file(path: Path, maximum_bytes: int) -> str:
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size <= maximum_bytes:
            return handle.read().decode("utf-8", errors="replace")
        half = max(1, maximum_bytes // 2)
        prefix = handle.read(half)
        handle.seek(max(0, size - half))
        suffix = handle.read(half)
    omitted = max(0, size - len(prefix) - len(suffix))
    return (
        prefix.decode("utf-8", errors="replace")
        + f"\n... <{omitted} bytes omitted> ...\n"
        + suffix.decode("utf-8", errors="replace")
    )


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        # The child may be blocked in uninterruptible kernel I/O. Do not turn
        # that platform failure into an unbounded qualification job.
        pass


def run_captured_command(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    maximum_output_bytes: int = COMMAND_OUTPUT_LIMIT_BYTES,
) -> subprocess.CompletedProcess[str]:
    fd, raw_path = tempfile.mkstemp(prefix="trnm-g1-command-", suffix=".log")
    os.close(fd)
    path = Path(raw_path)
    timed_out = False
    try:
        with path.open("wb") as output:
            process = subprocess.Popen(
                list(command),
                cwd=cwd,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                terminate_process_group(process)
        captured = read_bounded_file(path, maximum_output_bytes)
    finally:
        path.unlink(missing_ok=True)

    returncode = process.returncode
    if returncode is None:
        returncode = -signal.SIGKILL
    if timed_out:
        returncode = 124
        captured += (
            f"\ncommand exceeded hard timeout_seconds={timeout_seconds}: "
            f"{' '.join(command)}\n"
        )
    return subprocess.CompletedProcess(
        args=list(command),
        returncode=returncode,
        stdout=captured,
        stderr=None,
    )


def run_checked(
    command: list[str], *, cwd: Path, timeout_seconds: int
) -> subprocess.CompletedProcess[str]:
    result = run_captured_command(
        command,
        cwd=cwd,
        timeout_seconds=timeout_seconds,
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
    result = run_checked(command, cwd=repository, timeout_seconds=1_800)
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
    tests = [
        line[: -len(": test")]
        for line in output.splitlines()
        if line.endswith(": test")
    ]
    if len(tests) != len(set(tests)):
        raise SystemExit("duplicate test names discovered")
    return sorted(tests)


def list_tests(
    binary: Path, *, ignored_only: bool, cwd: Path
) -> list[str]:
    command = [str(binary), "--list", "--format", "terse"]
    if ignored_only:
        command.append("--ignored")
    result = run_captured_command(
        command,
        cwd=cwd,
        timeout_seconds=120,
        maximum_output_bytes=16 * 1024 * 1024,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        raise SystemExit(f"test discovery failed with exit {result.returncode}")
    return parse_test_list(result.stdout)


@dataclass
class RunningTest:
    name: str
    process: subprocess.Popen[bytes]
    log_path: Path
    output_handle: object
    started: float
    deadline: float


def skipped_result(test_name: str, reason: str) -> dict[str, object]:
    return {
        "test": test_name,
        "passed": False,
        "timed_out": reason in {
            "global_timeout",
            "not_started_global_timeout",
            "per_test_timeout",
        },
        "timeout_kind": reason,
        "selected_once": False,
        "returncode": -signal.SIGKILL,
        "elapsed_seconds": 0.0,
        "output": reason,
    }


def spawn_test(
    *,
    binary: Path,
    test_name: str,
    timeout_seconds: int,
    global_deadline: float,
    log_directory: Path,
) -> RunningTest:
    log_path = log_directory / (
        hashlib.sha256(test_name.encode("utf-8")).hexdigest() + ".log"
    )
    output_handle = log_path.open("wb")
    started = time.monotonic()
    process = subprocess.Popen(
        [
            str(binary),
            test_name,
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ],
        stdout=output_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    return RunningTest(
        name=test_name,
        process=process,
        log_path=log_path,
        output_handle=output_handle,
        started=started,
        deadline=min(global_deadline, started + float(timeout_seconds)),
    )


def finish_test(
    running: RunningTest,
    *,
    output_limit: int,
    timed_out: bool,
    timeout_kind: str,
) -> dict[str, object]:
    try:
        running.output_handle.close()
    except OSError:
        pass

    try:
        output = read_bounded_file(running.log_path, output_limit)
    except FileNotFoundError:
        output = "<missing test log>"
    finally:
        running.log_path.unlink(missing_ok=True)

    elapsed = round(time.monotonic() - running.started, 6)
    returncode = running.process.returncode
    if returncode is None:
        returncode = -signal.SIGKILL

    selected_once = "running 1 test" in output
    passed = (
        not timed_out
        and returncode == 0
        and selected_once
        and "test result: ok." in output
    )
    return {
        "test": running.name,
        "passed": passed,
        "timed_out": timed_out,
        "timeout_kind": timeout_kind,
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


def emit_heartbeat(
    *,
    active: dict[str, RunningTest],
    started: float,
    deadline: float,
    phase: str,
) -> None:
    now = time.monotonic()
    snapshot = sorted(
        (name, running.process.pid, round(now - running.started, 3))
        for name, running in active.items()
    )
    print(
        "g1_lab_heartbeat "
        f"phase={phase} elapsed_seconds={round(now - started, 3)} "
        f"remaining_seconds={max(0, round(deadline - now, 3))} "
        f"active={json.dumps(snapshot, separators=(',', ':'))}",
        flush=True,
    )


def run_phase(
    *,
    binary: Path,
    tests: list[str],
    workers: int,
    timeout_seconds: int,
    global_deadline: float,
    heartbeat_seconds: int,
    output_limit: int,
    log_directory: Path,
    results: list[dict[str, object]],
    completed: int,
    total: int,
    phase: str,
    whole_run_started: float,
) -> int:
    pending = deque(tests)
    active: dict[str, RunningTest] = {}
    next_heartbeat = time.monotonic() + heartbeat_seconds

    while pending or active:
        now = time.monotonic()

        while pending and len(active) < workers and now < global_deadline:
            test_name = pending.popleft()
            active[test_name] = spawn_test(
                binary=binary,
                test_name=test_name,
                timeout_seconds=timeout_seconds,
                global_deadline=global_deadline,
                log_directory=log_directory,
            )
            now = time.monotonic()

        if now >= global_deadline:
            for test_name, running in list(active.items()):
                terminate_process_group(running.process)
                result = finish_test(
                    running,
                    output_limit=output_limit,
                    timed_out=True,
                    timeout_kind="global_timeout",
                )
                results.append(result)
                completed += 1
                emit_progress(
                    result,
                    completed=completed,
                    total=total,
                    phase=phase,
                )
                active.pop(test_name, None)

            while pending:
                result = skipped_result(
                    pending.popleft(), "not_started_global_timeout"
                )
                results.append(result)
                completed += 1
                emit_progress(
                    result,
                    completed=completed,
                    total=total,
                    phase=phase,
                )
            break

        made_progress = False
        for test_name, running in list(active.items()):
            returncode = running.process.poll()
            if returncode is not None:
                result = finish_test(
                    running,
                    output_limit=output_limit,
                    timed_out=False,
                    timeout_kind="none",
                )
            elif now >= running.deadline:
                timeout_kind = (
                    "global_timeout"
                    if global_deadline - now <= 0.5
                    else "per_test_timeout"
                )
                terminate_process_group(running.process)
                result = finish_test(
                    running,
                    output_limit=output_limit,
                    timed_out=True,
                    timeout_kind=timeout_kind,
                )
            else:
                continue

            results.append(result)
            completed += 1
            emit_progress(
                result,
                completed=completed,
                total=total,
                phase=phase,
            )
            active.pop(test_name, None)
            made_progress = True

        if time.monotonic() >= next_heartbeat:
            emit_heartbeat(
                active=active,
                started=whole_run_started,
                deadline=global_deadline,
                phase=phase,
            )
            next_heartbeat = time.monotonic() + heartbeat_seconds

        if not made_progress:
            remaining = max(0.0, global_deadline - time.monotonic())
            time.sleep(min(0.1, remaining))

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
    all_tests = list_tests(binary, ignored_only=False, cwd=repository)
    ignored_tests = set(
        list_tests(binary, ignored_only=True, cwd=repository)
    )
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
        raise SystemExit(
            "resource-aware schedule is not an exact runnable-test partition"
        )
    if len(scheduled) != len(set(scheduled)):
        raise SystemExit("resource-aware schedule selects a test more than once")

    started = time.monotonic()
    deadline = started + args.global_timeout_seconds
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
    with tempfile.TemporaryDirectory(prefix="trnm-g1-lab-") as raw_log_directory:
        log_directory = Path(raw_log_directory)
        completed = run_phase(
            binary=binary,
            tests=parallel_tests,
            workers=args.workers,
            timeout_seconds=args.parallel_test_timeout_seconds,
            global_deadline=deadline,
            heartbeat_seconds=args.heartbeat_seconds,
            output_limit=args.max_captured_output_bytes,
            log_directory=log_directory,
            results=results,
            completed=completed,
            total=len(runnable),
            phase="parallel",
            whole_run_started=started,
        )

        if time.monotonic() >= deadline:
            for test_name in serial_tests:
                result = skipped_result(
                    test_name, "not_started_global_timeout"
                )
                results.append(result)
                completed += 1
                emit_progress(
                    result,
                    completed=completed,
                    total=len(runnable),
                    phase="serial",
                )
        else:
            completed = run_phase(
                binary=binary,
                tests=serial_tests,
                workers=1,
                timeout_seconds=args.serial_test_timeout_seconds,
                global_deadline=deadline,
                heartbeat_seconds=args.heartbeat_seconds,
                output_limit=args.max_captured_output_bytes,
                log_directory=log_directory,
                results=results,
                completed=completed,
                total=len(runnable),
                phase="serial",
                whole_run_started=started,
            )

    if completed != len(runnable) or len(results) != len(runnable):
        raise SystemExit("not every runnable laboratory test completed exactly once")
    if len({str(result["test"]) for result in results}) != len(runnable):
        raise SystemExit("one or more laboratory tests produced duplicate results")

    projection = canonical_result_projection(results)
    encoded = json.dumps(
        {
            "schema": "trnm-g1-lab-validator-bounded-result-v3",
            "discovered": len(all_tests),
            "ignored": sorted(ignored_tests),
            "parallel_tests": sorted(parallel_tests),
            "serial_prefixes": list(serial_prefixes),
            "serial_tests": sorted(serial_tests),
            "limits": {
                "workers": args.workers,
                "parallel_test_timeout_seconds": (
                    args.parallel_test_timeout_seconds
                ),
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
    report_path = (
        Path(tempfile.gettempdir()) / "trnm-g1-lab-validator-result-v3.json"
    )
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
