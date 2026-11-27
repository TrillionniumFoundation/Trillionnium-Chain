#!/usr/bin/env python3
"""Run the fixed 131 controls once in two independently owned serial processes.

This changes scheduling only. Each worker verifies both complete original module
registries, then runs its fixed alternating subset in its own main thread. The
parent accepts only the exact-once union of two complete successful observations.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import sys
import tempfile
import time
import traceback
import unittest

import pq_corpus_current_v2 as current

ROOT = Path(__file__).resolve().parents[2]
ORIGINAL = "scripts/ci/run_pq_corpus_current_controls_v2.py"
ORIGINAL_SHA256 = "be852b050a205c107858d49610993491d989731038d5338cfe75d1ae3cddd0cd"
PROCESS_OWNER = "formal/pon-nakamoto-v1/bounded_process.py"
PROCESS_OWNER_BLOB = "b8579d1ea76e8c84214570f3f08d84595bfc77b6"
WORKERS = 2
COUNTS = (18, 113)
PARTITION_COUNTS = (66, 65)
JOB_SECONDS = 600
OPERATION_SECONDS = 540
RECEIPT_LIMIT = 1024 * 1024
STREAM_LIMIT = 4 * 1024 * 1024
ERROR_FIELDS = (
    "loader_errors", "skipped", "failures", "errors",
    "expected_failures", "unexpected_successes",
)
require = current.require


def write_report(path, value, *, create=False):
    with path.open("x" if create else "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def read_receipt(path, limit=RECEIPT_LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(
            stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_uid == os.geteuid() and before.st_size <= limit,
            "receipt must be a bounded owned regular file",
        )
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        after, named = os.fstat(fd), path.lstat()
        key = lambda st: (
            st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns,
        )
        require(
            len(raw) == before.st_size <= limit
            and key(before) == key(after) == key(named),
            "receipt changed during its original descriptor read",
        )
    finally:
        os.close(fd)
    return raw, current.strict_json(raw)


def job_clock(path, output):
    require(
        path.is_absolute() and output.is_absolute() and path.parent == output.parent
        and path != output and not output.resolve().is_relative_to(ROOT),
        "clock and result require distinct paths in one external output directory",
    )
    raw, clock = read_receipt(path, 16384)
    current.fields(
        clock, "schema source_head run_id run_attempt boot_id started_monotonic_ns "
        "operation_deadline_monotonic_ns full_deadline_monotonic_ns "
        "original_job_timeout_seconds operation_budget_seconds "
        "retention_reserve_seconds clock_excludes_platform_setup", "job clock",
    )
    require(
        clock["schema"] == "trnm-pq-current-source-job-clock-v1"
        and clock["source_head"] == os.environ["EXPECTED_HEAD"]
        and clock["run_id"] == os.environ["GITHUB_RUN_ID"]
        and clock["run_attempt"] == os.environ["GITHUB_RUN_ATTEMPT"]
        and clock["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        and clock["clock_excludes_platform_setup"] is True,
        "job clock belongs to a different original invocation",
    )
    for name in (
        "started_monotonic_ns", "operation_deadline_monotonic_ns",
        "full_deadline_monotonic_ns", "original_job_timeout_seconds",
        "operation_budget_seconds", "retention_reserve_seconds",
    ):
        require(type(clock[name]) is int, "clock integer field changed")
    start = clock["started_monotonic_ns"]
    require(
        clock["original_job_timeout_seconds"] == JOB_SECONDS
        and clock["operation_budget_seconds"] == OPERATION_SECONDS
        and clock["retention_reserve_seconds"] == JOB_SECONDS - OPERATION_SECONDS
        and clock["operation_deadline_monotonic_ns"] == start + OPERATION_SECONDS * 10**9
        and clock["full_deadline_monotonic_ns"] == start + JOB_SECONDS * 10**9
        and start <= time.monotonic_ns(),
        "original 600-second ceiling or its fixed reserve changed",
    )
    return clock, hashlib.sha256(raw).hexdigest()


def remaining(clock):
    seconds = (clock["operation_deadline_monotonic_ns"] - time.monotonic_ns()) / 10**9
    require(0 < seconds <= OPERATION_SECONDS, "original job operation deadline expired")
    return seconds


def pinned_module(relative, name, *, sha256=None, blob=None):
    raw = current.read_regular(ROOT, relative, RECEIPT_LIMIT)
    actual_blob = hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    ).hexdigest()
    require(
        (sha256 is None or hashlib.sha256(raw).hexdigest() == sha256)
        and (blob is None or actual_blob == blob),
        "original source owner changed: " + relative,
    )
    require(name not in sys.modules, "source owner was already imported")
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    require(spec is not None and spec.loader is not None, "source loader unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        # Execute the exact descriptor-read bytes whose source pins were checked.
        # Loader metadata is preserved, but path and bytecode-cache reads are not used.
        exec(compile(raw, str(ROOT / relative), "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


def original_roster():
    legacy = pinned_module(ORIGINAL, "_pq_original_named_owner_v2", sha256=ORIGINAL_SHA256)
    require(tuple(legacy.COUNTS) == COUNTS, "original module counts changed")
    raw = current.read_regular(ROOT, legacy.ROSTER, current.MAX_MAP_BYTES)
    require(hashlib.sha256(raw).hexdigest() == legacy.ROSTER_SHA256, "frozen roster changed")
    roster = current.strict_json(raw)
    current.fields(roster, "schema expected_tests suites qualification", "control roster")
    require(
        roster["schema"] == "trnm-pq-corpus-current-required-controls-v2"
        and type(roster["expected_tests"]) is int and roster["expected_tests"] == sum(COUNTS)
        and current.canonical(roster["qualification"]) == current.canonical(current.QUALIFICATION)
        and type(roster["suites"]) is list and len(roster["suites"]) == len(COUNTS),
        "original roster scope changed",
    )
    for row, module, count in zip(roster["suites"], legacy.MODULES, COUNTS):
        current.fields(row, "module expected_tests tests", "control suite")
        names = row["tests"]
        require(
            row["module"] == module and type(row["expected_tests"]) is int
            and row["expected_tests"] == count and type(names) is list
            and all(type(name) is str and name.startswith(module + ".") for name in names)
            and len(names) == count and names == sorted(set(names)),
            "complete original module registry changed",
        )
    return legacy, roster


def run_worker(index, output, clock_path):
    start, cpu = time.monotonic(), resource.getrusage(resource.RUSAGE_SELF)
    clock, clock_sha = job_clock(clock_path, output)
    remaining(clock)
    legacy, roster = original_roster()
    require(tempfile.gettempdir() == os.environ["TMPDIR"], "explicit private fixture root differs")
    report = {
        "schema": "trnm-pq-fixed-partition-observation-v3", "status": "RUNNING",
        "worker": index, "pid": os.getpid(), "source_head": clock["source_head"],
        "run_id": clock["run_id"], "run_attempt": clock["run_attempt"],
        "job_clock_sha256": clock_sha, "roster_sha256": legacy.ROSTER_SHA256,
        "original_named_owner_sha256": ORIGINAL_SHA256, "full_required_tests": sum(COUNTS),
        "partition_tests": PARTITION_COUNTS[index], "suites": [],
        "qualification": dict(current.QUALIFICATION), "all_named_controls_passed": False,
        "serial_in_process_main_thread": True, "private_tmpdir": tempfile.gettempdir(),
    }
    write_report(output, report, create=True)
    for required in roster["suites"]:
        module, expected = required["module"], required["tests"]
        selected = expected[index::WORKERS]
        row = {"module": module, "selected_ids": selected, "passed": False}
        try:
            remaining(clock)
            loader = unittest.TestLoader()
            suite = loader.discover(str(ROOT / "scripts/ci"), pattern=module + ".py")
            cases = list(legacy.flatten(suite))
            registered = [test.id() for test in cases]
            row.update(registered_ids=registered, loader_errors=list(loader.errors))
            require(
                not loader.errors and Counter(registered) == Counter(expected),
                "registered complete module differs from the fixed original roster",
            )
            by_name = {test.id(): test for test in cases}
            chosen = unittest.TestSuite(by_name[name] for name in selected)
            result = unittest.TextTestRunner(
                stream=sys.stderr, verbosity=2, descriptions=False,
                resultclass=legacy.ObservedResult,
            ).run(chosen)
            row.update(
                tests_run=result.testsRun, started_ids=result.started_ids,
                success_ids=result.success_ids,
                skipped=[(test.id(), why) for test, why in result.skipped],
                failures=[(test.id(), why) for test, why in result.failures],
                errors=[(test.id(), why) for test, why in result.errors],
                expected_failures=[(test.id(), why) for test, why in result.expectedFailures],
                unexpected_successes=[test.id() for test in result.unexpectedSuccesses],
            )
            row["passed"] = (
                result.testsRun == len(selected)
                and Counter(result.started_ids) == Counter(selected)
                and Counter(result.success_ids) == Counter(selected)
                and result.wasSuccessful() and not any(row[name] for name in ERROR_FIELDS)
            )
        except (Exception, SystemExit) as error:
            row["exception"] = f"{type(error).__name__}: {error}"
            traceback.print_exc(file=sys.stderr)
        report["suites"].append(row)
        write_report(output, report)
    report["status"] = (
        "PASS_PARTITION_ONLY" if all(row["passed"] is True for row in report["suites"]) else "FAIL"
    )
    end_cpu = resource.getrusage(resource.RUSAGE_SELF)
    report["worker_wall_seconds"] = time.monotonic() - start
    report["worker_process_cpu_seconds"] = (
        end_cpu.ru_utime + end_cpu.ru_stime - cpu.ru_utime - cpu.ru_stime
    )
    try:
        remaining(clock)
    except ValueError as error:
        report.update(status="FAIL", deadline_error=str(error))
    write_report(output, report)
    print(json.dumps({"worker": index, "status": report["status"]}, sort_keys=True))
    return 0 if report["status"] == "PASS_PARTITION_ONLY" else 1


def launch(owner, index, output, clock_path, clock):
    prefix = output.parent / f"{output.stem}.worker-{index}"
    report_path = prefix.with_name(prefix.name + ".json")
    paths = {name: prefix.with_name(prefix.name + "." + name) for name in ("stdout", "stderr", "process.json")}
    require(
        not report_path.exists() and all(not path.exists() for path in paths.values()),
        "partition artifacts already exist; no retry or overwrite is allowed",
    )
    record = {
        "worker": index, "receipt": str(report_path), "status": "RUNNING",
        "process_owner_git_blob": PROCESS_OWNER_BLOB, "attempts": 1,
        "owned_completion": False, "returncode": None, "streams_complete": False,
    }
    write_report(paths["process.json"], record, create=True)
    start, stdout, stderr = time.monotonic(), b"", b""
    try:
        result = owner.run_bounded(
            [sys.executable, str(Path(__file__).resolve()), "--worker", str(index),
             "--output", str(report_path), "--job-clock", str(clock_path)],
            b"", timeout=remaining(clock), stdout_limit=STREAM_LIMIT, stderr_limit=STREAM_LIMIT,
            cwd=ROOT, env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        stdout, stderr = result.stdout, result.stderr
        record.update(
            status="COMPLETED", owned_completion=True, returncode=result.returncode,
            streams_complete=True, stdout_truncated=False, stderr_truncated=False,
        )
    except owner.ProcessFailure as error:
        stdout, stderr = error.stdout, error.stderr
        record.update(
            status="FAIL", error=str(error), returncode=error.returncode,
            stdout_truncated=error.stdout_truncated, stderr_truncated=error.stderr_truncated,
            stdin_written=error.stdin_written,
        )
    except BaseException as error:
        record.update(status="FAIL", error=f"{type(error).__name__}: {error}")
    finally:
        for name, raw in (("stdout", stdout), ("stderr", stderr)):
            with paths[name].open("xb") as stream:
                stream.write(raw)
            record[name] = {
                "path": str(paths[name]), "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        record["owner_wall_seconds"] = time.monotonic() - start
        write_report(paths["process.json"], record)
    return record


def run(output, clock_path):
    start = time.monotonic()
    clock, clock_sha = job_clock(clock_path, output)
    remaining(clock)
    legacy, roster = original_roster()
    owner = pinned_module(PROCESS_OWNER, "_pq_bounded_process_owner_v3", blob=PROCESS_OWNER_BLOB)
    report = {
        "schema": "trnm-pq-corpus-current-named-observation-v3", "status": "RUNNING",
        "source_head": clock["source_head"], "run_id": clock["run_id"],
        "run_attempt": clock["run_attempt"], "job_clock_sha256": clock_sha,
        "roster_sha256": legacy.ROSTER_SHA256, "required_tests": sum(COUNTS),
        "original_named_owner_sha256": ORIGINAL_SHA256, "worker_count": WORKERS,
        "partition_counts": list(PARTITION_COUNTS), "suites": [], "workers": [],
        "qualification": dict(current.QUALIFICATION), "all_named_controls_passed": False,
        "tests_are_not_run_in_supervisor_threads": True, "automatic_retries": 0,
    }
    write_report(output, report, create=True)
    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            futures = [
                pool.submit(launch, owner, index, output, clock_path, clock)
                for index in range(WORKERS)
            ]
            for future in futures:
                report["workers"].append(future.result())
                write_report(output, report)
        observed = []
        for index, process in enumerate(report["workers"]):
            require(
                process["worker"] == index and process["status"] == "COMPLETED"
                and process["owned_completion"] is True and process["returncode"] == 0
                and process["streams_complete"] is True
                and process["stdout_truncated"] is False and process["stderr_truncated"] is False,
                "an owned partition did not complete successfully with both streams",
            )
            raw, worker = read_receipt(Path(process["receipt"]))
            require(
                worker["schema"] == "trnm-pq-fixed-partition-observation-v3"
                and worker["status"] == "PASS_PARTITION_ONLY" and type(worker["worker"]) is int
                and worker["worker"] == index and type(worker["pid"]) is int
                and worker["pid"] > 0 and worker["pid"] != os.getpid()
                and worker["source_head"] == clock["source_head"]
                and worker["run_id"] == clock["run_id"] and worker["run_attempt"] == clock["run_attempt"]
                and worker["job_clock_sha256"] == clock_sha
                and worker["roster_sha256"] == legacy.ROSTER_SHA256
                and worker["original_named_owner_sha256"] == ORIGINAL_SHA256
                and worker["full_required_tests"] == sum(COUNTS)
                and worker["partition_tests"] == PARTITION_COUNTS[index]
                and worker["all_named_controls_passed"] is False
                and worker["serial_in_process_main_thread"] is True
                and worker["private_tmpdir"] == os.environ["TMPDIR"]
                and current.canonical(worker["qualification"]) == current.canonical(current.QUALIFICATION)
                and type(worker["suites"]) is list and len(worker["suites"]) == len(COUNTS),
                "partition receipt scope differs from this original execution",
            )
            process["receipt_sha256"] = hashlib.sha256(raw).hexdigest()
            observed.append(worker)
        require(len({worker["pid"] for worker in observed}) == WORKERS, "workers are not distinct processes")
        for position, required in enumerate(roster["suites"]):
            expected = required["tests"]
            rows = [worker["suites"][position] for worker in observed]
            started, success, selected = [], [], []
            for index, row in enumerate(rows):
                subset = expected[index::WORKERS]
                require(
                    row["module"] == required["module"] and row["passed"] is True
                    and Counter(row["registered_ids"]) == Counter(expected)
                    and row["selected_ids"] == subset and type(row["tests_run"]) is int
                    and row["tests_run"] == len(subset)
                    and Counter(row["started_ids"]) == Counter(subset)
                    and Counter(row["success_ids"]) == Counter(subset)
                    and all(type(row[name]) is list and not row[name] for name in ERROR_FIELDS)
                    and "exception" not in row,
                    "partition omitted, repeated, skipped or failed an original named control",
                )
                selected.extend(row["selected_ids"])
                started.extend(row["started_ids"])
                success.extend(row["success_ids"])
            require(
                Counter(selected) == Counter(expected)
                and Counter(started) == Counter(expected) and Counter(success) == Counter(expected),
                "the merged original roster is not exact-once complete",
            )
            report["suites"].append({
                "module": required["module"], "expected_ids": expected,
                "selected_ids": selected, "started_ids": started, "success_ids": success,
                "tests_run": len(started), "passed": True,
                "complete_discoveries": [row["registered_ids"] for row in rows],
            })
        remaining(clock)
        report.update(status="PASS_METADATA_ONLY", all_named_controls_passed=True)
    except BaseException as error:
        report.update(status="FAIL", error=f"{type(error).__name__}: {error}")
        traceback.print_exc(file=sys.stderr)
    finally:
        report["parent_scope_wall_seconds"] = time.monotonic() - start
        report["first_step_elapsed_seconds"] = (time.monotonic_ns() - clock["started_monotonic_ns"]) / 10**9
        report["actual_full_job_duration_requires_original_platform_job_readback"] = True
        report["cpu_accounting_owner"] = "fixture wrapper self plus reaped children; worker CPU is diagnostic only"
        write_report(output, report)
    print(json.dumps({
        "status": report["status"], "required_tests": sum(COUNTS),
        "roster_sha256": legacy.ROSTER_SHA256, "workers": WORKERS,
    }, sort_keys=True))
    return 0 if report["status"] == "PASS_METADATA_ONLY" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--job-clock", type=Path, required=True)
    parser.add_argument("--worker", type=int, choices=range(WORKERS))
    args = parser.parse_args()
    try:
        if args.worker is not None:
            return run_worker(args.worker, args.output, args.job_clock)
        return run(args.output, args.job_clock)
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        print(f"REFUSE: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
