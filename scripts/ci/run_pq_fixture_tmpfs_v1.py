#!/usr/bin/env python3
"""Run the fixed metadata roster in two owned processes on private tmpfs.

Only scheduling and disposable fixture placement change. Original descriptors,
assertions, source checks and qualification remain unchanged. The first workflow
step supplies one deadline; no faster wall time or lower CPU cost is presumed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import sys
import tempfile
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/ci/run_pq_corpus_partitioned_controls_v3.py"
RUNNER_SHA256 = "7687c5ebe67e23c7c67baab0ba6112473e549501084f44822483407dd196d9cc"
ORIGINAL_NAMED_RUNNER_SHA256 = "be852b050a205c107858d49610993491d989731038d5338cfe75d1ae3cddd0cd"
BASE = Path("/dev/shm")
MIN_FREE_BYTES = 256 * 1024 * 1024
MIN_FREE_INODES = 65536


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_runner_source():
    limit = 1024 * 1024
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    fd = os.open(RUNNER, flags)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size <= limit, "runner source must be a bounded regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        after, named = os.fstat(fd), RUNNER.lstat()
        key = lambda value: (
            value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
        )
        require(len(raw) == before.st_size <= limit
                and key(before) == key(after) == key(named),
                "runner source changed during its original descriptor read")
        require(hashlib.sha256(raw).hexdigest() == RUNNER_SHA256,
                "the reviewed fixed-partition execution owner differs")
        return raw
    finally:
        os.close(fd)


def run_verified_main(raw, argv):
    # Match the direct-file __main__ namespace, using only the verified buffer.
    code = compile(raw, str(RUNNER), "exec", dont_inherit=True)
    module = type(sys)("__main__")
    module.__dict__.update(
        __name__="__main__", __file__=str(RUNNER), __cached__=None,
        __doc__=None, __loader__=None, __package__="", __spec__=None,
    )
    missing = object()
    prior_main = sys.modules.get("__main__", missing)
    prior_argv = sys.argv
    try:
        sys.modules["__main__"] = module
        sys.argv = argv
        exec(code, module.__dict__)
    finally:
        sys.argv = prior_argv
        if prior_main is missing:
            sys.modules.pop("__main__", None)
        else:
            sys.modules["__main__"] = prior_main


def directory_key(value):
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid


def capacity(fd):
    value = os.fstatvfs(fd)
    return {"block_size": value.f_frsize, "total_bytes": value.f_blocks * value.f_frsize,
            "available_bytes": value.f_bavail * value.f_frsize,
            "total_inodes": value.f_files, "available_inodes": value.f_favail}


def mount_observation(fd):
    with open("/proc/self/mountinfo", "rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, "mount observation exceeds its bound")
    device = os.fstat(fd).st_dev
    rows = []
    for line in raw.decode("utf-8").splitlines():
        left, right = line.split(" - ", 1)
        before, after = left.split(), right.split()
        if before[4] == str(BASE) and before[2] == f"{os.major(device)}:{os.minor(device)}":
            require(after[0] == "tmpfs" and "rw" in before[5].split(","),
                    "fixture root is not the existing writable tmpfs mount")
            rows.append({"mount_id": before[0], "device": before[2], "root": before[3],
                         "mount_point": before[4], "mount_options": before[5],
                         "filesystem": after[0], "super_options": after[2], "raw": line})
    require(len(rows) == 1, "fixture tmpfs mount observation is ambiguous or absent")
    return rows[0]


def run(output, receipt, job_clock):
    start, cpu = time.monotonic(), resource.getrusage(resource.RUSAGE_SELF)
    children_cpu = resource.getrusage(resource.RUSAGE_CHILDREN)
    require(output.is_absolute() and receipt.is_absolute() and output.parent == receipt.parent,
            "named and fixture receipts require one explicit absolute output directory")
    require(not receipt.resolve().is_relative_to(ROOT) and output != receipt,
            "fixture receipt must be separate and outside the unchanged checkout")
    require(not receipt.exists(), "fixture scope receipt already exists")
    require(sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true",
            "private tmpfs fixtures are scoped to this explicit Linux CI invocation")
    runner_raw = read_runner_source()
    require(tempfile.tempdir is None, "temporary root was selected before fixture setup")
    prior_tmpdir, prior_argv = os.environ.get("TMPDIR"), sys.argv
    base_fd = owner_fd = None
    base_identity = None
    private = owner_identity = None
    record = {"schema": "trnm-pq-private-tmpfs-fixture-observation-v2", "status": "RUNNING",
              "source_head": os.environ.get("EXPECTED_HEAD"),
              "run_id": os.environ.get("GITHUB_RUN_ID"),
              "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
              "original_named_runner_sha256": ORIGINAL_NAMED_RUNNER_SHA256,
              "partitioned_named_runner_sha256": RUNNER_SHA256,
              "minimum_available_bytes": MIN_FREE_BYTES, "minimum_available_inodes": MIN_FREE_INODES,
              "capacity_is_observed_not_reserved_or_a_private_quota": True,
              "original_roster": {"current": 18, "frozen": 113, "workers": 2,
                                  "serial_per_worker": True, "partition_counts": [66, 65]},
              "additional_fixture_ancestor_components_vs_tmp": 2,
              "all_original_descriptor_ancestor_checks_retained": True,
              "original_job_timeout_seconds": 600, "additional_fixture_test_probes": 0,
              "partitioned_owner_invocations": 0, "original_serial_owner_main_invocations": 0,
              "native_or_campaign_qualification": False, "speed_advantage_qualified": False,
              "cleanup": "NOT_CREATED", "partitioned_returncode": None}
    with receipt.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
    try:
        for path in (Path("/dev"), BASE):
            require(stat.S_ISDIR(path.lstat().st_mode), "tmpfs ancestor must be an actual directory")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        base_fd = os.open(BASE, flags)
        base_identity = os.fstat(base_fd)
        require(directory_key(base_identity) == directory_key(BASE.lstat()), "tmpfs directory changed")
        record["mount_before"] = mount_observation(base_fd)
        record["capacity_before"] = capacity(base_fd)
        require(record["capacity_before"]["available_bytes"] >= MIN_FREE_BYTES
                and record["capacity_before"]["available_inodes"] >= MIN_FREE_INODES,
                "tmpfs has insufficient observed bytes or inodes for two independent fixture processes")
        private = Path(tempfile.mkdtemp(prefix="pq-current-", dir=BASE))
        owner_fd = os.open(private.name, flags, dir_fd=base_fd)
        owner_identity = os.fstat(owner_fd)
        require(directory_key(owner_identity) == directory_key(private.lstat())
                and stat.S_IMODE(owner_identity.st_mode) == 0o700
                and owner_identity.st_uid == os.geteuid()
                and owner_identity.st_dev == base_identity.st_dev,
                "fresh fixture directory is not privately owned on the observed tmpfs")
        record["private_root"] = {"path": str(private), "device": owner_identity.st_dev,
                                  "inode": owner_identity.st_ino, "mode": "0700", "uid": os.geteuid()}
        record["cleanup"] = "PENDING"
        os.environ["TMPDIR"] = str(private)
        require(tempfile.gettempdir() == str(private), "stdlib did not select the explicit fixture root")
        receipt.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        # Each owned worker verifies the complete original registry and runs its
        # fixed subset serially in its main thread. The parent requires all 131.
        runner_argv = [str(RUNNER), "--output", str(output), "--job-clock", str(job_clock)]
        record["partitioned_owner_invocations"] = 1
        receipt.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        try:
            run_verified_main(runner_raw, runner_argv)
        except SystemExit as error:
            record["partitioned_returncode"] = error.code
        require(type(record["partitioned_returncode"]) is int and record["partitioned_returncode"] == 0,
                "partitioned named metadata execution did not exit successfully")
        observed = json.loads(output.read_bytes())
        require(observed["schema"] == "trnm-pq-corpus-current-named-observation-v3"
                and observed["status"] == "PASS_METADATA_ONLY" and observed["required_tests"] == 131
                and observed["worker_count"] == 2 and observed["partition_counts"] == [66, 65]
                and observed["original_named_owner_sha256"] == ORIGINAL_NAMED_RUNNER_SHA256
                and observed["all_named_controls_passed"] is True,
                "the original named receipt does not report the complete unchanged roster")
        record["status"] = "PASS_METADATA_ONLY"
    except BaseException as error:
        record.update(status="FAIL", error=f"{type(error).__name__}: {error}")
        traceback.print_exc(file=sys.stderr)
    finally:
        sys.argv = prior_argv
        try:
            if base_fd is not None:
                record["capacity_after_tests"] = capacity(base_fd)
                record["mount_after"] = mount_observation(base_fd)
                require(record["mount_after"] == record.get("mount_before"),
                        "tmpfs mount changed or its initial observation was incomplete")
        except BaseException as error:
            record.update(status="FAIL", observation_error=f"{type(error).__name__}: {error}")
        try:
            if private is not None:
                require(base_fd is not None and base_identity is not None
                        and directory_key(BASE.lstat()) == directory_key(base_identity)
                        and owner_fd is not None and owner_identity is not None
                        and directory_key(os.fstat(owner_fd)) == directory_key(owner_identity)
                        and directory_key(os.stat(private.name, dir_fd=base_fd, follow_symlinks=False))
                        == directory_key(owner_identity), "fixture directory identity changed before cleanup")
                # Original fixtures own their individual cleanups. Never
                # recursively delete an unexpected remaining test tree here.
                os.rmdir(private.name, dir_fd=base_fd)
                record["cleanup"] = "EMPTY_PRIVATE_ROOT_REMOVED"
        except BaseException as error:
            record.update(status="FAIL", cleanup="UNRESOLVED", cleanup_error=f"{type(error).__name__}: {error}")
        try:
            if base_fd is not None:
                record["capacity_after_cleanup"] = capacity(base_fd)
        except BaseException as error:
            record.update(status="FAIL", final_capacity_error=f"{type(error).__name__}: {error}")
        for fd in (owner_fd, base_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError as error:
                    record.update(status="FAIL", descriptor_close_error=str(error))
        if prior_tmpdir is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = prior_tmpdir
        end_cpu = resource.getrusage(resource.RUSAGE_SELF)
        end_children_cpu = resource.getrusage(resource.RUSAGE_CHILDREN)
        record["fixture_scope_wall_seconds"] = time.monotonic() - start
        record["fixture_scope_process_cpu_seconds"] = (
            end_cpu.ru_utime + end_cpu.ru_stime - cpu.ru_utime - cpu.ru_stime)
        record["fixture_scope_reaped_children_cpu_seconds"] = (
            end_children_cpu.ru_utime + end_children_cpu.ru_stime
            - children_cpu.ru_utime - children_cpu.ru_stime)
        record["fixture_scope_total_accounted_cpu_seconds"] = (
            record["fixture_scope_process_cpu_seconds"]
            + record["fixture_scope_reaped_children_cpu_seconds"])
        record["worker_cpu_is_diagnostic_and_not_added_again"] = True
        record["fixture_scope_max_rss_kib"] = end_cpu.ru_maxrss
        record["full_job_cost_requires_original_checkout_preflight_and_upload_logs"] = True
        receipt.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: record.get(key) for key in
                      ("status", "partitioned_returncode", "cleanup", "fixture_scope_wall_seconds")}, sort_keys=True))
    return 0 if record["status"] == "PASS_METADATA_ONLY" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fixture-receipt", type=Path, required=True)
    parser.add_argument("--job-clock", type=Path, required=True)
    args = parser.parse_args()
    return run(args.output, args.fixture_receipt, args.job_clock)


if __name__ == "__main__":
    raise SystemExit(main())
