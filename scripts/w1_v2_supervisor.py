#!/usr/bin/env python3
"""Finite, Linux-only research owner for the saved W1 V2 verifier.

This is not a Node ingress, a consensus-invalid cache, or the Node's shared CPU
owner. All callers of ONE instance share its finite campaign budget. It reuses
bounded_process's process-group owner; no native replay or retry is possible.
The executable is a trusted, explicitly hash-pinned local input, not a sandboxed
user program. Same-session descendants are killed; escaped sessions and kernel
uninterruptible waits retain bounded_process's documented limitations.
"""
from __future__ import annotations

import argparse
from collections import OrderedDict
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import shutil
import signal
import stat
import struct
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "formal/pon-nakamoto-v1"))
from bounded_process import ProcessFailure, run_bounded

PROFILE = "trnm-w1-risc0-3.0.6-poseidon2-join-v2"
IMAGE = [1958252411, 3287394615, 1805488136, 1516578702,
         78549041, 790278610, 301018785, 4279049364]
MAX_RECEIPT = 16 * 1024 * 1024
HEADER_BYTES, ARTIFACT_BYTES = 318, 64
INPUT_RESERVATION = MAX_RECEIPT + HEADER_BYTES + ARTIFACT_BYTES
REJECTIONS = {20: "W1_V2_WIRE_REJECT", 21: "W1_V2_PUBLIC_REJECT", 22: "W1_V2_CRYPTO_REJECT"}
CACHE_DOMAIN = b"TRNM-W1-V2-RESEARCH-EXACT-REJECTION1\0"
STREAM_LIMIT = 64 * 1024

# Python is launched in isolated, no-site mode. Limits are installed in that
# fresh single-threaded child, never with thread-unsafe Popen(preexec_fn=...).
# execve(fd) preserves the actual pinned executable inode across path rename.
# Its hash is checked again under the worker's limits; no shell is invoked.
RESOURCE_EXEC = r'''
import hashlib, os, resource, sys
try:
    fd, soft_cpu, hard_cpu, memory = map(int, sys.argv[1:5])
    for key, value in ((resource.RLIMIT_CORE, (0, 0)),
                       (resource.RLIMIT_AS, (memory, memory)),
                       (resource.RLIMIT_CPU, (soft_cpu, hard_cpu)),
                       (resource.RLIMIT_NOFILE, (64, 64)),
                       (resource.RLIMIT_FSIZE, (65536, 65536))):
        resource.setrlimit(key, value)
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, 65536, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    if digest.hexdigest() != sys.argv[5]:
        raise ValueError("pinned executable changed")
    os.execve(fd, sys.argv[6:], {"LANG": "C", "LC_ALL": "C", "RAYON_NUM_THREADS": "1"})
except BaseException as error:
    os.write(2, ("W1_V2_WORKER_UNAVAILABLE: " + type(error).__name__ + "\n").encode())
    os._exit(78)
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def is_hash(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def strict_json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate verifier JSON key")
            value[key] = item
        return value

    def reject(value):
        raise ValueError("nonfinite verifier JSON: " + value)

    return json.loads(data, object_pairs_hook=pairs, parse_constant=reject)


@dataclass(frozen=True)
class Limits:
    workers: int = 2
    unverified_bytes: int = 2 * INPUT_RESERVATION
    soft_cpu_seconds: int = 1
    hard_cpu_seconds: int = 2
    campaign_cpu_ns: int = 8_000_000_000
    worker_address_space_bytes: int = 256 * 1024 * 1024
    wall_seconds: float = 3.0
    cache_entries: int = 128
    cache_ttl_seconds: float = 30.0

    def __post_init__(self):
        for key in ("workers", "unverified_bytes", "soft_cpu_seconds", "hard_cpu_seconds",
                    "campaign_cpu_ns", "worker_address_space_bytes", "cache_entries"):
            require(type(getattr(self, key)) is int, "integer limit required: " + key)
        require(1 <= self.workers <= 8, "worker bound")
        require(1 <= self.unverified_bytes <= 8 * INPUT_RESERVATION, "unverified byte bound")
        require(1 <= self.soft_cpu_seconds < self.hard_cpu_seconds <= 30, "CPU limits")
        require(0 < self.campaign_cpu_ns <= 256_000_000_000, "finite campaign CPU")
        require(64 * 1024 * 1024 <= self.worker_address_space_bytes <= 1024 * 1024 * 1024,
                "worker address space bound")
        require(0 <= self.cache_entries <= 4096, "cache capacity")
        for value in (self.wall_seconds, self.cache_ttl_seconds):
            require(type(value) in (int, float) and math.isfinite(value) and 0 < value <= 60,
                    "finite time bound")


class InputLength(ValueError):
    """An on-open size refusal; only receipt inputs imply statement Invalid."""


class DeadlineReached(ValueError):
    pass


def check_deadline(deadline):
    if time.monotonic() >= deadline:
        raise DeadlineReached("original deadline exhausted")


def wire_precheck(path, size):
    """Same necessary 12-byte Succinct framing checks as Rust wire::decode.

    This is not receipt decoding or proof verification. The input is the
    owner's private regular-file snapshot, already bounded and hashed.
    """
    with open(path, "rb") as stream:
        prefix = stream.read(12)
    if len(prefix) != 12 or prefix[:4] != (1).to_bytes(4, "little"):
        return "wire preflight: bounded Succinct tag/length required"
    count = int.from_bytes(prefix[4:12], "little")
    if count == 0 or 12 + 4 * count > size:
        return "wire preflight: impossible seal length"
    return None


def snapshot(path, destination, bound, exact, deadline):
    """Read only a same-fd regular file; copy in bounded chunks into private storage.

    No path.resolve()/is_file() race and no blocking FIFO open. This still
    assumes responsive local storage; O_NONBLOCK does not make regular-file
    kernel I/O hard real-time. A late observation never becomes Verified/Invalid.
    """
    check_deadline(deadline)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), "regular input file required")
        if before.st_size > bound or (exact is not None and before.st_size != exact):
            raise InputLength("input length outside frozen format")
        digest, total = hashlib.sha256(), 0
        with open(destination, "xb") as out:
            while True:
                check_deadline(deadline)
                data = os.read(fd, min(65536, bound - total + 1))
                if not data:
                    break
                total += len(data)
                # The initial same-fd size was within bound. Crossing it
                # now means the local source changed during this snapshot;
                # it is not a stable statement that can be judged Invalid.
                require(total <= bound, "input changed beyond length bound during snapshot")
                out.write(data)
                digest.update(data)
        after = os.fstat(fd)
        require(total == before.st_size == after.st_size
                and before.st_mtime_ns == after.st_mtime_ns
                and before.st_ctime_ns == after.st_ctime_ns,
                "input changed during snapshot")
        check_deadline(deadline)
        return {"bytes": total, "sha256": digest.hexdigest()}
    finally:
        os.close(fd)


class VerifierOwner:
    """One finite owner; caller labels/identities never select separate budgets.

    Construct once and share it. Recreating this object/process is NOT a durable
    CPU ledger, and this research API is not wired into the Node's scalar_cpu.
    No automatic retry, batch splitting, native replay or positive cache exists.
    """
    def __init__(self, verifier, expected_sha256, limits=Limits()):
        require(sys.platform == "linux" and os.execve in os.supports_fd,
                "Linux descriptor-exec resource worker required")
        require(is_hash(expected_sha256), "explicit verifier SHA-256 required")
        require(type(limits) is Limits, "validated finite Limits required")
        self.limits, self.verifier = limits, os.path.abspath(verifier)
        self.verifier_sha256 = expected_sha256
        fd = os.open(self.verifier, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 128 * 1024 * 1024,
                    "bounded regular verifier executable required")
            digest = hashlib.sha256()
            for offset in range(0, info.st_size, 65536):
                digest.update(os.pread(fd, min(65536, info.st_size - offset), offset))
            require(digest.hexdigest() == expected_sha256, "verifier executable SHA-256 mismatch")
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd
        self._lock = threading.Lock()
        self._active, self._bytes, self._reserved = 0, 0, 0
        self._credit = limits.campaign_cpu_ns
        self._worker_cpu, self._owner_cpu, self._started = 0, 0, 0
        self._unknown = False
        self._cache = OrderedDict()

    def close(self):
        with self._lock:
            require(self._active == 0, "cannot close owner with unsettled workers")
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def stats(self):
        with self._lock:
            return {"active_workers": self._active, "reserved_unverified_bytes": self._bytes,
                    "reserved_cpu_ns": self._reserved, "available_cpu_ns": self._credit,
                    "settled_worker_cpu_ns": self._worker_cpu, "settled_owner_thread_cpu_ns": self._owner_cpu,
                    "workers_started": self._started, "negative_cache_entries": len(self._cache),
                    "blocked_on_unknown_worker": self._unknown}

    def _admit(self):
        reserve = self.limits.hard_cpu_seconds * 1_000_000_000
        with self._lock:
            if self._fd is None or self._unknown:
                return "OperationalFailure", "owner unavailable or prior worker unsettled"
            if (self._active >= self.limits.workers
                    or self._bytes + INPUT_RESERVATION > self.limits.unverified_bytes
                    or self._credit < reserve):
                return "Busy", "shared worker, byte or CPU reservation exhausted"
            self._active += 1
            self._bytes += INPUT_RESERVATION
            self._credit -= reserve
            self._reserved += reserve
        return None

    def _settle(self, worker_cpu, owner_cpu, *, admitted, settled):
        with self._lock:
            self._owner_cpu += owner_cpu
            self._credit -= owner_cpu
            if admitted and settled:
                reserve = self.limits.hard_cpu_seconds * 1_000_000_000
                self._active -= 1
                self._bytes -= INPUT_RESERVATION
                self._reserved -= reserve
                self._credit += reserve - worker_cpu
                self._worker_cpu += worker_cpu
            elif admitted:
                # Unknown execution keeps its full reservation and stops new
                # work. Absence of wait4 evidence is never a zero-cost refund.
                self._unknown = True

    def _cached(self, key):
        now = time.monotonic()
        with self._lock:
            for stale in [key for key, (end, _) in self._cache.items() if end <= now]:
                del self._cache[stale]
            found = self._cache.get(key)
            if found:
                self._cache.move_to_end(key)
                return found[1]
        return None

    def _cache_invalid(self, key, code):
        if not self.limits.cache_entries:
            return
        with self._lock:
            self._cache[key] = (time.monotonic() + self.limits.cache_ttl_seconds, code)
            self._cache.move_to_end(key)
            while len(self._cache) > self.limits.cache_entries:
                self._cache.popitem(last=False)

    def verify(self, receipt, header, expected_artifacts, *, deadline, caller_class="public"):
        require(caller_class in ("public", "history", "recovery", "relay"), "unknown diagnostic caller label")
        require(type(deadline) in (int, float) and math.isfinite(deadline), "finite absolute deadline required")
        started, cpu_started = time.monotonic(), time.thread_time_ns()
        effective_deadline = min(deadline, started + self.limits.wall_seconds)
        row = {"schema": "TRNM-W1-V2-SUPERVISED1", "profile_id": PROFILE,
               "caller_class": caller_class, "status": "OperationalFailure", "reason": None,
               "cache_hit": False, "worker_started": False, "worker_reaped": False,
               "worker_cpu_ns": 0, "owner_thread_cpu_ns": 0, "worker_usage": None,
               "worker_settlement": "not_started", "wire_precheck_rejected": False,
               "verifier_sha256": self.verifier_sha256, "proof_context_sha256": None,
               "returncode": None, "stdout": "", "stderr": "", "assets": None,
               "node_cpu_owner_integrated": False, "parent_eligibility_checked": False,
               "admission_authorized": False, "consensus_validity": None,
               "new_proofs_generated": 0, "native_replay_calls": 0}
        admitted, settled, directory, result, key = False, True, None, None, None
        cache_code = None
        try:
            check_deadline(effective_deadline)
            refusal = self._admit()
            if refusal:
                row["status"], row["reason"] = refusal
            else:
                admitted = True
                directory = tempfile.mkdtemp(prefix="trnm-w1-v2-supervisor-")
                paths, assets = {}, {}
                for label, path, bound, exact in (
                        ("header", header, HEADER_BYTES, HEADER_BYTES),
                        ("artifacts", expected_artifacts, ARTIFACT_BYTES, ARTIFACT_BYTES),
                        ("receipt", receipt, MAX_RECEIPT, None)):
                    paths[label] = str(Path(directory) / (label + ".bin"))
                    try:
                        assets[label] = snapshot(path, paths[label], bound, exact, effective_deadline)
                    except InputLength as error:
                        if label == "receipt":
                            raise
                        # Header and expected commitments are caller-supplied
                        # checked local context. A truncated/misconfigured
                        # context file does not reject the remote statement.
                        raise ValueError("local " + label + " input: " + str(error)) from error
                row["assets"] = assets
                digest = hashlib.sha256(CACHE_DOMAIN + PROFILE.encode() + bytes.fromhex(self.verifier_sha256))
                for label in ("header", "artifacts", "receipt"):
                    digest.update(struct.pack("<Q", assets[label]["bytes"]))
                    digest.update(bytes.fromhex(assets[label]["sha256"]))
                key = row["proof_context_sha256"] = digest.hexdigest()
                cached = self._cached(key)
                if cached is not None:
                    row.update(status="Invalid", reason=REJECTIONS[cached], cache_hit=True)
                elif (wire_error := wire_precheck(paths["receipt"], assets["receipt"]["bytes"])):
                    row.update(status="Invalid", reason=wire_error, wire_precheck_rejected=True)
                    cache_code = 20
                else:
                    check_deadline(effective_deadline)
                    argv = [sys.executable, "-I", "-S", "-c", RESOURCE_EXEC, str(self._fd),
                            str(self.limits.soft_cpu_seconds), str(self.limits.hard_cpu_seconds),
                            str(self.limits.worker_address_space_bytes), self.verifier_sha256,
                            self.verifier, paths["receipt"], paths["header"], paths["artifacts"]]
                    remaining = effective_deadline - time.monotonic()
                    if remaining <= 0:
                        raise DeadlineReached("original deadline exhausted before worker admission")
                    # From entry until a wait4 receipt or known pre-spawn error,
                    # cleanup cannot be assumed. Never release an unknown owner.
                    settled = False
                    row.update(worker_started=None, worker_cpu_ns=None, worker_settlement="unknown")
                    try:
                        result = run_bounded(argv, b"", timeout=remaining, absolute_deadline=effective_deadline,
                            stdout_limit=STREAM_LIMIT, stderr_limit=STREAM_LIMIT, cwd=directory,
                            env={"LANG": "C", "LC_ALL": "C"}, pass_fds=(self._fd,), collect_usage=True)
                    except ProcessFailure as error:
                        result = error
                        row["status"] = "Deadline" if str(error) == "NATIVE_EXECUTOR_TIMEOUT" else "OperationalFailure"
                        row["reason"] = str(error)
                    except ValueError as error:
                        if str(error) in ("NATIVE_EXECUTOR_UNAVAILABLE", "NATIVE_PROCESS_ARGUMENT", "NATIVE_PROCESS_PLATFORM",
                                          "NATIVE_EXECUTOR_DEADLINE_BEFORE_SPAWN"):
                            settled = True  # Explicit no-child paths in the shared owner.
                            row.update(worker_started=False, worker_cpu_ns=0, worker_settlement="not_started")
                        if str(error) == "NATIVE_EXECUTOR_DEADLINE_BEFORE_SPAWN":
                            raise DeadlineReached(str(error)) from error
                        raise
                    if result is not None and result.usage is not None:
                        settled = True
                        row["worker_started"] = row["worker_reaped"] = True
                        row["worker_settlement"] = "reaped"
                        row["worker_usage"] = asdict(result.usage)
                        row["worker_cpu_ns"] = math.ceil(
                            (result.usage.user_seconds + result.usage.system_seconds) * 1_000_000_000)
                        with self._lock:
                            self._started += 1
                        row.update(returncode=result.returncode,
                                   stdout=result.stdout.decode("utf-8", errors="replace"),
                                   stderr=result.stderr.decode("utf-8", errors="replace"))
                        if not isinstance(result, ProcessFailure):
                            if result.returncode == 0:
                                report = strict_json(result.stdout)
                                validate_success(report, assets)
                                require(not result.stderr, "successful verifier emitted diagnostics")
                                row.update(status="VerifiedResearchStatement", reason="complete pinned V2 verification", report=report)
                            elif result.returncode in REJECTIONS and result.stdout == b"" and result.stderr.startswith(
                                    ("Error: " + REJECTIONS[result.returncode] + "\n").encode()):
                                row.update(status="Invalid", reason=REJECTIONS[result.returncode])
                                cache_code = result.returncode
                            elif result.returncode == -signal.SIGXCPU:
                                row.update(status="Deadline", reason="worker CPU soft limit")
                            else:
                                row.update(status="OperationalFailure", reason="worker signal or untyped refusal")
                    else:
                        row.update(status="OperationalFailure", reason="worker settlement unavailable")
        except InputLength as error:
            row.update(status="Invalid", reason=str(error))
        except DeadlineReached as error:
            row.update(status="Deadline", reason=str(error))
        except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError) as error:
            row.update(status="OperationalFailure", reason=type(error).__name__ + ": " + str(error))
        finally:
            if directory and settled:
                try:
                    shutil.rmtree(directory)
                except OSError as error:
                    row.update(status="OperationalFailure", reason="snapshot cleanup: " + str(error),
                               retained_snapshot_directory=directory)
            elif directory:
                row["retained_snapshot_directory"] = directory
            if time.monotonic() >= effective_deadline and row["status"] != "OperationalFailure":
                row.update(status="Deadline", reason="completion/cleanup not observed before original deadline")
            if row["status"] == "Invalid" and cache_code is not None and settled:
                self._cache_invalid(key, cache_code)
            row["owner_thread_cpu_ns"] = max(0, time.thread_time_ns() - cpu_started)
            self._settle(row["worker_cpu_ns"], row["owner_thread_cpu_ns"], admitted=admitted, settled=settled)
            row["wall_seconds"] = time.monotonic() - started
            row["owner_after"] = self.stats()
        return row

    def verify_batch(self, requests, *, deadline):
        preparation_cpu = time.thread_time_ns()
        try:
            require(type(requests) in (tuple, list) and 1 <= len(requests) <= 64, "bounded explicit batch required")
            require(all(type(request) in (tuple, list) and len(request) == 3 for request in requests),
                    "every batch request must be receipt, header, expected artifacts")
            # Freeze all shapes BEFORE the first side effect. A malformed later
            # item must not discard already executed/charged earlier results.
            prepared = tuple(tuple(request) for request in requests)
        finally:
            self._settle(0, max(0, time.thread_time_ns() - preparation_cpu), admitted=False, settled=True)
        # No optimistic aggregate claim or free binary-search retry. Every
        # attempted leaf goes through the same owner and ORIGINAL deadline.
        return [self.verify(*request, deadline=deadline) for request in prepared]


def validate_success(report, assets):
    require(type(report) is dict, "verifier report object required")
    require(report.get("schema") == "TRNM-W1-V2-FULL-VERIFY1" and report.get("profile_id") == PROFILE,
            "unexpected verifier report/profile")
    require(report.get("sdk") == "3.0.6" and report.get("image_id") == IMAGE, "unexpected SDK/image")
    require(type(report.get("iterations")) is int and report["iterations"] == 1, "single verification required")
    require(report.get("parent_eligibility_checked") is False and report.get("admission_authorized") is False,
            "research verifier cannot assert Node authority")
    require(report.get("receipt_bytes") == assets["receipt"]["bytes"]
            and report.get("receipt_sha256") == assets["receipt"]["sha256"]
            and report.get("header_sha256") == assets["header"]["sha256"]
            and report.get("expected_artifacts_sha256") == assets["artifacts"]["sha256"],
            "verifier report differs from actual private input snapshot")
    require(is_hash(report.get("work_id")) and is_hash(report.get("journal_sha256")), "complete verifier identity required")
    samples = report.get("decode_and_verify_ns")
    require(type(samples) is list and len(samples) == 1 and type(samples[0]) is int and samples[0] >= 0,
            "one actual decode/verify duration required")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("verifier", "verifier-sha256", "receipt", "header", "expected-artifacts", "out"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--wall-seconds", type=float, default=3.0)
    args = parser.parse_args(argv)
    limits = Limits(wall_seconds=args.wall_seconds)
    out = Path(args.out)
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    owner = VerifierOwner(args.verifier, args.verifier_sha256, limits)
    row = owner.verify(args.receipt, args.header, args.expected_artifacts,
                       deadline=time.monotonic() + limits.wall_seconds)
    row["limits"] = asdict(limits)
    row["resource_scope"] = "one finite owner; wait4 child + owner thread CPU; RLIMIT_AS per trusted worker; not a Node/cgroup/WAN bound"
    row["worker_launcher_sha256"] = sha(RESOURCE_EXEC.encode())
    for key in ("stdout", "stderr"):
        (out / (key + ".log")).write_text(row.pop(key), encoding="utf-8")
    row["owner_close"] = {"state": "pending"}
    # A close refusal for unknown execution must not erase its result/ledger.
    # First persist the observed outcome; then append close state atomically.
    with (out / "result.json").open("x", encoding="utf-8") as stream:
        json.dump(row, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    try:
        owner.close()
        row["owner_close"] = {"state": "closed"}
    except (OSError, ValueError) as failure:
        row["owner_close"] = {"state": "failed", "error": type(failure).__name__ + ": " + str(failure),
                              "owner_after": owner.stats()}
    with (out / "result-close.json").open("x", encoding="utf-8") as stream:
        json.dump(row, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(out / "result-close.json", out / "result.json")
    print(json.dumps({"status": row["status"], "reason": row["reason"], "out": str(out)}))
    return 0 if row["status"] == "VerifiedResearchStatement" and row["owner_close"]["state"] == "closed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
