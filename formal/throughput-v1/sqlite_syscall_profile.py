#!/usr/bin/env python3
"""Read a separately captured, hash-bound SQLite WAL syscall diagnostic.

Capture one owned executable with command_for(); keep all return statuses and
exit records. Source receipt bytes are hashed, not treated as a compiler proof.
Only exact caller-selected WAL paths in each call's -yy annotation are counted.
No fd table is reconstructed, and ambiguous unfinished/resumed pairs never join.
The supported format is documented in strace(1):
https://man7.org/linux/man-pages/man1/strace.1.html

This is instrumented syscall evidence, not service throughput, CPU time, device
I/O, power-loss durability, or evidence for either throughput acceptance contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import signal
import sys


SCHEMA = "sqlite-wal-syscall-profile-v1"
CAPTURE_SCHEMA = "sqlite-wal-syscall-capture-v1"
WRITES = ("pwrite64", "pwritev", "pwritev2", "write", "writev")
SYNCS = ("fsync", "fdatasync")
IO_CALLS = WRITES + SYNCS
TRACE_CALLS = ("execve", "execveat") + IO_CALLS
MAX_LINE = 1_048_576
MAX_TIDS = 16_384
PREFIX = re.compile(r"^\s*(\d+)\s+(\d{1,20}\.\d{1,9})\s+(.*)$")
START = re.compile(r"^([a-zA-Z_][a-zA-Z_0-9]*)\((.*)$")
RESUME = re.compile(r"^<\.\.\. ([a-zA-Z_][a-zA-Z_0-9]*) resumed>(.*)$")
END = re.compile(r"^(.*)\)\s+=\s+(.*?)\s*(?:<(\d{1,20}\.\d{1,9})>)?$")
FD = re.compile(r"^\s*\d+<([^<>]+)>(?=\s*[,)]|\s*$)")
EXIT = re.compile(r"^\+\+\+ exited with (\d+) \+\+\+$")
KILLED = re.compile(r"^\+\+\+ killed by (SIG[A-Z0-9]+)(?: \(core dumped\))? \+\+\+$")


def command_for(trace: Path, binary: Path, arguments: list[str]) -> list[str]:
    return [
        "/usr/bin/strace", "-f", "-ttt", "-T", "-yy", "-s", "1", "-e",
        "trace=" + ",".join(TRACE_CALLS), "-o", str(trace), "--", str(binary),
        *arguments,
    ]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def seconds_ns(value: str) -> int:
    whole, fraction = value.split(".")
    return int(whole) * 1_000_000_000 + int(fraction.ljust(9, "0"))


def counters() -> dict:
    return {
        "attempt_starts_observed": 0,
        "terminal_records_observed": 0,
        "successes_observed": 0,
        "failures_observed": 0,
        "unknown_results_observed": 0,
        "returned_write_bytes_known": 0,
        "duration_samples": 0,
        "duration_ns_known_sum": 0,
        "duration_ns_max": None,
        "errors_observed": {},
    }


class TraceReader:
    def __init__(self, wal_paths: list[str], binary: str):
        self.binary = binary
        self.wals = {path: {name: counters() for name in IO_CALLS} for path in wal_paths}
        self.other = {name: counters() for name in IO_CALLS}
        self.unknown = {name: counters() for name in IO_CALLS}
        self.pending: dict[int, tuple[str, str, int, dict | None]] = {}
        self.tainted: set[int] = set()
        self.tids: set[int] = set()
        self.exits: dict[int, dict] = {}
        self.last_time: dict[int, int] = {}
        self.root_tid = None
        self.first_ns = None
        self.last_ns = None
        self.issues: dict[str, int] = {}
        self.issue_examples: list[dict] = []
        self.lines = 0
        self.seen_wals: set[str] = set()
        self.unmatched_resumes = 0

    def issue(self, code: str, tid: int | None = None) -> None:
        self.issues[code] = self.issues.get(code, 0) + 1
        if len(self.issue_examples) < 24:
            self.issue_examples.append({"code": code, "line": self.lines, "tid": tid})

    def bucket(self, name: str, args: str, tid: int) -> dict:
        match = FD.match(args)
        annotation = match[1] if match else None
        if annotation is None or "\\" in annotation or annotation.endswith(" (deleted)"):
            self.issue("fd_path_unresolved", tid)
            return self.unknown[name]
        if annotation in self.wals:
            self.seen_wals.add(annotation)
            return self.wals[annotation][name]
        if annotation.startswith("/") or annotation.startswith(
            ("pipe:[", "socket:[", "TCP", "UDP", "UNIX", "anon_inode:", "eventfd:", "pidfd:")
        ):
            return self.other[name]
        self.issue("fd_annotation_unsupported", tid)
        return self.unknown[name]

    def terminal(self, tid: int, name: str, args: str, bucket: dict | None) -> None:
        match = END.fullmatch(args)
        if match is None:
            self.issue("terminal_syntax_unresolved", tid)
            return
        body, result, duration = match.groups()
        if duration is None:
            self.issue("duration_missing", tid)
        failure = re.fullmatch(r"-1 ([A-Z][A-Z0-9_]+)(?: \(.*\))?", result)
        if name in ("execve", "execveat"):
            if result == "0":
                path = re.match(r'^"([^"\\]+)",', body) if name == "execve" else None
                if path is None or path[1] != self.binary:
                    self.issue("executable_not_bound", tid)
                elif self.root_tid is None:
                    self.root_tid = tid
            elif failure is None:
                # Only an explicit failed exec proves the previous image was
                # retained. A restart/unknown/impossible return cannot inherit it.
                self.issue("executable_result_unresolved", tid)
            return
        assert bucket is not None
        bucket["terminal_records_observed"] += 1
        if duration is not None:
            ns = seconds_ns(duration)
            bucket["duration_samples"] += 1
            bucket["duration_ns_known_sum"] += ns
            bucket["duration_ns_max"] = max(bucket["duration_ns_max"] or 0, ns)
        success = re.fullmatch(r"\d+", result)
        if success and int(result) <= (1 << 63) - 1 and (name in WRITES or result == "0"):
            bucket["successes_observed"] += 1
            if name in WRITES:
                bucket["returned_write_bytes_known"] += int(result)
        elif failure:
            bucket["failures_observed"] += 1
            errors = bucket["errors_observed"]
            errors[failure[1]] = errors.get(failure[1], 0) + 1
        else:
            # Restart markers are not a successful return or an errno result.
            bucket["unknown_results_observed"] += 1
            self.issue("syscall_result_unresolved", tid)

    def line(self, raw: str) -> None:
        self.lines += 1
        if len(raw) > MAX_LINE:
            raise ValueError("trace line exceeds bounded parser input")
        if not raw.endswith("\n"):
            self.issue("trailing_line_incomplete")
        match = PREFIX.fullmatch(raw.rstrip("\n"))
        if match is None:
            self.issue("line_prefix_unresolved")
            self.tainted.update(self.pending)
            return
        tid, stamp, body = int(match[1]), seconds_ns(match[2]), match[3]
        if not 0 < tid < (1 << 31):
            self.issue("invalid_tid")
            self.tainted.update(self.pending)
            return
        self.tids.add(tid)
        if len(self.tids) > MAX_TIDS:
            raise ValueError("trace exceeds bounded TID inventory")
        self.first_ns = stamp if self.first_ns is None else min(self.first_ns, stamp)
        self.last_ns = stamp if self.last_ns is None else max(self.last_ns, stamp)
        if stamp < self.last_time.get(tid, stamp):
            self.issue("tid_timestamp_regressed", tid)
            self.tainted.add(tid)
        self.last_time[tid] = stamp
        if tid in self.exits:
            # Do not carry pending state into a reused numeric TID.
            self.issue("tid_seen_after_exit", tid)
            return
        exited, killed = EXIT.fullmatch(body), KILLED.fullmatch(body)
        if exited or killed:
            self.exits[tid] = {"exit_code": int(exited[1])} if exited else {"signal": killed[1]}
            if tid in self.pending:
                self.issue("exit_with_unfinished_call", tid)
            return
        if body.startswith("--- SIG") and body.endswith(" ---"):
            return
        resumed = RESUME.fullmatch(body)
        if resumed:
            old = self.pending.pop(tid, None)
            if old is None or tid in self.tainted or old[0] != resumed[1] or stamp < old[2]:
                self.unmatched_resumes += 1
                self.issue("resume_without_unique_matching_entry", tid)
                self.tainted.add(tid)
                return
            self.terminal(tid, old[0], old[1] + resumed[2], old[3])
            return
        started = START.fullmatch(body)
        if started is None or started[1] not in TRACE_CALLS:
            self.issue("call_or_event_unsupported", tid)
            self.tainted.add(tid)
            return
        name, args = started.groups()
        if tid in self.pending:
            # Quarantine subsequent resumes: replacing the pending slot could
            # join an old call to a new call with the same name and reused fd.
            self.pending.pop(tid)
            self.tainted.add(tid)
            self.issue("overlapping_entries_same_tid", tid)
        bucket = self.bucket(name, args, tid) if name in IO_CALLS else None
        if bucket is not None:
            bucket["attempt_starts_observed"] += 1
        marker = " <unfinished ...>"
        if args.endswith(marker):
            if tid in self.tainted:
                self.issue("unfinished_entry_on_ambiguous_tid", tid)
            else:
                self.pending[tid] = (name, args[:-len(marker)], stamp, bucket)
        else:
            self.terminal(tid, name, args, bucket)

    def finish(self) -> None:
        if self.lines == 0:
            self.issue("empty_trace")
        if self.root_tid is None:
            self.issue("original_executable_entry_missing")
        for tid in sorted(self.tids - self.exits.keys()):
            self.issue("tid_exit_not_observed", tid)
        for tid in sorted(self.pending):
            self.issue("unfinished_call_at_eof", tid)
        for path in self.wals.keys() - self.seen_wals:
            self.issue("selected_wal_path_not_observed")
        for group in [*self.wals.values(), self.other, self.unknown]:
            for row in group.values():
                row["uncompleted_calls_observed"] = (
                    row["attempt_starts_observed"] - row["terminal_records_observed"]
                )


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate capture receipt key")
        value[key] = item
    return value


def read_profile(trace: Path, binary: Path, source: Path, capture: Path, wal_paths: list[str]) -> dict:
    if not all(path.is_absolute() for path in (trace, binary, source, capture)):
        raise ValueError("artifact paths must be absolute")
    if not wal_paths or len(wal_paths) > 128 or len(set(wal_paths)) != len(wal_paths):
        raise ValueError("one to 128 distinct exact WAL paths required")
    if any(not path.startswith("/") or not path.endswith("-wal") or re.search(r"[\\<>\x00-\x1f]", path)
           for path in wal_paths):
        raise ValueError("WAL paths require unescaped absolute strace path annotations")
    with capture.open("rb") as stream:
        receipt_bytes = stream.read(MAX_LINE + 1)
    if len(receipt_bytes) > MAX_LINE:
        raise ValueError("capture receipt exceeds bounded parser input")
    receipt_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
    receipt = json.loads(receipt_bytes, object_pairs_hook=unique_object)
    if not isinstance(receipt, dict) or receipt.get("schema") != CAPTURE_SCHEMA:
        raise ValueError("capture schema mismatch")
    hashes = {"trace_sha256": sha256_file(trace), "binary_sha256": sha256_file(binary),
              "source_receipt_sha256": sha256_file(source)}
    if any(receipt.get(key) != value for key, value in hashes.items()):
        raise ValueError("capture binary/source/trace hash binding mismatch")
    for key in ("source_commit", "source_tree"):
        if not isinstance(receipt.get(key), str) or not re.fullmatch(r"[0-9a-f]{40}", receipt[key]):
            raise ValueError(f"invalid {key} claim")
    command = receipt.get("command")
    prefix = command_for(trace, binary, [])
    if not isinstance(command, list) or command[:len(prefix)] != prefix or not all(
        isinstance(argument, str) for argument in command
    ):
        raise ValueError("capture command must preserve exact all-status tracing profile")
    start = receipt.get("capture_started_unix_ns")
    end = receipt.get("capture_finished_unix_ns")
    returncode = receipt.get("strace_returncode")
    if type(start) is not int or start <= 0 or (end is not None and type(end) is not int):
        raise ValueError("invalid capture timestamp receipt")
    if returncode is not None and (type(returncode) is not int or not -255 <= returncode <= 255):
        raise ValueError("invalid strace returncode receipt")
    reader = TraceReader(wal_paths, str(binary))
    with trace.open(encoding="utf-8", newline="") as stream:
        while raw := stream.readline(MAX_LINE + 1):
            reader.line(raw)
    reader.finish()
    if end is None or end < start or returncode is None:
        reader.issue("capture_completion_unknown")
    elif reader.first_ns is not None and (
        reader.first_ns + 1_000_000 < start or reader.last_ns > end + 1_000_000
    ):
        reader.issue("trace_outside_capture_window")
    root_exit = reader.exits.get(reader.root_tid)
    if root_exit is not None and returncode is not None:
        expected = [root_exit["exit_code"]] if "exit_code" in root_exit else [
            -int(getattr(signal, root_exit["signal"], 0)),
            128 + int(getattr(signal, root_exit["signal"], 0)),
        ]
        if returncode not in expected:
            reader.issue("root_exit_disagrees_with_capture")
    # A live trace or artifact replacement cannot inherit the earlier binding.
    if any(sha256_file(path) != hashes[key] for key, path in (
        ("trace_sha256", trace), ("binary_sha256", binary), ("source_receipt_sha256", source)
    )):
        raise ValueError("capture artifact changed while reading")
    if sha256_file(capture) != receipt_sha256:
        raise ValueError("capture receipt changed while reading")
    complete = not reader.issues
    return {
        "schema": SCHEMA,
        "status": "complete" if complete else "partial",
        "status_scope": "closure of this selected syscall diagnostic; never service acceptance",
        "binding": {**hashes, "capture_receipt_sha256": receipt_sha256,
                    "source_commit_claim": receipt["source_commit"], "source_tree_claim": receipt["source_tree"],
                    "source_binding_scope": "supplied source receipt bytes; not independent recompilation proof"},
        "capture": {"command": command, "strace_returncode": returncode, "root_tid": reader.root_tid,
                    "root_termination": root_exit, "trace_first_unix_ns": reader.first_ns,
                    "trace_last_unix_ns": reader.last_ns, "tids_observed": sorted(reader.tids),
                    "terminations_observed": reader.exits, "lines": reader.lines},
        "observed": {"wal_by_exact_path": reader.wals, "other_annotated_fds": reader.other,
                     "unattributed_fds": reader.unknown, "unmatched_resumes": reader.unmatched_resumes},
        "complete_selected_wal_totals": reader.wals if complete else None,
        "issues": {"counts": reader.issues, "examples": reader.issue_examples},
        "limits": {"path_scope": "path annotations, not inode identities or fd lifetimes",
                   "duration_scope": "strace instrumented syscall elapsed; sums may overlap and are not CPU time",
                   "bytes_scope": "successful write-family return values, not device or network bytes",
                   "failed_and_unknown_calls_retained": True, "physical_durability_proven": False,
                   "original_4s_contract_accepted": False, "campaign_30s_contract_accepted": False},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("trace", "binary", "source", "capture"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--wal", action="append", required=True, help="exact absolute annotated WAL path")
    args = parser.parse_args()
    try:
        report = read_profile(args.trace, args.binary, args.source, args.capture, args.wal)
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        print(f"sqlite syscall profile refused: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
