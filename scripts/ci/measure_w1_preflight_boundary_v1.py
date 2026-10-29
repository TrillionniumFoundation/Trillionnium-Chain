#!/usr/bin/env python3
"""Bounded offline measurement of E's original Composite grammar preflight.

Every input is synthetic grammar, never a valid proof. No SDK or network runs.
The fixed parser blob is compiled directly with std-only rustc. Each case has
its own process and durable line records; constructed inputs never touch disk.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import signal
import statistics
import subprocess
import time

BASE = "974932be6dcfe830ce1ce92d58cb10e89cb8358d"
PARSER_BLOB = "a35271781ae442c534b456dde3c930ecd034eb86"
PARSER = "trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/host/src/receipt_bounds.rs"
HARNESS = "scripts/ci/w1_preflight_boundary_v1.rs"
CASES = (
    "small_control", "largest_seal_control", "max_segments_cycles_control",
    "near_total_bytes_control", "exact_total_bytes_control",
    "late_last_segment_index", "late_last_segment_hash", "late_last_segment_cycle",
    "late_last_claim_option", "late_outer_assumptions", "late_outer_journal_length",
    "late_truncated_metadata", "late_trailing_byte", "over_total_bytes",
    "over_segment_count", "over_seal_words", "over_seal_length_u64max",
    "short_last_seal",
)
REPEATS = 11
CPU_BATCH_CALLS = 4096
CASE_WALL_SECONDS = 20
CASE_ADDRESS_SPACE_BYTES = 512 * 1024**2
COMPILE_WALL_SECONDS = 45
COMPILE_ADDRESS_SPACE_BYTES = 2 * 1024**3
CAMPAIGN_SECONDS = 90
FILE_CAP = 128 * 1024


def write_new(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def file_identity(path):
    data = path.read_bytes()
    return {
        "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "git_blob": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
    }


def run_owned(command, out, label, timeout, address_space, *, environment=None):
    """Direct wait4 accounting; this is not a whole compiler-family resource claim."""
    started = time.monotonic()
    row = {
        "command": list(map(str, command)), "wall_limit_seconds": timeout,
        "address_space_limit_bytes": address_space, "file_size_limit_bytes": FILE_CAP,
        "timed_out": False, "returncode": None, "cleanup_complete": False,
        "started_utc": datetime.now(timezone.utc).isoformat(),
    }

    def limits():
        resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
        resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_CAP, FILE_CAP))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        cpu = COMPILE_WALL_SECONDS if label == "compile" else CASE_WALL_SECONDS
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))

    child = None
    try:
        # WNOWAIT only reserves the leader if SIGCHLD cannot auto-reap it.
        # Refuse the caller's nondefault disposition; never silently reset it.
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise ValueError("nondefault SIGCHLD would invalidate leader reservation")
        with (out / f"{label}.stdout.jsonl").open("xb") as stdout, \
                (out / f"{label}.stderr.log").open("xb") as stderr:
            child = subprocess.Popen(
                list(map(str, command)), stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, start_new_session=True,
                preexec_fn=limits, env=environment,
            )
            row["leader_pid"] = child.pid
            # Reserve the original leader PID until our last group signal.
            while True:
                status = os.waitid(
                    os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT
                )
                if status is not None:
                    break
                if time.monotonic() - started >= timeout:
                    row["timed_out"] = True
                    break
                time.sleep(0.005)
    except (OSError, ValueError) as error:
        row["owner_error"] = repr(error)
    finally:
        if child is not None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as error:
                row["cleanup_error"] = repr(error)
            cleanup_deadline = time.monotonic() + 2
            while time.monotonic() < cleanup_deadline:
                pid, status, usage = os.wait4(child.pid, os.WNOHANG)
                if pid:
                    child.returncode = os.waitstatus_to_exitcode(status)
                    row.update(
                        returncode=child.returncode,
                        user_cpu_seconds=usage.ru_utime,
                        system_cpu_seconds=usage.ru_stime,
                        max_waited_rss_kib=usage.ru_maxrss,
                        cleanup_complete=True,
                    )
                    break
                time.sleep(0.005)
        row["wall_seconds"] = time.monotonic() - started
        row["success"] = (
            row["returncode"] == 0 and not row["timed_out"]
            and row["cleanup_complete"] and "owner_error" not in row
            and "cleanup_error" not in row
        )
        write_new(out / f"{label}.process.json", row)
    return row


def summarize_case(out, case, process):
    records, parse_error = [], None
    try:
        for line in (out / f"{case}.stdout.jsonl").read_text().splitlines():
            records.append(json.loads(line))
    except (OSError, ValueError) as error:
        parse_error = str(error)
    construction = [r for r in records if r.get("record") == "construction"]
    trials = [r for r in records if r.get("record") == "trial"]
    batches = [r for r in records if r.get("record") == "cpu_batch"]
    empty = [r for r in records if r.get("record") == "empty_loop_reference"]
    allocation_counter_live = (
        len(construction) == 1 and construction[0].get("rust_allocations", 0) >= 1
        and construction[0].get("requested_allocation_bytes", 0)
        >= construction[0].get("input_capacity_bytes", 1)
    )
    batch_passed = (
        len(batches) == 1 and batches[0].get("calls") == CPU_BATCH_CALLS
        and batches[0].get("passed") is True
        and batches[0].get("expected_outcome_matches") is True
        and all(batches[0].get(k) == 0 for k in (
            "rust_allocations", "rust_reallocations", "rust_deallocations",
            "requested_allocation_bytes",
        ))
    )
    empty_passed = (
        len(empty) == 1 and empty[0].get("calls") == CPU_BATCH_CALLS
        and empty[0].get("passed") is True
        and empty[0].get("subtracted_from_parser") is False
        and all(empty[0].get(k) == 0 for k in (
            "rust_allocations", "rust_reallocations", "rust_deallocations",
            "requested_allocation_bytes",
        ))
    )
    passed = (
        process["success"] and parse_error is None and len(construction) == 1
        and allocation_counter_live and batch_passed and empty_passed
        and len(trials) == REPEATS and len(records) == REPEATS + 3
        and all(r.get("case") == case for r in records)
        and [r.get("trial") for r in trials] == list(range(REPEATS))
        and all(r.get("passed") is True and r.get("expected_outcome_matches") is True
                and r.get("zero_parser_allocation") is True
                and all(r.get(k) == 0 for k in (
                    "rust_allocations", "rust_reallocations", "rust_deallocations",
                    "requested_allocation_bytes",
                )) for r in trials)
    )
    row = {
        "case": case, "passed": passed, "parse_error": parse_error,
        "construction": construction[0] if len(construction) == 1 else construction,
        "trial_count": len(trials), "process": process,
        "allocation_counter_positive_control": allocation_counter_live,
        "cpu_batch": batches[0] if len(batches) == 1 else batches,
        "empty_loop_reference": empty[0] if len(empty) == 1 else empty,
        "recorded_classes": sorted({r["class"] for r in trials}),
    }
    for key in ("wall_ns", "process_cpu_ns"):
        values = [r[key] for r in trials]
        row[key] = {
            "samples": values, "min": min(values), "median": statistics.median(values),
            "max": max(values), "first_after_construction": values[0],
        } if values else None
    row["shapes"] = [r["shape"] for r in trials[:1]]
    if len(batches) == 1:
        value = batches[0]["process_cpu_ns"]
        row["amortized_observed_cpu_ns_per_call"] = (
            value / CPU_BATCH_CALLS if value > 0 else None
        )
        row["cpu_zero_means"] = "unresolved short-interval measurement, never zero computation"
    write_new(out / f"{case}.result.json", row)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = args.repository_root.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source_before = file_identity(root / PARSER)
    harness_before = file_identity(root / HARNESS)
    report = {
        "schema": "pon-w1-preflight-boundary-campaign-v1",
        "base_commit_reference": BASE, "actual_parser": source_before,
        "harness_source": harness_before, "runner_source": file_identity(Path(__file__)),
        "parser_expected_git_blob": PARSER_BLOB,
        "synthetic_grammar": True, "preflight_only": True, "sdk_called": False,
        "proof_generated": False, "cryptographic_worst_case_established": False,
        "source_checkout_qualified": False, "network_used": False,
        "platform": platform.platform(), "architecture": platform.machine(),
        "python": platform.python_version(),
        "limits": {
            "case_wall_seconds": CASE_WALL_SECONDS,
            "case_address_space_bytes": CASE_ADDRESS_SPACE_BYTES,
            "compile_wall_seconds": COMPILE_WALL_SECONDS,
            "compile_address_space_bytes": COMPILE_ADDRESS_SPACE_BYTES,
            "command_scheduling_deadline_seconds": CAMPAIGN_SECONDS,
            "cleanup_allowance_seconds": 2,
            "parent_finalization_outside_deadline": True,
            "blocking_kernel_operations_hard_bounded": False,
            "file_size_bytes": FILE_CAP,
        },
        "timing_scope": (
            "Each process constructs its own in-memory input. Construction time and Rust "
            "allocator calls are separate. Eleven black-box preflight calls follow. "
            "Clock/counter overhead is included without subtraction. First sample is after "
            "construction, not a cold-cache guarantee. A fixed4096-call batch also records "
            "CPU with loop/counter overhead; zero deltas are unresolved, not zero cost. "
            "A fixed empty-loop reference is recorded raw and never subtracted. "
            "Per-trial output fsync is outside "
            "parser timing but inside process wall/CPU/RSS. RSS includes construction."
        ),
        "cases": [], "failures": [],
    }
    deadline = time.monotonic() + CAMPAIGN_SECONDS
    try:
        if source_before["git_blob"] != PARSER_BLOB:
            raise ValueError("original E parser blob mismatch")
        rustc = args.rustc.resolve()
        libraries = list((rustc.parent.parent / "lib" / "rustlib").glob(
            platform.machine() + "-unknown-linux-gnu/lib/libstd-*.so"
        ))
        if len(libraries) != 1:
            raise ValueError("one actual compiler-owned dynamic std library required")
        stdlib = libraries[0]
        report["rustc"] = dict(path=str(rustc), **file_identity(rustc))
        report["dynamic_std"] = dict(path=str(stdlib), **file_identity(stdlib))
        report["linkage"] = (
            "Dynamic compiler-owned std plus symbol stripping keeps the ELF inside "
            "the unchanged128KiB file cap. No SDK or non-std Rust dependency."
        )
        child_environment = dict(os.environ)
        child_environment["LD_LIBRARY_PATH"] = str(stdlib.parent)
        binary = out / "w1-preflight-boundary"
        compiled = run_owned(
            [rustc, "--edition=2024", "-C", "opt-level=3", "-C", "prefer-dynamic",
             "-C", "strip=symbols", "-C", "codegen-units=1", "-D", "warnings",
             root / HARNESS, "-o", binary],
            out, "compile", min(COMPILE_WALL_SECONDS, deadline - time.monotonic()),
            COMPILE_ADDRESS_SPACE_BYTES,
        )
        report["compile"] = compiled
        if not compiled["success"]:
            raise ValueError("fixed compile envelope failed; no budget enlargement")
        report["binary"] = file_identity(binary)
        for case in CASES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("fixed campaign deadline reached")
            process = run_owned(
                [binary, case], out, case, min(CASE_WALL_SECONDS, remaining),
                CASE_ADDRESS_SPACE_BYTES, environment=child_environment,
            )
            report["cases"].append(summarize_case(out, case, process))
    except (OSError, ValueError) as error:
        report["failures"].append(str(error))
    finally:
        report["parser_after"] = file_identity(root / PARSER)
        report["harness_after"] = file_identity(root / HARNESS)
        report["source_unchanged"] = (
            report["parser_after"] == source_before
            and report["harness_after"] == harness_before
        )
        if "dynamic_std" in report:
            report["dynamic_std_after"] = dict(
                path=report["dynamic_std"]["path"],
                **file_identity(Path(report["dynamic_std"]["path"])),
            )
            report["source_unchanged"] &= (
                report["dynamic_std_after"] == report["dynamic_std"]
            )
        report["passed"] = (
            not report["failures"] and report["source_unchanged"]
            and len(report["cases"]) == len(CASES)
            and all(r["passed"] for r in report["cases"])
        )
        write_new(out / "report.json", report)
    print(json.dumps({
        "report": str(out / "report.json"), "passed": report["passed"],
        "cases": len(report["cases"]), "failures": report["failures"],
        "proof_generated": False, "cryptographic_worst_case_established": False,
    }))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
