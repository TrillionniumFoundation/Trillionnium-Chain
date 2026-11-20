"""Actual owned-process CLOCK_MONOTONIC fault controls at W1 boundaries."""
from __future__ import annotations
from pathlib import Path
import shutil
from .build import need, write_json
from .native_io import run_case
from .trace_audit import audit_trace

BOUNDARIES = (1, 2, 258, 386, 897, 898, 1098, 1099)

def profiles():
    rows = []
    for sequence in BOUNDARIES:
        for stage in ("before-fresh-host", "after-fresh-host"):
            ordinal = 2 * sequence + int(stage == "after-fresh-host")
            rows.append({"name": f"clock-EIO-{ordinal}", "errno": "EIO", "ordinal": ordinal,
                         "progress": sequence, "worker_host_calls": sequence + int(stage == "after-fresh-host"),
                         "boundary": stage})
    rows.append({"name": "clock-EIO-2200", "errno": "EIO", "ordinal": 2200,
                 "progress": 1099, "worker_host_calls": 1101, "boundary": "final-success-deadline"})
    rows.append({"name": "clock-EINVAL-2", "errno": "EINVAL", "ordinal": 2,
                 "progress": 1, "worker_host_calls": 1, "boundary": "before-fresh-host"})
    need(len(rows) == 18 and len({r["name"] for r in rows}) == 18, "Actual clock fault roster differs")
    return rows

def trace_argv(path, *, error=None, ordinal=None):
    tool = shutil.which("strace")
    need(tool is not None, "Actual strace is mandatory for Work owner trace qualification")
    args = [str(Path(tool).resolve(strict=True)), "-f", "-qq", "-v", "-xx", "-s", "65536"]
    if error is not None:
        need(error in ("EIO", "EINVAL") and type(ordinal) is int and 2 <= ordinal <= 2200,
             "Unreviewed private clock-fault profile")
        args += ["-e", "inject=clock_gettime:error=" + error + ":when=" + str(ordinal)]
    return [*args, "-o", str(path)]

def run_clock_faults(image, baseline, output):
    output = Path(output); output.mkdir(mode=0o700)
    rows = []
    report = {"schema": "trnm.hia.work-owner-clock-faults.v1", "status": "FAIL", "rows": rows,
              "original_Rust_fault_comparison": "OPEN",
              "production_fixed_parent_authority": False,
              "ordinary_native_clock_values_supplied_by_caller": False}
    try:
        for profile in profiles():
            directory = output / profile["name"]
            row = run_case(image, bytes.fromhex(baseline["request_hex"]), directory,
                           trace_argv=trace_argv(directory / "syscalls.raw",
                                                 error=profile["errno"], ordinal=profile["ordinal"]),
                           timeout=30)
            need(row["status"] == "PHYSICAL_FRAME_PASS_SEMANTIC_EXPECTATIONS_PENDING",
                 "Actual controlled native execution did not yield its complete terminal frame")
            decoded = row["decoded"]; h = decoded["header"]
            need((h["domain"], h["code"], h["progress_count"], h["worker_host_calls"], h["alive_clocks"]) ==
                 (4, 1, profile["progress"], profile["worker_host_calls"], profile["ordinal"]),
                 "Actual panic/fresh-check order differs")
            need(h["pre_checks"] == 3 and h["post_checks"] == h["aggregate_samples"] == 0
                 and h["joins"] == 1 and decoded["host_after"] == [0] * 32
                 and decoded["product_bytes"] == 0,
                 "Clock panic skipped join or claimed ordinary after-sampling/product authority")
            need(decoded["progress"] == baseline["progress"][:profile["progress"]],
                 "Clock fault moved to another original progress boundary")
            audit = audit_trace((directory / "syscalls.raw").read_text(),
                                (directory / "stdin.raw").read_bytes(),
                                (directory / "stdout.raw").read_bytes(),
                                fault_profile="worker-clock-" + profile["errno"] + "-" + str(profile["ordinal"]))
            write_json(directory / "trace-audit.json", audit)
            rows.append({"name": profile["name"], "status": "PASS", "profile": profile,
                         "physical": row, "trace": audit})
        report.update(status="PASS", count=len(rows))
    except BaseException as error:
        report["failure"] = repr(error)
        raise
    finally:
        write_json(output / "report.json", report)
    return report
