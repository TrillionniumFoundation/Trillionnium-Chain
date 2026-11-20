"""Execute and independently reread actual original CLOCK faults on owned children."""
from __future__ import annotations
from pathlib import Path
import json
import traceback
from .build import identity, need, write_json
from .cases import corpus, original_cases
from .faults import profiles
from .clock_trace import run as trace_original
from .clock_evidence import audit, TEST
from .primitive_evidence import same

def original_input():
    """Use the exact original observer projection, never its native envelope."""
    baseline = corpus()[0]
    actual = original_cases()[0]
    expected = {"name": baseline["name"], "request_hex": baseline["request_hex"],
                "gate_stage": 0, "gate_sequence": 0, "actions": [], "signal": 0, "delay_ms": 0}
    need(same(baseline["options"], {}) and same(actual, expected),
         "Controlled original CLOCK requires the exact ordinary original-input projection")
    return baseline, actual

def run(binary, executable, output, native, *, check):
    """The caller has admitted the complete current native bundle and compiled source."""
    need(__debug__, "Original controlled CLOCK comparison refuses optimized Python")
    output = Path(output)
    need(output.is_absolute() and output.resolve() == output and not output.exists(),
         "Fresh original CLOCK comparison output required")
    output.mkdir(mode=0o700)
    baseline, actual_input = original_input()
    input_path = output / "baseline.jsonl"
    input_path.write_bytes((json.dumps(actual_input, sort_keys=True, separators=(",", ":")) + "\n").encode())
    saved_input = identity(input_path)
    argv = [str(binary), "--exact", TEST, "--nocapture", "--test-threads=1"]
    environment = {"PATH": "/usr/bin:/bin", "TRNM_HIA_WORK_OWNER_CORPUS": str(input_path)}
    native_rows = native["report"]["clock_faults"]["rows"]
    need([row["profile"] for row in native_rows] == profiles(), "Original CLOCK comparison lacks native fault roster")
    report = {"schema": "trnm.hia.work-owner-original-clock-comparison.v1", "status": "FAIL",
        "input": saved_input, "executable": executable, "argv": argv, "environment": environment,
        "rows": [], "positive_count": 0, "fault_count": 0,
        "source_inputs": native["source_inputs"], "original_sources": native["original_sources"],
        "original_deadline_seconds": 4, "normal_vdso_fault_behavior_claimed": False,
        "production_fixed_parent_authority": False, "whole_Node_or_paid_checkpoint_closed": False,
        "original_4s_16_service_gate_closed": False}
    def fence():
        check()
        need(identity(binary) == executable and identity(input_path) == saved_input,
             "Original CLOCK binary/input changed")
    try:
        fence()
        work = [("normal-vdso-positive", False, None), ("private-raw-positive", True, None)]
        work += [(row["name"], True, row) for row in profiles()]
        for label, disable_vdso, profile in work:
            directory = output / label
            fault = None if profile is None else {
                "clock_roles": [3], "clock_when": profile["ordinal"],
                "clock_error": 5 if profile["errno"] == "EIO" else 22}
            actual = trace_original(argv, directory, disable_vdso=disable_vdso,
                                    env=environment, fault=fault, timeout=45)
            observed = audit(directory, argv=argv, environment=environment, executable=executable,
                             baseline=baseline, profile=profile, disable_vdso=disable_vdso)
            write_json(directory / "audit.json", observed)
            row = {"name": label, "status": "PASS", "audit": observed,
                   "trace_report": identity(directory / "report.json"),
                   "actual_seconds": actual["duration_seconds"]}
            if profile is None:
                report["positive_count"] += 1
            else:
                original = observed["observation"]
                selected = next(value for value in native_rows if value["name"] == label)
                frame = selected["physical"]["decoded"]; header = frame["header"]
                expected = (4, 1, profile["progress"], profile["worker_host_calls"], profile["ordinal"], 3, 0, 0, 1)
                fields = ("domain", "code", "progress_count", "worker_host_calls", "alive_clocks",
                          "pre_checks", "post_checks", "aggregate_samples", "joins")
                need(same([header[key] for key in fields], list(expected)),
                     "Native controlled panic-class frame differs")
                need(same(frame["progress"], original["progress"]) and frame["product_bytes"] == 0
                     and same(frame["host_after"], [0] * 32)
                     and original["worker_panicked"] is True and original["joined"] is True
                     and original["after_sample_attempts"] == 0 and original["product_hex"] is None,
                     "Actual original CLOCK unwind/join/progress differs from native")
                row["actual_native_frame"] = frame
                row["comparison_scope"] = "actual panic class, retained progress, fresh Host order, real join and absent after-sampling/product"
                row["original_panic_relabelled_as_returned_error"] = False
                report["fault_count"] += 1
            report["rows"].append(row)
            print(json.dumps({"original_clock": label, "status": "PASS",
                              "progress": len(observed["observation"]["progress"]),
                              "counter_files": observed["actual_counter_files"],
                              "clock_syscalls": observed["actual_worker_CLOCK1_syscalls"]}, sort_keys=True), flush=True)
        need(report["positive_count"] == 2 and report["fault_count"] == 18 and len(report["rows"]) == 20,
             "Actual original CLOCK run roster incomplete")
        from .test_clock_evidence import actual_controls
        report["actual_raw_reader_controls"] = actual_controls(output, report, output / "actual-reader-controls")
        fence(); report["status"] = "PASS"
    except BaseException as error:
        report.update(failure=repr(error), traceback=traceback.format_exc())
    finally:
        try:
            fence(); report["source_after"] = "MATCH"; report["binary_after"] = "MATCH"
        except BaseException as error:
            report.update(status="FAIL", source_after="FAIL", final_fence_failure=repr(error))
        write_json(output / "report.json", report)
    need(report["status"] == "PASS", "Actual original controlled CLOCK comparison failed: " + str(report.get("failure")))
    return report
