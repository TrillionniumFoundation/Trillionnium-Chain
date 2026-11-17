"""Qualify the complete native Work/Host owner with real files and threads."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import signal
import subprocess
import traceback
from .build import ROOT, Build, identity, need, new_output, source_manifest, write_json
from .bundle import artifacts, include_graph, original_manifest
from .cases import corpus, corpus_bytes, native_options, require_semantics
from .native_io import run_case
from .primitive_qualification import run as primitives
from .faults import run_clock_faults, trace_argv
from .trace_audit import audit_trace
from .trace_controls import run_controls, run_signal_controls

def qualify(output, *, require_trace=True):
    need(__debug__, "Work owner qualification refuses optimized Python")
    output = new_output(output)
    report = {"schema": "trnm.hia.work-owner-qualification.v1", "status": "FAIL",
              "semantic": [], "traces": [], "trace_status": "NOT_REQUESTED",
              "production_fixed_parent_authority": False, "actual_original_Rust": False,
              "whole_Node_or_paid_checkpoint_closed": False, "original_4s_16_service_gate_closed": False}
    before = None; build = None
    try:
        sources = source_manifest(); originals = original_manifest(ROOT)
        before = {"source_inputs": sources, "original_sources": originals,
                  "original_include_graph": include_graph(ROOT),
                  "repository_head": subprocess.check_output(
                      ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True, timeout=20).strip()}
        write_json(output / "source-before.json", before)
        report.update(source_inputs=sources, original_sources=originals)
        build = Build(output / "build")
        report["build"] = build.build()
        cases = corpus()
        (output / "cases.json").write_bytes(corpus_bytes())
        report["corpus"] = identity(output / "cases.json")
        report["primitives"] = primitives(output / "build", cases, output / "primitives")
        semantic = output / "semantic"; semantic.mkdir(mode=0o700)
        image = (output / "build/fixture.elf").read_bytes()
        for case in cases:
            physical = run_case(image, bytes.fromhex(case["request_hex"]), semantic / case["name"],
                                **native_options(case))
            row = {"name": case["name"], "status": "FAIL", "physical": physical}
            report["semantic"].append(row)
            require_semantics(case, physical)
            row["status"] = "PASS"
            print(json.dumps({"case": case["name"], "status": "PASS",
                              "progress": len(case["progress"]), "wall_ns": physical["wall_ns"]}), flush=True)
        report["semantic_count"] = len(cases)
        report["progress_points"] = sum(len(c["progress"]) for c in cases)
        if require_trace:
            trace_root = output / "traces"; trace_root.mkdir(mode=0o700)
            selected = [
                ("baseline", cases[0], image, None, None),
                ("late-cancel", next(c for c in cases if c["name"] == "cancel-at-1098-stage-5"),
                 image, 1, None),
                ("closed-parent", {**cases[0], "domain": 3, "code": 4, "product_hex": None,
                                   "progress": cases[0]["progress"][:1]},
                 (output / "build/closed-fd.elf").read_bytes(), None, "closed-parent-first-progress"),
            ]
            for name, case, executable, expected_signal, fault in selected:
                directory = trace_root / name
                physical = run_case(executable, bytes.fromhex(case["request_hex"]), directory,
                                    trace_argv=trace_argv(directory / "syscalls.raw"),
                                    timeout=30, **native_options(case))
                require_semantics(case, physical)
                audit = audit_trace((directory / "syscalls.raw").read_text(),
                                    (directory / "stdin.raw").read_bytes(),
                                    (directory / "stdout.raw").read_bytes(),
                                    expected_signal=expected_signal, fault_profile=fault)
                write_json(directory / "trace-audit.json", audit)
                report["traces"].append({"name": name, "signal": expected_signal, "fault_profile": fault,
                                         "physical": physical, "audit": audit})
                print(json.dumps({"trace": name, "status": "PASS", "calls": audit["syscalls"]}), flush=True)
            baseline = trace_root / "baseline"
            report["trace_controls"] = run_controls((baseline / "syscalls.raw").read_text(),
                (baseline / "stdin.raw").read_bytes(), (baseline / "stdout.raw").read_bytes(),
                output / "trace-controls")
            cancelled = trace_root / "late-cancel"
            report["signal_controls"] = run_signal_controls((cancelled / "syscalls.raw").read_text(),
                (cancelled / "stdin.raw").read_bytes(), (cancelled / "stdout.raw").read_bytes(),
                output / "signal-controls")
            report["clock_faults"] = run_clock_faults(image, cases[0], output / "clock-faults")
            report["trace_status"] = "PASS"
        build.check_pin()
        report["status"] = "PASS"
    except BaseException as error:
        report.update(failure=repr(error), traceback=traceback.format_exc())
    finally:
        if before is not None:
            try:
                after = {"source_inputs": source_manifest(), "original_sources": original_manifest(ROOT),
                         "original_include_graph": include_graph(ROOT),
                         "repository_head": subprocess.check_output(
                             ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True, timeout=20).strip()}
                write_json(output / "source-after.json", after)
                need(after == before, "Complete native/original source changed during qualification")
                if build is not None: build.check_pin()
                report["source_after"] = "MATCH"
            except BaseException as error:
                report.update(status="FAIL", source_after="FAIL", final_fence_failure=repr(error))
        else:
            report["source_after"] = "ADMISSION_DID_NOT_COMPLETE"
        write_json(output / "artifacts.json", artifacts(output))
        write_json(output / "report.json", report)
    return report

def main():
    need(__debug__, "Work owner qualifier refuses optimized Python")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-trace", action="store_true")
    args = parser.parse_args()
    report = qualify(args.output, require_trace=args.require_trace)
    print(json.dumps({key: report.get(key) for key in
        ("status", "semantic_count", "progress_points", "trace_status", "source_after", "failure")}, sort_keys=True))
    raise SystemExit(0 if report["status"] == "PASS" else 1)

if __name__ == "__main__":
    main()
