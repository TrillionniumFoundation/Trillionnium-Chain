#!/usr/bin/env python3
"""Eight retained native reorg observations against exact e70f134.

This continuation has its own fixed baseline. It imports the existing V5 sole
wait4 reaper and the original reorg report/comparison readers without changing
that historical campaign's baseline, observer, budgets or result files.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
from ci_observation import digest
from check_cross_arch_cost import ARCHITECTURES, COST_TERMINATION_GRACE_SECONDS, unique
from run_w1_rank_batch_v5 import capture, checked_source, host, write_json

READER = ROOT / "evidence/pon-six-workpackages-20261106/next/service/run_reorg_abba.py"
_spec = importlib.util.spec_from_file_location("retained_reorg_abba_v2", READER)
retained = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(retained)

BASELINE = "e70f13448aad715286fb8eb56fc802b09db643a3"
ORDER = ("baseline", "candidate", "candidate", "baseline") * 2
COMMAND_SECONDS = 300
GRACE_SECONDS = 5
OBSERVER = "trillionnium/crates/trnm-pon-node/examples/native_reorg_query_cost.rs"
STORE = "trillionnium/crates/trnm-pon-node/src/store.rs"
validate_report = retained.validate_report
comparison = retained.comparison
checked_binary = retained.checked_binary
require = retained.require


def git(*args):
    return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=ROOT)


def source_digest(commit, filename):
    return hashlib.sha256(git("show", commit + ":" + filename)).hexdigest()


def binding(kind, binary, receipt_path, expected, machine, output):
    require(kind in ("baseline", "candidate"), "unknown implementation")
    raw = receipt_path.read_bytes()
    with (output / (kind + "-build-receipt.json")).open("xb") as stream:
        stream.write(raw)
    receipt = json.loads(raw, object_pairs_hook=unique)
    require(type(receipt.get("build_exit")) is int and receipt["build_exit"] == 0,
            "successful release build receipt required")
    expected_commit = BASELINE if kind == "baseline" else expected
    require(receipt.get("source_commit") == expected_commit, "build source commit mismatch")
    for field, filename in (("observer_sha256", OBSERVER), ("store_sha256", STORE)):
        require(receipt.get(field) == source_digest(expected_commit, filename),
                "build source differs: " + filename)
    identity = checked_binary(binary, receipt, machine)
    return {"binary": str(binary), "receipt": receipt, "identity": identity,
            "receipt_file": kind + "-build-receipt.json",
            "receipt_sha256": hashlib.sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline", "candidate", "baseline-receipt", "candidate-receipt", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    require(not output.is_relative_to(ROOT.resolve()), "output must be outside source checkout")
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    parent_start = resource.getrusage(resource.RUSAGE_SELF)
    children_start = resource.getrusage(resource.RUSAGE_CHILDREN)
    report = {
        "schema": "native-legacy-reorg-root-abba-v1", "result": "HOLD", "order": ORDER,
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "baseline_commit": BASELINE, "expected_commit": args.expected_commit,
        "execution_context": "local-component-observation",
        "command_timeout_seconds": COMMAND_SECONDS, "termination_grace_seconds": GRACE_SECONDS,
        "maximum_declared_command_budget_seconds": len(ORDER) * (COMMAND_SECONDS + GRACE_SECONDS),
        "no_retry_or_result_selection": True, "attempts": [],
        "reader_sha256": digest(READER), "runner_sha256": digest(Path(__file__)),
        "native_cpu_scope": "wait4-process-all-threads-and-reaped-descendants",
        "native_rss_scope": "Linux-wait4-ru_maxrss-KiB-not-sum-or-global-simultaneous-peak",
        "failed_or_unreaped_descendants_may_be_missing": True,
        "preparation_scope": "both owners, every W1 generation/admission; separately reported within entire native scope",
        "build_cost_scope": "separate exact-source builds and receipts; missing build CPU/RSS is unknown",
        "whole_campaign_scope": "parent wall/CPU and cumulative reaped-child CPU including source checks and native wait4; overlapping scopes must not be added",
        **retained.FALSE_FLAGS,
    }
    write_json(output / "plan.json", report)
    bindings, initialization_error = {}, None
    try:
        require(ORDER == retained.ORDER, "historical comparison denominator changed")
        require(COMMAND_SECONDS == retained.COMMAND_SECONDS == 300, "command budget changed")
        require(GRACE_SECONDS == retained.GRACE_SECONDS == COST_TERMINATION_GRACE_SECONDS == 5,
                "shared capture grace changed")
        specs = [spec for spec in ARCHITECTURES.values() if spec["machine"] == platform.machine()]
        require(platform.system() == "Linux" and len(specs) == 1, "native supported Linux required")
        require(all(hasattr(os, name) for name in ("wait4", "waitid", "WNOWAIT", "killpg")),
                "sole reaper platform")
        report["source_before"] = checked_source(args.expected_commit)
        subprocess.run(["git", "--no-replace-objects", "merge-base", "--is-ancestor", BASELINE,
                        args.expected_commit], cwd=ROOT, check=True)
        report["host"] = host(output)
        for kind in ("baseline", "candidate"):
            bindings[kind] = binding(kind, getattr(args, kind).absolute(),
                                    getattr(args, kind + "_receipt"), args.expected_commit,
                                    specs[0]["elf_machine"], output)
        require(bindings["baseline"]["receipt"]["observer_sha256"] ==
                bindings["candidate"]["receipt"]["observer_sha256"], "same 512-block observer required")
        report["bindings"] = bindings
        write_json(output / "source-bindings.json", {"source": report["source_before"],
                   "bindings": bindings, "host": report["host"]})
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        initialization_error = str(error)
        report["initialization_error"] = initialization_error

    for ordinal, kind in enumerate(ORDER, 1):
        stem = f"attempt-{ordinal:02d}-{kind}"
        item = {"ordinal": ordinal, "implementation": kind, "result": "HOLD",
                "executed": False, "unmeasured_cost_is_zero": False}
        report["attempts"].append(item)
        try:
            require(initialization_error is None, "setup refused: " + str(initialization_error))
            bound = bindings[kind]
            binary = Path(bound["binary"])
            item["source_before"] = checked_source(args.expected_commit)
            item["binary_before"] = checked_binary(binary, bound["receipt"], specs[0]["elf_machine"])
            observed = capture([str(binary)], output, stem, timeout=COMMAND_SECONDS, cwd=ROOT)
            item["observation"] = observed
            item["executed"] = observed["executed"]
            code = observed["process_exit_code"]
            observed["termination_signal"] = -code if isinstance(code, int) and code < 0 else None
            write_json(output / (stem + ".process.json"), observed)
            try:
                item["report"] = json.loads((output / observed["stdout"]).read_bytes(),
                                            object_pairs_hook=unique)
            except (ValueError, UnicodeError) as error:
                item["readback_error"] = str(error)
            item["binary_after"] = checked_binary(binary, bound["receipt"], specs[0]["elf_machine"])
            item["source_after"] = checked_source(args.expected_commit)
            require(item["source_before"] == item["source_after"], "source changed during attempt")
            require(observed["exit_code"] == 0 and observed["process_exit_code"] == 0 and
                    not observed["timed_out"], "native command failed; all costs retained")
            require(isinstance(item.get("report"), dict), "one complete native JSON report required")
            validate_report(item["report"], bound["receipt"])
            item["result"] = "COMPLETE_COMPONENT_OBSERVATION"
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            item["error"] = str(error)
        write_json(output / (stem + ".json"), item)
        print(json.dumps({"attempt": ordinal, "planned": len(ORDER), "implementation": kind,
                          "result": item["result"], "executed": item["executed"]}), flush=True)

    report["comparison"] = comparison(report["attempts"])
    try:
        report["source_after"] = checked_source(args.expected_commit)
        require(report.get("source_before") == report["source_after"], "campaign source changed")
        if report["comparison"]["complete_comparison"]:
            report["result"] = "COMPLETE_COMPONENT_OBSERVATION"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["final_check_error"] = str(error)
        report["comparison"]["complete_comparison"] = False
        report["comparison"].pop("medians", None)
    observations = [item["observation"] for item in report["attempts"] if "observation" in item]
    parent_end = resource.getrusage(resource.RUSAGE_SELF)
    children_end = resource.getrusage(resource.RUSAGE_CHILDREN)
    for prefix, start, end in (("parent", parent_start, parent_end),
                               ("all_reaped_children", children_start, children_end)):
        report[prefix + "_user_ns"] = round((end.ru_utime - start.ru_utime) * 1_000_000_000)
        report[prefix + "_system_ns"] = round((end.ru_stime - start.ru_stime) * 1_000_000_000)
    report["all_reaped_children_cpu_includes_native_wait4"] = True
    report["campaign_elapsed_ns"] = time.monotonic_ns() - started
    report["executed_commands"] = sum(row["executed"] for row in observations)
    report["planned_attempts_without_wait4_usage"] = len(ORDER) - sum(
        row["wait4_cpu_ns"] is not None for row in observations)
    report["observed_wait4_cpu_ns_sum_including_failed_attempts"] = sum(
        row["wait4_cpu_ns"] for row in observations if row["wait4_cpu_ns"] is not None)
    report["artifact_sha256"] = {path.name: digest(path) for path in sorted(output.iterdir())
                                 if path.is_file()}
    write_json(output / "manifest.json", report)
    print(json.dumps({"result": report["result"], "receipt": str(output)}, sort_keys=True))
    return 0 if report["result"] == "COMPLETE_COMPONENT_OBSERVATION" else 1


if __name__ == "__main__":
    sys.exit(main())
