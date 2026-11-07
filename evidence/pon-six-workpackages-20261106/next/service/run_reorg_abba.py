#!/usr/bin/env python3
"""Fixed eight-attempt native reorg component observation, not Host acceptance.

Use after both release builds and all other compiles have stopped. This runner
uses the reviewed V5 Popen/wait4 sole reaper; /usr/bin/time is not required.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts/ci"))
from ci_observation import digest
from check_cross_arch_cost import ARCHITECTURES, COST_TERMINATION_GRACE_SECONDS, elf_machine, unique
from run_w1_rank_batch_v5 import capture, checked_source, host, write_json

ORDER = ("baseline", "candidate", "candidate", "baseline") * 2
COMMAND_SECONDS = 300
GRACE_SECONDS = 5
BASE = "0ca272d09d1522b0ffd740e441b6d3de1ed81de6"
CONTROL = "852b61eeeb41c283f3bc291ce71cbe32350087a1"
OBSERVER = "trillionnium/crates/trnm-pon-node/examples/native_reorg_query_cost.rs"
STORE = "trillionnium/crates/trnm-pon-node/src/store.rs"
FALSE_FLAGS = {
    "original_history_4105_accepted": False,
    "original_four_second_accepted": False,
    "original_public_service_resource_contract_used": False,
    "public_network_ready": False,
    "production_activation": False,
    "global_cpu_complete": False,
    "global_memory_peak_observed": False,
}
CONTEXT = ("planned_blocks", "admitted_blocks", "packet_bytes", "backend", "task_profile",
           "observer_source_sha256", "network", "parameters", "genesis", "target")
NATIVE_COSTS = ("preparation_wall_ns", "preparation_process_cpu_ns", "activation_wall_ns",
                "activation_process_cpu_ns", "entire_wall_ns", "entire_process_cpu_ns")


def require(condition, message):
    if not condition:
        raise ValueError("REORG_ABBA:" + message)


def git(*args):
    return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=ROOT)


def source_digest(commit, filename):
    return hashlib.sha256(git("show", commit + ":" + filename)).hexdigest()


def checked_binary(path, receipt, machine):
    require(path.is_file() and not path.is_symlink(), "regular retained binary required")
    observed = {"sha256": digest(path), "bytes": path.stat().st_size,
                "elf_machine": elf_machine(path)}
    require(observed["sha256"] == receipt["sha256"] and observed["bytes"] == receipt["bytes"],
            "binary differs from build receipt")
    require(observed["elf_machine"] == machine, "native ELF architecture mismatch")
    return observed


def binding(kind, binary, receipt_path, expected, machine, output):
    raw = receipt_path.read_bytes()
    with (output / (kind + "-build-receipt.json")).open("xb") as stream:
        stream.write(raw)
    receipt = json.loads(raw, object_pairs_hook=unique)
    require(type(receipt.get("build_exit")) is int and receipt["build_exit"] == 0,
            "successful release build receipt required")
    expected_commit = CONTROL if kind == "baseline" else expected
    require(receipt.get("source_commit") == expected_commit, "build source commit mismatch")
    require(receipt.get("observer_sha256") == source_digest(expected_commit, OBSERVER),
            "observer differs from build source")
    require(receipt.get("store_sha256") == source_digest(expected_commit, STORE),
            "store differs from build source")
    if kind == "baseline":
        require(receipt.get("base") == BASE, "original baseline source required")
        require(git("rev-parse", CONTROL + "^").decode().strip() == BASE, "control parent changed")
        require(git("diff", "--name-status", BASE, CONTROL).decode().strip() == "A\t" + OBSERVER,
                "baseline may only add the identical observer")
    identity = checked_binary(binary, receipt, machine)
    return {"binary": str(binary), "receipt": receipt, "identity": identity,
            "receipt_file": kind + "-build-receipt.json",
            "receipt_sha256": hashlib.sha256(raw).hexdigest()}


def validate_report(report, receipt):
    require(report.get("schema") == "native-reorg-query-cost-v1", "native report schema")
    for flag in ("completed", "same_native_state", "cold_reopen_same_state"):
        require(report.get(flag) is True, "native completion/state/cold readback required")
    for field in ("planned_blocks", "admitted_blocks"):
        require(type(report.get(field)) is int and report[field] == 512, "fixed 512-block fixture")
    require(report.get("backend") == "legacy" and
            report.get("task_profile") == "consensus-maintenance-continuity-dev-v1", "native fixture profile")
    require(report.get("observer_source_sha256") == receipt["observer_sha256"] and
            report.get("store_source_sha256") == receipt["store_sha256"], "embedded source identity mismatch")
    for field in NATIVE_COSTS + ("packet_bytes",):
        require(type(report.get(field)) is int and report[field] > 0, "missing actual cost/input: " + field)
    for field in ("network", "parameters", "genesis", "target"):
        value = report.get(field)
        require(isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value),
                "context digest: " + field)
    for field in ("original_history_4105_accepted", "original_four_second_accepted",
                  "public_network_ready", "production_activation"):
        require(report.get(field) is False, "scope widened: " + field)


def comparison(attempts):
    result = {"complete_comparison": False, "planned_attempts": len(ORDER),
              "retained_attempts": len(attempts), "failed_attempts_are_zero": False}
    if (len(attempts) != len(ORDER) or tuple(a.get("implementation") for a in attempts) != ORDER or
            any(a.get("result") != "COMPLETE_COMPONENT_OBSERVATION" for a in attempts)):
        return result
    reports = [a["report"] for a in attempts]
    result["identical_context_and_fixture"] = all(
        all(report[field] == reports[0][field] for field in CONTEXT) for report in reports)
    if not result["identical_context_and_fixture"]:
        return result
    result["complete_comparison"] = True
    result["medians"] = {}
    for scope, fields in (("report", NATIVE_COSTS),
                          ("observation", ("wait4_cpu_ns", "elapsed_ns", "wait4_maxrss_kib"))):
        for field in fields:
            values = {kind: statistics.median(a[scope][field] for a in attempts if a["implementation"] == kind)
                      for kind in ("baseline", "candidate")}
            values["candidate_over_baseline"] = (values["candidate"] / values["baseline"]
                                                  if values["baseline"] > 0 else None)
            result["medians"][scope + "." + field] = values
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--baseline-receipt", type=Path, required=True)
    parser.add_argument("--candidate-receipt", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    require(not output.is_relative_to(ROOT.resolve()), "output must be outside source checkout")
    output.mkdir(parents=True, exist_ok=False)
    started, parent_start = time.monotonic_ns(), resource.getrusage(resource.RUSAGE_SELF)
    children_start = resource.getrusage(resource.RUSAGE_CHILDREN)
    report = {"schema": "native-reorg-query-cost-abba-v2", "result": "HOLD", "order": ORDER,
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "execution_context": "local-component-observation", "expected_commit": args.expected_commit,
        "command_timeout_seconds": COMMAND_SECONDS, "termination_grace_seconds": GRACE_SECONDS,
        "maximum_declared_command_budget_seconds": len(ORDER) * (COMMAND_SECONDS + GRACE_SECONDS),
        "no_retry_or_result_selection": True, "attempts": [],
        "native_cpu_scope": "wait4-process-all-threads-and-reaped-descendants",
        "native_rss_scope": "Linux-wait4-ru_maxrss-KiB-not-sum-or-global-simultaneous-peak",
        "failed_or_unreaped_descendants_may_be_missing": True,
        "preparation_scope": "native fixture construction, both owners, generation and every admission; retained separately and within entire native scope",
        "build_cost_scope": "existing release builds are separate; retain their original logs/receipts; old build CPU/RSS was not measured and is not zero",
        "whole_campaign_scope": "parent wall/CPU and separately cumulative reaped-child CPU including git checks and native captures; do not add wait4 totals a second time",
        **FALSE_FLAGS}
    write_json(output / "plan.json", report)
    bindings, initialization_error = {}, None
    try:
        require(COST_TERMINATION_GRACE_SECONDS == GRACE_SECONDS, "shared capture grace changed")
        specs = [s for s in ARCHITECTURES.values() if s["machine"] == platform.machine()]
        require(platform.system() == "Linux" and len(specs) == 1, "native supported Linux required")
        require(all(hasattr(os, name) for name in ("wait4", "waitid", "WNOWAIT", "killpg")), "sole reaper platform")
        report["source_before"] = checked_source(args.expected_commit)
        report["host"] = host(output)
        for kind in ("baseline", "candidate"):
            bindings[kind] = binding(kind, getattr(args, kind).absolute(),
                getattr(args, kind + "_receipt"), args.expected_commit, specs[0]["elf_machine"], output)
        require(bindings["baseline"]["receipt"]["observer_sha256"] ==
                bindings["candidate"]["receipt"]["observer_sha256"], "same observer source required")
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
            # Retain the actual process outcome before report or source validation.
            write_json(output / (stem + ".process.json"), observed)
            try:
                item["report"] = json.loads((output / observed["stdout"]).read_bytes(), object_pairs_hook=unique)
            except (ValueError, UnicodeError) as error:
                item["readback_error"] = str(error)
            item["binary_after"] = checked_binary(binary, bound["receipt"], specs[0]["elf_machine"])
            item["source_after"] = checked_source(args.expected_commit)
            require(item["source_before"] == item["source_after"], "source changed during attempt")
            require(observed["exit_code"] == 0 and observed["process_exit_code"] == 0 and not observed["timed_out"],
                    "native command failed; all partial work/costs retained")
            require(isinstance(item.get("report"), dict), "exactly one complete native JSON report required")
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
    observations = [a["observation"] for a in report["attempts"] if "observation" in a]
    parent_end = resource.getrusage(resource.RUSAGE_SELF)
    children_end = resource.getrusage(resource.RUSAGE_CHILDREN)
    report["parent_user_ns"] = round((parent_end.ru_utime - parent_start.ru_utime) * 1_000_000_000)
    report["parent_system_ns"] = round((parent_end.ru_stime - parent_start.ru_stime) * 1_000_000_000)
    report["all_reaped_children_user_ns"] = round((children_end.ru_utime - children_start.ru_utime) * 1_000_000_000)
    report["all_reaped_children_system_ns"] = round((children_end.ru_stime - children_start.ru_stime) * 1_000_000_000)
    report["all_reaped_children_cpu_includes_native_wait4"] = True
    report["campaign_elapsed_ns"] = time.monotonic_ns() - started
    report["executed_commands"] = sum(o["executed"] for o in observations)
    report["planned_attempts_without_wait4_usage"] = len(ORDER) - sum(o["wait4_cpu_ns"] is not None for o in observations)
    report["observed_wait4_cpu_ns_sum_including_failed_attempts"] = sum(o["wait4_cpu_ns"] for o in observations if o["wait4_cpu_ns"] is not None)
    report["artifact_sha256"] = {p.name: digest(p) for p in sorted(output.iterdir()) if p.is_file()}
    write_json(output / "manifest.json", report)
    print(json.dumps({"result": report["result"], "receipt": str(output)}, sort_keys=True))
    return 0 if report["result"] == "COMPLETE_COMPONENT_OBSERVATION" else 1


if __name__ == "__main__":
    sys.exit(main())
