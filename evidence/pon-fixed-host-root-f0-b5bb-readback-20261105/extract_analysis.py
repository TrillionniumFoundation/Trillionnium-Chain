#!/usr/bin/env python3
"""Derive a bounded F0 review from downloaded artifact text; runs no tests."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "files"
OUT = ROOT / "evidence-bundle"
SOURCE = Path("/workspace/scratch/822cc50e24f0/prospective-merge-822cc50e/checkout")
HEAD = "b5bb7bc8d7ffe79d46c6a58fd5189e2bb9e4550c"


def read(path):
    return json.loads(path.read_text())


def identity(path):
    b = path.read_bytes()
    return {"bytes": len(b), "sha256": hashlib.sha256(b).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(b)).encode() + b"\0" + b).hexdigest()}


def write(name, value):
    p = OUT / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def copy_member(name):
    p = OUT / "artifact" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(RAW / name, p)


def counters(text):
    return {parts[0]: int(parts[1]) for line in text.splitlines()
            if len(parts := line.split()) == 2}


def main():
    OUT.mkdir(exist_ok=True)
    result = read(RAW / "execution/results.json")
    final = read(RAW / "finalization/result.json")
    inventory = read(ROOT / "artifact-inventory.json")
    imports = read(ROOT / "client-import-summary.json")
    stages = read(ROOT / "phase-performance-summary.json")
    assert result["head"] == final["head"] == HEAD
    assert result["tree"] == final["tree"] == "8be28a72673ce318d60a464898ab610d9ba39216"
    originals = [
        "SCOPE.txt", "source-before.json", "source-after.json", "workflow-outcomes.json",
        "workflow-predeclared.json", "systemd-run.stderr.log", "systemd-run.stdout.log",
        "prepared/prepared.json", "prepared/hardware.json", "prepared/build.step.json",
        "execution/predeclared.json", "execution/results.json",
        "execution/supplement.stdout.log", "execution/supplement.stderr.log",
        "execution/raw/predeclared-denominators.json", "finalization/result.json",
    ]
    for phase in ["baseline", "valid-work-root"]:
        for when in ["inside-before", "inside-after", "outside-before", "outside-after"]:
            originals.append(f"execution/raw/{phase}-fixed-root-host-control/host/{when}.json")
    for name in originals:
        copy_member(name)
    for name in ["artifact-inventory.json", "workflow-job-127038806677.log",
                 "phase-performance-summary.json", "client-import-summary.json"]:
        shutil.copyfile(ROOT / name, OUT / name)
    phase_rows = {}
    phase_extracts = {}
    for phase in ["baseline", "valid-work-root"]:
        source = RAW / f"execution/raw/{phase}.json"
        d = read(source)
        packets = [x for x in result["all_planned_business_packets"] if x["phase"] == phase]
        host = {}
        for when in ["inside-before", "inside-after", "outside-before", "outside-after"]:
            m = f"execution/raw/{phase}-fixed-root-host-control/host/{when}.json"
            h = read(RAW / m)
            host[when] = {"artifact_member": m, "limits": h["limits"],
                          "read_errors": h["read_errors"],
                          "cpu_stat": counters(h["counters"]["cpu.stat"]),
                          "memory_events": counters(h["counters"]["memory.events"]),
                          "memory_current_bytes": int(h["counters"]["memory.current"])}
        host_sum = {}
        import_rows = []
        for index, history in enumerate(d["history"]):
            imp = history.get("client_import")
            if imp is None:
                continue
            import_rows.append({"history_index": index, "client_import": imp})
            for h in imp["native_import_observation"]["host_checks"]:
                row = host_sum.setdefault(h["phase"], {k: 0 for k in [
                    "calls_started", "calls_completed", "calls_accepted", "calls_rejected",
                    "calls_unfinished", "cpu_clock_unknown_calls", "wall_clock_unknown_calls",
                    "thread_cpu_ns", "wall_ns"]})
                for k in row:
                    row[k] += h[k]
        scalar_keys = ["state_backend", "finite_phase_criteria_met", "all_signed_rounds_confirmed_in_window",
                       "receiver_client_state_equal", "observer_complete", "verifier_errors",
                       "attacker_processes_requested", "attacker_processes_ready", "full_work_accepted",
                       "full_work_failed", "whole_parent_phase_cpu_ns", "whole_parent_phase_wall_ns"]
        phase_extracts[phase] = {
            "source": {"artifact_member": f"execution/raw/{phase}.json", **identity(source)},
            "extraction": "Exact copies of selected original JSON values; reserialized, not original file bytes.",
            "top_level_fields": {k: d[k] for k in scalar_keys},
            "history_client_imports": import_rows,
        }
        phase_rows[phase] = {
            "raw_source": phase_extracts[phase]["source"],
            "state_backend": d["state_backend"],
            "finite_phase_criteria_met": d["finite_phase_criteria_met"],
            "observer_complete": d["observer_complete"],
            "verifier_errors": d["verifier_errors"],
            "packets": {"planned": len(packets),
                        "observed_attempts": sum(x["observed_attempts"] for x in packets),
                        "timely_network_ack": sum(x["timely_network_ack"] for x in packets),
                        "unobserved": sum(x["observed_attempts"] == 0 for x in packets),
                        "ack_is_not_confirmation": True},
            "client_import": {k: v for k, v in imports[phase].items() if not isinstance(v, list)},
            "client_host_checks_sum": host_sum,
            "client_stage_after_minus_before": stages[phase]["stages"]["client_native_history_arithmetic"],
            "public_host_observations": host,
            "root_checks": stages[phase].get("root_checks"),
        }
    source_points = {
        "scripts/run_fixed_host_root_f0.py": "check_report 215-224; execute failure/report extraction 478-501",
        "scripts/ci/finalize_fixed_root_f0.py": "denominator retention 182-240; aggregate exit gate 283-288",
        "trillionnium/crates/trnm-pon-node/tests/support/multiprocess_root_phase_host.rs": "AuthenticatedV1/RawR14 415-443; ordinary client importer 651-685; criteria panic 1423",
        "trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs": "explicit state-backend routing 135-169",
        "trillionnium/crates/trnm-pon-node/src/store.rs": "AuthenticatedV1 constructor 1083-1109",
        "trillionnium/crates/trnm-pon-node/src/store/growth.rs": "separate GrowthV2 constructor 238-249",
    }
    source_map = []
    for path, lines in source_points.items():
        sha = subprocess.check_output(["git", "rev-parse", f"{HEAD}:{path}"], cwd=SOURCE, text=True).strip()
        source_map.append({"path": path, "git_blob": sha, "review_locations": lines,
                           "url": f"https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/{HEAD}/{path}"})
    summary = {
        "schema": "pon-fixed-host-root-f0-readback-analysis-v1",
        "scope": "Read-only analysis of an already completed GitHub head campaign. No new native/model tests, no CI dispatch, no threshold/source changes.",
        "head": HEAD, "tree": result["tree"], "run_id": 41964674522, "job_id": 127038806677,
        "run_url": "https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41964674522",
        "job_url": "https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41964674522/job/127038806677",
        "artifact": {k: inventory[k] for k in ["artifact_id", "zip_bytes", "zip_sha256", "entry_count", "extracted_text_count", "extracted_text_bytes"]},
        "artifact_url": "https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41964674522/artifacts/13386124417",
        "bindings": {"source_before": identity(RAW / "source-before.json"),
                     "source_after": identity(RAW / "source-after.json"),
                     "prepared_binary": result["binary"]},
        "outcome": {k: result[k] for k in ["failure", "native_result_failure", "report_validation_failure", "complete_success", "native_execution_observed", "direct_process_exit_observed", "controller_resources_complete", "four_second_slo_successes", "planned_confirmations", "planned_business_packet_exposures"]},
        "inputs": result["inputs"],
        "rounds": result["all_planned_rounds"],
        "round_time_semantics": "Phase-relative nanoseconds. elapsed_from_scheduled_ns includes scheduling delay; it is not actual execution duration. Missing observations remain unsuccessful in the original denominator.",
        "finalization": {"all_services_known_empty": final["all_services_known_empty"],
                         "complete_success": final["complete_success"],
                         "services": [{k: s.get(k) for k in ["phase", "failure", "known_empty", "remaining", "observed_empty_at_readback", "controller_terminal_before_phase_observation"]} for s in final["services"]],
                         "denominator": {k: v for k, v in final["denominator"].items() if k not in ["all_planned_business_packets", "all_planned_rounds", "controller_resource_summary"]}},
        "phases": phase_rows,
        "measurement_limits": [
            "CPU/stage/Host intervals are nested and must not be added across categories.",
            "Host checkpoint timing is actual per-call observation; it does not establish which account-graph instruction dominates or justify skipping a check.",
            "CPU throttling was observed under the declared public Host limits; the observed GitHub memory.events contain no OOM. Current local shared-cgroup OOM is unrelated evidence.",
            "full_work_accepted is work-verification-stage acceptance, not successful admission of invalid-root hostile packets.",
            "This single finite x64 head F0 pair uses AuthenticatedV1 and RawR14, not the GrowthV2 path. It does not cover the newly added GrowthV2/B1 native selectors.",
            "F0 uses 24 hostile producers, two 30-second phases and six scheduled 4-second SLOs. It does not rerun or close original issue #639's from-zero 4-second/16-hostile-producer gate.",
            "No prospective-merge native, independent operator/WAN, production, F1, PQ or quantum qualification follows.",
        ],
        "source_map": source_map,
        "raw_report_binding": {"artifact_member": "execution/raw/report.json", **identity(RAW / "execution/raw/report.json")},
        "no_artifact_binary_executed": True,
        "wrapper_or_parser_bug_established": False,
        "review_conclusion": "The native business pair genuinely failed, starting with the no-attack baseline. Denominator/finalization failure is the intended aggregate failure because native_complete_success is false and 0 of 6 SLOs passed; report/resource observations and service-empty evidence are present. Measured ordinary client imports justify inspecting that exact authenticated replay path; they do not identify a safe statement deletion.",
    }
    write("analysis.json", summary)
    write("phase-client-import-extracts.json", phase_extracts)
    shutil.copyfile(Path(__file__), OUT / "extract_analysis.py")
    print(json.dumps({"output": str(OUT), "analysis": identity(OUT / "analysis.json"),
                      "phase_extracts": identity(OUT / "phase-client-import-extracts.json"),
                      "host_checkpoint_sums": {p: phase_rows[p]["client_host_checks_sum"]["checkpoint"] for p in phase_rows}}, indent=2))


if __name__ == "__main__":
    main()
