#!/usr/bin/env python3
"""Audit retained F0 bytes and call exact-source pure readers; never execute/provision native code."""
from pathlib import Path, PurePosixPath
import argparse
import collections
import datetime
import hashlib
import json
import re
import stat
import subprocess
import sys
import tempfile
import zipfile

sys.dont_write_bytecode = True
HEAD = "bb026697a972521009bc133ae6ed2b653e18e931"
TREE = "18175756871bf341586fc37be1b17a00ef1dd099"
ARCHIVE_BYTES = 17336784
ARCHIVE_SHA = "b11e386e99d56722090bf3a31be0a575d053deb58458fcc8e77fa7c98b29157d"
ELF_SHA = "e38433c515bf93f0edfb6f4e61cefabf8d7266bcb425a596c788e183444e79e1"
ROOT = Path(__file__).resolve().parent

def require(value, message):
    if not value:
        raise ValueError(message)

def digest(stream):
    h, n = hashlib.sha256(), 0
    for c in iter(lambda: stream.read(1024 * 1024), b""):
        h.update(c); n += len(c)
    return n, h.hexdigest()

def zip_digest(z, name):
    with z.open(name) as f:
        return digest(f)

def js(z, name):
    return json.loads(z.read(name))

def write_json(path, value):
    with path.open("x") as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")

def pure_failure(call):
    try:
        call()
    except (ValueError, KeyError, TypeError) as e:
        return str(e)
    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    def git(*a):
        return subprocess.check_output(["git", "--no-replace-objects", "-C", str(args.source), *a])
    require(git("rev-parse", "HEAD").decode().strip() == HEAD, "reader HEAD mismatch")
    require(git("status", "--porcelain=v1", "--untracked-files=all") == b"", "reader source dirty")
    sys.path.insert(0, str(args.source / "scripts"))
    sys.path.insert(0, str(args.source / "scripts/ci"))
    import run_fixed_host_root_f0 as runner
    import finalize_fixed_root_f0 as finalizer
    import public_host_ci_observation as host
    import fixed_root_f0_ownership as ownership
    archive = ROOT / "f0-bb026697-attempt-1.zip"
    with archive.open("rb") as f:
        require(digest(f) == (ARCHIVE_BYTES, ARCHIVE_SHA), "GitHub archive identity")
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        names = [i.filename for i in infos]
        require(len(names) == len(set(names)), "duplicate ZIP member")
        for i in infos:
            p = PurePosixPath(i.filename)
            require(not p.is_absolute() and ".." not in p.parts and not stat.S_ISLNK(i.external_attr >> 16), "unsafe ZIP member")
        inventory = js(z, "artifact-files.json")
        require(inventory["schema"] == "fixed-host-root-f0-artifact-inventory-v1"
                and inventory["errors"] == [] and inventory["all_files_retained"] is True, "original inventory failure")
        entries = {r["path"]: r for r in inventory["files"]}
        require(len(entries) == len(inventory["files"]) and set(entries) | {"artifact-files.json"} == set(names), "full ZIP inventory coverage")
        hashes = {}
        for name, row in entries.items():
            hashes[name] = zip_digest(z, name)
            require(hashes[name] == (row["bytes"], row["sha256"]), "manifest mismatch: " + name)
        prepared = js(z, "prepared/prepared.json")
        execution = js(z, "execution/results.json")
        report = js(z, "execution/raw/report.json")
        final = js(z, "finalization/result.json")
        require(prepared["prepared"] is True and prepared["selector_invocation_attempted"] is False, "preparation identity")
        require(prepared["head"] == execution["head"] == final["head"] == HEAD
                and prepared["tree"] == execution["tree"] == final["tree"] == TREE, "source result binding")
        require(prepared["inputs"] == execution["inputs"] == runner.INPUTS, "unchanged input contract")
        require(prepared["binary"] == execution["binary"] and hashes["prepared/public_v3_multiprocess.bin"] == (12391424, ELF_SHA), "retained exact ELF")
        require(prepared["binary"]["sha256"] == ELF_SHA and prepared["binary"]["bytes"] == 12391424, "ELF record")
        profile = {"debug_assertions": False, "debuginfo": 0, "opt_level": "3", "overflow_checks": False, "test": True}
        require(prepared["binary"]["compiler_profile"] == profile, "release profile")
        artifacts = [json.loads(line) for line in z.read("prepared/build.stdout.log").splitlines()]
        actual = [r for r in artifacts if r.get("reason") == "compiler-artifact" and r.get("target", {}).get("name") == "public_v3_multiprocess"
                  and r.get("profile", {}).get("test") is True and r.get("executable")]
        require(len(actual) == 1 and actual[0]["executable"] == prepared["binary"]["build_artifact"]
                and actual[0]["profile"] == profile, "actual compiler artifact binding")
        require(prepared["runner_sha256"] == hashlib.sha256((args.source / "scripts/run_fixed_host_root_f0.py").read_bytes()).hexdigest(), "runner bytes")
        require(prepared["rust_source_control_selectors"] == list(runner.SOURCE_CONTROLS)
                and len(prepared["rust_source_controls"]) == 7, "all source controls")
        for i, step in enumerate(prepared["rust_source_controls"]):
            require(step["complete_success"] is True and step["returncode"] == 0, "source control native result")
            text = z.read("prepared/" + step["stdout"]).decode()
            require(re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", text, re.MULTILINE), "one exact control executed")
            require(step["command"] == [prepared["binary"]["path"], "--exact", runner.SOURCE_CONTROLS[i], "--nocapture", "--test-threads=1"], "source control command")
        source_names = [p for p in names if p in ("source-before.json", "source-after.json",
                         "prepared/source-before.json", "prepared/source-after.json",
                         "execution/source-before.json", "execution/source-after.json")]
        source_rows = [js(z, p) for p in source_names]
        require(len(source_rows) == 6 and all(r == source_rows[0] for r in source_rows), "six unchanged source receipts")
        require(source_rows[0]["tested_commit"] == HEAD and source_rows[0]["tested_tree"] == TREE
                and source_rows[0]["tracked_entries"] == 23515 and source_rows[0]["tracked_bytes"] == 2382494143
                and source_rows[0]["tracked_worktree_verified"] is True, "complete original source receipt")
        for path, row in execution["files"].items():
            require(hashes["execution/" + path] == (row["bytes"], row["sha256"]), "execution nested inventory")
        require(execution["file_inventory_errors"] == [], "execution inventory errors")
        require(execution["prepared_sha256"] == hashes["prepared/prepared.json"][1]
                and execution["report_sha256"] == hashes["execution/raw/report.json"][1], "prepared/report binding")
        step = execution["step"]
        require(step["command"] == [prepared["binary"]["path"], "--exact", runner.SELECTOR, "--ignored", "--nocapture", "--test-threads=1"], "exact selector")
        require(step["returncode"] == 101 and step["error"] is None and step["complete_success"] is False
                and not step["stdout_truncated"] and not step["stderr_truncated"], "native failure preserved")
        require(execution["native_execution_observed"] is True and execution["direct_process_exit_observed"] is True
                and execution["complete_success"] is False, "observed native execution")
        for stream in ("stdout", "stderr"):
            require(hashes["execution/" + step[stream]] == (step[stream + "_bytes"], step[stream + "_sha256"]), "actual execution output binding")
        require(all(r["complete_success"] is True and r["failure"] is None for r in execution["post_observations"].values()), "independent post observations")
        resources = [js(z, "execution/resource-" + kind + ".json") for kind in ("before", "after")]
        for resource in resources:
            runner.validate_resources(resource, 10)
        group = resources[0]["cgroup"]
        require(resources[1]["cgroup"] == group, "controller cgroup drift")
        live = js(z, "execution/controller-live.json")
        intent = js(z, "controller-intent.json")
        manager = ownership.parse_manager(z.read("execution/service-identity.stdout.log").decode())
        ownership.manager_matches(manager, intent, live)
        require(live["binary_sha256"] == intent["binary_sha256"] == ELF_SHA
                and live["job_sha256"] == intent["job_sha256"] == execution["prepared_sha256"], "live executable/intent binding")
        require(z.read("execution/service-runtime.stdout.log").strip() == b"10min", "original 600-second service runtime")
        native_id = report["controller_identity_before"]["process"]
        require(native_id["parent_pid"] == live["pid"] and native_id["boot_id"] == live["boot_id"]
                and native_id["cgroup"] == group and native_id["executable"]["bytes"] == 12391424, "native child/controller ancestry")
        controller_summary = runner.check_controller_resources(report, group)
        require(controller_summary == execution["controller_resource_summary"] == final["denominator"]["controller_resource_summary"], "six actual resource boundaries")
        host_checks = []
        phase_controls = []
        for index, phase in enumerate(("baseline", "valid-work-root")):
            prefix = f"execution/raw/{phase}-fixed-root-host-control/"
            first = js(z, prefix + "host/inside-before.json")
            for tag, inside in (("inside-before", True), ("inside-after", True), ("outside-after", False)):
                path = prefix + "host/" + tag + ".json"
                row = js(z, path)
                errors = host.validate(row, inside=inside, uid=1001, gid=1001,
                                       cwd="/home/runner/work/Trillionnium-Chain/Trillionnium-Chain", reference=first)
                require(errors == [], "public Host resource failure: " + path)
                host_checks.append({"path": path, "sha256": hashes[path][1], "errors": errors, "limits": row["limits"]})
            ctrl = js(z, prefix + "host/controller-result.json")
            job = js(z, prefix + "root-phase-job.json")
            require(ctrl["failure"] is None and ctrl["final_host_errors"] == [] and ctrl["passed"] is True, "phase launcher validity")
            require(ctrl["binary_sha256"] == job["binary_sha256"] == ELF_SHA
                    and ctrl["job_sha256"] == hashes[prefix + "root-phase-job.json"][1], "phase binary/job bytes")
            require(len(job["seed"]) == 4 and len(job["business"]) == 21, "original business packet denominator")
            require(job["business"] == js(z, "execution/raw/baseline-fixed-root-host-control/root-phase-job.json")["business"], "same actual business packet bytes")
            phase_controls.append({"phase": phase, "launcher_passed": ctrl["passed"], "service_or_depletion_criteria_met": ctrl["service_or_depletion_criteria_met"],
                                   "binary_sha256": ctrl["binary_sha256"], "job_sha256": ctrl["job_sha256"]})
        rounds, packets = runner.f0_rounds(report), runner.f0_packets(report)
        require(len(rounds) == 6 and len(packets) == 42 and rounds == execution["all_planned_rounds"]
                and packets == execution["all_planned_business_packets"], "complete exact denominator projection")
        for actual, retained in zip(rounds, report["all_planned_rounds"]):
            require(all(retained[k] == v for k, v in actual.items())
                    and retained["old_root_code_already_enforced_four_second_slo"] is False, "native round projection")
        require(packets == report["all_planned_business_packets"], "native packet projection")
        report_failure = pure_failure(lambda: runner.check_report(report, group))
        timing_failure = pure_failure(lambda: runner.check_f0_placement_and_timing(report, group))
        require(report_failure == execution["report_validation_failure"] == "BASELINE_MUST_PASS", "original report reader failure")
        require(timing_failure == "F0_ALL_SIX_SCHEDULED_FOUR_SECOND_TARGETS_REQUIRED", "original placement/timing refusal")
        require(all(report[key] is False for key in runner.QUALIFICATIONS), "supplement scope")
        with tempfile.TemporaryDirectory(prefix="f0-reader-", dir=ROOT) as temp:
            for name in ("execution/raw/report.json", "execution/results.json", "execution/controller-live.json", "prepared/prepared.json"):
                dest = Path(temp) / name; dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes(z.read(name))
            recomputed = finalizer.final_report(Path(temp), HEAD, TREE)
            require(recomputed == final["denominator"], "exact-source final report recomputation")
        cleanup = [{k: r.get(k) for k in ("phase", "ownership_validated", "cleanup_attempted", "known_empty",
                    "remaining", "failure", "observed_empty_at_readback", "controller_terminal_before_phase_observation")} for r in final["services"]]
        require(final["all_services_known_empty"] is True and all(r["known_empty"] and r["failure"] is None for r in cleanup), "original terminal service observations")
        selected = [p for p in names if len(PurePosixPath(p).parts) <= 2 and not p.endswith(".bin")]
        selected += [x["path"] for x in host_checks]
        for phase in ("baseline", "valid-work-root"):
            prefix = f"execution/raw/{phase}-fixed-root-host-control/"
            selected += [prefix + "root-phase-job.json"] + [prefix + "host/" + name for name in ("controller-result.json", "owned-service.json", "owned-service-live.json")]
        for name in sorted(set(selected)):
            out = ROOT / "selected-original" / name; out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("xb") as f:
                f.write(z.read(name))
        phase_summary = []
        for phase in report["phases"]:
            row = {k: phase.get(k) for k in ("mode", "finite_phase_criteria_met", "verifier_errors", "receiver_client_state_equal",
                   "observer_complete", "attacker_processes_ready", "actor_reports_successful_without_cap_or_kill", "genuine_budget_depletion_observed",
                   "full_work_accepted", "full_work_failed", "whole_parent_phase_cpu_ns", "whole_parent_phase_wall_ns")}
            root = phase.get("root_supplement")
            if root:
                row["root_summary"] = {k: v for k, v in root.items() if not isinstance(v, (dict, list))}
            phase_summary.append(row)
        output = {"schema": "f0-original-artifact-readonly-audit-v1", "observed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "run_id": 42509669473, "run_attempt": 1, "artifact_id": 13629594740, "head": HEAD, "tree": TREE,
                  "archive": {"path": archive.name, "bytes": ARCHIVE_BYTES, "sha256": ARCHIVE_SHA,
                              "members": len(infos), "uncompressed_bytes": sum(i.file_size for i in infos)},
                  "all_artifact_manifest_members_verified": len(entries),
                  "all_execution_manifest_members_verified": len(execution["files"]),
                  "source_receipts": source_names, "source_receipts_identical": True,
                  "binary": prepared["binary"], "seven_exact_native_source_controls_succeeded": True,
                  "native_step": step, "native_failure": execution["failure"],
                  "report_validation_failure": report_failure, "placement_and_timing_failure": timing_failure,
                  "original_final_report_recomputed_exactly": True,
                  "controller_resources": controller_summary, "public_host_samples": host_checks, "phase_controls": phase_controls,
                  "rounds": rounds, "packets": packets, "four_second_successes": sum(r["four_second_slo_met"] for r in rounds),
                  "planned_confirmations": len(rounds), "confirmed_in_thirty_second_phase": sum(r["confirmed_inside_original_window"] for r in rounds),
                  "observed_failed_confirmation_slots": sum(r["observed_exactly_once"] and not r["confirmed_inside_original_window"] for r in rounds),
                  "unobserved_confirmation_slots": sum(not r["observed_exactly_once"] for r in rounds),
                  "planned_packet_exposures": len(packets), "packet_exposures_with_attempts": sum(r["observed_attempts"] > 0 for r in packets),
                  "observed_packet_attempts": sum(r["observed_attempts"] for r in packets),
                  "timely_network_ack_exposures": sum(r["timely_network_ack"] for r in packets),
                  "phases": phase_summary, "cleanup": cleanup, "all_services_known_empty": final["all_services_known_empty"],
                  "finalization_false_preserves_native_failure": True,
                  "native_workload_reexecuted": False, "host_services_created_or_changed_by_this_audit": False,
                  "selected_original_file_count": len(set(selected)), "selected_original_bytes": sum(z.getinfo(p).file_size for p in set(selected)),
                  "qualified_goodput": None, "qualified_tail_latency": None,
                  "qualifications": {key: report[key] for key in runner.QUALIFICATIONS},
                  "all_audit_checks_completed": True, "performance_gate": "HOLD",
                  "limitations": ["This audits original CI bytes with exact-source pure readers; it does not reexecute a native workload.",
                                  "CI source/binary/process receipts are not an independent operator custody attestation or complete build/load closure.",
                                  "Only this one finite F0 pair is observed. It does not qualify the original three-run campaign, work hardness, WAN or production.",
                                  "All planned failed/unobserved slots remain; network acknowledgements are not confirmations."]}
        write_json(ROOT / "artifact-audit.json", output)
        print(json.dumps({k: output[k] for k in ("all_artifact_manifest_members_verified", "all_execution_manifest_members_verified",
                          "four_second_successes", "planned_confirmations", "confirmed_in_thirty_second_phase",
                          "observed_failed_confirmation_slots", "unobserved_confirmation_slots", "observed_packet_attempts",
                          "timely_network_ack_exposures", "all_services_known_empty", "selected_original_file_count", "performance_gate")}, indent=2))
if __name__ == "__main__":
    main()
