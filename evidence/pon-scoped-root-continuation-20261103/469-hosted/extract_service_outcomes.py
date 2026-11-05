"""Read retained exact-source service artifacts; no native execution or repo edits."""
import collections
import hashlib
import json
import pathlib
import zipfile
from datetime import datetime, timezone

BASE = pathlib.Path(__file__).resolve().parent
HEAD = "469c4d4bb36efb37045d968f35f83cb2c1771933"
MERGE = "bfe1f33959a02d0766b33f6acc082e5990d82ea1"
TREE = "383a3cbc8a4a71f27e4f18d7df089b860f302439"
URL = "https://github.com/TrillionniumFoundation/Trillionnium-Chain"
helper = BASE.parent / "summarize_current_reports.py"
ns = {"__file__": str(helper)}
exec(helper.read_text().split("four_zip = ")[0], ns)
calls_summary = ns["calls_summary"]
imports_summary = ns["imports_summary"]
phase_sums = ns["phase_sums"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_member(z, name):
    data = z.read(name)
    return json.loads(data), {"member": name, "bytes": len(data), "sha256": sha(data)}


def archive_metadata(name, artifact_id, run_id, job_id, expected):
    path = BASE / name
    assert sha(path.read_bytes()) == expected
    return {"retained_zip": name, "bytes": path.stat().st_size, "artifact_id": artifact_id,
            "artifact_url": f"{URL}/actions/runs/{run_id}/artifacts/{artifact_id}",
            "run_id": run_id, "job_id": job_id, "job_url": f"{URL}/actions/runs/{run_id}/job/{job_id}",
            "github_sha256": expected, "local_sha256_verified": True}


def import_observation(imports, four=False):
    summary = imports_summary(imports, four)
    summary.pop("per_call")
    summary.pop("scope")
    failed_phase_rows = []
    for owner in ("page", "packet"):
        phases = summary.pop(owner + "_phase_sums_nested_do_not_add")
        for name, counts in phases.items():
            if counts["rejected"] or counts["unfinished"] or counts["cpu_unknown_started"]:
                failed_phase_rows.append({"owner": owner, "phase": name, **counts})
    summary["failed_unfinished_or_unknown_inclusive_phases"] = failed_phase_rows
    per = []
    for item in imports:
        host = item["native_import_observation"]["host_checks"]
        checkpoint = next(x for x in host if x["phase"] == "checkpoint")
        if four:
            started, ended, accepted, error, cpu, wall = [item[k] for k in
                ("replay_started_ns", "replay_ended_ns", "replay_accepted", "replay_error", "replay_thread_cpu_ns", "replay_wall_ns")]
        else:
            started, ended, accepted, error, cpu, wall = [item[k] for k in
                ("started_ns", "ended_ns", "succeeded", "error", "thread_cpu_ns", "wall_ns")]
        per.append([started, ended, accepted, error, cpu, wall, checkpoint["calls_started"],
                    checkpoint["thread_cpu_ns"], checkpoint["calls_rejected"], checkpoint["calls_unfinished"],
                    checkpoint["cpu_clock_unknown_calls"]])
    summary["per_call_rows"] = per
    return summary


retained_metadata = []
four = []
for lane, source, name, artifact, job, digest in [
    ("head", HEAD, "fresh-service-head-13233397622.zip", 13233397622, 125935911820,
     "5b0866840f91f04f148bcf4b972825acfd3a91ed952232fbd89d7b5bbad75b8d"),
    ("actual_merge", MERGE, "fresh-service-merge-13233258159.zip", 13233258159, 125935911889,
     "ae89fd9a0aa32f0e4e58acddd561deb74b47f49def28c02b6a6e8e25d4677919"),
]:
    metadata = archive_metadata(name, artifact, 41641510557, job, digest)
    with zipfile.ZipFile(BASE / name) as z:
        manifest, manifest_meta = json_member(z, "fresh-service/manifest.json")
        assert manifest["source_before"] == manifest["source_after"]
        assert manifest["source_before"]["commit"] == source and manifest["source_before"]["tree"] == TREE
        outer, outer_meta = json_member(z, "source-before.json")
        outer_after, _ = json_member(z, "source-after.json")
        assert outer == outer_after and outer["tested_commit"] == source and outer["tested_tree"] == TREE
        assert outer["tracked_worktree_verified"]
        host_before, _ = json_member(z, "fresh-service-host/inside-before.json")
        host_after, _ = json_member(z, "fresh-service-host/inside-after.json")
        assert host_before["limits"] == host_after["limits"]
        assert host_before["limits"]["cpu.max"] == "25000 100000"
        assert host_before["limits"]["memory.max"] == "2147483648"
        assert host_before["limits"]["memory.swap.max"] == "0"
        lane_result = {"lane": lane, "source": outer, "artifact": metadata,
                       "manifest": manifest_meta, "original_host_limits_before_after": host_before["limits"],
                       "all_named_tests_passed": manifest["all_named_tests_passed"], "variants": []}
        for index, kind in enumerate(("original", "fresh")):
            report, report_meta = json_member(z, f"fresh-service/{kind}/report.json")
            assert report_meta["sha256"] == manifest["files"][f"{kind}/report.json"]
            native = manifest["runs"][index]
            assert sha(z.read("fresh-service/" + native["process"]["log"])) == native["log_sha256"]
            assert len(report["signed_honest_packets"]) == 7
            variant = {"variant": kind, "report": report_meta, "finite_target_met": report["finite_target_met"],
                       "invariant_target_met": report.get("invariant_target_met"),
                       "invariant_target_field_present": "invariant_target_met" in report,
                       "signed_packet_count": 7, "planned_confirmations_per_phase": 1,
                       "native_execution": native, "phases": []}
            assert len(report["phases"]) == 2
            for phase in report["phases"]:
                assert phase["requested_window_ns"] == 4000000000
                scalar_keys = ["mode", "workers", "business_started_ns", "client_confirmation_latency_ns",
                    "confirmation_ended_ns", "client_confirmed_transactions", "client_confirmed_before_original_window_end",
                    "finite_business_target_met", "invariant_target_met", "accounting_closed", "no_attack_accepted",
                    "full_native_state_equal", "overlap_demonstrated", "overlapping_false_calls",
                    "attacker_workers_cpu_ns", "completed_false_calls_before_business", "completed_false_calls_at_confirmation"]
                p = {k: phase[k] for k in scalar_keys}
                confirmation = phase["independent_client_confirmation"]
                p["independent_confirmation"] = None if confirmation is None else {
                    k: confirmation[k] for k in ("confirmed", "depth", "required_work_delta", "work_delta", "reorged", "finalized", "execution_authority")}
                p["honest_submissions"] = calls_summary(phase["honest_submissions"])
                p["history"] = calls_summary(phase["honest_history"])
                p["attacker_calls"] = calls_summary([c for a in phase["attacks"] for c in a["calls"]])
                p["imports"] = import_observation(phase["independent_history_page_replay"], True)
                p["verification_errors"] = phase["verification_errors"]
                p["receiver_observer_health"] = {k: phase["observations"][k] for k in
                    ("accepted_connections_seen", "records_not_retained", "counter_overflow", "measurement_failures")}
                p["receiver_terminal_errors"] = dict(collections.Counter(str(r["terminal_error_code"]) for r in phase["observations"]["records"]))
                variant["phases"].append(p)
            lane_result["variants"].append(variant)
        four.append(lane_result)
        for member in ("fresh-service/manifest.json", "fresh-service/original.log", "fresh-service/fresh.log",
                       "fresh-service-host/inside-before.json", "fresh-service-host/inside-after.json",
                       "source-before.json", "source-after.json"):
            raw = z.read(member)
            assert len(raw) < 100000
            dest = BASE / f"four-second-{lane}-raw" / member
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("xb") as f:
                f.write(raw)
            retained_metadata.append({"path": str(dest.relative_to(BASE)), "bytes": len(raw), "sha256": sha(raw)})

f0_artifact = archive_metadata("f0-head-13232758564.zip", 13232758564, 41641510389, 125935910380,
    "0f468ee9ad7c0fd534a95c30b92da2f480eddacef299f192821f9f34359d70d1")
arithmetic = []
with zipfile.ZipFile(BASE / f0_artifact["retained_zip"]) as z:
    result, result_meta = json_member(z, "execution/results.json")
    assert result["head"] == HEAD and result["tree"] == TREE
    raw_report = z.read("execution/raw/report.json")
    assert sha(raw_report) == result["report_sha256"]
    original_report = json.loads(raw_report)
    assert result["planned_confirmations"] == 6 and result["planned_business_packet_exposures"] == 42
    assert len(result["all_planned_rounds"]) == 6 and len(result["all_planned_business_packets"]) == 42
    f0 = {"artifact": f0_artifact, "execution_result": result_meta, "native_report_sha256": result["report_sha256"],
          **{k:result[k] for k in ("head", "tree", "failure", "native_result_failure", "report_validation_failure",
             "complete_success", "native_execution_observed", "direct_process_exit_observed", "controller_resources_complete",
             "planned_confirmations", "planned_business_packet_exposures", "four_second_slo_successes")},
          "confirmed_inside_original_window": sum(r["confirmed_inside_original_window"] for r in result["all_planned_rounds"]),
          "all_planned_rounds": result["all_planned_rounds"],
          "packet_columns": ["phase", "packet_index", "observed_attempts", "timely_network_ack"],
          "all_planned_packet_rows": [[p[k] for k in ("phase", "packet_index", "observed_attempts", "timely_network_ack")] for p in result["all_planned_business_packets"]],
          "original_profile": {k:original_report[k] for k in ("phase_seconds", "actor_call_cap", "business_blocks", "seed_blocks", "seed_transfers", "m06_workers", "state_backend", "original_scalar_profile_changed")},
          "phases": []}
    for mode in ("baseline", "valid-work-root"):
        phase, phase_meta = json_member(z, f"execution/raw/{mode}.json")
        imports = [h["client_import"] for h in phase["history"] if h.get("client_import")]
        p = {"phase": mode, "report": phase_meta,
             **{k:phase[k] for k in ("duration_seconds", "attacker_processes_ready", "attacker_processes_requested",
                 "genuine_budget_depletion_observed", "finite_phase_criteria_met", "all_signed_rounds_confirmed_in_window",
                 "observer_complete", "full_work_accepted", "full_work_failed", "receiver_client_state_equal")},
             "submissions": calls_summary(phase["submissions"]), "history": calls_summary(phase["history"]),
             "imports": import_observation(imports), "verifier_errors": phase["verifier_errors"],
             "host_before": phase["phase_process_context"]["host_before"], "host_after": phase["phase_process_context"]["host_after"],
             "observed_confirmations": []}
        for c in phase["confirmations"]:
            p["observed_confirmations"].append({k:v for k,v in c.items() if k in
                ("round", "scheduled_offset_ns", "started_ns", "ended_ns", "confirmed_inside_pressure_window",
                 "paid_credit_depletion_observed_during_round", "receiver_hostile_work_rejected_during_round",
                 "accepted_work_admission_refusal_during_round", "signed_root_responses_inside_round")})
        f0["phases"].append(p)
        for owner in ("client_native_history_arithmetic", "native_history_arithmetic"):
            before, after = phase[owner + "_before"], phase[owner + "_after"]
            b = {s["stage"]:s["totals"] for s in before["stages"]}
            a = {s["stage"]:s["totals"] for s in after["stages"]}
            cols = ["calls", "cpu_ns", "wall_ns", "cpu_known_calls", "cpu_unknown_calls", "unwinding_calls"]
            rows = []
            for stage in b:
                prior = [b[stage][k] for k in cols]
                end = [a[stage][k] for k in cols]
                delta = [e-s for s,e in zip(prior,end)]
                assert all(v >= 0 for v in delta)
                rows.append([stage,prior,end,delta])
            arithmetic.append({"phase":mode,"owner":owner,"report":phase_meta,
                "stage_columns":cols,"row_columns":["stage","before","after","after_minus_before"],"rows":rows,
                "stage_observation_failed_before_after":[before["stage_observation_failed"],after["stage_observation_failed"]]})
    for member in ("execution/results.json", "execution/raw/predeclared-denominators.json", "execution/supplement.stdout.log",
                   "execution/supplement.stderr.log", "execution/source-before.json", "execution/source-after.json",
                   "workflow-outcomes.json", "finalization/result.json"):
        raw=z.read(member)
        assert len(raw)<100000
        dest=BASE/"f0-head-raw"/member
        dest.parent.mkdir(parents=True,exist_ok=True)
        with dest.open("xb") as f:f.write(raw)
        retained_metadata.append({"path":str(dest.relative_to(BASE)),"bytes":len(raw),"sha256":sha(raw)})

outcome = {
    "schema":"chain-469-service-outcomes-v1", "extracted_at_utc":datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    "head":HEAD,"actual_merge":MERGE,"tree":TREE,
    "actual_merge_ordered_parents":["9a05cae09b175a51773db398541b14ab76061a39",HEAD],
    "new_native_execution_by_extractor":False,"rerun_requested":False,
    "import_row_columns":["started_ns","ended_ns","accepted","error","caller_cpu_ns","wall_ns","Host_checkpoint_calls",
        "Host_checkpoint_caller_cpu_ns","Host_checkpoint_rejected","Host_checkpoint_unfinished","Host_checkpoint_cpu_unknown"],
    "four_second":four,"F0":f0,
    "scope":[
        "These are new hosted results for 469 HEAD and its actual bfe merge only. Old c39 results and later unpublished frontier prototypes are outside this evidence.",
        "ACK is not confirmation. Each four-second phase retains 7 signed packet exposures and 1 planned independent confirmation, original 16 hostile workers, 4-second deadline, depth 6 and required work 0c. No successful late ACK is credited.",
        "The original four-second native selector exit 0 checks invariant/accounting behavior; its wrapper still fails CONFIRMATION_TARGET. Fresh selector really executes and exits 101; its generic FRESH_NATIVE_PROCESS_REQUIRED wrapper string does not mean a missing process.",
        "F0 retains all 6 planned confirmations and 42 packet exposures, including unobserved rounds and attempts after the window. Its 1 in-window confirmation misses the original four-second SLO; failure remains NATIVE_F0_FAILED / BASELINE_MUST_PASS.",
        "Import and Host checkpoint CPU use the same calling-thread operation scope. Host spans are nested in import and must not be added. Worker CPU is separate. All failed and cancelled imports and unknown clocks are retained.",
        "F0 arithmetic snapshots cover subsequent client_confirmation/read_active as well as import. Account-graph CPU must not be divided by import CPU as an exact percentage. Arithmetic stages are inclusive/nested and cannot be added or treated as exclusive costs.",
        "Four-second report overlap_demonstrated is false on the failed pressure observations; preserve the raw flag and do not infer qualified fairness or independent-operator pressure coverage from the worker count alone.",
        "No 30-second campaign, pending ARM CPU, recent 79/19, or full-workspace runtime result is inferred here. Each will retain its own exact source, native command and complete denominator.",
    ],
    "retained_small_metadata":retained_metadata,
}
for filename, value in (("service-outcomes.json",outcome),("f0-arithmetic-stages.json",{
    "schema":"chain-469-f0-arithmetic-stages-v1","head":HEAD,"tree":TREE,"artifact":f0_artifact,
    "measurement_scope":"before/after client snapshots also cover subsequent confirmation/read_active, not strictly nested in import; inclusive stages are not additive; no graph/import exact fraction",
    "samples":arithmetic})):
    path=BASE/filename
    with path.open("x") as f:json.dump(value,f,ensure_ascii=False,separators=(",",":"));f.write("\n")
    print(json.dumps({"path":str(path),"bytes":path.stat().st_size,"sha256":sha(path.read_bytes())}))
