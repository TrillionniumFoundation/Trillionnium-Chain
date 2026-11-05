#!/usr/bin/env python3
"""Exact-source service readback with original denominators and failed samples."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent
HEAD = "bebb1f3289cd7050fefde89ea8f2cf33c6c37588"
MERGE = "0153600a002c420d20128983c3280ff6c16e70c4"
TREE = "58c31e8a6220c6be20029b33cb060f3a2034d1a7"
URL = "https://github.com/TrillionniumFoundation/Trillionnium-Chain"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked_archive(name, artifact_id, run_id, digest):
    data = (ROOT / name).read_bytes()
    assert sha(data) == digest
    return zipfile.ZipFile(ROOT / name), {
        "archive": name, "artifact_id": artifact_id, "run_id": run_id,
        "archive_bytes": len(data), "sha256": digest,
        "url": f"{URL}/actions/runs/{run_id}/artifacts/{artifact_id}",
    }


def member(z, name):
    data = z.read(name)
    return json.loads(data), {"member": name, "bytes": len(data), "sha256": sha(data)}


def source(z, before, after, commit):
    a, am = member(z, before)
    b, bm = member(z, after)
    assert a == b
    assert a["tested_commit"] == commit and a["tested_tree"] == TREE
    assert a["tracked_worktree_verified"] is True
    return {"identity": a, "before": am, "after": bm}


CALL_COLUMNS = ["started_ns", "ended_ns", "status", "error", "response_ok",
                "returned_after_window", "returned_after_deadline", "caller_cpu_ns", "elapsed_wall_ns", "original_cpu_field"]


def calls(rows):
    result = []
    for r in rows:
        response = r.get("response")
        cpu_field = ("client_thread_cpu_ns" if "client_thread_cpu_ns" in r else
                     "calling_process_cpu_ns" if "calling_process_cpu_ns" in r else None)
        result.append([r.get("started_ns"), r.get("ended_ns"), r.get("status"), r.get("error"),
                       response.get("ok") if isinstance(response, dict) else None,
                       r.get("returned_after_window"), r.get("returned_after_deadline"),
                       r.get(cpu_field) if cpu_field else None, r.get("elapsed_wall_ns"), cpu_field])
    return {"count": len(rows), "status_counts": dict(Counter(r.get("status") for r in rows)),
            "timely_ok": sum(r[2] == "ok" and r[4] is True and r[5] is False for r in result),
            "cpu_unknown": sum(r[7] is None for r in result),
            "caller_cpu_sum_ns": sum(r[7] for r in result if r[7] is not None),
            "cpu_scope": "Original field preserved per call: client_thread_cpu_ns is thread CPU; calling_process_cpu_ns is process CPU. Different scopes/cohorts are not combined.",
            "columns": CALL_COLUMNS, "rows": result}


def imports(rows, four=False, window_end_ns=None):
    # Preserve each original observation, including nested spans, unknown clocks,
    # unfinished phases, cancellation/refusal and host calls on other worker threads.
    out = []
    for r in rows:
        names = ("replay_started_ns", "replay_ended_ns", "replay_accepted", "replay_error", "replay_thread_cpu_ns", "replay_wall_ns") if four else (
            "started_ns", "ended_ns", "succeeded", "error", "thread_cpu_ns", "wall_ns")
        item = dict(zip(("started_ns", "ended_ns", "accepted", "error", "caller_cpu_ns", "wall_ns"),
                        (r.get(k) for k in names)))
        item["ended_before_original_window"] = (
            item["ended_ns"] < window_end_ns
            if type(item["ended_ns"]) is int and type(window_end_ns) is int else None)
        item["native_import_observation"] = r.get("native_import_observation")
        out.append(item)
    return {"attempts": len(out), "accepted": sum(r["accepted"] is True for r in out),
            "original_window_end_ns": window_end_ns,
            "timely_accepted": sum(r["accepted"] is True and r["ended_before_original_window"] is True for r in out),
            "accepted_at_or_after_window": sum(r["accepted"] is True and r["ended_before_original_window"] is False for r in out),
            "accepted_timing_unknown": sum(r["accepted"] is True and r["ended_before_original_window"] is None for r in out),
            "rejected": sum(r["accepted"] is False for r in out),
            "unknown_outcome": sum(r["accepted"] is None for r in out),
            "cpu_unknown": sum(r["caller_cpu_ns"] is None for r in out),
            "caller_cpu_sum_ns": sum(r["caller_cpu_ns"] for r in out if r["caller_cpu_ns"] is not None),
            "calls": out,
            "scope": "Each original call retained. Accepted is the native result, not timeliness or confirmation; those outcomes remain separate. Packet/page/Host spans are inclusive and not additive; Host CPU includes actual calling threads and is not exclusively importer-thread CPU."}


def four_second():
    lanes = []
    for lane, commit, name, artifact, digest in [
        ("head", HEAD, "bebb-fresh-head.zip", 13239869502, "99fa79f0df16c7a8792fd04e9b803d5aa63b6fc23b7724a179481d1e4a067648"),
        ("prospective-merge", MERGE, "bebb-fresh-merge.zip", 13242555260, "2878a4bb1d696590cb2bfdad845f98b315c016ec997fec4dce69c0986bc056f8"),
    ]:
        z, archive = checked_archive(name, artifact, 41658914625, digest)
        with z:
            identity = source(z, "source-before.json", "source-after.json", commit)
            manifest, manifest_meta = member(z, "fresh-service/manifest.json")
            assert manifest["source_before"] == manifest["source_after"]
            assert manifest["source_before"]["commit"] == commit
            assert manifest["source_before"]["tree"] == TREE
            host_before, hbm = member(z, "fresh-service-host/inside-before.json")
            host_after, ham = member(z, "fresh-service-host/inside-after.json")
            assert host_before["limits"] == host_after["limits"]
            assert host_before["limits"]["cpu.max"] == "25000 100000"
            assert host_before["limits"]["memory.max"] == "2147483648"
            assert host_before["limits"]["memory.swap.max"] == "0"
            result = {"lane": lane, "artifact": archive, "source": identity,
                      "manifest": manifest_meta, "limits": host_before["limits"],
                      "host_identity_members": [hbm, ham], "variants": []}
            for index, variant in enumerate(["original", "fresh"]):
                report, meta = member(z, f"fresh-service/{variant}/report.json")
                assert meta["sha256"] == manifest["files"][f"{variant}/report.json"]
                execution = manifest["runs"][index]
                assert sha(z.read("fresh-service/" + execution["process"]["log"])) == execution["log_sha256"]
                assert len(report["signed_honest_packets"]) == 7
                assert len(report["phases"]) == 2
                v = {"variant": variant, "report": meta, "execution": execution,
                     "finite_target_met": report["finite_target_met"], "phases": []}
                for phase in report["phases"]:
                    assert phase["requested_window_ns"] == 4000000000
                    keys = ["mode", "workers", "business_started_ns", "requested_window_ns",
                            "client_confirmation_latency_ns", "confirmation_ended_ns", "client_confirmed_transactions",
                            "client_confirmed_before_original_window_end", "finite_business_target_met", "invariant_target_met",
                            "accounting_closed", "no_attack_accepted", "full_native_state_equal", "overlap_demonstrated",
                            "overlapping_false_calls", "attacker_workers_cpu_ns", "completed_false_calls_before_business",
                            "completed_false_calls_at_confirmation", "independent_client_confirmation", "independent_final_confirmation_stage"]
                    p = {k: phase.get(k) for k in keys}
                    p.update({"planned_confirmations": 1, "planned_signed_packets": 7,
                              "submissions": calls(phase["honest_submissions"]), "history": calls(phase["honest_history"]),
                              "attacks": calls([c for actor in phase["attacks"] for c in actor["calls"]]),
                              "imports": imports(phase["independent_history_page_replay"], True, phase["requested_window_ns"]),
                              "verification_errors": phase["verification_errors"],
                              "receiver_observer_health": {k: phase["observations"][k] for k in ["accepted_connections_seen", "records_not_retained", "counter_overflow", "measurement_failures"]},
                              "receiver_terminal_errors": dict(Counter(str(r["terminal_error_code"]) for r in phase["observations"]["records"]))})
                    v["phases"].append(p)
                result["variants"].append(v)
            lanes.append(result)
    return lanes


def phase_summary(phase, meta):
    keys = ["mode", "duration_seconds", "attacker_processes_ready", "attacker_processes_requested",
            "genuine_budget_depletion_observed", "finite_phase_criteria_met", "all_signed_rounds_confirmed_in_window",
            "observer_complete", "full_work_accepted", "full_work_failed", "receiver_client_state_equal", "verifier_errors"]
    result = {k: phase[k] for k in keys}
    result.update({"report": meta, "submissions": calls(phase["submissions"]), "history": calls(phase["history"]),
                   "imports": imports([h["client_import"] for h in phase["history"] if h.get("client_import")],
                                      window_end_ns=phase["duration_seconds"] * 1_000_000_000),
                   "host_before": phase["phase_process_context"]["host_before"], "host_after": phase["phase_process_context"]["host_after"],
                   "confirmations": phase["confirmations"]})
    return result


def f0():
    z, archive = checked_archive("bebb-f0-head.zip", 13241471698, 41658914767,
                                "33addf9426f51dad1a7cc5e23aaa860f9542e721f787a8b631a295cd2b321a72")
    with z:
        raw, meta = member(z, "execution/results.json")
        assert raw["head"] == HEAD and raw["tree"] == TREE
        assert raw["planned_confirmations"] == 6 and raw["planned_business_packet_exposures"] == 42
        assert len(raw["all_planned_rounds"]) == 6 and len(raw["all_planned_business_packets"]) == 42
        report, rm = member(z, "execution/raw/report.json")
        assert rm["sha256"] == raw["report_sha256"]
        keys = ["failure", "native_result_failure", "report_validation_failure", "complete_success", "native_execution_observed",
                "direct_process_exit_observed", "controller_resources_complete", "planned_confirmations", "planned_business_packet_exposures",
                "four_second_slo_successes", "all_planned_rounds", "all_planned_business_packets", "step", "binary"]
        result = {k: raw[k] for k in keys}
        result.update({"artifact": archive, "result": meta, "report": rm,
                       "confirmed_inside_original_window": sum(r["confirmed_inside_original_window"] for r in raw["all_planned_rounds"]),
                       "profile": {k: report[k] for k in ["phase_seconds", "actor_call_cap", "business_blocks", "seed_blocks", "seed_transfers", "m06_workers", "state_backend", "original_scalar_profile_changed"]},
                       "phases": [], "arithmetic_snapshots": []})
        for mode in ["baseline", "valid-work-root"]:
            phase, pm = member(z, f"execution/raw/{mode}.json")
            result["phases"].append(phase_summary(phase, pm))
            for owner in ["client_native_history_arithmetic", "native_history_arithmetic"]:
                result["arithmetic_snapshots"].append({"mode": mode, "owner": owner,
                    "before": phase[owner + "_before"], "after": phase[owner + "_after"],
                    "original_client_observation_scope": phase["client_observation_scope"],
                    "scope": "Client snapshot includes imports plus subsequent confirmation/internal reads, but excludes final standalone read_active. Do not divide graph snapshot CPU by native import CPU. Nested stages must not be summed."})
        return result


def campaign():
    z, archive = checked_archive("bebb-original-campaign.zip", 13241387206, 41658915167,
                                "ab3be95db238bfdb2f74a4e49dfbc7a741baffd787f43a869823e0ee457e25db")
    with z:
        result, meta = member(z, "results.json")
        assert result["expected_head"] == HEAD and result["expected_tree"] == TREE
        assert result["planned_complete_runs"] == len(result["attempts"]) == 3
        assert result["original_inputs"] == {"attacker_processes": [0, 24, 24], "business_blocks": 21,
            "modes": ["baseline", "from-zero", "late-product"], "phase_seconds": 30, "seed_blocks": 4, "seed_transfers": 1024}
        rounds, packets, phases = [], [], []
        for attempt in result["attempts"]:
            number = attempt["number"]
            report, rm = member(z, f"run-{number}-raw/report.json")
            assert rm["sha256"] == attempt["report_sha256"]
            assert len(report["phases"]) == 3
            for stream in ["stdout", "stderr"]:
                assert sha(z.read(attempt["step"][stream])) == attempt["step"][stream + "_sha256"]
            for phase in report["phases"]:
                mode = phase["mode"]
                raw_phase, pm = member(z, f"run-{number}-raw/{mode}.json")
                assert raw_phase == phase
                observations = {r["round"]: r for r in phase["confirmations"]}
                assert len(observations) == len(phase["confirmations"]) and all(0 <= r < 3 for r in observations)
                for index in range(3):
                    row = observations.get(index)
                    rounds.append({"run": number, "mode": mode, "round": index, "observed": row is not None,
                        "started_ns": row.get("started_ns") if row else None, "ended_ns": row.get("ended_ns") if row else None,
                        "confirmed_inside_original_window": bool(row and row["confirmed_inside_pressure_window"])})
                assert all(0 <= r["packet_index"] < 21 for r in phase["submissions"])
                for index in range(21):
                    group = [r for r in phase["submissions"] if r["packet_index"] == index]
                    packets.append({"run": number, "mode": mode, "packet_index": index, "attempts": len(group),
                                    "timely_ack": calls(group)["timely_ok"]})
                p = phase_summary(phase, pm)
                p["run"] = number
                phases.append(p)
        assert len(rounds) == 27 and len(packets) == 189
        return {"artifact": archive, "result": meta, "complete_success": result["complete_success"], "failure": result["failure"],
                "original_inputs": result["original_inputs"], "attempts": result["attempts"], "phases": phases,
                "planned_confirmations": 27, "planned_business_packet_exposures": 189,
                "confirmed_inside_original_window": sum(r["confirmed_inside_original_window"] for r in rounds),
                "observed_rounds": sum(r["observed"] for r in rounds), "actual_submission_attempts": sum(r["attempts"] for r in packets),
                "timely_ack_count": sum(r["timely_ack"] for r in packets), "all_planned_rounds": rounds, "all_planned_packets": packets}


def main():
    result = {"schema": "bebb-original-service-outcomes-v1", "head": HEAD, "actual_merge": MERGE, "tree": TREE,
              "native_rerun": False, "four_second": four_second(), "F0": f0(), "original_thirty_second_campaign": campaign(),
              "scope": "Exact original artifacts only; all planned denominators and failed/late/unknown samples retained. ACK is not confirmation. Imports, page/packet/Host stages are nested, different clock/worker scopes cannot be subtracted or divided. No independent hardware/operator/WAN/cryptographic/economic acceptance is granted.",
              "production_activation": False}
    path = ROOT / "bebb-original-service-outcomes.json"
    path.write_text(json.dumps(result, separators=(",", ":")) + "\n")
    print(json.dumps({"path": str(path), "bytes": path.stat().st_size, "sha256": sha(path.read_bytes())}))
    for lane in result["four_second"]:
        for variant in lane["variants"]:
            for p in variant["phases"]:
                print(json.dumps({"lane": lane["lane"], "variant": variant["variant"], "mode": p["mode"],
                    "confirmed": p["client_confirmed_transactions"], "latency_ns": p["client_confirmation_latency_ns"],
                    "timely_ack": p["submissions"]["timely_ok"], "history_calls": p["history"]["count"],
                    "imports": [[r["started_ns"], r["ended_ns"], r["accepted"], r["error"]] for r in p["imports"]["calls"]]}))
    print(json.dumps({"F0_confirmed": result["F0"]["confirmed_inside_original_window"],
                      "F0_four_second": result["F0"]["four_second_slo_successes"], "F0_planned": 6}))
    c = result["original_thirty_second_campaign"]
    print(json.dumps({k: c[k] for k in ["confirmed_inside_original_window", "planned_confirmations", "planned_business_packet_exposures", "observed_rounds", "actual_submission_attempts", "timely_ack_count"]}))


if __name__ == "__main__":
    main()
