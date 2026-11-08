#!/usr/bin/env python3
"""Retain and describe the three pinned C3 CI artifacts; execute no tests.

This is a deterministic diagnostic extraction, not a source/release validator.
The original ZIP commitments are external inputs fixed below. Failed campaign
criteria stay failed. Inclusive/nested phase measurements are never summed
across phase names or promoted to total process-tree CPU.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile

HEAD = "abab79dac0cb89eb2753d3f579119ac135650eb5"
TREE = "194808f4a0db5d642aa746beb251ca9e9532cebb"
PINS = {
    "protocol": (13598537139, 42433029659, 5997415, "8c7fa04540912d6e5514893da14e369c729131e8bc3700a66d79d6f4a6aea538"),
    "fresh": (13598253920, 42433029674, 5617790, "4067ef4aede73de57f49370c87ef2653246a738848c02d2bfb00f23839f68e69"),
    "campaign": (13598547220, 42433029746, 70256249, "ef0d55c5b0a5ed2b57d5bb848cc7e5a7437849c52b84d14e00279c253daed668"),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for kind in PINS:
        parser.add_argument("--" + kind, type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    raw_records, artifacts, documents = {}, {}, {}
    for kind, (artifact_id, run_id, size, digest) in PINS.items():
        raw = getattr(args, kind).read_bytes()
        if len(raw) != size or sha(raw) != digest:
            raise ValueError("pinned ZIP differs: " + kind)
        artifacts[kind] = {"artifact_id": artifact_id, "workflow_run_id": run_id,
                           "zip_bytes": size, "zip_sha256": digest,
                           "url": f"https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/{run_id}/artifacts/{artifact_id}"}
        if kind == "protocol":
            names = ["from-zero-native/manifest.json", "from-zero-native/confirmation/report.json",
                     "from-zero-native-host/controller-result.json"]
        elif kind == "fresh":
            names = ["fresh-service/manifest.json", "fresh-service/original/report.json",
                     "fresh-service/fresh/report.json", "fresh-service-host/controller-result.json"]
        else:
            names = ["results.json", "artifact-files.json", "binary-before.json",
                     "source-before-campaigns.json", "source-after-native.json",
                     "resource-before-build.json", "resource-after-native.json"]
            for number in (1, 2, 3):
                names += [f"run-{number}-raw/report.json", f"run-{number}-phase-readback.json",
                          f"run-{number}-result.json", f"run-{number}.step.json",
                          f"run-{number}.stderr.log", f"run-{number}.stdout.log",
                          f"run-{number}-source-after.json", f"run-{number}-resource-before.json",
                          f"run-{number}-resource-after.json"]
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for name in names:
                data = archive.read(name)
                key = kind + "/" + name
                raw_records[key] = data
                if name.endswith(".json"):
                    documents[key] = json.loads(data)

    confirmation = []
    for key in ("protocol/from-zero-native/confirmation/report.json",
                "fresh/fresh-service/original/report.json", "fresh/fresh-service/fresh/report.json"):
        report = documents[key]
        phases = []
        for phase in report["phases"]:
            replays = phase["independent_history_page_replay"]
            phases.append({
                "mode": phase["mode"], "original_window_ns": phase["requested_window_ns"],
                "confirmed_transactions": phase["client_confirmed_transactions"],
                "confirmed_before_original_window_end": phase["client_confirmed_before_original_window_end"],
                "confirmation_ended_ns": phase["confirmation_ended_ns"],
                "verification_errors": phase["verification_errors"],
                "submissions": len(phase["honest_submissions"]),
                "submission_statuses": [row.get("status") for row in phase["honest_submissions"]],
                "history_calls": len(phase["honest_history"]),
                "history_replays": [{k: row[k] for k in ("history_call_index", "replay_accepted",
                                      "replay_ended_ns", "replay_error")} for row in replays],
            })
        confirmation.append({"raw_path": key, "finite_target_met": report["finite_target_met"], "phases": phases})

    campaigns = []
    for number in (1, 2, 3):
        key = f"campaign/run-{number}-raw/report.json"
        report = documents[key]
        retained = documents[f"campaign/run-{number}-phase-readback.json"]
        if retained["input"]["sha256"] != sha(raw_records[key]):
            raise ValueError("phase report pin differs")
        phases = []
        for phase in retained["phases"]:
            totals = {}
            for row in phase["client_history_import_observations"]["records"]:
                native = row["client_import"].get("native_import_observation") or {}
                for packet in native.get("packets", []):
                    for span in packet.get("phases", []):
                        if span.get("completed") is True and type(span.get("thread_cpu_ns")) is int:
                            item = totals.setdefault(span["phase"], {"completed_spans_with_known_cpu": 0,
                                                                     "thread_cpu_ns": 0, "wall_ns": 0})
                            item["completed_spans_with_known_cpu"] += 1
                            item["thread_cpu_ns"] += span["thread_cpu_ns"]
                            item["wall_ns"] += span["wall_ns"]
            phases.append({
                "mode": phase["mode"], "window_seconds": phase["window_seconds"],
                "scheduled_confirmation_rounds": phase["scheduled_confirmation_rounds"],
                "observed_confirmation_rounds": phase["observed_confirmation_rounds"],
                "confirmed_rounds": phase["confirmed_rounds"],
                "confirmation_rounds": phase["confirmation_rounds"],
                "finite_phase_criteria_met": phase["native_phase_criteria_met"],
                "actor_reports_successful_without_cap_or_kill": phase["actor_reports_successful_without_cap_or_kill"],
                "attacker_processes_ready": phase["attacker_processes_ready"],
                "attacker_processes_requested": phase["attacker_processes_requested"],
                "genuine_budget_depletion_observed": phase["genuine_budget_depletion_observed"],
                "receiver_client_state_equal": phase["receiver_client_state_equal"],
                "native_verifier_errors": phase["native_verifier_errors"],
                "submission_status_counts": phase["submissions"]["status_counts"],
                "history_calls": phase["history"]["attempts"],
                "history_call_wall_ns": phase["history"]["elapsed_wall_ns"]["sum_known_ns"],
                "completed_packet_phase_measurements": totals,
            })
        campaigns.append({"number": number, "raw_path": key,
                          "finite_experiment_criteria_met": report["finite_experiment_criteria_met"],
                          "state_backend": report["state_backend"],
                          "actual_signed_seed_transfers": report["preparation"]["actual_signed_seed_transfers"],
                          "business_blocks": report["preparation"]["business_blocks"], "phases": phases})

    source = documents["campaign/source-before-campaigns.json"]
    if source["tested_commit"] != HEAD or source["tested_tree"] != TREE:
        raise ValueError("unexpected measured source")
    if source != documents["campaign/source-after-native.json"]:
        raise ValueError("campaign source changed")
    summary = {"schema": "TRNM-W1-C3-CI-DIAGNOSTIC-READBACK1", "measured_head": HEAD,
               "measured_tree": TREE, "artifacts": artifacts, "confirmation_reports": confirmation,
               "campaigns": campaigns, "manifest_failures": {
                   "protocol": documents["protocol/from-zero-native/manifest.json"]["failures"],
                   "fresh": documents["fresh/fresh-service/manifest.json"]["failures"]},
               "scope": {"new_native_campaigns": 0, "new_proofs": 0, "current_source_qualification": False,
                         "deployment_wan_measured": False, "causal_speedup_established": False,
                         "population_tail_established": False, "production_qualified": False,
                         "phase_intervals_are_inclusive_and_must_not_be_added_across_names": True,
                         "cpu_is_calling_thread_only_not_full_process_tree": True,
                         "completed_known_spans_exclude_unknown_and_unfinished_spans": True,
                         "retained_phase_readback_is_a_CI_derivation_not_an_independent_attestation": True}}
    args.out.mkdir(parents=True, exist_ok=False)
    with (args.out / "raw.tar.gz").open("xb") as out:
        with gzip.GzipFile(fileobj=out, filename="", mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|") as archive:
                for name, raw in sorted(raw_records.items()):
                    entry = tarfile.TarInfo(name)
                    entry.size, entry.mode, entry.mtime = len(raw), 0o644, 0
                    archive.addfile(entry, io.BytesIO(raw))
    for name, value in (("summary.json", summary), ("raw-manifest.json", {
            "scope": "exact allowlisted bytes from the pinned complete ZIPs; no database or binary payloads",
            "files": [{"path": name, "bytes": len(raw), "sha256": sha(raw)} for name, raw in sorted(raw_records.items())],
            "archive_sha256": sha((args.out / "raw.tar.gz").read_bytes())})):
        with (args.out / name).open("x") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
    print(json.dumps({"retained_raw_records": len(raw_records), "native_campaigns_read": len(campaigns),
                      "native_campaigns_passed": sum(row["finite_experiment_criteria_met"] is True for row in campaigns),
                      "new_native_campaigns": 0, "new_proofs": 0, "production_qualified": False}))


if __name__ == "__main__":
    main()
