#!/usr/bin/env python3
"""Re-read immutable native reports and consume the actual pinned 06 interface.

Inputs are archived executions, not new experiments. All output directories are
new: no previous raw record, reader, input contract or result is overwritten.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

import native_reader_v2 as v2

VERSION = "sp27-02-collector-analysis-v2"
PAIR = {
    "key": "ci-43052900246-13871459353", "run_id": 43052900246,
    "job_id": 130634539770, "artifact_id": 13871459353,
    "source_commit": "8ebcdb01016946a131f9067ebe1ace39b9c4f260",
    "source_tree": "1b887f5fe57c6c3875ad28b8cc26bd83a8f77b83",
    "zip_bytes": 8297569,
    "zip_sha256": "8b21d753e0ac85ffdca7bc3e0a5f953d4dfffb24c7a10cc9ae394dcfe6590307",
    "report_member": "from-zero-native/confirmation/report.json",
    "report_sha256": "4a4ec5d92810f51df792a2f1f08e4af4c9cb47c107c5ed3e3a8e2ef71dae9a1d",
    "binary_member": "from-zero-native/public_v3_from_zero",
    "binary_sha256": "03d0dada775a2531876ce796192b59d27d78f86848e053de554ee70e281eb387",
}
CORPUS_SHA256 = "a95d5051d117adfec54bc1d6d47e04f851504234344c0cc076fd57607de3e7a0"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def jsonl(rows):
    return b"".join((json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False)
                     + "\n").encode() for row in rows)


def source_digests():
    paths = ["native_reader_v2.py", "consume_native_v2.py", "test_native_reader_v2.py",
             "frozen/legacy_reader_v1.py", "frozen/analyzer_06_v1.py",
             "frozen/exporter_06_v1.py", "frozen/CONTRACT_06_V1.md"]
    return {p: {"bytes": (v2.HERE / p).stat().st_size,
                "sha256": sha((v2.HERE / p).read_bytes())} for p in paths}


def write_consumed(export, out, experiment_id, audit, input_identity):
    """The real consumer, not a handwritten summary, determines every outcome."""
    v2.require(not out.exists(), "OUTPUT_ALREADY_EXISTS")
    contract = {
        "schema": "sp27-confirmed-goodput-contract-v1",
        "collector_analysis_contract_version": VERSION,
        "evidence_scope": "archival_reanalysis", "experiment_id": experiment_id,
        "runs": export.runs, "new_native_experiments": 0,
        "joint_freeze_status": "current_02_measurement_consumer_executed; prior_Agent06_human_ack_not_observed",
        "shared_with_sp27_02": True,
        "input_identity": input_identity,
    }
    analyzer = v2.load_frozen("analyzer")
    consumed = analyzer.analyze(contract, export.schedule, export.events)
    out.mkdir(parents=True, exist_ok=False)
    for name, data in [("contract.json", canonical(contract)),
                       ("schedule.jsonl", jsonl(export.schedule)),
                       ("events.jsonl", jsonl(export.events)),
                       ("native_boundary_audit.json", canonical(audit))]:
        (out / name).write_bytes(data)
    inputs = [out / name for name in ["contract.json", "schedule.jsonl", "events.jsonl"]]
    analyzer.write_outputs(consumed, out / "consumer", inputs)
    receipt = {
        "schema": "sp27-02-consumer-receipt-v2", "experiment_id": experiment_id,
        "reader_version": v2.VERSION, "collector_analysis_contract_version": VERSION,
        "upstream_papers_commit": "c49c769fb3b08ee8f60c993c8ca6be2a4600246f",
        "actual_consumer_executed": True, "native_experiments_executed": 0,
        "input_identity": input_identity, "source_files": source_digests(),
        "input_files": {p.name: {"bytes": p.stat().st_size, "sha256": sha(p.read_bytes())} for p in inputs},
        "consumer_result_sha256": sha((out / "consumer" / "summary.json").read_bytes()),
        "phase_runs": len(consumed["runs"]), "planned_operations": len(consumed["operations"]),
        "outcomes": dict(Counter(o["outcome"] for o in consumed["operations"])),
        "confirmed_operations": sum(o["confirmed_in_window"] for o in consumed["operations"]),
        "phase_counts": [{"run_id": r["run_id"], "planned": r["planned_operations"],
                          "confirmed": r["confirmed_operations"]} for r in consumed["runs"]],
        "no_statistical_pooling": True, "no_native_crypto_reexecution": True,
        "prior_Agent06_acknowledgement": "NOT_OBSERVED",
        "coordinator_acceptance": "NOT_OBSERVED",
        "current_measurement_reviewer": "/root/measurement_contract",
        "source_endpoint_agreement": "strict endpoint < T AND preserved native final gate",
    }
    (out / "CONSUMER_RECEIPT.json").write_bytes(canonical(receipt))
    print(json.dumps({k: receipt[k] for k in ["experiment_id", "phase_runs", "planned_operations",
                                             "confirmed_operations", "outcomes", "consumer_result_sha256"]}, sort_keys=True))
    return receipt


def audit_endpoints(records):
    audited = []
    for record in records:
        decision = v2.window_decision(record["observation"], record["endpoint_ns"],
                                      record["window_ns"], record["native_gate"])
        old_time_predicate = bool(record["observation"] and
                                  record["observation"].get("confirmed") is True and
                                  v2.integer(record["endpoint_ns"]) and
                                  record["endpoint_ns"] <= record["window_ns"])
        audited.append({k: value for k, value in record.items() if k != "observation"} | {
            "decision": decision, "v1_timestamp_predicate": old_time_predicate,
            "v1_assertion_would_refuse": record["native_gate"] is not None
                and old_time_predicate != record["native_gate"],
            "credit_differs": old_time_predicate != decision["confirmed_in_window"],
        })
    return {
        "schema": "sp27-02-raw-endpoint-audit-v2", "recorded_attempts": len(audited),
        "positive_observations": sum(x["decision"]["observed_confirmed"] is True for x in audited),
        "endpoints_exactly_T": sum(x["endpoint_ns"] == x["window_ns"] for x in audited),
        "positive_endpoint_below_T_native_gate_false": sum(
            x["decision"]["observed_confirmed"] is True and
            x["decision"]["endpoint_before_window_end"] is True and
            x["decision"]["native_window_gate"] is False for x in audited),
        "legacy_timestamp_credit_discrepancies": sum(x["credit_differs"] for x in audited),
        "unknown_native_gates": sum(x["native_gate"] is None for x in audited),
        "records": audited,
    }


def consume_pair(path, out):
    lib, exporter = v2.get_reader(), v2.load_frozen("exporter")
    lib.ARCHIVES[PAIR["key"]] = (path.name, PAIR["zip_bytes"], PAIR["zip_sha256"], PAIR["source_commit"])
    archive = lib.Archive(PAIR["key"], path)
    manifest = archive.read("from-zero-native/manifest.json")
    before = manifest["source_before"]["tracked_source_identity"]
    after = manifest["source_after"]["tracked_source_identity"]
    for identity in (before, after):
        v2.require(identity["tested_commit"] == PAIR["source_commit"]
                   and identity["tested_tree"] == PAIR["source_tree"]
                   and identity["tracked_worktree_verified"] is True, "CI_SOURCE_IDENTITY")
    binary_sha = sha(archive.raw(PAIR["binary_member"]))
    v2.require(binary_sha == manifest["binary_sha256_before"] == manifest["binary_sha256_after"]
               == PAIR["binary_sha256"], "CI_BINARY_IDENTITY")
    report = archive.read(PAIR["report_member"])
    v2.require(archive.reads[PAIR["report_member"]]["sha256"] == PAIR["report_sha256"], "CI_REPORT_IDENTITY")
    v2.require(report["schema"] == "public-v3-signed-confirmation-pressure-v1", "CI_REPORT_SCHEMA")
    v2.require(report["same_packet_sequence_in_both_runs"] is True, "CI_SAME_PACKETS")
    v2.require([p["mode"] for p in report["phases"]] == ["attack-free-baseline", "from-zero-pressure"], "CI_RETAINED_ORDER")
    packets = [lib.decode_packet_fields(x) for x in report["signed_honest_packets"]]
    v2.require([len(x["transactions"]) for x in packets] == [1, 0, 0, 0, 0, 0, 0], "CI_SIGNED_DENOMINATOR")
    transaction = lib.wire_hash(b"tx-id", bytes.fromhex(packets[0]["transactions"][0]))
    v2.require(len({p["initial_tip"] for p in report["phases"]}) == 1
               and len({p["initial_state_root"] for p in report["phases"]}) == 1, "CI_INITIAL_STATE")
    host_before = archive.read("from-zero-native-host/inside-before.json")
    host_after = archive.read("from-zero-native-host/inside-after.json")
    controller = archive.read("from-zero-native-host/controller-result.json")
    child = archive.read("from-zero-native-host/child-result.json")
    v2.require(host_before["read_errors"] == host_after["read_errors"] == {}, "CI_HOST_READ_ERRORS")
    v2.require(child["host_errors"] == [] and controller["final_host_errors"] == [], "CI_HOST_ERRORS")
    export = exporter.Export()
    records, phase_readbacks = [], []
    identity = {"source_before": before, "source_after": after, "binary_sha256": binary_sha}
    legacy = v2.get_reader(version=1)
    for i, phase in enumerate(report["phases"]):
        observation = phase.get("independent_client_confirmation")
        if observation:
            v2.require(observation["transaction"] == transaction
                       and observation["included_block"] == packets[0]["id"], "CI_PREPARED_BINDING")
            v2.require(observation["depth"] >= 6 and int(observation["work_delta"], 16)
                       >= int(observation["required_work_delta"], 16), "CI_DEPTH_WORK")
        row = lib.pair_phase(archive, PAIR["report_member"], phase, i, "confirmation")
        old_row = legacy.pair_phase(archive, PAIR["report_member"], phase, i, "confirmation")
        row.update(prepared_transaction_id=transaction, prepared_packet_ids=[p["id"] for p in packets])
        export.pair_phase(lib, archive, PAIR["report_member"], report, row, identity)
        metadata = export.runs[-1]["metadata"]
        metadata.update(ci_run_id=PAIR["run_id"], ci_job_id=PAIR["job_id"], ci_artifact_id=PAIR["artifact_id"],
                        collector_analysis_contract_version=VERSION, original_pair_phase_index=i,
                        original_phase_order=[p["mode"] for p in report["phases"]],
                        randomized_order=False, exclusive_resources_established=False,
                        host_before=host_before, host_after=host_after,
                        host_child_errors=child["host_errors"], host_controller_errors=controller["final_host_errors"],
                        causal_mechanism_established=False, previous_local_failure_verified=False)
        records.append({"artifact_sha256": PAIR["zip_sha256"], "member": PAIR["report_member"],
                        "pointer": "/phases/" + str(i), "endpoint_ns": phase["confirmation_ended_ns"],
                        "window_ns": phase["requested_window_ns"],
                        "native_gate": phase["client_confirmed_before_original_window_end"],
                        "observation": observation})
        phase_readbacks.append({"mode": phase["mode"], "v1_count": old_row["confirmed_in_window"],
                                "v2_count": row["confirmed_in_window"], "reader_v2": row})
    audit = audit_endpoints(records)
    audit.update(batch="new_ci_pair_separate_from_historical_corpus", retained_order="baseline_then_pressure",
                 randomized=False, phase_readbacks=phase_readbacks)
    input_identity = dict(PAIR)
    input_identity["archive_read_members"] = archive.reads
    receipt = write_consumed(export, out, PAIR["key"], audit, input_identity)
    archive.z.close()
    return receipt


def consume_corpus(directory, out):
    capsule = directory / "native_originals.tar.xz"
    v2.require(capsule.is_file(), "RAW_CAPSULE_MISSING: historical-corpus raw audit UNKNOWN")
    v2.require(sha(capsule.read_bytes()) == CORPUS_SHA256, "RAW_CAPSULE_DIGEST")
    exporter = v2.load_frozen("exporter")
    old = exporter.from_capsule(v2.get_reader(version=1), directory)
    new = exporter.from_capsule(v2.get_reader(version=2), directory)
    # This comparison uses full re-derived events. No summary file is an input.
    v2.require(old.runs == new.runs and old.schedule == new.schedule and old.events == new.events,
               "OLD_CORPUS_SEMANTICS_CHANGED: preserve both outputs and investigate")
    records = []
    for run in new.runs:
        metadata = run["metadata"]
        member = metadata["report_member"]
        report = exporter.strict_json(new.members[metadata["archive_key"] + "/" + member])
        index = next(i for i, p in enumerate(report["phases"]) if p["mode"] == metadata["mode"])
        phase = report["phases"][index]
        if "requested_window_ns" in phase:
            records.append({"artifact_sha256": metadata["zip_sha256"], "member": member,
                            "pointer": "/phases/" + str(index), "endpoint_ns": phase["confirmation_ended_ns"],
                            "window_ns": phase["requested_window_ns"],
                            "native_gate": phase["client_confirmed_before_original_window_end"],
                            "observation": phase.get("independent_client_confirmation")})
        else:
            for j, attempt in enumerate(phase["confirmations"]):
                records.append({"artifact_sha256": metadata["zip_sha256"], "member": member,
                                "pointer": f"/phases/{index}/confirmations/{j}",
                                "endpoint_ns": attempt["ended_ns"], "window_ns": run["window_end_ns"],
                                "native_gate": attempt["confirmed_inside_pressure_window"],
                                "observation": attempt.get("observation")})
    audit = audit_endpoints(records)
    audit.update(all_retained_raw_members_rehashed=True, v1_v2_rederived_events_equal=True,
                 original_zip_and_binary_bytes_rehashed_this_run=False,
                 raw_capsule_scope="53 retained report/source/identity members; not original ZIPs/databases/binaries",
                 missing_original_binary_or_zip_bytes_do_not_become_present=True)
    for run in new.runs:
        run["metadata"]["collector_analysis_contract_version"] = VERSION
    identity = {"native_originals_tar_xz_sha256": CORPUS_SHA256,
                "capsule_bytes": capsule.stat().st_size,
                "input_manifest_sha256": sha((directory / "input_manifest.json").read_bytes()),
                "original_members_sha256": sha((directory / "original_members.json").read_bytes()),
                "raw_report_capsule_reanalysis": True,
                "original_zip_and_binary_bytes_rehashed_this_run": False}
    return write_consumed(new, out, "historical-35-phase-corpus-v2-reanalysis", audit, identity)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    pair = sub.add_parser("ci-pair")
    pair.add_argument("--zip", type=Path, required=True)
    pair.add_argument("--out", type=Path, required=True)
    corpus = sub.add_parser("historical-corpus")
    corpus.add_argument("--inputs", type=Path, required=True)
    corpus.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "ci-pair":
        consume_pair(args.zip, args.out)
    else:
        consume_corpus(args.inputs, args.out)


if __name__ == "__main__":
    main()
