#!/usr/bin/env python3
"""New campaign adapter to the immutable SP27-06 analyzer, never a raw writer.

Packet decoding binds identities only. Native verification is not reexecuted by
Python; positive observations retain the native path's explicit attestation.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
VERSION = "sp27-02-strata-analysis-v1"
WINDOW_NS = 4_000_000_000
READER_SHA256 = "e9d49be7d060d71c4b13ef43b32568028f26fdc6e737587fc47a78457a8c1a28"
ANALYZER_SHA256 = "9719f822394e6295a7787be0be2c8d394d25ab19e8d17be543e4145f6bae9acc"
RUNNER_SHA256 = "7b7437402b19d63e22e48174ce0c24a63c8e0de8272ad2597ea7f268cc751653"


def require(value, code):
    if not value:
        raise ValueError(code)


def unsigned(value):
    return type(value) is int and value >= 0


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_module(path, name, expected=None):
    if expected is not None:
        require(digest(path.read_bytes()) == expected, "SOURCE_DIGEST:" + name)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def reader():
    return load_module(HERE.parent / "reader_v2/native_reader_v2.py",
                       "sp27_strata_frozen_window_v2", READER_SHA256)


def source_digests():
    paths = [HERE / "adapter.py", HERE / "CONTRACT.md",
             HERE.parent / "audit_strata_ci.py", ROOT / "scripts/ci/run_sp27_strata_controls.py",
             HERE.parent / "reader_v2/native_reader_v2.py",
             HERE.parent / "reader_v2/frozen/analyzer_06_v1.py"]
    return {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in paths}


def business_identity(acquisition):
    """Decode retained packets; this function makes no cryptographic claim."""
    require(type(acquisition) is dict, "PREPARED_BUSINESS_MISSING")
    require(acquisition.get("schema") == "sp27-receiver-seven-packet-acquisition-v1",
            "PREPARED_BUSINESS_SCHEMA")
    packets = acquisition.get("signed_honest_packets")
    require(type(packets) is list and len(packets) == 7, "PREPARED_SEVEN_PACKETS")
    lib = reader().load_frozen("legacy")
    decoded = [lib.decode_packet_fields(packet) for packet in packets]
    require([len(row["transactions"]) for row in decoded] == [1, 0, 0, 0, 0, 0, 0],
            "PREPARED_ONE_SIGNED_TRANSACTION")
    require(acquisition.get("packet_ids") == [row["id"] for row in decoded],
            "PREPARED_PACKET_ID_BINDING")
    return {"transaction_id": lib.wire_hash(b"tx-id", bytes.fromhex(decoded[0]["transactions"][0])),
            "expected_block_id": decoded[0]["id"], "packet_ids": acquisition["packet_ids"],
            "cryptography_reexecuted_by_python": False}


def positive_observation(raw, prepared_identity, phase_index):
    """Validate a recorded positive endpoint before exposing native attestations."""
    obs = raw.get("independent_client_confirmation")
    if obs is None or obs.get("confirmed") is not True:
        return None
    require(obs.get("transaction") == prepared_identity["transaction_id"]
            and obs.get("included_block") == prepared_identity["expected_block_id"],
            "POSITIVE_PREPARED_TRANSACTION_BLOCK_BINDING")
    require(obs.get("policy") == "installed-depth-and-required-work"
            and obs.get("execution_authority") is False and obs.get("finalized") is False
            and obs.get("reorged") is False and type(obs.get("depth")) is int and obs["depth"] == 6,
            "POSITIVE_OBSERVATION_POLICY")
    require(type(obs.get("required_work_delta")) is str and type(obs.get("work_delta")) is str
            and int(obs["required_work_delta"], 16) == 12 and int(obs["work_delta"], 16) >= 12,
            "POSITIVE_WORK_POLICY")
    final = raw.get("independent_final_confirmation_stage")
    require(type(final) is dict and final.get("observation_returned") is True
            and unsigned(final.get("confirmation_started_ns"))
            and unsigned(final.get("confirmation_ended_ns"))
            and unsigned(raw.get("confirmation_ended_ns"))
            and final["confirmation_started_ns"] <= final["confirmation_ended_ns"]
            <= raw["confirmation_ended_ns"], "POSITIVE_INDEPENDENT_FINAL_STAGE")
    imports = raw.get("independent_history_page_replay")
    require(type(imports) is list and imports and all(
        type(row) is dict and row.get("replay_accepted") is True
        and row.get("replay_error") is None
        and type(row.get("native_import_observation")) is dict for row in imports),
        "POSITIVE_INDEPENDENT_NATIVE_IMPORT")
    require(phase_index.get("host_before_verified") is True
            and phase_index.get("host_after_verified") is True, "POSITIVE_PHASE_HOST_ATTESTATION")
    return obs


def build_export(plan, report, phases, acquisition, prepared, raw_identities,
                 strict_reader_passed, experiment_id, synthetic=False):
    """Import all planned phases only after the existing strict reader accepts.

`phases` and `raw_identities` map phase IDs to original parsed records and their
file observations. Unstarted phases are explicit events, not invented starts.
"""
    require(strict_reader_passed is True, "STRICT_CAMPAIGN_READER_REQUIRED")
    require(type(plan) is list and len(plan) == 13
            and type(report.get("phases")) is list, "CAMPAIGN_PLAN_REQUIRED")
    identity = business_identity(acquisition)
    v2 = reader()
    runs, schedule, events, decisions = [], [], [], []
    recorded = {row["phase_id"]: row for row in report["phases"]}
    require(len(recorded) == len(report["phases"]), "DUPLICATE_PHASE")
    source = prepared["source_before"]

    def event(run, kind, oid=None, at=None, **fields):
        row = {"event_id": run["run_id"] + "/event-" + str(len(events)),
               "run_id": run["run_id"], "operation_id": oid, "type": kind,
               "at_ns": at, "clock_id": run["clock_id"], "actor_id": run["observer_id"],
               "attempt_id": oid + "/attempt-0" if oid else None}
        row.update(fields)
        events.append(row)

    for planned in plan:
        phase_id = planned["phase_id"]
        rid = experiment_id + "/" + phase_id
        row = recorded.get(phase_id)
        raw = phases.get(phase_id)
        run = {"run_id": rid, "chain_instance_id": rid + "/fresh-native-ledger",
               "profile_id": "strata/" + (planned.get("arm") or planned["kind"]),
               "clock_id": rid + "/original-traffic-epoch",
               "observer_id": rid + "/independent-native-verifier",
               "window_start_ns": 0, "window_end_ns": WINDOW_NS,
               "confirmation_policy": {"policy_id": "installed-depth-and-required-work",
                   "min_depth": 6, "required_work_delta": "0c", "semantics": "first_observed",
                   "window_end_rule": "exclusive", "require_native_window_gate": True},
               "identity": {"source_commit": source.get("commit"), "source_tree": source.get("tree"),
                   "binary_sha256": prepared.get("binary", {}).get("sha256"), "config_sha256": None},
               "event_coverage_complete": False, "resource_inventory_complete": False, "recovery": None,
               "metadata": {"adapter_version": VERSION, "planned_index": planned["planned_index"],
                   "native_phase_id": phase_id, "campaign_qualification": report["qualification"],
                   "native_phase_attempted": row is not None,
                   "native_phase_completed": row.get("completed") if row else False,
                   "business_schedule_timestamp_missing": True,
                   "control_arrival_is_not_business_arrival": True,
                   "prospective_registration": False, "config_freeze_complete": False,
                   "cryptography_reexecuted_by_python": False,
                   "source_path_attestation": "compiled native independent replay and confirmation path",
                   "causal_mechanism_status": "UNKNOWN"}}
        runs.append(run)
        oid = rid + "/business-operation-0"
        schedule.append({"operation_id": oid, "run_id": rid, "scheduled_ns": None,
                         "deadline_ns": WINDOW_NS, "transaction_ids": [identity["transaction_id"]],
                         "expected_block_id": identity["expected_block_id"],
                         "content_id": "signed-transaction-digest:" + identity["transaction_id"],
                         "useful_compute_id": None, "useful_compute_evidence": None,
                         "plan_provenance": "native/plan.json and native/business-acquisition.json; "
                             "one prepared business transaction per original four-second phase; "
                             "no exact business scheduled timestamp retained"})
        if row is None:
            event(run, "not_started", oid, reason="validated campaign stopped before this planned phase")
            decisions.append({"phase_id": phase_id, "status": "UNSTARTED", "window_decision": None})
            continue
        if raw is None:
            event(run, "unknown", oid, reason="attempted phase has no complete original raw phase record")
            decisions.append({"phase_id": phase_id, "status": "ATTEMPTED_INCOMPLETE", "window_decision": None})
            continue
        require(row.get("completed") is True, "RAW_WITHOUT_COMPLETED_INDEX")
        start = raw.get("business_started_ns")
        require(unsigned(start), "BUSINESS_START_MISSING")
        event(run, "request_start", oid, start)
        decision = v2.window_decision(raw.get("independent_client_confirmation"),
                                     raw.get("confirmation_ended_ns"), WINDOW_NS,
                                     raw.get("client_confirmed_before_original_window_end"))
        decisions.append({"phase_id": phase_id, "status": "RECORDED", "window_decision": decision})
        obs = positive_observation(raw, identity, row)
        if obs is not None:
            observed = raw_identities[phase_id]
            event(run, "confirmation", oid, raw["confirmation_ended_ns"],
                  transaction_id=obs["transaction"], block_id=obs["included_block"],
                  policy_id=obs["policy"], depth=obs["depth"], work_delta=obs["work_delta"],
                  required_work_delta=obs["required_work_delta"], execution_authority=False,
                  native_window_gate=raw["client_confirmed_before_original_window_end"],
                  flags={key: True for key in ("full_verification", "admission", "host", "history", "activation")},
                  flags_provenance="native independent replay/confirmation path attestation; "
                      "prepared identity, replay, final-stage and phase Host checks retained; "
                      "not independent Python cryptographic verification",
                  provenance={"artifact_sha256": observed["sha256"],
                              "artifact_identity_scope": "individual unchanged raw phase file",
                              "member": observed["member"], "pointer": "/independent_client_confirmation"})
        # No implicit zeros: absence of a resource field yields no resource event.
        for field, owner in (("reader_cpu_ns", "business-reader-thread"),
                             ("independent_replay_and_confirmation_cpu_ns", "independent-replay-caller-thread"),
                             ("attacker_workers_cpu_ns", "control-worker-total")):
            if unsigned(raw.get(field)):
                event(run, "resource", metric="cpu_ns", value=raw[field], owner_id=owner,
                      scope="whole_lifecycle", inclusive=False, coverage="partial",
                      started_ns=None, ended_ns=None, native_field=field,
                      whole_span_only=True, not_exact_original_window_cost=True)
    contract = {"schema": "sp27-confirmed-goodput-contract-v1",
                "collector_analysis_contract_version": VERSION,
                "evidence_scope": "synthetic_validation" if synthetic else "archival_reanalysis",
                "experiment_id": experiment_id, "runs": runs, "new_native_experiments": 0,
                "planned_campaign_phases": len(plan), "campaign_qualification": report["qualification"],
                "mechanism_status": "UNKNOWN", "pool_with_other_batches": False,
                "estimated_full_lifecycle_cost": None, "statistical_significance_claimed": False}
    analyzed = v2.load_frozen("analyzer").analyze(contract, schedule, events)
    operations = {row["run_id"].rsplit("/", 1)[1]: row for row in analyzed["operations"]}
    for decision in decisions:
        if decision["window_decision"] is not None:
            require(operations[decision["phase_id"]]["confirmed_in_window"]
                    == decision["window_decision"]["confirmed_in_window"], "FROZEN_CONSUMER_WINDOW_DISAGREEMENT")
    return {"contract": contract, "schedule": schedule, "events": events,
            "decisions": decisions, "analyzed": analyzed, "prepared_business_identity": identity}


def write_export(export, out):
    out.mkdir(parents=True, exist_ok=False)
    for name in ("contract", "decisions", "prepared_business_identity"):
        (out / (name + ".json")).write_bytes(canonical(export[name]))
    for name in ("schedule", "events"):
        (out / (name + ".jsonl")).write_text("".join(
            json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
            for row in export[name]))
    reader().load_frozen("analyzer").write_outputs(export["analyzed"], out / "consumer",
        [str(out / (name + extension)) for name, extension in
         (("contract", ".json"), ("schedule", ".jsonl"), ("events", ".jsonl"))])
