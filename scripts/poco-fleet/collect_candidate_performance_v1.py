#!/usr/bin/env python3
"""Derive bounded performance facts from one real candidate fleet run.

This collector consumes the output of ``run_consensus_fleet.py``.  It never
creates validator observations and never turns a candidate run into G3 or
production evidence.  All rates are derived from the signed observer
summaries and the coordinator's monotonic process interval; transaction TPS,
independent recovery, host attestation, and acceptance remain explicitly
unavailable until their own authorities supply evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import pathlib
import re
import sys
import tomllib
from typing import Any

import native_client_campaign_v1 as native_campaign


HERE = pathlib.Path(__file__).resolve().parent
INVENTORY = HERE / "inventory.toml"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RUN_ID = re.compile(r"^poco-g3-(7|31|100)-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ARTIFACTS = 16_384


def fail(message: str) -> None:
    raise SystemExit(f"candidate performance evidence invalid: {message}")


def read_json(path: pathlib.Path, field: str) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                fail(f"{field} contains duplicate JSON key {key!r}")
            value[key] = child
        return value

    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or metadata.st_size <= 0:
            fail(f"{field} must be one regular non-symlink file")
        if metadata.st_size > MAX_JSON_BYTES:
            fail(f"{field} exceeds its byte bound")
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read {field}: {error}")
    if not isinstance(value, dict):
        fail(f"{field} must be one JSON object")
    return value


def sha256_file(path: pathlib.Path, field: str) -> str:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or metadata.st_size <= 0:
            fail(f"{field} must be one regular non-symlink file")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as error:
        fail(f"cannot hash {field}: {error}")


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_new(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = path.open("xb")
    try:
        descriptor.write(canonical_json(value))
        descriptor.flush()
    finally:
        descriptor.close()


def hex_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        fail(f"{field} must be canonical sha256")
    return value


def positive_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"{field} must be a positive integer")
    return value


def inventory_digest() -> str:
    return hashlib.sha256(INVENTORY.read_bytes()).hexdigest()


def topology_digest(validators: list[dict[str, Any]]) -> str:
    projected = [
        {
            "validator_id": item["validator_id"],
            "host_id": item["host_id"],
            "management": item.get("management"),
        }
        for item in sorted(validators, key=lambda row: row["validator_id"])
    ]
    return hashlib.sha256(canonical_json(projected)).hexdigest()


def collect(run_root: pathlib.Path) -> dict[str, Any]:
    summary = read_json(run_root / "consensus-run-summary.json", "run summary")
    plan = read_json(run_root / "prestart-plan.json", "prestart plan")
    lifecycle = read_json(run_root / "runner-lifecycle.json", "runner lifecycle")
    run_id = summary.get("run_id")
    if not isinstance(run_id, str) or RUN_ID.fullmatch(run_id) is None:
        fail("run summary run_id is not canonical")
    if plan.get("run_id") != run_id or lifecycle.get("run_id") != run_id:
        fail("run, prestart plan, and lifecycle run_id differ")
    validator_count = positive_int(summary.get("validator_count"), "validator_count")
    if validator_count not in {7, 31, 100}:
        fail("validator_count is outside the supported topology")
    if summary.get("failure") is not None:
        fail("candidate run has a failure; incomplete output cannot be measured")
    processes = summary.get("processes")
    if not isinstance(processes, list) or len(processes) != validator_count:
        fail("run summary process cardinality differs from validator_count")
    if len(processes) > MAX_ARTIFACTS:
        fail("process cardinality exceeds bound")

    anchor = hex_digest(summary.get("coordinator_manifest_sha256"), "coordinator anchor")
    if plan.get("coordinator_manifest_sha256") != anchor:
        fail("prestart plan does not bind coordinator anchor")
    if summary.get("production_activation") is not False:
        fail("candidate run crosses production activation boundary")
    if summary.get("g3_lan_multihost_evidence") is not False:
        fail("candidate run already claims independent G3 evidence")

    lifecycle_events = lifecycle.get("events")
    if not isinstance(lifecycle_events, list):
        fail("runner lifecycle events are missing")
    event_by_kind: dict[str, dict[str, Any]] = {}
    for event in lifecycle_events:
        if not isinstance(event, dict) or not isinstance(event.get("kind"), str):
            fail("runner lifecycle event is malformed")
        if event["kind"] in event_by_kind:
            fail("runner lifecycle contains duplicate event kinds")
        event_by_kind[event["kind"]] = event
    launch = event_by_kind.get("validator_launch_completed")
    exited = event_by_kind.get("validator_processes_exited")
    if launch is None or exited is None:
        fail("runner lifecycle lacks process launch/exit interval")
    started_ns = positive_int(launch.get("monotonic_ns"), "launch monotonic_ns")
    ended_ns = positive_int(exited.get("monotonic_ns"), "exit monotonic_ns")
    if ended_ns <= started_ns:
        fail("process interval is not positive")
    measurement_seconds = (ended_ns - started_ns) / 1_000_000_000

    planned_validators = plan.get("validators")
    if not isinstance(planned_validators, list) or len(planned_validators) != validator_count:
        fail("prestart plan validator topology is missing")
    planned_by_id: dict[str, dict[str, Any]] = {}
    for item in planned_validators:
        if not isinstance(item, dict) or not isinstance(item.get("validator_id"), str):
            fail("prestart plan validator entry is malformed")
        if item["validator_id"] in planned_by_id:
            fail("prestart plan validator IDs are duplicated")
        planned_by_id[item["validator_id"]] = item

    report_rows: list[dict[str, Any]] = []
    source_digests: set[str] = set()
    topology_digests: set[str] = set()
    binary_digests: set[str] = set()
    config_digests: set[str] = set()
    host_ids: set[str] = set()
    committed_blocks: set[int] = set()
    finalized_heights: set[int] = set()
    finalized_blocks: set[int] = set()
    artifact_hashes: list[dict[str, Any]] = []
    observed_validator_ids: set[str] = set()
    for index, process in enumerate(processes):
        if not isinstance(process, dict):
            fail(f"process[{index}] is malformed")
        validator_id = process.get("validator_id")
        if not isinstance(validator_id, str) or HEX64.fullmatch(validator_id) is None:
            fail(f"process[{index}] validator_id is not canonical")
        if validator_id in observed_validator_ids:
            fail(f"process[{index}] repeats validator_id {validator_id}")
        observed_validator_ids.add(validator_id)
        verification = process.get("observer_report_verification")
        if not isinstance(verification, dict):
            fail(f"process[{index}] lacks observer report verification")
        for field in ("candidate_source_sha256", "topology_sha256", "binary_sha256", "config_sha256"):
            hex_digest(verification.get(field), f"{validator_id}.{field}")
        if verification.get("signature_verified") is not True or verification.get("semantics_verified") is not True:
            fail(f"{validator_id} report was not independently verified")
        if verification.get("validator_run_completed") is not True:
            fail(f"{validator_id} report does not prove completed candidate runtime")
        source_digests.add(verification["candidate_source_sha256"])
        topology_digests.add(verification["topology_sha256"])
        binary_digests.add(verification["binary_sha256"])
        config_digests.add(verification["config_sha256"])
        host_id = process.get("host_id")
        if not isinstance(host_id, str) or not host_id:
            fail(f"{validator_id} host_id is missing")
        host_ids.add(host_id)
        planned = planned_by_id.get(validator_id)
        if planned is None or planned.get("host_id") != host_id:
            fail(f"{validator_id} process host differs from prestart topology")
        committed_blocks.add(positive_int(verification.get("committed_ordinary_block_count"), f"{validator_id}.committed_ordinary_block_count"))
        finalized_heights.add(positive_int(verification.get("finalized_height"), f"{validator_id}.finalized_height"))
        finalized_blocks.add(positive_int(verification.get("finalized_ordinary_block_count"), f"{validator_id}.finalized_ordinary_block_count"))
        report_rows.append({"validator_id": validator_id, "host_id": host_id})
        artifact_paths = {
            "signed_report_sha256": run_root / "signed-reports" / f"{validator_id}.json",
            "signed_runtime_metrics_sha256": run_root / "signed-runtime-metrics" / f"{validator_id}.json",
            "signed_runtime_final_state_sha256": run_root / "signed-runtime-final-states" / f"{validator_id}.json",
            "signed_runtime_journal_sha256": run_root / "signed-runtime-journals" / f"{validator_id}.jsonl",
        }
        for role, artifact_path in artifact_paths.items():
            declared = hex_digest(process.get(role), f"{validator_id}.{role}")
            observed = sha256_file(artifact_path, f"{validator_id}.{role} artifact")
            if declared != observed:
                fail(f"{validator_id}.{role} hash differs from raw artifact")
            artifact_hashes.append({"validator_id": validator_id, "role": role, "sha256": observed})
        raw_report = read_json(artifact_paths["signed_report_sha256"], f"{validator_id} signed report")
        # Do not treat the metrics/final-state files as opaque byte blobs.  A
        # summary can carry a valid report hash while pairing it with a
        # different rehashed terminal artifact; those joins are the source of
        # every derived block-rate fact below.
        raw_metrics = read_json(
            artifact_paths["signed_runtime_metrics_sha256"],
            f"{validator_id} signed runtime metrics",
        )
        raw_final_state = read_json(
            artifact_paths["signed_runtime_final_state_sha256"],
            f"{validator_id} signed runtime final state",
        )
        raw_bindings = {
            "run_id": run_id,
            "validator_id": validator_id,
            "host_id": host_id,
            "coordinator_manifest_sha256": anchor,
            "candidate_source_sha256": verification["candidate_source_sha256"],
            "topology_sha256": verification["topology_sha256"],
            "binary_sha256": verification["binary_sha256"],
            "config_sha256": verification["config_sha256"],
            "committed_ordinary_block_count": verification["committed_ordinary_block_count"],
            "finalized_height": verification["finalized_height"],
            "finalized_ordinary_block_count": verification["finalized_ordinary_block_count"],
        }
        for field, expected in raw_bindings.items():
            if raw_report.get(field) != expected:
                fail(f"{validator_id} raw signed report {field} differs from observer verification")
        hex_digest(raw_report.get("report_sha256"), f"{validator_id}.report_sha256")
        if raw_report.get("production_activation") is not False or raw_report.get("g3_evidence_complete") is not False:
            fail(f"{validator_id} raw signed report crosses candidate boundary")
        for field, expected in {
            "run_id": run_id,
            "validator_id": validator_id,
            "validator_run_completed": True,
            "g3_evidence_complete": False,
            "geo_wan_evidence": False,
            "production_activation": False,
        }.items():
            if raw_metrics.get(field) != expected:
                fail(f"{validator_id} raw runtime metrics {field} differs from report context")
        for field in ("process_id", "process_instance_count", "ordinary_start_height", "fsync_count"):
            positive_int(raw_metrics.get(field), f"{validator_id}.runtime_metrics.{field}")
        samples = raw_metrics.get("finality_samples_ms")
        if not isinstance(samples, list) or not samples:
            fail(f"{validator_id} runtime metrics finality samples are missing")
        if any(
            isinstance(sample, bool)
            or not isinstance(sample, (int, float))
            or not math.isfinite(float(sample))
            or sample <= 0
            for sample in samples
        ):
            fail(f"{validator_id} runtime metrics finality samples are invalid")
        metrics_body_sha256 = hex_digest(
            raw_metrics.get("body_sha256"), f"{validator_id}.runtime_metrics.body_sha256"
        )
        if raw_metrics.get("consensus_report_sha256") != raw_report["report_sha256"]:
            fail(f"{validator_id} runtime metrics consensus report differs from signed report")
        final_context = {
            "run_id": run_id,
            "validator_id": validator_id,
            "finalized_height": verification["finalized_height"],
            "finalized_ordinary_block_count": verification["finalized_ordinary_block_count"],
            "validator_run_completed": True,
            "g3_evidence_complete": False,
            "geo_wan_evidence": False,
            "production_activation": False,
            "runtime_metrics_sha256": metrics_body_sha256,
            "consensus_report_sha256": raw_report["report_sha256"],
        }
        for field, expected in final_context.items():
            if raw_final_state.get(field) != expected:
                fail(f"{validator_id} raw final state {field} differs from terminal evidence")
        if raw_final_state.get("finalized_nonempty_ordinary_block_count") != raw_final_state.get(
            "finalized_ordinary_block_count"
        ):
            fail(f"{validator_id} raw final state includes an empty finalized block")
        for field in (
            "double_sign_events",
            "duplicate_apply_events",
            "state_drift_events",
            "safety_halt_violations",
        ):
            if raw_final_state.get(field) != 0:
                fail(f"{validator_id} raw final state {field} is nonzero")
    if len(source_digests) != 1 or len(topology_digests) != 1:
        fail("signed reports disagree on source or topology")
    if len(committed_blocks) != 1 or len(finalized_heights) != 1 or len(finalized_blocks) != 1:
        fail("signed validators disagree on committed/finalized cut")
    if len(host_ids) < 2:
        fail("candidate performance run must observe at least two provisioned hosts")
    planned_validator_ids = set(planned_by_id)
    if observed_validator_ids != planned_validator_ids:
        missing = sorted(planned_validator_ids - observed_validator_ids)
        unexpected = sorted(observed_validator_ids - planned_validator_ids)
        fail(
            "signed process set differs from prestart topology: "
            f"missing={missing!r} unexpected={unexpected!r}"
        )

    topology = topology_digest([planned_by_id[key] for key in sorted(planned_by_id)])
    observed_topology = next(iter(topology_digests))
    # The Rust observer's topology digest is authoritative.  The local
    # projection is retained as an audit hint and cannot replace it.
    topology_projection_sha256 = topology
    committed = next(iter(committed_blocks))
    finalized = next(iter(finalized_blocks))

    transaction_goodput_tps = None
    transaction_goodput_scope = None
    transaction_goodput_transfers = 0
    transaction_history_growth = None
    native_campaign_sha256 = None
    native_path = run_root / native_campaign.ARTIFACT
    if native_path.exists():
        native_document = read_json(native_path, "native client campaign")
        native_campaign.validate_document(
            native_document,
            run_id=run_id,
            anchor=anchor,
            validator_ids=observed_validator_ids,
        )
        if not started_ns <= native_document["started_monotonic_ns"] < native_document["completed_monotonic_ns"] <= ended_ns:
            fail("native campaign timing is outside the completed validator lifetime")
        if native_document["business_transfer_count"] <= 0:
            fail("native campaign has no finalized business transfer")
        transaction_goodput_tps = native_document["business_goodput_per_second"]
        transaction_goodput_transfers = native_document["business_transfer_count"]
        transaction_goodput_scope = (
            "sequential signed business transfers counted only after client-verified finalized proof; "
            "collector validates the retained campaign but does not replace independent binary re-verification"
        )
        transaction_history_growth = native_document["history_growth"]
        native_campaign_sha256 = sha256_file(native_path, "native client campaign")

    return {
        "schema_version": 1,
        "profile": "candidate-committed-performance-v1",
        "run_id": run_id,
        "validator_count": validator_count,
        "observed_host_count": len(host_ids),
        "inventory_sha256": inventory_digest(),
        "coordinator_manifest_sha256": anchor,
        "candidate_source_sha256": next(iter(source_digests)),
        "topology_sha256": observed_topology,
        "topology_projection_sha256": topology_projection_sha256,
        "binary_sha256_set": sorted(binary_digests),
        "config_sha256_count": len(config_digests),
        "measurement": {
            "measurement_seconds": measurement_seconds,
            "committed_ordinary_blocks": committed,
            "committed_blocks_per_second": committed / measurement_seconds,
            "finalized_ordinary_blocks": finalized,
            "finalized_height": next(iter(finalized_heights)),
            "finality_cut_agreement": True,
            "transaction_goodput_tps": transaction_goodput_tps,
            "transaction_goodput_transfers": transaction_goodput_transfers,
            "transaction_goodput_scope": transaction_goodput_scope,
            "transaction_history_growth": transaction_history_growth,
            "native_campaign_sha256": native_campaign_sha256,
        },
        "recovery": {
            "recovery_evidence_present": False,
            "restart_catchup_measured": False,
            "fault_heal_measured": False,
        },
        "artifact_sha256": sorted(artifact_hashes, key=lambda row: (row["validator_id"], row["role"])),
        "performance_evidence": False,
        "independent_multihost_evidence": False,
        "host_attestation": False,
        "production_activation": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_root", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    report = collect(args.run_root)
    if args.output is None:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        write_new(args.output, report)
        print(f"candidate_performance_evidence=measured output={args.output}")


if __name__ == "__main__":
    main()
