#!/usr/bin/env python3
"""Contract tests for candidate performance evidence derivation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "collect_candidate_performance_v1", HERE / "collect_candidate_performance_v1.py"
)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)

import native_client_campaign_v1 as native_campaign


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def write(path: pathlib.Path, value: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, sort_keys=True) + "\n").encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def fixture(root: pathlib.Path) -> None:
    validators = []
    processes = []
    for index in range(7):
        validator_id = f"{index + 1:064x}"
        host_id = ("local", "x230", "desktop", "rog", "rog", "j3160", "local")[index]
        run_id = "poco-g3-7-20260920T120000Z-01234567"
        anchor = "aa" * 32
        validators.append({"validator_id": validator_id, "host_id": host_id, "management": host_id})
        report = {
            "run_id": run_id,
            "validator_id": validator_id,
            "host_id": host_id,
            "coordinator_manifest_sha256": anchor,
            "candidate_source_sha256": "11" * 32,
            "topology_sha256": "22" * 32,
            "binary_sha256": "33" * 32,
            "config_sha256": "44" * 32,
            "signature_verified": True,
            "semantics_verified": True,
            "validator_run_completed": True,
            "committed_ordinary_block_count": 10,
            "finalized_height": 13,
            "finalized_ordinary_block_count": 10,
            "report_sha256": "55" * 32,
            "production_activation": False,
            "g3_evidence_complete": False,
        }
        process = {
            "validator_id": validator_id,
            "host_id": host_id,
            "observer_report_verification": report,
        }
        for role, suffix in (
            ("signed_report_sha256", "report"),
            ("signed_runtime_metrics_sha256", "metrics"),
            ("signed_runtime_final_state_sha256", "final"),
            ("signed_runtime_journal_sha256", "journal"),
        ):
            path = {
                "signed_report_sha256": root / "signed-reports" / f"{validator_id}.json",
                "signed_runtime_metrics_sha256": root / "signed-runtime-metrics" / f"{validator_id}.json",
                "signed_runtime_final_state_sha256": root / "signed-runtime-final-states" / f"{validator_id}.json",
                "signed_runtime_journal_sha256": root / "signed-runtime-journals" / f"{validator_id}.jsonl",
            }[role]
            if role == "signed_report_sha256":
                artifact = report
            elif role == "signed_runtime_metrics_sha256":
                artifact = {
                    "run_id": run_id,
                    "validator_id": validator_id,
                    "process_id": 1000 + index,
                    "process_instance_count": 1,
                    "ordinary_start_height": 4,
                    "finality_samples_ms": [1.0],
                    "fsync_count": 1,
                    "consensus_report_sha256": report["report_sha256"],
                    "validator_run_completed": True,
                    "g3_evidence_complete": False,
                    "geo_wan_evidence": False,
                    "production_activation": False,
                    "body_sha256": "66" * 32,
                }
            elif role == "signed_runtime_final_state_sha256":
                artifact = {
                    "run_id": run_id,
                    "validator_id": validator_id,
                    "finalized_height": 13,
                    "finalized_ordinary_block_count": 10,
                    "finalized_nonempty_ordinary_block_count": 10,
                    "runtime_metrics_sha256": "66" * 32,
                    "consensus_report_sha256": report["report_sha256"],
                    "validator_run_completed": True,
                    "g3_evidence_complete": False,
                    "geo_wan_evidence": False,
                    "production_activation": False,
                    "double_sign_events": 0,
                    "duplicate_apply_events": 0,
                    "state_drift_events": 0,
                    "safety_halt_violations": 0,
                }
            else:
                artifact = {"role": suffix, "validator_id": validator_id}
            value = write(path, artifact)
            process[role] = value
        processes.append(process)

    run_id = "poco-g3-7-20260920T120000Z-01234567"
    anchor = "aa" * 32
    write(
        root / "prestart-plan.json",
        {
            "run_id": run_id,
            "coordinator_manifest_sha256": anchor,
            "validators": validators,
        },
    )
    write(
        root / "consensus-run-summary.json",
        {
            "run_id": run_id,
            "validator_count": 7,
            "coordinator_manifest_sha256": anchor,
            "failure": None,
            "production_activation": False,
            "g3_lan_multihost_evidence": False,
            "processes": processes,
        },
    )
    write(
        root / "runner-lifecycle.json",
        {
            "run_id": run_id,
            "events": [
                {"kind": "validator_launch_completed", "monotonic_ns": 1_000_000_000},
                {"kind": "validator_processes_exited", "monotonic_ns": 3_000_000_000},
            ],
        },
    )


def test_derives_committed_block_goodput_and_keeps_acceptance_false() -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-candidate-performance-") as raw:
        root = pathlib.Path(raw)
        fixture(root)
        report = collector.collect(root)
        assert report["measurement"]["committed_ordinary_blocks"] == 10
        assert report["measurement"]["committed_blocks_per_second"] == 5.0
        assert report["measurement"]["transaction_goodput_tps"] is None
        assert report["recovery"]["recovery_evidence_present"] is False
        assert report["independent_multihost_evidence"] is False
        assert report["production_activation"] is False




def native_campaign_fixture(root: pathlib.Path) -> None:
    summary = json.loads((root / "consensus-run-summary.json").read_text())
    run_id = summary["run_id"]
    anchor = summary["coordinator_manifest_sha256"]
    validator_id = summary["processes"][0]["validator_id"]
    records = []
    for index in range(2):
        native_hash = f"{index + 10:064x}"
        response = {
            "ok": True,
            "profile_sha256": "77" * 32,
            "candidate_only": True,
            "data": {
                "native_tx_hash": native_hash,
                "receive_sequence": str(index + 1),
                "status": "committed",
            },
        }
        outer = b"{}"
        records.append(
            {
                "kind": "funding" if index == 0 else "transfer",
                "native_tx_hash": native_hash,
                "outer_hex": outer.hex(),
                "outer_sha256": hashlib.sha256(outer).hexdigest(),
                "submitted_monotonic_ns": 1_200_000_000 + index * 200_000_000,
                "ack_monotonic_ns": 1_210_000_000 + index * 200_000_000,
                "verified_monotonic_ns": 1_220_000_000 + index * 200_000_000,
                "ack": response,
                "retry_ack": json.loads(json.dumps(response)),
                "proof_response": json.loads(json.dumps(response)),
                "mac_verification": {
                    "candidate_only": True,
                    "m05_intent_binding": False,
                    "native_tx_hash": native_hash,
                    "proof_verified_by_client": True,
                    "height": "4",
                    "index": index,
                },
            }
        )
    window = records[-1]["verified_monotonic_ns"] - records[1]["submitted_monotonic_ns"]
    write(
        root / "native-client-campaign.json",
        {
            "schema": "trnm.native-client-campaign.v1",
            "run_id": run_id,
            "coordinator_manifest_sha256": anchor,
            "profile_sha256": "77" * 32,
            "submit_validator_id": validator_id,
            "signing_host": "mac",
            "verification_host": "mac",
            "transport": "ssh-private-unix-ipc",
            "started_monotonic_ns": 1_100_000_000,
            "completed_monotonic_ns": 1_800_000_000,
            "business_transfer_count": 1,
            "business_window_ns": window,
            "business_goodput_per_second": 1_000_000_000 / window,
            "history_growth": native_campaign.derive_history_growth_v1(records, 1),
            "records": records,
            "candidate_only": True,
            "m05_intent_binding": False,
            "fault_matrix_completed": False,
            "performance_acceptance": False,
            "host_attestation": False,
            "production_activation": False,
        },
    )


def test_joins_only_proof_verified_native_business_goodput() -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-candidate-performance-") as raw:
        root = pathlib.Path(raw)
        fixture(root)
        native_campaign_fixture(root)
        report = collector.collect(root)
        assert report["measurement"]["transaction_goodput_transfers"] == 1
        assert report["measurement"]["transaction_goodput_tps"] == 50.0
        assert "client-verified finalized proof" in report["measurement"]["transaction_goodput_scope"]
        assert report["measurement"]["native_campaign_sha256"] is not None
        assert report["measurement"]["transaction_history_growth"]["first_verified_height"] == 4
        assert report["measurement"]["transaction_history_growth"]["finality_latency_ms"]["p99"] == 20.0
        assert report["performance_evidence"] is False
        assert report["production_activation"] is False


def test_rejects_native_goodput_without_client_verified_proof() -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-candidate-performance-") as raw:
        root = pathlib.Path(raw)
        fixture(root)
        native_campaign_fixture(root)
        path = root / "native-client-campaign.json"
        campaign = json.loads(path.read_text())
        campaign["records"][1]["mac_verification"]["proof_verified_by_client"] = False
        write(path, campaign)
        try:
            collector.collect(root)
        except RuntimeError as error:
            assert "independent verification summary differs" in str(error)
        else:
            raise AssertionError("unverified native business goodput was accepted")


def test_rejects_raw_artifact_mutation_after_runner_summary() -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-candidate-performance-") as raw:
        root = pathlib.Path(raw)
        fixture(root)
        path = next((root / "signed-reports").iterdir())
        path.write_bytes(path.read_bytes() + b"tampered")
        try:
            collector.collect(root)
        except SystemExit as error:
            assert "hash differs" in str(error)
        else:
            raise AssertionError("mutated raw artifact was accepted")


def test_rejects_raw_report_semantic_substitution_even_when_rehashed() -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-candidate-performance-") as raw:
        root = pathlib.Path(raw)
        fixture(root)
        summary_path = root / "consensus-run-summary.json"
        summary = json.loads(summary_path.read_text())
        process = summary["processes"][0]
        report_path = root / "signed-reports" / f"{process['validator_id']}.json"
        report = json.loads(report_path.read_text())
        report["candidate_source_sha256"] = "99" * 32
        new_hash = write(report_path, report)
        process["signed_report_sha256"] = new_hash
        write(summary_path, summary)
        try:
            collector.collect(root)
        except SystemExit as error:
            assert "raw signed report candidate_source_sha256 differs" in str(error)
        else:
            raise AssertionError("rehashed semantic substitution was accepted")


def test_rejects_duplicate_and_missing_validator_process_records() -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-candidate-performance-") as raw:
        root = pathlib.Path(raw)
        fixture(root)
        summary_path = root / "consensus-run-summary.json"
        summary = json.loads(summary_path.read_text())
        processes = summary["processes"]
        # Keep the list cardinality and every individual record well-formed,
        # while omitting one topology member and repeating another.  A
        # cardinality-only collector must not treat that as a seven-validator
        # observation.
        processes[1]["validator_id"] = processes[0]["validator_id"]
        processes[1]["host_id"] = processes[0]["host_id"]
        processes[1]["signed_report_sha256"] = processes[0]["signed_report_sha256"]
        processes[1]["signed_runtime_metrics_sha256"] = processes[0]["signed_runtime_metrics_sha256"]
        processes[1]["signed_runtime_final_state_sha256"] = processes[0]["signed_runtime_final_state_sha256"]
        processes[1]["signed_runtime_journal_sha256"] = processes[0]["signed_runtime_journal_sha256"]
        processes[1]["observer_report_verification"] = processes[0]["observer_report_verification"]
        write(summary_path, summary)
        try:
            collector.collect(root)
        except SystemExit as error:
            assert "repeats validator_id" in str(error)
        else:
            raise AssertionError("duplicate validator process record was accepted")


def test_rejects_rehashed_terminal_state_substitution() -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-candidate-performance-") as raw:
        root = pathlib.Path(raw)
        fixture(root)
        summary_path = root / "consensus-run-summary.json"
        summary = json.loads(summary_path.read_text())
        process = summary["processes"][0]
        validator_id = process["validator_id"]
        final_path = root / "signed-runtime-final-states" / f"{validator_id}.json"
        final_state = json.loads(final_path.read_text())
        final_state["finalized_ordinary_block_count"] = 11
        final_state["finalized_nonempty_ordinary_block_count"] = 11
        final_hash = write(final_path, final_state)
        process["signed_runtime_final_state_sha256"] = final_hash
        write(summary_path, summary)
        try:
            collector.collect(root)
        except SystemExit as error:
            assert "raw final state finalized_ordinary_block_count" in str(error)
        else:
            raise AssertionError("rehashed terminal-state substitution was accepted")


if __name__ == "__main__":
    test_derives_committed_block_goodput_and_keeps_acceptance_false()
    test_joins_only_proof_verified_native_business_goodput()
    test_rejects_native_goodput_without_client_verified_proof()
    test_rejects_raw_artifact_mutation_after_runner_summary()
    test_rejects_raw_report_semantic_substitution_even_when_rehashed()
    test_rejects_duplicate_and_missing_validator_process_records()
    test_rejects_rehashed_terminal_state_substitution()
    print("collect_candidate_performance_v1_test=passed")
