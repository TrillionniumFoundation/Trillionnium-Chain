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
            value = write(path, report if role == "signed_report_sha256" else {"role": suffix, "validator_id": validator_id})
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


if __name__ == "__main__":
    test_derives_committed_block_goodput_and_keeps_acceptance_false()
    test_rejects_raw_artifact_mutation_after_runner_summary()
    print("collect_candidate_performance_v1_test=passed")
