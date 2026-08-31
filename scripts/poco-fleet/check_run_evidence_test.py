#!/usr/bin/env python3
"""Positive and negative controls for the strict G3 run-evidence verifier."""

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import check_run_evidence as checker  # noqa: E402
import evidence_bundle_profiles_v1 as profiles  # noqa: E402


FAULTS = (
    "asymmetric_partition",
    "bounded_delay_loss",
    "epoch_handoff",
    "host_loss",
    "leader_loss",
    "rollback_attempt",
    "stale_snapshot",
    "validator_process_kill",
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def source_provenance() -> dict[str, object]:
    return {
        "source_candidate_profile": "clean-commit-v1",
        "source_base_commit": "1" * 40,
        "source_git_object_format": "sha1",
        "source_git_tree_oid": "2" * 40,
        "source_git_status_sha256": checker.EMPTY_STATUS_SHA256,
        "cargo_lock_path": checker.CARGO_LOCK_PATH,
        "cargo_lock_sha256": digest("cargo-lock"),
        "cargo_lock_bytes": len(b"cargo-lock"),
    }


def topology(count: int) -> dict:
    return json.loads(
        subprocess.check_output(
            [sys.executable, str(HERE / "plan_topology.py"), str(count)],
            text=True,
        )
    )


def valid_document(count: int) -> dict:
    planned = topology(count)
    validators = []
    for item in planned["validators"]:
        validators.append(
            {
                "validator_id": item["validator_id"],
                "host_id": item["host_id"],
                "lan_ip": item["lan_ip"],
                "p2p_port": item["p2p_port"],
                "metrics_port": item["metrics_port"],
                "weight": item["weight"],
                "process_id": 1000 + item["index"],
                "binary_sha256": digest("linux"),
                "config_sha256": digest(f"config/{count}/{item['validator_id']}"),
            }
        )
    validators_by_host = {
        host_id: [item for item in validators if item["host_id"] == host_id]
        for host_id in {item["host_id"] for item in validators}
    }
    participants = []
    for item in planned["participants"]:
        host_id = item["host_id"]
        if item["validator_eligible"]:
            hosted = validators_by_host[host_id]
            participants.append(
                {
                    "host_id": host_id,
                    "lan_ip": item["lan_ip"],
                    "run_roles": item["run_roles"],
                    "process_ids": [validator["process_id"] for validator in hosted],
                    "binary_sha256": digest("linux"),
                    "config_set_sha256": checker.host_validator_configuration_set_digest(hosted),
                }
            )
        else:
            participants.append(
                {
                    "host_id": host_id,
                    "lan_ip": item["lan_ip"],
                    "run_roles": item["run_roles"],
                    "process_ids": [9001],
                    "binary_sha256": digest("macos"),
                    "config_set_sha256": checker.observer_configuration_set_digest(
                        digest("observer-config/mac")
                    ),
                }
            )
    document = {
        "schema_version": 3,
        "evidence_profile": profiles.NO_FAULT_V1,
        "run_id": f"poco-g3-{count}-20260813T120000Z-deadbeef",
        "fleet_id": "trnm-poco-lan-six-host-2026-08-13",
        "candidate": {
            "source_tree_sha256": digest("source"),
            **source_provenance(),
            "linux_x86_64_sha256": digest("linux"),
            "macos_arm64_sha256": digest("macos"),
            "configuration_set_sha256": "0" * 64,
            "reproducible_build": True,
            "production_activation": False,
        },
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "validator_run_completed": True,
        "topology": {
            "validator_count": count,
            "weight_profile": "equal",
            "peer_degree": count - 1 if count == 7 else 8,
            "ephemeral_test_keys": True,
        },
        "started_at": "2026-08-13T12:00:00Z",
        "ended_at": "2026-08-13T12:10:00Z",
        "validators": validators,
        "participants": participants,
        "consensus": {
            "ordinary_start_height": 4,
            "submitted_nonempty_blocks": 100,
            "committed_nonempty_blocks": 99,
            "finalized_height": 102,
            "state_root_agreement": True,
            "double_sign_events": 0,
            "duplicate_apply_events": 0,
            "state_drift_events": 0,
            "safety_halt_violations": 0,
            "restart_catchup_passed": False,
            "heal_convergence_passed": False,
        },
        "faults": [],
        "performance": {
            "measurement_seconds": 600,
            "committed_goodput_tps": 99 / 600,
            "finality_ms_p50": 100.0,
            "finality_ms_p95": 200.0,
            "finality_ms_p99": 300.0,
            "cpu_seconds": 400.0,
            "peak_rss_bytes": 1048576,
            "disk_bytes": 2097152,
            "fsync_count": 100,
            "network_tx_bytes": 3145728,
            "network_rx_bytes": 3145728,
        },
    }
    document["candidate"]["configuration_set_sha256"] = checker.configuration_set_digest(
        validators
    )
    return document


def check(document: dict, count: int) -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-poco-g3-evidence-test-") as directory:
        path = pathlib.Path(directory) / "evidence.json"
        path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
        checker.validate(
            path, count, profile=profiles.NO_FAULT_V1, emit=False
        )


def reject(document: dict, count: int, expected: str) -> None:
    try:
        check(document, count)
    except SystemExit as error:
        if expected not in str(error):
            raise AssertionError(
                f"negative control expected {expected!r}, observed {error!s}"
            ) from error
    else:
        raise AssertionError(f"negative control unexpectedly passed: {expected}")


def mutated(base: dict, mutate) -> dict:
    document = copy.deepcopy(base)
    mutate(document)
    return document


def main() -> None:
    for count in (7, 31, 100):
        check(valid_document(count), count)

    base = valid_document(7)
    controls = (
        (lambda d: d.update(schema_version=2), "schema_version must be 3"),
        (
            lambda d: d["candidate"].update(
                source_candidate_profile="exact-git-visible-worktree-v1"
            ),
            "source_candidate_profile must be clean-commit-v1",
        ),
        (
            lambda d: d["candidate"].update(source_git_object_format="sha256"),
            "source_base_commit must match the Git object format",
        ),
        (
            lambda d: d["candidate"].update(
                source_git_status_sha256=digest("dirty-status")
            ),
            "must bind an empty Git status",
        ),
        (
            lambda d: d["candidate"].update(cargo_lock_path="Cargo.lock"),
            "cargo_lock_path must be trillionnium/Cargo.lock",
        ),
        (
            lambda d: d["candidate"].update(cargo_lock_bytes=0),
            "cargo_lock_bytes must be a positive integer",
        ),
        (lambda d: d.update(geo_wan_evidence=True), "geo_wan_evidence=false"),
        (
            lambda d: d.update(validator_run_completed=False),
            "validator_run_completed=true",
        ),
        (
            lambda d: d["candidate"].update(production_activation=True),
            "must not activate production",
        ),
        (
            lambda d: d["candidate"].update(reproducible_build=False),
            "reproducible_build=true",
        ),
        (
            lambda d: d["topology"].update(validator_count=31),
            "validator_count does not match",
        ),
        (
            lambda d: d["topology"].update(ephemeral_test_keys=False),
            "ephemeral test keys",
        ),
        (lambda d: d["validators"].pop(), "exact topology cardinality"),
        (
            lambda d: d["validators"][1].update(
                validator_id=d["validators"][0]["validator_id"]
            ),
            "validator_id values must be unique",
        ),
        (
            lambda d: d["validators"][1].update(
                p2p_port=d["validators"][0]["p2p_port"],
                lan_ip=d["validators"][0]["lan_ip"],
                host_id=d["validators"][0]["host_id"],
            ),
            "P2P endpoints must be unique",
        ),
        (
            lambda d: d["validators"][0].update(
                process_id=d["validators"][1]["process_id"]
            ),
            "must have unique OS process ids",
        ),
        (
            lambda d: d["validators"][0].update(weight=100),
            "differs from frozen topology field weight",
        ),
        (
            lambda d: d["validators"][0].update(binary_sha256=digest("foreign")),
            "binary hash differs from candidate architecture",
        ),
        (
            lambda d: d["candidate"].update(
                configuration_set_sha256=digest("foreign-config")
            ),
            "does not bind every validator config",
        ),
        (
            lambda d: d["consensus"].update(committed_nonempty_blocks=0),
            "committed_nonempty_blocks must be a positive integer",
        ),
        (
            lambda d: d["consensus"].update(committed_nonempty_blocks=101),
            "committed blocks cannot exceed submitted",
        ),
        (
            lambda d: d["consensus"].update(ordinary_start_height=5),
            "ordinary_start_height must be 4",
        ),
        (
            lambda d: d["consensus"].update(finalized_height=99),
            "finalized height does not map exactly",
        ),
        (
            lambda d: d["consensus"].update(state_root_agreement=False),
            "state_root_agreement must be true",
        ),
        (
            lambda d: d["consensus"].update(double_sign_events=1),
            "double_sign_events must be zero",
        ),
        (
            lambda d: d.update(
                faults=[
                    {
                        "kind": kind,
                        "schedule_sha256": digest(f"legacy/{kind}"),
                        "safety_passed": True,
                        "expected_outcome_passed": True,
                    }
                    for kind in FAULTS
                ]
            ),
            "zero fault claims",
        ),
        (
            lambda d: d["consensus"].update(restart_catchup_passed=True),
            "must not claim restart/catch-up",
        ),
        (
            lambda d: d.update(
                evidence_profile=profiles.MIXED_AUTHORITY_FAULT_MATRIX_V1
            ),
            "differs from the explicit CLI profile",
        ),
        (
            lambda d: d["performance"].update(committed_goodput_tps=0),
            "committed_goodput_tps must be positive",
        ),
        (
            lambda d: d["performance"].update(finality_ms_p99=50),
            "quantiles are not monotonic",
        ),
        (
            lambda d: d.update(ended_at=d["started_at"]),
            "ended_at must be later",
        ),
        (
            lambda d: d.update(run_id="free-form"),
            "run_id must be a canonical",
        ),
        (
            lambda d: d.update(untrusted_summary="passed"),
            "document keys must be exactly",
        ),
    )
    for mutate, expected in controls:
        reject(mutated(base, mutate), 7, expected)

    print(
        "poco_g3_run_evidence_self_test=passed positives=3 negatives=33 "
        "topologies=7,31,100 geo_wan=false production_activation=false"
    )


if __name__ == "__main__":
    main()
