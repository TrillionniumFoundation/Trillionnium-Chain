#!/usr/bin/env python3
"""Positive and negative controls for the PoCO G3 run-bundle verifier."""

from __future__ import annotations

import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import check_run_bundle as bundle_checker  # noqa: E402
import check_run_evidence as evidence_checker  # noqa: E402
import check_run_evidence_test as evidence_test  # noqa: E402
import check_signed_runtime_evidence_test as signed_test  # noqa: E402
import evidence_bundle_profiles_v1 as profiles  # noqa: E402
from poco_consensus_contract import canonical_lab_genesis_hash  # noqa: E402


ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_VALIDATOR_AUTH_CACHE: dict[
    tuple[str, str], tuple[str, str, bytes]
] = {}


def pop_challenge(run_id: str, validator_id: str) -> bytes:
    run = run_id.encode("ascii")
    validator = validator_id.encode("ascii")
    return b"".join(
        (
            b"TRNM/PoCO/G3/EphemeralKeyPoP/v1\0",
            len(run).to_bytes(4, "big"),
            run,
            len(validator).to_bytes(4, "big"),
            validator,
        )
    )


def validator_auth(run_id: str, validator_id: str) -> tuple[str, str, bytes]:
    cache_key = (run_id, validator_id)
    if cache_key in _VALIDATOR_AUTH_CACHE:
        return _VALIDATOR_AUTH_CACHE[cache_key]
    with tempfile.TemporaryDirectory(prefix="trnm-poco-g3-bundle-key-") as raw:
        root = pathlib.Path(raw)
        secret = root / "secret.pk8"
        message = root / "challenge.bin"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-outform",
                "DER",
                "-out",
                str(secret),
            ],
            check=True,
            capture_output=True,
        )
        public_der = subprocess.run(
            [
                "openssl",
                "pkey",
                "-inform",
                "DER",
                "-in",
                str(secret),
                "-pubout",
                "-outform",
                "DER",
            ],
            check=True,
            capture_output=True,
        ).stdout
        if not public_der.startswith(ED25519_SPKI_PREFIX) or len(public_der) != 44:
            raise AssertionError("OpenSSL returned a non-canonical Ed25519 public key")
        secret_bytes = secret.read_bytes()
        message.write_bytes(pop_challenge(run_id, validator_id))
        signature = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-keyform",
                "DER",
                "-inkey",
                str(secret),
                "-in",
                str(message),
            ],
            check=True,
            capture_output=True,
        ).stdout
    if len(signature) != 64:
        raise AssertionError("OpenSSL returned a non-canonical Ed25519 signature")
    value = (public_der[-32:].hex(), signature.hex(), secret_bytes)
    _VALIDATOR_AUTH_CACHE[cache_key] = value
    return value


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(root: pathlib.Path, relative: str, payload: bytes) -> dict:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return {"path": relative, "sha256": digest(path), "bytes": len(payload)}


def artifact(root: pathlib.Path, role: str, subject: str, relative: str, payload: bytes) -> dict:
    return {"role": role, "subject": subject, **write(root, relative, payload)}


def append_signed_runtime_artifacts(
    root: pathlib.Path,
    artifacts: list[dict],
    summary: dict,
    topology_artifact: dict,
    validator_set: dict,
    validator_set_artifact: dict,
    coordinator_artifact: dict,
    candidate_source: dict,
    linux_binary: dict,
    config_artifacts: dict[str, dict],
    validator_auth_records: dict[str, tuple[str, str, bytes]],
    fault_assignments: dict[str, list[str]],
    restart_validator_id: str | None,
    final_block: str,
    final_state_root: str,
    final_chain_root: str,
) -> None:
    """Add the fleet certificate and four validator-signed evidence roles."""
    set_id = signed_test.checker.validator_set_id(validator_set)
    with tempfile.TemporaryDirectory(prefix="trnm-poco-g3-runtime-signing-") as raw:
        key_root = pathlib.Path(raw)
        for validator in summary["validators"]:
            validator_id = validator["validator_id"]
            secret = key_root / f"{validator_id}.pk8"
            secret.write_bytes(validator_auth_records[validator_id][2])
            context: dict[str, object] = {
                "run_id": summary["run_id"],
                "validator_id": validator_id,
                "host_id": validator["host_id"],
                "validator_set_sha256": validator_set_artifact["sha256"],
                "topology_sha256": topology_artifact["sha256"],
                "coordinator_manifest_sha256": coordinator_artifact["sha256"],
                "candidate_source_sha256": candidate_source["sha256"],
                "binary_sha256": linux_binary["sha256"],
                "config_sha256": config_artifacts[validator_id]["sha256"],
                "ordinary_start_height": 4,
                "requested_duration_seconds": 600,
                "requested_max_blocks": 2,
                "submitted_ordinary_block_count": 2,
                "committed_ordinary_block_count": 1,
                "finalized_ordinary_block_count": 1,
                "application_head_block_id": final_block,
                "application_state_root": final_state_root,
                "measurement_started_at": "2026-08-13T12:00:00Z",
                "measurement_ended_at": "2026-08-13T12:10:00Z",
                "finality_samples_ms": [100.0, 200.0, 300.0],
                "cpu_seconds": 1.0,
                "peak_rss_bytes": 1048576,
                "disk_bytes": 2097152,
                "fsync_count": 1,
                "network_tx_bytes": 3145728,
                "network_rx_bytes": 3145728,
            }
            signed_events: list[dict[str, object]] = []
            instance = 1
            monotonic_ns = 0
            terminal_process_id = validator["process_id"]
            process_id = (
                terminal_process_id + 1_000_000
                if restart_validator_id is not None
                and validator_id == restart_validator_id
                else terminal_process_id
            )

            def append_event(
                kind: str,
                subject: str,
                value: int,
                *,
                reset_clock: bool = False,
            ) -> None:
                nonlocal monotonic_ns
                if reset_clock:
                    monotonic_ns = 0
                elif signed_events:
                    monotonic_ns += 1
                previous = (
                    str(signed_events[-1]["event_sha256"])
                    if signed_events
                    else "0" * 64
                )
                signed_events.append(
                    signed_test.signed_event(
                        context,
                        secret,
                        instance=instance,
                        sequence=len(signed_events),
                        monotonic_ns=monotonic_ns,
                        kind=kind,
                        subject=subject,
                        value=value,
                        previous=previous,
                    )
                )

            append_event("process_start", "instance-1", process_id, reset_clock=True)
            append_event(
                "finalized",
                hashlib.sha256(b"commissioned-h1-block").hexdigest(),
                1,
            )
            append_event(
                "application_acknowledged",
                hashlib.sha256(b"commissioned-h1-state").hexdigest(),
                1,
            )
            append_event(
                "fleet_ready",
                hashlib.sha256(b"common-n-of-n-ready-set").hexdigest(),
                1,
            )
            append_event(
                "fleet_started",
                hashlib.sha256(b"common-n-of-n-start-certificate").hexdigest(),
                1,
            )
            append_event("vote_broadcast", "height-4-view-1", 4)
            append_event("quorum_certificate_admitted", "height-4-view-1", 4)
            append_event("finalized", final_block, 4)
            append_event("application_acknowledged", final_state_root, 4)
            for fault in sorted(fault_assignments[validator_id]):
                append_event("fault_applied", fault, 1)
                if fault == "validator_process_kill":
                    instance = 2
                    process_id = terminal_process_id
                    append_event(
                        "process_start", "instance-2", process_id, reset_clock=True
                    )
                    append_event("restart", "instance-2", process_id)
                    append_event("catchup_complete", final_block, 4)
                    append_event("fault_recovered", fault, 4)
                else:
                    append_event("fault_recovered", fault, 4)
            append_event(
                "final_tip",
                f"{final_block}:{final_state_root}:{final_chain_root}",
                4,
            )
            append_event("clean_stop", "bounded-run-complete", process_id)
            final_tip = signed_events[-2]
            terminal = signed_events[-1]
            artifacts.append(
                artifact(
                    root,
                    "validator_fleet_start_certificate",
                    validator_id,
                    f"validators/{validator_id}/signed/fleet-start-certificate.bin",
                    b"common-n-of-n-start-certificate",
                )
            )
            artifacts.append(
                artifact(
                    root,
                    "validator_runtime_event_journal",
                    validator_id,
                    f"validators/{validator_id}/signed/runtime-events.jsonl",
                    b"".join(
                        signed_test.compact(event) + b"\n" for event in signed_events
                    ),
                )
            )
            report = signed_test.signed_report(context, secret, set_id, terminal)
            artifacts.append(
                artifact(
                    root,
                    "validator_consensus_run_report",
                    validator_id,
                    f"validators/{validator_id}/signed/consensus-report.json",
                    signed_test.compact(report),
                )
            )
            metrics = signed_test.signed_metrics(context, secret, terminal, report)
            artifacts.append(
                artifact(
                    root,
                    "validator_runtime_metrics",
                    validator_id,
                    f"validators/{validator_id}/signed/runtime-metrics.json",
                    signed_test.compact(metrics),
                )
            )
            final_state = signed_test.signed_final_state(
                context,
                secret,
                terminal,
                final_tip,
                report,
                metrics,
                fault_assignments[validator_id],
            )
            artifacts.append(
                artifact(
                    root,
                    "validator_runtime_final_state",
                    validator_id,
                    f"validators/{validator_id}/signed/runtime-final-state.json",
                    signed_test.compact(final_state),
                )
            )


def build(root: pathlib.Path, count: int = 7) -> None:
    summary = evidence_test.valid_document(count)
    topology = evidence_test.topology(count)
    topology["run_id"] = summary["run_id"]
    candidate_source = artifact(
        root, "candidate_source", "", "candidate/source.tar", b"source"
    )
    linux_binary = artifact(
        root, "linux_binary", "", "candidate/linux.bin", b"linux"
    )
    macos_binary = artifact(
        root, "macos_binary", "", "candidate/macos.bin", b"macos"
    )
    material_builder_binary = artifact(
        root,
        "material_builder_binary",
        "",
        "candidate/material-builder-linux.bin",
        b"material-builder",
    )
    macos_material_builder_sha256 = evidence_test.digest("macos-material-builder")
    topology_artifact = artifact(
        root,
        "topology",
        "",
        "topology.json",
        json.dumps(topology, sort_keys=True).encode("utf-8"),
    )
    artifacts = [
        candidate_source,
        linux_binary,
        macos_binary,
        material_builder_binary,
        artifact(
            root,
            "build_report",
            "",
            "candidate/build-report.json",
            json.dumps(
                {
                    "schema_version": 3,
                    "source_tree_sha256": candidate_source["sha256"],
                    **evidence_test.source_provenance(),
                    "linux_first_sha256": linux_binary["sha256"],
                    "linux_second_sha256": linux_binary["sha256"],
                    "linux_material_builder_first_sha256": material_builder_binary[
                        "sha256"
                    ],
                    "linux_material_builder_second_sha256": material_builder_binary[
                        "sha256"
                    ],
                    "macos_first_sha256": macos_binary["sha256"],
                    "macos_second_sha256": macos_binary["sha256"],
                    "macos_material_builder_first_sha256": macos_material_builder_sha256,
                    "macos_material_builder_second_sha256": macos_material_builder_sha256,
                    "independent_build_roots": True,
                    "production_activation": False,
                },
                sort_keys=True,
            ).encode("utf-8"),
        ),
        topology_artifact,
    ]
    events: dict[str, list[dict]] = {
        validator["validator_id"]: [
            {
                "schema_version": 1,
                "run_id": summary["run_id"],
                "validator_id": validator["validator_id"],
                "sequence": 0,
                "observed_at": "2026-08-13T12:00:00Z",
                "kind": "process_start",
                "subject": "instance-1",
                "value": validator["process_id"],
            }
        ]
        for validator in summary["validators"]
    }
    submission_owner = summary["validators"][0]
    events[submission_owner["validator_id"]].append(
        {
            "schema_version": 1,
            "run_id": summary["run_id"],
            "validator_id": submission_owner["validator_id"],
            "sequence": 0,
            "observed_at": "2026-08-13T12:00:01Z",
            "kind": "submitted_nonempty_blocks",
            "subject": "",
            "value": 2,
        }
    )
    derived_faults = []
    fault_assignments: dict[str, list[str]] = {
        validator["validator_id"]: [] for validator in summary["validators"]
    }
    planned_by_id = {item["validator_id"]: item for item in topology["validators"]}
    validator_auth_records = {
        validator_id: validator_auth(summary["run_id"], validator_id)
        for validator_id in planned_by_id
    }
    consensus_keys = {
        validator_id: record[0]
        for validator_id, record in validator_auth_records.items()
    }
    validator_set = {
        "schema_version": 1,
        "run_id": summary["run_id"],
        "chain_id": "trnm-poco-g3-lab-v0",
        "genesis_hash": canonical_lab_genesis_hash(
            "trnm-poco-g3-lab-v0",
            (
                (
                    bytes.fromhex(validator_id),
                    bytes.fromhex(consensus_keys[validator_id]),
                    planned_by_id[validator_id]["weight"],
                )
                for validator_id in sorted(planned_by_id)
            ),
        ).hex(),
        "protocol_version": 0,
        "epoch": 0,
        "consensus_parameters_profile": "reference-shadow-v0",
        "candidate_source_sha256": candidate_source["sha256"],
        "production_activation": False,
        "validators": [
            {
                "validator_id": validator_id,
                "consensus_public_key": consensus_keys[validator_id],
                "voting_power": planned_by_id[validator_id]["weight"],
                "key_pop_signature": validator_auth_records[validator_id][1],
            }
            for validator_id in sorted(planned_by_id)
        ],
    }
    validator_set_artifact = artifact(
        root,
        "validator_set",
        "",
        "public/validator-set.json",
        json.dumps(validator_set, sort_keys=True).encode("utf-8"),
    )
    artifacts.append(validator_set_artifact)
    public_material_artifacts = [
        artifact(
            root,
            "workload_corpus",
            "",
            "public/workload.corpus",
            b"workload-corpus",
        ),
        artifact(
            root,
            "workload_policy",
            "",
            "public/workload-policy.json",
            b"workload-policy",
        ),
        artifact(
            root,
            "bootstrap_h1_proposal",
            "",
            "public/bootstrap/h1.proposal",
            b"bootstrap-h1-proposal",
        ),
        artifact(
            root,
            "bootstrap_h2_proposal",
            "",
            "public/bootstrap/h2.proposal",
            b"bootstrap-h2-proposal",
        ),
        artifact(
            root,
            "bootstrap_h3_proposal",
            "",
            "public/bootstrap/h3.proposal",
            b"bootstrap-h3-proposal",
        ),
        artifact(
            root,
            "bootstrap_finality_proof",
            "",
            "public/bootstrap/finality-proof.cev0",
            b"bootstrap-finality-proof",
        ),
        artifact(
            root,
            "bootstrap_manifest",
            "",
            "public/bootstrap/bootstrap.json",
            b"bootstrap-manifest",
        ),
    ]
    artifacts.extend(public_material_artifacts)
    validator_set_sha256 = validator_set_artifact["sha256"]
    final_block = evidence_test.digest("final-block")
    final_state_root = evidence_test.digest("final-state")
    final_chain_root = evidence_test.digest("final-chain")
    for validator in summary["validators"]:
        validator_id = validator["validator_id"]
        config = {
            "schema_version": 1,
            "run_id": summary["run_id"],
            "validator_id": validator_id,
            "host_id": validator["host_id"],
            "lan_ip": validator["lan_ip"],
            "p2p_port": validator["p2p_port"],
            "metrics_port": validator["metrics_port"],
            "weight": validator["weight"],
            "consensus_public_key": consensus_keys[validator_id],
            "validator_set_sha256": validator_set_sha256,
            "binary_sha256": validator["binary_sha256"],
            "ordinary_start_height": 4,
            "workload_corpus_sha256": evidence_test.digest("workload-corpus"),
            "workload_policy_sha256": evidence_test.digest("workload-policy"),
            "secret_key_path": f"secrets/{validator_id}.pk8",
            "peers": [
                {
                    "validator_id": peer_id,
                    "lan_ip": planned_by_id[peer_id]["lan_ip"],
                    "p2p_port": planned_by_id[peer_id]["p2p_port"],
                    "consensus_public_key": consensus_keys[peer_id],
                }
                for peer_id in planned_by_id[validator_id]["peers"]
            ],
            "network_scope": "single-lan",
            "geo_wan_evidence": False,
            "production_activation": False,
        }
        config_artifact = artifact(
            root,
            "validator_config",
            validator_id,
            f"validators/{validator_id}/config.json",
            json.dumps(config, sort_keys=True).encode("utf-8"),
        )
        artifacts.append(config_artifact)
        validator["config_sha256"] = config_artifact["sha256"]

        events[validator_id].append(
            {
                "schema_version": 1,
                "run_id": summary["run_id"],
                "validator_id": validator_id,
                "sequence": 0,
                "observed_at": "2026-08-13T12:09:59Z",
                "kind": "finalized_tip",
                "subject": f"{final_block}:{final_state_root}:{final_chain_root}",
                "value": 4,
            }
        )
        for sequence, event in enumerate(events[validator_id]):
            event["sequence"] = sequence
        event_payload = "".join(
            json.dumps(event, sort_keys=True) + "\n" for event in events[validator_id]
        ).encode("utf-8")
        artifacts.append(
            artifact(
                root,
                "validator_event_log",
                validator_id,
                f"validators/{validator_id}/events.jsonl",
                event_payload,
            )
        )
        artifacts.append(
            artifact(
                root,
                "validator_metrics",
                validator_id,
                f"validators/{validator_id}/metrics.json",
                json.dumps(
                    {
                        "schema_version": 1,
                        "run_id": summary["run_id"],
                        "validator_id": validator_id,
                        "measurement_started_at": "2026-08-13T12:00:00Z",
                        "measurement_ended_at": "2026-08-13T12:10:00Z",
                        "finality_samples_ms": [100.0, 200.0, 300.0],
                        "cpu_seconds": 1.0,
                        "peak_rss_bytes": 1048576,
                        "disk_bytes": 2097152,
                        "fsync_count": 1,
                        "network_tx_bytes": 3145728,
                        "network_rx_bytes": 3145728,
                    },
                    sort_keys=True,
                ).encode("utf-8"),
            )
        )
        artifacts.append(
            artifact(
                root,
                "validator_final_state",
                validator_id,
                f"validators/{validator_id}/final-state.json",
                json.dumps(
                    {
                        "schema_version": 2,
                        "run_id": summary["run_id"],
                        "validator_id": validator_id,
                        "process_id": validator["process_id"],
                        "process_instance_count": 1,
                        "ordinary_start_height": 4,
                        "finalized_height": 4,
                        "finalized_ordinary_block_count": 1,
                        "finalized_block_id": final_block,
                        "finalized_state_root": final_state_root,
                        "finalized_chain_root": final_chain_root,
                        "applied_height": 4,
                        "all_finalized_ordinary_blocks_nonempty": True,
                        "double_sign_events": 0,
                        "duplicate_apply_events": 0,
                        "state_drift_events": 0,
                        "safety_halt_violations": 0,
                    },
                    sort_keys=True,
                ).encode("utf-8"),
            )
        )

    observer_config = artifact(
        root,
        "observer_config",
        "mac",
        "observer/mac/config.json",
        json.dumps(
            {
                "schema_version": 1,
                "run_id": summary["run_id"],
                "host_id": "mac",
                "lan_ip": "192.168.0.5",
                "os": "macos",
                "arch": "arm64",
                "run_roles": [
                    "load-generator",
                    "evidence-collector",
                    "crypto-cross-verifier",
                ],
                "binary_sha256": evidence_test.digest("macos"),
                "candidate_source_sha256": evidence_test.digest("source"),
                "validator_set_sha256": validator_set_sha256,
                "validator_endpoints": [
                    {
                        "validator_id": item["validator_id"],
                        "lan_ip": item["lan_ip"],
                        "p2p_port": item["p2p_port"],
                        "metrics_port": item["metrics_port"],
                        "consensus_public_key": consensus_keys[item["validator_id"]],
                    }
                    for item in topology["validators"]
                ],
                "network_scope": "single-lan",
                "geo_wan_evidence": False,
                "production_activation": False,
            },
            sort_keys=True,
        ).encode("utf-8"),
    )
    artifacts.append(observer_config)
    artifacts.append(
        artifact(
            root,
            "observer_report",
            "mac",
            "observer/mac/report.json",
            json.dumps(
                {
                    "schema_version": 1,
                    "run_id": summary["run_id"],
                    "host_id": "mac",
                    "process_id": 9001,
                    "config_sha256": observer_config["sha256"],
                    "binary_sha256": evidence_test.digest("macos"),
                    "load_submitted_nonempty_blocks": 2,
                    "verified_qc_signatures": count,
                    "rejected_invalid_signature_controls": 1,
                    "started_at": "2026-08-13T12:00:00Z",
                    "ended_at": "2026-08-13T12:10:00Z",
                },
                sort_keys=True,
            ).encode("utf-8"),
        )
    )

    config_artifacts = {
        item["subject"]: item
        for item in artifacts
        if item["role"] == "validator_config"
    }
    coordinator_manifest = {
        "schema_version": 2,
        "run_id": summary["run_id"],
        "fleet_id": summary["fleet_id"],
        "validator_count": count,
        "weight_profile": summary["topology"]["weight_profile"],
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "candidate": {
            "source_tree_sha256": candidate_source["sha256"],
            "linux_x86_64_sha256": linux_binary["sha256"],
            "macos_arm64_sha256": macos_binary["sha256"],
        },
        "material_author": {
            "binary_sha256": material_builder_binary["sha256"],
            "runtime_deployed": False,
        },
        "validator_set_sha256": validator_set_sha256,
        "public_files": [
            {
                "path": "topology.json",
                "sha256": topology_artifact["sha256"],
                "bytes": topology_artifact["bytes"],
            },
            {
                "path": "public/validator-set.json",
                "sha256": validator_set_artifact["sha256"],
                "bytes": validator_set_artifact["bytes"],
            },
            *[
                {
                    "path": profiles.COORDINATOR_PUBLIC_SINGLETON_PATHS[
                        material["role"]
                    ],
                    "sha256": material["sha256"],
                    "bytes": material["bytes"],
                }
                for material in public_material_artifacts
            ],
            *[
                {
                    "path": f"public/configs/{validator_id}.json",
                    "sha256": config_artifacts[validator_id]["sha256"],
                    "bytes": config_artifacts[validator_id]["bytes"],
                }
                for validator_id in sorted(config_artifacts)
            ],
            {
                "path": "public/observer-configs/mac.json",
                "sha256": observer_config["sha256"],
                "bytes": observer_config["bytes"],
            },
        ],
        "secret_files": [
            {
                "path": f"secrets/{validator_id}.pk8",
                "sha256": hashlib.sha256(
                    validator_auth_records[validator_id][2]
                ).hexdigest(),
                "bytes": len(validator_auth_records[validator_id][2]),
            }
            for validator_id in sorted(planned_by_id)
        ],
        "production_activation": False,
    }
    coordinator_artifact = artifact(
        root,
        "coordinator_manifest",
        "",
        "coordinator-manifest.json",
        json.dumps(coordinator_manifest, sort_keys=True).encode("utf-8"),
    )
    artifacts.append(coordinator_artifact)
    append_signed_runtime_artifacts(
        root,
        artifacts,
        summary,
        topology_artifact,
        validator_set,
        validator_set_artifact,
        coordinator_artifact,
        candidate_source,
        linux_binary,
        config_artifacts,
        validator_auth_records,
        fault_assignments,
        None,
        final_block,
        final_state_root,
        final_chain_root,
    )

    summary["candidate"]["configuration_set_sha256"] = (
        bundle_checker.check_run_evidence.configuration_set_digest(summary["validators"])
    )
    validators_by_host = {
        host_id: [
            validator
            for validator in summary["validators"]
            if validator["host_id"] == host_id
        ]
        for host_id in {
            validator["host_id"] for validator in summary["validators"]
        }
    }
    for participant in summary["participants"]:
        if participant["host_id"] == "mac":
            participant["process_ids"] = [9001]
            participant["config_set_sha256"] = (
                bundle_checker.check_run_evidence.observer_configuration_set_digest(
                    observer_config["sha256"]
                )
            )
            continue
        hosted = validators_by_host[participant["host_id"]]
        participant["process_ids"] = [validator["process_id"] for validator in hosted]
        participant["config_set_sha256"] = (
            bundle_checker.check_run_evidence.host_validator_configuration_set_digest(hosted)
        )
    summary["started_at"] = "2026-08-13T12:00:00Z"
    summary["ended_at"] = "2026-08-13T12:10:00Z"
    summary["consensus"] = {
        "ordinary_start_height": 4,
        "submitted_nonempty_blocks": 2,
        "committed_nonempty_blocks": 1,
        "finalized_height": 4,
        "state_root_agreement": True,
        "double_sign_events": 0,
        "duplicate_apply_events": 0,
        "state_drift_events": 0,
        "safety_halt_violations": 0,
        "restart_catchup_passed": False,
        "heal_convergence_passed": False,
    }
    summary["faults"] = derived_faults
    summary["performance"] = {
        "measurement_seconds": 600,
        "committed_goodput_tps": 1 / 600,
        "finality_ms_p50": 200.0,
        "finality_ms_p95": 300.0,
        "finality_ms_p99": 300.0,
        "cpu_seconds": float(count),
        "peak_rss_bytes": 1048576,
        "disk_bytes": 2097152 * count,
        "fsync_count": count,
        "network_tx_bytes": 3145728 * count,
        "network_rx_bytes": 3145728 * count,
    }
    summary_bytes = json.dumps(summary, sort_keys=True).encode("utf-8")
    summary_ref = write(root, "summary.json", summary_bytes)
    collector = {
        "schema_version": 1,
        "evidence_profile": profiles.NO_FAULT_V1,
        "run_id": summary["run_id"],
        "validator_count": count,
        "summary_sha256": summary_ref["sha256"],
        "ordered_input_root": bundle_checker.ordered_input_root(
            profiles.NO_FAULT_V1, artifacts
        ),
        "derived_from_raw_artifacts": True,
    }
    artifacts.append(
        artifact(
            root,
            "collector_report",
            "",
            "collector-report.json",
            json.dumps(collector, sort_keys=True).encode("utf-8"),
        )
    )
    manifest = {
        "schema_version": 1,
        "evidence_profile": profiles.NO_FAULT_V1,
        "run_id": summary["run_id"],
        "validator_count": count,
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "completed_run_summary": summary_ref,
        "artifacts": artifacts,
    }
    (root / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )


def load(root: pathlib.Path) -> dict:
    return json.loads((root / "manifest.json").read_text(encoding="utf-8"))


def save(root: pathlib.Path, document: dict) -> None:
    (root / "manifest.json").write_text(
        json.dumps(document, sort_keys=True), encoding="utf-8"
    )


def reject(change, expected: str) -> None:
    with tempfile.TemporaryDirectory(prefix="trnm-poco-g3-bundle-mutant-") as raw:
        root = pathlib.Path(raw)
        build(root)
        anchor = next(
            entry["sha256"]
            for entry in load(root)["artifacts"]
            if entry["role"] == "coordinator_manifest"
        )
        replacement_anchor = change(root)
        if (
            isinstance(replacement_anchor, str)
            and bundle_checker.HEX64.fullmatch(replacement_anchor)
        ):
            anchor = replacement_anchor
        try:
            bundle_checker.validate(
                root,
                7,
                profile=profiles.NO_FAULT_V1,
                coordinator_manifest_sha256=anchor,
                emit=False,
            )
        except SystemExit as error:
            if expected not in str(error):
                raise AssertionError(
                    f"bundle mutant expected {expected!r}, observed {error!s}"
                ) from error
        else:
            raise AssertionError(f"bundle mutant unexpectedly passed: {expected}")


def edit_manifest(root: pathlib.Path, change) -> None:
    document = load(root)
    change(document)
    save(root, document)


def remove_artifact(root: pathlib.Path, role: str) -> None:
    document = load(root)
    item = next(entry for entry in document["artifacts"] if entry["role"] == role)
    (root / item["path"]).unlink()
    document["artifacts"].remove(item)
    save(root, document)


def tamper_first(root: pathlib.Path, role: str) -> None:
    item = next(entry for entry in load(root)["artifacts"] if entry["role"] == role)
    with (root / item["path"]).open("ab") as target:
        target.write(b"tamper")


def tamper_signed_report_signature(root: pathlib.Path) -> None:
    document = load(root)
    item = next(
        entry
        for entry in document["artifacts"]
        if entry["role"] == "validator_consensus_run_report"
    )
    path = root / item["path"]
    report = json.loads(path.read_text(encoding="utf-8"))
    report["signature"] = (
        ("00" if report["signature"][:2] != "00" else "01")
        + report["signature"][2:]
    )
    path.write_bytes(signed_test.compact(report))
    item["bytes"] = path.stat().st_size
    item["sha256"] = digest(path)
    refresh_collector(root, document)


def symlink_first(root: pathlib.Path, role: str) -> None:
    item = next(entry for entry in load(root)["artifacts"] if entry["role"] == role)
    path = root / item["path"]
    backup = path.with_suffix(path.suffix + ".target")
    path.rename(backup)
    path.symlink_to(backup.name)


def corrupt_collector(root: pathlib.Path, field: str, value: object) -> None:
    document = load(root)
    item = next(entry for entry in document["artifacts"] if entry["role"] == "collector_report")
    path = root / item["path"]
    collector = json.loads(path.read_text(encoding="utf-8"))
    collector[field] = value
    path.write_text(json.dumps(collector, sort_keys=True), encoding="utf-8")
    item["bytes"] = path.stat().st_size
    item["sha256"] = digest(path)
    save(root, document)


def rewrite_json_artifact(root: pathlib.Path, role: str, change) -> None:
    document = load(root)
    item = next(entry for entry in document["artifacts"] if entry["role"] == role)
    path = root / item["path"]
    payload = json.loads(path.read_text(encoding="utf-8"))
    change(payload)
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    item["bytes"] = path.stat().st_size
    item["sha256"] = digest(path)

    collector_item = next(
        entry for entry in document["artifacts"] if entry["role"] == "collector_report"
    )
    collector_path = root / collector_item["path"]
    collector = json.loads(collector_path.read_text(encoding="utf-8"))
    collector["ordered_input_root"] = bundle_checker.ordered_input_root(
        profiles.NO_FAULT_V1, document["artifacts"]
    )
    collector_path.write_text(
        json.dumps(collector, sort_keys=True), encoding="utf-8"
    )
    collector_item["bytes"] = collector_path.stat().st_size
    collector_item["sha256"] = digest(collector_path)
    save(root, document)


def rewrite_coordinator_and_reanchor(root: pathlib.Path, change) -> str:
    rewrite_json_artifact(root, "coordinator_manifest", change)
    return next(
        entry["sha256"]
        for entry in load(root)["artifacts"]
        if entry["role"] == "coordinator_manifest"
    )


def downgrade_build_report_to_schema2(root: pathlib.Path) -> None:
    def change(document: dict) -> None:
        document["schema_version"] = 2
        for field in evidence_checker.SOURCE_PROVENANCE_KEYS:
            document.pop(field)

    rewrite_json_artifact(root, "build_report", change)


def rewrite_text_artifact(root: pathlib.Path, role: str, payload: bytes) -> None:
    document = load(root)
    item = next(entry for entry in document["artifacts"] if entry["role"] == role)
    path = root / item["path"]
    path.write_bytes(payload)
    item["bytes"] = path.stat().st_size
    item["sha256"] = digest(path)
    collector_item = next(
        entry for entry in document["artifacts"] if entry["role"] == "collector_report"
    )
    collector_path = root / collector_item["path"]
    collector = json.loads(collector_path.read_text(encoding="utf-8"))
    collector["ordered_input_root"] = bundle_checker.ordered_input_root(
        profiles.NO_FAULT_V1, document["artifacts"]
    )
    collector_path.write_text(
        json.dumps(collector, sort_keys=True), encoding="utf-8"
    )
    collector_item["bytes"] = collector_path.stat().st_size
    collector_item["sha256"] = digest(collector_path)
    save(root, document)


def refresh_collector(root: pathlib.Path, document: dict) -> None:
    collector_item = next(
        entry for entry in document["artifacts"]
        if entry["role"] == "collector_report"
    )
    collector_path = root / collector_item["path"]
    collector = json.loads(collector_path.read_text(encoding="utf-8"))
    collector["summary_sha256"] = document["completed_run_summary"]["sha256"]
    collector["ordered_input_root"] = bundle_checker.ordered_input_root(
        profiles.NO_FAULT_V1, document["artifacts"]
    )
    collector_path.write_text(
        json.dumps(collector, sort_keys=True), encoding="utf-8"
    )
    collector_item["bytes"] = collector_path.stat().st_size
    collector_item["sha256"] = digest(collector_path)
    save(root, document)


def rewrite_event_log(root: pathlib.Path, select, change) -> None:
    document = load(root)
    item = next(
        entry for entry in document["artifacts"]
        if entry["role"] == "validator_event_log"
        and select((root / entry["path"]).read_text(encoding="utf-8"))
    )
    path = root / item["path"]
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    change(rows)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    item["bytes"] = path.stat().st_size
    item["sha256"] = digest(path)
    refresh_collector(root, document)


def coherent_foreign_validator_set_hash(root: pathlib.Path) -> str:
    """Keep every secondary reference coherent while severing descriptor identity."""
    document = load(root)
    foreign = evidence_test.digest("coherent-foreign-validator-set")
    config_refs: dict[str, dict] = {}
    observer_ref: dict | None = None
    for item in document["artifacts"]:
        if item["role"] not in {"validator_config", "observer_config"}:
            continue
        path = root / item["path"]
        value = json.loads(path.read_text(encoding="utf-8"))
        value["validator_set_sha256"] = foreign
        path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        item["bytes"] = path.stat().st_size
        item["sha256"] = digest(path)
        if item["role"] == "validator_config":
            config_refs[item["subject"]] = item
        else:
            observer_ref = item
    assert observer_ref is not None

    observer_report_item = next(
        item for item in document["artifacts"]
        if item["role"] == "observer_report"
    )
    observer_report_path = root / observer_report_item["path"]
    observer_report = json.loads(observer_report_path.read_text(encoding="utf-8"))
    observer_report["config_sha256"] = observer_ref["sha256"]
    observer_report_path.write_text(
        json.dumps(observer_report, sort_keys=True), encoding="utf-8"
    )
    observer_report_item["bytes"] = observer_report_path.stat().st_size
    observer_report_item["sha256"] = digest(observer_report_path)

    summary_path = root / document["completed_run_summary"]["path"]
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    for validator in summary["validators"]:
        validator["config_sha256"] = config_refs[validator["validator_id"]]["sha256"]
    summary["candidate"]["configuration_set_sha256"] = (
        evidence_checker.configuration_set_digest(summary["validators"])
    )
    for participant in summary["participants"]:
        if participant["host_id"] == "mac":
            participant["config_set_sha256"] = (
                evidence_checker.observer_configuration_set_digest(
                    observer_ref["sha256"]
                )
            )
        else:
            hosted = [
                validator for validator in summary["validators"]
                if validator["host_id"] == participant["host_id"]
            ]
            participant["config_set_sha256"] = (
                evidence_checker.host_validator_configuration_set_digest(hosted)
            )
    summary_path.write_text(json.dumps(summary, sort_keys=True), encoding="utf-8")
    document["completed_run_summary"]["bytes"] = summary_path.stat().st_size
    document["completed_run_summary"]["sha256"] = digest(summary_path)

    coordinator_item = next(
        item for item in document["artifacts"]
        if item["role"] == "coordinator_manifest"
    )
    coordinator_path = root / coordinator_item["path"]
    coordinator = json.loads(coordinator_path.read_text(encoding="utf-8"))
    public_by_path = {
        value["path"]: value for value in coordinator["public_files"]
    }
    for validator_id, ref in config_refs.items():
        value = public_by_path[f"public/configs/{validator_id}.json"]
        value["sha256"], value["bytes"] = ref["sha256"], ref["bytes"]
    value = public_by_path["public/observer-configs/mac.json"]
    value["sha256"], value["bytes"] = observer_ref["sha256"], observer_ref["bytes"]
    coordinator_path.write_text(
        json.dumps(coordinator, sort_keys=True), encoding="utf-8"
    )
    coordinator_item["bytes"] = coordinator_path.stat().st_size
    coordinator_item["sha256"] = digest(coordinator_path)
    refresh_collector(root, document)
    return coordinator_item["sha256"]


def duplicate_anchored_coordinator_key(root: pathlib.Path) -> str:
    document = load(root)
    item = next(
        value for value in document["artifacts"]
        if value["role"] == "coordinator_manifest"
    )
    path = root / item["path"]
    raw = path.read_text(encoding="utf-8")
    marker = '"production_activation": false'
    if raw.count(marker) != 1:
        raise AssertionError("coordinator fixture lost production_activation marker")
    path.write_text(
        raw.replace(
            marker,
            '"production_activation": true, "production_activation": false',
        ),
        encoding="utf-8",
    )
    item["bytes"] = path.stat().st_size
    item["sha256"] = digest(path)
    refresh_collector(root, document)
    return item["sha256"]


def duplicate_bundle_manifest_key(root: pathlib.Path) -> None:
    path = root / "manifest.json"
    raw = path.read_text(encoding="utf-8")
    marker = '"geo_wan_evidence": false'
    if raw.count(marker) != 1:
        raise AssertionError("bundle fixture lost geo_wan_evidence marker")
    path.write_text(
        raw.replace(
            marker,
            '"geo_wan_evidence": true, "geo_wan_evidence": false',
        ),
        encoding="utf-8",
    )


def duplicate_event_jsonl_key(root: pathlib.Path) -> None:
    document = load(root)
    item = next(
        value for value in document["artifacts"]
        if value["role"] == "validator_event_log"
    )
    path = root / item["path"]
    raw = path.read_text(encoding="utf-8")
    marker = '"schema_version": 1'
    if marker not in raw:
        raise AssertionError("event fixture lost schema_version marker")
    path.write_text(
        raw.replace(
            marker,
            '"schema_version": 2, "schema_version": 1',
            1,
        ),
        encoding="utf-8",
    )
    item["bytes"] = path.stat().st_size
    item["sha256"] = digest(path)
    refresh_collector(root, document)


def reverse_restart_catchup(root: pathlib.Path) -> None:
    def change(rows: list[dict]) -> None:
        restart = next(row for row in rows if row["kind"] == "restart")
        catchup = next(row for row in rows if row["kind"] == "catchup_complete")
        for field in ("kind", "subject", "value"):
            restart[field], catchup[field] = catchup[field], restart[field]

    rewrite_event_log(
        root,
        lambda raw: '"kind": "restart"' in raw,
        change,
    )


def inject_unsigned_restart(root: pathlib.Path) -> None:
    def change(rows: list[dict]) -> None:
        tip_index = next(
            index for index, row in enumerate(rows) if row["kind"] == "finalized_tip"
        )
        validator_id = rows[0]["validator_id"]
        process_id = rows[0]["value"]
        rows[tip_index:tip_index] = [
            {
                "schema_version": 1,
                "run_id": rows[0]["run_id"],
                "validator_id": validator_id,
                "sequence": 0,
                "observed_at": "2026-08-13T12:00:02Z",
                "kind": "restart",
                "subject": "instance-2",
                "value": process_id,
            },
            {
                "schema_version": 1,
                "run_id": rows[0]["run_id"],
                "validator_id": validator_id,
                "sequence": 0,
                "observed_at": "2026-08-13T12:00:03Z",
                "kind": "catchup_complete",
                "subject": evidence_test.digest("final-block"),
                "value": 4,
            },
        ]
        for sequence, row in enumerate(rows):
            row["sequence"] = sequence

    rewrite_event_log(root, lambda _raw: True, change)


def add_legacy_fault_artifact(root: pathlib.Path) -> None:
    edit_manifest(
        root,
        lambda document: document["artifacts"].append(
            {
                "role": "fault_schedule",
                "subject": "leader_loss",
                "path": "faults/smuggled.json",
                "sha256": "0" * 64,
                "bytes": 1,
            }
        ),
    )


def rewrite_summary_profile(root: pathlib.Path) -> None:
    document = load(root)
    summary_path = root / document["completed_run_summary"]["path"]
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["evidence_profile"] = profiles.MIXED_AUTHORITY_FAULT_MATRIX_V1
    summary_path.write_text(json.dumps(summary, sort_keys=True), encoding="utf-8")
    document["completed_run_summary"]["bytes"] = summary_path.stat().st_size
    document["completed_run_summary"]["sha256"] = digest(summary_path)
    refresh_collector(root, document)


def conflict_unsigned_submitted_count(root: pathlib.Path) -> None:
    def change(rows: list[dict]) -> None:
        submitted = next(
            row for row in rows if row["kind"] == "submitted_nonempty_blocks"
        )
        submitted["value"] += 1

    rewrite_event_log(
        root,
        lambda raw: '"kind": "submitted_nonempty_blocks"' in raw,
        change,
    )


def reverse_fault_transition(root: pathlib.Path) -> None:
    def change(rows: list[dict]) -> None:
        applied = next(row for row in rows if row["kind"] == "fault_applied")
        recovered = next(
            row for row in rows
            if row["kind"] == "fault_recovered"
            and row["subject"] == applied["subject"]
        )
        applied["kind"], recovered["kind"] = recovered["kind"], applied["kind"]

    rewrite_event_log(
        root,
        lambda raw: '"kind": "fault_applied"' in raw,
        change,
    )


def move_fault_transition_outside_window(root: pathlib.Path) -> None:
    document = load(root)
    schedule_item = next(
        value for value in document["artifacts"]
        if value["role"] == "fault_schedule"
    )
    schedule = json.loads(
        (root / schedule_item["path"]).read_text(encoding="utf-8")
    )
    ended = datetime.datetime.strptime(
        schedule["ended_at"], "%Y-%m-%dT%H:%M:%SZ"
    )

    def change(rows: list[dict]) -> None:
        applied = next(
            row for row in rows
            if row["kind"] == "fault_applied"
            and row["subject"] == schedule["kind"]
        )
        recovered = next(
            row for row in rows
            if row["kind"] == "fault_recovered"
            and row["subject"] == schedule["kind"]
        )
        applied["observed_at"] = (
            ended + datetime.timedelta(seconds=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        recovered["observed_at"] = (
            ended + datetime.timedelta(seconds=2)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

    rewrite_event_log(
        root,
        lambda raw: schedule["kind"] in raw,
        change,
    )


def main() -> None:
    a_tier = profiles.role_vocabulary(
        profiles.NO_FAULT_SIGNED_RUNTIME_OBSERVER_V1
    )
    assert a_tier.singleton == frozenset(
        {
            "candidate_source",
            "linux_binary",
            "macos_binary",
            "material_builder_binary",
            "build_report",
            "topology",
            "validator_set",
            "workload_corpus",
            "workload_policy",
            "bootstrap_h1_proposal",
            "bootstrap_h2_proposal",
            "bootstrap_h3_proposal",
            "bootstrap_finality_proof",
            "bootstrap_manifest",
            "coordinator_manifest",
            "observer_public_manifest",
            "coordinator_anchor_record",
            "runner_prestart_plan",
            "runner_resource_preflight",
            "runner_clock_envelope",
            "runner_lifecycle",
            "runner_launch_observation",
            "runner_summary",
            "runner_output_manifest",
            "collector_report",
        }
    )
    assert a_tier.validator == frozenset(
        {
            "validator_config",
            "validator_deployment_manifest",
            "validator_fleet_start_certificate",
            "validator_runtime_event_journal",
            "validator_consensus_run_report",
            "validator_runtime_metrics",
            "validator_runtime_final_state",
            "validator_replay_archive_context",
            "validator_replay_archive_entries",
            "validator_replay_archive_head",
            "validator_replay_archive_terminal_seal",
            "validator_process_stdout",
            "validator_process_stderr",
        }
    )
    assert a_tier.host == frozenset({"host_run_provenance"})
    assert a_tier.host_subjects == profiles.FROZEN_LAN_HOST_SUBJECTS
    assert a_tier.observer == frozenset(
        {"observer_config", "signed_observer_report"}
    )
    assert not (profiles.LEGACY_UNSIGNED_VALIDATOR_ROLES & a_tier.validator)
    assert profiles.LEGACY_OBSERVER_REPORT_ROLE not in a_tier.observer
    external_load = profiles.role_vocabulary(
        profiles.NO_FAULT_SIGNED_RUNTIME_EXTERNAL_LOAD_V1
    )
    assert external_load.singleton == a_tier.singleton
    assert external_load.host == a_tier.host
    assert external_load.validator - a_tier.validator == {
        "validator_workload_receipt_log"
    }
    assert external_load.observer - a_tier.observer == {
        "signed_observer_load_submission_log"
    }
    profile_root_checked = False
    for count in (7, 31, 100):
        with tempfile.TemporaryDirectory(prefix="trnm-poco-g3-bundle-positive-") as raw:
            root = pathlib.Path(raw)
            build(root, count)
            anchor = next(
                entry["sha256"]
                for entry in load(root)["artifacts"]
                if entry["role"] == "coordinator_manifest"
            )
            bundle_checker.validate(
                root,
                count,
                profile=profiles.NO_FAULT_V1,
                coordinator_manifest_sha256=anchor,
                emit=False,
            )
            if not profile_root_checked:
                artifacts = load(root)["artifacts"]
                assert bundle_checker.ordered_input_root(
                    profiles.NO_FAULT_V1, artifacts
                ) != bundle_checker.ordered_input_root(
                    profiles.MIXED_AUTHORITY_FAULT_MATRIX_V1, artifacts
                )
                try:
                    bundle_checker.validate(
                        root,
                        count,
                        profile=profiles.MIXED_AUTHORITY_FAULT_MATRIX_V1,
                        coordinator_manifest_sha256=anchor,
                        emit=False,
                    )
                except SystemExit as error:
                    assert "plan-only" in str(error)
                else:
                    raise AssertionError(
                        "mixed-authority active verification unexpectedly passed"
                    )
                for planned_profile in (
                    profiles.NO_FAULT_SIGNED_RUNTIME_OBSERVER_V1,
                    profiles.NO_FAULT_SIGNED_RUNTIME_EXTERNAL_LOAD_V1,
                ):
                    try:
                        bundle_checker.validate(
                            root,
                            count,
                            profile=planned_profile,
                            coordinator_manifest_sha256=anchor,
                            emit=False,
                        )
                    except SystemExit as error:
                        assert planned_profile in str(error)
                        assert "plan-only" in str(error)
                    else:
                        raise AssertionError(
                            f"{planned_profile} active verification unexpectedly passed"
                        )
                profile_root_checked = True
    controls = (
        (lambda r: edit_manifest(r, lambda d: d.update(schema_version=2)), "schema_version must be 1"),
        (
            duplicate_bundle_manifest_key,
            "duplicate JSON object name 'geo_wan_evidence'",
        ),
        (lambda r: edit_manifest(r, lambda d: d.update(geo_wan_evidence=True)), "single-lan"),
        (lambda r: remove_artifact(r, "linux_binary"), "exactly one linux_binary"),
        (
            lambda r: remove_artifact(r, "material_builder_binary"),
            "exactly one material_builder_binary",
        ),
        (lambda r: remove_artifact(r, "validator_set"), "exactly one validator_set"),
        (
            lambda r: remove_artifact(r, "coordinator_manifest"),
            "exactly one coordinator_manifest",
        ),
        (
            lambda r: remove_artifact(r, "workload_corpus"),
            "exactly one workload_corpus",
        ),
        (
            lambda r: remove_artifact(r, "bootstrap_manifest"),
            "exactly one bootstrap_manifest",
        ),
        *(
            (
                lambda r, role=role: remove_artifact(r, role),
                f"one {role} per validator",
            )
            for role in (
                "validator_runtime_event_journal",
                "validator_fleet_start_certificate",
                "validator_consensus_run_report",
                "validator_runtime_metrics",
                "validator_runtime_final_state",
            )
        ),
        (
            tamper_signed_report_signature,
            "consensus report Ed25519 signature is invalid",
        ),
        (lambda r: tamper_first(r, "candidate_source"), "bytes mismatch"),
        (lambda r: symlink_first(r, "validator_metrics"), "non-symlink"),
        (lambda r: (r / "unreferenced").write_text("x", encoding="utf-8"), "unreferenced"),
        (
            lambda r: edit_manifest(
                r, lambda d: d["artifacts"][0].update(role="unknown")
            ),
            "unknown role",
        ),
        (
            lambda r: edit_manifest(
                r, lambda d: d["artifacts"][0].update(subject="not-empty")
            ),
            "empty subject",
        ),
        (
            lambda r: edit_manifest(
                r,
                lambda d: next(
                    entry for entry in d["artifacts"] if entry["role"] == "validator_config"
                ).update(subject="foreign"),
            ),
            "not a run validator",
        ),
        (
            lambda r: edit_manifest(
                r,
                lambda d: d.update(
                    evidence_profile=profiles.MIXED_AUTHORITY_FAULT_MATRIX_V1
                ),
            ),
            "differs from the explicit CLI profile",
        ),
        (lambda r: corrupt_collector(r, "ordered_input_root", "0" * 64), "collector report"),
        (lambda r: corrupt_collector(r, "derived_from_raw_artifacts", False), "collector report"),
        (
            lambda r: edit_manifest(
                r, lambda d: d["completed_run_summary"].update(path="../summary.json")
            ),
            "remain inside",
        ),
        (
            lambda r: edit_manifest(
                r, lambda d: d.update(run_id="poco-g3-7-20260813T120000Z-feedface")
            ),
            "run_id differs",
        ),
        (
            lambda r: rewrite_json_artifact(
                r,
                "build_report",
                lambda d: d.update(linux_second_sha256=evidence_test.digest("foreign")),
            ),
            "build binding differs",
        ),
        (
            downgrade_build_report_to_schema2,
            "aggregate build report keys must be exactly",
        ),
        (
            lambda r: rewrite_json_artifact(
                r,
                "build_report",
                lambda d: d.update(
                    linux_material_builder_second_sha256=evidence_test.digest(
                        "foreign-builder"
                    )
                ),
            ),
            "build binding differs",
        ),
        (
            lambda r: rewrite_coordinator_and_reanchor(
                r,
                lambda d: d["material_author"].update(runtime_deployed=True),
            ),
            "candidate/material author/build binding differs",
        ),
        (
            lambda r: rewrite_json_artifact(
                r,
                "coordinator_manifest",
                lambda d: d.update(production_activation=True),
            ),
            "differs from the out-of-band pre-run anchor",
        ),
        (
            duplicate_anchored_coordinator_key,
            "duplicate JSON object name 'production_activation'",
        ),
        (
            lambda r: rewrite_json_artifact(
                r,
                "validator_set",
                lambda d: d["validators"][0].update(
                    consensus_public_key=evidence_test.digest("substituted-set-key")
                ),
            ),
            "candidate/material author/build binding differs",
        ),
        (
            lambda r: rewrite_json_artifact(
                r,
                "validator_final_state",
                lambda d: d.update(finalized_state_root=evidence_test.digest("foreign")),
            ),
            "conflicts with signed final state",
        ),
        (
            lambda r: rewrite_json_artifact(
                r,
                "validator_final_state",
                lambda d: d.update(finalized_ordinary_block_count=2),
            ),
            "ordinary count/height mapping differs",
        ),
        (
            lambda r: rewrite_json_artifact(
                r,
                "validator_final_state",
                lambda d: d.update(all_finalized_ordinary_blocks_nonempty=False),
            ),
            "includes an empty finalized ordinary block",
        ),
        (
            lambda r: rewrite_json_artifact(
                r, "validator_metrics", lambda d: d.update(cpu_seconds=0)
            ),
            "conflicts with signed runtime metrics",
        ),
        (
            lambda r: rewrite_json_artifact(
                r, "validator_metrics", lambda d: d.update(cpu_seconds=2.0)
            ),
            "conflicts with signed runtime metrics",
        ),
        (
            lambda r: rewrite_json_artifact(
                r,
                "validator_final_state",
                lambda d: d.update(process_id=d["process_id"] + 1),
            ),
            "conflicts with signed final state",
        ),
        (
            conflict_unsigned_submitted_count,
            "unsigned submitted block observation conflicts with signed report",
        ),
        (
            lambda r: rewrite_json_artifact(
                r, "validator_config", lambda d: d.update(p2p_port=39999)
            ),
            "deployment/ancestry binding differs",
        ),
        (
            lambda r: rewrite_json_artifact(
                r,
                "validator_config",
                lambda d: d.update(
                    validator_set_sha256=evidence_test.digest("foreign-validator-set")
                ),
            ),
            "differs from observer-public inputs",
        ),
        (
            coherent_foreign_validator_set_hash,
            "differs from observer-public inputs",
        ),
        (
            lambda r: rewrite_json_artifact(
                r,
                "validator_config",
                lambda d: d.update(
                    consensus_public_key=evidence_test.digest("foreign-consensus-key")
                ),
            ),
            "differs from observer-public inputs",
        ),
        (
            lambda r: rewrite_json_artifact(
                r,
                "validator_config",
                lambda d: d["peers"][0].update(
                    consensus_public_key=evidence_test.digest("substituted-peer-key")
                ),
            ),
            "deployment/ancestry binding differs",
        ),
        (add_legacy_fault_artifact, "fault artifact smuggling"),
        (
            lambda r: edit_manifest(r, lambda d: d.pop("evidence_profile")),
            "manifest keys must be exactly",
        ),
        (
            lambda r: corrupt_collector(
                r,
                "evidence_profile",
                profiles.MIXED_AUTHORITY_FAULT_MATRIX_V1,
            ),
            "collector report",
        ),
        (rewrite_summary_profile, "completed-run evidence_profile differs"),
        (
            lambda r: remove_artifact(r, "observer_config"),
            "exactly one observer_config",
        ),
        (
            lambda r: rewrite_json_artifact(
                r, "observer_config", lambda d: d.update(run_roles=["validator"])
            ),
            "coordinator public reference differs",
        ),
        (
            lambda r: rewrite_json_artifact(
                r,
                "observer_config",
                lambda d: d.update(
                    candidate_source_sha256=evidence_test.digest("foreign-source")
                ),
            ),
            "coordinator public reference differs",
        ),
        (
            lambda r: rewrite_json_artifact(
                r,
                "observer_config",
                lambda d: d.update(
                    validator_set_sha256=evidence_test.digest("foreign-validator-set")
                ),
            ),
            "coordinator public reference differs",
        ),
        (
            lambda r: rewrite_json_artifact(
                r,
                "observer_config",
                lambda d: d["validator_endpoints"][0].update(
                    consensus_public_key=evidence_test.digest("substituted-peer-key")
                ),
            ),
            "coordinator public reference differs",
        ),
        (
            lambda r: rewrite_json_artifact(
                r, "observer_report", lambda d: d.update(verified_qc_signatures=0)
            ),
            "must be a positive integer",
        ),
        (
            lambda r: rewrite_json_artifact(
                r,
                "observer_report",
                lambda d: d.update(load_submitted_nonempty_blocks=3),
            ),
            "differs from validator observation",
        ),
        (
            inject_unsigned_restart,
            "restart event does not bind the terminal process instance",
        ),
        (
            duplicate_event_jsonl_key,
            "duplicate JSON object name 'schema_version'",
        ),
    )
    for change, expected in controls:
        reject(change, expected)
    assert len(controls) == 58
    print(
        "poco_g3_run_bundle_self_test=passed positives=3 negatives=58 "
        "topologies=7,31,100 "
        "content_addressed=true raw_summary_derived=true "
        "unique_json_keys=true exact_validator_set_hash=true "
        "ordered_recovery_state_machines=true"
    )


if __name__ == "__main__":
    main()
