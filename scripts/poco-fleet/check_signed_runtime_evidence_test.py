#!/usr/bin/env python3
"""Positive and negative controls for signed G3 runtime evidence."""

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

import check_signed_runtime_evidence as checker  # noqa: E402
import check_run_evidence as run_evidence  # noqa: E402
import evidence_bundle_profiles_v1 as profiles  # noqa: E402
from poco_consensus_contract import canonical_lab_genesis_hash  # noqa: E402


RUN_ID = "poco-g3-7-20260814T000000Z-a1b2c3d4"
_SIGNATURE_CACHE: dict[tuple[str, bytes], str] = {}


def source_provenance() -> dict[str, object]:
    return {
        "source_candidate_profile": "clean-commit-v1",
        "source_base_commit": "1" * 40,
        "source_git_object_format": "sha1",
        "source_git_tree_oid": "2" * 40,
        "source_git_status_sha256": run_evidence.EMPTY_STATUS_SHA256,
        "cargo_lock_path": run_evidence.CARGO_LOCK_PATH,
        "cargo_lock_sha256": hashlib.sha256(b"cargo-lock").hexdigest(),
        "cargo_lock_bytes": len(b"cargo-lock"),
    }


def compact(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def write(root: pathlib.Path, relative: str, content: bytes) -> dict[str, object]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return {
        "path": relative,
        "sha256": hashlib.sha256(content).hexdigest(),
        "bytes": len(content),
    }


def artifact(root: pathlib.Path, role: str, subject: str, relative: str, content: bytes) -> dict[str, object]:
    return {"role": role, "subject": subject, **write(root, relative, content)}


def keypair(root: pathlib.Path, index: int) -> tuple[pathlib.Path, str]:
    secret = root / f"key-{index}.pk8"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-outform", "DER", "-out", str(secret)],
        check=True,
        capture_output=True,
    )
    public = subprocess.run(
        ["openssl", "pkey", "-inform", "DER", "-in", str(secret), "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout
    if not public.startswith(checker.ED25519_SPKI_PREFIX) or len(public) != 44:
        raise AssertionError("unexpected OpenSSL Ed25519 public key")
    return secret, public[-32:].hex()


def sign(secret: pathlib.Path, message: bytes) -> str:
    cache_key = (hashlib.sha256(secret.read_bytes()).hexdigest(), message)
    cached = _SIGNATURE_CACHE.get(cache_key)
    if cached is not None:
        return cached
    with tempfile.NamedTemporaryFile(prefix="poco-g3-signed-test-message-") as source:
        source.write(message)
        source.flush()
        signature = subprocess.run(
            [
                "openssl", "pkeyutl", "-sign", "-rawin", "-keyform", "DER",
                "-inkey", str(secret), "-in", source.name,
            ],
            check=True,
            capture_output=True,
        ).stdout
    if len(signature) != 64:
        raise AssertionError("unexpected OpenSSL Ed25519 signature")
    encoded = signature.hex()
    _SIGNATURE_CACHE[cache_key] = encoded
    return encoded


def signed_event(
    context: dict[str, object],
    secret: pathlib.Path,
    *,
    instance: int,
    sequence: int,
    monotonic_ns: int,
    kind: str,
    subject: str,
    value: int,
    previous: str,
) -> dict[str, object]:
    event: dict[str, object] = {
        "schema_version": 1,
        "run_id": context["run_id"],
        "validator_id": context["validator_id"],
        "process_instance": instance,
        "sequence": sequence,
        "monotonic_ns": monotonic_ns,
        "kind": kind,
        "subject": subject,
        "value": value,
        "coordinator_manifest_sha256": context["coordinator_manifest_sha256"],
        "validator_set_sha256": context["validator_set_sha256"],
        "config_sha256": context["config_sha256"],
        "candidate_source_sha256": context["candidate_source_sha256"],
        "binary_sha256": context["binary_sha256"],
        "previous_event_sha256": previous,
        "event_sha256": "",
        "signature": "",
        "production_activation": False,
    }
    event_hash = checker.domain_hash(
        checker.EVENT_HASH_DOMAIN,
        compact(checker.ordered(event, checker.EVENT_BODY_KEYS)),
    )
    event["event_sha256"] = event_hash.hex()
    event["signature"] = sign(
        secret,
        checker.domain_hash(checker.EVENT_SIGNATURE_DOMAIN, event_hash),
    )
    return event


def signed_report(
    context: dict[str, object],
    secret: pathlib.Path,
    set_id: str,
    terminal: dict[str, object],
) -> dict[str, object]:
    nonzero = hashlib.sha256(str(context["validator_id"]).encode("ascii")).hexdigest()
    ordinary_start_height = int(context["ordinary_start_height"])
    submitted_count = int(context.get("submitted_ordinary_block_count", 10))
    committed_count = int(context.get("committed_ordinary_block_count", 9))
    finalized_count = int(context.get("finalized_ordinary_block_count", 8))
    finalized_height = ordinary_start_height + finalized_count - 1
    requested_duration_seconds = int(context.get("requested_duration_seconds", 60))
    requested_max_blocks = int(context.get("requested_max_blocks", 100))
    pacemaker_base_timeout_seconds = 2
    terminal_drain_allowance_seconds = 30
    timeout_view_budget_allowance_seconds = 30
    timeout_view_horizon = (
        requested_duration_seconds
        + terminal_drain_allowance_seconds
        + timeout_view_budget_allowance_seconds
    )
    maximum_timeout_view_advances = (
        timeout_view_horizon + pacemaker_base_timeout_seconds - 1
    ) // pacemaker_base_timeout_seconds
    maximum_local_vote_intents = (
        requested_max_blocks + maximum_timeout_view_advances
    )
    maximum_local_timeout_intents = maximum_timeout_view_advances
    maximum_total_signer_intents = (
        maximum_local_vote_intents + maximum_local_timeout_intents
    )
    maximum_proposal_archive_entries = maximum_local_vote_intents
    maximum_quorum_certificate_archive_entries = (
        maximum_proposal_archive_entries + 1
    )
    maximum_signed_replay_archive_entries = (
        maximum_proposal_archive_entries
        + maximum_quorum_certificate_archive_entries
    )
    report: dict[str, object] = {
        "schema_version": 3,
        "run_id": context["run_id"],
        "protocol_id": "poco-bft-v0",
        "profile": "authenticated-h1-h3-bootstrap-single-epoch-bounded-consensus-v3",
        "network_scope": "single-lan",
        "validator_id": context["validator_id"],
        "validator_set_id": set_id,
        "validator_set_sha256": context["validator_set_sha256"],
        "topology_sha256": context["topology_sha256"],
        "coordinator_manifest_sha256": context["coordinator_manifest_sha256"],
        "candidate_source_sha256": context["candidate_source_sha256"],
        "binary_sha256": context["binary_sha256"],
        "config_sha256": context["config_sha256"],
        "host_id": context["host_id"],
        "process_id": terminal["value"],
        "process_instance": terminal["process_instance"],
        "requested_duration_seconds": requested_duration_seconds,
        "requested_max_blocks": requested_max_blocks,
        "pacemaker_base_timeout_seconds": pacemaker_base_timeout_seconds,
        "terminal_drain_allowance_seconds": terminal_drain_allowance_seconds,
        "timeout_view_budget_allowance_seconds": (
            timeout_view_budget_allowance_seconds
        ),
        "signer_journal_capacity": 4_096,
        "maximum_timeout_view_advances": maximum_timeout_view_advances,
        "maximum_local_vote_intents": maximum_local_vote_intents,
        "maximum_local_timeout_intents": maximum_local_timeout_intents,
        "maximum_total_signer_intents": maximum_total_signer_intents,
        "signed_replay_archive_capacity": 8_192,
        "maximum_proposal_archive_entries": maximum_proposal_archive_entries,
        "maximum_quorum_certificate_archive_entries": (
            maximum_quorum_certificate_archive_entries
        ),
        "maximum_signed_replay_archive_entries": (
            maximum_signed_replay_archive_entries
        ),
        "ordinary_start_height": ordinary_start_height,
        "started_monotonic_ns": 0,
        "ended_monotonic_ns": terminal["monotonic_ns"],
        "monotonic_clock": "process-local-std-instant",
        "external_wall_clock_temporal_provenance": False,
        "submitted_height": ordinary_start_height + submitted_count - 1,
        "committed_height": ordinary_start_height + committed_count - 1,
        "finalized_height": finalized_height,
        "submitted_ordinary_block_count": submitted_count,
        "committed_ordinary_block_count": committed_count,
        "finalized_ordinary_block_count": finalized_count,
        "application_head_block_id": context.get(
            "application_head_block_id", hashlib.sha256(b"common-block").hexdigest()
        ),
        "application_committed_height": finalized_height,
        "application_state_root": context.get(
            "application_state_root", hashlib.sha256(b"common-state").hexdigest()
        ),
        "safety_revision": 8,
        "safety_state_record_checksum": nonzero,
        "safety_record_chain_checksum": nonzero,
        "application_store_id": nonzero,
        "application_store_sequence": 8,
        "application_head_row_checksum": nonzero,
        "whole_node_checkpoint_generation": 8,
        "whole_node_checkpoint_checksum": nonzero,
        "signer_scope": nonzero,
        "signer_journal_id": nonzero,
        "signer_watermark_sequence": 8,
        "signer_chain_checksum": nonzero,
        "continuous_signed_vote_intents": 8,
        "continuous_signed_timeout_intents": 0,
        "runtime_event_sequence": terminal["sequence"],
        "runtime_event_sha256": terminal["event_sha256"],
        "safety_halt_count": 0,
        "double_vote_count": 0,
        "double_timeout_count": 0,
        "conflicting_certificate_count": 0,
        "pending_safety_persistence_count": 0,
        "pending_payload_validation_count": 0,
        "pending_signature_count": 0,
        "pending_finalization_count": 0,
        "pending_sync_count": 0,
        "unresolved_obligation_count": 0,
        "clean_stop": True,
        "validator_run_completed": True,
        "continuous_consensus_runtime": True,
        "g3_evidence_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
        "report_sha256": "",
        "signature": "",
    }
    report_hash = checker.domain_hash(
        checker.REPORT_HASH_DOMAIN,
        compact(checker.ordered(report, checker.REPORT_BODY_KEYS)),
    )
    report["report_sha256"] = report_hash.hex()
    report["signature"] = sign(
        secret,
        checker.domain_hash(checker.REPORT_SIGNATURE_DOMAIN, report_hash),
    )
    return report


def signed_metrics(
    context: dict[str, object],
    secret: pathlib.Path,
    terminal: dict[str, object],
    report: dict[str, object],
) -> dict[str, object]:
    metrics: dict[str, object] = {
        "schema_version": 2,
        "run_id": context["run_id"],
        "validator_id": context["validator_id"],
        "validator_set_sha256": context["validator_set_sha256"],
        "topology_sha256": context["topology_sha256"],
        "coordinator_manifest_sha256": context["coordinator_manifest_sha256"],
        "candidate_source_sha256": context["candidate_source_sha256"],
        "binary_sha256": context["binary_sha256"],
        "config_sha256": context["config_sha256"],
        "process_id": terminal["value"],
        "process_instance_count": terminal["process_instance"],
        "ordinary_start_height": context["ordinary_start_height"],
        "runtime_event_sequence": terminal["sequence"],
        "runtime_event_sha256": terminal["event_sha256"],
        "consensus_report_sha256": report["report_sha256"],
        "measurement_started_at": context.get(
            "measurement_started_at", "2026-08-14T01:00:00Z"
        ),
        "measurement_ended_at": context.get(
            "measurement_ended_at", "2026-08-14T02:00:00Z"
        ),
        "runtime_started_monotonic_ns": 0,
        "runtime_ended_monotonic_ns": terminal["monotonic_ns"],
        "finality_samples_ms": context.get("finality_samples_ms", [1.0, 2.0]),
        "fsync_count": context.get("fsync_count", 3),
        "cpu_seconds": context.get("cpu_seconds", 4.0),
        "peak_rss_bytes": context.get("peak_rss_bytes", 5),
        "disk_bytes": context.get("disk_bytes", 6),
        "network_tx_bytes": context.get("network_tx_bytes", 7),
        "network_rx_bytes": context.get("network_rx_bytes", 8),
        "os_metrics_corroboration": True,
        "validator_run_completed": True,
        "g3_evidence_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
        "body_sha256": "",
        "signature": "",
    }
    body_hash = checker.domain_hash(
        checker.METRICS_HASH_DOMAIN,
        compact(checker.ordered(metrics, checker.METRICS_BODY_KEYS)),
    )
    metrics["body_sha256"] = body_hash.hex()
    metrics["signature"] = sign(
        secret,
        checker.domain_hash(checker.METRICS_SIGNATURE_DOMAIN, body_hash),
    )
    return metrics


def signed_final_state(
    context: dict[str, object],
    secret: pathlib.Path,
    terminal: dict[str, object],
    final_tip: dict[str, object],
    report: dict[str, object],
    metrics: dict[str, object],
    recovered_faults: list[str],
) -> dict[str, object]:
    block_id, state_root, chain_root = str(final_tip["subject"]).split(":")
    final_state: dict[str, object] = {
        "schema_version": 3,
        "run_id": context["run_id"],
        "validator_id": context["validator_id"],
        "validator_set_sha256": context["validator_set_sha256"],
        "topology_sha256": context["topology_sha256"],
        "coordinator_manifest_sha256": context["coordinator_manifest_sha256"],
        "candidate_source_sha256": context["candidate_source_sha256"],
        "binary_sha256": context["binary_sha256"],
        "config_sha256": context["config_sha256"],
        "process_id": terminal["value"],
        "process_instance_count": terminal["process_instance"],
        "ordinary_start_height": context["ordinary_start_height"],
        "finalized_height": report["finalized_height"],
        "finalized_ordinary_block_count": report["finalized_ordinary_block_count"],
        "finalized_block_id": block_id,
        "finalized_state_root": state_root,
        "finalized_chain_root": chain_root,
        "applied_height": report["application_committed_height"],
        "finalized_nonempty_ordinary_block_count": report[
            "finalized_ordinary_block_count"
        ],
        "runtime_event_sequence": terminal["sequence"],
        "runtime_event_sha256": terminal["event_sha256"],
        "consensus_report_sha256": report["report_sha256"],
        "runtime_metrics_sha256": metrics["body_sha256"],
        "recovered_faults": sorted(recovered_faults),
        "restart_completed": terminal["process_instance"] == 2,
        "double_sign_events": 0,
        "duplicate_apply_events": 0,
        "state_drift_events": 0,
        "safety_halt_violations": 0,
        "validator_run_completed": True,
        "g3_evidence_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
        "body_sha256": "",
        "signature": "",
    }
    body_hash = checker.domain_hash(
        checker.FINAL_STATE_HASH_DOMAIN,
        compact(checker.ordered(final_state, checker.FINAL_STATE_BODY_KEYS)),
    )
    final_state["body_sha256"] = body_hash.hex()
    final_state["signature"] = sign(
        secret,
        checker.domain_hash(checker.FINAL_STATE_SIGNATURE_DOMAIN, body_hash),
    )
    return final_state


def build(root: pathlib.Path) -> str:
    source = artifact(root, "candidate_source", "", "candidate/source.tar", b"source")
    binary = artifact(root, "linux_binary", "", "candidate/linux.bin", b"linux")
    macos = artifact(root, "macos_binary", "", "candidate/macos.bin", b"macos")
    material_builder = artifact(
        root,
        "material_builder_binary",
        "",
        "candidate/material-builder-linux.bin",
        b"material-builder",
    )
    macos_builder_sha256 = hashlib.sha256(b"material-builder-macos").hexdigest()
    build_report = artifact(
        root,
        "build_report",
        "",
        "candidate/build-report.json",
        compact(
            {
                "schema_version": 3,
                "source_tree_sha256": source["sha256"],
                **source_provenance(),
                "linux_first_sha256": binary["sha256"],
                "linux_second_sha256": binary["sha256"],
                "linux_material_builder_first_sha256": material_builder["sha256"],
                "linux_material_builder_second_sha256": material_builder["sha256"],
                "macos_first_sha256": macos["sha256"],
                "macos_second_sha256": macos["sha256"],
                "macos_material_builder_first_sha256": macos_builder_sha256,
                "macos_material_builder_second_sha256": macos_builder_sha256,
                "independent_build_roots": True,
                "production_activation": False,
            }
        ),
    )
    validator_ids = sorted(hashlib.sha256(f"validator-{index}".encode()).hexdigest() for index in range(7))
    role_secrets: dict[str, dict[str, pathlib.Path]] = {}
    role_public_keys: dict[str, dict[str, str]] = {}
    for index, validator_id in enumerate(validator_ids):
        role_secrets[validator_id] = {}
        role_public_keys[validator_id] = {}
        for offset, role in enumerate(
            ("consensus", "p2p-identity", "operator-recovery")
        ):
            secret, public_key = keypair(root, index * 3 + offset)
            role_secrets[validator_id][role] = secret
            role_public_keys[validator_id][role] = public_key
    secrets = {
        validator_id: values["consensus"]
        for validator_id, values in role_secrets.items()
    }
    public_keys = {
        validator_id: values["consensus"]
        for validator_id, values in role_public_keys.items()
    }
    topology = {
        "schema_version": 1,
        "run_id": RUN_ID,
        "fleet_id": "trnm-poco-lan-six-host-2026-08-13",
        "validator_count": 7,
        "weight_profile": "equal",
        "peer_degree": 6,
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "test_keys_included": False,
        "participants": [],
        "validators": [
            {
                "index": index,
                "validator_id": validator_id,
                "host_id": f"host-{index % 5}",
                "lan_ip": f"192.168.0.{20 + index}",
                "p2p_port": 27000 + index,
                "metrics_port": 28000 + index,
                "weight": 1,
                "peers": [peer for peer in validator_ids if peer != validator_id],
            }
            for index, validator_id in enumerate(validator_ids)
        ],
    }
    topology_artifact = artifact(root, "topology", "", "topology.json", compact(topology))
    run = RUN_ID.encode("ascii")
    validators = []
    for validator_id in validator_ids:
        author = validator_id.encode("ascii")
        role_pops: dict[str, str] = {}
        for role in ("consensus", "p2p-identity", "operator-recovery"):
            role_bytes = role.encode("ascii")
            pop = (
                b"TRNM/PoCO/G3/EphemeralKeyRolePoP/v2\0"
                + len(role_bytes).to_bytes(4, "big")
                + role_bytes
                + len(run).to_bytes(4, "big")
                + run
                + len(author).to_bytes(4, "big")
                + author
            )
            role_pops[role] = sign(role_secrets[validator_id][role], pop)
        validators.append(
            {
                "validator_id": validator_id,
                "consensus_public_key": role_public_keys[validator_id]["consensus"],
                "p2p_identity_public_key": role_public_keys[validator_id][
                    "p2p-identity"
                ],
                "operator_recovery_public_key": role_public_keys[validator_id][
                    "operator-recovery"
                ],
                "voting_power": 1,
                "key_pop_signature": role_pops["consensus"],
                "p2p_identity_key_pop_signature": role_pops["p2p-identity"],
                "operator_recovery_key_pop_signature": role_pops[
                    "operator-recovery"
                ],
            }
        )
    descriptor = {
        "schema_version": 2,
        "run_id": RUN_ID,
        "chain_id": "trnm-poco-g3-lab-v0",
        "genesis_hash": canonical_lab_genesis_hash(
            "trnm-poco-g3-lab-v0",
            (
                (
                    bytes.fromhex(record["validator_id"]),
                    bytes.fromhex(record["consensus_public_key"]),
                    record["voting_power"],
                )
                for record in validators
            ),
        ).hex(),
        "protocol_version": 0,
        "epoch": 0,
        "consensus_parameters_profile": "reference-shadow-v0",
        "candidate_source_sha256": source["sha256"],
        "production_activation": False,
        "validators": validators,
    }
    set_artifact = artifact(root, "validator_set", "", "public/validator-set.json", compact(descriptor))
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
    artifacts = [
        source,
        binary,
        macos,
        material_builder,
        build_report,
        topology_artifact,
        set_artifact,
        *public_material_artifacts,
    ]
    # Deliberately contradictory unsigned observation. The authenticity gate
    # must neither consume it as finality authority nor let it override the
    # signed journal/report terminal cut.
    artifacts.append(
        artifact(
            root,
            "validator_event_log",
            validator_ids[0],
            "legacy-observation/events.jsonl",
            b'{"observed_at":"2099-01-01T00:00:00Z","finalized_height":999999}\n',
        )
    )
    configs: dict[str, dict[str, object]] = {}
    config_refs: dict[str, dict[str, object]] = {}
    plan_by_id = {item["validator_id"]: item for item in topology["validators"]}
    for validator_id in validator_ids:
        plan = plan_by_id[validator_id]
        config = {
            "schema_version": 2,
            "run_id": RUN_ID,
            "validator_id": validator_id,
            "host_id": plan["host_id"],
            "lan_ip": plan["lan_ip"],
            "p2p_port": plan["p2p_port"],
            "metrics_port": plan["metrics_port"],
            "weight": 1,
            "consensus_public_key": public_keys[validator_id],
            "p2p_identity_public_key": role_public_keys[validator_id][
                "p2p-identity"
            ],
            "operator_recovery_public_key": role_public_keys[validator_id][
                "operator-recovery"
            ],
            "validator_set_sha256": set_artifact["sha256"],
            "binary_sha256": binary["sha256"],
            "ordinary_start_height": 4,
            "workload_corpus_sha256": hashlib.sha256(b"workload-corpus").hexdigest(),
            "workload_policy_sha256": hashlib.sha256(b"workload-policy").hexdigest(),
            "consensus_secret_key_path": f"secrets/consensus/{validator_id}.pk8",
            "p2p_identity_secret_key_path": (
                f"secrets/p2p-identity/{validator_id}.pk8"
            ),
            "operator_recovery_secret_key_path": (
                f"secrets/operator-recovery/{validator_id}.pk8"
            ),
            "peers": [],
            "network_scope": "single-lan",
            "geo_wan_evidence": False,
            "production_activation": False,
        }
        ref = artifact(
            root,
            "validator_config",
            validator_id,
            f"public/configs/{validator_id}.json",
            compact(config),
        )
        artifacts.append(ref)
        configs[validator_id] = config
        config_refs[validator_id] = ref
    observer_config_artifact = artifact(
        root,
        "observer_config",
        "mac",
        "public/observer-configs/mac.json",
        b"observer-config",
    )
    artifacts.append(observer_config_artifact)
    coordinator = {
        "schema_version": 2,
        "run_id": RUN_ID,
        "fleet_id": "trnm-poco-lan-six-host-2026-08-13",
        "validator_count": 7,
        "weight_profile": "equal",
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "candidate": {
            "source_tree_sha256": source["sha256"],
            "linux_x86_64_sha256": binary["sha256"],
            "macos_arm64_sha256": macos["sha256"],
        },
        "material_author": {
            "binary_sha256": material_builder["sha256"],
            "runtime_deployed": False,
        },
        "validator_set_sha256": set_artifact["sha256"],
        "public_files": [
            {
                "path": "topology.json",
                "sha256": topology_artifact["sha256"],
                "bytes": topology_artifact["bytes"],
            },
            {
                "path": "public/validator-set.json",
                "sha256": set_artifact["sha256"],
                "bytes": set_artifact["bytes"],
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
                    "sha256": config_refs[validator_id]["sha256"],
                    "bytes": config_refs[validator_id]["bytes"],
                }
                for validator_id in validator_ids
            ],
            {
                "path": "public/observer-configs/mac.json",
                "sha256": observer_config_artifact["sha256"],
                "bytes": observer_config_artifact["bytes"],
            },
        ],
        "secret_files": [
            {
                "path": f"secrets/{role}/{validator_id}.pk8",
                "sha256": hashlib.sha256(
                    role_secrets[validator_id][role].read_bytes()
                ).hexdigest(),
                "bytes": role_secrets[validator_id][role].stat().st_size,
            }
            for validator_id in validator_ids
            for role in ("consensus", "p2p-identity", "operator-recovery")
        ],
        "production_activation": False,
    }
    coordinator_artifact = artifact(
        root, "coordinator_manifest", "", "coordinator-manifest.json", compact(coordinator)
    )
    artifacts.append(coordinator_artifact)
    coordinator_hash = str(coordinator_artifact["sha256"])
    set_id = checker.validator_set_id(descriptor)
    fault_assignments: dict[str, list[str]] = {validator_id: [] for validator_id in validator_ids}
    for validator_id in validator_ids:
        context: dict[str, object] = {
            "run_id": RUN_ID,
            "validator_id": validator_id,
            "host_id": configs[validator_id]["host_id"],
            "validator_set_sha256": set_artifact["sha256"],
            "topology_sha256": topology_artifact["sha256"],
            "coordinator_manifest_sha256": coordinator_hash,
            "candidate_source_sha256": source["sha256"],
            "binary_sha256": binary["sha256"],
            "config_sha256": config_refs[validator_id]["sha256"],
            "ordinary_start_height": configs[validator_id]["ordinary_start_height"],
        }
        events: list[dict[str, object]] = []
        instance = 1
        process_id = 1000 + validator_ids.index(validator_id)
        monotonic_ns = 0

        def append_event(kind: str, subject: str, value: int, *, reset_clock: bool = False) -> None:
            nonlocal monotonic_ns
            if reset_clock:
                monotonic_ns = 0
            elif events:
                monotonic_ns += 1
            previous = str(events[-1]["event_sha256"]) if events else "0" * 64
            events.append(
                signed_event(
                    context,
                    secrets[validator_id],
                    instance=instance,
                    sequence=len(events),
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
        append_event(
            "finalized",
            hashlib.sha256(b"common-block").hexdigest(),
            11,
        )
        append_event(
            "application_acknowledged",
            hashlib.sha256(b"common-state").hexdigest(),
            11,
        )
        for fault in fault_assignments[validator_id]:
            append_event("fault_applied", fault, 1)
            if fault == "validator_process_kill":
                instance = 2
                process_id += 10_000
                append_event("process_start", "instance-2", process_id, reset_clock=True)
                append_event("restart", "instance-2", process_id)
                append_event(
                    "catchup_complete",
                    hashlib.sha256(b"common-block").hexdigest(),
                    11,
                )
                append_event("fault_recovered", fault, 11)
            else:
                append_event("fault_recovered", fault, 11)
        append_event(
            "final_tip",
            ":".join(
                (
                    hashlib.sha256(b"common-block").hexdigest(),
                    hashlib.sha256(b"common-state").hexdigest(),
                    hashlib.sha256(b"common-chain").hexdigest(),
                )
            ),
            11,
        )
        append_event("clean_stop", "bounded-run-complete", process_id)
        final_tip = events[-2]
        stop = events[-1]
        journal = b"".join(compact(event) + b"\n" for event in events)
        artifacts.append(
            artifact(
                root,
                "validator_fleet_start_certificate",
                validator_id,
                f"validators/{validator_id}/fleet-start-certificate.bin",
                b"common-n-of-n-start-certificate",
            )
        )
        artifacts.append(
            artifact(
                root,
                "validator_runtime_event_journal",
                validator_id,
                f"validators/{validator_id}/runtime-events.jsonl",
                journal,
            )
        )
        report = signed_report(context, secrets[validator_id], set_id, stop)
        artifacts.append(
            artifact(
                root,
                "validator_consensus_run_report",
                validator_id,
                f"validators/{validator_id}/consensus-report.json",
                compact(report),
            )
        )
        metrics = signed_metrics(context, secrets[validator_id], stop, report)
        artifacts.append(
            artifact(
                root,
                "validator_runtime_metrics",
                validator_id,
                f"validators/{validator_id}/runtime-metrics.json",
                compact(metrics),
            )
        )
        final_state = signed_final_state(
            context,
            secrets[validator_id],
            stop,
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
                f"validators/{validator_id}/runtime-final-state.json",
                compact(final_state),
            )
        )
    manifest = {
        "schema_version": 1,
        "evidence_profile": profiles.NO_FAULT_V1,
        "run_id": RUN_ID,
        "validator_count": 7,
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "artifacts": artifacts,
    }
    (root / "manifest.json").write_bytes(compact(manifest))
    return coordinator_hash


def refresh_ref(root: pathlib.Path, role: str, subject: str) -> None:
    manifest = json.loads((root / "manifest.json").read_text())
    for record in manifest["artifacts"]:
        if record["role"] == role and record["subject"] == subject:
            content = (root / record["path"]).read_bytes()
            record["sha256"] = hashlib.sha256(content).hexdigest()
            record["bytes"] = len(content)
            break
    else:
        raise AssertionError("artifact not found")
    (root / "manifest.json").write_bytes(compact(manifest))


def rewrite_signed_journal(
    root: pathlib.Path,
    validator_id: str,
    mutate,
) -> None:
    manifest = json.loads((root / "manifest.json").read_text())
    journal_ref = next(
        item
        for item in manifest["artifacts"]
        if item["role"] == "validator_runtime_event_journal"
        and item["subject"] == validator_id
    )
    journal_path = root / journal_ref["path"]
    events = [json.loads(line) for line in journal_path.read_text().splitlines()]
    mutate(events)
    validator_ids = sorted(
        item["subject"]
        for item in manifest["artifacts"]
        if item["role"] == "validator_runtime_event_journal"
    )
    secret = root / f"key-{validator_ids.index(validator_id) * 3}.pk8"
    previous = bytes(32)
    for sequence, event in enumerate(events):
        event["sequence"] = sequence
        event["previous_event_sha256"] = previous.hex()
        event["event_sha256"] = ""
        event["signature"] = ""
        event_hash = checker.domain_hash(
            checker.EVENT_HASH_DOMAIN,
            compact(checker.ordered(event, checker.EVENT_BODY_KEYS)),
        )
        event["event_sha256"] = event_hash.hex()
        event["signature"] = sign(
            secret,
            checker.domain_hash(checker.EVENT_SIGNATURE_DOMAIN, event_hash),
        )
        previous = event_hash
    journal_path.write_bytes(b"".join(compact(event) + b"\n" for event in events))
    refresh_ref(root, "validator_runtime_event_journal", validator_id)

    manifest = json.loads((root / "manifest.json").read_text())
    report_ref = next(
        item
        for item in manifest["artifacts"]
        if item["role"] == "validator_consensus_run_report"
        and item["subject"] == validator_id
    )
    report_path = root / report_ref["path"]
    report = json.loads(report_path.read_text())
    terminal = events[-1]
    report["process_id"] = terminal["value"]
    report["process_instance"] = terminal["process_instance"]
    report["ended_monotonic_ns"] = terminal["monotonic_ns"]
    report["runtime_event_sequence"] = terminal["sequence"]
    report["runtime_event_sha256"] = terminal["event_sha256"]
    report["report_sha256"] = ""
    report["signature"] = ""
    report_hash = checker.domain_hash(
        checker.REPORT_HASH_DOMAIN,
        compact(checker.ordered(report, checker.REPORT_BODY_KEYS)),
    )
    report["report_sha256"] = report_hash.hex()
    report["signature"] = sign(
        secret,
        checker.domain_hash(checker.REPORT_SIGNATURE_DOMAIN, report_hash),
    )
    report_path.write_bytes(compact(report))
    refresh_ref(root, "validator_consensus_run_report", validator_id)

    manifest = json.loads((root / "manifest.json").read_text())
    metrics_ref = next(
        item
        for item in manifest["artifacts"]
        if item["role"] == "validator_runtime_metrics"
        and item["subject"] == validator_id
    )
    metrics_path = root / metrics_ref["path"]
    metrics = json.loads(metrics_path.read_text())
    metrics.update(
        {
            "process_id": terminal["value"],
            "process_instance_count": terminal["process_instance"],
            "runtime_event_sequence": terminal["sequence"],
            "runtime_event_sha256": terminal["event_sha256"],
            "consensus_report_sha256": report["report_sha256"],
            "runtime_ended_monotonic_ns": terminal["monotonic_ns"],
            "body_sha256": "",
            "signature": "",
        }
    )
    metrics_hash = checker.domain_hash(
        checker.METRICS_HASH_DOMAIN,
        compact(checker.ordered(metrics, checker.METRICS_BODY_KEYS)),
    )
    metrics["body_sha256"] = metrics_hash.hex()
    metrics["signature"] = sign(
        secret,
        checker.domain_hash(checker.METRICS_SIGNATURE_DOMAIN, metrics_hash),
    )
    metrics_path.write_bytes(compact(metrics))
    refresh_ref(root, "validator_runtime_metrics", validator_id)

    manifest = json.loads((root / "manifest.json").read_text())
    final_ref = next(
        item
        for item in manifest["artifacts"]
        if item["role"] == "validator_runtime_final_state"
        and item["subject"] == validator_id
    )
    final_path = root / final_ref["path"]
    final_state = json.loads(final_path.read_text())
    final_tip = next(event for event in events if event["kind"] == "final_tip")
    tip_block, tip_state, tip_chain = str(final_tip["subject"]).split(":")
    recovered_faults = sorted(
        str(event["subject"])
        for event in events
        if event["kind"] == "fault_recovered"
    )
    final_state.update(
        {
            "process_id": terminal["value"],
            "process_instance_count": terminal["process_instance"],
            "finalized_block_id": tip_block,
            "finalized_state_root": tip_state,
            "finalized_chain_root": tip_chain,
            "runtime_event_sequence": terminal["sequence"],
            "runtime_event_sha256": terminal["event_sha256"],
            "consensus_report_sha256": report["report_sha256"],
            "runtime_metrics_sha256": metrics["body_sha256"],
            "recovered_faults": recovered_faults,
            "restart_completed": terminal["process_instance"] == 2,
            "body_sha256": "",
            "signature": "",
        }
    )
    final_hash = checker.domain_hash(
        checker.FINAL_STATE_HASH_DOMAIN,
        compact(checker.ordered(final_state, checker.FINAL_STATE_BODY_KEYS)),
    )
    final_state["body_sha256"] = final_hash.hex()
    final_state["signature"] = sign(
        secret,
        checker.domain_hash(checker.FINAL_STATE_SIGNATURE_DOMAIN, final_hash),
    )
    final_path.write_bytes(compact(final_state))
    refresh_ref(root, "validator_runtime_final_state", validator_id)


def rewrite_signed_report_until_semantic_rejection(
    root: pathlib.Path,
    validator_id: str,
    mutate,
) -> None:
    manifest = json.loads((root / "manifest.json").read_text())
    report_ref = next(
        item
        for item in manifest["artifacts"]
        if item["role"] == "validator_consensus_run_report"
        and item["subject"] == validator_id
    )
    validator_ids = sorted(
        item["subject"]
        for item in manifest["artifacts"]
        if item["role"] == "validator_runtime_event_journal"
    )
    secret = root / f"key-{validator_ids.index(validator_id) * 3}.pk8"
    report_path = root / report_ref["path"]
    report = json.loads(report_path.read_text())
    mutate(report)
    report["report_sha256"] = ""
    report["signature"] = ""
    report_hash = checker.domain_hash(
        checker.REPORT_HASH_DOMAIN,
        compact(checker.ordered(report, checker.REPORT_BODY_KEYS)),
    )
    report["report_sha256"] = report_hash.hex()
    report["signature"] = sign(
        secret,
        checker.domain_hash(checker.REPORT_SIGNATURE_DOMAIN, report_hash),
    )
    report_path.write_bytes(compact(report))
    refresh_ref(root, "validator_consensus_run_report", validator_id)


def reject(root: pathlib.Path, count: int, anchor: str, expected: str) -> None:
    try:
        checker.validate(
            root, count, anchor, profile=profiles.NO_FAULT_V1, emit=False
        )
    except SystemExit as error:
        if expected not in str(error):
            raise AssertionError(f"expected {expected!r}, observed {error!s}") from error
    else:
        raise AssertionError(f"mutant unexpectedly passed: {expected}")


def clone(source: pathlib.Path, target: pathlib.Path) -> None:
    import shutil

    shutil.copytree(source, target)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="poco-g3-signed-runtime-test-") as raw:
        root = pathlib.Path(raw) / "base"
        root.mkdir()
        anchor = build(root)
        checker.validate(
            root, 7, anchor, profile=profiles.NO_FAULT_V1, emit=False
        )

        legacy = pathlib.Path(raw) / "legacy-build-report-schema2"
        clone(root, legacy)
        manifest = json.loads((legacy / "manifest.json").read_text())
        build_ref = next(
            item for item in manifest["artifacts"] if item["role"] == "build_report"
        )
        build_path = legacy / build_ref["path"]
        build_report = json.loads(build_path.read_text())
        build_report["schema_version"] = 2
        for field in run_evidence.SOURCE_PROVENANCE_KEYS:
            build_report.pop(field)
        build_path.write_bytes(compact(build_report))
        refresh_ref(legacy, "build_report", "")
        reject(
            legacy,
            7,
            anchor,
            "aggregate build report keys must be exactly",
        )

        validator_id = sorted(
            record["subject"]
            for record in json.loads((root / "manifest.json").read_text())["artifacts"]
            if record["role"] == "validator_runtime_event_journal"
        )[0]
        cases = []
        for name in (
            "event-signature",
            "event-tail",
            "report-event-bind",
            "report-signature",
            "unknown-signed-event",
            "missing-signed-fault",
            "duplicate-signed-fault",
            "missing-signed-restart",
            "missing-signed-metrics",
            "metrics-signature",
            "metrics-report-bind",
            "final-state-signature",
            "final-state-metrics-bind",
            "final-state-nonempty-count",
            "catchup-terminal-bind",
            "fault-terminal-bind",
            "report-timeout-cap",
            "report-time-budget-authority",
            "missing-fleet-ready",
            "reordered-fleet-barrier",
            "fleet-barrier-round-mismatch",
            "consensus-before-fleet-start",
            "fleet-certificate-digest-disagreement",
            "fleet-certificate-artifact-substitution",
            "missing-workload-corpus",
            "workload-artifact-config-bind",
        ):
            target = pathlib.Path(raw) / name
            clone(root, target)
            cases.append((name, target))

        target = cases[0][1]
        manifest = json.loads((target / "manifest.json").read_text())
        ref = next(item for item in manifest["artifacts"] if item["role"] == "validator_runtime_event_journal" and item["subject"] == validator_id)
        path = target / ref["path"]
        lines = path.read_text().splitlines()
        event = json.loads(lines[-1])
        event["signature"] = ("00" if event["signature"][:2] != "00" else "01") + event["signature"][2:]
        lines[-1] = compact(event).decode()
        path.write_text("\n".join(lines) + "\n")
        refresh_ref(target, "validator_runtime_event_journal", validator_id)
        reject(target, 7, anchor, "Ed25519 signature is invalid")

        target = cases[1][1]
        manifest = json.loads((target / "manifest.json").read_text())
        ref = next(item for item in manifest["artifacts"] if item["role"] == "validator_runtime_event_journal" and item["subject"] == validator_id)
        path = target / ref["path"]
        path.write_bytes(path.read_bytes()[:-1])
        refresh_ref(target, "validator_runtime_event_journal", validator_id)
        reject(target, 7, anchor, "exact framing bound")

        target = cases[2][1]
        manifest = json.loads((target / "manifest.json").read_text())
        ref = next(item for item in manifest["artifacts"] if item["role"] == "validator_consensus_run_report" and item["subject"] == validator_id)
        path = target / ref["path"]
        report = json.loads(path.read_text())
        report["runtime_event_sequence"] += 1
        path.write_bytes(compact(report))
        refresh_ref(target, "validator_consensus_run_report", validator_id)
        reject(target, 7, anchor, "does not bind the signed runtime journal")

        target = cases[3][1]
        manifest = json.loads((target / "manifest.json").read_text())
        ref = next(item for item in manifest["artifacts"] if item["role"] == "validator_consensus_run_report" and item["subject"] == validator_id)
        path = target / ref["path"]
        report = json.loads(path.read_text())
        report["signature"] = ("00" if report["signature"][:2] != "00" else "01") + report["signature"][2:]
        path.write_bytes(compact(report))
        refresh_ref(target, "validator_consensus_run_report", validator_id)
        reject(target, 7, anchor, "Ed25519 signature is invalid")

        target = cases[4][1]
        rewrite_signed_journal(
            target,
            validator_id,
            lambda events: events[1].__setitem__("kind", "invented_runtime_claim"),
        )
        reject(target, 7, anchor, "unknown event kind")

        target = cases[5][1]
        all_validator_ids = sorted(
            item["subject"]
            for item in json.loads((target / "manifest.json").read_text())["artifacts"]
            if item["role"] == "validator_runtime_event_journal"
        )

        def add_legacy_fault(events: list[dict[str, object]]) -> None:
            insert_at = next(index for index, event in enumerate(events) if event["kind"] == "final_tip")
            prior = events[insert_at - 1]
            applied = copy.deepcopy(prior)
            applied.update({"kind": "fault_applied", "subject": "leader_loss", "value": 1})
            recovered = copy.deepcopy(prior)
            recovered.update({"kind": "fault_recovered", "subject": "leader_loss", "value": 11})
            events[insert_at:insert_at] = [applied, recovered]

        rewrite_signed_journal(target, validator_id, add_legacy_fault)
        reject(target, 7, anchor, "zero signed fault transitions")

        target = cases[6][1]

        def add_restart(events: list[dict[str, object]]) -> None:
            insert_at = next(
                index for index, event in enumerate(events) if event["kind"] == "final_tip"
            )
            prior = events[insert_at - 1]
            process_id = int(events[0]["value"]) + 10_000
            process_start = copy.deepcopy(prior)
            process_start.update(
                {
                    "process_instance": 2,
                    "monotonic_ns": 0,
                    "kind": "process_start",
                    "subject": "instance-2",
                    "value": process_id,
                }
            )
            restart = copy.deepcopy(process_start)
            restart.update({"monotonic_ns": 1, "kind": "restart"})
            catchup = copy.deepcopy(process_start)
            catchup.update(
                {
                    "monotonic_ns": 2,
                    "kind": "catchup_complete",
                    "subject": hashlib.sha256(b"common-block").hexdigest(),
                    "value": 11,
                }
            )
            events[insert_at:insert_at] = [process_start, restart, catchup]
            monotonic = 2
            for event in events[insert_at + 3 :]:
                monotonic += 1
                event["process_instance"] = 2
                event["monotonic_ns"] = monotonic
                if event["kind"] == "clean_stop":
                    event["value"] = process_id

        rewrite_signed_journal(target, validator_id, add_restart)
        reject(target, 7, anchor, "process_instance=1 for every validator")

        target = cases[7][1]
        manifest = json.loads((target / "manifest.json").read_text())
        manifest["evidence_profile"] = profiles.MIXED_AUTHORITY_FAULT_MATRIX_V1
        (target / "manifest.json").write_bytes(compact(manifest))
        reject(target, 7, anchor, "differs from the explicit CLI profile")

        target = cases[8][1]
        manifest = json.loads((target / "manifest.json").read_text())
        manifest["artifacts"] = [
            item
            for item in manifest["artifacts"]
            if not (
                item["role"] == "validator_runtime_metrics"
                and item["subject"] == validator_id
            )
        ]
        (target / "manifest.json").write_bytes(compact(manifest))
        reject(target, 7, anchor, "one validator_runtime_metrics per validator")

        target = cases[9][1]
        manifest = json.loads((target / "manifest.json").read_text())
        ref = next(
            item
            for item in manifest["artifacts"]
            if item["role"] == "validator_runtime_metrics"
            and item["subject"] == validator_id
        )
        path = target / ref["path"]
        metrics = json.loads(path.read_text())
        metrics["signature"] = (
            ("00" if metrics["signature"][:2] != "00" else "01")
            + metrics["signature"][2:]
        )
        path.write_bytes(compact(metrics))
        refresh_ref(target, "validator_runtime_metrics", validator_id)
        reject(target, 7, anchor, "runtime metrics Ed25519 signature is invalid")

        target = cases[10][1]
        manifest = json.loads((target / "manifest.json").read_text())
        ref = next(
            item
            for item in manifest["artifacts"]
            if item["role"] == "validator_runtime_metrics"
            and item["subject"] == validator_id
        )
        path = target / ref["path"]
        metrics = json.loads(path.read_text())
        metrics["consensus_report_sha256"] = hashlib.sha256(b"wrong-report").hexdigest()
        path.write_bytes(compact(metrics))
        refresh_ref(target, "validator_runtime_metrics", validator_id)
        reject(target, 7, anchor, "consensus_report_sha256 differs from the terminal cut")

        target = cases[11][1]
        manifest = json.loads((target / "manifest.json").read_text())
        ref = next(
            item
            for item in manifest["artifacts"]
            if item["role"] == "validator_runtime_final_state"
            and item["subject"] == validator_id
        )
        path = target / ref["path"]
        final_state = json.loads(path.read_text())
        final_state["signature"] = (
            ("00" if final_state["signature"][:2] != "00" else "01")
            + final_state["signature"][2:]
        )
        path.write_bytes(compact(final_state))
        refresh_ref(target, "validator_runtime_final_state", validator_id)
        reject(target, 7, anchor, "runtime final state Ed25519 signature is invalid")

        target = cases[12][1]
        manifest = json.loads((target / "manifest.json").read_text())
        ref = next(
            item
            for item in manifest["artifacts"]
            if item["role"] == "validator_runtime_final_state"
            and item["subject"] == validator_id
        )
        path = target / ref["path"]
        final_state = json.loads(path.read_text())
        final_state["runtime_metrics_sha256"] = hashlib.sha256(b"wrong-metrics").hexdigest()
        path.write_bytes(compact(final_state))
        refresh_ref(target, "validator_runtime_final_state", validator_id)
        reject(target, 7, anchor, "runtime_metrics_sha256 differs from the terminal evidence chain")

        target = cases[13][1]
        manifest = json.loads((target / "manifest.json").read_text())
        ref = next(
            item
            for item in manifest["artifacts"]
            if item["role"] == "validator_runtime_final_state"
            and item["subject"] == validator_id
        )
        path = target / ref["path"]
        final_state = json.loads(path.read_text())
        final_state["finalized_nonempty_ordinary_block_count"] -= 1
        path.write_bytes(compact(final_state))
        refresh_ref(target, "validator_runtime_final_state", validator_id)
        reject(target, 7, anchor, "includes an empty finalized ordinary block")

        target = cases[14][1]
        manifest = json.loads((target / "manifest.json").read_text())
        manifest.pop("evidence_profile")
        (target / "manifest.json").write_bytes(compact(manifest))
        reject(target, 7, anchor, "bundle evidence_profile differs")

        target = cases[15][1]
        rewrite_signed_journal(
            target,
            all_validator_ids[1],
            add_legacy_fault,
        )
        reject(target, 7, anchor, "zero signed fault transitions")

        target = cases[16][1]
        rewrite_signed_report_until_semantic_rejection(
            target,
            validator_id,
            lambda report: report.__setitem__(
                "maximum_local_timeout_intents",
                int(report["maximum_local_timeout_intents"]) - 1,
            ),
        )
        reject(target, 7, anchor, "signer/archive lifetime accounting differs")

        target = cases[18][1]
        rewrite_signed_journal(
            target,
            validator_id,
            lambda events: events.__setitem__(
                slice(None),
                [event for event in events if event["kind"] != "fleet_ready"],
            ),
        )
        reject(target, 7, anchor, "fleet Started does not immediately bind Ready")

        target = cases[19][1]

        def reorder_fleet_barrier(events: list[dict[str, object]]) -> None:
            ready = next(index for index, event in enumerate(events) if event["kind"] == "fleet_ready")
            started = next(index for index, event in enumerate(events) if event["kind"] == "fleet_started")
            events[ready], events[started] = events[started], events[ready]

        rewrite_signed_journal(target, validator_id, reorder_fleet_barrier)
        reject(target, 7, anchor, "fleet Started does not immediately bind Ready")

        target = cases[20][1]
        rewrite_signed_journal(
            target,
            validator_id,
            lambda events: next(
                event for event in events if event["kind"] == "fleet_started"
            ).__setitem__("value", 2),
        )
        reject(target, 7, anchor, "fleet Started does not immediately bind Ready")

        target = cases[21][1]

        def move_vote_before_start(events: list[dict[str, object]]) -> None:
            vote = next(
                event for event in events if event["kind"] == "vote_broadcast"
            )
            events.remove(vote)
            ready = next(
                index for index, event in enumerate(events) if event["kind"] == "fleet_ready"
            )
            events.insert(ready, vote)

        rewrite_signed_journal(target, validator_id, move_vote_before_start)
        reject(target, 7, anchor, "ordinary consensus event precedes fleet Started/catch-up")

        target = cases[22][1]
        rewrite_signed_journal(
            target,
            validator_id,
            lambda events: next(
                event for event in events if event["kind"] == "fleet_started"
            ).__setitem__(
                "subject", hashlib.sha256(b"valid-but-foreign-certificate").hexdigest()
            ),
        )
        manifest = json.loads((target / "manifest.json").read_text())
        ref = next(
            item
            for item in manifest["artifacts"]
            if item["role"] == "validator_fleet_start_certificate"
            and item["subject"] == validator_id
        )
        (target / ref["path"]).write_bytes(b"valid-but-foreign-certificate")
        refresh_ref(target, "validator_fleet_start_certificate", validator_id)
        reject(target, 7, anchor, "validators disagree on the exact N/N fleet barrier")

        target = cases[23][1]
        manifest = json.loads((target / "manifest.json").read_text())
        ref = next(
            item
            for item in manifest["artifacts"]
            if item["role"] == "validator_fleet_start_certificate"
            and item["subject"] == validator_id
        )
        (target / ref["path"]).write_bytes(b"substituted-start-certificate")
        refresh_ref(
            target, "validator_fleet_start_certificate", validator_id
        )
        reject(
            target,
            7,
            anchor,
            "StartCertificate artifact does not bind the signed FleetStarted event",
        )

        target = cases[17][1]
        rewrite_signed_report_until_semantic_rejection(
            target,
            validator_id,
            lambda report: report.__setitem__(
                "timeout_view_budget_allowance_seconds", 31
            ),
        )
        reject(target, 7, anchor, "signer/archive lifetime accounting differs")

        target = cases[24][1]
        manifest = json.loads((target / "manifest.json").read_text())
        manifest["artifacts"] = [
            item for item in manifest["artifacts"] if item["role"] != "workload_corpus"
        ]
        (target / "manifest.json").write_bytes(compact(manifest))
        reject(target, 7, anchor, "missing signed runtime artifact role='workload_corpus'")

        target = cases[25][1]
        manifest = json.loads((target / "manifest.json").read_text())
        workload_ref = next(
            item for item in manifest["artifacts"] if item["role"] == "workload_corpus"
        )
        (target / workload_ref["path"]).write_bytes(b"foreign-workload-corpus")
        refresh_ref(target, "workload_corpus", "")
        reject(
            target,
            7,
            anchor,
            "validator configs do not bind the exact public workload artifacts",
        )

    print(
        "poco_g3_signed_runtime_evidence_tests=passed positives=1 negatives=27 "
        "unsigned_observation_authority=false g3_complete=false"
    )


if __name__ == "__main__":
    main()
