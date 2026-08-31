#!/usr/bin/env python3
"""Strict verifier for one completed PoCO G3 LAN validator run.

The inventory/reachability baseline deliberately does not invoke this checker:
it accepts only a real, independently-process-hosted 7/31/100-validator run.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import ipaddress
import json
import math
import pathlib
import re
import tomllib

import evidence_bundle_profiles_v1 as evidence_profiles


ROOT = pathlib.Path(__file__).resolve().parents[2]
INVENTORY = pathlib.Path(__file__).with_name("inventory.toml")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
RUN_ID = re.compile(r"^poco-g3-(7|31|100)-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
REQUIRED_FAULTS = {
    "leader_loss",
    "validator_process_kill",
    "host_loss",
    "asymmetric_partition",
    "bounded_delay_loss",
    "stale_snapshot",
    "rollback_attempt",
    "epoch_handoff",
}
EMPTY_STATUS_SHA256 = hashlib.sha256(b"").hexdigest()
CARGO_LOCK_PATH = "trillionnium/Cargo.lock"
SOURCE_PROVENANCE_KEYS = {
    "source_candidate_profile",
    "source_base_commit",
    "source_git_object_format",
    "source_git_tree_oid",
    "source_git_status_sha256",
    "cargo_lock_path",
    "cargo_lock_sha256",
    "cargo_lock_bytes",
}


def fail(message: str) -> None:
    raise SystemExit(f"PoCO G3 run evidence invalid: {message}")


def unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate object names in every evidence JSON document."""
    value: dict[str, object] = {}
    for key, child in pairs:
        if key in value:
            fail(f"duplicate JSON object name {key!r}")
        value[key] = child
    return value


def read_json(path: pathlib.Path, field: str) -> dict:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_json_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"{field} is not one exact UTF-8 JSON document: {error}")
    if not isinstance(value, dict):
        fail(f"{field} must be one JSON object")
    return value


def exact_keys(value: object, expected: set[str], field: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{field} keys must be exactly {sorted(expected)!r}")
    return value


def validate_source_provenance(value: dict, field: str, *, fail_fn=fail) -> None:
    """Require the clean-commit provenance carried by schema-3 build evidence."""

    object_format = value.get("source_git_object_format")
    oid_length = 40 if object_format == "sha1" else 64 if object_format == "sha256" else 0
    base_commit = value.get("source_base_commit")
    tree_oid = value.get("source_git_tree_oid")
    if value.get("source_candidate_profile") != "clean-commit-v1":
        fail_fn(f"{field}.source_candidate_profile must be clean-commit-v1")
    if (
        not isinstance(base_commit, str)
        or len(base_commit) != oid_length
        or re.fullmatch(r"[0-9a-f]+", base_commit) is None
    ):
        fail_fn(f"{field}.source_base_commit must match the Git object format")
    if (
        not isinstance(tree_oid, str)
        or len(tree_oid) != oid_length
        or re.fullmatch(r"[0-9a-f]+", tree_oid) is None
    ):
        fail_fn(f"{field}.source_git_tree_oid must match the Git object format")
    if value.get("source_git_status_sha256") != EMPTY_STATUS_SHA256:
        fail_fn(f"{field}.source_git_status_sha256 must bind an empty Git status")
    if value.get("cargo_lock_path") != CARGO_LOCK_PATH:
        fail_fn(f"{field}.cargo_lock_path must be {CARGO_LOCK_PATH}")
    cargo_lock_sha256 = value.get("cargo_lock_sha256")
    if not isinstance(cargo_lock_sha256, str) or not HEX64.fullmatch(cargo_lock_sha256):
        fail_fn(f"{field}.cargo_lock_sha256 must be canonical sha256")
    cargo_lock_bytes = value.get("cargo_lock_bytes")
    if (
        isinstance(cargo_lock_bytes, bool)
        or not isinstance(cargo_lock_bytes, int)
        or cargo_lock_bytes <= 0
    ):
        fail_fn(f"{field}.cargo_lock_bytes must be a positive integer")


def positive_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        fail(f"{field} must be positive")
    return float(value)


def positive_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"{field} must be a positive integer")
    return value


def zero_integer(value: object, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value != 0:
        fail(f"{field} must be zero")


def validator_identity(fleet_id: str, index: int) -> str:
    return hashlib.sha256(
        f"{fleet_id}/validator/{index:03d}".encode("ascii")
    ).hexdigest()


def expected_validators(inventory: dict, count: int, profile: str) -> dict[str, dict]:
    topology_key = {7: "seven", 31: "thirty_one", 100: "one_hundred"}[count]
    expected: dict[str, dict] = {}
    index = 0
    for host in inventory["hosts"]:
        for _ in range(host["validator_counts"][topology_key]):
            validator_id = validator_identity(inventory["fleet_id"], index)
            expected[validator_id] = {
                "host_id": host["id"],
                "lan_ip": host["lan_ip"],
                "p2p_port": 31000 + index,
                "metrics_port": 32000 + index,
                "weight": 1 if profile == "equal" else 1 + ((index * 17 + 3) % 4),
                "os": host["os"],
            }
            index += 1
    if index != count:
        fail("inventory allocation does not match validator_count")
    return expected


def configuration_set_digest(validators: list[dict]) -> str:
    digest = hashlib.sha256()
    digest.update(b"TRNM/PoCO/G3/ConfigurationSet/v1\0")
    for validator in sorted(validators, key=lambda item: item["validator_id"]):
        validator_id = validator["validator_id"].encode("ascii")
        config_hash = bytes.fromhex(validator["config_sha256"])
        digest.update(len(validator_id).to_bytes(4, "big"))
        digest.update(validator_id)
        digest.update(config_hash)
    return digest.hexdigest()


def host_validator_configuration_set_digest(validators: list[dict]) -> str:
    digest = hashlib.sha256()
    digest.update(b"TRNM/PoCO/G3/HostValidatorConfigurationSet/v1\0")
    for validator in sorted(validators, key=lambda item: item["validator_id"]):
        validator_id = validator["validator_id"].encode("ascii")
        digest.update(len(validator_id).to_bytes(4, "big"))
        digest.update(validator_id)
        digest.update(bytes.fromhex(validator["config_sha256"]))
    return digest.hexdigest()


def observer_configuration_set_digest(config_sha256: str) -> str:
    """Bind one observer's immutable configuration into a typed set digest."""
    digest = hashlib.sha256()
    digest.update(b"TRNM/PoCO/G3/ObserverConfigurationSet/v1\0")
    digest.update(bytes.fromhex(config_sha256))
    return digest.hexdigest()


def validate(
    path: pathlib.Path,
    expected_count: int,
    *,
    profile: str,
    emit: bool = True,
) -> None:
    with INVENTORY.open("rb") as source:
        inventory = tomllib.load(source)
    document = read_json(path, "completed_run_evidence")
    exact_keys(
        document,
        {
            "schema_version",
            "evidence_profile",
            "run_id",
            "fleet_id",
            "candidate",
            "network_scope",
            "geo_wan_evidence",
            "validator_run_completed",
            "topology",
            "started_at",
            "ended_at",
            "validators",
            "participants",
            "consensus",
            "faults",
            "performance",
        },
        "document",
    )
    try:
        selected_profile = evidence_profiles.require_active(profile)
    except (ValueError, RuntimeError) as error:
        fail(str(error))
    if document["evidence_profile"] != selected_profile:
        fail("completed-run evidence_profile differs from the explicit CLI profile")
    if document["schema_version"] != 3:
        fail("schema_version must be 3")
    if not isinstance(document["run_id"], str) or not RUN_ID.fullmatch(document["run_id"]):
        fail("run_id must be a canonical topology/time/nonce identifier")
    if document["fleet_id"] != inventory["fleet_id"]:
        fail("fleet_id mismatch")
    if document["network_scope"] != "single-lan" or document["geo_wan_evidence"] is not False:
        fail("LAN run must keep geo_wan_evidence=false")
    if document["validator_run_completed"] is not True:
        fail("completed run evidence must set validator_run_completed=true")
    if not RFC3339_UTC.fullmatch(document["started_at"]) or not RFC3339_UTC.fullmatch(
        document["ended_at"]
    ):
        fail("timestamps must be second-precision RFC3339 UTC")
    if document["started_at"] >= document["ended_at"]:
        fail("ended_at must be later than started_at")
    started = datetime.datetime.strptime(document["started_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc
    )
    ended = datetime.datetime.strptime(document["ended_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc
    )

    candidate = exact_keys(
        document["candidate"],
        {
            "source_tree_sha256",
            "linux_x86_64_sha256",
            "macos_arm64_sha256",
            "configuration_set_sha256",
            "reproducible_build",
            "production_activation",
        }
        | SOURCE_PROVENANCE_KEYS,
        "candidate",
    )
    for field in (
        "source_tree_sha256",
        "linux_x86_64_sha256",
        "macos_arm64_sha256",
        "configuration_set_sha256",
    ):
        if not isinstance(candidate[field], str) or not HEX64.fullmatch(candidate[field]):
            fail(f"candidate.{field} must be canonical sha256")
    if candidate["reproducible_build"] is not True:
        fail("candidate must have reproducible_build=true")
    if candidate["production_activation"] is not False:
        fail("G3 test evidence must not activate production")
    validate_source_provenance(candidate, "candidate")

    topology = exact_keys(
        document["topology"],
        {"validator_count", "weight_profile", "peer_degree", "ephemeral_test_keys"},
        "topology",
    )
    if expected_count not in (7, 31, 100) or topology["validator_count"] != expected_count:
        fail("validator_count does not match the requested 7/31/100 topology")
    if topology["weight_profile"] not in {"equal", "bounded-unequal"}:
        fail("unknown weight_profile")
    expected_degree = expected_count - 1 if expected_count == 7 else 8
    if topology["peer_degree"] != expected_degree:
        fail("peer_degree differs from the frozen LAN plan")
    if topology["ephemeral_test_keys"] is not True:
        fail("LAN evidence must identify its ephemeral test keys")

    known_hosts = {host["id"]: host for host in inventory["hosts"]}
    planned_validators = expected_validators(
        inventory, expected_count, topology["weight_profile"]
    )
    validators = document["validators"]
    if not isinstance(validators, list) or len(validators) != expected_count:
        fail("validators must contain the exact topology cardinality")
    ids: set[str] = set()
    endpoints: set[tuple[str, int]] = set()
    observed_hosts: set[str] = set()
    process_ids: set[tuple[str, int]] = set()
    validators_by_host: dict[str, list[dict]] = {}
    total_weight = 0
    for index, validator in enumerate(validators):
        exact_keys(
            validator,
            {
                "validator_id",
                "host_id",
                "lan_ip",
                "p2p_port",
                "metrics_port",
                "weight",
                "process_id",
                "binary_sha256",
                "config_sha256",
            },
            f"validators[{index}]",
        )
        validator_id = validator["validator_id"]
        if not isinstance(validator_id, str) or not validator_id or validator_id in ids:
            fail("validator_id values must be unique non-empty strings")
        ids.add(validator_id)
        if validator_id not in planned_validators:
            fail(f"validator {validator_id} is not in the frozen topology")
        host_id = validator["host_id"]
        if host_id not in known_hosts or validator["lan_ip"] != known_hosts[host_id]["lan_ip"]:
            fail(f"validator {validator_id} is not bound to its inventory host/LAN address")
        ipaddress.ip_address(validator["lan_ip"])
        observed_hosts.add(host_id)
        validators_by_host.setdefault(host_id, []).append(validator)
        for field in ("p2p_port", "metrics_port", "process_id"):
            if isinstance(validator[field], bool) or not isinstance(validator[field], int) or validator[field] <= 0:
                fail(f"validator {validator_id} has invalid {field}")
        process_id = (host_id, validator["process_id"])
        if process_id in process_ids:
            fail("validators on one host must have unique OS process ids")
        process_ids.add(process_id)
        endpoint = (validator["lan_ip"], validator["p2p_port"])
        if endpoint in endpoints:
            fail("validator P2P endpoints must be unique")
        endpoints.add(endpoint)
        weight = validator["weight"]
        if isinstance(weight, bool) or not isinstance(weight, int) or weight <= 0:
            fail("validator weights must be positive integers")
        total_weight += weight
        for field in ("binary_sha256", "config_sha256"):
            if not isinstance(validator[field], str) or not HEX64.fullmatch(validator[field]):
                fail(f"validator {validator_id} has invalid {field}")
        expected = planned_validators[validator_id]
        for field in ("host_id", "lan_ip", "p2p_port", "metrics_port", "weight"):
            if validator[field] != expected[field]:
                fail(f"validator {validator_id} differs from frozen topology field {field}")
        expected_binary = (
            candidate["linux_x86_64_sha256"]
            if expected["os"] == "linux"
            else candidate["macos_arm64_sha256"]
        )
        if validator["binary_sha256"] != expected_binary:
            fail(f"validator {validator_id} binary hash differs from candidate architecture")
    expected_validator_hosts = {
        host_id for host_id, host in known_hosts.items() if host["validator_eligible"]
    }
    if observed_hosts != expected_validator_hosts:
        fail("every validator-eligible physical host must run at least one validator")
    if any(validator["weight"] * 4 > total_weight for validator in validators):
        fail("one validator exceeds the 25 percent voting-power cap")
    if configuration_set_digest(validators) != candidate["configuration_set_sha256"]:
        fail("candidate configuration_set_sha256 does not bind every validator config")

    participants = document["participants"]
    if not isinstance(participants, list) or len(participants) != len(known_hosts):
        fail("participants must contain the exact six physical hosts")
    participant_ids: set[str] = set()
    for index, participant in enumerate(participants):
        exact_keys(
            participant,
            {
                "host_id",
                "lan_ip",
                "run_roles",
                "process_ids",
                "binary_sha256",
                "config_set_sha256",
            },
            f"participants[{index}]",
        )
        host_id = participant["host_id"]
        if host_id not in known_hosts or host_id in participant_ids:
            fail("participant host ids must be the unique frozen fleet")
        participant_ids.add(host_id)
        host = known_hosts[host_id]
        if participant["lan_ip"] != host["lan_ip"] or participant["run_roles"] != host["run_roles"]:
            fail(f"participant {host_id} differs from its frozen LAN role")
        ids_for_host = participant["process_ids"]
        if (
            not isinstance(ids_for_host, list)
            or not ids_for_host
            or any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in ids_for_host)
            or len(set(ids_for_host)) != len(ids_for_host)
        ):
            fail(f"participant {host_id} process_ids must be unique positive integers")
        expected_binary = (
            candidate["linux_x86_64_sha256"]
            if host["validator_eligible"]
            else candidate["macos_arm64_sha256"]
        )
        if participant["binary_sha256"] != expected_binary:
            fail(f"participant {host_id} binary hash differs from its frozen role")
        config_set = participant["config_set_sha256"]
        if not isinstance(config_set, str) or not HEX64.fullmatch(config_set):
            fail(f"participant {host_id} config_set_sha256 must be canonical")
        if host["validator_eligible"]:
            host_validators = validators_by_host.get(host_id, [])
            if sorted(ids_for_host) != sorted(item["process_id"] for item in host_validators):
                fail(f"participant {host_id} process ids differ from its validators")
            if config_set != host_validator_configuration_set_digest(host_validators):
                fail(f"participant {host_id} config set does not bind its validators")
        elif any(validator["host_id"] == host_id for validator in validators):
            fail(f"observer participant {host_id} must not host validators")
    if participant_ids != set(known_hosts):
        fail("every physical host must participate in its frozen role")

    consensus = exact_keys(
        document["consensus"],
        {
            "ordinary_start_height",
            "submitted_nonempty_blocks",
            "committed_nonempty_blocks",
            "finalized_height",
            "state_root_agreement",
            "double_sign_events",
            "duplicate_apply_events",
            "state_drift_events",
            "safety_halt_violations",
            "restart_catchup_passed",
            "heal_convergence_passed",
        },
        "consensus",
    )
    for field in (
        "ordinary_start_height",
        "submitted_nonempty_blocks",
        "committed_nonempty_blocks",
        "finalized_height",
    ):
        positive_integer(consensus[field], f"consensus.{field}")
    if consensus["ordinary_start_height"] != 4:
        fail("consensus.ordinary_start_height must be 4 for the authenticated h1-h3 bootstrap profile")
    if consensus["committed_nonempty_blocks"] > consensus["submitted_nonempty_blocks"]:
        fail("committed blocks cannot exceed submitted blocks")
    if consensus["finalized_height"] != (
        consensus["ordinary_start_height"]
        + consensus["committed_nonempty_blocks"]
        - 1
    ):
        fail("finalized height does not map exactly to the committed ordinary-block count")
    if consensus["state_root_agreement"] is not True:
        fail("consensus.state_root_agreement must be true")
    if (
        consensus["restart_catchup_passed"] is not False
        or consensus["heal_convergence_passed"] is not False
    ):
        fail(
            "no-fault-v1 must not claim restart/catch-up or fault-heal convergence"
        )
    for field in (
        "double_sign_events",
        "duplicate_apply_events",
        "state_drift_events",
        "safety_halt_violations",
    ):
        zero_integer(consensus[field], f"consensus.{field}")

    faults = document["faults"]
    if faults != []:
        fail("no-fault-v1 completed-run evidence must contain zero fault claims")

    performance = exact_keys(
        document["performance"],
        {
            "measurement_seconds",
            "committed_goodput_tps",
            "finality_ms_p50",
            "finality_ms_p95",
            "finality_ms_p99",
            "cpu_seconds",
            "peak_rss_bytes",
            "disk_bytes",
            "fsync_count",
            "network_tx_bytes",
            "network_rx_bytes",
        },
        "performance",
    )
    for field, value in performance.items():
        positive_number(value, f"performance.{field}")
    expected_goodput = (
        consensus["committed_nonempty_blocks"] / performance["measurement_seconds"]
    )
    if not math.isclose(
        performance["committed_goodput_tps"],
        expected_goodput,
        rel_tol=1e-12,
        abs_tol=0.0,
    ):
        fail("committed_goodput_tps is not derived from ordinary committed blocks")
    if performance["measurement_seconds"] > (ended - started).total_seconds():
        fail("measurement_seconds exceeds the recorded run interval")
    if not (
        performance["finality_ms_p50"]
        <= performance["finality_ms_p95"]
        <= performance["finality_ms_p99"]
    ):
        fail("finality quantiles are not monotonic")

    if emit:
        print(
            f"poco_g3_run_evidence=passed validators={expected_count} "
            "profile=no-fault-v1 validator_hosts=5 mac_observer=true hosts=6 "
            "nonempty=true faults=0 "
            "committed_goodput=true geo_wan=false"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=pathlib.Path)
    parser.add_argument("--validators", required=True, type=int, choices=(7, 31, 100))
    parser.add_argument(
        "--profile", required=True, choices=sorted(evidence_profiles.KNOWN_PROFILES)
    )
    args = parser.parse_args()
    validate(args.evidence, args.validators, profile=args.profile)


if __name__ == "__main__":
    main()
