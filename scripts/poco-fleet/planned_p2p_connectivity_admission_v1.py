#!/usr/bin/env python3
"""Pure contract for the Stage0 planned P2P TCP connectivity admission.

This module deliberately performs no network, filesystem, SSH, firewall, or
validator effect.  It defines the content-bound direct-seven endpoint plan,
the bounded request/ack frames used by a future active helper, and the exact
double-sided result join that a runner may later call before deploying any
validator binary or secret.

The acknowledgement is deterministic and is not a P2P-identity signature.
It binds the already-verified P2P public-key metadata into the challenge, while
keeping cryptographic P2P authentication and every production/G3/fault/
performance truth bit false.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any


PROFILE = "planned-p2p-connectivity-admission-v1"
SCHEMA_VERSION = 1
DIRECT_SEVEN_VALIDATORS = 7
DIRECT_SEVEN_SOURCE_HOSTS = 5
DIRECT_SEVEN_ENDPOINTS = 7
DIRECT_SEVEN_PHYSICAL_EDGES = 35
DIRECT_SEVEN_LOGICAL_EDGES = 42
MAXIMUM_MATERIAL_JSON_BYTES = 1024 * 1024
MAXIMUM_FRAME_BYTES = 4096
MAXIMUM_REPORT_BYTES = 1024 * 1024
MINIMUM_HELPER_TTL_SECONDS = 5
MAXIMUM_HELPER_TTL_SECONDS = 120
MAXIMUM_ATTEMPTS_PER_EDGE = 3

HEX64 = re.compile(r"^[0-9a-f]{64}$")
RUN_ID = re.compile(r"^poco-g3-7-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
HOST_ID = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
MANAGEMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")

REQUEST_KIND = "planned-p2p-connectivity-probe-request-v1"
ACK_KIND = "planned-p2p-connectivity-probe-ack-v1"
CHALLENGE_DOMAIN = b"TRNM/PoCO/Stage0/PlannedP2PConnectivity/Challenge/v1\0"
ACK_DOMAIN = b"TRNM/PoCO/Stage0/PlannedP2PConnectivity/Ack/v1\0"
NONCE_DOMAIN = b"TRNM/PoCO/Stage0/PlannedP2PConnectivity/Nonce/v1\0"

PLAN_TRUTH_FIELDS = {
    "firewall_mutated": False,
    "firewall_policy_attested": False,
    "p2p_identity_metadata_bound": True,
    "p2p_identity_cryptographically_authenticated": False,
    "validator_binary_deployed": False,
    "validator_secret_deployed": False,
    "validator_run_completed": False,
    "production_activation": False,
    "g3_lan_multihost_evidence": False,
    "fault_campaign_completed": False,
    "performance_campaign_completed": False,
    "geo_wan_evidence": False,
}
REPORT_TRUTH_FIELDS = {
    "double_sided_join_complete": True,
    "cleanup_confirmed": True,
    "point_in_time_observation": True,
    "subsequent_network_state_stable": False,
    **PLAN_TRUTH_FIELDS,
    "admission_passed": True,
}

PLAN_KEYS = {
    "schema_version",
    "profile",
    "run_id",
    "coordinator_manifest_sha256",
    "topology_sha256",
    "validator_count",
    "source_host_count",
    "endpoint_count",
    "physical_edge_count",
    "logical_peer_edge_count",
    "source_hosts",
    "endpoints",
    "physical_edges",
    "logical_peer_edges",
    "network_scope",
    *PLAN_TRUTH_FIELDS,
}
SOURCE_HOST_KEYS = {"host_id", "management", "lan_ip", "validator_ids"}
ENDPOINT_KEYS = {
    "validator_id",
    "host_id",
    "lan_ip",
    "p2p_port",
    "p2p_identity_public_key",
    "config_sha256",
    "deployment_manifest_sha256",
}
PHYSICAL_EDGE_KEYS = {
    "source_host_id",
    "source_lan_ip",
    "destination_validator_id",
    "destination_host_id",
    "destination_lan_ip",
    "destination_p2p_port",
    "destination_p2p_identity_public_key",
}
LOGICAL_EDGE_KEYS = {
    "source_validator_id",
    "source_host_id",
    "destination_validator_id",
    "destination_host_id",
}
REQUEST_KEYS = {
    "schema_version",
    "profile",
    "kind",
    "endpoint_plan_sha256",
    "nonce_hex",
    *PHYSICAL_EDGE_KEYS,
    "challenge_sha256",
}
ACK_KEYS = {
    "schema_version",
    "profile",
    "kind",
    "endpoint_plan_sha256",
    "nonce_hex",
    "source_host_id",
    "observed_source_lan_ip",
    "destination_validator_id",
    "challenge_sha256",
    "ack_sha256",
}
CLIENT_RESULT_KEYS = {
    "schema_version",
    "profile",
    "endpoint_plan_sha256",
    "nonce_hex",
    "source_host_id",
    "bound_source_lan_ip",
    "getsockname_source_lan_ip",
    "destination_validator_id",
    "challenge_sha256",
    "ack_sha256",
    "attempt_count",
    "duplicate_count",
    "connected",
    "ack_verified",
}
SERVER_OBSERVATION_KEYS = {
    "schema_version",
    "profile",
    "endpoint_plan_sha256",
    "nonce_hex",
    "source_host_id",
    "observed_source_lan_ip",
    "destination_validator_id",
    "challenge_sha256",
    "ack_sha256",
    "observation_count",
    "duplicate_count",
}
HELPER_REPORT_KEYS = {
    "schema_version",
    "profile",
    "endpoint_plan_sha256",
    "nonce_hex",
    "host_id",
    "endpoint_validator_ids",
    "ttl_seconds",
    "ready",
    "stop_reason",
    "ttl_expired",
    "exit_code",
}
CLEANUP_REPORT_KEYS = {
    "schema_version",
    "profile",
    "endpoint_plan_sha256",
    "nonce_hex",
    "host_id",
    "endpoint_validator_ids",
    "helper_exit_confirmed",
    "exact_endpoints_rebound",
    "cleanup_confirmed",
}
REPORT_KEYS = {
    "schema_version",
    "profile",
    "run_id",
    "coordinator_manifest_sha256",
    "topology_sha256",
    "endpoint_plan_sha256",
    "nonce_hex",
    "validator_count",
    "source_host_count",
    "endpoint_count",
    "physical_edge_count",
    "logical_peer_edge_count",
    "icmp_readiness_passed",
    "client_results",
    "server_observations",
    "helper_reports",
    "cleanup_reports",
    *REPORT_TRUTH_FIELDS,
}


class AdmissionContractError(RuntimeError):
    """The planned connectivity admission contract failed closed."""


def fail(message: str) -> None:
    raise AdmissionContractError(
        f"planned P2P connectivity admission v1 failed: {message}"
    )


def canonical_json_bytes_v1(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def canonical_frame_bytes_v1(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"JSON object contains duplicate key {key!r}")
        value[key] = item
    return value

def _strict_json_object(
    raw: bytes,
    field: str,
    maximum_bytes: int,
    *,
    canonical_frame: bool,
) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum_bytes:
        fail(f"{field} crosses its byte bound")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_unique_pairs,
            parse_constant=lambda item: fail(
                f"{field} contains non-finite JSON number {item!r}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        fail(f"{field} is not strict UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{field} must be one JSON object")
    canonical = (
        canonical_frame_bytes_v1(value)
        if canonical_frame
        else canonical_json_bytes_v1(value)
    )
    if raw != canonical:
        fail(f"{field} is not in its canonical JSON encoding")
    return value


def strict_material_json_object_v1(raw: bytes, field: str) -> dict[str, Any]:
    return _strict_json_object(
        raw,
        field,
        MAXIMUM_MATERIAL_JSON_BYTES,
        canonical_frame=False,
    )


def strict_frame_json_object_v1(raw: bytes, field: str) -> dict[str, Any]:
    return _strict_json_object(
        raw,
        field,
        MAXIMUM_FRAME_BYTES,
        canonical_frame=True,
    )


def _exact(value: object, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{field} keys differ from the exact contract")
    return value


def _exact_int(
    value: object,
    field: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if type(value) is not int:
        fail(f"{field} must be one exact integer")
    if minimum is not None and value < minimum:
        fail(f"{field} is below its minimum")
    if maximum is not None and value > maximum:
        fail(f"{field} exceeds its maximum")
    return value


def _require_exact_bool(value: object, expected: bool, field: str) -> None:
    if value is not expected:
        fail(f"{field} must be exactly {str(expected).lower()}")


def _require_hex64(value: object, field: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        fail(f"{field} must be one canonical lowercase 32-byte hash")
    return value


def _require_run_id(value: object, field: str = "run_id") -> str:
    if not isinstance(value, str) or RUN_ID.fullmatch(value) is None:
        fail(f"{field} must be one direct-seven run ID")
    return value


def _require_host_id(value: object, field: str) -> str:
    if not isinstance(value, str) or HOST_ID.fullmatch(value) is None:
        fail(f"{field} is not one canonical host ID")
    return value


def _require_management(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or MANAGEMENT.fullmatch(value) is None
        or value.startswith("-")
    ):
        fail(f"{field} is not one bounded management route")
    return value


def _require_lan_ip(value: object, field: str) -> str:
    if not isinstance(value, str):
        fail(f"{field} must be one LAN IPv4 address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        fail(f"{field} is not one IPv4 address: {error}")
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or not address.is_private
        or address.is_loopback
        or address.is_multicast
        or address.is_unspecified
    ):
        fail(f"{field} must be one private non-loopback LAN IPv4 address")
    return value


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_reference(value: object, field: str) -> dict[str, Any]:
    record = _exact(value, {"path", "sha256", "bytes"}, field)
    path = record["path"]
    if (
        not isinstance(path, str)
        or not path
        or path.startswith("/")
        or "//" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        fail(f"{field}.path is not one safe relative path")
    _require_hex64(record["sha256"], f"{field}.sha256")
    _exact_int(record["bytes"], f"{field}.bytes", minimum=1)
    return record


def _references_by_path(value: object, field: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list):
        fail(f"{field} must be one list")
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(value):
        record = _file_reference(item, f"{field}[{index}]")
        path = record["path"]
        if path in result:
            fail(f"{field} contains duplicate path {path!r}")
        result[path] = record
    return result


def _require_bound_reference(
    references: Mapping[str, dict[str, Any]],
    path: str,
    raw: bytes,
    field: str,
) -> None:
    reference = references.get(path)
    if (
        reference is None
        or reference["sha256"] != _sha256(raw)
        or reference["bytes"] != len(raw)
    ):
        fail(f"{field} does not content-bind {path}")


def _validate_topology_v1(raw: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    topology = _exact(
        strict_material_json_object_v1(raw, "topology"),
        {
            "schema_version",
            "fleet_id",
            "network_scope",
            "geo_wan_evidence",
            "validator_count",
            "weight_profile",
            "peer_degree",
            "test_keys_included",
            "participants",
            "validators",
        },
        "topology",
    )
    if (
        _exact_int(topology["schema_version"], "topology.schema_version") != 1
        or _exact_int(topology["validator_count"], "topology.validator_count")
        != DIRECT_SEVEN_VALIDATORS
        or _exact_int(topology["peer_degree"], "topology.peer_degree") != 6
        or topology["network_scope"] != "single-lan"
        or topology["weight_profile"] not in {"equal", "bounded-unequal"}
    ):
        fail("topology is outside the frozen direct-seven profile")
    _require_exact_bool(
        topology["geo_wan_evidence"], False, "topology.geo_wan_evidence"
    )
    _require_exact_bool(
        topology["test_keys_included"], False, "topology.test_keys_included"
    )
    if not isinstance(topology["fleet_id"], str) or not topology["fleet_id"]:
        fail("topology.fleet_id is invalid")

    participants = topology["participants"]
    if not isinstance(participants, list) or len(participants) != 6:
        fail("direct-seven topology must contain six exact participants")
    participant_by_host: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(participants):
        participant = _exact(
            value,
            {
                "host_id",
                "management",
                "lan_ip",
                "os",
                "arch",
                "validator_eligible",
                "run_roles",
            },
            f"topology.participants[{index}]",
        )
        host_id = _require_host_id(
            participant["host_id"], f"topology.participants[{index}].host_id"
        )
        if host_id in participant_by_host:
            fail("topology participant host IDs are duplicated")
        _require_management(
            participant["management"],
            f"topology.participants[{index}].management",
        )
        _require_lan_ip(
            participant["lan_ip"], f"topology.participants[{index}].lan_ip"
        )
        if type(participant["validator_eligible"]) is not bool:
            fail("topology validator_eligible must be one exact boolean")
        if not isinstance(participant["run_roles"], list) or any(
            not isinstance(item, str) or not item
            for item in participant["run_roles"]
        ):
            fail("topology participant run roles are invalid")
        if participant["validator_eligible"] is True and (
            participant["os"] != "linux"
            or participant["arch"] != "x86_64"
            or participant["run_roles"] != ["validator"]
        ):
            fail("validator source participant is outside the Linux/x86_64 role")
        participant_by_host[host_id] = participant
    eligible = {
        host_id: participant
        for host_id, participant in participant_by_host.items()
        if participant["validator_eligible"] is True
    }
    if len(eligible) != DIRECT_SEVEN_SOURCE_HOSTS:
        fail("direct-seven topology must contain five validator source hosts")
    if sum(item["management"] == "local" for item in eligible.values()) != 1:
        fail("direct-seven topology must contain one exact local source host")
    if len({item["lan_ip"] for item in participant_by_host.values()}) != len(
        participant_by_host
    ):
        fail("topology participant LAN addresses are duplicated")

    validators = topology["validators"]
    if (
        not isinstance(validators, list)
        or len(validators) != DIRECT_SEVEN_VALIDATORS
    ):
        fail("direct-seven topology validator cardinality differs")
    validator_by_id: dict[str, dict[str, Any]] = {}
    p2p_addresses: set[tuple[str, int]] = set()
    indexes: set[int] = set()
    host_local_indexes: dict[str, set[int]] = {}
    for ordinal, value in enumerate(validators):
        validator = _exact(
            value,
            {
                "index",
                "validator_id",
                "host_id",
                "management",
                "lan_ip",
                "host_local_index",
                "p2p_port",
                "metrics_port",
                "weight",
                "peers",
            },
            f"topology.validators[{ordinal}]",
        )
        index = _exact_int(
            validator["index"],
            f"topology.validators[{ordinal}].index",
            minimum=0,
            maximum=DIRECT_SEVEN_VALIDATORS - 1,
        )
        if index in indexes:
            fail("topology validator indexes are duplicated")
        indexes.add(index)
        validator_id = _require_hex64(
            validator["validator_id"],
            f"topology.validators[{ordinal}].validator_id",
        )
        if validator_id in validator_by_id:
            fail("topology validator IDs are duplicated")
        host_id = _require_host_id(
            validator["host_id"], f"topology.validators[{ordinal}].host_id"
        )
        participant = eligible.get(host_id)
        if participant is None:
            fail("topology validator is assigned to a non-validator participant")
        if (
            validator["management"] != participant["management"]
            or validator["lan_ip"] != participant["lan_ip"]
        ):
            fail("topology validator host metadata differs from its participant")
        _require_management(
            validator["management"],
            f"topology.validators[{ordinal}].management",
        )
        lan_ip = _require_lan_ip(
            validator["lan_ip"], f"topology.validators[{ordinal}].lan_ip"
        )
        local_index = _exact_int(
            validator["host_local_index"],
            f"topology.validators[{ordinal}].host_local_index",
            minimum=0,
        )
        if local_index in host_local_indexes.setdefault(host_id, set()):
            fail("topology host-local validator indexes are duplicated")
        host_local_indexes[host_id].add(local_index)
        p2p_port = _exact_int(
            validator["p2p_port"],
            f"topology.validators[{ordinal}].p2p_port",
            minimum=1,
            maximum=65535,
        )
        _exact_int(
            validator["metrics_port"],
            f"topology.validators[{ordinal}].metrics_port",
            minimum=1,
            maximum=65535,
        )
        _exact_int(
            validator["weight"],
            f"topology.validators[{ordinal}].weight",
            minimum=1,
        )
        if (lan_ip, p2p_port) in p2p_addresses:
            fail("topology P2P endpoints are duplicated")
        p2p_addresses.add((lan_ip, p2p_port))
        if not isinstance(validator["peers"], list):
            fail("topology validator peers must be one list")
        validator_by_id[validator_id] = validator
    if indexes != set(range(DIRECT_SEVEN_VALIDATORS)):
        fail("topology validator indexes are not the closed zero-based set")
    for host_id, local_indexes in host_local_indexes.items():
        if local_indexes != set(range(len(local_indexes))):
            fail(f"topology host-local indexes are not closed for {host_id}")
    validator_ids = set(validator_by_id)
    for validator_id, validator in validator_by_id.items():
        peers = validator["peers"]
        if (
            len(peers) != 6
            or any(not isinstance(peer, str) for peer in peers)
            or len(set(peers)) != 6
            or set(peers) != validator_ids - {validator_id}
        ):
            fail("direct-seven logical peer set is not exact all-to-all")
    return topology, participant_by_host


def _validate_config_v2(
    raw: bytes,
    validator_id: str,
    run_id: str,
) -> dict[str, Any]:
    config = _exact(
        strict_material_json_object_v1(raw, f"config[{validator_id}]"),
        {
            "schema_version",
            "run_id",
            "validator_id",
            "host_id",
            "lan_ip",
            "p2p_port",
            "metrics_port",
            "weight",
            "consensus_public_key",
            "p2p_identity_public_key",
            "operator_recovery_public_key",
            "validator_set_sha256",
            "binary_sha256",
            "ordinary_start_height",
            "workload_corpus_sha256",
            "workload_policy_sha256",
            "consensus_secret_key_path",
            "p2p_identity_secret_key_path",
            "operator_recovery_secret_key_path",
            "peers",
            "network_scope",
            "geo_wan_evidence",
            "production_activation",
        },
        f"config[{validator_id}]",
    )
    if (
        _exact_int(config["schema_version"], "config.schema_version") != 2
        or config["run_id"] != run_id
        or config["validator_id"] != validator_id
        or config["network_scope"] != "single-lan"
    ):
        fail(f"config[{validator_id}] fixed fields differ")
    _require_host_id(config["host_id"], f"config[{validator_id}].host_id")
    _require_lan_ip(config["lan_ip"], f"config[{validator_id}].lan_ip")
    _exact_int(
        config["p2p_port"], f"config[{validator_id}].p2p_port", minimum=1, maximum=65535
    )
    _exact_int(
        config["metrics_port"],
        f"config[{validator_id}].metrics_port",
        minimum=1,
        maximum=65535,
    )
    _exact_int(config["weight"], f"config[{validator_id}].weight", minimum=1)
    _exact_int(
        config["ordinary_start_height"],
        f"config[{validator_id}].ordinary_start_height",
        minimum=1,
    )
    for key in (
        "consensus_public_key",
        "p2p_identity_public_key",
        "operator_recovery_public_key",
        "validator_set_sha256",
        "binary_sha256",
        "workload_corpus_sha256",
        "workload_policy_sha256",
    ):
        _require_hex64(config[key], f"config[{validator_id}].{key}")
    expected_secret_paths = {
        "consensus_secret_key_path": f"secrets/consensus/{validator_id}.pk8",
        "p2p_identity_secret_key_path": f"secrets/p2p-identity/{validator_id}.pk8",
        "operator_recovery_secret_key_path": (
            f"secrets/operator-recovery/{validator_id}.pk8"
        ),
    }
    for field, expected in expected_secret_paths.items():
        if config[field] != expected:
            fail(f"config[{validator_id}].{field} differs")
    _require_exact_bool(
        config["geo_wan_evidence"], False, f"config[{validator_id}].geo_wan_evidence"
    )
    _require_exact_bool(
        config["production_activation"],
        False,
        f"config[{validator_id}].production_activation",
    )
    if not isinstance(config["peers"], list):
        fail(f"config[{validator_id}].peers must be one list")
    return config


def _validate_deployment_manifest_v3(
    raw: bytes,
    validator_id: str,
    run_id: str,
    coordinator_manifest_sha256: str,
    topology_raw: bytes,
    config_raw: bytes,
) -> dict[str, Any]:
    manifest = _exact(
        strict_material_json_object_v1(raw, f"deployment_manifest[{validator_id}]"),
        {
            "schema_version",
            "deployment_validator_id",
            "coordinator_manifest_sha256",
            "run_id",
            "fleet_id",
            "validator_count",
            "weight_profile",
            "network_scope",
            "geo_wan_evidence",
            "candidate",
            "material_author",
            "validator_set_sha256",
            "public_files",
            "secret_files",
            "production_activation",
        },
        f"deployment_manifest[{validator_id}]",
    )
    if (
        _exact_int(manifest["schema_version"], "deployment.schema_version") != 3
        or manifest["deployment_validator_id"] != validator_id
        or manifest["coordinator_manifest_sha256"]
        != coordinator_manifest_sha256
        or manifest["run_id"] != run_id
        or _exact_int(manifest["validator_count"], "deployment.validator_count")
        != DIRECT_SEVEN_VALIDATORS
        or manifest["network_scope"] != "single-lan"
        or manifest["weight_profile"] not in {"equal", "bounded-unequal"}
    ):
        fail(f"deployment manifest {validator_id} fixed fields differ")
    if not isinstance(manifest["fleet_id"], str) or not manifest["fleet_id"]:
        fail("deployment fleet_id is invalid")
    _require_exact_bool(
        manifest["geo_wan_evidence"],
        False,
        f"deployment_manifest[{validator_id}].geo_wan_evidence",
    )
    _require_exact_bool(
        manifest["production_activation"],
        False,
        f"deployment_manifest[{validator_id}].production_activation",
    )
    candidate = _exact(
        manifest["candidate"],
        {"source_tree_sha256", "linux_x86_64_sha256", "macos_arm64_sha256"},
        f"deployment_manifest[{validator_id}].candidate",
    )
    for key, value in candidate.items():
        _require_hex64(value, f"deployment_manifest[{validator_id}].candidate.{key}")
    material_author = _exact(
        manifest["material_author"],
        {"binary_sha256", "runtime_deployed"},
        f"deployment_manifest[{validator_id}].material_author",
    )
    _require_hex64(
        material_author["binary_sha256"],
        f"deployment_manifest[{validator_id}].material_author.binary_sha256",
    )
    _require_exact_bool(
        material_author["runtime_deployed"],
        False,
        f"deployment_manifest[{validator_id}].material_author.runtime_deployed",
    )
    _require_hex64(
        manifest["validator_set_sha256"],
        f"deployment_manifest[{validator_id}].validator_set_sha256",
    )
    public = _references_by_path(
        manifest["public_files"], f"deployment_manifest[{validator_id}].public_files"
    )
    _references_by_path(
        manifest["secret_files"], f"deployment_manifest[{validator_id}].secret_files"
    )
    _require_bound_reference(public, "topology.json", topology_raw, "deployment")
    _require_bound_reference(
        public,
        f"public/configs/{validator_id}.json",
        config_raw,
        "deployment",
    )
    return manifest


def build_direct_seven_endpoint_plan_v1(
    *,
    run_id: str,
    coordinator_manifest_sha256: str,
    topology_bytes: bytes,
    validator_config_bytes: Mapping[str, bytes],
    deployment_manifest_bytes: Mapping[str, bytes],
) -> dict[str, Any]:
    """Build the deterministic direct-seven endpoint plan from verified bytes."""

    run_id = _require_run_id(run_id)
    coordinator_manifest_sha256 = _require_hex64(
        coordinator_manifest_sha256, "coordinator_manifest_sha256"
    )
    topology, participants = _validate_topology_v1(topology_bytes)
    topology_by_id = {
        item["validator_id"]: item for item in topology["validators"]
    }
    validator_ids = set(topology_by_id)
    if (
        not isinstance(validator_config_bytes, Mapping)
        or len(validator_config_bytes) != DIRECT_SEVEN_VALIDATORS
    ):
        fail("validator config byte inventory cardinality differs")
    if (
        not isinstance(deployment_manifest_bytes, Mapping)
        or len(deployment_manifest_bytes) != DIRECT_SEVEN_VALIDATORS
    ):
        fail("deployment manifest byte inventory cardinality differs")
    if set(validator_config_bytes) != validator_ids:
        fail("validator config byte inventory differs from topology")
    if set(deployment_manifest_bytes) != validator_ids:
        fail("deployment manifest byte inventory differs from topology")

    configs: dict[str, dict[str, Any]] = {}
    endpoints: list[dict[str, Any]] = []
    for validator_id in sorted(validator_ids):
        config_raw = validator_config_bytes[validator_id]
        deployment_raw = deployment_manifest_bytes[validator_id]
        config = _validate_config_v2(config_raw, validator_id, run_id)
        deployment = _validate_deployment_manifest_v3(
            deployment_raw,
            validator_id,
            run_id,
            coordinator_manifest_sha256,
            topology_bytes,
            config_raw,
        )
        topology_record = topology_by_id[validator_id]
        if (
            config["host_id"] != topology_record["host_id"]
            or config["lan_ip"] != topology_record["lan_ip"]
            or config["p2p_port"] != topology_record["p2p_port"]
            or config["metrics_port"] != topology_record["metrics_port"]
            or config["weight"] != topology_record["weight"]
            or deployment["fleet_id"] != topology["fleet_id"]
            or deployment["weight_profile"] != topology["weight_profile"]
        ):
            fail(f"validator {validator_id} material differs from topology")
        configs[validator_id] = config
        endpoints.append(
            {
                "validator_id": validator_id,
                "host_id": config["host_id"],
                "lan_ip": config["lan_ip"],
                "p2p_port": config["p2p_port"],
                "p2p_identity_public_key": config[
                    "p2p_identity_public_key"
                ],
                "config_sha256": _sha256(config_raw),
                "deployment_manifest_sha256": _sha256(deployment_raw),
            }
        )

    logical_edges: list[dict[str, Any]] = []
    all_p2p_keys = {
        validator_id: config["p2p_identity_public_key"]
        for validator_id, config in configs.items()
    }
    if len(set(all_p2p_keys.values())) != DIRECT_SEVEN_VALIDATORS:
        fail("P2P identity public keys are not unique")
    for source_validator_id in sorted(validator_ids):
        config = configs[source_validator_id]
        topology_record = topology_by_id[source_validator_id]
        peers = config["peers"]
        if len(peers) != 6:
            fail(f"config[{source_validator_id}] peer cardinality differs")
        peer_ids: list[str] = []
        for index, value in enumerate(peers):
            peer = _exact(
                value,
                {
                    "validator_id",
                    "lan_ip",
                    "p2p_port",
                    "consensus_public_key",
                    "p2p_identity_public_key",
                    "operator_recovery_public_key",
                },
                f"config[{source_validator_id}].peers[{index}]",
            )
            destination_validator_id = peer["validator_id"]
            if destination_validator_id not in validator_ids:
                fail("config peer refers to a foreign validator")
            destination = configs[destination_validator_id]
            _require_lan_ip(
                peer["lan_ip"],
                f"config[{source_validator_id}].peers[{index}].lan_ip",
            )
            _exact_int(
                peer["p2p_port"],
                f"config[{source_validator_id}].peers[{index}].p2p_port",
                minimum=1,
                maximum=65535,
            )
            for key in (
                "consensus_public_key",
                "p2p_identity_public_key",
                "operator_recovery_public_key",
            ):
                _require_hex64(
                    peer[key],
                    f"config[{source_validator_id}].peers[{index}].{key}",
                )
                if peer[key] != destination[key]:
                    fail("config peer public keys differ from destination config")
            if (
                peer["lan_ip"] != destination["lan_ip"]
                or peer["p2p_port"] != destination["p2p_port"]
            ):
                fail("config peer endpoint differs from destination config")
            peer_ids.append(destination_validator_id)
            logical_edges.append(
                {
                    "source_validator_id": source_validator_id,
                    "source_host_id": config["host_id"],
                    "destination_validator_id": destination_validator_id,
                    "destination_host_id": destination["host_id"],
                }
            )
        if peer_ids != topology_record["peers"]:
            fail("config peer order differs from topology")

    source_hosts: list[dict[str, Any]] = []
    for host_id, participant in sorted(participants.items()):
        local_validators = sorted(
            validator_id
            for validator_id, endpoint in topology_by_id.items()
            if endpoint["host_id"] == host_id
        )
        if not local_validators:
            continue
        source_hosts.append(
            {
                "host_id": host_id,
                "management": participant["management"],
                "lan_ip": participant["lan_ip"],
                "validator_ids": local_validators,
            }
        )

    physical_edges = [
        {
            "source_host_id": source["host_id"],
            "source_lan_ip": source["lan_ip"],
            "destination_validator_id": endpoint["validator_id"],
            "destination_host_id": endpoint["host_id"],
            "destination_lan_ip": endpoint["lan_ip"],
            "destination_p2p_port": endpoint["p2p_port"],
            "destination_p2p_identity_public_key": endpoint[
                "p2p_identity_public_key"
            ],
        }
        for source in source_hosts
        for endpoint in endpoints
    ]
    plan = {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "run_id": run_id,
        "coordinator_manifest_sha256": coordinator_manifest_sha256,
        "topology_sha256": _sha256(topology_bytes),
        "validator_count": DIRECT_SEVEN_VALIDATORS,
        "source_host_count": DIRECT_SEVEN_SOURCE_HOSTS,
        "endpoint_count": DIRECT_SEVEN_ENDPOINTS,
        "physical_edge_count": DIRECT_SEVEN_PHYSICAL_EDGES,
        "logical_peer_edge_count": DIRECT_SEVEN_LOGICAL_EDGES,
        "source_hosts": source_hosts,
        "endpoints": endpoints,
        "physical_edges": physical_edges,
        "logical_peer_edges": sorted(
            logical_edges,
            key=lambda item: (
                item["source_validator_id"],
                item["destination_validator_id"],
            ),
        ),
        "network_scope": "single-lan",
        **PLAN_TRUTH_FIELDS,
    }
    validate_direct_seven_endpoint_plan_v1(plan)
    return plan


def validate_direct_seven_endpoint_plan_v1(plan: object) -> str:
    value = _exact(plan, PLAN_KEYS, "endpoint_plan")
    if (
        _exact_int(value["schema_version"], "endpoint_plan.schema_version")
        != SCHEMA_VERSION
        or value["profile"] != PROFILE
        or _exact_int(value["validator_count"], "endpoint_plan.validator_count")
        != DIRECT_SEVEN_VALIDATORS
        or _exact_int(value["source_host_count"], "endpoint_plan.source_host_count")
        != DIRECT_SEVEN_SOURCE_HOSTS
        or _exact_int(value["endpoint_count"], "endpoint_plan.endpoint_count")
        != DIRECT_SEVEN_ENDPOINTS
        or _exact_int(value["physical_edge_count"], "endpoint_plan.physical_edge_count")
        != DIRECT_SEVEN_PHYSICAL_EDGES
        or _exact_int(
            value["logical_peer_edge_count"],
            "endpoint_plan.logical_peer_edge_count",
        )
        != DIRECT_SEVEN_LOGICAL_EDGES
        or value["network_scope"] != "single-lan"
    ):
        fail("endpoint plan fixed fields differ")
    _require_run_id(value["run_id"], "endpoint_plan.run_id")
    _require_hex64(
        value["coordinator_manifest_sha256"],
        "endpoint_plan.coordinator_manifest_sha256",
    )
    _require_hex64(value["topology_sha256"], "endpoint_plan.topology_sha256")
    for field, expected in PLAN_TRUTH_FIELDS.items():
        _require_exact_bool(value[field], expected, f"endpoint_plan.{field}")

    source_hosts = value["source_hosts"]
    if not isinstance(source_hosts, list) or len(source_hosts) != 5:
        fail("endpoint plan source host cardinality differs")
    source_by_id: dict[str, dict[str, Any]] = {}
    previous_host = ""
    source_validator_ids: set[str] = set()
    for index, item in enumerate(source_hosts):
        source = _exact(item, SOURCE_HOST_KEYS, f"source_hosts[{index}]")
        host_id = _require_host_id(source["host_id"], f"source_hosts[{index}].host_id")
        if host_id <= previous_host:
            fail("endpoint plan source hosts must be strictly host-ID sorted")
        previous_host = host_id
        _require_management(source["management"], f"source_hosts[{index}].management")
        _require_lan_ip(source["lan_ip"], f"source_hosts[{index}].lan_ip")
        validator_ids = source["validator_ids"]
        if (
            not isinstance(validator_ids, list)
            or not validator_ids
            or validator_ids != sorted(validator_ids)
        ):
            fail("source host validator IDs are not one non-empty sorted list")
        for validator_id in validator_ids:
            _require_hex64(validator_id, "source host validator ID")
            if validator_id in source_validator_ids:
                fail("source host validator assignment is duplicated")
            source_validator_ids.add(validator_id)
        source_by_id[host_id] = source
    if sum(item["management"] == "local" for item in source_hosts) != 1:
        fail("endpoint plan must retain one exact local source host")
    if len({item["lan_ip"] for item in source_hosts}) != 5:
        fail("endpoint plan source host LAN addresses are duplicated")

    endpoints = value["endpoints"]
    if not isinstance(endpoints, list) or len(endpoints) != 7:
        fail("endpoint plan endpoint cardinality differs")
    endpoint_by_id: dict[str, dict[str, Any]] = {}
    previous_validator = ""
    endpoint_addresses: set[tuple[str, int]] = set()
    p2p_keys: set[str] = set()
    for index, item in enumerate(endpoints):
        endpoint = _exact(item, ENDPOINT_KEYS, f"endpoints[{index}]")
        validator_id = _require_hex64(
            endpoint["validator_id"], f"endpoints[{index}].validator_id"
        )
        if validator_id <= previous_validator:
            fail("endpoint plan endpoints must be strictly validator-ID sorted")
        previous_validator = validator_id
        host_id = _require_host_id(endpoint["host_id"], f"endpoints[{index}].host_id")
        source = source_by_id.get(host_id)
        if source is None or validator_id not in source["validator_ids"]:
            fail("endpoint host assignment differs from source host inventory")
        lan_ip = _require_lan_ip(endpoint["lan_ip"], f"endpoints[{index}].lan_ip")
        if lan_ip != source["lan_ip"]:
            fail("endpoint LAN address differs from source host")
        port = _exact_int(
            endpoint["p2p_port"],
            f"endpoints[{index}].p2p_port",
            minimum=1,
            maximum=65535,
        )
        if (lan_ip, port) in endpoint_addresses:
            fail("endpoint plan contains duplicate LAN endpoint")
        endpoint_addresses.add((lan_ip, port))
        key = _require_hex64(
            endpoint["p2p_identity_public_key"],
            f"endpoints[{index}].p2p_identity_public_key",
        )
        if key in p2p_keys:
            fail("endpoint plan contains duplicate P2P identity metadata")
        p2p_keys.add(key)
        _require_hex64(endpoint["config_sha256"], f"endpoints[{index}].config_sha256")
        _require_hex64(
            endpoint["deployment_manifest_sha256"],
            f"endpoints[{index}].deployment_manifest_sha256",
        )
        endpoint_by_id[validator_id] = endpoint
    if source_validator_ids != set(endpoint_by_id):
        fail("source host validator set differs from endpoint set")

    expected_physical = [
        {
            "source_host_id": source["host_id"],
            "source_lan_ip": source["lan_ip"],
            "destination_validator_id": endpoint["validator_id"],
            "destination_host_id": endpoint["host_id"],
            "destination_lan_ip": endpoint["lan_ip"],
            "destination_p2p_port": endpoint["p2p_port"],
            "destination_p2p_identity_public_key": endpoint[
                "p2p_identity_public_key"
            ],
        }
        for source in source_hosts
        for endpoint in endpoints
    ]
    physical_edges = value["physical_edges"]
    if not isinstance(physical_edges, list):
        fail("endpoint plan physical edges must be one list")
    for index, edge in enumerate(physical_edges):
        checked_edge = _exact(
            edge, PHYSICAL_EDGE_KEYS, f"physical_edges[{index}]"
        )
        _require_host_id(
            checked_edge["source_host_id"],
            f"physical_edges[{index}].source_host_id",
        )
        _require_lan_ip(
            checked_edge["source_lan_ip"],
            f"physical_edges[{index}].source_lan_ip",
        )
        _require_hex64(
            checked_edge["destination_validator_id"],
            f"physical_edges[{index}].destination_validator_id",
        )
        _require_host_id(
            checked_edge["destination_host_id"],
            f"physical_edges[{index}].destination_host_id",
        )
        _require_lan_ip(
            checked_edge["destination_lan_ip"],
            f"physical_edges[{index}].destination_lan_ip",
        )
        _exact_int(
            checked_edge["destination_p2p_port"],
            f"physical_edges[{index}].destination_p2p_port",
            minimum=1,
            maximum=65535,
        )
        _require_hex64(
            checked_edge["destination_p2p_identity_public_key"],
            f"physical_edges[{index}].destination_p2p_identity_public_key",
        )
    if physical_edges != expected_physical:
        fail("endpoint plan physical edge set/order is not the exact 5x7 matrix")

    expected_logical = [
        {
            "source_validator_id": source_validator_id,
            "source_host_id": endpoint_by_id[source_validator_id]["host_id"],
            "destination_validator_id": destination_validator_id,
            "destination_host_id": endpoint_by_id[destination_validator_id]["host_id"],
        }
        for source_validator_id in sorted(endpoint_by_id)
        for destination_validator_id in sorted(endpoint_by_id)
        if destination_validator_id != source_validator_id
    ]
    logical_edges = value["logical_peer_edges"]
    if not isinstance(logical_edges, list):
        fail("endpoint plan logical edges must be one list")
    for index, edge in enumerate(logical_edges):
        checked_edge = _exact(
            edge, LOGICAL_EDGE_KEYS, f"logical_peer_edges[{index}]"
        )
        _require_hex64(
            checked_edge["source_validator_id"],
            f"logical_peer_edges[{index}].source_validator_id",
        )
        _require_host_id(
            checked_edge["source_host_id"],
            f"logical_peer_edges[{index}].source_host_id",
        )
        _require_hex64(
            checked_edge["destination_validator_id"],
            f"logical_peer_edges[{index}].destination_validator_id",
        )
        _require_host_id(
            checked_edge["destination_host_id"],
            f"logical_peer_edges[{index}].destination_host_id",
        )
    if logical_edges != expected_logical:
        fail("endpoint plan logical peer edges are not the exact directed 7x6 set")
    physical_coverage = {
        (edge["source_host_id"], edge["destination_validator_id"])
        for edge in physical_edges
    }
    if any(
        (edge["source_host_id"], edge["destination_validator_id"])
        not in physical_coverage
        for edge in logical_edges
    ):
        fail("one logical peer edge lacks physical host-to-endpoint coverage")
    return _sha256(canonical_json_bytes_v1(value))


def endpoint_plan_sha256_v1(plan: object) -> str:
    return validate_direct_seven_endpoint_plan_v1(plan)


def _require_nonce(value: object) -> str:
    nonce = _require_hex64(value, "nonce_hex")
    if nonce == "0" * 64:
        fail("nonce_hex must not be all zero")
    return nonce


def derive_attempt_nonce_hex_v1(plan: dict[str, Any], entropy: bytes) -> str:
    """Domain-separate 32 bytes supplied by a future cryptographic RNG.

    Entropy acquisition remains outside this pure module.  A caller must use a
    fresh RNG sample for every attempt; a failed attempt's nonce is never
    eligible for reuse or promotion into later evidence.
    """

    if not isinstance(entropy, bytes) or len(entropy) != 32:
        fail("attempt nonce entropy must be exactly 32 bytes")
    if entropy == b"\0" * 32:
        fail("attempt nonce entropy must not be all zero")
    plan_sha256 = endpoint_plan_sha256_v1(plan)
    return hashlib.sha256(
        NONCE_DOMAIN + bytes.fromhex(plan_sha256) + entropy
    ).hexdigest()


def _physical_edge(
    plan: dict[str, Any], source_host_id: str, destination_validator_id: str
) -> dict[str, Any]:
    matches = [
        edge
        for edge in plan["physical_edges"]
        if edge["source_host_id"] == source_host_id
        and edge["destination_validator_id"] == destination_validator_id
    ]
    if len(matches) != 1:
        fail("probe edge is outside the exact physical matrix")
    return matches[0]


def _domain_hash(domain: bytes, value: object) -> str:
    payload = canonical_frame_bytes_v1(value)
    return hashlib.sha256(domain + len(payload).to_bytes(4, "big") + payload).hexdigest()


def challenge_sha256_v1(
    plan: dict[str, Any],
    nonce_hex: str,
    source_host_id: str,
    destination_validator_id: str,
) -> str:
    plan_sha256 = endpoint_plan_sha256_v1(plan)
    nonce_hex = _require_nonce(nonce_hex)
    edge = _physical_edge(plan, source_host_id, destination_validator_id)
    return _domain_hash(
        CHALLENGE_DOMAIN,
        {
            "endpoint_plan_sha256": plan_sha256,
            "nonce_hex": nonce_hex,
            **edge,
        },
    )


def ack_sha256_v1(
    plan: dict[str, Any],
    nonce_hex: str,
    source_host_id: str,
    destination_validator_id: str,
    observed_source_lan_ip: str,
) -> str:
    edge = _physical_edge(plan, source_host_id, destination_validator_id)
    if observed_source_lan_ip != edge["source_lan_ip"]:
        fail("server observed the wrong source LAN address")
    challenge = challenge_sha256_v1(
        plan, nonce_hex, source_host_id, destination_validator_id
    )
    return _domain_hash(
        ACK_DOMAIN,
        {
            "endpoint_plan_sha256": endpoint_plan_sha256_v1(plan),
            "nonce_hex": nonce_hex,
            "source_host_id": source_host_id,
            "observed_source_lan_ip": observed_source_lan_ip,
            "destination_validator_id": destination_validator_id,
            "challenge_sha256": challenge,
        },
    )


def build_probe_request_frame_v1(
    plan: dict[str, Any],
    nonce_hex: str,
    source_host_id: str,
    destination_validator_id: str,
) -> bytes:
    plan_sha256 = endpoint_plan_sha256_v1(plan)
    nonce_hex = _require_nonce(nonce_hex)
    edge = _physical_edge(plan, source_host_id, destination_validator_id)
    value = {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "kind": REQUEST_KIND,
        "endpoint_plan_sha256": plan_sha256,
        "nonce_hex": nonce_hex,
        **edge,
        "challenge_sha256": challenge_sha256_v1(
            plan, nonce_hex, source_host_id, destination_validator_id
        ),
    }
    raw = canonical_frame_bytes_v1(value)
    if len(raw) > MAXIMUM_FRAME_BYTES:
        fail("probe request frame exceeds its byte bound")
    return raw


def parse_probe_request_frame_v1(
    raw: bytes, plan: dict[str, Any]
) -> dict[str, Any]:
    value = _exact(
        strict_frame_json_object_v1(raw, "probe request frame"),
        REQUEST_KEYS,
        "probe request frame",
    )
    if (
        _exact_int(value["schema_version"], "request.schema_version")
        != SCHEMA_VERSION
        or value["profile"] != PROFILE
        or value["kind"] != REQUEST_KIND
        or value["endpoint_plan_sha256"] != endpoint_plan_sha256_v1(plan)
    ):
        fail("probe request fixed fields differ")
    nonce = _require_nonce(value["nonce_hex"])
    edge = _physical_edge(
        plan, value["source_host_id"], value["destination_validator_id"]
    )
    if any(value[key] != edge[key] for key in PHYSICAL_EDGE_KEYS):
        fail("probe request edge metadata differs from endpoint plan")
    expected_challenge = challenge_sha256_v1(
        plan, nonce, value["source_host_id"], value["destination_validator_id"]
    )
    if value["challenge_sha256"] != expected_challenge:
        fail("probe request challenge differs")
    return value


def build_probe_ack_frame_v1(
    request: Mapping[str, Any],
    plan: dict[str, Any],
    observed_source_lan_ip: str,
) -> bytes:
    request_raw = canonical_frame_bytes_v1(dict(request))
    checked = parse_probe_request_frame_v1(request_raw, plan)
    ack = ack_sha256_v1(
        plan,
        checked["nonce_hex"],
        checked["source_host_id"],
        checked["destination_validator_id"],
        observed_source_lan_ip,
    )
    value = {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "kind": ACK_KIND,
        "endpoint_plan_sha256": checked["endpoint_plan_sha256"],
        "nonce_hex": checked["nonce_hex"],
        "source_host_id": checked["source_host_id"],
        "observed_source_lan_ip": observed_source_lan_ip,
        "destination_validator_id": checked["destination_validator_id"],
        "challenge_sha256": checked["challenge_sha256"],
        "ack_sha256": ack,
    }
    raw = canonical_frame_bytes_v1(value)
    if len(raw) > MAXIMUM_FRAME_BYTES:
        fail("probe acknowledgement frame exceeds its byte bound")
    return raw


def parse_probe_ack_frame_v1(
    raw: bytes,
    plan: dict[str, Any],
    request: Mapping[str, Any],
) -> dict[str, Any]:
    checked_request = parse_probe_request_frame_v1(
        canonical_frame_bytes_v1(dict(request)), plan
    )
    value = _exact(
        strict_frame_json_object_v1(raw, "probe acknowledgement frame"),
        ACK_KEYS,
        "probe acknowledgement frame",
    )
    if (
        _exact_int(value["schema_version"], "ack.schema_version")
        != SCHEMA_VERSION
        or value["profile"] != PROFILE
        or value["kind"] != ACK_KIND
        or value["endpoint_plan_sha256"]
        != checked_request["endpoint_plan_sha256"]
        or value["nonce_hex"] != checked_request["nonce_hex"]
        or value["source_host_id"] != checked_request["source_host_id"]
        or value["destination_validator_id"]
        != checked_request["destination_validator_id"]
        or value["challenge_sha256"] != checked_request["challenge_sha256"]
    ):
        fail("probe acknowledgement does not join its request")
    expected_ack = ack_sha256_v1(
        plan,
        value["nonce_hex"],
        value["source_host_id"],
        value["destination_validator_id"],
        value["observed_source_lan_ip"],
    )
    if value["ack_sha256"] != expected_ack:
        fail("probe acknowledgement hash differs")
    return value


def expected_client_result_v1(
    plan: dict[str, Any],
    nonce_hex: str,
    source_host_id: str,
    destination_validator_id: str,
    *,
    attempt_count: int = 1,
) -> dict[str, Any]:
    attempts = _exact_int(
        attempt_count,
        "attempt_count",
        minimum=1,
        maximum=MAXIMUM_ATTEMPTS_PER_EDGE,
    )
    edge = _physical_edge(plan, source_host_id, destination_validator_id)
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "endpoint_plan_sha256": endpoint_plan_sha256_v1(plan),
        "nonce_hex": _require_nonce(nonce_hex),
        "source_host_id": source_host_id,
        "bound_source_lan_ip": edge["source_lan_ip"],
        "getsockname_source_lan_ip": edge["source_lan_ip"],
        "destination_validator_id": destination_validator_id,
        "challenge_sha256": challenge_sha256_v1(
            plan, nonce_hex, source_host_id, destination_validator_id
        ),
        "ack_sha256": ack_sha256_v1(
            plan,
            nonce_hex,
            source_host_id,
            destination_validator_id,
            edge["source_lan_ip"],
        ),
        "attempt_count": attempts,
        "duplicate_count": attempts - 1,
        "connected": True,
        "ack_verified": True,
    }


def expected_server_observation_v1(
    plan: dict[str, Any],
    nonce_hex: str,
    source_host_id: str,
    destination_validator_id: str,
    *,
    observation_count: int = 1,
) -> dict[str, Any]:
    observations = _exact_int(
        observation_count,
        "observation_count",
        minimum=1,
        maximum=MAXIMUM_ATTEMPTS_PER_EDGE,
    )
    edge = _physical_edge(plan, source_host_id, destination_validator_id)
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "endpoint_plan_sha256": endpoint_plan_sha256_v1(plan),
        "nonce_hex": _require_nonce(nonce_hex),
        "source_host_id": source_host_id,
        "observed_source_lan_ip": edge["source_lan_ip"],
        "destination_validator_id": destination_validator_id,
        "challenge_sha256": challenge_sha256_v1(
            plan, nonce_hex, source_host_id, destination_validator_id
        ),
        "ack_sha256": ack_sha256_v1(
            plan,
            nonce_hex,
            source_host_id,
            destination_validator_id,
            edge["source_lan_ip"],
        ),
        "observation_count": observations,
        "duplicate_count": observations - 1,
    }


def expected_helper_report_v1(
    plan: dict[str, Any], nonce_hex: str, host_id: str, *, ttl_seconds: int = 30
) -> dict[str, Any]:
    endpoint_ids = sorted(
        endpoint["validator_id"]
        for endpoint in plan["endpoints"]
        if endpoint["host_id"] == host_id
    )
    if not endpoint_ids:
        fail("helper host is outside the endpoint host set")
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "endpoint_plan_sha256": endpoint_plan_sha256_v1(plan),
        "nonce_hex": _require_nonce(nonce_hex),
        "host_id": host_id,
        "endpoint_validator_ids": endpoint_ids,
        "ttl_seconds": _exact_int(
            ttl_seconds,
            "ttl_seconds",
            minimum=MINIMUM_HELPER_TTL_SECONDS,
            maximum=MAXIMUM_HELPER_TTL_SECONDS,
        ),
        "ready": True,
        "stop_reason": "stop",
        "ttl_expired": False,
        "exit_code": 0,
    }


def expected_cleanup_report_v1(
    plan: dict[str, Any], nonce_hex: str, host_id: str
) -> dict[str, Any]:
    endpoint_ids = sorted(
        endpoint["validator_id"]
        for endpoint in plan["endpoints"]
        if endpoint["host_id"] == host_id
    )
    if not endpoint_ids:
        fail("cleanup host is outside the endpoint host set")
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "endpoint_plan_sha256": endpoint_plan_sha256_v1(plan),
        "nonce_hex": _require_nonce(nonce_hex),
        "host_id": host_id,
        "endpoint_validator_ids": endpoint_ids,
        "helper_exit_confirmed": True,
        "exact_endpoints_rebound": True,
        "cleanup_confirmed": True,
    }


def _check_common_observation_fields(
    value: dict[str, Any],
    plan_sha256: str,
    nonce_hex: str,
    field: str,
) -> None:
    if (
        _exact_int(value["schema_version"], f"{field}.schema_version")
        != SCHEMA_VERSION
        or value["profile"] != PROFILE
        or value["endpoint_plan_sha256"] != plan_sha256
        or value["nonce_hex"] != nonce_hex
    ):
        fail(f"{field} is bound to the wrong attempt or plan")


def _observation_edge_key(value: Mapping[str, Any], field: str) -> tuple[str, str]:
    return (
        _require_host_id(value["source_host_id"], f"{field}.source_host_id"),
        _require_hex64(
            value["destination_validator_id"],
            f"{field}.destination_validator_id",
        ),
    )


def evaluate_admission_attempt_v1(
    *,
    plan: dict[str, Any],
    nonce_hex: str,
    icmp_readiness_passed: bool,
    client_results: Sequence[object],
    server_observations: Sequence[object],
    helper_reports: Sequence[object],
    cleanup_reports: Sequence[object],
) -> dict[str, Any]:
    """Validate the exact double-sided 35-edge join and return a pass report.

    A green ICMP readiness bit is recorded but never substitutes for one TCP
    edge.  Any missing client acknowledgement, including an observed request
    whose reply/result was lost, blocks the entire admission.
    """

    plan_sha256 = endpoint_plan_sha256_v1(plan)
    nonce_hex = _require_nonce(nonce_hex)
    if type(icmp_readiness_passed) is not bool:
        fail("icmp_readiness_passed must be one exact boolean")
    if icmp_readiness_passed is not True:
        fail("current ICMP readiness must pass before active TCP admission")
    expected_edges = {
        (edge["source_host_id"], edge["destination_validator_id"]): edge
        for edge in plan["physical_edges"]
    }

    clients: dict[tuple[str, str], dict[str, Any]] = {}
    if not isinstance(client_results, Sequence) or isinstance(
        client_results, (str, bytes)
    ):
        fail("client_results must be one sequence")
    if len(client_results) != DIRECT_SEVEN_PHYSICAL_EDGES:
        fail("TCP client result cardinality differs from the exact edge set")
    for index, item in enumerate(client_results):
        result = _exact(item, CLIENT_RESULT_KEYS, f"client_results[{index}]")
        _check_common_observation_fields(
            result, plan_sha256, nonce_hex, f"client_results[{index}]"
        )
        edge_key = _observation_edge_key(result, f"client_results[{index}]")
        if edge_key not in expected_edges:
            fail("client result contains a foreign physical edge")
        if edge_key in clients:
            fail("client result contains a duplicate physical edge record")
        attempts = _exact_int(
            result["attempt_count"],
            f"client_results[{index}].attempt_count",
            minimum=1,
            maximum=MAXIMUM_ATTEMPTS_PER_EDGE,
        )
        duplicates = _exact_int(
            result["duplicate_count"],
            f"client_results[{index}].duplicate_count",
            minimum=0,
            maximum=MAXIMUM_ATTEMPTS_PER_EDGE - 1,
        )
        if duplicates != attempts - 1:
            fail("client retry duplicate count differs from attempt count")
        _require_exact_bool(
            result["connected"], True, f"client_results[{index}].connected"
        )
        _require_exact_bool(
            result["ack_verified"], True, f"client_results[{index}].ack_verified"
        )
        expected = expected_client_result_v1(
            plan,
            nonce_hex,
            edge_key[0],
            edge_key[1],
            attempt_count=attempts,
        )
        if result != expected:
            fail("client result source-bind/challenge/ack differs from the exact edge")
        clients[edge_key] = result

    servers: dict[tuple[str, str], dict[str, Any]] = {}
    if not isinstance(server_observations, Sequence) or isinstance(
        server_observations, (str, bytes)
    ):
        fail("server_observations must be one sequence")
    if len(server_observations) != DIRECT_SEVEN_PHYSICAL_EDGES:
        fail("TCP server observation cardinality differs from the exact edge set")
    for index, item in enumerate(server_observations):
        observation = _exact(
            item, SERVER_OBSERVATION_KEYS, f"server_observations[{index}]"
        )
        _check_common_observation_fields(
            observation,
            plan_sha256,
            nonce_hex,
            f"server_observations[{index}]",
        )
        edge_key = _observation_edge_key(
            observation, f"server_observations[{index}]"
        )
        edge = expected_edges.get(edge_key)
        if edge is None:
            fail("server observation contains a foreign physical edge")
        if edge_key in servers:
            fail("server observation contains a duplicate physical edge record")
        observations = _exact_int(
            observation["observation_count"],
            f"server_observations[{index}].observation_count",
            minimum=1,
            maximum=MAXIMUM_ATTEMPTS_PER_EDGE,
        )
        duplicates = _exact_int(
            observation["duplicate_count"],
            f"server_observations[{index}].duplicate_count",
            minimum=0,
            maximum=MAXIMUM_ATTEMPTS_PER_EDGE - 1,
        )
        if duplicates != observations - 1:
            fail("server retry duplicate count differs from observation count")
        if observation["observed_source_lan_ip"] != edge["source_lan_ip"]:
            fail("server observation has the wrong source LAN address")
        expected = expected_server_observation_v1(
            plan,
            nonce_hex,
            edge_key[0],
            edge_key[1],
            observation_count=observations,
        )
        if observation != expected:
            fail("server observation challenge/ack differs from the exact edge")
        servers[edge_key] = observation

    if set(clients) != set(expected_edges):
        fail("TCP client result edge set is missing or extra")
    if set(servers) != set(expected_edges):
        fail("TCP server observation edge set is missing or extra")
    for edge_key in expected_edges:
        client = clients[edge_key]
        server = servers[edge_key]
        if (
            client["challenge_sha256"] != server["challenge_sha256"]
            or client["ack_sha256"] != server["ack_sha256"]
            or server["observation_count"] > client["attempt_count"]
        ):
            fail("TCP edge lacks an exact double-sided client/server join")

    source_hosts = {item["host_id"]: item for item in plan["source_hosts"]}
    helpers: dict[str, dict[str, Any]] = {}
    if not isinstance(helper_reports, Sequence) or isinstance(
        helper_reports, (str, bytes)
    ):
        fail("helper_reports must be one sequence")
    if len(helper_reports) != DIRECT_SEVEN_SOURCE_HOSTS:
        fail("helper report cardinality differs from the source host set")
    for index, item in enumerate(helper_reports):
        report = _exact(item, HELPER_REPORT_KEYS, f"helper_reports[{index}]")
        _check_common_observation_fields(
            report, plan_sha256, nonce_hex, f"helper_reports[{index}]"
        )
        host_id = _require_host_id(
            report["host_id"], f"helper_reports[{index}].host_id"
        )
        source = source_hosts.get(host_id)
        if source is None or host_id in helpers:
            fail("helper report host set is foreign or duplicated")
        if report["endpoint_validator_ids"] != source["validator_ids"]:
            fail("helper report endpoint set differs from its host")
        _exact_int(
            report["ttl_seconds"],
            f"helper_reports[{index}].ttl_seconds",
            minimum=MINIMUM_HELPER_TTL_SECONDS,
            maximum=MAXIMUM_HELPER_TTL_SECONDS,
        )
        _require_exact_bool(report["ready"], True, f"helper_reports[{index}].ready")
        if report["stop_reason"] != "stop":
            fail("successful helper must stop by coordinator request")
        _require_exact_bool(
            report["ttl_expired"], False, f"helper_reports[{index}].ttl_expired"
        )
        if _exact_int(report["exit_code"], f"helper_reports[{index}].exit_code") != 0:
            fail("helper did not exit successfully")
        helpers[host_id] = report
    if set(helpers) != set(source_hosts):
        fail("helper report host set is missing or extra")

    cleanups: dict[str, dict[str, Any]] = {}
    if not isinstance(cleanup_reports, Sequence) or isinstance(
        cleanup_reports, (str, bytes)
    ):
        fail("cleanup_reports must be one sequence")
    if len(cleanup_reports) != DIRECT_SEVEN_SOURCE_HOSTS:
        fail("cleanup report cardinality differs from the source host set")
    for index, item in enumerate(cleanup_reports):
        report = _exact(item, CLEANUP_REPORT_KEYS, f"cleanup_reports[{index}]")
        _check_common_observation_fields(
            report, plan_sha256, nonce_hex, f"cleanup_reports[{index}]"
        )
        host_id = _require_host_id(
            report["host_id"], f"cleanup_reports[{index}].host_id"
        )
        source = source_hosts.get(host_id)
        if source is None or host_id in cleanups:
            fail("cleanup report host set is foreign or duplicated")
        if report["endpoint_validator_ids"] != source["validator_ids"]:
            fail("cleanup report endpoint set differs from its host")
        for field in (
            "helper_exit_confirmed",
            "exact_endpoints_rebound",
            "cleanup_confirmed",
        ):
            _require_exact_bool(
                report[field], True, f"cleanup_reports[{index}].{field}"
            )
        cleanups[host_id] = report
    if set(cleanups) != set(source_hosts):
        fail("cleanup report host set is missing or extra")

    ordered_clients = [clients[key] for key in sorted(clients)]
    ordered_servers = [servers[key] for key in sorted(servers)]
    ordered_helpers = [helpers[key] for key in sorted(helpers)]
    ordered_cleanups = [cleanups[key] for key in sorted(cleanups)]
    report = {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "run_id": plan["run_id"],
        "coordinator_manifest_sha256": plan["coordinator_manifest_sha256"],
        "topology_sha256": plan["topology_sha256"],
        "endpoint_plan_sha256": plan_sha256,
        "nonce_hex": nonce_hex,
        "validator_count": DIRECT_SEVEN_VALIDATORS,
        "source_host_count": DIRECT_SEVEN_SOURCE_HOSTS,
        "endpoint_count": DIRECT_SEVEN_ENDPOINTS,
        "physical_edge_count": DIRECT_SEVEN_PHYSICAL_EDGES,
        "logical_peer_edge_count": DIRECT_SEVEN_LOGICAL_EDGES,
        "icmp_readiness_passed": icmp_readiness_passed,
        "client_results": ordered_clients,
        "server_observations": ordered_servers,
        "helper_reports": ordered_helpers,
        "cleanup_reports": ordered_cleanups,
        **REPORT_TRUTH_FIELDS,
    }
    encoded = canonical_json_bytes_v1(report)
    if len(encoded) > MAXIMUM_REPORT_BYTES:
        fail("admission report exceeds its byte bound")
    return report


def validate_admission_report_v1(
    report: object,
    plan: dict[str, Any],
    *,
    expected_nonce_hex: str | None = None,
) -> str:
    """Re-evaluate a materialized report and return its canonical SHA-256."""

    value = _exact(report, REPORT_KEYS, "admission_report")
    if (
        _exact_int(value["schema_version"], "admission_report.schema_version")
        != SCHEMA_VERSION
        or value["profile"] != PROFILE
        or value["run_id"] != plan["run_id"]
        or value["coordinator_manifest_sha256"]
        != plan["coordinator_manifest_sha256"]
        or value["topology_sha256"] != plan["topology_sha256"]
        or value["endpoint_plan_sha256"] != endpoint_plan_sha256_v1(plan)
        or _exact_int(
            value["validator_count"], "admission_report.validator_count"
        )
        != DIRECT_SEVEN_VALIDATORS
        or _exact_int(
            value["source_host_count"], "admission_report.source_host_count"
        )
        != DIRECT_SEVEN_SOURCE_HOSTS
        or _exact_int(value["endpoint_count"], "admission_report.endpoint_count")
        != DIRECT_SEVEN_ENDPOINTS
        or _exact_int(
            value["physical_edge_count"], "admission_report.physical_edge_count"
        )
        != DIRECT_SEVEN_PHYSICAL_EDGES
        or _exact_int(
            value["logical_peer_edge_count"],
            "admission_report.logical_peer_edge_count",
        )
        != DIRECT_SEVEN_LOGICAL_EDGES
    ):
        fail("admission report fixed fields differ from its endpoint plan")
    if type(value["icmp_readiness_passed"]) is not bool:
        fail("admission_report.icmp_readiness_passed must be one exact boolean")
    for field, expected_truth_value in REPORT_TRUTH_FIELDS.items():
        _require_exact_bool(
            value[field],
            expected_truth_value,
            f"admission_report.{field}",
        )
    nonce_hex = _require_nonce(value["nonce_hex"])
    if expected_nonce_hex is not None and nonce_hex != _require_nonce(
        expected_nonce_hex
    ):
        fail("admission report nonce differs from the expected fresh attempt")
    expected = evaluate_admission_attempt_v1(
        plan=plan,
        nonce_hex=nonce_hex,
        icmp_readiness_passed=value["icmp_readiness_passed"],
        client_results=value["client_results"],
        server_observations=value["server_observations"],
        helper_reports=value["helper_reports"],
        cleanup_reports=value["cleanup_reports"],
    )
    if value != expected:
        fail("admission report fields differ from the re-evaluated contract")
    encoded = canonical_json_bytes_v1(value)
    if len(encoded) > MAXIMUM_REPORT_BYTES:
        fail("admission report exceeds its byte bound")
    return _sha256(encoded)


def parse_admission_report_v1(
    raw: bytes,
    plan: dict[str, Any],
    *,
    expected_nonce_hex: str | None = None,
) -> dict[str, Any]:
    value = _strict_json_object(
        raw,
        "admission report",
        MAXIMUM_REPORT_BYTES,
        canonical_frame=False,
    )
    validate_admission_report_v1(
        value, plan, expected_nonce_hex=expected_nonce_hex
    )
    return value
