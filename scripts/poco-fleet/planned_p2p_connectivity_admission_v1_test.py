#!/usr/bin/env python3
"""Pure fixtures for planned-p2p-connectivity-admission-v1."""

from __future__ import annotations

import copy
import hashlib
import pathlib
import sys
from collections.abc import Callable
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import planned_p2p_connectivity_admission_v1 as admission  # noqa: E402


RUN_ID = "poco-g3-7-20260821T120000Z-1234abcd"
COORDINATOR_SHA256 = hashlib.sha256(b"coordinator-manifest").hexdigest()
NONCE = hashlib.sha256(b"fresh-attempt-nonce").hexdigest()

HOSTS = (
    ("local", "local", "192.168.0.9", 2),
    ("x230", "p4-x230", "192.168.0.3", 1),
    ("desktop", "p4-desktop", "192.168.0.4", 1),
    ("rog", "p4-rog", "192.168.0.6", 2),
    ("j3160", "p4-j3160", "192.168.0.8", 1),
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def expect_failure(action: Callable[[], object], contains: str) -> None:
    try:
        action()
    except admission.AdmissionContractError as error:
        if contains not in str(error):
            raise AssertionError(f"unexpected failure: {error}") from error
    else:
        raise AssertionError("negative control unexpectedly succeeded")


def reference(path: str, raw: bytes) -> dict[str, Any]:
    return {"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def material_fixture() -> tuple[
    bytes,
    dict[str, bytes],
    dict[str, bytes],
]:
    participants = [
        {
            "host_id": host_id,
            "management": management,
            "lan_ip": lan_ip,
            "os": "linux",
            "arch": "x86_64",
            "validator_eligible": True,
            "run_roles": ["validator"],
        }
        for host_id, management, lan_ip, _count in HOSTS
    ]
    participants.append(
        {
            "host_id": "mac",
            "management": "p4-mac",
            "lan_ip": "192.168.0.5",
            "os": "macos",
            "arch": "arm64",
            "validator_eligible": False,
            "run_roles": [
                "load-generator",
                "evidence-collector",
                "crypto-cross-verifier",
            ],
        }
    )
    validators: list[dict[str, Any]] = []
    index = 0
    for host_id, management, lan_ip, count in HOSTS:
        for host_local_index in range(count):
            validators.append(
                {
                    "index": index,
                    "validator_id": f"{index + 1:064x}",
                    "host_id": host_id,
                    "management": management,
                    "lan_ip": lan_ip,
                    "host_local_index": host_local_index,
                    "p2p_port": 31000 + index,
                    "metrics_port": 32000 + index,
                    "weight": 1,
                    "peers": [],
                }
            )
            index += 1
    assert index == 7
    for source in validators:
        source_index = source["index"]
        source["peers"] = [
            validators[(source_index + offset) % 7]["validator_id"]
            for offset in range(1, 7)
        ]
    topology = {
        "schema_version": 1,
        "fleet_id": "fixture-direct-seven",
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "validator_count": 7,
        "weight_profile": "equal",
        "peer_degree": 6,
        "test_keys_included": False,
        "participants": participants,
        "validators": validators,
    }
    topology_bytes = admission.canonical_json_bytes_v1(topology)

    by_id = {item["validator_id"]: item for item in validators}
    public_keys = {
        validator_id: {
            "consensus_public_key": digest(f"consensus/{validator_id}"),
            "p2p_identity_public_key": digest(f"p2p/{validator_id}"),
            "operator_recovery_public_key": digest(f"recovery/{validator_id}"),
        }
        for validator_id in by_id
    }
    configs: dict[str, bytes] = {}
    for validator_id, planned in by_id.items():
        peers = [
            {
                "validator_id": peer_id,
                "lan_ip": by_id[peer_id]["lan_ip"],
                "p2p_port": by_id[peer_id]["p2p_port"],
                **public_keys[peer_id],
            }
            for peer_id in planned["peers"]
        ]
        config = {
            "schema_version": 2,
            "run_id": RUN_ID,
            "validator_id": validator_id,
            "host_id": planned["host_id"],
            "lan_ip": planned["lan_ip"],
            "p2p_port": planned["p2p_port"],
            "metrics_port": planned["metrics_port"],
            "weight": planned["weight"],
            **public_keys[validator_id],
            "validator_set_sha256": digest("validator-set"),
            "binary_sha256": digest("linux-validator"),
            "ordinary_start_height": 4,
            "workload_corpus_sha256": digest("workload-corpus"),
            "workload_policy_sha256": digest("workload-policy"),
            "consensus_secret_key_path": f"secrets/consensus/{validator_id}.pk8",
            "p2p_identity_secret_key_path": (
                f"secrets/p2p-identity/{validator_id}.pk8"
            ),
            "operator_recovery_secret_key_path": (
                f"secrets/operator-recovery/{validator_id}.pk8"
            ),
            "peers": peers,
            "network_scope": "single-lan",
            "geo_wan_evidence": False,
            "production_activation": False,
        }
        configs[validator_id] = admission.canonical_json_bytes_v1(config)

    deployments: dict[str, bytes] = {}
    for validator_id in sorted(by_id):
        public_files = [
            reference("topology.json", topology_bytes),
            reference(f"public/configs/{validator_id}.json", configs[validator_id]),
        ]
        deployment = {
            "schema_version": 3,
            "deployment_validator_id": validator_id,
            "coordinator_manifest_sha256": COORDINATOR_SHA256,
            "run_id": RUN_ID,
            "fleet_id": topology["fleet_id"],
            "validator_count": 7,
            "weight_profile": "equal",
            "network_scope": "single-lan",
            "geo_wan_evidence": False,
            "candidate": {
                "source_tree_sha256": digest("source"),
                "linux_x86_64_sha256": digest("linux"),
                "macos_arm64_sha256": digest("macos"),
            },
            "material_author": {
                "binary_sha256": digest("material-builder"),
                "runtime_deployed": False,
            },
            "validator_set_sha256": digest("validator-set"),
            "public_files": public_files,
            "secret_files": [
                {
                    "path": f"secrets/p2p-identity/{validator_id}.pk8",
                    "sha256": digest(f"secret/{validator_id}"),
                    "bytes": 48,
                }
            ],
            "production_activation": False,
        }
        deployments[validator_id] = admission.canonical_json_bytes_v1(deployment)
    return topology_bytes, configs, deployments


def build_plan() -> dict[str, Any]:
    topology, configs, deployments = material_fixture()
    return admission.build_direct_seven_endpoint_plan_v1(
        run_id=RUN_ID,
        coordinator_manifest_sha256=COORDINATOR_SHA256,
        topology_bytes=topology,
        validator_config_bytes=configs,
        deployment_manifest_bytes=deployments,
    )


def successful_observations(
    plan: dict[str, Any], *, retry_edge: tuple[str, str] | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    clients = []
    servers = []
    for edge in plan["physical_edges"]:
        key = (edge["source_host_id"], edge["destination_validator_id"])
        attempts = 3 if key == retry_edge else 1
        clients.append(
            admission.expected_client_result_v1(
                plan, NONCE, key[0], key[1], attempt_count=attempts
            )
        )
        servers.append(
            admission.expected_server_observation_v1(
                plan, NONCE, key[0], key[1], observation_count=attempts
            )
        )
    return clients, servers


def successful_helpers(
    plan: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    helpers = [
        admission.expected_helper_report_v1(plan, NONCE, source["host_id"])
        for source in plan["source_hosts"]
    ]
    cleanups = [
        admission.expected_cleanup_report_v1(plan, NONCE, source["host_id"])
        for source in plan["source_hosts"]
    ]
    return helpers, cleanups


def evaluate(
    plan: dict[str, Any],
    clients: list[dict[str, Any]],
    servers: list[dict[str, Any]],
    helpers: list[dict[str, Any]],
    cleanups: list[dict[str, Any]],
) -> dict[str, Any]:
    return admission.evaluate_admission_attempt_v1(
        plan=plan,
        nonce_hex=NONCE,
        icmp_readiness_passed=True,
        client_results=clients,
        server_observations=servers,
        helper_reports=helpers,
        cleanup_reports=cleanups,
    )


def main() -> None:
    topology, configs, deployments = material_fixture()
    plan = admission.build_direct_seven_endpoint_plan_v1(
        run_id=RUN_ID,
        coordinator_manifest_sha256=COORDINATOR_SHA256,
        topology_bytes=topology,
        validator_config_bytes=configs,
        deployment_manifest_bytes=deployments,
    )
    plan_sha256 = admission.endpoint_plan_sha256_v1(plan)
    assert len(plan_sha256) == 64
    derived_nonce = admission.derive_attempt_nonce_hex_v1(plan, b"n" * 32)
    assert derived_nonce == admission.derive_attempt_nonce_hex_v1(plan, b"n" * 32)
    assert derived_nonce != NONCE
    expect_failure(
        lambda: admission.derive_attempt_nonce_hex_v1(plan, b"short"),
        "exactly 32 bytes",
    )
    expect_failure(
        lambda: admission.derive_attempt_nonce_hex_v1(plan, b"\0" * 32),
        "must not be all zero",
    )
    assert plan["source_host_count"] == 5
    assert plan["endpoint_count"] == 7
    assert len(plan["physical_edges"]) == 35
    assert len(plan["logical_peer_edges"]) == 42
    assert {
        (edge["source_host_id"], edge["destination_validator_id"])
        for edge in plan["physical_edges"]
    } == {
        (source["host_id"], endpoint["validator_id"])
        for source in plan["source_hosts"]
        for endpoint in plan["endpoints"]
    }
    assert all(
        (
            edge["source_host_id"],
            edge["destination_validator_id"],
        )
        in {
            (physical["source_host_id"], physical["destination_validator_id"])
            for physical in plan["physical_edges"]
        }
        for edge in plan["logical_peer_edges"]
    )

    for edge in plan["physical_edges"]:
        request_raw = admission.build_probe_request_frame_v1(
            plan,
            NONCE,
            edge["source_host_id"],
            edge["destination_validator_id"],
        )
        request = admission.parse_probe_request_frame_v1(request_raw, plan)
        ack_raw = admission.build_probe_ack_frame_v1(
            request, plan, edge["source_lan_ip"]
        )
        ack = admission.parse_probe_ack_frame_v1(ack_raw, plan, request)
        assert ack["challenge_sha256"] == request["challenge_sha256"]
        assert len(request_raw) <= admission.MAXIMUM_FRAME_BYTES
        assert len(ack_raw) <= admission.MAXIMUM_FRAME_BYTES

    clients, servers = successful_observations(plan)
    helpers, cleanups = successful_helpers(plan)
    report = evaluate(plan, clients, servers, helpers, cleanups)
    report_sha256 = admission.validate_admission_report_v1(
        report, plan, expected_nonce_hex=NONCE
    )
    assert len(report_sha256) == 64
    parsed_report = admission.parse_admission_report_v1(
        admission.canonical_json_bytes_v1(report),
        plan,
        expected_nonce_hex=NONCE,
    )
    assert parsed_report == report
    assert report["admission_passed"] is True
    assert report["icmp_readiness_passed"] is True
    assert report["double_sided_join_complete"] is True
    assert report["cleanup_confirmed"] is True
    assert report["point_in_time_observation"] is True
    assert report["subsequent_network_state_stable"] is False
    assert report["firewall_mutated"] is False
    assert report["firewall_policy_attested"] is False
    assert report["p2p_identity_metadata_bound"] is True
    assert report["p2p_identity_cryptographically_authenticated"] is False
    for field in (
        "validator_binary_deployed",
        "validator_secret_deployed",
        "validator_run_completed",
        "production_activation",
        "g3_lan_multihost_evidence",
        "fault_campaign_completed",
        "performance_campaign_completed",
        "geo_wan_evidence",
    ):
        assert report[field] is False
    inflated_report = copy.deepcopy(report)
    inflated_report["validator_run_completed"] = True
    expect_failure(
        lambda: admission.validate_admission_report_v1(inflated_report, plan),
        "validator_run_completed",
    )
    bool_report_schema = copy.deepcopy(report)
    bool_report_schema["schema_version"] = True
    expect_failure(
        lambda: admission.validate_admission_report_v1(bool_report_schema, plan),
        "exact integer",
    )

    retry_key = (
        plan["physical_edges"][0]["source_host_id"],
        plan["physical_edges"][0]["destination_validator_id"],
    )
    retry_clients, retry_servers = successful_observations(
        plan, retry_edge=retry_key
    )
    retry_report = evaluate(plan, retry_clients, retry_servers, helpers, cleanups)
    retry_result = next(
        item
        for item in retry_report["client_results"]
        if (item["source_host_id"], item["destination_validator_id"]) == retry_key
    )
    assert retry_result["attempt_count"] == 3
    assert retry_result["duplicate_count"] == 2

    first_edge = plan["physical_edges"][0]
    request_raw = admission.build_probe_request_frame_v1(
        plan,
        NONCE,
        first_edge["source_host_id"],
        first_edge["destination_validator_id"],
    )
    request = admission.parse_probe_request_frame_v1(request_raw, plan)
    tampered_request = copy.deepcopy(request)
    tampered_request["challenge_sha256"] = digest("tampered-challenge")
    expect_failure(
        lambda: admission.parse_probe_request_frame_v1(
            admission.canonical_frame_bytes_v1(tampered_request), plan
        ),
        "challenge differs",
    )
    bool_schema = copy.deepcopy(request)
    bool_schema["schema_version"] = True
    expect_failure(
        lambda: admission.parse_probe_request_frame_v1(
            admission.canonical_frame_bytes_v1(bool_schema), plan
        ),
        "exact integer",
    )
    expect_failure(
        lambda: admission.strict_frame_json_object_v1(
            b'{"schema_version":1,"schema_version":1}\n', "duplicate fixture"
        ),
        "duplicate key",
    )
    expect_failure(
        lambda: admission.strict_frame_json_object_v1(
            b"{" + b"x" * admission.MAXIMUM_FRAME_BYTES,
            "oversize fixture",
        ),
        "byte bound",
    )

    tampered_material = dict(configs)
    first_validator = sorted(tampered_material)[0]
    first_config = admission.strict_material_json_object_v1(
        tampered_material[first_validator], "fixture config"
    )
    first_config["p2p_identity_public_key"] = digest("foreign-p2p-key")
    tampered_material[first_validator] = admission.canonical_json_bytes_v1(first_config)
    expect_failure(
        lambda: admission.build_direct_seven_endpoint_plan_v1(
            run_id=RUN_ID,
            coordinator_manifest_sha256=COORDINATOR_SHA256,
            topology_bytes=topology,
            validator_config_bytes=tampered_material,
            deployment_manifest_bytes=deployments,
        ),
        "does not content-bind",
    )

    tampered_plan = copy.deepcopy(plan)
    tampered_plan["physical_edges"] = tampered_plan["physical_edges"][:-1]
    expect_failure(
        lambda: admission.validate_direct_seven_endpoint_plan_v1(tampered_plan),
        "5x7 matrix",
    )
    duplicated_plan = copy.deepcopy(plan)
    duplicated_plan["physical_edges"].append(
        copy.deepcopy(duplicated_plan["physical_edges"][0])
    )
    expect_failure(
        lambda: admission.validate_direct_seven_endpoint_plan_v1(duplicated_plan),
        "5x7 matrix",
    )
    float_port_plan = copy.deepcopy(plan)
    float_port_plan["physical_edges"][0]["destination_p2p_port"] = float(
        float_port_plan["physical_edges"][0]["destination_p2p_port"]
    )
    expect_failure(
        lambda: admission.validate_direct_seven_endpoint_plan_v1(float_port_plan),
        "exact integer",
    )

    missing_clients = copy.deepcopy(clients[:-1])
    expect_failure(
        lambda: evaluate(plan, missing_clients, servers, helpers, cleanups),
        "client result cardinality",
    )
    duplicate_clients = copy.deepcopy(clients)
    duplicate_clients[-1] = copy.deepcopy(duplicate_clients[0])
    expect_failure(
        lambda: evaluate(plan, duplicate_clients, servers, helpers, cleanups),
        "duplicate physical edge record",
    )
    foreign_clients = copy.deepcopy(clients)
    foreign_clients[0]["destination_validator_id"] = "f" * 64
    expect_failure(
        lambda: evaluate(plan, foreign_clients, servers, helpers, cleanups),
        "foreign physical edge",
    )
    wrong_source_servers = copy.deepcopy(servers)
    wrong_source_servers[0]["observed_source_lan_ip"] = "192.168.0.250"
    expect_failure(
        lambda: evaluate(plan, clients, wrong_source_servers, helpers, cleanups),
        "wrong source LAN address",
    )
    wrong_client_source = copy.deepcopy(clients)
    wrong_client_source[0]["getsockname_source_lan_ip"] = "192.168.0.250"
    expect_failure(
        lambda: evaluate(plan, wrong_client_source, servers, helpers, cleanups),
        "challenge/ack differs",
    )
    wrong_plan_clients = copy.deepcopy(clients)
    wrong_plan_clients[0]["endpoint_plan_sha256"] = digest("wrong-plan")
    expect_failure(
        lambda: evaluate(plan, wrong_plan_clients, servers, helpers, cleanups),
        "wrong attempt or plan",
    )
    wrong_hash_clients = copy.deepcopy(clients)
    wrong_hash_clients[0]["ack_sha256"] = digest("wrong-ack")
    expect_failure(
        lambda: evaluate(plan, wrong_hash_clients, servers, helpers, cleanups),
        "challenge/ack differs",
    )
    bool_attempt_clients = copy.deepcopy(clients)
    bool_attempt_clients[0]["attempt_count"] = True
    expect_failure(
        lambda: evaluate(plan, bool_attempt_clients, servers, helpers, cleanups),
        "exact integer",
    )

    ttl_helpers = copy.deepcopy(helpers)
    ttl_helpers[0]["ttl_seconds"] = 4
    expect_failure(
        lambda: evaluate(plan, clients, servers, ttl_helpers, cleanups),
        "below its minimum",
    )
    expired_helpers = copy.deepcopy(helpers)
    expired_helpers[0]["ttl_expired"] = True
    expect_failure(
        lambda: evaluate(plan, clients, servers, expired_helpers, cleanups),
        "ttl_expired",
    )
    false_cleanup = copy.deepcopy(cleanups)
    false_cleanup[0]["exact_endpoints_rebound"] = False
    expect_failure(
        lambda: evaluate(plan, clients, servers, helpers, false_cleanup),
        "exact_endpoints_rebound",
    )
    missing_cleanup = copy.deepcopy(cleanups[:-1])
    expect_failure(
        lambda: evaluate(plan, clients, servers, helpers, missing_cleanup),
        "cleanup report cardinality",
    )

    # ICMP readiness may be green while one planned TCP edge times out.  The
    # active contract still blocks and cannot be upgraded by server-only facts.
    tcp_timeout_clients = copy.deepcopy(clients)
    tcp_timeout_clients[0]["connected"] = False
    expect_failure(
        lambda: evaluate(
            plan, tcp_timeout_clients, servers, helpers, cleanups
        ),
        ".connected",
    )
    lost_reply_clients = copy.deepcopy(clients[1:])
    expect_failure(
        lambda: evaluate(plan, lost_reply_clients, servers, helpers, cleanups),
        "client result cardinality",
    )

    print(
        "planned_p2p_connectivity_admission_v1_test=passed "
        "source_hosts=5 endpoints=7 physical_edges=35 logical_edges=42 "
        "strict_frames=true double_sided_join=true bounded_retry=true "
        "icmp_green_tcp_edge_failure=blocked helper_ttl=true rebind_cleanup=true "
        "firewall_mutated=false firewall_policy_attested=false "
        "p2p_identity_metadata_bound=true p2p_identity_authenticated=false "
        "validator_binary_deployed=false validator_secret_deployed=false "
        "validator_run=false production=false g3=false fault=false performance=false "
        "geo_wan=false"
    )


if __name__ == "__main__":
    main()
