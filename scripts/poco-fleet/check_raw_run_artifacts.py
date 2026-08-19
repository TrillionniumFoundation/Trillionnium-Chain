#!/usr/bin/env python3
"""Derive one G3 LAN summary from the content-addressed raw run artifacts.

This checker deliberately does not trust the completed-run summary or the
collector's ``derived_from_raw_artifacts`` boolean.  It re-parses the frozen
topology, per-validator configuration/event/metric/final-state records and the
two-build reproducibility report, then requires the derived projection to
equal the accepted summary. The active no-fault profile rejects all fault and
restart artifacts rather than treating their absence as incomplete evidence.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import math
import pathlib
import re
import subprocess
import tempfile
from typing import Any

import check_run_evidence
import evidence_bundle_profiles_v1 as evidence_profiles
from poco_consensus_contract import canonical_lab_genesis_hash


HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def fail(message: str) -> None:
    raise SystemExit(f"PoCO G3 raw run artifacts invalid: {message}")


def unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate object names in JSON and JSONL raw evidence."""
    value: dict[str, object] = {}
    for key, child in pairs:
        if key in value:
            fail(f"duplicate JSON object name {key!r}")
        value[key] = child
    return value


def exact(value: object, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{field} keys must be exactly {sorted(keys)!r}")
    return value


def read_json(path: pathlib.Path, field: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_json_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"{field} is not one exact UTF-8 JSON document: {error}")
    if not isinstance(value, dict):
        fail(f"{field} must be a JSON object")
    return value


def read_jsonl(path: pathlib.Path, field: str) -> list[dict[str, Any]]:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"{field} is not UTF-8: {error}")
    if not raw.endswith("\n"):
        fail(f"{field} must end with one newline")
    lines = raw.splitlines()
    if not lines or any(not line for line in lines):
        fail(f"{field} must contain non-empty JSONL records")
    values: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        try:
            value = json.loads(line, object_pairs_hook=unique_json_object)
        except json.JSONDecodeError as error:
            fail(f"{field}[{index}] is not exact JSON: {error}")
        values.append(
            exact(
                value,
                {
                    "schema_version",
                    "run_id",
                    "validator_id",
                    "sequence",
                    "observed_at",
                    "kind",
                    "subject",
                    "value",
                },
                f"{field}[{index}]",
            )
        )
    return values


def positive_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"{field} must be a positive integer")
    return value


def nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(f"{field} must be a non-negative integer")
    return value


def positive_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        fail(f"{field} must be positive")
    return float(value)


def timestamp(value: object, field: str) -> datetime.datetime:
    if not isinstance(value, str) or not RFC3339_UTC.fullmatch(value):
        fail(f"{field} must be second-precision RFC3339 UTC")
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc
    )


def nearest_rank(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


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


def verify_pop(public_key: str, signature: str, run_id: str, validator_id: str) -> None:
    public_der = ED25519_SPKI_PREFIX + bytes.fromhex(public_key)
    with tempfile.NamedTemporaryFile(prefix="poco-g3-raw-pub-") as public_file:
        with tempfile.NamedTemporaryFile(prefix="poco-g3-raw-msg-") as message_file:
            with tempfile.NamedTemporaryFile(prefix="poco-g3-raw-sig-") as signature_file:
                public_file.write(public_der)
                public_file.flush()
                message_file.write(pop_challenge(run_id, validator_id))
                message_file.flush()
                signature_file.write(bytes.fromhex(signature))
                signature_file.flush()
                try:
                    result = subprocess.run(
                        [
                            "openssl",
                            "pkeyutl",
                            "-verify",
                            "-rawin",
                            "-pubin",
                            "-keyform",
                            "DER",
                            "-inkey",
                            public_file.name,
                            "-in",
                            message_file.name,
                            "-sigfile",
                            signature_file.name,
                        ],
                        capture_output=True,
                        check=False,
                    )
                except OSError as error:
                    fail(f"OpenSSL PoP verifier unavailable: {error}")
    if result.returncode != 0:
        fail("validator_set proof-of-possession is invalid")


def artifact(
    records: dict[tuple[str, str], tuple[dict[str, Any], pathlib.Path]],
    role: str,
    subject: str = "",
) -> tuple[dict[str, Any], pathlib.Path]:
    try:
        return records[(role, subject)]
    except KeyError:
        fail(f"missing raw artifact role={role!r} subject={subject!r}")


def validate(
    summary: dict[str, Any],
    records: dict[tuple[str, str], tuple[dict[str, Any], pathlib.Path]],
    signed_runtime: dict[str, Any],
    *,
    profile: str,
) -> None:
    try:
        selected_profile = evidence_profiles.require_active(profile)
    except (ValueError, RuntimeError) as error:
        fail(str(error))
    run_id = summary["run_id"]
    validator_count = summary["topology"]["validator_count"]
    summary_validators = {
        validator["validator_id"]: validator for validator in summary["validators"]
    }
    if (
        summary.get("evidence_profile") != selected_profile
        or signed_runtime.get("evidence_profile") != selected_profile
        or signed_runtime.get("run_id") != run_id
        or signed_runtime.get("validator_count") != validator_count
        or not isinstance(signed_runtime.get("validators"), dict)
        or set(signed_runtime["validators"]) != set(summary_validators)
    ):
        fail("signed runtime projection differs from the completed-run identity")
    signed_validators: dict[str, dict[str, Any]] = signed_runtime["validators"]

    source_ref, _ = artifact(records, "candidate_source")
    linux_ref, _ = artifact(records, "linux_binary")
    macos_ref, _ = artifact(records, "macos_binary")
    material_builder_ref, _ = artifact(records, "material_builder_binary")
    candidate = summary["candidate"]
    if candidate["source_tree_sha256"] != source_ref["sha256"]:
        fail("candidate source hash is not derived from candidate_source")
    if candidate["linux_x86_64_sha256"] != linux_ref["sha256"]:
        fail("Linux candidate hash is not derived from linux_binary")
    if candidate["macos_arm64_sha256"] != macos_ref["sha256"]:
        fail("macOS candidate hash is not derived from macos_binary")

    _, build_path = artifact(records, "build_report")
    build = exact(
        read_json(build_path, "build_report"),
        {
            "schema_version",
            "source_tree_sha256",
            "linux_first_sha256",
            "linux_second_sha256",
            "linux_material_builder_first_sha256",
            "linux_material_builder_second_sha256",
            "macos_first_sha256",
            "macos_second_sha256",
            "macos_material_builder_first_sha256",
            "macos_material_builder_second_sha256",
            "independent_build_roots",
            "production_activation",
        }
        | check_run_evidence.SOURCE_PROVENANCE_KEYS,
        "build_report",
    )
    check_run_evidence.validate_source_provenance(
        build,
        "build_report",
        fail_fn=fail,
    )
    if build != {
        "schema_version": 3,
        "source_tree_sha256": source_ref["sha256"],
        **{
            field: candidate[field]
            for field in check_run_evidence.SOURCE_PROVENANCE_KEYS
        },
        "linux_first_sha256": linux_ref["sha256"],
        "linux_second_sha256": linux_ref["sha256"],
        "linux_material_builder_first_sha256": material_builder_ref["sha256"],
        "linux_material_builder_second_sha256": material_builder_ref["sha256"],
        "macos_first_sha256": macos_ref["sha256"],
        "macos_second_sha256": macos_ref["sha256"],
        "macos_material_builder_first_sha256": build[
            "macos_material_builder_first_sha256"
        ],
        "macos_material_builder_second_sha256": build[
            "macos_material_builder_first_sha256"
        ],
        "independent_build_roots": True,
        "production_activation": False,
    }:
        fail("build_report does not prove two matching builds per architecture")
    if (
        not isinstance(build["macos_material_builder_first_sha256"], str)
        or not HEX64.fullmatch(build["macos_material_builder_first_sha256"])
        or build["macos_material_builder_first_sha256"] == "0" * 64
        or material_builder_ref["sha256"]
        in {source_ref["sha256"], linux_ref["sha256"], macos_ref["sha256"]}
    ):
        fail("build_report material-author role separation differs")
    if candidate["reproducible_build"] is not True or candidate["production_activation"] is not False:
        fail("candidate build/activation flags are not derived from build_report")

    _, topology_path = artifact(records, "topology")
    topology = read_json(topology_path, "topology")
    if topology.get("schema_version") != 1 or topology.get("fleet_id") != summary["fleet_id"]:
        fail("topology schema/fleet mismatch")
    if topology.get("network_scope") != "single-lan" or topology.get("geo_wan_evidence") is not False:
        fail("topology must remain single-lan and geo_wan_evidence=false")
    if topology.get("validator_count") != validator_count:
        fail("topology validator_count mismatch")
    if topology.get("peer_degree") != summary["topology"]["peer_degree"]:
        fail("topology peer_degree mismatch")
    if topology.get("weight_profile") != summary["topology"]["weight_profile"]:
        fail("topology weight_profile mismatch")
    if topology.get("test_keys_included") is not False or summary["topology"]["ephemeral_test_keys"] is not True:
        fail("topology must omit private keys and identify ephemeral run keys")
    planned = topology.get("validators")
    if not isinstance(planned, list) or len(planned) != validator_count:
        fail("topology validators do not match the run cardinality")
    planned_by_id = {item.get("validator_id"): item for item in planned if isinstance(item, dict)}
    if set(planned_by_id) != set(summary_validators):
        fail("topology validator identities differ from the summary")

    planned_participants = topology.get("participants")
    if not isinstance(planned_participants, list):
        fail("topology participants must bind the six physical hosts")
    planned_participants_by_id = {
        item.get("host_id"): item for item in planned_participants if isinstance(item, dict)
    }
    if set(planned_participants_by_id) != {
        participant["host_id"] for participant in summary["participants"]
    }:
        fail("topology participants differ from the summary")

    validator_set_ref, validator_set_path = artifact(records, "validator_set")
    validator_set = exact(
        read_json(validator_set_path, "validator_set"),
        {
            "schema_version",
            "run_id",
            "chain_id",
            "genesis_hash",
            "protocol_version",
            "epoch",
            "consensus_parameters_profile",
            "candidate_source_sha256",
            "production_activation",
            "validators",
        },
        "validator_set",
    )
    if (
        validator_set["schema_version"] != 1
        or validator_set["run_id"] != run_id
        or validator_set["chain_id"] != "trnm-poco-g3-lab-v0"
        or validator_set["protocol_version"] != 0
        or validator_set["epoch"] != 0
        or validator_set["consensus_parameters_profile"] != "reference-shadow-v0"
        or validator_set["candidate_source_sha256"] != source_ref["sha256"]
        or validator_set["production_activation"] is not False
    ):
        fail("validator_set fixed fields differ from the pre-run lab contract")
    set_records = validator_set["validators"]
    if not isinstance(set_records, list) or len(set_records) != validator_count:
        fail("validator_set cardinality mismatch")
    validator_set_by_id: dict[str, dict[str, Any]] = {}
    previous_validator_id = ""
    set_public_keys: set[str] = set()
    canonical_inventory: list[tuple[bytes, bytes, int]] = []
    total_power = 0
    for index, value in enumerate(set_records):
        record = exact(
            value,
            {
                "validator_id",
                "consensus_public_key",
                "voting_power",
                "key_pop_signature",
            },
            f"validator_set.validators[{index}]",
        )
        validator_id = record["validator_id"]
        public_key = record["consensus_public_key"]
        signature = record["key_pop_signature"]
        power = record["voting_power"]
        if (
            not isinstance(validator_id, str)
            or not HEX64.fullmatch(validator_id)
            or (previous_validator_id and validator_id <= previous_validator_id)
            or validator_id not in planned_by_id
            or not isinstance(public_key, str)
            or not HEX64.fullmatch(public_key)
            or public_key in set_public_keys
            or not isinstance(signature, str)
            or not HEX128.fullmatch(signature)
            or isinstance(power, bool)
            or not isinstance(power, int)
            or power <= 0
            or power != planned_by_id[validator_id]["weight"]
        ):
            fail("validator_set record differs from topology/canonical inventory")
        previous_validator_id = validator_id
        set_public_keys.add(public_key)
        total_power += power
        verify_pop(public_key, signature, run_id, validator_id)
        validator_set_by_id[validator_id] = record
        canonical_inventory.append(
            (bytes.fromhex(validator_id), bytes.fromhex(public_key), power)
        )
    if set(validator_set_by_id) != set(summary_validators):
        fail("validator_set identities differ from the completed run")
    if any(record["voting_power"] * 4 > total_power for record in set_records):
        fail("validator_set violates the 25 percent voting-power cap")
    try:
        expected_genesis = canonical_lab_genesis_hash(
            validator_set["chain_id"], canonical_inventory
        ).hex()
    except (UnicodeError, ValueError) as error:
        fail(f"validator_set canonical genesis input is invalid: {error}")
    if validator_set["genesis_hash"] != expected_genesis:
        fail("validator_set genesis differs from canonical chain-only inputs")

    _, coordinator_path = artifact(records, "coordinator_manifest")
    coordinator = exact(
        read_json(coordinator_path, "coordinator_manifest"),
        {
            "schema_version",
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
        "coordinator_manifest",
    )
    if (
        coordinator["schema_version"] != 2
        or coordinator["run_id"] != run_id
        or coordinator["fleet_id"] != summary["fleet_id"]
        or coordinator["validator_count"] != validator_count
        or coordinator["weight_profile"] != summary["topology"]["weight_profile"]
        or coordinator["network_scope"] != "single-lan"
        or coordinator["geo_wan_evidence"] is not False
        or coordinator["candidate"]
        != {
            "source_tree_sha256": source_ref["sha256"],
            "linux_x86_64_sha256": linux_ref["sha256"],
            "macos_arm64_sha256": macos_ref["sha256"],
        }
        or coordinator["material_author"]
        != {
            "binary_sha256": material_builder_ref["sha256"],
            "runtime_deployed": False,
        }
        or coordinator["validator_set_sha256"] != validator_set_ref["sha256"]
        or coordinator["production_activation"] is not False
    ):
        fail("coordinator_manifest differs from the run/candidate boundary")

    # Re-parse the exact schema-1 deployment configs, not the older synthetic
    # evidence projection.  These public files are the bytes each validator
    # actually receives; peer keys, the validator-set descriptor hash, source
    # candidate, and non-production LAN boundary must therefore all agree
    # before any process evidence can be interpreted.
    configs: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    consensus_keys: dict[str, str] = {}
    validator_set_hashes: set[str] = set()
    workload_bindings: set[tuple[int, str, str]] = set()
    for validator_id in sorted(summary_validators):
        config_ref, config_path = artifact(records, "validator_config", validator_id)
        config = exact(
            read_json(config_path, f"validator_config[{validator_id}]"),
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
                "validator_set_sha256",
                "binary_sha256",
                "ordinary_start_height",
                "workload_corpus_sha256",
                "workload_policy_sha256",
                "secret_key_path",
                "peers",
                "network_scope",
                "geo_wan_evidence",
                "production_activation",
            },
            f"validator_config[{validator_id}]",
        )
        expected = summary_validators[validator_id]
        plan = planned_by_id[validator_id]
        public_key = config["consensus_public_key"]
        validator_set_sha256 = config["validator_set_sha256"]
        if (
            config["schema_version"] != 1
            or config["run_id"] != run_id
            or config["validator_id"] != validator_id
            or config["host_id"] != expected["host_id"]
            or config["lan_ip"] != expected["lan_ip"]
            or config["p2p_port"] != expected["p2p_port"]
            or config["metrics_port"] != expected["metrics_port"]
            or config["weight"] != expected["weight"]
            or config["binary_sha256"] != expected["binary_sha256"]
            or isinstance(config["ordinary_start_height"], bool)
            or not isinstance(config["ordinary_start_height"], int)
            or config["ordinary_start_height"] != 4
            or not isinstance(config["workload_corpus_sha256"], str)
            or not HEX64.fullmatch(config["workload_corpus_sha256"])
            or not isinstance(config["workload_policy_sha256"], str)
            or not HEX64.fullmatch(config["workload_policy_sha256"])
            or config["secret_key_path"] != f"secrets/{validator_id}.pk8"
            or config["network_scope"] != "single-lan"
            or config["geo_wan_evidence"] is not False
            or config["production_activation"] is not False
            or not isinstance(public_key, str)
            or not HEX64.fullmatch(public_key)
            or not isinstance(validator_set_sha256, str)
            or not HEX64.fullmatch(validator_set_sha256)
            or not isinstance(plan, dict)
        ):
            fail(f"validator_config[{validator_id}] differs from topology/candidate")
        if public_key in consensus_keys.values():
            fail("validator configs contain duplicate consensus public keys")
        if public_key != validator_set_by_id[validator_id]["consensus_public_key"]:
            fail(f"validator_config[{validator_id}] key differs from validator_set")
        consensus_keys[validator_id] = public_key
        validator_set_hashes.add(validator_set_sha256)
        workload_bindings.add(
            (
                config["ordinary_start_height"],
                config["workload_corpus_sha256"],
                config["workload_policy_sha256"],
            )
        )
        configs[validator_id] = (config_ref, config)
    if validator_set_hashes != {validator_set_ref["sha256"]}:
        fail(
            "validator configs do not bind the exact validator-set descriptor artifact"
        )
    if len(workload_bindings) != 1:
        fail("validator configs do not share one exact ordinary workload binding")
    workload_binding = next(iter(workload_bindings))
    ordinary_start_height = workload_binding[0]
    if workload_binding != (
        4,
        artifact(records, "workload_corpus")[0]["sha256"],
        artifact(records, "workload_policy")[0]["sha256"],
    ):
        fail("validator configs do not bind the exact public workload artifacts")

    for validator_id, (_, config) in configs.items():
        plan = planned_by_id[validator_id]
        expected_peers = [
            {
                "validator_id": peer_id,
                "lan_ip": planned_by_id[peer_id]["lan_ip"],
                "p2p_port": planned_by_id[peer_id]["p2p_port"],
                "consensus_public_key": consensus_keys[peer_id],
            }
            for peer_id in plan["peers"]
        ]
        if config["peers"] != expected_peers:
            fail(f"validator_config[{validator_id}] peer graph/key binding differs from topology")

    observer_config_ref, observer_config_path = artifact(records, "observer_config", "mac")
    observer_config = exact(
        read_json(observer_config_path, "observer_config[mac]"),
        {
            "schema_version",
            "run_id",
            "host_id",
            "lan_ip",
            "os",
            "arch",
            "run_roles",
            "binary_sha256",
            "candidate_source_sha256",
            "validator_set_sha256",
            "validator_endpoints",
            "network_scope",
            "geo_wan_evidence",
            "production_activation",
        },
        "observer_config[mac]",
    )
    planned_observer = planned_participants_by_id.get("mac")
    expected_observer_config = {
        "schema_version": 1,
        "run_id": run_id,
        "host_id": "mac",
        "lan_ip": planned_observer.get("lan_ip") if isinstance(planned_observer, dict) else None,
        "os": "macos",
        "arch": "arm64",
        "run_roles": planned_observer.get("run_roles") if isinstance(planned_observer, dict) else None,
        "binary_sha256": macos_ref["sha256"],
        "candidate_source_sha256": source_ref["sha256"],
        "validator_set_sha256": validator_set_ref["sha256"],
        "validator_endpoints": [
            {
                "validator_id": item["validator_id"],
                "lan_ip": item["lan_ip"],
                "p2p_port": item["p2p_port"],
                "metrics_port": item["metrics_port"],
                "consensus_public_key": consensus_keys[item["validator_id"]],
            }
            for item in planned
        ],
        "network_scope": "single-lan",
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    if observer_config != expected_observer_config:
        fail("observer_config[mac] differs from topology/candidate")

    def manifest_ref(value: object, field: str) -> dict[str, Any]:
        record = exact(value, {"path", "sha256", "bytes"}, field)
        if (
            not isinstance(record["path"], str)
            or not record["path"]
            or not isinstance(record["sha256"], str)
            or not HEX64.fullmatch(record["sha256"])
            or isinstance(record["bytes"], bool)
            or not isinstance(record["bytes"], int)
            or record["bytes"] <= 0
        ):
            fail(f"{field} is not one canonical content reference")
        return record

    public_values = coordinator["public_files"]
    if not isinstance(public_values, list):
        fail("coordinator_manifest public_files must be a list")
    public_by_path: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(public_values):
        record = manifest_ref(value, f"coordinator_manifest.public_files[{index}]")
        if record["path"] in public_by_path:
            fail("coordinator_manifest has duplicate public paths")
        public_by_path[record["path"]] = record
    expected_public: dict[str, dict[str, Any]] = {
        path: artifact(records, role)[0]
        for role, path in evidence_profiles.COORDINATOR_PUBLIC_SINGLETON_PATHS.items()
    }
    expected_public.update({
        "public/observer-configs/mac.json": observer_config_ref,
    })
    expected_public.update(
        {
            f"public/configs/{validator_id}.json": configs[validator_id][0]
            for validator_id in sorted(configs)
        }
    )
    if set(public_by_path) != set(expected_public):
        fail("coordinator_manifest public inventory differs from raw run inputs")
    for path, expected_ref in expected_public.items():
        if public_by_path[path] != {
            "path": path,
            "sha256": expected_ref["sha256"],
            "bytes": expected_ref["bytes"],
        }:
            fail("coordinator_manifest public content reference differs from raw bytes")

    secret_values = coordinator["secret_files"]
    if not isinstance(secret_values, list) or len(secret_values) != validator_count:
        fail("coordinator_manifest secret inventory cardinality mismatch")
    secret_ids: set[str] = set()
    for index, value in enumerate(secret_values):
        record = manifest_ref(value, f"coordinator_manifest.secret_files[{index}]")
        match = re.fullmatch(r"secrets/([0-9a-f]{64})\.pk8", record["path"])
        if match is None or match.group(1) in secret_ids:
            fail("coordinator_manifest secret inventory is not closed and unique")
        secret_ids.add(match.group(1))
    if secret_ids != set(summary_validators):
        fail("coordinator_manifest secret inventory differs from validator_set")

    _, observer_report_path = artifact(records, "observer_report", "mac")
    observer_report = exact(
        read_json(observer_report_path, "observer_report[mac]"),
        {
            "schema_version",
            "run_id",
            "host_id",
            "process_id",
            "config_sha256",
            "binary_sha256",
            "load_submitted_nonempty_blocks",
            "verified_qc_signatures",
            "rejected_invalid_signature_controls",
            "started_at",
            "ended_at",
        },
        "observer_report[mac]",
    )
    if (
        observer_report["schema_version"] != 1
        or observer_report["run_id"] != run_id
        or observer_report["host_id"] != "mac"
    ):
        fail("observer_report[mac] identity mismatch")
    positive_int(observer_report["process_id"], "observer_report[mac].process_id")
    if observer_report["config_sha256"] != observer_config_ref["sha256"]:
        fail("observer_report[mac] does not bind observer_config")
    if observer_report["binary_sha256"] != macos_ref["sha256"]:
        fail("observer_report[mac] does not bind the macOS candidate")
    positive_int(
        observer_report["load_submitted_nonempty_blocks"],
        "observer_report[mac].load_submitted_nonempty_blocks",
    )
    if positive_int(
        observer_report["verified_qc_signatures"],
        "observer_report[mac].verified_qc_signatures",
    ) < validator_count:
        fail("observer_report[mac] verified fewer QC signatures than validators")
    positive_int(
        observer_report["rejected_invalid_signature_controls"],
        "observer_report[mac].rejected_invalid_signature_controls",
    )
    if timestamp(observer_report["started_at"], "observer_report[mac].started_at") >= timestamp(
        observer_report["ended_at"], "observer_report[mac].ended_at"
    ):
        fail("observer_report[mac] interval is empty")

    derived_validators: list[dict[str, Any]] = []
    submitted_counts: list[int] = []
    restart_pairs: list[
        tuple[str, datetime.datetime, datetime.datetime]
    ] = []
    fault_transitions: dict[
        tuple[str, str], dict[str, datetime.datetime]
    ] = {}
    final_tip_times: dict[str, datetime.datetime] = {}
    run_started = timestamp(summary["started_at"], "summary.started_at")
    run_ended = timestamp(summary["ended_at"], "summary.ended_at")

    metric_start: str | None = None
    metric_end: str | None = None
    finality_samples: list[float] = []
    cpu_seconds = 0.0
    peak_rss_bytes = 0
    disk_bytes = 0
    fsync_count = 0
    network_tx_bytes = 0
    network_rx_bytes = 0

    for validator_id in sorted(summary_validators):
        expected = summary_validators[validator_id]
        signed = signed_validators[validator_id]
        signed_journal = signed["journal"]
        signed_report = signed["report"]
        signed_metrics = signed["metrics"]
        signed_final_state = signed["final_state"]
        config_ref, _ = configs[validator_id]
        if expected["config_sha256"] != config_ref["sha256"]:
            fail(f"validator {validator_id} config hash is not content-derived")

        _, final_path = artifact(records, "validator_final_state", validator_id)
        final_state = exact(
            read_json(final_path, f"validator_final_state[{validator_id}]"),
            {
                "schema_version",
                "run_id",
                "validator_id",
                "process_id",
                "process_instance_count",
                "ordinary_start_height",
                "finalized_height",
                "finalized_ordinary_block_count",
                "finalized_block_id",
                "finalized_state_root",
                "finalized_chain_root",
                "applied_height",
                "all_finalized_ordinary_blocks_nonempty",
                "double_sign_events",
                "duplicate_apply_events",
                "state_drift_events",
                "safety_halt_violations",
            },
            f"validator_final_state[{validator_id}]",
        )
        if final_state["schema_version"] != 2 or final_state["run_id"] != run_id or final_state["validator_id"] != validator_id:
            fail(f"validator_final_state[{validator_id}] identity mismatch")
        for field in ("finalized_block_id", "finalized_state_root", "finalized_chain_root"):
            if not isinstance(final_state[field], str) or not HEX64.fullmatch(final_state[field]):
                fail(f"validator_final_state[{validator_id}].{field} must be sha256")
        positive_int(final_state["process_id"], f"validator_final_state[{validator_id}].process_id")
        positive_int(final_state["process_instance_count"], f"validator_final_state[{validator_id}].process_instance_count")
        if final_state["ordinary_start_height"] != ordinary_start_height:
            fail(f"validator_final_state[{validator_id}] ordinary start differs from config")
        positive_int(final_state["finalized_height"], f"validator_final_state[{validator_id}].finalized_height")
        if final_state["finalized_height"] < ordinary_start_height:
            fail(f"validator_final_state[{validator_id}] has no finalized ordinary block")
        if final_state["finalized_ordinary_block_count"] != (
            final_state["finalized_height"] - ordinary_start_height + 1
        ):
            fail(f"validator_final_state[{validator_id}] ordinary count/height mapping differs")
        if final_state["applied_height"] != final_state["finalized_height"]:
            fail(f"validator_final_state[{validator_id}] is not fully applied")
        if final_state["all_finalized_ordinary_blocks_nonempty"] is not True:
            fail(f"validator_final_state[{validator_id}] includes an empty finalized ordinary block")
        for field in ("double_sign_events", "duplicate_apply_events", "state_drift_events", "safety_halt_violations"):
            if nonnegative_int(final_state[field], f"validator_final_state[{validator_id}].{field}") != 0:
                fail(f"validator_final_state[{validator_id}].{field} must be zero")
        signed_final_projection = {
            "process_id": signed_final_state["process_id"],
            "process_instance_count": signed_final_state["process_instance_count"],
            "ordinary_start_height": signed_final_state["ordinary_start_height"],
            "finalized_height": signed_final_state["finalized_height"],
            "finalized_ordinary_block_count": signed_final_state[
                "finalized_ordinary_block_count"
            ],
            "finalized_block_id": signed_final_state["finalized_block_id"],
            "finalized_state_root": signed_final_state["finalized_state_root"],
            "finalized_chain_root": signed_final_state["finalized_chain_root"],
            "applied_height": signed_final_state["applied_height"],
            "all_finalized_ordinary_blocks_nonempty": signed_final_state[
                "finalized_nonempty_ordinary_block_count"
            ]
            == signed_final_state["finalized_ordinary_block_count"],
            "double_sign_events": signed_final_state["double_sign_events"],
            "duplicate_apply_events": signed_final_state["duplicate_apply_events"],
            "state_drift_events": signed_final_state["state_drift_events"],
            "safety_halt_violations": signed_final_state["safety_halt_violations"],
        }
        if {
            key: final_state[key] for key in signed_final_projection
        } != signed_final_projection:
            fail(
                f"validator_final_state[{validator_id}] conflicts with signed final state"
            )
        _, events_path = artifact(records, "validator_event_log", validator_id)
        events = read_jsonl(events_path, f"validator_event_log[{validator_id}]")
        previous_time: datetime.datetime | None = None
        process_start_count = 0
        pending_restart: datetime.datetime | None = None
        completed_restart = False
        observed_restart_event: dict[str, Any] | None = None
        observed_catchup_event: dict[str, Any] | None = None
        for index, event in enumerate(events):
            if event["schema_version"] != 1 or event["run_id"] != run_id or event["validator_id"] != validator_id:
                fail(f"validator_event_log[{validator_id}][{index}] identity mismatch")
            if nonnegative_int(
                event["sequence"],
                f"validator_event_log[{validator_id}][{index}].sequence",
            ) != index:
                fail(f"validator_event_log[{validator_id}] sequence is not contiguous")
            observed = timestamp(event["observed_at"], f"validator_event_log[{validator_id}][{index}].observed_at")
            if previous_time is not None and observed < previous_time:
                fail(f"validator_event_log[{validator_id}] timestamps regress")
            if observed < run_started or observed > run_ended:
                fail(f"validator_event_log[{validator_id}] event is outside the run interval")
            previous_time = observed
            kind = event["kind"]
            if kind == "process_start":
                process_start_count += 1
                if (
                    index != 0
                    or process_start_count != 1
                    or event["subject"] != "instance-1"
                ):
                    fail(
                        f"validator_event_log[{validator_id}] has an invalid initial process_start"
                    )
                positive_int(
                    event["value"],
                    f"validator_event_log[{validator_id}].process_start.value",
                )
            elif kind == "submitted_nonempty_blocks":
                if event["subject"] != "":
                    fail("submitted_nonempty_blocks subject must be empty")
                submitted = positive_int(
                    event["value"], "submitted_nonempty_blocks.value"
                )
                if submitted != signed_report["submitted_ordinary_block_count"]:
                    fail(
                        "unsigned submitted block observation conflicts with signed report"
                    )
                submitted_counts.append(submitted)
            elif kind == "restart":
                if pending_restart is not None or completed_restart:
                    fail("restart/catch-up evidence must contain exactly one pair per subject")
                if (
                    final_state["process_instance_count"] != 2
                    or event["subject"] != "instance-2"
                    or positive_int(event["value"], "restart.value")
                    != final_state["process_id"]
                ):
                    fail("restart event does not bind the terminal process instance")
                pending_restart = observed
                observed_restart_event = event
            elif kind == "catchup_complete":
                if pending_restart is None or completed_restart:
                    fail("catch-up event has no preceding restart for the same validator")
                if observed <= pending_restart:
                    fail("catch-up event must be strictly later than restart")
                if (
                    event["subject"] != final_state["finalized_block_id"]
                    or nonnegative_int(event["value"], "catchup_complete.value")
                    != final_state["finalized_height"]
                ):
                    fail("catch-up event does not bind the validator terminal tip")
                restart_pairs.append((validator_id, pending_restart, observed))
                pending_restart = None
                completed_restart = True
                observed_catchup_event = event
            elif kind == "fault_applied":
                subject = event["subject"]
                if not isinstance(subject, str) or subject not in check_run_evidence.REQUIRED_FAULTS:
                    fail("fault_applied event names an unknown fault")
                if type(event["value"]) is not int or event["value"] != 1:
                    fail("fault_applied event value must be the integer one")
                if signed_journal["fault_values"].get(subject, {}).get("applied") != 1:
                    fail("unsigned fault application conflicts with signed journal")
                key = (validator_id, subject)
                if key in fault_transitions:
                    fail("fault application is duplicated or follows recovery")
                fault_transitions[key] = {"applied": observed}
            elif kind == "fault_recovered":
                subject = event["subject"]
                if not isinstance(subject, str) or subject not in check_run_evidence.REQUIRED_FAULTS:
                    fail("fault_recovered event names an unknown fault")
                key = (validator_id, subject)
                transition = fault_transitions.get(key)
                if transition is None or "recovered" in transition:
                    fail("fault recovery has no unique preceding application")
                if observed <= transition["applied"]:
                    fail("fault recovery must be strictly later than application")
                recovered_value = nonnegative_int(
                    event["value"], "fault_recovered.value"
                )
                if recovered_value != final_state["finalized_height"]:
                    fail("fault recovery does not bind the validator terminal height")
                if (
                    signed_journal["fault_values"]
                    .get(subject, {})
                    .get("recovered")
                    != recovered_value
                ):
                    fail("unsigned fault recovery conflicts with signed journal")
                transition["recovered"] = observed
            elif kind != "finalized_tip":
                fail(f"validator_event_log[{validator_id}] has unknown event kind {kind!r}")
        if process_start_count != 1:
            fail(f"validator_event_log[{validator_id}] requires one initial process_start")
        if pending_restart is not None:
            fail("restart has no later catch-up event for the same validator")
        if final_state["process_instance_count"] != (2 if completed_restart else 1):
            fail("process_instance_count differs from the restart state machine")
        if completed_restart != signed_final_state["restart_completed"]:
            fail(
                f"validator_event_log[{validator_id}] restart state conflicts with signed journal"
            )
        signed_restart_event = signed_journal["restart_event"]
        signed_catchup_event = signed_journal["catchup_event"]
        if completed_restart:
            if (
                signed_restart_event is None
                or signed_catchup_event is None
                or observed_restart_event is None
                or observed_catchup_event is None
                or {
                    key: observed_restart_event[key]
                    for key in ("subject", "value")
                }
                != {
                    key: signed_restart_event[key] for key in ("subject", "value")
                }
                or {
                    key: observed_catchup_event[key]
                    for key in ("subject", "value")
                }
                != {
                    key: signed_catchup_event[key] for key in ("subject", "value")
                }
            ):
                fail(
                    f"validator_event_log[{validator_id}] restart/catch-up values "
                    "conflict with signed journal"
                )
        elif signed_restart_event is not None or signed_catchup_event is not None:
            fail(
                f"validator_event_log[{validator_id}] omits signed restart/catch-up"
            )
        if set(signed_journal["fault_transitions"]) != {
            subject
            for (owner, subject), transition in fault_transitions.items()
            if owner == validator_id and set(transition) == {"applied", "recovered"}
        }:
            fail(
                f"validator_event_log[{validator_id}] fault set conflicts with signed journal"
            )
        tips = [event for event in events if event["kind"] == "finalized_tip"]
        expected_tip_subject = ":".join(
            (
                final_state["finalized_block_id"],
                final_state["finalized_state_root"],
                final_state["finalized_chain_root"],
            )
        )
        if (
            len(tips) != 1
            or tips[0]["subject"] != expected_tip_subject
            or nonnegative_int(
                tips[0]["value"],
                f"validator_event_log[{validator_id}].finalized_tip.value",
            )
            != final_state["finalized_height"]
        ):
            fail(f"validator_event_log[{validator_id}] does not bind the exact final state")
        final_tip_times[validator_id] = timestamp(
            tips[0]["observed_at"],
            f"validator_event_log[{validator_id}].finalized_tip.observed_at",
        )
        _, metrics_path = artifact(records, "validator_metrics", validator_id)
        metrics = exact(
            read_json(metrics_path, f"validator_metrics[{validator_id}]"),
            {
                "schema_version",
                "run_id",
                "validator_id",
                "measurement_started_at",
                "measurement_ended_at",
                "finality_samples_ms",
                "cpu_seconds",
                "peak_rss_bytes",
                "disk_bytes",
                "fsync_count",
                "network_tx_bytes",
                "network_rx_bytes",
            },
            f"validator_metrics[{validator_id}]",
        )
        if metrics["schema_version"] != 1 or metrics["run_id"] != run_id or metrics["validator_id"] != validator_id:
            fail(f"validator_metrics[{validator_id}] identity mismatch")
        signed_metric_projection = {
            "measurement_started_at": signed_metrics["measurement_started_at"],
            "measurement_ended_at": signed_metrics["measurement_ended_at"],
            "finality_samples_ms": signed_metrics["finality_samples_ms"],
            "cpu_seconds": signed_metrics["cpu_seconds"],
            "peak_rss_bytes": signed_metrics["peak_rss_bytes"],
            "disk_bytes": signed_metrics["disk_bytes"],
            "fsync_count": signed_metrics["fsync_count"],
            "network_tx_bytes": signed_metrics["network_tx_bytes"],
            "network_rx_bytes": signed_metrics["network_rx_bytes"],
        }
        if {key: metrics[key] for key in signed_metric_projection} != signed_metric_projection:
            fail(f"validator_metrics[{validator_id}] conflicts with signed runtime metrics")
        start = signed_metrics["measurement_started_at"]
        end = signed_metrics["measurement_ended_at"]
        start_dt = timestamp(start, f"validator_metrics[{validator_id}].measurement_started_at")
        end_dt = timestamp(end, f"validator_metrics[{validator_id}].measurement_ended_at")
        if start_dt >= end_dt:
            fail(f"validator_metrics[{validator_id}] interval is empty")
        if metric_start is None:
            metric_start, metric_end = start, end
        elif (start, end) != (metric_start, metric_end):
            fail("all validator metrics must use the exact same interval")
        samples = metrics["finality_samples_ms"]
        if not isinstance(samples, list) or not samples:
            fail(f"validator_metrics[{validator_id}].finality_samples_ms must be non-empty")
        finality_samples.extend(
            positive_number(
                value,
                f"signed runtime metrics[{validator_id}].finality_samples_ms",
            )
            for value in signed_metrics["finality_samples_ms"]
        )
        cpu_seconds += positive_number(
            signed_metrics["cpu_seconds"], "signed metrics.cpu_seconds"
        )
        peak_rss_bytes = max(
            peak_rss_bytes,
            positive_int(
                signed_metrics["peak_rss_bytes"], "signed metrics.peak_rss_bytes"
            ),
        )
        disk_bytes += positive_int(
            signed_metrics["disk_bytes"], "signed metrics.disk_bytes"
        )
        fsync_count += positive_int(
            signed_metrics["fsync_count"], "signed metrics.fsync_count"
        )
        network_tx_bytes += positive_int(
            signed_metrics["network_tx_bytes"], "signed metrics.network_tx_bytes"
        )
        network_rx_bytes += positive_int(
            signed_metrics["network_rx_bytes"], "signed metrics.network_rx_bytes"
        )
        derived_validators.append(
            {
                **{key: expected[key] for key in ("validator_id", "host_id", "lan_ip", "p2p_port", "metrics_port", "weight", "binary_sha256", "config_sha256")},
                "process_id": signed_final_state["process_id"],
            }
        )

    if len(submitted_counts) != 1:
        fail("exactly one validator must report submitted_nonempty_blocks")
    signed_report_counts = {
        (
            value["report"]["submitted_ordinary_block_count"],
            value["report"]["committed_ordinary_block_count"],
            value["report"]["finalized_ordinary_block_count"],
        )
        for value in signed_validators.values()
    }
    if len(signed_report_counts) != 1:
        fail("signed reports disagree on ordinary-block counts")
    (
        authoritative_submitted_count,
        authoritative_committed_count,
        authoritative_finalized_count,
    ) = next(iter(signed_report_counts))
    if submitted_counts[0] != authoritative_submitted_count:
        fail("unsigned submission observation conflicts with signed reports")
    if observer_report["load_submitted_nonempty_blocks"] != authoritative_submitted_count:
        fail("observer load submission count differs from validator observation")
    tip_tuples = {
        (
            value["final_state"]["finalized_height"],
            value["final_state"]["finalized_block_id"],
            value["final_state"]["finalized_state_root"],
            value["final_state"]["finalized_chain_root"],
        )
        for value in signed_validators.values()
    }
    if len(tip_tuples) != 1:
        fail("validator final-state roots/heights do not agree")
    finalized_height = next(iter(tip_tuples))[0]
    finalized_ordinary_block_count = finalized_height - ordinary_start_height + 1
    if finalized_ordinary_block_count != authoritative_finalized_count:
        fail("signed report/final-state finalized ordinary-block counts differ")
    if authoritative_submitted_count < finalized_ordinary_block_count:
        fail("submitted non-empty blocks are below the finalized ordinary-block count")
    signed_safety_counts = {
        field: sum(
            value["final_state"][field] for value in signed_validators.values()
        )
        for field in (
            "double_sign_events",
            "duplicate_apply_events",
            "state_drift_events",
            "safety_halt_violations",
        )
    }
    if restart_pairs or signed_runtime.get("restarted_validator_id") is not None:
        fail("no-fault-v1 forbids restart/catch-up observations")
    if fault_transitions or signed_runtime.get("fault_owners") != {}:
        fail("no-fault-v1 forbids fault transition observations")
    if any(role in {"fault_schedule", "fault_command_log"} for role, _ in records):
        fail("no-fault-v1 forbids fault artifacts")
    derived_faults: list[dict[str, Any]] = []

    assert metric_start is not None and metric_end is not None
    start_dt = timestamp(metric_start, "measurement_started_at")
    end_dt = timestamp(metric_end, "measurement_ended_at")
    measurement_seconds = int((end_dt - start_dt).total_seconds())
    if (
        observer_report["started_at"] != metric_start
        or observer_report["ended_at"] != metric_end
    ):
        fail("observer report and validator measurements use different intervals")
    validators_by_host: dict[str, list[dict[str, Any]]] = {}
    for validator in derived_validators:
        validators_by_host.setdefault(validator["host_id"], []).append(validator)
    derived_participants: list[dict[str, Any]] = []
    for host_id, plan in sorted(planned_participants_by_id.items()):
        hosted = validators_by_host.get(host_id, [])
        if host_id == "mac":
            derived_participants.append(
                {
                    "host_id": host_id,
                    "lan_ip": plan["lan_ip"],
                    "run_roles": plan["run_roles"],
                    "process_ids": [observer_report["process_id"]],
                    "binary_sha256": macos_ref["sha256"],
                    "config_set_sha256": check_run_evidence.observer_configuration_set_digest(
                        observer_config_ref["sha256"]
                    ),
                }
            )
        else:
            derived_participants.append(
                {
                    "host_id": host_id,
                    "lan_ip": plan["lan_ip"],
                    "run_roles": plan["run_roles"],
                    "process_ids": sorted(item["process_id"] for item in hosted),
                    "binary_sha256": linux_ref["sha256"],
                    "config_set_sha256": check_run_evidence.host_validator_configuration_set_digest(
                        hosted
                    ),
                }
            )
    derived = {
        "started_at": metric_start,
        "ended_at": metric_end,
        "validators": sorted(derived_validators, key=lambda item: item["validator_id"]),
        "participants": derived_participants,
        "consensus": {
            "ordinary_start_height": ordinary_start_height,
            "submitted_nonempty_blocks": authoritative_submitted_count,
            "committed_nonempty_blocks": authoritative_committed_count,
            "finalized_height": finalized_height,
            "state_root_agreement": True,
            **signed_safety_counts,
            "restart_catchup_passed": False,
            "heal_convergence_passed": False,
        },
        "faults": derived_faults,
        "performance": {
            "measurement_seconds": measurement_seconds,
            "committed_goodput_tps": authoritative_committed_count
            / measurement_seconds,
            "finality_ms_p50": nearest_rank(finality_samples, 0.50),
            "finality_ms_p95": nearest_rank(finality_samples, 0.95),
            "finality_ms_p99": nearest_rank(finality_samples, 0.99),
            "cpu_seconds": cpu_seconds,
            "peak_rss_bytes": peak_rss_bytes,
            "disk_bytes": disk_bytes,
            "fsync_count": fsync_count,
            "network_tx_bytes": network_tx_bytes,
            "network_rx_bytes": network_rx_bytes,
        },
    }
    if summary["started_at"] != derived["started_at"] or summary["ended_at"] != derived["ended_at"]:
        fail("summary timestamps are not raw-derived")
    if sorted(summary["validators"], key=lambda item: item["validator_id"]) != derived["validators"]:
        fail("summary validators are not raw-derived")
    if sorted(summary["participants"], key=lambda item: item["host_id"]) != derived["participants"]:
        fail("summary participants are not raw-derived")
    if summary["consensus"] != derived["consensus"]:
        fail("summary consensus is not raw-derived")
    if summary["faults"] != derived["faults"]:
        fail("summary faults are not raw-derived")
    if summary["performance"] != derived["performance"]:
        fail("summary performance is not raw-derived")
    if candidate["configuration_set_sha256"] != check_run_evidence.configuration_set_digest(summary["validators"]):
        fail("candidate configuration set is not raw-derived")
