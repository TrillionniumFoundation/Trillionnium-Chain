#!/usr/bin/env python3
"""Strict candidate-only G1-R5 campaign contract validator v2."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

HEX40 = set("0123456789abcdef")
HEX64 = set("0123456789abcdef")
COMMON_SCENARIOS = {
    "normal-finality",
    "minority-offline-rejoin",
    "leader-crash-timeout-certificate",
    "restart-catch-up",
    "trusted-checkpoint-state-sync",
    "epoch-key-rotation",
    "signer-outage-recovery",
    "disk-full-io-fault",
    "commit-response-loss",
}
COUNT_SCENARIOS = {
    4: {
        "partition-3-1-progress",
        "partition-2-2-safe-stall",
        "partition-heal-convergence",
    },
    7: {
        "partition-5-2-progress",
        "partition-weighted-minority-safe-stall",
        "partition-heal-convergence",
    },
}


class ContractError(ValueError):
    pass


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ContractError(f"duplicate-json-key:{key}")
        out[key] = value
    return out


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ContractError(f"non-finite-json:{token}")
            ),
        )
    except json.JSONDecodeError as exc:
        raise ContractError(f"invalid-json:{exc}") from exc
    if not isinstance(value, dict):
        raise ContractError("root-not-object")
    return value


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def require_hex(value: Any, size: int, label: str) -> str:
    if not isinstance(value, str) or len(value) != size:
        raise ContractError(f"{label}:wrong-length")
    allowed = HEX40 if size == 40 else HEX64
    if any(character not in allowed for character in value):
        raise ContractError(f"{label}:not-lower-hex")
    if set(value) == {"0"}:
        raise ContractError(f"{label}:zero")
    return value


def require_false(value: Any, label: str) -> None:
    if value is not False:
        raise ContractError(f"{label}:must-be-false")


def expected_pop(validator_id: str, public_key: str) -> str:
    frame = (
        b"trnm.g1-r5.validator-pop.v2\0"
        + bytes.fromhex(validator_id)
        + bytes.fromhex(public_key)
    )
    return hashlib.sha256(frame).hexdigest()


def validate_manifest(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("schema") != "trnm-g1-r5-native-campaign-v2":
        raise ContractError("schema")
    campaign_id = value.get("campaign_id")
    if not isinstance(campaign_id, str) or not campaign_id:
        raise ContractError("campaign-id")
    validator_count = value.get("validator_count")
    if validator_count not in (4, 7):
        raise ContractError("validator-count")

    identity = value.get("identity")
    if not isinstance(identity, dict):
        raise ContractError("identity")
    require_hex(identity.get("source_commit"), 40, "source-commit")
    require_hex(identity.get("source_tree"), 40, "source-tree")
    for key in (
        "binary_sha256",
        "sbom_sha256",
        "genesis_sha256",
        "topology_sha256",
        "workload_sha256",
        "fault_schedule_sha256",
    ):
        require_hex(identity.get(key), 64, key)
    if not isinstance(identity.get("binary_built"), bool):
        raise ContractError("binary-built-type")

    topology = value.get("topology")
    if not isinstance(topology, dict):
        raise ContractError("topology")
    validators = topology.get("validators")
    if not isinstance(validators, list) or len(validators) != validator_count:
        raise ContractError("validator-rows")
    if digest({"validators": validators}) != identity["topology_sha256"]:
        raise ContractError("topology-digest")

    seen: dict[str, set[Any]] = {
        name: set()
        for name in (
            "validator_id",
            "public_key",
            "process_id",
            "host_id",
            "operator_id",
            "custody_domain",
        )
    }
    regions: set[str] = set()
    total_weight = 0
    for row in validators:
        if not isinstance(row, dict):
            raise ContractError("validator-row")
        validator_id = require_hex(row.get("validator_id"), 64, "validator-id")
        public_key = require_hex(row.get("public_key"), 64, "public-key")
        pop = require_hex(row.get("proof_of_possession"), 64, "proof-of-possession")
        if pop != expected_pop(validator_id, public_key):
            raise ContractError("proof-of-possession")
        for name in seen:
            item = row.get(name)
            if name in ("validator_id", "public_key"):
                item = row[name]
            elif not isinstance(item, str) or not item:
                raise ContractError(f"{name}:invalid")
            if item in seen[name]:
                raise ContractError(f"{name}:duplicate")
            seen[name].add(item)
        region = row.get("region_id")
        if not isinstance(region, str) or not region:
            raise ContractError("region-id")
        regions.add(region)
        voting_power = row.get("voting_power")
        if (
            not isinstance(voting_power, int)
            or isinstance(voting_power, bool)
            or voting_power <= 0
        ):
            raise ContractError("voting-power")
        total_weight += voting_power

    expected_quorum = (2 * total_weight) // 3 + 1
    if topology.get("total_voting_power") != total_weight:
        raise ContractError("total-voting-power")
    if topology.get("quorum_voting_power") != expected_quorum:
        raise ContractError("quorum-voting-power")
    if len(seen["host_id"]) < 3 or len(seen["operator_id"]) < 3:
        raise ContractError("insufficient-host-or-operator-separation")
    if len(seen["custody_domain"]) < 3 or len(regions) < 3:
        raise ContractError("insufficient-custody-or-region-separation")
    counts = topology.get("topology_counts")
    expected_counts = {
        "validators": validator_count,
        "processes": len(seen["process_id"]),
        "hosts": len(seen["host_id"]),
        "operators": len(seen["operator_id"]),
        "custody_domains": len(seen["custody_domain"]),
        "regions": len(regions),
    }
    if counts != expected_counts:
        raise ContractError("topology-counts")

    workload = value.get("workload")
    if not isinstance(workload, dict) or digest(workload) != identity["workload_sha256"]:
        raise ContractError("workload-digest")
    if workload.get("transport") != "authenticated-bounded-p2p":
        raise ContractError("workload-transport")
    if (
        not isinstance(workload.get("duration_seconds"), int)
        or workload["duration_seconds"] <= 0
    ):
        raise ContractError("workload-duration")
    operations = workload.get("operation_mix")
    if not isinstance(operations, list) or not operations:
        raise ContractError("operation-mix")
    if sum(row.get("weight", 0) for row in operations if isinstance(row, dict)) != 100:
        raise ContractError("operation-mix-weight")

    fault_schedule = value.get("fault_schedule")
    if (
        not isinstance(fault_schedule, dict)
        or digest(fault_schedule) != identity["fault_schedule_sha256"]
    ):
        raise ContractError("fault-schedule-digest")
    scenarios = fault_schedule.get("scenarios")
    if not isinstance(scenarios, list):
        raise ContractError("scenarios")
    scenario_ids: set[str] = set()
    for row in scenarios:
        if not isinstance(row, dict):
            raise ContractError("scenario-row")
        scenario_id = row.get("id")
        if (
            not isinstance(scenario_id, str)
            or not scenario_id
            or scenario_id in scenario_ids
        ):
            raise ContractError("scenario-id")
        scenario_ids.add(scenario_id)
        if not isinstance(row.get("trigger"), dict) or not isinstance(
            row.get("expected"), dict
        ):
            raise ContractError("scenario-contract")
    required = COMMON_SCENARIOS | COUNT_SCENARIOS[validator_count]
    if not required.issubset(scenario_ids):
        raise ContractError("scenario-coverage")

    gate = value.get("execution_gate")
    if not isinstance(gate, dict):
        raise ContractError("execution-gate")
    authorized = gate.get("campaign_execution_authorized")
    if not isinstance(authorized, bool):
        raise ContractError("execution-authorized-type")
    evidence = gate.get("g1_r4_evidence")
    if not isinstance(evidence, dict):
        raise ContractError("g1-r4-evidence")
    if authorized:
        if evidence.get("status") != "accepted":
            raise ContractError("accepted-r4-evidence-required")
        if (
            evidence.get("g1_r4_exit") is not True
            or evidence.get("independent_review_accepted") is not True
        ):
            raise ContractError("accepted-r4-review-required")
        if (
            evidence.get("source_commit") != identity["source_commit"]
            or evidence.get("source_tree") != identity["source_tree"]
        ):
            raise ContractError("r4-source-binding")
        require_hex(evidence.get("evidence_root"), 64, "r4-evidence-root")
        reviewers = evidence.get("reviewer_ids")
        if not isinstance(reviewers, list) or len(set(reviewers)) < 2:
            raise ContractError("independent-reviewers")
        if identity.get("binary_built") is not True:
            raise ContractError("built-binary-required")
    elif evidence.get("status") == "accepted":
        raise ContractError("accepted-evidence-with-disabled-execution")

    non_claims = value.get("non_claims")
    if not isinstance(non_claims, dict):
        raise ContractError("non-claims")
    for key in (
        "g1_r5_exit",
        "validator_run_completed",
        "network_evidence_accepted",
        "production_candidate",
        "production_consensus_activation",
        "release_ready",
    ):
        require_false(non_claims.get(key), key)

    return {
        "schema": "trnm-g1-r5-campaign-validation-v2",
        "campaign_id": campaign_id,
        "validator_count": validator_count,
        "quorum_voting_power": expected_quorum,
        "scenario_count": len(scenario_ids),
        "topology_counts": expected_counts,
        "manifest_digest": digest(value),
        "campaign_execution_authorized": authorized,
        "outcome": "READY_TO_EXECUTE_CANDIDATE" if authorized else "BLOCKED_UPSTREAM",
        "production_candidate": False,
        "production_consensus_activation": False,
    }


def validate_result(manifest: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    validated = validate_manifest(manifest)
    if not validated["campaign_execution_authorized"]:
        raise ContractError("result-for-unauthorized-campaign")
    if result.get("schema") != "trnm-g1-r5-campaign-result-v2":
        raise ContractError("result-schema")
    if result.get("campaign_id") != manifest["campaign_id"]:
        raise ContractError("result-campaign")
    if result.get("manifest_digest") != validated["manifest_digest"]:
        raise ContractError("result-manifest-digest")
    if result.get("transport_only_smoke") is not False:
        raise ContractError("transport-smoke-is-not-validator-evidence")
    for key in ("conflicting_finality", "double_sign", "root_divergence"):
        if result.get(key) is not False:
            raise ContractError(key)
    reports = result.get("scenario_reports")
    expected_ids = {row["id"] for row in manifest["fault_schedule"]["scenarios"]}
    if (
        not isinstance(reports, list)
        or {row.get("id") for row in reports if isinstance(row, dict)} != expected_ids
    ):
        raise ContractError("result-scenario-coverage")
    if any(row.get("status") != "passed" for row in reports):
        raise ContractError("result-scenario-failure")
    signatures = result.get("review_signatures")
    if (
        not isinstance(signatures, list)
        or len(
            {
                row.get("reviewer_id")
                for row in signatures
                if isinstance(row, dict)
            }
        )
        < 2
    ):
        raise ContractError("result-independent-review")
    return {
        "schema": "trnm-g1-r5-campaign-result-validation-v2",
        "campaign_id": manifest["campaign_id"],
        "accepted_candidate_evidence": True,
        "production_candidate": False,
        "production_consensus_activation": False,
    }


def self_test(manifest: dict[str, Any]) -> dict[str, Any]:
    baseline = validate_manifest(manifest)
    mutations: list[dict[str, Any]] = []

    mutant = copy.deepcopy(manifest)
    mutant["topology"]["validators"][1]["host_id"] = mutant["topology"][
        "validators"
    ][0]["host_id"]
    mutations.append(mutant)
    mutant = copy.deepcopy(manifest)
    mutant["topology"]["validators"][0]["proof_of_possession"] = "f" * 64
    mutations.append(mutant)
    mutant = copy.deepcopy(manifest)
    mutant["topology"]["quorum_voting_power"] -= 1
    mutations.append(mutant)
    mutant = copy.deepcopy(manifest)
    mutant["identity"]["workload_sha256"] = "f" * 64
    mutations.append(mutant)
    mutant = copy.deepcopy(manifest)
    mutant["fault_schedule"]["scenarios"] = mutant["fault_schedule"][
        "scenarios"
    ][:-1]
    mutations.append(mutant)
    mutant = copy.deepcopy(manifest)
    mutant["topology"]["validators"][0]["region_id"] = ""
    mutations.append(mutant)
    mutant = copy.deepcopy(manifest)
    mutant["execution_gate"]["campaign_execution_authorized"] = True
    mutations.append(mutant)
    mutant = copy.deepcopy(manifest)
    mutant["non_claims"]["production_candidate"] = True
    mutations.append(mutant)

    rejected = 0
    for mutant in mutations:
        try:
            validate_manifest(mutant)
        except ContractError:
            rejected += 1
    if rejected != len(mutations):
        raise ContractError("retained-mutant-accepted")
    return {
        "schema": "trnm-g1-r5-campaign-self-test-v2",
        "baseline_outcome": baseline["outcome"],
        "retained_mutants": len(mutations),
        "retained_mutants_rejected": rejected,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--result", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    manifest = load(args.manifest)
    if args.result:
        output = validate_result(manifest, load(args.result))
    elif args.self_test:
        output = self_test(manifest)
    else:
        output = validate_manifest(manifest)
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
