#!/usr/bin/env python3
"""Closed-set contract checks used by the Plan v2 convergence entrypoint."""
from __future__ import annotations

import json
import pathlib
import tomllib
from typing import Any, Callable

CONTRACT = pathlib.Path("config/technical-convergence-v1.toml")
PARAMETERS = pathlib.Path("docs/protocol/poco-bft-v0/parameters.toml")
MACHINE_TRUTH = pathlib.Path("config/consensus-mainline.json")
EXPECTED_PARENT = "1d46ba8423c33a35b7923516959ce7734b442f86"
EXPECTED_INTEGRATION = "work/plan-v2-full-gap-closure-20260902"
EXPECTED_DELIVERY = "work/plan-v2-technical-convergence-20260906"
MVP = ("M00", "M01", "M02", "M03", "M04", "M05", "M06", "M07", "M08", "M13", "M15", "M17")
CANDIDATE = ("M09", "M10", "M11", "M12")
NON_AUTHORITY = ("M14", "M16")
DETAILED_SPECS = {
    "M04": "docs/modules/M04_P2P_TECHNICAL_SPEC_V1.md",
    "M05": "docs/modules/M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md",
    "M08": "docs/modules/M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md",
    "M14": "docs/modules/M14_CLIENT_PLATFORM_TECHNICAL_SPEC_V1.md",
    "M15": "docs/modules/M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md",
    "M16": "docs/modules/M16_CONTROL_PLANE_TECHNICAL_SPEC_V1.md",
    "M17": "docs/modules/M17_EVIDENCE_SECURITY_TECHNICAL_SPEC_V1.md",
}
RUNTIME_GAPS = {
    "P0-TRUTH-001", "P0-SCHEMA-001", "P0-PROTOCOL-001", "P0-TC-001",
    "P1-CORE-001", "P1-EXEC-001", "P2-NODE-001", "P2-TX-001",
    "P2-NET-001", "P2-OPS-001", "P2-STORE-001", "MIG-ROOT-001",
    "P3-HISTORY-001", "MIG-CLEAN-001",
}
EXTERNAL_GATES = {
    "EXT-REVIEW-001", "EXT-G1-CAMPAIGN-001", "EXT-ANCHOR-HSM-001",
    "EXT-POWERLOSS-001", "EXT-AUDIT-001", "EXT-SOAK-ACTIVATION-001",
}
HEADINGS = (
    "## Authority", "## Interfaces", "## State machine",
    "## Persistence and recovery", "## Resource bounds", "## Security",
    "## Observability and SLO", "## Verification and evidence",
    "## Activation boundary",
)


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def load_toml(root: pathlib.Path, relative: pathlib.Path) -> dict[str, Any]:
    try:
        with (root / relative).open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ContractError(f"{relative}: {error}") from error
    require(isinstance(value, dict), f"{relative}: table required")
    return value


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON member: {key}")
        value[key] = item
    return value


def load_json(root: pathlib.Path, relative: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads((root / relative).read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"{relative}: {error}") from error
    require(isinstance(value, dict), f"{relative}: object required")
    return value


def false_claims(value: dict[str, Any], keys: tuple[str, ...], label: str, required: bool = True) -> None:
    for key in keys:
        if required:
            require(key in value, f"{label} missing {key}")
        if key in value:
            require(value[key] is False, f"{label} promoted {key}")


def validate(root: pathlib.Path) -> tuple[dict[str, Any], dict[str, Any]]:
    contract = load_toml(root, CONTRACT)
    parameters = load_toml(root, PARAMETERS)
    truth = load_json(root, MACHINE_TRUTH)
    require(contract.get("schema_version") == 1, "contract schema drift")
    require(contract.get("contract_id") == "trnm-technical-convergence-v1", "contract id drift")
    require(contract.get("plan_id") == "trnm-chain-development-plan-v2", "plan id drift")
    require(contract.get("as_of") == "2026-09-06", "contract date drift")
    require(contract.get("parent_integration_head") == EXPECTED_PARENT, "parent integration head drift")
    require(contract.get("integration_branch") == EXPECTED_INTEGRATION, "integration branch drift")
    require(contract.get("delivery_branch") == EXPECTED_DELIVERY, "delivery branch drift")
    false_claims(contract, ("production_authority", "production_candidate", "production_consensus_activation", "public_testnet_ready", "release_ready", "all_gaps_closed"), "contract")

    scope = contract.get("scope")
    require(isinstance(scope, dict), "scope missing")
    require(scope == {
        "objective": "converge the smallest auditable native PoCO-BFT node before activating AI-market extensions",
        "single_integration_successor": True,
        "large_models_and_nondeterministic_inference_off_chain": True,
        "repository_documentation_gap_closed_by_this_contract": True,
        "repository_runtime_gap_closed": False,
        "external_evidence_gap_closed": False,
    }, "scope drift")

    partition = contract.get("module_partition")
    require(isinstance(partition, dict), "module partition missing")
    require(tuple(partition.get("mvp", ())) == MVP, "MVP partition drift")
    require(tuple(partition.get("candidate_application", ())) == CANDIDATE, "candidate partition drift")
    require(tuple(partition.get("non_authoritative_service", ())) == NON_AUTHORITY, "service partition drift")
    modules = (*MVP, *CANDIDATE, *NON_AUTHORITY)
    require(len(modules) == len(set(modules)) == 18, "module partition duplicate or incomplete")

    consensus = contract.get("consensus")
    require(consensus == {
        "engine": "native-poco-bft", "engine_status": "candidate-only",
        "poco_weight_phase": "shadow", "poco_weight_affects_membership": False,
        "poco_weight_affects_quorum": False, "poco_weight_affects_leader_selection": False,
        "reference_engine_role": "differential-oracle-only",
        "reference_engine_production_dependency": False,
        "aggregate_signature_decision": "deferred-until-benchmark-and-security-review",
        "leader_policy_decision": "round-robin-v0-requires-sybil-and-liveness-review",
    }, "consensus decisions drift")
    require(parameters.get("production_activation") is False, "parameter profile activated")
    require(parameters.get("rollout", {}).get("current_phase") == "shadow", "parameter phase left shadow")
    false_claims(truth, ("production_candidate", "production_consensus_activation"), "machine truth")
    false_claims(truth, ("public_testnet_ready", "release_ready", "all_gaps_closed"), "machine truth", required=False)
    require(truth.get("stage") == "G1-native-host-incomplete", "machine stage drift")

    specs = contract.get("detailed_spec")
    require(isinstance(specs, list), "detailed specs missing")
    found: dict[str, str] = {}
    for row in specs:
        require(isinstance(row, dict), "detailed spec row invalid")
        module_id, relative = row.get("id"), row.get("path")
        require(row.get("status") == "implementation-contract", f"{module_id}: status drift")
        require(isinstance(module_id, str) and isinstance(relative, str), "detailed spec identity missing")
        require(module_id not in found, f"{module_id}: duplicate detailed spec")
        found[module_id] = relative
        path = root / relative
        require(path.is_file(), f"{module_id}: spec missing")
        text = path.read_text(encoding="utf-8")
        require(len(text.encode()) >= 2500 and text.startswith(f"# {module_id} "), f"{module_id}: shallow/title mismatch")
        for heading in HEADINGS:
            require(heading in text, f"{module_id}: missing {heading}")
    require(found == DETAILED_SPECS, "detailed specification map drift")

    runtime = contract.get("runtime_gaps")
    require(isinstance(runtime, dict) and runtime.get("status") == "open-until-exact-source-evidence", "runtime status drift")
    ids = runtime.get("ids")
    require(isinstance(ids, list) and len(ids) == len(set(ids)), "runtime IDs invalid")
    require(set(ids) == RUNTIME_GAPS, "runtime gap set drift")
    blockers = truth.get("blockers")
    require(isinstance(blockers, list), "machine blocker rows missing")
    truth_ids = {row.get("id") for row in blockers if isinstance(row, dict)}
    require(truth_ids == RUNTIME_GAPS == set(ids), "machine/convergence blocker mismatch")

    gates = contract.get("external_gate")
    require(isinstance(gates, list), "external gates missing")
    require({row.get("id") for row in gates if isinstance(row, dict)} == EXTERNAL_GATES, "external gate set drift")
    for row in gates:
        require(isinstance(row, dict), "external gate row invalid")
        require(row.get("status") == "open-external" and row.get("self_attestation_allowed") is False, f"{row.get('id')}: external gate fabricated")
    return contract, {
        "modules": 18, "detailed_specs": len(found), "runtime_gaps": len(ids),
        "external_gates": len(gates), "poco_weight_phase": "shadow",
    }
