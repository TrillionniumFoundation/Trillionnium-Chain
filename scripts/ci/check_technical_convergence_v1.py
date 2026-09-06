#!/usr/bin/env python3
"""Fail-closed validation for the Plan v2 technical-convergence contract."""

from __future__ import annotations

import json
import pathlib
import sys
import tomllib
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTRACT = pathlib.Path("config/technical-convergence-v1.toml")
PARAMETERS = pathlib.Path("docs/protocol/poco-bft-v0/parameters.toml")
MACHINE_TRUTH = pathlib.Path("config/consensus-mainline.json")

EXPECTED_MODULES = {f"M{index:02d}" for index in range(18)}
DETAILED_MODULES = {"M04", "M05", "M08", "M14", "M15", "M16", "M17"}
EXTERNAL_GATES = {
    "EXT-REVIEW-001",
    "EXT-G1-CAMPAIGN-001",
    "EXT-ANCHOR-HSM-001",
    "EXT-POWERLOSS-001",
    "EXT-AUDIT-001",
    "EXT-SOAK-ACTIVATION-001",
}
REQUIRED_HEADINGS = (
    "## Authority",
    "## Interfaces",
    "## State machine",
    "## Persistence and recovery",
    "## Resource bounds",
    "## Security",
    "## Observability and SLO",
    "## Verification and evidence",
    "## Activation boundary",
)
FALSE_CLAIMS = (
    "production_authority",
    "production_candidate",
    "production_consensus_activation",
    "public_testnet_ready",
    "release_ready",
    "all_gaps_closed",
)


class ConvergenceError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ConvergenceError(message)


def load_toml(root: pathlib.Path, relative: pathlib.Path) -> dict[str, Any]:
    try:
        with (root / relative).open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConvergenceError(f"{relative}: {error}") from error
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
        value = json.loads(
            (root / relative).read_text(encoding="utf-8"),
            object_pairs_hook=strict_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ConvergenceError(f"{relative}: {error}") from error
    require(isinstance(value, dict), f"{relative}: object required")
    return value


def validate(root: pathlib.Path = ROOT) -> dict[str, Any]:
    contract = load_toml(root, CONTRACT)
    parameters = load_toml(root, PARAMETERS)
    truth = load_json(root, MACHINE_TRUTH)

    require(contract.get("schema_version") == 1, "contract schema drift")
    require(
        contract.get("contract_id") == "trnm-technical-convergence-v1",
        "contract id drift",
    )
    require(
        contract.get("plan_id") == "trnm-chain-development-plan-v2",
        "plan id drift",
    )
    for claim in FALSE_CLAIMS:
        require(contract.get(claim) is False, f"contract promoted {claim}")

    scope = contract.get("scope")
    require(isinstance(scope, dict), "scope missing")
    require(scope.get("single_integration_successor") is True, "multiple successors allowed")
    require(
        scope.get("repository_documentation_gap_closed_by_this_contract") is True,
        "documentation closure is not declared",
    )
    require(scope.get("repository_runtime_gap_closed") is False, "runtime closure fabricated")
    require(scope.get("external_evidence_gap_closed") is False, "external closure fabricated")

    partition = contract.get("module_partition")
    require(isinstance(partition, dict), "module partition missing")
    ordered: list[str] = []
    for key in ("mvp", "candidate_application", "non_authoritative_service"):
        value = partition.get(key)
        require(
            isinstance(value, list) and all(isinstance(item, str) for item in value),
            f"invalid module partition {key}",
        )
        ordered.extend(value)
    require(len(ordered) == len(set(ordered)), "module partition contains duplicates")
    require(set(ordered) == EXPECTED_MODULES, "module partition does not cover M00-M17")
    require(
        set(partition["candidate_application"]) == {"M09", "M10", "M11", "M12"},
        "AI application modules escaped candidate partition",
    )
    require(
        set(partition["non_authoritative_service"]) == {"M14", "M16"},
        "non-authoritative service partition drift",
    )

    consensus = contract.get("consensus")
    require(isinstance(consensus, dict), "consensus convergence table missing")
    require(consensus.get("engine_status") == "candidate-only", "engine promoted")
    require(consensus.get("poco_weight_phase") == "shadow", "PoCO phase left shadow")
    for key in (
        "poco_weight_affects_membership",
        "poco_weight_affects_quorum",
        "poco_weight_affects_leader_selection",
        "reference_engine_production_dependency",
    ):
        require(consensus.get(key) is False, f"unsafe consensus switch: {key}")
    require(parameters.get("production_activation") is False, "parameter profile activated")
    require(
        parameters.get("rollout", {}).get("current_phase") == "shadow",
        "protocol parameter phase is not shadow",
    )

    for claim in (
        "production_candidate",
        "production_consensus_activation",
        "public_testnet_ready",
        "release_ready",
        "all_gaps_closed",
    ):
        require(truth.get(claim) is False, f"machine truth promoted {claim}")
    require(truth.get("stage") == "G1-native-host-incomplete", "machine stage drift")

    ci = contract.get("ci")
    require(isinstance(ci, dict), "CI contract missing")
    for key in (
        "exact_head_required",
        "prospective_merge_required",
        "non_empty_execution_required",
        "terminal_success_required",
        "candidate_code_with_repository_write_token_forbidden",
        "persistent_runner_with_candidate_write_token_forbidden",
        "independent_final_push_review_required",
    ):
        require(ci.get(key) is True, f"CI safeguard disabled: {key}")
    require(ci.get("skipped_or_action_required_is_success") is False, "empty CI credited")

    supply = contract.get("supply_chain")
    require(isinstance(supply, dict), "supply-chain policy missing")
    require(supply.get("publisher_executes_candidate_code") is False, "publisher executes candidate")
    for relative in supply.get("prohibited_candidate_workflows", []):
        require(isinstance(relative, str) and relative, "invalid prohibited workflow")
        require(not (root / relative).exists(), f"prohibited workflow present: {relative}")

    specs = contract.get("detailed_spec")
    require(isinstance(specs, list), "detailed specs missing")
    require({row.get("id") for row in specs if isinstance(row, dict)} == DETAILED_MODULES,
            "detailed module set drift")
    for row in specs:
        require(isinstance(row, dict), "detailed spec row must be a table")
        module_id = row.get("id")
        relative = row.get("path")
        require(isinstance(relative, str) and relative, f"{module_id}: spec path missing")
        path = root / relative
        require(path.is_file(), f"{module_id}: spec missing: {relative}")
        text = path.read_text(encoding="utf-8")
        require(len(text.encode("utf-8")) >= 2500, f"{module_id}: spec too shallow")
        require(text.startswith(f"# {module_id} "), f"{module_id}: title mismatch")
        for heading in REQUIRED_HEADINGS:
            require(heading in text, f"{module_id}: missing heading {heading}")

    runtime = contract.get("runtime_gaps")
    require(isinstance(runtime, dict), "runtime gap register missing")
    require(runtime.get("status") == "open-until-exact-source-evidence",
            "runtime gaps improperly closed")
    runtime_ids = runtime.get("ids")
    require(isinstance(runtime_ids, list) and len(runtime_ids) >= 10,
            "runtime gap register is incomplete")
    require(len(runtime_ids) == len(set(runtime_ids)), "duplicate runtime gap id")

    gates = contract.get("external_gate")
    require(isinstance(gates, list), "external gates missing")
    require({row.get("id") for row in gates if isinstance(row, dict)} == EXTERNAL_GATES,
            "external gate set drift")
    for row in gates:
        require(row.get("status") == "open-external", f"{row.get('id')}: external gate fabricated")
        require(row.get("self_attestation_allowed") is False,
                f"{row.get('id')}: self-attestation enabled")

    return {
        "schema": "trnm-technical-convergence-check-v1",
        "modules": len(ordered),
        "detailed_specs": len(specs),
        "runtime_gaps": len(runtime_ids),
        "external_gates": len(gates),
        "poco_weight_phase": "shadow",
        "production_candidate": False,
        "result": "PASS",
    }


def main() -> int:
    print(json.dumps(validate(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ConvergenceError, OSError, UnicodeError) as error:
        print(f"technical convergence validation failed: {error}", file=sys.stderr)
        raise SystemExit(2)
