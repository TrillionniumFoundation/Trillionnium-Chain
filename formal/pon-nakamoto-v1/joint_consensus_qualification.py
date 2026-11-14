#!/usr/bin/env python3
"""Read the joint difficulty/time/credit research qualification contract.

This is a source-consistency and claim-boundary checker. PASS means that the
reviewed *listed* source files, development parameters, unproved cost contract,
and open obligations agree. It is not a network model, proof checker, native
execution receipt, source/build closure, or production authorization interface.
V1 has no route from caller-supplied claims to a native failure probability.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
from pq_source_reader import SourceReadError, read_regular
from fixed_probability_contract import ContractError, audit_contract


SCHEMA = "trnm-joint-consensus-qualification-v1"
MANIFEST = "config/pon/joint-consensus-qualification-v1.json"
COST_CONTRACT = "formal/pon-nakamoto-v1/fixed_probability_contract_v1.json"
DEVNET = "config/pon/devnet-v1.json"
MAX_JSON_BYTES = 262144
MAX_SOURCE_BYTES = 2097152
REVIEWED_NATIVE_COMMIT = "2d9baf313e54e49a4507c5057578e89ddbe7a1b6"
# Independently anchored in the checker, after comparing all 23 source files to
# the named Git commit. Editing source bytes and their JSON hashes alone cannot
# preserve a claim about that reviewed source. A new anchor needs code review.
REVIEWED_SOURCE_MAP_SHA256 = "5fd6aea2f2d1a6a3831853f54c8cc6e83cc8233cc61ab97a01a8e482749be674"

# Deliberately a named scope, not a claim to cover every dependency or entrypoint.
# Omission/addition requires code review; no CLI automatically repins a source.
SOURCE_PATHS = (
    "PROJECT_BOUNDARY.json",
    "config/consensus-mainline.json",
    "config/pon-nakamoto-v1.json",
    DEVNET,
    "config/pon/work-profile-v1.json",
    "trillionnium/Cargo.lock",
    "trillionnium/crates/trnm-pon-node/Cargo.toml",
    "trillionnium/crates/trnm-pon-node/src/lib.rs",
    "trillionnium/crates/trnm-pon-node/src/consensus.rs",
    "trillionnium/crates/trnm-pon-node/src/store.rs",
    "trillionnium/crates/trnm-pon-node/src/store/growth.rs",
    "trillionnium/crates/trnm-pon-node/src/store/growth/confirmation.rs",
    "trillionnium/crates/trnm-pon-node/src/store/growth/recovery.rs",
    "trillionnium/crates/trnm-pon-node/src/store/growth/profile.rs",
    "trillionnium/crates/trnm-pon-node/src/store/growth/work_checked.rs",
    "trillionnium/crates/trnm-protocol/src/pon_wire.rs",
    "trillionnium/crates/trnm-protocol/src/pon_growth.rs",
    "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
    "formal/pon-nakamoto-v1/mandatory_units_relation.py",
    "formal/pon-nakamoto-v1/work_oracle.py",
    "formal/pon-nakamoto-v1/contract_wire.py",
    "formal/pon-nakamoto-v1/fixed_probability_contract.py",
    COST_CONTRACT,
)

PARAMETERS = {
    "work_profile": "pon-matmul-transcript-64-v1",
    "initial_target_hex": "7" + "f" * 63,
    "pow_limit_hex": "7" + "f" * 63,
    "target_spacing_seconds": 10,
    "retarget_interval": 16,
    "median_time_width": 11,
    "retarget_factor": 4,
    "future_skew_seconds": 120,
    "confirmation_depth": 6,
    "confirmation_work_multiplier": 6,
    "production_activation": False,
}

NATIVE_SEMANTICS = {
    "owner_profiles": ["PNH1/PNP1", "PGH2/PNP2"],
    "credit_formula": "floor(2^256/(T+1))",
    "target_zero_valid": False,
    "chainwork_accumulator_bits": 512,
    "target_history": "selected-parent-validated-ancestry",
    "retarget_inputs": "ancestor-endpoints-with-inclusive-integer-credit",
    "timestamp_rule": "strict-upper-MTP11-and-observed-clock-upper-bound",
    "header_time_certifies_elapsed_work": False,
    "fork_choice": "strictly-greater-fully-validated-cumulative-required-work",
    "equal_work_replaces_current_tip": False,
    "confirmation_policy": "installed-depth-and-required-work",
    "confirmation_depth_counts": "successors-excluding-inclusion-block",
    "confirmation_work_counts": "tip-chainwork-minus-inclusion-chainwork",
    "confirmation_work_threshold_basis": "included-block-required-work",
    "confirmation_requires_both_thresholds": True,
    "finalized": False,
    "execution_authority": False,
}

# The unknowns describe a single joint environment, not independently chosen
# favorable assumptions for each property. Null is not zero, independence, a
# trusted clock, a positive honest-rate floor, or an empty initial inventory.
UNKNOWN_PARAMETERS = {
    "resources": (
        "physical_resource_unit_and_scalarization",
        "all_algorithm_classical_cost_lower_envelope",
        "all_algorithm_quantum_cost_lower_envelope",
        "joint_initial_help_preprocessing_and_residual_state_bound",
        "cross_fork_batch_cache_and_unpublished_work_composition",
    ),
    "participation": (
        "qualified_honest_production_lower_tail",
        "adversarial_complete_credit_upper_tail",
        "variation_window_and_churn_bound",
        "bootstrap_currentness_and_entry_debt_bound",
    ),
    "delivery": (
        "complete_validated_eligible_delivery_delay",
        "availability_queue_verification_and_state_service_capacity",
        "stale_parent_and_retention_bounds",
    ),
    "clocks": (
        "wall_clock_skew_and_drift_bound",
        "wall_to_monotonic_to_model_clock_mapping",
        "activation_confirmation_and_recovery_clock_coverage",
    ),
    "lifetime": (
        "analysis_horizon_and_adaptive_start_budget",
        "initial_private_inventory_bound",
        "joint_bad_environment_and_cryptographic_failure_budget",
    ),
}

PROPERTIES = {
    "common_prefix": {
        "metric": "prefix-retention-for-qualified-honest-views",
        "scope": "adaptive-confirmations-across-nodes-epochs-and-restarts",
        "native_reduction_proved": False,
        "failure_bound": None,
    },
    "chain_growth": {
        "metric": "fully-validated-eligible-required-credit-per-model-time",
        "scope": "declared-qualified-participation-windows",
        "native_reduction_proved": False,
        "minimum_rate": None,
        "failure_bound": None,
    },
    "chain_quality": {
        "metric": "honest-required-credit-fraction-in-stable-segments",
        "scope": "declared-minimum-stable-segment-size",
        "native_reduction_proved": False,
        "minimum_honest_fraction": None,
        "failure_bound": None,
    },
    "block_count_quality": {
        "metric": "honest-block-count-fraction",
        "derived_from_credit_quality": False,
        "failure_bound": None,
    },
    "business_liveness": {
        "metric": "eligible-honest-transaction-inclusion-and-service",
        "derived_from_chain_growth": False,
        "failure_bound": None,
    },
}

# Exact roster: removing an open premise cannot turn a partial model into a
# joint certificate. Existing conditional components are linked, not promoted.
OBLIGATIONS = {
    "native-to-model": (
        "formal/pon-nakamoto-v1/NATIVE_FORK_MAPPING_V1.md",
        "Map both native owners, complete validity, target, clocks, selection and recovery to one model.",
    ),
    "all-legal-resource-cost": (
        "docs/protocol/pon-nakamoto-v1/details/FIXED_PROBABILITY_COST_CONTRACT_V1.md",
        "Cover every legal strategy and all setup, reuse, failed, cancelled and unpublished work.",
    ),
    "joint-initial-state": (
        "formal/pon-nakamoto-v1/STATEFUL_RESOURCE_TAIL_V1.md",
        "Bound correlated classical/quantum help and residual state without epoch or restart resets.",
    ),
    "time-target-credit": (
        "docs/protocol/pon-nakamoto-v1/details/JOINT_CONSENSUS_DAA_AUDIT_20261108.md",
        "Prove the joint process for parent-derived targets, native time eligibility and accumulated credit.",
    ),
    "mixed-resource-calibration": (
        "formal/pon-nakamoto-v1/CREDIT_ENVELOPE_CONTRACT_V1.md",
        "Justify the resource envelopes used for public credit; no universal square-root substitution.",
    ),
    "dynamic-participation": (
        "docs/protocol/pon-nakamoto-v1/details/DYNAMIC_PARTICIPATION_V1.md",
        "Authenticate bootstrap and qualified participation, retain entry debt and departure obligations.",
    ),
    "complete-delivery": (
        "formal/pon-nakamoto-v1/NATIVE_FORK_MAPPING_V1.md",
        "Bound data availability, transport, queues, full verification, state readiness and eligible delivery.",
    ),
    "honest-progress-tail": (
        "formal/pon-nakamoto-v1/WORK_SCALE_SECURITY_CONTRACT_V1.md",
        "Prove a lower tail for effective qualified honest progress under the same environment.",
    ),
    "adversarial-credit-tail": (
        "formal/pon-nakamoto-v1/STATEFUL_RESOURCE_TAIL_V1.md",
        "Prove a complete adaptive all-branch credit upper tail in the declared resource model.",
    ),
    "common-prefix": (
        "formal/pon-nakamoto-v1/NATIVE_FORK_MAPPING_V1.md",
        "Connect native cross-node prefix failure, initial inventory and all chosen confirmation starts to a tail event.",
    ),
    "chain-growth": (
        "formal/pon-nakamoto-v1/WORK_SCALE_SECURITY_CONTRACT_V1.md",
        "Connect qualified progress to native eligible chain growth with explicit outage and delay deficits.",
    ),
    "chain-quality": (
        "formal/pon-nakamoto-v1/WORK_SCALE_SECURITY_CONTRACT_V1.md",
        "Prove stable-segment honest credit share; count share and business inclusion need separate reductions.",
    ),
    "lifetime-composition": (
        "formal/pon-nakamoto-v1/NATIVE_RISK_LEDGER_V1.md",
        "Cover adaptive starts, selection, reorg/restart, environment and cryptographic failures without refilling risk.",
    ),
}


class QualificationError(ValueError):
    """The contract is missing, ambiguous, changed, or claims an unproved fact."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise QualificationError(code)


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False,
                      ensure_ascii=False)


def same(value: object, expected: object, code: str) -> None:
    # bool/int equality must not accept true in place of 1 or vice versa.
    require(canonical(value) == canonical(expected), code)


def fields(value: object, names: set[str], code: str) -> None:
    require(type(value) is dict and set(value) == names, code)


def strict_json(raw: bytes) -> dict:
    require(type(raw) is bytes and len(raw) <= MAX_JSON_BYTES, "JSON_SIZE")

    def unique(pairs):
        out = {}
        for key, item in pairs:
            require(key not in out, "DUPLICATE_JSON_KEY")
            out[key] = item
        return out

    def integer(text):
        require(len(text) <= 20, "JSON_INTEGER_SIZE")
        return int(text)

    def no_number(_text):
        raise QualificationError("NONINTEGER_OR_NONFINITE_JSON")

    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                          parse_int=integer, parse_float=no_number,
                          parse_constant=no_number)
        canonical(data).encode("utf-8")
    except (UnicodeError, ValueError, RecursionError) as error:
        if isinstance(error, QualificationError):
            raise
        raise QualificationError("INVALID_JSON") from error
    require(type(data) is dict, "JSON_OBJECT")
    return data


def read_source(root: Path, path: str, ceiling: int = MAX_SOURCE_BYTES) -> bytes:
    try:
        return read_regular(root, path, ceiling)
    except SourceReadError as error:
        raise QualificationError(str(error)) from error


def check_development_claims(blobs: dict[str, bytes]) -> None:
    """Check actual source flags as well as the reviewed-file anchor."""
    main = strict_json(blobs["config/consensus-mainline.json"])
    boundary = strict_json(blobs["PROJECT_BOUNDARY.json"])
    protocol = strict_json(blobs["config/pon-nakamoto-v1.json"])
    profile = strict_json(blobs["config/pon/work-profile-v1.json"])
    for value, names in (
        (main, ("runtime_implemented", "work_profile_qualified", "production_candidate",
                "production_consensus_activation", "public_testnet_ready", "release_ready")),
        (boundary.get("consensus"), ("production_candidate", "production_consensus_activation")),
        (protocol, ("production_candidate", "production_consensus_activation",
                    "public_testnet_ready", "release_ready")),
        (protocol.get("implementation"), ("work_profile_qualified", "independent_security_accepted")),
        (protocol.get("work_profile"), ("cost_hardness_accepted",)),
        (profile, ("production_eligible",)),
    ):
        require(type(value) is dict, "ACTUAL_SECURITY_CONFIG")
        for key in names:
            require(value.get(key) is False, "ACTUAL_UNSUPPORTED_PROMOTION:" + key)
    require(main.get("active_consensus_implementation") is None
            and boundary["consensus"].get("active_implementation") is None,
            "ACTUAL_ACTIVE_IMPLEMENTATION")


def inspect(root: Path = ROOT) -> dict:
    """Check the current listed source and return an explicitly unqualified report.

    Hashes identify the bytes that were read. They do not authenticate an owner,
    prove the semantic summary, freeze concurrent writers, or identify a binary.
    Source mutation and unsupported claim promotion are errors, not HOLD passes.
    """
    root = Path(root).absolute()
    try:
        require(root.resolve(strict=True) == root and root.is_dir(), "ROOT_ALIAS")
    except (OSError, RuntimeError) as error:
        raise QualificationError("ROOT_UNAVAILABLE") from error
    raw = read_source(root, MANIFEST, MAX_JSON_BYTES)
    data = strict_json(raw)
    fields(data, {"schema", "qualification", "reviewed_native_source_commit",
                  "source_binding_scope", "source_sha256", "parameters",
                  "native_semantics", "unknown_parameters", "properties",
                  "obligations", "security_probability_calibrated",
                  "actual_lifetime_failure_bound", "production_activation"},
           "CONTRACT_FIELDS")
    same(data["schema"], SCHEMA, "CONTRACT_SCHEMA")
    same(data["qualification"], "HOLD_NO_GO", "UNSUPPORTED_QUALIFICATION")
    same(data["reviewed_native_source_commit"], REVIEWED_NATIVE_COMMIT, "REVIEWED_SOURCE")
    same(data["source_binding_scope"], "listed-files-only-not-build-or-runtime-closure", "SOURCE_SCOPE")
    for key in ("security_probability_calibrated", "production_activation"):
        require(data[key] is False, "UNSUPPORTED_PROMOTION:" + key)
    require(data["actual_lifetime_failure_bound"] is None, "UNPROVED_LIFETIME_BOUND")

    pins = data["source_sha256"]
    fields(pins, set(SOURCE_PATHS), "SOURCE_ROSTER")
    for path in SOURCE_PATHS:
        require(type(pins[path]) is str and re.fullmatch(r"[0-9a-f]{64}", pins[path]) is not None,
                "SOURCE_DIGEST_FORMAT:" + path)
    require(hashlib.sha256(canonical(pins).encode("utf-8")).hexdigest()
            == REVIEWED_SOURCE_MAP_SHA256, "REVIEWED_SOURCE_MAP")
    observed = {}
    blobs = {}
    for path in SOURCE_PATHS:
        blobs[path] = read_source(root, path)
        observed[path] = hashlib.sha256(blobs[path]).hexdigest()
        require(observed[path] == pins[path], "SOURCE_DIGEST_MISMATCH:" + path)

    same(data["parameters"], PARAMETERS, "PARAMETER_CONTRACT")
    dev = strict_json(blobs[DEVNET])
    same({key: dev.get(key) for key in PARAMETERS}, PARAMETERS, "ACTUAL_PARAMETERS")
    check_development_claims(blobs)
    same(data["native_semantics"], NATIVE_SEMANTICS, "NATIVE_SEMANTICS")
    unknown = {group: {name: None for name in names}
               for group, names in UNKNOWN_PARAMETERS.items()}
    same(data["unknown_parameters"], unknown, "UNPROVED_ENVIRONMENT_PARAMETER")
    same(data["properties"], PROPERTIES, "UNPROVED_PROPERTY_OR_METRIC_CHANGE")

    obligations = data["obligations"]
    fields(obligations, set(OBLIGATIONS), "OBLIGATION_ROSTER")
    for key, (path, statement) in OBLIGATIONS.items():
        same(obligations[key], {"status": "open", "contract": path, "required": statement},
             "UNPROVED_OBLIGATION:" + key)
        # Contract presence does not upgrade its mathematical or native status.
        read_source(root, path)

    # Reuse the original MU1 audit. Its target 1/16 and credit 16u belong to an
    # unactivated research relation, not the installed variable-target W1 chain.
    try:
        cost = audit_contract(strict_json(blobs[COST_CONTRACT]), root=root)
    except (ContractError, OSError) as error:
        raise QualificationError("COST_CONTRACT:" + str(error)) from error
    require(cost["qualification"] == "HOLD_NO_GO" and len(cost["unknown_cost_points"]) == 16,
            "COST_SCOPE")
    # Check again after the composition reader; no claim of an atomic snapshot
    # against a same-UID/privileged writer between these bounded reads is made.
    for path in SOURCE_PATHS:
        require(hashlib.sha256(read_source(root, path)).hexdigest() == observed[path],
                "SOURCE_CHANGED_DURING_INSPECTION:" + path)
    require(read_source(root, MANIFEST, MAX_JSON_BYTES) == raw, "CONTRACT_CHANGED_DURING_INSPECTION")

    return {
        "schema": "trnm-joint-consensus-qualification-report-v1",
        "contract_validation": "PASS",
        "qualification": "HOLD_NO_GO",
        "contract_sha256": hashlib.sha256(raw).hexdigest(),
        "reviewed_native_source_commit": REVIEWED_NATIVE_COMMIT,
        "reviewed_source_map_sha256": REVIEWED_SOURCE_MAP_SHA256,
        "source_binding_scope": data["source_binding_scope"],
        "source_sha256": observed,
        "source_files_checked": len(observed),
        "native_execution_performed": False,
        "native_semantics_formally_verified": False,
        "current_repository_ancestry_verified": False,
        "full_build_closure_verified": False,
        "parameters": dict(PARAMETERS),
        "native_semantics": dict(NATIVE_SEMANTICS),
        "unknown_parameter_count": sum(len(names) for names in UNKNOWN_PARAMETERS.values()),
        "unknown_parameters": unknown,
        "open_obligations": sorted(OBLIGATIONS),
        "properties": data["properties"],
        "fixed_probability_research_contract": {
            "profile": cost["relation_profile"],
            "qualification": cost["qualification"],
            "unknown_cost_points": cost["unknown_cost_points"],
            "native_variable_target_cost_bound": False,
        },
        "security_probability_calibrated": False,
        "actual_lifetime_failure_bound": None,
        "common_prefix_failure_bound": None,
        "chain_growth_failure_bound": None,
        "chain_quality_failure_bound": None,
        "six_confirmations_failure_bound": None,
        "production_activation": False,
        "finalized": False,
        "execution_authority": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true", help="check research contract consistency only")
    action.add_argument("--require-qualified", action="store_true", help="V1 must refuse qualification")
    args = parser.parse_args(argv)
    try:
        result = inspect(args.root)
    except (QualificationError, OSError) as error:
        print(json.dumps({"contract_validation": "FAIL", "qualification": "HOLD_NO_GO",
                          "error": str(error), "production_activation": False}, sort_keys=True))
        return 2
    if args.require_qualified:
        result["qualification_request"] = "REFUSED_UNPROVED_JOINT_CONSENSUS"
    print(json.dumps(result, indent=2, sort_keys=True))
    return 3 if args.require_qualified else 0


if __name__ == "__main__":
    raise SystemExit(main())
