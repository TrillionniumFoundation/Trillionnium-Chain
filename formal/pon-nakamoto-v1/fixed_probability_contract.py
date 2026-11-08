"""Bind the fixed-p cost audit to the real, unactivated MU1 relation.

This is a research contract reader, not a consensus authorization interface.
In particular, a source digest, a benchmark and a finite cost model are not
an all-algorithm lower bound. Unknown lower bounds remain unknown.
"""
from __future__ import annotations

import argparse
from dataclasses import fields
from fractions import Fraction
import hashlib
import json
from math import gcd
from pathlib import Path

import mandatory_units_relation as mu


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = Path(__file__).with_name("fixed_probability_contract_v1.json")
SCHEMA = "pon-fixed-probability-cost-contract-v1"
SOURCE_PATHS = (
    "formal/pon-nakamoto-v1/mandatory_units_relation.py",
    "formal/pon-nakamoto-v1/work_oracle.py",
    "formal/pon-nakamoto-v1/contract_wire.py",
    "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
)
STRATEGIES = (
    "batching", "shared-base-and-low-rank-work", "cached-products",
    "precomputation-and-nonce-banks", "adaptive-cross-scale-selection",
    "shared-work-across-scales", "all-legal-task-and-parameter-choices",
    "public-help-and-outsourced-work", "failed-abandoned-unpublished-attempts",
    "all-competing-forks", "restart-and-profile-transition-state",
    "proof-and-encoding-grinding", "false-root-first-search",
    "quantum-restricted-subsets", "quantum-state-preparation-and-uncomputation",
    "quantum-variable-time-and-parallel-search", "retained-quantum-state",
)
OBLIGATIONS = (
    "complete-legal-strategy-simulation",
    "classical-amortized-cost-lower-bound",
    "quantum-amortized-cost-lower-bound",
    "bounded-initial-classical-and-quantum-potential",
    "cross-scale-and-cross-fork-composition",
    "actual-hash-to-search-model-reduction",
    "resource-to-physical-time-and-network-model",
    "mixed-miner-common-prefix-chain-quality-chain-growth",
    "native-work-identity-and-weight-bridge",
    "real-cell-quality-and-owner-adoption",
)


class ContractError(ValueError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ContractError(code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def reject_number(_value):
    raise ContractError("NONINTEGER_JSON_NUMBER")


def load_contract(path: Path) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(65537)
    require(len(raw) <= 65536, "CONTRACT_TOO_LARGE")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_float=reject_number, parse_constant=reject_number)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ContractError("CONTRACT_JSON") from error
    require(type(value) is dict, "CONTRACT_OBJECT")
    return value


def exact_fraction(value, name: str, *, positive: bool = True) -> Fraction:
    require(type(value) is dict and set(value) == {"numerator", "denominator"}, name)
    n, d = value["numerator"], value["denominator"]
    require(type(n) is int and type(d) is int and d > 0, name)
    require(n >= int(positive) and gcd(n, d) == 1, name)
    return Fraction(n, d)


def ratio(value: Fraction) -> dict[str, int]:
    return {"numerator": value.numerator, "denominator": value.denominator}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected_relation() -> dict:
    return {
        "profile": mu.PROFILE.decode("ascii"),
        "parameter_digest_hex": mu.RELATION_PARAMETERS.hex(),
        "target_hex": mu.T0.hex(),
        "inclusive_target": True,
        "ideal_probability": ratio(mu.IDEAL_TICKET_PROBABILITY),
        "probability_assumption": "independent-uniform-terminal-oracle",
        "implemented_hash": "SHA-256",
        "minimum_units": mu.U_MIN,
        "maximum_units": mu.U_MAX,
        "research_credit_per_unit": mu.BASE_CREDIT,
        "context_fields": [field.name for field in fields(mu.Context)],
        "native_consensus_credit": False,
    }


ACCOUNTING = {
    "success_standard": "at-least-one-valid-distinct-result-with-probability-at-least-one-half",
    "all_attempt_costs_counted": True,
    "setup_charged_once": True,
    "public-model-training-charged-to-each-miner": False,
    "initial_potential_bound": None,
    "epoch_restart_or_profile_resets_account": False,
    "already_credited_identity_in_potential": False,
    "post_win_proof_is_per_grover_query_cost": False,
    "resource_model": "not-yet-certified-for-all-legal-algorithms",
    "single_scale_bound_implies_joint_bound": False,
}


def audit_contract(contract: dict, *, root: Path = ROOT) -> dict:
    """Check a frozen audit input; never infer missing mathematical premises.

    V1 intentionally has no route from supplied claims to activation. A future
    proved bound needs a separately reviewed contract version and a verifier
    for its evidence, not a switch in this JSON file.
    """
    require(type(contract) is dict and set(contract) == {
        "schema", "relation", "source_sha256", "accounting",
        "required_strategy_classes", "unclosed_obligations", "cost_envelopes",
    }, "CONTRACT_FIELDS")
    require(contract["schema"] == SCHEMA, "CONTRACT_SCHEMA")
    # Canonical JSON equality distinguishes true from 1, unlike Python ==.
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
    require(canonical(contract["relation"]) == canonical(expected_relation()), "RELATION_BINDING")
    actual_p = Fraction(int.from_bytes(mu.T0, "big") + 1, 1 << 256)
    require(actual_p == mu.IDEAL_TICKET_PROBABILITY, "TARGET_PROBABILITY")
    pins = contract["source_sha256"]
    require(type(pins) is dict and set(pins) == set(SOURCE_PATHS), "SOURCE_SET")
    for name in SOURCE_PATHS:
        pin = pins[name]
        require(type(pin) is str and len(pin) == 64
                and all(c in "0123456789abcdef" for c in pin), "SOURCE_DIGEST_FORMAT")
        path = root / name
        require(path.is_file() and not path.is_symlink(), "SOURCE_UNAVAILABLE")
        require(sha256_file(path) == pin, "SOURCE_DIGEST_MISMATCH")
    require(canonical(contract["accounting"]) == canonical(ACCOUNTING), "ACCOUNTING_CONTRACT")
    require(contract["required_strategy_classes"] == list(STRATEGIES), "STRATEGY_COVERAGE_SCOPE")
    require(contract["unclosed_obligations"] == list(OBLIGATIONS), "UNPROVED_OBLIGATION_PROMOTION")
    envelopes = contract["cost_envelopes"]
    require(type(envelopes) is dict and set(envelopes) == {"classical", "quantum"}, "COST_CLASSES")
    unknown = []
    for category in ("classical", "quantum"):
        rows = envelopes[category]
        require(type(rows) is list and len(rows) == mu.U_MAX - mu.U_MIN + 1, "COST_GRID")
        for u, row in zip(range(mu.U_MIN, mu.U_MAX + 1), rows):
            require(type(row) is dict and set(row) == {"units", "lower", "upper", "status"}, "COST_ROW")
            require(type(row["units"]) is int and row["units"] == u, "COST_UNITS")
            require(row["lower"] is None and row["upper"] is None
                    and row["status"] == "unproved", "UNSUPPORTED_COST_CERTIFICATE")
            unknown.append({"class": category, "units": u})
    return {
        "schema": "pon-fixed-probability-cost-audit-result-v1",
        "contract_sha256": hashlib.sha256(canonical(contract).encode("utf-8")).hexdigest(),
        "binding_validation": "PASS",
        "source_binding_scope": "four_relation_source_files_only",
        "full_execution_identity_verified": False,
        "qualification": "HOLD_NO_GO",
        "relation_profile": mu.PROFILE.decode("ascii"),
        "relation_parameters": mu.RELATION_PARAMETERS.hex(),
        "ideal_probability": ratio(actual_p),
        "research_credit_range": [mu.BASE_CREDIT * mu.U_MIN, mu.BASE_CREDIT * mu.U_MAX],
        "unknown_cost_points": unknown,
        "unclosed_obligations": list(OBLIGATIONS),
        "finite_model_certificate_is_actual_w1_lower_bound": False,
        "native_admission_policy_changed": False,
        "production_activation": False,
    }


def normalized_subset(*, baseline_probability: Fraction,
                      retained_winner_fraction: Fraction,
                      retained_domain_fraction: Fraction,
                      classical_attempt_ratio: Fraction,
                      coherent_query_ratio: Fraction) -> dict:
    """Exact screening in the explicitly idealized search scaling model.

    q is the fraction of ALL baseline winners retained, g is domain mass.
    Search is uniform on the retained domain; its density is p0*q/g.
    Costs must already include the strategy's specified per-attempt state
    preparation, membership and uncomputation. Setup and accepted-result tails
    remain separate lifecycle costs. This function does not price them or infer
    a real quantum implementation from a classical benchmark.
    """
    values = (baseline_probability, retained_winner_fraction, retained_domain_fraction,
              classical_attempt_ratio, coherent_query_ratio)
    require(all(type(x) is Fraction and x > 0 for x in values), "SUBSET_EXACT_POSITIVE_RATIONAL")
    p, q, g, a_c, a_q = values
    require(p <= 1 and q <= 1 and g <= 1, "SUBSET_MASS_RANGE")
    require(p * q <= g and p * (1 - q) <= 1 - g, "IMPOSSIBLE_SUBSET_MASSES")
    density_ratio = q / g
    classical_ratio = a_c / density_ratio
    quantum_ratio_squared = a_q * a_q / density_ratio

    def comparison(x: Fraction) -> str:
        return "cheaper" if x < 1 else "equal" if x == 1 else "dearer"

    return {
        "model": "ideal-search-scaling-only",
        "ratio_semantics": "assumed-inverse-p-and-inverse-sqrt-p-cost-laws;"
                           "not-finite-grover-or-fixed-success-exact-runtime",
        "normalized_probability": ratio(p * density_ratio),
        "normalized_probability_ratio": ratio(density_ratio),
        "classical_winner_cost_ratio": ratio(classical_ratio),
        "quantum_winner_cost_ratio_squared": ratio(quantum_ratio_squared),
        "classical_comparison": comparison(classical_ratio),
        "quantum_comparison": comparison(quantum_ratio_squared),
        "setup_and_post_win_tail_included": False,
        "actual_w1_quantum_attack_implemented": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    args = parser.parse_args()
    output = audit_contract(load_contract(args.contract))
    output["subset_controls"] = {
        "classically_dearer_quantum_cheaper": normalized_subset(
            baseline_probability=Fraction(1, 16), retained_winner_fraction=Fraction(1, 8),
            retained_domain_fraction=Fraction(1, 2), classical_attempt_ratio=Fraction(2, 5),
            coherent_query_ratio=Fraction(2, 5)),
        "quarter_domain_quarter_winners_keeps_density": normalized_subset(
            baseline_probability=Fraction(1, 16), retained_winner_fraction=Fraction(1, 4),
            retained_domain_fraction=Fraction(1, 4), classical_attempt_ratio=Fraction(1),
            coherent_query_ratio=Fraction(1)),
    }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
