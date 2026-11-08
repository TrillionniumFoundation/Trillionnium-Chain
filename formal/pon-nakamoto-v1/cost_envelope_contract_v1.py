"""Exact, scoped cost-envelope feasibility; never a production-work certificate.

All public arithmetic is rational.  A finite-catalog certificate proves only
the minimum of its explicit table, not completeness over legal implementations.
Hypotheses, measurements, and source hashes cannot upgrade that scope.  The
production gate is unconditionally HOLD_NO_GO in this research component.

See docs/protocol/pon-nakamoto-v1/details/COST_ENVELOPE_CONTRACT_V1.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from fractions import Fraction
from pathlib import Path
from typing import Any


SCHEMA = "pon.cost-envelope.contract.v1"
RESULT_SCHEMA = "pon.cost-envelope.result.v1"
CATALOG_SCHEMA = "pon.cost-envelope.finite-catalog.v1"
BATCH_SCHEMA = "pon.cost-envelope.batch.v1"
BUDGET_SCHEMA = "pon.cost-envelope.failure-budget.v1"
SUCCESS_STANDARD = "total_cost_for_fixed_success_probability_by_deadline"
PROBABILITY_SCOPE = "declared_model_not_statistical_confidence"
BATCH_WINDOW = "expected_accepted_credit_within_same_window"
MAX_ITEMS = 256
MAX_INTEGER_BITS = 4096


def _object(value: Any, keys: set[str], path: str,
            optional: set[str] | None = None) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError(f"{path}: expected object")
    optional = optional or set()
    if not keys <= value.keys() or not value.keys() <= keys | optional:
        raise ValueError(f"{path}: missing or unknown keys")
    return value


def _integer(value: Any, path: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum or value.bit_length() > MAX_INTEGER_BITS:
        raise ValueError(f"{path}: expected bounded integer >= {minimum}")
    return value


def _name(value: Any, path: str) -> str:
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value):
        raise ValueError(f"{path}: invalid identifier")
    return value


def _reference(value: Any, path: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 4096:
        raise ValueError(f"{path}: expected nonempty reference")
    return value


def _list(value: Any, path: str, *, nonempty: bool = False) -> list[Any]:
    if type(value) is not list or len(value) > MAX_ITEMS or (nonempty and not value):
        raise ValueError(f"{path}: expected bounded list")
    return value


def rational(value: Any, path: str = "rational") -> Fraction:
    """Read only canonical {n, d}; reject booleans, floats, signs in d, aliases."""
    value = _object(value, {"n", "d"}, path)
    n, d = value["n"], value["d"]
    if type(n) is not int or abs(n).bit_length() > MAX_INTEGER_BITS:
        raise ValueError(f"{path}.n: expected bounded integer")
    _integer(d, f"{path}.d", 1)
    if math.gcd(n, d) != 1:
        raise ValueError(f"{path}: fraction is not reduced")
    return Fraction(n, d)


def rational_json(value: Fraction) -> dict[str, int]:
    if type(value) is not Fraction:
        raise ValueError("expected Fraction")
    return {"n": value.numerator, "d": value.denominator}


def _q(value: Any, path: str, *, positive: bool = False,
       probability: bool = False) -> Fraction:
    result = rational(value, path)
    if result < 0 or (positive and result == 0) or (probability and result > 1):
        raise ValueError(f"{path}: outside permitted range")
    return result


def _nullable_q(value: Any, path: str, *, positive: bool = False) -> Fraction | None:
    return None if value is None else _q(value, path, positive=positive)


def _json_value(value: Any) -> Any:
    if type(value) is Fraction:
        return rational_json(value)
    if type(value) is list:
        return [_json_value(item) for item in value]
    if type(value) is dict:
        return {key: _json_value(item) for key, item in value.items()}
    return value


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _catalog(evidence: Any, path: str, alpha: Fraction, deadline_ms: int,
             horizon_rounds: int) -> tuple[str, Fraction | None, str, list[str]]:
    """Validate the evidence language; no 'certified: true' assertion exists."""
    if type(evidence) is not dict:
        raise ValueError(f"{path}: expected evidence object")
    kind = evidence.get("kind")
    if kind == "hypothesis":
        _object(evidence, {"kind", "reference"}, path)
        _reference(evidence["reference"], path + ".reference")
        return kind, None, _digest(evidence), []
    if kind != "finite_catalog":
        raise ValueError(f"{path}: unsupported evidence kind")
    _object(evidence, {"kind", "schema", "entries", "minimum_strategy_id"}, path)
    if evidence["schema"] != CATALOG_SCHEMA:
        raise ValueError(f"{path}: wrong catalog schema")
    entries = _list(evidence["entries"], path + ".entries", nonempty=True)
    costs: dict[str, Fraction] = {}
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        where = f"{path}.entries[{index}]"
        _object(entry, {"strategy_id", "total_lifecycle_cost", "success_probability",
                       "elapsed_ms", "rounds"}, where)
        strategy = _name(entry["strategy_id"], where + ".strategy_id")
        if strategy in seen:
            raise ValueError(f"{where}: duplicate strategy")
        seen.add(strategy)
        cost = _q(entry["total_lifecycle_cost"], where + ".total_lifecycle_cost", positive=True)
        probability = _q(entry["success_probability"], where + ".success_probability", probability=True)
        elapsed = _integer(entry["elapsed_ms"], where + ".elapsed_ms")
        rounds = _integer(entry["rounds"], where + ".rounds")
        if probability >= alpha and elapsed <= deadline_ms and rounds <= horizon_rounds:
            costs[strategy] = cost
    if not costs:
        if evidence["minimum_strategy_id"] is not None:
            raise ValueError(f"{path}: no qualifying strategy can witness a minimum")
        return kind, None, _digest(evidence), []
    witness = _name(evidence["minimum_strategy_id"], path + ".minimum_strategy_id")
    minimum = min(costs.values())
    if witness not in costs or costs[witness] != minimum:
        raise ValueError(f"{path}: invalid finite minimum witness")
    return kind, minimum, _digest(evidence), sorted(costs)


def failure_budget(value: Any) -> dict[str, Any]:
    """Union arithmetic conditional on every supplied bound and occurrence cap.

    A joint lifetime term is counted once.  Shared primitives need a joint bound
    from their entire query budget; this function neither invents such a bound
    nor multiplies probabilities as if failures were independent.
    """
    _object(value, {"schema", "target", "terms"}, "failure_budget")
    if value["schema"] != BUDGET_SCHEMA:
        raise ValueError("failure_budget: wrong schema")
    target = _q(value["target"], "failure_budget.target", positive=True, probability=True)
    if target >= 1:
        raise ValueError("failure_budget.target: must be less than one")
    terms = _list(value["terms"], "failure_budget.terms", nonempty=True)
    seen: set[str] = set()
    unknown: list[str] = []
    subtotal = Fraction(0)
    for index, term in enumerate(terms):
        path = f"failure_budget.terms[{index}]"
        _object(term, {"id", "upper", "occurrences", "scope", "reference"}, path)
        name = _name(term["id"], path + ".id")
        if name in seen:
            raise ValueError(f"{path}: duplicate failure term")
        seen.add(name)
        _reference(term["reference"], path + ".reference")
        scope = term["scope"]
        if scope not in ("per_invocation", "joint_lifetime"):
            raise ValueError(f"{path}: unsupported failure scope")
        upper = None if term["upper"] is None else _q(term["upper"], path + ".upper", probability=True)
        count = None if term["occurrences"] is None else _integer(term["occurrences"], path + ".occurrences")
        if scope == "joint_lifetime" and count not in (None, 1):
            raise ValueError(f"{path}: joint lifetime term must be counted once")
        # Even unknown upper * zero does not silently erase an unreviewed term.
        if upper is None or count is None:
            unknown.append(name)
        else:
            subtotal += upper * count
    status = "HOLD_MISSING_BOUND" if unknown else (
        "CONDITIONAL_WITHIN_TARGET" if subtotal <= target else "TARGET_EXCEEDED")
    return _json_value({
        "schema": BUDGET_SCHEMA + ".result", "status": status,
        "target": target, "known_union_subtotal": subtotal,
        "total_failure_upper": None if unknown else min(Fraction(1), subtotal),
        "unknown_terms": unknown, "verified_security_bits": None,
    })


def check_contract(value: Any) -> dict[str, Any]:
    """Decide the declared rational interval/monotonicity/batch model exactly.

    For normalized bounds L_j <= C_j <= U_j and distortion k >= 1, robust
    credit must lie in [max_j U_j/k, min_j k L_j].  With nondecreasing credit,
    the least possible vector is its prefix maximum (rounded upward to a
    declared credit lattice if present).  Every batch has nonnegative yields,
    so testing this least vector decides feasibility of *all declared* upper
    batch constraints as well.  It does not establish any input cost claim.
    """
    required = {"schema", "profile_sha256", "p0", "success_standard", "probability_scope",
                "success_probability_target", "deadline_ms", "horizon_rounds", "work_levels",
                "class_scales", "max_distortion", "envelopes", "nondecreasing",
                "credit_quantum", "batches", "failure_budget"}
    _object(value, required, "contract")
    if value["schema"] != SCHEMA:
        raise ValueError("contract: wrong schema")
    profile = value["profile_sha256"]
    if type(profile) is not str or not re.fullmatch(r"[0-9a-f]{64}", profile):
        raise ValueError("contract: profile_sha256 must be lowercase SHA-256")
    p0 = _q(value["p0"], "contract.p0", positive=True, probability=True)
    if p0 >= 1:
        raise ValueError("contract.p0: must be less than one")
    if value["success_standard"] != SUCCESS_STANDARD:
        raise ValueError("contract: unsupported success standard")
    if value["probability_scope"] != PROBABILITY_SCOPE:
        raise ValueError("contract: unsupported probability scope")
    alpha = _q(value["success_probability_target"], "contract.success_probability_target",
               positive=True, probability=True)
    deadline_ms = _integer(value["deadline_ms"], "contract.deadline_ms", 1)
    horizon_rounds = _integer(value["horizon_rounds"], "contract.horizon_rounds", 1)
    levels = _list(value["work_levels"], "contract.work_levels", nonempty=True)
    levels = [_integer(u, "contract.work_levels[]", 1) for u in levels]
    if levels != sorted(set(levels)):
        raise ValueError("contract: work levels must be unique and increasing")
    if type(value["class_scales"]) is not dict or not 1 <= len(value["class_scales"]) <= MAX_ITEMS:
        raise ValueError("contract: invalid class scales")
    scales = {_name(name, "contract.class_scales.key"):
              _q(scale, f"contract.class_scales.{name}", positive=True)
              for name, scale in value["class_scales"].items()}
    distortion = _q(value["max_distortion"], "contract.max_distortion", positive=True)
    if distortion < 1:
        raise ValueError("contract: max_distortion must be at least one")
    if type(value["nondecreasing"]) is not bool:
        raise ValueError("contract: nondecreasing must be a boolean")
    quantum = _nullable_q(value["credit_quantum"], "contract.credit_quantum", positive=True)
    envelopes: dict[tuple[str, int], tuple[Fraction | None, Fraction | None]] = {}
    evidence_records = []
    unqualified = []
    for index, item in enumerate(_list(value["envelopes"], "contract.envelopes")):
        path = f"contract.envelopes[{index}]"
        _object(item, {"class", "u", "lower", "upper", "evidence"}, path)
        name = _name(item["class"], path + ".class")
        u = _integer(item["u"], path + ".u", 1)
        if name not in scales or u not in levels or (name, u) in envelopes:
            raise ValueError(f"{path}: unknown or duplicate class/work level")
        lower = _nullable_q(item["lower"], path + ".lower", positive=True)
        upper = _nullable_q(item["upper"], path + ".upper", positive=True)
        if lower is not None and upper is not None and lower > upper:
            raise ValueError(f"{path}: lower exceeds upper")
        kind, minimum, digest, eligible = _catalog(item["evidence"], path + ".evidence",
                                                  alpha, deadline_ms, horizon_rounds)
        if kind == "finite_catalog" and not eligible:
            unqualified.append({"class": name, "u": u})
        if minimum is not None and ((lower is not None and lower > minimum) or
                                    (upper is not None and upper < minimum)):
            raise ValueError(f"{path}: interval contradicts finite catalog")
        envelopes[name, u] = (None if lower is None else lower / scales[name],
                              None if upper is None else upper / scales[name])
        evidence_records.append({"class": name, "u": u, "kind": kind,
                                 "certificate_sha256": digest,
                                 "finite_model_minimum": minimum,
                                 "qualifying_strategy_ids": eligible})
    batches = []
    seen_batches: set[str] = set()
    for index, item in enumerate(_list(value["batches"], "contract.batches")):
        path = f"contract.batches[{index}]"
        _object(item, {"schema", "id", "class", "window_semantics", "deadline_ms", "horizon_rounds",
                       "expected_accepts", "total_lifecycle_cost",
                       "credit_per_normalized_cost_cap", "basis", "reference"}, path)
        if item["schema"] != BATCH_SCHEMA:
            raise ValueError(f"{path}: wrong batch schema")
        if item["window_semantics"] != BATCH_WINDOW:
            raise ValueError(f"{path}: unsupported batch window semantics")
        batch_deadline = _integer(item["deadline_ms"], path + ".deadline_ms", 1)
        batch_rounds = _integer(item["horizon_rounds"], path + ".horizon_rounds", 1)
        if batch_deadline != deadline_ms or batch_rounds != horizon_rounds:
            raise ValueError(f"{path}: batch window differs from success contract")
        name = _name(item["id"], path + ".id")
        model = _name(item["class"], path + ".class")
        if name in seen_batches or model not in scales:
            raise ValueError(f"{path}: unknown class or duplicate batch")
        seen_batches.add(name)
        if item["basis"] not in ("hypothesis", "declared_finite_strategy"):
            raise ValueError(f"{path}: unsupported batch basis")
        _reference(item["reference"], path + ".reference")
        cost = _q(item["total_lifecycle_cost"], path + ".total_lifecycle_cost", positive=True)
        cap = _q(item["credit_per_normalized_cost_cap"], path + ".credit_per_normalized_cost_cap", positive=True)
        yields: dict[int, Fraction] = {}
        for entry in _list(item["expected_accepts"], path + ".expected_accepts", nonempty=True):
            _object(entry, {"u", "count"}, path + ".expected_accepts[]")
            u = _integer(entry["u"], path + ".expected_accepts[].u", 1)
            if u not in levels or u in yields:
                raise ValueError(f"{path}: unknown or duplicate batch work level")
            yields[u] = _q(entry["count"], path + ".expected_accepts[].count")
        if not any(yields.values()):
            raise ValueError(f"{path}: batch must have positive expected accepts")
        batches.append({"id": name, "basis": item["basis"], "yields": yields,
                        "credit_cap": cap * cost / scales[model]})
    budget = None if value["failure_budget"] is None else failure_budget(value["failure_budget"])
    missing = []
    for u in levels:
        for name in scales:
            bounds = envelopes.get((name, u), (None, None))
            for label, bound in zip(("lower", "upper"), bounds):
                if bound is None:
                    missing.append({"class": name, "u": u, "bound": label})
    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA, "contract_sha256": _digest(value), "profile_sha256": profile,
        "arithmetic_status": ("HOLD_MISSING_BOUNDS" if missing else
                              "HOLD_NO_QUALIFYING_STRATEGY" if unqualified else "FEASIBLE"),
        "evidence_scope": "CONDITIONAL_HYPOTHESES" if (
            any(record["kind"] == "hypothesis" for record in evidence_records) or
            any(batch["basis"] == "hypothesis" for batch in batches)
        ) else "DECLARED_FINITE_MODEL_ONLY",
        "production_gate": "HOLD_NO_GO", "all_legal_algorithms_lower_bound": None,
        "mixed_consensus_proof": None, "profile_identity_verified": False,
        "p0_is_input_hypothesis": True, "missing_bounds": missing,
        "unqualified_envelopes": unqualified,
        "success_contract": {"standard": SUCCESS_STANDARD, "probability_scope": PROBABILITY_SCOPE,
                             "success_probability_target": alpha, "deadline_ms": deadline_ms,
                             "horizon_rounds": horizon_rounds},
        "evidence": evidence_records, "credit_witness": [], "violations": [],
        "failure_budget": budget,
    }
    if missing or unqualified:
        return _json_value(result)
    selected: dict[int, Fraction] = {}
    running_lower = Fraction(0)
    for u in levels:
        low = max(envelopes[name, u][1] / distortion for name in scales)
        high = min(distortion * envelopes[name, u][0] for name in scales)
        candidate = max(low, running_lower) if value["nondecreasing"] else low
        if quantum is not None:
            candidate = math.ceil(candidate / quantum) * quantum
        running_lower = candidate
        selected[u] = candidate
        result["credit_witness"].append({"u": u, "interval_lower": low,
                                          "interval_upper": high, "credit": candidate})
        if candidate > high:
            result["violations"].append({"kind": "EMPTY_CREDIT_INTERVAL", "u": u,
                                         "required_lower": candidate, "permitted_upper": high})
    for batch in batches:
        expected_credit = sum((selected[u] * count for u, count in batch["yields"].items()), Fraction(0))
        if expected_credit > batch["credit_cap"]:
            result["violations"].append({"kind": "JOINT_BATCH_CAP", "batch_id": batch["id"],
                                         "minimum_expected_credit": expected_credit,
                                         "permitted_credit": batch["credit_cap"]})
    if result["violations"]:
        result["arithmetic_status"] = "INFEASIBLE"
        # An infeasible result contains the *attempted least vector*, not a
        # feasible witness.  Its coordinates make the contradiction reviewable.
        result["least_credit_candidate"] = result.pop("credit_witness")
    return _json_value(result)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract", type=Path)
    parser.add_argument("--arithmetic-only", action="store_true",
                        help="exit 0 for model feasibility; never implies production qualification")
    args = parser.parse_args()
    try:
        value = json.loads(args.contract.read_text(encoding="utf-8"),
                           object_pairs_hook=_unique_pairs,
                           parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)))
        result = check_contract(value)
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({"schema": RESULT_SCHEMA, "arithmetic_status": "INVALID_INPUT",
                          "production_gate": "HOLD_NO_GO", "error": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.arithmetic_only:
        return 0 if result["arithmetic_status"] == "FEASIBLE" else 1
    return 3  # Default mode cannot be mistaken for a release/admission pass.


if __name__ == "__main__":
    raise SystemExit(main())
