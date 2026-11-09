#!/usr/bin/env python3
"""Exact finite common-credit feasibility, conditional on declared cost envelopes.

This module checks the proposed inequalities, not the truth of a lower bound,
resource-to-tail composition, a native work relation, or a consensus upgrade.
All arithmetic is rational. No logarithm, root approximation, or measured
implementation cost is silently promoted to a lower bound.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha256
from itertools import product
import json
from math import gcd, lcm
from pathlib import Path
import re
from typing import Any


INPUT_SCHEMA = "pon-credit-feasibility-v1"
RESULT_SCHEMA = "pon-credit-feasibility-result-v1"
MAX_SCALES = 64
MAX_MODELS = 8
MAX_RATIONAL_BITS = 4096
QUALIFICATION = {
    "domain": "finite_declared_envelopes",
    "lower_bound_claims": "unverified_declarations",
    "lifecycle_composition": "not_proved",
    "native_consensus": "not_qualified",
}


def _text(value: Any, name: str, limit: int = 256) -> str:
    if (type(value) is not str or not value or len(value) > limit
            or value.strip() != value
            or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF
                   for char in value)):
        raise ValueError(f"INVALID_TEXT:{name}")
    return value


def _positive_integer(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"POSITIVE_INTEGER_REQUIRED:{name}")
    if value.bit_length() > MAX_RATIONAL_BITS:
        raise ValueError(f"INTEGER_TOO_LARGE:{name}")
    return value


def _fraction(value: Any, name: str) -> Fraction:
    if type(value) is not Fraction or value <= 0:
        raise ValueError(f"POSITIVE_EXACT_FRACTION_REQUIRED:{name}")
    if max(value.numerator.bit_length(), value.denominator.bit_length()) > MAX_RATIONAL_BITS:
        raise ValueError(f"RATIONAL_TOO_LARGE:{name}")
    return value


def _fraction_text(value: Fraction) -> str:
    """Encode exact derived rationals without changing Python's global limits."""
    def decimal(number: int) -> str:
        pieces = []
        while number >= 1_000_000_000:
            number, piece = divmod(number, 1_000_000_000)
            pieces.append(f"{piece:09d}")
        return str(number) + "".join(reversed(pieces))
    numerator = decimal(value.numerator)
    return numerator if value.denominator == 1 else numerator + "/" + decimal(value.denominator)


def _tuple(value: Any, expected_type: type, name: str, limit: int) -> tuple:
    if (type(value) is not tuple or not 1 <= len(value) <= limit
            or any(type(item) is not expected_type for item in value)):
        raise ValueError(f"INVALID_NONEMPTY_TUPLE:{name}")
    return value


@dataclass(frozen=True)
class SuccessStandard:
    """One explicitly shared experiment; unsuccessful work is included in cost."""

    kind: str
    probability: Fraction | None = None
    cost_accounting: str = "unconditional_including_failures"

    def __post_init__(self) -> None:
        if type(self.kind) is not str or self.kind not in (
                "fixed_success_probability", "almost_sure_first_success"):
            raise ValueError("INVALID_SUCCESS_STANDARD")
        if (type(self.cost_accounting) is not str
                or self.cost_accounting != "unconditional_including_failures"):
            raise ValueError("INVALID_SUCCESS_COST_ACCOUNTING")
        if self.kind == "fixed_success_probability":
            _fraction(self.probability, "success_probability")
            if self.probability > 1:
                raise ValueError("SUCCESS_PROBABILITY_OUT_OF_RANGE")
        elif self.probability is not None:
            raise ValueError("UNEXPECTED_SUCCESS_PROBABILITY")


@dataclass(frozen=True)
class Scope:
    relation_id: str
    profile_id: str
    epoch_scope: str
    success_standard: SuccessStandard

    def __post_init__(self) -> None:
        for name in ("relation_id", "profile_id", "epoch_scope"):
            _text(getattr(self, name), name)
        if type(self.success_standard) is not SuccessStandard:
            raise ValueError("INVALID_SUCCESS_STANDARD_TYPE")


@dataclass(frozen=True)
class Scale:
    id: str
    units: int

    def __post_init__(self) -> None:
        _text(self.id, "scale_id")
        _positive_integer(self.units, "units")


@dataclass(frozen=True)
class Bound:
    """A bound declaration. A reference is not authenticated by this checker."""

    value: Fraction
    basis: str
    reference: str

    def __post_init__(self) -> None:
        _fraction(self.value, "bound")
        if type(self.basis) is not str or self.basis not in (
                "assumption", "proof_reference", "measurement", "implementation"):
            raise ValueError("INVALID_BOUND_BASIS")
        _text(self.reference, "bound_reference", 4096)


@dataclass(frozen=True)
class CostPoint:
    scale_id: str
    scope: Scope
    resource_model: str
    lower: Bound
    upper: Bound

    def __post_init__(self) -> None:
        _text(self.scale_id, "scale_id")
        _text(self.resource_model, "resource_model")
        if type(self.scope) is not Scope:
            raise ValueError("INVALID_SCOPE_TYPE")
        if type(self.lower) is not Bound or type(self.upper) is not Bound:
            raise ValueError("INVALID_BOUND_TYPE")
        if self.lower.basis not in ("assumption", "proof_reference"):
            raise ValueError("MEASUREMENT_OR_IMPLEMENTATION_IS_NOT_LOWER_BOUND")
        if self.lower.value > self.upper.value:
            raise ValueError("LOWER_EXCEEDS_UPPER")


@dataclass(frozen=True)
class CostModel:
    id: str
    family: str
    gamma: Fraction
    resource_model: str
    points: tuple[CostPoint, ...]

    def __post_init__(self) -> None:
        _text(self.id, "model_id")
        _text(self.resource_model, "resource_model")
        if type(self.family) is not str or self.family not in ("classical", "quantum"):
            raise ValueError("INVALID_MODEL_FAMILY")
        _fraction(self.gamma, "gamma")
        if self.gamma < 1:
            raise ValueError("GAMMA_BELOW_ONE")
        _tuple(self.points, CostPoint, "points", MAX_SCALES)
        if len({point.scale_id for point in self.points}) != len(self.points):
            raise ValueError("DUPLICATE_POINT_SCALE_ID")
        if any(point.resource_model != self.resource_model for point in self.points):
            raise ValueError("RESOURCE_MODEL_MISMATCH")


@dataclass(frozen=True)
class CreditProblem:
    scope: Scope
    scales: tuple[Scale, ...]
    models: tuple[CostModel, ...]

    def __post_init__(self) -> None:
        if type(self.scope) is not Scope:
            raise ValueError("INVALID_SCOPE_TYPE")
        _tuple(self.scales, Scale, "scales", MAX_SCALES)
        _tuple(self.models, CostModel, "models", MAX_MODELS)
        if len({scale.id for scale in self.scales}) != len(self.scales):
            raise ValueError("DUPLICATE_SCALE_ID")
        if len({scale.units for scale in self.scales}) != len(self.scales):
            raise ValueError("DUPLICATE_SCALE_UNITS")
        if len({model.id for model in self.models}) != len(self.models):
            raise ValueError("DUPLICATE_MODEL_ID")
        scale_ids = {scale.id for scale in self.scales}
        for model in self.models:
            if {point.scale_id for point in model.points} != scale_ids:
                raise ValueError("INCOMPLETE_OR_UNKNOWN_SCALE_GRID")
            for point in model.points:
                if point.scope.success_standard != self.scope.success_standard:
                    raise ValueError("SUCCESS_STANDARD_MISMATCH")
                if point.scope.epoch_scope != self.scope.epoch_scope:
                    raise ValueError("EPOCH_SCOPE_MISMATCH")
                if point.scope != self.scope:
                    raise ValueError("RELATION_OR_PROFILE_MISMATCH")


@dataclass(frozen=True)
class Edge:
    model_id: str
    source: str
    target: str
    multiplier: Fraction


def _require_problem(problem: CreditProblem) -> None:
    if type(problem) is not CreditProblem:
        raise ValueError("INVALID_CREDIT_PROBLEM_TYPE")


def constraints(problem: CreditProblem) -> tuple[Edge, ...]:
    """v -> u has multiplier Gamma_chi L_chi(u) / U_chi(v)."""
    _require_problem(problem)
    rows = []
    for model in problem.models:
        points = {point.scale_id: point for point in model.points}
        for source, target in product(problem.scales, repeat=2):
            factor = (model.gamma * points[target.id].lower.value
                      / points[source.id].upper.value)
            rows.append(Edge(model.id, source.id, target.id, factor))
    return tuple(rows)


def verify_credit_schedule(problem: CreditProblem,
                           credits: dict[str, Fraction]) -> bool:
    """Check original inequalities directly, independent of the graph solver."""
    _require_problem(problem)
    if (type(credits) is not dict or set(credits) != {s.id for s in problem.scales}
            or any(type(key) is not str for key in credits)):
        raise ValueError("INVALID_CREDIT_GRID")
    # Derived credits can be larger than the bounded input coefficients.
    if any(type(value) is not Fraction or value <= 0 for value in credits.values()):
        raise ValueError("POSITIVE_EXACT_CREDIT_REQUIRED")
    for model in problem.models:
        for left, right in product(model.points, repeat=2):
            if (credits[left.scale_id] * right.upper.value
                    > model.gamma * credits[right.scale_id] * left.lower.value):
                raise ValueError(f"CREDIT_CONSTRAINT_VIOLATION:{model.id}:"
                                 f"{left.scale_id}:{right.scale_id}")
    return True


def verify_cycle(problem: CreditProblem, cycle: tuple[Edge, ...]) -> Fraction:
    """Verify a short directed cycle against the input, never a supplied graph.

    Repeating vertices are refused: Bellman-Ford emits a simple cycle, including
    a possible one-edge self cycle. Its product must be strictly below one.
    """
    _require_problem(problem)
    _tuple(cycle, Edge, "cycle", len(problem.scales))
    models = {model.id: model for model in problem.models}
    product_value = Fraction(1)
    sources = set()
    for position, edge in enumerate(cycle):
        if (type(edge.model_id) is not str or edge.model_id not in models
                or type(edge.source) is not str or type(edge.target) is not str
                or type(edge.multiplier) is not Fraction or edge.multiplier <= 0):
            raise ValueError("INVALID_CYCLE_EDGE")
        model = models[edge.model_id]
        points = {point.scale_id: point for point in model.points}
        if edge.source not in points or edge.target not in points:
            raise ValueError("UNKNOWN_CYCLE_SCALE")
        if edge.target != cycle[(position + 1) % len(cycle)].source:
            raise ValueError("CYCLE_NOT_CLOSED")
        if edge.source in sources:
            raise ValueError("CYCLE_NOT_SIMPLE")
        sources.add(edge.source)
        expected = (model.gamma * points[edge.target].lower.value
                    / points[edge.source].upper.value)
        if edge.multiplier != expected:
            raise ValueError("CYCLE_MULTIPLIER_MISMATCH")
        product_value *= expected
    if product_value >= 1:
        raise ValueError("CYCLE_NOT_STRICTLY_CONTRADICTORY")
    return product_value


def _contradictory_cycle(walk: tuple[Edge, ...]) -> tuple[Edge, ...]:
    """Extract the first repeated-vertex cycle from an improving n-edge walk."""
    vertices = [walk[0].source] + [edge.target for edge in walk]
    first = {}
    for index, vertex in enumerate(vertices):
        if vertex in first:
            return walk[first[vertex]:index]
        first[vertex] = index
    raise RuntimeError("INTERNAL_MISSING_CYCLE")


def solve(problem: CreditProblem) -> dict[str, Any]:
    """Synchronous multiplicative Bellman-Ford with exact witness provenance.

    d_k(v) is the least product of any walk of at most k edges ending at v,
    starting with value one at any vertex. A strict nth-pass improvement has
    an n-edge walk. Removing a cycle of product >= 1 would produce a no-costlier
    shorter walk, contradicting strict improvement. Thus its first repeated
    vertex supplies a strict product-<1 witness. Synchronous rounds bound every
    stored walk to n edges, even when a negative cycle exists.
    """
    _require_problem(problem)
    edges = constraints(problem)
    distances = {scale.id: Fraction(1) for scale in problem.scales}
    walks: dict[str, tuple[Edge, ...]] = {scale.id: () for scale in problem.scales}
    changed: str | None = None
    for _ in range(len(problem.scales)):
        following = distances.copy()
        following_walks = walks.copy()
        changed = None
        for edge in edges:
            candidate = distances[edge.source] * edge.multiplier
            if candidate < following[edge.target]:
                following[edge.target] = candidate
                following_walks[edge.target] = walks[edge.source] + (edge,)
                changed = edge.target
        distances, walks = following, following_walks
        if changed is None:
            break
    result = {
        "schema": RESULT_SCHEMA,
        "problem_sha256": problem_sha256(problem),
        "qualification": QUALIFICATION.copy(),
    }
    if changed is None:
        reference = distances[problem.scales[0].id]
        credits = {scale.id: distances[scale.id] / reference for scale in problem.scales}
        verify_credit_schedule(problem, credits)
        result.update(status="feasible", credits=[
            {"scale_id": scale.id, "value": _fraction_text(credits[scale.id])}
            for scale in problem.scales])
    else:
        cycle = _contradictory_cycle(walks[changed])
        factor = verify_cycle(problem, cycle)
        result.update(status="infeasible", cycle=[
            {"model_id": edge.model_id, "source": edge.source,
             "target": edge.target, "multiplier": _fraction_text(edge.multiplier)}
            for edge in cycle], cycle_product=_fraction_text(factor))
    verify_result(problem, result)
    return result


def integer_credit_schedule(problem: CreditProblem,
                            credits: dict[str, Fraction]) -> dict[str, int]:
    """Scale a verified rational schedule to coprime integers, with no rounding."""
    verify_credit_schedule(problem, credits)
    denominator = lcm(*(value.denominator for value in credits.values()))
    integers = {key: value.numerator * (denominator // value.denominator)
                for key, value in credits.items()}
    divisor = gcd(*integers.values())
    integers = {key: value // divisor for key, value in integers.items()}
    verify_credit_schedule(problem, {key: Fraction(value) for key, value in integers.items()})
    return integers


def _object(value: Any, keys: set[str], name: str) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise ValueError(f"INVALID_OBJECT_FIELDS:{name}")
    return value


def _array(value: Any, name: str, maximum: int) -> list:
    if type(value) is not list or not 1 <= len(value) <= maximum:
        raise ValueError(f"INVALID_NONEMPTY_ARRAY:{name}")
    return value


def _parse_fraction(value: Any, name: str, *, bounded: bool = True) -> Fraction:
    if type(value) is int:
        number = Fraction(value)
    elif type(value) is str:
        # Check length before int(): an input coefficient is at most 4096 bits.
        limit = 2 * MAX_RATIONAL_BITS if bounded else 2 * MAX_RATIONAL_BITS * (4 * MAX_SCALES + 4)
        if len(value) > limit or re.fullmatch(r"(?:0|[1-9][0-9]*)(?:/[1-9][0-9]*)?", value) is None:
            raise ValueError(f"INVALID_RATIONAL_ENCODING:{name}")
        parts = value.split("/")
        # Parse bounded chunks so legitimate derived certificates do not depend
        # on Python's global decimal-string conversion setting.
        def decimal(text: str) -> int:
            number = 0
            for index in range(0, len(text), 1000):
                part = text[index:index + 1000]
                number = number * 10 ** len(part) + int(part)
            return number
        number = Fraction(decimal(parts[0]), decimal(parts[1]) if len(parts) == 2 else 1)
    else:
        raise ValueError(f"EXACT_RATIONAL_ENCODING_REQUIRED:{name}")
    if bounded:
        return _fraction(number, name)
    if number <= 0:
        raise ValueError(f"POSITIVE_EXACT_CREDIT_REQUIRED:{name}")
    return number


def _scope_from_document(value: Any) -> Scope:
    row = _object(value, {"relation_id", "profile_id", "epoch_scope", "success_standard"}, "scope")
    success = row["success_standard"]
    if type(success) is not dict:
        raise ValueError("INVALID_SUCCESS_STANDARD_TYPE")
    fields = {"kind", "cost_accounting"}
    if success.get("kind") == "fixed_success_probability":
        fields.add("probability")
    _object(success, fields, "success_standard")
    standard = SuccessStandard(
        success["kind"],
        _parse_fraction(success["probability"], "success_probability") if "probability" in success else None,
        success["cost_accounting"],
    )
    return Scope(row["relation_id"], row["profile_id"], row["epoch_scope"], standard)


def _bound_from_document(value: Any) -> Bound:
    row = _object(value, {"value", "basis", "reference"}, "bound")
    return Bound(_parse_fraction(row["value"], "bound"), row["basis"], row["reference"])


def problem_from_document(value: Any) -> CreditProblem:
    row = _object(value, {"schema", "scope", "scales", "models"}, "problem")
    if type(row["schema"]) is not str or row["schema"] != INPUT_SCHEMA:
        raise ValueError("UNSUPPORTED_INPUT_SCHEMA")
    scope = _scope_from_document(row["scope"])
    scales = []
    for entry in _array(row["scales"], "scales", MAX_SCALES):
        item = _object(entry, {"id", "units"}, "scale")
        scales.append(Scale(item["id"], item["units"]))
    models = []
    for entry in _array(row["models"], "models", MAX_MODELS):
        item = _object(entry, {"id", "family", "gamma", "resource_model", "points"}, "model")
        points = []
        for entry_point in _array(item["points"], "points", MAX_SCALES):
            point = _object(entry_point, {"scale_id", "scope", "resource_model", "lower", "upper"}, "point")
            points.append(CostPoint(
                point["scale_id"], _scope_from_document(point["scope"]), point["resource_model"],
                _bound_from_document(point["lower"]), _bound_from_document(point["upper"])))
        models.append(CostModel(item["id"], item["family"],
                                _parse_fraction(item["gamma"], "gamma"),
                                item["resource_model"], tuple(points)))
    return CreditProblem(scope, tuple(scales), tuple(models))


def _scope_document(scope: Scope) -> dict[str, Any]:
    standard = {"kind": scope.success_standard.kind,
                "cost_accounting": scope.success_standard.cost_accounting}
    if scope.success_standard.probability is not None:
        standard["probability"] = _fraction_text(scope.success_standard.probability)
    return {"relation_id": scope.relation_id, "profile_id": scope.profile_id,
            "epoch_scope": scope.epoch_scope, "success_standard": standard}


def problem_to_document(problem: CreditProblem) -> dict[str, Any]:
    _require_problem(problem)
    def bound(row: Bound) -> dict[str, str]:
        return {"value": _fraction_text(row.value), "basis": row.basis, "reference": row.reference}
    return {
        "schema": INPUT_SCHEMA,
        "scope": _scope_document(problem.scope),
        "scales": [{"id": row.id, "units": row.units} for row in problem.scales],
        "models": [{"id": model.id, "family": model.family, "gamma": _fraction_text(model.gamma),
                    "resource_model": model.resource_model,
                    "points": [{"scale_id": row.scale_id, "scope": _scope_document(row.scope),
                                "resource_model": row.resource_model,
                                "lower": bound(row.lower), "upper": bound(row.upper)}
                               for row in model.points]} for model in problem.models],
    }


def problem_sha256(problem: CreditProblem) -> str:
    payload = json.dumps(problem_to_document(problem), sort_keys=True,
                         separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return sha256(payload).hexdigest()


def verify_result(problem: CreditProblem, value: Any) -> bool:
    """Verify a JSON certificate without solving or trusting its claimed factors."""
    _require_problem(problem)
    if type(value) is not dict:
        raise ValueError("INVALID_RESULT_TYPE")
    fields = {"schema", "problem_sha256", "qualification", "status"}
    if value.get("status") == "feasible":
        fields.add("credits")
    elif value.get("status") == "infeasible":
        fields |= {"cycle", "cycle_product"}
    else:
        raise ValueError("INVALID_RESULT_STATUS")
    _object(value, fields, "result")
    if value["schema"] != RESULT_SCHEMA or type(value["schema"]) is not str:
        raise ValueError("UNSUPPORTED_RESULT_SCHEMA")
    if type(value["problem_sha256"]) is not str or value["problem_sha256"] != problem_sha256(problem):
        raise ValueError("RESULT_PROBLEM_DIGEST_MISMATCH")
    if type(value["qualification"]) is not dict or value["qualification"] != QUALIFICATION:
        raise ValueError("INVALID_RESULT_QUALIFICATION")
    if value["status"] == "feasible":
        credits = {}
        for entry in _array(value["credits"], "credits", len(problem.scales)):
            row = _object(entry, {"scale_id", "value"}, "credit")
            key = _text(row["scale_id"], "scale_id")
            if key in credits:
                raise ValueError("DUPLICATE_CREDIT_SCALE_ID")
            credits[key] = _parse_fraction(row["value"], "credit", bounded=False)
        return verify_credit_schedule(problem, credits)
    cycle = []
    for entry in _array(value["cycle"], "cycle", len(problem.scales)):
        row = _object(entry, {"model_id", "source", "target", "multiplier"}, "edge")
        cycle.append(Edge(row["model_id"], row["source"], row["target"],
                          _parse_fraction(row["multiplier"], "cycle_multiplier", bounded=False)))
    factor = verify_cycle(problem, tuple(cycle))
    if _parse_fraction(value["cycle_product"], "cycle_product", bounded=False) != factor:
        raise ValueError("CYCLE_PRODUCT_MISMATCH")
    return True


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"DUPLICATE_JSON_KEY:{key}")
        value[key] = item
    return value


def load_document(path: str | Path) -> Any:
    def reject_inexact(text: str) -> None:
        raise ValueError(f"INEXACT_JSON_NUMBER:{text}")
    return json.loads(Path(path).read_text(encoding="utf-8"),
                      object_pairs_hook=_no_duplicate_keys,
                      parse_float=reject_inexact, parse_constant=reject_inexact)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("solve", help="emit exact finite feasibility certificate")
    run.add_argument("input", type=Path)
    run.add_argument("--output", type=Path)
    check = commands.add_parser("verify", help="check a certificate without solving")
    check.add_argument("input", type=Path)
    check.add_argument("certificate", type=Path)
    args = parser.parse_args()
    try:
        problem = problem_from_document(load_document(args.input))
        if args.command == "verify":
            verify_result(problem, load_document(args.certificate))
            report = {"verification": "passed", "problem_sha256": problem_sha256(problem),
                      "qualification": QUALIFICATION.copy()}
        else:
            report = solve(problem)
        rendered = json.dumps(report, sort_keys=True, indent=2) + "\n"
        if args.command == "solve" and args.output is not None:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    except (OSError, UnicodeError, ValueError) as error:
        parser.exit(2, f"credit-feasibility: {error}\n")


if __name__ == "__main__":
    main()
