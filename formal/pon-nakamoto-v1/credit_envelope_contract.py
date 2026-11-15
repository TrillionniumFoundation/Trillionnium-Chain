"""Exact public-credit feasibility for a declared finite cost rectangle.

This is conditional arithmetic, not evidence that any interval bounds the
cheapest legal W1 strategy.  For each miner class, the same positive credits
must have cross-scale efficiency spread at most rho for EVERY cost vector in
the supplied rectangular intervals.  Distinct scales only are compared: one
scale has spread one even when its cost interval is wide.

The solver uses multiplicative Bellman--Ford over Fraction values.  Its
independent witness checker reconstructs all inequalities or verifies a
closed walk with product below one; it never calls the solver.  No network,
consensus, lower-bound, hardware, or production qualification can be enabled.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
from typing import Any


F = Fraction
MAX_POINTS = 16
MAX_INPUT_BITS = 128
# Each edge is rho * lower / upper.  A shortest path has at most n edges;
# normalizing by another path can double its numerator/denominator bit budget.
MAX_CERT_BITS = 2 * (MAX_POINTS + 1) * 3 * MAX_INPUT_BITS
MAX_SCALE = (1 << 64) - 1
MAX_JSON_BYTES = 2 * 1024 * 1024
CLASSES = ("classical", "quantum")
INPUT_SCHEMA = "pon-credit-envelope-input-v1"
REPORT_SCHEMA = "pon-credit-envelope-report-v1"
FEASIBLE = "FEASIBLE_FOR_DECLARED_RECTANGULAR_ENVELOPES"
INFEASIBLE = "INFEASIBLE_FOR_DECLARED_RECTANGULAR_ENVELOPES"
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/+\-]{0,159}\Z")
_RATIONAL = re.compile(r"-?(?:0|[1-9][0-9]*)(?:/[1-9][0-9]*)?\Z")


class ContractError(ValueError):
    """Malformed input or an invalid mathematical certificate."""


def need(condition: bool, code: str) -> None:
    if not condition:
        raise ContractError(code)


def label(value: Any, code: str) -> str:
    need(type(value) is str and _LABEL.fullmatch(value) is not None, code)
    return value


def natural_scale(value: Any) -> int:
    need(type(value) is int and 1 <= value <= MAX_SCALE, "SCALE")
    return value


def exact_positive(value: Any, code: str, bits: int = MAX_INPUT_BITS) -> F:
    need(type(value) is F, code + "_EXACT_FRACTION")
    need(value > 0, code + "_POSITIVE")
    need(value.numerator.bit_length() <= bits and value.denominator.bit_length() <= bits,
         code + "_BIT_LIMIT")
    return value


def fields(value: Any, expected: set[str], code: str) -> dict:
    need(type(value) is dict and set(value) == expected, code)
    return value


def parse_fraction(value: Any, code: str, bits: int = MAX_INPUT_BITS) -> F:
    need(type(value) is str, code + "_STRING")
    need(len(value) <= 2 * bits + 3 and _RATIONAL.fullmatch(value) is not None,
         code + "_ENCODING")
    try:
        number = F(value)
    except (ValueError, ZeroDivisionError) as exc:
        raise ContractError(code + "_ENCODING") from exc
    need(str(number) == value, code + "_CANONICAL")
    return exact_positive(number, code, bits)


@dataclass(frozen=True)
class Scope:
    success_contract: str
    resource_model: str
    competitive_scope: str

    def __post_init__(self) -> None:
        label(self.success_contract, "SUCCESS_CONTRACT")
        label(self.resource_model, "RESOURCE_MODEL")
        label(self.competitive_scope, "COMPETITIVE_SCOPE")


@dataclass(frozen=True)
class CostEnvelope:
    lower: F
    upper: F
    scope: Scope

    def __post_init__(self) -> None:
        exact_positive(self.lower, "LOWER")
        exact_positive(self.upper, "UPPER")
        need(self.lower <= self.upper, "REVERSED_INTERVAL")
        need(type(self.scope) is Scope, "ENVELOPE_SCOPE")


@dataclass(frozen=True)
class CostPoint:
    scale: int
    classical: CostEnvelope
    quantum: CostEnvelope

    def __post_init__(self) -> None:
        natural_scale(self.scale)
        need(type(self.classical) is CostEnvelope and type(self.quantum) is CostEnvelope,
             "COST_ENVELOPES")


@dataclass(frozen=True)
class CreditProblem:
    rho: F
    scope: Scope
    points: tuple[CostPoint, ...]

    def __post_init__(self) -> None:
        exact_positive(self.rho, "RHO")
        need(self.rho >= 1, "RHO_BELOW_ONE")
        need(type(self.scope) is Scope, "PROBLEM_SCOPE")
        need(type(self.points) is tuple and 1 <= len(self.points) <= MAX_POINTS,
             "POINT_COUNT")
        need(all(type(point) is CostPoint for point in self.points), "COST_POINT")
        need(len({point.scale for point in self.points}) == len(self.points),
             "DUPLICATE_SCALE")
        for point in self.points:
            for miner_class in CLASSES:
                need(getattr(point, miner_class).scope == self.scope, "SCOPE_MISMATCH")


@dataclass(frozen=True)
class Edge:
    source_scale: int
    target_scale: int
    miner_class: str
    bound: F


def constraints(problem: CreditProblem) -> tuple[Edge, ...]:
    """s[target] <= (rho * L[target] / U[source]) * s[source]."""
    need(type(problem) is CreditProblem, "PROBLEM_TYPE")
    points = sorted(problem.points, key=lambda point: point.scale)
    return tuple(
        Edge(source.scale, target.scale, miner_class,
             problem.rho * getattr(target, miner_class).lower
             / getattr(source, miner_class).upper)
        for source in points for target in points if source.scale != target.scale
        for miner_class in CLASSES
    )


def edge_document(edge: Edge) -> dict:
    return {"source_scale": edge.source_scale, "target_scale": edge.target_scale,
            "miner_class": edge.miner_class, "bound": str(edge.bound)}


def _spread_values(problem: CreditProblem, credits: dict[int, F]) -> dict[str, F]:
    """Exact supremum, including the same-scale ratio one, over the rectangle."""
    out = {}
    for miner_class in CLASSES:
        ratios = [F(1)]
        for numerator in problem.points:
            for denominator in problem.points:
                if numerator.scale != denominator.scale:
                    ratios.append(
                        credits[numerator.scale] / credits[denominator.scale]
                        * getattr(denominator, miner_class).upper
                        / getattr(numerator, miner_class).lower)
        out[miner_class] = max(ratios)
    return out


def worst_spreads(problem: CreditProblem, credits: dict[int, F]) -> dict[str, str]:
    return {miner_class: str(exact_positive(value, "SPREAD", MAX_CERT_BITS))
            for miner_class, value in _spread_values(problem, credits).items()}


def _negative_subwalk(path: tuple[Edge, ...]) -> tuple[Edge, ...]:
    # An improving n-edge path in an n-vertex graph contains a negative cycle.
    # Search its contiguous closed subwalks; do not assume predecessor pointers
    # assembled at different relaxation times already constitute a certificate.
    for start in range(len(path)):
        product = F(1)
        for end in range(start, len(path)):
            product *= path[end].bound
            if path[end].target_scale == path[start].source_scale and product < 1:
                return path[start:end + 1]
    raise ContractError("INTERNAL_MISSING_NEGATIVE_CYCLE")


def solve_credit(problem: CreditProblem) -> dict:
    """Return a rational credit witness or a checkable product-below-one cycle.

    Synchronous relaxations bound every saved path length by the round number.
    This also bounds exact-integer growth on hostile but admitted inputs.
    """
    edges = constraints(problem)
    scales = sorted(point.scale for point in problem.points)
    distances = {scale: F(1) for scale in scales}
    paths: dict[int, tuple[Edge, ...]] = {scale: () for scale in scales}
    for round_number in range(1, len(scales) + 1):
        next_distances = dict(distances)
        next_paths = dict(paths)
        changed = None
        for edge in edges:
            candidate = distances[edge.source_scale] * edge.bound
            if candidate < next_distances[edge.target_scale]:
                next_distances[edge.target_scale] = candidate
                next_paths[edge.target_scale] = paths[edge.source_scale] + (edge,)
                changed = edge.target_scale
        distances, paths = next_distances, next_paths
        if changed is None:
            break
        if round_number == len(scales):
            cycle = _negative_subwalk(paths[changed])
            product = F(1)
            for edge in cycle:
                product *= edge.bound
            return {"status": INFEASIBLE,
                    "cycle": [edge_document(edge) for edge in cycle],
                    "cycle_product": str(product)}
    factor = distances[scales[0]]
    credits = {scale: distances[scale] / factor for scale in scales}
    return {"status": FEASIBLE,
            "credits": [{"scale": scale, "credit": str(credits[scale])} for scale in scales],
            "worst_case_efficiency_spread": worst_spreads(problem, credits)}


def verify_witness(problem: CreditProblem, witness: Any) -> dict:
    """Independent certificate verifier; never invokes solve_credit.

    Feasibility is checked against EVERY class/ordered-pair inequality.  A
    refusal certificate is rebuilt from the ORIGINAL intervals, checked for
    continuity and closure, and multiplied exactly.  No supplied edge weight,
    spread, status, or product is accepted without recomputation.
    """
    need(type(problem) is CreditProblem, "PROBLEM_TYPE")
    need(type(witness) is dict, "WITNESS_OBJECT")
    scales = sorted(point.scale for point in problem.points)
    if witness.get("status") == FEASIBLE:
        fields(witness, {"status", "credits", "worst_case_efficiency_spread"},
               "FEASIBLE_FIELDS")
        rows = witness["credits"]
        need(type(rows) is list and len(rows) == len(scales), "CREDIT_COUNT")
        credits = {}
        for row in rows:
            fields(row, {"scale", "credit"}, "CREDIT_FIELDS")
            scale = natural_scale(row["scale"])
            need(scale in scales and scale not in credits, "CREDIT_SCALE")
            credits[scale] = parse_fraction(row["credit"], "CREDIT", MAX_CERT_BITS)
        need([row["scale"] for row in rows] == scales, "CREDIT_ORDER")
        need(credits[scales[0]] == 1, "CREDIT_NORMALIZATION")
        # Recompute directly, without calling the solver's constraint builder.
        for miner_class in CLASSES:
            for numerator in problem.points:
                for denominator in problem.points:
                    if numerator.scale != denominator.scale:
                        left = credits[numerator.scale] * getattr(denominator, miner_class).upper
                        right = (problem.rho * credits[denominator.scale]
                                 * getattr(numerator, miner_class).lower)
                        need(left <= right, "CREDIT_INEQUALITY")
        expected = _spread_values(problem, credits)
        fields(witness["worst_case_efficiency_spread"], set(CLASSES), "SPREAD_FIELDS")
        for miner_class in CLASSES:
            observed = parse_fraction(witness["worst_case_efficiency_spread"][miner_class],
                                      "SPREAD", MAX_CERT_BITS)
            need(observed == expected[miner_class], "SPREAD_MISMATCH")
        return {"status": FEASIBLE, "inequalities_checked":
                len(CLASSES) * len(scales) * (len(scales) - 1)}
    need(witness.get("status") == INFEASIBLE, "WITNESS_STATUS")
    fields(witness, {"status", "cycle", "cycle_product"}, "INFEASIBLE_FIELDS")
    rows = witness["cycle"]
    need(type(rows) is list and 2 <= len(rows) <= len(scales), "CYCLE_LENGTH")
    by_scale = {point.scale: point for point in problem.points}
    product = F(1)
    endpoints = []
    for row in rows:
        fields(row, {"source_scale", "target_scale", "miner_class", "bound"},
               "EDGE_FIELDS")
        source = natural_scale(row["source_scale"])
        target = natural_scale(row["target_scale"])
        need(source in by_scale and target in by_scale and source != target, "EDGE_SCALES")
        miner_class = row["miner_class"]
        need(type(miner_class) is str and miner_class in CLASSES, "EDGE_CLASS")
        bound = parse_fraction(row["bound"], "EDGE_BOUND", MAX_CERT_BITS)
        expected = (problem.rho * getattr(by_scale[target], miner_class).lower
                    / getattr(by_scale[source], miner_class).upper)
        need(bound == expected, "EDGE_BOUND_MISMATCH")
        product *= expected
        endpoints.append((source, target))
    for index, (_, target) in enumerate(endpoints):
        need(target == endpoints[(index + 1) % len(endpoints)][0], "CYCLE_NOT_CLOSED")
    observed_product = parse_fraction(witness["cycle_product"], "CYCLE_PRODUCT", MAX_CERT_BITS)
    need(product == observed_product, "CYCLE_PRODUCT_MISMATCH")
    need(product < 1, "CYCLE_NOT_NEGATIVE")
    return {"status": INFEASIBLE, "verified_cycle_product": str(product)}


def scope_document(scope: Scope) -> dict:
    return {"success_contract": scope.success_contract, "resource_model": scope.resource_model,
            "competitive_scope": scope.competitive_scope}


def scope_from_document(value: Any) -> Scope:
    fields(value, {"success_contract", "resource_model", "competitive_scope"}, "SCOPE_FIELDS")
    return Scope(value["success_contract"], value["resource_model"], value["competitive_scope"])


def problem_document(problem: CreditProblem) -> dict:
    rows = []
    for point in sorted(problem.points, key=lambda row: row.scale):
        row: dict[str, Any] = {"scale": point.scale}
        for miner_class in CLASSES:
            envelope = getattr(point, miner_class)
            row[miner_class] = {"lower": str(envelope.lower), "upper": str(envelope.upper),
                                "scope": scope_document(envelope.scope)}
        rows.append(row)
    return {"schema": INPUT_SCHEMA, "rho": str(problem.rho),
            "scope": scope_document(problem.scope), "points": rows}


def problem_from_document(value: Any) -> CreditProblem:
    fields(value, {"schema", "rho", "scope", "points"}, "INPUT_FIELDS")
    need(value["schema"] == INPUT_SCHEMA, "INPUT_SCHEMA")
    rho = parse_fraction(value["rho"], "RHO")
    scope = scope_from_document(value["scope"])
    rows = value["points"]
    need(type(rows) is list and 1 <= len(rows) <= MAX_POINTS, "POINT_COUNT")
    points = []
    for row in rows:
        fields(row, {"scale", "classical", "quantum"}, "POINT_FIELDS")
        envelopes = {}
        for miner_class in CLASSES:
            envelope = row[miner_class]
            fields(envelope, {"lower", "upper", "scope"}, "ENVELOPE_FIELDS")
            envelopes[miner_class] = CostEnvelope(
                parse_fraction(envelope["lower"], "LOWER"),
                parse_fraction(envelope["upper"], "UPPER"),
                scope_from_document(envelope["scope"]))
        points.append(CostPoint(natural_scale(row["scale"]),
                                envelopes["classical"], envelopes["quantum"]))
    return CreditProblem(rho, scope, tuple(points))


def qualification() -> dict:
    return {"actual_w1_lower_bounds_proved": False,
            "all_legal_classical_and_quantum_strategies_covered": False,
            "stateful_composition_proved": False,
            "mixed_mining_consensus_qualified": False,
            "production_activation": False}


def limitations() -> list[str]:
    return [
        "Cost intervals and their common success/resource/scope labels are declared inputs, not verified bounds.",
        "Infeasible means no credit is robust for the entire declared rectangle; actual unknown costs may still allow a credit.",
        "Pointwise feasibility does not cover preprocessing, shared work, adaptive task portfolios, hidden inventory or quantum residual state.",
        "This component supplies no W1 all-algorithm lower bound and no common-prefix, chain-quality or chain-growth theorem.",
    ]


def example_problems() -> dict[str, CreditProblem]:
    scope = Scope("complete-accepted-winner-v1", "declared-additive-resource-v1", "finite-demo-all-scales-v1")

    def make(rho: F, classical: list[tuple[int, int]], quantum: list[tuple[int, int]],
             scales: list[int] | None = None) -> CreditProblem:
        need(len(classical) == len(quantum), "EXAMPLE_LENGTH")
        scales = list(range(1, len(classical) + 1)) if scales is None else scales
        need(len(scales) == len(classical), "EXAMPLE_SCALES")
        return CreditProblem(rho, scope, tuple(
            CostPoint(scale, CostEnvelope(F(c[0]), F(c[1]), scope),
                      CostEnvelope(F(q[0]), F(q[1]), scope))
            for scale, c, q in zip(scales, classical, quantum)))

    return {
        "proportional-exact": make(F(1), [(1, 1), (4, 4), (16, 16)],
                                   [(2, 2), (8, 8), (32, 32)], [1, 4, 16]),
        "exponent-mismatch-rho-three-halves": make(F(3, 2), [(1, 1), (16, 16)],
                                                   [(1, 1), (4, 4)], [1, 16]),
        "exponent-mismatch-rho-two": make(F(2), [(1, 1), (16, 16)], [(1, 1), (4, 4)], [1, 16]),
        "three-cycle-without-negative-two-cycle": make(F(2), [(1, 1), (1, 3), (4, 4)],
                                                       [(3, 3), (4, 4), (4, 8)]),
        "wide-single-scale": make(F(1), [(1, 1000000)], [(2, 3000000)]),
        "robust-uncertainty-only-refusal": make(F(1), [(1, 2), (1, 2)], [(1, 2), (1, 2)]),
        "proportional-intervals": make(F(2), [(1, 2), (2, 4), (4, 8)],
                                       [(3, 6), (6, 12), (12, 24)], [1, 2, 4]),
    }


def source_binding() -> list[dict[str, str]]:
    directory = Path(__file__).resolve().parent
    return [{"path": "formal/pon-nakamoto-v1/" + name,
             "sha256": hashlib.sha256((directory / name).read_bytes()).hexdigest()}
            for name in ("credit_envelope_contract.py", "test_credit_envelope_contract.py")]


def build_report() -> dict:
    cases = []
    for case_id, problem in example_problems().items():
        witness = solve_credit(problem)
        verify_witness(problem, witness)
        cases.append({"case_id": case_id, "input": problem_document(problem), "witness": witness})
    return {"schema": REPORT_SCHEMA, "qualification": qualification(),
            "limitations": limitations(), "source_binding": source_binding(), "cases": cases}


def verify_report(report: Any) -> dict:
    """Recheck the fixed demonstration roster, inputs, sources and witnesses.

    Deliberately no solver call: even a compromised solver must supply a valid
    mathematical witness.  Source hashes identify local files, not an external
    theorem, trusted execution environment, or authenticated production source.
    """
    fields(report, {"schema", "qualification", "limitations", "source_binding", "cases"},
           "REPORT_FIELDS")
    need(report["schema"] == REPORT_SCHEMA, "REPORT_SCHEMA")
    fields(report["qualification"], set(qualification()), "QUALIFICATION_FIELDS")
    need(all(value is False for value in report["qualification"].values()), "QUALIFICATION_UPGRADE")
    need(report["limitations"] == limitations(), "LIMITATIONS_CHANGED")
    need(report["source_binding"] == source_binding(), "SOURCE_BINDING")
    expected = example_problems()
    cases = report["cases"]
    need(type(cases) is list and len(cases) == len(expected), "REPORT_CASE_COUNT")
    need(all(type(case) is dict for case in cases), "REPORT_CASE_OBJECT")
    need([case.get("case_id") for case in cases] == list(expected), "REPORT_CASE_ROSTER")
    summaries = []
    for case in cases:
        fields(case, {"case_id", "input", "witness"}, "REPORT_CASE_FIELDS")
        problem = problem_from_document(case["input"])
        need(case["input"] == problem_document(expected[case["case_id"]]), "REPORT_INPUT_CHANGED")
        summaries.append({"case_id": case["case_id"], **verify_witness(problem, case["witness"])})
    return {"verification": "PASS", "cases": summaries, "qualification": qualification()}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    out = {}
    for key, value in pairs:
        need(key not in out, "DUPLICATE_JSON_KEY")
        out[key] = value
    return out


def _no_json_float(value: str) -> None:
    raise ContractError("JSON_FLOAT_OR_NONFINITE")


def _bounded_json_integer(value: str) -> int:
    # Integers in this schema are scale identities; costs are rational strings.
    # Check length before Python's decimal conversion, including malformed JSON
    # that will never reach the schema checker.
    need(len(value) <= 21, "JSON_INTEGER_LIMIT")
    number = int(value)
    need(number.bit_length() <= 64, "JSON_INTEGER_LIMIT")
    return number


def load_json(path: Path) -> Any:
    with path.open("rb") as handle:
        raw = handle.read(MAX_JSON_BYTES + 1)
    need(len(raw) <= MAX_JSON_BYTES, "JSON_BYTE_LIMIT")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_float=_no_json_float, parse_constant=_no_json_float,
                          parse_int=_bounded_json_integer)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ContractError("JSON_ENCODING") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--output", type=Path, help="Create a new demonstration report; refuse overwrite")
    group.add_argument("--verify", type=Path, help="Independently verify a saved demonstration report")
    args = parser.parse_args()
    report = verify_report(load_json(args.verify)) if args.verify else build_report()
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
