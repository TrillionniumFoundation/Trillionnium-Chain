"""Finite-prefix tail integration under explicitly unverified transfer premises.

This checks exact arithmetic, not the truth of a supplied cap theorem or an
all-legal-W1 simulation. See COST_TAIL_TRANSFER_V1.md. In particular a one-way
initial-state probability bound cannot transport an expected cost frontier.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
import json
from typing import Any


SCHEMA = "pon-cost-tail-transfer-v1"
MAX_BUDGETS = 1024
MAX_CAPS = 4097
MAX_BITS = 32768


class TransferError(ValueError):
    pass


def _require(ok: bool, code: str) -> None:
    if not ok:
        raise TransferError(code)


def _fraction(value: Any, code: str) -> Fraction:
    _require(type(value) is Fraction, code)
    _require(value >= 0, code)
    _require(max(value.numerator.bit_length(), value.denominator.bit_length())
             <= MAX_BITS, "RATIONAL_LIMIT")
    return value


def _wire(value: Fraction) -> dict[str, int]:
    _fraction(value, "EXACT_NONNEGATIVE_RATIONAL")
    return {"numerator": value.numerator, "denominator": value.denominator}


@dataclass(frozen=True)
class TransferSpec:
    alpha: Fraction
    reference_caps: tuple[Fraction, ...]
    budgets: int
    rate: Fraction = Fraction(1)
    overhead: Fraction = Fraction(0)
    domination: Fraction = Fraction(1)
    excess: Fraction = Fraction(0)


def _validate(spec: TransferSpec) -> None:
    _require(type(spec) is TransferSpec, "TRANSFER_SPEC")
    for name in ("alpha", "rate", "overhead", "domination", "excess"):
        _fraction(getattr(spec, name), "EXACT_" + name.upper())
    _require(spec.alpha <= 1 and spec.excess <= 1, "PROBABILITY_RANGE")
    _require(spec.domination >= 1, "DOMINATION_RANGE")
    _require(type(spec.budgets) is int and 1 <= spec.budgets <= MAX_BUDGETS,
             "BUDGET_LIMIT")
    _require(type(spec.reference_caps) is tuple
             and 1 <= len(spec.reference_caps) <= MAX_CAPS, "CAP_TABLE_LIMIT")
    previous = Fraction(0)
    for bound in spec.reference_caps:
        _fraction(bound, "EXACT_CAP")
        _require(previous <= bound <= 1, "MONOTONE_PROBABILITY_CAPS")
        previous = bound
    last = spec.rate * (spec.budgets - 1) + spec.overhead
    _fraction(last, "DERIVED_QUERY_CAP")
    _require(last.numerator // last.denominator < len(spec.reference_caps),
             "MISSING_REFERENCE_CAP")


def _input(spec: TransferSpec) -> dict[str, Any]:
    return {
        "alpha": _wire(spec.alpha),
        "reference_caps": [_wire(x) for x in spec.reference_caps],
        "budgets": spec.budgets,
        "rate": _wire(spec.rate),
        "overhead": _wire(spec.overhead),
        "domination": _wire(spec.domination),
        "excess": _wire(spec.excess),
    }


def _header(spec: TransferSpec) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "qualification": "HOLD_NO_GO",
        "arithmetic_only": True,
        "premises_verified": False,
        "reference_cap_theorem_verified": False,
        "initial_state_coverage_verified": False,
        "all_legal_resource_simulation_verified": False,
        "actual_w1_cost_bound": False,
        "production_activation": False,
        "cost_unit": "declared-observable-nonnegative-integer-resource",
        "tail_scope": "finite-prefix-only-no-tail-extrapolation",
        "input": _input(spec),
    }


def build_certificate(spec: TransferSpec) -> dict[str, Any]:
    _validate(spec)
    rows = []
    total = Fraction(0)
    markov = Fraction(0)
    for budget in range(spec.budgets):
        query_cap = (spec.rate * budget + spec.overhead).__floor__()
        reference = spec.reference_caps[query_cap]
        success_cap = min(Fraction(1), spec.domination * reference + spec.excess)
        tail = max(Fraction(0), spec.alpha - success_cap)
        total += tail
        markov = max(markov, (budget + 1) * tail)
        rows.append({"budget": budget, "query_cap": query_cap,
                     "reference_cap": _wire(reference),
                     "success_cap": _wire(success_cap),
                     "tail_lower": _wire(tail)})
    report = _header(spec)
    report.update(rows=rows, sum_lower=_wire(total), markov_lower=_wire(markov))
    return report


def _canonical(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          allow_nan=False)
    except (TypeError, ValueError) as error:
        raise TransferError("JSON_VALUE") from error


def verify_certificate(spec: TransferSpec, certificate: Any) -> bool:
    """Check the finite arithmetic witness without calling its constructor.

    Reference caps and universal simulation premises are inputs, never proved
    by this verifier. Exact key/type/canonical comparisons prevent changing a
    false qualification flag to zero, or turning this report into an admission.
    """
    _validate(spec)
    _require(type(certificate) is dict, "CERTIFICATE_OBJECT")
    header = _header(spec)
    _require(set(certificate) == set(header) | {"rows", "sum_lower", "markov_lower"},
             "CERTIFICATE_KEYS")
    for key, expected in header.items():
        _require(_canonical(certificate[key]) == _canonical(expected),
                 "CERTIFICATE_HEADER_" + key)
    rows = certificate["rows"]
    _require(type(rows) is list and len(rows) == spec.budgets, "COMPLETE_BUDGET_PREFIX")
    accumulated = Fraction(0)
    single_cut = Fraction(0)
    for index, row in enumerate(rows):
        scaled = spec.rate * index + spec.overhead
        cap_index = scaled.numerator // scaled.denominator
        bound = spec.reference_caps[cap_index]
        transformed = spec.domination * bound + spec.excess
        if transformed > 1:
            transformed = Fraction(1)
        deficit = spec.alpha - transformed
        if deficit < 0:
            deficit = Fraction(0)
        expected = {"budget": index, "query_cap": cap_index,
                    "reference_cap": _wire(bound),
                    "success_cap": _wire(transformed),
                    "tail_lower": _wire(deficit)}
        _require(_canonical(row) == _canonical(expected), "BUDGET_ROW")
        accumulated += deficit
        candidate = (index + 1) * deficit
        if candidate > single_cut:
            single_cut = candidate
    _require(_canonical(certificate["sum_lower"]) == _canonical(_wire(accumulated)),
             "TAIL_SUM")
    _require(_canonical(certificate["markov_lower"]) == _canonical(_wire(single_cut)),
             "SINGLE_CUT")
    _require(accumulated >= single_cut, "TAIL_SUM_DOMINATES_SINGLE_CUT")
    return True


def bernoulli_caps(p: Fraction, domain: int, max_queries: int,
                   free_outputs: int = 0) -> tuple[Fraction, ...]:
    """Caps in the declared independent classical Bernoulli game only.

    Domain marks, program and initial state are independent. Final unchecked
    outputs are uncharged in this oracle metric; no real W1 cost is asserted.
    """
    _fraction(p, "EXACT_DENSITY")
    _require(p <= 1, "DENSITY_RANGE")
    for value in (domain, max_queries, free_outputs):
        _require(type(value) is int and 0 <= value < MAX_CAPS, "DOMAIN_LIMIT")
    return tuple(_fraction(1 - (1 - p) ** min(domain, q + free_outputs),
                           "BERNOULLI_CAP") for q in range(max_queries + 1))


def check_fixtures() -> dict[str, Any]:
    caps = bernoulli_caps(Fraction(1, 16), 11, 11)
    fixtures = {
        "independent_classical_caps": TransferSpec(Fraction(1, 2), caps, 12),
        "declared_domination_two": TransferSpec(Fraction(1, 2), caps, 12,
                                               domination=Fraction(2)),
        "eleven_virtual_checks": TransferSpec(Fraction(1, 2), caps, 1,
                                              overhead=Fraction(11)),
    }
    results = {}
    for name, spec in fixtures.items():
        certificate = build_certificate(spec)
        verify_certificate(spec, certificate)
        results[name] = certificate
    return {"schema": "pon-cost-tail-transfer-fixtures-v1",
            "qualification": "HOLD_NO_GO", "actual_w1_cost_bound": False,
            "fixtures": results}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", required=True)
    parser.parse_args()
    print(json.dumps(check_fixtures(), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
