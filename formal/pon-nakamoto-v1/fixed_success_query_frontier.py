"""Exact fixed-success frontier in a declared classical Bernoulli query game.

This module prices producer membership queries, not W1 execution. All oracle
bits are initially independent Bernoulli(p), and the producer's initial state
is independent of those bits. Any classical adaptive address choices,
randomization, repeat queries and stopping are allowed. Every producer query
costs one unit. At termination the producer may also return at most m distinct
previously unqueried addresses, without receiving their membership feedback.
Success means that a positively queried output or a final guess is marked.

The fixed finite available domain has d addresses and the hard producer query
cap is n. Put g=min(m,d), k=min(n,d-g), f=1-(1-p)^g and
M=1-(1-p)^(k+g). A success target alpha is feasible exactly when alpha<=M.
Its minimum unconditional expected paid query count is zero when alpha<=f,
and otherwise (alpha-f)/(p*(1-f)). Failed, abandoned and zero-query runs count.
The accompanying proof covers every policy in this idealized classical game;
finite controls do not establish that W1 admits a reduction to the game.

A verifier's virtual final membership tests are explicitly uncharged here.
Their existence does not bill them to a producer. The hard query cap is not
a wall-clock deadline. Quantum algorithms, correlated advice, public oracle
help, physical costs and complete proof/service lifecycles are not certified.
The sixteen actual W1/MU1 classical/quantum cost points remain unproved.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json
from math import gcd
from pathlib import Path
import re
import sys
from typing import Any


EXPERIMENT_SCHEMA = "pon-fixed-success-query-experiment-v1"
RESULT_SCHEMA = "pon-fixed-success-query-frontier-v1"
POLICY = "three-mode-first-hit-and-final-guesses-v1"
FEASIBLE = "FEASIBLE_DECLARED_CLASSICAL_QUERY_MODEL"
INFEASIBLE = "INFEASIBLE_DECLARED_CLASSICAL_QUERY_MODEL"
MAX_COUNT = 1024
MAX_INPUT_BITS = 128
MAX_DERIVED_BITS = 4096
MAX_JSON_BYTES = 262144


class QueryFrontierError(ValueError):
    pass


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise QueryFrontierError(code)


def _bounded(value: Fraction) -> Fraction:
    _require(type(value) is Fraction and value >= 0, "EXACT_NONNEGATIVE_VALUE")
    _require(max(value.numerator.bit_length(), value.denominator.bit_length())
             <= MAX_DERIVED_BITS, "DERIVED_RATIONAL_LIMIT")
    return value


def _wire(value: Fraction) -> dict[str, int]:
    value = _bounded(value)
    return {"numerator": value.numerator, "denominator": value.denominator}


def _read_fraction(value: Any, code: str) -> Fraction:
    _require(type(value) is dict and set(value) == {"numerator", "denominator"}, code)
    numerator, denominator = value["numerator"], value["denominator"]
    _require(type(numerator) is int and type(denominator) is int
             and numerator >= 0 and denominator > 0, code)
    _require(gcd(numerator, denominator) == 1, code)
    return _bounded(Fraction(numerator, denominator))


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _same_json(left: Any, right: Any) -> bool:
    # In particular, do not accept True as 1 or False as 0.
    return _canonical(left) == _canonical(right)


def _scope() -> dict[str, Any]:
    return {
        "model": "independent-classical-bernoulli-membership-oracle",
        "independent_bernoulli_marks": True,
        "known_mark_probability": True,
        "fixed_mark_count_model": False,
        "ideal_private_randomization": "arbitrary-exact-probability-coins-free-in-query-metric",
        "finite_seed_or_wall_clock_attainment_proved": False,
        "algorithm_scope": "all-classical-adaptive-policies-in-the-declared-game",
        "initial_information": "independent-of-all-oracle-membership-bits",
        "data_availability": "fixed-finite-domain-of-available-addresses",
        "accepted_event": "one-marked-queried-output-or-final-unqueried-output",
        "final_outputs": "distinct-unqueried-addresses-without-membership-feedback",
        "charged_resource": "producer-membership-query-count-only",
        "cost_accounting": "unconditional-including-failed-abandoned-and-zero-query-runs",
        "repeated_producer_queries_are_charged": True,
        "virtual_final_checks_billed_to_producer": False,
        "hard_query_cap_is_wall_clock_deadline": False,
        "oracle_correlated_initial_state_or_public_help_covered": False,
        "quantum_algorithms_covered": False,
        "proof_propagation_verification_recovery_costs_priced": False,
        "actual_w1_relation_reduction_verified": False,
        "actual_w1_lower_bound": False,
        "actual_classical_quantum_cost_points": "unproved",
        "physical_resource_lower_bound": None,
        "qualification": "HOLD_NO_GO",
        "native_admission_changed": False,
        "production_activation": False,
    }


@dataclass(frozen=True)
class QueryExperiment:
    probability: Fraction
    target_success: Fraction
    query_cap: int
    available_addresses: int
    final_unqueried_outputs: int = 0

    def __post_init__(self) -> None:
        for value, name in ((self.probability, "PROBABILITY"),
                            (self.target_success, "TARGET_SUCCESS")):
            _require(type(value) is Fraction and 0 <= value <= 1, name)
            _require(max(value.numerator.bit_length(), value.denominator.bit_length())
                     <= MAX_INPUT_BITS, "INPUT_RATIONAL_LIMIT")
        for value, name in ((self.query_cap, "QUERY_CAP"),
                            (self.available_addresses, "AVAILABLE_ADDRESSES"),
                            (self.final_unqueried_outputs, "FINAL_UNQUERIED_OUTPUTS")):
            _require(type(value) is int and 0 <= value <= MAX_COUNT, name)

    def document(self) -> dict[str, Any]:
        return {
            "schema": EXPERIMENT_SCHEMA,
            "probability": _wire(self.probability),
            "target_success": _wire(self.target_success),
            "query_cap": self.query_cap,
            "available_addresses": self.available_addresses,
            "final_unqueried_outputs": self.final_unqueried_outputs,
        }


def _experiment_digest(experiment: QueryExperiment) -> str:
    _require(type(experiment) is QueryExperiment, "QUERY_EXPERIMENT_REQUIRED")
    return hashlib.sha256(_canonical(experiment.document()).encode("utf-8")).hexdigest()


def analyze(experiment: QueryExperiment) -> dict[str, Any]:
    """Construct the exact frontier and an attaining mixture in this game."""
    digest = _experiment_digest(experiment)
    p, alpha = experiment.probability, experiment.target_success
    g = min(experiment.final_unqueried_outputs, experiment.available_addresses)
    k = min(experiment.query_cap, experiment.available_addresses - g)
    failure = 1 - p
    free_success = _bounded(1 - failure**g)
    paid_success = _bounded(1 - failure**k)
    max_success = _bounded(1 - failure**(k + g))
    paid_mode_queries = _bounded(paid_success / p if p else Fraction(k))
    feasible = alpha <= max_success

    output: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "experiment": experiment.document(),
        "experiment_sha256": digest,
        "scope": _scope(),
        "effective_caps": {
            "reserved_unqueried_outputs": g,
            "paid_fresh_queries": k,
            "distinct_tested_or_output_addresses": k + g,
        },
        "free_success_probability": _wire(free_success),
        "maximum_success_probability": _wire(max_success),
        "status": FEASIBLE if feasible else INFEASIBLE,
        "minimum_expected_paid_queries": None,
        "attaining_policy": None,
    }
    if not feasible:
        return output

    paid_mode = free_mode = Fraction(0)
    abort_mode = Fraction(1)
    expected = Fraction(0)
    if alpha > free_success:
        # Feasibility makes both denominators strictly positive here.
        paid_mode = _bounded((alpha - free_success) / (max_success - free_success))
        expected = _bounded((alpha - free_success) / (p * (1 - free_success)))
        if free_success:
            free_mode, abort_mode = 1 - paid_mode, Fraction(0)
        else:
            abort_mode = 1 - paid_mode
    elif alpha:
        free_mode, abort_mode = _bounded(alpha / free_success), 1 - alpha / free_success

    output["minimum_expected_paid_queries"] = _wire(expected)
    output["attaining_policy"] = {
        "policy": POLICY,
        "paid_mode_probability": _wire(paid_mode),
        "free_only_mode_probability": _wire(free_mode),
        "abort_mode_probability": _wire(abort_mode),
        "paid_mode_query_cap": k,
        "final_unqueried_output_cap": g,
        "paid_mode_success_probability": _wire(max_success),
        "paid_mode_expected_queries": _wire(paid_mode_queries),
        "mixture_success_probability": _wire(alpha),
        "mixture_expected_paid_queries": _wire(expected),
    }
    return output


def verify(experiment: QueryExperiment, certificate: dict[str, Any]) -> dict[str, Any]:
    """Independently check the witness by summing its finite first-hit law.

    This verifier does not invoke analyze. It verifies exact arithmetic on the
    explicitly fixed ideal-game assumptions; it does not authenticate those
    assumptions for a real implementation or certify a W1 relation reduction.
    """
    digest = _experiment_digest(experiment)
    _require(type(certificate) is dict and set(certificate) == {
        "schema", "experiment", "experiment_sha256", "scope", "effective_caps",
        "free_success_probability", "maximum_success_probability", "status",
        "minimum_expected_paid_queries", "attaining_policy",
    }, "CERTIFICATE_FIELDS")
    _require(certificate["schema"] == RESULT_SCHEMA, "CERTIFICATE_SCHEMA")
    _require(_same_json(certificate["experiment"], experiment.document())
             and certificate["experiment_sha256"] == digest, "EXPERIMENT_BINDING")
    _require(_same_json(certificate["scope"], _scope()), "CERTIFICATE_SCOPE")

    p, alpha = experiment.probability, experiment.target_success
    g = min(experiment.final_unqueried_outputs, experiment.available_addresses)
    k = min(experiment.query_cap, experiment.available_addresses - g)
    _require(_same_json(certificate["effective_caps"], {
        "reserved_unqueried_outputs": g,
        "paid_fresh_queries": k,
        "distinct_tested_or_output_addresses": k + g,
    }), "EFFECTIVE_CAPS")

    # Reconstruct success and mean paid queries from individual first-hit
    # probabilities. This is deliberately separate from the closed form above.
    survival = Fraction(1)
    paid_hit = paid_queries = Fraction(0)
    for _ in range(k):
        paid_queries = _bounded(paid_queries + survival)
        paid_hit = _bounded(paid_hit + survival * p)
        survival = _bounded(survival * (1 - p))
    free_survival, free_hit = Fraction(1), Fraction(0)
    for _ in range(g):
        free_hit = _bounded(free_hit + free_survival * p)
        free_survival = _bounded(free_survival * (1 - p))
    maximum = _bounded(paid_hit + survival * free_hit)
    _require(_read_fraction(certificate["free_success_probability"], "FREE_SUCCESS")
             == free_hit, "FREE_SUCCESS")
    _require(_read_fraction(certificate["maximum_success_probability"], "MAX_SUCCESS")
             == maximum, "MAX_SUCCESS")

    if alpha > maximum:
        _require(certificate["status"] == INFEASIBLE
                 and certificate["minimum_expected_paid_queries"] is None
                 and certificate["attaining_policy"] is None, "INFEASIBLE_CERTIFICATE")
    else:
        _require(certificate["status"] == FEASIBLE, "FEASIBLE_CERTIFICATE")
        expected = _read_fraction(certificate["minimum_expected_paid_queries"], "EXPECTED_QUERIES")
        if alpha <= free_hit:
            _require(expected == 0, "EXPECTED_QUERY_LOWER_BOUND")
        else:
            _require(expected * p * (1 - free_hit) == alpha - free_hit,
                     "EXPECTED_QUERY_LOWER_BOUND")
        _verify_policy(certificate["attaining_policy"], alpha, expected,
                       k, g, maximum, free_hit, paid_queries)

    return {
        "schema": "pon-fixed-success-query-verification-v1",
        "verified": True,
        "verified_scope": "conditional-classical-query-arithmetic-only",
        "experiment_sha256": digest,
        "certificate_sha256": hashlib.sha256(_canonical(certificate).encode("utf-8")).hexdigest(),
        "qualification": "HOLD_NO_GO",
        "actual_w1_lower_bound": False,
        "actual_classical_quantum_cost_points": "unproved",
        "native_admission_changed": False,
        "production_activation": False,
    }


def _verify_policy(witness: Any, alpha: Fraction, expected: Fraction, k: int, g: int,
                   maximum: Fraction, free_hit: Fraction, paid_queries: Fraction) -> None:
    _require(type(witness) is dict and set(witness) == {
        "policy", "paid_mode_probability", "free_only_mode_probability",
        "abort_mode_probability", "paid_mode_query_cap", "final_unqueried_output_cap",
        "paid_mode_success_probability", "paid_mode_expected_queries",
        "mixture_success_probability", "mixture_expected_paid_queries",
    }, "POLICY_FIELDS")
    _require(witness["policy"] == POLICY, "POLICY_KIND")
    _require(type(witness["paid_mode_query_cap"]) is int
             and witness["paid_mode_query_cap"] == k
             and type(witness["final_unqueried_output_cap"]) is int
             and witness["final_unqueried_output_cap"] == g, "POLICY_CAPS")
    paid = _read_fraction(witness["paid_mode_probability"], "PAID_MODE_PROBABILITY")
    free = _read_fraction(witness["free_only_mode_probability"], "FREE_MODE_PROBABILITY")
    abort = _read_fraction(witness["abort_mode_probability"], "ABORT_MODE_PROBABILITY")
    _require(paid <= 1 and free <= 1 and abort <= 1
             and paid + free + abort == 1, "POLICY_PROBABILITIES")
    _require(_read_fraction(witness["paid_mode_success_probability"], "PAID_MODE_SUCCESS")
             == maximum, "PAID_MODE_SUCCESS")
    _require(_read_fraction(witness["paid_mode_expected_queries"], "PAID_MODE_QUERIES")
             == paid_queries, "PAID_MODE_QUERIES")
    actual_success = _bounded(paid * maximum + free * free_hit)
    actual_queries = _bounded(paid * paid_queries)
    _require(actual_success == alpha
             and _read_fraction(witness["mixture_success_probability"], "MIXTURE_SUCCESS")
             == actual_success, "MIXTURE_SUCCESS")
    _require(actual_queries == expected
             and _read_fraction(witness["mixture_expected_paid_queries"], "MIXTURE_QUERIES")
             == actual_queries, "MIXTURE_QUERIES")


def check_examples() -> dict[str, Any]:
    """Check fixed examples with the independent certificate verifier."""
    specifications = (
        ("tested-output-cap-ten", QueryExperiment(Fraction(1, 16), Fraction(1, 2), 10, 32), None),
        ("tested-output-cap-eleven", QueryExperiment(Fraction(1, 16), Fraction(1, 2), 11, 32), Fraction(8)),
        ("one-final-output", QueryExperiment(Fraction(1, 16), Fraction(1, 2), 10, 32, 1), Fraction(112, 15)),
        ("eleven-final-outputs-no-producer-query", QueryExperiment(Fraction(1, 16), Fraction(1, 2), 0, 11, 11), Fraction(0)),
        ("finite-data-cap", QueryExperiment(Fraction(1, 16), Fraction(1, 2), 100, 10), None),
        ("final-outputs-exhaust-data", QueryExperiment(Fraction(1, 2), Fraction(7, 8), 4, 3, 10), Fraction(0)),
    )
    examples = []
    for name, experiment, expected in specifications:
        certificate = analyze(experiment)
        _require(certificate["status"] == (INFEASIBLE if expected is None else FEASIBLE),
                 "CHECK_STATUS")
        _require(certificate["minimum_expected_paid_queries"]
                 == (None if expected is None else _wire(expected)), "CHECK_EXPECTED_QUERIES")
        examples.append({"name": name, "certificate": certificate,
                         "verification": verify(experiment, certificate)})
    return {
        "schema": "pon-fixed-success-query-check-v1",
        "checked_examples": len(examples),
        "scope": _scope(),
        "qualification": "HOLD_NO_GO",
        "actual_w1_lower_bound": False,
        "actual_classical_quantum_cost_points": "unproved",
        "native_admission_changed": False,
        "production_activation": False,
        "examples": examples,
    }


def load_certificate(path: Path) -> dict[str, Any]:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def reject_number(_value):
        raise QueryFrontierError("NONINTEGER_JSON_NUMBER")

    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    _require(len(raw) <= MAX_JSON_BYTES, "CERTIFICATE_TOO_LARGE")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_float=reject_number, parse_constant=reject_number)
    except QueryFrontierError:
        raise
    except (UnicodeError, ValueError) as error:
        raise QueryFrontierError("CERTIFICATE_JSON") from error
    _require(type(value) is dict, "CERTIFICATE_OBJECT")
    return value


def _argument_fraction(text: str) -> Fraction:
    if not re.fullmatch(r"[0-9]+(?:/[1-9][0-9]*)?", text):
        raise argparse.ArgumentTypeError("use an exact nonnegative integer or fraction")
    try:
        return Fraction(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError("invalid exact fraction") from error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probability", type=_argument_fraction, default=Fraction(1, 16))
    parser.add_argument("--target", type=_argument_fraction, default=Fraction(1, 2))
    parser.add_argument("--query-cap", type=int, default=11)
    parser.add_argument("--addresses", type=int, default=32)
    parser.add_argument("--free-outputs", type=int, default=0)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--verify", type=Path)
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.check:
            output = check_examples()
        else:
            experiment = QueryExperiment(args.probability, args.target, args.query_cap,
                                         args.addresses, args.free_outputs)
            output = (verify(experiment, load_certificate(args.verify))
                      if args.verify else analyze(experiment))
        rendered = json.dumps(output, indent=2, sort_keys=True) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(rendered)
        else:
            print(rendered, end="")
    except (QueryFrontierError, OSError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()
