"""Exact finite posterior policies for a declared, hidden marked count.

This is a conditional research model, not a W1 implementation or a quantum
work lower bound. A domain has N items and a declared prior on its marked count
M. Each batch re-prepares a uniform state, runs a chosen number of ideal Grover
iterations and measures P independent processors sharing that SAME M. Only the
Boolean batch outcome is retained; measured identities and residual quantum
state are discarded. Successful batches end the search and pay one proof cost.

After failure the M posterior changes. A refresh pays setup for a new domain
with the original independent prior; realizability of such domains in W1 is
not established. The Bellman calculation maximizes delivered-winner probability
within a fixed additive resource budget over this finite policy class only.
All arithmetic is rational, including amplitudes, posterior updates and costs.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from fractions import Fraction as F
from functools import lru_cache
import hashlib
import json
from math import comb
import os
from pathlib import Path
import stat
import sys
from typing import Any


REQUEST_SCHEMA = "trnm-quantum-posterior-request-v1"
REPORT_SCHEMA = "trnm-quantum-posterior-policy-v1"
MAX_DOMAIN_SIZE = 32
MAX_ITERATIONS = 16
MAX_PROCESSORS = 8
MAX_BUDGET = 128
MAX_STATES = 25_000
MAX_FRACTION_BITS = 4096
MAX_INPUT_BYTES = 262_144
MAX_REPORT_BYTES = 4_194_304


def integer(value: Any, code: str, maximum: int, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(code)
    return value


def bounded(value: F) -> F:
    if type(value) is not F or max(value.numerator.bit_length(),
                                   value.denominator.bit_length()) > MAX_FRACTION_BITS:
        raise ValueError("EXACT_FRACTION_LIMIT")
    return value


def probability(value: Any, code: str = "EXACT_PROBABILITY") -> F:
    if type(value) is not F or not 0 <= value <= 1:
        raise ValueError(code)
    return bounded(value)


def wire(value: F) -> dict[str, int]:
    bounded(value)
    return {"numerator": value.numerator, "denominator": value.denominator}


def exact_fields(value: Any, expected: set[str], code: str) -> dict:
    if type(value) is not dict or set(value) != expected:
        raise ValueError(code)
    return value


def read_fraction(value: Any) -> F:
    item = exact_fields(value, {"numerator", "denominator"}, "FRACTION_SCHEMA")
    n, d = item["numerator"], item["denominator"]
    if type(n) is not int or type(d) is not int or d <= 0:
        raise ValueError("CANONICAL_FRACTION")
    result = bounded(F(n, d))
    if result.numerator != n or result.denominator != d:
        raise ValueError("CANONICAL_FRACTION")
    return result


def validate_prior(size: int, prior: tuple[F, ...]) -> None:
    integer(size, "DOMAIN_SIZE", MAX_DOMAIN_SIZE, 1)
    if type(prior) is not tuple or len(prior) != size + 1:
        raise ValueError("MARKED_COUNT_PRIOR_SHAPE")
    total = F(0)
    for mass in prior:
        total = bounded(total + probability(mass, "MARKED_COUNT_PRIOR_MASS"))
    if total != 1:
        raise ValueError("MARKED_COUNT_PRIOR_NOT_NORMALIZED")


def binomial_prior(size: int, ticket_probability: F) -> tuple[F, ...]:
    """Declared iid ticket prior; this does not establish the W1 ticket law."""
    integer(size, "DOMAIN_SIZE", MAX_DOMAIN_SIZE, 1)
    p = probability(ticket_probability)
    prior = tuple(bounded(F(comb(size, m)) * p**m * (1 - p)**(size - m))
                  for m in range(size + 1))
    validate_prior(size, prior)
    return prior


def batch_success(size: int, marked: int, iterations: int,
                  processors: int = 1) -> F:
    """Exact two-amplitude recurrence, then independent outcomes given M.

    Marked amplitudes are sqrt(M/N)*a and unmarked amplitudes sqrt(1-M/N)*b.
    Keeping a,b rational avoids approximate trigonometry, even after overshoot.
    The recurrence describes this circuit, not an upper bound for all algorithms.
    """
    integer(size, "DOMAIN_SIZE", MAX_DOMAIN_SIZE, 1)
    integer(marked, "MARKED_COUNT", size)
    integer(iterations, "GROVER_ITERATIONS", MAX_ITERATIONS)
    integer(processors, "PROCESSORS", MAX_PROCESSORS, 1)
    p, a, b = F(marked, size), F(1), F(1)
    for _ in range(iterations):
        a, b = (bounded((1 - 2*p)*a + 2*(1 - p)*b),
                bounded(-2*p*a + (1 - 2*p)*b))
    single = probability(bounded(p*a*a))
    return probability(bounded(1 - (1 - single)**processors))


@dataclass(frozen=True)
class FailureUpdate:
    success_probability: F
    failure_probability: F
    posterior: tuple[F, ...] | None


def after_failure(prior: tuple[F, ...], successes: tuple[F, ...]) -> FailureUpdate:
    """Condition on the coarsened Boolean failure; never resample M on retry."""
    validate_prior(len(prior) - 1, prior)
    if type(successes) is not tuple or len(successes) != len(prior):
        raise ValueError("SUCCESS_VECTOR_SHAPE")
    success = F(0)
    for mass, chance in zip(prior, successes):
        success = bounded(success + mass*probability(chance))
    failure = 1 - success
    if not failure:
        return FailureUpdate(success, failure, None)
    posterior = tuple(bounded(mass*(1 - chance)/failure)
                      for mass, chance in zip(prior, successes))
    validate_prior(len(prior) - 1, posterior)
    return FailureUpdate(success, failure, posterior)


@dataclass(frozen=True)
class ResourceCosts:
    """One caller-declared additive unit, not a physical timing calibration.

    Setup is paid once per domain. All P copies pay preparation, iterations,
    readout and checking, including failed and zero-iteration batches. Proof is
    paid once per successful batch. No parallel wall-clock inference is made.
    """
    domain_setup: int
    state_prepare: int
    oracle_iteration: int
    readout: int
    candidate_check: int
    winner_proof: int
    unit: str = "declared-additive-resource-units"

    def validate(self) -> None:
        for name in ("domain_setup", "state_prepare", "oracle_iteration",
                     "readout", "candidate_check", "winner_proof"):
            # Positive setup and measured-batch costs make every recursive
            # continuation consume budget; no zero-cost refresh loop exists.
            minimum = int(name in ("domain_setup", "oracle_iteration", "readout",
                                   "candidate_check"))
            integer(getattr(self, name), "COST_" + name.upper(), MAX_BUDGET, minimum)
        if (type(self.unit) is not str or not self.unit or len(self.unit) > 100
                or self.unit.strip() != self.unit):
            raise ValueError("RESOURCE_UNIT_LABEL")

    def measured_batch(self, iterations: int, processors: int) -> int:
        self.validate()
        integer(iterations, "GROVER_ITERATIONS", MAX_ITERATIONS)
        integer(processors, "PROCESSORS", MAX_PROCESSORS, 1)
        return processors*(self.state_prepare + iterations*self.oracle_iteration
                           + self.readout + self.candidate_check)


@dataclass(frozen=True)
class Model:
    domain_size: int
    marked_count_prior: tuple[F, ...]
    iteration_choices: tuple[int, ...]
    processors: int
    budget_units: int
    costs: ResourceCosts
    allow_refresh: bool = True

    def validate(self) -> None:
        validate_prior(self.domain_size, self.marked_count_prior)
        if (type(self.iteration_choices) is not tuple or not self.iteration_choices
                or len(self.iteration_choices) > MAX_ITERATIONS + 1):
            raise ValueError("ITERATION_CHOICES")
        previous = -1
        for count in self.iteration_choices:
            integer(count, "GROVER_ITERATIONS", MAX_ITERATIONS)
            if count <= previous:
                raise ValueError("ITERATION_CHOICE_ORDER")
            previous = count
        integer(self.processors, "PROCESSORS", MAX_PROCESSORS, 1)
        integer(self.budget_units, "BUDGET", MAX_BUDGET)
        if type(self.costs) is not ResourceCosts:
            raise ValueError("RESOURCE_COSTS_TYPE")
        self.costs.validate()
        if type(self.allow_refresh) is not bool:
            raise ValueError("ALLOW_REFRESH_BOOLEAN")

    def request(self) -> dict:
        self.validate()
        return {
            "schema": REQUEST_SCHEMA, "domain_size": self.domain_size,
            "marked_count_prior": [wire(x) for x in self.marked_count_prior],
            "iteration_choices": list(self.iteration_choices),
            "processors": self.processors, "budget_units": self.budget_units,
            "costs": asdict(self.costs), "allow_refresh": self.allow_refresh,
        }


def parse_request(value: Any) -> Model:
    item = exact_fields(value, {"schema", "domain_size", "marked_count_prior",
                               "iteration_choices", "processors", "budget_units",
                               "costs", "allow_refresh"}, "REQUEST_SCHEMA")
    if item["schema"] != REQUEST_SCHEMA:
        raise ValueError("REQUEST_SCHEMA")
    if type(item["marked_count_prior"]) is not list or type(item["iteration_choices"]) is not list:
        raise ValueError("REQUEST_LISTS")
    costs = exact_fields(item["costs"], set(ResourceCosts.__dataclass_fields__), "COST_SCHEMA")
    model = Model(item["domain_size"], tuple(read_fraction(x) for x in item["marked_count_prior"]),
                  tuple(item["iteration_choices"]), item["processors"], item["budget_units"],
                  ResourceCosts(**costs), item["allow_refresh"])
    model.validate()
    return model


@dataclass(frozen=True)
class Decision:
    delivered_probability: F
    expected_spent: F
    action: str
    iterations: int | None = None


def scope() -> dict:
    return {
        "model": "ideal finite count-prior search with coarsened Boolean batch observations",
        "policy_information": "count posterior only; identities and residual coherent state discarded",
        "parallelism": "independent re-prepared processors conditional on the SAME domain marked count",
        "refresh": "paid new independent domain drawn from the original caller-declared count prior",
        "proof_semantics": "ideal marked success produces one acceptable proof at its declared fixed cost; no real validation or delivery modeled",
        "optimality_scope": "finite declared iteration grid, fixed processor count, retry/refresh/stop, one delivered winner",
        "resource_scope": "declared additive units; all processors charged; no calibrated wall time",
        "conditional_finite_policy_optimum": True,
        "actual_w1_marked_prior_proved": False,
        "fresh_domains_realizable_in_w1_proved": False,
        "actual_candidate_proof_validity_established": False,
        "complete_w1_cost_oracle_used": False,
        "quantum_hardware_executed": False,
        "physical_calibration_performed": False,
        "all_algorithm_optimality_proved": False,
        "quantum_work_lower_bound_proved": False,
        "joint_w1_daa_timestamp_chainwork_security_proved": False,
        "whole_chain_quantum_qualified": False,
        "production_activation": False,
    }


def solve(model: Model, *, max_states: int = MAX_STATES) -> dict:
    """Exact Bellman optimum within the declared finite policy class.

    Each continuation has smaller budget, so induction proves the recurrence.
    Randomizing among the enumerated actions cannot exceed their maximum.
    On probability ties, minimize expected spend, then prefer earlier listed
    iterations to refresh. A zero-success continuation stops at zero cost.
    """
    if type(model) is not Model:
        raise ValueError("MODEL_TYPE")
    model.validate()
    integer(max_states, "STATE_LIMIT", MAX_STATES, 1)
    costs, prior = model.costs, model.marked_count_prior
    chances = {q: tuple(batch_success(model.domain_size, m, q, model.processors)
                        for m in range(model.domain_size + 1))
               for q in model.iteration_choices}
    stop = Decision(F(0), F(0), "stop")
    states = 0

    def better(candidate: Decision, incumbent: Decision) -> bool:
        return (candidate.delivered_probability > incumbent.delivered_probability
                or (candidate.delivered_probability == incumbent.delivered_probability
                    and candidate.expected_spent < incumbent.expected_spent))

    @lru_cache(maxsize=None)
    def value(budget: int, belief: tuple[F, ...]) -> Decision:
        nonlocal states
        states += 1
        if states > max_states:
            raise ValueError("EXACT_POLICY_STATE_LIMIT")
        best = stop
        for q in model.iteration_choices:
            charge = costs.measured_batch(q, model.processors)
            # If proof cannot fit after this batch, it cannot fit after further
            # spending either. Such an action is dominated by stopping.
            if budget < charge + costs.winner_proof:
                continue
            update = after_failure(belief, chances[q])
            child = (value(budget - charge, update.posterior)
                     if update.posterior is not None else stop)
            candidate = Decision(
                probability(bounded(update.success_probability
                                    + update.failure_probability*child.delivered_probability)),
                bounded(F(charge) + update.success_probability*costs.winner_proof
                        + update.failure_probability*child.expected_spent),
                "measure", q)
            if better(candidate, best):
                best = candidate
        # Refreshing an unchanged belief pays positive setup for the same
        # decision problem with less budget, and is weakly dominated.
        if model.allow_refresh and belief != prior and budget >= costs.domain_setup:
            child = value(budget - costs.domain_setup, prior)
            candidate = Decision(child.delivered_probability,
                                 bounded(F(costs.domain_setup) + child.expected_spent), "refresh")
            if better(candidate, best):
                best = candidate
        if best.expected_spent > budget:
            raise AssertionError("POLICY_EXCEEDS_PATHWISE_BUDGET")
        return best

    available = model.budget_units - costs.domain_setup
    initial = value(available, prior) if available >= 0 else stop
    started = initial.delivered_probability > 0
    total_spent = bounded(F(costs.domain_setup) + initial.expected_spent) if started else F(0)
    path, belief, reached = [], prior, F(1)
    if started:
        while True:
            decision = value(available, belief)
            row = {"remaining_budget": available, "marked_count_posterior": [wire(x) for x in belief],
                   "reach_probability": wire(reached), "action": decision.action,
                   "continuation_delivered_probability": wire(decision.delivered_probability),
                   "continuation_expected_spent": wire(decision.expected_spent)}
            if decision.action == "stop":
                path.append(row)
                break
            if decision.action == "refresh":
                row["charged_units"] = costs.domain_setup
                available -= costs.domain_setup
                belief = prior
            else:
                q = decision.iterations
                charge = costs.measured_batch(q, model.processors)
                update = after_failure(belief, chances[q])
                row.update(iterations=q, charged_units=charge,
                           conditional_success_probability=wire(update.success_probability),
                           conditional_failure_probability=wire(update.failure_probability),
                           winner_proof_units_on_success_only=costs.winner_proof)
                available -= charge
                reached = bounded(reached*update.failure_probability)
                belief = update.posterior
            path.append(row)
            if belief is None:
                break
    report = {
        "schema": REPORT_SCHEMA, "request": model.request(), "scope": scope(),
        "source_binding": {"scope": "this research module only; not repository/build/runtime closure",
                           "quantum_posterior_policy.py_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        "objective": "maximize delivered-winner probability, then minimize expected budget spent",
        "arithmetic": "exact rational amplitudes, Bayes updates and Bellman comparisons",
        "initial_action": "pay-domain-setup" if started else "stop",
        "initial_setup_units_charged": costs.domain_setup if started else 0,
        "optimal_delivered_probability": wire(initial.delivered_probability),
        "expected_budget_spent": wire(total_spent),
        "persistent_single_domain_existence_ceiling": wire(1 - prior[0]),
        "existence_ceiling_scope": "only when no domain refresh occurs; not a W1 security bound",
        "chosen_policy_all_failures_path": path,
        "states_evaluated": states,
        "limits": {"domain_size": MAX_DOMAIN_SIZE, "iterations": MAX_ITERATIONS,
                   "processors": MAX_PROCESSORS, "budget": MAX_BUDGET,
                   "exact_fraction_bits": MAX_FRACTION_BITS, "states": max_states},
    }
    if len((json.dumps(report, sort_keys=True, indent=2) + "\n").encode()) > MAX_REPORT_BYTES:
        raise ValueError("REPORT_BYTE_LIMIT")
    return report


def recheck_report(model: Model, report: Any) -> dict:
    """Reject edited policies, probability promotions and substituted input/source."""
    if type(report) is not dict or type(report.get("limits")) is not dict:
        raise ValueError("REPORT_SCHEMA")
    max_states = report["limits"].get("states")
    integer(max_states, "STATE_LIMIT", MAX_STATES, 1)
    expected = solve(model, max_states=max_states)
    # Python's numeric equality equates false with 0 and true with 1. Those
    # are distinct wire claims, and must not pass a report integrity check.
    if (json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False)
            != json.dumps(expected, sort_keys=True, separators=(",", ":"), allow_nan=False)):
        raise ValueError("POSTERIOR_REPORT_MISMATCH")
    return expected


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def read_json(path: Path, limit: int = MAX_INPUT_BYTES) -> Any:
    # Opening a FIFO before checking its mode can block forever. Nonblocking
    # open makes the regular-file refusal effective before any input read.
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("REGULAR_JSON_FILE_REQUIRED")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            raw = source.read(limit + 1)
    finally:
        os.close(descriptor)
    if len(raw) > limit:
        raise ValueError("JSON_BYTE_LIMIT")

    def reject_number(_):
        raise ValueError("INTEGER_JSON_NUMBERS_REQUIRED")

    return json.loads(raw, object_pairs_hook=_unique, parse_float=reject_number,
                      parse_constant=reject_number)


def example_model(*, allow_refresh: bool = True) -> Model:
    return Model(4, binomial_prior(4, F(1, 4)), (0, 1, 2), 1, 20,
                 ResourceCosts(2, 1, 1, 1, 1, 2), allow_refresh)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--request", type=Path)
    source.add_argument("--example", action="store_true")
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args()
    try:
        model = parse_request(read_json(args.request)) if args.request else example_model()
        report = (recheck_report(model, read_json(args.verify, MAX_REPORT_BYTES)) if args.verify
                  else solve(model))
        print(json.dumps(report, sort_keys=True, indent=2))
        if args.require_qualified:
            print("REFUSED_UNPROVED_NATIVE_QUANTUM_SECURITY", file=sys.stderr)
            return 3
        return 0
    except (ValueError, TypeError, OSError, OverflowError, RecursionError) as error:
        print(f"INPUT_OR_MODEL_REJECTED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
