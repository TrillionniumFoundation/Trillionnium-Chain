"""Exact, conditional search probabilities and stationary renewal accounting.

This finite calculator does not implement a W1 attack, a state-preparation
circuit, a quantum oracle, a network process, or a lower bound. Probability
masses can describe a classical sampler or computational-basis probabilities
of a supplied quantum initial state. The latter do not specify its phases or
prove that preparation and reflection are available at the claimed cost.

The ideal a_C/f and a_Q/sqrt(f) comparison assumes fixed-cost independent
classical sampling and ideal amplitude amplification with the SAME declared
success probabilities, ignoring finite-iteration rounding and additive setup.
Complete repeated search-unit costs must include applicable membership,
preparation/reflection and uncomputation; success-only proofs belong outside
those units. Variable-time amplification and other algorithms are not modeled.

The renewal formula is P + E[C]/q + H. P is paid once per declared campaign;
C includes every outcome's attempt and restart costs; H is paid once after
success. Attempts must be independent and stationary and unsuccessful attempts
must return to the same initial search state. An ABANDON ends an attempt, not
the campaign. Adaptive choices, persistent unknown marked counts, retained
quantum progress, deadlines and honest-block interruptions need a different
process model. A cold-start calculation is not a compositional cost lower bound.

This is a bounded diagnostic: each reduced rational input and derived value
is limited to 512 bits in its numerator and denominator, with at most 4096
entries in any declared finite collection. These bounds are implementation
limits, not restrictions proved for real mining strategies. Success-contract
labels must agree before costs are compared; a matching label is still only a
caller assertion about the meaning of the successful event.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from enum import Enum
from fractions import Fraction
import hashlib
import json
from math import isqrt
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "trnm-normalized-search-cost-v1"
REPORT_SCHEMA = "trnm-normalized-search-cost-report-v1"
MAX_ENTRIES = 4096
MAX_FRACTION_BITS = 512
MAX_JSON_BYTES = 262144


def _label(value: Any, field: str) -> str:
    if type(value) is not str or not value or len(value) > 200 or value.strip() != value:
        raise ValueError(field)
    return value


def _fraction(value: Any, field: str, *, positive: bool = False) -> Fraction:
    if type(value) is not Fraction:
        raise ValueError(field)
    if max(value.numerator.bit_length(), value.denominator.bit_length()) > MAX_FRACTION_BITS:
        raise ValueError("FRACTION_BIT_LIMIT")
    if value < 0 or (positive and value == 0):
        raise ValueError(field)
    return value


def _probability(value: Any, field: str) -> Fraction:
    result = _fraction(value, field)
    if result > 1:
        raise ValueError(field)
    return result


def _wire(value: Fraction) -> dict[str, int]:
    _fraction(value, "EXACT_DERIVED_VALUE")
    return {"numerator": value.numerator, "denominator": value.denominator}


def _sum(values: Iterable[Fraction]) -> Fraction:
    total = Fraction(0)
    for value in values:
        total = _fraction(total + value, "EXACT_DERIVED_SUM")
    return total


def _scope() -> dict[str, Any]:
    # Fresh values prevent callers from mutating a shared authority statement.
    return {
        "schema": SCHEMA,
        "evidence": "conditional finite arithmetic on caller-supplied premises",
        "w1_quantum_attack_implemented": False,
        "quantum_state_preparation_implemented": False,
        "global_cost_lower_bound_proved": False,
        "composition_lower_bound_proved": False,
        "network_security_proved": False,
        "consensus_activation": False,
        "release_ready": False,
    }


class SamplingKind(Enum):
    CLASSICAL = "classical_sampling_distribution"
    QUANTUM = "quantum_computational_basis_probabilities"


@dataclass(frozen=True)
class NormalizedSearch:
    """A declared finite normalized measure, never a raw retained fraction."""

    kind: SamplingKind
    masses: tuple[tuple[str, Fraction], ...]
    marked: frozenset[str]
    success_contract: str

    def __post_init__(self) -> None:
        _label(self.success_contract, "SUCCESS_CONTRACT")
        if type(self.kind) is not SamplingKind:
            raise ValueError("SAMPLING_KIND")
        if type(self.masses) is not tuple or not 1 <= len(self.masses) <= MAX_ENTRIES:
            raise ValueError("FINITE_MASSES")
        labels = set()
        total = Fraction(0)
        for entry in self.masses:
            if type(entry) is not tuple or len(entry) != 2:
                raise ValueError("MASS_ENTRY")
            name, probability = entry
            _label(name, "MASS_LABEL")
            if name in labels:
                raise ValueError("DUPLICATE_MASS_LABEL")
            labels.add(name)
            total = _fraction(total + _probability(probability, "EXACT_PROBABILITY"),
                              "EXACT_PROBABILITY_SUM")
        if total != 1:
            raise ValueError("MASSES_NOT_NORMALIZED")
        if type(self.marked) is not frozenset or not self.marked <= labels:
            raise ValueError("MARKED_NOT_SUBSET")

    @property
    def success_probability(self) -> Fraction:
        return _sum(p for label, p in self.masses if label in self.marked)

    def report(self) -> dict[str, Any]:
        return {
            **_scope(), "kind": self.kind.value, "success_contract": self.success_contract,
            "masses": [{"label": name, "probability": _wire(p)} for name, p in self.masses],
            "marked": sorted(self.marked),
            "success_probability": _wire(self.success_probability),
            "normalization": "sum of all declared probability masses equals one exactly",
            "state_scope": "basis masses only; preparation, phases and reflection not constructed",
        }


@dataclass(frozen=True)
class UniformRestriction:
    baseline: NormalizedSearch
    restricted: NormalizedSearch

    def __post_init__(self) -> None:
        if type(self.baseline) is not NormalizedSearch or type(self.restricted) is not NormalizedSearch:
            raise ValueError("NORMALIZED_SEARCH_REQUIRED")
        if self.baseline.success_contract != self.restricted.success_contract:
            raise ValueError("SUCCESS_CONTRACT_MISMATCH")
        full = {name for name, _ in self.baseline.masses}
        kept = {name for name, _ in self.restricted.masses}
        if (self.baseline.kind is not self.restricted.kind or not kept <= full
                or self.restricted.marked != self.baseline.marked & kept):
            raise ValueError("INCONSISTENT_DOMAIN_RESTRICTION")
        if any(p != Fraction(1, len(search.masses))
               for search in (self.baseline, self.restricted) for _, p in search.masses):
            raise ValueError("UNIFORM_RESTRICTION_REQUIRES_UNIFORM_MASSES")

    @property
    def raw_domain_retention(self) -> Fraction:
        return Fraction(len(self.restricted.masses), len(self.baseline.masses))

    @property
    def marked_retention(self) -> Fraction | None:
        count = len(self.baseline.marked)
        return Fraction(len(self.restricted.marked), count) if count else None

    @property
    def success_ratio(self) -> Fraction | None:
        p0 = self.baseline.success_probability
        return _fraction(self.restricted.success_probability / p0, "EXACT_SUCCESS_RATIO") if p0 else None

    def report(self) -> dict[str, Any]:
        return {
            **_scope(), "success_contract": self.baseline.success_contract,
            "raw_domain_retention": _wire(self.raw_domain_retention),
            "marked_retention": None if self.marked_retention is None else _wire(self.marked_retention),
            "baseline_probability": _wire(self.baseline.success_probability),
            "restricted_probability": _wire(self.restricted.success_probability),
            "normalized_success_ratio": None if self.success_ratio is None else _wire(self.success_ratio),
            "restriction_cost": "not supplied; finding and sampling the subset are not free",
        }


def uniform_restriction(
    domain: tuple[str, ...], marked: frozenset[str], retained: frozenset[str],
    *, kind: SamplingKind = SamplingKind.CLASSICAL,
    success_contract: str = "finite-marked-event-v1",
) -> UniformRestriction:
    """Condition a uniform domain on a nonempty subset and renormalize it.

    f = (retained marked / all marked) / (retained domain / full domain)
    when the baseline contains a marked element. Finding this subset may itself
    require solving the search problem; this helper supplies no cheap algorithm.
    """
    if type(domain) is not tuple or not 1 <= len(domain) <= MAX_ENTRIES:
        raise ValueError("FINITE_DOMAIN")
    for name in domain:
        _label(name, "DOMAIN_LABEL")
    if len(set(domain)) != len(domain):
        raise ValueError("DUPLICATE_DOMAIN_LABEL")
    if type(retained) is not frozenset or not retained or not retained <= set(domain):
        raise ValueError("RETAINED_NOT_NONEMPTY_SUBSET")
    baseline = NormalizedSearch(kind, tuple((x, Fraction(1, len(domain))) for x in domain),
                                marked, success_contract)
    restricted = NormalizedSearch(
        kind, tuple((x, Fraction(1, len(retained))) for x in domain if x in retained),
        marked & retained, success_contract,
    )
    return UniformRestriction(baseline, restricted)


def exact_square_root(value: Fraction) -> Fraction:
    """Reject irrational results instead of rounding an advantage boundary."""
    _fraction(value, "EXACT_NONNEGATIVE_RADICAND")
    numerator, denominator = isqrt(value.numerator), isqrt(value.denominator)
    if numerator * numerator != value.numerator or denominator * denominator != value.denominator:
        raise ValueError("IRRATIONAL_SQUARE_ROOT_OUTSIDE_EXACT_MODEL")
    return Fraction(numerator, denominator)


@dataclass(frozen=True)
class IdealShortcutComparison:
    baseline_probability: Fraction
    shortcut_probability: Fraction
    classical_unit_cost_ratio: Fraction
    quantum_unit_cost_ratio: Fraction
    baseline_success_contract: str
    shortcut_success_contract: str

    def __post_init__(self) -> None:
        _label(self.baseline_success_contract, "SUCCESS_CONTRACT")
        _label(self.shortcut_success_contract, "SUCCESS_CONTRACT")
        if self.baseline_success_contract != self.shortcut_success_contract:
            raise ValueError("SUCCESS_CONTRACT_MISMATCH")
        for probability in (self.baseline_probability, self.shortcut_probability):
            if not _probability(probability, "EXACT_SUCCESS_PROBABILITY"):
                raise ValueError("ZERO_SUCCESS_PROBABILITY")
        _fraction(self.classical_unit_cost_ratio, "POSITIVE_EXACT_CLASSICAL_COST_RATIO", positive=True)
        _fraction(self.quantum_unit_cost_ratio, "POSITIVE_EXACT_QUANTUM_COST_RATIO", positive=True)
        exact_square_root(self.success_ratio)

    @property
    def success_ratio(self) -> Fraction:
        return _fraction(self.shortcut_probability / self.baseline_probability, "EXACT_SUCCESS_RATIO")

    @property
    def classical_relative_cost(self) -> Fraction:
        return _fraction(self.classical_unit_cost_ratio / self.success_ratio, "EXACT_CLASSICAL_RELATIVE_COST")

    @property
    def quantum_relative_cost(self) -> Fraction:
        return _fraction(self.quantum_unit_cost_ratio / exact_square_root(self.success_ratio),
                         "EXACT_QUANTUM_RELATIVE_COST")

    def report(self) -> dict[str, Any]:
        return {
            **_scope(), "model": "ideal-fixed-cost-search-scaling",
            "success_contract": self.baseline_success_contract,
            "baseline_probability": _wire(self.baseline_probability),
            "shortcut_probability": _wire(self.shortcut_probability),
            "normalized_success_ratio": _wire(self.success_ratio),
            "classical_unit_cost_ratio": _wire(self.classical_unit_cost_ratio),
            "quantum_unit_cost_ratio": _wire(self.quantum_unit_cost_ratio),
            "classical_relative_cost": _wire(self.classical_relative_cost),
            "quantum_relative_cost": _wire(self.quantum_relative_cost),
            "assumptions": [
                "same declared baseline and shortcut success probabilities for both categories",
                "classical independent sampling and ideal fixed-cost amplitude amplification",
                "all repeated sampling/oracle stages included in the supplied cost ratios",
                "state preparation, subset membership, reflection and uncomputation are caller premises",
                "no additive campaign setup, post-win proof, rounding, network interruption or variable-time speedup",
                "endpoint probabilities are formal scaling values, not exact Grover iteration counts",
            ],
        }


def ideal_shortcut_comparison(
    baseline: NormalizedSearch, shortcut: NormalizedSearch, *,
    a_classical: Fraction, a_quantum: Fraction,
) -> IdealShortcutComparison:
    if type(baseline) is not NormalizedSearch or type(shortcut) is not NormalizedSearch:
        raise ValueError("NORMALIZED_SEARCH_REQUIRED")
    if baseline.success_contract != shortcut.success_contract:
        raise ValueError("SUCCESS_CONTRACT_MISMATCH")
    p0, p1 = baseline.success_probability, shortcut.success_probability
    if not p0 or not p1:
        raise ValueError("ZERO_SUCCESS_PROBABILITY")
    _fraction(a_classical, "POSITIVE_EXACT_CLASSICAL_COST_RATIO", positive=True)
    _fraction(a_quantum, "POSITIVE_EXACT_QUANTUM_COST_RATIO", positive=True)
    exact_square_root(p1 / p0)
    return IdealShortcutComparison(p0, p1, a_classical, a_quantum,
                                   baseline.success_contract, shortcut.success_contract)


@dataclass(frozen=True)
class Cost:
    amount: Fraction
    unit: str

    def __post_init__(self) -> None:
        _fraction(self.amount, "EXACT_NONNEGATIVE_COST")
        _label(self.unit, "COST_UNIT")

    def report(self) -> dict[str, Any]:
        return {"amount": _wire(self.amount), "unit": self.unit}


def _same_unit(costs: tuple[Cost, ...]) -> str:
    if not costs or any(type(cost) is not Cost for cost in costs):
        raise ValueError("TYPED_COST_REQUIRED")
    if len({cost.unit for cost in costs}) != 1:
        raise ValueError("MIXED_COST_UNITS")
    return costs[0].unit


@dataclass(frozen=True)
class SearchUnitCosts:
    """Explicit costs per classical attempt or repeated coherent search unit.

    For quantum search, preparation means the preparation/reflection work that
    actually recurs in this unit, not campaign-only setup. A once-per-trial
    initialization belongs in that trial's cost in the renewal model below.
    Each zero is a caller assertion, not evidence of a free implementation.
    """

    kind: SamplingKind
    sampling_or_state_preparation: Cost
    predicate: Cost
    subset_membership: Cost
    phase_or_reflection: Cost
    uncomputation: Cost
    other_required: Cost

    def __post_init__(self) -> None:
        if type(self.kind) is not SamplingKind:
            raise ValueError("SEARCH_COST_KIND")
        _same_unit(self.components)
        if self.total.amount == 0:
            raise ValueError("ZERO_SEARCH_UNIT_COST")

    @property
    def components(self) -> tuple[Cost, ...]:
        return (self.sampling_or_state_preparation, self.predicate, self.subset_membership,
                self.phase_or_reflection, self.uncomputation, self.other_required)

    @property
    def total(self) -> Cost:
        return Cost(_sum(c.amount for c in self.components), self.components[0].unit)

    def report(self) -> dict[str, Any]:
        names = ("sampling_or_state_preparation", "predicate", "subset_membership",
                 "phase_or_reflection", "uncomputation", "other_required")
        return {**_scope(), "kind": self.kind.value,
                "components": {name: getattr(self, name).report() for name in names},
                "total": self.total.report()}


def compare_complete_search_units(
    baseline: NormalizedSearch, shortcut: NormalizedSearch, *,
    classical_baseline: SearchUnitCosts, classical_shortcut: SearchUnitCosts,
    quantum_baseline: SearchUnitCosts, quantum_shortcut: SearchUnitCosts,
) -> IdealShortcutComparison:
    units = (classical_baseline, classical_shortcut, quantum_baseline, quantum_shortcut)
    if any(type(cost) is not SearchUnitCosts for cost in units):
        raise ValueError("TYPED_SEARCH_UNITS_REQUIRED")
    if tuple(cost.kind for cost in units) != (SamplingKind.CLASSICAL, SamplingKind.CLASSICAL,
                                             SamplingKind.QUANTUM, SamplingKind.QUANTUM):
        raise ValueError("SEARCH_UNIT_CATEGORY")
    _same_unit(tuple(cost.total for cost in units))
    return ideal_shortcut_comparison(
        baseline, shortcut,
        a_classical=classical_shortcut.total.amount / classical_baseline.total.amount,
        a_quantum=quantum_shortcut.total.amount / quantum_baseline.total.amount,
    )


class OutcomeKind(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    ABANDON = "abandon_attempt_and_restart"


@dataclass(frozen=True)
class AttemptOutcome:
    """One mutually exclusive outcome in a caller-declared complete partition.

    attempt_cost includes the entire trial: initial state preparation, all
    queries, uncomputation, readout and candidate checks that actually occur.
    restart_cost is additional cost after an unsuccessful trial. There is no
    success-only proof field here, so that proof cannot silently repeat per query.
    """

    name: str
    kind: OutcomeKind
    probability: Fraction
    attempt_cost: Cost
    restart_cost: Cost

    def __post_init__(self) -> None:
        _label(self.name, "OUTCOME_NAME")
        if type(self.kind) is not OutcomeKind:
            raise ValueError("OUTCOME_KIND")
        _probability(self.probability, "EXACT_OUTCOME_PROBABILITY")
        _same_unit((self.attempt_cost, self.restart_cost))
        if self.probability and not self.attempt_cost.amount:
            raise ValueError("POSITIVE_PROBABILITY_ATTEMPT_COST_REQUIRED")
        if self.kind is OutcomeKind.SUCCESS and self.restart_cost.amount:
            raise ValueError("SUCCESS_CANNOT_RESTART")


@dataclass(frozen=True)
class RenewalPremises:
    """Explicit caller assertions, not facts established by this calculator."""

    independent_stationary_attempts: bool
    unsuccessful_attempts_return_same_state: bool
    no_deadline_or_external_interruptions: bool

    def __post_init__(self) -> None:
        if any(value is not True for value in (
            self.independent_stationary_attempts,
            self.unsuccessful_attempts_return_same_state,
            self.no_deadline_or_external_interruptions,
        )):
            raise ValueError("OUTSIDE_STATIONARY_RENEWAL_MODEL")


@dataclass(frozen=True)
class RenewalTask:
    name: str
    outcomes: tuple[AttemptOutcome, ...]
    success_only_proof: Cost
    success_event: str

    def __post_init__(self) -> None:
        _label(self.name, "TASK_NAME")
        _label(self.success_event, "SUCCESS_EVENT")
        if (type(self.outcomes) is not tuple or not 1 <= len(self.outcomes) <= MAX_ENTRIES
                or any(type(o) is not AttemptOutcome for o in self.outcomes)):
            raise ValueError("FINITE_TYPED_OUTCOMES_REQUIRED")
        if len({outcome.name for outcome in self.outcomes}) != len(self.outcomes):
            raise ValueError("DUPLICATE_OUTCOME_NAME")
        if _sum(o.probability for o in self.outcomes) != 1:
            raise ValueError("OUTCOME_PARTITION_NOT_NORMALIZED")
        _same_unit((self.success_only_proof,) + tuple(
            cost for o in self.outcomes for cost in (o.attempt_cost, o.restart_cost)))
        if self.success_probability == 0:
            raise ValueError("ZERO_SUCCESS_PROBABILITY")

    @property
    def success_probability(self) -> Fraction:
        return _sum(o.probability for o in self.outcomes if o.kind is OutcomeKind.SUCCESS)

    @property
    def expected_attempt_cost(self) -> Cost:
        return Cost(_sum(o.probability * (o.attempt_cost.amount + o.restart_cost.amount)
                         for o in self.outcomes), self.success_only_proof.unit)

    @property
    def repeated_cost_until_success(self) -> Cost:
        return Cost(self.expected_attempt_cost.amount / self.success_probability, self.success_only_proof.unit)

    @property
    def total_excluding_campaign_preparation(self) -> Cost:
        return Cost(self.repeated_cost_until_success.amount + self.success_only_proof.amount,
                    self.success_only_proof.unit)

    def report(self) -> dict[str, Any]:
        q = self.success_probability
        return {
            **_scope(), "task": self.name, "success_event": self.success_event,
            "success_probability": _wire(q),
            "expected_attempts": _wire(1 / q),
            "expected_attempt_cost": self.expected_attempt_cost.report(),
            "repeated_cost_until_success": self.repeated_cost_until_success.report(),
            "success_only_proof_once": self.success_only_proof.report(),
            "total_excluding_campaign_preparation": self.total_excluding_campaign_preparation.report(),
            "outcomes": [{
                "name": o.name, "kind": o.kind.value, "probability": _wire(o.probability),
                "attempt_cost": o.attempt_cost.report(), "restart_cost": o.restart_cost.report(),
                "expected_occurrences_until_success": _wire(o.probability / q),
                "expected_cost_until_success": Cost(
                    o.probability * (o.attempt_cost.amount + o.restart_cost.amount) / q,
                    o.attempt_cost.unit,
                ).report(),
            } for o in self.outcomes],
        }


@dataclass(frozen=True)
class RenewalCampaignCost:
    preparation: Cost
    tasks: tuple[RenewalTask, ...]
    premises: RenewalPremises

    def __post_init__(self) -> None:
        if type(self.premises) is not RenewalPremises:
            raise ValueError("EXPLICIT_RENEWAL_PREMISES_REQUIRED")
        if (type(self.tasks) is not tuple or not 1 <= len(self.tasks) <= MAX_ENTRIES
                or any(type(task) is not RenewalTask for task in self.tasks)):
            raise ValueError("FINITE_RENEWAL_TASKS_REQUIRED")
        if len({task.name for task in self.tasks}) != len(self.tasks):
            raise ValueError("DUPLICATE_TASK_NAME")
        _same_unit((self.preparation,) + tuple(t.success_only_proof for t in self.tasks))

    @property
    def total(self) -> Cost:
        return Cost(self.preparation.amount + _sum(
            t.total_excluding_campaign_preparation.amount for t in self.tasks),
            self.preparation.unit)

    def report(self) -> dict[str, Any]:
        return {
            **_scope(), "model": "independent-stationary-renewal",
            "formula": "P + sum_tasks(E[C]/q + H)",
            "shared_preparation_once": self.preparation.report(),
            "preparation_charge_count": 1,
            "tasks": [task.report() for task in self.tasks],
            "expected_total_cost": self.total.report(),
            "assumptions": [
                "outcomes are a declared exhaustive mutually exclusive partition of each attempt",
                "independent stationary attempts conditional on the declared preparation",
                "every unsuccessful attempt returns to the same state with its restart cost charged",
                "success-only proof is produced exactly once after a successful attempt",
                "proof completion is guaranteed after success; otherwise its failures must enter the outcome partition",
                "no state-dependent task choice, cache evolution, finite deadline or honest-block interruption",
                "shared setup is charged once; cold task costs do not imply any composition lower bound",
            ],
        }


def stationary_renewal_cost(
    task: RenewalTask, *, preparation: Cost, premises: RenewalPremises,
) -> RenewalCampaignCost:
    """One task, one shared preparation, all failed attempts, one success tail."""
    return RenewalCampaignCost(preparation, (task,), premises)


def stationary_shared_campaign_cost(
    tasks: tuple[RenewalTask, ...], *, preparation: Cost, premises: RenewalPremises,
) -> RenewalCampaignCost:
    """Sum declared per-task renewal expectations with shared preparation once.

    This does not derive a warm-task law from cold observations or support
    adaptive/correlated state evolution. Each supplied task law must remain
    valid throughout the declared campaign; setup effects are a caller premise.
    """
    return RenewalCampaignCost(preparation, tasks, premises)


def source_binding() -> list[dict[str, str]]:
    """Identify these local sources, without asserting authenticated execution."""
    directory = Path(__file__).resolve().parent
    return [{"path": "formal/pon-nakamoto-v1/" + name,
             "sha256": hashlib.sha256((directory / name).read_bytes()).hexdigest()}
            for name in ("normalized_search_cost.py", "test_normalized_search_cost.py")]


def build_report() -> dict[str, Any]:
    """Four deterministic examples, each using only explicitly declared inputs."""
    event = "finite-marked-event-v1"
    classical, quantum = SamplingKind.CLASSICAL, SamplingKind.QUANTUM

    def measure(p: Fraction) -> NormalizedSearch:
        return NormalizedSearch(classical, (("win", p), ("lose", 1 - p)), frozenset({"win"}), event)

    def resource(amount: int) -> Cost:
        return Cost(Fraction(amount), "declared_resource_units")

    def unit(kind: SamplingKind, predicate: int, preparation: int = 0,
             uncompute: int = 0) -> SearchUnitCosts:
        return SearchUnitCosts(kind, resource(preparation), resource(predicate), resource(0),
                               resource(0), resource(uncompute), resource(0))

    domain = tuple(str(index) for index in range(8))
    restriction = uniform_restriction(domain, frozenset({"0", "1", "2", "3"}),
                                      frozenset({"0", "4"}))
    winners_only = uniform_restriction(domain, frozenset({"0", "1"}), frozenset({"0"}), kind=quantum)
    baseline, shortcut = measure(Fraction(1, 4)), measure(Fraction(1, 16))
    comparison = ideal_shortcut_comparison(baseline, shortcut,
                                           a_classical=Fraction(2, 5), a_quantum=Fraction(2, 5))
    classic_baseline, classic_shortcut = unit(classical, 10), unit(classical, 4)
    quantum_baseline = unit(quantum, 4, preparation=2, uncompute=4)
    quantum_incomplete = unit(quantum, 4)
    quantum_complete = unit(quantum, 4, preparation=1, uncompute=1)
    comparisons = [compare_complete_search_units(
        baseline, shortcut, classical_baseline=classic_baseline, classical_shortcut=classic_shortcut,
        quantum_baseline=quantum_baseline, quantum_shortcut=candidate,
    ).report() for candidate in (quantum_incomplete, quantum_complete)]
    outcomes = (
        AttemptOutcome("win", OutcomeKind.SUCCESS, Fraction(1, 4), resource(8), resource(0)),
        AttemptOutcome("failed", OutcomeKind.FAILURE, Fraction(1, 2), resource(4), resource(2)),
        AttemptOutcome("abandoned", OutcomeKind.ABANDON, Fraction(1, 4), resource(2), resource(6)),
    )
    tasks = tuple(RenewalTask(name, outcomes, resource(11),
                             "one valid winner with guaranteed proof completion") for name in ("first", "second"))
    assertions = RenewalPremises(True, True, True)
    single = stationary_renewal_cost(tasks[0], preparation=resource(7), premises=assertions)
    shared = stationary_shared_campaign_cost(tasks, preparation=resource(7), premises=assertions)
    separate = Cost(_sum(stationary_renewal_cost(task, preparation=resource(7), premises=assertions).total.amount
                         for task in tasks), "declared_resource_units")
    return {
        "schema": REPORT_SCHEMA, "scope": _scope(),
        "diagnostic_bounds": {"max_entries": MAX_ENTRIES, "max_fraction_bits": MAX_FRACTION_BITS},
        "source_binding": source_binding(),
        "cases": [
            {"case_id": "normalized-retention-and-winners-only",
             "input": {"restricted_example": {"baseline": restriction.baseline.report(),
                                                "restricted": restriction.restricted.report()},
                       "winners_only_example": {"baseline": winners_only.baseline.report(),
                                                "restricted": winners_only.restricted.report()}},
             "result": {"restricted_example": restriction.report(), "winners_only_example": winners_only.report()}},
            {"case_id": "classical-slower-quantum-faster-ideal",
             "input": {"baseline": baseline.report(), "shortcut": shortcut.report(),
                       "a_classical": _wire(Fraction(2, 5)), "a_quantum": _wire(Fraction(2, 5))},
             "result": comparison.report()},
            {"case_id": "required-quantum-stages-reverse-apparent-advantage",
             "input": {"baseline": baseline.report(), "shortcut": shortcut.report(),
                       "classical_baseline": classic_baseline.report(),
                       "classical_shortcut": classic_shortcut.report(),
                       "quantum_baseline": quantum_baseline.report(),
                       "quantum_incomplete_zero_stage_claim": quantum_incomplete.report(),
                       "quantum_with_required_stages": quantum_complete.report()},
             "result": {"incomplete_cost_assertion": comparisons[0], "with_required_stages": comparisons[1]}},
            {"case_id": "renewal-failures-proof-tail-and-shared-preparation",
             "input": {"preparation": resource(7).report(),
                       "tasks": [task.report() for task in tasks],
                       "premises": {"independent_stationary_attempts": True,
                                    "unsuccessful_attempts_return_same_state": True,
                                    "no_deadline_or_external_interruptions": True}},
             "result": {"single_task": single.report(), "shared_campaign": shared.report(),
                        "two_separate_cold_campaigns": separate.report()}},
        ],
    }


def _same_document(actual: Any, expected: Any, location: str = "report") -> None:
    """Compare exact JSON types too: False must never pass as integer zero."""
    if type(actual) is not type(expected):
        raise ValueError("REPORT_TYPE_CHANGED:" + location)
    if type(expected) is dict:
        if any(type(key) is not str for key in actual) or set(actual) != set(expected):
            raise ValueError("REPORT_FIELDS_CHANGED:" + location)
        for key, value in expected.items():
            _same_document(actual[key], value, location + "." + key)
    elif type(expected) is list:
        if len(actual) != len(expected):
            raise ValueError("REPORT_LENGTH_CHANGED:" + location)
        for index, (left, right) in enumerate(zip(actual, expected)):
            _same_document(left, right, location + "." + str(index))
    elif actual != expected:
        raise ValueError("REPORT_VALUE_CHANGED:" + location)


def verify_report(report: Any) -> dict[str, Any]:
    """Recompute all fixed inputs, cases and local hashes, rejecting any change.

    This is deterministic replay with the same arithmetic implementation, not
    an independent lower-bound proof or authenticated execution attestation.
    No caller-supplied security flag can be promoted by this verification.
    """
    expected = build_report()
    _same_document(report, expected)
    return {"verification": "PASS", "case_ids": [case["case_id"] for case in expected["cases"]],
            "scope": _scope(), "verification_scope": "fixed-example arithmetic and local-source replay only"}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _json_integer(raw: str) -> int:
    if len(raw) > 156:
        raise ValueError("JSON_INTEGER_BIT_LIMIT")
    result = int(raw)
    if result.bit_length() > MAX_FRACTION_BITS:
        raise ValueError("JSON_INTEGER_BIT_LIMIT")
    return result


def _reject_json_float(raw: str) -> None:
    raise ValueError("JSON_FLOAT_OR_NONFINITE")


def load_json(path: Path) -> Any:
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("JSON_BYTE_LIMIT")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_int=_json_integer, parse_float=_reject_json_float,
                          parse_constant=_reject_json_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("JSON_ENCODING") from error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--output", type=Path, help="Create a fixed demonstration report; refuse overwrite")
    group.add_argument("--verify", type=Path, help="Recompute and verify a saved fixed demonstration report")
    args = parser.parse_args()
    report = verify_report(load_json(args.verify)) if args.verify else build_report()
    text = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
