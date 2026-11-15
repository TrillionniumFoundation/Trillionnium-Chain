"""Exact conditional work-scale arithmetic; no native or quantum qualification.

The companion WORK_SCALE_SECURITY_CONTRACT_V1.md proves the abstract crossing
lemma and names the missing resource-to-process and fork-accounting premises.
Finite toy laws here are NOT inferred from W1 or from an observed average rate.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
from functools import lru_cache
import hashlib
import json
from math import isqrt
from pathlib import Path
from typing import Iterable

from work_query_bound import parameters


BASE_COMMIT = "3d1b6507671ec694ce58e86d4063a125c8deeb66"
HERE = Path(__file__).resolve().parent
SOURCE_FILES = (
    "work_scale_contract.py",
    "test_work_scale_contract.py",
    "WORK_SCALE_SECURITY_CONTRACT_V1.md",
    "work_query_bound.py",
)
POLICIES = ("fixed-target", "absolute-target-band", "fixed-p-variable-units")


def natural(value: int, name: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < int(positive):
        raise ValueError(name)
    return value


def rational(value: Fraction, name: str, *, positive: bool = False) -> Fraction:
    if type(value) is not Fraction or value < 0 or (positive and value == 0):
        raise ValueError(name)
    return value


def sqrt_exact(value: Fraction) -> Fraction:
    """Reject irrational examples rather than silently certify rounded bounds."""
    rational(value, "RADICAND")
    a, b = isqrt(value.numerator), isqrt(value.denominator)
    if a * a != value.numerator or b * b != value.denominator:
        raise ValueError("NON_RATIONAL_SQUARE_ROOT")
    return Fraction(a, b)


def target_for_difficulty(difficulty: int, bits: int = 256) -> int:
    natural(difficulty, "DIFFICULTY", positive=True)
    if type(bits) is not int or not 2 <= bits <= 256:
        raise ValueError("BITS")
    modulus = 1 << bits
    if modulus % difficulty:
        raise ValueError("NONINTEGRAL_TARGET")
    target = modulus // difficulty - 1
    parameters(target, bits)
    return target


@dataclass(frozen=True)
class Context:
    branch: str
    anchor_id: str
    target: int
    units: int


@dataclass(frozen=True)
class Scope:
    """A predeclared experiment profile, not an authenticated consensus anchor.

    Every compared fork uses this *same* object. Branch-local configuration
    must not be used to construct a new scope after seeing a branch's target.
    """

    policy: str
    anchor_id: str
    reference_target: int
    hardest_target: int
    easiest_target: int
    minimum_units: int = 1
    maximum_units: int = 1
    bits: int = 256

    def __post_init__(self) -> None:
        if self.policy not in POLICIES:
            raise ValueError("POLICY")
        if type(self.anchor_id) is not str or not self.anchor_id:
            raise ValueError("ANCHOR_ID")
        for target in (self.reference_target, self.hardest_target, self.easiest_target):
            parameters(target, self.bits)
        if not self.hardest_target <= self.reference_target <= self.easiest_target:
            raise ValueError("TARGET_RANGE")
        natural(self.minimum_units, "MINIMUM_UNITS", positive=True)
        natural(self.maximum_units, "MAXIMUM_UNITS", positive=True)
        if self.minimum_units > self.maximum_units:
            raise ValueError("UNIT_RANGE")
        if self.policy != "absolute-target-band" and not (
            self.hardest_target == self.reference_target == self.easiest_target
        ):
            raise ValueError("TARGET_NOT_FIXED")
        if self.policy != "fixed-p-variable-units" and not (
            self.minimum_units == self.maximum_units == 1
        ):
            raise ValueError("UNITS_NOT_ONE")

    def check(self, contexts: Iterable[Context]) -> tuple[Context, ...]:
        rows = tuple(contexts)
        if not rows:
            raise ValueError("EMPTY_COMPARISON")
        for row in rows:
            if type(row) is not Context or type(row.branch) is not str or not row.branch:
                raise ValueError("CONTEXT")
            if row.anchor_id != self.anchor_id:
                raise ValueError("ANCHOR_REBINDING")
            parameters(row.target, self.bits)
            natural(row.units, "UNITS", positive=True)
            if not self.hardest_target <= row.target <= self.easiest_target:
                raise ValueError("OUTSIDE_ABSOLUTE_TARGET_BAND")
            if not self.minimum_units <= row.units <= self.maximum_units:
                raise ValueError("OUTSIDE_UNIT_RANGE")
        return rows

    def difficulty_ratio(self) -> Fraction:
        return Fraction(self.easiest_target + 1, self.hardest_target + 1)


@dataclass(frozen=True)
class CostPoint:
    probability: Fraction
    difficulty: Fraction
    credited_work: int
    classical_winner_cost: Fraction
    quantum_winner_cost: Fraction

    @property
    def classical_efficiency(self) -> Fraction:
        return self.credited_work / self.classical_winner_cost

    @property
    def quantum_efficiency(self) -> Fraction:
        return self.credited_work / self.quantum_winner_cost


def cost_point(target: int, units: int, *, quantum_exponent: Fraction = Fraction(1),
               quantum_coefficient: Fraction = Fraction(1),
               quantum_linear_tail: Fraction = Fraction(0), bits: int = 256) -> CostPoint:
    """Idealized success costs C_C=u*D, C_Q=a*u**alpha*sqrt(D)+b*u.

    Only alpha=1 and alpha=1/2 with exact rational square roots are evaluated.
    These are caller assumptions for a complete successful search, not measured
    gates, a lower bound, or the optimal interrupted/parallel quantum strategy.
    A positive b must refer to a separately justified nonreusable accepted-block
    cost in the SAME additive resource as a; seconds and gates cannot be added.
    """
    modulus, weight = parameters(target, bits)
    natural(units, "UNITS", positive=True)
    rational(quantum_coefficient, "QUANTUM_COEFFICIENT", positive=True)
    rational(quantum_linear_tail, "LINEAR_TAIL")
    if type(quantum_exponent) is not Fraction or quantum_exponent not in (
        Fraction(1), Fraction(1, 2)
    ):
        raise ValueError("SUPPORTED_EXACT_EXPONENT")
    difficulty = Fraction(modulus, target + 1)
    quantum_units = Fraction(units) if quantum_exponent == 1 else sqrt_exact(Fraction(units))
    return CostPoint(
        Fraction(target + 1, modulus), difficulty, units * weight,
        units * difficulty,
        quantum_coefficient * quantum_units * sqrt_exact(difficulty)
        + quantum_linear_tail * units,
    )


def reuse_counterexample(units: int, winners: int) -> Fraction:
    """Relative credit/resource for cost u+(k-1), versus u=1, for k winners.

    k=1 costs exactly u. Across k winners the first preparation is reused.
    This is a logical cost-model counterexample, not a legal W1 construction.
    """
    natural(units, "UNITS", positive=True)
    natural(winners, "WINNERS", positive=True)
    return Fraction(winners * units, units + winners - 1)


@dataclass(frozen=True)
class StepLaw:
    """A specified conditional law for X = adversarial weight - honest barrier.

    The honest barrier is a hypothetical fork-accounting quantity. It is NOT
    the sum of all honest blocks, nor automatically the observed public growth.
    """

    name: str
    outcomes: tuple[tuple[int, Fraction], ...]

    def __post_init__(self) -> None:
        if (type(self.name) is not str or not self.name
                or type(self.outcomes) is not tuple or not self.outcomes):
            raise ValueError("LAW")
        seen = set()
        for outcome in self.outcomes:
            if type(outcome) is not tuple or len(outcome) != 2:
                raise ValueError("LAW_OUTCOME")
            step, probability = outcome
            if type(step) is not int or not -4096 <= step <= 4096 or step in seen:
                raise ValueError("LAW_STEP")
            rational(probability, "LAW_PROBABILITY", positive=True)
            seen.add(step)
        if sum(p for _, p in self.outcomes) != 1:
            raise ValueError("LAW_TOTAL")

    @property
    def mean(self) -> Fraction:
        return sum((x * p for x, p in self.outcomes), Fraction(0))

    def pgf(self, z: Fraction) -> Fraction:
        rational(z, "EXPONENTIAL_BASE", positive=True)
        if z <= 1:
            raise ValueError("EXPONENTIAL_BASE")
        return sum((p * z ** x for x, p in self.outcomes), Fraction(0))


@dataclass(frozen=True)
class ConditionalEnvelope:
    """Verify a finite menu of assumed laws, including adaptive mixtures.

    Actual protocol security requires that every reachable conditional history
    obey this envelope. Merely listing, fitting or testing these laws does not
    establish that premise. A failed law is refused even if its mean is negative.
    """

    laws: tuple[StepLaw, ...]
    z: Fraction

    def __post_init__(self) -> None:
        if (type(self.laws) is not tuple or not self.laws
                or any(type(law) is not StepLaw for law in self.laws)):
            raise ValueError("LAW_MENU")
        if len({law.name for law in self.laws}) != len(self.laws):
            raise ValueError("DUPLICATE_LAW")
        for law in self.laws:
            if law.pgf(self.z) > 1:
                raise ValueError("CONDITIONAL_MOMENT_EXCEEDS_ONE:" + law.name)

    def crossing_bound(self, observed_gap: int, *, hidden_inventory: int = 0,
                       network_margin: int = 0, attack_starts: int = 1,
                       premise_failure: Fraction = Fraction(0)) -> Fraction:
        """Use a GLOBAL bound on the union of premise failures over all starts.

        Per-start failure bounds must be combined before this call. The moment
        premise must hold for the dominating process, or a justified process
        stopped/coupled before failure; conditioning on an eventual good event
        alone need not preserve a supermartingale.
        """
        for value, name in ((observed_gap, "GAP"), (hidden_inventory, "INVENTORY"),
                            (network_margin, "NETWORK_MARGIN")):
            natural(value, name)
        natural(attack_starts, "ATTACK_STARTS", positive=True)
        rational(premise_failure, "PREMISE_FAILURE")
        if premise_failure > 1:
            raise ValueError("PREMISE_FAILURE")
        deficit = observed_gap - hidden_inventory - network_margin
        if deficit <= 0:
            return Fraction(1)
        return min(Fraction(1), premise_failure + attack_starts / self.z ** deficit)

    def minimum_gap(self, risk: Fraction, *, hidden_inventory: int = 0,
                    network_margin: int = 0, attack_starts: int = 1,
                    maximum: int = 4096) -> int:
        rational(risk, "RISK", positive=True)
        natural(maximum, "MAXIMUM", positive=True)
        if risk >= 1 or maximum > 4096:
            raise ValueError("RISK_OR_FINITE_CAP")
        for gap in range(maximum + 1):
            if self.crossing_bound(gap, hidden_inventory=hidden_inventory,
                                   network_margin=network_margin,
                                   attack_starts=attack_starts) <= risk:
                return gap
        raise ValueError("FINITE_GAP_SEARCH_EXHAUSTED")


def adaptive_crossing_probability(laws: tuple[StepLaw, ...], deficit: int,
                                  horizon: int) -> Fraction:
    """Exact finite MDP over a stated law menu; NOT a native chain simulator.

    At every step an adversary may choose a new law based on the past. This
    backwards recursion independently checks the exponential upper bound.
    No resource fairness, quantum completeness or network mapping is inferred.
    """
    natural(deficit, "DEFICIT", positive=True)
    natural(horizon, "HORIZON")
    if horizon > 64 or deficit > 4096 or not laws or len(laws) > 16:
        raise ValueError("FINITE_MDP_CAP")
    if any(type(law) is not StepLaw for law in laws):
        raise ValueError("LAW_MENU")

    @lru_cache(maxsize=None)
    def solve(left: int, gap: int) -> Fraction:
        if gap <= 0:
            return Fraction(1)
        if left == 0:
            return Fraction(0)
        return max(sum((p * solve(left - 1, gap - x) for x, p in law.outcomes),
                       Fraction(0)) for law in laws)

    return solve(horizon, deficit)


def toy_laws() -> tuple[StepLaw, StepLaw, StepLaw]:
    small = StepLaw("unit-jumps", ((1, Fraction(2, 5)), (-1, Fraction(3, 5))))
    idle = StepLaw("unit-jumps-with-idle", (
        (1, Fraction(3, 10)), (-1, Fraction(1, 2)), (0, Fraction(1, 5)),
    ))
    burst = StepLaw("eight-unit-burst", (
        (8, Fraction(1, 20)), (-1, Fraction(3, 5)), (0, Fraction(7, 20)),
    ))
    return small, idle, burst


def comparison_rows() -> list[dict]:
    reference = target_for_difficulty(16)
    scopes = (
        Scope("fixed-target", "experiment-global-v1", reference, reference, reference),
        Scope("absolute-target-band", "experiment-global-v1", reference,
              target_for_difficulty(256), reference),
        Scope("fixed-p-variable-units", "experiment-global-v1", reference,
              reference, reference, 1, 256),
    )
    output = []
    for scope in scopes:
        points = [(16, 1)]
        if scope.policy == "absolute-target-band":
            points = [(difficulty, 1) for difficulty in (16, 64, 256)]
        elif scope.policy == "fixed-p-variable-units":
            points = [(16, units) for units in (1, 4, 16, 64, 256)]
        for alpha, tail in ((Fraction(1), Fraction(0)),
                            (Fraction(1, 2), Fraction(0)),
                            (Fraction(1, 2), Fraction(1, 16))):
            baseline = cost_point(reference, 1, quantum_exponent=alpha,
                                  quantum_coefficient=Fraction(1, 4),
                                  quantum_linear_tail=tail)
            for difficulty, units in points:
                context = Context("compared-fork", scope.anchor_id,
                                  target_for_difficulty(difficulty), units)
                scope.check((context,))
                point = cost_point(context.target, units, quantum_exponent=alpha,
                                   quantum_coefficient=Fraction(1, 4),
                                   quantum_linear_tail=tail)
                output.append({
                    "policy": scope.policy, "difficulty": difficulty, "units": units,
                    "probability": str(point.probability), "quantum_exponent": str(alpha),
                    "quantum_linear_tail": str(tail),
                    "credited_work": point.credited_work,
                    "classical_normalized_efficiency": str(
                        point.classical_efficiency / baseline.classical_efficiency),
                    "quantum_normalized_efficiency": str(
                        point.quantum_efficiency / baseline.quantum_efficiency),
                    "global_difficulty_ratio": str(scope.difficulty_ratio()),
                })
    return output


def build_report() -> dict:
    small, idle, burst = toy_laws()
    ordinary = ConditionalEnvelope((small, idle), Fraction(3, 2))
    with_bursts = ConditionalEnvelope((small, idle, burst), Fraction(17, 16))
    risk = Fraction(1, 1_000_000)
    return {
        "schema": "pon-work-scale-conditional-arithmetic-v1",
        "starting_integration_commit": BASE_COMMIT,
        "source_binding": "sha256-of-current-listed-files-not-a-native-runtime-attestation",
        "source_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                          for name in SOURCE_FILES},
        "claims": {
            "native_consensus_changed": False,
            "w1_minimum_cost_proved": False,
            "quantum_hardware_measured": False,
            "native_fork_accounting_proved": False,
            "conditional_laws_verified_for_w1": False,
            "common_prefix_qualified": False,
            "chain_growth_qualified": False,
            "chain_quality_qualified": False,
            "production_consensus_activation": False,
            "release_ready": False,
        },
        "unknown_resources": {"physical_qubits": None, "quantum_seconds": None,
                              "minimum_accepted_block_cost": None},
        "comparison": comparison_rows(),
        "cross_winner_reuse_counterexample": {
            "assumed_cost": "u+k-1", "units": 256,
            "single_winner_amplification": str(reuse_counterexample(256, 1)),
            "256_winner_amplification": str(reuse_counterexample(256, 256)),
            "is_w1_attack": False,
        },
        "same_mean_different_tail": {
            "unit_mean": str(small.mean), "burst_mean": str(burst.mean),
            "unit_pgf_at_3_over_2": str(small.pgf(Fraction(3, 2))),
            "burst_pgf_at_3_over_2": str(burst.pgf(Fraction(3, 2))),
            "burst_pgf_at_17_over_16": str(burst.pgf(Fraction(17, 16))),
            "burst_first_step_crossing_gap_8": "1/20",
            "invalidly_transferred_unit_bound_gap_8": str(Fraction(2, 3) ** 8),
        },
        "abstract_crossing_examples": {
            "premises": "assumed conditional law menu and external fork accounting",
            "risk_target": str(risk),
            "unit_jump_gap": ordinary.minimum_gap(risk),
            "unit_jump_gap_with_inventory_5_and_margin_3": ordinary.minimum_gap(
                risk, hidden_inventory=5, network_margin=3),
            "unit_jump_gap_for_100_attack_starts": ordinary.minimum_gap(
                risk, attack_starts=100),
            "burst_menu_gap": with_bursts.minimum_gap(risk),
            "unit_menu_exact_12_step_crossing_gap_4": str(
                adaptive_crossing_probability((small, idle), 4, 12)),
            "unit_menu_anytime_bound_gap_4": str(ordinary.crossing_bound(4)),
            "units_are": "normalized weighted deficit; not confirmations or seconds",
        },
        "research_gate": "HOLD-missing-accepted-work-tail-and-native-fork-reduction",
    }


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def verify_report(path: Path) -> None:
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("REPORT_TOO_LARGE")
    parsed = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    # Python equality conflates False with 0 and integer 1 with float 1.0.
    # Canonical JSON equality preserves those security-relevant type choices.
    if json.dumps(parsed, sort_keys=True, allow_nan=False) != json.dumps(
        build_report(), sort_keys=True, allow_nan=False
    ):
        raise ValueError("REPORT_SOURCE_OR_RESULT_MISMATCH")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", type=Path)
    group.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.verify is not None:
        verify_report(args.verify)
        print("PASS: exact conditional arithmetic and source hashes; all qualification gates remain closed")
    else:
        payload = json.dumps(build_report(), indent=2, sort_keys=True) + "\n"
        with args.out.open("x", encoding="utf-8") as handle:
            handle.write(payload)
        print("WROTE: conditional arithmetic only; no W1 security certificate")


if __name__ == "__main__":
    main()
