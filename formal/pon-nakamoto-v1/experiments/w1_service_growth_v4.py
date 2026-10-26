"""Conditional service, visible-work and private-overtake arithmetic.

This is not a native execution simulator or a production parameter certificate.
Inputs are hypotheses: the program cannot establish physical throughput, a
resource-to-query conversion, queue fairness, SHA coupling, or block visibility.
All probabilities and service quantities use exact rational arithmetic.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import json

MAX_EXACT_EXPONENT = 4096
MAX_EXACT_STAGES = 128


def natural(value: int, name: str, positive: bool = False) -> int:
    if type(value) is not int or value < int(positive):
        raise ValueError(name)
    return value


def rational(value: Fraction | int, name: str, positive: bool = False) -> Fraction:
    if type(value) not in (int, Fraction) or value < 0 or (positive and value == 0):
        raise ValueError(name)
    return Fraction(value)


def probability(value: Fraction | int, name: str) -> Fraction:
    result = rational(value, name)
    if result > 1:
        raise ValueError(name)
    return result


@dataclass(frozen=True)
class LotteryEnvelope:
    bits: int
    exposure_cap: int

    def __post_init__(self) -> None:
        natural(self.bits, 'bits', True)
        natural(self.exposure_cap, 'exposure_cap', True)
        if not 2 <= self.bits <= 256 or self.exposure_cap > self.space:
            raise ValueError('lottery_envelope')

    @property
    def space(self) -> int:
        return 1 << self.bits

    @property
    def rho(self) -> Fraction:
        return Fraction(self.space, self.space - self.exposure_cap + 1)

    def target(self, target: int) -> int:
        natural(target, 'target', True)
        if target > self.space // 2 - 1:
            raise ValueError('target')
        return target

    def weight(self, target: int) -> int:
        return self.space // (self.target(target) + 1)

    def lower_probability(self, target: int) -> Fraction:
        numerator = max(0, self.target(target) + 2 - self.exposure_cap)
        return Fraction(numerator, self.space - self.exposure_cap + 1)


@dataclass(frozen=True)
class HonestSlot:
    """Predeclared target range and attempts completed unless an earlier hit.

    One selected parent and its target remain fixed inside a slot. Between slots
    they may adapt to the complete past. The target interval bounds all choices;
    it is not chosen after observing the successful target or a DAA history.
    """
    attempts: int
    target_floor: int
    target_ceiling: int

    def quantities(self, lottery: LotteryEnvelope) -> tuple[Fraction, int]:
        natural(self.attempts, 'attempts')
        lottery.target(self.target_floor)
        lottery.target(self.target_ceiling)
        if self.target_floor > self.target_ceiling:
            raise ValueError('target_range')
        if self.attempts > MAX_EXACT_EXPONENT:
            raise OverflowError('exact_attempt_power')
        lower = lottery.lower_probability(self.target_floor)
        hit = 1 - (1 - lower) ** self.attempts
        return hit, lottery.weight(self.target_ceiling)

    def lower_tail_factor(self, lottery: LotteryEnvelope, tilt: Fraction) -> Fraction:
        z = rational(tilt, 'tilt', True)
        if z <= 1:
            raise ValueError('tilt')
        hit, minimum_weight = self.quantities(lottery)
        if minimum_weight > MAX_EXACT_EXPONENT:
            raise OverflowError('exact_weight_power')
        return 1 - hit * (1 - z ** (-minimum_weight))


def honest_shortfall_bound(slots: tuple[HonestSlot, ...], minimum_work: int,
                           tilt: Fraction, lottery: LotteryEnvelope) -> Fraction:
    """P[minimum visible work increment < minimum_work] in the comparison.

    Each slot must have the search-completion, parent-frontier, full-admissibility
    and all-node visibility guarantees in the accompanying theorem. Missing
    guesses are not padded as actual honest work. Failures are added separately.
    This function never infers a slot count from an observed CPU average.
    """
    natural(minimum_work, 'minimum_work')
    if type(slots) is not tuple or any(type(slot) is not HonestSlot for slot in slots):
        raise ValueError('slots')
    if len(slots) > MAX_EXACT_STAGES or minimum_work > MAX_EXACT_EXPONENT:
        raise OverflowError('exact_honest_tail')
    z = rational(tilt, 'tilt', True)
    if z <= 1:
        raise ValueError('tilt')
    for slot in slots:
        slot.quantities(lottery)
    if sum(slot.attempts for slot in slots) > lottery.exposure_cap:
        raise ValueError('attempts_exceed_global_exposure_cap')
    if minimum_work == 0:
        return Fraction(0)
    product = Fraction(1)
    for slot in slots:
        product *= slot.lower_tail_factor(lottery, z)
    # Integer work: shortfall is S <= minimum_work - 1.
    return min(Fraction(1), z ** (minimum_work - 1) * product)


def forest_upper_bound(fresh_opportunities: int, threshold: int,
                       old_weight: int, rho: Fraction) -> Fraction:
    """Conditional mean-rho forest bound, before all coupling/cap failures."""
    natural(fresh_opportunities, 'fresh_opportunities')
    natural(threshold, 'threshold')
    natural(old_weight, 'old_weight')
    mean = rational(rho, 'rho', True)
    if mean < 1:
        raise ValueError('rho')
    if threshold <= old_weight:
        return Fraction(1)
    return min(Fraction(1), mean * fresh_opportunities / (threshold - old_weight))


def private_overtake_bound(*, honest_shortfall: Fraction, honest_work_floor: int,
                           initial_work_deficit: int, fresh_opportunities: int,
                           old_weight: int, rho: Fraction,
                           world_failure: Fraction) -> dict[str, Fraction | int]:
    """Fixed-deadline necessary condition for a purely adversarial private fork.

    Assumes native strict-heavier fork choice and no new honest blocks on the
    private fork. This is not a common-prefix, balance-attack or settlement bound.
    The world failure must cover the entire coupled experiment; None is refused.
    """
    honest = probability(honest_shortfall, 'honest_shortfall')
    failure = probability(world_failure, 'world_failure')
    natural(honest_work_floor, 'honest_work_floor')
    natural(initial_work_deficit, 'initial_work_deficit')
    threshold = initial_work_deficit + honest_work_floor + 1
    adversary = forest_upper_bound(fresh_opportunities, threshold, old_weight, rho)
    return {'strict_overtake_threshold': threshold,
            'honest_shortfall': honest, 'adversary_forest_tail': adversary,
            'world_failure': failure,
            'bound': min(Fraction(1), honest + adversary + failure)}


def deadline_union_bound(comparison_bounds: tuple[Fraction, ...],
                         shared_world_failure: Fraction) -> Fraction:
    """Finite predeclared deadlines; one shared whole-horizon bad-world event."""
    if type(comparison_bounds) is not tuple:
        raise ValueError('comparison_bounds')
    failure = probability(shared_world_failure, 'shared_world_failure')
    return min(Fraction(1), failure + sum(
        (probability(value, 'deadline_bound') for value in comparison_bounds),
        Fraction(0)))


@dataclass(frozen=True)
class RateLatency:
    unit: str
    rate: Fraction
    latency: Fraction

    def __post_init__(self) -> None:
        if type(self.unit) is not str or not self.unit:
            raise ValueError('unit')
        object.__setattr__(self, 'rate', rational(self.rate, 'rate', True))
        object.__setattr__(self, 'latency', rational(self.latency, 'latency'))

    def service(self, seconds: Fraction) -> Fraction:
        duration = rational(seconds, 'seconds')
        return self.rate * max(Fraction(0), duration - self.latency)


@dataclass(frozen=True)
class ArrivalCurve:
    unit: str
    burst: Fraction
    rate: Fraction

    def __post_init__(self) -> None:
        if type(self.unit) is not str or not self.unit:
            raise ValueError('unit')
        object.__setattr__(self, 'burst', rational(self.burst, 'burst'))
        object.__setattr__(self, 'rate', rational(self.rate, 'rate'))


def leftover_service(server: RateLatency, *, interference_burst: Fraction,
                     interference_rate: Fraction,
                     initial_or_unmetered_work: Fraction) -> RateLatency | None:
    """Strict backlogged service minus all-window executed interfering work.

    The extra work term covers supplied backlog/unmetered nonpreemptive work only
    when a finite bound is justified. Omitting it, or passing None, is an error.
    This does not interpret the native CPU bucket refill as server capacity.
    """
    burst = rational(interference_burst, 'interference_burst')
    interference = rational(interference_rate, 'interference_rate')
    residual_work = rational(initial_or_unmetered_work, 'initial_or_unmetered_work')
    rate = server.rate - interference
    if rate <= 0:
        return None
    latency = (server.rate * server.latency + burst + residual_work) / rate
    return RateLatency(server.unit, rate, latency)


def fifo_delay(arrivals: ArrivalCurve, service: RateLatency) -> Fraction | None:
    """Delay for a retained FIFO flow with both curves, full packets included.

    Each stage needs its own offered-arrival curve and buffer/retention premise.
    A packetization latency or maximum packet work must already be covered.
    A refused request is not merely a packet waiting behind the FIFO head.
    """
    if arrivals.unit != service.unit:
        raise ValueError('resource_unit_mismatch')
    if arrivals.rate > service.rate:
        return None
    return service.latency + arrivals.burst / service.rate


def tandem_delay(stages: tuple[tuple[ArrivalCurve, RateLatency], ...]) -> Fraction | None:
    """Add separately established stage delays; do not convert bytes into CPU."""
    if type(stages) is not tuple or not stages:
        raise ValueError('stages')
    total = Fraction(0)
    for arrivals, service in stages:
        delay = fifo_delay(arrivals, service)
        if delay is None:
            return None
        total += delay
    return total


def all_window_burst_check(events: tuple[tuple[Fraction, Fraction], ...],
                           burst: Fraction, rate: Fraction) -> bool:
    """Exact finite arrival-curve check at every contiguous event interval.

    Instantaneous work arrivals are a mathematical control, not a claim that
    native CPU executes instantaneously. All work in coincident events counts.
    """
    sigma = rational(burst, 'burst')
    slope = rational(rate, 'rate')
    previous = Fraction(0)
    for timestamp, work in events:
        rational(timestamp, 'timestamp')
        rational(work, 'work')
        if timestamp < previous:
            raise ValueError('event_order')
        previous = timestamp
    for first, (start, _) in enumerate(events):
        total = Fraction(0)
        for end, work in events[first:]:
            total += work
            if total > sigma + slope * (end - start):
                return False
    return True


def slot_frontier_floor(initial: int, slots: tuple[tuple[int, int, bool], ...]) -> int:
    """Deterministic induction control: (parent work, block work, visible).

    A nonvisible slot adds nothing. A visible block on a parent below the current
    certified frontier is refused as a slot witness; sibling work is not summed.
    Visibility here is supplied mathematical input, not a network attestation.
    """
    floor = natural(initial, 'initial')
    for parent, work, visible in slots:
        natural(parent, 'parent')
        natural(work, 'block_work', True)
        if type(visible) is not bool:
            raise ValueError('visible')
        if visible:
            if parent < floor:
                raise ValueError('stale_parent_below_slot_frontier')
            floor += work
    return floor


def controls() -> dict:
    lottery = LotteryEnvelope(8, 16)
    slots = (HonestSlot(2, 63, 127),) * 4
    lower = honest_shortfall_bound(slots, 2, Fraction(2), lottery)
    server = RateLatency('cpu-second', Fraction(1), Fraction(1, 10))
    leftover = leftover_service(server, interference_burst=Fraction(1, 5),
                               interference_rate=Fraction(1, 4),
                               initial_or_unmetered_work=Fraction(1, 10))
    assert leftover is not None
    arrivals = ArrivalCurve('cpu-second', Fraction(3, 10), Fraction(1, 10))
    hostile_only = tuple((Fraction(4 * i), Fraction(1)) for i in range(6))
    return {
        'schema': 'w1-service-growth-v4-controls',
        'scope': 'exact conditional arithmetic and synthetic counterexamples',
        'native_execution': False, 'production_parameter_certificate': False,
        'toy_lottery': {'bits': lottery.bits, 'global_exposure_cap': lottery.exposure_cap,
                        'rho': lottery.rho, 'slot_count': len(slots),
                        'attempts_per_slot': 2, 'target_range': [63, 127],
                        'minimum_slot_weight': 2, 'shortfall_below_2': lower},
        'abstract_service': {'unit': leftover.unit, 'residual_rate': leftover.rate,
                             'residual_latency': leftover.latency,
                             'fifo_delay': fifo_delay(arrivals, leftover)},
        'global_quota_counterexample': {
            'events': hostile_only, 'burst': 1, 'rate': Fraction(1, 4),
            'all_windows_conform': all_window_burst_check(hostile_only, Fraction(1), Fraction(1, 4)),
            'honest_service': 0,
            'meaning': 'an aggregate upper quota alone has no positive per-honest lower service'},
        'scope_exclusions': ['actual-SHA coupling', 'physical opportunity conversion',
                             'native service guarantee', 'all-fork common prefix',
                             'production kappa', 'independent hardware'],
    }


def json_default(value: object) -> dict[str, int]:
    if isinstance(value, Fraction):
        return {'numerator': value.numerator, 'denominator': value.denominator}
    raise TypeError(type(value).__name__)


if __name__ == '__main__':
    print(json.dumps(controls(), default=json_default, indent=2, sort_keys=True))
