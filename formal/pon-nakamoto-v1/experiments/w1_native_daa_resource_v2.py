"""Native-rule dynamic difficulty and conditional opportunity-to-work controls.

No physical W1 lower bound or common-prefix theorem is asserted. The exact
finite policy model has a declared timestamp alphabet, independent fresh ideal
lotteries, and paid query counts, not real elapsed time or an optimal CPU miner.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from functools import lru_cache
import json

INTERVAL = 16
SPACING = 10
MEDIAN_WIDTH = 11
FUTURE_SKEW = 120
U64_MAX = (1 << 64) - 1
MAX_EXACT_WEIGHT = 4096
MAX_POLICY_QUERIES = 4


def natural(value: int, name: str, positive: bool = False) -> int:
    if type(value) is not int or value < int(positive):
        raise ValueError(name)
    return value


def u64(value: int, name: str) -> int:
    natural(value, name)
    if value > U64_MAX:
        raise ValueError(name)
    return value


def space(bits: int = 256) -> int:
    natural(bits, 'bits', True)
    if not 2 <= bits <= 256:
        raise ValueError('bits')
    return 1 << bits


def target_limit(bits: int = 256) -> int:
    return space(bits) // 2 - 1


def checked_target(target: int, bits: int = 256) -> int:
    natural(target, 'target', True)
    if target > target_limit(bits):
        raise ValueError('target')
    return target


def work(target: int, bits: int = 256) -> int:
    return space(bits) // (checked_target(target, bits) + 1)


def probability(target: int, bits: int = 256) -> Fraction:
    return Fraction(checked_target(target, bits) + 1, space(bits))


def expected_work(target: int, bits: int = 256) -> Fraction:
    return probability(target, bits) * work(target, bits)


def native_retarget(parent: int, first: int, last: int, bits: int = 256) -> int:
    checked_target(parent, bits)
    u64(first, 'first')
    u64(last, 'last')
    desired = (INTERVAL - 1) * SPACING
    lower = (desired + 3) // 4
    observed = min(4 * desired, max(lower, max(1, last - first)))
    return min(target_limit(bits), max(1, parent * observed // desired))


def native_time(candidate: int, parent_first_times: tuple[int, ...], now: int) -> None:
    u64(candidate, 'candidate')
    u64(now, 'now')
    if not parent_first_times:
        raise ValueError('UNKNOWN_PARENT')
    for value in parent_first_times:
        u64(value, 'ancestor_time')
    recent = sorted(parent_first_times[:MEDIAN_WIDTH])
    if candidate <= recent[len(recent) // 2]:
        raise ValueError('TIME')
    # Rust adds in u128, not a wrapping/saturating u64 operation.
    if candidate > now + FUTURE_SKEW:
        raise ValueError('TIME_DEFERRED')


@dataclass(frozen=True, order=True)
class Parent:
    height: int
    target: int
    times: tuple[int, ...]  # validated parent first, at most 16
    extension_work: int = 0


def check_parent(parent: Parent, bits: int = 256) -> None:
    natural(parent.height, 'height')
    checked_target(parent.target, bits)
    natural(parent.extension_work, 'extension_work')
    if type(parent.times) is not tuple or len(parent.times) != min(parent.height + 1, INTERVAL):
        raise ValueError('parent_window')
    for value in parent.times:
        u64(value, 'parent_time')


def next_target(parent: Parent, bits: int = 256) -> int:
    check_parent(parent, bits)
    if (parent.height + 1) % INTERVAL:
        return parent.target
    return native_retarget(parent.target, parent.times[INTERVAL - 1], parent.times[0], bits)


def append_header_rule(parent: Parent, timestamp: int, now: int, bits: int = 256) -> Parent:
    """Rule arithmetic only: this function neither creates nor verifies a W1 proof."""
    target = next_target(parent, bits)
    native_time(timestamp, parent.times, now)
    return Parent(parent.height + 1, target, (timestamp,) + parent.times[:INTERVAL - 1],
                  parent.extension_work + work(target, bits))


def bookend_parent(genesis: int = 1, now: int = 1201, bits: int = 256) -> Parent:
    """Thirty rule-valid headers; actual native execution is a separate Rust example."""
    u64(genesis, 'genesis')
    parent = Parent(0, target_limit(bits), (genesis,))
    for height in range(1, 31):
        offset = 11 if height == 16 else height
        parent = append_header_rule(parent, genesis + offset, now, bits)
    return parent


def bookend_vectors(genesis: int = 1, now: int = 1201, bits: int = 256) -> dict:
    base = bookend_parent(genesis, now, bits)
    rows = {}
    for name, offset in [('tighten', 31), ('unchanged', 161), ('ease', 611)]:
        parent31 = append_header_rule(base, genesis + offset, now, bits)
        child32 = append_header_rule(parent31, genesis + 32, now, bits)
        rows[name] = {'height31_timestamp': genesis + offset,
                      'height32_timestamp': genesis + 32,
                      'first_timestamp_for_retarget': parent31.times[15],
                      'raw_span': parent31.times[0] - parent31.times[15],
                      'target32': child32.target, 'work32': work(child32.target, bits),
                      'chainwork32': child32.extension_work,
                      'ideal_expected_work_per_query': expected_work(child32.target, bits)}
    return {'genesis': genesis, 'observed_now': now, 'base_height': 30,
            'base_work': base.extension_work, 'base_target': base.target, 'branches': rows,
            'all_forest_work': base.extension_work + 3 * work(base.target, bits)
                + sum(row['work32'] for row in rows.values()),
            'native_execution_claim': False}


def known_bank_weight(entries: tuple[tuple[str, int], ...]) -> int:
    """Distinct already-revealed winning block identities, remaining capacity one.

    A compact statement digest must first be proved to have this credit meaning.
    Duplicate identical entries are replay, not new work. Different weights for
    one identity are rejected. Unseen prepared lotteries instead belong in N.
    """
    unique: dict[str, int] = {}
    for key, amount in entries:
        if type(key) is not str or not key:
            raise ValueError('bank_identity')
        natural(amount, 'bank_work', True)
        if key in unique and unique[key] != amount:
            raise ValueError('BANK_IDENTITY_WEIGHT')
        unique[key] = amount
    return sum(unique.values())


def dda_weight_envelope(parents: tuple[Parent, ...], fresh_queries: int,
                        external_ancestry_blocks: int | None, bits: int = 256) -> dict:
    """Safe candidate-weight cap, not an exact reachable-target characterization.

    Count supplied honest/helper ancestors separately: a query cap on this miner
    does not bound the height or target of externally obtained parents. None
    declines that additional premise and uses the global native maximum.
    Initial prepared/withheld eligible parent geometry must already be included.
    """
    natural(fresh_queries, 'fresh_queries')
    if not parents:
        raise ValueError('initial_parents')
    for parent in parents:
        check_parent(parent, bits)
    if fresh_queries == 0:
        return {'weight_cap': 0, 'target_floor': None, 'retarget_count_cap': 0,
                'scope': 'no-fresh-query'}
    if external_ancestry_blocks is None:
        return {'weight_cap': space(bits) // 2, 'target_floor': 1,
                'retarget_count_cap': None, 'scope': 'unbounded-external-ancestry'}
    natural(external_ancestry_blocks, 'external_ancestry_blocks')
    floors = []
    counts = []
    for parent in parents:
        count = (parent.height + fresh_queries + external_ancestry_blocks) // INTERVAL - parent.height // INTERVAL
        target = parent.target
        for _ in range(count):
            target = max(1, target * 38 // 150)
            if target == 1:
                break
        floors.append(target)
        counts.append(count)
    floor = min(floors)
    return {'weight_cap': work(floor, bits), 'target_floor': floor,
            'retarget_count_cap': max(counts), 'scope': 'explicit-initial-forest-and-ancestry-cap'}


def exact_probability(value: Fraction | int) -> Fraction:
    if type(value) not in (int, Fraction) or not 0 <= value <= 1:
        raise ValueError('probability')
    return Fraction(value)


def forest_markov_bound(queries: int, threshold: int, *, bank: int = 0,
                         failure: Fraction = Fraction()) -> Fraction:
    """Any stopping time up to N, total distinct newly successful forest work.

    Requires predictable targets, conditional-uniform fresh lottery answers,
    unit native block identity fanout, and a cap holding outside named failure.
    It is not a bound on arbitrary common-prefix failure or external resources.
    """
    for value, name in [(queries, 'queries'), (threshold, 'threshold'), (bank, 'bank')]:
        natural(value, name)
    eps = exact_probability(failure)
    if threshold <= bank:
        return Fraction(1)
    return min(Fraction(1), Fraction(queries, threshold - bank) + eps)


def forest_mgf_bound(queries: int, threshold: int, weight_cap: int,
                      tilt: Fraction, *, bank: int = 0,
                      failure: Fraction = Fraction()) -> Fraction | None:
    """Exact rational conservative bounded-jump tail; None means arithmetic cap.

    beta=1+(z**W-1)/W follows from convexity and E[X|past]<=1.
    z**S/beta**i is a nonnegative supermartingale. For i<=N, crossing S>=d
    crosses z**d/beta**N. No conditioning on a future good event is used.
    """
    for value, name in [(queries, 'queries'), (threshold, 'threshold'), (bank, 'bank')]:
        natural(value, name)
    natural(weight_cap, 'weight_cap', True)
    if type(tilt) not in (int, Fraction) or tilt <= 1:
        raise ValueError('tilt')
    eps = exact_probability(failure)
    if threshold <= bank:
        return Fraction(1)
    if queries > 512 or weight_cap > MAX_EXACT_WEIGHT or threshold - bank > 1_000_000:
        return None
    z = Fraction(tilt)
    beta = 1 + (z ** weight_cap - 1) / weight_cap
    return min(Fraction(1), beta ** queries / z ** (threshold - bank) + eps)


def adaptive_capital(outcomes: tuple[tuple[int, bool], ...], tilt: Fraction,
                     bits: int = 256) -> Fraction:
    """The exact normalized lottery process, under externally established freshness.

    The function does not validate a physical trace or prove its predicates.
    """
    if type(tilt) not in (int, Fraction) or tilt <= 1:
        raise ValueError('tilt')
    z = Fraction(tilt)
    capital = Fraction(1)
    for target, hit in outcomes:
        if type(hit) is not bool:
            raise ValueError('hit')
        w, p = work(target, bits), probability(target, bits)
        if w > MAX_EXACT_WEIGHT:
            raise ValueError('exact_weight_cap')
        capital *= (z ** w if hit else 1) / (1 + p * (z ** w - 1))
    return capital


def finite_policy_actions(parent: Parent, genesis: int, now: int,
                          bits: int) -> tuple[Parent, ...]:
    height = parent.height + 1
    if height == 31:
        offsets = (31, 161, 611)
    elif 32 <= height <= 34:
        offsets = (height,)
    else:
        return ()
    return tuple(append_header_rule(parent, genesis + offset, now, bits) for offset in offsets)


def exact_finite_policy_tail(queries: int, threshold: int, *, metric: str = 'forest',
                            bits: int = 256) -> Fraction:
    """Bellman optimum for a declared finite timestamp alphabet after height 30.

    Every attempt is a fresh ideal lottery and costs one query, including misses.
    All discovered parent profiles remain eligible. Profiles with the same
    geometry and extension work are symmetry-merged, not credited twice for a
    replay: a new hit still has a new nonce identity and increases forest work.
    This does not optimize arbitrary timestamps, CPU algorithms or real mining.
    """
    natural(queries, 'queries')
    natural(threshold, 'threshold')
    if queries > MAX_POLICY_QUERIES or metric not in ('forest', 'heaviest-extension'):
        raise ValueError('finite_policy_scope')
    base = bookend_parent(bits=bits)
    base = Parent(base.height, base.target, base.times, 0)

    @lru_cache(maxsize=None)
    def solve(left: int, parents: tuple[Parent, ...], total: int) -> Fraction:
        score = total if metric == 'forest' else max(parent.extension_work for parent in parents)
        if score >= threshold:
            return Fraction(1)
        if not left:
            return Fraction()
        miss = solve(left - 1, parents, total)
        best = Fraction()
        for parent in parents:
            for child in finite_policy_actions(parent, 1, 1201, bits):
                p = probability(child.target, bits)
                expanded = tuple(sorted(set(parents + (child,))))
                hit = solve(left - 1, expanded, total + work(child.target, bits))
                best = max(best, (1 - p) * miss + p * hit)
        return best

    return solve(queries, (base,), 0)


def report() -> dict:
    vectors = bookend_vectors()
    parent = bookend_parent()
    p31 = probability(parent.target)
    tight = vectors['branches']['tighten']['target32']
    easy = vectors['branches']['ease']['target32']
    return {
        'schema': 'pon-w1-native-daa-resource-v2',
        'status': 'conditional-native-rule-and-exact-finite-policy-controls',
        'production_activation': False, 'physical_resource_bound_established': False,
        'actual_sha_instantiation_established': False, 'common_prefix_established': False,
        'O03_closed': False,
        'native_rule_vectors_without_proofs': vectors,
        'two_query_cap_from_height30': dda_weight_envelope((parent,), 2, 0),
        'without_external_ancestry_cap': dda_weight_envelope((parent,), 2, None),
        'exact_declared_policy': {
            'queries': 2, 'initial_height30_history_cost_excluded_and_required_as_bank': True,
            'tail_forest_38': exact_finite_policy_tail(2, 38),
            'independent_two_hit_formula_38': p31 * probability(tight),
            'tail_forest_9': exact_finite_policy_tail(2, 9),
            'independent_two_hit_formula_9': p31 * probability(easy),
            'fixed_weight7_binomial_tail_38': Fraction(),
            'markov_tail_38': forest_markov_bound(2, 38),
            'bounded_mgf_tail_38': forest_mgf_bound(2, 38, 31, Fraction(11, 10)),
            'forest_and_heaviest_are_distinct': {
                'queries': 2, 'threshold': 14,
                'forest': exact_finite_policy_tail(2, 14),
                'heaviest_extension': exact_finite_policy_tail(2, 14, metric='heaviest-extension')},
        },
    }


def json_default(value):
    if isinstance(value, Fraction):
        return str(value)
    raise TypeError(type(value).__name__)


if __name__ == '__main__':
    print(json.dumps(report(), default=json_default, sort_keys=True, indent=2))
