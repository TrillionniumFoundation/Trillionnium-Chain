#!/usr/bin/env python3
"""Finite prepaid iid-ticket batch theorem; no concrete-SHA assumption implied."""
from fractions import Fraction as F
from functools import lru_cache
from itertools import combinations


def optimal_batch(counts, setup_costs, probability, continuation=0):
    """Exact optimum among complete-batch schedules with >=1 result slot.

    Counts/selector bank are already known and their acquisition is sunk.
    Constant independent ticket success p; nonnegative coordinate setup u_i;
    common continuation c. Full-batch maximum success is required. This
    covers random/history scheduling, prefetch, eviction and recomputation
    within this fixed-cost oracle model, not alternative arithmetic algorithms.
    """
    counts, costs = tuple(counts), tuple(map(F, setup_costs))
    p, c = F(probability), F(continuation)
    if len(counts) != len(costs) or not 0 < p < 1 or c < 0:
        raise ValueError('DOMAIN')
    if any(type(n) is not int or n < 0 for n in counts) or any(u < 0 for u in costs):
        raise ValueError('DOMAIN')
    q = 1-p
    order = tuple(sorted((i for i, n in enumerate(counts) if n),
                         key=lambda i: (costs[i]/(1-q**counts[i]), i)))
    before, useful = 0, F(0)
    for i in order:
        useful += costs[i]*q**before
        before += counts[i]
    success = 1-q**sum(counts)
    common = c*success/p
    return {'order': order, 'success': success, 'expected_setup': useful,
            'expected_continuation': common, 'expected_cost': useful+common}


def exhaustive_batch_value(counts, setup_costs, probability, continuation=0, capacity=1):
    """Independent finite state search over interleavings and every eviction.

    For small tests. States retain coordinate identities, not the sorted
    occupancy theorem. No contiguity or order is assumed. Delaying unused
    prefetch is justified separately in THEOREMS.md.
    """
    counts, costs = tuple(counts), tuple(map(F, setup_costs))
    p, c = F(probability), F(continuation)
    if capacity < 1:
        raise ValueError('CAPACITY')

    @lru_cache(None)
    def value(remaining, cache):
        if not any(remaining):
            return F(0)
        options = []
        for i, n in enumerate(remaining):
            if not n:
                continue
            rest = remaining[:i]+(n-1,)+remaining[i+1:]
            immediate = c+(F(0) if i in cache else costs[i])
            available = tuple(sorted(set(cache) | {i}))
            # Keeping fewer entries is also admitted; their costs are zero.
            for size in range(min(capacity, len(available))+1):
                for future in combinations(available, size):
                    options.append(immediate+(1-p)*value(rest, future))
        return min(options)

    return value(counts, ())


def online_penalty_identity_search(coordinates, rounds, probability, gate,
                                   continuation, useful, capacity, penalty):
    """Independent identity-state Bellman tree for the old irrevocable class.

    Explicitly admits stop; a drawn selector must be skipped forever or
    attempted now. A miss may be retained only if a slot remains. It cannot
    bank an unattempted nonce. All histories/private randomization are
    bounded by Bellman induction; this is not the expanded bank policy class.
    """
    p, g, c, u, penalty = map(F, (probability, gate, continuation, useful, penalty))

    @lru_cache(None)
    def value(left, cache):
        if not left:
            return penalty
        branches = []
        for i in range(coordinates):
            options = [value(left-1, cache)]
            options.append(c+(0 if i in cache else u)+(1-p)*value(left-1, cache))
            if i not in cache and len(cache) < capacity:
                future = tuple(sorted((*cache, i)))
                options.append(c+u+(1-p)*value(left-1, future))
            branches.append(min(options))
        return min(penalty, g+sum(branches)/coordinates)

    return value(rounds, ())
