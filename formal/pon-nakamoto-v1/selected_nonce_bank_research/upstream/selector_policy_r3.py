#!/usr/bin/env python3
"""Exact optimal expected tariff in a closed iid selector/cache policy class.

No claim about concrete SHA, QROM, finite-nonce eventual success, arbitrary
algorithms, physical time, energy, useful demand, or production admission.
"""
from dataclasses import dataclass
from fractions import Fraction as F
from decimal import Decimal, localcontext
from itertools import product


def fraction_record(x):
    x = F(x)
    with localcontext() as context:
        context.prec = 32
        decimal = str(Decimal(x.numerator)/Decimal(x.denominator))
    return {'numerator': str(x.numerator), 'denominator': str(x.denominator),
            'decimal': decimal}


def lazy_expected_products(draws, coordinates=512):
    if type(draws) is not int or draws < 0 or type(coordinates) is not int or coordinates < 1:
        raise ValueError('DOMAIN')
    return coordinates*(1-F(coordinates-1, coordinates)**draws)


def cache_until_first_hit_expected_products(coordinates, hit_probability):
    """Unbounded iid auxiliary model only. Cache all first-seen coordinates."""
    p = F(hit_probability)
    if coordinates < 1 or not 0 < p <= 1:
        raise ValueError('DOMAIN')
    return F(coordinates, 1+(coordinates-1)*p)


def optimal_static_filter(gate_cost, continuation_costs, hit_probability):
    """All adaptive/no-cache policies in the stated iid class reduce to this.

    Equal selector probabilities; accepts one lower-cost prefix. Includes
    gate work for every discarded selector and every unsuccessful attempt.
    """
    g, p = F(gate_cost), F(hit_probability)
    costs = tuple(F(x) for x in continuation_costs)
    if g <= 0 or not 0 < p <= 1 or not costs or any(c < 0 for c in costs):
        raise ValueError('DOMAIN')
    ordering = sorted(range(len(costs)), key=lambda i: (costs[i], i))
    prefix_sum = F(0)
    options = []
    for count, index in enumerate(ordering, 1):
        prefix_sum += costs[index]
        value = (len(costs)*g+prefix_sum)/(count*p)
        options.append((value, tuple(ordering[:count])))
    value, accepted = min(options)
    # Bellman residual independently checks skip/continue decisions.
    rhs = g+sum(min(value, c+(1-p)*value) for c in costs)/len(costs)
    if rhs != value:
        raise AssertionError('BELLMAN_RESIDUAL')
    return {'value': value, 'accepted': accepted, 'threshold': p*value}


@dataclass(frozen=True)
class CacheModel:
    coordinates: int
    capacity: int
    probability: F
    gate: F
    common: F
    useful: F
    lookup: F = F(0)
    insertion: F = F(0)

    def validate(self):
        if type(self.coordinates) is not int or type(self.capacity) is not int:
            raise ValueError('DOMAIN')
        if not 1 <= self.coordinates <= 4096 or not 0 <= self.capacity <= self.coordinates:
            raise ValueError('DOMAIN')
        if not 0 < F(self.probability) <= 1 or F(self.gate) <= 0:
            raise ValueError('DOMAIN')
        if any(F(x) < 0 for x in (self.common, self.useful, self.lookup, self.insertion)):
            raise ValueError('DOMAIN')
        return self


def fixed_actions_value(model, k, hit_action, miss_action, next_value):
    """Eliminate the self-loop exactly for one pair of state actions."""
    m = model
    p, hit = F(m.probability), F(k, m.coordinates)
    constant, self_coefficient = F(m.gate)+F(m.lookup), F(0)
    if hit_action == 'skip':
        self_coefficient += hit
    elif hit_action == 'attempt':
        constant += hit*F(m.common)
        self_coefficient += hit*(1-p)
    else:
        raise ValueError('HIT_ACTION')
    miss = 1-hit
    if miss_action == 'skip':
        self_coefficient += miss
    elif miss_action == 'attempt':
        constant += miss*(F(m.common)+F(m.useful))
        self_coefficient += miss*(1-p)
    elif miss_action == 'store':
        if k >= m.capacity or next_value is None:
            raise ValueError('CAPACITY')
        constant += miss*(F(m.common)+F(m.useful)+F(m.insertion)+(1-p)*next_value)
    else:
        raise ValueError('MISS_ACTION')
    if self_coefficient == 1:
        return None  # pays gate forever and never succeeds
    return constant/(1-self_coefficient)


def optimal_cache(model):
    """Descending exact Bellman solution; all history/randomized policies covered."""
    m = model.validate()
    states = [None]*(m.capacity+1)
    for k in range(m.capacity, -1, -1):
        next_value = states[k+1]['value'] if k < m.capacity else None
        options = []
        for hit_action, miss_action in product(('skip', 'attempt'),
                                               ('skip', 'attempt', 'store') if k < m.capacity else ('skip', 'attempt')):
            value = fixed_actions_value(m, k, hit_action, miss_action, next_value)
            if value is not None:
                options.append((value, hit_action, miss_action))
        value, hit_action, miss_action = min(options)
        hit = F(k, m.coordinates)
        hit_rhs = min(value, F(m.common)+(1-F(m.probability))*value)
        miss_options = [value, F(m.common)+F(m.useful)+(1-F(m.probability))*value]
        if k < m.capacity:
            miss_options.append(F(m.common)+F(m.useful)+F(m.insertion)+
                                (1-F(m.probability))*next_value)
        rhs = F(m.gate)+F(m.lookup)+hit*hit_rhs+(1-hit)*min(miss_options)
        if value != rhs:
            raise AssertionError('BELLMAN_RESIDUAL')
        states[k] = {'k': k, 'value': value, 'hit': hit_action, 'miss': miss_action}
    return states


def finite_penalty(model, rounds, failure_penalty):
    """Finite nonce-attempt cap: exact min E[cost]+penalty*Pr(no success).

    All states permit stopping, explicit selector skip, attempt without store,
    and attempt with store up to capacity. Cost and failure probability are
    returned separately; the penalty is a declared objective, not qualification.
    """
    m = model.validate()
    penalty = F(failure_penalty)
    if type(rounds) is not int or rounds < 0 or penalty < 0:
        raise ValueError('DOMAIN')
    previous = [{'value': penalty, 'cost': F(0), 'failure': F(1),
                 'hit': 'stop', 'miss': 'stop'} for _ in range(m.capacity+1)]
    p = F(m.probability)
    for _ in range(rounds):
        current = []
        for k in range(m.capacity+1):
            hit_prob = F(k, m.coordinates)
            stay = previous[k]
            def branch(action, useful):
                if action == 'skip':
                    return stay['cost'], stay['failure']
                future = previous[k+1] if action == 'store' else stay
                cost = F(m.common)+useful+(F(m.insertion) if action == 'store' else 0)
                return cost+(1-p)*future['cost'], (1-p)*future['failure']
            hit_options = [(branch(a, F(0)), a) for a in ('skip', 'attempt')]
            miss_options = [(branch(a, F(m.useful)), a) for a in
                            (('skip', 'attempt', 'store') if k < m.capacity else ('skip', 'attempt'))]
            best_hit = min(hit_options, key=lambda x:(x[0][0]+penalty*x[0][1], x[1]))
            best_miss = min(miss_options, key=lambda x:(x[0][0]+penalty*x[0][1], x[1]))
            cost = F(m.gate)+F(m.lookup)+hit_prob*best_hit[0][0]+(1-hit_prob)*best_miss[0][0]
            failure = hit_prob*best_hit[0][1]+(1-hit_prob)*best_miss[0][1]
            value = cost+penalty*failure
            current.append({'value': value, 'cost': cost, 'failure': failure,
                            'hit': best_hit[1], 'miss': best_miss[1]} if value < penalty else
                           {'value': penalty, 'cost': F(0), 'failure': F(1), 'hit': 'stop', 'miss': 'stop'})
        previous = current
    return previous


def finite_success_lower_bound(model, rounds, required_success, failure_penalty):
    """Weak-dual cost lower bound inside the exact finite policy class.

    If a policy has success probability at least alpha, its expected cost
    is at least V_lambda - lambda*(1-alpha), even if randomized/adaptive.
    This is not an achievability claim for alpha or a bound outside this class.
    """
    alpha, penalty = F(required_success), F(failure_penalty)
    if not 0 <= alpha <= 1 or penalty < 0:
        raise ValueError('DOMAIN')
    state = finite_penalty(model, rounds, penalty)[0]
    return {'required_success': alpha, 'failure_penalty': penalty,
            'penalized_optimum': state['value'],
            'cost_lower_bound': max(F(0), state['value']-penalty*(1-alpha)),
            'penalty_optimal_policy_cost': state['cost'],
            'penalty_optimal_policy_success': 1-state['failure']}
