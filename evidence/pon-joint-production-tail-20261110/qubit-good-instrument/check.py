"""Exact in-process real-Kraus qubit certificates, never native qualification."""
from dataclasses import dataclass
from fractions import Fraction as Q
import json


class Refused(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Refused(reason)


def bounded(x):
    need(type(x) is Q, 'EXACT_FRACTION_REQUIRED')
    need(max(x.numerator.bit_length(), x.denominator.bit_length()) <= 8192,
         'ARITHMETIC_LIMIT')
    return x


def mat(a, b, c, d):
    return ((Q(a), Q(b)), (Q(c), Q(d)))


I = mat(1, 0, 0, 1)
ZERO = mat(0, 0, 0, 0)


def matrix(x):
    need(type(x) is tuple and len(x) == 2 and
         all(type(r) is tuple and len(r) == 2 for r in x), 'MATRIX_SHAPE')
    for r in x:
        for v in r:
            bounded(v)
            need(max(v.numerator.bit_length(), v.denominator.bit_length()) <= 64,
                 'INPUT_PART_LIMIT')


def add(a, b):
    return tuple(tuple(bounded(a[i][j] + b[i][j]) for j in range(2)) for i in range(2))


def scale(s, a):
    return tuple(tuple(bounded(s * v) for v in r) for r in a)


def transpose(a):
    return tuple(tuple(a[j][i] for j in range(2)) for i in range(2))


def mul(a, b):
    return tuple(tuple(bounded(sum((a[i][k] * b[k][j] for k in range(2)), Q(0)))
                       for j in range(2)) for i in range(2))


def dual(k, f):
    return mul(transpose(k), mul(f, k))


def psd(a):
    need(a[0][1] == a[1][0], 'SYMMETRIC_REQUIRED')
    return (a[0][0] >= 0 and a[1][1] >= 0 and
            bounded(a[0][0] * a[1][1] - a[0][1] * a[1][0]) >= 0)


@dataclass(frozen=True)
class Outcome:
    kraus: tuple
    next_state: object  # None is a physically declared bad outcome.
    adversarial: int = 0
    entry: int = 0
    honest: int = 0


@dataclass(frozen=True)
class Action:
    name: str
    outcomes: tuple
    bad_bound: Q


@dataclass(frozen=True)
class State:
    name: str
    witness: tuple
    actions: tuple


def certificate(states, initial, z, horizon, gap):
    """Check ALL declared actions in PSD order, uniformly over input states.

    Each outcome has one real rational Kraus matrix. Multiple outcomes may
    share the same public successor; refining the instrument this way is part
    of the declared observation model, not inferred from native execution.
    """
    need(type(states) is tuple and 1 <= len(states) <= 8, 'STATE_LIMIT')
    bounded(z)
    need(Q(1) < z <= Q(4), 'Z_RANGE')
    need(type(horizon) is int and 0 <= horizon <= 8, 'HORIZON_RANGE')
    need(type(gap) is int and 0 <= gap <= 16, 'GAP_RANGE')
    def label(s):
        need(type(s) is str and 1 <= len(s) <= 64 and
             all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in s),
             'LABEL')
    names = {}
    actions = branches = 0
    for s in states:
        need(type(s) is State, 'STATE_TYPE')
        label(s.name)
        need(s.name not in names, 'DUPLICATE_STATE')
        names[s.name] = s
        matrix(s.witness)
        need(psd(add(s.witness, scale(Q(-1), I))), 'WITNESS_BELOW_IDENTITY')
        need(type(s.actions) is tuple and 1 <= len(s.actions) <= 32, 'ACTION_LIMIT')
        actions += len(s.actions)
        seen = set()
        for a in s.actions:
            need(type(a) is Action, 'ACTION_TYPE')
            label(a.name)
            need(a.name not in seen, 'DUPLICATE_ACTION')
            seen.add(a.name)
            need(type(a.outcomes) is tuple and 1 <= len(a.outcomes) <= 128,
                 'OUTCOME_LIMIT')
            branches += len(a.outcomes)
    need(actions <= 32 and branches <= 128, 'TOTAL_MODEL_LIMIT')
    need(type(initial) is str and initial in names, 'INITIAL_STATE')
    bmax = Q(0)
    for s in states:
        for a in s.actions:
            bounded(a.bad_bound)
            need(0 <= a.bad_bound <= 1, 'BAD_BOUND_RANGE')
            total = bad = moment = ZERO
            for o in a.outcomes:
                need(type(o) is Outcome, 'OUTCOME_TYPE')
                matrix(o.kraus)
                for v in (o.adversarial, o.entry, o.honest):
                    need(type(v) is int and 0 <= v <= 4, 'CREDIT_RANGE')
                effect = dual(o.kraus, I)
                total = add(total, effect)
                if o.next_state is None:
                    need((o.adversarial, o.entry, o.honest) == (0, 0, 0),
                         'BAD_CANONICAL_UNUSED_CREDIT')
                    bad = add(bad, effect)
                else:
                    need(type(o.next_state) is str and o.next_state in names,
                         'NEXT_STATE')
                    delta = o.adversarial + o.entry - o.honest
                    moment = add(moment, scale(bounded(z ** delta),
                                 dual(o.kraus, names[o.next_state].witness)))
            need(total == I, 'INCOMPLETE_INSTRUMENT')
            need(psd(add(s.witness, scale(Q(-1), moment))), 'GOOD_OPERATOR_MOMENT')
            need(psd(add(scale(a.bad_bound, I), scale(Q(-1), bad))), 'BAD_OPERATOR_MASS')
            bmax = max(bmax, a.bad_bound)
    f = names[initial].witness
    # Gershgorin gives a rational all-state upper bound on lambda_max(F).
    initial_upper = max(f[0][0] + abs(f[0][1]), f[1][1] + abs(f[1][0]))
    crossing = min(Q(1), bounded(initial_upper * z ** (-gap)))
    spending_ceiling = bounded(horizon * bmax)
    probability_cap = min(Q(1), spending_ceiling)
    return {'scope': 'declared-real-rational-qubit-instruments-only',
            'states': len(states), 'actions': actions, 'outcomes': branches,
            'initial_potential_upper': initial_upper,
            'crossing_allowance': crossing,
            'finite_bad_spending_ceiling': spending_ceiling,
            'finite_bad_probability_cap': probability_cap,
            'finite_union_allowance': min(Q(1), crossing + probability_cap),
            'native_reduction_proved': False, 'all_legal_strategies_covered': False,
            'actual_joint_obligations_open': 13, 'native_CP_CG_CQ_bound': None,
            'six_successor_failure_bound': None, 'lifetime_failure_bound': None,
            'production_activation': False, 'qualification': 'HOLD_NO_GO'}


def benign_model():
    good = Outcome(scale(Q(3, 13), I), 'live', adversarial=1)
    honest = Outcome(scale(Q(12, 13), I), 'live', honest=1)
    bad = Outcome(scale(Q(4, 13), I), None)
    return (State('live', I, (Action('paid_good_mass', (good, honest, bad), Q(16, 169)),)),)


if __name__ == '__main__':
    result = certificate(benign_model(), 'live', Q(2), 2, 2)
    print(json.dumps(result, default=lambda v: {'num': v.numerator, 'den': v.denominator},
                     sort_keys=True))
