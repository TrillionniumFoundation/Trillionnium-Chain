"""Exact finite good-subkernel controls; no native security qualification."""
from fractions import Fraction as F
from functools import lru_cache


def require(ok, code):
    if not ok:
        raise ValueError(code)


def bounded(x):
    require(max(x.numerator.bit_length(), x.denominator.bit_length()) <= 8192, 'ARITHMETIC_BITS')
    return x


def fraction(x, low, high):
    require(type(x) is F and low <= x <= high, 'EXACT_RATIONAL_RANGE')
    require(max(x.numerator.bit_length(), x.denominator.bit_length()) <= 64, 'INPUT_BITS')
    return x


def validate(model, z):
    fraction(z, F(1), F(16))
    require(z > 1, 'Z')
    require(type(model) is dict and 1 <= len(model) <= 8, 'STATES')
    actions = branches = 0
    for state, node in model.items():
        require(type(state) is str and 1 <= len(state) <= 32, 'STATE_NAME')
        require(type(node) is dict and set(node) == {'f', 'actions'}, 'NODE')
        fraction(node['f'], F(1), F(16))
        require(type(node['actions']) is list and 1 <= len(node['actions']) <= 8, 'ACTIONS')
        actions += len(node['actions'])
        for row in node['actions']:
            require(type(row) is list and 1 <= len(row) <= 16, 'ROW')
            branches += len(row)
            total = F(0)
            for branch in row:
                require(type(branch) is tuple and len(branch) == 4, 'BRANCH')
                p, nxt, dy, dj = branch
                fraction(p, F(0), F(1))
                require(p > 0, 'POSITIVE_MASS')
                require(type(dy) is int and type(dj) is int and 0 <= dy <= 4 and 0 <= dj <= 4, 'CREDIT')
                require(nxt is None or type(nxt) is str and nxt in model, 'NEXT_STATE')
                require(nxt is not None or dy == dj == 0, 'BAD_PLACEHOLDER')
                total = bounded(total + p)
            require(total == 1, 'TOTAL_MASS')
    require(actions <= 32 and branches <= 128, 'MODEL_SIZE')


def analyze(model, initial, *, z=F(2), gap=1, horizon=2):
    """None next-state means bad: pay its mass, never normalize it away.

    dy includes A+E. Bad-branch zero fields are unused placeholders, not costs.
    Every supplied action/state is certified; the Bellman diagnostic maximizes
    over all adaptive policies in this declared sufficient-state finite law.
    """
    validate(model, z)
    require(type(initial) is str and initial in model, 'INITIAL')
    require(type(gap) is int and 0 <= gap <= 16, 'GAP')
    require(type(horizon) is int and 0 <= horizon <= 8, 'HORIZON')
    rows = []
    for state, node in model.items():
        for index, row in enumerate(node['actions']):
            moment = bad = F(0)
            for p, nxt, dy, dj in row:
                if nxt is None:
                    bad = bounded(bad + p)
                else:
                    multiplier = bounded(model[nxt]['f'] / node['f'] * z ** (dy - dj))
                    moment = bounded(moment + p * multiplier)
            rows.append({'state': state, 'action': index, 'good_subkernel_moment': moment, 'bad_mass': bad})
    certified = all(r['good_subkernel_moment'] <= 1 for r in rows)
    cells = edges = 0

    @lru_cache(None)
    def value(state, debt, left, union):
        nonlocal cells, edges
        cells += 1
        require(cells <= 20000, 'DP_CELLS')
        if union and debt >= gap:
            return F(1)
        if left == 0:
            return F(0)
        options = []
        for row in model[state]['actions']:
            total = F(0)
            for p, nxt, dy, dj in row:
                edges += 1
                require(edges <= 200000, 'DP_EDGES')
                v = F(1) if nxt is None else value(nxt, debt + dy - dj if union else 0, left - 1, union)
                total = bounded(total + p * v)
            options.append(total)
        return max(options)

    worst_union = value(initial, 0, horizon, True)
    worst_bad = value(initial, 0, horizon, False)
    hazard_budget = min(F(1), horizon * max(r['bad_mass'] for r in rows))
    crossing = min(F(1), model[initial]['f'] * z ** (-gap)) if certified else None
    bound = min(F(1), crossing + hazard_budget) if certified else None
    return {'rows': rows, 'certified': certified, 'exact_finite_worst_union': worst_union,
            'exact_finite_worst_bad': worst_bad, 'finite_hazard_budget': hazard_budget,
            'conditional_crossing_bound': crossing, 'finite_union_bound': bound,
            'native_failure_bound': None, 'production_activation': False}


if __name__ == '__main__':
    import json
    model = {'s': {'f': F(1), 'actions': [[(F(1, 8), 's', 1, 0), (F(3, 4), 's', 0, 1), (F(1, 8), None, 0, 0)]]}}
    result = analyze(model, 's', gap=2, horizon=2)
    print(json.dumps(result, default=str, sort_keys=True))
