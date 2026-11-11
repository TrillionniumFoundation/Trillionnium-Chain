from fractions import Fraction as F
from itertools import product
import unittest
from check import analyze


def policies(model, state, debt, gap, depth):
    """Enumerate attainable policy-tree values; do not use Bellman maximization."""
    if debt >= gap:
        return {F(1)}
    if not depth:
        return {F(0)}
    values = set()
    for row in model[state]['actions']:
        children = [{F(1)} if nxt is None else policies(model, nxt, debt + dy - dj, gap, depth - 1)
                    for _, nxt, dy, dj in row]
        for choice in product(*children):
            values.add(sum((branch[0] * v for branch, v in zip(row, choice)), F(0)))
    return values


class Controls(unittest.TestCase):
    def test_good_law_is_not_renormalized(self):
        m = {'s': {'f': F(1), 'actions': [[(F(1, 2), 's', 1, 0), (F(1, 2), None, 0, 0)]]}}
        r = analyze(m, 's', horizon=1)
        self.assertTrue(r['certified'])
        self.assertEqual(r['rows'][0]['good_subkernel_moment'], 1)
        self.assertEqual(r['rows'][0]['good_subkernel_moment'] / (1 - r['rows'][0]['bad_mass']), 2)
        self.assertEqual(r['exact_finite_worst_union'], 1)

    def test_nontrivial_exact_union_and_bad_budget(self):
        m = {'s': {'f': F(1), 'actions': [[(F(1, 8), 's', 1, 0), (F(3, 4), 's', 0, 1), (F(1, 8), None, 0, 0)]]}}
        r = analyze(m, 's', gap=2, horizon=2)
        self.assertEqual(r['rows'][0]['good_subkernel_moment'], F(5, 8))
        self.assertEqual(r['exact_finite_worst_bad'], F(15, 64))
        self.assertEqual(r['exact_finite_worst_union'], F(1, 4))
        self.assertEqual(r['finite_union_bound'], F(1, 2))

    def test_all_declared_actions_must_pass(self):
        m = {'s': {'f': F(1), 'actions': [[(F(1), 's', 0, 1)]]},
             'unused': {'f': F(1), 'actions': [[(F(1), 'unused', 1, 0)]]}}
        r = analyze(m, 's')
        self.assertFalse(r['certified'])
        self.assertIsNone(r['finite_union_bound'])

    def test_initial_residual_potential_cannot_be_reset(self):
        m = {'s': {'f': F(2), 'actions': [[(F(1), 't', 1, 0)]]},
             't': {'f': F(1), 'actions': [[(F(1), 't', 0, 1)]]}}
        r = analyze(m, 's')
        self.assertTrue(r['certified'])
        self.assertEqual(r['exact_finite_worst_union'], 1)
        self.assertEqual(r['conditional_crossing_bound'], 1)

    def test_independent_complete_tiny_policy_trees(self):
        m = {'s': {'f': F(1), 'actions': [[(F(1, 4), 's', 1, 0), (F(3, 4), 's', 0, 1)],
                                       [(F(1, 8), None, 0, 0), (F(7, 8), 's', 0, 1)]]}}
        for gap in range(4):
            for depth in range(4):
                r = analyze(m, 's', gap=gap, horizon=depth)
                self.assertEqual(r['exact_finite_worst_union'], max(policies(m, 's', 0, gap, depth)))
                self.assertLessEqual(r['exact_finite_worst_union'], r['finite_union_bound'])
                self.assertLessEqual(r['exact_finite_worst_bad'], r['finite_hazard_budget'])

    def test_strict_types_mass_and_limits(self):
        for branch in ((F(1), 's', True, 0), (F(1), None, 1, 0), (F(1), 'missing', 0, 0), (1.0, 's', 0, 0), (F(1, 2), 's', 0, 0)):
            with self.assertRaises(ValueError):
                analyze({'s': {'f': F(1), 'actions': [[branch]]}}, 's')
        m = {'s': {'f': F(1), 'actions': [[(F(1), 's', 0, 1)]]}}
        for kwargs in ({'horizon': 9}, {'gap': True}, {'z': F(1)}, {'horizon': -1}):
            with self.assertRaises(ValueError):
                analyze(m, 's', **kwargs)

    def test_never_issues_native_qualification(self):
        m = {'s': {'f': F(1), 'actions': [[(F(1), 's', 0, 1)]]}}
        r = analyze(m, 's')
        self.assertIsNone(r['native_failure_bound'])
        self.assertFalse(r['production_activation'])


if __name__ == '__main__':
    unittest.main()
