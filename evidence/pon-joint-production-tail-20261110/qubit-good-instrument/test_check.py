import itertools
import unittest
from dataclasses import replace
from fractions import Fraction as Q
import check as c


class InstrumentControls(unittest.TestCase):
    def run_model(self, states, initial='live', horizon=2, gap=2):
        return c.certificate(states, initial, Q(2), horizon, gap)

    def test_probability_mass_and_exact_independent_two_cut_truth(self):
        result = self.run_model(c.benign_model())
        # Independent disjoint-event arithmetic: first bad by two cuts or two up.
        exact = 1 - Q(153, 169) ** 2 + Q(9, 169) ** 2
        self.assertEqual(exact, Q(5233, 28561))
        self.assertEqual(result['finite_bad_spending_ceiling'], Q(32, 169))
        self.assertEqual(result['finite_union_allowance'], Q(297, 676))
        self.assertLess(exact, result['finite_union_allowance'])

    def test_independent_exhaustive_scalar_outcome_paths(self):
        # Enumerate all original outcome histories, not the certificate recursion.
        outcomes = [(1, Q(9, 169)), (-1, Q(144, 169)), (None, Q(16, 169))]
        for horizon, gap in itertools.product(range(5), range(5)):
            exact = Q(0)
            for path in itertools.product(outcomes, repeat=horizon):
                probability = Q(1)
                for _, p in path: probability *= p
                credit = 0
                hit = credit >= gap
                for delta, _ in path:
                    if hit: break
                    if delta is None: hit = True; break
                    credit += delta
                    hit = credit >= gap
                if hit: exact += probability
            result = self.run_model(c.benign_model(), horizon=horizon, gap=gap)
            self.assertLessEqual(exact, result['finite_union_allowance'])

    def test_noncommuting_witness_rotation_preserves_operator(self):
        rotation = c.mat(Q(3, 5), Q(-4, 5), Q(4, 5), Q(3, 5))
        before = c.mat(1, 0, 0, 2)
        after = c.mul(rotation, c.mul(before, c.transpose(rotation)))
        self.assertNotEqual(after[0][1], 0)
        states = (c.State('live', before, (c.Action('rotate', (c.Outcome(rotation, 'rotated'),), Q(0)),)),
                  c.State('rotated', after, (c.Action('stop', (c.Outcome(c.I, 'rotated'),), Q(0)),)))
        result = self.run_model(states)
        self.assertEqual(result['initial_potential_upper'], 2)

    def test_coherent_input_violation_hidden_by_diagonal_or_mixed_state(self):
        plus = c.mat(Q(1, 2), Q(1, 2), Q(1, 2), Q(1, 2))
        minus = c.mat(Q(1, 2), Q(-1, 2), Q(-1, 2), Q(1, 2))
        # For moment2P+, both diagonal entries and the maximally mixed mean
        # equal1, but |+> has mean2. A determinant/PSD check must reject.
        moment = c.scale(Q(2), plus)
        self.assertEqual((moment[0][0] + moment[1][1]) / 2, 1)
        self.assertEqual(sum(moment[i][j] for i in range(2) for j in range(2)) / 2, 2)
        state = c.State('live', c.I, (c.Action('coherent', (c.Outcome(plus, 'live', adversarial=1), c.Outcome(minus, None)), Q(1)),))
        with self.assertRaisesRegex(c.Refused, 'GOOD_OPERATOR_MOMENT'):
            self.run_model((state,))

    def test_residual_release_cannot_reset_initial_witness(self):
        state = c.State('live', c.scale(Q(2), c.I), (c.Action('release', (c.Outcome(c.I, 'spent', adversarial=1),), Q(0)),))
        spent = c.State('spent', c.I, (c.Action('stop', (c.Outcome(c.I, 'spent'),), Q(0)),))
        result = self.run_model((state, spent), gap=1)
        self.assertEqual(result['crossing_allowance'], 1)
        with self.assertRaisesRegex(c.Refused, 'GOOD_OPERATOR_MOMENT'):
            self.run_model((replace(state, witness=c.I), spent), gap=1)

    def test_incomplete_probability_mass_is_refused(self):
        original = c.benign_model()[0]
        a = original.actions[0]
        with self.assertRaisesRegex(c.Refused, 'INCOMPLETE_INSTRUMENT'):
            self.run_model((replace(original, actions=(replace(a, outcomes=a.outcomes[:-1]),)),))

    def test_bad_hazard_cannot_be_omitted(self):
        original = c.benign_model()[0]
        with self.assertRaisesRegex(c.Refused, 'BAD_OPERATOR_MASS'):
            self.run_model((replace(original, actions=(replace(original.actions[0], bad_bound=Q(0)),)),))

    def test_unused_actions_are_not_excluded(self):
        live = c.benign_model()[0]
        unsafe = c.Action('not_chosen', (c.Outcome(c.I, 'live', adversarial=1),), Q(0))
        with self.assertRaisesRegex(c.Refused, 'GOOD_OPERATOR_MOMENT'):
            self.run_model((replace(live, actions=live.actions + (unsafe,)),))

    def test_witness_below_identity_is_refused(self):
        with self.assertRaisesRegex(c.Refused, 'WITNESS_BELOW_IDENTITY'):
            self.run_model((replace(c.benign_model()[0], witness=c.scale(Q(1, 2), c.I)),))

    def test_nonsymmetric_witness_is_refused(self):
        with self.assertRaisesRegex(c.Refused, 'SYMMETRIC_REQUIRED'):
            self.run_model((replace(c.benign_model()[0], witness=c.mat(2, 1, 0, 2)),))

    def test_repeated_bad_budget_is_not_refunded_to_one(self):
        result = self.run_model(c.benign_model(), horizon=8)
        self.assertEqual(result['finite_bad_spending_ceiling'], Q(128, 169))
        good = c.Outcome(c.scale(Q(3, 5), c.I), 'live', honest=1)
        bad = c.Outcome(c.scale(Q(4, 5), c.I), None)
        large = self.run_model((c.State('live', c.I, (c.Action('one', (good, bad), Q(16, 25)),)),), horizon=8)
        self.assertEqual(large['finite_bad_spending_ceiling'], Q(128, 25))
        self.assertEqual(large['finite_bad_probability_cap'], 1)

    def test_strict_fraction_types_credit_and_resource_limits(self):
        original = c.benign_model()[0]
        with self.assertRaisesRegex(c.Refused, 'EXACT_FRACTION_REQUIRED'):
            c.certificate((original,), 'live', 2.0, 2, 2)
        bad_credit = replace(original.actions[0].outcomes[0], adversarial=True)
        action = replace(original.actions[0], outcomes=(bad_credit,) + original.actions[0].outcomes[1:])
        with self.assertRaisesRegex(c.Refused, 'CREDIT_RANGE'):
            self.run_model((replace(original, actions=(action,)),))
        with self.assertRaisesRegex(c.Refused, 'HORIZON_RANGE'):
            self.run_model((original,), horizon=9)
        with self.assertRaisesRegex(c.Refused, 'DUPLICATE_STATE'):
            self.run_model((original, original))

    def test_qualification_stays_unproved(self):
        r = self.run_model(c.benign_model())
        self.assertFalse(r['native_reduction_proved'])
        self.assertFalse(r['all_legal_strategies_covered'])
        self.assertIsNone(r['native_CP_CG_CQ_bound'])
        self.assertIsNone(r['six_successor_failure_bound'])
        self.assertIsNone(r['lifetime_failure_bound'])
        self.assertEqual(r['qualification'], 'HOLD_NO_GO')


if __name__ == '__main__':
    unittest.main()
