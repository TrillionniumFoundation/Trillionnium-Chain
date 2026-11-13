"""Adversarial CPU denominator controls, not production cost validation."""
import unittest
import w2e_matched_costs as S

class MatchedCostTests(unittest.TestCase):
    def test_real_five_round_and_late_ticket_amplification_are_both_retained(self):
        report=S.report((1,3),128)
        self.assertEqual([row['material'] for row in report['honest_rows']],
                         ['dense','zero','sparse'])
        self.assertEqual([row['seed'] for row in report['invalid_rows']],[1,3])
        self.assertTrue(all(row['outcome']=='BATCHED_TILE_RELATION'
                            for row in report['invalid_rows']))
        for row in report['invalid_rows']:
            self.assertEqual(row['full_false_attempt_cpu_ns'],
                             sum(v['cpu_ns'] for v in row['trial_rows']))
            self.assertTrue(row['trial_rows'][-1]['ticket_hit'])
            self.assertGreater(row['one_time_legal_setup_cpu_ns'],0)
            self.assertFalse(row['chainwork'])
        self.assertFalse(report['production_activation'])
        self.assertFalse(report['full_verified_work'])

    def test_invalid_bounds_reject(self):
        for seeds in ((),(1,1),tuple(range(17))):
            with self.assertRaisesRegex(ValueError,'SEEDS'):
                S.report(seeds,1)
        with self.assertRaisesRegex(ValueError,'CAP'):
            S.report((1,),0)

if __name__=='__main__':unittest.main(verbosity=2)
