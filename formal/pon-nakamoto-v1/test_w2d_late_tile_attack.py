"""W2-D late-rejection amplification regression; not a security certification."""
import unittest
import w2d_late_tile_attack as A


class LateTileAttackControls(unittest.TestCase):
    def test_public_initial_half_target_accepts_cheap_false_claim(self):
        row=A.campaign(1,128)
        self.assertEqual(row['status'],'TICKET_HIT_REJECTED')
        self.assertEqual(row['outcome'],'TILE_RELATION')
        self.assertEqual(row['final_tile_corrupted'],511)
        self.assertTrue(row['trial_rows'][-1]['ticket_hit'])
        self.assertFalse(row['verified_work'])
        self.assertFalse(row['chainwork'])
        self.assertFalse(row['production_activation'])
        self.assertGreater(row['complete_negative_verifier_cpu_ns'],0)
        self.assertGreater(row['full_false_attempt_cpu_ns'],0)

    def test_all_hash_misses_are_retained_even_on_hard_target(self):
        row=A.campaign(3,1,bytes(31)+b'\x01')
        self.assertEqual(row['status'],'CAPPED')
        self.assertEqual(len(row['trial_rows']),1)
        self.assertFalse(row['trial_rows'][0]['ticket_hit'])
        self.assertIsNone(row['complete_negative_verifier_cpu_ns'])

    def test_input_and_cost_denominators_are_exact(self):
        row=A.campaign(4,128)
        self.assertEqual(row['full_false_attempt_cpu_ns'],
                         sum(r['cpu_ns'] for r in row['trial_rows']))
        self.assertEqual(len({r['trace'] for r in row['trial_rows']}),len(row['trial_rows']))
        self.assertGreater(row['one_time_legal_setup_cpu_ns'],0)
        self.assertGreater(row['complete_negative_verifier_cpu_ns'],0)
        self.assertEqual(row['schema'],A.SCHEMA)

    def test_fails_closed_for_unbounded_search_inputs(self):
        with self.assertRaisesRegex(ValueError,'CAP'):
            A.campaign(1,0)
        with self.assertRaisesRegex(ValueError,'SEED'):
            A.campaign(-1)
        with self.assertRaisesRegex(ValueError,'TARGET'):
            A.campaign(1,1,bytes(32))


if __name__=='__main__':unittest.main(verbosity=2)
