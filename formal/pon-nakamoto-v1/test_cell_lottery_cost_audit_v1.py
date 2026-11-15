"""Complete V2 replay distinguishes reusable values from work qualification."""
import unittest

from cell_lottery_cost_audit_v1 import run_audit


class CellLotteryCostAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_audit()

    def test_fresh_full_transcripts_can_have_identical_complete_useful_products(self):
        r = self.report
        self.assertEqual(r['fixed_nonces'], [0, 1])
        self.assertEqual(r['accepted_complete_witnesses'], 2)
        self.assertEqual(r['complete_w1_verifications_in_accepted_paths'], 15)
        self.assertTrue(all(p['useful_product_equal'] and p['transcript_changed']
                            for p in r['products']))

    def test_nonce_and_independent_context_still_require_original_verification(self):
        self.assertEqual(self.report['refusals'], {
            'nonce_change_without_reexecution': 'TRANSCRIPT',
            'noncanonical_witness_whitespace': 'V2_WITNESS_CANONICAL',
            'independent_parent_mismatch': 'EXPECTED_PARENT_CONTEXT'})

    def test_padded_relation_counts_do_not_create_work_or_model_credit(self):
        r = self.report
        self.assertEqual(r['useful_dense_positions'], 15 * 2 * 257)
        self.assertEqual(r['padded_dense_product_positions'], 5 * 64 ** 3)
        self.assertEqual(r['additional_same_witness_replays'], 1)
        self.assertFalse(r['position_counts_are_physical_cost_bounds'])
        self.assertFalse(r['work_profile_qualified'])
        self.assertFalse(r['ordinary_hepta_encoder_verified'])
        self.assertEqual(r['additional_chainwork'], 0)
        self.assertIsNone(r['physical_cost_lower_bound'])
        self.assertEqual(len(r['open_cost_obligations']), 6)


if __name__ == '__main__':
    unittest.main(verbosity=2)
