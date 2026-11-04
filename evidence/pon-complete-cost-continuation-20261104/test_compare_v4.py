"""Synthetic in-memory reader controls; never generate performance evidence."""
from pathlib import Path
import copy
import importlib.util
import json
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('compare_v4', HERE/'compare_v4.py')
READER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(READER)


class ComparisonReaderTests(unittest.TestCase):
    def setUp(self):
        self.registration = json.loads((HERE/'comparison-preregistration.json').read_text())
        self.readback = {'source_sha256':self.registration['compiled_test_source_sha256']}
        self.provenance = self.registration['reference_provenance']
        source = {
            'original_full_map_commit':self.registration['original_commit'],
            'parent_shared_map_commit':self.registration['actual_parent_commit'],
            'original_reference_source_sha256':self.provenance['original_full_map']['file_sha256'],
            'parent_reference_source_sha256':self.provenance['actual_parent_shared_map']['file_sha256'],
            'compiled_production_source_sha256':self.registration['candidate_production_sha256'],
            'compiled_test_source_sha256':self.readback['source_sha256'],
        }
        self.rows = []
        for count, width in self.registration['common_inputs']:
            for case in self.registration['cases']:
                self.rows.append({
                    'schema':'unchanged-snapshot-full-binding-cost-v4',
                    'state_keys':count, 'value_width':width, 'case':case,
                    'decision':copy.deepcopy(self.registration['decision']),
                    'arm_names':self.registration['arms'],
                    'arm_order_per_six_rounds':self.registration['six_permutation_order'],
                    'order':'fixed six-permutation rotation repeated twice',
                    'samples_per_arm':12, 'bindings_per_sample':8,
                    'expected_returns_per_arm':[96,96,96],
                    'unexpected_returns_per_arm':[0,0,0],
                    'equal_result':True, 'complete_actual_state_compared':True,
                    'expected_root_checked':True, 'tree_empty_delta_check_retained':True,
                    'public_tps_measured':False, 'node_owner_measured':False,
                    'physical_memory_bound':False, 'source_identity':copy.deepcopy(source),
                    'original_full_map_ns':[1000]*12,
                    'parent_40a_shared_map_ns':[1000]*12,
                    'checked_shared_map_ns':[900]*12,
                })

    def evaluate(self, rows=None, registration=None):
        return READER.evaluate(
            self.rows if rows is None else rows,
            self.registration if registration is None else registration,
            self.readback, self.provenance,
        )

    def test_complete_synthetic_cohorts_preserve_component_scope_and_denominators(self):
        result = self.evaluate()
        self.assertEqual(result['status'], 'PASS_COMPONENT_ONLY')
        self.assertEqual(len(result['comparisons']), 18)
        self.assertEqual(result['planned_bindings'], 2592)
        self.assertEqual(result['expected_commitment_root_error_bindings'], 1728)
        self.assertFalse(result['public_business_gate_replaced'])
        self.assertFalse(result['statistical_confidence_established'])

    def test_both_primary_targets_keep_exact_five_percent_boundary(self):
        for index in (0, 2):
            rows = copy.deepcopy(self.rows)
            rows[index]['checked_shared_map_ns'] = [950]*12
            self.assertEqual(self.evaluate(rows)['status'], 'PASS_COMPONENT_ONLY')
            rows[index]['checked_shared_map_ns'] = [951]*12
            self.assertEqual(self.evaluate(rows)['status'], 'HOLD')
        weakened = copy.deepcopy(self.registration)
        weakened['decision']['primary_targets'] = []
        with self.assertRaisesRegex(ValueError, 'primary targets'):
            self.evaluate(registration=weakened)

    def test_one_tail_regression_cannot_hide_inside_faster_median(self):
        rows = copy.deepcopy(self.rows)
        rows[1]['checked_shared_map_ns'][-1] = 1100
        self.assertEqual(self.evaluate(rows)['status'], 'PASS_COMPONENT_ONLY')
        rows[1]['checked_shared_map_ns'][-1] = 1101
        self.assertEqual(self.evaluate(rows)['status'], 'HOLD')

    def test_missing_duplicate_and_nonpositive_samples_are_refused(self):
        with self.assertRaisesRegex(ValueError, 'nine v4 cells'):
            self.evaluate(self.rows[:-1])
        rows = copy.deepcopy(self.rows)
        rows[-1] = rows[0]
        with self.assertRaisesRegex(ValueError, 'duplicate cell'):
            self.evaluate(rows)
        for invalid in (0, -1, True, 1.5):
            rows = copy.deepcopy(self.rows)
            rows[0]['checked_shared_map_ns'][0] = invalid
            with self.assertRaisesRegex(ValueError, 'timing'):
                self.evaluate(rows)

    def test_unexpected_or_missing_return_bindings_are_refused(self):
        for field, value in [('unexpected_returns_per_arm',[0,1,0]), ('expected_returns_per_arm',[96,95,96])]:
            rows = copy.deepcopy(self.rows)
            rows[0][field] = value
            with self.assertRaisesRegex(ValueError, 'returns'):
                self.evaluate(rows)

    def test_source_relabelling_and_mixed_experiment_bytes_are_refused(self):
        for field in ('parent_shared_map_commit','compiled_production_source_sha256','compiled_test_source_sha256'):
            rows = copy.deepcopy(self.rows)
            rows[0]['source_identity'][field] = 'substituted'
            with self.assertRaisesRegex(ValueError, 'source'):
                self.evaluate(rows)

    def test_schedule_and_recorded_decision_must_match_registration(self):
        rows = copy.deepcopy(self.rows)
        rows[0]['arm_order_per_six_rounds'] = [[0,1,2]]*6
        with self.assertRaisesRegex(ValueError, 'schedule'):
            self.evaluate(rows)
        rows = copy.deepcopy(self.rows)
        rows[0]['decision']['maximum_p95_regression_fraction'] = 1.0
        with self.assertRaisesRegex(ValueError, 'decision'):
            self.evaluate(rows)


if __name__ == '__main__':
    unittest.main()
