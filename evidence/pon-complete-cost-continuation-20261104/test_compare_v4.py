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
        self.assertFalse(result['native_execution_verified'])
        self.assertTrue(result['requires_separate_source_binary_and_native_exit_verification'])

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

    def test_spaced_and_escaped_schema_lines_cannot_hide_a_tenth_cell(self):
        text = '\n'.join(json.dumps(row) for row in self.rows)
        self.assertEqual(self.evaluate(READER.parse_rows(text))['status'], 'PASS_COMPONENT_ONLY')
        tenth = json.dumps(self.rows[0])
        for extra in [tenth, tenth.replace('unchanged-snapshot', r'\u0075nchanged-snapshot'), tenth.replace('"schema"', r'"\u0073chema"')]:
            rows = READER.parse_rows(text + '\n' + extra)
            self.assertEqual(len(rows), 10)
            with self.assertRaisesRegex(ValueError, 'nine v4 cells'):
                self.evaluate(rows)

    def test_duplicate_keys_and_malformed_json_like_lines_are_refused(self):
        text = '\n'.join(json.dumps(row) for row in self.rows)
        for extra in [
            '{"schema":"other","schema":"unchanged-snapshot-full-binding-cost-v4"}',
            '{"schema":"unchanged-snapshot-full-binding-cost-v4"',
            '{"schema":"other","nested":{"x":1,"x":2}}',
            '{"schema":"other","value":NaN}',
        ]:
            with self.assertRaises(ValueError):
                READER.parse_rows(text + '\n' + extra)

    def test_float_and_boolean_aliases_cannot_replace_integer_receipts(self):
        for field, value in [
            ('state_keys', 128.0), ('value_width', 64.0),
            ('samples_per_arm', 12.0), ('bindings_per_sample', 8.0),
            ('expected_returns_per_arm', [96.0,96,96]),
            ('unexpected_returns_per_arm', [False,0,0]),
        ]:
            rows = copy.deepcopy(self.rows)
            rows[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.evaluate(rows)
        for value in (False, 0.0):
            rows = copy.deepcopy(self.rows)
            rows[0]['arm_order_per_six_rounds'] = copy.deepcopy(rows[0]['arm_order_per_six_rounds'])
            rows[0]['arm_order_per_six_rounds'][0][0] = value
            with self.assertRaisesRegex(ValueError, 'schedule'):
                self.evaluate(rows)
        rows = copy.deepcopy(self.rows)
        rows[0]['decision']['primary_targets'][0]['state_keys'][0] = 128.0
        with self.assertRaisesRegex(ValueError, 'decision'):
            self.evaluate(rows)

    def test_registration_integer_aliases_are_refused(self):
        for field, value in [('samples_per_arm',12.0), ('bindings_per_sample',8.0), ('permutation_repetitions',2.0)]:
            registration = copy.deepcopy(self.registration)
            registration[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.evaluate(registration=registration)
        registration = copy.deepcopy(self.registration)
        registration['decision']['maximum_missing_or_unexpected_result_bindings'] = False
        with self.assertRaisesRegex(ValueError, 'result requirement'):
            self.evaluate(registration=registration)


if __name__ == '__main__':
    unittest.main()
