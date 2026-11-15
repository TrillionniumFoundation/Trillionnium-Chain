#!/usr/bin/env python3
"""Mutation controls over a supplied native capture, never fabricated CPU evidence.

Set PON_WORK_EXPENSIVE_FIXTURE to the exact JSONL emitted by the native example,
(or pass --fixture PATH when running this file). Missing fixture means explicit
SKIP. The fixture must exercise misses, verified hits and multiple actual cache
epochs. These tests validate reader refusals, not execution/clock authenticity.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_work_expensive_reader_v1 as reader


def encode(rows):
    return b''.join(json.dumps(row, separators=(',', ':'), allow_nan=False).encode() + b'\n'
                    for row in rows)


class WorkExpensiveNativeReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = os.environ.get('PON_WORK_EXPENSIVE_FIXTURE')
        if not fixture:
            raise unittest.SkipTest('PON_WORK_EXPENSIVE_FIXTURE is unset: no native capture; '
                                    'invented timings/verdicts are not substituted')
        with Path(fixture).open('rb') as source:
            cls.raw = source.read(reader.MAX_BYTES + 1)
        cls.rows = reader.decode(cls.raw)
        cls.calibration_samples = 1
        cls.report = reader.inspect(cls.raw, calibration_samples=cls.calibration_samples)
        if cls.report['status'] != 'complete':
            raise ValueError('native fixture must contain a complete observed campaign')
        if cls.report['samples'] < 3 or cls.report['attempts_per_arm'] <= cls.report['reuse_attempts']:
            raise ValueError('native fixture must exercise calibration/evaluation and multiple epochs')
        attempts = [row for row in cls.rows if row['kind'] == 'attempt']
        if not any(row['target_hit'] is False for row in attempts):
            raise ValueError('native fixture needs an observed losing attempt')
        if not any(row['target_hit'] is True for row in attempts):
            raise ValueError('native fixture needs an observed verified hit')
        print('native fixture SHA-256: ' + hashlib.sha256(cls.raw).hexdigest(), file=sys.stderr)

    def records(self):
        return copy.deepcopy(self.rows)

    def first(self, rows, kind, **fields):
        return next(row for row in rows if row['kind'] == kind and
                    all(row.get(key) == value for key, value in fields.items()))

    def inspect(self, rows, **kwargs):
        return reader.inspect(encode(rows), calibration_samples=self.calibration_samples, **kwargs)

    def rejects(self, rows, pattern):
        with self.assertRaisesRegex(ValueError, pattern):
            self.inspect(rows)

    def test_complete_native_capture_preserves_all_attempts_and_no_qualification(self):
        result = self.report
        self.assertGreater(result['counts']['attempts'], result['counts']['hits'])
        self.assertEqual(result['counts']['verified_hits'], result['counts']['hits'])
        self.assertEqual(result['counts']['failed_cells'], 0)
        self.assertIsNone(result['gamma'])
        self.assertIsNone(result['gamma_upper_bound'])
        self.assertIsNone(result['native_branch_accepted_work'])
        self.assertIs(result['work_hardness_qualified'], False)
        self.assertIs(result['production_activation'], False)
        self.assertIs(result['budgets']['actual_early_stop_executed'], False)
        for selection in result['calibration_selection']:
            self.assertEqual(selection['calibration_samples'], [0])
            self.assertEqual(selection['evaluation_samples'], list(range(1, result['samples'])))

    def test_removed_losing_attempt_cannot_improve_the_denominator(self):
        rows = self.records()
        rows.remove(self.first(rows, 'attempt', target_hit=False))
        self.rejects(rows, 'ROW_CONTEXT|ROW_ORDER_ATTEMPT')

    def test_removed_setup_or_teardown_cannot_create_free_preparation(self):
        for kind in ('setup', 'teardown'):
            with self.subTest(kind=kind):
                rows = self.records()
                rows.remove(self.first(rows, kind))
                self.rejects(rows, 'ROW_ORDER_' + kind.upper())

    def test_removed_whole_epoch_cannot_shrink_paid_cache_lifetime(self):
        rows = self.records()
        selected = self.first(rows, 'setup', status='prepared', epoch=1)
        context = {key: selected[key] for key in ('class', 'sample', 'arm', 'epoch')}
        rows = [row for row in rows if not all(row.get(key) == value for key, value in context.items())]
        self.rejects(rows, 'ROW_CONTEXT|ROW_ORDER_SETUP')

    def test_repeated_attempt_or_trailing_rows_are_rejected(self):
        rows = self.records()
        index = rows.index(self.first(rows, 'attempt'))
        rows.insert(index + 1, copy.deepcopy(rows[index]))
        self.rejects(rows, 'ROW_CONTEXT|ROW_ORDER_TEARDOWN')
        rows = self.records()
        rows.append(copy.deepcopy(rows[-1]))
        self.rejects(rows, 'EXTRA_ROWS')

    def test_duplicate_json_keys_are_refused_even_when_values_match(self):
        raw = encode(self.rows)
        needle = b'"schema":' + json.dumps(self.rows[0]['schema']).encode()
        self.assertIn(needle, raw)
        mutated = raw.replace(needle, needle + b',' + needle, 1)
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            reader.inspect(mutated, calibration_samples=self.calibration_samples)

    def test_versioned_arm_registry_cannot_relabel_legacy_observations(self):
        rows = self.records()
        other = reader.SCHEMA if rows[0]['schema'] == reader.SCHEMA_V1 else reader.SCHEMA_V1
        for row in rows:
            row['schema'] = other
        self.rejects(rows, 'PROFILE_BINDING')

    def test_mixed_record_namespaces_are_refused(self):
        rows = self.records()
        rows[-1]['schema'] = reader.SCHEMA if rows[0]['schema'] == reader.SCHEMA_V1 else reader.SCHEMA_V1
        self.rejects(rows, 'SCHEMA')

    def test_changed_component_costs_and_cumulative_debits_are_rejected(self):
        for kind, field, nested in (
            ('setup', 'timing', True),
            ('attempt', 'timing', True),
            ('attempt', 'cleanup_timing', True),
            ('teardown', 'timing', True),
            ('attempt', 'producer_cumulative_cpu_ns', False),
            ('cell_summary', 'producer_timing', True),
        ):
            with self.subTest(kind=kind, field=field):
                rows = self.records()
                row = self.first(rows, kind)
                if nested:
                    row[field]['cpu_ns'] += 1
                else:
                    row[field] += 1
                self.rejects(rows, 'PRODUCER_CUMULATIVE|PHASE_SUM_|PRODUCER_SUM')

    def test_missing_cpu_or_boolean_counts_are_not_real_numeric_observations(self):
        mutations = [
            ('run', 'samples', True),
            ('run', 'attempts_per_arm', False),
            ('setup', 'setup_generation', True),
            ('attempt', 'index', True),
            ('attempt', 'producer_cumulative_cpu_ns', False),
            ('teardown', 'actual_attempts', True),
            ('cell_summary', 'attempts', True),
            ('run_summary', 'requested_cells', True),
        ]
        for kind, field, value in mutations:
            with self.subTest(kind=kind, field=field):
                rows = self.records()
                self.first(rows, kind)[field] = value
                self.rejects(rows, 'SAMPLE_LIMIT|ATTEMPT_LIMIT|SETUP_GENERATION|ROW_CONTEXT|'
                             'CUMULATIVE|ACTUAL_REUSE|CELL_COUNT|REQUESTED_CELLS')
        for value in (None, True, -1):
            with self.subTest(cpu_ns=value):
                rows = self.records()
                self.first(rows, 'attempt')['timing']['cpu_ns'] = value
                self.rejects(rows, 'TIMING_VALUE')
        rows = self.records()
        self.first(rows, 'attempt')['timing']['cpu_ns'] = 1.0
        self.rejects(rows, 'NONINTEGER_JSON_NUMBER')

    def test_boolean_verdicts_do_not_accept_integer_aliases(self):
        for kind, field in (('run', 'production_activation'),
                            ('attempt', 'target_hit'),
                            ('attempt', 'stream_equal'),
                            ('teardown', 'lifetime_includes_audit_and_output'),
                            ('run_summary', 'all_attempts_retained')):
            with self.subTest(kind=kind, field=field):
                rows = self.records()
                row = self.first(rows, kind)
                row[field] = int(row[field])
                self.rejects(rows, 'PROFILE_BINDING|HIT_OR_STREAM|CACHE_LIFETIME|RUN_STATUS')

    def test_output_dependent_or_replayed_work_id_is_not_extra_work(self):
        rows = self.records()
        trials = [row for row in rows if row['kind'] == 'attempt']
        self.assertNotEqual(trials[0]['work_id'], trials[1]['work_id'])
        trials[1]['work_id'] = trials[0]['work_id']
        self.rejects(rows, 'WORK_ID')
        rows = self.records()
        trial = self.first(rows, 'attempt')
        task = self.first(rows, 'material')['task']
        target = rows[0]['target']
        trial['work_id'] = reader.H('pon-work-expensive-work-v1',
            bytes.fromhex(trial['challenge']), bytes.fromhex(task), bytes.fromhex(target),
            bytes.fromhex(trial['trace'])).hex()
        self.rejects(rows, 'WORK_ID')

    def test_missing_independent_verification_or_changed_hit_is_refused(self):
        rows = self.records()
        self.first(rows, 'attempt', target_hit=True)['verification']['scalar']['outcome'] = 'Transcript'
        self.rejects(rows, 'NATIVE_VERDICT')
        rows = self.records()
        self.first(rows, 'attempt', target_hit=True)['verification']['products_equal'] = False
        self.rejects(rows, 'VERIFIED_PRODUCT')
        rows = self.records()
        self.first(rows, 'attempt', target_hit=False)['target_hit'] = True
        self.rejects(rows, 'HIT_OR_STREAM')

    def test_fake_future_reuse_and_nonmonotone_epoch_clocks_are_refused(self):
        rows = self.records()
        self.first(rows, 'teardown')['actual_attempts'] += 1
        self.rejects(rows, 'CACHE_LIFETIME')
        rows = self.records()
        self.first(rows, 'setup')['intended_reuse_attempts'] += 1
        self.rejects(rows, 'SETUP_BINDING')
        rows = self.records()
        self.first(rows, 'teardown')['observed_cell_cumulative_cpu_ns'] = 0
        self.rejects(rows, 'TEARDOWN_CLOCK_ORDER')
        rows = self.records()
        self.first(rows, 'cell_summary')['observed_cell_timing']['wall_ns'] = 0
        self.rejects(rows, 'OBSERVED_TOTAL')

    def test_lucky_window_deletion_and_reordering_do_not_change_the_frozen_roster(self):
        rows = self.records()
        rows = [row for row in rows if row.get('sample') != self.report['samples'] - 1]
        self.rejects(rows, 'ROW_ORDER_SETUP|ROW_CONTEXT')
        rows = self.records()
        first = self.first(rows, 'attempt', sample=0)
        second = self.first(rows, 'attempt', sample=1)
        i, j = rows.index(first), rows.index(second)
        rows[i], rows[j] = rows[j], rows[i]
        self.rejects(rows, 'ROW_CONTEXT')
        for calibration in (-1, True, self.report['samples']):
            with self.subTest(calibration_samples=calibration):
                with self.assertRaisesRegex(ValueError, 'CALIBRATION_SPLIT'):
                    reader.inspect(self.raw, calibration_samples=calibration)
        for budgets in ([], [1, 1], [True], [0], [-1], [1.0]):
            with self.subTest(budgets=budgets):
                with self.assertRaisesRegex(ValueError, 'BUDGETS'):
                    reader.inspect(self.raw, budgets=budgets, calibration_samples=1)

    def test_prefix_budgets_use_actual_destroyed_epochs_only(self):
        cell = next(cell for cell in self.report['cells'] if cell['status'] == 'complete')
        first = cell['settled_epoch_boundaries'][0]
        self.assertGreater(first['producer_cpu_ns'], 0)
        self.assertGreater(first['observed_cpu_ns'], 0)
        budgets = sorted(set((first['producer_cpu_ns'] - 1, first['producer_cpu_ns'],
                              first['observed_cpu_ns'] - 1, first['observed_cpu_ns'])))
        budgets = [budget for budget in budgets if budget > 0]
        report = reader.inspect(self.raw, budgets=budgets, calibration_samples=1)
        candidate = next(item for item in report['cells'] if
                         all(item[k] == cell[k] for k in ('class', 'sample', 'arm')))
        for prefix in candidate['prefixes']:
            budget = prefix['budget_cpu_ns']
            for scope in ('producer', 'observed'):
                completed = [entry for entry in candidate['settled_epoch_boundaries']
                             if entry[scope + '_cpu_ns'] <= budget]
                expected = completed[-1]['completed_attempts'] if completed else 0
                self.assertEqual(prefix[scope + '_settled_attempts'], expected)
                if budget < first[scope + '_cpu_ns']:
                    self.assertEqual(prefix[scope + '_verified_unique_hits'], 0)
        self.assertEqual(candidate['actual_cache_lifetimes'][0]['actual_attempts'],
                         self.report['reuse_attempts'])

    def test_evaluation_support_cannot_reselect_the_calibrated_strategy(self):
        # Make a self-consistent unsupported evaluation cell, leaving every
        # calibration observation untouched. Before the support invariant this
        # adversarial capture silently selected a different, favorable arm.
        rows = self.records()
        selection = self.report['calibration_selection'][0]
        context = {'class': selection['class'], 'arm': selection['selected_arm'],
                   'sample': self.report['samples'] - 1}
        indexes = [i for i, row in enumerate(rows)
                   if all(row.get(k) == v for k, v in context.items())]
        setup = copy.deepcopy(rows[indexes[0]])
        old = copy.deepcopy(rows[indexes[-1]])
        self.assertEqual(setup['kind'], 'setup')
        self.assertEqual(old['kind'], 'cell_summary')
        setup.update(status='unsupported', error=None)
        summary = copy.deepcopy(old)
        summary.update(status='unsupported', attempts=0, hits=0, verified_hits=0,
                       setup_count=1, unsupported_count=1, error_count=0,
                       sequence_complete=False, distinct_application_results=0)
        for key in ('setup_timing', 'producer_timing'):
            summary[key] = copy.deepcopy(setup['timing'])
        for key in ('attempt_timing', 'cleanup_timing', 'teardown_timing', 'verification_timing'):
            summary[key] = {'cpu_ns': 0, 'wall_ns': 0}
        rows[indexes[0]:indexes[-1]+1] = [setup, summary]
        final = rows[-1]
        final['completed_cells'] -= 1
        final['unsupported_cells'] += 1
        for key in ('attempts', 'hits', 'verified_hits'):
            final[key] -= old[key]
        self.rejects(rows, 'SUPPORT_CHANGED_WITH_SAMPLE')

    def test_replicate_budget_is_not_misrepresented_as_one_total_budget(self):
        for selection in self.report['calibration_selection']:
            n = len(selection['evaluation_samples'])
            for row in selection['evaluation_budget_counts']:
                self.assertEqual(row['evaluation_replicates'], n)
                self.assertEqual(row['aggregate_budget_ceiling_cpu_ns'],
                                 n * row['per_sample_budget_cpu_ns'])
                self.assertEqual(row['selected_mean_hits_per_replicate'],
                                 row['selected_hits_across_replicates'] / n)

    def test_truncated_missing_final_record_or_extra_success_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'TRUNCATED_OR_OVERSIZED_STREAM'):
            reader.inspect(self.raw[:-1], calibration_samples=1)
        self.rejects(self.records()[:-1], 'MISSING_RUN_SUMMARY')
        rows = self.records()
        rows[-1]['verified_hits'] += 1
        self.rejects(rows, 'RUN_COUNT_verified_hits')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--fixture', type=Path)
    args, remaining = parser.parse_known_args()
    if args.fixture is not None:
        os.environ['PON_WORK_EXPENSIVE_FIXTURE'] = str(args.fixture)
    unittest.main(argv=[sys.argv[0], *remaining])
