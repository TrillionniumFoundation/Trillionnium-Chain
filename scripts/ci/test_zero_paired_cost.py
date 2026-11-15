#!/usr/bin/env python3
"""Synthetic cost-accounting tests; no fixture is proof/hardware evidence."""
from __future__ import annotations

import copy
from contextlib import redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from analyze_zero_paired_cost import (FALSE_FLAGS, MODES, STRATEGIES, TARGETS, TIMING_SCOPE,
                                     main, projection, ratio, read_bound_report, summarize_report)


def fixture():
    data = {'schema': 'pon-w1-zero-locality-v2', 'zero_structure_only': True,
        'seed': 0, 'samples_per_case_target': 2, 'searches_per_cohort': 2, 'attempt_budget': 8,
        'targets': list(TARGETS), 'timing': 'monotonic-wall-elapsed-nanoseconds-not-cpu-accounting',
        'timing_scope': dict(TIMING_SCOPE), 'observations': [], **{key: False for key in FALSE_FLAGS}}
    for target in TARGETS:
        for sample in range(2):
            for order in range(10):
                invocation = (sample // 2 + (order if sample % 2 == 0 else 9 - order)) % 10
                strategy, mode = STRATEGIES[invocation // 2], MODES[invocation % 2]
                outcomes = []
                for index in range(2):
                    winner = index == 0
                    outcomes.append({'search_index': index, 'status': 'winner' if winner else 'exhausted',
                        'attempts': 1 if winner else 8, 'search_elapsed_ns': 10 if winner else 80,
                        'ticket_stream_commitment': '1' * 64, 'proof_stream_commitment': '2' * 64,
                        'winning_challenge': '3' * 64 if winner else None,
                        'winner_proof_commitment': '4' * 64 if winner else None,
                        'production_verifier_elapsed_ns': 20 if winner else None,
                        'reference_verifier_elapsed_ns': 25 if winner else None,
                        'reference_verifier_first': (sample % 2 == 0) if winner else None})
                setups = [5] * (2 if mode == MODES[0] else 1)
                data['observations'].append({'class': 'zero', 'input_source': 'synthetic-fixture',
                    'task': 'a' * 64, 'rank_a': 0, 'rank_b': 0, 'target': target, 'sample': sample,
                    'invocation_order': order, 'strategy': strategy, 'method': 'synthetic-accounting-only',
                    'mode': mode, 'proof_bytes': 49188, 'setup_observations_ns': setups,
                    'setup_calls': len(setups), 'setup_elapsed_ns': sum(setups), 'search_elapsed_ns': 90,
                    'total_elapsed_ns': 90 + sum(setups), 'outcomes': outcomes})
    return data


def scale_generation(row, factor):
    row['setup_observations_ns'] = [v * factor for v in row['setup_observations_ns']]
    for field in ('setup_elapsed_ns', 'search_elapsed_ns', 'total_elapsed_ns'):
        row[field] *= factor
    for outcome in row['outcomes']:
        outcome['search_elapsed_ns'] *= factor


class PairedCostTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()

    def rejected(self, change):
        change(self.data)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            summarize_report(self.data)

    def test_totals_include_exhaustion_misses_and_setup(self):
        arm = summarize_report(self.data)['groups'][0]['arms'][0]
        self.assertEqual((arm['attempts'], arm['winners'], arm['exhausted'], arm['target_misses']), (18, 2, 2, 16))
        self.assertEqual((arm['setup_elapsed_ns'], arm['search_elapsed_ns'], arm['generation_elapsed_ns']), (20, 180, 200))
        self.assertEqual(arm['generation_ns_per_winner'], ratio(200, 2))
        self.assertEqual(arm['observed_generation_to_production_verifier_ratio'], ratio(200, 40))

    def test_modes_and_targets_are_never_pooled(self):
        groups = summarize_report(self.data)['groups']
        self.assertEqual([(g['target'], g['mode']) for g in groups], [(t, m) for t in TARGETS for m in MODES])
        self.assertEqual(groups[1]['arms'][0]['generation_elapsed_ns'], 190)

    def test_one_fixed_arm_is_selected_not_per_sample_hindsight(self):
        for row in self.data['observations']:
            if row['strategy'] == 'blocked-zero':
                scale_generation(row, 3 if row['sample'] else 1)
            elif row['strategy'] == 'blocked-zero-integer-paired':
                scale_generation(row, 3 if not row['sample'] else 1)
            else:
                scale_generation(row, 3)
        groups = summarize_report(self.data)['groups']
        self.assertEqual(groups[0]['lowest_observed_fixed_arms'], ['blocked-zero', 'blocked-zero-integer-paired'])
        self.assertEqual(groups[0]['arms'][2]['generation_elapsed_ns'], 400)

    def test_slow_new_arm_is_retained_and_compared_to_old_fastest(self):
        for row in self.data['observations']:
            if row['strategy'] == STRATEGIES[-1]:
                scale_generation(row, 4)
        group = summarize_report(self.data)['groups'][0]
        self.assertNotIn(STRATEGIES[-1], group['lowest_observed_fixed_arms'])
        self.assertEqual(group['arms'][-1]['comparisons'][1]['aggregate_cost_ratio'], ratio(800, 200))

    def test_exact_ratios_not_averages_of_per_sample_ratios(self):
        for row in self.data['observations']:
            if row['strategy'] == STRATEGIES[0] and row['sample'] == 1:
                scale_generation(row, 9)
            if row['strategy'] == STRATEGIES[-1]:
                scale_generation(row, 2)
        comparison = summarize_report(self.data)['groups'][0]['arms'][-1]['comparisons'][0]
        self.assertEqual(comparison['aggregate_cost_ratio'], ratio(400, 1000))
        self.assertEqual([p['cost_ratio'] for p in comparison['paired_samples']], [ratio(200, 100), ratio(200, 900)])

    def test_all_tied_arms_are_retained(self):
        self.assertEqual(summarize_report(self.data)['groups'][0]['lowest_observed_fixed_arms'], list(STRATEGIES))

    def test_zero_successes_keep_all_cost_and_null_success_ratios(self):
        for row in self.data['observations']:
            for outcome in row['outcomes']:
                outcome.update(status='exhausted', attempts=8, winning_challenge=None,
                    winner_proof_commitment=None, production_verifier_elapsed_ns=None,
                    reference_verifier_elapsed_ns=None, reference_verifier_first=None)
        arm = summarize_report(self.data)['groups'][0]['arms'][0]
        self.assertEqual((arm['generation_elapsed_ns'], arm['attempts'], arm['exhausted']), (200, 32, 4))
        self.assertIsNone(arm['generation_ns_per_winner'])
        self.assertIsNone(arm['observed_generation_to_production_verifier_ratio'])

    def test_zero_winner_sample_is_visible_inside_a_successful_aggregate(self):
        for row in self.data['observations']:
            if row['sample'] == 1:
                for outcome in row['outcomes']:
                    outcome.update(status='exhausted', attempts=8, winning_challenge=None,
                        winner_proof_commitment=None, production_verifier_elapsed_ns=None,
                        reference_verifier_elapsed_ns=None, reference_verifier_first=None)
        arm = summarize_report(self.data)['groups'][0]['arms'][0]
        self.assertEqual(arm['winners'], 1)
        self.assertEqual(arm['cohorts'][1]['winners'], 0)
        self.assertIsNone(arm['cohorts'][1]['generation_ns_per_winner'])
        self.assertEqual(arm['cohorts'][1]['generation_elapsed_ns'], 100)

    def test_zero_clock_resolution_does_not_establish_fastest(self):
        for row in self.data['observations']:
            if row['strategy'] == STRATEGIES[-1]:
                scale_generation(row, 0)
        self.assertIsNone(summarize_report(self.data)['groups'][0]['lowest_observed_fixed_arms'])

    def test_zero_verifier_clock_does_not_make_infinite_ratio(self):
        for row in self.data['observations']:
            row['outcomes'][0]['production_verifier_elapsed_ns'] = 0
        self.assertIsNone(summarize_report(self.data)['groups'][0]['arms'][0]['observed_generation_to_production_verifier_ratio'])

    def test_does_not_mutate_input(self):
        before = copy.deepcopy(self.data)
        summarize_report(self.data)
        self.assertEqual(self.data, before)

    def test_output_does_not_promote_proof_or_hardware_acceptance(self):
        result = summarize_report(self.data)
        for key in (*FALSE_FLAGS, 'proof_correctness_replayed', 'native_artifact_authenticity_established',
                    'speed_threshold_applied', 'independent_hardware_qualified', 'confidence_interval_established'):
            self.assertIs(result[key], False)

    def test_missing_arm_rejected(self):
        self.rejected(lambda d: d['observations'].pop())

    def test_different_proof_stream_rejected(self):
        self.rejected(lambda d: d['observations'][4]['outcomes'][1].update(proof_stream_commitment='5' * 64))

    def test_different_reuse_stream_rejected(self):
        self.rejected(lambda d: d['observations'][1]['outcomes'][0].update(ticket_stream_commitment='5' * 64))

    def test_different_task_rejected(self):
        self.rejected(lambda d: d['observations'][1].update(task='b' * 64))

    def test_missing_exhausted_search_rejected(self):
        self.rejected(lambda d: d['observations'][0]['outcomes'].pop())

    def test_boolean_clock_rejected(self):
        self.rejected(lambda d: d['observations'][0].update(total_elapsed_ns=True))

    def test_lost_setup_total_rejected(self):
        self.rejected(lambda d: d['observations'][0].update(total_elapsed_ns=90))

    def test_empty_campaign_rejected(self):
        self.rejected(lambda d: d.update(samples_per_case_target=0, observations=[]))

    def test_fake_exhaustion_verifier_rejected(self):
        self.rejected(lambda d: d['observations'][0]['outcomes'][1].update(production_verifier_elapsed_ns=0))

    def test_unsupported_cannot_be_a_zero_cost_fastest_arm(self):
        self.rejected(lambda d: d['observations'][4]['outcomes'][0].update(status='unsupported', attempts=0))

    def test_historical_schema_not_normalized(self):
        self.rejected(lambda d: d.update(schema='pon-w1-zero-locality-v1'))

    def test_false_scope_not_accepted(self):
        self.rejected(lambda d: d['timing_scope'].update(all_attempts_including_target_misses=False))

    def test_json_byte_digest_and_duplicate_field_controls(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'raw.json'
            raw = b'{"x":1,"x":2}'
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                read_bound_report(path, hashlib.sha256(raw).hexdigest())
            path.write_text('{}')
            with self.assertRaises(ValueError):
                read_bound_report(path, '0' * 64)

    def test_cli_keeps_architectures_separate_and_output_create_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args = []
            for arch in ('x64', 'arm64'):
                raw = copy.deepcopy(self.data)
                if arch == 'arm64':
                    for row in raw['observations']:
                        scale_generation(row, 2)
                path = root / (arch + '.json')
                path.write_text(json.dumps(raw))
                args += ['--' + arch, str(path), '--' + arch + '-sha256', hashlib.sha256(path.read_bytes()).hexdigest()]
            output = root / 'result.json'
            args += ['--output', str(output)]
            self.assertEqual(main(args), 0)
            before = output.read_bytes()
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 1)
            self.assertEqual(output.read_bytes(), before)
            result = json.loads(before)
            self.assertEqual(set(result['architectures']), {'x64', 'arm64'})

    def test_projection_drops_only_clocks_and_preserves_setup_count(self):
        slower = copy.deepcopy(self.data)
        for row in slower['observations']:
            scale_generation(row, 100)
        self.assertEqual(projection(slower), projection(self.data))
        slower['observations'][0]['setup_observations_ns'].append(1)
        self.assertNotEqual(projection(slower), projection(self.data))


if __name__ == '__main__':
    unittest.main()
