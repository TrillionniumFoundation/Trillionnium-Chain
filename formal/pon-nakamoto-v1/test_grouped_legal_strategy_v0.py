"""Adversarial equality and honest accounting checks for lawful Cell shortcuts."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from grouped_legal_strategy_v0 import (
    ARMS, ArithmeticCache, DIM, REPRESENTATION, execute, independent_reference,
    observe, prepare, validate_requests)
from experiments import grouped_legal_strategy_v0 as campaign


def fixture(rank=1):
    model = {'fixture': 'controlled-no-training-no-demand',
             'base': [[((r * 7 + k * 11) % 13) - 6 for k in range(DIM)] for r in range(3)],
             'router': [[((e * 5 + k * 3) % 11) - 5 for k in range(DIM)] for e in range(3)],
             'deltas': []}
    factors = []
    for e in range(3):
        down = [[((k + j * 3 + e) % 5) - 2 for k in range(DIM)] for j in range(rank)]
        up = [[((r + j + e) % 5) - 2 for j in range(rank)] for r in range(3)]
        factors.append({'up': up, 'down': down})
        model['deltas'].append([[sum(up[r][j] * down[j][k] for j in range(rank))
                                 for k in range(DIM)] for r in range(3)])
    return model, factors


def requests(count=8, x=None):
    return [{'id': f'request-{i}', 'scope': 'owned-test-scope', 'generation': 'generation-1',
             'representation': REPRESENTATION,
             'x': list(x) if x is not None else [((k * 7 + i * 3) % 17) - 8 for k in range(256)] + [8]}
            for i in range(count)]


class LegalStrategyTests(unittest.TestCase):
    def test_every_lawful_strategy_matches_complete_independent_relation(self):
        for rank in (1, 3, 8):
            model, factors = fixture(rank)
            for rows in (requests(), requests(x=[0] * 256 + [8]), requests(x=[8] * 257)):
                expected, _ = independent_reference(model, rows)
                for arm in ARMS:
                    with self.subTest(rank=rank, arm=arm):
                        actual, _ = execute(prepare(model, arm, factors), rows)
                        self.assertEqual(actual, expected)

    def test_bias_only_is_legal_but_zero_bias_is_not(self):
        model, _ = fixture()
        rows = requests(64, [0] * 256 + [8])
        output, cost = execute(prepare(model, 'sparse_cached_merged'), rows)
        self.assertEqual(cost.execution_macs, 6 * 64)
        self.assertEqual(cost.input_scan_elements, DIM * 64)
        self.assertEqual(output['useful_dense_macs'], 6 * DIM * 64)
        self.assertEqual(output['useful_dense_macs'] // cost.execution_macs, 257)
        with self.assertRaisesRegex(ValueError, 'INPUT_BIAS'):
            execute(prepare(model, 'sparse_cached_merged'), requests(1, [0] * DIM))

    def test_input_validation_precedes_cache_hit(self):
        model, _ = fixture()
        prepared = prepare(model, 'repeated_cached_merged')
        cache = ArithmeticCache()
        rows = requests(2, [0] * 256 + [8])
        execute(prepared, rows, cache=cache)
        for change, expected in ((True, 'INPUT_RANGE'), (9, 'INPUT_RANGE'), (0.5, 'INPUT_RANGE')):
            bad = copy.deepcopy(rows)
            bad[0]['x'][2] = change
            with self.assertRaisesRegex(ValueError, expected):
                execute(prepared, bad, cache=cache)

    def test_repeated_inputs_reduce_arithmetic_not_reference_or_commitments(self):
        model, _ = fixture()
        report = observe(model, requests(64, [1] * 256 + [8]),
                         arm='repeated_cached_merged', rounds=2)
        first, second = report['attempts']
        self.assertEqual(first['cost']['execution_macs'], 6 * DIM)
        self.assertEqual(first['cost']['cache_hits'], 63)
        self.assertEqual(second['cost']['execution_macs'], 0)
        self.assertEqual(second['cost']['cache_hits'], 64)
        self.assertEqual(report['total_cost']['reference_macs'], 2 * 9 * DIM * 64)
        self.assertEqual(report['preparation']['cost']['preparation_additions'], 3 * 3 * DIM)
        self.assertEqual(report['total_cost']['preparation_additions'], 3 * 3 * DIM)
        self.assertGreater(first['cost']['hash_input_bytes'], 0)
        self.assertGreater(second['cost']['hash_input_bytes'], 0)
        self.assertTrue(report['rounds_are_replayed_requests'])
        self.assertEqual(report['chainwork_awarded'], 0)
        self.assertFalse(report['minimum_legal_cost_proved'])

    def test_cache_separates_input_model_scope_generation_and_representation(self):
        model, _ = fixture()
        prepared = prepare(model, 'repeated_cached_merged')
        rows = requests(1)
        cache = ArithmeticCache()
        execute(prepared, rows, cache=cache)
        for field, replacement in (('scope', 'other-owner'), ('generation', 'generation-2')):
            changed = copy.deepcopy(rows)
            changed[0][field] = replacement
            _, cost = execute(prepared, changed, cache=cache)
            self.assertEqual(cost.cache_hits, 0)
        changed = copy.deepcopy(rows)
        changed[0]['x'][0] = 7
        _, cost = execute(prepared, changed, cache=cache)
        self.assertEqual(cost.cache_hits, 0)
        other_model = copy.deepcopy(model)
        other_model['base'][0][0] += 1
        _, cost = execute(prepare(other_model, 'repeated_cached_merged'), rows, cache=cache)
        self.assertEqual(cost.cache_hits, 0)
        changed = copy.deepcopy(rows)
        changed[0]['representation'] = 'f32-merged'
        with self.assertRaisesRegex(ValueError, 'REPRESENTATION'):
            execute(prepared, changed, cache=cache)
        # Request ID changes need a new observation, but cannot alter pure math.
        changed = copy.deepcopy(rows)
        changed[0]['id'] = 'fresh-request'
        _, cost = execute(prepared, changed, cache=cache)
        self.assertEqual(cost.cache_hits, 1)

    def test_bounded_cache_eviction_does_not_create_wrong_output(self):
        model, _ = fixture()
        rows = requests(4)
        prepared = prepare(model, 'repeated_cached_merged')
        cache = ArithmeticCache(1)
        expected, _ = independent_reference(model, rows)
        for _ in range(2):
            actual, cost = execute(prepared, rows, cache=cache)
            self.assertEqual(actual, expected)
            self.assertEqual(cost.cache_hits, 0)
            self.assertEqual(cache.entries, 1)

    def test_factor_comparison_includes_router_base_and_full_preparation(self):
        for rank in (1, 3, 8):
            model, factors = fixture(rank)
            rows = requests(4)
            report = observe(model, rows, arm='factor_selected', factors=factors)
            cost = report['attempts'][0]['cost']
            self.assertEqual(cost['execution_macs'], 4 * (6 * DIM + rank * (DIM + 3)))
            self.assertEqual(report['preparation']['cost']['preparation_macs'], 3 * 3 * rank * DIM)
            self.assertGreater(cost['execution_macs'], 4 * 6 * DIM)
            self.assertEqual(cost['reference_macs'], 4 * 9 * DIM)
            self.assertTrue(report['arithmetic_semantics_verified'])

    def test_factor_admission_checks_unobserved_coordinates(self):
        model, factors = fixture()
        rows = requests(4, [0] * 256 + [8])
        changed = copy.deepcopy(factors)
        changed[0]['down'][0][0] += 1
        with self.assertRaisesRegex(ValueError, 'FACTOR_NOT_SAME_DELTA'):
            prepare(model, 'factor_selected', changed)
        report = observe(model, rows, arm='factor_selected', factors=changed, rounds=3)
        self.assertFalse(report['arithmetic_semantics_verified'])
        self.assertEqual(report['attempts'][0]['stage'], 'preparation')
        self.assertFalse(report['attempts'][0]['partial_operation_counts_available'])
        self.assertEqual(report['attempts'][0]['round'], 0)
        self.assertIsNone(report['attempts'][0]['cost'])
        self.assertIsNone(report['total_cost'])
        self.assertEqual(report['attempted_rounds'], 1)
        self.assertEqual([a['round'] for a in report['not_started']], [1, 2])
        self.assertTrue(report['round_accounting_complete'])
        self.assertFalse(report['instrumented_counts_complete'])
        report['observation_id'] = 'preparation-failure'
        plan = {'planned_observations': 1, 'planned_rounds': 3,
                'observations': [{'observation_id': 'preparation-failure',
                                  'planned_rounds': 3, 'round_indices': [0, 1, 2]}]}
        accounting = campaign.account_plan(plan, [report], [])
        self.assertEqual(accounting['actual_attempts'], 1)
        self.assertEqual(accounting['not_started_rounds'], 2)
        self.assertEqual(accounting['planned_rounds'], 3)
        self.assertTrue(accounting['round_accounting_complete'])
        self.assertGreater(report['whole_observation_wall_ns'], 0)

    def test_original_extreme_coefficients_fit_exact_relation(self):
        model = {'base': [[32767] * DIM for _ in range(3)],
                 'router': [[-32767] * DIM for _ in range(3)],
                 'deltas': [[[32767] * DIM for _ in range(3)] for _ in range(3)]}
        rows = requests(1, [8] * DIM)
        expected, _ = independent_reference(model, rows)
        self.assertEqual(expected['logits'], [[134737904] * 3])
        self.assertEqual(expected['routes'], [0])
        self.assertEqual(expected['predictions'], [0])
        for arm in ARMS[:-1]:
            self.assertEqual(execute(prepare(model, arm), rows)[0], expected)
        model['base'][0][0] = 32768
        with self.assertRaisesRegex(ValueError, 'BASE_RANGE'):
            prepare(model, 'direct_cached_merged')

    def test_caller_mutation_cannot_change_prepared_model(self):
        model, factors = fixture()
        expected, _ = independent_reference(model, requests())
        prepared = prepare(model, 'factor_selected', factors)
        model['base'][0][0] += 1
        factors[0]['down'][0][0] += 1
        self.assertEqual(execute(prepared, requests())[0], expected)

    def test_invalid_requests_and_rank_limits_are_rejected(self):
        model, factors = fixture()
        for rows in ([], requests(65), requests(1) * 2):
            with self.assertRaises(ValueError):
                validate_requests(rows)
        for bad_rank in (0, 9):
            changed = copy.deepcopy(factors)
            changed[0]['down'] = [[1] * DIM for _ in range(bad_rank)]
            with self.assertRaisesRegex(ValueError, 'FACTOR_RANK'):
                prepare(model, 'factor_selected', changed)
        for capacity in (0, 65, True):
            with self.assertRaisesRegex(ValueError, 'CACHE_CAPACITY'):
                ArithmeticCache(capacity)

    def test_unexpected_execution_failure_retains_every_attempt(self):
        model, _ = fixture()
        with patch('grouped_legal_strategy_v0.execute', side_effect=RuntimeError('injected-engine-failure')):
            report = observe(model, requests(1), arm='direct_cached_merged', rounds=3)
        self.assertEqual(len(report['attempts']), 3)
        self.assertTrue(all(a['status'] == 'rejected' and a['error'] == 'injected-engine-failure'
                            for a in report['attempts']))
        self.assertFalse(report['arithmetic_semantics_verified'])
        self.assertGreater(report['whole_observation_cpu_ns'], 0)

    def test_independent_verifier_failure_does_not_count_success(self):
        model, _ = fixture()
        with patch('grouped_legal_strategy_v0.independent_reference', side_effect=RuntimeError('verifier-failure')):
            report = observe(model, requests(1), arm='direct_cached_merged', rounds=2)
        self.assertTrue(all(a['status'] == 'rejected' and a['stage'] == 'independent_reference'
                            for a in report['attempts']))
        self.assertIsNone(report['total_cost'])
        self.assertEqual(report['known_completed_stage_cost']['execution_macs'], 2 * 6 * DIM)
        self.assertTrue(all(a['cost'] is None for a in report['attempts']))
        self.assertTrue(all(not a['partial_operation_counts_available'] for a in report['attempts']))

    def test_failure_rounds_remain_in_denominator(self):
        model, _ = fixture()
        rows = requests(1, [0] * DIM)
        report = observe(model, rows, arm='direct_cached_merged', rounds=3)
        self.assertEqual(report['planned_rounds'], 3)
        self.assertEqual(len(report['attempts']), 3)
        self.assertTrue(all(a['status'] == 'rejected' for a in report['attempts']))
        self.assertTrue(all(a['error'] == 'INPUT_BIAS' for a in report['attempts']))
        self.assertFalse(report['arithmetic_semantics_verified'])
        self.assertTrue(report['all_attempts_retained'])


class CampaignIntegrityTests(unittest.TestCase):
    def test_manifest_includes_imported_verification_and_feature_sources(self):
        required = {'experiments/shared_cell_operator_v1.py', 'experiments/model_loop.py',
                    'evaluation_bundle.py', 'model_contract.py', 'contract_wire.py',
                    'evaluation.py', 'ledger.py', 'strict_signature.py', 'work_backend.py',
                    'work_oracle.py', 'bounded_process.py'}
        self.assertTrue({campaign.FORMAL + path for path in required} <= set(campaign.RELEVANT_SOURCES))

    def test_exact_source_gate_rejects_untracked_and_hidden_changed_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(['git', *args], cwd=root, text=True).strip()

            git('init', '-q')
            (root / 'tracked.py').write_text('VALUE = 1\n')
            git('add', 'tracked.py')
            git('-c', 'user.name=Legal Strategy Test', '-c', 'user.email=legal-strategy@example.invalid',
                'commit', '-q', '--no-gpg-sign', '-m', 'source guard fixture')
            expected = git('rev-parse', 'HEAD')
            (root / 'untracked-evidence.json').write_text('{}\n')
            clean = campaign.source_identity(root=root, sources=('tracked.py',))
            self.assertTrue(clean['tracked_tree_clean'])
            self.assertFalse(clean['clean'])
            self.assertEqual(campaign.source_gate_failures(clean, expected), [])
            self.assertIn('SOURCE_SHA_MISMATCH', {
                row['reason'] for row in campaign.source_gate_failures(clean, '0' * 40)})
            self.assertIn('EXPECTED_SOURCE_SHA_FORMAT', {
                row['reason'] for row in campaign.source_gate_failures(clean, 'HEAD')})

            (root / 'new-runner.py').write_text('VALUE = 2\n')
            untracked = campaign.source_identity(root=root, sources=('tracked.py', 'new-runner.py'))
            self.assertTrue(untracked['tracked_tree_clean'])
            self.assertIn({'reason': 'RELEVANT_SOURCE_NOT_IN_HEAD', 'path': 'new-runner.py'},
                          campaign.source_gate_failures(untracked, expected))

            (root / 'tracked.py').write_text('VALUE = 2\n')
            dirty = campaign.source_identity(root=root, sources=('tracked.py',))
            self.assertIn({'reason': 'TRACKED_TREE_DIRTY'}, campaign.source_gate_failures(dirty, expected))
            git('update-index', '--assume-unchanged', 'tracked.py')
            hidden = campaign.source_identity(root=root, sources=('tracked.py',))
            self.assertTrue(hidden['tracked_tree_clean'])
            self.assertIn({'reason': 'RELEVANT_SOURCE_BYTES_DIFFER', 'path': 'tracked.py'},
                          campaign.source_gate_failures(hidden, expected))

    def test_source_gate_failure_prevents_observations_but_retains_full_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            args = campaign.parser().parse_args(['--out', str(Path(directory) / 'run'),
                                                 '--source-sha', '0' * 40])
            with patch.object(campaign, 'load_inputs') as loader, patch.object(campaign, 'observe') as observer:
                report = campaign.run(args)
            loader.assert_not_called()
            observer.assert_not_called()
            self.assertEqual(report['measurement_mode'], 'final_exact_source')
            self.assertFalse(report['exact_committed_source_verified'])
            self.assertEqual(report['planned_observations'], 151)
            self.assertEqual(report['planned_rounds'], 453)
            self.assertEqual(report['actual_attempts'], 0)
            self.assertEqual(report['not_started_rounds'], 453)
            self.assertTrue(report['round_accounting_complete'])
            self.assertTrue((args.out / 'plan.json').is_file())

    def test_load_failure_retains_unstarted_real_arms_and_preregistered_schedule(self):
        with tempfile.TemporaryDirectory() as directory:
            args = campaign.parser().parse_args(['--out', str(Path(directory) / 'run'),
                                                 '--batch-size', '1', '--rounds', '3'])

            def fail_loader(*unused_args, **unused_kwargs):
                plan = json.loads((args.out / 'plan.json').read_text())
                self.assertEqual(plan['planned_observations'], 13)
                self.assertEqual(plan['planned_rounds'], 39)
                self.assertTrue(all(row['round_indices'] == [0, 1, 2] for row in plan['observations']))
                raise RuntimeError('injected-source-load-failure')

            with patch.object(campaign, 'CONTROL_RANKS', (1,)), \
                    patch.object(campaign, 'CONTROL_NAMES', ('bias_only',)), \
                    patch.object(campaign, 'load_inputs', side_effect=fail_loader):
                report = campaign.run(args)
            self.assertEqual(report['measurement_mode'], 'development_unqualified')
            self.assertFalse(report['exact_committed_source_verified'])
            self.assertEqual(report['planned_rounds'], 39)
            self.assertEqual(report['actual_attempts'], 24)
            self.assertEqual(report['not_started_rounds'], 15)
            self.assertEqual(report['verified_attempts'], 18)
            self.assertEqual(report['rejected_attempts'], 6)
            self.assertTrue(report['round_accounting_complete'])
            self.assertEqual(len(report['not_started_observations']), 5)
            self.assertTrue(all(row['cost'] is None for row in report['not_started_observations']))

    def test_after_gate_invalidates_otherwise_successful_exact_source_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model, _ = fixture()
            model_path = root / 'model.json'
            model_path.write_text(json.dumps(model))
            expected = 'a' * 40
            args = campaign.parser().parse_args(['--out', str(root / 'run'), '--model', str(model_path),
                                                 '--batch-size', '1', '--rounds', '3',
                                                 '--source-sha', expected])
            before = {'commit': expected, 'tracked_tree_clean': True,
                      'relevant_sources': {'fixture.py': {'tracked_at_head': True, 'matches_head_bytes': True}},
                      'relevant_sources_sha256': {'fixture.py': 'b' * 64}}
            after = dict(before, tracked_tree_clean=False)
            provenance = {'model_artifact': 'c' * 64, 'scope': 'unit-test-fixture', 'selected_tasks': {'rows': 1}}
            with patch.object(campaign, 'CONTROL_RANKS', (1,)), \
                    patch.object(campaign, 'CONTROL_NAMES', ('bias_only',)), \
                    patch.object(campaign, 'load_inputs', return_value=(model, requests(1), provenance)), \
                    patch.object(campaign, 'source_identity', side_effect=[before, after]) as identity:
                report = campaign.run(args)
            self.assertEqual(identity.call_count, 2)
            self.assertEqual(report['actual_attempts'], 39)
            self.assertEqual(report['verified_attempts'], 33)
            self.assertEqual(report['rejected_attempts'], 6)
            self.assertTrue(report['round_accounting_complete'])
            self.assertFalse(report['exact_committed_source_verified'])
            self.assertEqual(report['status'], 'failed_research_hold')
            self.assertIn({'case': 'source_identity', 'stage': 'after', 'reason': 'TRACKED_TREE_DIRTY'},
                          report['failures'])


if __name__ == '__main__':
    unittest.main()
