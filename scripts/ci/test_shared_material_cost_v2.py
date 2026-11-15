#!/usr/bin/env python3
"""Cost-reader adversarial controls; synthetic rows never claim native evidence.

Optional --actual-run DIR checks immutable retained complete source observations
and mutates disposable copies only. All synthetic controls run without that input.
"""
import argparse
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import shared_material_cost_v2 as cost

ACTUAL_RUN = None


def timed(value):
    return {'cpu_ns': value, 'wall_ns': value * 2}


def native_fixture(verifiers=2):
    """Artificial counting fixture, intentionally not a legal W1 transcript."""
    product = 'ab' * 32
    replay = [{'index': index, 'outcome': 'Accepted', 'timing': timed(index + 3),
               'product_sha256': product} for index in range(verifiers)]
    rows = [
        {'kind': 'material', 'record_build_timing': timed(1)},
        {'kind': 'setup', 'timing': timed(7), 'record_build_timing': timed(1)},
        {'kind': 'search', 'timing': timed(11), 'record_build_timing': timed(1),
         'attempts': [{'nonce': 0, 'timing': timed(4)}, {'nonce': 1, 'timing': timed(5)}]},
        {'kind': 'candidate', 'record_build_timing': timed(1)},
        {'kind': 'verification', 'native': {'outcome': 'Accepted', 'timing': timed(3)},
         'native_verifiers': replay, 'record_build_timing': timed(1),
         'scalar_reference': {'outcome': 'Accepted', 'timing': timed(9)}},
        {'kind': 'winner', 'product_sha256': product, 'typed_copy_timing': timed(2),
         'record_build_timing': timed(1)},
        {'kind': 'summary', 'record_build_timing': timed(1), 'producer_subtotal': timed(18),
         'native_verifier_subtotal': timed(sum(index + 3 for index in range(verifiers))),
         'reference_verifier_subtotal': timed(9), 'typed_copy_subtotal': timed(2),
         'record_build_subtotal': timed(6), 'serialization_output_subtotal': timed(10),
         'run_through_before_summary': timed(90), 'attempts': 2, 'winners': 1},
    ]
    return rows


def baseline_fixture(cpu=True):
    values = {'repetitions': 3, 'preparation_ns': 20, 'first_execution_ns': 10,
              'cold_preparation_plus_execution_ns': 30, 'warm_samples_ns': [5, 7, 9], 'warm_min_ns': 5, 'warm_median_ns': 7,
              'warm_p95_ns': 9, 'scalar_predict_rows_ns': 11}
    if cpu:
        values['cpu'] = dict(values, preparation_ns=10, first_execution_ns=5,
                             cold_preparation_plus_execution_ns=15, warm_samples_ns=[2, 3, 4],
                             warm_min_ns=2, warm_median_ns=3, warm_p95_ns=4, scalar_predict_rows_ns=6)
    return values


def phase_fixture():
    """Synthetic independent clocks for containment controls, not observations."""
    cpu = {key: 100 for key in cost.PHASES}
    wall = {key: 200 for key in cost.PHASES}
    cpu[cost.TOTAL_PHASE] = 1000
    wall[cost.TOTAL_PHASE] = 2000
    return {'phase_cpu_ns': cpu, 'phases_ns': wall}


def run_fixture():
    values = cost.recompute_native(native_fixture(), 2)
    return {'status': 'complete_consistent_observation', 'record_fingerprint': 'a',
            'material_identity': {'input': 'same'}, 'paired_comparison_identity': 'pair',
            'mathematical_stream_sha256': 'same-stream',
            'native_leaf_costs': values, 'bytes': {'proofs_all_cycles': 100},
            'distinct_application_batches_credited': 1}


def staged_failure(directory):
    """Real frozen material plus artificial failed-process counters, never proof evidence."""
    cell = cost.cell
    model, rows, provenance = cell.load_inputs(
        cell.DEFAULT_MATERIAL / 'model.json', cell.DEFAULT_MATERIAL / 'consumer.json',
        cell.DEFAULT_MATERIAL / 'evaluation-bundle.json', cell.DEFAULT_BUNDLE, 'consumer', 0, 7)
    tiles, _ = cell.build_tiles(model, rows)
    manifest = {'schema': 'pon-shared-cell-operator-v2', 'provenance': provenance,
                'execution_source': {'native_runner_sha256': '00' * 32, 'fixture_only': True},
                'execution_parameters': {'target_index': 0, 'target': '7f' + 'ff' * 31,
                    'seed': '8c' * 32, 'cycles': 1, 'verifiers': 1, 'max_attempts': 1,
                    'baseline_repetitions': 3, 'arithmetic': 'full-limb', 'preparation': 'sparse',
                    'verifier_scope': 'same_process_sequential_full_replay'},
                'geometry': {'w1_product_multiply_adds_per_batch': 5 * 64 ** 3,
                    'all_five_operator_multiply_adds': 15 * 257 * len(rows),
                    'ordinary_cached_selected_expert_multiply_adds': 6 * 257 * len(rows)},
                'tiles': [{k: v for k, v in tile.items() if k != 'material'} for tile in tiles]}
    for filename, value in (('manifest.json', manifest), ('model.json', model), ('tasks.json', rows)):
        (directory / filename).write_text(json.dumps(value))
    for tile in tiles:
        place = directory / f"tile-{tile['index']}"
        place.mkdir()
        (place / 'material.bin').write_bytes(tile['material'])
    return manifest


class CostControls(unittest.TestCase):
    def test_misses_and_setup_are_charged_once(self):
        value = cost.recompute_native(native_fixture(), 2)
        self.assertEqual(value['producer_subtotal']['cpu_ns'], 18)
        self.assertEqual(value['all_searches_including_misses']['cpu_ns'], 11)
        self.assertEqual((value['attempts'], value['misses'], value['winners']), (2, 1, 1))
        self.assertNotIn('setup', value['additive_work_components'])

    def test_first_verifier_is_alias_not_third_charge(self):
        value = cost.recompute_native(native_fixture(), 2)
        self.assertEqual(value['native_verifier_subtotal']['cpu_ns'], 7)
        self.assertEqual(value['native_first_verifier_subtotal']['cpu_ns'], 3)
        self.assertEqual(value['full_native_verifier_calls'], 2)

    def test_omitted_verifier_is_refused(self):
        rows = native_fixture()
        rows[4]['native_verifiers'].pop()
        with self.assertRaisesRegex(ValueError, 'VERIFIER_COVERAGE'):
            cost.recompute_native(rows, 2)

    def test_duplicated_verifier_identity_is_refused(self):
        rows = native_fixture()
        rows[4]['native_verifiers'][1]['index'] = 0
        with self.assertRaisesRegex(ValueError, 'VERIFIER_INDEX'):
            cost.recompute_native(rows, 2)

    def test_unobserved_population_cannot_be_supplied_as_measured(self):
        rows = native_fixture(1)
        del rows[4]['native_verifiers']
        with self.assertRaisesRegex(ValueError, 'UNOBSERVED_VERIFIERS'):
            cost.recompute_native(rows, 2)

    def test_reference_cannot_replace_full_native_verifier(self):
        rows = native_fixture()
        rows[4]['native_verifiers'][1]['outcome'] = 'Rejected'
        with self.assertRaisesRegex(ValueError, 'VERIFIER_OUTCOME'):
            cost.recompute_native(rows, 2)

    def test_verifier_product_must_match_consumed_product(self):
        rows = native_fixture()
        rows[4]['native_verifiers'][1]['product_sha256'] = 'cd' * 32
        with self.assertRaisesRegex(ValueError, 'VERIFIER_PRODUCT'):
            cost.recompute_native(rows, 2)

    def test_first_alias_timing_mismatch_is_refused(self):
        rows = native_fixture()
        rows[4]['native']['timing'] = timed(2)
        with self.assertRaisesRegex(ValueError, 'FIRST_VERIFIER_ALIAS'):
            cost.recompute_native(rows, 2)

    def test_forged_zero_subtotal_is_refused(self):
        for key in ('producer_subtotal', 'native_verifier_subtotal', 'reference_verifier_subtotal'):
            rows = native_fixture()
            rows[-1][key] = timed(0)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'SUMMARY_COST_MISMATCH'):
                cost.recompute_native(rows, 2)

    def test_missing_attempt_cannot_be_erased_from_summary(self):
        rows = native_fixture()
        rows[2]['attempts'].pop(0)
        with self.assertRaisesRegex(ValueError, 'ATTEMPT_SEQUENCE'):
            cost.recompute_native(rows, 2)

    def test_declared_attempt_count_does_not_override_ledger(self):
        rows = native_fixture()
        rows[-1]['attempts'] = 1
        with self.assertRaisesRegex(ValueError, 'SUMMARY_COUNT_MISMATCH'):
            cost.recompute_native(rows, 2)

    def test_boolean_and_negative_clocks_are_not_numbers(self):
        for bad in (True, False, -1, 2 ** 64, 0.0):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                cost.timing({'cpu_ns': bad, 'wall_ns': 1})

    def test_unknown_is_not_zero_or_known_total(self):
        value = cost.timing_sum([{'cpu_ns': None, 'wall_ns': 2}, {'cpu_ns': 3, 'wall_ns': 4}])
        self.assertIsNone(value['cpu_ns'])
        self.assertEqual(value['wall_ns'], 6)
        self.assertIsNone(cost.sum_known([0, None]))

    def test_v1_missing_cpu_stays_unknown(self):
        value = cost.baseline_measurements(baseline_fixture(False))
        self.assertIsNone(value['cpu_ns'])
        self.assertEqual(value['wall_ns']['warm_median'], 7)

    def test_cpu_and_wall_baselines_are_separate(self):
        value = cost.baseline_measurements(baseline_fixture())
        self.assertEqual(value['cpu_ns']['warm_median'], 3)
        self.assertEqual(value['wall_ns']['warm_median'], 7)

    def test_baseline_median_is_recomputed(self):
        value = baseline_fixture()
        value['cpu']['warm_median_ns'] = 1
        with self.assertRaisesRegex(ValueError, 'BASELINE_MEDIAN_MISMATCH'):
            cost.baseline_measurements(value)

    def test_missing_baseline_samples_cannot_be_hidden(self):
        value = baseline_fixture()
        value['warm_samples_ns'].pop()
        with self.assertRaisesRegex(ValueError, 'BASELINE_SAMPLE_COUNT'):
            cost.baseline_measurements(value)

    def test_cpu_baseline_timed_samples_must_fit_cpu_phase(self):
        baseline = baseline_fixture()
        cpu = baseline['cpu']
        cpu['warm_samples_ns'] = [value * 1000000 for value in cpu['warm_samples_ns']]
        ordered = sorted(cpu['warm_samples_ns'])
        cpu.update(warm_min_ns=min(ordered), warm_median_ns=int(cost.statistics.median(ordered)),
                   warm_p95_ns=ordered[min(len(ordered) - 1, (95 * len(ordered) + 99) // 100 - 1)])
        with self.assertRaisesRegex(ValueError, 'BASELINE_PHASE_ENVELOPE:cpu_ns'):
            cost.phase_measurements(phase_fixture(), cost.baseline_measurements(baseline), require_cpu=True)

    def test_cpu_parent_phase_cannot_be_removed(self):
        for key in ('all_baseline_diagnostics', 'native_runs_and_evidence_checks', cost.TOTAL_PHASE):
            report = phase_fixture()
            del report['phase_cpu_ns'][key]
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'PHASE_CPU_COVERAGE'):
                cost.phase_measurements(report, cost.baseline_measurements(baseline_fixture()), require_cpu=True)

    def test_cpu_native_phase_must_cover_exchange_cpu(self):
        report = phase_fixture()
        report['phase_cpu_ns']['native_runs_and_evidence_checks'] = 7
        processes = [{'wall_ns': 20, 'supervisor_cpu_ns': 8}]
        with self.assertRaisesRegex(ValueError, 'NATIVE_PHASE_ENVELOPE:cpu_ns'):
            cost.validate_native_phase_envelope(report['phase_cpu_ns'], report['phases_ns'], processes)

    def test_native_process_containment_has_no_implicit_tolerance(self):
        process = {'wall_ns': 60, 'supervisor_cpu_ns': 3, 'child_user_cpu_ns': 30, 'child_system_cpu_ns': 0}
        native = {'run_through_before_summary': timed(30)}
        cost.validate_process_native_envelope(process, native)
        for key, code in (('wall_ns', 'PROCESS_NATIVE_WALL_ENVELOPE'),
                          ('child_user_cpu_ns', 'PROCESS_NATIVE_CPU_ENVELOPE')):
            changed = dict(process)
            changed[key] -= 1
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, code):
                cost.validate_process_native_envelope(changed, native)

    def test_baseline_minimum_and_percentile_are_recomputed(self):
        for clock in ('wall_ns', 'cpu_ns'):
            for field, code in (('warm_min_ns', 'BASELINE_MIN_MISMATCH'), ('warm_p95_ns', 'BASELINE_P95_MISMATCH')):
                value = baseline_fixture()
                source = value if clock == 'wall_ns' else value['cpu']
                source[field] += 1
                with self.subTest(clock=clock, field=field), self.assertRaisesRegex(ValueError, code):
                    cost.baseline_measurements(value)

    def test_matching_pair_must_have_identical_mathematical_stream(self):
        first, second = run_fixture(), run_fixture()
        second.update(record_fingerprint='b', mathematical_stream_sha256='changed-lottery')
        with mock.patch.object(cost, 'analyze_run', side_effect=[first, second]):
            with self.assertRaisesRegex(ValueError, 'PAIRED_MATHEMATICAL_STREAM_MISMATCH'):
                cost.reconcile(['dense', 'sparse'])

    def test_scenario_keeps_stale_cost_without_measured_claim(self):
        value = cost.scenario(run_fixture(), {'name': 'two', 'verifiers': 2, 'stale_fraction_bps': 5000})
        self.assertEqual(value['partial_work_cpu_ns_per_distinct_live_batch'], {'numerator': 260000, 'denominator': 5000})
        self.assertIsNone(value['net_compute_benefit'])
        self.assertIsNone(value['wall_ns'])
        self.assertFalse(value['qualification'])

    def test_scenario_no_live_output_and_bool_count_refused(self):
        for verifiers, stale in ((1, 10000), (True, 0), (0, 0), (1, True)):
            with self.subTest(verifiers=verifiers, stale=stale), self.assertRaises(ValueError):
                cost.scenario(run_fixture(), {'name': 'bad', 'verifiers': verifiers, 'stale_fraction_bps': stale})

    def test_duplicate_physical_observation_cannot_be_counted_twice(self):
        with mock.patch.object(cost, 'analyze_run', return_value=run_fixture()), self.assertRaisesRegex(ValueError, 'DUPLICATE_PHYSICAL_OBSERVATION'):
            cost.reconcile(['original', 'copy'])

    def test_two_arms_add_no_application_credit(self):
        first, second = run_fixture(), run_fixture()
        second['record_fingerprint'] = 'b'
        with mock.patch.object(cost, 'analyze_run', side_effect=[first, second]):
            value = cost.reconcile(['dense', 'sparse'])
        self.assertEqual(value['distinct_material_batches_across_all_arms'], 1)
        self.assertEqual(value['additional_useful_output_credit_from_cycles_or_arms'], 0)
        self.assertEqual(value['paired_comparison_groups'], [[0, 1]])
        self.assertTrue(all(item is None for item in value['coverage'].values()))

    def test_mismatched_material_cannot_enter_paired_comparison(self):
        first, second = run_fixture(), run_fixture()
        second.update(record_fingerprint='b', material_identity={'input': 'different'})
        with mock.patch.object(cost, 'analyze_run', side_effect=[first, second]), self.assertRaisesRegex(ValueError, 'MATERIAL_COHORT_MISMATCH'):
            cost.reconcile(['same', 'different'])

    def test_different_targets_are_separate_comparisons(self):
        first, second = run_fixture(), run_fixture()
        second.update(record_fingerprint='b', paired_comparison_identity='another-target')
        with mock.patch.object(cost, 'analyze_run', side_effect=[first, second]):
            value = cost.reconcile(['t0', 't1'])
        self.assertEqual(value['paired_comparison_groups'], [[0], [1]])

    def test_process_tree_charges_all_children_once(self):
        report = {'process_cpu_ns': {'supervisor_through_before_final_report': 100,
                                    'all_children_user': 60, 'all_children_system': 10,
                                    'scope': 'all reaped children in isolated supervisor'},
                  'phase_cpu_ns': {'total_experiment_before_final_report_write': 100}}
        value = cost.process_envelope(report, 20)
        self.assertEqual(value['cpu_ns'], 170)
        self.assertEqual(value['all_children_cpu_ns'], 70)
        self.assertEqual(value['native_children_cpu_ns_subset'], 20)
        self.assertFalse(value['native_subtotal_added_again'])

    def test_process_tree_cannot_hide_native_children(self):
        report = {'process_cpu_ns': {'supervisor_through_before_final_report': 100,
                                    'all_children_user': 5, 'all_children_system': 10,
                                    'scope': 'artificial cost-count fixture'},
                  'phase_cpu_ns': {'total_experiment_before_final_report_write': 100}}
        with self.assertRaisesRegex(ValueError, 'PROCESS_CPU_CHILD_SUBSET'):
            cost.process_envelope(report, 20)

    def test_process_tree_parent_must_match_phase_alias(self):
        report = {'process_cpu_ns': {'supervisor_through_before_final_report': 0,
                                    'all_children_user': 60, 'all_children_system': 10,
                                    'scope': 'artificial cost-count fixture'},
                  'phase_cpu_ns': {'total_experiment_before_final_report_write': 100}}
        with self.assertRaisesRegex(ValueError, 'PROCESS_CPU_PARENT_ALIAS'):
            cost.process_envelope(report, 20)

    def test_process_tree_missing_phase_total_is_not_zero(self):
        report = {'process_cpu_ns': {'supervisor_through_before_final_report': 100,
                                    'all_children_user': 60, 'all_children_system': 10,
                                    'scope': 'artificial cost-count fixture'}}
        with self.assertRaisesRegex(ValueError, 'PROCESS_CPU_PHASE_TOTAL'):
            cost.process_envelope(report, 20)

    def test_missing_process_tree_is_not_inferred_from_native_children(self):
        value = cost.process_envelope({}, 20)
        self.assertIsNone(value['cpu_ns'])
        self.assertIsNone(value['all_children_cpu_ns'])
        self.assertEqual(value['native_children_cpu_ns_subset'], 20)

    def test_interrupted_job_retains_partial_spend_and_unknown_attempts(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = staged_failure(Path(temp))
            place = Path(temp) / 'tile-0'
            (place / 'native.stdout.jsonl').write_bytes(b'')
            (place / 'native.stderr.txt').write_bytes(b'')
            (place / 'process-failure.json').write_text(json.dumps({
                'child_user_cpu_ns': 10, 'child_system_cpu_ns': 2, 'wall_ns': 30,
                'runner_sha256': '00' * 32, 'stdout_retained_bytes': 0, 'stderr_retained_bytes': 0,
                'stdin_written': 0}))
            value = cost.incomplete_run(Path(temp), {'status': 'failed'}, manifest)
        self.assertEqual(value['observed_partial_child_cpu_ns'], 12)
        self.assertEqual(value['not_observed_tiles'], [1, 2, 3, 4])
        self.assertEqual(value['partial_processes'][0]['internal_attempt_coverage'], 'unknown')
        self.assertEqual(value['distinct_application_batches_credited'], 0)
        self.assertIsNone(value['net_compute_benefit'])

    def test_empty_partial_observation_is_unknown_not_free(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = staged_failure(Path(temp))
            value = cost.incomplete_run(Path(temp), {'status': 'failed'}, manifest)
        self.assertIsNone(value['observed_partial_child_cpu_ns'])
        self.assertIsNone(value['observed_partial_sequential_child_wall_ns'])


    def test_incomplete_material_manifest_is_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = staged_failure(Path(temp))
            manifest['tiles'][4]['material_sha256'] = 'ff' * 32
            with self.assertRaisesRegex(ValueError, 'MATERIAL_MANIFEST_BINDING'):
                cost.incomplete_run(Path(temp), {'status': 'failed'}, manifest)

    def test_incomplete_material_bytes_are_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = staged_failure(Path(temp))
            material = Path(temp) / 'tile-4/material.bin'
            altered = bytearray(material.read_bytes())
            altered[0] ^= 1
            material.write_bytes(altered)
            with self.assertRaisesRegex(ValueError, 'MATERIAL_BYTES'):
                cost.incomplete_run(Path(temp), {'status': 'failed'}, manifest)

    def test_incomplete_target_index_must_match_target(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = staged_failure(Path(temp))
            manifest['execution_parameters']['target_index'] = 1
            with self.assertRaisesRegex(ValueError, 'TARGET_BINDING'):
                cost.incomplete_run(Path(temp), {'status': 'failed'}, manifest)

    def test_incomplete_run_cannot_hide_wrong_material_cohort(self):
        first, second = run_fixture(), run_fixture()
        second.update(status='incomplete', record_fingerprint='b', material_identity={'input': 'other'})
        with mock.patch.object(cost, 'analyze_run', side_effect=[first, second]):
            with self.assertRaisesRegex(ValueError, 'MATERIAL_COHORT_MISMATCH'):
                cost.reconcile(['complete', 'failed'])

    def test_copied_failure_cannot_double_the_research_cost(self):
        value = run_fixture()
        value['status'] = 'incomplete'
        with mock.patch.object(cost, 'analyze_run', return_value=value):
            with self.assertRaisesRegex(ValueError, 'DUPLICATE_PHYSICAL_OBSERVATION'):
                cost.reconcile(['failed', 'same-failure-copy'])

    def test_only_failures_have_material_but_no_output_credit(self):
        value = run_fixture()
        value.update(status='incomplete', distinct_application_batches_credited=0)
        with mock.patch.object(cost, 'analyze_run', return_value=value):
            result = cost.reconcile(['failed'])
        self.assertEqual(result['distinct_material_cohorts_observed'], 1)
        self.assertEqual(result['distinct_material_batches_across_all_arms'], 0)
        self.assertEqual(result['status'], 'incomplete_local_observations')
        self.assertIsNone(result['full_system_cost'])

    def test_partial_process_cannot_be_charged_both_finished_and_failed(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = staged_failure(Path(temp))
            place = Path(temp) / 'tile-0'
            for filename in ('process.json', 'process-failure.json'):
                (place / filename).write_text('{}')
            with self.assertRaisesRegex(ValueError, 'PARTIAL_PROCESS_OVERLAP'):
                cost.incomplete_run(Path(temp), {'status': 'failed'}, manifest)


class ActualObservationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if ACTUAL_RUN is None:
            raise unittest.SkipTest('actual retained observation not supplied')
        cls.original = Path(ACTUAL_RUN).resolve()
        cls.original_hashes = {str(p.relative_to(cls.original)): cost.digest(p.read_bytes()) for p in cls.original.rglob('*') if p.is_file()}
        cls.observation = cost.analyze_run(cls.original)

    @classmethod
    def tearDownClass(cls):
        for relative, expected in cls.original_hashes.items():
            if cost.digest((cls.original / relative).read_bytes()) != expected:
                raise AssertionError('retained original mutated: ' + relative)

    def test_actual_raw_observation_is_reconciled(self):
        self.assertEqual(self.observation['status'], 'complete_consistent_observation')
        self.assertGreater(self.observation['attempts'], 0)
        self.assertEqual(self.observation['distinct_application_batches_credited'], 1)
        self.assertIsNone(self.observation['full_system_cost'])

    def reject_mutation(self, mutation, code):
        with tempfile.TemporaryDirectory() as temp:
            copied = Path(temp) / 'copy'
            shutil.copytree(self.original, copied)
            report = json.loads((copied / 'report.json').read_text())
            mutation(copied, report)
            (copied / 'report.json').write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, code):
                cost.analyze_run(copied)

    @staticmethod
    def update_baseline(copied, report, mutation):
        mutation(report['baseline'])
        (copied / 'baseline.json').write_text(json.dumps(report['baseline']))
        # Keep existing report aliases consistent so the independent envelope
        # and model bindings, rather than a stale duplicate, must stop the edit.
        costs = report['costs']
        costs['native_wall_to_one_ordinary_warm_batch_ratio'] = (
            costs['native_process_wall_ns'] / report['baseline']['warm_median_ns'])
        costs['native_wall_to_one_ordinary_cold_batch_ratio'] = (
            costs['native_process_wall_ns'] / report['baseline']['cold_preparation_plus_execution_ns'])

    @staticmethod
    def refresh_process_aliases(copied, report):
        report['native'] = []
        for index in range(5):
            place = copied / f'tile-{index}'
            process = json.loads((place / 'process.json').read_text())
            summary = json.loads((place / 'native.stdout.jsonl').read_bytes().splitlines()[-1])
            report['native'].append(dict(process, native_summary=summary))
        values = report['native']
        report['costs']['native_process_wall_ns'] = sum(row['wall_ns'] for row in values)
        report['costs']['native_child_cpu_ns'] = sum(row['child_user_cpu_ns'] + row['child_system_cpu_ns'] for row in values)
        report['costs']['all_local_pipe_bytes'] = sum(row['stdin_bytes'] + row['stdout_bytes'] + row['stderr_bytes'] for row in values)
        report['costs']['native_wall_to_one_ordinary_warm_batch_ratio'] = (
            report['costs']['native_process_wall_ns'] / report['baseline']['warm_median_ns'])
        report['costs']['native_wall_to_one_ordinary_cold_batch_ratio'] = (
            report['costs']['native_process_wall_ns'] / report['baseline']['cold_preparation_plus_execution_ns'])

    def test_contradictory_claimed_summary_costs_are_refused(self):
        for field in ('native_child_cpu_ns', 'native_process_wall_ns', 'all_local_pipe_bytes',
                      'canonical_matrices_bytes', 'proof_bytes', 'typed_product_bytes',
                      'same_inputs_cycles', 'distinct_application_batches',
                      'native_wall_to_one_ordinary_warm_batch_ratio',
                      'native_wall_to_one_ordinary_cold_batch_ratio'):
            with self.subTest(field=field):
                self.reject_mutation(lambda copied, report: report['costs'].__setitem__(field, 0),
                                     'REPORT_COST_ALIAS')

    def test_cost_scope_aliases_cannot_claim_another_measurement(self):
        for field in ('transmission_scope', 'cache_credit', 'mining_and_proof_and_full_verification_included'):
            with self.subTest(field=field):
                self.reject_mutation(lambda copied, report: report['costs'].__setitem__(field, 'different scope'),
                                     'REPORT_COST_ALIAS')

    def test_baseline_identity_is_bound_even_if_both_copies_are_changed(self):
        changes = [('implementation', 'another algorithm', 'BASELINE_IMPLEMENTATION'),
                   ('predictions', [], 'BASELINE_PREDICTIONS'),
                   ('routes', [], 'BASELINE_ROUTES'),
                   ('logical_multiply_adds', 0, 'BASELINE_LOGICAL_MACS'),
                   ('warmup_runs', 0, 'BASELINE_WARMUP'),
                   ('numpy_version', 'another version', 'BASELINE_NUMPY_VERSION')]
        for field, value, code in changes:
            with self.subTest(field=field):
                self.reject_mutation(lambda copied, report: self.update_baseline(
                    copied, report, lambda baseline: baseline.__setitem__(field, value)), code)

    def test_baseline_vectors_reject_changed_values_and_boolean_aliases(self):
        for field in ('predictions', 'routes'):
            for boolean in (False, True):
                def mutation(copied, report):
                    values = report['baseline'][field]
                    values[0] = bool(values[0]) if boolean else (values[0] + 1) % 3
                    self.update_baseline(copied, report, lambda baseline: None)
                with self.subTest(field=field, boolean=boolean):
                    self.reject_mutation(mutation, 'BASELINE_' + field.upper())

    def test_baseline_repetition_count_is_bound_to_manifest(self):
        def mutation(copied, report):
            def adjust(baseline):
                baseline['repetitions'] -= 1
                for source in (baseline, baseline.get('cpu')):
                    if source is None:
                        continue
                    source['warm_samples_ns'].pop()
                    ordered = sorted(source['warm_samples_ns'])
                    source.update(warm_min_ns=min(ordered), warm_median_ns=int(cost.statistics.median(ordered)),
                                  warm_p95_ns=ordered[min(len(ordered) - 1, (95 * len(ordered) + 99) // 100 - 1)])
            self.update_baseline(copied, report, adjust)
        self.reject_mutation(mutation, 'BASELINE_REPETITIONS_BINDING')

    def test_baseline_millionfold_wall_inflation_exceeds_parent_phase(self):
        def mutation(copied, report):
            def inflate(baseline):
                baseline['warm_samples_ns'] = [value * 1000000 for value in baseline['warm_samples_ns']]
                ordered = sorted(baseline['warm_samples_ns'])
                baseline.update(warm_min_ns=min(ordered), warm_median_ns=int(cost.statistics.median(ordered)),
                                warm_p95_ns=ordered[min(len(ordered) - 1, (95 * len(ordered) + 99) // 100 - 1)])
            self.update_baseline(copied, report, inflate)
        self.reject_mutation(mutation, 'BASELINE_PHASE_ENVELOPE:wall_ns')

    def test_baseline_millionfold_cpu_inflation_exceeds_parent_phase(self):
        if 'cpu' not in json.loads((self.original / 'baseline.json').read_text()):
            self.skipTest('v1 observation has no baseline CPU; synthetic CPU envelope control applies')
        def mutation(copied, report):
            def inflate(baseline):
                source = baseline['cpu']
                source['warm_samples_ns'] = [value * 1000000 for value in source['warm_samples_ns']]
                ordered = sorted(source['warm_samples_ns'])
                source.update(warm_min_ns=min(ordered), warm_median_ns=int(cost.statistics.median(ordered)),
                              warm_p95_ns=ordered[min(len(ordered) - 1, (95 * len(ordered) + 99) // 100 - 1)])
            self.update_baseline(copied, report, inflate)
        self.reject_mutation(mutation, 'BASELINE_PHASE_ENVELOPE:cpu_ns')

    def test_missing_wall_parent_phases_cannot_bypass_envelopes(self):
        for field in ('all_baseline_diagnostics', 'native_runs_and_evidence_checks',
                      'total_experiment_before_final_report_write'):
            with self.subTest(field=field):
                self.reject_mutation(lambda copied, report: report['phases_ns'].pop(field), 'PHASE_WALL_COVERAGE')

    def test_missing_cpu_parent_phases_cannot_bypass_envelopes(self):
        original = json.loads((self.original / 'report.json').read_text())
        if 'phase_cpu_ns' not in original:
            self.skipTest('v1 observation has no CPU phases; synthetic CPU coverage control applies')
        for field in ('all_baseline_diagnostics', 'native_runs_and_evidence_checks',
                      'total_experiment_before_final_report_write'):
            with self.subTest(field=field):
                self.reject_mutation(lambda copied, report: report['phase_cpu_ns'].pop(field), 'PHASE_CPU_COVERAGE')

    def test_zero_tile_wall_cannot_hide_real_native_execution(self):
        def mutation(copied, report):
            for path in copied.glob('tile-*/process.json'):
                process = json.loads(path.read_text())
                process['wall_ns'] = 0
                path.write_text(json.dumps(process))
            self.refresh_process_aliases(copied, report)
        self.reject_mutation(mutation, 'PROCESS_NATIVE_WALL_ENVELOPE')

    def test_zero_tile_cpu_cannot_hide_real_native_execution(self):
        def mutation(copied, report):
            for path in copied.glob('tile-*/process.json'):
                process = json.loads(path.read_text())
                process['child_user_cpu_ns'] = process['child_system_cpu_ns'] = 0
                path.write_text(json.dumps(process))
            self.refresh_process_aliases(copied, report)
        self.reject_mutation(mutation, 'PROCESS_NATIVE_CPU_ENVELOPE')

    def test_parent_native_wall_must_cover_sequential_children(self):
        def mutation(copied, report):
            report['phases_ns']['native_runs_and_evidence_checks'] = sum(row['wall_ns'] for row in report['native']) - 1
        self.reject_mutation(mutation, 'NATIVE_PHASE_ENVELOPE:wall_ns')

    def test_parent_native_cpu_must_cover_supervisor_exchanges(self):
        original = json.loads((self.original / 'report.json').read_text())
        if 'phase_cpu_ns' not in original:
            self.skipTest('v1 observation has no CPU phases; synthetic CPU envelope control applies')
        def mutation(copied, report):
            report['phase_cpu_ns']['native_runs_and_evidence_checks'] = sum(row['supervisor_cpu_ns'] for row in report['native']) - 1
        self.reject_mutation(mutation, 'NATIVE_PHASE_ENVELOPE:cpu_ns')

    def test_native_report_process_and_summary_aliases_are_exact(self):
        mutations = [lambda copied, report: report['native'].pop(),
                     lambda copied, report: report['native'][0].__setitem__('wall_ns', 0),
                     lambda copied, report: report['native'][0]['native_summary']['producer_subtotal'].__setitem__('cpu_ns', 0)]
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                self.reject_mutation(mutation, 'REPORT_NATIVE_(COVERAGE|ALIAS)')

    def test_consistently_changed_miss_is_refused_by_paired_stream_binding(self):
        # The reader cannot authenticate a measurement author. This controlled
        # edit keeps the wire-level miss valid but changes its trace; paired
        # mathematical streams must nevertheless expose the inconsistency.
        with tempfile.TemporaryDirectory() as temp:
            copied = Path(temp) / 'copy'
            shutil.copytree(self.original, copied)
            report = json.loads((copied / 'report.json').read_text())
            chosen = None
            for place in sorted(copied.glob('tile-*')):
                records = [json.loads(line) for line in (place / 'native.stdout.jsonl').read_bytes().splitlines()]
                for row in records:
                    if row['kind'] == 'search' and len(row['attempts']) > 1:
                        chosen = place, records, row
                        break
                if chosen:
                    break
            self.assertIsNotNone(chosen, 'retained observation must exercise a real missed attempt')
            place, records, search = chosen
            attempt = search['attempts'][0]
            challenge, target = bytes.fromhex(attempt['challenge']), bytes.fromhex(search['target'])
            nonce = 0
            while True:
                trace = cost.H('cost-reader-test-only-mutated-miss', bytes.fromhex(attempt['trace']), nonce.to_bytes(8, 'little'))
                ticket = cost.H('ticket', challenge, trace)
                if ticket > target:
                    break
                nonce += 1
            attempt['trace'], attempt['ticket'] = trace.hex(), ticket.hex()
            before = b''.join(cost.canonical(row) + b'\n' for row in records[:-1])
            records[-1]['bytes_before_summary'] = len(before)
            raw = before + cost.canonical(records[-1]) + b'\n'
            (place / 'native.stdout.jsonl').write_bytes(raw)
            process = json.loads((place / 'process.json').read_text())
            process.update(stdout_sha256=cost.digest(raw), stdout_bytes=len(raw))
            (place / 'process.json').write_text(json.dumps(process))
            accepted = json.loads((place / 'accepted.json').read_text())
            accepted['stdout_sha256'] = cost.digest(raw)
            (place / 'accepted.json').write_text(json.dumps(accepted))
            self.refresh_process_aliases(copied, report)
            (copied / 'report.json').write_text(json.dumps(report))
            # Individually consistent syntax is insufficient to declare the
            # two algorithm arms worked on the same actual lottery stream.
            changed = cost.analyze_run(copied)
            self.assertNotEqual(changed['mathematical_stream_sha256'], self.observation['mathematical_stream_sha256'])
            with self.assertRaisesRegex(ValueError, 'PAIRED_MATHEMATICAL_STREAM_MISMATCH'):
                cost.reconcile([self.original, copied])

    def test_changed_material_bytes_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            copied = Path(temp) / 'copy'
            shutil.copytree(self.original, copied)
            path = copied / 'tile-0/material.bin'
            raw = bytearray(path.read_bytes())
            raw[0] ^= 1
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'MATERIAL_BYTES'):
                cost.analyze_run(copied)

    def test_changed_process_counts_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            copied = Path(temp) / 'copy'
            shutil.copytree(self.original, copied)
            path = copied / 'tile-0/process.json'
            process = json.loads(path.read_text())
            process['stdout_bytes'] = 0
            path.write_text(json.dumps(process))
            with self.assertRaisesRegex(ValueError, 'PROCESS_COUNT'):
                cost.analyze_run(copied)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--actual-run', type=Path)
    args, remaining = parser.parse_known_args()
    ACTUAL_RUN = args.actual_run
    unittest.main(argv=[sys.argv[0]] + remaining)
