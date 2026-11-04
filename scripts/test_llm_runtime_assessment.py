#!/usr/bin/env python3
"""Cost-return controls for the existing pilot, using declared receipt fixtures.

No model execution or economic/independent acceptance is claimed by this suite.
"""
from __future__ import annotations

import copy
import unittest

import llm_runtime_assessment as assessment
import llm_runtime_pilot as runtime


def fixture():
    plan = runtime.experiment_plan({'fixture': 'observation-boundary-only'})
    family = runtime.read_json(runtime.FAMILY_PATH)
    roster = dict(experiment=runtime.identity(plan), contract='a' * 64,
                  artifacts={r: str(i + 1) * 64 for i, r in enumerate(runtime.PARTICIPANTS)},
                  frozen_before_evaluation=True, scope='five-actual-local-artifacts-no-independent-authority')
    order = [('loader-1thread', 'loader', 'current-backbone'),
             ('loader-reference', 'loader', 'current-backbone')]
    order += [('train-' + r, 'train', r) for r in runtime.PARTICIPANTS]
    order += [('evaluate-' + r, 'evaluate', r) for r in runtime.PARTICIPANTS]
    records, receipts = [], {}
    for name, phase, role in order:
        actual_plan = dict(plan, threads=1) if name == 'loader-1thread' else plan
        records.append(dict(name=name, exit_code=0, outcome='success', stop_reason=None,
                            waited_child_reaped=True, owned_child_reap_resolved=True,
                            child_spawned=True, waited_child_observation_error=None,
                            budget=plan['training_budget' if phase == 'train' else 'inference_budget'],
                            observed_wall_ns=1000, child_cpu_ns=200, observer_cpu_ns=50,
                            sampled_peak_rss_bytes=16 * 1024, waited_child_peak_rss_bytes=32 * 1024))
        receipt = dict(schema='llm-runtime-actual-child-v1', phase=phase, role=role,
                       experiment=runtime.identity(actual_plan), runtime_source=plan['runtime_source'],
                       actual_backend=plan['backend'], actual_threads=actual_plan['threads'],
                       scope='local-actual-runtime-no-native-admission', outcome='success',
                       process_wall_ns=800, process_cpu_ns=150, process_peak_rss_bytes=32 * 1024,
                       contract='b' * 64 if name == 'loader-1thread' else roster['contract'],
                       artifact=roster['artifacts'][role], source_weight_sha256=runtime.WEIGHT_SHA,
                       derived_backbone_root=family['material_pins']['fp32_backbone_index_root'],
                       parameter_count=134515008,
                       **{flag: False for flag in runtime.QUALIFICATIONS})
        receipt['cost_events'] = [dict(stage=stage, outcome='success', error_type=None,
            cpu_ns=1, wall_ns=2, memory_peak_bytes=32 * 1024,
            bytes_read=7, bytes_written=3, gpu_ns=0) for stage in assessment._stages(phase, role)]
        receipts[name] = receipt
    scores = {r: dict(calibration=[0, 1], evaluation=[0, 1]) for r in runtime.PARTICIPANTS}
    return plan, roster, scores, records, receipts


class CostAssessmentTests(unittest.TestCase):
    def test_one_thread_contract_remains_distinct_with_the_same_material(self):
        args = fixture()
        result = assessment.build_assessment(*args)
        one, reference = result['cost_observations'][:2]
        self.assertNotEqual(args[4]['loader-1thread']['contract'], args[1]['contract'])
        self.assertEqual(one['contract'], args[4]['loader-1thread']['contract'])
        self.assertEqual(reference['contract'], args[1]['contract'])
        self.assertNotEqual(one['experiment'], reference['experiment'])
        self.assertEqual(one['experiment'], runtime.identity(dict(args[0], threads=1)))
        self.assertEqual(reference['experiment'], runtime.identity(args[0]))
        self.assertEqual(one['derived_backbone_root'], reference['derived_backbone_root'])
        self.assertEqual(one['source_weight_sha256'], runtime.WEIGHT_SHA)
        self.assertEqual(reference['source_weight_sha256'], runtime.WEIGHT_SHA)
        self.assertEqual(one['parameter_count'], reference['parameter_count'])

    def test_one_thread_contract_is_still_a_nonzero_canonical_digest(self):
        for value in (None, '', '0' * 64, 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64, True):
            args = fixture()
            args[4]['loader-1thread']['contract'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, '^RUNTIME_COST_CONTRACT$'):
                assessment.build_assessment(*args)

    def test_reference_training_and_evaluation_stay_bound_to_roster_contract(self):
        for name in fixture()[4]:
            if name == 'loader-1thread':
                continue
            args = fixture()
            args[4][name]['contract'] = 'f' * 64
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, '^RUNTIME_ASSESSMENT_ARTIFACT_BINDING$'):
                assessment.build_assessment(*args)

    def test_each_phase_keeps_exact_frozen_shared_source_and_model_identity(self):
        attacks = [('source_weight_sha256', 'f' * 64), ('source_weight_sha256', None),
                   ('derived_backbone_root', 'f' * 64), ('derived_backbone_root', None),
                   ('parameter_count', True), ('parameter_count', 134515008.0),
                   ('parameter_count', 134515009), ('parameter_count', None)]
        for name in ('loader-1thread', 'loader-reference', 'train-candidate',
                     'evaluate-budget-matched-full-tune'):
            for field, value in attacks:
                args = fixture()
                args[4][name][field] = value
                with self.subTest(name=name, field=field, value=value), \
                     self.assertRaisesRegex(ValueError, '^RUNTIME_COST_MATERIAL_BINDING$'):
                    assessment.build_assessment(*args)

    def test_family_source_must_match_the_frozen_plan(self):
        args = fixture()
        args[0]['model_family_configuration_sha256'] = 'f' * 64
        args[1]['experiment'] = runtime.identity(args[0])
        for name, receipt in args[4].items():
            actual = dict(args[0], threads=1) if name == 'loader-1thread' else args[0]
            receipt['experiment'] = runtime.identity(actual)
        with self.assertRaisesRegex(ValueError, '^RUNTIME_COST_FAMILY_BINDING$'):
            assessment.build_assessment(*args)

    def test_complete_local_channels_do_not_become_a_complete_no_update(self):
        result = assessment.build_assessment(*fixture())
        self.assertTrue(result['local_process_channels_complete'])
        self.assertTrue(result['all_required_controls_executed'])
        self.assertEqual(result['decision'], 'incomplete')
        self.assertFalse(result['no_update'])
        self.assertFalse(result['complete_economic_cost'])
        self.assertFalse(result['complete_release_evaluation'])
        self.assertIsNone(result['net_benefit_lower_bound'])
        self.assertFalse(result['adoption'])
        self.assertFalse(result['reward'])
        self.assertEqual(result['aggregate_observed_costs']['max_waited_child_peak_rss_bytes'], 32 * 1024)
        self.assertEqual(result['aggregate_observed_costs']['waited_child_cpu_ns'], 12 * 200)
        self.assertEqual(result['aggregate_observed_costs']['observed_sequential_phase_wall_ns'], 12 * 1000)

    def test_positive_score_cannot_cancel_missing_release_and_cost_gates(self):
        args = fixture(); args[2]['candidate']['evaluation'] = [1, 1]
        result = assessment.build_assessment(*args)
        self.assertTrue(result['positive_vs_all_controls'])
        self.assertFalse(result['adoption'])
        self.assertFalse(result['no_update'])
        self.assertEqual(result['decision'], 'incomplete')

    def test_missing_io_and_gpu_are_retained_as_unknown(self):
        args = fixture()
        args[4]['evaluate-candidate']['cost_events'][-1]['bytes_read'] = None
        result = assessment.build_assessment(*args)
        self.assertIsNone(result['aggregate_observed_costs']['stage_bytes_read'])
        self.assertFalse(result['local_process_channels_complete'])
        row = result['cost_observations'][7]
        self.assertEqual(row['missing_channels'], ['real-forward-greedy-decode:bytes_read'])
        self.assertFalse(result['no_update'])
        # Optional GPU timing remains unknown on an accelerator, not zero.
        args = fixture(); args[0]['backend'] = 'cuda'
        plan = args[0]; args[1]['experiment'] = runtime.identity(plan)
        for name, receipt in args[4].items():
            actual_plan = dict(plan, threads=1) if name == 'loader-1thread' else plan
            receipt.update(actual_backend='cuda', experiment=runtime.identity(actual_plan))
            for event in receipt['cost_events']: event['gpu_ns'] = None
        result = assessment.build_assessment(*args)
        self.assertIsNone(result['aggregate_observed_costs']['stage_gpu_ns'])
        self.assertFalse(result['local_process_channels_complete'])

    def test_missing_boolean_negative_or_zero_rss_refuses(self):
        for field, child in [('waited_child_peak_rss_bytes', False), ('sampled_peak_rss_bytes', False),
                             ('process_peak_rss_bytes', True)]:
            values = [None, True, -1] + ([0] if field != 'sampled_peak_rss_bytes' else [])
            for value in values:
                args = fixture(); target = args[4]['evaluate-candidate'] if child else args[3][7]
                target[field] = value
                with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, 'RUNTIME_COST_RSS'):
                    assessment.build_assessment(*args)

    def test_success_exit_cannot_hide_failed_or_foreign_receipt(self):
        for field, value in [('outcome', 'failed'), ('phase', 'train'), ('role', 'current-backbone'),
                             ('experiment', 'b' * 64), ('runtime_source', 'b' * 64),
                             ('actual_threads', True), ('actual_backend', 'cuda'),
                             ('independent_accepted', True)]:
            args = fixture(); args[4]['evaluate-candidate'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'RUNTIME_COST_CHILD_BINDING'):
                assessment.build_assessment(*args)

    def test_missing_or_duplicate_phase_cannot_count_as_all_controls(self):
        for action in ('missing', 'duplicate', 'extra'):
            args = fixture()
            if action == 'missing': args[3].pop()
            elif action == 'duplicate': args[3][-1] = args[3][0]
            else: args[4]['extra'] = args[4]['loader-reference']
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, 'RUNTIME_ASSESSMENT_PHASE_SET'):
                assessment.build_assessment(*args)

    def test_missing_failed_or_duplicated_cost_stage_refuses(self):
        for action in ('missing', 'duplicate', 'failed', 'missing-rss', 'negative-cpu'):
            args = fixture(); events = args[4]['train-candidate']['cost_events']
            if action == 'missing': events.pop()
            elif action == 'duplicate': events[-1] = events[0]
            elif action == 'failed': events[0]['outcome'] = 'failed'
            elif action == 'missing-rss': events[-1]['memory_peak_bytes'] = None
            else: events[-1]['cpu_ns'] = -1
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, 'RUNTIME_COST_'):
                assessment.build_assessment(*args)

    def test_receipt_cannot_relabel_artifact_or_contract(self):
        for field in ('artifact', 'contract'):
            args = fixture(); args[4]['evaluate-candidate'][field] = 'b' * 64
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'RUNTIME_ASSESSMENT_ARTIFACT_BINDING'):
                assessment.build_assessment(*args)

    def test_success_string_cannot_hide_unreaped_missing_cpu_or_budget_failure(self):
        attacks = [('exit_code', True), ('waited_child_reaped', False),
                   ('owned_child_reap_resolved', False), ('child_cpu_ns', None),
                   ('observer_cpu_ns', True), ('stop_reason', 'rss-observation-unavailable'),
                   ('waited_child_peak_rss_bytes', 99 * 1024**3),
                   ('observed_wall_ns', 601 * 1_000_000_000)]
        for field, value in attacks:
            args = fixture(); args[3][7][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'RUNTIME_COST_'):
                assessment.build_assessment(*args)

    def test_integer_channels_reject_overflow_and_score_aliases(self):
        args = fixture()
        for record in args[3]: record['child_cpu_ns'] = assessment.LIMIT
        with self.assertRaisesRegex(ValueError, 'RUNTIME_COST_OVERFLOW'):
            assessment.build_assessment(*args)
        for value in ([True, 1], [1, True], [1, 0], [2, 1], [0.0, 1]):
            args = fixture(); args[2]['candidate']['evaluation'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'RUNTIME_ASSESSMENT_SCORE'):
                assessment.build_assessment(*args)


if __name__ == '__main__':
    unittest.main()
