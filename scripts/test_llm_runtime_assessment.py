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
        if phase == 'train':
            steps = plan['training_steps'] if runtime.PARTICIPANT_KINDS[role] in ('lora', 'full-tune') else 0
            receipt['training'] = dict(steps=steps, loss=['1.25'] * steps, tokens=64 * steps,
                supervised_tokens=4 * steps, supported_profile_flops=100 * steps,
                flop_scope='profiler-supported-operators-only-not-total-work')
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

    def test_six_physical_cost_containment_counterexamples_refuse(self):
        # All six were accepted as complete local channels by the old verifier.
        # The values remain individually valid and below the frozen budgets.
        cases = (
            ('process_wall_ns', 5000, False, 'RUNTIME_COST_WALL_CONTAINMENT'),
            ('process_cpu_ns', 5000, False, 'RUNTIME_COST_CPU_CONTAINMENT'),
            ('wall_ns', 5000, True, 'RUNTIME_COST_STAGE_WALL_CONTAINMENT'),
            ('cpu_ns', 5000, True, 'RUNTIME_COST_STAGE_CPU_CONTAINMENT'),
            ('memory_peak_bytes', 1024 * 1024, True, 'RUNTIME_COST_STAGE_RSS_CONTAINMENT'),
            ('process_peak_rss_bytes', 1024 * 1024, False, 'RUNTIME_COST_RSS_CONTAINMENT'),
        )
        for field, value, stage, code in cases:
            args = fixture(); receipt = args[4]['evaluate-candidate']
            target = receipt['cost_events'][0] if stage else receipt
            target[field] = value
            with self.subTest(field=field, stage=stage), self.assertRaisesRegex(ValueError, '^' + code + '$'):
                assessment.build_assessment(*args)

    def test_stage_totals_not_just_largest_stage_must_fit_child_interval(self):
        for field, total, value, code in (
                ('wall_ns', 'process_wall_ns', 400, 'RUNTIME_COST_STAGE_WALL_CONTAINMENT'),
                ('cpu_ns', 'process_cpu_ns', 75, 'RUNTIME_COST_STAGE_CPU_CONTAINMENT')):
            args = fixture(); receipt = args[4]['evaluate-candidate']
            receipt['cost_events'][0][field] = receipt['cost_events'][1][field] = value
            self.assertTrue(all(event[field] <= receipt[total] for event in receipt['cost_events']))
            self.assertGreater(sum(event[field] for event in receipt['cost_events']), receipt[total])
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, '^' + code + '$'):
                assessment.build_assessment(*args)

    def test_equal_cost_containment_boundaries_remain_valid(self):
        args = fixture(); receipt = args[4]['evaluate-candidate']; supervisor = args[3][7]
        receipt['process_wall_ns'] = supervisor['observed_wall_ns']
        receipt['process_cpu_ns'] = supervisor['child_cpu_ns']
        receipt['process_peak_rss_bytes'] = supervisor['waited_child_peak_rss_bytes']
        events = receipt['cost_events']
        for field, total in (('wall_ns', 'process_wall_ns'), ('cpu_ns', 'process_cpu_ns')):
            events[0][field] = receipt[total] - sum(event[field] for event in events[1:])
        for event in events:
            event['memory_peak_bytes'] = receipt['process_peak_rss_bytes']
        result = assessment.build_assessment(*args)
        self.assertTrue(result['local_process_channels_complete'])
        self.assertEqual(result['decision'], 'incomplete')
        self.assertFalse(result['no_update'])
        self.assertFalse(result['adoption'])
        self.assertFalse(result['reward'])

    def test_wait4_cpu_slack_is_bounded_quantization_not_workload_percentage(self):
        # Two microsecond timeval truncations, plus only bounded binary64
        # roundoff in the runner's seconds-to-nanoseconds conversion.
        for value, slack in ((0, 2002), (2_000_000, 2002),
                             (1 << 62, 10193), (assessment.LIMIT, 18385)):
            with self.subTest(waited_cpu=value):
                self.assertEqual(assessment._wait4_cpu_slack_ns(value), slack)
        for excess in (0, 1999, 2000, 2002, 2003):
            args = fixture(); receipt = args[4]['evaluate-candidate']; supervisor = args[3][7]
            supervisor['observed_wall_ns'] = 10_000_000
            receipt['process_wall_ns'] = 8_000_000
            supervisor['child_cpu_ns'] = 2_000_000
            receipt['process_cpu_ns'] = 2_000_000 + excess
            with self.subTest(excess=excess):
                if excess <= 2002:
                    result = assessment.build_assessment(*args)
                    self.assertTrue(result['local_process_channels_complete'])
                    self.assertFalse(result['complete_economic_cost'])
                else:
                    with self.assertRaisesRegex(ValueError, '^RUNTIME_COST_CPU_CONTAINMENT$'):
                        assessment.build_assessment(*args)

    def test_stage_time_totals_cannot_overflow_the_cost_integer_domain(self):
        for field in ('wall_ns', 'cpu_ns'):
            args = fixture()
            for event in args[4]['evaluate-candidate']['cost_events']:
                event[field] = assessment.LIMIT
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, '^RUNTIME_COST_OVERFLOW$'):
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


class TrainingReceiptAssessmentTests(unittest.TestCase):
    TRAINED = ('candidate', 'fresh-budget-matched-lora', 'budget-matched-full-tune')
    ZERO = ('current-backbone', 'randomized-rank-matched-lora')

    def test_v3_names_only_reported_counts_and_retains_missing_actual_schedule(self):
        result = assessment.build_assessment(*fixture())
        self.assertEqual(result['schema'], 'llm-runtime-actual-pilot-assessment-v3')
        self.assertTrue(result['training_steps_and_reported_token_counts_matched'])
        self.assertFalse(result['actual_token_schedule_verified'])
        self.assertNotIn('training_budget_matched_by_steps_and_token_schedule', result)
        self.assertIn('actual-per-step-token-schedule-commitments-and-cross-role-verification',
                      result['unresolved_obligations'])
        self.assertTrue(result['consumption_not_assumed_equal'])
        for field in ('adoption', 'reward', 'no_update', 'complete_economic_cost',
                      'complete_release_evaluation', *runtime.QUALIFICATIONS):
            self.assertIs(result[field], False)

    def test_original_zero_candidate_and_trained_backbone_counterexample_refuses(self):
        args = fixture()
        for role in runtime.PARTICIPANTS:
            args[4]['train-' + role]['training'].update(steps=0, loss=[], tokens=0,
                                                       supervised_tokens=0, supported_profile_flops=0)
        args[4]['train-current-backbone']['training']['steps'] = 99
        with self.assertRaisesRegex(ValueError, '^RUNTIME_TRAINING_STEPS$'):
            assessment.build_assessment(*args)

    def test_each_training_role_requires_closed_present_receipt_fields(self):
        fields = ('steps', 'loss', 'tokens', 'supervised_tokens', 'supported_profile_flops', 'flop_scope')
        for role in runtime.PARTICIPANTS:
            for field in (None, *fields, 'invented-token-schedule'):
                args = fixture(); receipt = args[4]['train-' + role]
                if field is None:
                    del receipt['training']
                elif field == 'invented-token-schedule':
                    receipt['training']['token_schedule_sha256'] = 'f' * 64
                else:
                    del receipt['training'][field]
                with self.subTest(role=role, missing=field), \
                     self.assertRaisesRegex(ValueError, '^RUNTIME_TRAINING_FIELDS$'):
                    assessment.build_assessment(*args)
        for value in (None, True, [], {}, {'steps': 10}):
            args = fixture(); args[4]['train-candidate']['training'] = value
            with self.subTest(training=value), self.assertRaisesRegex(ValueError, '^RUNTIME_TRAINING_FIELDS$'):
                assessment.build_assessment(*args)

    def test_training_numbers_refuse_boolean_negative_missing_and_overflow_aliases(self):
        for role in ('candidate', 'current-backbone', 'randomized-rank-matched-lora'):
            for field in ('steps', 'tokens', 'supervised_tokens', 'supported_profile_flops'):
                for value in (False, True, None, -1, 0.0, '0', 1 << 63):
                    args = fixture(); args[4]['train-' + role]['training'][field] = value
                    with self.subTest(role=role, field=field, value=value), \
                         self.assertRaisesRegex(ValueError, '^RUNTIME_TRAINING_NUMBER$'):
                        assessment.build_assessment(*args)

    def test_trained_role_step_count_must_equal_frozen_plan_even_if_all_roles_agree(self):
        for value in (0, 1, 9, 11, 100):
            args = fixture()
            for role in self.TRAINED:
                args[4]['train-' + role]['training']['steps'] = value
            with self.subTest(steps=value), self.assertRaisesRegex(ValueError, '^RUNTIME_TRAINING_STEPS$'):
                assessment.build_assessment(*args)

    def test_individually_valid_reported_totals_must_match_across_all_three_trained_roles(self):
        for role in self.TRAINED:
            for field in ('tokens', 'supervised_tokens'):
                args = fixture(); args[4]['train-' + role]['training'][field] += 1
                with self.subTest(role=role, field=field), \
                     self.assertRaisesRegex(ValueError, '^RUNTIME_MATCHED_TRAINING_BUDGET$'):
                    assessment.build_assessment(*args)

    def test_equal_but_impossible_reported_totals_do_not_satisfy_training_budget(self):
        # Identical numbers across roles still need the runner's three EOS,
        # nonempty prompt and total per-step token bounds.
        for tokens, supervised in ((0, 0), (40, 29), (40, 31), (40, 41),
                                    (1281, 40), (assessment.LIMIT, assessment.LIMIT)):
            args = fixture()
            for role in self.TRAINED:
                args[4]['train-' + role]['training'].update(tokens=tokens, supervised_tokens=supervised)
            with self.subTest(tokens=tokens, supervised=supervised), \
                 self.assertRaisesRegex(ValueError, '^RUNTIME_TRAINING_TOKENS$'):
                assessment.build_assessment(*args)

    def test_nontraining_roles_require_exact_zero_training_observations(self):
        for role in self.ZERO:
            for field, value, code in (('steps', 1, 'RUNTIME_TRAINING_STEPS'),
                                       ('loss', ['1'], 'RUNTIME_TRAINING_LOSS'),
                                       ('tokens', 1, 'RUNTIME_TRAINING_ZERO_ROLE'),
                                       ('supervised_tokens', 1, 'RUNTIME_TRAINING_ZERO_ROLE'),
                                       ('supported_profile_flops', 1, 'RUNTIME_TRAINING_ZERO_ROLE')):
                args = fixture(); args[4]['train-' + role]['training'][field] = value
                with self.subTest(role=role, field=field), self.assertRaisesRegex(ValueError, '^' + code + '$'):
                    assessment.build_assessment(*args)

    def test_loss_trace_requires_one_finite_nonnegative_observation_per_step(self):
        for value in (None, True, [], ['1'] * 9, ['1'] * 11):
            args = fixture(); args[4]['train-candidate']['training']['loss'] = value
            with self.subTest(loss=value), self.assertRaisesRegex(ValueError, '^RUNTIME_TRAINING_LOSS$'):
                assessment.build_assessment(*args)
        for value in (None, True, 0, 1.0, '', ' ', '1 ', ' nan', 'nan', 'inf', '-inf',
                      '1e999', '-1', '-1e-999', 'a' * 65, '１'):
            args = fixture(); args[4]['train-candidate']['training']['loss'][0] = value
            with self.subTest(loss_value=value), self.assertRaisesRegex(ValueError, '^RUNTIME_TRAINING_LOSS$'):
                assessment.build_assessment(*args)

    def test_valid_count_boundaries_allow_different_losses_and_profiled_consumption(self):
        for tokens, supervised in ((40, 30), (1280, 1270)):
            args = fixture()
            for index, role in enumerate(self.TRAINED):
                args[4]['train-' + role]['training'].update(tokens=tokens, supervised_tokens=supervised,
                    loss=[str(index)] * 10, supported_profile_flops=index * 100)
            result = assessment.build_assessment(*args)
            self.assertTrue(result['training_steps_and_reported_token_counts_matched'])
            self.assertFalse(result['actual_token_schedule_verified'])
            self.assertTrue(result['consumption_not_assumed_equal'])

    def test_legitimate_formatted_negative_zero_loss_is_not_a_negative_observation(self):
        args = fixture()
        args[4]['train-candidate']['training']['loss'] = ['-0'] * args[0]['training_steps']
        result = assessment.build_assessment(*args)
        self.assertTrue(result['training_steps_and_reported_token_counts_matched'])
        self.assertFalse(result['actual_token_schedule_verified'])

    def test_no_planned_training_tasks_cannot_be_reported_as_matched_training(self):
        args = fixture(); plan = args[0]
        plan['tasks'] = [row for row in plan['tasks'] if row['partition'] != 'training']
        args[1]['experiment'] = runtime.identity(plan)
        for name, receipt in args[4].items():
            actual = dict(plan, threads=1) if name == 'loader-1thread' else plan
            receipt['experiment'] = runtime.identity(actual)
        with self.assertRaisesRegex(ValueError, '^RUNTIME_TRAINING_PLAN$'):
            assessment.build_assessment(*args)


if __name__ == '__main__':
    unittest.main()
