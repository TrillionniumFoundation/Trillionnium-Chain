"""Adversarial boundary tests; synthetic receipts do not claim model execution."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import llm_frozen_evaluation as frozen
import llm_inherited_operation as operation
import llm_inherited_runtime as inherited
import llm_runtime_assessment as costs
import llm_runtime_pilot as runtime


def input_fixture():
    return dict(schema='hepta-smollm-training-input-v1', scope='public-smoke-fixtures',
                records=[dict(prompt='synthetic training input', expected_output='yes')])


def profile_fixture():
    plan = runtime.experiment_plan({'synthetic': 'no material'}, threads=2, steps=3)
    plan['tasks'] = inherited.training_rows(input_fixture())
    return dict(schema=frozen.PROFILE, operation_id='fixture-train',
        parent=dict(schema=inherited.PARENT_SCHEMA, generation=3, operation_id='old-task',
            directory='/explicit/fixture-parent', contract='a' * 64, adapter='b' * 64,
            file_sha256='c' * 64),
        training_input_sha256=hashlib.sha256(runtime.canonical(input_fixture())).hexdigest(),
        evaluation_input_sha256='d' * 64, runtime=plan,
        evaluation=dict(metric='greedy-exact-match-v1', min_correct_gain=1, rows=4,
            participants=frozen.PARTICIPANTS.copy(),
            rule='candidate-exceeds-retained-parent-and-every-control-v1'),
        source_pins=frozen.sources(), authority=frozen.AUTHORITY.copy())


def held_out_fixture():
    return dict(schema=frozen.INPUT, scope='public-smoke-fixtures', records=[
        dict(prompt='synthetic held-out ' + str(number), expected_output='yes' if number % 2 else 'no')
        for number in range(4)])


class FreezeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.profile = profile_fixture()

    def test_freeze_contains_no_held_out_labels_and_all_six_roles(self):
        frozen.validate_freeze(self.profile)
        self.assertNotIn('synthetic held-out', json.dumps(self.profile))
        self.assertEqual(self.profile['evaluation']['participants'],
                         ['retained-parent', 'candidate', *runtime.CONTROLS])
        self.assertTrue(all(row['partition'] == 'training' for row in self.profile['runtime']['tasks']))

    def test_zero_gain_or_posthoc_rule_changes_cannot_be_selected(self):
        for change in ({'min_correct_gain': 0}, {'min_correct_gain': True},
                       {'min_correct_gain': 5}, {'rows': 0}, {'rows': 129},
                       {'participants': ['retained-parent', 'candidate']},
                       {'metric': 'choose-after-reading-scores'}, {'rule': 'best-looking-control'}):
            bad = copy.deepcopy(self.profile)
            bad['evaluation'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                frozen.validate_freeze(bad)

    def test_source_budget_recipe_and_authority_changes_rejected(self):
        changes = [lambda p: p['source_pins'].update(frozen_evaluation='e' * 64),
            lambda p: p['runtime']['training_budget'].update(wall_seconds=1700),
            lambda p: p['runtime']['inference_budget'].update(rss_bytes=7 * 1024**3),
            lambda p: p['runtime']['recipes']['candidate'].update(learning_rate='0.01'),
            lambda p: p['authority'].update(independent_accepted=True),
            lambda p: p['authority'].update(independent_accepted=0),
            lambda p: p.update(installed=True),
            lambda p: p.update(evaluation_input_sha256=p['training_input_sha256'])]
        for change in changes:
            bad = copy.deepcopy(self.profile)
            change(bad)
            with self.subTest(change=change), self.assertRaises(ValueError):
                frozen.validate_freeze(bad)

    def test_revealed_rows_must_be_distinct_from_training(self):
        value = held_out_fixture()
        rows = frozen.evaluation_rows(value, self.profile)
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row['partition'] == 'evaluation' for row in rows))
        value['records'][0]['prompt'] = input_fixture()['records'][0]['prompt']
        with self.assertRaisesRegex(ValueError, 'TRAINING_EVALUATION_OVERLAP'):
            frozen.evaluation_rows(value, self.profile)

    def test_revealed_row_count_duplicate_scope_and_fields_rejected(self):
        for change in (lambda v: v['records'].pop(),
                       lambda v: v['records'].__setitem__(0, v['records'][1]),
                       lambda v: v.update(scope='independent-accepted'),
                       lambda v: v['records'][0].update(weight=100)):
            value = held_out_fixture()
            change(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                frozen.evaluation_rows(value, self.profile)

    def test_raw_freeze_bytes_and_duplicate_keys_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'profile.json'
            raw = json.dumps(self.profile, indent=2).encode() + b'\n'
            frozen.publish(path, raw)
            value, observed = frozen.read_pinned(path, hashlib.sha256(raw).hexdigest())
            self.assertEqual(value, self.profile)
            self.assertEqual(observed, raw)
            with self.assertRaisesRegex(ValueError, 'FILE_PIN'):
                frozen.read_pinned(path, runtime.identity(value))
            raw = b'{"schema":1,"schema":2}'
            other = Path(temporary) / 'duplicate.json'
            frozen.publish(other, raw)
            with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON'):
                frozen.read_pinned(other, hashlib.sha256(raw).hexdigest())

    def test_published_profile_cannot_be_rewritten_or_symlinked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'profile.json'
            frozen.publish_json(path, self.profile)
            frozen.publish_json(path, self.profile)
            with self.assertRaisesRegex(ValueError, 'PUBLISHED_BYTES_CHANGED'):
                frozen.publish(path, b'{}')
            (root / 'alias.json').symlink_to(path)
            with self.assertRaises(ValueError):
                frozen.publish(root / 'alias.json', path.read_bytes())


class NumericalDecisionTests(unittest.TestCase):
    def setUp(self):
        self.profile = profile_fixture()
        self.rows = frozen.evaluation_rows(held_out_fixture(), self.profile)

    def observations(self, scores):
        result = {}
        for role in frozen.PARTICIPANTS:
            count = scores.get(role, 0)
            outputs = {row['id']: row['target_output_sha256'] if index < count else 'f' * 64
                       for index, row in enumerate(self.rows)}
            result[role] = dict(status='SUCCESS', outputs=outputs)
        return result

    def test_equal_scores_are_no_update_with_exact_parent_retention(self):
        result = frozen.numerical_assessment(self.profile, self.rows,
            self.observations({role: 2 for role in frozen.PARTICIPANTS}))
        self.assertEqual(result['numerical_disposition'], 'NoUpdate')
        self.assertEqual(result['retained_parent'], self.profile['parent'])
        self.assertEqual(result['gain_correct_vs_strongest_control'], 0)
        self.assertFalse(result['native_iteration_completed'])
        self.assertFalse(result['independent_custody_verified'])
        self.assertTrue(all(value is False for value in result['authority'].values()))

    def test_best_control_and_actual_installed_parent_both_must_be_beaten(self):
        cases = [({'candidate': 3, 'retained-parent': 3}, 'NoUpdate'),
                 ({'candidate': 3, 'retained-parent': 1, runtime.CONTROLS[-1]: 3}, 'NoUpdate'),
                 ({'candidate': 3, 'retained-parent': 1, runtime.CONTROLS[0]: 2}, 'Candidate')]
        for scores, disposition in cases:
            with self.subTest(scores=scores):
                result = frozen.numerical_assessment(self.profile, self.rows, self.observations(scores))
                self.assertEqual(result['numerical_disposition'], disposition)
                self.assertFalse(result['improvement_bonus_authorized'])
                self.assertFalse(result['base_service_fee_authorized'])
                self.assertFalse(result['consensus_credit_authorized'])

    def test_precommitted_absolute_gain_threshold_applies(self):
        self.profile['evaluation']['min_correct_gain'] = 2
        scores = {'candidate': 3, 'retained-parent': 2}
        self.assertEqual(frozen.numerical_assessment(self.profile, self.rows,
                         self.observations(scores))['numerical_disposition'], 'NoUpdate')
        scores['candidate'] = 4
        self.assertEqual(frozen.numerical_assessment(self.profile, self.rows,
                         self.observations(scores))['numerical_disposition'], 'Candidate')

    def test_direct_numerical_entry_cannot_accept_a_zero_threshold(self):
        self.profile['evaluation']['min_correct_gain'] = 0
        with self.assertRaisesRegex(ValueError, 'POSITIVE_GAIN_REQUIRED'):
            frozen.numerical_assessment(self.profile, self.rows, self.observations({}))

    def test_missing_failed_or_unknown_control_cannot_be_no_update(self):
        for failure in ('missing', 'FAILED', 'UNKNOWN', 'NOT_STARTED'):
            observations = self.observations({'candidate': 4})
            if failure == 'missing':
                observations.pop(runtime.CONTROLS[0])
            else:
                observations[runtime.CONTROLS[0]]['status'] = failure
            with self.subTest(failure=failure), self.assertRaisesRegex(ValueError, 'COMPLETE_EVALUATION'):
                frozen.numerical_assessment(self.profile, self.rows, observations)

    def test_a_missing_output_or_extra_task_cannot_shift_the_denominator(self):
        for change in ('missing', 'extra'):
            observations = self.observations({'candidate': 4})
            outputs = observations['candidate']['outputs']
            if change == 'missing':
                outputs.pop(self.rows[0]['id'])
            else:
                outputs['unregistered-task'] = 'a' * 64
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'EVALUATION_OUTPUT_SET'):
                frozen.numerical_assessment(self.profile, self.rows, observations)

    def test_matching_caps_do_not_excuse_unequal_observed_training_steps_or_tokens(self):
        receipts = {}
        for role in runtime.PARTICIPANTS:
            trained = runtime.PARTICIPANT_KINDS[role] in ('lora', 'full-tune')
            receipts['train-' + role] = dict(training=dict(steps=3 if trained else 0,
                loss=['1'] * (3 if trained else 0), tokens=30 if trained else 0,
                supervised_tokens=12 if trained else 0, supported_profile_flops=0,
                flop_scope='profiler-supported-operators-only-not-total-work'))
        costs.validate_training_match(self.profile['runtime'], receipts)
        receipts['train-budget-matched-full-tune']['training']['tokens'] += 1
        with self.assertRaisesRegex(ValueError, 'MATCHED_TRAINING_BUDGET'):
            costs.validate_training_match(self.profile['runtime'], receipts)


class DurableStageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.profile = profile_fixture()
        # Deliberately noncanonical: the exact original freeze bytes must survive.
        self.raw = json.dumps(self.profile, indent=2).encode() + b'\n'
        frozen.publish(self.root / 'evaluation-profile.json', self.raw)
        self.context = dict(original_authority_id='a' * 64, original_intent_sha256='b' * 64,
                            evaluation_profile_sha256=hashlib.sha256(self.raw).hexdigest())
        initialized = operation.initialize(self.root / 'journal.sqlite3')
        self.authority = initialized['authority_id']
        self.journal = operation.Journal(self.root / 'journal.sqlite3', self.authority)
        self.stage, self.intent, self.request = frozen.stage_request(
            self.context, self.root, 'train', runtime.CONTROLS[0])

    def tearDown(self):
        self.journal.close()
        self.temporary.cleanup()

    def test_crash_after_reservation_is_unknown_and_never_dispatched_twice(self):
        dispatch = mock.Mock(side_effect=RuntimeError('synthetic crash before spawn'))
        with mock.patch.object(frozen, 'observe_stage', return_value=None):
            first = frozen.stage_once(self.journal, self.stage, self.intent, self.request, self.profile, dispatch)
            second = frozen.stage_once(self.journal, self.stage, self.intent, self.request, self.profile, dispatch)
        self.assertEqual(first['status'], 'UNKNOWN')
        self.assertEqual(second['status'], 'UNKNOWN')
        self.assertEqual(dispatch.call_count, 1)
        retained = self.journal.lookup(self.stage, self.intent)
        self.assertEqual(retained['freeze']['raw_utf8'].encode(), self.raw)
        self.assertEqual(retained['request']['original_authority_id'], self.context['original_authority_id'])

    def test_pending_reservation_survives_cold_reopen_without_reexecution(self):
        with mock.patch.object(frozen, 'observe_stage', return_value=None):
            frozen.stage_once(self.journal, self.stage, self.intent, self.request, self.profile, mock.Mock())
        self.journal.close()
        self.journal = operation.Journal(self.root / 'journal.sqlite3', self.authority)
        dispatch = mock.Mock()
        with mock.patch.object(frozen, 'observe_stage', return_value=None):
            result = frozen.stage_once(self.journal, self.stage, self.intent, self.request, self.profile, dispatch)
        self.assertEqual(result['status'], 'UNKNOWN')
        dispatch.assert_not_called()

    def test_query_never_initializes_or_dispatches_a_missing_stage(self):
        with mock.patch.object(runtime, 'supervise', side_effect=AssertionError('must not spawn')):
            result = frozen.stage_once(self.journal, self.stage, self.intent, self.request, self.profile)
        self.assertEqual(result['status'], 'NOT_STARTED')
        self.assertIsNone(self.journal.lookup(self.stage, self.intent))
        self.assertFalse(Path(self.request['directory']).exists())

    def test_changed_output_or_replacement_id_cannot_escape_a_pending_stage(self):
        with mock.patch.object(frozen, 'observe_stage', return_value=None):
            frozen.stage_once(self.journal, self.stage, self.intent, self.request, self.profile, mock.Mock())
        changed = dict(self.request, directory=str(self.root / 'replacement'), output=str(self.root / 'replacement'))
        with self.assertRaisesRegex(ValueError, 'STAGE_REQUEST_CHANGED'):
            frozen.stage_once(self.journal, self.stage, self.intent, changed, self.profile, mock.Mock())
        with self.assertRaisesRegex(ValueError, 'IDENTITY_REUSE'):
            frozen.stage_once(self.journal, 'replacement-operation', self.intent, self.request, self.profile, mock.Mock())

    def test_terminal_evidence_is_pinned_and_cannot_be_replaced(self):
        first = dict(status='FAILED', pins={'supervisor.json': 'e' * 64}, costs={})
        with mock.patch.object(frozen, 'observe_stage', return_value=first):
            result = frozen.stage_once(self.journal, self.stage, self.intent, self.request, self.profile, mock.Mock())
        self.assertEqual(result['status'], 'FAILED')
        with mock.patch.object(frozen, 'observe_stage', return_value=dict(first, status='SUCCESS')):
            with self.assertRaisesRegex(ValueError, 'TERMINAL_EVIDENCE_CHANGED'):
                frozen.stage_once(self.journal, self.stage, self.intent, self.request, self.profile, mock.Mock())

    def test_mismatched_freeze_is_rejected_before_dispatch(self):
        request = dict(self.request, evaluation_profile_sha256='f' * 64)
        dispatch = mock.Mock()
        with self.assertRaisesRegex(ValueError, 'STAGE_FREEZE_BINDING'):
            frozen.stage_once(self.journal, self.stage, self.intent, request, self.profile, dispatch)
        dispatch.assert_not_called()
        self.assertIsNone(self.journal.lookup(self.stage, self.intent))


class ArtifactAndBudgetTests(unittest.TestCase):
    def test_streamed_file_pin_uses_the_existing_native_artifact_domain(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'synthetic.bin'
            frozen.publish(path, b'synthetic bytes, not model material')
            pin = frozen.file_pin(path)
            self.assertEqual(pin['sha256'], runtime.file_sha(path))
            self.assertEqual(pin['native_artifact_H'], runtime.native_artifact_digest(path))
            with self.assertRaises(ValueError):
                frozen.file_pin(path, 4)

    def test_reported_success_cannot_hide_budget_overrun(self):
        budget = dict(wall_seconds=10, rss_bytes=1024)
        supervisor = dict(budget=budget, outcome='success', exit_code=0, stop_reason=None,
            observed_wall_ns=8 * 10**9, child_cpu_ns=100, observer_cpu_ns=10,
            sampled_peak_rss_bytes=500, waited_child_peak_rss_bytes=600)
        receipt = dict(process_wall_ns=7 * 10**9, process_peak_rss_bytes=600)
        frozen.budget_readback(supervisor, receipt, budget)
        for change in ({'observed_wall_ns': 11 * 10**9}, {'waited_child_peak_rss_bytes': 1025},
                       {'child_cpu_ns': None}, {'observed_wall_ns': True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                frozen.budget_readback(dict(supervisor, **change), receipt, budget)

    def test_parent_baseline_cannot_be_replaced_by_bare_backbone(self):
        profile = profile_fixture()
        artifacts = {}
        for role in ('retained-parent', 'candidate'):
            descriptor = copy.deepcopy(profile['parent'])
            if role == 'candidate':
                descriptor.update(generation=4, operation_id=profile['operation_id'], adapter='e' * 64)
            artifacts[role] = dict(kind='inherited', descriptor=descriptor,
                artifact=descriptor['adapter'], contract=descriptor['contract'])
        for role in runtime.CONTROLS:
            artifacts[role] = dict(kind='pilot', directory='/explicit/' + role,
                artifact='f' * 64, contract='1' * 64, artifact_record_sha256='2' * 64)
        roster = dict(schema=frozen.ROSTER, evaluation_profile_sha256='3' * 64,
                      operation_id=profile['operation_id'], artifacts=artifacts)
        frozen.validate_roster(roster, profile, '3' * 64)
        roster['artifacts']['retained-parent'] = artifacts[runtime.CONTROLS[0]]
        with self.assertRaises(ValueError):
            frozen.validate_roster(roster, profile, '3' * 64)


class ExecutionRoutingTests(unittest.TestCase):
    def test_control_jobs_use_all_original_trainers_and_receive_no_held_out_file(self):
        """Only dispatch wiring is mocked; this fixture asserts no model quality."""
        profile = profile_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            frozen.publish_json(root / 'evaluation-profile.json', profile)
            frozen.publish_json(root / 'training-plan.json', profile['runtime'])
            context = dict(schema=frozen.RUN, operation_id=profile['operation_id'],
                evaluation_profile_sha256=runtime.file_sha(root / 'evaluation-profile.json'),
                original_authority_id='1' * 64, original_intent_sha256='2' * 64,
                materials=str(root / 'synthetic-materials'), output=str(root))
            (root / 'candidate').mkdir(mode=0o700)
            (root / 'candidate/worker').mkdir(mode=0o700)
            child_parent = dict(profile['parent'], generation=4, operation_id=profile['operation_id'],
                directory=str(root / 'candidate/worker'), adapter='e' * 64)
            frozen.publish_json(root / 'candidate/worker/parent-material.json', child_parent)
            observations = {}
            for role in runtime.PARTICIPANTS:
                path = root / ('candidate/worker' if role == 'candidate' else 'train-' + role)
                if role != 'candidate':
                    path.mkdir(mode=0o700)
                trained = runtime.PARTICIPANT_KINDS[role] in ('lora', 'full-tune')
                training = dict(steps=3 if trained else 0, loss=['1'] * (3 if trained else 0),
                    tokens=30 if trained else 0, supervised_tokens=12 if trained else 0,
                    supported_profile_flops=0, flop_scope='profiler-supported-operators-only-not-total-work')
                frozen.publish_json(path / 'actual-receipt.json', dict(training=training))
                observations[role] = dict(status='SUCCESS', artifact='f' * 64, contract='a' * 64,
                    pins={'artifact.json': '3' * 64}, training=training)

            def invoke(journal, stage, intent, request, frozen_profile, dispatch):
                self.assertEqual(frozen_profile, profile)
                self.assertEqual(request['evaluation_profile_sha256'], context['evaluation_profile_sha256'])
                self.assertEqual(request['original_authority_id'], context['original_authority_id'])
                self.assertEqual(request['output'], request['directory'])
                dispatch()
                return observations[request['role']]

            with mock.patch.object(frozen, 'candidate_readback', return_value={'status': 'SUCCESS'}), \
                    mock.patch.object(frozen, 'stage_once', side_effect=invoke), \
                    mock.patch.object(runtime, 'supervise') as supervised:
                result = frozen.train_all(None, profile, context, root, dispatch=True)
            self.assertEqual(result['status'], 'TRAINED')
            self.assertEqual(supervised.call_count, len(runtime.CONTROLS))
            actual_roles = []
            for call in supervised.call_args_list:
                command, output, budget = call.args
                self.assertEqual(command[1], str(Path(runtime.__file__).resolve()))
                self.assertEqual(command[2], '_child')
                self.assertEqual(command[command.index('--phase') + 1], 'train')
                self.assertEqual(command[command.index('--plan') + 1], str(root / 'training-plan.json'))
                self.assertNotIn('--evaluation-input', command)
                self.assertNotIn('held-out', ' '.join(command))
                actual_roles.append(command[command.index('--role') + 1])
                self.assertEqual(budget, profile['runtime']['training_budget'])
            self.assertEqual(actual_roles, runtime.CONTROLS)
            roster = runtime.read_json(root / 'artifact-roster.json')
            self.assertEqual(roster['artifacts']['retained-parent']['descriptor'], profile['parent'])

    def test_unknown_candidate_cannot_dispatch_controls(self):
        with mock.patch.object(frozen, 'candidate_readback', return_value={'status': 'UNKNOWN'}), \
                mock.patch.object(frozen, 'child_journal', side_effect=AssertionError('must not dispatch')):
            result = frozen.train_all(None, profile_fixture(), {}, Path('/unused'), dispatch=True)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertIsNone(result['numerical_disposition'])

    def test_changed_candidate_request_error_is_not_masked_by_old_success(self):
        profile = profile_fixture()
        context = dict(original_intent_sha256='a' * 64, materials='/unused',
                       evaluation_profile_sha256='b' * 64)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            frozen.publish_json(root / 'installed-parent.json', profile['parent'])
            frozen.publish_json(root / 'evaluation-profile.json', profile)
            journal = mock.Mock()
            journal.lookup.return_value = dict(request={'output': '/a/different/run'})
            with mock.patch.object(operation, 'run_once', side_effect=ValueError('REQUEST_CHANGED')), \
                    mock.patch.object(operation, 'query') as query:
                with self.assertRaisesRegex(ValueError, 'REQUEST_CHANGED'):
                    frozen.candidate_readback(journal, context, profile, root, dispatch=True)
            query.assert_not_called()


if __name__ == '__main__':
    unittest.main()
