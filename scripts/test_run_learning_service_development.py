"""Driver boundaries and actual subprocess logging; no model-quality fixtures."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import llm_frozen_evaluation as frozen
import llm_inherited_operation as operation
import llm_inherited_runtime as inherited
import llm_runtime_pilot as runtime
import run_learning_service_development as driver


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for name in ('inputs', 'logs', 'trial'):
            (self.root / name).mkdir(mode=0o700)
        self.parent = dict(schema=inherited.PARENT_SCHEMA, generation=1, operation_id='bootstrap',
            directory='/synthetic/parent', contract='a' * 64, adapter='b' * 64, file_sha256='c' * 64)
        frozen.publish_json(self.root / 'inputs/parent.json', self.parent)
        frozen.publish_json(self.root / 'inputs/next.json', dict(schema='hepta-smollm-inference-input-v1',
                                                               request_id='next-task', prompt='synthetic next'))
        self.training = dict(schema='hepta-smollm-training-input-v1', scope='public-smoke-fixtures',
                             records=[dict(prompt='synthetic train', expected_output='yes')])
        self.held_out = dict(schema=frozen.INPUT, scope='public-smoke-fixtures',
                            records=[dict(prompt='synthetic holdout', expected_output='yes')])
        frozen.publish_json(self.root / 'inputs/training.json', self.training)
        frozen.publish_json(self.root / 'inputs/evaluation.json', self.held_out)
        self.manifest = dict(schema=driver.SCHEMA, operation_id='train-task', output=str(self.root),
            materials='/synthetic/materials', inputs={role: dict(path=str(self.root / 'inputs' / (role + '.json')),
                sha256=runtime.file_sha(self.root / 'inputs' / (role + '.json'))) for role in
                ('parent', 'training', 'evaluation', 'next')}, steps=3, threads=2, evaluation_rows=1,
            min_correct_gain=1, next_expected_output_sha256=None, base_fee=2000,
            training_cpu_cap_ns=5400 * 10**9, parameter_byte_cap=16 * 1024**2,
            native_binary=dict(path='/synthetic/native', sha256='d' * 64), scope=driver.SCOPE)
        self.binding = dict(operation_id='train-task', authority_id='1' * 64,
            plan_sha256='2' * 64, evaluation_profile_sha256='3' * 64, intent_sha256='4' * 64)

    def tearDown(self):
        self.temporary.cleanup()

    def evaluation(self, disposition='NoUpdate'):
        return dict(schema=frozen.RESULT, status='COMPLETE', operation_id='train-task',
            evaluation_profile_sha256=self.binding['evaluation_profile_sha256'],
            numerical_disposition=disposition, numerical_gate_passed=disposition == 'Candidate',
            all_required_controls_executed=True, retained_parent=self.parent if disposition == 'NoUpdate' else None,
            authority=frozen.AUTHORITY.copy())

    def test_native_request_binds_original_provider_output_profile_and_caps(self):
        value = driver.service_request(self.manifest, self.binding['authority_id'],
                                       self.binding['evaluation_profile_sha256'])
        self.assertEqual(set(value), {'schema', 'provider_authority_id', 'operation_id', 'output_directory',
            'base_fee', 'training_cpu_cap_ns', 'parameter_byte_cap', 'evaluation_protocol_sha256'})
        self.assertEqual(value['output_directory'], str(self.root / 'trial/candidate'))
        self.assertEqual(value['provider_authority_id'], self.binding['authority_id'])
        self.assertEqual(value['evaluation_protocol_sha256'], self.binding['evaluation_profile_sha256'])
        self.assertEqual(value['training_cpu_cap_ns'], self.manifest['training_cpu_cap_ns'])

    def test_only_complete_no_update_on_exact_parent_permits_next_input(self):
        value = self.evaluation()
        self.assertTrue(driver.numerical_no_update(value, self.manifest, self.binding))
        for change in ({'status': 'UNKNOWN'}, {'all_required_controls_executed': False},
                       {'numerical_disposition': 'Candidate'}, {'retained_parent': None},
                       {'evaluation_profile_sha256': 'f' * 64}, {'operation_id': 'another'},
                       {'authority': dict(frozen.AUTHORITY, independent_accepted=0)}):
            with self.subTest(change=change):
                self.assertFalse(driver.numerical_no_update(dict(value, **change), self.manifest, self.binding))

    def test_nonzero_exit_cannot_authorize_next_input_from_success_text(self):
        stage = dict(receipt=dict(exit_code=1), data=self.evaluation())
        result = driver.evaluation_result(stage, self.manifest, self.binding)
        self.assertFalse(driver.numerical_no_update(result, self.manifest, self.binding))
        self.assertEqual(result['status'], 'COMPLETE_RESPONSE_WITH_UNCONFIRMED_EXIT')

    def test_wrong_evaluation_binding_remains_failure_without_hiding_service_success(self):
        stage = dict(receipt=dict(exit_code=0), data=dict(self.evaluation(), operation_id='another'))
        evaluation = driver.evaluation_result(stage, self.manifest, self.binding)
        result = driver.summary(self.manifest, self.binding, evaluation, {'status': 'SUCCESS'},
            {'status': 'PAID_CURRENT_BRANCH', 'current_branch_base_fee': 2000}, None, {})
        self.assertEqual(result['status'], 'TRAINING_SERVICE_COMPLETED_EVALUATION_INCOMPLETE')
        self.assertFalse(result['numerical_no_update_completed'])
        self.assertEqual(result['development_settlement']['current_branch_base_fee'], 2000)

    def test_base_fee_success_does_not_invent_no_update_or_improvement(self):
        result = driver.summary(self.manifest, self.binding, None, {'status': 'SUCCESS'},
            {'status': 'PAID_CURRENT_BRANCH', 'current_branch_base_fee': 2000}, None, {})
        self.assertEqual(result['status'], 'TRAINING_SERVICE_COMPLETED_EVALUATION_INCOMPLETE')
        self.assertFalse(result['native_iteration_completed'])
        self.assertFalse(result['candidate_selected'])
        self.assertFalse(result['candidate_installed'])
        self.assertEqual(result['scope']['improvement_bonus'], 0)
        self.assertEqual(result['scope']['anti_sybil_consensus_credit'], 0)
        self.assertFalse(result['scope']['real_asset_funding_verified'])

    def test_candidate_waits_for_original_owner_and_next_output_mismatch_is_retained(self):
        candidate = driver.summary(self.manifest, self.binding, self.evaluation('Candidate'),
            {'status': 'SUCCESS'}, {'status': 'PAID_CURRENT_BRANCH'}, None, {})
        self.assertEqual(candidate['status'], 'CANDIDATE_PENDING_ORIGINAL_OWNER_SELECTION')
        self.assertIsNone(candidate['next_input'])
        mismatch = driver.summary(self.manifest, self.binding, self.evaluation(), {'status': 'SUCCESS'},
            {'status': 'PAID_CURRENT_BRANCH'}, {'status': 'SUCCESS', 'expected_output_match': False}, {})
        self.assertEqual(mismatch['status'], 'NO_UPDATE_NEXT_INPUT_OUTPUT_MISMATCH')
        self.assertTrue(mismatch['numerical_no_update_completed'])

    def test_next_input_without_expected_output_remains_explicitly_unchecked(self):
        result = driver.summary(self.manifest, self.binding, self.evaluation(), {'status': 'SUCCESS'},
            {'status': 'PAID_CURRENT_BRANCH'}, {'status': 'SUCCESS', 'expected_output_match': None}, {})
        self.assertEqual(result['status'], 'NO_UPDATE_NEXT_INPUT_UNCHECKED')
        checked = driver.summary(self.manifest, self.binding, self.evaluation(), {'status': 'SUCCESS'},
            {'status': 'PAID_CURRENT_BRANCH'}, {'status': 'SUCCESS', 'expected_output_match': True}, {})
        self.assertEqual(checked['status'], 'COMPLETED_DEVELOPMENT_NO_UPDATE')

    def native_query_fixture(self):
        value = dict(schema='native-learning-service-round-v1', operation_id='train-task',
            provider_authority_id=self.binding['authority_id'], plan_sha256=self.binding['plan_sha256'],
            evaluation_profile_sha256=self.binding['evaluation_profile_sha256'],
            intent_sha256=self.binding['intent_sha256'], dispatch_allowed=False,
            improvement_bonus=0, anti_sybil_consensus_credit=0, production_activation=False,
            status='PAID_CURRENT_BRANCH', locally_revoked=False, current_branch_base_fee=2000,
            base_fee_contract=2000)
        return dict(receipt=dict(exit_code=0), data=value)

    def test_new_next_input_requires_fresh_paid_and_unrevoked_native_observation(self):
        stage = self.native_query_fixture()
        self.assertTrue(driver.next_dispatch_gate(stage, self.manifest, self.binding)['allowed'])
        cases = [({'locally_revoked': True}, 'LOCALLY_REVOKED'),
                 ({'locally_revoked': None}, 'LOCAL_REVOCATION_UNCONFIRMED'),
                 ({'status': 'UNKNOWN_OR_UNPAID_CURRENT_BRANCH'}, 'PAYMENT_NOT_CURRENT'),
                 ({'current_branch_base_fee': 0}, 'PAYMENT_NOT_CURRENT'),
                 ({'intent_sha256': 'f' * 64}, 'NATIVE_QUERY_BINDING_FAILED')]
        for change, expected in cases:
            changed = copy.deepcopy(stage)
            changed['data'].update(change)
            gate = driver.next_dispatch_gate(changed, self.manifest, self.binding)
            with self.subTest(change=change):
                self.assertFalse(gate['allowed'])
                self.assertEqual(gate['blocked_reason'], expected)
        for missing in (None, dict(receipt=dict(exit_code=1), data=stage['data']),
                        dict(receipt=dict(exit_code=0), data=None)):
            gate = driver.next_dispatch_gate(missing, self.manifest, self.binding)
            self.assertFalse(gate['allowed'])
            self.assertEqual(gate['blocked_reason'], 'NATIVE_QUERY_UNCONFIRMED')

    def next_readback_fixture(self):
        identity = driver.next_identity(self.manifest, self.binding)
        frozen.publish_json(self.root / 'next-intent.json', identity)
        return dict(schema=operation.OBSERVATION, authority_id=self.binding['authority_id'],
            operation_id=identity['operation_id'], intent_sha256=identity['intent_sha256'],
            evaluation_profile_sha256=self.binding['evaluation_profile_sha256'],
            original_output=str(self.root / 'next-input'), dispatch_allowed=False,
            reservation='RETAINED', no_update_decided=False, payment_authorized=False,
            authority=frozen.AUTHORITY.copy(), status='UNKNOWN', observation=None)

    def test_next_readback_cannot_be_transplanted_from_another_source_or_owner(self):
        value = self.next_readback_fixture()
        self.assertEqual(driver.next_observation(self.root, self.manifest, self.binding, value)['status'], 'UNKNOWN')
        for change in ({'schema': 'another'}, {'authority_id': 'f' * 64}, {'operation_id': 'train-task'},
                       {'intent_sha256': self.binding['intent_sha256']}, {'evaluation_profile_sha256': 'e' * 64},
                       {'original_output': '/another/output'}, {'dispatch_allowed': 0},
                       {'authority': dict(frozen.AUTHORITY, hepta_final_use=True)}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                driver.next_observation(self.root, self.manifest, self.binding, dict(value, **change))

    def test_next_success_binds_original_retained_parent_input_and_prediction_bytes(self):
        value = self.next_readback_fixture()
        (self.root / 'next-input').mkdir(mode=0o700)
        (self.root / 'next-input/worker').mkdir(mode=0o700)
        inputs = driver.document(Path(self.manifest['inputs']['next']['path']))
        plan = dict(schema=inherited.SCHEMA, phase='infer', operation_id=inputs['request_id'],
                    parent=self.parent, generation=1, inputs=inputs,
                    inputs_sha256=self.manifest['inputs']['next']['sha256'])
        frozen.publish_json(self.root / 'next-input/execution-plan.json', plan)
        prediction = dict(artifact=self.parent['adapter'], task=runtime.identity(inputs),
            output_sha256=hashlib.sha256(b'yes').hexdigest(), response=dict(decoded_outputs=['yes']))
        frozen.publish_json(self.root / 'next-input/worker/prediction.json', prediction)
        pins = {name: dict(sha256=runtime.file_sha(self.root / 'next-input' / name))
                for name in ('execution-plan.json', 'worker/prediction.json')}
        value.update(status='SUCCESS', plan_sha256=pins['execution-plan.json']['sha256'],
                     observation=dict(pins=pins, artifact=self.parent['adapter']))
        self.manifest['next_expected_output_sha256'] = hashlib.sha256(b'yes').hexdigest()
        result = driver.next_observation(self.root, self.manifest, self.binding, value)
        self.assertTrue(result['expected_output_match'])
        self.assertEqual(result['decoded_outputs'], ['yes'])
        bad = copy.deepcopy(value)
        bad['observation']['artifact'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'NEXT_SOURCE_PLAN_BINDING'):
            driver.next_observation(self.root, self.manifest, self.binding, bad)

    def test_next_intent_is_stable_and_source_linked(self):
        first = driver.next_identity(self.manifest, self.binding)
        self.assertEqual(first, driver.next_identity(self.manifest, self.binding))
        self.assertEqual(first['source_intent_sha256'], self.binding['intent_sha256'])
        self.assertEqual(first['operation_id'], 'next-task')
        changed = driver.next_identity(self.manifest, dict(self.binding, intent_sha256='5' * 64))
        self.assertNotEqual(first['intent_sha256'], changed['intent_sha256'])
        args = driver.next_arguments(self.root, self.manifest, self.binding, first)
        self.assertEqual(args[0], 'infer')
        self.assertEqual(args[args.index('--parent') + 1], self.manifest['inputs']['parent']['path'])
        self.assertEqual(args[args.index('--source-operation-id') + 1], self.manifest['operation_id'])
        self.assertEqual(args[args.index('--source-intent-sha256') + 1], self.binding['intent_sha256'])

    def test_original_task_cannot_be_relabelled_as_next_input(self):
        with self.assertRaisesRegex(ValueError, 'DISTINCT_NEXT_INPUT'):
            driver.check_next_input(dict(schema='hepta-smollm-inference-input-v1',
                                         request_id='train-task', prompt='same task'), 'train-task')

    def test_original_subprocess_stdout_stderr_and_nonzero_exit_are_retained(self):
        code = 'import sys; print("{\\"schema\\":\\"synthetic-log-test\\"}"); print("original error",file=sys.stderr); sys.exit(7)'
        result = driver.phase(self.root / 'logs', 'actual-process', [sys.executable, '-c', code])
        directory = self.root / 'logs/actual-process'
        self.assertEqual(result['receipt']['exit_code'], 7)
        self.assertEqual(result['data'], {'schema': 'synthetic-log-test'})
        self.assertEqual((directory / 'stderr.log').read_text(), 'original error\n')
        self.assertEqual(result['receipt']['stdout_sha256'], runtime.file_sha(directory / 'stdout.log'))
        self.assertFalse(driver.document(directory / 'invocation.json')['automatically_replayable'])
        with self.assertRaises(FileExistsError):
            driver.phase(self.root / 'logs', 'actual-process', [sys.executable, '-c', 'raise AssertionError'])

    def test_query_invokes_only_original_query_entrypoints(self):
        frozen.publish_json(self.root / 'manifest.json', self.manifest)
        frozen.publish_json(self.root / 'binding.json', self.binding)
        calls = []

        def python(logs, name, module, arguments):
            calls.append((module, arguments))
            self.assertEqual(arguments[0], 'query')
            value = (dict(schema=frozen.RESULT, status='UNKNOWN', operation_id='train-task',
                evaluation_profile_sha256=self.binding['evaluation_profile_sha256'])
                if module == 'llm_frozen_evaluation.py' else dict(schema=operation.OBSERVATION, status='UNKNOWN'))
            return dict(receipt=dict(exit_code=2), data=value, directory=str(logs / name))

        def native(logs, name, manifest, arguments, native_override=None):
            calls.append(('native', arguments))
            self.assertEqual(arguments, ['query', str(self.root / 'native-service')])
            return dict(receipt=dict(exit_code=1), data=None, directory=str(logs / name))

        with mock.patch.object(driver, 'python_phase', side_effect=python), \
                mock.patch.object(driver, 'native_phase', side_effect=native):
            result = driver.query(SimpleNamespace(output=str(self.root), native_bin=None, native_bin_sha256=None))
        self.assertTrue(result['query_only'])
        self.assertEqual(len(calls), 3)
        self.assertFalse((self.root / 'provider.sqlite3').exists())
        self.assertFalse((self.root / 'next-input').exists())

    def test_query_of_incomplete_setup_creates_no_authority_or_native_task(self):
        with mock.patch.object(driver, 'python_phase', side_effect=AssertionError('no subprocess')), \
                mock.patch.object(driver, 'native_phase', side_effect=AssertionError('no subprocess')):
            result = driver.query(SimpleNamespace(output=str(self.root), native_bin=None, native_bin_sha256=None))
        self.assertEqual(result['status'], 'INCOMPLETE_SETUP_QUERY_ORIGINAL_STAGE_FILES')
        self.assertFalse((self.root / 'queries').exists())

    def complete_next_readback_fixture(self):
        """Synthetic retained bytes; only the query subprocesses below execute."""
        value = self.next_readback_fixture()
        (self.root / 'next-input').mkdir(mode=0o700)
        (self.root / 'next-input/worker').mkdir(mode=0o700)
        inputs = driver.document(Path(self.manifest['inputs']['next']['path']))
        plan = dict(schema=inherited.SCHEMA, phase='infer', operation_id=inputs['request_id'],
            parent=self.parent, generation=1, inputs=inputs,
            inputs_sha256=self.manifest['inputs']['next']['sha256'])
        frozen.publish_json(self.root / 'next-input/execution-plan.json', plan)
        prediction = dict(artifact=self.parent['adapter'], task=runtime.identity(inputs),
            output_sha256=hashlib.sha256(b'yes').hexdigest(), response=dict(decoded_outputs=['yes']))
        frozen.publish_json(self.root / 'next-input/worker/prediction.json', prediction)
        pins = {name: dict(sha256=runtime.file_sha(self.root / 'next-input' / name))
                for name in ('execution-plan.json', 'worker/prediction.json')}
        value.update(status='SUCCESS', plan_sha256=pins['execution-plan.json']['sha256'],
                     observation=dict(pins=pins, artifact=self.parent['adapter']))
        return value

    def query_with_observed_process_exits(self, *, native_exit=0, next_exit=0,
                                         candidate_exit=0, complete_evaluation=True):
        """Use actual process exits/stdout with synthetic original-owner replies."""
        self.manifest['next_expected_output_sha256'] = hashlib.sha256(b'yes').hexdigest()
        next_use = self.complete_next_readback_fixture()
        frozen.publish_json(self.root / 'manifest.json', self.manifest)
        frozen.publish_json(self.root / 'binding.json', self.binding)
        next_log = self.root / 'logs/08-retained-parent-next-input'
        next_log.mkdir(mode=0o700)
        frozen.publish_json(next_log / 'invocation.json', {'fixture': True})
        evaluation = self.evaluation() if complete_evaluation else dict(schema=frozen.RESULT,
            status='UNKNOWN', operation_id=self.manifest['operation_id'],
            evaluation_profile_sha256=self.binding['evaluation_profile_sha256'])
        commands = []

        def observe(logs, name, value, code):
            command = [sys.executable, '-c',
                       'import sys; print(sys.argv[1], flush=True); sys.exit(int(sys.argv[2]))',
                       json.dumps(value), str(code)]
            return driver.phase(logs, name, command)

        def python(logs, name, module, arguments):
            commands.append((module, arguments))
            self.assertEqual(arguments[0], 'query')
            if module == 'llm_frozen_evaluation.py':
                return observe(logs, name, evaluation, 0 if complete_evaluation else 2)
            if name == '04-next-input-query':
                return observe(logs, name, next_use, next_exit)
            return observe(logs, name, dict(schema=operation.OBSERVATION, status='SUCCESS'), candidate_exit)

        def native(logs, name, manifest, arguments, native_override=None):
            commands.append(('native', arguments))
            self.assertEqual(arguments, ['query', str(self.root / 'native-service')])
            return observe(logs, name, self.native_query_fixture()['data'], native_exit)

        with mock.patch.object(driver, 'python_phase', side_effect=python), \
                mock.patch.object(driver, 'native_phase', side_effect=native):
            result = driver.query(SimpleNamespace(output=str(self.root), native_bin=None, native_bin_sha256=None))
        self.assertEqual(len(commands), 4)
        self.assertTrue(result['query_only'])
        self.assertFalse((self.root / 'provider.sqlite3').exists())
        return result

    def test_query_requires_zero_native_exit_before_completed_no_update(self):
        result = self.query_with_observed_process_exits(native_exit=7)
        stage = result['stages']['native_query']
        self.assertEqual(stage['receipt']['exit_code'], 7)
        self.assertEqual(stage['data']['status'], 'PAID_CURRENT_BRANCH')
        self.assertEqual(json.loads((Path(stage['directory']) / 'stdout.log').read_bytes()), stage['data'])
        self.assertEqual((Path(stage['directory']) / 'stderr.log').read_bytes(), b'')
        self.assertIsNone(result['development_settlement'])
        self.assertEqual(result['status'], 'NO_UPDATE_WITH_INCOMPLETE_DEVELOPMENT_EFFECTS')

    def test_query_requires_zero_next_provider_exit_before_completed_no_update(self):
        result = self.query_with_observed_process_exits(next_exit=7)
        stage = result['stages']['next_query']
        self.assertEqual(stage['receipt']['exit_code'], 7)
        self.assertEqual(stage['data']['status'], 'SUCCESS')
        self.assertEqual(runtime.file_sha(Path(stage['directory']) / 'stdout.log'), stage['receipt']['stdout_sha256'])
        self.assertIsNone(result['next_input']['status'])
        self.assertIsNone(result['next_input']['expected_output_match'])
        self.assertEqual(result['status'], 'NO_UPDATE_WITH_INCOMPLETE_DEVELOPMENT_EFFECTS')

    def test_query_does_not_confirm_training_service_after_nonzero_provider_exit(self):
        result = self.query_with_observed_process_exits(candidate_exit=7, complete_evaluation=False)
        self.assertEqual(result['stages']['candidate_query']['data']['status'], 'SUCCESS')
        self.assertEqual(result['stages']['candidate_query']['receipt']['exit_code'], 7)
        self.assertIsNone(result['candidate_operation'])
        self.assertEqual(result['status'], 'INCOMPLETE_OR_UNKNOWN')

    def test_complete_comparison_cannot_hide_an_unconfirmed_candidate_query(self):
        result = self.query_with_observed_process_exits(candidate_exit=7)
        self.assertTrue(result['numerical_no_update_completed'])
        self.assertEqual(result['evaluation']['status'], 'COMPLETE')
        self.assertTrue(result['next_input']['expected_output_match'])
        self.assertIsNone(result['candidate_operation'])
        self.assertEqual(result['status'], 'NO_UPDATE_WITH_INCOMPLETE_DEVELOPMENT_EFFECTS')

    def test_query_still_accepts_confirmed_processes_without_dispatching_new_work(self):
        result = self.query_with_observed_process_exits()
        self.assertEqual(result['status'], 'COMPLETED_DEVELOPMENT_NO_UPDATE')
        self.assertTrue(result['next_input']['expected_output_match'])
        self.assertTrue(result['no_automatic_retry'])
        self.assertFalse(result['native_iteration_completed'])

    def test_unconfirmed_exit_types_cannot_authorize_next_input(self):
        for receipt in ({}, {'exit_code': None}, {'exit_code': False}, {'exit_code': '0'}):
            with self.subTest(receipt=receipt):
                native = dict(self.native_query_fixture(), receipt=receipt)
                self.assertFalse(driver.next_dispatch_gate(native, self.manifest, self.binding)['allowed'])
                evaluation = dict(receipt=receipt, data=self.evaluation())
                self.assertFalse(driver.numerical_no_update(
                    driver.evaluation_result(evaluation, self.manifest, self.binding), self.manifest, self.binding))

    def test_provider_unknown_and_failed_results_keep_original_exit_and_reservation(self):
        for status, code in (('UNKNOWN', 2), ('FAILED', 3)):
            with self.subTest(status=status):
                value = dict(schema=operation.OBSERVATION, status=status, dispatch_allowed=False,
                    reservation='RETAINED', no_update_decided=False, payment_authorized=False)
                stage = driver.phase(self.root / 'logs', 'provider-' + status.lower(),
                    [sys.executable, '-c',
                     'import sys; print(sys.argv[1], flush=True); sys.exit(int(sys.argv[2]))',
                     json.dumps(value), str(code)])
                self.assertEqual(driver.provider_observation(stage), value)
                self.assertEqual(stage['receipt']['exit_code'], code)
                self.assertEqual(json.loads((Path(stage['directory']) / 'stdout.log').read_bytes()), value)

    def test_start_does_not_complete_after_next_query_prints_success_then_fails(self):
        # Actual subprocess receipts exercise the original start orchestration;
        # all model, freeze and ledger replies remain controlled test fixtures.
        from test_llm_frozen_evaluation import profile_fixture
        profile = profile_fixture()
        profile.update(operation_id=self.manifest['operation_id'], parent=self.parent,
            training_input_sha256=self.manifest['inputs']['training']['sha256'],
            evaluation_input_sha256=self.manifest['inputs']['evaluation']['sha256'])
        profile['runtime']['tasks'] = inherited.training_rows(self.training)
        profile['evaluation']['rows'] = 1
        self.manifest['next_expected_output_sha256'] = hashlib.sha256(b'yes').hexdigest()
        commands = []

        def observed(logs, name, value, code=0):
            return driver.phase(logs, name, [sys.executable, '-c',
                'import sys; print(sys.argv[1], flush=True); sys.exit(int(sys.argv[2]))',
                json.dumps(value), str(code)])

        def python(logs, name, module, arguments):
            commands.append((module, arguments[0]))
            if name == '01-freeze':
                frozen.publish_json(self.root / 'evaluation-profile.json', profile)
                self.binding['evaluation_profile_sha256'] = runtime.file_sha(self.root / 'evaluation-profile.json')
                return observed(logs, name, dict(schema=frozen.PROFILE,
                    evaluation_profile_sha256=self.binding['evaluation_profile_sha256']))
            if name == '02-provider-authority':
                return observed(logs, name, dict(schema=operation.SCHEMA, authority_id=self.binding['authority_id']))
            if name == '04-model-trial':
                return observed(logs, name, self.evaluation())
            if name == '05-candidate-query':
                return observed(logs, name, dict(schema=operation.OBSERVATION, status='SUCCESS',
                    intent_sha256=self.binding['intent_sha256'], plan_sha256=self.binding['plan_sha256']))
            if name == '08-retained-parent-next-input':
                self.assertEqual(arguments[0], 'infer')
                return observed(logs, name, {'fixture': 'no model execution'})
            self.assertEqual(name, '09-next-input-query')
            self.assertEqual(arguments[0], 'query')
            return observed(logs, name, self.complete_next_readback_fixture(), 7)

        def native(logs, name, manifest, arguments, native_override=None):
            commands.append(('native', arguments[0]))
            self.binding['plan_sha256'] = runtime.file_sha(self.root / 'candidate-plan.json')
            value = self.native_query_fixture()['data']
            if arguments[0] == 'prepare':
                value.update(status='PREPARED', dispatch_allowed=True)
            return observed(logs, name, value)

        with mock.patch.object(driver, 'setup', return_value=(self.root, self.manifest)), \
                mock.patch.object(inherited, 'prepare_plan', return_value=dict(runtime=profile['runtime'], parent=self.parent)), \
                mock.patch.object(driver, 'python_phase', side_effect=python), \
                mock.patch.object(driver, 'native_phase', side_effect=native):
            result = driver.start(SimpleNamespace())
        self.assertEqual(result['stages']['next_query']['receipt']['exit_code'], 7)
        self.assertEqual(result['stages']['next_query']['data']['status'], 'SUCCESS')
        self.assertEqual(result['status'], 'NO_UPDATE_WITH_INCOMPLETE_DEVELOPMENT_EFFECTS')
        self.assertIsNone(result['next_input']['expected_output_match'])
        self.assertEqual(commands.count(('llm_inherited_operation.py', 'infer')), 1)
        self.assertTrue(result['no_automatic_retry'])



@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os, 'memfd_create'), 'Linux sealed ELF')
class SealedExecutableTests(unittest.TestCase):
    def test_exact_existing_elf_executes_and_sealed_bytes_cannot_be_mutated(self):
        path = Path('/usr/bin/true').resolve()
        if not path.exists():
            self.skipTest('coreutils true unavailable')
        with driver.pinned_native(path, runtime.file_sha(path)) as (executable, descriptors):
            fd = descriptors[0]
            self.assertTrue(fcntl.fcntl(fd, driver.GET_SEALS) & 0x0008)
            with self.assertRaises(OSError):
                os.write(fd, b'corrupt')
            self.assertEqual(subprocess.run([executable], pass_fds=descriptors, check=False).returncode, 0)
        with self.assertRaisesRegex(ValueError, 'NATIVE_PIN'):
            with driver.pinned_native(path, 'f' * 64):
                self.fail('mismatched ELF must never execute')


if __name__ == '__main__':
    unittest.main()
