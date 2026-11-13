"""Real SQLite/process-loss controls. Receipt fixtures do not claim model execution."""
import copy
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import llm_inherited_operation as operation
import llm_inherited_runtime as inherited
import llm_runtime_pilot as runtime
import llm_frozen_evaluation as frozen


def private_json(path, value):
    path.write_bytes(runtime.canonical(value) + b'\n')
    path.chmod(0o600)


def reserve_worker(database, authority, payload, queue):
    journal = operation.Journal(database, authority)
    try:
        queue.put(journal.reserve(*payload))
    finally:
        journal.close()


class InheritedOperationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name); self.root.chmod(0o700)
        self.db = self.root / 'operations.sqlite'
        self.authority = operation.initialize(self.db)['authority_id']
        self.journal = operation.Journal(self.db, self.authority)
        self.intent = 'a' * 64
        self.parent = dict(schema=inherited.PARENT_SCHEMA, generation=3, operation_id='original',
                           directory=str(self.root / 'parent'), contract='b' * 64,
                           adapter='c' * 64, file_sha256='d' * 64)
        inputs = dict(schema='hepta-smollm-training-input-v1', scope='public-smoke-fixtures',
                      records=[dict(prompt='A controlled fixture, not a real model task', expected_output='yes')])
        private_json(self.root / 'input.json', inputs)
        pilot = runtime.experiment_plan({'controlled': 'not-model-material'})
        pilot['tasks'] = inherited.training_rows(inputs)
        self.plan = dict(schema=inherited.SCHEMA, phase='train', operation_id='training-task-4',
                         generation=4, parent=self.parent, runtime=pilot, inputs=inputs,
                         inputs_sha256=runtime.file_sha(self.root / 'input.json'),
                         source_pins=inherited.source_pins(), authority=inherited.NO_AUTHORITY.copy())
        freeze = dict(schema='hepta-smollm-frozen-evaluation-profile-v1',
                      operation_id=self.plan['operation_id'], parent=self.parent,
                      training_input_sha256=self.plan['inputs_sha256'], evaluation_input_sha256='f' * 64,
                      runtime=pilot, evaluation=dict(metric='greedy-exact-match-v1', min_correct_gain=1,
                          rows=1, participants=frozen.PARTICIPANTS.copy(),
                          rule='candidate-exceeds-retained-parent-and-every-control-v1'),
                      source_pins=frozen.sources(), authority=inherited.NO_AUTHORITY.copy())
        private_json(self.root / 'freeze.json', freeze)
        self.freeze = dict(raw_utf8=(self.root / 'freeze.json').read_text(),
                           sha256=runtime.file_sha(self.root / 'freeze.json'))
        self.args = SimpleNamespace(command='train', operation_id='training-task-4',
            materials=str(self.root / 'materials'), output=str(self.root / 'output'),
            input=str(self.root / 'input.json'), input_sha256=self.plan['inputs_sha256'],
            parent=str(self.root / 'parent.json'), parent_sha256='e' * 64,
            bootstrap=False, threads=4, steps=10, evaluation_freeze=str(self.root / 'freeze.json'),
            evaluation_profile_sha256=self.freeze['sha256'])
        self.request = operation.invocation(self.args)
        self.parent_check = patch.object(inherited.parent_material, 'verify_parent_bytes', return_value=None)
        self.parent_check.start()

    def tearDown(self):
        self.journal.close()
        self.parent_check.stop()
        self.temporary.cleanup()

    def reserve(self):
        return self.journal.reserve(self.args.operation_id, self.intent, self.request,
                                    self.plan, self.freeze)

    def outputs(self, *, success=True, reaped=True):
        directory = Path(self.args.output); directory.mkdir(mode=0o700)
        worker = directory / 'worker'; worker.mkdir(mode=0o700)
        private_json(directory / 'execution-plan.json', self.plan)
        supervisor = dict(outcome='success' if success else 'failed', exit_code=0 if success else 1,
                          stop_reason=None, waited_child_reaped=reaped,
                          owned_child_reap_resolved=reaped, waited_child_observation_error=None,
                          budget=self.plan['runtime']['training_budget'],
                          observed_wall_ns=100, child_cpu_ns=60, observer_cpu_ns=10,
                          waited_child_peak_rss_bytes=1024)
        private_json(directory / 'supervisor.json', supervisor)
        for name in ('artifact.safetensors', 'target-contract.json', 'wrapped-adapter.json'):
            path = worker / name; path.write_bytes(b'Controlled parser fixture; not model bytes.'); path.chmod(0o600)
        output_parent = dict(self.parent, generation=4, operation_id=self.args.operation_id,
                             directory=str(worker), file_sha256=runtime.file_sha(worker / 'artifact.safetensors'))
        private_json(worker / 'parent-material.json', output_parent)
        receipt = dict(schema=inherited.SCHEMA, operation_id=self.plan['operation_id'],
            phase='train', generation=4, parent=self.parent,
            input_sha256=self.plan['inputs_sha256'],
            plan_sha256=runtime.file_sha(directory / 'execution-plan.json'),
            source_pins=self.plan['source_pins'], outcome='success', authority=inherited.NO_AUTHORITY,
            actual_loaded_parent=self.parent['adapter'], artifact=self.parent['adapter'],
            contract=self.parent['contract'],
            parent_material_sha256=runtime.file_sha(worker / 'parent-material.json'))
        private_json(worker / 'actual-receipt.json', receipt)

    def query(self):
        return operation.query(self.journal, self.args.operation_id, self.intent)

    def test_real_journal_reopen_keeps_unknown_and_original_reservation(self):
        self.assertTrue(self.reserve())
        self.journal.close(); self.journal = operation.Journal(self.db, self.authority)
        result = self.query()
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertEqual(result['reservation'], 'RETAINED')
        self.assertFalse(result['dispatch_allowed'])
        self.assertFalse(self.reserve())

    def test_exact_once_entry_never_calls_executor_twice(self):
        def execute(*_):
            self.outputs()
        with patch.object(inherited, 'prepare_plan', return_value=self.plan) as prepare, \
             patch.object(inherited, 'execute_plan', side_effect=execute) as executor:
            first = operation.run_once(self.journal, self.intent, self.args)
            second = operation.run_once(self.journal, self.intent, self.args)
        self.assertEqual(first, second)
        self.assertEqual(first['status'], 'SUCCESS')
        self.assertEqual(prepare.call_count, 1)
        self.assertEqual(executor.call_count, 1)
        self.assertEqual(first['evaluation_profile_sha256'], self.freeze['sha256'])
        self.assertFalse(first['no_update_decided'])
        self.assertFalse(first['payment_authorized'])

    def test_original_intent_cannot_be_aliased_to_new_operation(self):
        self.reserve()
        with self.assertRaisesRegex(ValueError, 'IDENTITY_REUSE'):
            self.journal.lookup('replacement-operation', self.intent)
        with self.assertRaisesRegex(ValueError, 'IDENTITY_REUSE'):
            self.journal.lookup(self.args.operation_id, 'f' * 64)

    def test_changed_output_or_budget_does_not_restart_pending(self):
        self.reserve()
        for changes in ({'output': str(self.root / 'replacement')}, {'steps': 11},
                        {'evaluation_profile_sha256': '1' * 64}):
            args = copy.copy(self.args)
            for key, value in changes.items(): setattr(args, key, value)
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, 'REQUEST_CHANGED'), \
                 patch.object(inherited, 'execute_plan') as execute:
                operation.run_once(self.journal, self.intent, args)
            execute.assert_not_called()

    def test_output_directory_is_exclusive_across_operations(self):
        self.reserve()
        with self.assertRaisesRegex(ValueError, 'OUTPUT_REUSE'):
            self.journal.reserve('another-operation', 'f' * 64, self.request, self.plan, self.freeze)

    def test_lost_ack_readback_uses_original_files_without_redispatch(self):
        self.reserve(); self.outputs()
        self.journal.close(); self.journal = operation.Journal(self.db, self.authority)
        with patch.object(inherited, 'execute_plan') as execute:
            self.assertEqual(self.query()['status'], 'SUCCESS')
            self.assertEqual(self.query()['status'], 'SUCCESS')
        execute.assert_not_called()

    def test_terminal_file_changes_are_refused(self):
        self.reserve(); self.outputs(); self.query()
        path = Path(self.args.output) / 'worker/artifact.safetensors'
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'OUTPUT_ARTIFACT_CHANGED|TERMINAL_EVIDENCE_CHANGED'):
            self.query()

    def test_different_operation_parent_or_freeze_is_refused(self):
        self.reserve(); self.outputs()
        path = Path(self.args.output) / 'worker/actual-receipt.json'
        original = json.loads(path.read_text())
        for field, value in (('operation_id', 'other'), ('actual_loaded_parent', '2' * 64),
                             ('input_sha256', '3' * 64)):
            private_json(path, dict(original, **{field: value}))
            with self.subTest(field=field), self.assertRaises(ValueError): self.query()
        private_json(path, original)
        self.journal.db.execute('UPDATE operations SET freeze=?',
                               (json.dumps(dict(self.freeze, raw_utf8='{}')),))
        with self.assertRaisesRegex(ValueError, 'FROZEN_PROFILE_CHANGED'): self.query()

    def test_failed_execution_is_not_no_update_or_payment(self):
        self.reserve(); self.outputs(success=False)
        result = self.query()
        self.assertEqual(result['status'], 'FAILED')
        self.assertFalse(result['no_update_decided'])
        self.assertFalse(result['payment_authorized'])
        self.assertEqual(result['reservation'], 'RETAINED')

    def test_exit_without_original_owner_reap_remains_unknown(self):
        self.reserve(); self.outputs(reaped=False)
        self.assertEqual(self.query()['status'], 'UNKNOWN')

    def test_next_inference_binds_original_training_and_rejects_other_parent(self):
        self.reserve(); self.outputs(); self.query()
        args = copy.copy(self.args)
        args.command = 'infer'; args.operation_id = 'actual-next-operation'
        args.output = str(self.root / 'next-output')
        args.source_operation_id = self.args.operation_id
        args.source_intent_sha256 = self.intent
        inputs = dict(schema='hepta-smollm-inference-input-v1', request_id=args.operation_id,
                      prompt='Controlled next-input fixture')
        next_input = self.root / 'next-input.json'; private_json(next_input, inputs)
        args.input = str(next_input); args.input_sha256 = runtime.file_sha(next_input)
        plan = dict(self.plan, phase='infer', operation_id=args.operation_id, generation=3,
                    inputs=inputs, inputs_sha256=args.input_sha256)
        bad = copy.deepcopy(plan); bad['parent']['adapter'] = '9' * 64
        with patch.object(inherited, 'prepare_plan', return_value=bad), \
             patch.object(inherited, 'execute_plan') as execute, \
             self.assertRaisesRegex(ValueError, 'NEXT_TASK_MODEL_LINEAGE'):
            operation.run_once(self.journal, '1' * 64, args)
        execute.assert_not_called()
        self.assertIsNone(self.journal.lookup(args.operation_id, '1' * 64))

        def infer(frozen_plan, _materials, output):
            directory = Path(output); directory.mkdir(mode=0o700)
            worker = directory / 'worker'; worker.mkdir(mode=0o700)
            private_json(directory / 'execution-plan.json', frozen_plan)
            supervisor = json.loads((Path(self.args.output) / 'supervisor.json').read_text())
            supervisor['budget'] = plan['runtime']['inference_budget']
            private_json(directory / 'supervisor.json', supervisor)
            request = dict(contract=self.parent['contract'])
            request_id = runtime.contract_module().H('causal-decoder-request-v1', runtime.canonical(request)).hex()
            prediction = dict(task=runtime.identity(inputs), snapshot=plan['runtime']['snapshot'],
                numeric_dtype='float32', request=request, request_id=request_id,
                response=dict(contract=self.parent['contract'], request=request_id,
                    decoded_outputs=['fixture'], generated_token_ids=[[1] * 8]),
                role='installed-parent-input', artifact=self.parent['adapter'], actual_device='cpu',
                generated_tokens=8, output_sha256=hashlib.sha256(b'fixture').hexdigest())
            private_json(worker / 'prediction.json', prediction)
            receipt = dict(schema=inherited.SCHEMA, operation_id=args.operation_id, phase='infer',
                generation=3, parent=self.parent, input_sha256=args.input_sha256,
                plan_sha256=runtime.file_sha(directory / 'execution-plan.json'),
                source_pins=plan['source_pins'], outcome='success', authority=inherited.NO_AUTHORITY,
                actual_loaded_parent=self.parent['adapter'], artifact=self.parent['adapter'],
                forward_executed=True, prediction=prediction)
            private_json(worker / 'actual-receipt.json', receipt)

        with patch.object(inherited, 'prepare_plan', return_value=plan), \
             patch.object(inherited, 'execute_plan', side_effect=infer) as execute:
            result = operation.run_once(self.journal, '1' * 64, args)
            self.assertEqual(result['status'], 'SUCCESS')
            self.assertEqual(result, operation.run_once(self.journal, '1' * 64, args))
            self.assertEqual(execute.call_count, 1)

    def test_output_descriptor_types_and_contract_cannot_alias(self):
        self.reserve(); self.outputs()
        path = Path(self.args.output) / 'worker/parent-material.json'
        original = json.loads(path.read_text())
        for changes in ({'generation': True}, {'contract': 'f' * 64}, {'extra': False}):
            private_json(path, dict(original, **changes))
            # Even if a producer recomputes its parent hash, the original
            # descriptor schema and contract must still agree with this plan.
            receipt_path = Path(self.args.output) / 'worker/actual-receipt.json'
            receipt = json.loads(receipt_path.read_text())
            receipt['parent_material_sha256'] = runtime.file_sha(path)
            private_json(receipt_path, receipt)
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.query()

    def test_missing_supervisor_cannot_be_replaced_by_child_success(self):
        self.reserve(); self.outputs()
        (Path(self.args.output) / 'supervisor.json').unlink()
        self.assertEqual(self.query()['status'], 'UNKNOWN')

    def test_wrong_authority_and_symlink_journal_refused(self):
        with self.assertRaisesRegex(ValueError, 'AUTHORITY'):
            operation.Journal(self.db, 'f' * 64)
        alias = self.root / 'alias.sqlite'; alias.symlink_to(self.db)
        with self.assertRaisesRegex(ValueError, 'FILE_PATH'):
            operation.Journal(alias, self.authority)

    def test_freeze_mismatch_refuses_before_reservation_or_execution(self):
        self.args.evaluation_profile_sha256 = 'f' * 64
        with patch.object(inherited, 'execute_plan') as execute, \
             self.assertRaisesRegex(ValueError, 'FROZEN_PROFILE_IDENTITY'):
            operation.run_once(self.journal, self.intent, self.args)
        execute.assert_not_called()
        self.assertIsNone(self.journal.lookup(self.args.operation_id, self.intent))

    def test_actual_competing_processes_reserve_only_once(self):
        context = multiprocessing.get_context('spawn')
        queue = context.Queue()
        payload = (self.args.operation_id, self.intent, self.request, self.plan, self.freeze)
        children = [context.Process(target=reserve_worker,
                    args=(str(self.db), self.authority, payload, queue)) for _ in range(2)]
        for child in children: child.start()
        for child in children:
            child.join(10)
            self.assertEqual(child.exitcode, 0)
        self.assertEqual(sorted(queue.get(timeout=2) for _ in children), [False, True])
        queue.close()

    def test_actual_process_crash_after_commit_never_regrants_dispatch(self):
        payload = self.root / 'reservation.json'
        private_json(payload, [self.args.operation_id, self.intent, self.request, self.plan, self.freeze])
        source = ('import json,os,sys; import llm_inherited_operation as m; '
                  'j=m.Journal(sys.argv[1],sys.argv[2]); '
                  'j.reserve(*json.load(open(sys.argv[3]))); os._exit(37)')
        completed = subprocess.run([sys.executable, '-c', source, str(self.db), self.authority,
                                    str(payload)], cwd=Path(__file__).parent, timeout=10)
        self.assertEqual(completed.returncode, 37)
        self.assertFalse(self.reserve())
        self.assertEqual(self.query()['status'], 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()
