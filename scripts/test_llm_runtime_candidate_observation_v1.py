"""Synthetic lineage and real tiny-tensor decode controls, never135M proof."""
from contextlib import ExitStack
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import llm_runtime_candidate_observation_v1 as observation
import llm_runtime_parent_step as step
import llm_runtime_parent_step_v2 as producer
import llm_runtime_pilot as runtime
import test_llm_runtime_parent_step_task_v2 as prior


class CandidateObservationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = prior.NewTaskProfileTests(); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.training = self.fixture.value
        execution, actual = self.fixture.base.completed_fixture(changed=True)
        actual.update(source=self.training['source'], task_link=self.fixture.verify())
        runtime.save(execution / 'actual-receipt.json', actual)
        self.directory = execution.parent
        runtime.save(self.directory / 'parent-step-input-v2.json', self.training)
        self.plan = self.fixture.plan
        self.terminal = dict(outcome='success', exit_code=0, stop_reason=None,
            budget=self.plan['training_budget'], waited_child_reaped=True, owned_child_reap_resolved=True,
            owned_child_echild_observed=False, waited_child_observation_error=None, observed_wall_ns=13)
        runtime.save(execution / 'supervisor.json', self.terminal)
        self.result = dict(schema=producer.RESULT, scope=step.SCOPE, input=runtime.identity(self.training),
            attempt_binding=producer.binding(self.training), supervisor=self.terminal, outcome='success',
            completion_verified=True, actual_receipt_sha256=runtime.file_sha(execution / 'actual-receipt.json'),
            flags=step.FALSES)
        runtime.save(self.directory / 'parent-step-result-v2.json', self.result)
        self.value = dict(schema=observation.INPUT, scope=observation.SCOPE, operation='evaluate',
            attempt_id=hashlib.sha256(b'observation-attempt').hexdigest(),
            source=observation._sources(producer.NEW_TASK_PROFILE), training_directory=str(self.directory),
            training_input_digest=runtime.identity(self.training),
            training_result_sha256=runtime.file_sha(self.directory / 'parent-step-result-v2.json'),
            candidate_record_sha256=runtime.file_sha(execution / 'parent-candidate-v2.json'),
            actual_training_receipt_sha256=self.result['actual_receipt_sha256'], parent=self.training['parent'],
            candidate=actual['candidate'], plan_digest=self.training['experiment'],
            output=str(self.directory.parent / 'observation/execution'), flags=step.FALSES)

    def args(self):
        return SimpleNamespace(training_directory=str(self.directory),
            expected_training_result_sha256=self.value['training_result_sha256'],
            expected_candidate_record_sha256=self.value['candidate_record_sha256'],
            expected_contract=self.value['parent']['contract'], expected_parent_adapter=self.value['parent']['adapter'],
            expected_parent_file_sha256=self.value['parent']['file_sha256'],
            expected_candidate_adapter=self.value['candidate']['adapter'],
            expected_candidate_file_sha256=self.value['candidate']['file_sha256'],
            output=str(Path(self.value['output']).parent), attempt_id=self.value['attempt_id'])

    def test_exact_completed_producer_and_every_evidence_pin_before_effects(self):
        self.assertEqual(observation._preflight(self.value)[0], self.training)
        changes = [lambda v: v.update(schema='unknown'), lambda v: v.update(operation='readback'),
            lambda v: v.update(extra=1), lambda v: v.update(attempt_id=self.training['attempt_id']),
            lambda v: v['source'].update(observer='f' * 64),
            lambda v: v['source']['producer'].update(parent_step_v2='f' * 64),
            lambda v: v['candidate'].update(adapter='f' * 64), lambda v: v['parent'].update(contract='f' * 64),
            lambda v: v.update(flags=dict.fromkeys(step.FALSES, 0))]
        changes += [lambda v, n=n: v.update({n: 'f' * 64}) for n in
            ('training_input_digest', 'training_result_sha256', 'candidate_record_sha256',
             'actual_training_receipt_sha256', 'plan_digest')]
        with patch.object(runtime, 'supervise') as supervise, patch.object(runtime, 'runtime_import') as imports:
            for change in changes:
                value = copy.deepcopy(self.value); change(value)
                with self.subTest(change=change), self.assertRaises(ValueError): observation._preflight(value)
            supervise.assert_not_called(); imports.assert_not_called()
        self.assertFalse(Path(self.value['output']).parent.exists())

    def test_rehashed_outer_terminal_and_result_lies_still_refuse(self):
        path = self.directory / 'parent-step-result-v2.json'
        bad = [dict(exit_code=0.0), dict(exit_code=False), dict(stop_reason='unknown'),
            dict(waited_child_reaped=False), dict(owned_child_reap_resolved=False),
            dict(owned_child_echild_observed=True), dict(waited_child_observation_error='lost'),
            dict(budget=dict(wall_seconds=1801, rss_bytes=16 * 1024**3))]
        for changes in bad:
            result = dict(self.result, supervisor=dict(self.terminal, **changes))
            runtime.save(path, result); value = dict(self.value, training_result_sha256=runtime.file_sha(path))
            with self.subTest(changes=changes), self.assertRaises(ValueError): observation._preflight(value)
        for changes in [dict(completion_verified=1), dict(input='f' * 64),
                        dict(actual_receipt_sha256='f' * 64), dict(flags=dict.fromkeys(step.FALSES, 0))]:
            runtime.save(path, dict(self.result, **changes))
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                observation._preflight(dict(self.value, training_result_sha256=runtime.file_sha(path)))

    def test_rehashed_outer_supervisor_must_match_actual_saved_document_before_effects(self):
        result_path = self.directory / 'parent-step-result-v2.json'
        runtime.save(result_path, dict(self.result, supervisor=dict(self.terminal, observed_wall_ns=17)))
        value = dict(self.value, training_result_sha256=runtime.file_sha(result_path))
        with patch.object(runtime, 'supervise') as supervise, patch.object(runtime, 'runtime_import') as imports:
            with self.assertRaises(ValueError): observation._preflight(value)
            supervise.assert_not_called(); imports.assert_not_called()
        self.assertFalse(Path(self.value['output']).parent.exists())

    def test_strict_profile_import_does_not_load_unpinned_task_module(self):
        code = ('import sys; import llm_runtime_candidate_observation_v1 as o; '
                'o._sources(o.producer.PROFILE); '
                'assert "llm_runtime_parent_step_task_v2" not in sys.modules')
        result = subprocess.run([sys.executable, '-B', '-c', code], cwd=Path(observation.__file__).parent,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_result_duplicate_json_symlink_and_training_output_alias_refuse(self):
        path = self.directory / 'parent-step-result-v2.json'; original = path.read_bytes()
        path.write_bytes(original[:-2] + b',"schema":"duplicate"}\n')
        with self.assertRaises(ValueError):
            observation._preflight(dict(self.value, training_result_sha256=runtime.file_sha(path)))
        path.unlink(); other = self.directory / 'result-copy.json'; other.write_bytes(original); path.symlink_to(other)
        with self.assertRaises(ValueError): observation._preflight(self.value)
        path.unlink(); path.write_bytes(original)
        alias = self.directory.parent / 'training-alias'; alias.symlink_to(self.directory, target_is_directory=True)
        for output in [str(self.directory / 'nested/execution'), str(alias / 'nested/execution')]:
            with self.assertRaises(ValueError): observation._preflight(dict(self.value, output=output))

    def test_zero_exit_without_reap_cannot_verify_or_claim_completion(self):
        terminal = dict(self.terminal, budget=self.plan['inference_budget'], waited_child_reaped=False)
        with patch.object(runtime, 'supervise', return_value=terminal) as supervise, \
                patch.object(observation, '_verify_observation') as verify, self.assertRaises(ValueError):
            observation._run(self.args())
        verify.assert_not_called()
        command, _, budget = supervise.call_args.args
        self.assertEqual(command[1], str(Path(observation.__file__).resolve()))
        self.assertEqual(budget, self.plan['inference_budget'])
        self.assertEqual(supervise.call_args.kwargs, dict(exit_observation=self.plan.get('exit_observation')))
        result = runtime.read_json(Path(self.value['output']).parent / 'candidate-observation-result.json')
        self.assertFalse(result['completion_verified']); self.assertEqual(result['outcome'], 'failed')

    def toy(self):
        import torch
        contract = self.fixture.parent
        class Toy(torch.nn.Module):
            def __init__(self):
                super().__init__(); self.layers = torch.nn.ModuleList(); self.lookup = {}; self.calls = 0
                for target in contract['targets']:
                    layer = torch.nn.Module()
                    layer.lora_A = torch.nn.ModuleDict({'default': torch.nn.Linear(576, 4, bias=False)})
                    layer.lora_B = torch.nn.ModuleDict({'default': torch.nn.Linear(4, target['out_features'], bias=False)})
                    self.layers.append(layer); self.lookup[target['module']] = layer
            def get_base_model(self): return self
            def get_submodule(self, name): return self.lookup[name]
            def forward(self, input_ids, **kwargs):
                self.calls += 1
                value = self.layers[0].lora_B['default'].weight[0, 0].item()
                if value != .5: raise ValueError('TOY_CANDIDATE_NOT_LOADED')
                logits = torch.zeros((1, input_ids.shape[1], 49152), dtype=torch.float32)
                logits[:, :, 7] = value
                return SimpleNamespace(logits=logits)
        class Tokenizer:
            def apply_chat_template(self, messages, **kwargs): return messages[0]['content']
            def encode(self, text, **kwargs): return [3, 4]
            def decode(self, tokens, **kwargs): return ','.join(map(str, tokens))
        model = Toy(); stack = ExitStack(); old_threads = torch.get_num_threads(); torch.set_num_threads(self.plan['threads'])
        stack.callback(torch.set_num_threads, old_threads)
        # Toy boundary: loader, backbone measurement and PEFT insertion are
        # synthetic. Factor copying/wrapping and all64 Torch decoder calls are real.
        sentinels = {name: object() for name in contract['backbone']['index']}
        descriptors = {id(sentinels[name]): value for name, value in contract['backbone']['index'].items()}
        descriptor = runtime.tensor_descriptor
        stack.enter_context(patch.object(runtime, 'runtime_import', return_value=(torch, torch.device('cpu'))))
        stack.enter_context(patch.object(runtime, 'load_model', return_value=(model, Tokenizer(), {}, {})))
        stack.enter_context(patch.object(runtime, 'make_contract', return_value=(
            self.fixture.current, self.fixture.current_raw, self.fixture.current_id)))
        stack.enter_context(patch.object(runtime, 'insert_lora', return_value=model))
        stack.enter_context(patch.object(runtime, 'backbone_tensors', return_value=sentinels))
        stack.enter_context(patch.object(runtime, 'tensor_descriptor', side_effect=lambda t:
            descriptors[id(t)] if id(t) in descriptors else descriptor(t)))
        return stack, model

    def test_real_toy_candidate_copy_64_decodes_and_closed_observation_readback(self):
        output = Path(self.value['output']); output.mkdir(parents=True)
        frozen = output.parent / 'input.json'; runtime.save(frozen, self.value)
        stack, model = self.toy()
        with stack: observation._child(SimpleNamespace(input=str(frozen), expected_input=runtime.identity(self.value)))
        self.assertEqual(model.calls, 64)
        self.assertEqual(observation._verify_observation(self.value), runtime.file_sha(output / 'actual-observation.json'))
        path = output / 'actual-observation.json'; original = runtime.read_json(path)
        self.assertEqual((original['requests'], original['completed_decode_steps']), (8, 64))
        self.assertNotEqual(original['actual_loaded_contract'], self.value['parent']['contract'])
        for changes in [dict(actual_loaded_contract=self.value['parent']['contract']), dict(requests=True),
                        dict(completed_decode_steps=63), dict(extra=1), dict(installation_accepted=True)]:
            runtime.save(path, dict(original, **changes))
            with self.subTest(changes=changes), self.assertRaises(ValueError): observation._verify_observation(self.value)
        runtime.save(path, original)
        predictions = output / 'predictions.json'; raw = predictions.read_bytes(); rows = json.loads(raw)
        for mutate in [lambda r: r[0].update(artifact='f' * 64), lambda r: r[0].update(actual_device='cuda'),
                       lambda r: r[0].update(request_id='f' * 64), lambda r: r.pop()]:
            changed = copy.deepcopy(rows); mutate(changed); runtime.save(predictions, changed)
            runtime.save(path, dict(original, predictions_sha256=runtime.file_sha(predictions)))
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): observation._verify_observation(self.value)
        predictions.write_bytes(raw); runtime.save(path, original); predictions.write_bytes(raw + b' ')
        with self.assertRaisesRegex(ValueError, 'PREDICTIONS_PIN'): observation._verify_observation(self.value)
        with patch.object(runtime, 'runtime_import') as imports, self.assertRaises(ValueError):
            observation._child(SimpleNamespace(input=str(frozen), expected_input=runtime.identity(self.value)))
        imports.assert_not_called()

    def test_wrong_actual_loaded_raw_refuses_before_adapter_or_forward(self):
        output = Path(self.value['output']); output.mkdir(parents=True)
        frozen = output.parent / 'input.json'; runtime.save(frozen, self.value)
        stack, model = self.toy()
        with stack, patch.object(runtime, 'make_contract', return_value=(self.fixture.current,
                self.fixture.current_raw + b' ', self.fixture.current_id)), \
                patch.object(runtime, 'insert_lora') as insert, self.assertRaisesRegex(ValueError, 'CONTRACT_DIFFERENCE'):
            observation._child(SimpleNamespace(input=str(frozen), expected_input=runtime.identity(self.value)))
        insert.assert_not_called(); self.assertEqual(model.calls, 0)
        self.assertEqual(runtime.read_json(output / 'actual-observation.json')['outcome'], 'failed')

    def test_semantically_rehashed_decoder_schema_and_fields_refuse(self):
        output = Path(self.value['output']); output.mkdir(parents=True)
        frozen = output.parent / 'input.json'; runtime.save(frozen, self.value)
        stack, _ = self.toy()
        with stack: observation._child(SimpleNamespace(input=str(frozen), expected_input=runtime.identity(self.value)))
        predictions, actual = output / 'predictions.json', output / 'actual-observation.json'
        rows, report = runtime.read_json(predictions), runtime.read_json(actual)
        for mutate in [lambda r: r['request'].update(schema='future-v999'),
                lambda r: r['request'].update(extra=1),
                lambda r: r['request']['input_ids'][0].__setitem__(0, 49152),
                lambda r: r['response'].update(schema='future-v999'),
                lambda r: r.update(input_tokens=-1), lambda r: r.update(extra=1)]:
            changed = copy.deepcopy(rows); mutate(changed[0]); row = changed[0]
            c = runtime.contract_module()
            row['request_id'] = c.H('causal-decoder-request-v1', c.canonical(row['request'])).hex()
            row['response']['request'] = row['request_id']
            runtime.save(predictions, changed)
            runtime.save(actual, dict(report, predictions_sha256=runtime.file_sha(predictions)))
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): observation._verify_observation(self.value)


if __name__ == '__main__':
    unittest.main(verbosity=2)
