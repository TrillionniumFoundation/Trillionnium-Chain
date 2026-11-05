"""Synthetic byte/dispatch controls only; no pretrained-model execution proof."""
import ast
import copy
import hashlib
import inspect
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

import llm_inherited_runtime as inherited
import llm_initial_trainable_setup_v2 as setup
import llm_runtime_parent_step as step
import llm_runtime_parent_step_v2 as v2
import llm_runtime_pilot as runtime
import test_llm_runtime_parent_step as original_tests


class ParentStepV2Tests(unittest.TestCase):
    def setUp(self):
        # Original explicit fabricated backbone fixture; never runtime material.
        self.base = original_tests.ParentStepTests()
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.root, self.contract = self.base.root, self.base.contract
        f = self.base.fixture
        f.artifact_path.write_bytes(setup.canonical_zero_parent())
        self.original = step.parent.factor_bytes(f.artifact_path.read_bytes(), self.contract)
        raw, aid = runtime.contract_module().freeze_wrapped_adapter(
            setup._wrapped(self.contract, self.base.cid, self.original), self.contract, self.base.cid)
        f.adapter_path.write_bytes(raw)
        self.value = copy.deepcopy(self.base.value)
        self.value.update(schema=v2.SCHEMA, source=v2.sources(), parent=dict(contract=self.base.cid,
            adapter=aid, file_sha256=setup.PARENT_SHA256))
        self.origin = dict(schema=inherited.PARENT_SCHEMA, generation=1, operation_id='original-parent',
            directory=str(self.root), **self.value['parent'])
        self.origin_path = self.root / 'origin.json'
        runtime.save(self.origin_path, self.origin)
        self.value['initial_setup'] = dict(profile=v2.PROFILE, recipe=dict(setup.RECIPE),
            parent_material=dict(path=str(self.origin_path), sha256=runtime.file_sha(self.origin_path)))

    def arguments(self, value=None):
        value = value or self.value
        args = self.base.arguments(value)
        args.initial_setup_profile = v2.PROFILE
        args.parent_material = str(self.origin_path)
        args.parent_material_sha256 = value['initial_setup']['parent_material']['sha256']
        return args

    def material(self, directory, prefix, factors):
        raw, aid = runtime.contract_module().freeze_wrapped_adapter(
            setup._wrapped(self.contract, self.base.cid, factors), self.contract, self.base.cid)
        (directory / (prefix + 'wrapped-adapter.json')).write_bytes(raw)
        canonical = setup.canonical_zero_parent()
        length = int.from_bytes(canonical[:8], 'little')
        header = json.loads(canonical[8:8 + length]); header.pop('__metadata__')
        encoded = runtime.canonical(header)
        path = directory / (prefix + 'artifact.safetensors')
        path.write_bytes(len(encoded).to_bytes(8, 'little') + encoded + b''.join(factors[n] for n in sorted(factors)))
        return dict(adapter=aid, file_sha256=runtime.file_sha(path))

    def completed_fixture(self, changed=False):
        directory = Path(self.value['output']); directory.mkdir(parents=True)
        prepared = {n: struct.pack('<f', .25) * (len(b) // 4) if n.endswith('.A') else b
                    for n, b in self.original.items()}
        descriptor = self.material(directory, 'setup-', prepared)
        report = dict(schema=setup.SCHEMA, operation_id=self.value['attempt_id'],
            original_parent=dict(generation=1, **self.value['parent']),
            original_parent_readback=self.value['parent']['adapter'], setup_adapter=descriptor['adapter'],
            recipe=dict(setup.RECIPE), source_pins=setup._sources(),
            old_factor_sha256={n: hashlib.sha256(b).hexdigest() for n, b in self.original.items()},
            setup_factor_sha256={n: hashlib.sha256(b).hexdigest() for n, b in prepared.items()},
            B_positive_zero=True, function_equivalence='algebraic-B-zero-only',
            full_model_numeric_preservation='NOT_RUN', trainability='NOT_RUN',
            capture_cost=dict(wall_ns=1, cpu_ns=1), setup_cost=dict(wall_ns=1, cpu_ns=1),
            flags=dict.fromkeys(('trained', 'learned_change', 'gain', 'selected', 'installed', 'ordinary', 'reward'), False))
        runtime.save(directory / 'initial-setup-v2.json', report)
        descriptor['receipt_sha256'] = runtime.file_sha(directory / 'initial-setup-v2.json')
        final = dict(prepared)
        if changed: final[next(n for n in final if n.endswith('.B'))] = struct.pack('<f', .5) * 2304
        candidate = self.material(directory, '', final)
        (directory / 'target-contract.json').write_bytes(self.base.fixture.contract_path.read_bytes())
        actual = dict(schema=v2.ACTUAL, scope=step.SCOPE, operation='train', attempt_id=self.value['attempt_id'],
            attempt_binding=v2.binding(self.value), input=runtime.identity(self.value), source=v2.sources(),
            experiment=self.value['experiment'], parent=self.value['parent'], parent_preflight=v2.preflight(self.value)[6],
            parent_readback=self.value['parent']['adapter'], actual_backend='cpu', actual_device='cpu',
            actual_threads=self.base.plan['threads'], torch_cuda=None,
            environment=dict.fromkeys(('torch', 'transformers', 'peft', 'safetensors', 'tokenizers', 'numpy', 'accelerate'), 'fixture'),
            outcome='success', observed_wall_ns=1, setup=descriptor, candidate=candidate,
            setup_changed_from_parent=True, training_changed_from_setup=changed,
            training=dict(steps=10, loss=['1'] * 10, tokens=40, supervised_tokens=30, supported_profile_flops=0,
                          flop_scope='profiler-supported-operators-only-not-total-work'), **step.FALSES)
        runtime.save(directory / 'parent-candidate-v2.json', v2.candidate_record(self.value, descriptor, candidate, changed))
        runtime.save(directory / 'actual-receipt.json', actual)
        return directory, actual

    def test_explicit_v2_preflight_uses_original_canonical_parent_and_closed_fields(self):
        self.assertEqual(step.preflight(self.value)[4], self.original)
        for mutate in [lambda v: v.update(extra=1), lambda v: v.update(schema='unknown-v3'),
                lambda v: v['source'].update(initial_setup='f' * 64),
                lambda v: v['initial_setup']['recipe'].update(initialization_seed=7.0),
                lambda v: v['initial_setup'].update(extra=1)]:
            changed = copy.deepcopy(self.value); mutate(changed)
            with self.assertRaises(ValueError): step.preflight(changed)
        self.assertFalse(Path(self.value['output']).parent.exists())

    def test_original_v1_rejects_new_fields_and_arguments_without_opt_in(self):
        with self.assertRaises(ValueError): step.preflight(dict(self.base.value, initial_setup=self.value['initial_setup']))
        args = self.arguments(); args.initial_setup_profile = None
        with self.assertRaisesRegex(ValueError, 'PARENT_V2_ARGUMENTS'): step.run(args)
        self.assertFalse(Path(args.output).exists())

    def test_unimplemented_evaluate_and_readback_refuse_before_any_effect(self):
        with patch.object(runtime, 'supervise') as supervisor, patch.object(runtime, 'runtime_import') as imports:
            for operation in ('evaluate', 'readback'):
                changed = dict(self.value, operation=operation)
                with self.assertRaisesRegex(ValueError, 'OPERATION_UNIMPLEMENTED'): step.preflight(changed)
                with self.assertRaisesRegex(ValueError, 'OPERATION_UNIMPLEMENTED'): step.run(self.arguments(changed))
            supervisor.assert_not_called(); imports.assert_not_called()
        self.assertFalse(Path(self.value['output']).parent.exists())

    def test_other_origin_generation_and_parent_role_refuse(self):
        for generation in (True, 0, 2):
            runtime.save(self.origin_path, dict(self.origin, generation=generation))
            self.value['initial_setup']['parent_material']['sha256'] = runtime.file_sha(self.origin_path)
            with self.assertRaises(ValueError): step.preflight(self.value)
        runtime.save(self.origin_path, self.origin)
        self.value['initial_setup']['parent_material']['sha256'] = runtime.file_sha(self.origin_path)
        self.value['files']['parent_artifact'] += '-wrong'
        with self.assertRaisesRegex(ValueError, 'ORIGIN_ROLES'): step.preflight(self.value)

    def test_setup_hash_change_alone_is_not_training_change(self):
        directory, report = self.completed_fixture()
        self.assertEqual(step.verify_completion(self.value), runtime.file_sha(directory / 'actual-receipt.json'))
        self.assertFalse(report['training_changed_from_setup'])
        self.assertTrue(all(report[n] is False for n in step.FALSES))
        report['training_changed_from_setup'] = True
        runtime.save(directory / 'actual-receipt.json', report)
        with self.assertRaisesRegex(ValueError, 'LINEAGE'): step.verify_completion(self.value)

    def test_reported_training_delta_is_checked_against_actual_factor_bytes(self):
        directory, _ = self.completed_fixture(changed=True)
        self.assertEqual(step.verify_completion(self.value), runtime.file_sha(directory / 'actual-receipt.json'))

    def test_setup_corruption_and_missing_training_record_refuse(self):
        directory, report = self.completed_fixture()
        path = directory / 'setup-artifact.safetensors'; raw = path.read_bytes(); path.write_bytes(raw[:-1] + b'\1')
        with self.assertRaises(ValueError): step.verify_completion(self.value)
        path.write_bytes(raw)
        (directory / 'parent-candidate-v2.json').unlink()
        with self.assertRaises(OSError): step.verify_completion(self.value)
        self.assertEqual(report['parent_readback'], self.value['parent']['adapter'])

    def test_candidate_v1_relabelling_false_flags_and_generation_bool_refuse(self):
        directory, _ = self.completed_fixture()
        path = directory / 'parent-candidate-v2.json'
        original = runtime.read_json(path)
        for change in [dict(schema='llm-runtime-parent-candidate-v1'), dict(parent_generation=True),
                dict(training_changed_from_setup=0), dict(flags=dict.fromkeys(step.FALSES, 0)),
                dict(source=dict(v2.sources(), initial_setup='f' * 64))]:
            runtime.save(path, dict(original, **change))
            with self.assertRaises(ValueError): step.verify_completion(self.value)
        runtime.save(path, original)
        self.assertEqual(step.verify_completion(self.value), runtime.file_sha(directory / 'actual-receipt.json'))

    def test_no_completion_before_original_exact_terminal_result(self):
        args = self.arguments()
        result = dict(outcome='success', exit_code=0, stop_reason=None, budget=self.base.plan['training_budget'],
            waited_child_reaped=False, owned_child_reap_resolved=False, owned_child_echild_observed=False,
            waited_child_observation_error=None)
        with patch.object(runtime, 'supervise', return_value=result) as supervisor, \
                patch.object(v2, 'verify_completion') as verify, self.assertRaisesRegex(ValueError, 'CHILD_FAILED'):
            step.run(args)
        verify.assert_not_called()
        command, _, budget = supervisor.call_args.args
        self.assertEqual(command[1], str(Path(runtime.__file__).resolve()))
        self.assertIn('parent-step', command)
        self.assertEqual(budget, self.base.plan['training_budget'])
        self.assertFalse(runtime.read_json(Path(args.output) / 'parent-step-result-v2.json')['completion_verified'])

    def test_single_original_backend_and_capture_copy_train_order(self):
        source = inspect.getsource(v2.child)
        self.assertLess(source.index('preflight(value)'), source.index('runtime.runtime_import'))
        self.assertLess(source.index('capture_seeded_a'), source.index('prepare_working_copy'))
        self.assertLess(source.index('verify_setup('), source.index('runtime.train'))
        calls = [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
        self.assertEqual(sum(n.func.attr == 'insert_lora' for n in calls), 1)
        self.assertNotIn('supervise(', source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
