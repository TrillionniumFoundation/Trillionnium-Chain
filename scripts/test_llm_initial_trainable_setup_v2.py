"""Real small CPU Torch/PEFT controls, never a pretrained-model qualification."""
import copy
from dataclasses import FrozenInstanceError
import hashlib
import math
import unittest
from unittest.mock import patch

import llm_initial_trainable_setup_v2 as setup
import llm_runtime_parent_step as step
import llm_runtime_pilot as runtime
c = runtime.contract_module()
from test_llm_adapter_contract import fixture_contract


class ActualInitialSetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import torch
        cls.torch = torch
        torch.set_num_threads(1)
        torch.set_num_interop_threads(1)

    def setUp(self):
        t = self.torch
        self.contract = fixture_contract()
        self.contract['architecture'] = runtime.read_json(runtime.FAMILY_PATH)['architecture']
        self.contract['tokenizer']['vocabulary'] = self.contract['architecture']['vocabulary']
        self.contract['ports']['tied_lm_head'] = self.contract['architecture']['tied_embeddings']
        index = {name: dict(dtype='float32', shape=shape, byte_length=4 * math.prod(shape),
                 sha256=hashlib.sha256(name.encode()).hexdigest()) for name, shape in
                 runtime.contract_module().architecture_shapes(self.contract['architecture']).items()}
        self.contract['backbone']['index'] = index
        self.contract['backbone']['index_root'] = runtime.contract_module().H(
            'llm-tensor-index-v1', runtime.canonical(index)).hex()
        self.contract['numeric']['storage_dtype'] = 'float32'
        self.contract['targets'] = setup._targets()
        self.cid = runtime.contract_module().freeze_target_contract(self.contract)[1]
        model = t.nn.Module()
        model.config = {'model_type': 'custom'}
        model.model = t.nn.Module()
        model.model.layers = t.nn.ModuleList([t.nn.Module() for _ in range(30)])
        for layer in model.model.layers:
            layer.self_attn = t.nn.Module()
            layer.self_attn.q_proj = t.nn.Linear(576, 576, bias=False)
            layer.self_attn.v_proj = t.nn.Linear(576, 192, bias=False)
        # Actual original PEFT insertion/seeding; no tensor/module/provider stub.
        self.model = runtime.insert_lora(model, {'recipes': {'candidate': {
            'initialization_seed': 7, 'kind': 'lora'}}}, 'candidate', t)
        self.raw = setup.canonical_zero_parent()
        self.factors = step.parent.factor_bytes(self.raw, self.contract)
        self.adapter = runtime.contract_module().freeze_wrapped_adapter(
            setup._wrapped(self.contract, self.cid, self.factors), self.contract, self.cid)[1]
        self.parent = dict(generation=1, contract=self.cid, adapter=self.adapter,
                           file_sha256=setup.PARENT_SHA256)
        self.parameters = runtime.adapter_tensors(self.model, self.contract['targets'])
        self.capture = setup.capture_seeded_a(self.model, self.contract, t, setup.RECIPE)
        self.layer = self.model.get_base_model().get_submodule(self.contract['targets'][0]['module'])
        self.x = t.linspace(-1, 1, 1152).reshape(2, 576)

    def prepare(self, **kwargs):
        values = dict(model=self.model, contract=self.contract, contract_digest=self.cid,
                      parent=self.parent, parent_bytes=self.raw, captured=self.capture,
                      torch=self.torch, operation_id='explicit-setup-only')
        values.update(kwargs)
        return setup.prepare_working_copy(**values)

    def test_canonical_original_full_sha_and_factor_wire_are_unchanged(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), setup.PARENT_SHA256)
        self.assertEqual(len(self.factors), 120)
        self.assertEqual(sum(map(len, self.factors.values())), 921600)
        self.assertTrue(all(not any(b) for b in self.factors.values()))

    def test_original_double_zero_has_zero_gradients_and_no_optimizer_update(self):
        step.copy_factors(self.model, self.contract, self.factors, self.adapter, self.torch)
        optimizer = self.torch.optim.AdamW(self.parameters.values(), lr=.01, weight_decay=0)
        for _ in range(2):
            optimizer.zero_grad(set_to_none=True)
            self.layer(self.x).square().sum().backward()
            self.assertTrue(all(p.grad is None or not p.grad.count_nonzero().item()
                                for p in self.parameters.values()))
            optimizer.step()
            self.assertEqual(dict(setup._snapshot(self.parameters)), self.factors)

    def test_explicit_setup_keeps_tested_function_then_real_gradient_update_starts(self):
        actual_copy = step.copy_factors
        observed = []
        def observe_original(*args):
            result = actual_copy(*args)
            self.assertEqual(dict(setup._snapshot(self.parameters)), self.factors)
            observed.append(self.layer(self.x).detach().clone())
            return result
        with patch.object(step, 'copy_factors', side_effect=observe_original):
            factors, _, report = self.prepare()
        self.assertEqual(len(observed), 1)
        self.assertTrue(self.torch.equal(observed[0], self.layer(self.x)))
        self.assertTrue(all(not any(v) for n, v in factors.items() if n.endswith('.B')))
        self.assertTrue(all(not v for v in report['flags'].values()))
        self.assertEqual(report['trainability'], 'NOT_RUN')
        optimizer = self.torch.optim.AdamW(self.parameters.values(), lr=.01, weight_decay=0)
        optimizer.zero_grad(set_to_none=True)
        self.layer(self.x).square().sum().backward()
        a, b = self.layer.lora_A['default'].weight, self.layer.lora_B['default'].weight
        self.assertEqual(a.grad.count_nonzero().item(), 0)
        self.assertGreater(b.grad.count_nonzero().item(), 0)
        frozen = self.layer.base_layer.weight.detach().clone()
        optimizer.step()
        self.assertGreater((b @ a).count_nonzero().item(), 0)
        self.assertFalse(self.torch.equal(observed[0], self.layer(self.x)))
        self.assertTrue(self.torch.equal(frozen, self.layer.base_layer.weight))

    def test_immutable_capture_and_returned_bytes_do_not_alias_tensors(self):
        with self.assertRaises(FrozenInstanceError):
            self.capture.snapshot = ()
        self.assertTrue(all(type(v) is bytes for _, v in self.capture.snapshot))
        values, _, _ = self.prepare()
        before = dict(setup._snapshot(self.parameters))
        values.clear()
        self.assertEqual(dict(setup._snapshot(self.parameters)), before)
        with self.assertRaisesRegex(ValueError, 'CAPTURE_OWNER_OR_REUSE'):
            self.prepare()

    def test_other_parent_generation_bytes_and_extra_fields_refuse_without_mutation(self):
        before = setup._snapshot(self.parameters)
        for change in [dict(generation=2), dict(generation=True), dict(extra=1),
                       dict(file_sha256='f' * 64), dict(adapter='f' * 64)]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.prepare(parent=dict(self.parent, **change))
            self.assertEqual(setup._snapshot(self.parameters), before)
        with self.assertRaisesRegex(ValueError, 'PARENT_BYTES'):
            self.prepare(parent_bytes=self.raw[:-1] + b'\1')
        self.assertEqual(setup._snapshot(self.parameters), before)

    def test_mutated_or_foreign_capture_and_source_drift_refuse(self):
        with self.assertRaisesRegex(ValueError, 'CAPTURE_OWNER_OR_REUSE'):
            self.prepare(captured=object())
        with self.assertRaisesRegex(ValueError, 'CAPTURE_OWNER_OR_REUSE'):
            self.prepare(model=copy.deepcopy(self.model))
        with patch.object(setup, '_sources', return_value={'wrong': 'f' * 64}):
            with self.assertRaisesRegex(ValueError, 'CAPTURE_SOURCE'):
                self.prepare()
        with self.torch.no_grad():
            next(iter(self.parameters.values())).add_(.01)
        with self.assertRaisesRegex(ValueError, 'CAPTURE_DRIFT'):
            self.prepare()

    def test_nonfinite_nonzero_B_and_alias_capture_refuse(self):
        a, b = self.layer.lora_A['default'].weight, self.layer.lora_B['default'].weight
        original = a.detach().clone()
        for value in [float('nan'), float('inf')]:
            with self.torch.no_grad():
                a.fill_(value)
            with self.assertRaisesRegex(ValueError, 'FACTOR_PROFILE'):
                setup.capture_seeded_a(self.model, self.contract, self.torch, setup.RECIPE)
        with self.torch.no_grad():
            a.copy_(original)
        for value in [-0.0, 1.0]:
            with self.torch.no_grad():
                b.fill_(value)
            with self.assertRaisesRegex(ValueError, 'B_NOT_POSITIVE_ZERO'):
                setup.capture_seeded_a(self.model, self.contract, self.torch, setup.RECIPE)
        with self.torch.no_grad():
            b.zero_()
        second = self.model.get_base_model().get_submodule(self.contract['targets'][1]['module'])
        second.lora_A['default'].weight = a
        with self.assertRaisesRegex(ValueError, 'ALIASED_PARAMETERS'):
            setup.capture_seeded_a(self.model, self.contract, self.torch, setup.RECIPE)

    def test_missing_extra_and_wrong_dtype_parameters_refuse(self):
        bad = copy.deepcopy(self.contract)
        bad['targets'].pop()
        with self.assertRaisesRegex(ValueError, 'TARGETS'):
            self.prepare(contract=bad)
        self.model.extra = self.torch.nn.Parameter(self.torch.ones(1))
        with self.assertRaisesRegex(ValueError, 'TRAINABLE_SET'):
            self.prepare()
        del self.model.extra
        self.layer.lora_A['default'].to(dtype=self.torch.float64)
        with self.assertRaisesRegex(ValueError, 'FACTOR_PROFILE'):
            self.prepare()
        del self.layer.lora_A['default']
        with self.assertRaisesRegex(ValueError, 'FACTOR_SET'):
            self.prepare()

    def test_post_copy_failure_is_explicit_and_capture_cannot_retry(self):
        original = step.copy_factors
        def failed_copy(*args):
            original(*args)
            raise ValueError('actual-copy-then-failure')
        with patch.object(step, 'copy_factors', side_effect=failed_copy):
            with self.assertRaisesRegex(ValueError, 'actual-copy-then-failure'):
                self.prepare()
        self.assertEqual(self.capture.state, 'failed-working-copy-may-be-mutated')
        self.assertEqual(dict(setup._snapshot(self.parameters)), self.factors)
        with self.assertRaisesRegex(ValueError, 'CAPTURE_OWNER_OR_REUSE'):
            self.prepare()

    def test_numeric_positive_and_negative_zero_A_are_both_refused(self):
        for value in [0.0, -0.0]:
            with self.subTest(value=math.copysign(1, value)), self.torch.no_grad():
                self.layer.lora_A['default'].weight.fill_(value)
                before = setup._snapshot(self.parameters)
                with self.assertRaisesRegex(ValueError, 'A_INITIALIZER'):
                    setup.capture_seeded_a(self.model, self.contract, self.torch, setup.RECIPE)
                self.assertEqual(setup._snapshot(self.parameters), before)

    def test_overlapping_wrappers_frozen_backbone_and_buffer_refuse_before_copy(self):
        t = self.torch
        for kind in ['parameter', 'buffer', 'buffer_same_object', 'factor']:
            with self.subTest(kind=kind):
                self.setUp()
                raw = bytearray(576 * 576 * 4 + 4)
                a = t.nn.Parameter(t.frombuffer(raw, dtype=t.float32, count=2304).reshape(4, 576))
                with t.no_grad(): a.fill_(.25)
                self.layer.lora_A['default'].weight = a
                overlap = t.frombuffer(memoryview(raw)[4:], dtype=t.float32)
                if kind == 'parameter':
                    self.layer.base_layer.weight = t.nn.Parameter(overlap.reshape(576, 576), requires_grad=False)
                elif kind == 'buffer': self.model.register_buffer('overlap', overlap)
                elif kind == 'buffer_same_object': self.model.register_buffer('overlap', a)
                else:
                    other = self.model.get_base_model().get_submodule(self.contract['targets'][1]['module'])
                    other.lora_A['default'].weight = t.nn.Parameter(overlap[:2304].reshape(4, 576))
                self.assertNotEqual(a.untyped_storage().data_ptr(), overlap.untyped_storage().data_ptr())
                before = [(p, p.detach().clone()) for p in list(self.model.parameters()) + list(self.model.buffers())]
                with patch.object(step, 'copy_factors', wraps=step.copy_factors) as copier:
                    with self.assertRaisesRegex(ValueError, 'ALIASED_PARAMETERS'):
                        captured = setup.capture_seeded_a(self.model, self.contract, t, setup.RECIPE)
                        self.prepare(captured=captured)
                    copier.assert_not_called()
                self.assertTrue(all(t.equal(p, old) for p, old in before))

    def test_actual_peft_operator_drift_refuses_before_mutation(self):
        t = self.torch
        cases = dict(r={'default': 5}, lora_alpha={'default': 9}, scaling={'default': 3.0},
            lora_dropout=t.nn.ModuleDict({'default': t.nn.Dropout(.1)}), _active_adapter='other',
            _disable_adapters=True, merged_adapters=['default'], use_rslora={'default': True},
            use_dora={'default': True}, lora_variant={'default': object()}, lora_bias={'default': True},
            fan_in_fan_out=True)
        for attribute, value in cases.items():
            self.capture = setup.capture_seeded_a(self.model, self.contract, t, setup.RECIPE)
            with self.subTest(attribute=attribute), patch.object(self.layer, attribute, value):
                before = setup._snapshot(self.parameters)
                with self.assertRaisesRegex(ValueError, 'OPERATOR_PROFILE'):
                    self.prepare()
                self.assertEqual(setup._snapshot(self.parameters), before)
        for module in [self.layer.base_layer, self.layer.lora_A['default'], self.layer.lora_B['default']]:
            self.capture = setup.capture_seeded_a(self.model, self.contract, t, setup.RECIPE)
            with self.subTest(bias=module), patch.object(module, 'bias', t.nn.Parameter(t.ones(module.out_features), requires_grad=False)):
                with self.assertRaisesRegex(ValueError, 'OPERATOR_PROFILE'): self.prepare()
        self.capture = setup.capture_seeded_a(self.model, self.contract, t, setup.RECIPE)
        with patch.object(self.layer, 'forward', lambda x: x):
            with self.assertRaisesRegex(ValueError, 'OPERATOR_PROFILE'): self.prepare()

    def test_actual_public_compile_state_refuses_without_forward_or_mutation(self):
        for module in [self.model, self.model.get_base_model().model.layers, self.layer]:
            self.capture = setup.capture_seeded_a(self.model, self.contract, self.torch, setup.RECIPE)
            before = setup._snapshot(self.parameters)
            module.compile(backend='eager')
            try:
                with patch.object(module, '_compiled_call_impl', wraps=module._compiled_call_impl) as dispatch:
                    with self.assertRaisesRegex(ValueError, 'OPERATOR_PROFILE'): self.prepare()
                    dispatch.assert_not_called()
            finally:
                module._compiled_call_impl = None
                self.assertEqual(setup._snapshot(self.parameters), before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
