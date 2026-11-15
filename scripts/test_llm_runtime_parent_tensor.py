"""Opt-in actual CPU tensor units; fabricated tiny weights are not an LLM run.

TRNM_ACTUAL_PARENT_TENSOR_TESTS=1 is required so ordinary lightweight/source
checks do not import optional Torch. An opted-in run fails if Torch is absent.
No pretrained weights, tokenizer, PEFT, forward decoder, training or GPU is used.
"""
import copy
import hashlib
import os
import struct
import unittest

import llm_runtime_parent_step as step
import llm_runtime_pilot as runtime

c = runtime.contract_module()
from test_llm_adapter_contract import fixture_contract


@unittest.skipUnless(os.environ.get('TRNM_ACTUAL_PARENT_TENSOR_TESTS') == '1',
                     'explicit CPU Torch unit opt-in absent; actual tensor helper NOT_RUN')
class ActualParentTensorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import torch
        cls.torch = torch
        torch.set_num_threads(1)
        torch.set_num_interop_threads(1)

    def setUp(self):
        self.contract = fixture_contract()
        self.contract['numeric']['storage_dtype'] = 'float32'
        for descriptor in self.contract['backbone']['index'].values():
            descriptor['dtype'] = 'float32'
            descriptor['byte_length'] *= 2
            descriptor['sha256'] = hashlib.sha256(bytes(descriptor['byte_length'])).hexdigest()
        self.contract['backbone']['index_root'] = c.H('llm-tensor-index-v1',
            c.canonical(self.contract['backbone']['index'])).hex()
        for target in self.contract['targets']:
            target.update(rank=4, alpha=[8, 1])
        _, self.cid = c.freeze_target_contract(self.contract)
        self.model = self.new_model()
        self.parent = self.factors(0.25)
        self.candidate = self.factors(1.5)

    def new_model(self):
        torch = self.torch
        class TinyAdapter(torch.nn.Module):
            def __init__(self, targets):
                super().__init__()
                self.model = torch.nn.Module()
                layer = torch.nn.Module()
                layer.self_attn = torch.nn.Module()
                self.model.layers = torch.nn.ModuleList([layer])
                for target in targets:
                    projection = torch.nn.Module()
                    projection.lora_A = torch.nn.ModuleDict({'default': torch.nn.Linear(
                        target['in_features'], target['rank'], bias=False, device='cpu', dtype=torch.float32)})
                    projection.lora_B = torch.nn.ModuleDict({'default': torch.nn.Linear(
                        target['rank'], target['out_features'], bias=False, device='cpu', dtype=torch.float32)})
                    setattr(layer.self_attn, target['module'].rsplit('.', 1)[1], projection)

            def get_base_model(self):
                return self
        return TinyAdapter(self.contract['targets'])

    def factors(self, offset):
        result = {}
        for number, target in enumerate(self.contract['targets']):
            for factor, count in (('A', target['rank'] * target['in_features']),
                                  ('B', target['out_features'] * target['rank'])):
                # Exactly representable finite F32 values, independently packed.
                values = [offset + number + i / 8 for i in range(count)]
                result[target['module'] + '.' + factor] = struct.pack('<' + 'f' * count, *values)
        return result

    def adapter_id(self, factors):
        modules = {}
        for target in self.contract['targets']:
            module = {}
            for factor, shape in (('A', [target['rank'], target['in_features']]),
                                  ('B', [target['out_features'], target['rank']])):
                blob = factors[target['module'] + '.' + factor]
                module[factor] = dict(dtype='float32', shape=shape, byte_length=len(blob),
                                      sha256=hashlib.sha256(blob).hexdigest())
            modules[target['module']] = dict(**module, rank=4, alpha=[8, 1], dropout=False)
        return c.freeze_wrapped_adapter(dict(schema='pon-wrapped-decoder-lora-material-v1',
            contract=self.cid, modules=modules,
            material_scope='factor-bytes-and-insertion-interface-not-functional-equivalence'),
            self.contract, self.cid)[1]

    def apply(self, factors, model=None, expected=None):
        return step.copy_factors(self.model if model is None else model, self.contract, factors,
            self.adapter_id(factors) if expected is None else expected, self.torch)

    def observed(self, model=None):
        return {name: runtime.tensor_bytes(value) for name, value in runtime.adapter_tensors(
            self.model if model is None else model, self.contract['targets']).items()}

    def test_actual_f32_copy_and_wrapper_readback_match_independently_packed_bytes(self):
        observed = self.apply(self.parent)
        self.assertEqual(observed, self.adapter_id(self.parent))
        self.assertEqual(self.observed(), self.parent)
        self.assertTrue(all(value.device.type == 'cpu' and value.dtype == self.torch.float32
            for value in runtime.adapter_tensors(self.model, self.contract['targets']).values()))

    def test_actual_candidate_is_absolute_replacement_not_parent_plus_candidate(self):
        self.apply(self.parent)
        self.apply(self.candidate)
        self.assertEqual(self.observed(), self.candidate)
        target = self.contract['targets'][0]
        projection = self.model.get_submodule(target['module'])
        x = self.torch.arange(target['in_features'], dtype=self.torch.float32).reshape(1, -1)
        as_tensor = lambda raw, shape: self.torch.frombuffer(bytearray(raw), dtype=self.torch.float32).reshape(shape)
        pa = as_tensor(self.parent[target['module'] + '.A'], [4, target['in_features']])
        pb = as_tensor(self.parent[target['module'] + '.B'], [target['out_features'], 4])
        ca = as_tensor(self.candidate[target['module'] + '.A'], [4, target['in_features']])
        cb = as_tensor(self.candidate[target['module'] + '.B'], [target['out_features'], 4])
        actual = x @ projection.lora_A['default'].weight.T @ projection.lora_B['default'].weight.T
        self.assertTrue(self.torch.equal(actual, x @ ca.T @ cb.T))
        self.assertFalse(self.torch.equal(actual, x @ ca.T @ cb.T + x @ pa.T @ pb.T))

    def test_parent_module_and_input_bytes_do_not_alias_the_working_copy(self):
        self.apply(self.parent)
        original = self.observed()
        working = copy.deepcopy(self.model)
        self.apply(self.candidate, model=working)
        self.assertEqual(self.observed(), original)
        before = dict(self.candidate)
        with self.torch.no_grad():
            next(iter(runtime.adapter_tensors(working, self.contract['targets']).values())).add_(7)
        self.assertEqual(self.candidate, before)
        self.assertEqual(self.parent, original)

    def test_actual_nonfinite_factors_cannot_return_a_successful_readback(self):
        name = next(iter(self.parent))
        for bad in (float('nan'), float('inf'), float('-inf')):
            factors = dict(self.parent)
            factors[name] = struct.pack('<f', bad) + factors[name][4:]
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'LLM_ADAPTER_NONFINITE'):
                self.apply(factors)

    def test_actual_dtype_shape_set_and_expected_identity_faults_refuse(self):
        name = next(iter(self.parent))
        for factors in ({k: v for k, v in self.parent.items() if k != name},
                        dict(self.parent, extra=b'\0' * 4)):
            with self.assertRaisesRegex(ValueError, 'PARENT_STEP_FACTOR_SET'):
                self.apply(factors, expected='f' * 64)
        factors = dict(self.parent); factors[name] = factors[name][4:]
        with self.assertRaisesRegex(ValueError, 'PARENT_STEP_FACTOR_SHAPE'):
            self.apply(factors, expected='f' * 64)
        self.model.to(dtype=self.torch.float64)
        with self.assertRaisesRegex(ValueError, 'PARENT_STEP_FACTOR_DTYPE'):
            self.apply(self.parent)
        self.model.to(dtype=self.torch.float32)
        with self.assertRaisesRegex(ValueError, 'PARENT_STEP_ADAPTER_READBACK'):
            self.apply(self.parent, expected='f' * 64)


if __name__ == '__main__':
    unittest.main()
