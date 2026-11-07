"""Actual child control flow with invented tiny tensors, never an LLM result.

Only optional runtime/model operations are replaced. Artifact metadata, byte
parsing, identities, refusal receipts and the existing child entrypoint execute.
"""
import contextlib
import copy
import hashlib
import json
import math
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import llm_runtime_pilot as runtime

c = runtime.contract_module()
from test_llm_adapter_contract import fixture_contract


class TensorDouble:
    """Private exact bytes for child sequencing tests, not Torch execution."""
    def __init__(self, raw, shape, device=None):
        self.raw = bytes(raw)
        self.shape = tuple(shape)
        self.dtype = 'float32'
        self.device = SimpleNamespace(type='cpu') if device is None else device
        self.copies = 0

    def reshape(self, shape):
        if 4 * math.prod(shape) != len(self.raw):
            raise ValueError('test-double-length')
        return TensorDouble(self.raw, shape, self.device)

    def to(self, device):
        return TensorDouble(self.raw, self.shape, device)

    def copy_(self, other):
        if self.dtype != other.dtype or self.shape != other.shape:
            raise ValueError('test-double-copy-profile')
        self.raw = other.raw
        self.copies += 1


def descriptor(value):
    return dict(dtype=value.dtype, shape=list(value.shape), byte_length=len(value.raw),
                sha256=hashlib.sha256(value.raw).hexdigest())


def encoded(header, payload):
    raw = json.dumps(header, separators=(',', ':')).encode()
    return struct.pack('<Q', len(raw)) + raw + payload


def material_wire(material, shapes):
    header, payload = {}, bytearray()
    for name, shape in shapes.items():
        raw = material[name]
        header[name] = dict(dtype='F32', shape=list(shape),
                            data_offsets=[len(payload), len(payload) + len(raw)])
        payload.extend(raw)
    return header, bytes(payload)


class ArtifactChildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.artifacts = self.directory / 'artifact'
        self.artifacts.mkdir()
        self.manifest = dict(scope='invented-child-orchestration-fixture-not-model-material')
        self.plan = runtime.experiment_plan(self.manifest)
        self.plan_path = self.directory / 'plan.json'
        runtime.save(self.plan_path, self.plan)
        self.contract = fixture_contract()
        self.contract['numeric']['storage_dtype'] = 'float32'
        for item in self.contract['backbone']['index'].values():
            item['dtype'] = 'float32'
            item['byte_length'] *= 2
            item['sha256'] = hashlib.sha256(bytes(item['byte_length'])).hexdigest()
        self.contract['backbone']['index_root'] = c.H('llm-tensor-index-v1',
            c.canonical(self.contract['backbone']['index'])).hex()
        for target in self.contract['targets']:
            target.update(rank=4, alpha=[8, 1])
        self.raw_contract, self.cid = c.freeze_target_contract(self.contract)
        self.shapes = c.architecture_shapes(self.contract['architecture'])
        self.base = self.contract['backbone']['index_root']
        self.parameters = {name: TensorDouble(bytes(4 * math.prod(shape)), shape)
                           for name, shape in self.shapes.items()}
        self.factor_shapes = {target['module'] + '.' + factor: shape
            for target in self.contract['targets']
            for factor, shape in (('A', [target['rank'], target['in_features']]),
                                  ('B', [target['out_features'], target['rank']]))}
        self.factor_parameters = {name: TensorDouble(bytes(4 * math.prod(shape)), shape)
                                  for name, shape in self.factor_shapes.items()}
        self.decode = Mock(return_value=dict(scope='mock-decode-not-inference'))
        self.insert = Mock(side_effect=lambda model, *_: model)
        self.path_loader = Mock(side_effect=AssertionError('artifact path reopened'))
        self.model = object()
        self.tokenizer = object()
        self.frombuffer = Mock(side_effect=lambda raw, dtype: TensorDouble(raw, [len(raw) // 4]))
        self.torch = SimpleNamespace(get_num_threads=lambda: 1, float32='float32',
            version=SimpleNamespace(cuda=None, hip=None), no_grad=contextlib.nullcontext,
            frombuffer=self.frombuffer, isfinite=lambda value: SimpleNamespace(
                all=lambda: SimpleNamespace(item=lambda: all(math.isfinite(v)
                    for (v,) in struct.iter_unpack('<f', value.raw)))))

    def prepared(self, role='budget-matched-full-tune', material=None):
        factor = self.plan['recipes'][role]['kind'] in ('lora', 'random-lora')
        shapes = self.factor_shapes if factor else self.shapes
        if material is None:
            material = {name: struct.pack('<f', 1 + number / 8) * math.prod(shape)
                        for number, (name, shape) in enumerate(shapes.items())}
        admitted = self.record(role)
        if factor:
            modules = {}
            for target in self.contract['targets']:
                module = {part: descriptor(TensorDouble(material[target['module'] + '.' + part], shape))
                    for part, shape in (('A', [target['rank'], target['in_features']]),
                                        ('B', [target['out_features'], target['rank']]))}
                modules[target['module']] = dict(**module, rank=4, alpha=[8, 1], dropout=False)
            wrapped = dict(schema='pon-wrapped-decoder-lora-material-v1', contract=self.cid,
                modules=modules, material_scope='factor-bytes-and-insertion-interface-not-functional-equivalence')
            raw, admitted['artifact'] = c.freeze_wrapped_adapter(wrapped, self.contract, self.cid)
            (self.artifacts / 'wrapped-adapter.json').write_bytes(raw)
        else:
            index = {name: descriptor(TensorDouble(raw, shapes[name])) for name, raw in material.items()}
            admitted['artifact'] = admitted['resulting_backbone'] = c.H(
                'llm-tensor-index-v1', c.canonical(index)).hex()
        header, payload = material_wire(material, shapes)
        self.write_material(admitted, encoded(header, payload))
        return admitted, material, header, payload

    def write_material(self, admitted, raw):
        (self.artifacts / 'artifact.safetensors').write_bytes(raw)
        admitted.update(file_sha256=hashlib.sha256(raw).hexdigest(),
                        native_artifact_H=c.H('artifact', raw).hex())

    def record(self, role='current-backbone'):
        return dict(role=role, artifact=self.base, contract=self.cid,
            kind=self.plan['recipes'][role]['kind'], source_model=runtime.WEIGHT_SHA,
            experiment=runtime.identity(self.plan), parent_backbone=self.base,
            resulting_backbone=self.base, file_sha256=None, native_artifact_H=None,
            native_domain='artifact', native_admission_accepted=False)

    def invoke(self, record, role=None):
        runtime.save(self.artifacts / 'artifact.json', record)
        output = self.directory / 'output'
        output.mkdir(exist_ok=True)
        observer = SimpleNamespace(events=[], stage=lambda _, action: action())
        imports = (self.torch, SimpleNamespace(type='cpu'), None, None, None,
                   Mock(), self.path_loader)
        args = SimpleNamespace(phase='evaluate', role=record['role'] if role is None else role,
            output=str(output), materials=str(self.directory / 'unused-public-materials'),
            plan=str(self.plan_path), artifact=str(self.artifacts))
        with patch.object(runtime, 'Observer', return_value=observer), \
                patch.object(runtime, 'verify_materials', return_value=(self.manifest, {})), \
                patch.object(runtime, 'runtime_import', return_value=imports), \
                patch.object(runtime, 'load_model', return_value=(self.model, self.tokenizer, self.shapes, {})), \
                patch.object(runtime, 'make_contract', return_value=(self.contract, self.raw_contract, self.cid)), \
                patch.object(runtime.importlib.metadata, 'version', return_value='mock-runtime'), \
                patch.object(runtime, 'decode', self.decode), \
                patch.object(runtime, 'insert_lora', self.insert), \
                patch.object(runtime, 'backbone_tensors', return_value=self.parameters), \
                patch.object(runtime, 'adapter_tensors', return_value=self.factor_parameters), \
                patch.object(runtime, 'tensor_descriptor', side_effect=descriptor), \
                patch.object(runtime, 'tensor_bytes', side_effect=lambda value: value.raw):
            runtime.child(args)
        return runtime.read_json(output / 'actual-receipt.json')

    def assert_refused(self, record, pattern='RUNTIME_ARTIFACT_', role=None):
        self.decode.reset_mock()
        self.insert.reset_mock()
        with self.assertRaisesRegex(ValueError, pattern):
            self.invoke(record, role)
        self.decode.assert_not_called()
        self.insert.assert_not_called()
        self.path_loader.assert_not_called()
        self.assertTrue(all(value.copies == 0 for value in
                            [*self.parameters.values(), *self.factor_parameters.values()]))
        receipt = runtime.read_json(self.directory / 'output/actual-receipt.json')
        self.assertEqual(receipt['outcome'], 'failed')
        self.assertNotIn('forward_executed', receipt)
        self.assertTrue(all(receipt[name] is False for name in runtime.QUALIFICATIONS))

    def test_unknown_kind_cannot_skip_reload_and_claim_a_candidate(self):
        admitted = self.record('candidate')
        admitted.update(kind='unimplemented-candidate', artifact='a' * 64)
        self.assert_refused(admitted)

    def test_candidate_cannot_relabel_immutable_backbone_as_adapter(self):
        admitted = self.record('candidate')
        admitted.update(kind='immutable-backbone', artifact='a' * 64)
        self.assert_refused(admitted)

    def test_immutable_artifact_parent_and_result_must_match_loaded_backbone(self):
        for name in ('artifact', 'parent_backbone', 'resulting_backbone'):
            admitted = self.record()
            admitted[name] = 'a' * 64
            with self.subTest(name=name):
                self.assert_refused(admitted)

    def test_false_admission_source_domain_and_exact_existing_fields_are_enforced(self):
        attacks = [('source_model', 'f' * 64), ('native_admission_accepted', True),
                   ('native_admission_accepted', 0), ('native_domain', 'execution'),
                   ('executable', 'not-an-authorized-code-update')]
        for name, value in attacks:
            admitted = self.record()
            admitted[name] = value
            with self.subTest(name=name, value=value):
                self.assert_refused(admitted)
        admitted = self.record()
        del admitted['source_model']
        self.assert_refused(admitted)

    def test_immutable_control_cannot_claim_a_weight_file_identity(self):
        for name in ('file_sha256', 'native_artifact_H'):
            admitted = self.record()
            admitted[name] = 'a' * 64
            with self.subTest(name=name):
                self.assert_refused(admitted)

    def test_unchanged_immutable_control_keeps_existing_scope_and_artifact(self):
        receipt = self.invoke(self.record())
        self.assertEqual((receipt['outcome'], receipt['artifact']), ('success', self.base))
        self.assertEqual(self.decode.call_count,
                         sum(row['partition'] != 'training' for row in self.plan['tasks']))
        self.assertTrue(all(receipt[name] is False for name in runtime.QUALIFICATIONS))
        self.path_loader.assert_not_called()

    def test_all_existing_file_kinds_copy_exact_checked_bytes_and_preserve_scope(self):
        for role in ('candidate', 'fresh-budget-matched-lora',
                     'randomized-rank-matched-lora', 'budget-matched-full-tune'):
            with self.subTest(role=role):
                admitted, material, _, _ = self.prepared(role)
                receipt = self.invoke(admitted)
                target = self.parameters if admitted['kind'] == 'full-tune' else self.factor_parameters
                self.assertEqual({name: tensor.raw for name, tensor in target.items()}, material)
                self.assertEqual((receipt['outcome'], receipt['artifact']), ('success', admitted['artifact']))
                self.assertTrue(all(receipt[name] is False for name in runtime.QUALIFICATIONS))
        self.path_loader.assert_not_called()

    def test_full_shape_dtype_and_extra_tensor_reject_before_any_copy(self):
        admitted, _, header, payload = self.prepared()
        first = next(iter(header))
        attacks = [lambda h: h[first].update(shape=[1]),
                   lambda h: h[first].update(dtype='F64'),
                   lambda h: h[first].update(shape=[True, 8]),
                   lambda h: h.update(unexpected=h[first])]
        for attack in attacks:
            changed = copy.deepcopy(header)
            attack(changed)
            self.write_material(admitted, encoded(changed, payload))
            with self.subTest(attack=attack):
                self.assert_refused(admitted, 'PARENT_MATERIAL_TENSOR_')
        self.frombuffer.assert_not_called()

    def test_all_full_tune_values_are_checked_before_first_copy(self):
        _, material, _, _ = self.prepared()
        last = next(reversed(material))
        for value in (float('nan'), float('inf'), float('-inf')):
            changed = dict(material, **{last: struct.pack('<f', value) + material[last][4:]})
            admitted, _, _, _ = self.prepared(material=changed)
            with self.subTest(value=value):
                self.assert_refused(admitted, 'RUNTIME_ARTIFACT_NONFINITE')

    def test_adapter_all_factor_bytes_are_verified_before_insertion(self):
        admitted, _, header, payload = self.prepared('candidate')
        self.write_material(admitted, encoded(header, struct.pack('<f', 99.0) + payload[4:]))
        self.assert_refused(admitted, 'LLM_MATERIAL_BINDING')
        self.frombuffer.assert_not_called()

    def test_adapter_nonfinite_with_matching_new_identity_refuses_before_insertion(self):
        _, material, _, _ = self.prepared('candidate')
        last = next(reversed(material))
        material[last] = struct.pack('<f', float('nan')) + material[last][4:]
        admitted, _, _, _ = self.prepared('candidate', material)
        self.assert_refused(admitted, 'LLM_ADAPTER_NONFINITE')

    def test_file_sha_native_domain_and_material_root_are_separate_bindings(self):
        for name in ('file_sha256', 'native_artifact_H', 'artifact'):
            admitted, _, _, _ = self.prepared()
            admitted[name] = 'a' * 64
            if name == 'artifact':
                admitted['resulting_backbone'] = admitted[name]
            with self.subTest(name=name):
                self.assert_refused(admitted, 'RUNTIME_(ARTIFACT_FILE|FULL_TUNE_RELOAD)')

    def test_hash_and_decode_use_same_snapshot_even_if_path_is_replaced_after_read(self):
        import llm_parent_material as parent
        admitted, material, header, payload = self.prepared()
        alternate = encoded(header, struct.pack('<f', 11.0) + payload[4:])
        original_read, reads = parent.read_regular, []
        path = self.artifacts / 'artifact.safetensors'

        def replace_after_read(name, maximum):
            raw = original_read(name, maximum)
            if Path(name) == path:
                reads.append(raw)
                path.write_bytes(alternate)
            return raw

        with patch.object(parent, 'read_regular', side_effect=replace_after_read):
            receipt = self.invoke(admitted)
        self.assertEqual((receipt['outcome'], receipt['artifact']), ('success', admitted['artifact']))
        self.assertEqual(len(reads), 1)
        self.assertNotEqual(hashlib.sha256(path.read_bytes()).hexdigest(), admitted['file_sha256'])
        self.assertEqual({name: value.raw for name, value in self.parameters.items()}, material)
        self.path_loader.assert_not_called()

    def test_unpinned_replacement_cannot_supply_a_root_for_earlier_hashed_bytes(self):
        import llm_parent_material as parent
        admitted, material, _, _ = self.prepared()
        path = self.artifacts / 'artifact.safetensors'
        original_wire = path.read_bytes()
        material = {name: struct.pack('<f', 3.0) * math.prod(self.shapes[name]) for name in material}
        alternate, _, _, _ = self.prepared(material=material)
        alternate_wire = path.read_bytes()
        path.write_bytes(original_wire)
        admitted.update(artifact=alternate['artifact'], resulting_backbone=alternate['resulting_backbone'])
        original_read = parent.read_regular

        def replace_after_read(name, maximum):
            raw = original_read(name, maximum)
            if Path(name) == path:
                path.write_bytes(alternate_wire)
            return raw

        with patch.object(parent, 'read_regular', side_effect=replace_after_read):
            self.assert_refused(admitted, 'RUNTIME_FULL_TUNE_RELOAD')

    def test_wrong_late_target_profile_refuses_before_earlier_parameter_copy(self):
        admitted, _, _, _ = self.prepared()
        self.parameters[next(reversed(self.parameters))].dtype = 'float64'
        self.assert_refused(admitted, 'RUNTIME_ARTIFACT_PARAMETER_PROFILE')


class RecipeBindingTests(unittest.TestCase):
    def test_existing_recipes_allow_finite_positive_rates_and_valid_seed_range(self):
        plan = runtime.experiment_plan({'fixture': 'plan-only'})
        plan['recipes']['candidate'].update(learning_rate='0.0003', initialization_seed=(1 << 64) - 1)
        plan['recipes']['fresh-budget-matched-lora'].update(learning_rate='1e-5', initialization_seed=-(1 << 63))
        plan['recipes']['randomized-rank-matched-lora']['std'] = '0.01'
        self.assertEqual(runtime.validate_plan(plan), plan)

    def test_kind_field_set_numeric_and_seed_confusion_fail(self):
        plan = runtime.experiment_plan({'fixture': 'plan-only'})
        attacks = [('kind', 'immutable-backbone'), ('kind', 'unknown'), ('executable', 'arbitrary'),
            ('initialization_seed', True), ('initialization_seed', 7.0),
            ('initialization_seed', 1 << 64), ('initialization_seed', -(1 << 63) - 1),
            ('learning_rate', 0.002), ('learning_rate', True), ('learning_rate', 'nan'),
            ('learning_rate', 'inf'), ('learning_rate', '-0.01'), ('learning_rate', '0'),
            ('learning_rate', '1e999'), ('learning_rate', '1e-999'), ('learning_rate', ' 0.002')]
        for name, value in attacks:
            changed = copy.deepcopy(plan)
            changed['recipes']['candidate'][name] = value
            with self.subTest(name=name, value=value), self.assertRaisesRegex(ValueError, 'RUNTIME_RECIPE_'):
                runtime.validate_plan(changed)
        for role in runtime.PARTICIPANTS:
            changed = copy.deepcopy(plan)
            changed['recipes'][role]['kind'] = 'unknown'
            with self.subTest(role=role), self.assertRaisesRegex(ValueError, 'RUNTIME_RECIPE_KIND'):
                runtime.validate_plan(changed)


if __name__ == '__main__':
    unittest.main()
