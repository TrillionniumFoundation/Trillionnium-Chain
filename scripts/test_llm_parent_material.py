"""Complete fabricated factor files test byte boundaries, never model efficacy."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import llm_parent_material as parent
import llm_runtime_pilot as runtime

c = runtime.contract_module()
from test_llm_adapter_contract import fixture_contract


class ParentMaterialTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.family = copy.deepcopy(runtime.read_json(runtime.FAMILY_PATH))
        self.contract = fixture_contract()
        self.contract['architecture'] = self.family['architecture']
        self.contract['reference'] = runtime.MODEL + '@' + runtime.REVISION + ':derived-cpu-float32'
        self.contract['numeric']['storage_dtype'] = 'float32'
        self.contract['ports'].update(batch_max=1, input_tokens_max=128, output_tokens_max=16,
                                      tied_lm_head=True)
        self.contract['tokenizer'].update(vocabulary=49152, pad_id=2, add_bos=False)
        # Deliberately invented backbone descriptors: tests patch only the family
        # owner roots, never pretend these bytes are the actual 135M backbone.
        index = {name: dict(dtype='float32', shape=shape, byte_length=4 * self.product(shape),
                           sha256=hashlib.sha256(('fixture-' + name).encode()).hexdigest())
                 for name, shape in c.architecture_shapes(self.contract['architecture']).items()}
        self.contract['backbone'].update(index=index,
            index_root=c.H('llm-tensor-index-v1', c.canonical(index)).hex())
        self.family['material_pins']['fp32_backbone_index_root'] = self.contract['backbone']['index_root']
        self.family['material_pins']['tokenizer_files_root'] = self.contract['tokenizer']['files_root']
        self.contract['targets'] = sorted([dict(module=f'model.layers.{layer}.self_attn.{projection}',
            in_features=576, out_features=576 if projection == 'q_proj' else 192, rank=4, alpha=[8, 1])
            for layer in range(30) for projection in ('q_proj', 'v_proj')], key=lambda v: v['module'])
        self.raw_contract, self.cid = c.freeze_target_contract(self.contract)
        modules, self.material, self.header, payload = {}, {}, {}, bytearray()
        for target in self.contract['targets']:
            module = {}
            for factor, shape in [('A', [4, 576]), ('B', [target['out_features'], 4])]:
                blob = struct.pack('<f', 0.25) * self.product(shape)
                name = target['module'] + '.' + factor
                module[factor] = dict(dtype='float32', shape=shape, byte_length=len(blob),
                                     sha256=hashlib.sha256(blob).hexdigest())
                self.material[name] = blob
                self.header[name] = dict(dtype='F32', shape=shape,
                                        data_offsets=[len(payload), len(payload) + len(blob)])
                payload.extend(blob)
            modules[target['module']] = dict(**module, rank=4, alpha=[8, 1], dropout=False)
        self.payload = bytes(payload)
        self.adapter = dict(schema='pon-wrapped-decoder-lora-material-v1', contract=self.cid,
            modules=modules, material_scope='factor-bytes-and-insertion-interface-not-functional-equivalence')
        self.raw_adapter, self.aid = c.freeze_wrapped_adapter(self.adapter, self.contract, self.cid)
        self.contract_path = self.directory / 'target-contract.json'
        self.adapter_path = self.directory / 'wrapped-adapter.json'
        self.artifact_path = self.directory / 'artifact.safetensors'
        self.contract_path.write_bytes(self.raw_contract)
        self.adapter_path.write_bytes(self.raw_adapter)
        self.artifact_path.write_bytes(self.encoded(self.header, self.payload))
        self.sha = runtime.file_sha(self.artifact_path)

    @staticmethod
    def product(shape):
        result = 1
        for value in shape:
            result *= value
        return result

    @staticmethod
    def encoded(header, payload):
        raw = json.dumps(header, separators=(',', ':')).encode()
        return struct.pack('<Q', len(raw)) + raw + payload

    def verify(self, **changes):
        args = dict(expected_contract=self.cid, expected_adapter=self.aid, expected_file_sha256=self.sha)
        args.update(changes)
        with patch.object(runtime, 'verify_family', return_value=self.family):
            return parent.verify_parent(self.contract_path, self.adapter_path, self.artifact_path, **args)

    def test_complete_120_factor_file_and_explicit_cli_handoff(self):
        factors, receipt = self.verify()
        self.assertEqual(factors, self.material)
        self.assertEqual((receipt['factor_tensors'], receipt['factor_bytes']), (120, 921600))
        self.assertEqual(receipt['scope'], 'parent-material-preflight-only-no-training-or-installation')
        arguments = ['llm_parent_material.py', '--contract', str(self.contract_path),
            '--adapter', str(self.adapter_path), '--artifact', str(self.artifact_path),
            '--expected-contract', self.cid, '--expected-adapter', self.aid,
            '--expected-file-sha256', self.sha]
        output = io.StringIO()
        with patch.object(sys, 'argv', arguments), contextlib.redirect_stdout(output), \
                patch.object(runtime, 'verify_family', return_value=self.family):
            self.assertEqual(parent.main(), 0)
        self.assertEqual(json.loads(output.getvalue()), receipt)

    def test_all_three_independent_pins_are_required(self):
        for name in ('expected_contract', 'expected_adapter', 'expected_file_sha256'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.verify(**{name: 'f' * 64})

    def test_actual_family_rejects_fabricated_backbone_even_with_rehashed_contract(self):
        with self.assertRaisesRegex(ValueError, 'LLM_OWNER_CONTEXT'):
            parent.verify_parent(self.contract_path, self.adapter_path, self.artifact_path,
                expected_contract=self.cid, expected_adapter=self.aid, expected_file_sha256=self.sha)

    def test_matching_roots_cannot_substitute_model_targets_or_token_limits(self):
        for update in [lambda v: v['ports'].update(input_tokens_max=127),
                       lambda v: v.update(reference='a different parent'),
                       lambda v: v['targets'].pop()]:
            altered = copy.deepcopy(self.contract)
            update(altered)
            raw, cid = c.freeze_target_contract(altered)
            self.contract_path.write_bytes(raw)
            with self.subTest(change=update), self.assertRaisesRegex(ValueError, 'PARENT_MATERIAL_FAMILY'):
                self.verify(expected_contract=cid)

    def test_missing_extra_dtype_shape_offsets_overlap_holes_and_trailing_refuse(self):
        first, second = list(self.header)[:2]
        attacks = [lambda h: h.pop(first), lambda h: h.update(extra=h[first]),
            lambda h: h[first].update(dtype='BF16'), lambda h: h[first].update(shape=[4, 1]),
            lambda h: h[first].update(shape=[True, 576]),
            lambda h: h[first].update(data_offsets=[False, h[first]['data_offsets'][1]]),
            lambda h: h[first].update(data_offsets=[0, len(self.payload) + 1]),
            lambda h: h[second].update(data_offsets=list(h[first]['data_offsets'])),
            lambda h: h[first].update(data_offsets=[1, h[first]['data_offsets'][1] + 1])]
        for attack in attacks:
            header = copy.deepcopy(self.header)
            attack(header)
            with self.subTest(attack=attack), self.assertRaises(ValueError):
                parent.factor_bytes(self.encoded(header, self.payload), self.contract)
        with self.assertRaisesRegex(ValueError, 'TRAILING_BYTES'):
            parent.factor_bytes(self.encoded(self.header, self.payload + b'\0'), self.contract)

    def test_rehashed_nan_and_infinite_factors_still_refuse(self):
        first = next(iter(self.header))
        target = first.rsplit('.', 1)
        for bad in (float('nan'), float('inf'), float('-inf')):
            payload = struct.pack('<f', bad) + self.payload[4:]
            adapter = copy.deepcopy(self.adapter)
            n = self.header[first]['data_offsets'][1]
            adapter['modules'][target[0]][target[1]]['sha256'] = hashlib.sha256(payload[:n]).hexdigest()
            raw, aid = c.freeze_wrapped_adapter(adapter, self.contract, self.cid)
            self.adapter_path.write_bytes(raw)
            self.artifact_path.write_bytes(self.encoded(self.header, payload))
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'NONFINITE'):
                self.verify(expected_adapter=aid, expected_file_sha256=runtime.file_sha(self.artifact_path))

    def test_unchanged_pin_rejects_corruption_and_swapped_factor_contents(self):
        self.artifact_path.write_bytes(self.encoded(self.header, b'\1' + self.payload[1:]))
        with self.assertRaisesRegex(ValueError, 'FILE_IDENTITY'):
            self.verify()
        with self.assertRaisesRegex(ValueError, 'MATERIAL_BINDING'):
            self.verify(expected_file_sha256=runtime.file_sha(self.artifact_path))

    def test_duplicate_non_utf8_and_oversized_headers_refuse(self):
        for raw in [b'{"x":1,"x":2}', b'\xff\xfe{\0}\0', b'[]']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parent.factor_bytes(struct.pack('<Q', len(raw)) + raw, self.contract)
        with self.assertRaisesRegex(ValueError, 'HEADER'):
            parent.factor_bytes(struct.pack('<Q', 1024 * 1024 + 1) + b'{}', self.contract)

    def test_symlink_fifo_and_oversized_regular_file_refuse(self):
        link = self.directory / 'link'
        link.symlink_to(self.artifact_path)
        with self.assertRaisesRegex(ValueError, 'SYMLINK'):
            parent.read_regular(link, 2 * 1024**2)
        with self.assertRaisesRegex(ValueError, 'FILE_LIMIT'):
            parent.read_regular(self.artifact_path, 10)
        if hasattr(os, 'mkfifo'):
            fifo = self.directory / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, 'FILE_LIMIT'):
                parent.read_regular(fifo, 100)

    def test_real_cli_failure_never_echoes_input_or_creates_a_handoff(self):
        canary = 'sensitive-parent-canary'
        result = subprocess.run([sys.executable, str(Path(parent.__file__)),
            '--contract', canary, '--adapter', canary, '--artifact', canary,
            '--expected-contract', canary, '--expected-adapter', canary,
            '--expected-file-sha256', canary], text=True, capture_output=True)
        self.assertEqual((result.returncode, result.stdout), (2, ''))
        self.assertEqual(json.loads(result.stderr), dict(result='FAIL', error='PARENT_MATERIAL_INVALID'))
        self.assertNotIn(canary, result.stderr)


if __name__ == '__main__':
    unittest.main()
