"""Bounded snapshot and original-config controls without optional model imports."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import llm_base_material as base
import llm_runtime_pilot as runtime


class BaseMaterialTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = dict(model_type='llama', num_hidden_layers=30, hidden_size=576,
            intermediate_size=1536, num_attention_heads=9, num_key_value_heads=3,
            vocab_size=49152, max_position_embeddings=8192, tie_word_embeddings=True,
            attention_bias=False, mlp_bias=False, torch_dtype='bfloat16', rope_theta=100000,
            rms_norm_eps=1e-5, hidden_act='silu', attention_dropout=0.0, rope_scaling=None)
        self.blobs = {name: b'bounded non-model parser fixture' for name in runtime.PUBLIC_FILES}
        self.blobs['config.json'] = base.canonical(self.config)
        self.pins = {name: (len(raw), hashlib.sha256(raw).hexdigest()) for name, raw in self.blobs.items()}
        self.manifest = dict(model=runtime.MODEL, revision=runtime.REVISION,
            files={name: dict(size=size, sha256=sha, revision=runtime.REVISION)
                   for name, (size, sha) in self.pins.items()})
        for name, raw in self.blobs.items():
            (self.root / name).write_bytes(raw)
        (self.root / 'material-manifest.json').write_bytes(base.canonical(self.manifest))

    def capture(self):
        return base.capture(self.root, self.pins, runtime.MODEL, runtime.REVISION,
                            self.pins['model.safetensors'][1])

    def test_each_member_is_read_once_and_subsequent_path_change_cannot_change_snapshot(self):
        reader, observed = base._read_member, []
        def change_after_read(root, name, maximum):
            raw = reader(root, name, maximum)
            observed.append(name)
            (self.root / name).write_bytes(b'changed-after-exact-capture')
            return raw
        with patch.object(base, '_read_member', side_effect=change_after_read):
            material = self.capture()
        self.assertCountEqual(observed, ['material-manifest.json', *self.pins])
        self.assertEqual(len(observed), len(set(observed)))
        self.assertEqual(material.manifest(), self.manifest)
        self.assertEqual(material.document('config.json'), self.config)
        self.assertEqual(dict(material.files), self.blobs)

    def test_public_hash_and_manifest_must_both_match_the_independent_pins(self):
        path = self.root / 'tokenizer.json'
        path.write_bytes(b'different model material')
        with self.assertRaisesRegex(ValueError, 'MATERIAL_HASH'):
            self.capture()
        changed = copy.deepcopy(self.manifest)
        changed['files']['tokenizer.json'].update(size=path.stat().st_size,
            sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        (self.root / 'material-manifest.json').write_bytes(base.canonical(changed))
        with self.assertRaisesRegex(ValueError, 'PUBLIC_FILE_ROOT'):
            self.capture()

    def test_symlinks_and_nonregular_members_refuse_before_read(self):
        path = self.root / 'tokenizer.json'
        path.unlink()
        target = self.root / 'external.json'
        target.write_bytes(self.blobs['tokenizer.json'])
        path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'MATERIAL_HASH'):
            self.capture()
        path.unlink(); path.mkdir()
        with self.assertRaisesRegex(ValueError, 'MATERIAL_HASH'):
            self.capture()

    def test_oversized_manifest_or_member_cannot_expand_capture(self):
        (self.root / 'tokenizer.json').write_bytes(self.blobs['tokenizer.json'] + b'x')
        with self.assertRaisesRegex(ValueError, 'MATERIAL_HASH'):
            self.capture()
        (self.root / 'material-manifest.json').write_bytes(b'x' * (base.MAX_MANIFEST_BYTES + 1))
        with self.assertRaisesRegex(ValueError, 'MATERIAL_HASH'):
            self.capture()

    def test_decoded_mutable_views_do_not_rewrite_captured_bytes(self):
        material = self.capture()
        manifest, config = material.manifest(), material.document('config.json')
        manifest['files']['tokenizer.json']['sha256'] = '0' * 64
        config['rope_theta'] = 16
        self.assertEqual(material.manifest(), self.manifest)
        self.assertEqual(material.document('config.json'), self.config)
        self.assertIsInstance(material.raw('model.safetensors'), bytes)

    def test_caller_pin_mutation_after_capture_starts_cannot_redefine_members(self):
        reader = base._read_member
        original = dict(self.pins)
        def mutate_caller(root, name, maximum):
            self.pins['config.json'] = (0, 'changed-after-private-copy')
            return reader(root, name, maximum)
        with patch.object(base, '_read_member', side_effect=mutate_caller):
            material = self.capture()
        self.assertEqual(material.document('config.json'), self.config)
        self.assertEqual(material.manifest()['files']['config.json']['sha256'], original['config.json'][1])

    def test_duplicate_or_nonfinite_json_cannot_change_snapshot_context(self):
        raw = base.canonical(self.manifest)
        (self.root / 'material-manifest.json').write_bytes(b'{"model":"forged",' + raw[1:])
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON'):
            self.capture()
        with self.assertRaisesRegex(ValueError, 'BASE_NUMBER'):
            base.decode(b'{"rope_theta":NaN}')

    def test_load_entry_rechecks_changed_material_before_optional_model_imports(self):
        with patch.object(runtime, 'PUBLIC_FILES', self.pins), \
                patch.object(runtime, 'WEIGHT_SHA', self.pins['model.safetensors'][1]):
            manifest, config = runtime.verify_materials(self.root)
            self.assertEqual(config, self.config)
            plan = runtime.experiment_plan(manifest)
            for name in ('tokenizer.json', 'config.json', 'model.safetensors'):
                with self.subTest(name=name):
                    (self.root / name).write_bytes(b'substitution-after-preflight')
                    with self.assertRaisesRegex(ValueError, 'MATERIAL_HASH'):
                        runtime.load_model(self.root, plan, (None,) * 7)
                    (self.root / name).write_bytes(self.blobs[name])

    def test_rope_and_rms_are_actual_configuration_fields_not_hardcoded_labels(self):
        original = runtime.architecture(self.config)
        self.assertEqual(original['rope_theta'], [100000, 1])
        self.assertEqual(original['rms_epsilon'], [1, 100000])
        altered = runtime.architecture(dict(self.config, rope_theta=16, rms_norm_eps=0.125))
        self.assertEqual(altered['rope_theta'], [16, 1])
        self.assertEqual(altered['rms_epsilon'], [1, 8])
        self.assertNotEqual(original, altered)
        for key in ('rope_theta', 'rms_norm_eps'):
            missing = dict(self.config); del missing[key]
            with self.subTest(missing=key), self.assertRaisesRegex(ValueError, 'CONFIG_PROFILE'):
                runtime.architecture(missing)
            for value in (True, float('nan'), float('inf'), 0, -1):
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, 'CONFIG_PROFILE'):
                    runtime.architecture(dict(self.config, **{key: value}))

    def test_unloaded_objects_have_no_material_binding(self):
        with self.assertRaisesRegex(ValueError, 'BASE_LOAD_BINDING'):
            base.loaded_config(object(), object(), self.manifest)


if __name__ == '__main__':
    unittest.main()
