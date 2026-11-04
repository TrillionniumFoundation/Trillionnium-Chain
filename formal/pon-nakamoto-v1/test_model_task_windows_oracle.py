"""Source bytes, feature derivation, roots and owner-signature fixture parity."""
import hashlib
import json
from pathlib import Path
import unittest
import model_task_windows_oracle as oracle


class ModelTaskWindowsOracleTests(unittest.TestCase):
    def test_signed_manifest_and_native_differential_fixture_are_reproducible(self):
        raw, vector = oracle.generate()
        directory = Path(__file__).with_name('vectors')
        self.assertEqual(raw, (directory / 'model-task-windows-v1.manifest.json').read_bytes())
        self.assertEqual(vector, json.loads((directory / 'model-task-windows-v1.json').read_text()))
        self.assertEqual([row['candidate_correct'] for row in vector['windows']], [6, 6])
        self.assertTrue(all(row['score'] > 0 for row in vector['windows']))
        legacy = {row['source_content_sha256'] for row in oracle.evolution.EMPIRICAL['tasks']}
        current = [row['source_content_sha256'] for window in vector['windows'] for row in window['rows']]
        self.assertEqual(len(current), len(set(current)))
        self.assertFalse(legacy.intersection(current))

    def test_full_content_hash_and_snapshot_root_detect_replacement(self):
        raw, vector = oracle.generate()
        manifest = json.loads(raw)
        window = manifest['windows'][0]
        before = oracle.source_revision(manifest['source_repository'], window['tasks'])
        source = b'pub fn substituted_source() {}\n'
        window['tasks'][0]['content_utf8_hex'] = source.hex()
        with self.assertRaisesRegex(ValueError, 'TASK_WINDOW_CONTENT_HASH'):
            oracle.rows(bytes.fromhex(vector['family']), manifest['source_repository'], before, window['tasks'])
        window['tasks'][0]['content_sha256'] = hashlib.sha256(source).hexdigest()
        self.assertNotEqual(oracle.source_revision(manifest['source_repository'], window['tasks']), before)

    def test_token_filter_clipping_and_bias_are_explicit(self):
        empty = oracle.features('m00 M04 M10 trnm_private trnmOther')
        self.assertEqual(empty, [0] * 256 + [8])
        source = 'sample_token ' * 4096
        self.assertTrue(all(-8 <= value <= 8 for value in oracle.features(source)))
        with self.assertRaisesRegex(ValueError, 'TASK_WINDOW_CONTENT'):
            oracle.features('non-ascii \u4e2d')


if __name__ == '__main__':
    unittest.main(verbosity=2)
