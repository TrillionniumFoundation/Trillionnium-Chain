#!/usr/bin/env python3
"""Separate lane identity/roster controls; never evidence of actual native recovery."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from run_history_effect_v6_native import retain_binary, sha
from run_history_reorg_continuation_native_v1 import ROSTER, baseline, restore, roster, suite_passed


class ReorgNativeLane(unittest.TestCase):
    def test_exact_seven_required_and_no_ignored_or_substituted_case(self):
        self.assertEqual(len(ROSTER), 7)
        self.assertEqual(roster('\n'.join(name + ': test' for name in ROSTER)), ROSTER)
        for changed in (ROSTER[:-1], ROSTER + [ROSTER[0]], ROSTER[:-1] + [ROSTER[-1] + '_substitute']):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                roster('\n'.join(name + ': test' for name in changed))
        log = 'running 7 tests\n' + ''.join(f'test {name} ... ok\n' for name in ROSTER)
        summary = 'test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 700 filtered out; finished in 100.00s'
        self.assertTrue(suite_passed(log + summary))
        for bad in (summary.replace('7 passed', '0 passed'), summary.replace('0 ignored', '1 ignored'),
                    summary.replace('0 failed', '1 failed'), summary + '\n' + summary):
            self.assertFalse(suite_passed(log + bad))
        self.assertFalse(suite_passed(log.replace('... ok', '... ignored', 1) + summary))
        self.assertFalse(suite_passed(log.replace(ROSTER[0], ROSTER[1], 1) + summary))
        self.assertFalse(suite_passed(summary))

    def test_original_source_gate_and_six_hundred_second_budget_are_mandatory(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / 'actual-binary').mkdir()
            source = {'fixture': 'exact original source guard'}
            manifest = {'binary_sha256': 'a' * 64}
            for name in ('source-before.json', 'source-after.json'):
                (directory / name).write_text(json.dumps(source))
            (directory / 'actual-binary/manifest.json').write_text(json.dumps(manifest))
            original = {'schema': 'history-effect-v6-hosted-native-terminal-v1', 'expected_source': 'b' * 40,
                        'passed': True, 'source_stable': True, 'native_test_budget_seconds': 600,
                        'original_local_full_suite_budget_seconds': 600,
                        'native': {'exact_twenty_two_pass_one_ignored': True},
                        'binary_archive': manifest, 'binary_sha256': 'a' * 64}
            (directory / 'terminal.json').write_text(json.dumps(original))
            self.assertEqual(baseline(directory, 'b' * 40, source)[0], original)
            for key, value in [('passed', False), ('source_stable', False), ('expected_source', 'c' * 40),
                               ('native_test_budget_seconds', 900), ('binary_sha256', 'd' * 64)]:
                changed = dict(original, **{key: value})
                (directory / 'terminal.json').write_text(json.dumps(changed))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    baseline(directory, 'b' * 40, source)
            (directory / 'terminal.json').write_text(json.dumps(original))
            (directory / 'source-after.json').write_text('{}')
            with self.assertRaises(ValueError):
                baseline(directory, 'b' * 40, source)

    def test_exact_binary_roundtrip_and_noncanonical_part_refusal(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            original = directory / 'original'
            original.write_bytes(os.urandom(65536))
            manifest = retain_binary(original, directory / 'archive', sha(original), part_limit=16384)
            restored = directory / 'restored'
            self.assertEqual(restore(directory / 'archive', manifest, restored), sha(original))
            self.assertEqual(restored.read_bytes(), original.read_bytes())
            self.assertEqual(restored.stat().st_mode & 0o777, 0o700)
            changed = json.loads(json.dumps(manifest))
            changed['parts'][0]['path'] = '../outside'
            with self.assertRaisesRegex(ValueError, 'bounds or paths'):
                restore(directory / 'archive', changed, directory / 'refused')
            self.assertFalse((directory / 'refused').exists())
            part = directory / 'archive' / manifest['parts'][0]['path']
            raw = bytearray(part.read_bytes())
            raw[-1] ^= 1
            part.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'part identity mismatch'):
                restore(directory / 'archive', manifest, directory / 'corrupt')
            self.assertFalse((directory / 'corrupt').exists())


if __name__ == '__main__':
    unittest.main()
