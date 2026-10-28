#!/usr/bin/env python3
"""CI roster and command-owner controls; these do not execute or qualify Native."""
import unittest
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch
from run_history_effect_v6_native import HELPER, ROSTER, bounded, roster, suite_passed


class ExactNativeGate(unittest.TestCase):
    def test_exact_roster_retains_all_fifteen_and_the_process_helper(self):
        self.assertEqual(len(ROSTER), 16)
        self.assertEqual(roster('\n'.join(name + ': test' for name in ROSTER)), ROSTER)
        for changed in [ROSTER[:-1], ROSTER + [ROSTER[0]],
                        ROSTER[:-1] + ['store::history_effect_v6::tests::substitute']]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                roster('\n'.join(name + ': test' for name in changed))

    def test_zero_partial_failed_and_multiple_summaries_never_accept(self):
        prefix = 'running 16 tests\n' + ''.join(
            f'test {name} ... ' + ('ignored, fixture only' if name == HELPER else 'ok') + '\n'
            for name in ROSTER)
        valid = 'test result: ok. 15 passed; 0 failed; 1 ignored; 0 measured; 734 filtered out; finished in 300.00s'
        self.assertTrue(suite_passed(prefix + valid))
        for bad in [valid.replace('15 passed', '0 passed'), valid.replace('15 passed', '14 passed'),
                    valid.replace('0 failed', '1 failed'), valid.replace('1 ignored', '2 ignored'),
                    valid + '\n' + valid, 'test result: FAILED. 14 passed; 1 failed; 1 ignored;']:
            self.assertFalse(suite_passed(prefix + bad))
        self.assertFalse(suite_passed(valid))
        self.assertFalse(suite_passed(prefix.replace(ROSTER[-1], ROSTER[-2]) + valid))
        self.assertFalse(suite_passed(prefix.replace('running 16 tests', '') + valid))
        self.assertFalse(suite_passed(prefix + 'running 16 tests\n' + valid))

    def test_successful_leader_signals_owned_group_before_reaping(self):
        program = '''import os, time
reader, writer = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(reader)
    os.write(writer, b'1')
    while True:
        print('owned-writer-' + str(os.getpid()), flush=True)
        time.sleep(0.02)
os.close(writer)
os.read(reader, 1)
os._exit(0)
'''
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'run'
            with patch('run_history_effect_v6_native.os.statvfs',
                       return_value=SimpleNamespace(f_bavail=2 * 1024 ** 3, f_frsize=1)):
                result = bounded([sys.executable, '-c', program], out, 5, os.environ.copy())
            self.assertTrue(result['passed'], result)
            self.assertEqual(result['actual_wait4_status'], 0)
            self.assertTrue(result['final_owned_group_sigkill_sent'])
            self.assertTrue(result['cleanup_leader_terminal_observed'])
            self.assertFalse(result['descendant_quiescence_qualified'])
            before = (out / 'native.log').read_bytes()
            self.assertIn(b'owned-writer-', before)
            time.sleep(0.15)
            self.assertEqual((out / 'native.log').read_bytes(), before)

    def test_sampling_exception_still_kills_and_reaps_owned_child(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'run'
            with patch('run_history_effect_v6_native.os.statvfs', side_effect=[
                    SimpleNamespace(f_bavail=2 * 1024 ** 3, f_frsize=1), OSError('sampling fault')]):
                with self.assertRaisesRegex(OSError, 'sampling fault'):
                    bounded([sys.executable, '-c', 'import time; time.sleep(60)'],
                            out, 5, os.environ.copy())
            result = json.loads((out / 'terminal.json').read_text())
            self.assertFalse(result['passed'])
            self.assertEqual(result['termination_reason'], 'RUNNER_EXCEPTION')
            self.assertTrue(result['cleanup_leader_terminal_observed'])
            self.assertEqual(result['native_returncode'], -9)


if __name__ == '__main__':
    unittest.main()
