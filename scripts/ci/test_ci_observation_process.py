#!/usr/bin/env python3
"""Real process-group ownership regressions; no network or runtime qualification."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import ci_observation


class ObserverProcessOwnershipTests(unittest.TestCase):
    def _writer_case(self, exit_code, *, checked=False, timeout=False):
        with tempfile.TemporaryDirectory(prefix='trnm-ci-exit-owner-') as directory:
            root = Path(directory)
            ready = root / 'ready'
            parent = root / 'parent.py'
            parent.write_text(
                'import os, signal, sys, time\n'
                'from pathlib import Path\n'
                'ready = Path(sys.argv[1])\n'
                'pid = os.fork()\n'
                'if pid == 0:\n'
                '    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
                '    ready.write_text(str(os.getpid()))\n'
                '    print("retained-writer", flush=True)\n'
                '    deadline = time.monotonic() + 10\n'
                '    while time.monotonic() < deadline and not ready.with_name("stop").exists():\n'
                '        print("retained-writer", flush=True)\n'
                '        time.sleep(0.01)\n'
                '    ready.with_name("stopped").write_text("done")\n'
                '    os._exit(0)\n'
                'deadline = time.monotonic() + 5\n'
                'while not ready.exists():\n'
                '    if time.monotonic() >= deadline: os._exit(99)\n'
                '    time.sleep(0.001)\n'
                'print("leader-ready", flush=True)\n'
                'if sys.argv[3] == "timeout":\n'
                '    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\n'
                '    time.sleep(30)\n'
                'sys.exit(int(sys.argv[2]))\n')
            command = [sys.executable, '-S', str(parent), str(ready),
                       str(exit_code), 'timeout' if timeout else 'exit']
            log = root / 'observed.log'
            records = []
            actual_popen = subprocess.Popen
            children = []
            def capture(*args, **kwargs):
                child = actual_popen(*args, **kwargs)
                children.append(child)
                return child
            try:
                with mock.patch.object(ci_observation.subprocess, 'Popen', side_effect=capture):
                    if checked:
                        with self.assertRaisesRegex(RuntimeError, 'command exited 7'):
                            ci_observation.checked(command, log, records, timeout=2, cwd=root)
                        result = records[0]
                    else:
                        result = ci_observation.run(command, log,
                                                    timeout=1 if timeout else 5, cwd=root)
                self.assertTrue(ready.is_file(), 'fixture failed to start')
                self.assertEqual(result['exit_code'], 124 if timeout else exit_code)
                self.assertEqual(result['process_exit_code'], 0 if timeout else exit_code)
                self.assertIs(result['timed_out'], timeout)
                self.assertIn('leader-ready', log.read_text())
                time.sleep(0.05)
                before = log.read_bytes()
                time.sleep(0.15)
                self.assertEqual(log.read_bytes(), before, 'writer survived returned receipt')
            finally:
                # A cooperative fixture stop avoids signalling a numeric PID
                # or PGID after the tested implementation may have reaped it.
                ready.with_name('stop').write_text('stop')
                if children and ready.exists():
                    deadline = time.monotonic() + 1
                    while not ready.with_name('stopped').exists() and time.monotonic() < deadline:
                        time.sleep(0.01)

    def test_success_stops_inherited_log_writer(self):
        self._writer_case(0)

    def test_failure_stops_inherited_log_writer_and_keeps_exit(self):
        self._writer_case(7)

    def test_checked_failure_retains_receipt_and_stops_writer(self):
        self._writer_case(7, checked=True)

    def test_timeout_preserves_cooperative_exit_and_kills_writer(self):
        self._writer_case(0, timeout=True)

    def test_last_group_signal_precedes_first_reap(self):
        real_signal = os.killpg
        actual_popen = subprocess.Popen
        observed = []
        children = []
        def capture(*args, **kwargs):
            child = actual_popen(*args, **kwargs)
            children.append(child)
            return child
        def inspect(group, sig):
            observed.append((group, sig, children[0].returncode,
                             os.waitid(os.P_PID, group, os.WEXITED | os.WNOHANG | os.WNOWAIT)))
            return real_signal(group, sig)
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(ci_observation.subprocess, 'Popen', side_effect=capture), \
                    mock.patch.object(ci_observation.os, 'killpg', side_effect=inspect):
                result = ci_observation.run([sys.executable, '-S', '-c', 'pass'],
                                            Path(directory) / 'command.log', cwd=Path(directory))
            self.assertEqual(result['exit_code'], 0)
            self.assertEqual(len(observed), 1)
            group, sig, reaped, status = observed[0]
            self.assertEqual(group, children[0].pid)
            self.assertEqual(sig, signal.SIGKILL)
            self.assertIsNone(reaped)
            self.assertIsNotNone(status)
            self.assertEqual(status.si_pid, group)
            self.assertEqual(children[0].returncode, 0)

    def test_signal_exit_keeps_actual_status(self):
        with tempfile.TemporaryDirectory() as directory:
            result = ci_observation.run(
                [sys.executable, '-S', '-c', 'import os,signal; os.kill(os.getpid(),signal.SIGTERM)'],
                Path(directory) / 'signal.log', cwd=Path(directory))
            self.assertEqual(result['exit_code'], -signal.SIGTERM)
            self.assertEqual(result['process_exit_code'], -signal.SIGTERM)
            self.assertFalse(result['timed_out'])

    def test_non_timeout_wait_failure_is_not_relabelled(self):
        actual_popen = subprocess.Popen
        children = []
        def capture(*args, **kwargs):
            child = actual_popen(*args, **kwargs)
            children.append(child)
            return child
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(ci_observation.subprocess, 'Popen', side_effect=capture), \
                    mock.patch.object(ci_observation, '_wait_without_reaping',
                                      side_effect=ValueError('NATIVE_EXECUTOR_WAIT_STATUS')):
                with self.assertRaisesRegex(ValueError, '^NATIVE_EXECUTOR_WAIT_STATUS$'):
                    ci_observation.run([sys.executable, '-S', '-c', 'import time; time.sleep(30)'],
                                       Path(directory) / 'failed.log', cwd=Path(directory))
            self.assertEqual(children[0].returncode, -signal.SIGKILL)


if __name__ == '__main__':
    unittest.main(verbosity=2)
