#!/usr/bin/env python3
"""POSIX subprocess lifecycle fixtures, not Rust package qualification."""
from __future__ import annotations

import contextlib
import io
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import run_bounded_workspace_tests_v1 as runner


@unittest.skipUnless(os.name == 'posix', 'process-group contract is POSIX-only')
class ProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.cargo = self.root / 'cargo-fixture'
        self.output = io.StringIO()

    def run_fixture(self, code: str, timeout: int = 3):
        self.cargo.write_text('#!' + sys.executable + '\n' + code)
        self.cargo.chmod(0o700)
        with contextlib.redirect_stdout(self.output):
            return runner.run_package(self.root, str(self.cargo), 'fixture', timeout)

    def test_success(self) -> None:
        result = self.run_fixture('print("a real child process completed")\n')
        self.assertEqual(result.status, 'success')
        self.assertEqual(result.returncode, 0)
        self.assertIn('a real child process', self.output.getvalue())

    def test_failure_exit_is_preserved(self) -> None:
        result = self.run_fixture('import sys\nprint("failure")\nsys.exit(7)\n')
        self.assertEqual((result.status, result.returncode), ('failed', 7))

    def test_timeout_is_not_success(self) -> None:
        result = self.run_fixture('import time\ntime.sleep(60)\n', timeout=1)
        self.assertEqual(result.status, 'timeout')
        self.assertLess(result.elapsed_seconds, 8)

    def test_invalid_utf8_does_not_silently_kill_output_thread(self) -> None:
        result = self.run_fixture('import os\nos.write(1, b"bad byte: \\xff\\n")\n')
        self.assertEqual(result.status, 'success')
        self.assertIn('\\xff', self.output.getvalue())

    def test_successful_parent_with_inherited_pipe_is_rejected(self) -> None:
        result = self.run_fixture('''import os, signal, time
pid = os.fork()
if pid == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(60)
    os._exit(0)
os._exit(0)
''')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.status, 'failed')
        self.assertIn('process leak', self.output.getvalue())
        self.assertLess(result.elapsed_seconds, 8)

    def test_detached_output_but_same_group_child_is_rejected(self) -> None:
        result = self.run_fixture('''import os, signal, time
if os.fork() == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.close(1)
    os.close(2)
    time.sleep(60)
    os._exit(0)
time.sleep(0.1)
os._exit(0)
''')
        self.assertEqual(result.status, 'failed')
        self.assertEqual(result.returncode, 0)

    def test_output_exception_is_not_success(self) -> None:
        def failed_pump(stream, errors):
            stream.read()
            stream.close()
            errors.append(OSError('retained output mutant'))
        with mock.patch.object(runner, 'pump_output', failed_pump):
            result = self.run_fixture('print("hello")\n')
        self.assertEqual(result.status, 'failed')

    def test_terminate_kills_group_even_after_parent_has_exited(self) -> None:
        child_pid = self.root / 'child.pid'
        code = f'''import os, signal, time
if os.fork() == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    open({str(child_pid)!r}, 'w').write(str(os.getpid()))
    time.sleep(60)
    os._exit(0)
time.sleep(0.1)
os._exit(0)
'''
        proc = subprocess.Popen([sys.executable, '-c', code], start_new_session=True,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(runner.terminate_process_tree, proc)
        proc.wait(timeout=3)
        self.assertIsNotNone(proc.poll())
        runner.terminate_process_tree(proc)
        pid = int(child_pid.read_text())
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            stat = pathlib.Path(f'/proc/{pid}/stat')
            if not stat.exists() or stat.read_text().split()[2] == 'Z':
                break
            time.sleep(0.02)
        else:
            self.fail('SIGTERM-ignoring child remained alive after group cleanup')


if __name__ == '__main__':
    unittest.main(verbosity=2)
