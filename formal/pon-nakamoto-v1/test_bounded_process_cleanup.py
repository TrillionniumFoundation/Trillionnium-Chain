"""Real POSIX group cleanup controls; no consensus or performance qualification."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

import bounded_process as owner


class OwnedGroupCleanupTests(unittest.TestCase):
    def command(self, code):
        return [sys.executable, '-I', '-S', '-c', code]

    def stopped(self, pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        # Grandchildren are adopted by the OS, not reaped by run_bounded.
        # A zombie is stopped; do not mistake it for a live CPU consumer.
        proc = Path(f'/proc/{pid}/stat')
        if Path('/proc').is_dir():
            try:
                return proc.read_text().rsplit(')', 1)[1].split()[0] == 'Z'
            except FileNotFoundError:
                return True
        result = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)],
                                capture_output=True, check=False, timeout=2)
        if result.returncode == 0:
            return result.stdout.lstrip().startswith(b'Z')
        if result.returncode == 1 and not result.stdout.strip():
            return True
        raise AssertionError('process-state probe failed: ' + repr(result.stderr))

    def assert_stopped(self, pid):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if self.stopped(pid):
                return
            time.sleep(.01)
        self.fail('owned descendant survived completed process cleanup')

    def silent_descendant(self, status, incomplete=False):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'descendant'
            code = f'''import os,time
pid=os.fork()
if pid==0:
    with open({str(marker)!r},'w') as stream: stream.write(str(os.getpid()))
    for fd in (0,1,2):
        try: os.close(fd)
        except OSError: pass
    time.sleep(20)
    os._exit(0)
os.close(0)
os.write(1,b'OUT')
os.write(2,b'ERR')
os._exit({status})
'''
            try:
                payload = b'x' * (2 * 1024 * 1024) if incomplete else b''
                if incomplete and status == 0:
                    with self.assertRaisesRegex(owner.ProcessFailure, '^NATIVE_STDIN_INCOMPLETE$') as raised:
                        owner.run_bounded(self.command(code), payload, timeout=3)
                    result = raised.exception
                    self.assertLess(result.stdin_written, len(payload))
                else:
                    result = owner.run_bounded(self.command(code), payload, timeout=3)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (status, b'OUT', b'ERR'))
                self.assert_stopped(int(marker.read_text()))
            finally:
                # Old-source negative runs must not leave their leaked fixture.
                if marker.exists():
                    try:
                        os.kill(int(marker.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_success_stops_descendant_with_closed_pipes(self):
        self.silent_descendant(0)

    def test_nonzero_stops_descendant_and_keeps_original_failure(self):
        self.silent_descendant(17)

    def test_incomplete_zero_exit_stops_descendant_and_keeps_diagnostics(self):
        self.silent_descendant(0, incomplete=True)

    def test_nonzero_incomplete_exchange_remains_original_rejection(self):
        self.silent_descendant(17, incomplete=True)

    def observe_signal_before_reap(self, incomplete):
        seen = []
        killpg = os.killpg

        def inspect(pid, sig):
            status = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            self.assertIsNotNone(status, 'leader must still be waitable before group signal')
            self.assertEqual(status.si_code, os.CLD_EXITED)
            self.assertEqual(status.si_status, 0)
            seen.append((pid, sig))
            return killpg(pid, sig)

        code = 'import os;os.close(0);os.write(1,b"exact");os._exit(0)'
        with mock.patch.object(owner.os, 'killpg', side_effect=inspect):
            if incomplete:
                with self.assertRaisesRegex(owner.ProcessFailure, '^NATIVE_STDIN_INCOMPLETE$'):
                    owner.run_bounded(self.command(code), b'x' * (2 * 1024 * 1024))
            else:
                result = owner.run_bounded(self.command(code), b'')
                self.assertEqual((result.returncode, result.stdout), (0, b'exact'))
        self.assertEqual(len(seen), 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(seen[0][0], 0)

    def test_success_keeps_leader_reserved_until_group_signal(self):
        self.observe_signal_before_reap(False)

    def test_incomplete_exchange_never_signals_a_reaped_leader(self):
        self.observe_signal_before_reap(True)

    def test_closed_streams_still_obey_original_exit_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'leader'
            code = f'''import os,time
with open({str(marker)!r},'w') as stream: stream.write(str(os.getpid()))
for fd in (0,1,2): os.close(fd)
time.sleep(20)
'''
            with self.assertRaisesRegex(owner.ProcessFailure, '^NATIVE_EXECUTOR_TIMEOUT$'):
                owner.run_bounded(self.command(code), b'', timeout=.2)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(marker.read_text()), 0)

    def test_signal_exit_keeps_negative_returncode(self):
        result = owner.run_bounded(self.command(
            'import os,signal;os.write(2,b"signal");os.kill(os.getpid(),signal.SIGTERM)'), b'')
        self.assertEqual((result.returncode, result.stderr), (-signal.SIGTERM, b'signal'))

    def test_exact_limits_and_large_input_still_keep_all_bytes(self):
        payload = bytes(range(256)) * 8192
        result = owner.run_bounded(self.command(
            'import sys;sys.stderr.buffer.write(b"e"*4096);sys.stderr.flush();'
            'sys.stdout.buffer.write(sys.stdin.buffer.read()[::-1])'), payload,
            stdout_limit=len(payload), stderr_limit=4096)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, payload[::-1], b'e' * 4096))

    def test_platform_without_nonreaping_wait_refuses_before_spawn(self):
        with mock.patch.object(owner, 'os', types.SimpleNamespace()), \
                mock.patch.object(owner.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(ValueError, '^NATIVE_PROCESS_PLATFORM$'):
                owner.run_bounded(self.command('pass'), b'')
            spawn.assert_not_called()

    def test_unrelated_process_group_survives_cleanup(self):
        other = subprocess.Popen(self.command('import time;time.sleep(20)'),
                                 start_new_session=True)
        try:
            result = owner.run_bounded(self.command('pass'), b'')
            self.assertEqual(result.returncode, 0)
            self.assertIsNone(other.poll())
        finally:
            other.kill()
            other.wait(timeout=2)

    def test_caps_preserve_bounded_failure_after_group_cleanup(self):
        for fd, cap, label in [(1, 'stdout_limit', 'STDOUT'), (2, 'stderr_limit', 'STDERR')]:
            with self.subTest(fd=fd):
                with self.assertRaisesRegex(owner.ProcessFailure, '^NATIVE_' + label + '_LIMIT$') as raised:
                    owner.run_bounded(self.command(f'import os;os.write({fd},b"x"*65536)'),
                                      b'', **{cap: 4096})
                failure = raised.exception
                self.assertEqual(getattr(failure, label.lower()), b'x' * 4096)
                self.assertTrue(getattr(failure, label.lower() + '_truncated'))


if __name__ == '__main__':
    unittest.main()
