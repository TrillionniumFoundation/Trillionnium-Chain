"""Darwin zombie-only EPERM: real process edges and explicit kernel-ABI controls.

Simulated census rows test fail-closed decisions, not a macOS execution claim.
The unchanged cleanup workflow also runs the real owner suites on macOS.
"""
import ctypes
import errno
import os
import signal
import subprocess
import sys
import types
import unittest
from unittest import mock

import bounded_process as owner


class DarwinCleanupTests(unittest.TestCase):
    def child(self):
        return types.SimpleNamespace(pid=43210, returncode=None)

    def status(self, child, code=None, pid=None):
        return types.SimpleNamespace(si_pid=child.pid if pid is None else pid,
                                     si_code=os.CLD_EXITED if code is None else code,
                                     si_status=0)

    def census(self, child, members, size=None, error=0):
        def call(kind, pgid, buffer, capacity):
            self.assertEqual((kind, pgid, capacity), (2, child.pid, 8))
            self.assertEqual(ctypes.get_errno(), 0)
            for index, pid in enumerate(members[:2]):
                buffer[index] = pid
            ctypes.set_errno(error)
            return len(members) * 4 if size is None else size
        return mock.Mock(side_effect=call)

    def check(self, child, status, members, *, size=None, error=0):
        census = self.census(child, members, size, error)
        with mock.patch.object(owner.sys, 'platform', 'darwin'), \
                mock.patch.object(owner.os, 'waitid', return_value=status), \
                mock.patch.object(ctypes, 'CDLL', return_value=types.SimpleNamespace(proc_listpids=census)) as load:
            result = owner._darwin_only_exited_leader(child)
        if census.called:
            load.assert_called_once_with('/usr/lib/libproc.dylib', use_errno=True)
            self.assertEqual(census.argtypes, [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int])
            self.assertIs(census.restype, ctypes.c_int)
        return result, census

    def test_exact_singleton_after_exit_is_the_only_positive_census(self):
        child = self.child()
        for code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED):
            with self.subTest(code=code):
                result, census = self.check(child, self.status(child, code), [child.pid])
                self.assertTrue(result)
                census.assert_called_once()

    def test_live_leader_never_loads_census(self):
        result, census = self.check(self.child(), None, [43210])
        self.assertFalse(result)
        census.assert_not_called()

    def test_reaped_leader_never_reuses_group_identity(self):
        child = self.child()
        child.returncode = 0
        result, census = self.check(child, self.status(child), [child.pid])
        self.assertFalse(result)
        census.assert_not_called()

    def test_wrong_wait_identity_or_nonexit_refuses_before_census(self):
        child = self.child()
        for status in (self.status(child, pid=child.pid + 1), self.status(child, code=-1)):
            with self.subTest(status=status):
                result, census = self.check(child, status, [child.pid])
                self.assertFalse(result)
                census.assert_not_called()

    def test_empty_error_short_or_full_buffers_are_never_evidence(self):
        child = self.child()
        for size in (-1, 0, 1, 3, 5, 8, 12):
            with self.subTest(size=size):
                self.assertFalse(self.check(child, self.status(child), [child.pid], size=size)[0])
        self.assertFalse(self.check(child, self.status(child), [child.pid], error=errno.EPERM)[0])

    def test_foreign_singleton_and_extra_member_are_rejected(self):
        child = self.child()
        for members in ([child.pid + 1], [0], [child.pid, child.pid + 1], [child.pid, child.pid]):
            with self.subTest(members=members):
                self.assertFalse(self.check(child, self.status(child), members)[0])

    def test_unavailable_library_symbol_or_wait_refuses(self):
        child = self.child()
        with mock.patch.object(owner.sys, 'platform', 'darwin'), \
                mock.patch.object(owner.os, 'waitid', return_value=self.status(child)), \
                mock.patch.object(ctypes, 'CDLL', side_effect=OSError('unavailable')):
            self.assertFalse(owner._darwin_only_exited_leader(child))
        with mock.patch.object(owner.sys, 'platform', 'darwin'), \
                mock.patch.object(owner.os, 'waitid', return_value=self.status(child)), \
                mock.patch.object(ctypes, 'CDLL', return_value=types.SimpleNamespace()):
            self.assertFalse(owner._darwin_only_exited_leader(child))
        with mock.patch.object(owner.sys, 'platform', 'darwin'), \
                mock.patch.object(owner.os, 'waitid', side_effect=ChildProcessError()):
            self.assertFalse(owner._darwin_only_exited_leader(child))

    def test_other_platforms_do_not_waive_permission_errors(self):
        with mock.patch.object(owner.sys, 'platform', 'linux'), \
                mock.patch.object(owner.os, 'waitid') as wait, \
                mock.patch.object(ctypes, 'CDLL') as load:
            self.assertFalse(owner._darwin_only_exited_leader(self.child()))
            wait.assert_not_called()
            load.assert_not_called()

    def exchange(self, code, payload=b'', *, accept=True):
        seen = []
        def deny(pid, sig):
            status = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            self.assertIsNotNone(status)
            self.assertEqual(status.si_pid, pid)
            self.assertEqual(sig, signal.SIGKILL)
            seen.append(pid)
            raise PermissionError(errno.EPERM, 'controlled kernel denial')
        def decide(child):
            self.assertEqual(seen, [child.pid])
            self.assertIsNone(child.returncode)
            return accept
        try:
            with mock.patch.object(owner.os, 'killpg', side_effect=deny), \
                    mock.patch.object(owner, '_darwin_only_exited_leader', side_effect=decide):
                return owner.run_bounded([sys.executable, '-I', '-S', '-c', code], payload)
        finally:
            self.assertEqual(len(seen), 1)
            with self.assertRaises(ChildProcessError):
                os.waitpid(seen[0], os.WNOHANG)

    def test_success_preserves_exact_output_and_reaps_after_census(self):
        result = self.exchange('import os;os.write(1,b"out");os.write(2,b"err")')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'out', b'err'))

    def test_nonzero_is_not_reclassified_as_success(self):
        result = self.exchange('import os;os.write(2,b"rejected");os._exit(17)')
        self.assertEqual((result.returncode, result.stderr), (17, b'rejected'))

    def test_incomplete_input_keeps_failure_and_bounded_diagnostics(self):
        with self.assertRaisesRegex(owner.ProcessFailure, '^NATIVE_STDIN_INCOMPLETE$') as raised:
            self.exchange('import os;os.close(0);os.write(1,b"claim");os.write(2,b"partial")',
                          b'x' * (2 * 1024 * 1024))
        failure = raised.exception
        self.assertEqual((failure.returncode, failure.stdout, failure.stderr), (0, b'claim', b'partial'))
        self.assertLess(failure.stdin_written, 2 * 1024 * 1024)

    def test_signal_exit_is_preserved(self):
        result = self.exchange('import os,signal;os.kill(os.getpid(),signal.SIGTERM)')
        self.assertEqual(result.returncode, -signal.SIGTERM)

    def test_unproven_permission_denial_cannot_return_success(self):
        with self.assertRaises(PermissionError):
            self.exchange('pass', accept=False)

    def test_real_singleton_platform_contract(self):
        child = subprocess.Popen([sys.executable, '-I', '-S', '-c', 'pass'], start_new_session=True)
        try:
            import time
            owner._wait_without_reaping(child, time.monotonic() + 5)
            self.assertEqual(owner._darwin_only_exited_leader(child), sys.platform == 'darwin')
        finally:
            child.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
