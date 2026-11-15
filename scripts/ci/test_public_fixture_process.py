#!/usr/bin/env python3
"""Real harmless pidfd/owned-process controls; never provision a public Host."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import run_public_fixture_native as fixture


OWNER = '''import json, os, pathlib, sys
proc = pathlib.Path('/proc/self')
info = proc.stat()
fields = (proc / 'stat').read_text().rsplit(') ', 1)[1].split()
print(json.dumps({'process': {'pid': os.getpid(), 'parent_pid': int(fields[1]),
    'start_ticks': int(fields[19]), 'device': info.st_dev, 'inode': info.st_ino,
    'uid': info.st_uid, 'gid': info.st_gid}, 'proc_pid': int(os.readlink('/proc/self'))}), flush=True)
sys.stdin.buffer.read(1)
'''


class PublicFixtureProcessControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name).resolve()
        self.log = self.folder / 'native.log'
        self.identities = {}
        self.owners = []
        self.real_popen = subprocess.Popen

    @staticmethod
    def close_owner(child):
        if child.stdin is not None and not child.stdin.closed:
            child.stdin.close()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
        if child.stdout is not None:
            child.stdout.close()

    def owner(self, *, cwd=None):
        child = self.real_popen([sys.executable, '-c', OWNER], cwd=cwd,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)
        self.addCleanup(self.close_owner, child)
        readable, _, _ = select.select([child.stdout], [], [], 5)
        self.assertTrue(readable, 'harmless owner must publish its actual proc identity')
        row = json.loads(child.stdout.readline())
        self.assertEqual(row['process']['pid'], child.pid)
        self.identities[child.pid] = row['process']
        self.owners.append(child)
        return child, row

    def supervisors(self):
        return [{'role': role, 'process': self.owner()[1]['process']}
                for role in ('libtest', 'launcher')]

    def actual_identity(self, pid):
        # Some developer containers mount a /proc from the outer PID namespace.
        # The real owner supplies its own actual proc identity; pidfds, exit,
        # killpg and wait stay real. Production never uses this translation.
        return copy.deepcopy(self.identities[pid])

    def run_child(self, command, guards, *, timeout=0.1, cwd=None):
        with patch.object(fixture, 'process_identity', side_effect=self.actual_identity):
            return fixture.run_native_process(command, self.log, environment=dict(os.environ),
                supervisors=guards, timeout_seconds=timeout, cwd=cwd or self.folder)

    def assert_reaped_failure(self, result, command, guards, timeout, cwd=None):
        self.assertIs(result['started'], True)
        self.assertIs(result['reaped'], True)
        self.assertEqual(result['exit_code'], -signal.SIGKILL)
        self.assertEqual(result['cleanup_errors'], [])
        self.assertFalse(fixture.native_process_succeeded(
            result, command, timeout, guards, cwd or self.folder))
        with self.assertRaises(ChildProcessError):
            os.waitpid(result['pid'], os.WNOHANG)

    def test_architecture_original_timeout_kills_and_reaps_actual_owned_group(self):
        self.assertEqual(fixture.fixture(fixture.TARGET, fixture.SELECTOR)['timeout_seconds'], 120)
        guards = self.supervisors()
        command = [sys.executable, '-c', 'import time; time.sleep(30)']
        with patch.object(fixture.os, 'killpg', wraps=os.killpg) as kill:
            result = self.run_child(command, guards)
        self.assertIs(result['timed_out'], True)
        self.assertIn('TimeoutExpired', result['failure'])
        kill.assert_called_once_with(result['pid'], signal.SIGKILL)
        self.assert_reaped_failure(result, command, guards, 0.1)

    def test_either_original_owner_exit_kills_and_reaps_without_native_retry(self):
        for index, role in enumerate(('libtest', 'launcher')):
            with self.subTest(role=role):
                self.log = self.folder / (role + '.log')
                guards = self.supervisors()
                owner = self.owners[-2 + index]
                command = [sys.executable, '-c', 'import time; time.sleep(30)']

                def start(*args, **kwargs):
                    child = self.real_popen(*args, **kwargs)
                    owner.stdin.close()
                    owner.wait(timeout=5)
                    return child

                with patch.object(fixture.subprocess, 'Popen', side_effect=start) as spawn, \
                        patch.object(fixture.os, 'killpg', wraps=os.killpg) as kill:
                    result = self.run_child(command, guards, timeout=None)
                spawn.assert_called_once()
                kill.assert_called_once_with(result['pid'], signal.SIGKILL)
                self.assertEqual(result['supervisor_exit'], role)
                self.assertIs(result['timed_out'], False)
                self.assert_reaped_failure(result, command, guards, None)

    def test_live_owners_allow_one_complete_child_with_its_original_cwd(self):
        guards = self.supervisors()
        cwd = fixture.ROOT / 'trillionnium/crates/trnm-pon-node'
        command = [sys.executable, '-c', 'import pathlib; print(pathlib.Path.cwd())']
        result = self.run_child(command, guards, timeout=None, cwd=cwd)
        self.assertTrue(fixture.native_process_succeeded(result, command, None, guards, cwd))
        self.assertEqual(self.log.read_text().strip(), str(cwd))
        self.assertIsNone(result['timeout_seconds'])
        self.assertIsNone(result['supervisor_exit'])

    def test_actual_proc_starttime_is_read_and_foreign_parent_cwd_is_rejected(self):
        child, row = self.owner(cwd=self.folder)
        actual = fixture.process_identity(row['proc_pid'])
        expected = dict(row['process'], pid=row['proc_pid'])
        self.assertEqual(actual, expected)
        self.assertGreater(actual['start_ticks'], 0)
        with self.assertRaisesRegex(ValueError, 'PUBLIC_FIXTURE_ORIGINAL_NATIVE_CWD_REQUIRED'):
            fixture.parent_cwd(row['proc_pid'])
        self.assertIsNone(child.poll())

    def test_absent_or_failed_pidfd_refuses_before_any_child(self):
        guards = self.supervisors()
        command = [sys.executable, '-c', 'raise AssertionError("must not run")']
        with patch.object(fixture.os, 'pidfd_open'):
            del fixture.os.pidfd_open
            with patch.object(fixture.subprocess, 'Popen') as spawn:
                result = self.run_child(command, guards)
            spawn.assert_not_called()
        self.assertIn('PUBLIC_FIXTURE_PIDFD_REQUIRED', result['failure'])
        with patch.object(fixture.os, 'pidfd_open', side_effect=OSError('pidfd unavailable')), \
                patch.object(fixture.subprocess, 'Popen') as spawn:
            result = self.run_child(command, guards)
        spawn.assert_not_called()
        self.assertIs(result['started'], False)
        self.assertIs(result['supervisors_bound'], False)

    def test_pid_reuse_or_owner_exit_at_binding_refuses_before_child(self):
        guards = self.supervisors()
        command = [sys.executable, '-c', 'raise AssertionError("must not run")']
        original = guards[0]['process']
        changed = dict(original, start_ticks=original['start_ticks'] + 1)
        with patch.object(fixture, 'process_identity', side_effect=[original, changed]), \
                patch.object(fixture.subprocess, 'Popen') as spawn:
            result = fixture.run_native_process(command, self.log, environment=dict(os.environ),
                supervisors=guards, timeout_seconds=None, cwd=self.folder)
        spawn.assert_not_called()
        self.assertIn('PUBLIC_FIXTURE_SUPERVISOR_CHANGED', result['failure'])
        self.owners[0].stdin.close()
        self.owners[0].wait(timeout=5)
        with patch.object(fixture.subprocess, 'Popen') as spawn:
            result = self.run_child(command, guards)
        spawn.assert_not_called()
        self.assertIs(result['started'], False)
        self.assertIsNotNone(result['failure'])

    def test_cleanup_failures_and_unknown_exit_cannot_report_success(self):
        guards = self.supervisors()
        command = [sys.executable, '-c', 'never actually executed']
        child = Mock(pid=987654321, returncode=None)
        child.wait.side_effect = subprocess.TimeoutExpired(command, 5)
        # The two owner pidfds are real; failure to acquire the child pidfd
        # drives the production cleanup branch without creating any process.
        real_open = os.pidfd_open

        def open_pidfd(pid, flags):
            if pid == child.pid:
                raise OSError('synthetic child pidfd failure')
            return real_open(pid, flags)

        with patch.object(fixture.os, 'pidfd_open', side_effect=open_pidfd), \
                patch.object(fixture.subprocess, 'Popen', return_value=child), \
                patch.object(fixture.os, 'killpg', side_effect=PermissionError('synthetic refusal')):
            result = self.run_child(command, guards)
        self.assertIsNone(result['exit_code'])
        self.assertIs(result['reaped'], False)
        self.assertEqual(len(result['cleanup_errors']), 2)
        self.assertIn('PermissionError', result['cleanup_errors'][0])
        self.assertIn('TimeoutExpired', result['cleanup_errors'][1])
        self.assertFalse(fixture.native_process_succeeded(result, command, 0.1, guards, self.folder))

    def test_proc_directory_references_hold_actual_owners_and_close_on_all_exits(self):
        pids = tuple(self.owner()[1]['proc_pid'] for _ in range(2))
        real_open = os.open
        for fail in (False, True):
            descriptors = []

            def opened(*args, **kwargs):
                fd = real_open(*args, **kwargs)
                descriptors.append(fd)
                return fd

            def body():
                with fixture.hold_supervisor_directories(pids):
                    self.assertEqual(len(descriptors), 2)
                    for pid, fd in zip(pids, descriptors, strict=True):
                        identity = fixture.process_identity(pid)
                        observed = os.fstat(fd)
                        self.assertEqual((observed.st_dev, observed.st_ino),
                                         (identity['device'], identity['inode']))
                        self.assertFalse(os.get_inheritable(fd))
                    if fail:
                        raise ValueError('synthetic body failure')

            with self.subTest(fail=fail), patch.object(fixture.os, 'open', side_effect=opened):
                if fail:
                    with self.assertRaisesRegex(ValueError, 'synthetic body failure'):
                        body()
                else:
                    body()
            for fd in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_second_proc_directory_open_failure_releases_first_without_entering(self):
        pids = tuple(self.owner()[1]['proc_pid'] for _ in range(2))
        real_open = os.open
        descriptors = []
        entered = Mock()

        def opened(*args, **kwargs):
            if descriptors:
                raise PermissionError('synthetic second directory refusal')
            fd = real_open(*args, **kwargs)
            descriptors.append(fd)
            return fd

        with patch.object(fixture.os, 'open', side_effect=opened), \
                self.assertRaisesRegex(PermissionError, 'synthetic second directory refusal'):
            with fixture.hold_supervisor_directories(pids):
                entered()
        entered.assert_not_called()
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])

    def test_proc_directory_mismatch_refuses_and_releases_reference(self):
        pid = self.owner()[1]['proc_pid']
        original = fixture.process_identity(pid)
        changed = dict(original, inode=original['inode'] + 1)
        real_open = os.open
        descriptors = []
        entered = Mock()

        def opened(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            descriptors.append(fd)
            return fd

        with patch.object(fixture.os, 'open', side_effect=opened), \
                patch.object(fixture, 'process_identity', return_value=changed), \
                self.assertRaisesRegex(ValueError, 'PUBLIC_FIXTURE_SUPERVISOR_DIRECTORY_CHANGED'):
            with fixture.hold_supervisor_directories((pid,)):
                entered()
        entered.assert_not_called()
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError):
            os.fstat(descriptors[0])

    def test_every_supervisor_identity_field_remains_exact_and_mismatch_is_recorded(self):
        original = self.owner()[1]['process']
        with patch.object(fixture, 'process_identity', return_value=original):
            fixture.require_supervisor_identity(original)
            for key in original:
                changed = dict(original, **{key: original[key] + 1})
                with self.subTest(field=key), self.assertRaises(ValueError) as error:
                    fixture.require_supervisor_identity(changed)
                prefix, raw = str(error.exception).split(':', 1)
                self.assertEqual(prefix, 'PUBLIC_FIXTURE_SUPERVISOR_CHANGED')
                diagnostic = json.loads(raw)
                self.assertEqual(diagnostic, {'expected': changed, 'observed': original})
            with self.assertRaises(ValueError):
                fixture.require_supervisor_identity(dict(original, unexpected=True))

    def test_launch_holds_directory_references_through_final_binding_and_receipt(self):
        import run_from_zero_host as host
        out = self.folder / 'launch'
        binary = self.folder / 'unexecuted-elf'
        prepared = {'completed': True}
        command = ['python3', fixture.SCRIPT, '--out', str(out)]
        stages = []
        active = False
        real_write = fixture.write_new

        @fixture.contextlib.contextmanager
        def held(pids):
            nonlocal active
            self.assertEqual(pids, (123, os.getpid()))
            active = True
            stages.append('enter')
            try:
                yield
            finally:
                active = False
                stages.append('leave')

        def prepare(*args, **kwargs):
            self.assertTrue(active)
            stages.append('prepare')
            out.mkdir()
            return prepared

        def outer(argv):
            self.assertTrue(active)
            self.assertEqual(argv, command)
            stages.append('host')
            return 0

        def bind(observed, path):
            self.assertTrue(active)
            self.assertIs(observed, prepared)
            self.assertEqual(path, out)
            stages.append('bind')
            return {'synthetic': True}

        def write(path, value):
            self.assertTrue(active)
            stages.append('receipt')
            real_write(path, value)

        with patch.object(fixture, 'hold_supervisor_directories', side_effect=held), \
                patch.object(fixture, 'prepare', side_effect=prepare), \
                patch.object(host, 'outer', side_effect=outer), \
                patch.object(fixture.history, 'load_object',
                             return_value=({'passed': True, 'command_argv': command}, {})), \
                patch.object(fixture, 'bind_execution', side_effect=bind), \
                patch.object(fixture, 'write_new', side_effect=write):
            result = fixture.launch(out, binary, 123, target=fixture.TARGET,
                                    selector=fixture.SELECTOR, cli_binary=None)
        self.assertTrue(result['passed'])
        self.assertFalse(active)
        self.assertEqual(stages, ['enter', 'prepare', 'host', 'bind', 'receipt', 'leave'])


if __name__ == '__main__':
    unittest.main()
