#!/usr/bin/env python3
"""Launcher counterexamples only; no mocked record qualifies a native run."""
import copy
import json
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import from_zero_native_host as host


class HostBoundaryTests(unittest.TestCase):
    def test_parent_counter_observation_reopens_the_supplied_parent_not_the_leaf(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            (parent / 'cpu.stat').write_text('usage_usec 100\nnr_throttled 7\n')
            leaf = parent / 'leaf'
            leaf.mkdir()
            (leaf / 'cpu.stat').write_text('usage_usec 90\nnr_throttled 0\n')
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                first = host.fixed_parent_cpu_observation(fd)
                self.assertEqual(first['cpu_stat'], 'usage_usec 100\nnr_throttled 7')
                (parent / 'cpu.stat').write_text('usage_usec 200\nnr_throttled 9\n')
                second = host.fixed_parent_cpu_observation(fd)
                self.assertEqual(second['cpu_stat'], 'usage_usec 200\nnr_throttled 9')
                self.assertIsNone(second['error'])
                self.assertFalse(second['observation_is_authority'])
                self.assertLessEqual(first['started_ns'], first['ended_ns'])
                self.assertLessEqual(first['ended_ns'], second['started_ns'])
            finally:
                os.close(fd)

    def test_parent_counter_read_errors_are_explicit_and_grant_no_authority(self):
        for failure in (PermissionError('counter denied'), ValueError('counter bound')):
            with self.subTest(failure=failure), patch.object(host, 'read_at', side_effect=failure):
                observed = host.fixed_parent_cpu_observation(123)
                self.assertIsNone(observed['cpu_stat'])
                self.assertIn(str(failure), observed['error'])
                self.assertFalse(observed['observation_is_authority'])

    def test_parent_diagnostic_log_is_not_an_attach_authority_field(self):
        authority = {'attached': True, 'owner': '123.1'}
        diagnostic = {'fixed_parent_before': {'cpu_stat': 'nr_throttled 7',
                                              'observation_is_authority': False}}
        completed = subprocess.CompletedProcess([], 0, json.dumps(authority).encode(),
                                                 json.dumps(diagnostic).encode())
        with tempfile.TemporaryDirectory() as raw:
            folder = Path(raw)
            with patch.object(host.subprocess, 'run', return_value=completed):
                result = host.root_call('attach', '123.1', 'a' * 24, [], 5,
                                        log_directory=folder)
            self.assertEqual(result, authority)
            self.assertEqual(json.loads((folder / 'host-attach.stderr').read_bytes()), diagnostic)
            self.assertNotIn('fixed_parent_before', result)

    def test_extra_attach_field_blocks_the_real_gated_child_before_exec(self):
        binary = self.owned_elf()
        original = Path.cwd()
        try:
            os.chdir(host.ROOT)
            with tempfile.TemporaryDirectory() as raw:
                def root(action, run_owner, nonce, extra, remaining, **kwargs):
                    if action == 'release':
                        return {'closed': True, 'forced_cleanup': False}
                    values = dict(zip(extra[::2], extra[1::2]))
                    leaf, _ = host.names(run_owner, nonce)
                    return {'attached': True, 'owner': run_owner, 'leaf': leaf,
                            'pid': int(values['--pid']), 'start_ticks': 1234,
                            'uid': os.getuid(), 'gid': os.getgid(), 'source': 'a' * 40,
                            'binary_sha256': host.sha(binary.read_bytes()),
                            'membership': '/' + host.FIXED_UNIT + '/' + leaf,
                            'fixed_parent_before': {'observation_is_authority': False}}
                with patch.object(host, 'root_call', side_effect=root), \
                     patch.object(host, 'process_identity', return_value={'start_ticks': 1234}):
                    result = host.run_host_child(self.command(binary), Path(raw) / 'attempt', 90,
                        run_owner='123.1', source='a' * 40,
                        binary_sha256=host.sha(binary.read_bytes()))
                self.assertEqual(result['host_scope']['error'], 'HOST_ATTACH_RECEIPT')
                self.assertFalse(result['host_scope']['complete'])
                self.assertNotEqual(result['exit_code'], 0)
                self.assertEqual((Path(raw) / 'attempt' / 'stdout').read_bytes(), b'')
        finally:
            os.chdir(original)

    def owned_elf(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        binary = Path(temporary.name) / 'owned-gate-control-elf'
        shutil.copyfile(Path('/usr/bin/python3').resolve(), binary)
        binary.chmod(0o700)
        return binary

    def command(self, binary):
        return [str(binary), host.HOST_TEST, '--exact', '--nocapture', '--test-threads=1']

    def test_only_original_confirmation_selector_and_ninety_seconds(self):
        with tempfile.TemporaryDirectory() as raw:
            binary = Path(raw) / 'actual'; binary.write_bytes(b'ELF parser fixture only')
            command = self.command(binary)
            self.assertEqual(host.native_command(command, 90), binary)
            for changed in ([str(binary), 'cargo', 'build'], command[:-1],
                            [command[0], 'other_test', *command[2:]],
                            [*command, '--ignored'], [command[0], *command[1:-1], '--test-threads=2']):
                with self.subTest(command=changed), self.assertRaisesRegex(ValueError, 'EXACT_NATIVE'):
                    host.native_command(changed, 90)
            for seconds in (True, 0, 89, 91, 900):
                with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                    host.native_command(command, seconds)
            link = Path(raw) / 'link'; link.symlink_to(binary)
            with self.assertRaisesRegex(ValueError, 'BINARY_PATH'):
                host.native_command(self.command(link), 90)

    def test_owner_and_nonce_cannot_select_foreign_scope(self):
        self.assertEqual(host.names('123.2', 'a' * 24),
                         ('trnmfromzero-123-2-' + 'a' * 24, 'from-zero-' + 'a' * 24 + '.json'))
        for owner in ('', '0.1', '1.0', '01.2', '../1.2', '1.2/foreign', '1.2.3'):
            with self.subTest(owner=owner), self.assertRaises((ValueError, RuntimeError)):
                host.names(owner, 'a' * 24)
        for nonce in ('', 'a' * 23, 'A' * 24, '../' + 'a' * 21):
            with self.subTest(nonce=nonce), self.assertRaises(ValueError):
                host.names('123.2', nonce)

    def test_long_history_exact_profile_cannot_widen_confirmation_or_select_other_work(self):
        with tempfile.TemporaryDirectory() as raw:
            binary = Path(raw) / 'actual'; binary.write_bytes(b'parser fixture only')
            history = [str(binary), host.HISTORY_TEST, '--exact', '--ignored', '--show-output', '--test-threads=1']
            self.assertEqual(host.native_command(history, 3600), binary)
            for changed in (history[:-1], [*history, '--nocapture'],
                            [history[0], host.HOST_TEST, *history[2:]],
                            [history[0], 'other_history', *history[2:]],
                            [history[0], *history[1:-1], '--test-threads=2']):
                with self.subTest(command=changed), self.assertRaisesRegex(ValueError, 'EXACT_NATIVE'):
                    host.native_command(changed, 3600)
            for seconds in (True, 90, 3599, 3601):
                with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                    host.native_command(history, seconds)
            with self.assertRaises(ValueError):
                host.native_command(self.command(binary), 3600)

    def test_root_deadline_comes_from_the_observed_exact_child_profile(self):
        history = ['/fixture', host.HISTORY_TEST, '--exact', '--ignored', '--show-output', '--test-threads=1']
        pressure = self.command(Path('/fixture'))
        with patch.object(host.time, 'monotonic_ns', return_value=10):
            host.validate_native_deadline(10 + 90_000_000_000, pressure)
            host.validate_native_deadline(10 + 3_600_000_000_000, history)
            for command, deadline in ((pressure, 10), (pressure, 11 + 90_000_000_000),
                                      (pressure, 10 + 3_600_000_000_000),
                                      (history, 11 + 3_600_000_000_000)):
                with self.subTest(command=command, deadline=deadline), self.assertRaisesRegex(ValueError, 'ABSOLUTE_DEADLINE'):
                    host.validate_native_deadline(deadline, command)

    def test_real_long_history_gate_binds_ignored_selector_and_original_arguments(self):
        with tempfile.TemporaryDirectory() as raw:
            binary = Path(raw) / 'actual'; binary.write_bytes(b'fixture')
            args = SimpleNamespace(elf_fd=7, sha256='a' * 64, deadline_ns=123456)
            leaf, _ = host.names('123.1', 'b' * 24)
            command = ['/usr/bin/python3', '-I', '-B', str(host.SCRIPT), 'exec-native',
                       '--gate-fd', '6', '--elf-fd', '7', '--sha256', args.sha256,
                       '--membership', '/' + host.FIXED_UNIT + '/' + leaf,
                       '--deadline-ns', str(args.deadline_ns), str(binary), host.HISTORY_TEST,
                       '--exact', '--ignored', '--show-output', '--test-threads=1']
            self.assertEqual(host.validate_gate_arguments(command, args, leaf), binary)
            for index, value in ((16, host.HOST_TEST), (18, '--include-ignored'),
                                 (19, '--nocapture'), (20, '--test-threads=2')):
                changed = command.copy(); changed[index] = value
                with self.subTest(index=index), self.assertRaises(ValueError):
                    host.validate_gate_arguments(changed, args, leaf)

    def test_birth_parent_credentials_cwd_and_own_process_group_are_all_bound(self):
        parent = dict(pid=100, parent=50, group=100, start_ticks=1000,
                      uids=[1001] * 4, gids=[1002] * 4, cgroup='/outside', cwd=str(host.ROOT))
        child = dict(parent, pid=101, parent=100, group=101, start_ticks=1001)
        host.validate_child(child, parent, 1001, 1002, 101, 100, 1001)
        for field, value in (('pid', 102), ('parent', 99), ('group', 100), ('start_ticks', 1002),
                             ('uids', [1001, 0, 1001, 1001]), ('gids', [0] * 4),
                             ('cwd', '/other'), ('cgroup', '/' + host.FIXED_UNIT + '/foreign')):
            changed = copy.deepcopy(child); changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                host.validate_child(changed, parent, 1001, 1002, 101, 100, 1001)
        with self.assertRaises(ValueError):
            host.validate_child(child, parent, 0, 1002, 101, 100, 1001)

    def test_real_gate_argv_not_just_caller_claims(self):
        with tempfile.TemporaryDirectory() as raw:
            binary = Path(raw) / 'actual'; binary.write_bytes(b'fixture')
            args = SimpleNamespace(elf_fd=7, sha256='a' * 64, deadline_ns=123456)
            leaf, _ = host.names('123.1', 'b' * 24)
            command = ['/usr/bin/python3', '-I', '-B', str(host.SCRIPT), 'exec-native',
                       '--gate-fd', '6', '--elf-fd', '7', '--sha256', args.sha256,
                       '--membership', '/' + host.FIXED_UNIT + '/' + leaf,
                       '--deadline-ns', str(args.deadline_ns), *self.command(binary)]
            self.assertEqual(host.validate_gate_arguments(command, args, leaf), binary)
            for index, value in ((0, '/tmp/python3'), (1, '-c'), (3, '/tmp/helper.py'),
                                 (4, 'attach'), (6, '7'), (8, '8'), (10, 'c' * 64),
                                 (12, '/foreign'), (14, '123457'), (16, 'other_test')):
                changed = command.copy(); changed[index] = value
                with self.subTest(index=index), self.assertRaises(ValueError):
                    host.validate_gate_arguments(changed, args, leaf)

    def test_expired_attach_does_not_open_authority_or_touch_cgroup(self):
        args = SimpleNamespace(owner='123.1', nonce='a' * 24, sha256='b' * 64,
                               source='c' * 40, deadline_ns=1)
        with patch.object(host, 'authority') as authority, self.assertRaisesRegex(ValueError, 'ABSOLUTE_DEADLINE'):
            host.attach(args)
        authority.assert_not_called()

    def test_root_without_original_unprivileged_sudo_owner_is_rejected(self):
        args = SimpleNamespace(owner='123.1')
        for values in ({}, {'SUDO_UID': '0', 'SUDO_GID': '0'}):
            with patch.dict(os.environ, values, clear=True), patch.object(os, 'geteuid', return_value=0), \
                 self.assertRaisesRegex(ValueError, 'UNPRIVILEGED_CALLER'):
                with host.authority(args):
                    self.fail('no root scope was authorised')

    def test_failed_attachment_reaps_actual_gated_child_without_native_exec(self):
        # Real fork/exec/wait4 of the Python gate. Attachment is deliberately
        # denied; no cgroup action or native test execution takes place.
        binary = self.owned_elf()
        original = Path.cwd()
        try:
            os.chdir(host.ROOT)
            with tempfile.TemporaryDirectory() as raw:
                path = Path(raw) / 'attempt'
                calls = []
                def deny(action, *args, **kwargs):
                    calls.append(action)
                    if action == 'attach':
                        raise ValueError('deliberately refused root attachment')
                    return {'closed': False, 'no_owned_leaf': True, 'forced_cleanup': False}
                # Birth metadata is a fixture; this control tests actual gate
                # reaping after denial, not Linux /proc or privileged admission.
                with patch.object(host, 'root_call', side_effect=deny), \
                     patch.object(host, 'process_identity', return_value={'start_ticks': 1234}):
                    result = host.run_host_child(self.command(binary), path, 90, run_owner='123.1',
                                                 source='a' * 40, binary_sha256=host.sha(binary.read_bytes()))
                self.assertEqual(calls, ['attach', 'release'])
                self.assertFalse(result['host_scope']['complete'])
                self.assertIsNotNone(result['host_scope']['error'])
                self.assertIsNotNone(result['host_scope']['cleanup_error'])
                self.assertNotEqual(result['exit_code'], 0)
                self.assertEqual((path / 'stdout').read_bytes(), b'')
                self.assertIsNotNone(result['cpu_ns'])  # actual gate process wait4, not mocked native CPU
        finally:
            os.chdir(original)

    def test_cli_cannot_choose_budget_parent_command_or_omit_owner(self):
        for args in (['attach'], ['attach', '--parent', '/foreign'],
                     ['release', '--owner', '123.1', '--nonce', 'a' * 24, '--command', '/bin/true']):
            result = subprocess.run([sys.executable, '-B', str(host.SCRIPT), *args],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)

    def test_late_terminal_and_forced_or_uncertain_cleanup_never_grant_completion(self):
        # Synthetic kernel/process observations exercise the finite owner state
        # machine. They are deliberately not native CPU or Host qualification.
        binary = self.owned_elf()
        for late, cleanup in ((True, 'natural'), (False, 'forced'), (False, 'unknown')):
            with self.subTest(late=late, cleanup=cleanup), tempfile.TemporaryDirectory() as raw:
                process = SimpleNamespace(pid=40001, returncode=None)
                usage = SimpleNamespace(ru_utime=0, ru_stime=0, ru_maxrss=0, ru_minflt=0,
                                        ru_majflt=0, ru_nvcsw=0, ru_nivcsw=0)
                tick = iter([0, 1, 2, 91_000_000_000 if late else 3, 92_000_000_000])
                def root(action, run_owner, nonce, extra, remaining, **kwargs):
                    if action == 'release':
                        if cleanup == 'unknown':
                            raise subprocess.TimeoutExpired('explicit root cleanup fixture', 20)
                        return {'closed': True, 'forced_cleanup': cleanup == 'forced'}
                    leaf, _ = host.names(run_owner, nonce)
                    return {'attached': True, 'owner': run_owner, 'leaf': leaf, 'pid': process.pid,
                            'start_ticks': 1234, 'uid': os.getuid(), 'gid': os.getgid(),
                            'source': 'a' * 40, 'binary_sha256': host.sha(binary.read_bytes()),
                            'membership': '/' + host.FIXED_UNIT + '/' + leaf}
                with patch.object(host.subprocess, 'Popen', return_value=process), \
                     patch.object(host, 'process_identity', return_value={'start_ticks': 1234}), \
                     patch.object(host, 'root_call', side_effect=root), \
                     patch.object(host.time, 'monotonic_ns', side_effect=lambda: next(tick)), \
                     patch.object(host.os, 'write', return_value=1), \
                     patch.object(host.os, 'wait4', return_value=(process.pid, 0, usage)):
                    result = host.run_host_child(self.command(binary), Path(raw) / 'attempt', 90,
                        run_owner='123.1', source='a' * 40, binary_sha256=host.sha(binary.read_bytes()))
                self.assertEqual(result['exit_code'], 0)  # retain the observed native code
                self.assertFalse(result['host_scope']['complete'])
                self.assertEqual(result['timed_out'], late)
                if not late:
                    self.assertIsNotNone(result['host_scope']['cleanup_error'])

    def test_sudo_attach_timeout_reaps_the_same_gate_and_preserves_uncertainty(self):
        binary = self.owned_elf()
        original = Path.cwd()
        try:
            os.chdir(host.ROOT)
            with tempfile.TemporaryDirectory() as raw:
                def timeout(action, *args, **kwargs):
                    if action == 'attach':
                        raise subprocess.TimeoutExpired('explicit attach fixture', 20)
                    # Simulate cleanup of a record created before failure; it
                    # cannot turn an unknown attachment into successful work.
                    return {'closed': True, 'forced_cleanup': False}
                with patch.object(host, 'root_call', side_effect=timeout), \
                     patch.object(host, 'process_identity', return_value={'start_ticks': 1234}):
                    result = host.run_host_child(self.command(binary), Path(raw) / 'attempt', 90,
                        run_owner='123.1', source='a' * 40, binary_sha256=host.sha(binary.read_bytes()))
                self.assertNotEqual(result['exit_code'], 0)
                self.assertFalse(result['host_scope']['complete'])
                self.assertIn('timed out', result['host_scope']['error'])
                self.assertTrue(result['host_scope']['closure']['closed'])
        finally:
            os.chdir(original)


if __name__ == '__main__':
    unittest.main()
