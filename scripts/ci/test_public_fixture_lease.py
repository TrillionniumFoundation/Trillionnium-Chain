#!/usr/bin/env python3
"""Synthetic seal/kernel controls and real flock controls; no sudo or Host setup."""
from __future__ import annotations

import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import public_fixture_host_lease as lease
import public_host_ci_observation as observation
import run_from_zero_host as host
import run_public_fixture_native as fixture

ROOT_FILE = lease.root_file
ROOT_DIRECTORY = lease.root_directory


def sample(service='trnm-from-zero-123-1-fixture-55.service'):
    return {
        'parent_path': str(observation.PARENT),
        'parent': {'canonical_path': str(observation.PARENT), 'directory': True,
                   'symlink': False, 'uid': 0, 'gid': 0, 'mode': 0o755,
                   'device': 22, 'inode': 333},
        'limits': dict(observation.LIMITS), 'installed_unit_sha256': observation.UNIT_SHA256,
        'boot_id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'service': service,
        'thread_cgroup': '0::/trnmponpublic.slice/' + service,
        'thread_privileges': {'NoNewPrivs': '1', 'CapBnd': '0000000000000000'},
        'uid': 1001, 'gid': 1002, 'cwd': str(host.ROOT), 'read_errors': {},
        'counters': {'pids.current': '0', 'cgroup.events': 'populated 0\nfrozen 0'},
    }


class PublicFixtureLeaseControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name).resolve()
        self.run = self.folder / 'run'
        self.run.mkdir()
        self.receipts = self.folder / 'receipts'
        self.receipts.mkdir()
        self.controller = self.folder / 'creator-host'
        self.controller.mkdir()
        self.unit = self.run / observation.UNIT
        self.unit.write_bytes((lease.ROOT / 'config/systemd' / observation.UNIT).read_bytes())
        self.source = {'schema': 'trnm-ci-source-v1', 'kind': 'head',
                       'tested_commit': 'a' * 40, 'tested_tree': 'b' * 40,
                       'candidate': 'a' * 40, 'base': None, 'prospective_merge': None,
                       'tracked_worktree_verified': True,
                       'tests_executed_by_identity_check': False}
        (self.receipts / 'source.json').write_text(json.dumps(self.source))
        self.current = sample()
        self.command = ['python3', fixture.SCRIPT, '--out', str(self.folder / 'out')]
        patches = [
            patch.object(lease, 'RUN', self.run),
            patch.object(observation, 'RUNTIME_UNIT', self.unit),
            patch.object(lease.os, 'getuid', return_value=1001),
            patch.object(lease.os, 'getgid', return_value=1002),
            patch.object(lease.Path, 'cwd', return_value=lease.ROOT),
            patch.object(lease, 'verify_source', return_value=self.source),
            patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'CI': 'true',
                'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_JOB': 'fixture',
                'TRNM_EXPECTED_SOURCE_SHA': 'a' * 40, 'TRNM_CI_RECEIPT_DIR': str(self.receipts)}, clear=True),
        ]
        for replacement in patches:
            replacement.start()
            self.addCleanup(replacement.stop)
        # Only ownership is synthetic. Bounded reads, actual bytes, canonical
        # paths, inode/hash drift and exact source/job comparisons remain real.
        replacement = patch.object(lease, 'root_file', side_effect=lambda path, **_:
            lease.history.file_observation(path, lease.history.JSON_LIMIT)[0])
        replacement.start()
        self.addCleanup(replacement.stop)
        replacement = patch.object(lease, 'root_directory', side_effect=self.fixture_directory)
        replacement.start()
        self.addCleanup(replacement.stop)
        (self.controller / 'before-provision.json').write_text(json.dumps({
            'parent': None, 'installed_unit_sha256': None}))
        (self.controller / 'after-provision.json').write_text(json.dumps(self.current))
        (self.controller / 'unprovisioned-parent.json').write_text(json.dumps({
            'ActiveState': 'inactive', 'SubState': 'dead', 'FragmentPath': '',
            'DropInPaths': '', 'ControlGroup': '', 'Transient': 'no'}))
        self.properties = {
            'FragmentPath': str(self.unit), 'DropInPaths': '', 'ControlGroup': '/trnmponpublic.slice',
            'CPUQuotaPerSecUSec': '250ms', 'CPUQuotaPeriodUSec': '100ms',
            'MemoryMax': '2147483648', 'MemorySwapMax': '0', 'TasksMax': '256'}
        self.properties_path = self.controller / 'actual-systemd-parent.log'
        self.write_properties(self.properties_path)

    @staticmethod
    def fixture_directory(path):
        if not path.is_dir() or path.resolve(strict=True) != path:
            raise ValueError('synthetic root seal directory unavailable')

    def write_properties(self, path, values=None):
        path.write_text(''.join(f'{key}={value}\n' for key, value in (values or self.properties).items()))

    def simulated_setup(self, arguments, name):
        mirror, seal = lease.paths()
        if name == 'seal-parent-directory':
            self.assertEqual(arguments, ['sudo', '-n', 'mkdir', '--mode=0755', '--', str(seal.parent)])
            seal.parent.mkdir(mode=0o755)
        elif name == 'seal-parent-receipt':
            self.assertEqual(arguments, ['sudo', '-n', 'install', '-o', 'root', '-g', 'root',
                                         '-m', '0444', str(mirror), str(seal)])
            seal.write_bytes(mirror.read_bytes())
            seal.chmod(0o444)
        else:
            self.fail('unexpected privileged setup operation: ' + name)

    def seal(self):
        return lease.seal_after_provision(self.current, self.controller, self.command, self.simulated_setup)

    def validate(self, current=None):
        return lease.validate_for_reuse(current or self.current, self.properties_path)

    def test_actual_provision_seals_once_and_new_service_remains_distinct(self):
        created = self.seal()
        self.assertEqual(created['creator_service'], self.current['service'])
        current = sample('trnm-from-zero-123-1-fixture-66.service')
        reused = self.validate(current)
        self.assertEqual(created['parent_identity'], reused['parent_identity'])
        self.assertEqual(reused['creator_service'], created['creator_service'])
        self.assertEqual(reused['current_service'], current['service'])
        self.assertNotEqual(reused['current_service'], reused['creator_service'])
        self.assertEqual(observation.validate(current, inside=True, uid=1001, gid=1002,
                                              cwd=str(host.ROOT), reference=current), [])
        self.assertIn('OWNED_SERVICE_CHANGED', observation.validate(self.current, inside=True,
            uid=1001, gid=1002, cwd=str(host.ROOT), reference=current))
        with self.assertRaisesRegex(ValueError, 'FIXTURE_PARENT_SEAL_ALREADY_EXISTS'):
            self.seal()

    def test_existing_parent_without_root_seal_never_reuses_even_with_marker(self):
        with patch.dict(os.environ, {fixture.CHILD: '1'}), self.assertRaises((OSError, ValueError)):
            self.validate()
        mirror, seal = lease.paths()
        mirror.write_text(json.dumps({'schema': lease.SCHEMA, 'context': lease.context()}))
        seal.parent.mkdir()
        with self.assertRaises((OSError, ValueError)):
            self.validate()

    def test_original_absence_and_actual_provision_are_required_before_sealing(self):
        path = self.controller / 'before-provision.json'
        original = path.read_bytes()
        for before in ({'parent': self.current['parent'], 'installed_unit_sha256': None},
                       {'parent': None, 'installed_unit_sha256': 'already installed'}):
            path.write_text(json.dumps(before))
            with self.subTest(before=before), self.assertRaisesRegex(ValueError, 'ORIGINAL_ABSENCE_REQUIRED'):
                self.seal()
        path.write_bytes(original)
        (self.controller / 'after-provision.json').write_text(json.dumps(sample('wrong.service')))
        with self.assertRaisesRegex(ValueError, 'ACTUAL_PROVISION_REQUIRED'):
            self.seal()
        self.assertFalse(lease.paths()[0].exists())
        self.assertFalse(lease.paths()[1].exists())

    def test_stale_job_source_uid_and_receipt_root_cannot_reuse_sealed_parent(self):
        self.seal()
        mirror, original_seal = lease.paths()
        for key, value in (('GITHUB_JOB', 'other-job'), ('GITHUB_RUN_ID', '124'),
                           ('GITHUB_RUN_ATTEMPT', '2'), ('TRNM_EXPECTED_SOURCE_SHA', 'd' * 40)):
            with self.subTest(key=key), patch.dict(os.environ, {key: value}), \
                    self.assertRaises((OSError, ValueError)):
                self.validate()
        with patch.object(lease.os, 'getuid', return_value=1003), self.assertRaises(ValueError):
            self.validate()
        other = self.folder / 'other-receipts'
        other.mkdir()
        (other / 'source.json').write_bytes((self.receipts / 'source.json').read_bytes())
        (other / mirror.name).write_bytes(mirror.read_bytes())
        with patch.dict(os.environ, {'TRNM_CI_RECEIPT_DIR': str(other)}), \
                self.assertRaisesRegex(ValueError, 'LEASE_CONTEXT_CHANGED'):
            self.validate()
        self.assertEqual(lease.paths()[1], original_seal)
        changed = dict(self.source, tested_tree='d' * 40)
        (self.receipts / 'source.json').write_text(json.dumps(changed))
        with patch.object(lease, 'verify_source', return_value=changed), \
                self.assertRaisesRegex(ValueError, 'LEASE_CONTEXT_CHANGED'):
            self.validate()

    def test_parent_boot_inode_limits_unit_and_origin_drift_are_refused(self):
        self.seal()
        for change in ('inode', 'boot', 'limit', 'read-error'):
            current = copy.deepcopy(self.current)
            if change == 'inode':
                current['parent']['inode'] += 1
            elif change == 'boot':
                current['boot_id'] = 'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee'
            elif change == 'limit':
                current['limits']['cpu.max'] = '25001 100000'
            else:
                current['read_errors'] = {'pids.current': 'unavailable'}
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(current)
        self.unit.write_bytes(self.unit.read_bytes() + b'\n# changed unit\n')
        with self.assertRaisesRegex(ValueError, 'IDENTITY_CHANGED'):
            self.validate()

    def test_origin_receipt_cannot_be_replaced_by_same_json(self):
        self.seal()
        path = self.controller / 'after-provision.json'
        replacement = self.controller / 'replacement.json'
        replacement.write_bytes(path.read_bytes())
        replacement.replace(path)
        with self.assertRaisesRegex(ValueError, 'ORIGIN_CHANGED'):
            self.validate()

    def test_changed_systemd_properties_or_unreadable_children_refuse_reuse(self):
        self.seal()
        for counters in ({'pids.current': '1', 'cgroup.events': 'populated 1'},
                         {'pids.current': '0', 'cgroup.events': 'populated 1'},
                         {'pids.current': None, 'cgroup.events': 'populated 0'}, {}):
            current = dict(self.current, counters=counters)
            with self.subTest(counters=counters), self.assertRaisesRegex(ValueError, 'PRIOR_CHILDREN_NOT_EMPTY'):
                self.validate(current)
        for key, value in (('TasksMax', 'max'), ('CPUQuotaPerSecUSec', '500ms'),
                           ('DropInPaths', '/foreign.conf'), ('FragmentPath', '/foreign.slice')):
            self.write_properties(self.properties_path, dict(self.properties, **{key: value}))
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate()

    def test_sealed_mirror_tampering_truncation_duplicate_keys_and_symlinks_fail(self):
        self.seal()
        mirror, seal = lease.paths()
        original = mirror.read_bytes()
        for raw in (original + b' ', b'{', b'{"schema":"x","schema":"y"}',
                    original.replace(b'"host_readiness_only": true', b'"host_readiness_only": false')):
            mirror.write_bytes(raw)
            with self.subTest(raw=raw[:24]), self.assertRaises(ValueError):
                self.validate()
        mirror.write_bytes(original)
        mirror.unlink()
        mirror.symlink_to(seal)
        with self.assertRaises(ValueError):
            self.validate()

    def test_root_seal_and_directory_ownership_modes_and_types_are_strict(self):
        path = self.folder / 'ownership-control'
        path.write_text('{}')
        real_lstat = Path.lstat
        base = path.lstat()
        for mode, uid, gid in ((stat.S_IFREG | 0o644, 0, 0),
                                (stat.S_IFREG | 0o444, 1001, 0),
                                (stat.S_IFREG | 0o444, 0, 1001),
                                (stat.S_IFLNK | 0o777, 0, 0)):
            changed = SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid)
            with patch.object(Path, 'lstat', side_effect=lambda: changed), \
                    self.assertRaisesRegex(ValueError, 'ROOT_FILE_REQUIRED'):
                ROOT_FILE(path, sealed=True)
        for mode, uid in ((stat.S_IFDIR | 0o777, 0), (stat.S_IFDIR | 0o755, 1001),
                          (stat.S_IFREG | 0o755, 0)):
            changed = SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=0)
            with patch.object(Path, 'lstat', return_value=changed), \
                    patch.object(Path, 'resolve', return_value=path), \
                    self.assertRaisesRegex(ValueError, 'ROOT_SEAL_DIRECTORY_REQUIRED'):
                ROOT_DIRECTORY(path)

    def test_old_three_modes_refuse_existing_parent_before_preparation_or_mutation(self):
        existing = self.folder / 'existing-parent'
        existing.mkdir()
        for script in ('scripts/ci/run_from_zero_native.py', 'scripts/ci/run_w1_fresh_service_v1.py',
                       'scripts/ci/run_history_native.py'):
            command = ['python3', script, '--out', str(self.folder / 'out')]
            setup = Mock()
            with self.subTest(script=script), patch.object(host, 'PARENT', existing), \
                    patch.object(host, 'RUNTIME_UNIT', self.unit), \
                    patch.object(host, 'prepare_command') as prepare, \
                    patch.object(lease, 'validate_for_reuse') as reuse, \
                    self.assertRaisesRegex(ValueError, 'PARENT_ALREADY_PROVISIONED'):
                host.prepare_parent(command, Path(command[-1]), self.controller, {}, 'unused.service', setup)
            prepare.assert_not_called()
            reuse.assert_not_called()
            setup.assert_not_called()

    def test_new_mode_reuses_only_current_seal_and_creates_no_second_parent(self):
        self.seal()
        later = self.folder / 'later-host'
        later.mkdir()
        current = sample('trnm-from-zero-123-1-fixture-66.service')
        result = {}

        def setup(arguments, name):
            self.assertEqual(arguments[:3], ['systemctl', 'show', observation.UNIT])
            self.assertEqual(name, 'actual-systemd-parent')
            self.write_properties(later / 'actual-systemd-parent.log')

        with patch.object(host, 'RUNTIME_UNIT', self.unit), \
                patch.object(host, 'prepare_command', return_value={'exact_current_elf': True}), \
                patch.object(host, 'capture', return_value=current), \
                patch.object(lease, 'seal_after_provision') as seal:
            actual = host.prepare_parent(self.command, Path(self.command[-1]), later, result,
                                          current['service'], setup)
        seal.assert_not_called()
        self.assertEqual(actual, current)
        self.assertIs(result['parent_reused'], True)
        self.assertEqual(result['parent_lease']['current_service'], current['service'])

    def test_original_required_thread_contract_and_host_environment_are_preserved(self):
        workflow = (host.ROOT / '.github/workflows/trnm-required-baseline.yml').read_text()
        shell = (host.ROOT / 'scripts/ci/ci_job.sh').read_text()

        def check(workflow, shell):
            self.assertEqual(re.findall(r'^\s*RUST_TEST_THREADS:\s*(.+)$', workflow, re.MULTILINE), ['"1"'])
            self.assertIn('\nexport RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"\n', shell)

        check(workflow, shell)
        for changed_workflow, changed_shell in (
                (workflow.replace('RUST_TEST_THREADS: "1"', 'RUST_TEST_THREADS: "2"'), shell),
                (workflow, shell.replace('${RUST_TEST_THREADS:-1}', '${RUST_TEST_THREADS:-2}'))):
            with self.assertRaises(AssertionError):
                check(changed_workflow, changed_shell)
        self.assertIn('RUST_TEST_THREADS', host.ENVIRONMENT)
        self.assertNotIn(fixture.CHILD, host.ENVIRONMENT)
        self.assertNotIn('TRNM_PUBLIC_FIXTURE_CLI_BINARY', host.ENVIRONMENT)


class PublicFixtureLockControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name).resolve()
        self.path = self.folder / 'trnmponpublic-ci-owner.lock'
        self.context = {'source': 'synthetic locked source', 'receipts': '/first-receipts'}
        self.real_fstat = os.fstat
        self.real_lstat = Path.lstat
        self.real_flock = lease.fcntl.flock

    @staticmethod
    def root_metadata(info):
        return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino, st_mode=info.st_mode,
                               st_uid=0, st_gid=0, st_size=info.st_size)

    def fstat(self, fd):
        return self.root_metadata(self.real_fstat(fd))

    def lstat(self, path, *args, **kwargs):
        result = self.real_lstat(path, *args, **kwargs)
        return self.root_metadata(result) if path == self.path else result

    def creator(self, command, **kwargs):
        self.assertEqual(command[:6], ['sudo', '-n', '/usr/bin/python3', '-I', '-S', '-c'])
        self.assertEqual(command[-1], str(self.path))
        self.assertIn('os.O_CREAT | os.O_EXCL', command[6])
        self.assertNotIn('O_TRUNC', command[6])
        self.assertEqual(kwargs['timeout'], 30)
        # Execute only the bounded creator against this temporary fixture path;
        # ownership is simulated, never elevated or installed in /run.
        with patch('sys.argv', ['synthetic-lock-creator', str(self.path)]):
            exec(compile(command[6], '<synthetic lock creator>', 'exec'), {})
        return subprocess.CompletedProcess(command, 0)

    @contextmanager
    def simulated_root(self):
        with patch.object(lease, 'RUN', self.folder), \
                patch.object(lease, 'context', side_effect=lambda: dict(self.context)), \
                patch.object(lease.subprocess, 'run', side_effect=self.creator), \
                patch.object(lease.os, 'fstat', side_effect=self.fstat), \
                patch.object(Path, 'lstat', autospec=True, side_effect=self.lstat):
            yield

    def test_creator_sets_only_new_lock_mode_under_restrictive_child_umask(self):
        real_run = subprocess.run
        actual_uid, actual_gid = os.getuid(), os.getgid()

        for child_umask in (0o077, 0o777):
            def restrictive_creator(command, **kwargs):
                self.assertEqual(command[:6], ['sudo', '-n', '/usr/bin/python3', '-I', '-S', '-c'])
                self.assertEqual(command[-1], str(self.path))
                self.assertEqual(kwargs['timeout'], 30)
                # Run the unchanged creator as the actual test user. Only this
                # child's umask changes; no sudo or parent-process umask change.
                return real_run([sys.executable, *command[3:]], umask=child_umask, **kwargs)

            with self.subTest(child_umask=oct(child_umask)), self.simulated_root(), \
                    patch.object(lease.subprocess, 'run', side_effect=restrictive_creator):
                with lease.parent_lock():
                    created = self.real_lstat(self.path)
                    self.assertEqual(stat.S_IMODE(created.st_mode), 0o444)
                    self.assertEqual((created.st_uid, created.st_gid), (actual_uid, actual_gid))
                # O_EXCL's existing-file path must leave a wrong mode untouched.
                self.path.chmod(0o400)
                before = self.real_lstat(self.path)
                with self.assertRaisesRegex(ValueError, 'FIXTURE_PARENT_LOCK_OWNER'):
                    with lease.parent_lock():
                        self.fail('existing wrong mode must not be repaired')
                after = self.real_lstat(self.path)
                fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                          'st_size', 'st_mtime_ns', 'st_ctime_ns')
                self.assertEqual(tuple(getattr(after, key) for key in fields),
                                 tuple(getattr(before, key) for key in fields))
            self.path.unlink()

    def test_stable_lock_conflicts_across_receipt_roots_without_replacing_inode(self):
        with self.simulated_root():
            with lease.parent_lock():
                inode = self.real_lstat(self.path).st_ino
                self.context['receipts'] = '/different-receipts'
                with self.assertRaises(BlockingIOError):
                    with lease.parent_lock():
                        self.fail('a second receipt root must not own the same parent')
                self.assertEqual(self.real_lstat(self.path).st_ino, inode)
            with lease.parent_lock():
                self.assertEqual(self.real_lstat(self.path).st_ino, inode)
        self.assertEqual(self.path.read_bytes(), b'')

    def test_lock_rejects_symlink_wrong_mode_owner_or_size(self):
        with self.simulated_root():
            self.path.write_text('not-empty')
            self.path.chmod(0o444)
            with self.assertRaisesRegex(ValueError, 'LOCK_OWNER'):
                with lease.parent_lock():
                    self.fail('nonempty lock must refuse')
            self.path.unlink()
            self.path.touch(mode=0o644)
            with self.assertRaisesRegex(ValueError, 'LOCK_OWNER'):
                with lease.parent_lock():
                    self.fail('writable lock must refuse')
            self.path.chmod(0o444)
            info = self.root_metadata(self.real_lstat(self.path))
            info.st_uid = 1001
            with patch.object(lease.os, 'fstat', return_value=info), self.assertRaisesRegex(ValueError, 'LOCK_OWNER'):
                with lease.parent_lock():
                    self.fail('foreign owner must refuse')
            self.path.unlink()
            self.path.symlink_to(self.folder / 'unrelated')
            with self.assertRaises(OSError):
                with lease.parent_lock():
                    self.fail('symlink lock must refuse')

    def test_lock_inode_replacement_after_flock_is_not_accepted(self):
        def changed(fd, operation):
            self.real_flock(fd, operation)
            self.path.unlink()
            self.path.touch(mode=0o444)
            self.path.chmod(0o444)  # Keep non-inode fields equal under any caller umask.
        with self.simulated_root(), patch.object(lease.fcntl, 'flock', side_effect=changed), \
                self.assertRaisesRegex(ValueError, 'LOCK_CHANGED'):
            with lease.parent_lock():
                self.fail('changed lock inode must refuse')

    def test_context_must_be_valid_before_privileged_lock_creation(self):
        with patch.object(lease, 'context', side_effect=ValueError('wrong source/job')), \
                patch.object(lease.subprocess, 'run') as setup, self.assertRaises(ValueError):
            with lease.parent_lock():
                self.fail('invalid context must refuse')
        setup.assert_not_called()

    def test_outer_acquires_lock_before_any_absence_check_or_parent_setup(self):
        locked = False

        @contextmanager
        def lock():
            nonlocal locked
            locked = True
            try:
                yield
            finally:
                locked = False

        def owned(command):
            self.assertTrue(locked)
            return 0

        command = ['python3', fixture.SCRIPT, '--out', str(self.folder / 'out')]
        with patch.dict(os.environ, {'CI': 'true', 'GITHUB_ACTIONS': 'true'}), \
                patch.object(host.os, 'getuid', return_value=1001), \
                patch.object(host.Path, 'cwd', return_value=host.ROOT), \
                patch.object(lease, 'parent_lock', side_effect=lock), \
                patch.object(host, 'outer_owned', side_effect=owned) as run:
            self.assertEqual(host.outer(command), 0)
            run.assert_called_once_with(command)
        self.assertFalse(locked)


if __name__ == '__main__':
    unittest.main()
