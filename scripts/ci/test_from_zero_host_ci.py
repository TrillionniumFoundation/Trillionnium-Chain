#!/usr/bin/env python3
"""Refusal and harmless process controls; never provision sysfs or execute native CI."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import public_host_ci_observation as observation
import run_from_zero_host as host
import run_history_native as history
import run_public_fixture_native as architecture
from test_architecture_host_ci import ArchitectureAdapterControls
from test_public_fixture_process import PublicFixtureProcessControls
from test_public_fixture_lease import PublicFixtureLeaseControls, PublicFixtureLockControls
from check_ci_contract import (HISTORY_EXPECTED_SOURCE, HISTORY_HOST_STEPS,
                               check_from_zero_host_call, check_from_zero_host_callsites,
                               check_history_host_call)


def synthetic_sample():
    return {
        'parent_path': str(observation.PARENT),
        'parent': {'canonical_path': str(observation.PARENT), 'directory': True,
                   'symlink': False, 'uid': 0, 'gid': 0, 'mode': 0o755,
                   'device': 22, 'inode': 333},
        'limits': dict(observation.LIMITS), 'installed_unit_sha256': observation.UNIT_SHA256,
        'boot_id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
        'service': 'trnm-from-zero-123-1-cost-55.service',
        'thread_cgroup': '0::/trnmponpublic.slice/trnm-from-zero-123-1-cost-55.service',
        'thread_privileges': {'NoNewPrivs': '1', 'CapBnd': '0000000000000000'},
        'uid': 1001, 'gid': 1001, 'cwd': str(host.ROOT), 'read_errors': {},
    }


def errors(value, reference=None):
    return observation.validate(value, inside=True, uid=1001, gid=1001,
                                cwd=str(host.ROOT), reference=reference)


class OriginalHostControls(unittest.TestCase):
    @staticmethod
    def pristine_properties():
        return {'Id': observation.UNIT, 'LoadState': 'loaded',
                'ActiveState': 'inactive', 'SubState': 'dead', 'FragmentPath': '',
                'SourcePath': '', 'DropInPaths': '', 'ControlGroup': '',
                'Transient': 'no', 'Job': ''}

    def test_inactive_implicit_parent_is_not_a_resource_owner(self):
        for state in ('loaded', 'not-found'):
            for job in ('', '0'):
                values = self.pristine_properties()
                values.update(LoadState=state, Job=job)
                raw = ''.join(f'{key}={value}\n' for key, value in values.items())
                self.assertEqual(host.validate_unprovisioned_parent(raw), values)

    def test_existing_parent_configuration_and_activity_are_refused(self):
        for key, value in (('Id', 'foreign.slice'), ('LoadState', 'masked'),
                           ('ActiveState', 'active'), ('SubState', 'running'),
                           ('FragmentPath', '/etc/systemd/system/owned.slice'),
                           ('SourcePath', '/etc/init.d/owned'), ('DropInPaths', '/owned.conf'),
                           ('ControlGroup', '/trnmponpublic.slice'),
                           ('Transient', 'yes'), ('Job', '42')):
            values = self.pristine_properties()
            values[key] = value
            raw = ''.join(f'{name}={content}\n' for name, content in values.items())
            with self.subTest(key=key), self.assertRaises(ValueError):
                host.validate_unprovisioned_parent(raw)

    def test_parent_property_output_must_be_complete_and_unambiguous(self):
        raw = ''.join(f'{key}={value}\n' for key, value in self.pristine_properties().items())
        for bad in ('', raw + 'Id=' + observation.UNIT + '\n', raw + 'Unknown=\n',
                    raw.replace('Job=\n', ''), raw + '\x00', raw + '\n',
                    raw + ('x' * 65536)):
            with self.subTest(length=len(bad)), self.assertRaises(ValueError):
                host.validate_unprovisioned_parent(bad)

    def test_original_unit_bytes_and_finite_limits(self):
        raw = (host.ROOT / 'config/systemd/trnmponpublic.slice').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), observation.UNIT_SHA256)
        self.assertEqual(errors(synthetic_sample()), [])
        for key, wrong in (('cpu.max', '400000 100000'), ('cpu.max.burst', '1'),
                           ('memory.max', '17179869184'), ('memory.swap.max', 'max'),
                           ('pids.max', 'max')):
            sample = synthetic_sample()
            sample['limits'][key] = wrong
            with self.subTest(key=key):
                self.assertIn('ORIGINAL_FINITE_LIMITS', errors(sample))

    def test_parent_identity_refuses_absent_foreign_symlink_and_writable(self):
        for patch_value in ({'uid': 1001}, {'symlink': True}, {'mode': 0o775},
                            {'directory': False}, {'canonical_path': '/sys/fs/cgroup/other.slice'}):
            sample = synthetic_sample()
            sample['parent'].update(patch_value)
            with self.subTest(value=patch_value):
                self.assertIn('FIXED_PARENT_IDENTITY', errors(sample))
        sample['parent'] = None
        self.assertIn('FIXED_PARENT_IDENTITY', errors(sample))

    def test_current_thread_must_belong_to_this_service(self):
        for group in ('0::/', '0::/user.slice/runner.service',
                      '0::/trnmponpublic.slice/other.service',
                      synthetic_sample()['thread_cgroup'] + '-suffix',
                      synthetic_sample()['thread_cgroup'] + '/..',
                      synthetic_sample()['thread_cgroup'] + '\n0::/other.slice'):
            sample = synthetic_sample()
            sample['thread_cgroup'] = group
            with self.subTest(group=group):
                self.assertIn('ACTUAL_SERVICE_MEMBERSHIP', errors(sample))

    def test_changed_boot_parent_caps_or_unit_are_not_same_host(self):
        original = synthetic_sample()
        for name in ('parent', 'boot_id', 'limits', 'installed_unit_sha256'):
            changed = copy.deepcopy(original)
            if name == 'parent':
                changed[name]['inode'] += 1
            elif name == 'limits':
                changed[name]['cpu.max'] = '20000 100000'
            else:
                changed[name] = 'changed'
            with self.subTest(name=name):
                self.assertIn('HOST_CONTEXT_CHANGED:' + name, errors(changed, original))

    def test_observation_failure_or_wrong_caller_cannot_pass(self):
        sample = synthetic_sample()
        sample['read_errors'] = {'cpu.stat': 'unavailable'}
        self.assertIn('KERNEL_OBSERVATION_UNAVAILABLE', errors(sample))
        for field, value in (('uid', 0), ('gid', 0), ('cwd', '/tmp')):
            sample = synthetic_sample()
            sample[field] = value
            self.assertIn('ORIGINAL_CALLER_CONTEXT', errors(sample))

    def test_self_consistent_other_service_and_privilege_changes_refused(self):
        original = synthetic_sample()
        sample = copy.deepcopy(original)
        sample['service'] = 'other.service'
        sample['thread_cgroup'] = '0::/trnmponpublic.slice/other.service'
        self.assertIn('OWNED_SERVICE_CHANGED', errors(sample, original))
        for changed in ({'NoNewPrivs': '0', 'CapBnd': '0000000000000000'},
                        {'NoNewPrivs': '1', 'CapBnd': '00000000ffffffff'}, {}):
            sample = synthetic_sample()
            sample['thread_privileges'] = changed
            self.assertIn('UNPRIVILEGED_SERVICE_REQUIRED', errors(sample))

    def test_only_original_from_zero_argv_can_be_wrapped(self):
        valid = ['python3', 'scripts/ci/run_from_zero_native.py', '--out', '/tmp/original-output']
        self.assertEqual(host.validate_command(valid), Path(valid[-1]))
        changes = [valid + ['--skip'], ['bash', 'scripts/ci/ci_job.sh', 'protocol-contract'],
                   [*valid[:2], '--other', valid[3]], [*valid[:3], 'relative'],
                   [*valid[:3], str(host.ROOT / 'out')]]
        for command in changes:
            with self.subTest(command=command), self.assertRaises(ValueError):
                host.validate_command(command)

    def test_architecture_mode_is_exact_existing_elf_only_and_not_a_general_runner(self):
        command = ['python3', architecture.SCRIPT, '--out', '/tmp/architecture-output']
        self.assertEqual(host.validate_command(command), Path(command[-1]))
        for invalid in (command + ['--skip'], command + ['--launch'],
                        ['python3', architecture.SCRIPT, '--binary', '/tmp/arbitrary']):
            with self.subTest(command=invalid), self.assertRaises(ValueError):
                host.validate_command(invalid)
        with patch.object(host, 'prepare_native_build') as build, \
                patch.object(architecture, 'validate_preparation', return_value={'current_elf': True}) as bind:
            self.assertEqual(host.prepare_command(command, Path(command[-1]), Path('/tmp/receipts')),
                             {'current_elf': True})
            build.assert_not_called()
            bind.assert_called_once_with(Path(command[-1]))

    def test_architecture_child_marker_cannot_substitute_for_actual_host(self):
        sample = synthetic_sample()
        sample['thread_cgroup'] = '0::/user.slice/runner.service'
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(host, 'capture', return_value=sample), \
                patch.dict(os.environ, {architecture.CHILD: '1'}), \
                patch.object(host.subprocess, 'run') as run:
            self.assertEqual(host.inside(Path(temporary), sample['service'], 1001, 1001,
                ['python3', architecture.SCRIPT, '--out', '/tmp/architecture-output']), 1)
            run.assert_not_called()
        self.assertNotIn(architecture.CHILD, host.ENVIRONMENT)

    def test_transient_service_preserves_command_and_unprivileged_identity(self):
        command = ['python3', 'scripts/ci/run_from_zero_native.py', '--out', '/tmp/out']
        argv = host.service_command('trnm-from-zero-1-1-cost-55.service', Path('/tmp/receipt'),
                                    command, 1001, 1002, {'PATH': '/original/bin',
                                    'CARGO_BUILD_JOBS': '2', 'RUSTUP_TOOLCHAIN': '1.95.0',
                                    'OPENSSL_DIR': '/original/pinned-provider', 'OPENSSL_STATIC': '1',
                                    'OPENSSL_CONF': '/dev/null',
                                    'OPENSSL_MODULES': '/original/pinned-provider/lib/ossl-modules',
                                    'TRNM_PQ_OPENSSL': '/original/pinned-provider/bin/openssl',
                                    'TRNM_PQ_OPENSSL_SHA256': 'a' * 64,
                                    'TRNM_PQ_OPENSSL_VERSION': '3.5.9',
                                    'GITHUB_TOKEN': 'synthetic-not-a-token'})
        self.assertEqual(argv[-4:], command)
        for item in ('--slice=trnmponpublic.slice', '--uid=1001', '--gid=1002',
                     '--property=Delegate=no', '--property=NoNewPrivileges=yes',
                     '--property=CapabilityBoundingSet=', '--property=KillMode=control-group',
                     '--setenv=PATH=/original/bin', '--setenv=CARGO_BUILD_JOBS=2',
                     '--setenv=RUSTUP_TOOLCHAIN=1.95.0',
                     '--setenv=OPENSSL_DIR=/original/pinned-provider', '--setenv=OPENSSL_STATIC=1',
                     '--setenv=OPENSSL_CONF=/dev/null',
                     '--setenv=OPENSSL_MODULES=/original/pinned-provider/lib/ossl-modules',
                     '--setenv=TRNM_PQ_OPENSSL=/original/pinned-provider/bin/openssl',
                     '--setenv=TRNM_PQ_OPENSSL_SHA256=' + 'a' * 64,
                     '--setenv=TRNM_PQ_OPENSSL_VERSION=3.5.9'):
            self.assertIn(item, argv)
        self.assertFalse(any('GITHUB_TOKEN' in item for item in argv))
        self.assertFalse(any('CPUQuota=' in item or 'MemoryMax=' in item for item in argv))

    def test_preparation_uses_exact_build_only_and_retains_original_build_budget(self):
        expected = ['cargo', 'test', '--locked', '--release', '--manifest-path',
                    'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--test',
                    'public_v3_from_zero', '--no-run', '--message-format=json']
        self.assertEqual(host.native.native_build_command(), expected)
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            binary = folder / 'compiler-produced-test'
            binary.write_bytes(b'public test fixture, never executed')
            source = {'commit': 'a' * 40, 'tree': 'b' * 40}

            def build(command, output, deadline):
                self.assertEqual(command, expected)
                self.assertEqual(deadline, 900)
                output.mkdir()
                (output / 'stdout').write_text(json.dumps({
                    'reason': 'compiler-artifact', 'target': {'name': host.native.TARGET},
                    'profile': {'test': True}, 'executable': str(binary)}) + '\n')
                return {'exit_code': 0, 'timed_out': False, 'command': command}

            with patch.object(host.native, 'source_identity', return_value=source), \
                    patch.object(host.native, 'run_child', side_effect=build) as run:
                receipt = host.prepare_native_build(folder)
            run.assert_called_once()
            self.assertIs(receipt['completed'], True)
            self.assertIs(receipt['native_tests_executed'], False)
            self.assertIs(receipt['service_resource_observation'], False)
            self.assertEqual(receipt['binary_sha256'], hashlib.sha256(binary.read_bytes()).hexdigest())
            self.assertEqual(json.loads((folder / 'prepare-build.json').read_text()), receipt)

    def test_failed_and_timed_out_preparation_cannot_borrow_a_binary(self):
        for process in ({'exit_code': 1, 'timed_out': False},
                        {'exit_code': 0, 'timed_out': True}):
            with self.subTest(process=process), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(host.native, 'source_identity', return_value={'commit': 'a' * 40}), \
                    patch.object(host.native, 'run_child', return_value=process), \
                    patch.object(host.native, 'select_binary') as select:
                folder = Path(temporary)
                with self.assertRaisesRegex(ValueError, 'EXACT_NATIVE_PREPARATION_FAILED'):
                    host.prepare_native_build(folder)
                select.assert_not_called()
                saved = json.loads((folder / 'prepare-build.json').read_text())
                self.assertIs(saved['completed'], False)
                self.assertEqual(saved['process'], process)

    def test_preparation_signal_retains_incomplete_receipt(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(host.native, 'source_identity', return_value={'commit': 'a' * 40}), \
                patch.object(host.native, 'run_child', side_effect=host.HostSignal(15)):
            with self.assertRaises(host.HostSignal):
                host.prepare_native_build(Path(temporary))
            saved = json.loads((Path(temporary) / 'prepare-build.json').read_text())
            self.assertIs(saved['completed'], False)
            self.assertEqual(saved['failure_type'], 'HostSignal')

    def test_preparation_source_drift_refuses_and_keeps_both_identities(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / 'prepare-build').mkdir()
            (folder / 'prepare-build/stdout').write_text('')
            binary = folder / 'compiler-produced-test'
            binary.write_bytes(b'synthetic fixture')
            with patch.object(host.native, 'source_identity', side_effect=[
                    {'commit': 'a' * 40}, {'commit': 'b' * 40}]), \
                    patch.object(host.native, 'run_child', return_value={
                        'exit_code': 0, 'timed_out': False}), \
                    patch.object(host.native, 'select_binary', return_value=binary):
                with self.assertRaisesRegex(ValueError, 'NATIVE_PREPARATION_SOURCE_CHANGED'):
                    host.prepare_native_build(folder)
            saved = json.loads((folder / 'prepare-build.json').read_text())
            self.assertIs(saved['completed'], False)
            self.assertNotEqual(saved['source_before'], saved['source_after'])

    def test_prepared_execution_binds_source_binary_and_original_acceptance(self):
        source = {'commit': 'a' * 40, 'tree': 'b' * 40}
        prepared = {'completed': True, 'source_before': source, 'source_after': source,
                    'binary_sha256': 'c' * 64}
        original = {'schema': 'trnm-from-zero-native-execution-v3',
                    'source_before': source, 'source_after': source,
                    'binary_sha256_before': 'c' * 64, 'binary_sha256_after': 'c' * 64,
                    'passed': True, 'all_named_tests_passed': True, 'source_recompiled': True,
                    'runs': [{'name': name} for name in host.native.TESTS]}
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            path = folder / 'manifest.json'
            path.write_text(json.dumps(original))
            self.assertEqual(host.bind_prepared_execution(prepared, folder)['binary_sha256'], 'c' * 64)
            for key, value in (('source_after', {'commit': 'd' * 40}),
                               ('binary_sha256_before', 'd' * 64),
                               ('binary_sha256_after', 'd' * 64),
                               ('passed', False), ('all_named_tests_passed', False),
                               ('source_recompiled', False), ('runs', original['runs'][:-1])):
                changed = copy.deepcopy(original)
                changed[key] = value
                path.write_text(json.dumps(changed))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    host.bind_prepared_execution(prepared, folder)
            path.write_text(json.dumps(original))
            incomplete = dict(prepared, completed=False)
            with self.assertRaisesRegex(ValueError, 'NATIVE_PREPARATION_INCOMPLETE'):
                host.bind_prepared_execution(incomplete, folder)

    def test_local_invocation_never_runs_a_host_command(self):
        with patch.dict(host.os.environ, {'CI': 'true', 'GITHUB_ACTIONS': 'false'}, clear=True), \
                patch.object(host.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'HOSTED_CI_ONLY_NO_LOCAL_PROVISION'):
                host.outer(['python3', 'scripts/ci/run_from_zero_native.py', '--out', '/tmp/out'])
            run.assert_not_called()

    def test_invalid_inner_host_never_runs_native_child(self):
        sample = synthetic_sample()
        sample['limits']['cpu.max'] = 'max 100000'
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(host, 'capture', return_value=sample), \
                patch.object(host.subprocess, 'run') as run:
            result = host.inside(Path(temporary), sample['service'], 1001, 1001,
                                 ['python3', 'scripts/ci/run_from_zero_native.py', '--out', '/tmp/out'])
            self.assertEqual(result, 1)
            run.assert_not_called()
            saved = json.loads((Path(temporary) / 'child-result.json').read_text())
            self.assertIsNone(saved['native_child_exit'])
            self.assertIn('ORIGINAL_FINITE_LIMITS', saved['host_errors'])

    def test_native_failure_and_late_signal_remain_nonzero(self):
        sample = synthetic_sample()
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(host, 'capture', return_value=sample), \
                patch.object(host.subprocess, 'run', return_value=subprocess.CompletedProcess([], 7)):
            self.assertEqual(host.inside(Path(temporary), sample['service'], 1001, 1001,
                ['python3', 'scripts/ci/run_from_zero_native.py', '--out', '/tmp/out']), 7)
        self.assertEqual(host.exit_status({'passed': True, 'failure': 'SIGNAL_15',
                                          'systemd_run_exit': 143}), 143)
        self.assertEqual(host.exit_status({'passed': False, 'failure': 'cleanup',
                                          'systemd_run_exit': 0}), 1)

    def test_all_three_actual_callsites_retain_exact_one_wrapped_subprocess(self):
        check_from_zero_host_callsites(host.ROOT)
        block = ('    python3 scripts/ci/run_from_zero_host.py -- '
                 'python3 scripts/ci/run_from_zero_native.py --out "/tmp/out"\n')
        check_from_zero_host_call(block, block)
        for changed in (block + block, block.replace('run_from_zero_host.py -- ', ''),
                        block.replace('    python3', '    true # python3'),
                        block.replace('--out', '--skip')):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                check_from_zero_host_call(changed, block)


class HistoryAdapterControls(unittest.TestCase):
    """Synthetic build/report files are never executed or published as native evidence."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name).resolve()
        self.receipts = self.folder / 'receipts'
        self.receipts.mkdir()
        self.out = self.receipts / 'history-native'
        self.binary = self.folder / 'compiler-produced-test'
        self.binary.write_bytes(b'synthetic compiler fixture; never executed\n')
        self.binary.chmod(0o700)
        self.receipt = {'schema': 'trnm-ci-source-v1', 'kind': 'head',
                        'tested_commit': 'a' * 40, 'tested_tree': 'b' * 40,
                        'candidate': 'a' * 40, 'base': None, 'prospective_merge': None,
                        'tracked_worktree_verified': True, 'tracked_entries': 1,
                        'tracked_bytes': 1, 'tests_executed_by_identity_check': False}
        (self.receipts / 'source.json').write_text(json.dumps(self.receipt))
        environment = patch.dict(os.environ, {
            'TRNM_CI_RECEIPT_DIR': str(self.receipts), 'TRNM_EXPECTED_SOURCE_SHA': 'a' * 40,
            'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_JOB': 'history-control'})
        environment.start()
        self.addCleanup(environment.stop)
        verifier = patch.object(history, 'verify_source', side_effect=lambda *args, **kwargs: self.receipt)
        self.verify = verifier.start()
        self.addCleanup(verifier.stop)

    def build_row(self):
        return {'reason': 'compiler-artifact', 'target': {
            'name': history.TARGET, 'src_path': str(history.ROOT / history.SOURCE),
            'kind': ['test'], 'crate_types': ['bin'], 'test': True},
            'manifest_path': str(history.ROOT / 'trillionnium/crates/trnm-pon-node/Cargo.toml'),
            'profile': {'test': True, 'opt_level': '3'}, 'executable': str(self.binary),
            'filenames': [str(self.binary)]}

    def build_bytes(self, rows=None):
        rows = [self.build_row()] if rows is None else rows
        return ('\n'.join(json.dumps(row) for row in rows + [
            {'reason': 'build-finished', 'success': True}]) + '\n').encode()

    @staticmethod
    def process(command, exit_code=0):
        return {'command': command, 'started': True, 'pid': 123,
                'exit_code': exit_code, 'failure': None, 'cleanup_errors': []}

    def prepare(self):
        def build(command, log, *, stderr):
            self.assertEqual(command, history.build_command())
            log.write_bytes(self.build_bytes())
            stderr.write_text('synthetic build control\n')
            return self.process(command)
        with patch.object(history, 'run_process', side_effect=build) as run:
            prepared = history.prepare(self.out)
        run.assert_called_once()
        self.assertIs(prepared['completed'], True)
        return prepared

    @staticmethod
    def summary():
        return {'schema': history.SUMMARY_SCHEMA, 'passed': True,
                'blocks': 4105, 'confirmed_packets': 4105, 'renewals': 4,
                'corrupt_active_index_reopen_refused': True,
                **{key: False for key in history.FALSE_FLAGS}}

    def native_outputs(self, command, log, *, environment):
        self.assertEqual(command, history.native_command(self.out, self.binary))
        self.assertEqual(environment['TRNM_INDEX_EVIDENCE_DIRECTORY'], str(self.out / 'long-history'))
        log.write_text('running 1 test\ntest ' + history.SELECTOR + ' ... ok\n'
                       'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
                       '0 filtered out; finished in 0.01s\n')
        (self.out / 'history-resources.txt').write_text('synthetic resource fixture; not a measurement\n')
        (self.out / 'long-history').mkdir()
        (self.out / 'long-history/summary.json').write_text(json.dumps(self.summary()))
        return self.process(command)

    def test_exact_history_mode_does_not_generalize_or_rebuild_original_modes(self):
        command = ['python3', history.SCRIPT, '--out', str(self.out)]
        self.assertEqual(host.validate_command(command), self.out)
        for invalid in (command + ['--skip'], command[:2] + ['--prepare', '--out', str(self.out)],
                        ['python3', 'arbitrary.py', '--out', str(self.out)]):
            with self.subTest(command=invalid), self.assertRaises(ValueError):
                host.validate_command(invalid)
        with patch.object(host, 'prepare_native_build', return_value={'old': True}) as old, \
                patch.object(history, 'validate_preparation', return_value={'history': True}) as current:
            self.assertEqual(host.prepare_command(command, self.out, self.folder), {'history': True})
            old.assert_not_called()
            current.assert_called_once_with(self.out)
            for script in ('run_from_zero_native.py', 'run_w1_fresh_service_v1.py'):
                self.assertEqual(host.prepare_command(['python3', 'scripts/ci/' + script,
                    '--out', '/tmp/out'], self.out, self.folder), {'old': True})
            self.assertEqual(old.call_count, 2)
        self.assertEqual(history.build_command(), ['cargo', '+1.95.0', 'test', '--release',
            '--locked', '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-pon-node',
            '--test', 'ancestry_long_sync', '--no-run', '--message-format=json'])
        self.assertEqual(history.native_command(self.out, self.binary),
            ['/usr/bin/time', '-v', '-o', str(self.out / 'history-resources.txt'), str(self.binary),
             history.SELECTOR, '--exact', '--ignored', '--show-output'])

    def test_source_uses_workflow_receipt_and_event_expected_head_or_merge(self):
        source = history.source_identity()
        self.assertEqual(source['commit'], 'a' * 40)
        self.verify.assert_called_once_with('head', 'a' * 40, None, None, root=history.ROOT)
        self.receipt.update(kind='prospective-merge', tested_commit='c' * 40,
                            base='d' * 40, prospective_merge='c' * 40)
        (self.receipts / 'source.json').write_text(json.dumps(self.receipt))
        with patch.dict(os.environ, {'TRNM_EXPECTED_SOURCE_SHA': 'c' * 40}):
            self.assertEqual(history.source_identity()['commit'], 'c' * 40)
        self.verify.assert_called_with('prospective-merge', 'a' * 40, 'd' * 40,
                                       'c' * 40, root=history.ROOT)
        for expected in ('', 'HEAD', 'e' * 40):
            with self.subTest(expected=expected), patch.dict(os.environ, {
                    'TRNM_EXPECTED_SOURCE_SHA': expected}), self.assertRaises(ValueError):
                history.source_identity()
        (self.receipts / 'source.json').unlink()
        with self.assertRaises(OSError):
            history.source_identity()

    def test_compiler_artifact_requires_one_exact_target_source_and_real_bounded_binary(self):
        row = self.build_row()
        self.assertEqual(history.select_binary(self.build_bytes()), self.binary)
        variants = [[], [row, row], [dict(row, target={'name': 'public_v3_from_zero'})],
                    [dict(row, profile={'test': False})], [dict(row, executable='relative')],
                    [dict(row, target=dict(row['target'], src_path='/other/test.rs'))],
                    [dict(row, target=dict(row['target'], kind=['example']))],
                    [dict(row, target=dict(row['target'], test=False))],
                    [dict(row, target=dict(row['target'], crate_types=['lib']))],
                    [dict(row, profile={'test': True, 'opt_level': '0'})],
                    [dict(row, manifest_path='/other/Cargo.toml')],
                    [dict(row, filenames=[])]]
        for rows in variants:
            with self.subTest(rows=rows), self.assertRaises((OSError, ValueError)):
                history.select_binary(self.build_bytes(rows))
        incomplete = json.dumps(row).encode()
        for raw in (incomplete, self.build_bytes().replace(b'"success": true', b'"success": false'),
                    self.build_bytes() + incomplete,
                    self.build_bytes() + b'{"reason":"build-finished","success":true}\n'):
            with self.subTest(raw=raw[-80:]), self.assertRaises(ValueError):
                history.select_binary(raw)
        alias = self.folder / 'alias'
        alias.symlink_to(self.binary)
        with self.assertRaises(ValueError):
            history.select_binary(self.build_bytes([dict(row, executable=str(alias), filenames=[str(alias)])]))
        with self.binary.open('wb') as stream:
            stream.truncate(history.BINARY_LIMIT + 1)
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('unbounded read')):
            with self.assertRaisesRegex(ValueError, 'HISTORY_REGULAR_FILE_BOUND'):
                history.select_binary(self.build_bytes())


    def test_preparation_failure_signal_and_source_drift_keep_incomplete_receipt(self):
        for case in ('nonzero', 'unknown-exit', 'signal', 'source-drift'):
            with self.subTest(case=case):
                if self.out.exists():
                    for path in self.out.iterdir():
                        path.unlink()
                    self.out.rmdir()
                source = history.source_identity()

                def build(command, log, *, stderr):
                    log.write_bytes(self.build_bytes())
                    stderr.write_text('retained failure control\n')
                    if case == 'signal':
                        raise history.HistorySignal('15')
                    return self.process(command, 7 if case == 'nonzero' else
                                        None if case == 'unknown-exit' else 0)

                after = dict(source, commit='f' * 40) if case == 'source-drift' else source
                with patch.object(history, 'run_process', side_effect=build), \
                        patch.object(history, 'source_identity', side_effect=[source, after]):
                    result = history.prepare(self.out)
                self.assertIs(result['completed'], False)
                self.assertTrue(result['failures'])
                self.assertEqual(json.loads((self.out / 'preparation.json').read_text()), result)
                self.assertTrue((self.out / 'build.stderr').is_file())
                with self.assertRaises(ValueError):
                    history.validate_preparation(self.out)

    def test_preparation_cannot_borrow_other_job_source_or_changed_binary(self):
        prepared = self.prepare()
        self.assertIs(prepared['native_tests_executed'], False)
        self.assertIs(prepared['service_resource_observation'], False)
        self.assertEqual(history.validate_preparation(self.out), prepared)
        with self.assertRaises(FileExistsError):
            history.prepare(self.out)
        with patch.dict(os.environ, {'GITHUB_RUN_ATTEMPT': '2'}), self.assertRaisesRegex(
                ValueError, 'HISTORY_PREPARATION_JOB_CHANGED'):
            history.validate_preparation(self.out)
        with patch.dict(os.environ, {'OPENSSL_DIR': '/changed-provider'}), self.assertRaisesRegex(
                ValueError, 'HISTORY_PREPARATION_BUILD_ENV_CHANGED'):
            history.validate_preparation(self.out)
        with patch.object(history, 'source_identity', return_value={'commit': 'e' * 40}), \
                self.assertRaisesRegex(ValueError, 'HISTORY_PREPARATION_SOURCE_CHANGED'):
            history.validate_preparation(self.out)
        replacement = self.folder / 'replacement'
        replacement.write_bytes(self.binary.read_bytes())
        replacement.chmod(0o700)
        replacement.replace(self.binary)
        with self.assertRaisesRegex(ValueError, 'HISTORY_PREPARED_BINARY_CHANGED'):
            history.validate_preparation(self.out)

    def test_original_summary_requires_full_completion_and_unqualified_scope(self):
        history.validate_summary(self.summary())
        changes = [('schema', 'other'), ('passed', False), ('blocks', 4104),
                   ('confirmed_packets', 4104), ('renewals', 3), ('renewals', True),
                   ('corrupt_active_index_reopen_refused', False)]
        changes += [(key, True) for key in history.FALSE_FLAGS]
        for key, value in changes:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                history.validate_summary(dict(self.summary(), **{key: value}))

    def test_whole_native_command_and_actual_saved_outputs_bind_to_one_preparation(self):
        prepared = self.prepare()
        with patch.object(history, 'run_process', side_effect=self.native_outputs) as run:
            result = history.execution(self.out)
        run.assert_called_once()
        self.assertIs(result['passed'], True)
        self.assertIs(result['compilation_in_native_measurement'], False)
        self.assertIs(result['native_execution_authenticated'], False)
        self.assertEqual(history.bind_execution(prepared, self.out)['exact_selector'], history.SELECTOR)
        self.assertEqual(host.bind_command(['python3', history.SCRIPT, '--out', str(self.out)],
                                          prepared, self.out)['source_commit'], 'a' * 40)
        with self.assertRaises(FileExistsError):
            history.execution(self.out)
        manifest = self.out / 'manifest.json'
        for pid in (None, 0, True, '123'):
            changed = copy.deepcopy(result)
            changed['process']['pid'] = pid
            manifest.write_text(json.dumps(changed))
            with self.subTest(pid=pid), self.assertRaisesRegex(ValueError, 'HISTORY_NATIVE_PROCESS_REQUIRED'):
                history.bind_execution(prepared, self.out)
        manifest.write_text(json.dumps(result))
        (self.out / 'history.log').write_text('running 0 tests\n')
        with self.assertRaises(ValueError):
            history.bind_execution(prepared, self.out)


    def test_unknown_native_exit_retains_original_failed_summary(self):
        self.prepare()

        def fail(command, log, *, environment):
            self.native_outputs(command, log, environment=environment)
            summary = {'schema': history.SUMMARY_SCHEMA, 'passed': False,
                       'error': 'PUBLIC_REQUEST_DEADLINE',
                       **{key: False for key in history.FALSE_FLAGS}}
            (self.out / 'long-history/summary.json').write_text(json.dumps(summary))
            return dict(self.process(command, None), failure='unknown terminal observation')

        with patch.object(history, 'run_process', side_effect=fail):
            result = history.execution(self.out)
        self.assertIs(result['passed'], False)
        self.assertIsNone(result['process']['exit_code'])
        self.assertEqual(result['summary']['error'], 'PUBLIC_REQUEST_DEADLINE')
        self.assertEqual(result['binary_before'], result['binary_after'])
        self.assertEqual(result['source_before'], result['source_after'])
        self.assertTrue(result['resources'])
        self.assertTrue(result['summary_file'])
        self.assertEqual(json.loads((self.out / 'manifest.json').read_text()), result)

    def test_zero_test_exit_or_source_drift_never_becomes_history_pass(self):
        self.prepare()
        source = history.source_identity()

        def empty(command, log, *, environment):
            result = self.native_outputs(command, log, environment=environment)
            log.write_text('running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; '
                           '0 measured; 1 filtered out; finished in 0.00s\n')
            return result

        with patch.object(history, 'run_process', side_effect=empty), \
                patch.object(history, 'source_identity', side_effect=[source, dict(source, tree='f' * 40)]):
            result = history.execution(self.out)
        self.assertIs(result['passed'], False)
        self.assertTrue(any('HISTORY_EXECUTION_SOURCE_CHANGED' in value for value in result['failures']))
        self.assertTrue(any('required-native-test:' in value for value in result['failures']))
        self.assertIsNone(result['named_execution'])

    def test_native_binary_drift_is_retained_after_otherwise_successful_process(self):
        self.prepare()

        def changed(command, log, *, environment):
            result = self.native_outputs(command, log, environment=environment)
            self.binary.write_bytes(b'changed fixture after observed child\n')
            return result

        with patch.object(history, 'run_process', side_effect=changed):
            result = history.execution(self.out)
        self.assertIs(result['passed'], False)
        self.assertNotEqual(result['binary_before']['sha256'], result['binary_after']['sha256'])
        self.assertTrue(any('HISTORY_EXECUTION_BINARY_CHANGED' in value for value in result['failures']))

    def test_real_harmless_nonzero_process_has_known_exit_and_retained_log(self):
        command = [sys.executable, '-c', "print('harmless history adapter control'); raise SystemExit(7)"]
        path = self.folder / 'process.log'
        result = history.run_process(command, path)
        self.assertIs(result['started'], True)
        self.assertEqual(result['exit_code'], 7)
        self.assertIsNone(result['failure'])
        self.assertIn('harmless history adapter control', path.read_text())
        self.assertFalse(history.process_succeeded(result, command))

    def test_wait_failure_and_unobserved_cleanup_keep_unknown_exit(self):
        class UnknownChild:
            pid = 12345
            returncode = None

            @staticmethod
            def wait(*args, **kwargs):
                raise OSError('terminal observation unavailable')

            @staticmethod
            def poll():
                return None

        with patch.object(history.subprocess, 'Popen', return_value=UnknownChild()), \
                patch.object(history.os, 'killpg', side_effect=OSError('cleanup unavailable')):
            result = history.run_process(['synthetic-no-execution'], self.folder / 'unknown.log')
        self.assertIs(result['started'], True)
        self.assertIsNone(result['exit_code'])
        self.assertIn('terminal observation unavailable', result['failure'])
        self.assertEqual(len(result['cleanup_errors']), 2)
        self.assertFalse(history.process_succeeded(result, result['command']))

    def test_stderr_close_failure_keeps_actual_child_and_known_exit(self):
        stderr_path = self.folder / 'stderr'
        original_open = Path.open

        class CloseFailure:
            def __init__(self, stream):
                self.stream = stream

            def fileno(self):
                return self.stream.fileno()

            def close(self):
                self.stream.close()
                raise OSError('stderr close observation failed')

        def open_file(path, *args, **kwargs):
            stream = original_open(path, *args, **kwargs)
            return CloseFailure(stream) if path == stderr_path else stream

        command = [sys.executable, '-c', "print('harmless completed child')"]
        with patch.object(Path, 'open', autospec=True, side_effect=open_file):
            result = history.run_process(command, self.folder / 'close.log', stderr=stderr_path)
        self.assertIs(result['started'], True)
        self.assertEqual(result['exit_code'], 0)
        self.assertIn('stderr close observation failed', result['failure'])
        self.assertFalse(history.process_succeeded(result, command))

    def test_observed_success_requires_a_positive_integer_child_pid(self):
        command = history.build_command()
        self.assertTrue(history.process_succeeded(self.process(command), command))
        for value in (None, 0, -1, True, '123'):
            with self.subTest(pid=value):
                self.assertFalse(history.process_succeeded(dict(self.process(command), pid=value), command))


    def test_history_callsite_is_exact_and_does_not_allow_an_arbitrary_second_host(self):
        original = (host.ROOT / '.github/workflows/pon-priority-acceptance.yml').read_text()
        remainder = check_history_host_call(original)
        exact = ('      - name: Execute original release from-zero controls\n'
                 "        if: ${{ !cancelled() && steps.source.outcome == 'success' && "
                 "steps.toolchain.outcome == 'success' && matrix.campaign == 'service-model' }}\n"
                 '        run: python3 scripts/ci/run_from_zero_host.py -- '
                 'python3 scripts/ci/run_from_zero_native.py --out "$TRNM_CI_RECEIPT_DIR/from-zero-native"\n')
        check_from_zero_host_call(remainder, exact)
        mutations = [original.replace(HISTORY_HOST_STEPS, ''), original + HISTORY_HOST_STEPS,
                     original.replace('run_history_native.py --prepare', 'run_history_native.py --skip'),
                     original.replace('steps.history_build.outcome', 'steps.source.outcome'),
                     original.replace(HISTORY_EXPECTED_SOURCE, ''),
                     original.replace('    timeout-minutes: 180\n', '    timeout-minutes: 181\n'),
                     original + 'python3 scripts/ci/run_from_zero_host.py -- arbitrary\n']
        for changed in mutations:
            with self.subTest(changed=changed[-100:]), self.assertRaises(ValueError):
                check_from_zero_host_call(check_history_host_call(changed), exact)


if __name__ == '__main__':
    unittest.main()
