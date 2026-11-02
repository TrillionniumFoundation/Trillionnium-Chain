#!/usr/bin/env python3
"""Synthetic refusal/static tests only; never provision sysfs or execute native CI."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import public_host_ci_observation as observation
import run_from_zero_host as host
from check_ci_contract import check_from_zero_host_call, check_from_zero_host_callsites


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


class AuthenticatedOutboxHostControls(unittest.TestCase):
    command = ['python3', 'scripts/ci/run_authenticated_outbox_native_v1.py',
               '--out', '/tmp/authenticated-outbox-native']

    def test_only_exact_separate_outbox_argv_is_added(self):
        self.assertEqual(host.validate_command(self.command), Path(self.command[-1]))
        for changed in [self.command + ['--ignored'], self.command + ['--skip'],
                        [*self.command[:2], '--other', self.command[3]],
                        [*self.command[:3], 'relative'],
                        [*self.command[:3], str(host.ROOT / 'out')],
                        ['python3', 'scripts/ci/other_outbox.py', '--out', '/tmp/out']]:
            with self.subTest(command=changed), self.assertRaises(ValueError):
                host.validate_command(changed)

    def test_missing_real_host_blocks_outbox_child_before_execution(self):
        sample = synthetic_sample()
        sample['parent'] = None
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(host, 'capture', return_value=sample), \
                patch.object(host.subprocess, 'run') as run:
            result = host.inside(Path(temporary), sample['service'], 1001, 1001, self.command)
            self.assertEqual(result, 1)
            run.assert_not_called()
            saved = json.loads((Path(temporary) / 'child-result.json').read_text())
            self.assertEqual(saved['schema'], 'trnm-ci-authenticated-outbox-host-child-v1')
            self.assertIsNone(saved['native_child_exit'])

    def test_local_outbox_command_never_provisions_a_host(self):
        with patch.dict(host.os.environ, {'CI': 'true', 'GITHUB_ACTIONS': 'false'}, clear=True), \
                patch.object(host.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'HOSTED_CI_ONLY_NO_LOCAL_PROVISION'):
                host.outer(self.command)
            run.assert_not_called()

    def prepare(self, folder, *, after=None, process=None, override=None):
        import run_authenticated_outbox_native_v1 as outbox
        source = {'commit': 'a' * 40, 'tree': 'b' * 40}
        test = folder / 'test-build.elf'
        cli = folder / 'cli-build.elf'
        test.write_bytes(b'synthetic test ELF input')
        cli.write_bytes(b'synthetic CLI ELF input')
        (folder / 'prepare-build').mkdir()
        (folder / 'prepare-build/stdout').write_text('synthetic compiler output\n')
        with patch.object(outbox, 'source_identity', side_effect=[source, after or source]), \
                patch.object(outbox, 'expected_source', return_value=source['commit']), \
                patch.object(outbox, 'require_original_build_environment', side_effect=override), \
                patch.object(outbox, 'select_binaries', return_value=(test, cli)), \
                patch.object(host.native, 'run_child', return_value=process or {
                    'exit_code': 0, 'timed_out': False}) as run:
            result = host.prepare_authenticated_outbox_build(folder)
        run.assert_called_once_with(outbox.native_build_command(), folder / 'prepare-build', 900)
        return result

    def test_separate_preparation_pins_test_and_cli_without_running_native(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            result = self.prepare(folder)
            self.assertEqual(result['schema'], 'trnm-ci-authenticated-outbox-build-preparation-v1')
            self.assertIs(result['completed'], True)
            self.assertIs(result['native_tests_executed'], False)
            self.assertIs(result['service_resource_observation'], False)
            for label in ('test', 'cli'):
                self.assertEqual(result[label + '_binary_sha256'],
                                 hashlib.sha256(Path(result[label + '_binary_path']).read_bytes()).hexdigest())

    def test_source_drift_failed_build_and_override_keep_failed_preparation(self):
        cases = [dict(after={'commit': 'c' * 40, 'tree': 'b' * 40}),
                 dict(process={'exit_code': 1, 'timed_out': False}),
                 dict(process={'exit_code': 0, 'timed_out': True}),
                 dict(override=ValueError('synthetic forbidden compiler override'))]
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                with self.assertRaises(ValueError):
                    self.prepare(folder, **case)
                saved = json.loads((folder / 'prepare-build.json').read_text())
                self.assertIs(saved['completed'], False)

    def binder_case(self, folder):
        source = {'commit': 'a' * 40, 'tree': 'b' * 40}
        prepared = {'schema': 'trnm-ci-authenticated-outbox-build-preparation-v1',
                    'completed': True, 'source_before': source, 'source_after': source}
        result = {'schema': 'trnm-authenticated-outbox-native-execution-v1',
                  'source_expected': source['commit'], 'source_before': source,
                  'source_after': source, 'passed': True, 'failures': [],
                  'source_recompiled': True, 'execution_finished': True,
                  'all_named_tests_passed': True,
                  'production_activation': False, 'public_network_ready': False,
                  'physical_power_loss_accepted': False,
                  'process': {'exit_code': 0, 'expected_source': source['commit']},
                  'named_execution': {'executed_tests': 1},
                  'host_fixture': {'schema': 'synthetic fixture; not native evidence'}}
        for label in ('test', 'cli'):
            binary = folder / (label + '.elf')
            binary.write_bytes(('synthetic ' + label + ' artifact').encode())
            sha = hashlib.sha256(binary.read_bytes()).hexdigest()
            prepared[label + '_binary_path'] = result[label + '_binary_path'] = str(binary)
            prepared[label + '_binary_sha256'] = sha
            result[label + '_binary_sha256_before'] = result[label + '_binary_sha256_after'] = sha
        result['process']['command'] = [result['test_binary_path'], 'synthetic argv']
        sample = synthetic_sample()
        sample.update(uid=host.os.getuid(), gid=host.os.getgid())
        result['host_before'] = copy.deepcopy(sample)
        result['host_after'] = copy.deepcopy(sample)
        result['host_fixture']['perpid_cgroups'] = [{'cgroup': sample['thread_cgroup']}]
        (folder / 'native.log').write_text('synthetic execution transcript input\n')
        result['native_log_sha256'] = hashlib.sha256((folder / 'native.log').read_bytes()).hexdigest()
        return prepared, result

    def test_binder_requires_source_test_cli_log_and_actual_named_acceptance(self):
        import run_authenticated_outbox_native_v1 as outbox
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            prepared, result = self.binder_case(folder)
            manifest = folder / 'manifest.json'
            verified = {key: result[key] for key in ('named_execution', 'host_fixture')}
            with patch.object(outbox, 'expected_source', return_value='a' * 40), \
                    patch.object(outbox, 'validate_execution', return_value=verified):
                manifest.write_text(json.dumps(result))
                self.assertEqual(host.bind_prepared_authenticated_outbox_execution(
                    prepared, folder)['source_commit'], 'a' * 40)
                cases = [('source_after', {'commit': 'c' * 40}),
                         ('source_expected', 'c' * 40),
                         ('test_binary_sha256_before', 'c' * 64),
                         ('cli_binary_sha256_after', 'c' * 64),
                         ('test_binary_path', '/tmp/another-test'),
                         ('cli_binary_path', '/tmp/another-cli'),
                         ('native_log_sha256', 'c' * 64),
                         ('passed', False), ('failures', ['actual refusal']),
                         ('source_recompiled', False), ('execution_finished', False),
                         ('all_named_tests_passed', False), ('production_activation', True),
                         ('host_before', None),
                         ('host_after', dict(result['host_after'], thread_cgroup='0::/other')),
                         ('process', dict(result['process'], expected_source='c' * 40)),
                         ('process', dict(result['process'], command=['/tmp/other-ELF'])),
                         ('named_execution', {'executed_tests': 0})]
                for key, value in cases:
                    changed = dict(result, **{key: value})
                    manifest.write_text(json.dumps(changed))
                    with self.subTest(key=key), self.assertRaises(ValueError):
                        host.bind_prepared_authenticated_outbox_execution(prepared, folder)
                manifest.write_text(json.dumps(result))
                for label in ('test', 'cli'):
                    binary = folder / (label + '.elf')
                    original = binary.read_bytes()
                    binary.write_bytes(b'changed retained ELF')
                    with self.subTest(elf=label), self.assertRaises(ValueError):
                        host.bind_prepared_authenticated_outbox_execution(prepared, folder)
                    binary.write_bytes(original)

    def test_binder_cannot_accept_a_failed_or_zero_test_validator(self):
        import run_authenticated_outbox_native_v1 as outbox
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            prepared, result = self.binder_case(folder)
            (folder / 'manifest.json').write_text(json.dumps(result))
            with patch.object(outbox, 'expected_source', return_value='a' * 40), \
                    patch.object(outbox, 'validate_execution', side_effect=ValueError('zero actual tests')):
                with self.assertRaisesRegex(ValueError, 'zero actual tests'):
                    host.bind_prepared_authenticated_outbox_execution(prepared, folder)

    def test_workflow_uses_two_fresh_jobs_and_one_original_host_invocation(self):
        text = (host.ROOT / '.github/workflows/pon-authenticated-outbox-host-v1.yml').read_text()
        self.assertIn('runs-on: ubuntu-24.04\n', text)
        self.assertIn('source: [head, prospective-merge]\n', text)
        self.assertIn('cancel-in-progress: false\n', text)
        self.assertIn('          ref: ${{ env.EXPECTED_SOURCE }}\n', text)
        self.assertEqual(text.count('run: python3 scripts/ci/run_from_zero_host.py -- '
                                    'python3 scripts/ci/run_authenticated_outbox_native_v1.py --out '
                                    '"$OUT/qualified-native"\n'), 1)
        self.assertEqual(text.count('python3 scripts/ci/run_from_zero_host.py'), 1)
        self.assertIn('cargo +1.95.0 test --locked --release', text)
        self.assertIn('-- --exact --show-output', text)
        self.assertNotIn('CARGO_INCREMENTAL:', text)
        self.assertNotIn('CPUQuota=', text)


if __name__ == '__main__':
    unittest.main()
