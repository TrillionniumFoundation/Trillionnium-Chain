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
                                    'GITHUB_TOKEN': 'synthetic-not-a-token'})
        self.assertEqual(argv[-4:], command)
        for item in ('--slice=trnmponpublic.slice', '--uid=1001', '--gid=1002',
                     '--property=Delegate=no', '--property=NoNewPrivileges=yes',
                     '--property=CapabilityBoundingSet=', '--property=KillMode=control-group',
                     '--setenv=PATH=/original/bin', '--setenv=CARGO_BUILD_JOBS=2',
                     '--setenv=RUSTUP_TOOLCHAIN=1.95.0'):
            self.assertIn(item, argv)
        self.assertFalse(any('GITHUB_TOKEN' in item for item in argv))
        self.assertFalse(any('CPUQuota=' in item or 'MemoryMax=' in item for item in argv))

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


if __name__ == '__main__':
    unittest.main()
