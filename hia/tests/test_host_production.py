"""Fail-closed production qualifier controls; these grant no physical Host pass."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hia.platform.host_checkpoint import qualify_production as production
from hia.platform.host_checkpoint.qualify import audit_trace
from hia.tests.test_host_checkpoint import synthetic_trace


class HostProductionControls(unittest.TestCase):
    def test_actual_local_cli_refuses_before_outputs_or_provision(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'must-not-exist'
            environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
            for key in ('GITHUB_ACTIONS', 'CI', 'RUNNER_ENVIRONMENT'):
                environment.pop(key, None)
            result = subprocess.run([sys.executable, '-B', production.__file__,
                '--build', str(Path(directory) / 'absent-build'), '--output', str(output)],
                cwd=directory, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'HOSTED_CI_ONLY_NO_LOCAL_PROVISION', result.stderr)
            self.assertFalse(output.exists())

    def test_optimized_cli_cannot_admit_privileged_qualification(self):
        for options, setting in ((['-O'], None), (['-OO'], None), ([], '2')):
            environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
            if setting:
                environment['PYTHONOPTIMIZE'] = setting
            else:
                environment.pop('PYTHONOPTIMIZE', None)
            result = subprocess.run([sys.executable, *options, '-B', production.__file__, '--help'],
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'refuses optimized Python', result.stderr)

    def test_context_refuses_self_hosted_root_and_missing_identity(self):
        candidate = {'GITHUB_ACTIONS': 'true', 'CI': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                     'TRNM_EXPECTED_SOURCE_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123',
                     'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_JOB': 'native-platform'}
        # This is solely the argument gate; source and root-owned lease checks
        # still execute independently before privileged setup in the real CLI.
        production.hosted_context(candidate, uid=1001)
        for key, value in (('RUNNER_ENVIRONMENT', 'self-hosted'), ('GITHUB_ACTIONS', 'false'),
                           ('TRNM_EXPECTED_SOURCE_SHA', 'HEAD'), ('GITHUB_RUN_ID', ''),
                           ('GITHUB_JOB', '../another')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                production.hosted_context(dict(candidate, **{key: value}), uid=1001)
        with self.assertRaises(ValueError):
            production.hosted_context(candidate, uid=0)

    def test_owned_service_keeps_fixed_slice_and_drops_capabilities(self):
        arguments = production.service_argv('trnm-hia-host-123-1-native-platform-77.service',
            Path('/tmp/build'), Path('/tmp/output'), 1001, 1002,
            {'PATH': '/usr/bin', 'UNRELATED_PRIVATE_VALUE': 'never-forward'})
        for required in ('--slice=trnmponpublic.slice', '--uid=1001', '--gid=1002',
                         '--property=Delegate=no', '--property=NoNewPrivileges=yes',
                         '--property=CapabilityBoundingSet=', '--property=KillMode=control-group'):
            self.assertIn(required, arguments)
        self.assertFalse(any('UNRELATED_PRIVATE_VALUE' in item for item in arguments))
        with self.assertRaises(ValueError):
            production.service_argv('another.service', Path('/tmp/build'), Path('/tmp/out'), 1001, 1002, {})

    def test_actual_unit_install_refuses_existing_or_dangling_targets_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'reviewed-unit'
            source.write_bytes(b'bounded-test-unit\n')
            existing = root / 'existing'
            existing.write_bytes(b'other-owner\n')
            dangling = root / 'dangling'
            dangling.symlink_to('absent-target')
            for target in (existing, dangling):
                result = subprocess.run([sys.executable, '-I', '-S', '-c', production.INSTALL_NEW_UNIT,
                    str(source), str(target), production.digest(source.read_bytes())],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'FileExistsError', result.stderr)
            self.assertEqual(existing.read_bytes(), b'other-owner\n')
            self.assertTrue(dangling.is_symlink())
            self.assertFalse((root / 'absent-target').exists())

    def test_actual_partial_receipt_is_retained_on_eof(self):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b'partial')
        os.close(write_fd)
        captured = bytearray()
        with os.fdopen(read_fd, 'rb') as stream:
            with self.assertRaisesRegex(ValueError, 'INCOMPLETE_RECEIPT'):
                production.read_exact(stream, 128, captured)
        self.assertEqual(bytes(captured), b'partial')

    def test_actual_already_exited_child_keeps_both_unread_pipes(self):
        process = subprocess.Popen([sys.executable, '-I', '-S', '-c',
            "import os; os.write(1, b'incomplete-native-receipt'); "
            "os.write(2, b'actual-early-failure'); os._exit(23)"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
        self.assertEqual(process.wait(timeout=3), 23)
        stdout, stderr = bytearray(), bytearray()
        errors = production.drain_owned_process(process, stdout, stderr)
        self.assertEqual(errors, [])
        self.assertEqual(bytes(stdout), b'incomplete-native-receipt')
        self.assertEqual(bytes(stderr), b'actual-early-failure')
        self.assertEqual(process.returncode, 23)

    def test_production_trace_mapping_cannot_accept_other_parent_or_process_leader(self):
        source = synthetic_trace()
        reverse = {value: key for key, value in production.PRODUCTION_PATHS.items()}
        import re
        actual_syntax = re.sub(r'"([^"\\]*)"',
            lambda found: '"' + reverse.get(found[1], found[1]) + '"', source)
        parsed = audit_trace(production.normalize_trace(actual_syntax), expected_checks=2, expected_error=0)
        self.assertEqual(len(parsed['checks']), 2)
        for changed in (
            actual_syntax.replace('/proc/thread-self/cgroup', '/proc/self/cgroup'),
            actual_syntax.replace('/sys/fs/cgroup/trnmponpublic.slice',
                                  '/sys/fs/cgroup/trnmponpublic.slice-other'),
            actual_syntax.replace('/proc/sys/kernel/random/boot_id', '/tmp/boot_id'),
        ):
            with self.assertRaises(ValueError):
                audit_trace(production.normalize_trace(changed), expected_checks=2, expected_error=0)


if __name__ == '__main__':
    unittest.main()
