#!/usr/bin/env python3
"""Synthetic boundary controls, not native outbox success or Host provisioning."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_authenticated_outbox_native_v1 as runner


COMMIT = 'a' * 40
CGROUP = '0::/trnmponpublic.slice/trnm-from-zero-123-1-outbox-456.service'


def fixture():
    pids = [101, 102, 103, 104, 105]
    return {
        'schema': runner.FIXTURE_SCHEMA, 'test_pid': pids[0], 'server_pid': pids[1],
        'push_pids': pids[2:4], 'sync_pid': pids[4],
        'perpid_cgroups': [dict(role=role, pid=pid, cgroup=CGROUP, cgroup_observation_error=None)
                          for role, pid in zip(
                              ['test', 'server', 'push-first', 'push-replay', 'sync'], pids)],
        'sync_success': True, 'original_server_lifetime_seconds': 4,
        'verified_tip': 'b' * 64, 'authenticated_requests': 3, 'replayed_responses': 0,
        'authenticated_outbox_pending': 0, 'production_activation': False,
        'public_network_ready': False,
    }


def native_log(observed=None):
    value = fixture() if observed is None else observed
    return ('running 1 test\n' + 'test ' + runner.SELECTOR + ' ... '
            + json.dumps(value, sort_keys=True) + '\nok\n'
            'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
            '31 filtered out; finished in 4.01s\n')


def source():
    return dict(commit=COMMIT, tree='b' * 40, test_sha256='c' * 64,
                tracked_source_identity=dict(tested_commit=COMMIT, tested_tree='b' * 40,
                                             tracked_worktree_verified=True))


def process(command):
    return dict(command=command, executed=True, exit_code=0, process_exit_code=0,
                timed_out=False, source_verified=True, expected_source=COMMIT)


def create_binaries(directory):
    release = directory / 'release'
    (release / 'deps').mkdir(parents=True)
    test = release / 'deps/native_node-123abc'
    client = release / runner.CLI
    for path, payload in [(test, b'synthetic-test-not-executed'),
                          (client, b'synthetic-cli-not-executed')]:
        path.write_bytes(b'\x7fELF' + payload)
        path.chmod(0o755)
    return test, client


def artifact(path, target, kind, test):
    return json.dumps(dict(reason='compiler-artifact', executable=str(path),
                           target=dict(name=target, kind=[kind]), profile=dict(test=test)))


class SourceAndSelectionControls(unittest.TestCase):
    def test_exact_build_and_native_command_keep_original_bounds_and_selector(self):
        self.assertEqual(runner.native_build_command(), [
            'cargo', 'test', '--locked', '--release', '--manifest-path',
            'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--test', 'native_node',
            '--no-run', '--message-format=json'])
        self.assertEqual(runner.native_test_command(Path('/tmp/test')), [
            '/tmp/test', runner.SELECTOR, '--exact', '--ignored', '--nocapture', '--test-threads=1'])
        self.assertEqual((runner.BUILD_TIMEOUT_SECONDS, runner.TEST_TIMEOUT_SECONDS), (900, 90))

    def test_expected_source_is_mandatory_and_exact(self):
        for environment in [{}, {'TRNM_EXPECTED_SOURCE_SHA': 'A' * 40},
                            {'TRNM_EXPECTED_SOURCE_SHA': 'b' * 40}]:
            with self.subTest(environment=environment), patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(ValueError):
                    runner.expected_source(COMMIT)
        with patch.dict(os.environ, {'TRNM_EXPECTED_SOURCE_SHA': COMMIT}, clear=True):
            self.assertEqual(runner.expected_source(COMMIT), COMMIT)

    def test_dirty_or_hidden_source_error_propagates_without_a_cached_success(self):
        for error in ['source is not clean', 'tracked source bytes differ from commit',
                      'index hides tracked worktree entries', 'replacement refs are not source identity']:
            with self.subTest(error=error), \
                    patch.object(runner.subprocess, 'check_output', return_value=COMMIT + '\n'), \
                    patch.object(runner, 'verify_source', side_effect=ValueError(error)):
                with self.assertRaisesRegex(ValueError, error):
                    runner.source_identity()

    def test_compiler_and_profile_overrides_are_rejected_before_build(self):
        for key in ['CARGO_INCREMENTAL', 'RUSTFLAGS', 'RUSTC_WRAPPER',
                    'CARGO_BUILD_TARGET', 'CARGO_PROFILE_RELEASE_OPT_LEVEL']:
            with self.subTest(key=key), patch.dict(os.environ, {key: '0'}, clear=True):
                with self.assertRaisesRegex(ValueError, 'OUTBOX_ORIGINAL_BUILD_REQUIRED'):
                    runner.require_original_build_environment()

    def test_selection_requires_both_exact_emitted_elf_targets_and_embedded_cli_location(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            test, client = create_binaries(root)
            rows = [artifact(test, runner.TARGET, 'test', True),
                    artifact(client, runner.CLI, 'bin', False)]
            self.assertEqual(runner.select_binaries(rows), (test, client))
            for malformed in [rows[:1], rows[1:], rows + rows[:1], rows + rows[1:],
                              [artifact(test, runner.TARGET, 'bin', True), rows[1]],
                              [rows[0], artifact(client, runner.CLI, 'test', False)],
                              [rows[0], artifact(client, runner.CLI, 'bin', True)]]:
                with self.subTest(rows=malformed), self.assertRaises(ValueError):
                    runner.select_binaries(malformed)
            relocated = root / runner.CLI
            relocated.write_bytes(client.read_bytes())
            relocated.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'OUTBOX_EMBEDDED_CLI_LOCATION_REQUIRED'):
                runner.select_binaries([rows[0], artifact(relocated, runner.CLI, 'bin', False)])
            client.write_bytes(b'not ELF')
            with self.assertRaisesRegex(ValueError, 'OUTBOX_ELF_REQUIRED'):
                runner.select_binaries(rows)

    def test_missing_host_never_becomes_a_readiness_success(self):
        with patch.object(runner.Path, 'read_text', return_value='0::/unprovisioned\n'):
            with self.assertRaisesRegex(ValueError, 'OUTBOX_FIXED_HOST_MEMBERSHIP_REQUIRED'):
                runner.capture_host('synthetic-only')
        with patch.object(runner.Path, 'read_text', return_value=CGROUP), \
                patch.object(runner.host, 'capture', return_value={}), \
                patch.object(runner.host, 'validate', return_value=['FIXED_PARENT_IDENTITY']):
            with self.assertRaisesRegex(ValueError, 'OUTBOX_ACTUAL_HOST_REQUIRED'):
                runner.capture_host('synthetic-only')


class NativeExecutionControls(unittest.TestCase):
    def validate_log(self, text, observed_process=None):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / 'native.log'
            log.write_text(text)
            observed_process = (process(runner.native_test_command(Path('/tmp/test')))
                                if observed_process is None else observed_process)
            return runner.validate_execution(observed_process, log)

    def test_requires_real_named_positive_execution_and_retains_all_actual_pids(self):
        result = self.validate_log(native_log())
        self.assertEqual(result['named_execution']['executed_tests'], 1)
        self.assertEqual(result['host_fixture'], fixture())

    def test_short_lived_children_can_retain_explicit_missing_proc_observations(self):
        observed = fixture()
        for record in observed['perpid_cgroups'][1:]:
            record.update(cgroup=None, cgroup_observation_error='No such process (synthetic)')
        self.assertEqual(self.validate_log(native_log(observed))['host_fixture'], observed)
        observed['perpid_cgroups'][0].update(cgroup=None, cgroup_observation_error='missing test process')
        with self.assertRaises(ValueError):
            self.validate_log(native_log(observed))

    def test_zero_ignored_wrong_failed_or_incomplete_named_runs_are_not_success(self):
        good = native_log()
        for bad in [good.replace('running 1 test', 'running 0 tests'),
                    good.replace('1 passed; 0 failed; 0 ignored', '0 passed; 0 failed; 1 ignored'),
                    good.replace(runner.SELECTOR, 'another_test'),
                    good.replace('1 passed; 0 failed', '0 passed; 1 failed'),
                    good.split('test result:')[0], good + good]:
            with self.subTest(log=bad), self.assertRaises(ValueError):
                self.validate_log(bad)

    def test_wrong_process_outcome_or_command_cannot_be_overridden_by_a_success_log(self):
        good = process(runner.native_test_command(Path('/tmp/test')))
        for update in [dict(executed=False), dict(exit_code=101), dict(process_exit_code=-9),
                       dict(timed_out=True), dict(source_verified=False),
                       dict(command=['/tmp/test', runner.SELECTOR, '--exact']),
                       dict(command=['/tmp/test', 'negative_refusal_test', '--exact', '--ignored',
                                     '--nocapture', '--test-threads=1'])]:
            bad = {**good, **update}
            with self.subTest(update=update), self.assertRaises(ValueError):
                self.validate_log(native_log(), bad)

    def test_missing_malformed_duplicate_or_negative_fixture_cannot_count(self):
        good = native_log()
        for bad in [good.replace(json.dumps(fixture(), sort_keys=True), '{}'),
                    good.replace(json.dumps(fixture(), sort_keys=True), '{"schema":"' + runner.FIXTURE_SCHEMA),
                    good + json.dumps(fixture()) + '\n',
                    good.replace(runner.FIXTURE_SCHEMA, 'negative-missing-host-refusal')]:
            with self.subTest(log=bad), self.assertRaises((ValueError, json.JSONDecodeError)):
                self.validate_log(bad)

    def test_wrong_scope_counts_host_or_pid_observations_cannot_count(self):
        changes = [dict(sync_success=False), dict(original_server_lifetime_seconds=5),
                   dict(authenticated_requests=2), dict(authenticated_outbox_pending=1),
                   dict(production_activation=True), dict(public_network_ready=True),
                   dict(test_pid=102), dict(push_pids=[103]), dict(sync_pid=True)]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate_log(native_log({**fixture(), **change}))
        for field, value in [('pid', 900), ('role', 'Rust-thread-18'),
                             ('cgroup', '0::/unbounded.slice/service'),
                             ('cgroup', CGROUP + '/another-group'),
                             ('cgroup_observation_error', 'inconsistent available observation')]:
            changed = fixture()
            changed['perpid_cgroups'][4][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate_log(native_log(changed))
        changed = fixture()
        changed['perpid_cgroups'][4]['cgroup'] = CGROUP.replace('-456.service', '-999.service')
        with self.assertRaisesRegex(ValueError, 'OUTBOX_SHARED_ACTUAL_HOST_REQUIRED'):
            self.validate_log(native_log(changed))


class CompleteRunnerControls(unittest.TestCase):
    def observe(self, *, text=None, mutate=None, after_source=None, missing_host=False,
                build_exit=0):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            test, client = create_binaries(root)
            out = root / 'out'
            commands = []
            sources = [source(), source() if after_source is None else after_source]
            sample = dict(thread_cgroup=CGROUP)

            def execute(command, log, *, timeout, expected_source):
                self.assertEqual(expected_source, COMMIT)
                commands.append((command, timeout))
                if command == runner.native_build_command():
                    log.write_text(artifact(test, runner.TARGET, 'test', True) + '\n'
                                   + artifact(client, runner.CLI, 'bin', False) + '\n')
                    result = process(command)
                    result.update(exit_code=build_exit, process_exit_code=build_exit)
                    return result
                self.assertEqual(command, runner.native_test_command(test))
                log.write_text(native_log() if text is None else text)
                if mutate is not None:
                    mutate(test, client, out)
                return process(command)

            host_capture = (dict(side_effect=ValueError('OUTBOX_FIXED_HOST_MEMBERSHIP_REQUIRED'))
                            if missing_host else dict(return_value=sample))
            with patch.dict(os.environ, {'TRNM_EXPECTED_SOURCE_SHA': COMMIT}, clear=True), \
                    patch.object(runner, 'source_identity', side_effect=sources), \
                    patch.object(runner, 'require_original_build_environment'), \
                    patch.object(runner, 'capture_host', **host_capture), \
                    patch.object(runner.ci, 'run', side_effect=execute):
                result = runner.run(out)
            retained = json.loads((out / 'manifest.json').read_text())
            self.assertEqual(result, retained)
            return copy.deepcopy(result), commands

    def test_complete_observation_binds_both_elves_source_log_and_host(self):
        result, commands = self.observe()
        self.assertTrue(result['passed'])
        self.assertEqual([timeout for _, timeout in commands], [900, 90])
        self.assertEqual(result['source_before'], result['source_after'])
        self.assertEqual(result['test_binary_sha256_before'], result['test_binary_sha256_after'])
        self.assertEqual(result['cli_binary_sha256_before'], result['cli_binary_sha256_after'])
        self.assertIn('test.elf', result['files'])
        self.assertIn('cli.elf', result['files'])
        self.assertIn('native.log', result['files'])
        self.assertFalse(result['production_activation'])

    def test_test_or_cli_mutation_and_changed_retained_copy_are_preserved_failures(self):
        mutations = [lambda test, cli, out: test.write_bytes(b'\x7fELFchanged-test'),
                     lambda test, cli, out: cli.write_bytes(b'\x7fELFchanged-cli'),
                     lambda test, cli, out: (out / 'test.elf').write_bytes(b'\x7fELFchanged-copy'),
                     lambda test, cli, out: (out / 'cli.elf').write_bytes(b'\x7fELFchanged-copy')]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                result, _ = self.observe(mutate=mutation)
                self.assertFalse(result['passed'])
                self.assertTrue(any('OUTBOX_BINARY_CHANGED' in error for error in result['failures']))

    def test_same_commit_changed_complete_source_identity_cannot_be_relabelled(self):
        changed = source()
        changed['tree'] = 'd' * 40
        result, _ = self.observe(after_source=changed)
        self.assertFalse(result['passed'])
        self.assertIn('OUTBOX_COMPLETE_SOURCE_CHANGED', result['failures'])
        self.assertNotEqual(result['source_before'], result['source_after'])

    def test_failed_build_and_missing_host_never_execute_the_positive_test(self):
        failed, commands = self.observe(build_exit=101)
        self.assertFalse(failed['passed'])
        self.assertEqual(len(commands), 1)
        self.assertIsNone(failed['process'])
        absent, commands = self.observe(missing_host=True)
        self.assertFalse(absent['passed'])
        self.assertEqual(commands, [])
        self.assertIsNone(absent['process'])

    def test_zero_native_execution_and_different_fixture_host_remain_failed(self):
        zero, _ = self.observe(text=native_log().replace('running 1 test', 'running 0 tests'))
        self.assertFalse(zero['passed'])
        different = fixture()
        for record in different['perpid_cgroups']:
            record['cgroup'] = CGROUP.replace('-456.service', '-999.service')
        mismatch, _ = self.observe(text=native_log(different))
        self.assertFalse(mismatch['passed'])
        self.assertIn('OUTBOX_FIXTURE_RUNNER_HOST_MISMATCH', mismatch['failures'])


if __name__ == '__main__':
    unittest.main()
