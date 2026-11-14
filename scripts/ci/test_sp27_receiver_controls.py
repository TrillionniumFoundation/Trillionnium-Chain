#!/usr/bin/env python3
"""Synthetic adapter/readback controls; no native service or experiment claims."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run_from_zero_host as host
import run_sp27_receiver_controls as sp27
import public_host_ci_observation as observation


class AdapterControls(unittest.TestCase):
    def test_only_exact_command_and_external_output_are_admitted(self):
        command = ['python3', sp27.SCRIPT, '--out', '/tmp/sp27-receiver-controls']
        self.assertEqual(host.validate_command(command), Path(command[-1]))
        for bad in (command + ['--relax-host'], ['python3', '/tmp/foreign.py', '--out', command[-1]],
                    [*command[:3], str(host.ROOT / 'within-checkout')]):
            with self.subTest(command=bad), self.assertRaises(ValueError):
                host.validate_command(bad)

    def test_preparation_and_readback_use_only_new_adapter(self):
        command = ['python3', sp27.SCRIPT, '--out', '/tmp/sp27-receiver-controls']
        output = Path(command[-1])
        with patch.object(sp27, 'validate_preparation', return_value={'prepared': True}) as callback:
            self.assertEqual(host.prepare_command(command, output, Path('/tmp/host')), {'prepared': True})
            callback.assert_called_once_with(output)
        with patch.object(sp27, 'bind_execution', return_value={'bound': True}) as callback:
            self.assertEqual(host.bind_command(command, {'prepared': True}, output), {'bound': True})
            callback.assert_called_once_with({'prepared': True}, output)

    def test_original_resources_and_outer_timeout_are_preserved(self):
        self.assertEqual(sp27.NATIVE_TIMEOUT_SECONDS, 90)
        self.assertEqual(observation.LIMITS, {'cpu.max': '25000 100000', 'cpu.max.burst': '0',
            'memory.max': '2147483648', 'memory.swap.max': '0', 'pids.max': '256'})
        self.assertNotIn('TRNM_SP27_RECEIVER_CONTROLS_DIR', host.ENVIRONMENT)


class SyntheticHealthReadbackControls(unittest.TestCase):
    """Real file hashing over synthetic records, without running a native test."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.out = Path(self.temporary.name).resolve()
        (self.out / 'native/raw').mkdir(parents=True)
        binary = self.out / 'synthetic-not-executable'
        binary.write_bytes(b'synthetic fixture only; never executed')
        self.prepared = {
            'binary': sp27.history.file_observation(binary, 1024)[0],
            # Use serialized key order rather than job_identity() insertion
            # order: the declared run must not depend on dictionary ordering.
            'job': {'GITHUB_JOB': 'synthetic', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_ID': '123'},
            'source_before': {'commit': 'a' * 40, 'files_sha256': {
                sp27.native.SOURCE: 'b' * 64, sp27.MODULE: 'c' * 64}},
        }
        self.identity = {
            'schema': 'sp27-receiver-run-identity-v1',
            'pid': 1234, 'hostname': 'synthetic-host',
            'boot_id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
            'process_cgroup': '0::/trnmponpublic.slice/synthetic.service',
            'binary_path': str(binary), 'binary_sha256': sp27.digest(binary),
            'binary_identity_error': None,
            'compiled_test_source_sha256': 'b' * 64,
            'compiled_health_module_sha256': 'c' * 64,
            'runner_declared_source_sha': 'a' * 40,
            'runner_declared_run_id': '123-1-synthetic',
            'github_run_id': '123', 'github_run_attempt': '1',
        }
        self.host_record = {
            'schema': 'sp27-receiver-host-readback-v1',
            'fixed_parent': '/sys/fs/cgroup/trnmponpublic.slice',
            'verified': True, 'sample': {'synthetic_fixture_only': True}, 'error': None,
        }
        for when in ('before', 'after'):
            self.save(f'identity-{when}.json', self.identity)
            self.save(f'host-{when}.json', self.host_record)
        self.acquisition = {
            'schema': 'sp27-receiver-seven-packet-acquisition-v1',
            'same_seven_packets_in_all_health_phases': True,
            # Deliberately not real signed packets. This layer binds actual
            # bytes/inventory; only the native verifier validates cryptography.
            'signed_honest_packets': ['00' + f'{index:02x}' for index in range(7)],
            'packet_ids': [f'{index:064x}' for index in range(7)],
        }
        self.save('acquisition.json', self.acquisition)
        self.phase = {
            'requested_window_ns': 4_000_000_000, 'workers': 0,
            'invariant_target_met': True, 'finite_business_target_met': True,
            'client_confirmed_before_original_window_end': True,
            'full_native_state_equal': True, 'client_confirmed_transactions': 1,
            'confirmation_ended_ns': 3_999_999_999, 'verification_errors': [],
        }
        self.report = {
            'schema': 'sp27-receiver-health-gate-v1',
            'qualification': 'HEALTH_GATE_PASSED_CONTROLS_PENDING', 'health_gate_passed': True,
            'planned_health_repetitions': 3, 'attempted_health_repetitions': 3,
            'completed_health_repetitions': 3, 'not_executed_health_repetitions': 0,
            'incomplete_health_repetitions': 0, 'requested_window_ns': 4_000_000_000,
            'pressure_controls_executed': 0, 'causal_mechanism_status': 'UNKNOWN',
            'publication_qualified': False, 'public_network_ready': False,
            'production_activation': False, 'binary_unchanged': True,
            'host_before_verified': True, 'host_after_verified': True,
            'first_divergence': None, 'health_phases': [],
        }
        for index in range(3):
            self.save_phase(index, self.phase)

    def save(self, name, value):
        path = self.out / 'native' / name
        path.write_text(json.dumps(value, sort_keys=True) + '\n')
        return sp27.digest(path)

    def save_phase(self, index, phase, *, healthy=True):
        name = f'raw/health-{index:03}.json'
        row = {'health_index': index, 'raw_record': name, 'raw_sha256': self.save(name, phase),
               'healthy': healthy,
               'native_final_gate': phase.get('client_confirmed_before_original_window_end'),
               'confirmation_ended_ns': phase.get('confirmation_ended_ns')}
        if index == len(self.report['health_phases']):
            self.report['health_phases'].append(row)
        else:
            self.report['health_phases'][index] = row
        self.save('report.json', self.report)

    def read(self):
        return sp27.read_health(self.out, self.prepared)

    def no_go(self, *, attempted, completed, divergence):
        self.report.update(qualification='NO_GO', health_gate_passed=False,
                           attempted_health_repetitions=attempted,
                           completed_health_repetitions=completed,
                           not_executed_health_repetitions=3 - attempted,
                           incomplete_health_repetitions=attempted - completed,
                           first_divergence=divergence)
        self.report['health_phases'] = self.report['health_phases'][:completed]
        self.save('first-divergence.json', divergence)
        self.save('report.json', self.report)

    def test_exact_synthetic_records_bind_actual_file_bytes(self):
        report, observed, readback = self.read()
        self.assertEqual(report, self.report)
        self.assertEqual(observed['sha256'], sp27.digest(self.out / 'native/report.json'))
        self.assertEqual(set(readback), {'identity-before.json', 'identity-after.json',
                         'host-before.json', 'host-after.json', 'acquisition.json',
                         *(f'raw/health-{index:03}.json' for index in range(3))})
        self.assertEqual(readback['acquisition.json']['sha256'],
                         sp27.digest(self.out / 'native/acquisition.json'))

    def test_native_unsigned_integer_predicates_do_not_accept_bool_or_float(self):
        for key, value in (('workers', False), ('client_confirmed_transactions', True),
                           ('requested_window_ns', 4_000_000_000.0), ('confirmation_ended_ns', True)):
            phase = dict(self.phase, **{key: value})
            self.save_phase(0, phase)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'SP27_NATIVE_GATE_MISMATCH'):
                self.read()

    def test_report_integer_scope_and_denominators_require_integer_types(self):
        original = copy.deepcopy(self.report)
        for key, value in (('planned_health_repetitions', 3.0),
                           ('requested_window_ns', 4_000_000_000.0),
                           ('pressure_controls_executed', False),
                           ('attempted_health_repetitions', 3.0),
                           ('completed_health_repetitions', 3.0),
                           ('not_executed_health_repetitions', False),
                           ('incomplete_health_repetitions', False)):
            self.report = dict(original, **{key: value})
            self.save('report.json', self.report)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'SP27_HEALTH_'):
                self.read()

    def test_summary_cannot_coerce_phase_index_gate_or_endpoint(self):
        for key, value in (('health_index', False), ('native_final_gate', 1),
                           ('confirmation_ended_ns', 3_999_999_999.0)):
            self.save_phase(0, self.phase)
            self.report['health_phases'][0][key] = value
            self.save('report.json', self.report)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError,
                    'SP27_HEALTH_PHASE_IDENTITY|SP27_NATIVE_GATE_MISMATCH'):
                self.read()

    def test_matching_before_after_cannot_substitute_another_build_or_run(self):
        for key in ('binary_path', 'binary_sha256', 'compiled_test_source_sha256',
                    'compiled_health_module_sha256', 'runner_declared_source_sha',
                    'runner_declared_run_id', 'github_run_id', 'github_run_attempt'):
            identity = dict(self.identity, **{key: 'another-source-or-run'})
            for when in ('before', 'after'):
                self.save(f'identity-{when}.json', identity)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError,
                    'SP27_COMPILED_SOURCE_BINARY_RUN_BINDING'):
                self.read()

    def test_process_facts_must_be_present_typed_and_unchanged(self):
        for key, value in (('pid', True), ('hostname', None), ('boot_id', 'changed'),
                           ('process_cgroup', '0::/other.slice')):
            self.save('identity-after.json', dict(self.identity, **{key: value}))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'SP27_NATIVE_PROCESS_IDENTITY_'):
                self.read()

    def test_identity_host_and_attempted_phase_acquisition_files_must_exist(self):
        for name in ('identity-before.json', 'identity-after.json', 'host-before.json',
                     'host-after.json', 'acquisition.json'):
            path = self.out / 'native' / name
            raw = path.read_bytes()
            path.unlink()
            try:
                with self.subTest(name=name), self.assertRaises(OSError):
                    self.read()
            finally:
                path.write_bytes(raw)

    def test_acquisition_requires_seven_recorded_packets_and_ids(self):
        for changed in ({'signed_honest_packets': self.acquisition['signed_honest_packets'][:6]},
                        {'signed_honest_packets': self.acquisition['signed_honest_packets'] + ['00']},
                        {'packet_ids': self.acquisition['packet_ids'][:6]},
                        {'signed_honest_packets': ['not hex'] * 7},
                        {'packet_ids': ['aa'] * 7},
                        {'same_seven_packets_in_all_health_phases': 1}):
            self.save('acquisition.json', dict(self.acquisition, **changed))
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError,
                    'SP27_SEVEN_PACKET_ACQUISITION_REQUIRED'):
                self.read()

    def test_host_claims_are_bound_to_actual_native_readbacks(self):
        for changed in ({'verified': 1}, {'fixed_parent': '/sys/fs/cgroup/other.slice'},
                        {'verified': False, 'sample': None, 'error': 'PUBLIC_HOST_KERNEL_PARENT'},
                        {'sample': None}, {'error': 'unobserved failure'}):
            self.save('host-before.json', dict(self.host_record, **changed))
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'SP27_NATIVE_HOST_'):
                self.read()

    def test_no_go_before_acquisition_retains_legitimate_absence(self):
        (self.out / 'native/acquisition.json').unlink()
        failed_host = dict(self.host_record, verified=False, sample=None, error='PUBLIC_HOST_KERNEL_PARENT')
        self.save('host-before.json', failed_host)
        self.report['host_before_verified'] = False
        self.no_go(attempted=0, completed=0, divergence={
            'schema': 'sp27-receiver-first-divergence-v1', 'qualification': 'NO_GO',
            'stage': 'pre-execution-identity-or-host', 'host': failed_host})
        report, _, readback = self.read()
        self.assertEqual(report['qualification'], 'NO_GO')
        self.assertNotIn('acquisition.json', readback)
        self.assertIn('first-divergence.json', readback)

    def test_false_native_gate_before_deadline_is_no_go_and_stops(self):
        self.save_phase(0, dict(self.phase, client_confirmed_before_original_window_end=False), healthy=False)
        self.no_go(attempted=1, completed=1, divergence={
            'schema': 'sp27-receiver-first-divergence-v1', 'qualification': 'NO_GO',
            'health_index': 0, 'native_final_gate': False})
        self.assertEqual(self.read()[0]['qualification'], 'NO_GO')

    def test_following_phase_after_unhealthy_control_is_refused(self):
        self.save_phase(0, dict(self.phase, client_confirmed_before_original_window_end=False), healthy=False)
        self.no_go(attempted=3, completed=3, divergence={
            'schema': 'sp27-receiver-first-divergence-v1', 'qualification': 'NO_GO', 'health_index': 0})
        with self.assertRaisesRegex(ValueError, 'SP27_CONTINUED_AFTER_UNHEALTHY_CONTROL'):
            self.read()

    def test_bound_execution_refuses_changed_acquisition_even_with_valid_inventory(self):
        report, report_file, readback = self.read()
        manifest = {
            'schema': sp27.SCHEMA, 'collection_completed': True, 'failures': [],
            'job': self.prepared['job'], 'causal_mechanism_established': False,
            'runtime_limits_or_deadlines_changed': False,
            'source_before': self.prepared['source_before'], 'source_after': self.prepared['source_before'],
            'binary_before': self.prepared['binary'], 'binary_after': self.prepared['binary'],
            'report_file': report_file, 'native_readback_files': readback,
            'qualification': report['qualification'],
        }
        (self.out / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True) + '\n')
        changed = copy.deepcopy(self.acquisition)
        changed['signed_honest_packets'][0] = 'ffff'
        self.save('acquisition.json', changed)
        with patch.object(sp27, 'validate_preparation', return_value=self.prepared), \
                patch.object(sp27.history, 'job_identity', return_value=self.prepared['job']), \
                self.assertRaisesRegex(ValueError, 'SP27_NATIVE_READBACK_CHANGED'):
            sp27.bind_execution(self.prepared, self.out)


    def binding_manifest(self):
        # Only synthetic ordinary files are used; no native command is run.
        report, observed, readback = self.read()
        run = self.out / 'run'
        run.mkdir()
        stdout = ('running 1 test\n'
                  f'test {sp27.SELECTOR} ... ok\n'
                  'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
                  '0 filtered out; finished in 0.001s\n')
        (run / 'stdout').write_text(stdout)
        (run / 'stderr').write_bytes(b'')
        process = {
            'command': [self.prepared['binary']['path'], sp27.SELECTOR,
                        '--exact', '--ignored', '--show-output', '--test-threads=1'],
            'exit_code': 0, 'timed_out': False,
            'stdout_sha256': sp27.digest(run / 'stdout'),
            'stderr_sha256': sp27.digest(run / 'stderr'),
        }
        return {
            'schema': sp27.SCHEMA, 'collection_completed': True, 'failures': [],
            'job': self.prepared['job'], 'causal_mechanism_established': False,
            'runtime_limits_or_deadlines_changed': False,
            'source_before': self.prepared['source_before'],
            'source_after': self.prepared['source_before'],
            'binary_before': self.prepared['binary'], 'binary_after': self.prepared['binary'],
            'report_file': observed, 'qualification': report['qualification'],
            'native_readback_files': readback, 'process': process,
            'named_execution': sp27.named_test(stdout.splitlines(), sp27.SELECTOR),
        }

    def bind_manifest(self, value):
        (self.out / 'manifest.json').write_text(json.dumps(value, sort_keys=True) + '\n')
        with patch.object(sp27, 'validate_preparation', return_value=self.prepared), \
                patch.object(sp27.history, 'job_identity', return_value=self.prepared['job']):
            return sp27.bind_execution(self.prepared, self.out)

    def test_execution_binding_accepts_exact_synthetic_process(self):
        result = self.bind_manifest(self.binding_manifest())
        self.assertFalse(result['successful_collection_is_business_qualification'])
        self.assertFalse(result['runtime_limits_or_deadlines_changed'])

    def test_execution_binding_rejects_changed_process_with_unchanged_logs(self):
        original = self.binding_manifest()
        command = original['process']['command']
        changes = [
            ('command missing', 'command', None, True),
            ('command null', 'command', None, False),
            ('command string', 'command', ' '.join(command), False),
            ('different binary', 'command', ['/synthetic/other-binary', *command[1:]], False),
            ('different selector', 'command', [command[0], 'different_selector', *command[2:]], False),
            ('extra flag', 'command', [*command, '--nocapture'], False),
            ('missing flag', 'command', [*command[:3], *command[4:]], False),
            ('reordered flags', 'command', [*command[:4], command[5], command[4]], False),
            ('exit missing', 'exit_code', None, True),
            ('exit positive', 'exit_code', 1, False),
            ('exit negative', 'exit_code', -1, False),
            ('exit true', 'exit_code', True, False),
            ('exit false', 'exit_code', False, False),
            ('exit null', 'exit_code', None, False),
            ('exit float', 'exit_code', 0.0, False),
            ('timeout missing', 'timed_out', None, True),
            ('timeout true', 'timed_out', True, False),
            ('timeout numeric zero', 'timed_out', 0, False),
            ('timeout null', 'timed_out', None, False),
            ('timeout text', 'timed_out', 'false', False),
        ]
        for label, field, value, missing in changes:
            changed = copy.deepcopy(original)
            if missing:
                del changed['process'][field]
            else:
                changed['process'][field] = value
            with self.subTest(change=label), self.assertRaisesRegex(
                    ValueError, 'SP27_NATIVE_PROCESS_REQUIRED'):
                self.bind_manifest(changed)


if __name__ == '__main__':
    unittest.main()
