#!/usr/bin/env python3
"""Synthetic fixture/refusal controls; never provision a Host or run native CI."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import run_public_fixture_native as architecture
import run_from_zero_host as host
from test_architecture_compare import simulated_report

class ArchitectureAdapterControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name).resolve()
        self.receipts = self.folder / 'receipts'
        self.receipts.mkdir()
        self.out = self.receipts / 'public-fixtures' / architecture.TARGET / architecture.SELECTOR
        self.binary = self.folder / 'compiler-produced-test'
        self.binary.write_bytes(b'\x7fELF synthetic test fixture; never executed\n')
        self.binary.chmod(0o700)
        self.source = {'commit': 'a' * 40, 'tree': 'b' * 40, 'test_sha256': 'c' * 64}
        environment = patch.dict(os.environ, {
            'TRNM_CI_RECEIPT_DIR': str(self.receipts), 'TRNM_EXPECTED_SOURCE_SHA': 'a' * 40,
            'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_JOB': 'architecture-control',
            'CI': 'true', 'GITHUB_ACTIONS': 'true'}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        identity = patch.object(architecture, 'source_identity', return_value=self.source)
        self.identity = identity.start()
        self.addCleanup(identity.stop)
        owner = patch.object(architecture, 'process_identity', side_effect=self.owner_identity)
        owner.start()
        self.addCleanup(owner.stop)
        cwd = patch.object(architecture, 'parent_cwd', return_value={
            'path': str(architecture.ROOT), 'device': 1, 'inode': 2})
        cwd.start()
        self.addCleanup(cwd.stop)

    @staticmethod
    def owner_identity(pid):
        return {'pid': pid, 'parent_pid': 122 if pid == 123 else 123,
                'start_ticks': pid + 1000, 'device': 1, 'inode': pid, 'uid': 1001, 'gid': 1001}

    def parent_observation(self, pid, binary):
        self.assertEqual(pid, 123)
        return architecture.history.file_observation(binary, architecture.history.BINARY_LIMIT)[0]

    def prepare(self, *, target=architecture.TARGET, selector=architecture.SELECTOR,
                cli_binary=None):
        with patch.object(architecture.os, 'getuid', return_value=1001), \
                patch.object(architecture.os, 'getppid', return_value=123), \
                patch.object(architecture.Path, 'cwd', return_value=architecture.ROOT), \
                patch.object(architecture, 'parent_binary', side_effect=self.parent_observation):
            result = architecture.prepare(self.out, self.binary, 123, target=target,
                                           selector=selector, cli_binary=cli_binary)
        return result

    def process(self, command, exit_code=0, *, supervisors=None, timeout_seconds=120, cwd=None):
        if supervisors is None:
            supervisors = json.loads((self.out / 'preparation.json').read_text())['supervisors']
        return {'command': command, 'started': True, 'pid': 456,
                'exit_code': exit_code, 'failure': None, 'cleanup_errors': [],
                'timed_out': False, 'reaped': True, 'timeout_seconds': timeout_seconds,
                'supervisors': supervisors, 'supervisors_bound': True, 'supervisor_exit': None,
                'cwd': str(cwd or architecture.ROOT)}

    def native_outputs(self, command, log, *, environment, supervisors, timeout_seconds, cwd):
        self.assertEqual(command, architecture.native_command(self.binary))
        self.assertEqual(environment[architecture.CHILD], architecture.TARGET + '::' + architecture.SELECTOR)
        self.assertEqual(environment['TRNM_ARCHITECTURE_COMPARE_DIR'], str(self.out / 'native'))
        log.write_text('running 1 test\ntest ' + architecture.SELECTOR + ' ... ok\n'
                       'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
                       '1 filtered out; finished in 0.01s\n')
        (self.out / 'native').mkdir()
        (self.out / 'native/report.json').write_text(json.dumps(simulated_report()))
        return self.process(command, supervisors=supervisors, timeout_seconds=timeout_seconds, cwd=cwd)

    def execute(self, callback=None):
        with patch.object(architecture, 'parent_binary', side_effect=self.parent_observation), \
                patch.object(architecture, 'run_native_process', side_effect=callback or self.native_outputs) as run:
            result = architecture.execution(self.out)
        run.assert_called_once()
        return result

    def bind(self, prepared):
        with patch.object(architecture, 'parent_binary', side_effect=self.parent_observation):
            return architecture.bind_execution(prepared, self.out)

    def test_actual_process_binding_rejects_other_binary_symlink_and_non_elf(self):
        # Read the current real Python ELF without executing it again.
        current = Path(sys.executable).resolve(strict=True)
        pid = int(os.readlink('/proc/self'))
        observed = architecture.parent_binary(pid, current)
        self.assertEqual(observed['path'], str(current))
        with self.assertRaisesRegex(ValueError, 'PUBLIC_FIXTURE_PARENT_ELF_CHANGED'):
            architecture.parent_binary(pid, self.binary)
        self.binary.write_bytes(b'#!/bin/true\n')
        with self.assertRaisesRegex(ValueError, 'PUBLIC_FIXTURE_CURRENT_ELF_REQUIRED'):
            architecture.parent_binary(pid, self.binary)
        link = self.folder / 'linked'
        link.symlink_to(current)
        with self.assertRaises(ValueError):
            architecture.parent_binary(pid, link)

    def test_current_elf_preparation_never_builds_and_cannot_reuse_directory(self):
        with patch.object(architecture, 'run_native_process') as process:
            prepared = self.prepare()
        process.assert_not_called()
        self.assertIs(prepared['completed'], True)
        self.assertIs(prepared['nested_cargo_invoked'], False)
        with self.assertRaises(FileExistsError):
            self.prepare()

    def test_not_ci_wrong_parent_or_child_marker_never_creates_preparation(self):
        for environment in ({'CI': 'false'}, {'GITHUB_ACTIONS': 'false'}, {architecture.CHILD: '1'}):
            with self.subTest(environment=environment), patch.dict(os.environ, environment), \
                    self.assertRaises(ValueError):
                self.prepare()
            self.assertFalse(self.out.exists())
        with patch.object(architecture.os, 'getuid', return_value=1001), \
                patch.object(architecture.os, 'getppid', return_value=999), \
                patch.object(architecture.Path, 'cwd', return_value=architecture.ROOT), \
                self.assertRaisesRegex(ValueError, 'PUBLIC_FIXTURE_DIRECT_WORKSPACE_PARENT_REQUIRED'):
            architecture.prepare(self.out, self.binary, 123)

    def test_source_change_is_retained_and_incomplete_preparation_is_refused(self):
        with patch.object(architecture, 'source_identity', side_effect=[self.source, {'commit': 'd' * 40}]):
            prepared = self.prepare()
        self.assertIs(prepared['completed'], False)
        self.assertNotEqual(prepared['source_before'], prepared['source_after'])
        with self.assertRaisesRegex(ValueError, 'PUBLIC_FIXTURE_PREPARATION_REQUIRED'):
            architecture.validate_preparation(self.out)

    def test_parent_job_environment_and_elf_identity_are_bound(self):
        self.prepare()
        for environment in ({'GITHUB_RUN_ATTEMPT': '2'}, {'OPENSSL_DIR': '/other-provider'}):
            with self.subTest(environment=environment), patch.dict(os.environ, environment), \
                    self.assertRaises(ValueError):
                architecture.validate_preparation(self.out)
        replacement = self.folder / 'replacement'
        replacement.write_bytes(self.binary.read_bytes())
        replacement.chmod(0o700)
        replacement.replace(self.binary)
        with patch.object(architecture, 'parent_binary', side_effect=self.parent_observation), \
                self.assertRaisesRegex(ValueError, 'PUBLIC_FIXTURE_PREPARED_ELF_CHANGED'):
            architecture.validate_preparation(self.out)

    def test_explicit_native_output_is_fresh_and_bound(self):
        explicit = self.folder / 'caller-chosen-native'
        with patch.dict(os.environ, {'TRNM_ARCHITECTURE_COMPARE_DIR': str(explicit)}):
            prepared = self.prepare()
            self.assertEqual(prepared['native_output'], str(explicit))
        with patch.object(architecture, 'parent_binary', side_effect=self.parent_observation), \
                self.assertRaisesRegex(ValueError, 'ARCHITECTURE_PREPARED_OUTPUT_CHANGED'):
            architecture.validate_preparation(self.out)
        explicit.mkdir()
        with patch.dict(os.environ, {'TRNM_ARCHITECTURE_COMPARE_DIR': str(explicit)}), \
                self.assertRaisesRegex(ValueError, 'ARCHITECTURE_FRESH_NATIVE_OUTPUT_REQUIRED'):
            architecture.native_output(self.out)

    def test_whole_named_execution_report_and_exact_elf_bind_once(self):
        prepared = self.prepare()
        result = self.execute()
        self.assertIs(result['passed'], True)
        self.assertEqual(result['named_execution']['test'], architecture.SELECTOR)
        self.assertEqual(self.bind(prepared)['samples'], 18)
        with self.assertRaises(FileExistsError):
            architecture.execution(self.out)
        manifest = self.out / 'manifest.json'
        for pid in (None, 0, True, '456'):
            changed = copy.deepcopy(result)
            changed['process']['pid'] = pid
            manifest.write_text(json.dumps(changed))
            with self.subTest(pid=pid), self.assertRaisesRegex(ValueError, 'PUBLIC_FIXTURE_NATIVE_PROCESS_REQUIRED'):
                self.bind(prepared)

    def test_successful_process_without_named_log_or_report_is_not_pass(self):
        self.prepare()

        def missing(command, log, *, environment, **owners):
            log.write_text('running 0 tests\ntest result: ok. 0 passed; 0 failed\n')
            return self.process(command)

        result = self.execute(missing)
        self.assertIs(result['passed'], False)
        self.assertIsNone(result['named_execution'])
        self.assertIsNone(result['report'])
        self.assertGreaterEqual(len(result['failures']), 2)

    def test_failed_native_process_retains_report_without_promoting_it(self):
        self.prepare()

        def failing(command, log, *, environment, **owners):
            self.native_outputs(command, log, environment=environment, **owners)
            return self.process(command, 101)

        result = self.execute(failing)
        self.assertIs(result['passed'], False)
        self.assertEqual(result['process']['exit_code'], 101)
        self.assertEqual(result['report']['samples'], 18)

    def test_report_has_all_original_samples_order_and_native_assertions(self):
        path = self.folder / 'report.json'
        changes = [lambda r: r['samples'].pop(),
                   lambda r: r['samples'].__setitem__(1, copy.deepcopy(r['samples'][0])),
                   lambda r: r['samples'][0].update(sample=True),
                   lambda r: r['samples'][0].update(errors=['PUBLIC_HOST_KERNEL_PARENT']),
                   lambda r: r['samples'][0].update(cold_reopen_equal=False)]
        for edit in changes:
            report = simulated_report()
            edit(report)
            path.write_text(json.dumps(report))
            with self.assertRaises(ValueError):
                architecture.report_observation(path)

    def test_full_business_gate_failure_is_distinct_from_native_invariants(self):
        path = self.folder / 'report.json'
        report = simulated_report()
        report['all_finite_business_targets_met'] = False
        report['samples'][0].update(finite_business_target_met=False, confirmed_transactions=0)
        path.write_text(json.dumps(report))
        observed, _ = architecture.report_observation(path)
        self.assertIs(observed['native_invariants_passed'], True)
        self.assertIsNone(observed['business_reader'])
        self.assertIn('ARCHITECTURE_FINITE_TARGET', observed['business_reader_failure'])

    def test_report_or_log_change_after_execution_cannot_borrow_a_pass(self):
        prepared = self.prepare()
        self.execute()
        path = self.out / 'native/report.json'
        report = json.loads(path.read_text())
        report['samples'][0]['full_business_latency_ns'] += 1
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, 'ARCHITECTURE_NATIVE_REPORT_CHANGED'):
            self.bind(prepared)
        (self.out / 'native.log').write_text('synthetic changed transcript\n')
        with self.assertRaises(ValueError):
            self.bind(prepared)

    def test_original_parent_cwd_and_owner_starttime_cannot_change(self):
        self.prepare()
        for cwd in ({'path': str(architecture.ROOT / 'trillionnium/crates/trnm-pon-node'),
                     'device': 1, 'inode': 2},
                    {'path': str(architecture.ROOT), 'device': 1, 'inode': 3}):
            with self.subTest(cwd=cwd), \
                    patch.object(architecture, 'parent_binary', side_effect=self.parent_observation), \
                    patch.object(architecture, 'parent_cwd', return_value=cwd), \
                    self.assertRaisesRegex(ValueError, 'PUBLIC_FIXTURE_PARENT_CWD_CHANGED'):
                architecture.validate_preparation(self.out)
        for role in (123, os.getpid()):
            def changed(pid):
                value = self.owner_identity(pid)
                if pid == role:
                    value['start_ticks'] += 1
                return value
            with self.subTest(role=role), \
                    patch.object(architecture, 'process_identity', side_effect=changed), \
                    self.assertRaisesRegex(ValueError, 'PUBLIC_FIXTURE_SUPERVISOR_CHANGED'):
                architecture.validate_preparation(self.out)

    def test_exact_nine_fixtures_keep_original_selector_bounds(self):
        expected = {
            ('architecture_delivery_compare', 'signed_dag_delivery_comparison_uses_same_native_business_and_confirmation_contract'),
            ('public_intake_v2', 'unknown_caller_cannot_override_ledger_and_full_sync_independently_verifies_actual_work'),
            ('public_intake_v2', 'one_packet_history_preserves_partial_progress_and_independent_validation'),
            ('public_cli', 'actual_public_cli_pins_server_denials_fail_and_sync_verifies_native_history'),
            ('public_pool_cli', 'actual_v3_cli_unknown_guest_funding_and_atomic_renewal_reach_native_receiver'),
            ('public_pool_cli', 'actual_pinned_peer_cli_follows_native_blocks_and_closes_shared_owner'),
            ('mining_service_budget', 'mining_runtime_ends_before_service_and_fresh_native_follower_confirms_last_chain'),
            ('evaluation_sync_observation', 'actual_public_full_sync_query_partial_refusals_reorg_and_retirement'),
            ('native_node', 'test_authenticated_cli_push_and_sync_share_one_durable_outbox_owner'),
        }
        self.assertEqual(set(architecture.FIXTURES), expected)
        self.assertEqual(sum(architecture.FIXTURES.values()), 6)
        for target, selector in expected:
            spec = architecture.fixture(target, selector)
            self.assertEqual(spec['timeout_seconds'], 120 if target == architecture.TARGET else None)
            self.assertEqual(architecture.native_command(self.binary, selector),
                             [str(self.binary), selector, '--exact', '--show-output', '--test-threads=1'])
        for target, selector in (('native_node', 'test_authenticated_cli_push_and_sync'),
                                 ('public_cli', '--list'), ('foreign', architecture.SELECTOR)):
            with self.subTest(target=target, selector=selector), self.assertRaises(ValueError):
                architecture.fixture(target, selector)

    def test_direct_fixture_cannot_claim_undeclared_cli(self):
        with self.assertRaisesRegex(ValueError, 'PUBLIC_FIXTURE_EXACT_CLI_REQUIRED'):
            self.prepare(cli_binary=self.binary)
        self.assertFalse(self.out.exists())

    def test_cli_fixture_binds_original_compiled_cli_and_requires_full_named_exit(self):
        target, selector = next(pair for pair, needed in architecture.FIXTURES.items() if needed)
        self.out = self.receipts / 'public-fixtures' / target / selector
        with self.assertRaisesRegex(ValueError, 'PUBLIC_FIXTURE_EXACT_CLI_REQUIRED'):
            self.prepare(target=target, selector=selector)
        cli = self.folder / 'compiler-produced-cli'
        cli.write_bytes(b'\x7fELF synthetic CLI; never executed\n')
        cli.chmod(0o700)
        prepared = self.prepare(target=target, selector=selector, cli_binary=cli)

        def named(command, log, *, environment, supervisors, timeout_seconds, cwd):
            self.assertEqual(command, architecture.native_command(self.binary, selector))
            self.assertEqual(environment[architecture.CHILD], target + '::' + selector)
            self.assertEqual(environment['TRNM_PUBLIC_FIXTURE_CLI_BINARY'], str(cli))
            self.assertNotIn('TRNM_ARCHITECTURE_COMPARE_DIR', environment)
            self.assertIsNone(timeout_seconds)
            log.write_text('running 1 test\ntest ' + selector + ' ... ok\n'
                           'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
                           '0 filtered out; finished in 0.01s\n')
            return self.process(command, supervisors=supervisors, timeout_seconds=None, cwd=cwd)

        result = self.execute(named)
        self.assertIs(result['passed'], True)
        self.assertIsNone(result['report'])
        self.assertIsNone(result['report_file'])
        self.assertFalse((self.out / 'native').exists())
        binding = self.bind(prepared)
        self.assertIs(binding['performance_acceptance'], False)
        self.assertEqual(binding['cli_binary_sha256'], prepared['cli_binary']['sha256'])
        result['report'] = {'invented': True}
        (self.out / 'manifest.json').write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, 'PUBLIC_FIXTURE_UNDECLARED_REPORT'):
            self.bind(prepared)
        cli.write_bytes(b'\x7fELF changed compiled CLI\n')
        with patch.object(architecture, 'parent_binary', side_effect=self.parent_observation), \
                self.assertRaisesRegex(ValueError, 'PUBLIC_FIXTURE_PREPARED_CLI_CHANGED'):
            architecture.validate_preparation(self.out)

    def test_recorded_owner_exit_or_timeout_cannot_borrow_successful_named_report(self):
        prepared = self.prepare()
        original = self.execute()
        for change in ({'supervisor_exit': 'libtest'}, {'supervisor_exit': 'launcher'},
                       {'supervisors_bound': False}, {'timed_out': True}, {'reaped': False},
                       {'cwd': '/wrong/cwd'}, {'timeout_seconds': None}):
            result = copy.deepcopy(original)
            result['process'].update(change)
            (self.out / 'manifest.json').write_text(json.dumps(result))
            with self.subTest(change=change), \
                    self.assertRaisesRegex(ValueError, 'PUBLIC_FIXTURE_NATIVE_PROCESS_REQUIRED'):
                self.bind(prepared)


if __name__ == '__main__':
    unittest.main()
