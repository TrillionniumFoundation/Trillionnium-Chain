#!/usr/bin/env python3
"""Harmless process and refusal controls; no native Host or Rust qualification."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import native_test_runner as runner
import run_architecture_delivery_native as architecture
import run_from_zero_host as host
import run_history_native as history
from verify_ci_source import verify


def synthetic_report():
    rows = []
    for scenario in architecture.SCENARIOS:
        for mode in architecture.MODES:
            for sample in range(3):
                rows.append(dict(scenario=scenario, mode=mode, sample=sample,
                    finite_business_target_met=True, native_state_equal=True,
                    cold_reopen_equal=True, errors=[], confirmed_transactions=32,
                    signed_transaction_count=32, independent_confirmations=[
                        dict(confirmed=True, depth=6, finalized=False, execution_authority=False)
                        for _ in range(32)]))
    return dict(schema='native-signed-dag-delivery-comparison-v1',
        all_finite_business_targets_met=True, balanced_cyclic_mode_order=True,
        same_signed_packets_across_modes_and_repetitions=True,
        architecture_winner_declared=False, independent_accepted=False,
        production_activation=False, protocol_switch_qualified=False, wan_tested=False,
        samples_per_workload_and_mode=3, samples=rows)


def synthetic_transcript():
    return ('running 2 tests\n' + ''.join('test ' + name + ' ... ok\n'
            for name in sorted(architecture.TESTS)) +
            'test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; '
            '0 filtered out; finished in 0.01s\n').encode()


class ArchitectureControls(unittest.TestCase):
    def test_other_targets_retain_actual_arguments_environment_and_cwd(self):
        with tempfile.TemporaryDirectory() as raw:
            folder = Path(raw)
            command = [sys.executable, str(Path(runner.__file__).resolve()),
                sys.executable, '-c', 'import json,os,sys;print(json.dumps('
                '{"argv":sys.argv[1:],"cwd":os.getcwd(),"marker":os.environ["TEST_MARKER"]}));'
                'sys.exit(7)', '--exact', 'a space', '--ignored']
            result = subprocess.run(command, cwd=folder, env=dict(os.environ, TEST_MARKER='kept'),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(result.returncode, 7)
            self.assertEqual(json.loads(result.stdout),
                dict(argv=['--exact', 'a space', '--ignored'], cwd=str(folder), marker='kept'))

    def test_target_match_is_exact_and_filtered_or_local_invocation_refuses(self):
        name = architecture.TARGET + '-0123456789abcdef'
        self.assertTrue(runner.is_architecture_target('/target/debug/deps/' + name))
        for other in (name + '.d', name + '.exe', name + '0', 'not_' + name,
                      architecture.TARGET, architecture.TARGET + '-A123456789abcdef'):
            with self.subTest(other=other):
                self.assertFalse(runner.is_architecture_target(other))
        with patch.object(host, 'outer') as provision, patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'UNFILTERED'):
                runner.main([name, '--list'])
            with self.assertRaisesRegex(ValueError, 'HOSTED_UNPRIVILEGED'):
                runner.main([name])
            provision.assert_not_called()

    def test_transcript_rejects_zero_skipped_filtered_duplicate_and_wrong_test(self):
        good = synthetic_transcript()
        self.assertEqual(architecture.validate_transcript(good)['executed_tests'], 2)
        changes = [(b'running 2 tests', b'running 0 tests'), (b'0 ignored', b'1 ignored'),
                   (b'0 filtered out', b'1 filtered out'), (b' ... ok', b' ... ignored'),
                   (sorted(architecture.TESTS)[0].encode(), b'unrelated_test'),
                   (sorted(architecture.TESTS)[0].encode(), sorted(architecture.TESTS)[1].encode())]
        for before, after in changes:
            with self.subTest(after=after), self.assertRaises(ValueError):
                architecture.validate_transcript(good.replace(before, after, 1))

    def test_report_requires_every_sample_and_original_confirmation_contract(self):
        good = synthetic_report()
        self.assertFalse(architecture.validate_report(good)['four_second_pressure_gate_qualified'])
        changes = [lambda r: r['samples'].pop(),
            lambda r: r['samples'].__setitem__(0, copy.deepcopy(r['samples'][1])),
            lambda r: r.update(production_activation=True),
            lambda r: r.update(all_finite_business_targets_met=False),
            lambda r: r['samples'][0].update(native_state_equal=False),
            lambda r: r['samples'][0].update(cold_reopen_equal=False),
            lambda r: r['samples'][0].update(errors=['PUBLIC_HOST_KERNEL_PARENT']),
            lambda r: r['samples'][0].update(confirmed_transactions=31),
            lambda r: r['samples'][0].update(signed_transaction_count=True),
            lambda r: r['samples'][0]['independent_confirmations'].pop(),
            lambda r: r['samples'][0]['independent_confirmations'][0].update(depth=5),
            lambda r: r['samples'][0]['independent_confirmations'][0].update(finalized=True),
            lambda r: r['samples'][0]['independent_confirmations'][0].update(execution_authority=True)]
        for mutate in changes:
            value = copy.deepcopy(good)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                architecture.validate_report(value)

    def test_host_dispatch_adds_only_exact_mode_and_preserves_original_limits(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / 'architecture-native'
            command = ['python3', architecture.SCRIPT, '--out', str(out)]
            self.assertEqual(host.validate_command(command), out)
            for bad in (command + ['--skip'], ['python3', architecture.SCRIPT, str(out)],
                        ['python3', 'anything.py', '--out', str(out)]):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    host.validate_command(bad)
            with patch.object(architecture, 'validate_preparation', return_value={'fixture': True}) as check:
                with patch.object(host, 'prepare_native_build') as build:
                    self.assertEqual(host.prepare_command(command, out, out.parent), {'fixture': True})
                    check.assert_called_once_with(out)
                    build.assert_not_called()
            args = host.service_command('fixture.service', out, command, 1234, 1234, {})
            self.assertIn('--slice=trnmponpublic.slice', args)
            self.assertIn('--property=KillMode=control-group', args)
            self.assertIn('--property=NoNewPrivileges=yes', args)
            self.assertIn('--property=CapabilityBoundingSet=', args)
            self.assertFalse(any('CPUQuota=' in item or 'MemoryMax=' in item for item in args))


class BoundHarmlessProcess(unittest.TestCase):
    """Synthetic output exercises binding only; it is never native test evidence."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.root = self.home / 'source'
        self.root.mkdir()
        self.package = self.root / 'trillionnium/crates/trnm-pon-node'
        self.source = self.root / architecture.SOURCE
        self.source.parent.mkdir(parents=True)
        self.source.write_text('// Harmless source identity fixture; not native Rust.\n')
        def git(*args):
            return subprocess.check_output(['git', *args], cwd=self.root, text=True,
                                           stderr=subprocess.DEVNULL).strip()
        git('init', '-b', 'fixture')
        git('config', 'user.name', 'Architecture binding fixture')
        git('config', 'user.email', 'fixture@example.invalid')
        git('add', '.')
        git('commit', '-m', 'harmless fixture')
        self.head = git('rev-parse', 'HEAD')
        self.receipts = self.home / 'receipts'
        self.receipts.mkdir()
        (self.receipts / 'source.json').write_text(json.dumps(verify('head', self.head, root=self.root)))
        self.out = self.receipts / 'architecture-native'
        self.target = self.home / 'target'
        deps = self.target / 'debug/deps'
        deps.mkdir(parents=True)
        self.binary = deps / (architecture.TARGET + '-0123456789abcdef')
        program = ('#!' + sys.executable + '\nimport json,os\nfrom pathlib import Path\n'
            'Path(os.environ["TRNM_CI_RECEIPT_DIR"],"' + architecture.REPORT_NAME + '").write_text('
            + repr(json.dumps(synthetic_report())) + ')\n'
            'print(' + repr(synthetic_transcript().decode()) + ',end="")\n')
        self.binary.write_text(program)
        self.binary.chmod(0o755)
        for obj, name, value in [(architecture, 'ROOT', self.root), (history, 'ROOT', self.root),
                                 (architecture, 'NATIVE_CWD', self.package)]:
            context = patch.object(obj, name, value)
            context.start()
            self.addCleanup(context.stop)
        environment = dict(os.environ, TRNM_CI_RECEIPT_DIR=str(self.receipts),
            CARGO_TARGET_DIR=str(self.target), TRNM_EXPECTED_SOURCE_SHA=self.head,
            GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1', GITHUB_JOB='fixture',
            CARGO_MANIFEST_DIR=str(self.package), CARGO_PKG_NAME='fixture',
            CARGO_PKG_VERSION='0.0.0', LD_LIBRARY_PATH=str(deps), RUST_TEST_THREADS='1')
        context = patch.dict(os.environ, environment, clear=True)
        context.start()
        self.addCleanup(context.stop)

    def complete(self):
        prepared = architecture.prepare(self.binary, self.out, self.package)
        result = architecture.execution(self.out)
        self.assertTrue(result['passed'], result)
        self.assertFalse(result['native_execution_authenticated'])
        return prepared, architecture.bind_execution(prepared, self.out)

    def test_actual_child_then_parent_readback_retains_distinct_environment_contexts(self):
        prepared, binding = self.complete()
        with patch.dict(os.environ, {'LD_LIBRARY_PATH': '/parent-only',
                                    'CARGO_MANIFEST_DIR': '/parent-only'}):
            with self.assertRaisesRegex(ValueError, 'RUNTIME_ENV_CHANGED'):
                architecture.validate_preparation(self.out)
            with self.assertRaisesRegex(ValueError, 'RUNTIME_ENV_CHANGED'):
                architecture.bind_execution(prepared, self.out)
            self.assertEqual(architecture.bind_execution(prepared, self.out,
                                                       in_cargo_runtime=False), binding)
        path = self.out / 'manifest.json'
        manifest = json.loads(path.read_text())
        manifest['runtime_env_after']['LD_LIBRARY_PATH'] = '/changed-during-execution'
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'SOURCE_BINARY_CHANGED'):
            architecture.bind_execution(prepared, self.out, in_cargo_runtime=False)

    def test_current_binary_source_or_runtime_mutation_and_reuse_refuse(self):
        architecture.prepare(self.binary, self.out, self.package)
        with self.assertRaises(FileExistsError):
            architecture.prepare(self.binary, self.out, self.package)
        with patch.dict(os.environ, {'LD_LIBRARY_PATH': '/other'}):
            with self.assertRaisesRegex(ValueError, 'RUNTIME_ENV_CHANGED'):
                architecture.validate_preparation(self.out)
        self.binary.write_text(self.binary.read_text() + '# changed\n')
        with self.assertRaisesRegex(ValueError, 'BINARY_CHANGED'):
            architecture.validate_preparation(self.out)

    def test_source_drift_cannot_borrow_completed_result(self):
        prepared, _ = self.complete()
        self.source.write_text('// changed after actual harmless child\n')
        with self.assertRaises(ValueError):
            architecture.bind_execution(prepared, self.out, in_cargo_runtime=False)

    def test_missing_controller_or_late_host_failure_cannot_pass(self):
        _, binding = self.complete()
        with self.assertRaises(OSError):
            architecture.require_controller_success(self.out, in_cargo_runtime=False)
        folder = self.out.with_name(self.out.name + '-host')
        folder.mkdir()
        controller = dict(passed=True, failure=None, systemd_run_exit=0, final_host_errors=[],
            command_argv=['python3', architecture.SCRIPT, '--out', str(self.out)],
            preparation_execution_binding=binding)
        path = folder / 'controller-result.json'
        path.write_text(json.dumps(controller))
        self.assertEqual(architecture.require_controller_success(self.out,
                                                                in_cargo_runtime=False), binding)
        for key, value in [('passed', False), ('failure', 'SIGNAL_15'),
                           ('systemd_run_exit', False), ('final_host_errors', ['parent changed'])]:
            path.write_text(json.dumps(dict(controller, **{key: value})))
            with self.subTest(key=key), self.assertRaises(ValueError):
                architecture.require_controller_success(self.out, in_cargo_runtime=False)


if __name__ == '__main__':
    unittest.main()
