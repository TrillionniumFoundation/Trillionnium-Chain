#!/usr/bin/env python3
"""Reader/runner refusal controls. Transcript fixtures are not native evidence."""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import run_pon_budget_controls as runner


def process(failed=False):
    return dict(started=True, exit_code=101 if failed else 0,
                failure=None, cleanup_errors=[])


def transcript(name, failed=False, observation=None):
    payload = '' if observation is None else json.dumps(observation, separators=(',', ':'))
    status = 'FAILED' if failed else 'ok'
    passed, failures = (0, 1) if failed else (1, 0)
    return (f'\nrunning 1 test\ntest {name} ... {payload}\n{status}\n\n'
            f'test result: {status}. {passed} passed; {failures} failed; 0 ignored; '
            '0 measured; 4000 filtered out; finished in 0.25s\n')


def panic(name):
    if name in runner.HISTORY:
        source = 'ingress/history_import_detached_budget_tests.rs'
        reason = 'detached execution refused actual debt before its original refill control: Err(PUBLIC_MUTATION_CPU_BUDGET)'
    else:
        source = 'mining_prepare_control_tests.rs'
        reason = ('assertion failed: error.is(code)' if name == runner.MINING_FAILURES[0]
                  else 'assertion ' + chr(96) + 'left == right' + chr(96)
                  + ' failed\n  left: BeforeStateClone\n right: BeforeParentBinding')
    line = runner.PANIC_LINES.get(name, 100)
    return f"thread '{name}' panicked at crates/trnm-pon-node/src/{source}:{line}:5:\n{reason}\n"


def history(name, mode):
    before = mode == 'before'
    control = runner.HISTORY[name]
    code = ('PUBLIC_MUTATION_CPU_BUDGET' if before else
            'PUBLIC_REQUEST_CANCELLED' if control == 'Cancel' else
            'PUBLIC_REQUEST_DEADLINE' if control == 'Expire' else None)
    continued = not before and control == 'Continue'
    return dict(
        schema='history-detached-original-refill-control-v1', mode=control,
        native_campaign_executed=False,
        replay=dict(completed_native_replays=2, actual_thread_cpu_ns=90_000_000,
                    projected_paid_credit_ns=50_000_000),
        refill_resource_checks=0 if before else 1,
        flow=dict(initial_credit_ns=0, paid_cpu_debit_ns=100_000_000,
                  balance_identity_verified=True),
        history=dict(measurement_failures=0, packets=[dict(phases=[
            dict(phase='work', started=True, completed=True, accepted=True),
            dict(phase='execution', started=True, completed=True,
                 accepted=continued, error_code=code),
            dict(phase='commit', started=continued, completed=continued,
                 accepted=True if continued else None),
        ])]))


class BudgetControlsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def artifact(self):
        source, target = self.root / 'source', self.root / 'target'
        source.mkdir()
        target.mkdir()
        binary = target / 'libtest'
        binary.write_bytes(b'READER UNIT FIXTURE - NEVER EXECUTED')
        binary.chmod(0o500)
        row = dict(reason='compiler-artifact', executable=str(binary),
                   filenames=[str(binary)], profile=copy.deepcopy(runner.RELEASE_PROFILE),
                   target=dict(name='trnm_pon_node', kind=['lib'], crate_types=['lib'], test=True,
                               src_path=str(source / 'trillionnium/crates/trnm-pon-node/src/lib.rs')),
                   manifest_path=str(source / 'trillionnium/crates/trnm-pon-node/Cargo.toml'))
        return source, target, binary, row

    def test_exact_before_and_current_head_pair(self):
        current = 'a' * 40
        runner.validate_source_pair('before', current, runner.BEFORE_SHA)
        runner.validate_source_pair('fixed', current, current)
        for mode, driver, source in (
            ('before', current, 'b' * 40), ('before', runner.BEFORE_SHA, runner.BEFORE_SHA),
            ('fixed', current, runner.BEFORE_SHA), ('fixed', current, 'b' * 40),
            ('fixed', 'main', 'main'), ('unknown', current, current),
        ):
            with self.subTest(mode=mode, driver=driver, source=source), self.assertRaises(ValueError):
                runner.validate_source_pair(mode, driver, source)

    def test_build_uses_original_pin_lock_release_and_lib_once(self):
        self.assertEqual(runner.build_command(), [
            'cargo', '+1.95.0', 'test', '--locked', '--release', '--manifest-path',
            'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--lib',
            '--no-run', '--message-format=json'])

    def test_real_artifact_shape_and_finished_build_are_required(self):
        source, target, binary, row = self.artifact()
        finish = dict(reason='build-finished', success=True)
        encode = lambda rows: '\n'.join(json.dumps(item) for item in rows)
        self.assertEqual(runner.select_binary(encode([row, finish]), source, target), (binary, row))
        changed = copy.deepcopy(row)
        changed['target']['src_path'] = '/wrong/src/lib.rs'
        external = copy.deepcopy(row)
        external['executable'] = str(source / 'unrelated')
        external['filenames'] = [external['executable']]
        cases = ([row], [finish], [row, row, finish], [changed, finish], [external, finish],
                 [row, dict(reason='build-finished', success=False)], [row, finish, row])
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                runner.select_binary(encode(rows), source, target)

    def test_release_profile_cannot_be_relabeled(self):
        source, target, _, row = self.artifact()
        for key, value in (('opt_level', '0'), ('test', False), ('debug_assertions', True),
                           ('overflow_checks', True), ('debuginfo', 2), ('debuginfo', False)):
            changed = copy.deepcopy(row)
            changed['profile'][key] = value
            raw = json.dumps(changed) + '\n' + json.dumps(dict(reason='build-finished', success=True))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'RELEASE_PROFILE'):
                runner.select_binary(raw, source, target)

    def test_actual_list_requires_all_seven_and_consistent_unique_totals(self):
        names = [*runner.CONTROLS, 'existing::retained_test']
        listing = '\n'.join(name + ': test' for name in names) + '\n\n8 tests, 0 benchmarks\n'
        self.assertEqual(runner.validate_list(listing)['listed_tests'], 8)
        for bad in (listing.replace(names[0] + ': test\n', ''),
                    listing.replace('8 tests', '9 tests'),
                    listing.replace(names[0] + ': test', names[1] + ': test'),
                    listing.replace(names[0] + ': test', names[0] + ': benchmark'),
                    listing + listing):
            with self.assertRaises(ValueError):
                runner.validate_list(bad)

    def test_fixed_requires_named_passes_and_equivalence_passes_in_both_modes(self):
        for name in (*runner.MINING_FAILURES, runner.EQUIVALENCE):
            self.assertTrue(runner.validate_case(name, 'fixed', process(), transcript(name), '')
                            ['expected_outcome_observed'])
        self.assertEqual(runner.validate_case(runner.EQUIVALENCE, 'before', process(),
                         transcript(runner.EQUIVALENCE), '')['expected'], 'pass')
        with self.assertRaises(ValueError):
            runner.validate_case(runner.EQUIVALENCE, 'before', process(True),
                                 transcript(runner.EQUIVALENCE, True), panic(runner.EQUIVALENCE))

    def test_before_mining_requires_specific_control_assertion(self):
        for name in runner.MINING_FAILURES:
            self.assertEqual(runner.validate_case(name, 'before', process(True),
                             transcript(name, True), panic(name))['expected'], 'fail')
            for stderr in ('', 'setup failed', panic(name).replace('mining_prepare_control_tests.rs', 'store.rs'),
                           panic(name).replace(':' + str(runner.PANIC_LINES[name]) + ':', ':1:'),
                           panic(name).replace('BeforeStateClone', 'BeforeReward')
                           if name != runner.MINING_FAILURES[0] else
                           panic(name).replace('error.is(code)', 'unrelated.is(code)'),
                           panic(name).replace('BeforeParentBinding', 'BeforeWork')
                           if name != runner.MINING_FAILURES[0] else
                           panic(name).replace('error.is(code)', 'unrelated.is(code)')):
                with self.subTest(name=name, stderr=stderr), self.assertRaises(ValueError):
                    runner.validate_case(name, 'before', process(True), transcript(name, True), stderr)

    def test_nonzero_signal_missing_summary_and_ignored_never_count_as_controls(self):
        name = runner.MINING_FAILURES[0]
        for code in (1, -9, 130, 0, None, False):
            changed = dict(process(True), exit_code=code)
            with self.subTest(code=code), self.assertRaises(ValueError):
                runner.validate_case(name, 'before', changed, transcript(name, True), panic(name))
        for raw in ('', transcript(name, True).replace('1 failed', '0 failed'),
                    transcript(name, True).replace('0 ignored', '1 ignored'),
                    transcript(name, True).replace(name, 'other::test'),
                    transcript(name, True) + transcript(name, True),
                    transcript(name, True).replace('running 1 test', 'running 2 tests')):
            with self.assertRaises(ValueError):
                runner.validate_case(name, 'before', process(True), raw, panic(name))
        with self.assertRaises(ValueError):
            runner.validate_case(name, 'fixed', process(),
                                 transcript(name).replace('0 ignored', '1 ignored'), '')

    def test_history_before_requires_actual_replay_and_paid_deficit(self):
        for name in runner.HISTORY:
            record = history(name, 'before')
            self.assertEqual(runner.validate_case(name, 'before', process(True),
                transcript(name, True, record), panic(name))['history'], record)
            mutations = [
                dict(record, replay=None),
                dict(record, replay=dict(record['replay'], completed_native_replays=0)),
                dict(record, replay=dict(record['replay'], completed_native_replays=True)),
                dict(record, replay=dict(record['replay'], actual_thread_cpu_ns=75_000_000)),
                dict(record, replay=dict(record['replay'], projected_paid_credit_ns=True)),
                dict(record, flow=dict(record['flow'], paid_cpu_debit_ns=89_999_999)),
                dict(record, flow=dict(record['flow'], initial_credit_ns=1)),
                dict(record, flow=dict(record['flow'], initial_credit_ns=False)),
                dict(record, flow=dict(record['flow'], balance_identity_verified=False)),
            ]
            for changed in mutations:
                with self.subTest(name=name, changed=changed), self.assertRaises(ValueError):
                    runner.validate_case(name, 'before', process(True),
                                         transcript(name, True, changed), panic(name))

    def test_history_early_fixture_failure_and_wrong_native_phase_are_rejected(self):
        name = next(iter(runner.HISTORY))
        record = history(name, 'before')
        with self.assertRaises(ValueError):
            runner.validate_case(name, 'before', process(True), transcript(name, True), panic(name))
        for index, key, value in ((0, 'accepted', False), (1, 'started', False),
                                   (1, 'error_code', 'PUBLIC_REQUEST_DEADLINE'),
                                   (2, 'started', True)):
            changed = copy.deepcopy(record)
            changed['history']['packets'][0]['phases'][index][key] = value
            with self.subTest(index=index, key=key), self.assertRaises(ValueError):
                runner.validate_case(name, 'before', process(True),
                                     transcript(name, True, changed), panic(name))
        for changed in (dict(record, refill_resource_checks=1),
                        dict(record, native_campaign_executed=True),
                        dict(record, mode='Expire')):
            with self.assertRaises(ValueError):
                runner.validate_case(name, 'before', process(True),
                                     transcript(name, True, changed), panic(name))
        raw = transcript(name, True, record) + json.dumps(record, separators=(',', ':')) + '\n'
        with self.assertRaises(ValueError):
            runner.validate_case(name, 'before', process(True), raw, panic(name))

    def test_history_fixed_requires_original_refill_and_exact_cancellation(self):
        for name in runner.HISTORY:
            record = history(name, 'fixed')
            self.assertTrue(runner.validate_case(name, 'fixed', process(),
                            transcript(name, observation=record), '')['expected_outcome_observed'])
            with self.assertRaises(ValueError):
                runner.validate_case(name, 'fixed', process(),
                    transcript(name, observation=dict(record, refill_resource_checks=0)), '')
            changed = copy.deepcopy(record)
            changed['history']['packets'][0]['phases'][1]['accepted'] = False
            changed['history']['packets'][0]['phases'][1]['error_code'] = 'PUBLIC_MUTATION_CPU_BUDGET'
            with self.assertRaises(ValueError):
                runner.validate_case(name, 'fixed', process(), transcript(name, observation=changed), '')

    def test_capture_retains_separate_raw_streams_and_real_process_status(self):
        command = [sys.executable, '-B', '-c',
                   'import sys;sys.stdout.write("stdout\\n");sys.stderr.write("stderr\\n");sys.exit(101)']
        result = runner.capture(command, self.root, self.root, 'python-reader-probe', dict(os.environ))
        self.assertEqual(result['exit_code'], 101)
        self.assertEqual((self.root / 'python-reader-probe.stdout').read_bytes(), b'stdout\n')
        self.assertEqual((self.root / 'python-reader-probe.stderr').read_bytes(), b'stderr\n')
        self.assertFalse(runner.successful(result))
        self.assertEqual(json.loads((self.root / 'python-reader-probe.process.json').read_text()), result)
        self.assertFalse(runner.successful(dict(result, exit_code=False)))

    def test_failed_source_check_is_preserved_and_after_checks_still_run(self):
        source, driver = self.root / 'source', self.root / 'driver'
        source.mkdir()
        driver.mkdir()
        out = self.root / 'out'
        args = argparse.Namespace(source=source, out=out, mode='fixed',
                                  driver_sha='a' * 40, source_sha='a' * 40)
        with patch.object(runner, 'ROOT', driver), \
                patch.object(runner, 'verify_source', side_effect=ValueError('source refused')) as verify, \
                patch.object(runner, 'capture') as capture:
            report = runner.run(args)
        self.assertEqual(report['result'], 'FAIL')
        self.assertEqual(verify.call_count, 3)
        capture.assert_not_called()
        self.assertEqual(report['cases'], [])
        self.assertEqual(report['native_control_processes_started'], 0)
        self.assertEqual(report['matched_pass_controls'], 0)
        self.assertEqual(report['matched_failure_controls'], 0)
        for flag in runner.FALSE_FLAGS:
            self.assertIs(report[flag], False)
        self.assertFalse(json.loads((out / 'driver-source-before-error.json').read_text())['verified'])
        for label in ('driver', 'subject'):
            self.assertFalse(json.loads((out / (label + '-source-after-error.json')).read_text())['verified'])
        self.assertEqual(json.loads((out / 'report.json').read_text()), report)

    def test_workflow_keeps_two_sources_separate_and_all_failures(self):
        text = (runner.ROOT / '.github/workflows/pon-budget-controls.yml').read_text()
        for expected in ('source: [before, fixed]', runner.BEFORE_SHA, 'path: driver',
                         'path: subject', 'fail-fast: false', 'cancel-in-progress: false',
                         'if: always()', 'rustup toolchain install 1.95.0',
                         '--driver-sha "$DRIVER_SHA" --source-sha "$SUBJECT_SHA"'):
            self.assertIn(expected, text)
        self.assertNotIn('continue-on-error:', text)
        self.assertNotIn('run_public_v3_service_campaign', text)
        self.assertNotIn('pq-cross-branch-corpus', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
