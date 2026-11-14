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
    before = mode == 'budget-before-v2'
    control = runner.HISTORY[name]
    code = ('PUBLIC_MUTATION_CPU_BUDGET' if before else
            'PUBLIC_REQUEST_CANCELLED' if control == 'Cancel' else
            'PUBLIC_REQUEST_DEADLINE' if control == 'Expire' else None)
    continued = not before and control == 'Continue'
    dirty = before or control == 'Cancel'
    balance = -25_000_000 if dirty else 100_000_000
    flow = dict(schema='public-v3-local-actual-cpu-flow-v1', initial_credit_ns=0,
                credited_refill_ns=100_000_000 + balance, discarded_refill_ns=0,
                booked_reservation_ns=0, live_debited_cpu_ns=99_000_000,
                settlement_residual_cpu_ns=1_000_000, settled_full_cpu_ns=100_000_000,
                unsettled_known_live_cpu_ns=0, paid_cpu_debit_ns=100_000_000,
                settlement_discard_ns=0, remaining_paid_credit_ns=balance,
                balance_identity_verified=True, stored_credit_ns=balance, live_owners=0)
    cpu = dict(schema='public-v3-local-stored-cpu-budget-v1', stored_credit_ns=balance,
               in_flight=0, accounting_unavailable=False, burst_ns=2_000_000_000,
               refill_ns_per_second=250_000_000, start_reserve_ns=100_000_000, worker_limit=2)
    outer = 'PUBLIC_MUTATION_CPU_UNAVAILABLE' if dirty else code
    record = dict(
        schema='history-detached-original-refill-control-v2', mode=control,
        native_campaign_executed=False,
        outcome={'Ok': '11' * 32} if continued else {'Err': outer},
        replay=dict(completed_native_replays=2, actual_thread_cpu_ns=90_000_000,
                    projected_paid_credit_ns=50_000_000),
        refill_resource_checks=0 if before else 1,
        before_epoch_close=dict(cpu=cpu, flow=flow),
        after_epoch_close_cpu=dict(cpu, accounting_unavailable=dirty),
        epoch_marker=b'active-v1'.hex() if dirty else None,
        flow=None if dirty else copy.deepcopy(flow),
        history=dict(measurement_failures=0, phases=[
            dict(phase='cpu_settle', started=True, completed=True, accepted=True),
            dict(phase='history_epoch_close', started=True, completed=True,
                 accepted=not dirty, error_code='PUBLIC_MUTATION_CPU_UNAVAILABLE' if dirty else None),
            dict(phase='history_import', started=True, completed=True,
                 accepted=continued, error_code=outer),
        ], packets=[dict(packet_id=[17] * 32, phases=[
            dict(phase='work', started=True, completed=True, accepted=True),
            dict(phase='execution', started=True, completed=True,
                 accepted=continued, error_code=code),
            dict(phase='commit', started=continued, completed=continued,
                 accepted=True if continued else None),
            dict(phase='submit_result', started=continued, completed=continued,
                 accepted=True if continued else None),
            dict(phase='cpu_settle', started=True, completed=True, accepted=True),
        ])]))
    if not before:
        # These are explicitly synthetic reader fixtures. Current native v3
        # commits the first packet before waiting and observes a second packet.
        record['schema'] = 'history-detached-native-completion-control-v3'
        record['qualification'] = 'NativeCommitted'
        record['first_refill_credited_ns'] = 50_000_000
        observed = record['history']
        observed.update(schema='pon-local-history-import-observation-v1',
                        observation_has_consensus_authority=False, supplied_packets=2,
                        tip=[34] * 32)
        first = observed['packets'][0]
        first['packet_index'] = 0
        for index in (1, 2):
            first['phases'][index].update(started=True, completed=True, accepted=True,
                                          error_code=None)
        first['phases'][3].update(started=True, completed=True, accepted=continued,
                                  error_code=code)
        first['phases'].append(dict(phase='history_import', started=True, completed=True,
                                    accepted=continued, error_code=code))
        second = copy.deepcopy(first)
        second.update(packet_id=[34] * 32, packet_index=1)
        if not continued:
            for phase in second['phases']:
                phase.update(started=False, completed=False, accepted=None, error_code=None)
        observed['packets'].append(second)
        if continued:
            record['outcome'] = {'Ok': '22' * 32}
    return record


def pool_panic(name):
    marker, line, expected = runner.POOL_FAILURES[name]
    actual = 2 if expected == 0 else 512
    return (f"thread '{name}' panicked at crates/trnm-pon-node/src/pool_run_control_tests.rs:{line}:9:\n"
            'assertion ' + chr(96) + 'left == right' + chr(96) + ' failed: ' + marker
            + f'\n  left: {actual}\n right: {expected}\n')


def pool_scan_panic(name):
    return (f"thread '{name}' panicked at crates/trnm-pon-node/src/pool_reconcile_control_tests.rs:"
            f'{runner.POOL_SCAN_PANIC_LINE}:5:\n'
            'assertion ' + chr(96) + 'left == right' + chr(96) + ' failed: '
            + runner.POOL_SCAN_MARKER + '\n  left: 6\n right: 2\n')


def integration_transcript():
    return ('\nrunning 10 tests\n' + ''.join(f'test {name} ... ok\n' for name in runner.POOL_INTEGRATION)
            + '\ntest result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; '
            '0 filtered out; finished in 20.00s\n')


class BudgetControlsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def artifact(self, role='libtest', source=None, target=None):
        source = self.root / 'source' if source is None else source
        target = self.root / 'target' if target is None else target
        source.mkdir(exist_ok=True)
        target.mkdir(exist_ok=True)
        roles = {
            'libtest': ('trnm_pon_node', 'lib', 'lib', 'src/lib.rs', runner.RELEASE_PROFILE),
            'pool-integration': ('pool_mining', 'test', 'bin', 'tests/pool_mining.rs', runner.RELEASE_PROFILE),
            'cli': ('trnm-pon-node', 'bin', 'bin', 'src/main.rs', runner.RELEASE_CLI_PROFILE),
        }
        name, kind, crate_type, relative, profile = roles[role]
        binary = target / ('release/trnm-pon-node' if role == 'cli' else role)
        binary.parent.mkdir(exist_ok=True)
        binary.write_bytes(b'READER UNIT FIXTURE - NEVER EXECUTED ' + role.encode())
        binary.chmod(0o500)
        row = dict(reason='compiler-artifact', executable=str(binary),
                   filenames=[str(binary)], profile=copy.deepcopy(profile),
                   target=dict(name=name, kind=[kind], crate_types=[crate_type], test=True,
                               src_path=str(source / 'trillionnium/crates/trnm-pon-node' / relative)),
                   manifest_path=str(source / 'trillionnium/crates/trnm-pon-node/Cargo.toml'))
        return source, target, binary, row

    def test_exact_before_and_current_head_pair(self):
        current = 'a' * 40
        runner.validate_source_pair('budget-before-v2', current, runner.BUDGET_BEFORE_SHA)
        runner.validate_source_pair('fixed', current, current)
        for mode, driver, source in (
            ('budget-before-v2', current, 'b' * 40), ('budget-before-v2', runner.BUDGET_BEFORE_SHA, runner.BUDGET_BEFORE_SHA),
            ('pool-before', current, runner.POOL_BEFORE_SHA),
            ('pool-before-v2', current, 'db93026b9314bfd8bc4350945036998f1b7d34aa'),
            ('fixed', current, runner.BUDGET_BEFORE_SHA), ('fixed', current, 'b' * 40),
            ('fixed', 'main', 'main'), ('unknown', current, current),
        ):
            with self.subTest(mode=mode, driver=driver, source=source), self.assertRaises(ValueError):
                runner.validate_source_pair(mode, driver, source)

    def test_build_uses_original_pin_lock_release_and_lib_once(self):
        self.assertEqual(runner.build_command('budget-before-v2'), [
            'cargo', '+1.95.0', 'test', '--locked', '--release', '--manifest-path',
            'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--lib',
            '--no-run', '--message-format=json'])

    def test_real_artifact_shape_and_finished_build_are_required(self):
        source, target, binary, row = self.artifact()
        finish = dict(reason='build-finished', success=True)
        encode = lambda rows: '\n'.join(json.dumps(item) for item in rows)
        self.assertEqual(runner.select_binaries(encode([row, finish]), source, target, 'budget-before-v2'), {'libtest': (binary, row)})
        changed = copy.deepcopy(row)
        changed['target']['src_path'] = '/wrong/src/lib.rs'
        external = copy.deepcopy(row)
        external['executable'] = str(source / 'unrelated')
        external['filenames'] = [external['executable']]
        cases = ([row], [finish], [row, row, finish], [changed, finish], [external, finish],
                 [row, dict(reason='build-finished', success=False)], [row, finish, row])
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                runner.select_binaries(encode(rows), source, target, 'budget-before-v2')

    def test_release_profile_cannot_be_relabeled(self):
        source, target, _, row = self.artifact()
        for key, value in (('opt_level', '0'), ('test', False), ('debug_assertions', True),
                           ('overflow_checks', True), ('debuginfo', 2), ('debuginfo', False)):
            changed = copy.deepcopy(row)
            changed['profile'][key] = value
            raw = json.dumps(changed) + '\n' + json.dumps(dict(reason='build-finished', success=True))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'RELEASE_PROFILE'):
                runner.select_binaries(raw, source, target, 'budget-before-v2')

    def test_actual_list_requires_all_seven_and_consistent_unique_totals(self):
        names = [*runner.BUDGET_CONTROLS, 'existing::retained_test']
        listing = '\n'.join(name + ': test' for name in names) + '\n\n8 tests, 0 benchmarks\n'
        self.assertEqual(runner.validate_list(listing, runner.BUDGET_CONTROLS)['listed_tests'], 8)
        for bad in (listing.replace(names[0] + ': test\n', ''),
                    listing.replace('8 tests', '9 tests'),
                    listing.replace(names[0] + ': test', names[1] + ': test'),
                    listing.replace(names[0] + ': test', names[0] + ': benchmark'),
                    listing + listing):
            with self.assertRaises(ValueError):
                runner.validate_list(bad, runner.BUDGET_CONTROLS)

    def test_fixed_requires_named_passes_and_equivalence_passes_in_both_modes(self):
        for name in (*runner.MINING_FAILURES, runner.EQUIVALENCE):
            self.assertTrue(runner.validate_case(name, 'fixed', process(), transcript(name), '')
                            ['expected_outcome_observed'])
        self.assertEqual(runner.validate_case(runner.EQUIVALENCE, 'budget-before-v2', process(),
                         transcript(runner.EQUIVALENCE), '')['expected'], 'pass')
        with self.assertRaises(ValueError):
            runner.validate_case(runner.EQUIVALENCE, 'budget-before-v2', process(True),
                                 transcript(runner.EQUIVALENCE, True), panic(runner.EQUIVALENCE))

    def test_before_mining_requires_specific_control_assertion(self):
        for name in runner.MINING_FAILURES:
            self.assertEqual(runner.validate_case(name, 'budget-before-v2', process(True),
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
                    runner.validate_case(name, 'budget-before-v2', process(True), transcript(name, True), stderr)

    def test_before_budget_panic_requires_exact_name_and_no_second_worker_panic(self):
        for name in (*runner.HISTORY, *runner.MINING_FAILURES):
            observation = history(name, 'budget-before-v2') if name in runner.HISTORY else None
            raw = transcript(name, True, observation)
            stderr = panic(name)
            renamed = stderr.replace("thread '" + name + "'", "thread 'unrelated::test'")
            extra = stderr + "thread 'unrelated::worker' panicked at unrelated.rs:1:1:\nworker failed\n"
            for bad in (renamed, extra):
                with self.subTest(name=name, stderr=bad), self.assertRaisesRegex(
                        ValueError, 'EXPECTED_CONTROL_PANIC_SOURCE'):
                    runner.validate_case(name, 'budget-before-v2', process(True), raw, bad)
            self.assertTrue(runner.validate_case(name, 'budget-before-v2', process(True),
                            raw, stderr)['expected_outcome_observed'])

    def test_nonzero_signal_missing_summary_and_ignored_never_count_as_controls(self):
        name = runner.MINING_FAILURES[0]
        for code in (1, -9, 130, 0, None, False):
            changed = dict(process(True), exit_code=code)
            with self.subTest(code=code), self.assertRaises(ValueError):
                runner.validate_case(name, 'budget-before-v2', changed, transcript(name, True), panic(name))
        for raw in ('', transcript(name, True).replace('1 failed', '0 failed'),
                    transcript(name, True).replace('0 ignored', '1 ignored'),
                    transcript(name, True).replace(name, 'other::test'),
                    transcript(name, True) + transcript(name, True),
                    transcript(name, True).replace('running 1 test', 'running 2 tests')):
            with self.assertRaises(ValueError):
                runner.validate_case(name, 'budget-before-v2', process(True), raw, panic(name))
        with self.assertRaises(ValueError):
            runner.validate_case(name, 'fixed', process(),
                                 transcript(name).replace('0 ignored', '1 ignored'), '')

    def test_history_before_requires_actual_replay_and_paid_deficit(self):
        for name in runner.HISTORY:
            record = history(name, 'budget-before-v2')
            self.assertEqual(runner.validate_case(name, 'budget-before-v2', process(True),
                transcript(name, True, record), panic(name))['history'], record)
            mutations = [
                dict(record, replay=None),
                dict(record, replay=dict(record['replay'], completed_native_replays=0)),
                dict(record, replay=dict(record['replay'], completed_native_replays=True)),
                dict(record, replay=dict(record['replay'], actual_thread_cpu_ns=75_000_000)),
                dict(record, replay=dict(record['replay'], projected_paid_credit_ns=True)),
            ]
            for key, value in (('paid_cpu_debit_ns', 89_999_999), ('initial_credit_ns', 1),
                               ('initial_credit_ns', False), ('balance_identity_verified', False)):
                changed = copy.deepcopy(record)
                changed['before_epoch_close']['flow'][key] = value
                mutations.append(changed)
            for changed in mutations:
                with self.subTest(name=name, changed=changed), self.assertRaises(ValueError):
                    runner.validate_case(name, 'budget-before-v2', process(True),
                                         transcript(name, True, changed), panic(name))

    def test_history_early_fixture_failure_and_wrong_native_phase_are_rejected(self):
        name = next(iter(runner.HISTORY))
        record = history(name, 'budget-before-v2')
        with self.assertRaises(ValueError):
            runner.validate_case(name, 'budget-before-v2', process(True), transcript(name, True), panic(name))
        for index, key, value in ((0, 'accepted', False), (1, 'started', False),
                                   (1, 'error_code', 'PUBLIC_REQUEST_DEADLINE'),
                                   (2, 'started', True)):
            changed = copy.deepcopy(record)
            changed['history']['packets'][0]['phases'][index][key] = value
            with self.subTest(index=index, key=key), self.assertRaises(ValueError):
                runner.validate_case(name, 'budget-before-v2', process(True),
                                     transcript(name, True, changed), panic(name))
        for changed in (dict(record, refill_resource_checks=1),
                        dict(record, native_campaign_executed=True),
                        dict(record, mode='Expire')):
            with self.assertRaises(ValueError):
                runner.validate_case(name, 'budget-before-v2', process(True),
                                     transcript(name, True, changed), panic(name))
        raw = transcript(name, True, record) + json.dumps(record, separators=(',', ':')) + '\n'
        with self.assertRaises(ValueError):
            runner.validate_case(name, 'budget-before-v2', process(True), raw, panic(name))

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

    def test_history_requires_exact_settlement_before_original_crash_fence(self):
        name = next(iter(runner.HISTORY))
        record = history(name, 'budget-before-v2')
        changes = [
            (('before_epoch_close',), None),
            (('before_epoch_close', 'flow'), None),
            (('before_epoch_close', 'flow', 'booked_reservation_ns'), 1),
            (('before_epoch_close', 'flow', 'unsettled_known_live_cpu_ns'), 1),
            (('before_epoch_close', 'flow', 'live_owners'), True),
            (('before_epoch_close', 'flow', 'termination_reserved_ns'), 25_000_000),
            (('before_epoch_close', 'flow', 'settled_full_cpu_ns'), 100_000_001),
            (('before_epoch_close', 'flow', 'settlement_residual_cpu_ns'), 1_000_001),
            (('before_epoch_close', 'flow', 'credited_refill_ns'), 75_000_001),
            (('before_epoch_close', 'cpu', 'accounting_unavailable'), True),
            (('before_epoch_close', 'cpu', 'in_flight'), 1),
            (('before_epoch_close', 'cpu', 'stored_credit_ns'), 0),
            (('before_epoch_close', 'cpu', 'start_reserve_ns'), 200_000_000),
            (('after_epoch_close_cpu', 'accounting_unavailable'), False),
            (('after_epoch_close_cpu', 'stored_credit_ns'), 0),
            (('epoch_marker',), None),
            (('flow',), copy.deepcopy(record['before_epoch_close']['flow'])),
            (('outcome',), {'Err': 'PUBLIC_MUTATION_CPU_BUDGET'}),
            (('history', 'phases', 0, 'accepted'), False),
            (('history', 'phases', 1, 'accepted'), True),
            (('history', 'phases', 1, 'completed'), False),
            (('history', 'phases', 2, 'error_code'), 'PUBLIC_MUTATION_CPU_BUDGET'),
            (('history', 'packets', 0, 'phases', 4, 'accepted'), False),
        ]
        for path, value in changes:
            changed = copy.deepcopy(record)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                runner.validate_case(name, 'budget-before-v2', process(True),
                                     transcript(name, True, changed), panic(name))

    def test_history_continue_still_requires_complete_import_and_clean_close(self):
        name = next(iter(runner.HISTORY))
        record = history(name, 'fixed')
        changes = [
            (('flow',), None),
            (('after_epoch_close_cpu', 'accounting_unavailable'), True),
            (('epoch_marker',), b'active-v1'.hex()),
            (('outcome',), {'Err': 'PUBLIC_MUTATION_CPU_UNAVAILABLE'}),
            (('outcome',), {'Ok': '33' * 32}),
            (('history', 'packets', 0, 'phases', 2, 'accepted'), False),
            (('history', 'packets', 0, 'phases', 2, 'completed'), False),
            (('history', 'packets', 0, 'phases', 3, 'accepted'), False),
            (('history', 'phases', 1, 'accepted'), False),
            (('history', 'phases', 2, 'accepted'), False),
        ]
        for path, value in changes:
            changed = copy.deepcopy(record)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                runner.validate_case(name, 'fixed', process(), transcript(name, observation=changed), '')

    def test_history_versions_and_qualification_cannot_transfer_outcomes(self):
        for name in runner.HISTORY:
            current = history(name, 'fixed')
            old = history(name, 'budget-before-v2')
            for changed in (old, dict(current, schema=old['schema']),
                            dict(current, qualification='BeforeNativeCompletion'),
                            dict(current, qualification=None), dict(current, qualification=True)):
                with self.subTest(name=name, changed=changed), self.assertRaises(ValueError):
                    runner.validate_case(name, 'fixed', process(),
                                         transcript(name, observation=changed), '')
            with self.assertRaises(ValueError):
                runner.validate_case(name, 'budget-before-v2', process(True),
                                     transcript(name, True, current), panic(name))
            combined = transcript(name, observation=current) + json.dumps(old, separators=(',', ':'))
            with self.assertRaisesRegex(ValueError, 'ONE_ACTUAL_HISTORY_RECORD_REQUIRED'):
                runner.history_evidence(combined, name, 'fixed')

    def test_history_v3_requires_two_distinct_ordered_packets_and_exact_tip(self):
        name = next(iter(runner.HISTORY))
        record = history(name, 'fixed')
        changes = [
            (('history', 'packets'), record['history']['packets'][:1]),
            (('history', 'packets'), record['history']['packets'] * 2),
            (('history', 'packets', 1, 'packet_id'), [17] * 32),
            (('history', 'packets', 1, 'packet_id'), [True] * 32),
            (('history', 'packets', 0, 'packet_index'), False),
            (('history', 'packets', 1, 'packet_index'), 0),
            (('history', 'supplied_packets'), True),
            (('history', 'tip'), [17] * 32),
            (('history', 'tip'), [True] * 32),
            (('history', 'observation_has_consensus_authority'), True),
            (('outcome',), {'Ok': '11' * 32}),
        ]
        for path, value in changes:
            changed = copy.deepcopy(record)
            node = changed
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                runner.validate_case(name, 'fixed', process(), transcript(name, observation=changed), '')

    def test_history_v3_requires_real_original_refill_and_successor_completion(self):
        name = next(iter(runner.HISTORY))
        record = history(name, 'fixed')
        for credit in (None, False, -1, record['flow']['credited_refill_ns'],
                       record['flow']['credited_refill_ns'] + 1):
            changed = dict(record, first_refill_credited_ns=credit)
            with self.subTest(credit=credit), self.assertRaises(ValueError):
                runner.validate_case(name, 'fixed', process(), transcript(name, observation=changed), '')
        for index in range(len(record['history']['packets'][1]['phases'])):
            changed = copy.deepcopy(record)
            changed['history']['packets'][1]['phases'][index]['accepted'] = False
            with self.subTest(index=index), self.assertRaises(ValueError):
                runner.validate_case(name, 'fixed', process(), transcript(name, observation=changed), '')

    def test_history_v3_cancellation_keeps_durable_first_and_unstarted_successor(self):
        for name, control in runner.HISTORY.items():
            if control == 'Continue':
                continue
            record = history(name, 'fixed')
            changes = [
                (('history', 'packets', 0, 'phases', 1, 'accepted'), False),
                (('history', 'packets', 0, 'phases', 2, 'started'), False),
                (('history', 'packets', 0, 'phases', 2, 'accepted'), None),
                (('history', 'packets', 0, 'phases', 3, 'error_code'), 'PUBLIC_MUTATION_CPU_BUDGET'),
                (('history', 'packets', 0, 'phases', 5, 'accepted'), True),
                (('history', 'packets', 1, 'phases'), []),
                (('history', 'packets', 1, 'phases'), record['history']['packets'][1]['phases'][:-1]),
                (('first_refill_credited_ns',), False),
                (('before_epoch_close', 'flow', 'initial_credit_ns'), 1),
                (('before_epoch_close', 'flow', 'booked_reservation_ns'), 1),
                (('before_epoch_close', 'flow', 'paid_cpu_debit_ns'), 99_000_000),
            ]
            for index in range(len(record['history']['packets'][1]['phases'])):
                changes.append((('history', 'packets', 1, 'phases', index, 'started'), True))
            if control == 'Cancel':
                changes.extend([
                    (('flow',), copy.deepcopy(record['before_epoch_close']['flow'])),
                    (('after_epoch_close_cpu', 'accounting_unavailable'), False),
                    (('epoch_marker',), None),
                    (('outcome',), {'Err': 'PUBLIC_REQUEST_CANCELLED'}),
                ])
            for path, value in changes:
                changed = copy.deepcopy(record)
                node = changed
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = value
                with self.subTest(name=name, path=path), self.assertRaises(ValueError):
                    runner.validate_case(name, 'fixed', process(), transcript(name, observation=changed), '')

    def test_history_old_g2_null_flow_is_not_reclassified_as_v2_evidence(self):
        for name in runner.HISTORY:
            record = history(name, 'budget-before-v2')
            record['schema'] = 'history-detached-original-refill-control-v1'
            with self.assertRaisesRegex(ValueError, 'ONE_ACTUAL_HISTORY_RECORD_REQUIRED'):
                runner.validate_case(name, 'budget-before-v2', process(True),
                                     transcript(name, True, record), panic(name))


    def test_groups_bind_distinct_old_sources_and_only_their_shared_inputs(self):
        current = 'a' * 40
        for mode, (sha, _) in runner.BEFORE_SOURCES.items():
            runner.validate_source_pair(mode, current, sha)
            for wrong in (current, *(value[0] for key, value in runner.BEFORE_SOURCES.items() if key != mode)):
                with self.subTest(mode=mode, wrong=wrong), self.assertRaises(ValueError):
                    runner.validate_source_pair(mode, current, wrong)
        for sha, _ in runner.BEFORE_SOURCES.values():
            with self.assertRaises(ValueError):
                runner.validate_source_pair('fixed', sha, sha)
        self.assertEqual(runner.controls_for_mode('budget-before-v2'), runner.BUDGET_CONTROLS)
        self.assertEqual(runner.controls_for_mode('pool-before-v2'), runner.POOL_CONTROLS)
        self.assertEqual(runner.controls_for_mode('pool-scan-before'), runner.POOL_SCAN_CONTROLS)
        fixed = runner.controls_for_mode('fixed')
        self.assertEqual(len(fixed), 21)
        self.assertEqual(len(set(fixed)), 21)
        self.assertEqual(set(runner.same_input_groups('pool-before-v2')), {'common', 'pool'})
        self.assertEqual(set(runner.same_input_groups('budget-before-v2')), {'common', 'budget'})
        self.assertEqual(set(runner.same_input_groups('pool-scan-before')), {'common', 'pool-scan'})
        self.assertEqual(runner.GROUP_INPUTS['pool-scan'], (
            'trillionnium/crates/trnm-pon-node/src/pool_reconcile_control_tests.rs',))
        self.assertEqual(set(runner.same_input_groups('fixed')), {'common', 'budget', 'pool', 'pool-scan'})
        for mode in ('before', 'pool-before'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                runner.controls_for_mode(mode)

    def test_one_fixed_build_selects_lib_integration_and_its_real_cli(self):
        command = runner.build_command('fixed')
        self.assertEqual(command, [
            'cargo', '+1.95.0', 'test', '--locked', '--release', '--manifest-path',
            'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--lib', '--test', 'pool_mining',
            '--no-run', '--message-format=json'])
        self.assertEqual(runner.build_command('pool-before-v2'), runner.build_command('budget-before-v2'))
        self.assertEqual(runner.build_command('pool-scan-before'), runner.build_command('budget-before-v2'))
        source, target, binary, row = self.artifact()
        _, _, integration, integration_row = self.artifact('pool-integration')
        _, _, cli, cli_row = self.artifact('cli')
        finish = dict(reason='build-finished', success=True)
        encode = lambda rows: '\n'.join(json.dumps(item) for item in rows)
        actual = runner.select_binaries(encode([row, integration_row, cli_row, finish]), source, target, 'fixed')
        self.assertEqual(actual, {'libtest': (binary, row), 'pool-integration': (integration, integration_row),
                                  'cli': (cli, cli_row)})
        for rows in ([row, finish], [row, integration_row, finish], [row, cli_row, finish],
                     [row, integration_row, cli_row, cli_row, finish]):
            with self.assertRaises(ValueError):
                runner.select_binaries(encode(rows), source, target, 'fixed')
        with self.assertRaises(ValueError):
            runner.select_binaries(encode([row, integration_row, cli_row, finish]),
                                   source, target, 'pool-before-v2')

    def test_cli_target_source_profile_and_embedded_path_cannot_be_substituted(self):
        source, target, _, row = self.artifact()
        _, _, _, integration = self.artifact('pool-integration')
        _, _, _, cli = self.artifact('cli')
        altered_path = target / 'other-cli'
        altered_path.write_bytes(b'not the embedded CLI')
        altered_path.chmod(0o500)
        changes = [
            (('target', 'src_path'), str(source / 'unrelated/main.rs')),
            (('target', 'kind'), ['test']),
            (('target', 'test'), False),
            (('profile', 'test'), True),
            (('profile', 'opt_level'), '0'),
            (('profile', 'debug_assertions'), True),
            (('profile', 'overflow_checks'), True),
            (('profile', 'debuginfo'), False),
            (('manifest_path',), str(source / 'unrelated/Cargo.toml')),
        ]
        for path, value in changes:
            changed = copy.deepcopy(cli)
            node = changed
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
            raw = '\n'.join(json.dumps(item) for item in (
                row, integration, changed, dict(reason='build-finished', success=True)))
            with self.subTest(path=path), self.assertRaises(ValueError):
                runner.select_binaries(raw, source, target, 'fixed')
        changed = dict(cli, executable=str(altered_path), filenames=[str(altered_path)])
        raw = '\n'.join(json.dumps(item) for item in (
            row, integration, changed, dict(reason='build-finished', success=True)))
        with self.assertRaisesRegex(ValueError, 'EMBEDDED_CLI_PATH'):
            runner.select_binaries(raw, source, target, 'fixed')

    def test_each_actual_list_must_contain_its_assigned_names(self):
        for mode in runner.MODE_GROUPS:
            names = runner.controls_for_mode(mode)
            listing = '\n'.join(name + ': test' for name in names) + f'\n\n{len(names)} tests, 0 benchmarks\n'
            self.assertEqual(runner.validate_list(listing, names)['listed_tests'], len(names))
            with self.assertRaises(ValueError):
                runner.validate_list(listing.replace(names[-1] + ': test\n', ''), names)
        names = runner.POOL_INTEGRATION
        listing = '\n'.join(name + ': test' for name in names) + '\n\n10 tests, 0 benchmarks\n'
        runner.validate_list(listing, names, exact=True)
        with self.assertRaises(ValueError):
            runner.validate_list(listing.replace('\n\n10 tests', '\nunrelated: test\n\n11 tests'),
                                 names, exact=True)

    def test_pool_old_requires_exact_panic_and_work_after_the_original_signal(self):
        for name in runner.POOL_FAILURES:
            self.assertEqual(runner.validate_control(name, 'pool-before-v2', process(True),
                             transcript(name, True), pool_panic(name))['expected'], 'fail')
            _, line, right = runner.POOL_FAILURES[name]
            wrong_left = '1' if right == 0 else '256'
            changed = pool_panic(name).replace('left: 2\n' if right == 0 else 'left: 512\n',
                                               'left: ' + wrong_left + '\n')
            for bad in ('', 'setup failed', changed, pool_panic(name) + pool_panic(name),
                        pool_panic(name).replace(name, 'other::test'),
                        pool_panic(name).replace(':' + str(line) + ':', ':1:'),
                        pool_panic(name).replace('pool_run_control_tests.rs', 'mining.rs'),
                        pool_panic(name).replace('IGNORED_STOP', 'OTHER_FAILURE'),
                        pool_panic(name).replace('right: ' + str(right), 'right: 999')):
                with self.subTest(name=name, stderr=bad), self.assertRaises(ValueError):
                    runner.validate_control(name, 'pool-before-v2', process(True), transcript(name, True), bad)
            for code in (0, 1, -9, 130, None, False):
                with self.subTest(name=name, code=code), self.assertRaises(ValueError):
                    runner.validate_control(name, 'pool-before-v2', dict(process(True), exit_code=code),
                                            transcript(name, True), pool_panic(name))

    def test_pool_scan_before_requires_exact_named_assertion_and_six_to_two_rows(self):
        for name in runner.POOL_SCAN_CONTROLS:
            expected = runner.validate_control(name, 'pool-scan-before', process(True),
                                               transcript(name, True), pool_scan_panic(name))
            self.assertEqual(expected['expected'], 'fail')
            self.assertEqual(expected['group'], 'pool-scan')
            self.assertTrue(expected['expected_outcome_observed'])
            stderr = pool_scan_panic(name).replace("' panicked", "' (1234) panicked")
            self.assertTrue(runner.validate_control(name, 'pool-scan-before', process(True),
                            transcript(name, True), stderr)['expected_outcome_observed'])

    def test_pool_scan_wrong_panic_line_source_name_or_multiple_panics_are_refused(self):
        for name in runner.POOL_SCAN_CONTROLS:
            stderr = pool_scan_panic(name)
            for bad in (
                '', stderr.replace(':' + str(runner.POOL_SCAN_PANIC_LINE) + ':', ':200:'),
                stderr.replace('pool_reconcile_control_tests.rs', 'pool_run_control_tests.rs'),
                stderr.replace(name, 'unrelated::test'), stderr + stderr,
                stderr.replace('pool-batch', 'batch-revalidation'),
                stderr.replace(runner.POOL_SCAN_MARKER, 'fixture failed'),
            ):
                with self.subTest(name=name, stderr=bad), self.assertRaises(ValueError):
                    runner.validate_control(name, 'pool-scan-before', process(True),
                                            transcript(name, True), bad)

    def test_pool_scan_wrong_values_and_duplicate_row_observations_are_refused(self):
        name = runner.POOL_SCAN_CONTROLS[0]
        stderr = pool_scan_panic(name)
        for bad in (
            stderr.replace('left: 6', 'left: 2'), stderr.replace('left: 6', 'left: 7'),
            stderr.replace('left: 6', 'left: -6'), stderr.replace('right: 2', 'right: 6'),
            stderr.replace('right: 2', 'right: true'), stderr.replace('left: 6\n', ''),
            stderr + '  left: 6\n', stderr + ' right: 2\n',
        ):
            with self.subTest(stderr=bad), self.assertRaises(ValueError):
                runner.validate_control(name, 'pool-scan-before', process(True),
                                        transcript(name, True), bad)

    def test_pool_scan_signals_early_failure_and_incomplete_test_result_are_refused(self):
        for name in runner.POOL_SCAN_CONTROLS:
            for status in (
                *(dict(process(True), exit_code=code) for code in (0, 1, -9, 130, None, False, '101')),
                dict(process(True), started=False), dict(process(True), failure='spawn failed'),
                dict(process(True), cleanup_errors=['unreaped']),
            ):
                with self.subTest(name=name, status=status), self.assertRaises(ValueError):
                    runner.validate_control(name, 'pool-scan-before', status,
                                            transcript(name, True), pool_scan_panic(name))
            for raw in ('', transcript(name, True).split('test result:')[0],
                        transcript(name, True).replace('0 ignored', '1 ignored'),
                        transcript(name, True).replace(name, 'unrelated::test'),
                        transcript(name, True) + transcript(name, True)):
                with self.subTest(name=name, stdout=raw), self.assertRaises(ValueError):
                    runner.validate_control(name, 'pool-scan-before', process(True),
                                            raw, pool_scan_panic(name))
            early = pool_scan_panic(name).replace(
                'assertion ' + chr(96) + 'left == right' + chr(96) + ' failed: ' + runner.POOL_SCAN_MARKER,
                'POOL_RUN_RETAINED_FIXTURE_EXPIRED_BEFORE_SIGNAL')
            with self.assertRaisesRegex(ValueError, 'EXPECTED_POOL_SCAN_SIGNAL_ASSERTION'):
                runner.validate_control(name, 'pool-scan-before', process(True),
                                        transcript(name, True), early)

    def test_pool_scan_fixed_requires_named_pass_and_cannot_borrow_other_old_sources(self):
        for name in runner.POOL_SCAN_CONTROLS:
            self.assertEqual(runner.validate_control(name, 'fixed', process(),
                             transcript(name), '')['expected'], 'pass')
            with self.assertRaises(ValueError):
                runner.validate_control(name, 'fixed', process(True),
                                        transcript(name, True), pool_scan_panic(name))
            with self.assertRaises(ValueError):
                runner.validate_control(name, 'fixed', process(),
                                        transcript(name).replace('0 ignored', '1 ignored'), '')
            for mode in ('budget-before-v2', 'pool-before-v2'):
                with self.subTest(name=name, mode=mode), self.assertRaises(ValueError):
                    runner.validate_control(name, mode, process(True),
                                            transcript(name, True), pool_scan_panic(name))

    def test_pool_scan_actual_list_must_include_both_names_even_with_consistent_totals(self):
        names = runner.POOL_SCAN_CONTROLS
        for kept in ((), names[:1], names[1:], ('unrelated::test', names[1])):
            raw = '\n'.join(name + ': test' for name in kept) + f'\n\n{len(kept)} tests, 0 benchmarks\n'
            with self.subTest(kept=kept), self.assertRaises(ValueError):
                runner.validate_list(raw, names)

    def test_pool_scan_panic_line_is_the_committed_row_assertion(self):
        source = (runner.ROOT / runner.GROUP_INPUTS['pool-scan'][0]).read_text().splitlines()
        start = runner.POOL_SCAN_PANIC_LINE - 1
        self.assertEqual(source[start].strip(), 'assert_eq!(')
        self.assertEqual(source[start + 1].strip(), 'observation.max_rows_after_signal, 2,')
        self.assertIn('POOL_RUN_RECONCILIATION_ROWS_IGNORED_ORIGINAL_CONTROL: {stage}',
                      source[start + 2])

    def test_pool_fixed_and_two_old_positive_controls_require_real_named_success(self):
        for mode, names in (('fixed', runner.POOL_CONTROLS), ('pool-before-v2', runner.POOL_POSITIVES)):
            for name in names:
                self.assertEqual(runner.validate_control(name, mode, process(), transcript(name), '')['expected'], 'pass')
                for bad_process in (process(True), dict(process(), started=False),
                                    dict(process(), cleanup_errors=['not collected'])):
                    with self.subTest(mode=mode, name=name), self.assertRaises(ValueError):
                        runner.validate_control(name, mode, bad_process, transcript(name), '')
                with self.assertRaises(ValueError):
                    runner.validate_control(name, mode, process(), transcript(name).replace('0 ignored', '1 ignored'), '')
        for name in runner.POOL_CONTROLS:
            with self.assertRaises(ValueError):
                runner.validate_control(name, 'budget-before-v2', process(), transcript(name), '')

    def test_scalar_handoff_invariants_are_fixed_only_and_cannot_be_ignored(self):
        for name in runner.HANDOFF_CONTROLS:
            self.assertTrue(runner.validate_control(name, 'fixed', process(), transcript(name), '')
                            ['expected_outcome_observed'])
            for mode in runner.BEFORE_SOURCES:
                with self.assertRaises(ValueError):
                    runner.validate_control(name, mode, process(), transcript(name), '')
            for raw in ('', transcript(name).replace('1 passed', '0 passed'),
                        transcript(name).replace(name, 'other::test'),
                        transcript(name) + transcript(name)):
                with self.assertRaises(ValueError):
                    runner.validate_control(name, 'fixed', process(), raw, '')

    def test_full_pool_integration_requires_every_original_name_once(self):
        raw = integration_transcript()
        self.assertEqual(runner.validate_pool_integration(raw)['passed'], 10)
        first, second = runner.POOL_INTEGRATION[:2]
        for bad in ('', raw.replace(first, second), raw.replace(first, 'other_test'),
                    raw.replace('test ' + first + ' ... ok\n', ''),
                    raw.replace('test ' + first + ' ... ok', 'test ' + first + ' ... ignored'),
                    raw.replace('0 filtered out', '1 filtered out'),
                    raw.replace('0 ignored', '1 ignored'), raw.replace('10 passed', '9 passed'),
                    raw + raw, raw + 'test result: FAILED. 0 passed; 1 failed;\n',
                    raw.replace('running 10 tests', 'running 9 tests')):
            with self.subTest(raw=bad), self.assertRaises(ValueError):
                runner.validate_pool_integration(bad)

    def mock_component_run(self, mode, fail_first=False, mutate_cli=False, change_shared=False,
                           change_group=False):
        base = self.root / (mode + ('-failure' if fail_first else '') + ('-cli-change' if mutate_cli else ''))
        base.mkdir()
        source, driver, target, out = (base / name for name in ('subject', 'driver', 'target', 'observations'))
        source.mkdir()
        driver.mkdir()
        for root in (source, driver):
            for relatives in runner.same_input_groups(mode).values():
                for relative in relatives:
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('[toolchain]\nchannel = "1.95.0"\n' if relative == 'rust-toolchain.toml' else 'identical reader fixture\n')
            if mode == 'fixed':
                for relative in runner.FIXED_ONLY_INPUTS:
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('fixed-only reader fixture\n')
        if mode in ('pool-before-v2', 'pool-scan-before'):
            # Independent source groups do not compare unrelated test inputs.
            for group, relatives in runner.GROUP_INPUTS.items():
                if group not in runner.MODE_GROUPS[mode]:
                    path = source / relatives[0]
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('unrelated old group bytes\n')
        if change_shared:
            (source / runner.COMMON_INPUTS[0]).write_text('changed shared profile\n')
        if change_group:
            (source / runner.GROUP_INPUTS['pool-scan'][0]).write_text('changed pool-scan controls\n')
        rustc = base / 'rustc'
        rustc.write_text('mock compiler path; never executed\n')
        names = runner.controls_for_mode(mode)
        captured = []

        def fake_capture(command, cwd, observation, label, env):
            captured.append((label, command))
            raw, error, status = '', '', process()
            if label == 'rustc-path':
                raw = str(rustc) + '\n'
            elif label in ('rustc-version', 'cargo-version'):
                raw = 'release: 1.95.0\n'
            elif label == 'build':
                roles = ('libtest', 'pool-integration', 'cli') if mode == 'fixed' else ('libtest',)
                rows = [self.artifact(role, source, target)[3] for role in roles]
                raw = '\n'.join(json.dumps(row) for row in rows + [dict(reason='build-finished', success=True)])
            elif label in ('libtest-list', 'pool-integration-list'):
                listed = names if label == 'libtest-list' else runner.POOL_INTEGRATION
                raw = '\n'.join(name + ': test' for name in listed) + f'\n\n{len(listed)} tests, 0 benchmarks\n'
            elif label.startswith('test-'):
                name = command[2]
                failed = (mode == 'budget-before-v2' and name != runner.EQUIVALENCE
                          or mode == 'pool-before-v2' and name in runner.POOL_FAILURES
                          or mode == 'pool-scan-before' and name in runner.POOL_SCAN_CONTROLS)
                status = process(failed)
                observation_record = history(name, mode) if name in runner.HISTORY else None
                raw = transcript(name, failed, observation_record)
                error = (pool_scan_panic(name) if name in runner.POOL_SCAN_CONTROLS
                         else pool_panic(name) if name in runner.POOL_FAILURES
                         else panic(name)) if failed else ''
                if fail_first and label == 'test-01':
                    status = dict(status, exit_code=-9)
            elif label == 'pool-integration':
                raw = integration_transcript()
                if mutate_cli:
                    cli = target / 'release/trnm-pon-node'
                    cli.chmod(0o700)
                    cli.write_bytes(b'changed actual integration CLI')
            (observation / (label + '.stdout')).write_text(raw)
            (observation / (label + '.stderr')).write_text(error)
            return dict(status, command=command, cwd=str(cwd))

        current = 'a' * 40
        subject = runner.BEFORE_SOURCES[mode][0] if mode in runner.BEFORE_SOURCES else current
        args = argparse.Namespace(source=source, out=out, mode=mode, driver_sha=current, source_sha=subject)
        def verify(kind, sha, root):
            return dict(tested_commit=sha, tested_tree=runner.BEFORE_SOURCES[mode][1]
                        if root == source and mode in runner.BEFORE_SOURCES else 'b' * 40)
        with patch.object(runner, 'ROOT', driver), patch.object(runner, 'verify_source', side_effect=verify) as verified, \
                patch.object(runner, 'capture', side_effect=fake_capture), \
                patch.dict(os.environ, {'CARGO_TARGET_DIR': str(target), 'CARGO_HOME': str(base / 'cargo-home'),
                                        'CARGO_BUILD_JOBS': '1', 'CARGO_INCREMENTAL': '0'}, clear=True), \
                patch.object(runner.platform, 'system', return_value='Linux'), \
                patch.object(runner.platform, 'machine', return_value='x86_64'):
            report = runner.run(args)
        self.assertEqual(verified.call_count, 4)
        for flag in runner.FALSE_FLAGS:
            self.assertIs(report[flag], False)
        return report, captured

    def test_mock_orchestration_builds_once_and_keeps_each_group_separate(self):
        for mode in runner.MODE_GROUPS:
            report, captured = self.mock_component_run(mode)
            self.assertEqual(report['result'], 'PASS', report['errors'])
            self.assertEqual(sum(label == 'build' for label, _ in captured), 1)
            self.assertEqual(report['native_control_processes_started'], len(runner.controls_for_mode(mode)))
            self.assertEqual(report['matched_pass_controls'], report['expected_passes'])
            self.assertEqual(report['matched_failure_controls'], report['expected_failures'])
            self.assertEqual(report['native_pool_integration_process_started'], mode == 'fixed')
            if mode == 'fixed':
                self.assertEqual(report['pool_integration']['passed'], 10)
                self.assertEqual(set(report['executables']), {'libtest', 'pool-integration', 'cli'})
                self.assertTrue(report['executables']['cli']['execution_path'].endswith('/target/release/trnm-pon-node'))
            else:
                self.assertIsNone(report['pool_integration'])

    def test_mock_failure_keeps_all_later_cases_integration_and_final_identities(self):
        report, captured = self.mock_component_run('fixed', fail_first=True)
        self.assertEqual(report['result'], 'FAIL')
        self.assertEqual(report['native_control_processes_started'], 21)
        self.assertEqual(report['matched_pass_controls'], 20)
        self.assertEqual(report['pool_integration']['passed'], 10)
        self.assertEqual(len(report['source_after']), 2)
        self.assertEqual(sum(label == 'pool-integration' for label, _ in captured), 1)
        self.assertFalse(report['cases'][0]['expected_outcome_observed'])
        self.assertEqual(report['cases'][0]['process']['exit_code'], -9)

    def test_mock_actual_cli_change_invalidates_an_otherwise_complete_run(self):
        report, _ = self.mock_component_run('fixed', mutate_cli=True)
        self.assertEqual(report['pool_integration']['passed'], 10)
        self.assertEqual(report['result'], 'FAIL')
        self.assertTrue(any('EXECUTED_BINARY_CHANGED:cli' in error for error in report['errors']))

    def test_mock_pool_scan_signal_failure_preserves_later_case_and_final_identities(self):
        report, captured = self.mock_component_run('pool-scan-before', fail_first=True)
        self.assertEqual(report['result'], 'FAIL')
        self.assertEqual(report['expected_failures'], 2)
        self.assertEqual(report['native_control_processes_started'], 2)
        self.assertEqual(report['matched_failure_controls'], 1)
        self.assertEqual(report['matched_pass_controls'], 0)
        self.assertFalse(report['cases'][0]['expected_outcome_observed'])
        self.assertEqual(report['cases'][0]['process']['exit_code'], -9)
        self.assertTrue(report['cases'][1]['expected_outcome_observed'])
        self.assertEqual(len(report['source_after']), 2)
        self.assertEqual(sum(label == 'build' for label, _ in captured), 1)
        self.assertFalse(any(label == 'pool-integration' for label, _ in captured))

    def test_mock_pool_scan_input_change_is_refused_before_compilation(self):
        for mode in ('pool-scan-before', 'fixed'):
            report, captured = self.mock_component_run(mode, change_group=True)
            self.assertEqual(report['result'], 'FAIL')
            self.assertEqual(report['native_control_processes_started'], 0)
            self.assertFalse(any(label == 'build' for label, _ in captured))
            self.assertTrue(any('IDENTICAL_GROUP_TESTS_LOCK_AND_PROFILE_REQUIRED' in error
                                for error in report['errors']))

    def test_mock_shared_profile_change_is_rejected_before_compilation(self):
        for mode in runner.MODE_GROUPS:
            with self.subTest(mode=mode):
                report, captured = self.mock_component_run(mode, change_shared=True)
                self.assertEqual(report['result'], 'FAIL')
                self.assertEqual(report['native_control_processes_started'], 0)
                self.assertFalse(any(label == 'build' for label, _ in captured))
                self.assertTrue(any('IDENTICAL_GROUP_TESTS_LOCK_AND_PROFILE_REQUIRED' in error for error in report['errors']))


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

    def test_workflow_keeps_four_sources_separate_and_all_failures(self):
        text = (runner.ROOT / '.github/workflows/pon-budget-controls.yml').read_text()
        for expected in ('source: [budget-before-v2, pool-before-v2, pool-scan-before, fixed]', runner.BUDGET_BEFORE_SHA,
                         runner.POOL_BEFORE_SHA, runner.POOL_SCAN_BEFORE_SHA, 'CARGO_BUILD_JOBS: "1"', 'path: driver',
                         'path: subject', 'fail-fast: false', 'cancel-in-progress: false',
                         'if: always()', 'rustup toolchain install 1.95.0',
                         '--driver-sha "$DRIVER_SHA" --source-sha "$SUBJECT_SHA"'):
            self.assertIn(expected, text)
        self.assertNotIn('continue-on-error:', text)
        self.assertNotIn("matrix.source == 'pool-before'", text)
        self.assertNotIn('db93026b9314bfd8bc4350945036998f1b7d34aa', text)
        self.assertNotIn('run_public_v3_service_campaign', text)
        self.assertNotIn('pq-cross-branch-corpus', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
