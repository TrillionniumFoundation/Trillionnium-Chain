#!/usr/bin/env python3
"""Synthetic counterexamples for the reader; fixtures are never native evidence."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import read_native_campaign_attempt as reader
from test_pon_public_v3_phase_read import attribution_phase, business_round

HEAD, TREE = '1' * 40, '2' * 40


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def step(number, success):
    build = number == 'build'
    name = 'build' if build else f'run-{number}'
    command = ['/synthetic/cargo', '+1.95.0', 'test', '--locked', '--offline', '--release',
               '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--test',
               'public_v3_multiprocess']
    command += (['--no-run', '--message-format=json'] if build else
                ['separate_process_work_and_signed_confirmation_campaign', '--', '--exact',
                 '--ignored', '--nocapture', '--test-threads=1'])
    return dict(name=name, command=command, cwd='/synthetic/source', returncode=0 if success else 101,
                complete_success=success, error=None, elapsed_ns=1_000_000_000,
                outer_stage_timeout_seconds=1800 if build else 600)


def report(success=False):
    phases = []
    for mode, attackers in zip(('baseline', 'from-zero', 'late-product'), (0, 24, 24)):
        phase = attribution_phase([], [], [], [])
        phase.update(mode=mode, attacker_processes_requested=attackers,
                     finite_phase_criteria_met=success, all_signed_rounds_confirmed_in_window=success)
        count = 3 if success else 2 if mode == 'baseline' else 1
        # Supply the current reader's original confirmation identity/work relation.
        # These rows remain synthetic controls and do not authenticate a native run.
        phase['confirmations'] = [business_round(n,
            started=1_000_000_000 + n * 4_000_000_000,
            ended=2_000_000_000 + n * 4_000_000_000,
            confirmed=success or (mode == 'baseline' and n == 0)) for n in range(count)]
        phases.append(phase)
    return dict(schema='native-public-v3-separate-process-campaign-v2', state_backend='authenticated-v1',
        finite_experiment_criteria_met=success, economics_complete=True,
        best_observed_cold_legal_method=None, phases=phases,
        preparation=dict(state_backend='authenticated-v1', actual_signed_seed_transfers=1024,
                         seed_blocks=4, business_blocks=21, cpu_ns=None, wall_ns=None),
        cryptographic_hardness_qualified=False, work_profile_qualified=False,
        independent_operators=False, wan_qualified=False, production_candidate=False, release_ready=False)


class CampaignAttemptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='trnm-failed-campaign-reader-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.make()

    def make(self, success=False):
        self.reports = {n: report(success) for n in (1, 2, 3)}
        self.value = dict(schema='pon-original-native-campaign-ci-v1', source_kind='head',
            expected_head=HEAD, expected_tree=TREE, profile='release', toolchain='1.95.0',
            state_backend='authenticated-v1', planned_complete_runs=3, build_timeout_seconds=1800,
            original_campaign_outer_timeout_seconds=600, runner_sha256='3' * 64,
            original_inputs=dict(seed_transfers=1024, seed_blocks=4, business_blocks=21, phase_seconds=30,
                                 modes=['baseline', 'from-zero', 'late-product'], attacker_processes=[0, 24, 24]),
            expected_resources=dict(cpu_max='400000 100000', memory_max='17179869184', nice=10),
            public_phase_placement=copy.deepcopy(reader.PUBLIC_PLACEMENT),
            complete_success=success, failure=None if success else 'ORIGINAL_THREE_RUN_CAMPAIGN_FAILED',
            finalization_failures=[], build=step('build', True), source_after=dict(
                schema='trnm-ci-source-v1', kind='head', candidate=HEAD, tested_commit=HEAD, tested_tree=TREE,
                base=None, prospective_merge=None, tracked_worktree_verified=True,
                tests_executed_by_identity_check=False, tracked_entries=3, tracked_bytes=100),
            attempts=[dict(number=n, step=step(n, success), report_directory=f'run-{n}-raw',
                report_validation_failure=None, original_criteria_met=success, complete_success=success,
                phase_startup_errors=[]) for n in (1, 2, 3)])
        self.save()

    def save(self):
        files = []
        for number, raw in self.reports.items():
            data = encode(raw)
            name = f'run-{number}-raw/report.json'
            path = self.root / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(data)
            files.append(dict(path=name, bytes=len(data), sha256=sha(data)))
            for attempt in self.value['attempts']:
                if attempt['number'] == number:
                    attempt['report_sha256'] = sha(data)
        data = encode(self.value)
        (self.root / 'results.json').write_bytes(data)
        self.pin = sha(data)
        files.append(dict(path='results.json', bytes=len(data), sha256=self.pin))
        self.files = dict(scope='synthetic reader control only', files=files)
        self.save_manifest()

    def save_result(self):
        data = encode(self.value)
        (self.root / 'results.json').write_bytes(data)
        self.pin = sha(data)
        row = next(row for row in self.files['files'] if row['path'] == 'results.json')
        row.update(bytes=len(data), sha256=self.pin)
        self.save_manifest()

    def save_manifest(self):
        data = encode(self.files)
        (self.root / 'artifact-files.json').write_bytes(data)
        self.manifest_pin = sha(data)

    def read(self, *, originals=True, manifest=True):
        return reader.read_attempt(self.root / 'results.json', self.pin, HEAD, TREE,
            reports_root=self.root if originals else None,
            artifact_manifest_sha256=self.manifest_pin if originals and manifest else None)

    def test_three_failed_runs_keep_all_27_slots_and_unknown_costs(self):
        value = self.read()
        self.assertEqual(value['status'], 'failure')
        counts = value['denominators']
        self.assertEqual(counts, dict(planned_runs=3, planned_phases=9, planned_confirmation_rounds=27,
            planned_business_packet_exposures=189, attempt_records=3, raw_reports_observed=3,
            observed_confirmation_records=12, unknown_confirmation_slots=15, retained_confirmation_flags_true=3))
        slots = value['all_planned_slots']
        self.assertEqual(len({(r['run'], r['phase'], r['round']) for r in slots}), 27)
        self.assertTrue(all(r['confirmed_inside_pressure_window'] is None for r in slots if not r['observed']))
        self.assertIsNone(value['runs'][0]['raw']['phases'][0]['whole_parent_phase_cpu_ns'])
        self.assertEqual(value['result']['declared_failure'], 'ORIGINAL_THREE_RUN_CAMPAIGN_FAILED')
        self.assertEqual([r['step']['returncode'] for r in value['runs']], [101, 101, 101])

    def test_declared_failure_without_originals_is_status_only(self):
        value = self.read(originals=False)
        self.assertEqual((value['status'], value['coverage']), ('failure', 'status_only'))
        self.assertEqual(value['denominators']['unknown_confirmation_slots'], 27)
        self.assertEqual(value['denominators']['retained_confirmation_flags_true'], 0)

    def test_declared_success_without_originals_is_unknown_never_pass(self):
        self.make(success=True)
        value = self.read(originals=False)
        self.assertEqual((value['status'], value['coverage']), ('unknown', 'status_only'))
        for key in ('current_tuple_credit', 'native_qualification', 'independent_acceptance',
                    'production_qualification', 'four_second_slo_qualified'):
            self.assertIs(value['scope'][key], False)
        self.assertEqual(value['denominators']['unknown_confirmation_slots'], 27)

    def test_consistent_complete_reports_are_only_observed(self):
        self.make(success=True)
        value = self.read()
        self.assertEqual(value['status'], 'observed')
        self.assertFalse(value['scope']['host_or_source_authenticated'])
        self.assertFalse(value['scope']['binary_or_log_payloads_verified'])
        self.assertFalse(value['scope']['native_qualification'])
        self.assertEqual(value['denominators']['retained_confirmation_flags_true'], 27)

    def test_positive_summaries_cannot_hide_missing_original_confirmation_slots(self):
        self.make(success=True)
        for raw in self.reports.values():
            raw['phases'][0].update(confirmations=[], all_signed_rounds_confirmed_in_window=False)
        self.save()
        value = self.read()
        self.assertEqual(value['status'], 'partial')
        self.assertTrue(all(row['report_state'] == 'rejected' for row in value['runs']))
        self.assertTrue(all('all three planned confirmed rounds' in row['report_error'] for row in value['runs']))
        self.assertEqual(value['denominators']['unknown_confirmation_slots'], 27)
        self.assertFalse(value['scope']['native_qualification'])

    def test_positive_campaign_cannot_hide_a_failed_phase_or_incomplete_economics(self):
        for missing in ('phase', 'economics'):
            with self.subTest(missing=missing):
                self.make(success=True)
                if missing == 'phase':
                    self.reports[1]['phases'][0]['finite_phase_criteria_met'] = False
                else:
                    self.reports[1]['economics_complete'] = False
                self.value['attempts'][0].update(original_criteria_met=False, complete_success=False)
                self.value.update(complete_success=False, failure='ORIGINAL_THREE_RUN_CAMPAIGN_FAILED')
                self.save()
                value = self.read()
                self.assertEqual(value['runs'][0]['report_state'], 'rejected')
                self.assertIn('positive campaign summary', value['runs'][0]['report_error'])
                self.assertEqual(value['denominators']['unknown_confirmation_slots'], 9)

    def test_missing_report_preserves_planned_slots_and_does_not_claim_success(self):
        self.make(success=True)
        (self.root / 'run-2-raw/report.json').unlink()
        value = self.read()
        self.assertEqual(value['status'], 'partial')
        self.assertEqual(value['runs'][1]['report_state'], 'missing')
        self.assertEqual(value['denominators']['unknown_confirmation_slots'], 9)
        self.assertEqual(value['denominators']['planned_confirmation_rounds'], 27)

    def test_build_failure_has_zero_attempts_and_full_unknown_denominator(self):
        self.value.update(attempts=[], source_after=None, build=step('build', False), failure='RELEASE_TEST_BUILD_FAILED')
        self.save_result()
        value = self.read()
        self.assertEqual(value['status'], 'failure')
        self.assertEqual(value['denominators']['attempt_records'], 0)
        self.assertEqual(value['denominators']['unknown_confirmation_slots'], 27)

    def test_unknown_process_outcome_is_not_an_exit_zero_or_failure(self):
        self.value.update(failure=None, source_after=None)
        self.value['attempts'] = self.value['attempts'][:1]
        self.value['attempts'][0]['step'].update(returncode=None, error=None, elapsed_ns=None)
        self.save_result()
        value = self.read(originals=False)
        self.assertEqual(value['status'], 'unknown')
        self.assertIsNone(value['runs'][0]['step']['returncode'])
        self.assertEqual(value['denominators']['unknown_confirmation_slots'], 27)

    def test_late_30_second_confirmation_cannot_become_four_second_success(self):
        for raw in self.reports.values():
            raw['phases'][0]['confirmations'][0]['ended_ns'] = 22_000_000_000
        self.save()
        value = self.read()
        self.assertEqual(value['denominators']['retained_confirmation_flags_true'], 3)
        self.assertEqual(value['all_planned_slots'][0]['ended_ns'], 22_000_000_000)
        self.assertFalse(value['scope']['four_second_slo_qualified'])
        self.assertTrue(value['scope']['thirty_second_flags_are_not_four_second_slo'])

    def test_missing_attempts_are_not_replaced_by_next_runs_or_retries(self):
        self.value['attempts'] = self.value['attempts'][:1]
        self.save_result()
        value = self.read()
        self.assertEqual(value['denominators']['attempt_records'], 1)
        self.assertEqual(value['denominators']['unknown_confirmation_slots'], 23)
        self.value['attempts'][0]['number'] = 2
        self.save_result()
        with self.assertRaisesRegex(ValueError, 'attempt order'):
            self.read()

    def test_expected_source_and_embedded_source_must_both_match(self):
        with self.assertRaisesRegex(ValueError, 'declared measured source'):
            reader.read_attempt(self.root / 'results.json', self.pin, '4' * 40, TREE)
        self.value['source_after']['tested_tree'] = '5' * 40
        self.save_result()
        with self.assertRaisesRegex(ValueError, 'source head/tree'):
            self.read()

    def test_hash_mutation_is_rejected_even_for_reported_failure(self):
        with (self.root / 'results.json').open('ab') as stream:
            stream.write(b' ')
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            self.read()
        self.save_result()
        with (self.root / 'run-1-raw/report.json').open('ab') as stream:
            stream.write(b' ')
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            self.read()

    def test_independently_pinned_manifest_rejects_rebound_report(self):
        self.value['attempts'][0]['report_sha256'] = '4' * 64
        self.save_result()
        with self.assertRaisesRegex(ValueError, 'report pins disagree'):
            self.read()

    def test_result_cannot_shrink_or_change_workload_and_resource_budget(self):
        mutations = (
            lambda v: v.update(planned_complete_runs=1),
            lambda v: v['original_inputs'].update(attacker_processes=[0, 16, 16]),
            lambda v: v['original_inputs'].update(phase_seconds=60),
            lambda v: v['original_inputs'].update(seed_blocks=False),
            lambda v: v['expected_resources'].update(cpu_max='800000 100000'),
            lambda v: v['public_phase_placement'].update(receiver_and_verifier_cpu_max='400000 100000'),
            lambda v: v['attempts'][0]['step'].update(outer_stage_timeout_seconds=1200),
            lambda v: v['attempts'][0]['step']['command'].append('--skip'),
        )
        original = copy.deepcopy(self.value)
        for change in mutations:
            with self.subTest(change=change):
                self.value = copy.deepcopy(original)
                change(self.value)
                self.save_result()
                with self.assertRaises(ValueError):
                    self.read()

    def test_failure_cannot_be_overridden_by_complete_success_flag(self):
        self.value['complete_success'] = True
        self.save_result()
        with self.assertRaisesRegex(ValueError, 'successful campaign'):
            self.read(originals=False)

    def test_type_confusion_bool_exit_and_integer_success_are_refused(self):
        self.value['attempts'][0]['step']['returncode'] = True
        self.save_result()
        with self.assertRaisesRegex(ValueError, 'integer exit'):
            self.read()
        self.value['attempts'][0]['step']['returncode'] = 101
        self.value['complete_success'] = 1
        self.save_result()
        with self.assertRaisesRegex(ValueError, 'boolean'):
            self.read()

    def test_bound_but_malformed_report_preserves_failure_and_unknown_slots(self):
        self.reports[1]['phases'][1]['duration_seconds'] = 60
        self.save()
        value = self.read()
        self.assertEqual(value['status'], 'failure')
        self.assertEqual(value['runs'][0]['report_state'], 'rejected')
        self.assertIn('phase inputs changed', value['runs'][0]['report_error'])
        self.assertEqual(value['denominators']['unknown_confirmation_slots'], 19)
        self.assertEqual(value['denominators']['planned_confirmation_rounds'], 27)

    def test_duplicate_round_and_malformed_clocks_cannot_be_counted(self):
        original = copy.deepcopy(self.reports)
        changes = [lambda r: r['phases'][0]['confirmations'].append(copy.deepcopy(r['phases'][0]['confirmations'][0]))]
        for bad in (-1, True, 2**128):
            changes.append(lambda r, bad=bad: r['phases'][0]['confirmations'][0].update(ended_ns=bad))
        for change in changes:
            with self.subTest(change=change):
                self.reports = copy.deepcopy(original)
                change(self.reports[1])
                self.save()
                value = self.read()
                self.assertEqual(value['runs'][0]['report_state'], 'rejected')
                self.assertEqual(value['denominators']['unknown_confirmation_slots'], 19)

    def test_raw_phase_order_and_boolean_promotion_are_refused(self):
        self.reports[1]['phases'].reverse()
        self.save()
        self.assertEqual(self.read()['runs'][0]['report_state'], 'rejected')
        self.reports[1]['phases'].reverse()
        self.reports[1]['phases'][0]['confirmations'][0]['confirmed_inside_pressure_window'] = 1
        self.save()
        self.assertEqual(self.read()['runs'][0]['report_state'], 'rejected')

    def test_summary_criteria_cannot_replace_raw_criteria(self):
        self.value['attempts'][0]['original_criteria_met'] = True
        self.save_result()
        value = self.read()
        self.assertEqual(value['runs'][0]['report_state'], 'rejected')
        self.assertIn('criteria disagree', value['runs'][0]['report_error'])
        self.assertFalse(value['scope']['native_qualification'])

    def test_startup_failure_without_result_hash_uses_only_pinned_manifest(self):
        self.reports[1]['phases'][1] = dict(mode='from-zero', state_backend='authenticated-v1',
                                            startup_or_campaign_error='retained native startup failure')
        attempt = self.value['attempts'][0]
        attempt['phase_startup_errors'] = [dict(mode='from-zero', error='retained native startup failure')]
        attempt['report_validation_failure'] = 'ORIGINAL_NATIVE_PHASE_STARTUP_FAILED'
        self.save()
        del attempt['report_sha256']
        self.save_result()
        value = self.read()
        self.assertEqual(value['runs'][0]['report_state'], 'observed')
        self.assertEqual(value['runs'][0]['declared_phase_startup_errors'], attempt['phase_startup_errors'])
        self.assertEqual(value['denominators']['unknown_confirmation_slots'], 16)
        unbound = self.read(manifest=False)
        self.assertEqual(unbound['runs'][0]['report_state'], 'unbound')
        self.assertEqual(unbound['denominators']['unknown_confirmation_slots'], 19)

    def test_duplicate_nonfinite_and_oversized_result_refused(self):
        for raw in (b'{"schema":"a","schema":"b"}', b'{"x":NaN}'):
            (self.root / 'results.json').write_bytes(raw)
            self.pin = sha(raw)
            with self.assertRaises(ValueError):
                self.read(originals=False)
        self.save_result()
        with patch.object(reader, 'MAX_RESULT_BYTES', 10):
            with self.assertRaisesRegex(ValueError, 'bounded regular'):
                self.read(originals=False)

    def test_symlinks_and_nonregular_files_are_not_read(self):
        path = self.root / 'run-1-raw/report.json'
        original = path.with_name('real.json')
        path.rename(original)
        path.symlink_to(original)
        with self.assertRaises(OSError):
            self.read()
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(ValueError, 'bounded regular'):
            self.read()

    def test_symlinked_parent_directory_is_not_followed(self):
        directory = self.root / 'run-1-raw'
        moved = self.root / 'elsewhere'
        directory.rename(moved)
        directory.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(OSError):
            self.read()

    def test_manifest_cannot_traverse_duplicate_omit_or_rebind_result(self):
        original = copy.deepcopy(self.files)
        mutations = (
            lambda d: d['files'].append(copy.deepcopy(d['files'][0])),
            lambda d: d['files'][0].update(path='../outside'),
            lambda d: d['files'][0].update(path='artifact-files.json'),
            lambda d: d['files'].pop(0),
            lambda d: d['files'][-1].update(bytes=1),
            lambda d: d['files'][-1].update(sha256='9' * 64),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.files = copy.deepcopy(original)
                mutation(self.files)
                self.save_manifest()
                with self.assertRaises(ValueError):
                    self.read()

    def test_cli_distinguishes_failed_observation_from_rejected_input(self):
        args = ['--results', str(self.root / 'results.json'), '--results-sha256', self.pin,
                '--expected-head', HEAD, '--expected-tree', TREE, '--reports-root', str(self.root),
                '--artifact-manifest-sha256', self.manifest_pin]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = reader.main(args)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.getvalue())['status'], 'failure')
        args[3] = 'f' * 64
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = reader.main(args)
        self.assertEqual(code, 2)
        self.assertTrue(json.loads(out.getvalue())['input_rejected'])


    def test_current_confirmation_clock_and_observation_refusals_survive_partial_readback(self):
        self.assertTrue(all(row['report_state'] == 'observed' for row in self.read()['runs']))
        original = copy.deepcopy(self.reports)
        mutations = {
            'missing observation': lambda r: r.pop('observation'),
            'missing start': lambda r: r.pop('started_ns'),
            'missing end': lambda r: r.pop('ended_ns'),
            'not confirmed': lambda r: r['observation'].update(confirmed=False),
            'finality promoted': lambda r: r['observation'].update(finalized=True),
            'authority promoted': lambda r: r['observation'].update(execution_authority=True),
            'insufficient depth': lambda r: r['observation'].update(depth=5),
            'transaction rebound': lambda r: r.update(transaction='ff' * 32),
            'invalid required work': lambda r: r['observation'].update(required_work_delta='00' * 63 + '05'),
            'original deadline reached': lambda r: r.update(ended_ns=30_000_000_000),
        }
        for name, mutate in mutations.items():
            with self.subTest(refusal=name):
                self.reports = copy.deepcopy(original)
                mutate(self.reports[1]['phases'][0]['confirmations'][0])
                self.save()
                value = self.read()
                self.assertEqual(value['runs'][0]['report_state'], 'rejected')
                self.assertEqual(value['denominators']['unknown_confirmation_slots'], 19)
                self.assertEqual(value['denominators']['planned_confirmation_rounds'], 27)
                self.assertFalse(value['scope']['native_qualification'])
                self.assertFalse(value['scope']['four_second_slo_qualified'])


if __name__ == '__main__':
    unittest.main()
