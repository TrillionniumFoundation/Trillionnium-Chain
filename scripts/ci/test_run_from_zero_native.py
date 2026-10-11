#!/usr/bin/env python3
"""Execution-driver negative controls; compiler/test processes are simulated here.

These tests verify result handling, not Rust compilation or public service.
"""
from __future__ import annotations
import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_from_zero_native as driver


def artifact(path: Path, **fields: object) -> str:
    row = {'reason': 'compiler-artifact', 'target': {'name': driver.TARGET},
           'profile': {'test': True}, 'executable': str(path)}
    row.update(fields)
    return json.dumps(row)


def simulated_service_report():
    """Synthetic schema data only: these numbers are not measured CPU or work."""
    phases = []
    for index in range(2):
        phases.append({
            'phase': index, 'construction_count': 8, 'constructed_hits': 8,
            'exhausted_searches': 0, 'submitted_attacks': 8, 'late_transcript_rejections': 8,
            'complete_denominators': True, 'attacker_and_client_cpu_known': True,
            'no_attack_accepted': True, 'cpu_measurements_known': True,
            'all_started_work_finished': True, 'full_native_state_equal': True, 'finite_target_met': True,
            'from_zero': [{'construction': {'status': 'target_hit_unverified', 'attacker_cpu_ns': 1},
                           'call': {'status': 'refused', 'client_thread_cpu_ns': 1,
                                    'response': {'value': {'error': 'WORK:Transcript'}}}} for _ in range(8)],
            'honest_reads': [{'status': 'ok', 'returned_after_deadline': False,
                              'client_thread_cpu_ns': 1} for _ in range(8)],
            'honest_submit': {'status': 'ok', 'returned_after_deadline': False, 'client_thread_cpu_ns': 1},
            'honest_build_error': None, 'honest_read_successes': 8,
            'all_preparation_thread_cpu_ns': 10, 'attacker_worker_cpu_ns': 20,
            'attacker_preparation_and_worker_cpu_ns': 30, 'honest_build_aggregate_cpu_ns': None,
            'honest_worker_cpu_measured_by_this_clock': False,
            'service': {'error': None, 'metrics': {'work_started': 9, 'work_finished': 9,
                        'work_failed': 8, 'mutation_full_work_cpu_ns': 10,
                        'mutation_cpu_charged_ns': 20, 'mutation_cpu_clock_failures': 0}},
        })
    return {'schema': 'public-v3-local-from-zero-service-v2', 'simulated_control': True,
            **{key: 'a' * 64 for key in ('network', 'parameters', 'genesis', 'target', 'policy_id')},
            **{key: True for key in ('reopen_state_equal', 'cpu_domain_retained_across_owner_reopen',
                                    'all_requested_reads_required_on_time', 'finite_target_met')},
            **{key: False for key in ('budget_depletion_demonstrated', 'public_network_ready',
                'independent_accepted', 'work_profile_qualified', 'resource_fairness_qualified',
                'physical_power_loss', 'production_activation')}, 'phases': phases}


def simulated_sustained_report():
    """Explicitly synthetic driver inputs, never native execution evidence."""
    policy = dict(schema='public-v3-local-stored-cpu-budget-v1', stored_credit_ns=2_000_000_000,
                  in_flight=0, accounting_unavailable=False, burst_ns=2_000_000_000,
                  refill_ns_per_second=250_000_000, start_reserve_ns=100_000_000, worker_limit=2)
    call = dict(status='ok', client_thread_cpu_ns=1, started_ns=10, ended_ns=20,
                elapsed_wall_ns=10, deadline_ms=2000, returned_after_deadline=False)
    phases = []
    for index in range(2):
        constructions = [dict(status='target_hit_unverified', attacker_cpu_ns=1, attempt_budget=4096,
            attempts=[dict(nonce=0, target_hit=True)], winner_nonce=0, packet='00') for _ in range(16)]
        workers = [dict(worker=i, attempt_cap=1024, attempt_cap_reached=False, calling_thread_cpu_ns=2,
            calls=[dict(call, status='refused', packet_index=i,
                        response={'value': {'error': 'WORK:Transcript'}})]) for i in range(16)]
        records = [dict(connection_id=i+1, complete=True, connection_closed=True,
                        observation_failed=False, task_created=True, task_closed=True) for i in range(19)]
        phases.append(dict(phase=index, target='7f'+'ff'*31, construction=constructions, attacks=workers,
            requested_window_ns=4_000_000_000, traffic_and_join_wall_ns=4_000_000_001,
            preparation_cpu_ns=16, attacker_preparation_plus_workers_cpu_ns=48,
            preparation_wall_ns=20, diagnostic_verification_wall_ns=30, reader_cpu_ns=1,
            honest_build_wall_ns=40, honest_build_calling_thread_cpu_ns=20,
            honest_build_aggregate_cpu_ns=None, client_confirmed_transactions=None,
            honest_reads=[call.copy()], reads_on_time=1, honest_submissions=[call.copy()],
            post_pressure_head=call.copy(), initial_meter=policy.copy(), meter_at_traffic_end=policy.copy(),
            meter_samples=[{'elapsed_ns': 1, 'meter': policy.copy()}],
            stored_credit_below_start_reserve_observed=False, negative_stored_credit_observed=False,
            attempt_caps_not_reached=True, no_attack_accepted=True, accounting_closed=True,
            full_native_state_equal=True, service_target_met=True, invariant_target_met=True,
            public_network_ready=False, resource_fairness_qualified=False, work_profile_qualified=False,
            production_activation=False, strongest_honest_producer_used=False,
            service={'error': None, 'metrics': dict(mutation_cpu_charged_ns=20, mutation_full_work_cpu_ns=10,
                mutation_dispatch_excluding_work_cpu_ns=10, mutation_cpu_clock_failures=0,
                mutation_cpu_in_flight_after_shutdown=0, mutation_cpu_unavailable_after_shutdown=False,
                work_started=17, work_finished=17, work_failed=16, mutation_cpu_refusals=0, accepted_connections=19)},
            observations=dict(records=records, accepted_connections_seen=19, capacity=16384,
                records_not_retained=0, measurement_failures=0, counter_overflow=False,
                cpu_intervals_are_nested_not_additive=True, observation_has_consensus_authority=False,
                cpu_includes_reactor_authentication_or_response_signing=False)))
    return dict(schema='public-v3-sustained-local-from-zero-v1', simulated_control=True,
        network='a'*64, parameters='b'*64, genesis='c'*64, policy_id='d'*64,
        phases=phases, reopen_state_equal=True, same_stored_cpu_meter_across_reopen=True,
        meter_before_reopen=policy.copy(), meter_after_reopen=policy.copy(),
        reopen_wall_ns=10, finite_service_target_met=True, independent_accepted=False,
        physical_power_loss=False, ordinary_hepta_entry=False, public_network_ready=False,
        resource_fairness_qualified=False, work_profile_qualified=False, production_activation=False)


class BinarySelectionTests(unittest.TestCase):
    def test_exact_artifact_selected(self):
        p = Path('/tmp/exact-build-test')
        self.assertEqual(driver.select_binary(['ordinary compiler diagnostic', artifact(p)]), p)

    def test_empty_output_cannot_select_an_old_binary(self):
        with self.assertRaisesRegex(ValueError, 'EXACT_NEW_NATIVE_TEST_BINARY_REQUIRED'):
            driver.select_binary([])

    def test_duplicate_artifacts_are_not_silently_deduplicated(self):
        row = artifact(Path('/tmp/exact-build-test'))
        with self.assertRaisesRegex(ValueError, 'EXACT_NEW_NATIVE_TEST_BINARY_REQUIRED'):
            driver.select_binary([row, row])

    def test_non_test_binary_is_not_a_test_harness(self):
        with self.assertRaisesRegex(ValueError, 'EXACT_NEW_NATIVE_TEST_BINARY_REQUIRED'):
            driver.select_binary([artifact(Path('/tmp/other'), profile={'test': False})])

    def test_numeric_truth_is_not_boolean_test_identity(self):
        with self.assertRaisesRegex(ValueError, 'EXACT_NEW_NATIVE_TEST_BINARY_REQUIRED'):
            driver.select_binary([artifact(Path('/tmp/other'), profile={'test': 1})])

    def test_wrong_target_cannot_replace_required_test(self):
        with self.assertRaisesRegex(ValueError, 'EXACT_NEW_NATIVE_TEST_BINARY_REQUIRED'):
            driver.select_binary([artifact(Path('/tmp/other'), target={'name': 'different'})])

    def test_missing_executable_rejected(self):
        with self.assertRaisesRegex(ValueError, 'EXACT_NEW_NATIVE_TEST_BINARY_REQUIRED'):
            driver.select_binary([artifact(Path('/tmp/other'), executable=None)])

    def test_duplicate_json_identity_rejected(self):
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON_KEY'):
            driver.select_binary(['{"reason":"compiler-artifact","reason":"other"}'])


    def test_symlink_binary_is_rejected_before_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target'; target.write_bytes(b'not a native binary')
            link = root / 'link'; link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'REGULAR_BINARY_REQUIRED'):
                driver.select_binary([artifact(link)])

    def test_bounded_report_reader_rejects_oversized_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_bytes(b'x' * 65)
            with patch.object(driver, 'REPORT_LIMIT', 64):
                with self.assertRaisesRegex(ValueError, 'NATIVE_SERVICE_REPORT_LIMIT'):
                    driver.validate_service_report(path)

    def test_report_reader_rejects_symlink_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target'; target.write_text('{"schema":1,"schema":2}')
            link = root / 'link'; link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'NATIVE_SERVICE_REPORT_REQUIRED'):
                driver.validate_service_report(link)
            with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON_KEY'):
                driver.validate_service_report(target)


class ExecutionBoundaryTests(unittest.TestCase):
    def exercise(self, *, fail=None, zero=None, ignored=None, timeout=None,
                 format_exit=0, build_exit=0, source_drift=False, binary_drift=False,
                 missing_report=False, report_edit=None, log_drift=False, report_drift=False,
                 missing_sustained=False, sustained_edit=None, sustained_drift=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'source'; root.mkdir()
            test_source = root / driver.SOURCE
            test_source.parent.mkdir(parents=True)
            test_source.write_text('// simulated source; not Rust execution\n')
            binary = root / 'fake-binary'; binary.write_bytes(b'not a real executable')
            identity = {'commit': 'a'*40, 'tree': 'b'*40, 'test_sha256': driver.digest(test_source.read_bytes())}
            after = copy.deepcopy(identity)
            if source_drift:
                after['tree'] = 'c'*40
            out = Path(directory) / 'observations'
            seen = []
            def child(command, folder, seconds):
                folder.mkdir()
                name = folder.name
                seen.append(name)
                initial = json.loads((out / 'manifest.json').read_text())
                self.assertFalse(initial['passed'])
                self.assertIsNone(initial['source_after'])
                code = format_exit if name == 'format-check' else build_exit if name == 'build' else 0
                text = artifact(binary) if name == 'build' else ''
                timed_out = name == timeout
                if name in driver.TESTS:
                    if name == zero:
                        text = 'running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s\n'
                    elif name == ignored:
                        text = 'running 1 test\ntest ' + name + ' ... ignored\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 2 filtered out; finished in 0.00s\n'
                    else:
                        text = 'running 1 test\ntest ' + name + ' ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.01s\n'
                    if name == fail:
                        code = 101
                    if binary_drift:
                        binary.write_bytes(b'changed binary')
                if name == driver.TESTS[-1]:
                    if not missing_report:
                        native = out / 'native'; native.mkdir()
                        report = simulated_service_report()
                        if report_edit is not None:
                            report_edit(report)
                        (native / 'report.json').write_text(json.dumps(report))
                    if not missing_sustained:
                        sustained = out / 'native/sustained'; sustained.mkdir(parents=True, exist_ok=True)
                        report = simulated_sustained_report()
                        if sustained_edit is not None:
                            sustained_edit(report)
                        (sustained / 'report.json').write_text(json.dumps(report))
                    if log_drift:
                        (out / driver.TESTS[0] / 'stdout').write_text('changed after validation')
                (folder / 'stdout').write_text(text)
                (folder / 'stderr').write_text('retained simulated stderr\n')
                # There are deliberately no invented CPU values in this fixture.
                return {'exit_code': code, 'timed_out': timed_out, 'simulated_control': True}
            previous_cwd = Path.cwd()
            identities = iter([identity, after])
            def read_identity():
                current = next(identities)
                if current is after and report_drift:
                    report_path = out / 'native/report.json'
                    report_path.write_bytes(report_path.read_bytes() + b' ')
                if current is after and sustained_drift:
                    path = out / 'native/sustained/report.json'
                    path.write_bytes(path.read_bytes() + b' ')
                return current
            try:
                with patch.object(driver, 'ROOT', root), \
                     patch.object(driver, 'source_identity', side_effect=read_identity), \
                     patch.object(driver, 'run_child', side_effect=child), \
                     patch.object(driver.subprocess, 'check_output', return_value='simulated compiler version\n'):
                    with redirect_stdout(io.StringIO()):
                        result = driver.run(out)
                retained = json.loads((out / 'manifest.json').read_text())
                self.assertEqual(retained, result)
                self.assertEqual(Path.cwd(), previous_cwd)
                if 'build' in seen:
                    self.assertTrue((out / 'build/stderr').exists())
                return result, seen
            finally:
                os.chdir(previous_cwd)

    def test_driver_success_requires_all_three_named_results(self):
        result, _ = self.exercise()
        self.assertTrue(result['passed'])
        self.assertEqual([r['name'] for r in result['runs']], list(driver.TESTS))
        self.assertTrue(all(r['process']['simulated_control'] for r in result['runs']))

    def test_build_failure_preserved_without_test_execution(self):
        result, seen = self.exercise(build_exit=101)
        self.assertFalse(result['passed'])
        self.assertFalse(result['source_recompiled'])
        self.assertFalse(result['runs'])
        self.assertNotIn(driver.TESTS[0], seen)
        self.assertIn('NATIVE_BUILD_FAILED', result['failures'])

    def test_zero_match_exit_zero_is_still_failure(self):
        result, _ = self.exercise(zero=driver.TESTS[0])
        self.assertFalse(result['passed'])
        self.assertEqual([r['passed'] for r in result['runs']], [False, True, True])

    def test_ignored_exit_zero_is_still_failure(self):
        result, _ = self.exercise(ignored=driver.TESTS[1])
        self.assertFalse(result['passed'])
        self.assertEqual([r['passed'] for r in result['runs']], [True, False, True])

    def test_nonzero_exit_cannot_be_overridden_by_success_text(self):
        result, _ = self.exercise(fail=driver.TESTS[0])
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['runs']), 3)
        self.assertFalse(result['runs'][0]['passed'])

    def test_timeout_cannot_be_overridden_by_success_text(self):
        result, _ = self.exercise(timeout=driver.TESTS[2])
        self.assertFalse(result['passed'])
        self.assertFalse(result['runs'][2]['passed'])

    def test_format_failure_retains_native_results_but_refuses_overall_pass(self):
        result, _ = self.exercise(format_exit=1)
        self.assertFalse(result['passed'])
        self.assertTrue(result['all_named_tests_passed'])
        self.assertFalse(result['format_passed'])
        self.assertIn('NATIVE_FORMAT_CHECK_FAILED', result['failures'])

    def test_source_moved_after_build_cannot_pass(self):
        result, _ = self.exercise(source_drift=True)
        self.assertFalse(result['passed'])
        self.assertNotEqual(result['source_before'], result['source_after'])

    def test_binary_mutation_refuses_source_identity_substitution(self):
        result, _ = self.exercise(binary_drift=True)
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_BINARY_CHANGED', result['failures'])

    def test_caller_environment_is_restored(self):
        name = 'TRNM_PUBLIC_V3_FROM_ZERO_DIR'
        with patch.dict(os.environ, {name: 'unchanged-parent-setting'}):
            self.exercise()
            self.assertEqual(os.environ[name], 'unchanged-parent-setting')


    def test_first_timeout_prevents_later_native_starts(self):
        result, seen = self.exercise(timeout=driver.TESTS[0])
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['runs']), 1)
        self.assertNotIn(driver.TESTS[1], seen)
        self.assertIn('NATIVE_TIMEOUT_STOPS_CAMPAIGN', result['failures'])

    def test_formatter_timeout_prevents_compile(self):
        result, seen = self.exercise(timeout='format-check')
        self.assertFalse(result['passed'])
        self.assertNotIn('build', seen)

    def test_format_copy_timeout_prevents_more_tool_processes(self):
        result, seen = self.exercise(timeout='format-copy')
        self.assertFalse(result['passed'])
        self.assertEqual(seen, ['format-copy'])

    def test_missing_service_report_cannot_pass_named_stdout(self):
        result, _ = self.exercise(missing_report=True)
        self.assertTrue(result['all_named_tests_passed'])
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_SERVICE_REPORT_REQUIRED', result['failures'])

    def test_false_service_target_cannot_pass_named_stdout(self):
        result, _ = self.exercise(report_edit=lambda doc: doc.update(finite_target_met=False))
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_SERVICE_TARGET', result['failures'])

    def test_numeric_boolean_report_refused(self):
        result, _ = self.exercise(report_edit=lambda doc: doc.update(finite_target_met=1))
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_SERVICE_TARGET', result['failures'])

    def test_scope_promotion_refused(self):
        result, _ = self.exercise(report_edit=lambda doc: doc.update(resource_fairness_qualified=True))
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_SERVICE_SCOPE_PROMOTION', result['failures'])

    def test_lost_honest_probe_refused_despite_positive_summary(self):
        result, _ = self.exercise(report_edit=lambda doc: doc['phases'][0]['honest_reads'].pop())
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_SERVICE_DENOMINATORS', result['failures'])

    def test_honest_deadline_failure_cannot_hide_behind_summary(self):
        result, _ = self.exercise(report_edit=lambda doc: doc['phases'][1]['honest_reads'][0].update(returned_after_deadline=True, elapsed_wall_ns=2_000_000_001))
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_SERVICE_HONEST_GAP', result['failures'])

    def test_unknown_cpu_cannot_become_zero(self):
        result, _ = self.exercise(report_edit=lambda doc: doc['phases'][0].update(attacker_worker_cpu_ns=None))
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_SERVICE_NUMBER', result['failures'])

    def test_nested_cpu_double_count_refused(self):
        result, _ = self.exercise(report_edit=lambda doc: doc['phases'][0].update(attacker_preparation_and_worker_cpu_ns=40))
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_SERVICE_CPU_SUM', result['failures'])

    def test_unjoined_receiver_work_refused(self):
        result, _ = self.exercise(report_edit=lambda doc: doc['phases'][0]['service']['metrics'].update(work_finished=8))
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_SERVICE_UNJOINED_WORK', result['failures'])

    def test_count_summary_must_equal_raw_calls(self):
        result, _ = self.exercise(report_edit=lambda doc: doc['phases'][0].update(submitted_attacks=7))
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_SERVICE_DENOMINATORS', result['failures'])

    def test_exhaustion_without_dispatch_is_retained(self):
        def edit(doc):
            phase = doc['phases'][0]
            phase['from_zero'][-1]['construction']['status'] = 'exhausted'
            phase['from_zero'][-1]['call'] = None
            phase.update(constructed_hits=7, exhausted_searches=1, submitted_attacks=7,
                         late_transcript_rejections=7)
        result, _ = self.exercise(report_edit=edit)
        self.assertTrue(result['passed'])

    def test_exhaustion_cannot_be_reported_with_dispatch(self):
        result, _ = self.exercise(report_edit=lambda doc: doc['phases'][0]['from_zero'][0]['construction'].update(status='exhausted'))
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_SERVICE_EXHAUSTION_DISPATCH', result['failures'])

    def test_validated_log_must_remain_unchanged(self):
        result, _ = self.exercise(log_drift=True)
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_LOG_CHANGED', result['failures'])

    def test_validated_report_must_remain_unchanged(self):
        result, _ = self.exercise(report_drift=True)
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_SERVICE_REPORT_CHANGED', result['failures'])

    def test_duplicate_phase_refused(self):
        result, _ = self.exercise(report_edit=lambda doc: doc['phases'][1].update(phase=0))
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_SERVICE_PHASES', result['failures'])

    def test_boolean_count_refused(self):
        result, _ = self.exercise(report_edit=lambda doc: doc['phases'][0].update(submitted_attacks=True))
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_SERVICE_NUMBER', result['failures'])

    def test_manifest_is_not_its_own_stale_file_digest(self):
        result, _ = self.exercise()
        self.assertNotIn('manifest.json', result['files'])
        self.assertEqual(result['files']['native/report.json'], result['service_report']['sha256'])

    def test_bad_schema_context_and_missing_reopen_stay_failures(self):
        for edit, error in [
            (lambda doc: doc.update(schema='old-unsupported'), 'NATIVE_SERVICE_REPORT_SCHEMA'),
            (lambda doc: doc.update(target='not-a-digest'), 'NATIVE_SERVICE_CONTEXT'),
            (lambda doc: doc.update(reopen_state_equal=False), 'NATIVE_SERVICE_TARGET'),
        ]:
            with self.subTest(error=error):
                result, _ = self.exercise(report_edit=edit)
                self.assertFalse(result['passed'])
                self.assertIn(error, result['failures'])


    def test_sustained_report_is_mandatory_even_with_three_native_names(self):
        result, _ = self.exercise(missing_sustained=True)
        self.assertFalse(result['passed'])
        self.assertIn('SUSTAINED_REPORT_REQUIRED', result['failures'])

    def test_sustained_finite_non_depletion_remains_a_valid_observation(self):
        result, _ = self.exercise()
        self.assertTrue(result['passed'])
        self.assertEqual([p['attacks'] for p in result['sustained_report']['phases']], [16, 16])
        self.assertEqual([p['mutation_cpu_refusals'] for p in result['sustained_report']['phases']], [0, 0])
        self.assertEqual(result['files']['native/sustained/report.json'], result['sustained_report']['sha256'])

    def test_sustained_report_change_after_validation_refused(self):
        result, _ = self.exercise(sustained_drift=True)
        self.assertFalse(result['passed'])
        self.assertIn('SUSTAINED_REPORT_CHANGED', result['failures'])

    def sustained_refusal(self, edit, code):
        result, _ = self.exercise(sustained_edit=edit)
        self.assertFalse(result['passed'])
        self.assertIn(code, result['failures'])

    def test_sustained_missing_or_duplicate_phase_refused(self):
        self.sustained_refusal(lambda d: d['phases'].pop(), 'SUSTAINED_PHASES')
        self.sustained_refusal(lambda d: d['phases'][1].update(phase=0), 'SUSTAINED_PHASES')

    def test_sustained_shortened_window_refused(self):
        self.sustained_refusal(lambda d: d['phases'][0].update(requested_window_ns=1), 'SUSTAINED_WINDOW')
        self.sustained_refusal(lambda d: d['phases'][0].update(traffic_and_join_wall_ns=1), 'SUSTAINED_WINDOW')

    def test_sustained_missing_worker_and_attempt_cap_refused(self):
        self.sustained_refusal(lambda d: d['phases'][0]['attacks'].pop(), 'SUSTAINED_WORKERS')
        self.sustained_refusal(lambda d: d['phases'][0]['attacks'][0].update(attempt_cap_reached=True), 'SUSTAINED_CAP')

    def test_sustained_accepted_attack_and_early_only_refusals_rejected(self):
        self.sustained_refusal(lambda d: d['phases'][0]['attacks'][0]['calls'][0].update(status='ok'), 'SUSTAINED_ATTACK_ACCEPTED')
        def early(d):
            for w in d['phases'][0]['attacks']:
                w['calls'][0]['response']['value']['error'] = 'PUBLIC_MUTATION_CPU_BUDGET'
        self.sustained_refusal(early, 'SUSTAINED_NO_LATE_REJECTION')

    def test_sustained_omitted_search_miss_and_false_winner_refused(self):
        self.sustained_refusal(lambda d: d['phases'][0]['construction'][0]['attempts'][0].update(nonce=1), 'SUSTAINED_SEARCH')
        self.sustained_refusal(lambda d: d['phases'][0]['construction'][0].update(winner_nonce=1), 'SUSTAINED_SEARCH')

    def test_sustained_exhaustion_cannot_dispatch(self):
        def edit(d):
            d['phases'][0]['construction'][0].update(status='exhausted', winner_nonce=None, packet=None,
                attempts=[dict(nonce=i, target_hit=False) for i in range(4096)])
        self.sustained_refusal(edit, 'SUSTAINED_EXHAUSTED_DISPATCH')

    def test_sustained_honest_deadline_and_missing_reads_refused(self):
        self.sustained_refusal(lambda d: d['phases'][0]['honest_reads'][0].update(returned_after_deadline=True, elapsed_wall_ns=2_000_000_001), 'SUSTAINED_HONEST_GAP')
        self.sustained_refusal(lambda d: d['phases'][0].update(honest_reads=[]), 'SUSTAINED_HONEST_COUNT')

    def test_sustained_double_ack_is_not_two_honest_blocks(self):
        self.sustained_refusal(lambda d: d['phases'][0]['honest_submissions'].append(d['phases'][0]['honest_submissions'][0].copy()), 'SUSTAINED_HONEST_GAP')

    def test_sustained_unknown_and_double_counted_cpu_refused(self):
        self.sustained_refusal(lambda d: d['phases'][0]['attacks'][0].update(calling_thread_cpu_ns=None), 'SUSTAINED_NUMBER')
        self.sustained_refusal(lambda d: d['phases'][0].update(attacker_preparation_plus_workers_cpu_ns=25), 'SUSTAINED_CPU_SUM')
        self.sustained_refusal(lambda d: d['phases'][0]['service']['metrics'].update(mutation_cpu_charged_ns=30), 'SUSTAINED_CPU_SUM')

    def test_sustained_unjoined_work_and_unknown_settlement_refused(self):
        self.sustained_refusal(lambda d: d['phases'][0]['service']['metrics'].update(work_finished=4), 'SUSTAINED_UNJOINED_WORK')
        self.sustained_refusal(lambda d: d['phases'][0]['service']['metrics'].update(mutation_cpu_unavailable_after_shutdown=True), 'SUSTAINED_CPU_SUM')

    def test_sustained_missing_duplicate_or_incomplete_observer_refused(self):
        self.sustained_refusal(lambda d: d['phases'][0]['observations']['records'].pop(), 'SUSTAINED_CAPTURE')
        self.sustained_refusal(lambda d: d['phases'][0]['observations']['records'][1].update(connection_id=1), 'SUSTAINED_CAPTURE')
        self.sustained_refusal(lambda d: d['phases'][0]['observations']['records'][0].update(complete=False), 'SUSTAINED_TARGET')

    def test_sustained_scope_promotion_and_boolean_number_refused(self):
        self.sustained_refusal(lambda d: d.update(ordinary_hepta_entry=True), 'SUSTAINED_SCOPE')
        self.sustained_refusal(lambda d: d['phases'][0].update(client_confirmed_transactions=0), 'SUSTAINED_SCOPE')
        self.sustained_refusal(lambda d: d['phases'][0]['attacks'][0].update(calling_thread_cpu_ns=True), 'SUSTAINED_NUMBER')

    def test_sustained_fabricated_depletion_and_changed_budget_refused(self):
        self.sustained_refusal(lambda d: d['phases'][0].update(negative_stored_credit_observed=True), 'SUSTAINED_DEPLETION_CLAIM')
        self.sustained_refusal(lambda d: d['phases'][0]['meter_samples'][0]['meter'].update(start_reserve_ns=1), 'SUSTAINED_POLICY_CHANGED')

    def test_sustained_reopen_must_preserve_actual_meter_not_only_boolean(self):
        self.sustained_refusal(lambda d: d['meter_before_reopen'].update(stored_credit_ns=10), 'SUSTAINED_REOPEN')
        self.sustained_refusal(lambda d: d['phases'][1]['initial_meter'].update(in_flight=1), 'SUSTAINED_REOPEN')

    def test_sustained_report_reader_rejects_oversize_symlink_and_bad_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'; path.write_bytes(b'x' * 65)
            with patch.object(driver, 'REPORT_LIMIT', 64), self.assertRaisesRegex(ValueError, 'SUSTAINED_REPORT_LIMIT'):
                driver.validate_sustained_report(path)
            link = Path(directory) / 'link'; link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, 'SUSTAINED_REPORT_REQUIRED'):
                driver.validate_sustained_report(link)
            path.write_text('{"schema":1,"schema":2}')
            with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON_KEY'):
                driver.validate_sustained_report(path)



    def test_sustained_valid_exhaustion_is_retained_without_fabricated_connection(self):
        def edit(d):
            d['phases'][0]['construction'][15].update(status='exhausted', winner_nonce=None, packet=None,
                attempts=[dict(nonce=i, target_hit=False) for i in range(4096)])
            d['phases'][0]['attacks'][15]['calls'][0] = {'status': 'not_submitted_exhausted', 'packet_index': 15}
            d['phases'][0]['observations']['records'].pop()
            d['phases'][0]['observations']['accepted_connections_seen'] = 18
            d['phases'][0]['service']['metrics']['accepted_connections'] = 18
        result, _ = self.exercise(sustained_edit=edit)
        self.assertTrue(result['passed'])
        self.assertEqual(result['sustained_report']['phases'][0]['attacks'], 15)
        self.assertEqual(result['sustained_report']['phases'][0]['connections'], 18)

    def test_sustained_valid_packet_cannot_be_relabelled_as_exhausted(self):
        self.sustained_refusal(lambda d: d['phases'][0]['attacks'][0]['calls'].append(
            {'status': 'not_submitted_exhausted', 'packet_index': 0}), 'SUSTAINED_EXHAUSTED_DISPATCH')

    def test_sustained_deadline_boolean_must_match_actual_elapsed_interval(self):
        self.sustained_refusal(lambda d: d['phases'][0]['honest_reads'][0].update(
            elapsed_wall_ns=2_000_000_001), 'SUSTAINED_CALL_TIME')
        self.sustained_refusal(lambda d: d['phases'][0]['honest_reads'][0].update(
            deadline_ms=3000), 'SUSTAINED_CALL_TIME')
        self.sustained_refusal(lambda d: d['phases'][0]['honest_reads'][0].update(
            elapsed_wall_ns=0), 'SUSTAINED_CALL_TIME')


if __name__ == '__main__':
    unittest.main(verbosity=2)
