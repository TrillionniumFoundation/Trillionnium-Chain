#!/usr/bin/env python3
"""Synthetic refusal controls; never native service evidence or Host provisioning."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import run_from_zero_host as host
import run_w1_fresh_service_v1 as fresh
from contract_wire import header_encode
from test_run_from_zero_native import simulated_confirmation_report


def synthetic_fresh_report():
    doc = simulated_confirmation_report()
    a = b''.join(struct.pack('<I', i % 31) for i in range(4096))
    b = b''.join(struct.pack('<I', (i * 7) % 37) for i in range(4096))
    task = fresh.native.H('task', a, b)
    proof = b'PNW1' + a + b + bytes(16384 + 32)
    replacements = {doc['task']: task.hex()}
    parent = bytes.fromhex(doc['genesis'])
    for encoded in doc['signed_honest_packets']:
        old = bytes.fromhex(encoded)
        header = fresh.native.header_decode(old[:318])
        old_id = fresh.native.H('block', old[:318], old[-32:])
        header.update(parent=parent, work_task=task)
        raw_header = header_encode(header)
        packet = raw_header + old[318:-49188] + proof
        parent = fresh.native.H('block', raw_header, proof[-32:])
        replacements[old_id.hex()] = parent.hex()
        replacements[encoded] = packet.hex()

    def replace(value):
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        if isinstance(value, list):
            return [replace(item) for item in value]
        return replacements.get(value, value) if isinstance(value, str) else value

    doc = replace(doc)
    # Replacing packet bytes also changes the already compacted request digest.
    for phase in doc['phases']:
        for row in phase['honest_submissions']:
            request = json.dumps({'op': 'submit', 'packet': doc['signed_honest_packets'][row['packet_index']]},
                                 sort_keys=True, separators=(',', ':')).encode()
            row.update(recorded_request_bytes=len(request),
                       recorded_request_digest=fresh.native.H('pressure-recorded-request-v1', request).hex())
    doc.update(schema=fresh.FRESH_SCHEMA, requested_window_ns=4_000_000_000,
               attack_workers=16, per_worker_attempt_cap=1024,
               same_signed_business_packets=True, negative_cache_enabled=False,
               resource_fairness_qualified=False, shared_material_setup_cpu_ns=1,
               attacker_setup_and_workers_cpu_ns=321)
    del doc['from_zero_construction']
    count = 0
    for worker in doc['phases'][1]['attacks']:
        worker['calling_thread_cpu_ns'] = 20
        for attempt, row in enumerate(worker['calls']):
            index = attempt * 16 + worker['worker']
            header = fresh.native.header_decode(bytes.fromhex(doc['signed_honest_packets'][0])[:318])
            header.update(nonce=200_000 + index, state=bytes(32), receipts=bytes(32))
            encoded = header_encode(header)
            challenge = fresh.native.H('challenge', encoded)
            trials = []
            for ordinal in range(4096):
                trace = fresh.native.H('public-v3-from-zero-v1', challenge, struct.pack('<Q', ordinal))
                ticket = fresh.native.H('ticket', challenge, trace)
                hit = ticket <= bytes.fromhex(doc['target'])
                trials.append(dict(nonce=ordinal, trace=trace.hex(), ticket=ticket.hex(), target_hit=hit))
                if hit:
                    break
            assert trials[-1]['target_hit']
            packet = encoded + bytes(2) + proof[:-32] + trace
            request = json.dumps({'op': 'submit', 'packet': packet.hex()},
                                 sort_keys=True, separators=(',', ':')).encode()
            row.update(packet_index=index, recorded_request_bytes=len(request),
                       response={'value': {'error': 'WORK:Transcript'}},
                       recorded_request_digest=fresh.native.H('pressure-recorded-request-v1', request).hex(),
                       from_zero_construction=dict(header=encoded.hex(), challenge=challenge.hex(),
                           attempt_budget=4096, setup_calls=1, attempts=trials,
                           winner_nonce=len(trials) - 1, status='target_hit_unverified',
                           packet_digest=fresh.native.H('fresh-challenge-attack-packet-v1', packet).hex(),
                           attacker_cpu_ns=3, setup_cpu_ns=1, search_cpu_ns=1, packet_encoding_cpu_ns=1))
            count += 1
    doc['phases'][1]['attacker_workers_cpu_ns'] = 320
    doc['construction_coverage'] = dict(constructed=count, unique_challenges=count,
        unique_packet_indices=count, submitted=count, exhausted=0,
        full_transcript_rejections=count,
        all_context_bindings_and_challenges_unique=True, all_nested_cpu_measurements_known=True,
        nested_from_zero_construction_cpu_ns=count * 3)
    return doc


def synthetic_enabled_fresh_report():
    """Same synthetic business, with actual-mode-shaped cache path records."""
    doc = synthetic_fresh_report()
    doc.update(negative_cache_enabled=True,
               negative_cache_observation_source='actual-request-work-rejection-observations-v1')
    for phase in doc['phases']:
        attempts = 7 + sum(len(worker['calls']) for worker in phase['attacks'])
        for index, row in enumerate(phase['observations']['records']):
            row.update(full_work_started=index < attempts,
                       full_work_accepted=(index < 7 if index < attempts else None))
            if index >= attempts:
                continue
            row.update(
                work_rejection=dict(schema='public-v3-work-rejection-observation-v1',
                    slots=256, retained_software_bytes=24576, lifetime_ms=30000,
                    lifetime_seconds=30, lifetime_subsec_nanos=0, completed=True,
                    cache=dict(key_hashed=True, lookup_contended=False, lookup_poisoned=False,
                        exact_fact_found=False, cached_rejection_returned=False,
                        native_verifier_started=True, native_verifier_returned=True,
                        full_replay_started=True,
                        publication='none' if index < 7 else 'retained')))
    return doc


def process():
    return dict(executed=True, exit_code=0, process_exit_code=0, timed_out=False,
                source_verified=True, expected_source='a' * 40)


def passing_log(selector):
    return (f'running 1 test\ntest {selector} ... ok\n'
            'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n')


class FreshRefusalControls(unittest.TestCase):
    def validate_doc(self, doc):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text(json.dumps(doc))
            return fresh.validate_fresh_report(path)

    def test_historical_disabled_and_current_observed_mode_keep_distinct_scope(self):
        old = self.validate_doc(synthetic_fresh_report())
        self.assertNotIn('negative_cache_observation', old)
        current = self.validate_doc(synthetic_enabled_fresh_report())['negative_cache_observation']
        self.assertIs(current['enabled'], True)
        self.assertEqual([row['full_replay_started'] for row in current['phases']], [7, 24])
        self.assertEqual([row['cached_rejection_returned'] for row in current['phases']], [0, 0])

    def test_enabled_mode_requires_both_phases_and_every_started_attempt_observation(self):
        original = synthetic_enabled_fresh_report()
        changes = [
            lambda d: d.update(negative_cache_enabled=False),
            lambda d: d.update(negative_cache_enabled=None),
            lambda d: d.update(negative_cache_enabled=1),
            lambda d: d.pop('negative_cache_observation_source'),
            lambda d: d['phases'][0]['observations']['records'][0].pop('work_rejection'),
            lambda d: d['phases'][1]['observations']['records'][0].pop('work_rejection'),
            lambda d: d['phases'][1]['observations']['records'][0].update(full_work_started=False),
            lambda d: d['phases'][1]['observations']['records'][0].pop('full_work_started'),
        ]
        for index, change in enumerate(changes):
            doc = copy.deepcopy(original)
            change(doc)
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, 'FRESH_CACHE_'):
                self.validate_doc(doc)
        doc = copy.deepcopy(original)
        for row in doc['phases'][1]['observations']['records']:
            row.update(full_work_started=False)
            row.pop('work_rejection', None)
        with self.assertRaisesRegex(ValueError, 'FRESH_CACHE_NO_OBSERVED_ATTEMPTS'):
            self.validate_doc(doc)

    def test_cache_configuration_retains_exact_positive_submillisecond_lifetime(self):
        doc = synthetic_enabled_fresh_report()
        for phase in doc['phases']:
            for row in phase['observations']['records']:
                if row['full_work_started']:
                    row['work_rejection'].update(
                        lifetime_seconds=0, lifetime_subsec_nanos=1, lifetime_ms=0)
        observed = self.validate_doc(doc)['negative_cache_observation']['configuration']
        self.assertEqual((observed['lifetime_ms'], observed['lifetime_seconds'],
                          observed['lifetime_subsec_nanos']), (0, 0, 1))
        invalid = [dict(slots=0), dict(slots=257), dict(slots=True),
                   dict(retained_software_bytes=32769), dict(retained_software_bytes=0),
                   dict(lifetime_ms=1), dict(lifetime_seconds=-1), dict(lifetime_seconds=31),
                   dict(lifetime_subsec_nanos=-1), dict(lifetime_subsec_nanos=1_000_000_000),
                   dict(lifetime_seconds=0, lifetime_subsec_nanos=0, lifetime_ms=0),
                   dict(lifetime_seconds=30, lifetime_subsec_nanos=1, lifetime_ms=30000)]
        for mutation in invalid:
            bad = copy.deepcopy(doc)
            bad['phases'][0]['observations']['records'][0]['work_rejection'].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'FRESH_CACHE_CONFIGURATION'):
                self.validate_doc(bad)
        bad = copy.deepcopy(doc)
        bad['phases'][1]['observations']['records'][0]['work_rejection'].update(slots=128)
        with self.assertRaisesRegex(ValueError, 'FRESH_CACHE_CONFIGURATION_CHANGED'):
            self.validate_doc(bad)

    def test_fresh_cache_hit_and_cancelled_found_fact_cannot_claim_fresh_replay(self):
        for returned in (False, True):
            doc = synthetic_enabled_fresh_report()
            row = doc['phases'][1]['observations']['records'][0]
            row['full_work_accepted'] = False
            row['work_rejection']['cache'].update(exact_fact_found=True,
                cached_rejection_returned=returned, native_verifier_started=False,
                native_verifier_returned=False, full_replay_started=False)
            with self.subTest(returned=returned), self.assertRaisesRegex(ValueError, 'FRESH_CACHE_REUSED_FACT'):
                self.validate_doc(doc)
        doc = synthetic_enabled_fresh_report()
        doc['phases'][1]['observations']['records'][0]['work_rejection']['cache'].update(
            exact_fact_found=True, cached_rejection_returned=True)
        with self.assertRaisesRegex(ValueError, 'FRESH_CACHE_PATH_CONTRADICTION'):
            self.validate_doc(doc)

    def test_incomplete_and_cheap_error_path_is_not_counted_as_complete_native_replay(self):
        doc = synthetic_enabled_fresh_report()
        first = doc['phases'][0]['observations']['records'][0]
        first['full_work_accepted'] = None
        first['work_rejection'].update(completed=False, cache=None)
        second = doc['phases'][1]['observations']['records'][0]
        second['full_work_accepted'] = False
        second['work_rejection']['cache'].update(key_hashed=False, full_replay_started=False)
        phases = self.validate_doc(doc)['negative_cache_observation']['phases']
        self.assertEqual(phases[0]['incomplete_cache_observations'], 1)
        self.assertEqual(phases[0]['completed_cache_observations'], 6)
        self.assertEqual(phases[1]['native_verifier_started'], 24)
        self.assertEqual(phases[1]['full_replay_started'], 23)

    def test_cache_fact_types_completion_publication_and_acceptance_cannot_conflict(self):
        invalid = [dict(key_hashed=False), dict(lookup_contended=True, lookup_poisoned=True),
                   dict(cached_rejection_returned=True), dict(native_verifier_started=False),
                   dict(native_verifier_returned=False), dict(publication='unknown'),
                   dict(publication='retained'), dict(full_replay_started=1)]
        for mutation in invalid:
            doc = synthetic_enabled_fresh_report()
            doc['phases'][0]['observations']['records'][0]['work_rejection']['cache'].update(mutation)
            # key_hashed=false is valid before a cheap error, but contradicts a retained fact.
            if mutation == dict(key_hashed=False):
                doc['phases'][0]['observations']['records'][0]['work_rejection']['cache'].update(
                    publication='retained')
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'FRESH_CACHE_'):
                self.validate_doc(doc)
        for mutation in (dict(completed=True, cache=None), dict(completed=1), dict(completed=False)):
            doc = synthetic_enabled_fresh_report()
            doc['phases'][0]['observations']['records'][0]['work_rejection'].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'FRESH_CACHE_'):
                self.validate_doc(doc)

    def test_completed_full_replay_requires_a_hashed_statement(self):
        doc = synthetic_enabled_fresh_report()
        # An accepted native replay cannot precede the complete canonical key.
        # Keep publication=none so the publication check cannot mask this gap.
        doc['phases'][0]['observations']['records'][0]['work_rejection']['cache'].update(
            key_hashed=False)
        with self.assertRaisesRegex(ValueError, 'FRESH_CACHE_PATH_CONTRADICTION'):
            self.validate_doc(doc)

    def test_completed_keyed_miss_enters_native_but_unkeyed_cheap_errors_remain_valid(self):
        for lookup in ('miss', 'contended', 'poisoned'):
            doc = synthetic_enabled_fresh_report()
            row = doc['phases'][1]['observations']['records'][0]
            row['full_work_accepted'] = False
            row['work_rejection']['cache'].update(
                native_verifier_started=False, native_verifier_returned=False,
                full_replay_started=False, publication='none',
                lookup_contended=lookup == 'contended', lookup_poisoned=lookup == 'poisoned')
            with self.subTest(lookup=lookup), self.assertRaisesRegex(
                    ValueError, 'FRESH_CACHE_PATH_CONTRADICTION'):
                self.validate_doc(doc)
        for entered in (False, True):
            doc = synthetic_enabled_fresh_report()
            row = doc['phases'][1]['observations']['records'][0]
            row['full_work_accepted'] = False
            row['work_rejection']['cache'].update(
                key_hashed=False, native_verifier_started=entered,
                native_verifier_returned=entered, full_replay_started=False, publication='none')
            observed = self.validate_doc(doc)['negative_cache_observation']['phases'][1]
            self.assertEqual(observed['native_verifier_started'], 23 + int(entered))
            self.assertEqual(observed['full_replay_started'], 23)

    def test_enabled_cache_does_not_replace_original_business_and_pressure_predicates(self):
        changes = [lambda d: d.update(finite_target_met=False),
                   lambda d: d.update(requested_window_ns=4_000_000_001),
                   lambda d: d.update(attack_workers=15),
                   lambda d: d['phases'][1].update(overlap_demonstrated=False),
                   lambda d: d['phases'][1].update(confirmation_ended_ns=4_000_000_000),
                   lambda d: d['phases'][1].update(full_native_state_equal=False),
                   lambda d: d['phases'][1].pop('honest_history')]
        for index, change in enumerate(changes):
            doc = synthetic_enabled_fresh_report()
            change(doc)
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.validate_doc(doc)

    def test_missing_business_history_or_observer_cannot_hide_behind_positive_summary(self):
        original = synthetic_fresh_report()
        for name in ('honest_submissions', 'honest_history', 'observations'):
            bad = copy.deepcopy(original)
            for phase in bad['phases']:
                del phase[name]
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validate_doc(bad)

    def test_attack_outside_window_with_self_consistent_call_clocks_cannot_claim_overlap(self):
        bad = synthetic_fresh_report()
        phase = bad['phases'][1]
        phase.update(completed_false_calls_before_business=0,
                     completed_false_calls_at_confirmation=0, overlapping_false_calls=0)
        for worker in phase['attacks']:
            for attempt, row in enumerate(worker['calls']):
                row.update(started_ns=5_000_000_000 + attempt * 1_000_000_000,
                           ended_ns=6_000_000_000 + attempt * 1_000_000_000,
                           elapsed_wall_ns=1_000_000_000, returned_after_window=True)
        with self.assertRaisesRegex(ValueError, 'CONFIRMATION_NO_OVERLAP'):
            self.validate_doc(bad)

    def test_disjoint_phase_and_per_worker_cpu_cannot_be_hidden_by_global_totals(self):
        original = synthetic_fresh_report()
        too_large = copy.deepcopy(original)
        for worker in too_large['phases'][1]['attacks']:
            for row in worker['calls']:
                row['from_zero_construction']['setup_cpu_ns'] = 1_000_000_000
        with self.assertRaisesRegex(ValueError, 'CONSTRUCTION_CPU_CONTAINMENT'):
            self.validate_doc(too_large)
        wrong_owner = copy.deepcopy(original)
        workers = wrong_owner['phases'][1]['attacks']
        workers[0]['calling_thread_cpu_ns'] = 5  # Two constructions cost 6.
        workers[1]['calling_thread_cpu_ns'] = 35  # Aggregate remains 320.
        with self.assertRaisesRegex(ValueError, 'WORKER_CPU_CONTAINMENT'):
            self.validate_doc(wrong_owner)
        # Exact containment is a legitimate boundary, not missing overhead.
        boundary = copy.deepcopy(original)
        workers = boundary['phases'][1]['attacks']
        workers[0]['calling_thread_cpu_ns'] = 8  # Two constructions and two calls.
        workers[1]['calling_thread_cpu_ns'] = 32
        self.assertEqual(self.validate_doc(boundary)['unique_challenges'], 17)
        hidden_call = copy.deepcopy(original)
        hidden_call['phases'][1]['attacks'][0]['calls'][0]['client_thread_cpu_ns'] = 1_000_000_000
        with self.assertRaisesRegex(ValueError, 'WORKER_CPU_CONTAINMENT'):
            self.validate_doc(hidden_call)

    def test_hosted_expected_source_is_required_canonical_and_equal(self):
        for expected in (None, '', 'A' * 40, 'a' * 39, 'b' * 40):
            env = {'GITHUB_ACTIONS': 'true'}
            if expected is not None:
                env['TRNM_EXPECTED_SOURCE_SHA'] = expected
            with self.subTest(expected=expected), patch.dict(os.environ, env, clear=True):
                with self.assertRaises(ValueError):
                    fresh.expected_source('a' * 40)
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true',
                                    'TRNM_EXPECTED_SOURCE_SHA': 'a' * 40}, clear=True):
            self.assertEqual(fresh.expected_source('a' * 40), 'a' * 40)

    def test_consistent_wrong_head_cannot_build_under_workflow_expectation(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {'GITHUB_ACTIONS': 'true',
                                        'TRNM_EXPECTED_SOURCE_SHA': 'a' * 40}), \
                patch.object(fresh.native, 'source_identity', return_value={'commit': 'b' * 40}), \
                patch.object(fresh.ci, 'run') as observed:
            result = fresh.run(Path(directory) / 'wrong-head')
            self.assertFalse(result['passed'])
            self.assertEqual(result['source_before'], result['source_after'])
            observed.assert_not_called()
            self.assertIn('FRESH_EXPECTED_SOURCE_MISMATCH', result['failures'])

    def test_changed_workflow_expectation_cannot_pass_after_two_consistent_executions(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            binary = base / 'synthetic-never-executed-native'
            binary.write_bytes(b'synthetic-only; mocked process owner')

            def observed(command, log, **kwargs):
                self.assertEqual(kwargs['expected_source'], 'a' * 40)
                if command[0] != str(binary):
                    log.write_text('synthetic build control\n')
                    return process()
                name = command[1]
                log.write_text(passing_log(name))
                folder = Path(kwargs['env']['TRNM_PUBLIC_V3_CONFIRMATION_DIR' if name == fresh.ORIGINAL
                                           else 'TRNM_PUBLIC_V3_FRESH_CONFIRMATION_DIR'])
                folder.mkdir()
                fixture = simulated_confirmation_report() if name == fresh.ORIGINAL else synthetic_fresh_report()
                (folder / 'report.json').write_text(json.dumps(fixture))
                if name == fresh.FRESH:
                    os.environ['TRNM_EXPECTED_SOURCE_SHA'] = 'b' * 40
                return process()

            with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'TRNM_EXPECTED_SOURCE_SHA': 'a' * 40}), \
                    patch.object(fresh.native, 'source_identity', return_value={'commit': 'a' * 40}), \
                    patch.object(fresh.native, 'select_binary', return_value=binary), \
                    patch.object(fresh.ci, 'run', side_effect=observed):
                result = fresh.run(base / 'changed-expectation')
            self.assertTrue(result['all_named_tests_passed'])
            self.assertFalse(result['passed'])
            self.assertIn('FRESH_EXPECTED_SOURCE_MISMATCH', result['failures'])

    def test_business_history_observer_and_attempt_cap_keep_original_phase_rules(self):
        changes = [
            lambda x: x['phases'][1]['honest_submissions'][0].update(recorded_request_digest='00' * 32),
            lambda x: x['phases'][1]['honest_history'][0]['response']['value'].update(next='00' * 32),
            lambda x: x['phases'][1]['observations'].update(records_not_retained=1),
            lambda x: x['phases'][1]['observations']['records'][0].update(complete=False),
            lambda x: x['phases'][1]['service']['metrics'].update(work_failed=25),
            lambda x: x['phases'][1]['attacks'][0].update(attempt_cap_reached=True),
        ]
        for index, change in enumerate(changes):
            bad = synthetic_fresh_report()
            change(bad)
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.validate_doc(bad)

    def test_original_nonzero_is_retained_and_fresh_still_executes_without_aggregate_success(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            binary = base / 'synthetic-never-executed-native'
            binary.write_bytes(b'synthetic-only; mocked process owner')
            out = base / 'observations'
            calls = []

            def observed(command, log, **kwargs):
                calls.append(command)
                self.assertEqual(kwargs['expected_source'], 'a' * 40)
                result = process()
                if command[0] == str(binary):
                    name = command[1]
                    log.write_text(passing_log(name))
                    env = kwargs['env']
                    folder = Path(env['TRNM_PUBLIC_V3_CONFIRMATION_DIR' if name == fresh.ORIGINAL
                                      else 'TRNM_PUBLIC_V3_FRESH_CONFIRMATION_DIR'])
                    folder.mkdir()
                    if name == fresh.ORIGINAL:
                        result.update(exit_code=1, process_exit_code=1)
                        (folder / 'report.json').write_text('{"simulated_failure":true}')
                    else:
                        (folder / 'report.json').write_text(json.dumps(synthetic_fresh_report()))
                else:
                    log.write_text('synthetic build control; never compiled\n')
                return result

            with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'TRNM_EXPECTED_SOURCE_SHA': 'a' * 40}), \
                    patch.object(fresh.native, 'source_identity', return_value={'commit': 'a' * 40}), \
                    patch.object(fresh.native, 'select_binary', return_value=binary), \
                    patch.object(fresh.ci, 'run', side_effect=observed):
                result = fresh.run(out)
            self.assertEqual([row['name'] for row in result['runs']], list(fresh.SELECTORS))
            self.assertEqual([row['passed'] for row in result['runs']], [False, True])
            self.assertFalse(result['passed'])
            self.assertFalse(result['all_named_tests_passed'])
            self.assertTrue(result['execution_finished'])
            self.assertEqual(len(calls), 3)
            self.assertIn('original/report.json', result['files'])
            self.assertIn('fresh/report.json', result['files'])
            self.assertIn('--ignored', calls[2])

    def test_fresh_consistency_control_and_budget_context_cpu_mutations(self):
        original = synthetic_fresh_report()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text(json.dumps(original))
            self.assertEqual(fresh.validate_fresh_report(path)['unique_challenges'], 17)
            changes = [
                lambda x: x.update(requested_window_ns=5_000_000_000),
                lambda x: x.update(attack_workers=15),
                lambda x: x.update(negative_cache_enabled=True),
                lambda x: x.update(finite_target_met=False),
                lambda x: x.update(attacker_setup_and_workers_cpu_ns=322),
                lambda x: x['phases'][1].update(confirmation_ended_ns=4_000_000_000),
                lambda x: x['phases'][1]['independent_client_confirmation'].update(observed_tip='ff' * 32),
                lambda x: x['phases'][1]['attacks'][0]['calls'][1].update(packet_index=0),
                lambda x: x['phases'][1]['attacks'][0]['calls'][0].update(status='ok'),
                lambda x: x['phases'][1]['attacks'][0]['calls'][0]['from_zero_construction'].update(search_cpu_ns=None),
                lambda x: x['phases'][1]['attacks'][0]['calls'][0]['from_zero_construction']['attempts'][0].update(trace='00' * 32),
                lambda x: x.update(schema='public-v3-signed-confirmation-pressure-v1'),
                lambda x: [row.update(response={'value': {'error': 'PUBLIC_MUTATION_CPU_BUDGET'}})
                           for worker in x['phases'][1]['attacks'] for row in worker['calls']],
            ]
            for index, change in enumerate(changes):
                bad = copy.deepcopy(original)
                change(bad)
                path.write_text(json.dumps(bad))
                with self.subTest(index=index), self.assertRaises(ValueError):
                    fresh.validate_fresh_report(path)

    def test_unexecuted_nonzero_timeout_unknown_source_zero_test_and_missing_report_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log, report = root / 'test.log', root / 'missing.json'
            log.write_text(passing_log(fresh.FRESH))
            for change in (dict(executed=False), dict(exit_code=1), dict(process_exit_code=1),
                           dict(timed_out=True), dict(source_verified=False)):
                bad = process()
                bad.update(change)
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'PROCESS_REQUIRED'):
                    fresh.validate_execution(bad, log, fresh.FRESH, report)
            log.write_text('running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n')
            with self.assertRaises(ValueError):
                fresh.validate_execution(process(), log, fresh.FRESH, report)
            log.write_text(passing_log(fresh.FRESH))
            with self.assertRaisesRegex(ValueError, 'REPORT_REQUIRED'):
                fresh.validate_execution(process(), log, fresh.FRESH, report)
            with self.assertRaisesRegex(ValueError, 'EXACT_SELECTOR'):
                fresh.validate_execution(process(), log, 'unreviewed_test', report)

    def test_host_allows_only_two_exact_runners_and_external_output(self):
        valid = ['python3', 'scripts/ci/run_w1_fresh_service_v1.py', '--out', '/tmp/fresh-output']
        self.assertEqual(host.validate_command(valid), Path(valid[-1]))
        for bad in (valid + ['--skip'], [*valid[:1], 'scripts/ci/unknown.py', *valid[2:]],
                    [*valid[:3], str(host.ROOT / 'output')], [*valid[:3], 'relative'],
                    [*valid[:2], '--other', valid[-1]]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                host.validate_command(bad)

    def test_successor_binding_keeps_schema_selectors_source_binary_and_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            binary = out / fresh.native.TARGET
            binary.write_bytes(b'synthetic-non-executable-binding-control')
            identity = {'commit': 'a' * 40}
            digest = fresh.native.digest(binary.read_bytes())
            prepared = dict(completed=True, source_before=identity, source_after=identity,
                            binary_sha256=digest)
            verified = dict(named_execution={'test': 'synthetic'}, report={'sha256': 'synthetic'})
            rows = []
            for index, name in enumerate(fresh.SELECTORS):
                folder = 'original' if index == 0 else 'fresh'
                log = out / (folder + '.log')
                log.write_text(passing_log(name))
                rows.append(dict(name=name, process=process(), passed=True,
                    log_sha256=fresh.native.digest(log.read_bytes()),
                    report_path=folder + '/report.json', **verified))
            original = dict(schema=fresh.SCHEMA, source_before=identity, source_after=identity,
                source_expected='a' * 40,
                binary_sha256_before=digest, binary_sha256_after=digest,
                requested_window_ns=4_000_000_000, attack_workers=16, passed=True,
                all_named_tests_passed=True, execution_finished=True, source_recompiled=True,
                failures=[], runs=rows)
            path = out / 'manifest.json'
            with patch.object(fresh, 'validate_execution', return_value=verified), \
                    patch.dict(os.environ, {'TRNM_EXPECTED_SOURCE_SHA': 'a' * 40}):
                path.write_text(json.dumps(original))
                self.assertEqual(host.bind_prepared_fresh_execution(prepared, out)['exact_selectors'], list(fresh.SELECTORS))
                changes = [lambda x: x.update(schema='trnm-from-zero-native-execution-v3'),
                    lambda x: x.update(attack_workers=15),
                    lambda x: x.update(requested_window_ns=4_000_000_001),
                    lambda x: x.update(source_after={'commit': 'b' * 40}),
                    lambda x: x.update(binary_sha256_after='f' * 64),
                    lambda x: x.update(source_expected='b' * 40),
                    lambda x: x['runs'].pop(),
                    lambda x: x['runs'][1].update(name=fresh.ORIGINAL),
                    lambda x: x['runs'][1]['process'].update(expected_source='b' * 40)]
                for index, change in enumerate(changes):
                    bad = copy.deepcopy(original)
                    change(bad)
                    path.write_text(json.dumps(bad))
                    with self.subTest(index=index), self.assertRaises(ValueError):
                        host.bind_prepared_fresh_execution(prepared, out)
                path.write_text(json.dumps(original))
                with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(
                        ValueError, 'FRESH_EXPECTED_SOURCE_REQUIRED'):
                    host.bind_prepared_fresh_execution(prepared, out)
                with patch.dict(os.environ, {'TRNM_EXPECTED_SOURCE_SHA': 'b' * 40}), \
                        self.assertRaisesRegex(ValueError, 'FRESH_EXPECTED_SOURCE_MISMATCH'):
                    host.bind_prepared_fresh_execution(prepared, out)
                with self.assertRaisesRegex(ValueError, 'ORIGINAL_NATIVE_MANIFEST_SCHEMA'):
                    host.bind_prepared_execution(prepared, out)


class FreshFailureDiagnostics(unittest.TestCase):
    """Static metadata fixtures and mocked owners; no work construction/execution."""

    @staticmethod
    def report(selector=fresh.FRESH):
        return dict(schema=('public-v3-signed-confirmation-pressure-v1'
                            if selector == fresh.ORIGINAL else fresh.FRESH_SCHEMA),
                    finite_target_met=False, requested_window_ns=4_000_000_000,
                    attack_workers=16, per_worker_attempt_cap=1024,
                    phases=[dict(mode='attack-free-baseline', independent_history_page_replay=[]),
                            dict(mode='from-zero-pressure', independent_history_page_replay=[
                                dict(history_call_index=0, replay_accepted=True, replay_error=None),
                                dict(history_call_index=1, replay_accepted=False,
                                     replay_error='PUBLIC_REQUEST_DEADLINE')])])

    def diagnose(self, doc, observed=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text(json.dumps(doc))
            return fresh.failure_diagnostic(observed or process(), fresh.FRESH, path)

    def test_only_bounded_metadata_and_actual_child_returncode_are_retained(self):
        doc = self.report()
        doc['proof'] = 'never-copy-proof-or-request-material'
        doc['phases'][1]['independent_history_page_replay'][-1]['request'] = doc['proof']
        observed = dict(process(), exit_code=1, process_exit_code=101)
        result = self.diagnose(doc, observed)
        self.assertEqual(result, dict(schema='trnm-w1-fresh-failure-diagnostic-v1',
            native_returncode=101, finite_target_met=False, acceptance_authority=False,
            last_history_replay=dict(phase='from-zero-pressure', history_call_index=1,
                replay_accepted=False, replay_error='PUBLIC_REQUEST_DEADLINE')))
        encoded = json.dumps(result)
        self.assertNotIn(doc['proof'], encoded)
        self.assertLess(len(encoded), 512)

    def test_unknown_actual_returncode_never_borrows_the_effective_exit_code(self):
        for code in (None, True, '101', 1 << 40):
            with self.subTest(code=code):
                result = self.diagnose(self.report(), dict(process(), process_exit_code=code))
                self.assertEqual(result['native_returncode'], 'unknown')
        observed = process()
        del observed['process_exit_code']
        self.assertEqual(self.diagnose(self.report(), observed)['native_returncode'], 'unknown')
        self.assertEqual(self.diagnose(self.report(), dict(process(), process_exit_code=-9))
                         ['native_returncode'], -9)

    def test_missing_malformed_nonfinite_and_wrong_schema_reports_remain_unknown(self):
        cases = [None, b'{', b'[]', b'\xff', b'{"finite_target_met":NaN}',
                 b'{"schema":"one","schema":"two"}',
                 json.dumps(dict(self.report(), schema='other-report')).encode()]
        for raw in cases:
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'report.json'
                if raw is not None:
                    path.write_bytes(raw)
                result = fresh.failure_diagnostic(process(), fresh.FRESH, path)
                self.assertEqual(result['finite_target_met'], 'unknown')
                self.assertEqual(result['last_history_replay'], 'unknown')
                self.assertFalse(result['acceptance_authority'])
        for error in (OSError('unreadable'), RecursionError('malformed depth')):
            with self.subTest(error=type(error)), patch.object(fresh, 'load_report', side_effect=error):
                result = fresh.failure_diagnostic(process(), fresh.FRESH, Path('unused'))
                self.assertEqual(result['last_history_replay'], 'unknown')

    def test_report_size_and_symlink_bounds_apply_without_a_new_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_bytes(b' ' * 65)
            with patch.object(fresh.native, 'REPORT_LIMIT', 64):
                self.assertEqual(fresh.failure_diagnostic(process(), fresh.FRESH, path)
                                 ['finite_target_met'], 'unknown')
            path.write_text(json.dumps(self.report()))
            alias = path.with_name('alias.json')
            alias.symlink_to(path)
            self.assertEqual(fresh.failure_diagnostic(process(), fresh.FRESH, alias)
                             ['last_history_replay'], 'unknown')

    def test_malformed_last_replay_cannot_fall_back_to_an_earlier_row_or_baseline(self):
        changes = [
            lambda d: d.update(phases=[]),
            lambda d: d['phases'][1].update(mode='unreviewed-phase'),
            lambda d: d['phases'][1].update(independent_history_page_replay=[]),
            lambda d: d['phases'][1].update(independent_history_page_replay={}),
            lambda d: d['phases'][1]['independent_history_page_replay'].extend([{}] * 15),
            lambda d: d['phases'][1]['independent_history_page_replay'].append(None),
        ]
        row_changes = [dict(history_call_index=True), dict(history_call_index=-1),
                       dict(history_call_index=16), dict(history_call_index=0),
                       dict(replay_accepted=0), dict(replay_error=None),
                       dict(replay_error='PUBLIC_' + 'A' * 96),
                       dict(replay_error='PUBLIC_ERROR {"proof":"must-not-copy"}'),
                       dict(replay_error='ab' * 32), dict(replay_accepted=True)]
        for change in row_changes:
            changes.append(lambda d, change=change: d['phases'][1]
                           ['independent_history_page_replay'][-1].update(change))
        changes.append(lambda d: d['phases'][1]['independent_history_page_replay'][-1]
                       .pop('replay_error'))
        for index, change in enumerate(changes):
            doc = self.report()
            doc['phases'][0]['independent_history_page_replay'] = [
                dict(history_call_index=0, replay_accepted=True, replay_error=None)]
            change(doc)
            with self.subTest(index=index):
                self.assertEqual(self.diagnose(doc)['last_history_replay'], 'unknown')
        for finite in (None, 0, 'false'):
            with self.subTest(finite=finite):
                self.assertEqual(self.diagnose(dict(self.report(), finite_target_met=finite))
                                 ['finite_target_met'], 'unknown')

    def test_successful_last_replay_can_explain_a_later_failed_business_target(self):
        doc = self.report()
        doc['phases'][1]['independent_history_page_replay'].pop()
        result = self.diagnose(doc)
        self.assertFalse(result['finite_target_met'])
        self.assertEqual(result['last_history_replay']['history_call_index'], 0)
        self.assertIsNone(result['last_history_replay']['replay_error'])
        self.assertFalse(result['acceptance_authority'])

    def test_diagnostic_cannot_change_zero_exit_failed_report_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log, report = root / 'test.log', root / 'report.json'
            log.write_text(passing_log(fresh.FRESH))
            for raw in (None, b'{', json.dumps(self.report()).encode()):
                with self.subTest(raw=raw):
                    if report.exists():
                        report.unlink()
                    if raw is not None:
                        report.write_bytes(raw)
                    with self.assertRaises(ValueError) as before:
                        fresh.validate_execution(process(), log, fresh.FRESH, report)
                    fresh.failure_diagnostic(process(), fresh.FRESH, report)
                    with self.assertRaises(ValueError) as after:
                        fresh.validate_execution(process(), log, fresh.FRESH, report)
                    self.assertEqual(str(before.exception), str(after.exception))

    def test_failure_manifest_keeps_original_verdicts_budgets_and_execution_count(self):
        for kind in ('missing', 'malformed', 'failed', 'positive-summary'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                binary = base / 'synthetic-never-executed-native'
                binary.write_bytes(b'static fixture; no native execution')

                def observed(command, log, **kwargs):
                    log.write_text('synthetic build control\n')
                    if command[0] != str(binary):
                        return process()
                    selector = command[1]
                    log.write_text(f'running 1 test\ntest {selector} ... FAILED\n')
                    key = ('TRNM_PUBLIC_V3_CONFIRMATION_DIR' if selector == fresh.ORIGINAL
                           else 'TRNM_PUBLIC_V3_FRESH_CONFIRMATION_DIR')
                    folder = Path(kwargs['env'][key])
                    folder.mkdir()
                    if kind != 'missing':
                        doc = self.report(selector)
                        doc['finite_target_met'] = kind == 'positive-summary'
                        (folder / 'report.json').write_text('{' if kind == 'malformed'
                                                          else json.dumps(doc))
                    return dict(process(), exit_code=101, process_exit_code=101)

                with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true',
                                            'TRNM_EXPECTED_SOURCE_SHA': 'a' * 40}), \
                        patch.object(fresh.native, 'source_identity', return_value={'commit': 'a' * 40}), \
                        patch.object(fresh.native, 'select_binary', return_value=binary), \
                        patch.object(fresh.ci, 'run', side_effect=observed) as runner:
                    out = base / 'observations'
                    result = fresh.run(out)
                self.assertEqual(runner.call_count, 3)  # Existing build plus two named calls only.
                self.assertFalse(result['passed'])
                self.assertFalse(result['all_named_tests_passed'])
                self.assertTrue(result['execution_finished'])
                self.assertEqual(result['requested_window_ns'], 4_000_000_000)
                self.assertEqual(result['attack_workers'], 16)
                self.assertEqual(result['failures'], [selector + ': FRESH_NATIVE_PROCESS_REQUIRED'
                                                     for selector in fresh.SELECTORS])
                for row in result['runs']:
                    self.assertFalse(row['passed'])
                    self.assertEqual(row['failure'], 'FRESH_NATIVE_PROCESS_REQUIRED')
                    diagnostic = row['failure_diagnostic']
                    self.assertEqual(diagnostic['native_returncode'], 101)
                    self.assertFalse(diagnostic['acceptance_authority'])
                    self.assertEqual(diagnostic['finite_target_met'],
                                     'unknown' if kind in ('missing', 'malformed')
                                     else kind == 'positive-summary')
                for key in ('independent_wan_accepted', 'work_hardness_accepted',
                            'production_activation'):
                    self.assertFalse(result[key])
                self.assertEqual(json.loads((out / 'manifest.json').read_text()), result)


if __name__ == '__main__':
    unittest.main()
