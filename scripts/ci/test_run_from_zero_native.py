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
import re
import struct
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_from_zero_native as driver
from contract_wire import header_decode, header_encode, tx_unsigned
from pon_public_v3_phase_read import PHASES_V4, PHASE_PARENTS_V4


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
            observations=dict(schema='public-v3-local-request-resource-observation-v2',
                records=records, accepted_connections_seen=19, capacity=16384,
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


def simulated_confirmation_report():
    """Synthetic codec/report consistency only; unsigned fixtures are NOT evidence."""
    context = dict(network='aa'*32, parameters='bb'*32, genesis='cc'*32,
                   target='7f'+'ff'*31, task=driver.H('task', bytes(16384), bytes(16384)).hex(),
                   policy_id='dd'*32)
    proof = b'PNW1' + bytes(3*16384+32)
    tx = tx_unsigned(bytes.fromhex(context['network']), bytes([1])*32, 1, 1000, 1000000,
                     1, {'recipient': bytes([2])*32, 'amount': 1}) + bytes(64)
    packets, identifiers, headers = [], [], []
    parent = context['genesis']
    for height in range(1, 8):
        header = dict(network=context['network'], parameters=context['parameters'], parent=parent,
                      height=height, timestamp=1_750_000_000+height*10, target=context['target'],
                      miner='ee'*32, transactions='ab'*32, state='af'*32, receipts='ef'*32,
                      work_task=context['task'], nonce=height)
        encoded = header_encode(header)
        wire = encoded + struct.pack('<H', height == 1)
        if height == 1:
            wire += struct.pack('<H', len(tx)) + tx
        wire += proof
        parent = driver.H('block', encoded, proof[-32:]).hex()
        packets.append(wire.hex()); identifiers.append(parent); headers.append(encoded.hex())
    constructions = []
    for index in range(16):
        attack_header = header_decode(bytes.fromhex(headers[0]))
        attack_header['nonce'] = 100000 + index
        encoded = header_encode(attack_header)
        challenge = driver.H('challenge', encoded)
        attempts = []
        for nonce in range(4096):
            trace = driver.H('public-v3-from-zero-v1', challenge, struct.pack('<Q', nonce))
            ticket = driver.H('ticket', challenge, trace)
            hit = ticket <= bytes.fromhex(context['target'])
            attempts.append(dict(nonce=nonce, trace=trace.hex(), ticket=ticket.hex(), target_hit=hit))
            if hit:
                break
        assert attempts[-1]['target_hit']  # deterministic tiny synthetic fixture, not real Work
        wire = encoded + bytes(2) + proof[:-32] + trace
        constructions.append(dict(header=encoded.hex(), challenge=challenge.hex(), setup_calls=1,
            attempt_budget=4096, attempts=attempts, winner_nonce=len(attempts)-1,
            packet=wire.hex(), status='target_hit_unverified'))

    def compact(row, request, packet_index):
        encoded = json.dumps(request, sort_keys=True, separators=(',', ':')).encode()
        return dict(row, packet_index=packet_index, recorded_request_bytes=len(encoded),
                    recorded_request_digest=driver.H('pressure-recorded-request-v1', encoded).hex())

    phases = []
    for index in range(2):
        def call(start=20, end=30, **fields):
            return dict(status='ok', started_ns=start, ended_ns=end, elapsed_wall_ns=end-start,
                        client_thread_cpu_ns=1, deadline_ms=2000, returned_after_deadline=False,
                        returned_after_window=False, error=None, **fields)
        workers = []
        if index:
            for worker in range(16):
                request = dict(op='submit', packet=constructions[worker]['packet'])
                calls = [compact(call(15, 200), request, worker)]
                calls[0]['status'] = 'refused'
                if worker == 0:
                    early = compact(call(0, 5), request, 0); early['status'] = 'refused'
                    calls.insert(0, early)
                workers.append(dict(worker=worker, calling_thread_cpu_ns=2,
                                    attempt_cap_reached=False, calls=calls))
        pages, after = [], context['genesis']
        replay_stages = []
        for number, packet in enumerate(packets):
            value = dict(schema='pon-native-history-v1', network=context['network'],
                         parameters=context['parameters'], genesis=context['genesis'],
                         tip=identifiers[-1], after=after, packets=[packet], next=identifiers[number],
                         complete=number == 6)
            pages.append(call(100+number*10, 105+number*10, response={'value': value},
                              request=dict(op='history', tip=identifiers[-1], after=after)))
            replay_stages.append(dict(history_call_index=number,
                history_request_ended_ns=105+number*10,
                replay_started_ns=106+number*10, replay_ended_ns=107+number*10,
                replay_wall_ns=1, replay_thread_cpu_ns=1,
                prior_after=after, next_after=identifiers[number],
                replay_accepted=True,
                clock_scope='independent verifier caller thread; wall spans all waits, CPU only this thread'))
            after = identifiers[number]
        records = [dict(complete=True, observation_failed=False) for _ in range(15+17*index)]
        phases.append(dict(mode='attack-free-baseline' if index == 0 else 'from-zero-pressure',
            workers=16*index, target=context['target'], task=context['task'], initial_tip=context['genesis'],
            invariant_target_met=True, finite_business_target_met=True, no_attack_accepted=True,
            accounting_closed=True, full_native_state_equal=True, receiver_matches_valid_honest_prefix=True,
            client_confirmed_before_original_window_end=True, overlap_demonstrated=True,
            public_network_ready=False, independent_operator_accepted=False, work_profile_qualified=False,
            resource_fairness_qualified=False, production_activation=False,
            requested_window_ns=4_000_000_000, business_started_ns=10, confirmation_ended_ns=1000,
            client_confirmation_latency_ns=990, client_confirmed_transactions=1,
            independent_replay_and_confirmation_cpu_ns=20, independent_replay_and_confirmation_wall_ns=1000,
            independent_history_page_replay=replay_stages,
            independent_final_confirmation_stage=dict(
                confirmation_started_ns=167, confirmation_ended_ns=168,
                confirmation_wall_ns=1, confirmation_thread_cpu_ns=1,
                observation_returned=True,
                clock_scope='independent verifier caller thread; no consensus/host time claim'),
            verification_errors=[], independent_client_confirmation=dict(
                confirmed=True, reorged=False, finalized=False, execution_authority=False,
                network=context['network'], parameters=context['parameters'], genesis=context['genesis'],
                transaction=driver.H('tx-id', tx).hex(), included_block=identifiers[0],
                observed_tip=identifiers[-1], included_height=1, observed_height=7, depth=6,
                required_work_delta=(12).to_bytes(64, 'big').hex(), work_delta=(12).to_bytes(64, 'big').hex()),
            honest_submissions=[compact(call(20+height*10, 25+height*10, height=height),
                dict(op='submit', packet=packets[height-1]), height-1) for height in range(1, 8)],
            honest_history=pages, attacks=workers, attacker_workers_cpu_ns=32*index,
            overlapping_false_calls=16*index, completed_false_calls_before_business=index,
            completed_false_calls_at_confirmation=17*index,
            honest_heads=[compact(call(), dict(op='head'), None)],
            honest_head_successes_in_window=1, maximum_honest_head_gap_ns=4_000_000_000-30,
            service=dict(error=None, metrics=dict(mutation_cpu_charged_ns=20,
                mutation_full_work_cpu_ns=10, mutation_dispatch_excluding_work_cpu_ns=10,
                mutation_cpu_clock_failures=0, work_started=7+17*index,
                work_finished=7+17*index, work_failed=17*index)),
            observations=dict(schema='public-v3-local-request-resource-observation-v2',
                cpu_intervals_are_nested_not_additive=True, counter_overflow=False,
                observation_has_consensus_authority=False, cpu_includes_reactor_authentication_or_response_signing=False,
                stream_bytes_are_physical_network_bytes=False, capacity=16384,
                accepted_connections_seen=len(records), records_not_retained=0,
                measurement_failures=0, records=records)))
    return dict(schema='public-v3-signed-confirmation-pressure-v1', simulated_control=True, **context,
        finite_target_met=True, invariant_target_met=True, same_packet_sequence_in_both_runs=True,
        public_network_ready=False, work_profile_qualified=False, production_activation=False,
        strongest_honest_producer_used=False, honest_chain_aggregate_cpu_ns=None,
        honest_chain_acquisition_wall_ns=1, attacker_construction_cpu_ns=1,
        attacker_construction_wall_ns=1, signed_honest_packets=packets,
        from_zero_construction=constructions,
        phases=phases)


def simulated_import_observation():
    """Synthetic failed import/Host intervals, never measured resource evidence."""
    def phases():
        return [dict(phase=phase, started=False, completed=False, accepted=None,
            error_code=None, started_ns=None, ended_ns=None, wall_ns=None, thread_cpu_ns=None,
            parent_phase=PHASE_PARENTS_V4.get(phase)) for phase in PHASES_V4]
    def entered(rows, name, start, end):
        rows[PHASES_V4.index(name)].update(started=True, completed=True, accepted=False,
            error_code='PUBLIC_REQUEST_DEADLINE', started_ns=start, ended_ns=end,
            wall_ns=end-start, thread_cpu_ns=2)
    native, packet = phases(), phases()
    entered(native, 'history_import', 10, 90)
    entered(packet, 'history_import', 15, 85)
    host = []
    for phase, start, end, calls in [('resolve', 0, 1, 1), ('initial', 2, 3, 1),
                                   ('checkpoint', 20, 80, 2), ('final', 91, 92, 1)]:
        failed = int(phase == 'checkpoint')
        host.append(dict(phase=phase, calls_started=calls, calls_completed=calls,
            calls_accepted=calls-failed, calls_rejected=failed, calls_unfinished=0,
            first_started_ns=start, last_ended_ns=end, wall_ns=2 if calls == 2 else end-start,
            thread_cpu_ns=calls, wall_clock_unknown_calls=0, cpu_clock_unknown_calls=0,
            last_error_code='PUBLIC_REQUEST_DEADLINE' if failed else None))
    return dict(schema='pon-local-history-import-observation-v1', tip=[1]*32, after=[2]*32,
        supplied_packets=1, packet_capacity=16, phases=native,
        packets=[dict(packet_index=0, packet_id=[3]*32, phases=packet)], measurement_failures=0,
        host_checks=host, host_checks_are_nested_not_additive=True,
        cpu_intervals_are_nested_not_additive=True, phase_cpu_excludes_scoped_workers=True,
        host_cpu_includes_each_calling_thread=True, host_cpu_is_full_worker_cpu=False,
        observation_has_consensus_authority=False, clock_scope='one observer-local epoch')


class HistoryImportObservationTests(unittest.TestCase):
    def test_failed_import_is_retained_without_changing_its_native_or_host_outcome(self):
        value = simulated_import_observation()
        before = copy.deepcopy(value)
        driver.validate_history_import_observation(value)
        self.assertEqual(value, before)
        self.assertFalse(value['phases'][PHASES_V4.index('history_import')]['accepted'])

    def test_unknown_clocks_remain_unknown_and_partial_capture_is_explicit(self):
        value = simulated_import_observation()
        row = value['host_checks'][2]
        row.update(thread_cpu_ns=None, cpu_clock_unknown_calls=1)
        driver.validate_history_import_observation(value)
        row.update(calls_started=3)
        with self.assertRaisesRegex(ValueError, 'HOST_COUNTS'):
            driver.validate_history_import_observation(value)
        value['measurement_failures'] = 1
        driver.validate_history_import_observation(value)

    def test_new_shapes_counts_unknowns_and_nonfinite_samples_are_rejected(self):
        mutations = [
            lambda v: v.pop('host_checks'),
            lambda v: v['host_checks'].pop(),
            lambda v: v['host_checks'][2].pop('thread_cpu_ns'),
            lambda v: v['host_checks'][2].update(calls_completed=3),
            lambda v: v['host_checks'][2].update(calls_started=3),
            lambda v: v['host_checks'][2].update(thread_cpu_ns=float('nan')),
            lambda v: v['host_checks'][2].update(thread_cpu_ns=None),
            lambda v: v['host_checks'][2].update(cpu_clock_unknown_calls=1),
            lambda v: v['host_checks'][0].update(last_error_code='PUBLIC_HOST_KERNEL_CONTEXT'),
            lambda v: v.update(packets=v['packets']*17),
            lambda v: v.update(packets=v['packets']*2),
            lambda v: v['packets'][0].update(packet_index=16),
            lambda v: v['packets'][0].update(packet_id=[1]*31),
            lambda v: v['phases'].pop(),
            lambda v: v['phases'][-1].update(parent_phase='admission'),
            lambda v: v.update(host_checks_are_nested_not_additive=False),
            lambda v: v.update(cpu_intervals_are_nested_not_additive=False),
            lambda v: v.update(host_cpu_is_full_worker_cpu=True),
            lambda v: v.pop('phase_cpu_excludes_scoped_workers'),
        ]
        for index, mutate in enumerate(mutations):
            value = simulated_import_observation()
            mutate(value)
            with self.subTest(index=index), self.assertRaises(ValueError):
                driver.validate_history_import_observation(value)

    def test_host_and_packet_times_cannot_escape_known_native_parent(self):
        mutations = [
            lambda v: v['host_checks'][2].update(first_started_ns=9),
            lambda v: v['host_checks'][2].update(last_ended_ns=91),
            lambda v: v['host_checks'][1].update(last_ended_ns=11),
            lambda v: v['host_checks'][3].update(first_started_ns=89),
            lambda v: v['packets'][0]['phases'][PHASES_V4.index('history_import')]
                .update(started_ns=9, wall_ns=76),
        ]
        for index, mutate in enumerate(mutations):
            value = simulated_import_observation()
            mutate(value)
            with self.subTest(index=index), self.assertRaises(ValueError):
                driver.validate_history_import_observation(value)


class BinarySelectionTests(unittest.TestCase):
    def test_format_copy_retains_out_of_line_module_and_original_bytes(self):
        # Negative control: the old flat copy cannot resolve #[path].
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source/tests/public_v3_from_zero.rs'
            support = root / 'source/examples/support/w1_from_zero.rs'
            modules = {
                'public_v3_from_zero/fresh_challenge.rs': b'pub fn fresh_trial() {}\n',
                'public_v3_from_zero/sp27_receiver_controls.rs': b'pub fn controls_trial() {}\n',
                'public_v3_from_zero/sp27_receiver_strata.rs': b'pub fn strata_trial() {}\n',
                'public_v3_from_zero/sp27_receiver_campaign.rs': b'pub fn campaign_trial() {}\n',
            }
            source.parent.mkdir(parents=True)
            support.parent.mkdir(parents=True)
            (source.parent / 'public_v3_from_zero').mkdir()
            source.write_bytes(b'#[path = "../examples/support/w1_from_zero.rs"]\n'
                               b'mod w1_from_zero;\n'
                               b'#[path = "public_v3_from_zero/fresh_challenge.rs"]\n'
                               b'mod fresh_challenge;\n'
                               b'#[path = "public_v3_from_zero/sp27_receiver_controls.rs"]\n'
                               b'mod sp27_receiver_controls;\n'
                               b'#[path = "public_v3_from_zero/sp27_receiver_strata.rs"]\n'
                               b'mod sp27_receiver_strata;\n'
                               b'#[path = "public_v3_from_zero/sp27_receiver_campaign.rs"]\n'
                               b'mod sp27_receiver_campaign;\n')
            support.write_bytes(b'pub fn trial() {}\n')
            for relative, content in modules.items():
                (source.parent / relative).write_bytes(content)
            out = root / 'observations'
            out.mkdir()
            flattened = out / 'formatted.rs'
            flattened.write_bytes(source.read_bytes())
            self.assertFalse((flattened.parent / '../examples/support/w1_from_zero.rs').is_file())
            original_source, original_support = source.read_bytes(), support.read_bytes()
            original_modules = {
                relative: (source.parent / relative).read_bytes() for relative in modules
            }

            staged = driver.stage_format_copy(source, support, out)
            self.assertEqual(staged, out / 'format-copy-source/tests/public_v3_from_zero.rs')
            self.assertEqual(staged.read_bytes(), original_source)
            self.assertEqual(
                (staged.parent / '../examples/support/w1_from_zero.rs').resolve().read_bytes(),
                original_support)
            for relative, original in original_modules.items():
                with self.subTest(relative=relative):
                    self.assertEqual((staged.parent / relative).read_bytes(), original)
                    self.assertEqual((source.parent / relative).read_bytes(), original)
            self.assertEqual(source.read_bytes(), original_source)
            self.assertEqual(support.read_bytes(), original_support)

    def test_format_copy_covers_every_current_explicit_module_path(self):
        source = driver.ROOT / driver.SOURCE
        paths = re.findall(r'^#\[path = "([^"]+)"\]$', source.read_text(), re.MULTILINE)
        self.assertTrue(paths)
        with tempfile.TemporaryDirectory() as directory:
            staged = driver.stage_format_copy(source, driver.ROOT / driver.FORMAT_SUPPORT,
                                              Path(directory))
            for relative in paths:
                with self.subTest(relative=relative):
                    self.assertEqual((staged.parent / relative).read_bytes(),
                                     (source.parent / relative).read_bytes())

    def test_missing_out_of_line_module_cannot_be_silently_substituted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'test.rs'
            source.write_text('#[path = "../examples/support/w1_from_zero.rs"]\n'
                              'mod w1_from_zero;\n')
            with self.assertRaises(FileNotFoundError):
                driver.stage_format_copy(source, root / 'missing.rs', root / 'out')

    def test_observer_cpu_scope_keeps_historical_and_paid_envelope_distinct(self):
        legacy = dict(schema='public-v3-local-request-resource-observation-v2',
                      cpu_includes_reactor_authentication_or_response_signing=False)
        driver.observer_cpu_scope(legacy)
        current = dict(schema='public-v3-local-request-resource-observation-v3',
                       cpu_includes_reactor_authentication_or_response_signing=True,
                       cpu_includes_reactor_authentication=False,
                       dispatch_cpu_includes_paid_body_decode=True,
                       dispatch_cpu_includes_response_signing=True)
        driver.observer_cpu_scope(current)
        successor = dict(current, schema='public-v3-local-request-resource-observation-v4',
                         phase_parent_links_are_inclusive=True, cpu_wait_is_outside_dispatch=True,
                         monotonic_epoch_is_observer_local=True, records=[])
        driver.observer_cpu_scope(successor)
        for key in ('records', 'phase_parent_links_are_inclusive', 'cpu_wait_is_outside_dispatch',
                    'monotonic_epoch_is_observer_local'):
            changed = dict(successor)
            del changed[key]
            with self.subTest(v4_missing=key), self.assertRaises(ValueError):
                driver.observer_cpu_scope(changed)
        with self.assertRaises(ValueError):
            driver.observer_cpu_scope(dict(successor, records=[{}]))
        for key in ('cpu_includes_reactor_authentication_or_response_signing',
                    'cpu_includes_reactor_authentication',
                    'dispatch_cpu_includes_paid_body_decode',
                    'dispatch_cpu_includes_response_signing'):
            changed = {**current, key: not current[key]}
            with self.subTest(key=key), self.assertRaises(ValueError):
                driver.observer_cpu_scope(changed)
        for schema in ('unknown', None):
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                driver.observer_cpu_scope({**legacy, 'schema': schema})

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
                 missing_sustained=False, sustained_edit=None, sustained_drift=False,
                 missing_confirmation=False, confirmation_edit=None, confirmation_drift=False,
                 missing_format_module=False, missing_log=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'source'; root.mkdir()
            test_source = root / driver.SOURCE
            test_source.parent.mkdir(parents=True)
            test_source.write_text('// simulated source; not Rust execution\n')
            support = root / driver.FORMAT_SUPPORT
            support.parent.mkdir(parents=True)
            support.write_text('// simulated Rust out-of-line module\n')
            if not missing_format_module:
                for relative in driver.FORMAT_TEST_MODULES:
                    module = test_source.parent / relative
                    module.parent.mkdir(parents=True, exist_ok=True)
                    module.write_text('// simulated Rust test-local module\n')
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
                    if not missing_confirmation:
                        confirmation = out / 'confirmation'; confirmation.mkdir()
                        report = simulated_confirmation_report()
                        if confirmation_edit is not None:
                            confirmation_edit(report)
                        (confirmation / 'report.json').write_text(json.dumps(report))
                    if log_drift:
                        (out / driver.TESTS[0] / 'stdout').write_text('changed after validation')
                (folder / 'stdout').write_text(text)
                (folder / 'stderr').write_text('retained simulated stderr\n')
                if name == missing_log:
                    (folder / 'stdout').unlink()
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
                if current is after and confirmation_drift:
                    path = out / 'confirmation/report.json'
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
                for stage in result.get('terminal', {}).get('acceptance_stages', {}).values():
                    raw = stage['retained_report']
                    if raw['state'] == 'present':
                        path = out / stage['path']
                        self.assertEqual(raw['sha256'], driver.digest(path.read_bytes()))
                        self.assertEqual(raw['bytes'], path.stat().st_size)
                return result, seen
            finally:
                os.chdir(previous_cwd)

    def test_driver_success_requires_all_original_and_confirmation_results(self):
        result, _ = self.exercise()
        self.assertTrue(result['passed'])
        self.assertEqual([r['name'] for r in result['runs']], list(driver.TESTS))
        self.assertTrue(all(r['process']['simulated_control'] for r in result['runs']))
        self.assertEqual(result['schema'], 'trnm-from-zero-native-execution-v3')
        self.assertTrue(result['execution_finished'])
        self.assertTrue(result['terminal']['native_execution_completed'])
        self.assertTrue(result['terminal']['acceptance_passed'])
        self.assertTrue(all(stage['status'] == 'passed' and stage['retained_matches_before_validation']
                            for stage in result['terminal']['acceptance_stages'].values()))
        with patch.object(driver, 'run', return_value=result), redirect_stdout(io.StringIO()):
            self.assertEqual(driver.main(['--out', '/unused-simulated-output']), 0)

    def test_missing_format_module_is_retained_failure_before_any_child_runs(self):
        result, seen = self.exercise(missing_format_module=True)
        self.assertFalse(result['passed'])
        self.assertFalse(result['format_passed'])
        self.assertFalse(result['source_recompiled'])
        self.assertEqual(result['runs'], [])
        self.assertEqual(seen, [])
        self.assertTrue(any('fresh_challenge.rs' in error for error in result['failures']))

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
        self.assertEqual([r['name'] for r in result['runs']], list(driver.TESTS))
        self.assertEqual([r['passed'] for r in result['runs']],
                         [False] + [True] * (len(driver.TESTS) - 1))

    def test_ignored_exit_zero_is_still_failure(self):
        result, _ = self.exercise(ignored=driver.TESTS[1])
        self.assertFalse(result['passed'])
        self.assertEqual([r['name'] for r in result['runs']], list(driver.TESTS))
        self.assertEqual([r['passed'] for r in result['runs']],
                         [True, False] + [True] * (len(driver.TESTS) - 2))

    def test_nonzero_exit_cannot_be_overridden_by_success_text(self):
        result, _ = self.exercise(fail=driver.TESTS[0])
        self.assertFalse(result['passed'])
        self.assertEqual([r['name'] for r in result['runs']], list(driver.TESTS))
        self.assertEqual(len(result['runs']), len(driver.TESTS))
        self.assertFalse(result['runs'][0]['passed'])
        self.assertTrue(result['terminal']['native_execution_completed'])
        self.assertEqual(result['terminal']['native_invocations'][0]['exit_code'], 101)
        self.assertFalse(result['terminal']['acceptance_passed'])

    def test_final_named_ignored_exit_zero_is_still_failure(self):
        # Protect the fifth signed-business test from being credited when ignored.
        result, _ = self.exercise(ignored=driver.TESTS[-1])
        self.assertFalse(result['passed'])
        self.assertEqual([r['passed'] for r in result['runs']], [True, True, True, True, False])

    def test_final_named_nonzero_exit_cannot_claim_success(self):
        result, _ = self.exercise(fail=driver.TESTS[-1])
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['runs']), len(driver.TESTS))
        self.assertFalse(result['runs'][-1]['passed'])

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

    def test_missing_confirmation_report_cannot_pass_named_stdout(self):
        result, _ = self.exercise(missing_confirmation=True)
        self.assertTrue(result['all_named_tests_passed'])
        self.assertFalse(result['passed'])
        self.assertIn('CONFIRMATION_REPORT_REQUIRED', result['failures'])
        self.assertTrue(result['terminal']['native_execution_completed'])
        stage = result['terminal']['acceptance_stages']['confirmation_report']
        self.assertEqual(stage['status'], 'failed')
        self.assertEqual(stage['retained_report']['state'], 'missing')
        self.assertIsNone(stage['retained_report']['sha256'])

    def test_confirmation_report_is_required_even_when_component_exit_is_zero(self):
        result, _ = self.exercise(confirmation_edit=lambda doc: doc.update(finite_target_met=False))
        self.assertTrue(result['all_named_tests_passed'])
        self.assertFalse(result['passed'])
        self.assertIn('CONFIRMATION_TARGET', result['failures'])
        self.assertIsNotNone(result['confirmation_observation'])
        self.assertFalse(result['confirmation_observation']['original_gate_validated'])
        self.assertFalse(result['confirmation_observation']['network_capacity_qualified'])

    def test_failed_confirmation_retains_native_completion_and_failure_exit(self):
        result, _ = self.exercise(confirmation_edit=lambda doc: doc.update(finite_target_met=False))
        terminal = result['terminal']
        self.assertEqual(terminal['schema'], 'trnm-from-zero-native-terminal-v1')
        self.assertEqual(result['schema'], 'trnm-from-zero-native-execution-v3')
        self.assertTrue(terminal['finalization_completed'])
        self.assertTrue(terminal['native_execution_completed'])
        self.assertFalse(result['execution_finished'])  # The original acceptance sequence failed.
        self.assertIn('report validation', terminal['legacy_execution_finished_scope'])
        self.assertFalse(terminal['acceptance_passed'])
        self.assertFalse(terminal['subsequent_ci_steps_observed'])
        self.assertEqual(terminal['unexecuted_native_tests'], [])
        self.assertEqual(terminal['unexecuted_acceptance_stages'], [])
        self.assertTrue(all(row['status'] == 'returned' and row['exit_code'] == 0
                            and row['timed_out'] is False for row in terminal['native_invocations']))
        stage = terminal['acceptance_stages']['confirmation_report']
        self.assertEqual(stage['status'], 'failed')
        self.assertEqual(stage['error'], 'CONFIRMATION_TARGET')
        self.assertEqual(stage['before_validation'], stage['retained_report'])
        self.assertTrue(stage['retained_matches_before_validation'])
        self.assertEqual(stage['retained_report']['sha256'], result['files']['confirmation/report.json'])
        self.assertIsNone(result['confirmation_report'])
        with patch.object(driver, 'run', return_value=result), redirect_stdout(io.StringIO()):
            self.assertEqual(driver.main(['--out', '/unused-simulated-output']), 1)

    def test_failed_earlier_report_leaves_later_acceptance_unexecuted_but_retains_bytes(self):
        result, _ = self.exercise(report_edit=lambda doc: doc.update(finite_target_met=False))
        terminal = result['terminal']
        self.assertTrue(terminal['native_execution_completed'])
        self.assertFalse(result['passed'])
        self.assertIn('NATIVE_SERVICE_TARGET', result['failures'])
        self.assertEqual(terminal['acceptance_stages']['service_report']['status'], 'failed')
        self.assertEqual(terminal['unexecuted_acceptance_stages'],
                         ['sustained_report', 'confirmation_report'])
        for key in terminal['unexecuted_acceptance_stages']:
            stage = terminal['acceptance_stages'][key]
            self.assertEqual(stage['status'], 'not_executed')
            self.assertIsNone(stage['before_validation'])
            self.assertIsNone(stage['retained_matches_before_validation'])
            self.assertIsNone(result[key])
            self.assertEqual(stage['retained_report']['sha256'], result['files'][stage['path']])

    def test_returned_native_status_survives_a_later_log_read_error(self):
        result, seen = self.exercise(missing_log=driver.TESTS[0])
        terminal = result['terminal']
        self.assertFalse(result['passed'])
        self.assertFalse(terminal['native_execution_completed'])
        self.assertTrue(terminal['finalization_completed'])
        first = terminal['native_invocations'][0]
        self.assertEqual((first['status'], first['exit_code'], first['timed_out']),
                         ('returned', 0, False))
        self.assertEqual(terminal['unexecuted_native_tests'], list(driver.TESTS[1:]))
        self.assertNotIn(driver.TESTS[1], seen)
        self.assertTrue(any('stdout' in failure for failure in result['failures']))

    def test_failed_raw_report_change_retains_both_input_and_final_identities(self):
        result, _ = self.exercise(confirmation_edit=lambda doc: doc.update(finite_target_met=False),
                                  confirmation_drift=True)
        self.assertFalse(result['passed'])
        self.assertIn('CONFIRMATION_TARGET', result['failures'])
        self.assertIn('CONFIRMATION_OBSERVATION_CHANGED', result['failures'])
        stage = result['terminal']['acceptance_stages']['confirmation_report']
        self.assertEqual(stage['status'], 'failed')
        self.assertEqual(stage['before_validation']['state'], 'present')
        self.assertEqual(stage['retained_report']['state'], 'present')
        self.assertNotEqual(stage['before_validation']['sha256'], stage['retained_report']['sha256'])
        self.assertFalse(stage['retained_matches_before_validation'])

    def test_report_identity_is_bounded_and_does_not_parse_or_accept_raw_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            raw = b'not JSON'
            path.write_bytes(raw)
            identity = driver.report_file_identity(path)
            self.assertEqual(identity, {'state': 'present', 'bytes': len(raw),
                                        'sha256': driver.digest(raw)})
            with patch.object(driver, 'REPORT_LIMIT', 4):
                identity = driver.report_file_identity(path)
            self.assertEqual(identity['state'], 'over_limit')
            self.assertEqual(identity['bytes_at_least'], 5)
            self.assertIsNone(identity['sha256'])
            self.assertIsNone(identity['bytes'])
            self.assertEqual(path.read_bytes(), raw)
            link = Path(directory) / 'linked-report.json'
            link.symlink_to(path)
            self.assertEqual(driver.report_file_identity(link)['state'], 'not_regular')

    def test_confirmation_report_mutation_after_validation_cannot_pass(self):
        result, _ = self.exercise(confirmation_drift=True)
        self.assertFalse(result['passed'])
        self.assertIn('CONFIRMATION_REPORT_CHANGED', result['failures'])

    def test_confirmation_output_environment_is_restored(self):
        name = 'TRNM_PUBLIC_V3_CONFIRMATION_DIR'
        with patch.dict(os.environ, {name: 'parent-confirmation-path'}):
            result, _ = self.exercise()
            self.assertTrue(result['passed'])
            self.assertEqual(os.environ[name], 'parent-confirmation-path')

    def test_malformed_confirmation_retains_structured_failure_and_raw_report_hash(self):
        result, _ = self.exercise(confirmation_edit=lambda doc: doc['phases'].__setitem__(0, []))
        self.assertTrue(result['all_named_tests_passed'])
        self.assertFalse(result['passed'])
        self.assertIn('CONFIRMATION_PHASES', result['failures'])
        self.assertIn('confirmation/report.json', result['files'])
        stage = result['terminal']['acceptance_stages']['confirmation_report']
        self.assertEqual(stage['status'], 'failed')
        self.assertEqual(stage['retained_report']['sha256'], result['files']['confirmation/report.json'])

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
        terminal = result['terminal']
        self.assertFalse(terminal['native_execution_completed'])
        self.assertEqual(terminal['native_invocations'][0]['status'], 'returned')
        self.assertEqual(terminal['native_invocations'][0]['exit_code'],
                         result['runs'][0]['process']['exit_code'])
        self.assertTrue(terminal['native_invocations'][0]['timed_out'])
        self.assertEqual(terminal['unexecuted_native_tests'], list(driver.TESTS[1:]))
        self.assertEqual(terminal['unexecuted_acceptance_stages'],
                         ['service_report', 'sustained_report', 'confirmation_report'])

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


class ConfirmationObservationTests(unittest.TestCase):
    def summarize(self, edit=lambda doc: None):
        document = simulated_confirmation_report()
        edit(document)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text(json.dumps(document))
            return driver.summarize_confirmation_report(path)

    @staticmethod
    def fail_pressure(doc):
        doc['finite_target_met'] = False
        phase = doc['phases'][1]
        phase.update(client_confirmed_transactions=0, confirmation_ended_ns=None,
                     client_confirmation_latency_ns=None, independent_client_confirmation=None,
                     client_confirmed_before_original_window_end=False,
                     finite_business_target_met=False, full_native_state_equal=False,
                     independent_final_confirmation_stage=None,
                     verification_errors=['PUBLIC_REQUEST_DEADLINE'])
        phase['independent_history_page_replay'] = [dict(
            history_call_index=0, replay_started_ns=105, replay_ended_ns=4_000_000_001,
            replay_wall_ns=4_000_000_001-105, replay_thread_cpu_ns=None, replay_accepted=False)]

    def test_ack_count_and_confirmation_denominator_are_separate(self):
        result = self.summarize()
        self.assertTrue(result['simulated_control'])
        self.assertTrue(result['original_gate_validated'])
        self.assertFalse(result['tail_latency_qualified'])
        self.assertFalse(result['network_capacity_qualified'])
        for phase in result['phases']:
            self.assertEqual(phase['signed_submit_ack']['successful_in_original_window'], 7)
            self.assertEqual(phase['signed_submit_ack']['acknowledgements_per_window_second'], 1.75)
            business = phase['business']
            self.assertEqual(business['required_signed_transactions'], 1)
            self.assertEqual(business['reported_independently_confirmed_in_window'], 1)
            self.assertEqual(business['independent_confirmed_transactions_per_window_second'], .25)
            self.assertEqual(business['observed_success_latency_ns'], 990)
            self.assertEqual(business['successful_latency']['samples'], 1)
            for quantile in ('p50_ns', 'p95_ns', 'p99_ns'):
                self.assertIsNone(business['successful_latency'][quantile])

    def test_failed_business_retains_denominator_and_censor_bound_without_fake_latency(self):
        result = self.summarize(self.fail_pressure)
        self.assertFalse(result['original_gate_validated'])
        self.assertEqual(result['original_gate_validation_error'], 'CONFIRMATION_TARGET')
        phase = result['phases'][1]
        business = phase['business']
        self.assertEqual(phase['signed_submit_ack']['successful_in_original_window'], 7)
        self.assertEqual(business['reported_independently_confirmed_in_window'], 0)
        self.assertEqual(business['unconfirmed'], 1)
        self.assertEqual(business['unknown'], 0)
        self.assertEqual(business['independent_confirmed_transactions_per_window_second'], 0)
        self.assertEqual(business['unconfirmed_latency_lower_bound_ns'], 4_000_000_000-10)
        self.assertTrue(business['lower_bound_reaches_original_window_end'])
        self.assertIsNone(business['observed_success_latency_ns'])
        self.assertEqual(business['successful_latency']['samples'], 0)
        replay = phase['independent_page_replay']
        self.assertEqual(replay['failed_or_late'], 1)
        self.assertEqual(replay['accepted_in_original_window'], 0)
        self.assertEqual(replay['calling_thread_cpu']['missing_samples'], 1)

    def test_missing_confirmation_is_unknown_instead_of_zero(self):
        def edit(doc):
            self.fail_pressure(doc)
            del doc['phases'][1]['client_confirmed_transactions']
        business = self.summarize(edit)['phases'][1]['business']
        self.assertIsNone(business['reported_independently_confirmed_in_window'])
        self.assertIsNone(business['unconfirmed'])
        self.assertIsNone(business['independent_confirmed_transactions_per_window_second'])
        self.assertIsNone(business['unconfirmed_latency_lower_bound_ns'])
        self.assertEqual(business['unknown'], 1)

    def test_business_start_at_or_after_window_retains_failed_offer(self):
        for started in (4_000_000_000, 4_000_000_001, 9_000_000_000):
            def edit(doc):
                self.fail_pressure(doc)
                phase = doc['phases'][1]
                phase.update(business_started_ns=started, honest_submissions=[],
                             honest_history=[], independent_history_page_replay=[])
            with self.subTest(started=started):
                result = self.summarize(edit)
                self.assertFalse(result['original_gate_validated'])
                self.assertEqual(result['original_gate_validation_error'], 'CONFIRMATION_TARGET')
                phase = result['phases'][1]
                business = phase['business']
                self.assertEqual(business['required_signed_transactions'], 1)
                self.assertEqual(business['reported_independently_confirmed_in_window'], 0)
                self.assertEqual(business['unconfirmed'], 1)
                self.assertEqual(business['unknown'], 0)
                self.assertEqual(business['business_start_delay_ns'], started)
                self.assertFalse(business['business_started_before_original_window_end'])
                self.assertEqual(business['original_window_remaining_at_business_start_ns'], 0)
                self.assertEqual(business['pre_business_window_overrun_ns'], started-4_000_000_000)
                self.assertEqual(business['unconfirmed_latency_lower_bound_ns'], 0)
                self.assertIsNone(business['observed_success_latency_ns'])
                self.assertEqual(phase['signed_submit_ack']['attempts'], 0)
                self.assertEqual(phase['history_response']['attempts'], 0)

    def test_expired_business_start_keeps_unknown_confirmation_unknown(self):
        def edit(doc):
            self.fail_pressure(doc)
            phase = doc['phases'][1]
            phase.update(business_started_ns=4_000_000_001, honest_submissions=[],
                         honest_history=[], independent_history_page_replay=[])
            del phase['client_confirmed_transactions']
        business = self.summarize(edit)['phases'][1]['business']
        self.assertEqual(business['required_signed_transactions'], 1)
        self.assertEqual(business['unknown'], 1)
        self.assertIsNone(business['reported_independently_confirmed_in_window'])
        self.assertIsNone(business['unconfirmed'])
        self.assertIsNone(business['unconfirmed_latency_lower_bound_ns'])
        self.assertFalse(business['business_started_before_original_window_end'])

    def test_expired_business_start_cannot_claim_success_or_relax_window(self):
        for started in (4_000_000_000, 4_000_000_001):
            with self.subTest(started=started):
                with self.assertRaisesRegex(ValueError, 'CONFIRMATION_NATIVE_OBSERVATION'):
                    self.summarize(lambda doc: doc['phases'][1].update(business_started_ns=started))
        with self.assertRaisesRegex(ValueError, 'CONFIRMATION_OUTSIDE_ORIGINAL_WINDOW'):
            self.summarize(lambda doc: doc['phases'][1].update(requested_window_ns=30_000_000_000))

    def test_failed_and_late_calls_cannot_pollute_success_latency(self):
        def edit(doc):
            phase = doc['phases'][1]
            failed = dict(phase['honest_submissions'][0], status='error', started_ns=1,
                          ended_ns=3_000_000_001, elapsed_wall_ns=3_000_000_000,
                          returned_after_deadline=True, client_thread_cpu_ns=None)
            phase['honest_submissions'].append(failed)
        rows = self.summarize(edit)['phases'][1]['signed_submit_ack']
        self.assertEqual(rows['attempts'], 8)
        self.assertEqual(rows['successful_in_original_window'], 7)
        self.assertEqual(rows['failed_or_late'], 1)
        self.assertEqual(rows['successful_latency']['max_ns'], 5)
        self.assertIsNone(rows['successful_latency']['p95_ns'])
        self.assertIsNone(rows['successful_latency']['p99_ns'])
        self.assertIsNone(rows['failed_or_late_terminal_duration']['p99_ns'])
        self.assertEqual(rows['calling_thread_cpu']['missing_samples'], 1)

    def test_configured_deadline_alone_does_not_invent_observation_coverage(self):
        def edit(doc):
            self.fail_pressure(doc)
            doc['phases'][1]['independent_history_page_replay'] = []
        business = self.summarize(edit)['phases'][1]['business']
        self.assertFalse(business['lower_bound_reaches_original_window_end'])
        self.assertEqual(business['unconfirmed_latency_lower_bound_ns'], 165-10)

    def test_original_caller_elapsed_samples_can_follow_the_end_stamp(self):
        result = self.summarize(lambda doc: doc['phases'][0]['honest_submissions'][0].update(
            elapsed_wall_ns=8))
        distribution = result['phases'][0]['signed_submit_ack']['successful_latency']
        self.assertEqual(distribution['max_ns'], 8)
        self.assertIsNone(distribution['p95_ns'])
        self.assertIsNone(distribution['p99_ns'])

    def test_tail_quantiles_require_their_own_observed_sample_resolution(self):
        for count in (0, 1, 2, 19, 20, 99, 100):
            def edit(doc):
                phase = doc['phases'][0]
                row = phase['honest_heads'][0]
                phase['honest_heads'] = [dict(row, started_ns=10, ended_ns=10+value,
                                            elapsed_wall_ns=value, client_thread_cpu_ns=value)
                                        for value in range(1, count+1)]
            with self.subTest(samples=count):
                result = self.summarize(edit)
                rows = result['phases'][0]['head_response']
                for field in ('successful_latency', 'calling_thread_cpu'):
                    distribution = rows[field]
                    self.assertEqual(distribution['samples'], count)
                    self.assertEqual(distribution['min_ns'], 1 if count else None)
                    self.assertEqual(distribution['max_ns'], count if count else None)
                    self.assertEqual(distribution['minimum_samples'],
                                     {'p50': 2, 'p95': 20, 'p99': 100})
                    for percent, minimum in ((50, 2), (95, 20), (99, 100)):
                        expected = (count * percent + 99) // 100 if count >= minimum else None
                        self.assertEqual(distribution[f'p{percent}_ns'], expected)
                # Descriptive ranks never change the business-offer denominator
                # or confer a native tail-latency/network-capacity qualification.
                self.assertEqual(result['phases'][0]['business']['required_signed_transactions'], 1)
                self.assertFalse(result['tail_latency_qualified'])
                self.assertFalse(result['network_capacity_qualified'])

    def test_failed_or_missing_samples_cannot_unlock_successful_latency_tails(self):
        def edit(doc):
            phase = doc['phases'][0]
            row = phase['honest_heads'][0]
            phase['honest_heads'] = [dict(row, started_ns=10, ended_ns=10+value,
                                        elapsed_wall_ns=value,
                                        client_thread_cpu_ns=None if value == 100 else value,
                                        status='ok' if value <= 19 else 'error')
                                    for value in range(1, 101)]
        rows = self.summarize(edit)['phases'][0]['head_response']
        self.assertEqual(rows['attempts'], 100)
        self.assertEqual(rows['successful_in_original_window'], 19)
        self.assertEqual(rows['failed_or_late'], 81)
        self.assertIsNone(rows['successful_latency']['p95_ns'])
        self.assertIsNone(rows['successful_latency']['p99_ns'])
        self.assertEqual(rows['failed_or_late_terminal_duration']['p95_ns'], 96)
        self.assertIsNone(rows['failed_or_late_terminal_duration']['p99_ns'])
        self.assertEqual(rows['calling_thread_cpu']['missing_samples'], 1)
        self.assertEqual(rows['calling_thread_cpu']['samples'], 99)
        self.assertIsNone(rows['calling_thread_cpu']['p99_ns'])

    def test_malformed_metrics_and_changed_original_window_are_not_summarized(self):
        edits = [
            lambda doc: doc['phases'][1].update(client_confirmed_transactions=True),
            lambda doc: doc['phases'][1].update(requested_window_ns=8_000_000_000),
            lambda doc: doc['phases'][1]['honest_submissions'][0].update(client_thread_cpu_ns=True),
            lambda doc: doc['phases'][1]['honest_submissions'][0].update(elapsed_wall_ns=1),
            lambda doc: doc.update(schema='pon-native-pq-history-v6'),
        ]
        for edit in edits:
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                self.summarize(edit)


class CompleteConfirmationObservationTests(unittest.TestCase):
    """Synthetic accounting only; no request, runtime or performance is run."""

    def summarize(self, edit=lambda doc: None, **options):
        document = simulated_confirmation_report()
        edit(document)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text(json.dumps(document))
            return driver.summarize_confirmation_report(path, **options)

    @staticmethod
    def current_receiver(doc):
        captured = doc['phases'][0]['observations']
        captured.update(schema='public-v3-local-request-resource-observation-v4',
            cpu_includes_reactor_authentication_or_response_signing=True,
            cpu_includes_reactor_authentication=False,
            dispatch_cpu_includes_paid_body_decode=True,
            dispatch_cpu_includes_response_signing=True,
            phase_parent_links_are_inclusive=True, cpu_wait_is_outside_dispatch=True,
            monotonic_epoch_is_observer_local=True)
        for row in captured['records']:
            row.update(terminal_error_code=None, dispatch_error_code=None,
                dispatch_started=False, dispatch_accepted=None,
                dispatch_thread_cpu_ns=None, full_work_started=False,
                full_work_thread_cpu_ns=None, application_bytes_read=None,
                application_bytes_written=None,
                submit_phases=[dict(phase=name, started=False, completed=False,
                    accepted=None, error_code=None, started_ns=None, ended_ns=None,
                    wall_ns=None, thread_cpu_ns=None, parent_phase=PHASE_PARENTS_V4.get(name))
                    for name in PHASES_V4])
            for name in ('challenge_wait', 'grant_wait', 'paid_task_queue_wait', 'response_write'):
                row[name] = dict(started_ns=None, ended_ns=None, wall_ns=None,
                                 completed=False, accepted=None, error_code=None)
        return captured

    def test_default_v2_separates_five_products_and_keeps_unmeasured_products_unknown(self):
        result = self.summarize()
        self.assertEqual(result['schema'], 'trnm-original-confirmation-observation-v2')
        metrics = result['phases'][0]['product_metrics']
        self.assertEqual(set(metrics), {'confirmation', 'complete_release_download',
                                      'first_token', 'inference', 'model_net_benefit_per_cost'})
        self.assertEqual(metrics['confirmation']['finite_offer_transactions_per_second'], .25)
        self.assertIsNone(metrics['confirmation']['saturated_capacity_tps'])
        for name in set(metrics) - {'confirmation'}:
            self.assertEqual(metrics[name]['status'], 'not_observed_by_this_report')
            self.assertIsNone(metrics[name]['value'])

    def test_explicit_v1_reproduces_unchanged_historical_summary(self):
        result = self.summarize(observation_version=1)
        self.assertEqual(result['schema'], 'trnm-original-confirmation-observation-v1')
        # Captured from the pinned original implementation before this change.
        self.assertEqual(driver.digest(json.dumps(result, sort_keys=True, separators=(',', ':')).encode()),
                         '868038bb147c31963efaf6db6f83ca824fb46701815ca4d9f27de462400e6ea1')
        self.assertNotIn('product_metrics', result['phases'][0])

    def test_cli_selects_historical_schema_only_for_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text(json.dumps(simulated_confirmation_report()))
            for version in (1, 2):
                output = io.StringIO()
                with redirect_stdout(output):
                    status = driver.main(['--summarize-confirmation', str(path),
                                          '--observation-version', str(version)])
                self.assertEqual(status, 0)
                self.assertEqual(json.loads(output.getvalue())['schema'],
                                 f'trnm-original-confirmation-observation-v{version}')
            with patch.object(driver, 'run') as run, patch('sys.stderr', io.StringIO()), \
                    self.assertRaises(SystemExit) as error:
                driver.main(['--out', directory, '--observation-version', '1'])
            self.assertEqual(error.exception.code, 2)
            run.assert_not_called()

    def test_clock_keeps_initial_delay_without_inventing_receiver_clock_correlation(self):
        phase = self.summarize()['phases'][0]
        clock = phase['request_clock']
        self.assertEqual(clock['original_window_to_independent_confirmation_ns'], 1000)
        self.assertEqual(clock['business_start_to_independent_confirmation_ns'], 990)
        self.assertIsNone(clock['receiver_to_independent_confirmation_ns'])
        self.assertFalse(clock['receiver_and_client_epochs_correlated'])

    def test_missing_confirmation_never_produces_zero_latency_or_rate(self):
        def edit(doc):
            ConfirmationObservationTests.fail_pressure(doc)
            del doc['phases'][1]['client_confirmed_transactions']
        phase = self.summarize(edit)['phases'][1]
        self.assertIsNone(phase['request_clock']['original_window_to_independent_confirmation_ns'])
        self.assertIsNone(phase['product_metrics']['confirmation']['finite_offer_transactions_per_second'])

    def test_untrusted_client_error_text_is_retained_without_typing_it_as_cancellation(self):
        def edit(doc):
            row = doc['phases'][0]['honest_submissions'][0]
            row.update(status='error', error='PUBLIC_REQUEST_CANCELLED')
            doc['phases'][0]['honest_submissions'][1].update(status='refused',
                response={'value': {'error': 'PUBLIC_REQUEST_DEADLINE'}})
        detail = self.summarize(edit)['phases'][0]['signed_submit_ack']['outcome_detail']
        self.assertEqual(detail['status_counts'], {'ok': 5, 'refused': 1, 'error': 1})
        self.assertEqual(detail['raw_client_error_counts'], {'PUBLIC_REQUEST_CANCELLED': 1})
        self.assertEqual(detail['raw_refusal_error_counts'], {'PUBLIC_REQUEST_DEADLINE': 1})
        self.assertFalse(detail['diagnostic_text_is_typed_error'])

    def test_receiver_retains_cancel_timeout_unfinished_and_missing_outcomes_separately(self):
        def edit(doc):
            captured = self.current_receiver(doc)
            rows = captured['records']
            rows[0].update(dispatch_started=True, dispatch_accepted=True)
            rows[1].update(dispatch_started=True, dispatch_accepted=False,
                           dispatch_error_code='PUBLIC_REQUEST_CANCELLED')
            rows[2].update(terminal_error_code='PUBLIC_REQUEST_DEADLINE')
            rows[3].update(complete=False)
            del rows[4]['complete']
        detail = self.summarize(edit)['phases'][0]['receiver_requests']
        self.assertEqual(detail['dispatch_outcomes'], {'accepted': 1, 'rejected': 1, 'unknown': 13})
        self.assertEqual(detail['record_lifecycle'], {'closed': 13, 'unfinished': 1, 'unknown': 1})
        self.assertEqual(detail['typed_cancelled_records'], 1)
        self.assertEqual(detail['typed_deadline_records'], 1)
        self.assertEqual(detail['missing_terminal_error_slots'], 0)

    def test_receiver_dropped_records_remain_in_seen_denominator(self):
        def edit(doc):
            captured = self.current_receiver(doc)
            captured['records'].pop()
            captured['records_not_retained'] = 1
        detail = self.summarize(edit)['phases'][0]['receiver_requests']
        self.assertEqual((detail['accepted_connections_seen'], detail['retained_records'],
                          detail['records_not_retained']), (15, 14, 1))
        self.assertFalse(detail['all_seen_records_closed_and_retained'])
        self.assertIsNone(detail['unobserved_client_attempts'])

    def test_complete_record_does_not_erase_late_cancellation_after_dispatch(self):
        def edit(doc):
            row = self.current_receiver(doc)['records'][0]
            row.update(dispatch_started=True, dispatch_accepted=True,
                       terminal_error_code='PUBLIC_REQUEST_CANCELLED')
        detail = self.summarize(edit)['phases'][0]['receiver_requests']
        self.assertEqual(detail['dispatch_outcomes']['accepted'], 1)
        self.assertEqual(detail['typed_cancelled_records'], 1)
        self.assertFalse(detail['typed_causes_are_disjoint_outcomes'])

    def test_failed_and_unfinished_resource_samples_are_counted_without_nested_cpu_sum(self):
        def edit(doc):
            rows = self.current_receiver(doc)['records']
            rows[0].update(dispatch_started=True, dispatch_accepted=False,
                dispatch_thread_cpu_ns=7, full_work_started=True, full_work_thread_cpu_ns=5,
                application_bytes_read=90, application_bytes_written=10)
            rows[1].update(complete=False, dispatch_started=True, dispatch_thread_cpu_ns=None,
                          application_bytes_read=30, application_bytes_written=0)
        resources = self.summarize(edit)['phases'][0]['resource_coverage']
        cpu = resources['receiver_dispatch_thread_cpu_ns']
        self.assertEqual((cpu['known_count'], cpu['missing_count'], cpu['known_sum']), (1, 1, 7))
        self.assertEqual(resources['receiver_full_work_thread_cpu_ns']['known_sum'], 5)
        self.assertEqual(resources['application_bytes_read']['known_sum'], 120)
        self.assertEqual(resources['application_bytes_read']['missing_count'], 13)
        self.assertIsNone(resources['all_worker_cpu_ns'])
        self.assertIsNone(resources['physical_network_bytes'])
        self.assertIsNone(resources['disk_growth_bytes'])
        self.assertEqual(resources['request_peak_rss_bytes']['known_count'], 0)
        self.assertEqual(resources['request_peak_rss_bytes']['missing_count'], 15)

    def test_v2_cannot_report_timely_ack_when_deadline_flag_disagrees_with_real_elapsed(self):
        edit = lambda doc: doc['phases'][0]['honest_submissions'][0].update(
            elapsed_wall_ns=2_000_000_001, returned_after_deadline=False)
        with self.assertRaisesRegex(ValueError, 'CONFIRMATION_CALL_DEADLINE_FACT'):
            self.summarize(edit)
        # Historical shape remains replayable; the original strict gate still rejects it.
        legacy = self.summarize(edit, observation_version=1)
        self.assertFalse(legacy['original_gate_validated'])

    def test_missing_worker_cpu_keeps_original_sixteen_worker_denominator(self):
        def edit(doc):
            workers = doc['phases'][1]['attacks']
            workers.pop()
            workers[0]['calling_thread_cpu_ns'] = None
        cpu = self.summarize(edit)['phases'][1]['resource_coverage']['attacker_workers_calling_thread_cpu_ns']
        self.assertEqual((cpu['scheduled_workers'], cpu['observed_worker_records']), (16, 15))
        self.assertEqual((cpu['known_count'], cpu['missing_count']), (14, 2))
        self.assertEqual(cpu['known_sum'], 28)
        with self.assertRaisesRegex(ValueError, 'CONFIRMATION_ATTACKER_CPU_IDENTITY'):
            self.summarize(lambda doc: doc['phases'][1]['attacks'][1].update(worker=0))

    def test_invalid_version_counter_and_typed_error_are_rejected(self):
        for version in (True, 0, 3, '2'):
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, 'OBSERVATION_VERSION'):
                self.summarize(observation_version=version)
        for edit in (
            lambda doc: doc['phases'][0]['observations'].update(accepted_connections_seen=14),
            lambda doc: self.current_receiver(doc)['records'][0].update(terminal_error_code=True),
            lambda doc: self.current_receiver(doc)['records'][0].update(dispatch_thread_cpu_ns=True,
                                                                        dispatch_started=True),
        ):
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                self.summarize(edit)


class AttackAttemptObservationTests(unittest.TestCase):
    """Failed workload denominators are observations, never gate acceptance."""

    summarize = CompleteConfirmationObservationTests.summarize

    def test_repeated_hostile_packets_keep_every_call_and_nested_cpu(self):
        report = self.summarize()
        baseline, pressure = report['phases']
        empty = baseline['attacker_attempts']
        self.assertEqual((empty['scheduled_workers'], empty['recorded_attempts']), (0, 0))
        self.assertTrue(empty['all_scheduled_worker_call_lists_observed'])
        attacks = pressure['attacker_attempts']
        self.assertEqual((attacks['scheduled_workers'], attacks['observed_worker_records']), (16, 16))
        self.assertEqual((attacks['recorded_attempts'], attacks['submitted_client_calls_recorded']), (17, 17))
        self.assertEqual(attacks['submitted_status_counts'], {'ok': 0, 'refused': 17, 'error': 0})
        self.assertEqual(attacks['unique_recorded_packet_indices'], 16)
        self.assertEqual(attacks['repeated_recorded_packet_index_calls'], 1)
        self.assertEqual(attacks['calling_thread_cpu']['known_sum_ns'], 17)
        # This is the original worker total, not worker total plus nested calls.
        self.assertEqual(pressure['resource_coverage']['attacker_workers_calling_thread_cpu_ns']['known_sum'], 32)
        self.assertIsNone(attacks['unobserved_attempts'])

    def test_failed_late_exhausted_and_unknown_attempts_are_separate(self):
        def edit(doc):
            ConfirmationObservationTests.fail_pressure(doc)
            rows = doc['phases'][1]['attacks'][0]['calls']
            rows[0].update(status='error', error='PUBLIC_REQUEST_CANCELLED',
                started_ns=3_000_000_000, ended_ns=5_100_000_000,
                elapsed_wall_ns=2_100_000_000, returned_after_deadline=True,
                returned_after_window=True, client_thread_cpu_ns=None,
                recorded_request_bytes=None, packet_index=None)
            rows[1] = {'status': 'not_submitted_exhausted'}
            rows.append({})
        report = self.summarize(edit)
        self.assertFalse(report['original_gate_validated'])
        attacks = report['phases'][1]['attacker_attempts']
        self.assertEqual(attacks['recorded_attempts'], 18)
        self.assertEqual(attacks['submitted_client_calls_recorded'], 16)
        self.assertEqual(attacks['exhausted_without_submission'], 1)
        self.assertEqual(attacks['unknown_status_records'], 1)
        self.assertEqual(attacks['submitted_status_counts'], {'ok': 0, 'refused': 15, 'error': 1})
        self.assertEqual((attacks['returned_after_call_deadline'], attacks['returned_after_original_window']), (1, 1))
        self.assertEqual(attacks['calling_thread_cpu'], {'known_count': 15, 'missing_count': 1, 'known_sum_ns': 15})
        self.assertEqual(attacks['recorded_request_body_bytes']['missing_count'], 1)
        self.assertEqual(attacks['calls_without_packet_index'], 1)
        self.assertEqual(attacks['raw_client_error_counts'], {'PUBLIC_REQUEST_CANCELLED': 1})
        self.assertFalse(attacks['diagnostic_text_is_typed_error'])

    def test_missing_worker_and_call_list_do_not_become_empty_workloads(self):
        def edit(doc):
            workers = doc['phases'][1]['attacks']
            workers.pop()
            workers[0]['calls'] = None
        attacks = self.summarize(edit)['phases'][1]['attacker_attempts']
        self.assertEqual(attacks['missing_worker_records'], 1)
        self.assertEqual(attacks['worker_call_lists_observed'], 14)
        self.assertEqual(attacks['worker_call_lists_unavailable'], 2)
        self.assertEqual(attacks['recorded_attempts'], 14)
        self.assertFalse(attacks['all_scheduled_worker_call_lists_observed'])
        self.assertIsNone(attacks['unobserved_attempts'])
        absent = self.summarize(lambda doc: doc['phases'][1].update(attacks=None))['phases'][1]['attacker_attempts']
        self.assertEqual(absent['missing_worker_records'], 16)
        self.assertEqual(absent['worker_call_lists_unavailable'], 16)
        self.assertFalse(absent['all_scheduled_worker_call_lists_observed'])
        self.assertIsNone(absent['calling_thread_cpu']['known_sum_ns'])

    def test_missing_call_clock_does_not_discard_status_or_become_zero_duration(self):
        def edit(doc):
            doc['phases'][1]['attacks'][0]['calls'][0].pop('ended_ns')
        attacks = self.summarize(edit)['phases'][1]['attacker_attempts']
        self.assertEqual(attacks['submitted_client_calls_recorded'], 17)
        self.assertEqual((attacks['calls_with_complete_timing'], attacks['calls_with_unknown_timing']), (16, 1))

    def test_partial_clocks_keep_independent_late_flags_and_missing_flag_counts(self):
        def edit(doc):
            rows = doc['phases'][1]['attacks'][0]['calls']
            rows[0].update(started_ns=None, ended_ns=5_100_000_000,
                elapsed_wall_ns=2_100_000_000, returned_after_deadline=True,
                returned_after_window=True)
            rows[1].pop('returned_after_deadline')
        report = self.summarize(edit)
        self.assertFalse(report['original_gate_validated'])
        attacks = report['phases'][1]['attacker_attempts']
        self.assertEqual((attacks['calls_with_complete_timing'], attacks['calls_with_unknown_timing']), (15, 2))
        self.assertEqual((attacks['returned_after_call_deadline'], attacks['returned_after_original_window']), (1, 1))
        self.assertEqual(attacks['return_flag_coverage'], {
            'returned_after_call_deadline': {'known_count': 16, 'missing_count': 1},
            'returned_after_original_window': {'known_count': 17, 'missing_count': 0}})

    def test_unknown_status_keeps_costs_and_clocks_without_claiming_submission(self):
        def edit(doc):
            row = doc['phases'][1]['attacks'][0]['calls'][0]
            row.pop('status')
            row.update(client_thread_cpu_ns=1000, recorded_request_bytes=256,
                started_ns=None, ended_ns=5_100_000_000, elapsed_wall_ns=2_100_000_000,
                returned_after_deadline=True, returned_after_window=True,
                error='PUBLIC_CLIENT_DEADLINE')
        report = self.summarize(edit)
        self.assertFalse(report['original_gate_validated'])
        attacks = report['phases'][1]['attacker_attempts']
        self.assertEqual((attacks['recorded_attempts'], attacks['submitted_client_calls_recorded']), (17, 16))
        self.assertEqual(attacks['calling_thread_cpu']['known_sum_ns'], 16)
        unknown = attacks['unknown_status_observations']
        self.assertEqual(unknown['record_count'], 1)
        self.assertEqual(unknown['calling_thread_cpu'], {'known_count': 1, 'missing_count': 0, 'known_sum_ns': 1000})
        self.assertEqual(unknown['recorded_request_body_bytes'], {'known_count': 1, 'missing_count': 0, 'known_sum': 256})
        self.assertEqual((unknown['records_with_complete_timing'], unknown['records_with_unknown_timing']), (0, 1))
        self.assertEqual((unknown['returned_after_call_deadline'], unknown['returned_after_original_window']), (1, 1))
        self.assertEqual(unknown['raw_client_error_counts'], {'PUBLIC_CLIENT_DEADLINE': 1})

    def test_reached_original_attempt_cap_is_retained_without_acceptance(self):
        def edit(doc):
            worker = doc['phases'][1]['attacks'][0]
            worker.update(calls=[copy.deepcopy(worker['calls'][0]) for _ in range(1024)],
                          attempt_cap_reached=True)
        report = self.summarize(edit)
        attacks = report['phases'][1]['attacker_attempts']
        self.assertFalse(report['original_gate_validated'])
        self.assertEqual(attacks['recorded_attempts'], 1039)
        self.assertEqual(attacks['workers_reporting_attempt_cap_reached'], 1)
        self.assertEqual(attacks['repeated_recorded_packet_index_calls'], 1023)
        with self.assertRaisesRegex(ValueError, 'ATTACK_ATTEMPT_BOUND'):
            def too_many(doc):
                edit(doc)
                doc['phases'][1]['attacks'][0]['calls'].append({})
            self.summarize(too_many)

    def test_contradictory_attack_clocks_and_noncanonical_fields_are_refused(self):
        mutations = (
            lambda row: row.update(elapsed_wall_ns=2_000_000_001),
            lambda row: row.update(started_ns=20, ended_ns=10),
            lambda row: row.update(ended_ns=4_000_000_001, elapsed_wall_ns=4_000_000_001,
                                   returned_after_deadline=True, returned_after_window=False),
            lambda row: row.update(packet_index=True),
            lambda row: row.update(client_thread_cpu_ns=-1),
            lambda row: row.update(status='silently_filtered'),
            lambda row: row.update(started_ns=None, returned_after_deadline=1),
            lambda row: row.update(started_ns=None, elapsed_wall_ns=2_000_000_001),
            lambda row: row.update(started_ns=None, ended_ns=4_000_000_001,
                                   returned_after_window=False),
            lambda row: row.update(status=None, client_thread_cpu_ns=-1),
        )
        for mutate in mutations:
            def edit(doc):
                mutate(doc['phases'][1]['attacks'][0]['calls'][0])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.summarize(edit)

    def test_historical_v1_has_no_new_attacker_fields(self):
        report = self.summarize(observation_version=1)
        self.assertNotIn('attacker_attempts', report['phases'][1])
        self.assertEqual(driver.digest(json.dumps(report, sort_keys=True, separators=(',', ':')).encode()),
                         '868038bb147c31963efaf6db6f83ca824fb46701815ca4d9f27de462400e6ea1')


class ReceiveClockObservationTests(unittest.TestCase):
    """One synthetic local epoch and peer claims, never authenticated execution."""

    summarize = CompleteConfirmationObservationTests.summarize

    @staticmethod
    def receive_clock(doc):
        captured = CompleteConfirmationObservationTests.current_receiver(doc)
        phase = doc['phases'][0]
        offset = 100
        expected = driver.H('public-request-body-v3', json.dumps(
            {'op': 'submit', 'packet': doc['signed_honest_packets'][0]}, separators=(',', ':')).encode())
        phase['business_receive_clock'] = dict(schema='public-v3-business-receive-clock-v1',
            clock_scope='same-process-monotonic-observer', traffic_epoch_in_observer_ns=offset,
            first_business_packet_body_digest=expected.hex(),
            independent_confirmation_in_observer_ns=offset+phase['confirmation_ended_ns'],
            request_binding_stage='hello-claimed-body-digest', has_control_authority=False)
        for index, row in enumerate(captured['records']):
            row.update(connection_id=index+1, operation=2, body_digest=[index+1]*32,
                connection_closed=True, task_created=False, task_closed=False,
                lifecycle=dict(schema='public-v3-request-lifecycle-v1', accepted_ns=offset+200+index,
                    connection_closed_ns=offset+1200+index, task_closed_ns=None,
                    clock_is_observer_local=True, has_control_authority=False))
        # Deliberately out of order: earliest receive must include a failed retry.
        for index, at in ((0, offset+500), (1, offset+100)):
            row = captured['records'][index]
            row.update(operation=1, body_digest=list(expected))
            row['lifecycle']['accepted_ns'] = at
        captured['records'][1].update(dispatch_started=True, dispatch_accepted=False,
            dispatch_error_code='PUBLIC_REQUEST_CANCELLED')
        return phase

    def test_earliest_matching_failed_retry_is_included_in_correlated_receive_latency(self):
        phase = self.summarize(self.receive_clock)['phases'][0]
        clock = phase['request_clock']
        self.assertTrue(clock['receiver_and_client_epochs_correlated'])
        self.assertEqual(clock['receiver_to_independent_confirmation_ns'], 900)
        detail = clock['business_receive_observation']
        self.assertEqual(detail['matched_claim_records'], 2)
        self.assertEqual(detail['earliest_matched_claim_received_ns'], 200)
        self.assertEqual(detail['observed_matched_claim_to_confirmation_ns'], 900)
        self.assertTrue(detail['exact_claim_cohort_covered'])
        self.assertFalse(detail['body_or_sender_authenticated_by_clock'])
        self.assertFalse(detail['has_control_authority'])

    def test_unknown_prehello_or_dropped_record_prevents_shorter_exact_claim_latency(self):
        for kind in ('prehello', 'dropped', 'missing-lifecycle', 'failed-observation'):
            def edit(doc):
                phase = self.receive_clock(doc)
                captured = phase['observations']
                if kind == 'prehello':
                    captured['records'][2].update(operation=None, body_digest=None)
                elif kind == 'dropped':
                    captured['records'].pop()
                    captured['records_not_retained'] = 1
                elif kind == 'missing-lifecycle':
                    del captured['records'][2]['lifecycle']
                else:
                    captured['records'][2].update(observation_failed=True, complete=False)
                    captured['measurement_failures'] = 1
            with self.subTest(kind=kind):
                clock = self.summarize(edit)['phases'][0]['request_clock']
                self.assertIsNone(clock['receiver_to_independent_confirmation_ns'])
                detail = clock['business_receive_observation']
                self.assertEqual(detail['observed_matched_claim_to_confirmation_ns'], 900)
                self.assertFalse(detail['exact_claim_cohort_covered'])

    def test_matching_payload_with_wrong_operation_is_not_a_business_receive(self):
        def edit(doc):
            phase = self.receive_clock(doc)
            phase['observations']['records'][1]['operation'] = 2
        detail = self.summarize(edit)['phases'][0]['request_clock']['business_receive_observation']
        self.assertEqual(detail['matched_claim_records'], 1)
        self.assertEqual(detail['observed_matched_claim_to_confirmation_ns'], 500)

    def test_wrong_body_digest_offset_or_promoted_clock_scope_is_rejected(self):
        mutations = (
            lambda phase: phase['business_receive_clock'].update(first_business_packet_body_digest='a'*64),
            lambda phase: phase['business_receive_clock'].update(independent_confirmation_in_observer_ns=1101),
            lambda phase: phase['business_receive_clock'].update(traffic_epoch_in_observer_ns=None),
            lambda phase: phase['business_receive_clock'].update(has_control_authority=True),
            lambda phase: phase['business_receive_clock'].update(clock_scope='remote-wall-clock'),
            lambda phase: phase['business_receive_clock'].update(request_binding_stage='authenticated-body'),
            lambda phase: phase['business_receive_clock'].update(another_epoch=1),
        )
        for mutation in mutations:
            def edit(doc):
                mutation(self.receive_clock(doc))
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'RECEIVE_CLOCK'):
                self.summarize(edit)

    def test_lifecycle_owner_clocks_are_ordered_only_after_receive_not_each_other(self):
        def edit(doc):
            rows = self.receive_clock(doc)['observations']['records']
            for index, task_end in ((0, 700), (1, 2000)):
                rows[index].update(task_created=True, task_closed=True)
                rows[index]['lifecycle']['task_closed_ns'] = task_end
        result = self.summarize(edit)['phases'][0]['request_clock']
        self.assertEqual(result['receiver_to_independent_confirmation_ns'], 900)
        for mutation in (
            lambda row: row['lifecycle'].update(connection_closed_ns=0),
            lambda row: row['lifecycle'].update(task_closed_ns=900),
            lambda row: row.update(connection_closed=False),
            lambda row: row['lifecycle'].update(accepted_ns=None),
            lambda row: row['lifecycle'].update(clock_is_observer_local=False),
            lambda row: row['lifecycle'].update(accepted_ns=True),
        ):
            def bad(doc):
                mutation(self.receive_clock(doc)['observations']['records'][0])
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'LIFECYCLE'):
                self.summarize(bad)

    def test_live_matching_task_keeps_receive_diagnostic_without_claiming_complete_coverage(self):
        def edit(doc):
            row = self.receive_clock(doc)['observations']['records'][1]
            row.update(task_created=True, task_closed=False, complete=False)
        clock = self.summarize(edit)['phases'][0]['request_clock']
        self.assertIsNone(clock['receiver_to_independent_confirmation_ns'])
        self.assertEqual(clock['business_receive_observation']['observed_matched_claim_to_confirmation_ns'], 900)

    def test_missing_confirmation_and_overflow_never_become_a_measured_zero(self):
        def missing(doc):
            phase = self.receive_clock(doc)
            phase.update(client_confirmed_transactions=0, client_confirmed_before_original_window_end=False,
                confirmation_ended_ns=None, client_confirmation_latency_ns=None, independent_client_confirmation=None)
            phase['business_receive_clock']['independent_confirmation_in_observer_ns'] = None
        def overflow(doc):
            phase = self.receive_clock(doc)
            phase['business_receive_clock'].update(traffic_epoch_in_observer_ns=2**64-1,
                                                  independent_confirmation_in_observer_ns=None)
        for edit in (missing, overflow):
            with self.subTest(edit=edit):
                clock = self.summarize(edit)['phases'][0]['request_clock']
                self.assertIsNone(clock['receiver_to_independent_confirmation_ns'])
                self.assertIsNone(clock['business_receive_observation']['observed_matched_claim_to_confirmation_ns'])

    def test_ok_final_observation_and_late_confirmation_do_not_become_successful_latency(self):
        for late in (False, True):
            def edit(doc):
                phase = self.receive_clock(doc)
                phase.update(client_confirmed_transactions=0, client_confirmed_before_original_window_end=False)
                if late:
                    phase.update(confirmation_ended_ns=4_000_000_001,
                                 client_confirmation_latency_ns=4_000_000_001-phase['business_started_ns'])
                    phase['business_receive_clock']['independent_confirmation_in_observer_ns'] = 4_000_000_101
                else:
                    phase['independent_client_confirmation']['confirmed'] = False
            with self.subTest(late=late):
                clock = self.summarize(edit)['phases'][0]['request_clock']
                detail = clock['business_receive_observation']
                self.assertIsNotNone(detail['final_observation_in_observer_ns'])
                self.assertIsNotNone(detail['observed_matched_claim_to_final_observation_ns'])
                self.assertFalse(detail['confirmation_observed_in_original_window'])
                self.assertIsNone(detail['observed_matched_claim_to_confirmation_ns'])
                self.assertIsNone(clock['receiver_to_independent_confirmation_ns'])

    def test_failed_receive_clock_retains_unknown_instead_of_zero(self):
        def edit(doc):
            phase = self.receive_clock(doc)
            row = phase['observations']['records'][1]
            row.update(observation_failed=True, complete=False)
            row['lifecycle']['accepted_ns'] = None
            phase['observations']['measurement_failures'] = 1
        clock = self.summarize(edit)['phases'][0]['request_clock']
        detail = clock['business_receive_observation']
        self.assertEqual(detail['matching_claims_without_receive_clock'], 1)
        self.assertEqual(detail['earliest_matched_claim_received_ns'], 600)
        self.assertEqual(detail['observed_matched_claim_to_confirmation_ns'], 500)
        self.assertIsNone(clock['receiver_to_independent_confirmation_ns'])

    def test_duplicate_receiver_identity_or_malformed_digest_cannot_supply_coverage(self):
        for mutation in (
            lambda rows: rows[1].update(connection_id=1),
            lambda rows: rows[1].update(body_digest=[True]*32),
            lambda rows: rows[1].update(body_digest=[1]*31),
        ):
            def edit(doc):
                mutation(self.receive_clock(doc)['observations']['records'])
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'RECEIVE_CLOCK'):
                self.summarize(edit)


class ConfirmedObservationBindingTests(unittest.TestCase):
    """Reject contradictory positive claims without requiring the other phase."""

    summarize = CompleteConfirmationObservationTests.summarize

    def test_wrong_required_transaction_context_or_reorg_cannot_supply_positive_metrics(self):
        for field, value in (
                ('reorged', True), ('reorged', None), ('transaction', '00'*32),
                ('network', '00'*32), ('parameters', '00'*32), ('genesis', '00'*32),
                ('included_block', '00'*32), ('observed_tip', '00'*32),
                ('included_height', 2), ('observed_height', 8),
                ('work_delta', '00'*64), ('required_work_delta', '00'*64)):
            def edit(doc):
                phase = ReceiveClockObservationTests.receive_clock(doc)
                phase['independent_client_confirmation'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.summarize(edit)

    def test_binding_is_required_even_without_optional_receive_clock(self):
        for field, value in (('reorged', True), ('transaction', '00'*32), ('network', '00'*32)):
            def edit(doc):
                doc['phases'][0]['independent_client_confirmation'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.summarize(edit)
        with self.assertRaises(ValueError):
            self.summarize(lambda doc: doc['phases'][0]['independent_final_confirmation_stage'].update(
                observation_returned=False))

    def test_unreturned_missing_or_contradictory_final_stage_cannot_supply_confirmation(self):
        mutations = (
            lambda phase: phase['independent_final_confirmation_stage'].update(observation_returned=False),
            lambda phase: phase.update(independent_final_confirmation_stage=None),
            lambda phase: phase['independent_final_confirmation_stage'].update(confirmation_started_ns=1001),
            lambda phase: phase['independent_final_confirmation_stage'].update(confirmation_started_ns=100,
                confirmation_wall_ns=68),
            lambda phase: phase['independent_final_confirmation_stage'].update(confirmation_ended_ns=1001,
                confirmation_wall_ns=834),
            lambda phase: phase['independent_final_confirmation_stage'].update(confirmation_wall_ns=2),
            lambda phase: phase['independent_final_confirmation_stage'].update(clock_scope='remote-clock'),
        )
        for mutation in mutations:
            def edit(doc):
                mutation(ReceiveClockObservationTests.receive_clock(doc))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.summarize(edit)

    def test_passing_baseline_keeps_confirmed_rate_when_original_pressure_phase_fails(self):
        def edit(doc):
            ReceiveClockObservationTests.receive_clock(doc)
            ConfirmationObservationTests.fail_pressure(doc)
        result = self.summarize(edit)
        self.assertFalse(result['original_gate_validated'])
        baseline, pressure = result['phases']
        self.assertEqual(baseline['request_clock']['receiver_to_independent_confirmation_ns'], 900)
        self.assertEqual(baseline['product_metrics']['confirmation']['finite_offer_transactions_per_second'], .25)
        self.assertEqual(pressure['product_metrics']['confirmation']['finite_offer_transactions_per_second'], 0)

    def test_positive_binding_does_not_rewrite_explicit_v1_failed_readback(self):
        for mutation in (
            lambda phase: phase['independent_client_confirmation'].update(reorged=True),
            lambda phase: phase['independent_client_confirmation'].update(transaction='00'*32),
            lambda phase: phase['independent_client_confirmation'].update(network='00'*32),
            lambda phase: phase['independent_final_confirmation_stage'].update(observation_returned=False),
        ):
            def edit(doc):
                mutation(ReceiveClockObservationTests.receive_clock(doc))
            with self.subTest(mutation=mutation):
                legacy = self.summarize(edit, observation_version=1)
                self.assertEqual(legacy['schema'], 'trnm-original-confirmation-observation-v1')
                self.assertFalse(legacy['original_gate_validated'])
                self.assertNotIn('product_metrics', legacy['phases'][0])
                self.assertEqual(legacy['phases'][0]['business'][
                    'independent_confirmed_transactions_per_window_second'], .25)


class ConfirmationReportTests(unittest.TestCase):
    def validate(self, edit=lambda doc: None):
        document = simulated_confirmation_report()
        edit(document)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text(json.dumps(document))
            return driver.validate_confirmation_report(path)

    def test_synthetic_metadata_is_consistent_without_claiming_native_execution(self):
        result = self.validate()
        self.assertTrue(result['finite_target_met'])
        self.assertEqual([phase['attacks'] for phase in result['phases']], [0, 17])
        self.assertIn('no independent work/state oracle', result['scope'])

    def test_summary_flags_cannot_promote_scope_or_replace_success(self):
        for field, value in [('finite_target_met', False), ('finite_target_met', 1),
                             ('invariant_target_met', False), ('production_activation', True),
                             ('strongest_honest_producer_used', True), ('work_profile_qualified', True)]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.validate(lambda doc: doc.update({field: value}))

    def test_same_task_target_and_original_window_are_required(self):
        for field, value in [('task', '00'*32), ('target', '01'*32),
                             ('requested_window_ns', 8_000_000_000),
                             ('confirmation_ended_ns', 4_000_000_000),
                             ('client_confirmed_transactions', 0)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(lambda doc: doc['phases'][1].update({field: value}))

    def test_per_page_native_replay_evidence_cannot_be_forged_or_erased(self):
        mutations = [
            lambda d: d['phases'][1].pop('independent_history_page_replay'),
            lambda d: d['phases'][1]['independent_history_page_replay'].pop(),
            lambda d: d['phases'][1]['independent_history_page_replay'][0].update(history_call_index=1),
            lambda d: d['phases'][1]['independent_history_page_replay'][0].update(prior_after='00'*32),
            lambda d: d['phases'][1]['independent_history_page_replay'][0].update(next_after='00'*32),
            lambda d: d['phases'][1]['independent_history_page_replay'][0].update(replay_accepted=False),
            lambda d: d['phases'][1]['independent_history_page_replay'][0].update(replay_started_ns=99),
            lambda d: d['phases'][1]['independent_history_page_replay'][0].update(replay_ended_ns=99),
            lambda d: d['phases'][1]['independent_history_page_replay'][0].update(replay_wall_ns=9),
            lambda d: d['phases'][1]['independent_history_page_replay'][0].update(clock_scope='whole host CPU'),
            lambda d: d['phases'][1].update(independent_final_confirmation_stage=None),
            lambda d: d['phases'][1]['independent_final_confirmation_stage'].update(confirmation_started_ns=99),
            lambda d: d['phases'][1]['independent_final_confirmation_stage'].update(observation_returned=False),
            lambda d: d['phases'][1]['independent_final_confirmation_stage'].update(
                confirmation_thread_cpu_ns=1000),
        ]
        for edit in mutations:
            with self.subTest(edit=edit), self.assertRaisesRegex(ValueError, 'CONFIRMATION_REPLAY'):
                self.validate(edit)
        # A boolean is rejected by the shared numeric grammar before the
        # stage-specific consistency check; retain that exact early refusal.
        with self.assertRaisesRegex(ValueError, '^CONFIRMATION_NUMBER$'):
            self.validate(lambda d: d['phases'][1]['independent_history_page_replay'][0].update(
                replay_thread_cpu_ns=True))

    def test_independent_confirmation_cannot_change_identity_or_authority(self):
        for field, value in [('transaction', '00'*32), ('included_block', '00'*32),
                             ('depth', 5), ('work_delta', '00'*64),
                             ('execution_authority', True), ('finalized', True), ('confirmed', False)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(lambda doc: doc['phases'][1]['independent_client_confirmation'].update({field: value}))

    def test_history_bytes_and_cursor_must_match_submitted_sequence(self):
        for field, value in [('after', '00'*32), ('next', '00'*32), ('packets', []), ('complete', True)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(lambda doc: doc['phases'][1]['honest_history'][0]['response']['value'].update({field: value}))

    def test_overlap_cannot_be_inferred_from_only_a_positive_summary(self):
        for field in ['overlapping_false_calls', 'completed_false_calls_before_business',
                      'completed_false_calls_at_confirmation']:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(lambda doc: doc['phases'][1].update({field: 0}))

    def test_late_call_and_accepted_invalid_input_are_preserved_failures(self):
        with self.assertRaises(ValueError):
            self.validate(lambda doc: doc['phases'][1]['honest_submissions'][0].update(returned_after_window=True))
        with self.assertRaises(ValueError):
            self.validate(lambda doc: doc['phases'][1]['attacks'][0]['calls'][0].update(status='ok'))

    def test_cost_unknown_and_unfinished_work_cannot_be_relabeled_complete(self):
        for field, value in [('mutation_cpu_charged_ns', 21), ('work_finished', 7),
                             ('mutation_cpu_clock_failures', 1)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(lambda doc: doc['phases'][1]['service']['metrics'].update({field: value}))
        with self.assertRaises(ValueError):
            self.validate(lambda doc: doc['phases'][1].update(attacker_workers_cpu_ns=None))

    def test_dropped_observations_and_native_verification_errors_cannot_pass(self):
        with self.assertRaises(ValueError):
            self.validate(lambda doc: doc['phases'][1]['observations'].update(records_not_retained=1))
        with self.assertRaises(ValueError):
            self.validate(lambda doc: doc['phases'][1].update(verification_errors=['retained error']))

    def test_call_duration_cannot_hide_a_late_timestamp_interval(self):
        with self.assertRaisesRegex(ValueError, 'CONFIRMATION_CALL'):
            self.validate(lambda doc: doc['phases'][1]['honest_submissions'][0].update(
                started_ns=0, ended_ns=3_000_000_000, elapsed_wall_ns=10,
                returned_after_deadline=False))

    def test_pre_business_counter_cannot_count_only_later_completed_calls(self):
        def edit(doc):
            phase = doc['phases'][1]
            phase['attacks'][0]['calls'][0].update(ended_ns=15, elapsed_wall_ns=15)
            phase['overlapping_false_calls'] = 17
        with self.assertRaisesRegex(ValueError, 'CONFIRMATION_COMPLETION_COUNTER'):
            self.validate(edit)

    def test_submission_and_history_chronology_cannot_follow_confirmation(self):
        def late_submissions(doc):
            for row in doc['phases'][1]['honest_submissions']:
                row.update(started_ns=row['started_ns']+2000, ended_ns=row['ended_ns']+2000)
        for edit in [late_submissions,
                     lambda doc: doc['phases'][1]['honest_submissions'][0].update(
                         started_ns=0, ended_ns=5, elapsed_wall_ns=5),
                     lambda doc: doc['phases'][1]['honest_submissions'][1].update(
                         started_ns=31, ended_ns=41, elapsed_wall_ns=10),
                     lambda doc: doc['phases'][1]['honest_history'][0].update(
                         started_ns=2000, ended_ns=2005),
                     lambda doc: doc['phases'][1]['honest_history'][0].update(
                         started_ns=30, ended_ns=35)]:
            with self.subTest(edit=edit), self.assertRaisesRegex(ValueError, 'CONFIRMATION_BUSINESS_CHRONOLOGY'):
                self.validate(edit)

    def test_compact_request_indices_hashes_and_lengths_bind_exact_retained_packets(self):
        for lane in ['honest_submissions', 'honest_heads', 'attacks']:
            for field, value in [('packet_index', 99), ('recorded_request_bytes', 1),
                                 ('recorded_request_digest', '00'*32)]:
                def edit(doc):
                    row = (doc['phases'][1]['attacks'][0]['calls'][0] if lane == 'attacks'
                           else doc['phases'][1][lane][0])
                    row.update({field: value})
                with self.subTest(lane=lane, field=field), self.assertRaisesRegex(
                        ValueError, 'CONFIRMATION_REQUEST_BINDING'):
                    self.validate(edit)
        with self.assertRaisesRegex(ValueError, 'CONFIRMATION_REQUEST_BINDING'):
            self.validate(lambda doc: doc['phases'][1]['honest_history'][0]['request'].update(after='00'*32))

    def test_actual_construction_packet_and_trial_metadata_cannot_change_under_same_header(self):
        edits = [
            lambda doc: doc['from_zero_construction'][0].update(
                packet=doc['from_zero_construction'][1]['packet']),
            lambda doc: doc['from_zero_construction'][0].update(status='exhausted'),
            lambda doc: doc['from_zero_construction'][0].update(packet=None),
            lambda doc: doc['from_zero_construction'][0].update(challenge='00'*32),
            lambda doc: doc['from_zero_construction'][0].update(winner_nonce=99),
            lambda doc: doc['from_zero_construction'][0]['attempts'][0].update(ticket='00'*32),
            lambda doc: doc['from_zero_construction'][0]['attempts'][0].update(target_hit=1),
            lambda doc: doc['phases'][1]['attacks'][0]['calls'][0].update(status='not_submitted_exhausted'),
        ]
        for edit in edits:
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                self.validate(edit)

    def test_failed_work_count_cannot_exceed_finished_work_or_erase_honest_verifications(self):
        for failed in [10000, 18]:
            with self.subTest(failed=failed), self.assertRaisesRegex(ValueError, 'CONFIRMATION_WORK_CLOSURE'):
                self.validate(lambda doc: doc['phases'][1]['service']['metrics'].update(work_failed=failed))

    def test_malformed_nested_objects_fail_with_structured_value_error(self):
        edits = [
            lambda doc: doc['phases'].__setitem__(0, []),
            lambda doc: doc['phases'][1]['attacks'].__setitem__(0, None),
            lambda doc: doc['phases'][1]['attacks'][0]['calls'].__setitem__(0, None),
            lambda doc: doc['phases'][1]['honest_submissions'].__setitem__(0, []),
            lambda doc: doc['phases'][1]['honest_history'][0].update(response=[]),
            lambda doc: doc['phases'][1]['honest_heads'].__setitem__(0, None),
            lambda doc: doc['phases'][1]['observations']['records'].__setitem__(0, []),
            lambda doc: doc['from_zero_construction'][0]['attempts'].__setitem__(0, []),
        ]
        for edit in edits:
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                self.validate(edit)

    def test_process_acquisition_cpu_preserves_unknown_and_original_scope(self):
        self.assertNotIn('honest_chain_process_cpu_ns', self.validate())
        scope = 'synthetic process-clock field; not measured native CPU or per-actor attribution'
        for cpu in [None, 42]:
            with self.subTest(cpu=cpu):
                result = self.validate(lambda doc: doc.update(
                    honest_chain_process_cpu_ns=cpu, honest_chain_process_cpu_scope=scope))
                self.assertEqual(result['honest_chain_process_cpu_ns'], cpu)
                self.assertEqual(result['honest_chain_process_cpu_scope'], scope)
        for fields in [dict(honest_chain_process_cpu_ns=True, honest_chain_process_cpu_scope=scope),
                       dict(honest_chain_process_cpu_ns=42),
                       dict(honest_chain_process_cpu_ns=42, honest_chain_process_cpu_scope='')]:
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.validate(lambda doc: doc.update(fields))


if __name__ == '__main__':
    unittest.main(verbosity=2)
