#!/usr/bin/env python3
"""Synthetic reader boundaries only; these tests supply no native campaign evidence."""
import argparse
import copy
from contextlib import closing, redirect_stdout
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import check_pon_identity_churn as reader
import run_pon_identity_churn as collector

ACTUAL_CONTROL = None
ACTUAL_SMALL_CAMPAIGN = None
ACTUAL_V2_ACQUISITION = None
ACTUAL_V2_DESCRIPTOR = None
ACTUAL_CLAIM_DEBUG_BINARIES = []
ACTUAL_DESCENDANT_FD_CONTROL = None
ACTUAL_V2_FINITE_CAMPAIGN = None


def cpu_flow(paid=2_000_000_000, refill=0, owners=0):
    remaining = reader.BURST + refill - paid
    return dict(schema='public-v3-local-actual-cpu-flow-v1', initial_credit_ns=reader.BURST,
        credited_refill_ns=refill, discarded_refill_ns=0, booked_reservation_ns=owners * reader.RESERVE,
        live_debited_cpu_ns=paid, settlement_residual_cpu_ns=0, settled_full_cpu_ns=paid,
        unsettled_known_live_cpu_ns=0, paid_cpu_debit_ns=paid, settlement_discard_ns=0,
        remaining_paid_credit_ns=remaining, balance_identity_verified=True,
        stored_credit_ns=remaining - owners * reader.RESERVE, live_owners=owners)


def sample(start=0, end=0, paid=2_000_000_000, age=0):
    actual = cpu_flow(paid)
    offered = age * reader.REFILL // reader.SECOND
    projected = min(actual['stored_credit_ns'] + offered, reader.BURST)
    return dict(observation_started_ns=start, observation_ended_ns=end,
        credit_freshness=dict(schema='public-v3-local-cpu-credit-freshness-v1',
            watermark_age_ns=age, actual_flow=actual,
            projected_credited_refill_ns=projected - actual['stored_credit_ns'],
            projected_discarded_refill_ns=actual['stored_credit_ns'] + offered - projected,
            projected_stored_credit_ns=projected, projected_paid_credit_ns=projected,
            projected_scalar_start_eligible=projected >= reader.RESERVE))


class ConservationTests(unittest.TestCase):
    def test_known_closed_owner_conserves_actual_cpu(self):
        self.assertEqual(reader.flow(cpu_flow(), settled=True)['paid_cpu_debit_ns'], reader.BURST)

    def test_summary_true_cannot_override_bad_or_unknown_cpu(self):
        for key, value in [('paid_cpu_debit_ns', 1), ('booked_reservation_ns', 1),
                           ('stored_credit_ns', None), ('settled_full_cpu_ns', 0),
                           ('live_owners', True), ('initial_credit_ns', 0),
                           ('balance_identity_verified', False)]:
            with self.subTest(key=key):
                row = cpu_flow()
                row[key] = value
                with self.assertRaises(ValueError):
                    reader.flow(row, settled=True)

    def test_real_reservation_does_not_count_as_paid_cpu(self):
        row = cpu_flow(paid=1_950_000_000, owners=1)
        self.assertEqual(reader.flow(row)['stored_credit_ns'], -50_000_000)
        with self.assertRaises(ValueError):
            reader.flow(row, settled=True)

    def test_counter_reset_is_rejected_even_with_self_consistent_balance(self):
        with self.assertRaisesRegex(ValueError, 'reset'):
            reader.monotone(cpu_flow(paid=2_200_000_000, refill=200_000_000), cpu_flow())


class CoverageTests(unittest.TestCase):
    def test_credit_upper_bound_proves_only_finite_future_interval(self):
        self.assertEqual(reader.depletion_interval(sample()), (0, 399_999_999))
        self.assertEqual(reader.depletion_interval(sample(start=0, end=100_000_000)),
                         (100_000_000, 399_999_999))

    def test_sparse_samples_never_interpolate_depletion(self):
        intervals = [reader.depletion_interval(sample()),
                     reader.depletion_interval(sample(start=2_000_000_000, end=2_000_000_000))]
        result = reader.coverage(intervals, 0, 3_000_000_000)
        self.assertEqual(result['covered_ns'], 799_999_998)
        self.assertEqual(result['max_unproven_gap_ns'], 1_600_000_001)

    def test_stale_watermark_and_query_duration_can_remove_all_proof(self):
        self.assertIsNone(reader.depletion_interval(sample(age=400_000_000)))
        self.assertIsNone(reader.depletion_interval(sample(end=400_000_000)))
        self.assertIsNone(reader.depletion_interval(sample(paid=1_900_000_000)))

    def test_rounded_refill_is_conservative_and_unknown_is_not_zero(self):
        self.assertEqual(reader.depletion_interval(sample(end=1)), (1, 399_999_996))
        for key, value in [('projected_paid_credit_ns', -1), ('watermark_age_ns', None),
                           ('projected_scalar_start_eligible', 0)]:
            row = sample()
            row['credit_freshness'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                reader.depletion_interval(row)

    def test_union_clips_overlaps_and_includes_both_round_boundaries(self):
        self.assertEqual(reader.coverage([(-20, 20), (10, 70), (80, 200)], 0, 100),
                         dict(covered_ns=90, round_ns=100, max_unproven_gap_ns=10))
        self.assertEqual(reader.coverage([], 0, 100)['max_unproven_gap_ns'], 100)


class ConstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Actual scalar proof over a synthetic easy header, not a native timing
        # measurement or evidence that 4096 paid identities were ever submitted.
        vector = reader.ROOT / 'formal/pon-nakamoto-v1/vectors/accepted-block'
        header_path = vector / 'header.bin'
        if not header_path.exists():
            header_path = reader.ROOT / 'formal/pon-nakamoto-v1/vectors/header.bin'
        header = reader.header_decode(header_path.read_bytes())
        header['target'] = b'\xff' * 32
        template_proof = (vector / 'work.bin').read_bytes()
        cls.template = (reader.header_encode(header) + b'\x00\x00' + template_proof).hex()
        factors = reader.struct.unpack('<' + 'I' * (2 * reader.work_oracle.CELLS),
            template_proof[4:4 + 8 * reader.work_oracle.CELLS])
        header['state'] = bytes([header['state'][0] ^ 1]) + header['state'][1:]
        header['nonce'] = 2_000_000
        challenge = reader.H('challenge', reader.header_encode(header))
        proof = reader.work_oracle.prove(challenge, factors[:4096], factors[4096:])
        packet = reader.header_encode(header) + b'\x00\x00' + proof
        cls.row = dict(schema='public-v3-real-identity-prefix-v1', index=0,
            initial_nonce=2_000_000, attempt_limit=4096, status='winner', error=None,
            production_verified=True, reference_verified=True, packet=packet.hex(),
            completion_identity=reader.H('public-v3-complete-work-identity-v1', packet).hex(),
            construction_thread_cpu_ns=10, construction_wall_ns=20, verification_thread_cpu_ns=1,
            attempts=[dict(nonce=2_000_000, trace=proof[-32:].hex(),
                ticket=reader.H('ticket', challenge, proof[-32:]).hex(),
                target_hit=True, thread_cpu_ns=5)])

    def test_scalar_relation_control_is_not_a_native_capacity_claim(self):
        packet, identity = reader.construction(self.row, self.template, 0)
        self.assertEqual(packet.hex(), self.row['packet'])
        self.assertEqual(identity, self.row['completion_identity'])

    def test_changed_trace_missing_nonce_unknown_cost_and_replay_index_refused(self):
        mutations = [lambda r: r['attempts'][0].__setitem__('trace', '00' * 32),
            lambda r: r['attempts'][0].__setitem__('thread_cpu_ns', None),
            lambda r: r['attempts'][0].__setitem__('nonce', 2_000_001),
            lambda r: r.__setitem__('completion_identity', '00' * 32),
            lambda r: r.__setitem__('construction_thread_cpu_ns', 1),
            lambda r: r.__setitem__('attempts', [])]
        for mutate in mutations:
            row = copy.deepcopy(self.row)
            mutate(row)
            with self.assertRaises(ValueError):
                reader.construction(row, self.template, 0)
        with self.assertRaises(ValueError):
            reader.construction(self.row, self.template, 1)


class CollectorTests(unittest.TestCase):
    def test_complete_service_with_unknown_cost_cannot_return_ci_green(self):
        arguments = ['reader', '--bundle', '/synthetic-not-a-native-bundle', '--manifest-sha256', 'a' * 64,
                     '--source-commit', 'b' * 40, '--source-tree', 'c' * 40]
        with patch.object(reader.sys, 'argv', arguments), \
             patch.object(reader, 'validate_bundle', return_value=dict(overall_qualified=False)), \
             redirect_stdout(io.StringIO()):
            self.assertEqual(reader.main(), 2)

    def test_missing_collection_budget_never_contacts_source_or_native_executor(self):
        with tempfile.TemporaryDirectory() as directory:
            output, target = Path(directory) / 'out', Path(directory) / 'target'
            output.mkdir()
            args = SimpleNamespace(target_dir=target, expected_head='a' * 40,
                                   expected_tree='b' * 40, collection_seconds=None)
            with patch.object(collector, 'environment', return_value={}), \
                 patch.object(collector, 'run_step') as execute, \
                 patch.object(collector, 'exact_source') as source:
                self.assertFalse(collector.prepare(args, output))
                execute.assert_not_called()
                source.assert_not_called()
            self.assertFalse(reader.read_json(output / 'prepared.json')['selector_executed'])

    def test_changed_prepared_manifest_is_retained_as_failure_without_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'out'
            output.mkdir()
            prepared = Path(directory) / 'prepared.json'
            prepared.write_text('{}')
            args = SimpleNamespace(prepared=prepared, prepared_sha256='0' * 64,
                                   expected_head='a' * 40, expected_tree='b' * 40)
            with patch.object(collector, 'environment', return_value={}), \
                 patch.object(collector, 'run_step') as execute:
                self.assertFalse(collector.execute(args, output))
                execute.assert_not_called()
            record = reader.read_json(output / 'results.json')
            self.assertFalse(record['selector_executed'])
            self.assertIn('SHA', record['failure'])

    def test_file_inventory_cannot_silently_omit_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'real').write_bytes(b'unchanged')
            (root / 'alias').symlink_to(root / 'real')
            with self.assertRaises(ValueError):
                collector.inventory(root)

    def test_unlisted_failure_file_cannot_hide_behind_pinned_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'receipt').write_bytes(b'component input, not a native campaign')
            collector.inventory(root)
            expected = collector.sha(root / 'artifact-files.json')
            bundle = reader.IdentityBundle(root, expected)
            bundle.close()
            (root / 'omitted-failure.json').write_text('{"failed":true}')
            with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
                reader.IdentityBundle(root, expected)

    def test_descriptor_reader_refuses_symlink_after_inventory_was_frozen(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'receipt').write_bytes(b'actual bytes')
            collector.inventory(root)
            expected = collector.sha(root / 'artifact-files.json')
            (root / 'receipt').unlink()
            (root / 'receipt').symlink_to(root / 'artifact-files.json')
            with self.assertRaises((OSError, ValueError)):
                reader.IdentityBundle(root, expected)


class CompleteAttemptV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # New synthetic scalar material, never relabelled as retained native
        # measurements. A winner cannot hide a changed or omitted target miss.
        ConstructionTests.setUpClass()
        header = reader.header_decode(bytes.fromhex(ConstructionTests.template)[:318])
        raw = bytes.fromhex(ConstructionTests.template)
        _, _, template_proof = reader.decode_packet(raw)
        factors = reader.struct.unpack('<' + 'I' * (2 * reader.work_oracle.CELLS),
            template_proof[4:4 + 8 * reader.work_oracle.CELLS])
        header['target'] = b'\x3f' + b'\xff' * 31
        cls.template = (reader.header_encode(header) + b'\x00\x00' + template_proof).hex()
        header['state'] = bytes([header['state'][0] ^ 1]) + header['state'][1:]
        attempts = []
        for offset in range(64):
            header['nonce'] = 2_000_000 + offset
            challenge = reader.H('challenge', reader.header_encode(header))
            proof = reader.work_oracle.prove(challenge, factors[:4096], factors[4096:])
            ticket = reader.H('ticket', challenge, proof[-32:])
            hit = ticket <= header['target']
            attempts.append(dict(nonce=header['nonce'], proof=proof.hex(), challenge=challenge.hex(),
                trace=proof[-32:].hex(), ticket=ticket.hex(), target_hit=hit, thread_cpu_ns=5))
            if hit:
                break
        if len(attempts) < 2 or not hit:
            raise AssertionError('fixed synthetic v2 control must include miss and winner')
        packet = reader.header_encode(header) + b'\x00\x00' + proof
        cls.row = dict(schema='public-v3-real-identity-prefix-v2', index=0,
            initial_nonce=2_000_000, attempt_limit=4096, status='winner', error=None,
            production_verified=True, reference_verified=True, packet=packet.hex(),
            completion_identity=reader.H('public-v3-complete-work-identity-v1', packet).hex(),
            construction_thread_cpu_ns=5 * len(attempts) + 1, construction_wall_ns=1000,
            verification_thread_cpu_ns=1, attempts=attempts)
        cls.row['evidence_budget'] = dict(stage_limit_bytes=64 * 1024**2,
            stage_used_before_bytes=1024, per_construction_limit_bytes=8 * 1024**2,
            frame_limit_bytes=8 * 1024**2, frame_reservation_bytes=128 * 1024,
            attempt_reservation_bytes=100 * 1024,
            attempt_serialized_bytes=sum(len(reader.json.dumps(row, separators=(',', ':'),
                sort_keys=True, ensure_ascii=False).encode()) + 1 for row in attempts),
            working_buffer_limit_bytes=32 * 1024**2, successful_proof_bytes=49188,
            cap_reached=False, poisoned=False, buffer_scope='synthetic receipt only; not a native heap observation')

    def test_all_raw_attempts_match_independent_factors_product_trace_and_challenge(self):
        packet, identity = reader.construction(self.row, self.template, 0, version='v2')
        self.assertEqual(packet.hex(), self.row['packet'])
        self.assertEqual(identity, self.row['completion_identity'])
        self.assertGreater(len(self.row['attempts']), 1)

    def test_missing_miss_bytes_cannot_borrow_the_unchanged_winner(self):
        row = copy.deepcopy(self.row)
        del row['attempts'][0]['proof']
        with self.assertRaisesRegex(ValueError, 'complete raw proof bytes'):
            reader.construction(row, self.template, 0, version='v2')

    def test_changed_factor_product_trace_and_challenge_are_all_rejected(self):
        for byte in (4, 4 + 8 * 4096, 49187):
            row = copy.deepcopy(self.row)
            raw = bytearray.fromhex(row['attempts'][0]['proof'])
            raw[byte] ^= 1
            row['attempts'][0]['proof'] = raw.hex()
            with self.subTest(byte=byte), self.assertRaisesRegex(ValueError, 'complete attempt proof changed'):
                reader.construction(row, self.template, 0, version='v2')
        row = copy.deepcopy(self.row)
        row['attempts'][0]['challenge'] = '00' * 32
        with self.assertRaisesRegex(ValueError, 'challenge changed'):
            reader.construction(row, self.template, 0, version='v2')

    def test_wrong_length_unknown_cpu_and_cap_terminal_remain_failures(self):
        mutations = [lambda row: row['attempts'][0].__setitem__('proof', row['attempts'][0]['proof'][:-2]),
            lambda row: row['attempts'][0].__setitem__('thread_cpu_ns', None),
            lambda row: row.__setitem__('terminal_error', 'evidence-cap'),
            lambda row: row.__setitem__('evidence_budget', dict(cap_reached=True)),
            lambda row: row['attempts'].pop(0)]
        for mutate in mutations:
            row = copy.deepcopy(self.row)
            mutate(row)
            with self.assertRaises(ValueError):
                reader.construction(row, self.template, 0, version='v2')

    def test_byte_counter_or_preprove_reservation_cannot_borrow_the_summary(self):
        for key, value in (('attempt_serialized_bytes', 1), ('frame_limit_bytes', 131072),
                ('per_construction_limit_bytes', 16 * 1024**2),
                ('stage_limit_bytes', 16 * 1024**3), ('successful_proof_bytes', 0),
                ('working_buffer_limit_bytes', 64 * 1024**2)):
            row = copy.deepcopy(self.row)
            row['evidence_budget'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                reader.construction(row, self.template, 0, version='v2')

    def test_version_is_explicit_and_old_raw_cannot_be_relabelled_complete(self):
        with self.assertRaisesRegex(ValueError, 'profile/index'):
            reader.construction(self.row, self.template, 0)
        with self.assertRaisesRegex(ValueError, 'profile/index'):
            reader.construction(ConstructionTests.row, ConstructionTests.template, 0, version='v2')
        renamed = copy.deepcopy(ConstructionTests.row)
        renamed['schema'] = 'public-v3-real-identity-prefix-v2'
        with self.assertRaisesRegex(ValueError, 'complete raw proof bytes'):
            reader.construction(renamed, ConstructionTests.template, 0, version='v2')

    def test_local_service_cost_and_public_hardness_conclusions_are_separate(self):
        phases = [dict(mode=mode, all_completed_attempt_bytes_checked=True) for mode in reader.MODES]
        result = reader.conclusions(phases, version='v2')
        self.assertTrue(result['finite_local_acceptance'])
        self.assertTrue(result['complete_attempt_construction_evidence'])
        self.assertFalse(result['overall_qualified'])
        self.assertFalse(result['global_minimum_work_cost_proven'])
        self.assertFalse(result['hardware_fairness_qualified'])
        phases[0]['all_completed_attempt_bytes_checked'] = False
        self.assertFalse(reader.conclusions(phases, version='v2')['finite_local_acceptance'])
        self.assertFalse(reader.conclusions(phases)['finite_local_acceptance'])
        self.assertFalse(reader.conclusions(phases[:-1], version='v2')['finite_service_measurement_complete'])

    def test_finite_v2_exit_status_does_not_claim_public_qualification(self):
        arguments = ['reader', '--profile', 'v2', '--bundle', '/synthetic-not-native',
            '--manifest-sha256', 'a' * 64, '--source-commit', 'b' * 40, '--source-tree', 'c' * 40]
        with patch.object(reader.sys, 'argv', arguments), \
             patch.object(reader, 'validate_bundle', return_value=dict(finite_local_acceptance=True,
                overall_qualified=False, public_network_ready=False)), redirect_stdout(io.StringIO()):
            self.assertEqual(reader.main(), 0)

    def test_whole_v2_artifact_includes_manifest_and_stays_within_eight_gib(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Synthetic inventory only: no large files are created. The total
            # gate must reject before attempting to read any claimed members.
            manifest = dict(schema='pon-identity-artifact-files-v2', files=[dict(path=f'member-{i}',
                bytes=256 * 1024**2, sha256='0' * 64) for i in range(32)])
            (root / 'artifact-files.json').write_text(reader.json.dumps(manifest))
            expected = collector.sha(root / 'artifact-files.json')
            with self.assertRaisesRegex(ValueError, 'bounded artifact total'):
                reader.IdentityBundle(root, expected, version='v2')

    def test_unfrozen_v2_cannot_dispatch_or_qualify(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'out'
            output.mkdir()
            args = SimpleNamespace(profile='v2', target_dir=Path(directory) / 'target',
                expected_head='a' * 40, expected_tree='b' * 40, collection_seconds=6000)
            with patch.object(collector, 'environment', return_value={}), \
                 patch.object(collector, 'EVIDENCE_CAPS_V2', None), \
                 patch.object(collector, 'run_step') as execute:
                self.assertFalse(collector.prepare(args, output))
                execute.assert_not_called()
            record = reader.read_json(output / 'prepared.json')
            self.assertEqual(record['failure'], 'V2_COMPLETE_BYTE_LEDGER_NOT_FROZEN')
            self.assertFalse(record['selector_executed'])
            with patch.object(collector, 'EVIDENCE_CAPS_V2', None), \
                 self.assertRaisesRegex(ValueError, 'byte ledger not frozen'):
                reader.validate_bundle(output, 'a' * 64, 'b' * 40, 'c' * 40, version='v2')


class ActualControlTests(unittest.TestCase):
    def setUp(self):
        if ACTUAL_CONTROL is None:
            self.skipTest('explicit noncapacity actual-control input not supplied')
        self.report = reader.read_json(ACTUAL_CONTROL / 'report.json')
        self.template = reader.read_json(ACTUAL_CONTROL / 'seed.json')['template']
        self.rows = [reader.read_json(ACTUAL_CONTROL / f'{index:05}-construction.json') for index in range(3)]
        self.bodies = [row['body_digest'] for row in self.report['calls']]

    def test_real_three_proof_component_remains_below_capacity(self):
        identities = [reader.construction(row, self.template, index)[1] for index, row in enumerate(self.rows)]
        self.assertEqual(len(set(identities)), 3)
        self.assertFalse(self.report['capacity_crossed'])
        self.assertFalse(self.report['honest_service_qualified'])
        observed, roots = reader.receiver(self.report['receiver_observation'], self.bodies,
                                          self.report['actual_flow'], self.report['metrics'])
        self.assertEqual(sum(observed.values()), 3)
        self.assertEqual(set(roots), set(self.bodies))

    def test_changed_actual_miss_is_rejected_with_winner_unchanged(self):
        index = next(i for i, row in enumerate(self.rows) if len(row['attempts']) > 1)
        for mutate in (lambda row: row['attempts'][0].__setitem__('trace', '00' * 32),
                       lambda row: row['attempts'].pop(0)):
            row = copy.deepcopy(self.rows[index])
            mutate(row)
            with self.assertRaises(ValueError):
                reader.construction(row, self.template, index)

    def test_actual_paid_owner_rejects_omitted_record_and_invented_cpu(self):
        for mutate in (lambda observer: observer['records'].pop(),
                       lambda observer: observer['records'][0].__setitem__('dispatch_thread_cpu_ns', None)):
            observer = copy.deepcopy(self.report['receiver_observation'])
            mutate(observer)
            observer['accepted_connections_seen'] = len(observer['records'])
            with self.assertRaises(ValueError):
                reader.receiver(observer, self.bodies, self.report['actual_flow'], self.report['metrics'])
        metrics = dict(self.report['metrics'])
        metrics['mutation_cpu_charged_ns'] += 1
        with self.assertRaises(ValueError):
            reader.receiver(self.report['receiver_observation'], self.bodies, self.report['actual_flow'], metrics)

    def test_actual_body_reassignment_cannot_double_count_other_identity(self):
        observer = copy.deepcopy(self.report['receiver_observation'])
        observer['records'][0]['body_digest'] = observer['records'][1]['body_digest']
        with self.assertRaises(ValueError):
            reader.receiver(observer, self.bodies, self.report['actual_flow'], self.report['metrics'])


class ActualSmallCampaignTests(unittest.TestCase):
    def test_partial_native_counts_remain_diagnostic_and_missing_exit_stays_unknown(self):
        if ACTUAL_SMALL_CAMPAIGN is None:
            self.skipTest('explicit actual small failed campaign not supplied')

        class DiagnosticFiles:
            files = {'raw/' + path.relative_to(ACTUAL_SMALL_CAMPAIGN).as_posix(): None
                     for path in ACTUAL_SMALL_CAMPAIGN.rglob('*') if path.is_file()}

            def json(self, name):
                if name == 'results.json':
                    # Synthetic collector envelope around actual raw failure;
                    # no outer process exit was retained in this raw input.
                    return dict(complete_success=False, failure=None, step={})
                return reader.read_json(ACTUAL_SMALL_CAMPAIGN / name.removeprefix('raw/'))

        result = reader.diagnostic(DiagnosticFiles())
        self.assertIsNone(result['native_returncode'])
        self.assertEqual(result['phases'][0]['recorded_prefix_work']['retained_identities'], 2)
        self.assertTrue(result['phases'][0]['original_flow_arithmetic_checked'])
        self.assertFalse(result['overall_qualified'])
        self.assertFalse(result['finite_service_measurement_complete'])

    def test_small_failed_control_cannot_be_promoted_by_successful_summary_or_full_plan(self):
        if ACTUAL_SMALL_CAMPAIGN is None:
            self.skipTest('explicit actual small failed campaign not supplied')

        class NegativeOverlay:
            def json(self, name):
                value = reader.read_json(ACTUAL_SMALL_CAMPAIGN / name.removeprefix('raw/'))
                if name == 'raw/fresh-identities/report.json':
                    # Deliberate in-memory forgery; none of the retained raw files
                    # or historical failures is edited or labelled a full run.
                    value['plan'] = collector.PLAN
                    value['prefix_end_ns'] = value['prefix_epoch_ns'] + 1800 * reader.SECOND
                    value['pressure_end_ns'] = value['pressure_epoch_ns'] + 30 * reader.SECOND
                    value['paid_settled'] = value['cold_equal'] = True
                return value

        phase = reader.read_json(ACTUAL_SMALL_CAMPAIGN / 'fresh-identities/report.json')
        root = dict(preparation_file='preparation.json')
        resources = dict(cgroup=phase['controller_cgroup'].strip().removeprefix('0::'))
        with self.assertRaisesRegex(ValueError, 'prefix did not fill same owner'):
            reader.validate_phase(NegativeOverlay(), root, 'fresh-identities', phase['source_commit'],
                phase['source_tree'], dict(sha256=phase['binary_sha256']), resources)

    def test_actual_prepared_history_readback_and_extra_block_rejection(self):
        if ACTUAL_SMALL_CAMPAIGN is None:
            self.skipTest('explicit actual small failed campaign not supplied')
        facts = reader.preparation(reader.read_json(ACTUAL_SMALL_CAMPAIGN / 'preparation.json'))

        class ActualFiles:
            files = {'raw/' + path.relative_to(ACTUAL_SMALL_CAMPAIGN).as_posix(): None
                     for path in ACTUAL_SMALL_CAMPAIGN.rglob('*') if path.is_file()}

            def raw(self, name, limit):
                data = (ACTUAL_SMALL_CAMPAIGN / name.removeprefix('raw/')).read_bytes()
                self_limit = len(data) <= limit
                reader.require(self_limit, 'bounded actual test input')
                return data

        reader.durable_history(ActualFiles(), 'raw/honest-miner', facts, ['ff' * 32])
        # Inject into a newly owned temporary copy only. A successful summary
        # cannot conceal an extra actual block or manufacture its absence.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native.sqlite'
            path.write_bytes((ACTUAL_SMALL_CAMPAIGN / 'honest-miner/native.sqlite').read_bytes())
            with reader.sqlite3.connect(path) as db:
                db.execute('INSERT INTO blocks(id,parent,height,chainwork,packet,state_root) VALUES(?,?,?,?,?,?)',
                    (b'\xff' * 32, b'\x00' * 32, 26, b'\x00' * 64, b'forged', b'\x00' * 32))
                db.commit()

            class ChangedFiles:
                files = {'copy/' + member.name: None for member in Path(directory).glob('native.sqlite*')}

                def raw(self, name, limit):
                    return (Path(directory) / Path(name).name).read_bytes()

            with self.assertRaisesRegex(ValueError, 'missing/hostile block'):
                reader.durable_history(ChangedFiles(), 'copy', facts, ['ff' * 32])


class ActualAcquisitionV2Tests(unittest.TestCase):
    def test_actual_six_proofs_paid_bytes_and_tiny_cap_remain_component_only(self):
        if ACTUAL_V2_ACQUISITION is None:
            self.skipTest('explicit actual v2 acquisition input not supplied')
        result = reader.read_acquisition_v2(ACTUAL_V2_ACQUISITION)
        self.assertTrue(result['component_readback_pass'])
        self.assertEqual(result['all_attempts_checked'], 6)
        self.assertEqual(result['misses_checked'], 3)
        self.assertTrue(result['tiny_cap_zero_attempts'])
        self.assertTrue(result['tiny_cap_strictly_rejected'])
        self.assertFalse(result['full_campaign_qualified'])
        self.assertFalse(result['exact_commit_qualified'])
        self.assertFalse(result['original_two_actor_failure_closed'])


class FullLedgerV2Tests(unittest.TestCase):
    def setUp(self):
        self.caps = collector.profile('v2')['evidence_caps']
        self.files = {'raw/' + root + '/native.sqlite': dict(bytes=1)
                      for root in self.caps['node_roots']}
        self.files.update({'raw/' + root + '/owner.lock': dict(bytes=0) for root in self.caps['node_roots']})
        self.files['raw/plan.json'] = dict(bytes=1)

    def test_declared_complete_ledger_preserves_original_total_and_vm_envelope(self):
        keys = ['node_database_total_bytes', 'node_metadata_total_bytes', 'sample_total_bytes',
            'frozen_binary_bytes', 'phase_report_total_bytes', 'actor_metadata_total_bytes',
            'actor_log_total_bytes', 'outer_outputs_total_bytes', 'preparation_bytes', 'root_outputs_total_bytes']
        stage = 72 * self.caps['actor_prefix_bytes'] + 24 * self.caps['actor_fresh_pressure_bytes'] + 24 * self.caps['actor_replay_pressure_bytes']
        self.assertEqual(sum(self.caps[key] for key in keys) + stage, self.caps['reserved_total_bytes'])
        self.assertEqual(self.caps['reserved_total_bytes'] + self.caps['unassigned_bytes'], 8 * 1024**3)
        self.assertLess(24 * self.caps['actor_vm_bytes'] + self.caps['parent_vm_bytes'], 16 * 1024**3)
        result = reader.evidence_ledger_v2(self.files, 100, self.caps)
        self.assertEqual(result['total_bytes'], 108)
        self.assertFalse(result['complete_route_enforcement_inferred'])

    def test_source_emitted_descriptor_has_no_python_drift(self):
        if ACTUAL_V2_DESCRIPTOR is None:
            self.skipTest('explicit source-emitted v2 descriptor not supplied')
        self.assertEqual(reader.read_json(ACTUAL_V2_DESCRIPTOR), self.caps)

    def test_unknown_node_file_missing_database_oversize_and_nonempty_lock_are_rejected(self):
        mutations = [lambda rows: rows.__setitem__('raw/honest-miner/unknown.json', dict(bytes=1)),
            lambda rows: rows.pop('raw/honest-miner/native.sqlite'),
            lambda rows: rows.__setitem__('raw/honest-miner/native.sqlite', dict(bytes=16 * 1024**2 + 1)),
            lambda rows: rows.__setitem__('raw/honest-miner/owner.lock', dict(bytes=1)),
            lambda rows: rows.__setitem__('raw/unowned.json', dict(bytes=1))]
        for mutate in mutations:
            rows = copy.deepcopy(self.files)
            mutate(rows)
            with self.assertRaises(ValueError):
                reader.evidence_ledger_v2(rows, 100, self.caps)

    def test_partial_and_initializing_are_counted_and_preserved_but_never_qualified(self):
        self.files['raw/fresh-identities/actor-00/prefix/00000-construction.partial.json'] = dict(bytes=123)
        self.files['raw/honest-miner/initializing.json'] = dict(bytes=17)
        result = reader.evidence_ledger_v2(self.files, 100, self.caps, strict=False)
        self.assertEqual(result['bucket_bytes']['actor_stage'], 123)
        self.assertEqual(result['bucket_bytes']['node_metadata'], 17)
        self.assertEqual(len(result['retained_failure_files']), 2)
        with self.assertRaisesRegex(ValueError, 'prevents qualification'):
            reader.evidence_ledger_v2(self.files, 100, self.caps)

    def test_group_caps_cannot_be_evaded_with_more_small_files(self):
        for suffix, sizes in [('prefix', [8 * 1024**2] * 9), ('metadata', [300 * 1024] * 2)]:
            rows = copy.deepcopy(self.files)
            for index, size in enumerate(sizes):
                name = (f'prefix/{index:05}-construction.json' if suffix == 'prefix'
                        else ['job.json', 'ready.json'][index])
                rows['raw/fresh-identities/actor-00/' + name] = dict(bytes=size)
            with self.subTest(kind=suffix), self.assertRaisesRegex(ValueError, 'group byte cap'):
                reader.evidence_ledger_v2(rows, 100, self.caps)
        self.files['raw/replay-only/actor-00/actor.log'] = dict(bytes=65537)
        with self.assertRaisesRegex(ValueError, 'per-file byte cap'):
            reader.evidence_ledger_v2(self.files, 100, self.caps)

    def test_honest_pressure_chunk_count_and_root_manifest_have_no_spare_budget_escape(self):
        for name, size in [('raw/honest-only/actor-00/pressure/04608-call.json', 1),
                ('raw/fresh-identities/samples-12.jsonl', 1)]:
            rows = dict(self.files)
            rows[name] = dict(bytes=size)
            with self.assertRaises(ValueError):
                reader.evidence_ledger_v2(rows, 100, self.caps)
        with self.assertRaises(ValueError):
            reader.evidence_ledger_v2(self.files, 33 * 1024**2, self.caps)
        changed = dict(self.caps, artifact_total_bytes=16 * 1024**3)
        with self.assertRaisesRegex(ValueError, 'changed v2 ledger'):
            reader.evidence_ledger_v2(self.files, 100, changed)

    def test_process_limit_receipt_needs_actual_same_pid_group_both_hard_caps_and_full_owner(self):
        group = '0::/synthetic-owned-group\n'
        current = dict(pid=123, cgroup=group,
            address_space=dict(soft_bytes=self.caps['actor_vm_bytes'], hard_bytes=self.caps['actor_vm_bytes']),
            file_size=dict(soft_bytes=self.caps['actor_file_bytes'], hard_bytes=self.caps['actor_file_bytes']))
        value = dict(schema=self.caps['schema'], role='actor', before=copy.deepcopy(current),
            after=current, original_cgroup_required=True, full_ledger_implemented=True)
        self.assertEqual(reader.process_limits_v2(value, 'actor', group, 123), 123)
        for mutate in [lambda row: row.__setitem__('full_ledger_implemented', False),
                lambda row: row['after'].__setitem__('pid', 124),
                lambda row: row['after'].__setitem__('cgroup', '0::/another\n'),
                lambda row: row['after']['file_size'].__setitem__('hard_bytes', 16 * 1024**2),
                lambda row: row['after']['address_space'].__setitem__('soft_bytes', None)]:
            row = copy.deepcopy(value)
            mutate(row)
            with self.assertRaises(ValueError):
                reader.process_limits_v2(row, 'actor', group, 123)

    def test_chunks_are_complete_ordered_and_cannot_omit_an_actual_file(self):
        class Samples:
            files = {'raw/fresh-identities/samples-00.jsonl': None, 'raw/fresh-identities/samples-01.jsonl': None}
            data = {name: b'{"synthetic":true}\n' for name in files}

            def raw(self, name, limit):
                reader.require(len(self.data[name]) <= limit, 'bounded synthetic chunk')
                return self.data[name]

        row = dict(sample_files=['samples-00.jsonl', 'samples-01.jsonl'], sample_count=2,
            sample_chunk_bytes=8 * 1024**2, sample_chunks_limit=12, sample_cap_reached=False,
            sample_io_error=None, unpersisted_sample=None, sync_data_attempts=2, sync_data_successes=2,
            final_sync_all_attempts=1, final_sync_all_successes=1, final_sync_all_error=None,
            sample_bytes=sum(len(raw) for raw in Samples.data.values()))
        self.assertEqual(len(list(reader.sample_lines(Samples(), 'raw/fresh-identities/', row, version='v2'))), 2)
        for names in (['samples-01.jsonl', 'samples-00.jsonl'], ['samples-00.jsonl']):
            with self.assertRaises(ValueError):
                list(reader.sample_lines(Samples(), 'raw/fresh-identities/', dict(row, sample_files=names), version='v2'))
        broken = Samples()
        broken.data = dict(broken.data)
        broken.data['raw/fresh-identities/samples-01.jsonl'] = b'{"synthetic":true}'
        with self.assertRaisesRegex(ValueError, 'truncated'):
            list(reader.sample_lines(broken, 'raw/fresh-identities/', row, version='v2'))
        for key, value in [('sample_count', 1), ('sample_bytes', 1), ('sync_data_successes', 1),
                ('final_sync_all_successes', 0), ('sample_cap_reached', True),
                ('sample_io_error', 'retained original I/O error'), ('unpersisted_sample', {'index': 2}),
                ('final_sync_all_error', 'retained final sync failure')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                list(reader.sample_lines(Samples(), 'raw/fresh-identities/', dict(row, **{key:value}), version='v2'))

    def test_complete_descriptor_does_not_open_an_unimplemented_native_route(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'out'
            output.mkdir()
            args = SimpleNamespace(profile='v2', target_dir=Path(directory) / 'target',
                expected_head='a' * 40, expected_tree='b' * 40, collection_seconds=6000)
            with patch.object(collector, 'environment', return_value={}), \
                 patch.object(collector, 'run_step') as native:
                self.assertFalse(collector.prepare(args, output))
                native.assert_not_called()
            self.assertEqual(reader.read_json(output / 'prepared.json')['failure'], 'V2_FULL_IO_BOUNDARY_NOT_IMPLEMENTED')
            with self.assertRaisesRegex(ValueError, 'I/O boundary not implemented'):
                reader.validate_bundle(output, 'a' * 64, 'b' * 40, 'c' * 40, version='v2')


class OuterWriterV2Tests(unittest.TestCase):
    """Real tiny filesystem/process negatives; no W1/full qualification."""
    def owner(self, root, **changes):
        limits = dict(outer=1024, terminal=4096, binary=128, inventory=128)
        limits.update(changes)
        return collector.V2Writer(root, limits=limits)

    def test_json_precount_cap_poison_and_independent_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); owner = self.owner(root, outer=16)
            try:
                with self.assertRaisesRegex(ValueError, 'JSON_FILE_CAP'):
                    owner.json('over.json', {'actual':'x'*64})
                self.assertEqual(list(root.iterdir()), [])
                with self.assertRaisesRegex(ValueError, 'POISONED'):
                    owner.json('later.json', {})
                owner.terminal('cap-negative', 'second error')
                row = reader.read_json(root/'outer-terminal.json')
                self.assertIn('JSON_FILE_CAP', row['first_error'])
                self.assertFalse(row['qualification'])
                self.assertFalse(row['physical_enospc_terminal_guaranteed'])
                self.assertEqual(row['sync_calls_added'], 0)
            finally:
                owner.close()

    def test_partial_overrun_and_copy_hash_failure_are_retained_and_charged(self):
        for mode in ('overrun', 'copy-hash'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); output = root/'out'; output.mkdir(); owner = self.owner(output)
                try:
                    if mode == 'overrun':
                        with self.assertRaisesRegex(ValueError, 'RESERVED_STREAM'):
                            owner.chunks('actual.json', [b'ab', b'overflow'], owner.reserve('outer', 4))
                        expected = b'ab'
                    else:
                        source = root/'source'; source.write_bytes(b'real copy'); expected = b'real copy'
                        with self.assertRaisesRegex(ValueError, 'SHA_MISMATCH'):
                            owner.copy('actual.json', source, expected='0'*64)
                    self.assertEqual((output/'actual.json.partial.json').read_bytes(), expected)
                    self.assertEqual(owner.used['outer'], len(expected))
                    self.assertEqual(owner.held['outer'], 0)
                    self.assertFalse((output/'actual.json').exists())
                finally:
                    owner.close()

    def test_real_noreplace_collision_keeps_original_and_partial(self):
        for collision in ('final', 'partial'):
            with self.subTest(collision=collision), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); old = root/('entry.json' if collision == 'final' else 'entry.json.partial.json')
                old.write_bytes(b'old evidence'); owner = self.owner(root)
                try:
                    with self.assertRaises(FileExistsError):
                        owner.json('entry.json', {'new':True})
                    self.assertEqual(old.read_bytes(), b'old evidence')
                    if collision == 'final':
                        self.assertEqual(reader.read_json(root/'entry.json.partial.json'), {'new':True})
                        self.assertGreater(owner.used['outer'], 0)
                    self.assertIsNotNone(owner.failure)
                finally:
                    owner.close()

    def test_unsupported_publish_and_terminal_failure_have_no_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); owner = self.owner(root)
            try:
                with patch.object(collector, 'publish_new', side_effect=OSError(22, 'unsupported flags')) as publish:
                    with self.assertRaises(OSError): owner.json('entry.json', {'actual':True})
                    with self.assertRaises(OSError): owner.terminal('negative', 'second')
                    self.assertEqual(publish.call_count, 2)
                self.assertFalse((root/'entry.json').exists())
                self.assertFalse((root/'outer-terminal.json').exists())
                self.assertTrue((root/'entry.json.partial.json').exists())
                self.assertTrue((root/'outer-terminal.json.partial.json').exists())
                self.assertIn('unsupported flags', owner.failure)
                self.assertTrue(owner.terminal_attempted)
            finally:
                owner.close()

    def test_stream_reservations_and_collision_precede_any_child(self):
        for collision in (False, True):
            with self.subTest(collision=collision), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); owner = collector.CollectorIO(root, 'v2')
                if collision: (root/'probe.stdout.log.partial.json').write_bytes(b'preserved')
                else: owner.writer.limits['outer'] = 15
                try:
                    with patch.object(collector, 'run_bounded') as child, self.assertRaises((OSError, ValueError)):
                        owner.step('probe', ['never-start'], {}, timeout=2, stdout_limit=8, stderr_limit=8)
                    child.assert_not_called()
                    self.assertTrue(all(n == 0 for n in owner.writer.held.values()))
                    if collision: self.assertEqual((root/'probe.stdout.log.partial.json').read_bytes(), b'preserved')
                finally:
                    owner.writer.close()

    def test_existing_final_stdout_and_stderr_prevent_real_marker_child(self):
        for stream in ('stdout', 'stderr'):
            with self.subTest(stream=stream), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); old = root/('probe.'+stream+'.log'); old.write_bytes(b'historical output')
                marker = root/'child-was-started'; owner = collector.CollectorIO(root, 'v2')
                command = [collector.sys.executable, '-c', 'import pathlib,sys;pathlib.Path(sys.argv[1]).write_text("STARTED")', str(marker)]
                with patch.object(collector, 'run_bounded', wraps=collector.run_bounded) as child, self.assertRaises(FileExistsError):
                    owner.step('probe', command, {}, timeout=2, stdout_limit=8, stderr_limit=8)
                child.assert_not_called(); self.assertFalse(marker.exists())
                self.assertEqual(old.read_bytes(), b'historical output')
                self.assertFalse(owner.finish('results.json', {'complete_success':False}, False))
                self.assertTrue((root/'outer-terminal.json').exists())

    def test_actual_child_overflow_keeps_bound_stream_and_failed_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); owner = collector.CollectorIO(root, 'v2')
            row = owner.step('probe', [collector.sys.executable, '-c', 'import os;os.write(1,b"x"*129)'],
                             {}, timeout=2, stdout_limit=128, stderr_limit=32)
            self.assertFalse(row['complete_success']); self.assertTrue(row['stdout_truncated'])
            self.assertEqual((root/'probe.stdout.log').read_bytes(), b'x'*128)
            self.assertIn('STDOUT_LIMIT', row['error'])
            self.assertFalse(owner.finish('results.json', {'complete_success':False}, False))
            self.assertTrue((root/'probe.step.json').exists()); self.assertTrue((root/'outer-terminal.json').exists())
            self.assertFalse((root/'artifact-files.json').exists())

    def test_source_validator_stdout_is_bounded_and_has_no_unowned_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); owner = collector.CollectorIO(root, 'v2'); head, tree = 'a'*40, 'b'*40
            raw = dict(tested_commit=head, tested_tree=tree, tracked_worktree_verified=True)
            captured = SimpleNamespace(returncode=0, stdout=reader.json.dumps(raw).encode(), stderr=b'')
            try:
                with patch.object(collector, 'source_snapshot', return_value=dict(head=head, tree=tree, status_porcelain='')), \
                     patch.object(collector, 'run_bounded', return_value=captured) as child:
                    row = owner.source('source-before', {}, head, tree)
                self.assertTrue(row['complete_success'])
                self.assertNotIn('--output', child.call_args.args[0])
                self.assertEqual(child.call_args.args[0][1:3], ['scripts/ci/verify_ci_source.py', '--kind'])
                self.assertEqual(reader.read_json(root/'source-before.json'), raw)
                self.assertEqual((root/'source-before.stdout.log').read_bytes(), captured.stdout)
            finally:
                owner.writer.close()

    def test_inventory31_rawroot1_and_partial_binary_remain_separate(self):
        caps = collector.profile('v2')['evidence_caps']
        with self.assertRaisesRegex(ValueError, 'group byte cap'):
            reader.evidence_ledger_v2({'raw/plan.json':dict(bytes=600000), 'raw/report.json':dict(bytes=600000)}, 1, caps, strict=False)
        with self.assertRaises(ValueError): reader.evidence_ledger_v2({}, 31*1024**2+1, caps, strict=False)
        result = reader.evidence_ledger_v2({'frozen/'+collector.TARGET+'.bin.partial.json':dict(bytes=17*1024**2)}, 1, caps, strict=False)
        self.assertEqual(result['bucket_bytes']['binary'], 17*1024**2)
        self.assertEqual(len(result['retained_failure_files']), 1)
        with self.assertRaisesRegex(ValueError, 'prevents qualification'):
            reader.evidence_ledger_v2({'outer-terminal.json':dict(bytes=1)}, 1, caps)

    def test_bad_source_stdout_or_child_exit_cannot_publish_identity_receipt(self):
        for code in (0, 1):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); owner = collector.CollectorIO(root, 'v2'); head, tree = 'a'*40, 'b'*40
                raw = dict(tested_commit=head, tested_tree='c'*40, tracked_worktree_verified=True)
                captured = SimpleNamespace(returncode=code, stdout=reader.json.dumps(raw).encode(), stderr=b'')
                try:
                    with patch.object(collector, 'source_snapshot', return_value=dict(head=head, tree=tree, status_porcelain='')), \
                         patch.object(collector, 'run_bounded', return_value=captured), self.assertRaises(ValueError):
                        owner.source('source-before', {}, head, tree)
                    self.assertFalse((root/'source-before.json').exists())
                    self.assertEqual((root/'source-before.stdout.log').read_bytes(), captured.stdout)
                finally:
                    owner.writer.close()

    def test_inventory_streams_json_without_allocating_a_dumps_document(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'actual.log').write_bytes(b'actual')
            with patch.object(collector.json, 'dumps', side_effect=AssertionError('unbounded dumps forbidden')):
                collector.inventory(root, version='v2')
            self.assertEqual(reader.read_json(root/'artifact-files.json')['files'][0]['bytes'], 6)

    def test_failed_first_stream_publish_keeps_observed_child_and_both_buffer_denominators(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); owner = collector.CollectorIO(root, 'v2'); publish = collector.publish_new
            def inject(fd, temporary, destination):
                if destination == 'probe.stdout.log': raise OSError(5, 'injected stdout publication failure')
                return publish(fd, temporary, destination)
            with patch.object(collector, 'publish_new', side_effect=inject), \
                 patch.object(collector, 'run_bounded', return_value=SimpleNamespace(returncode=-9, stdout=b'out', stderr=b'err')), \
                 self.assertRaises(OSError):
                owner.step('probe', ['synthetic-child-result'], {}, timeout=2, stdout_limit=8, stderr_limit=8)
            with self.assertRaisesRegex(ValueError, 'POISONED'):
                owner.step('must-not-replace-primary', ['never-start'], {}, timeout=2)
            self.assertFalse(owner.finish('results.json', {'complete_success':False}, False))
            row = reader.read_json(root/'outer-terminal.json')['observed_step']
            self.assertEqual(row['returncode'], -9); self.assertEqual(row['timeout_seconds'], '2')
            self.assertEqual((row['observed_stdout_bytes'], row['observed_stderr_bytes']), (3, 3))
            self.assertEqual(row['observed_stderr_sha256'], collector.hashlib.sha256(b'err').hexdigest())
            self.assertFalse(row['raw_preservation_complete'])
            self.assertEqual((root/'probe.stdout.log.partial.json').read_bytes(), b'out')
            self.assertEqual((root/'probe.stderr.log.partial.json').read_bytes(), b'')


class PreparedClaimLedgerV1Tests(unittest.TestCase):
    """Input identity and actual-path accounting only; no native qualification."""
    def prepared(self, parent):
        root = parent/'prepared'; root.mkdir(); binary = root/(collector.TARGET+'.bin')
        binary.write_bytes(b'actual small component bytes'); binary.chmod(0o500)
        files = {binary.name:dict(bytes=binary.stat().st_size, sha256=collector.sha(binary))}
        history = root/'history.log'; history.write_bytes(b'original history')
        files[history.name] = dict(bytes=history.stat().st_size, sha256=collector.sha(history))
        value = dict(schema=collector.profile('v2')['prepared_schema'], prepared=True, selector_executed=False,
            plan=collector.PLAN, acceptance=collector.ACCEPTANCE, head='a'*40, tree='b'*40,
            evidence_caps=collector.profile('v2')['evidence_caps'], runner_sha256=collector.sha(collector.__file__),
            collector_seconds=2, files=files, binary=dict(path=str(binary), **files[binary.name]))
        collector.write_new(root/'prepared.json', value); collector.inventory(root, version='v2', preparation_only=True)
        return root, collector.sha(root/'prepared.json'), collector.sha(root/'artifact-files.json')

    def rows(self, size=1):
        pin = dict(bytes=10, sha256='0'*64)
        return ({'frozen/'+collector.TARGET+'.bin':dict(bytes=size), 'frozen/artifact-files.json':pin},
            {collector.TARGET+'.bin':dict(bytes=size), 'artifact-files.json':pin},
            {'owner.lock':dict(bytes=0), 'claim.json':dict(bytes=10), 'terminal.json':dict(bytes=10)})

    def test_held_original_manifest_binary_and_directory_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            root, prepared, inventory = self.prepared(Path(directory))
            value = collector.PreparedInput(root/'prepared.json', prepared, inventory, 'a'*40, 'b'*40)
            try:
                value.recheck(); self.assertEqual(value.binding['binary_bytes'], 28)
                self.assertEqual(value.binding['prepared_identity']['inode'], root.stat().st_ino)
                binary = root/(collector.TARGET+'.bin'); binary.rename(root/'old-binary')
                binary.write_bytes(b'actual small component bytes'); binary.chmod(0o500)
                with self.assertRaisesRegex(ValueError, 'BINARY_REPLACED'): value.recheck()
            finally: value.close()

    def test_symlink_input_root_and_changed_inventory_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory); root, prepared, inventory = self.prepared(parent)
            alias = parent/'alias'; alias.symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError): collector.PreparedInput(alias/'prepared.json', prepared, inventory, 'a'*40, 'b'*40)
            value = collector.PreparedInput(root/'prepared.json', prepared, inventory, 'a'*40, 'b'*40)
            try:
                (root/'artifact-files.json').write_text('{}')
                with self.assertRaisesRegex(ValueError, 'INVENTORY_CHANGED'): value.recheck()
            finally: value.close()

    def test_combined_counter_counts_identical_digests_once_per_real_path(self):
        execution, prepared, claims = self.rows(80*1024**2)
        result = reader.linked_evidence_ledger_v2(execution, 10, prepared, claims,
                                                 collector.profile('v2')['evidence_caps'], strict=False)
        self.assertEqual(result['bucket_bytes']['binary'], 160*1024**2)
        self.assertEqual(result['group_bytes']['inventory'], 30)
        self.assertFalse(result['sha_or_inode_deduplication'])
        self.assertFalse(result['qualification'])

    def test_changed_history_and_replaced_original_directory_fail_held_recheck(self):
        for mode in ('history', 'directory'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root, prepared, inventory = self.prepared(Path(directory))
                value = collector.PreparedInput(root/'prepared.json', prepared, inventory, 'a'*40, 'b'*40)
                try:
                    if mode == 'history': (root/'history.log').write_bytes(b'changed history!')
                    else: root.rename(root.with_name('old-prepared')); root.mkdir()
                    with self.assertRaises(ValueError): value.recheck()
                finally: value.close()

    def test_combined_binary_outer_inventory_and_shadow_cannot_evade_original_caps(self):
        caps = collector.profile('v2')['evidence_caps']
        for mode in ('binary', 'outer', 'inventory', 'shadow'):
            execution, prepared, claims = self.rows(97*1024**2 if mode=='binary' else 1)
            if mode == 'outer':
                execution.update({f'log-{i}':dict(bytes=16*1024**2) for i in range(5)})
                prepared.update({f'log-{i}':dict(bytes=16*1024**2) for i in range(5)})
            if mode == 'inventory':
                for files,name in [(execution,'frozen/artifact-files.json'),(prepared,'artifact-files.json')]:
                    files[name] = dict(bytes=11*1024**2, sha256='0'*64)
            if mode == 'shadow': execution['input-prepared/forged.json'] = dict(bytes=0)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                reader.linked_evidence_ledger_v2(execution, 11*1024**2 if mode=='inventory' else 10,
                                               prepared, claims, caps, strict=False)

    def test_actual_debug_two_copy_reservations_are_rejected_without_a_child(self):
        if not ACTUAL_CLAIM_DEBUG_BINARIES: self.skipTest('explicit retained debug binary inputs not supplied')
        for binary in ACTUAL_CLAIM_DEBUG_BINARIES:
            size = binary.stat().st_size; self.assertGreater(2*size, 192*1024**2)
            execution, prepared, claims = self.rows(size)
            with self.subTest(binary=str(binary)), patch.object(collector, 'run_bounded') as child, \
                 self.assertRaisesRegex(ValueError, 'linked actual path bucket cap: binary'):
                reader.linked_evidence_ledger_v2(execution, 10, prepared, claims,
                                               collector.profile('v2')['evidence_caps'], strict=False)
            child.assert_not_called()


class OneShotClaimOwnerV1Tests(unittest.TestCase):
    """Small owned marker script only; this never starts native W1/Hepta/LAN."""
    def prepared(self, parent):
        root = parent/'prepared'; root.mkdir(); binary = root/(collector.TARGET+'.bin')
        binary.write_bytes(b'#!/usr/bin/python3\nimport sys\nwith open(sys.argv[1],"a") as f:f.write("X")\n')
        binary.chmod(0o500)
        files = {binary.name:dict(bytes=binary.stat().st_size, sha256=collector.sha(binary))}
        value = dict(schema=collector.profile('v2')['prepared_schema'], prepared=True, selector_executed=False,
            plan=collector.PLAN, acceptance=collector.ACCEPTANCE, head='a'*40, tree='b'*40,
            evidence_caps=collector.profile('v2')['evidence_caps'], runner_sha256=collector.sha(collector.__file__),
            collector_seconds=2, files=files, binary=dict(path=str(binary), **files[binary.name]),
            scope='small component fixture; no native source/release/full qualification')
        collector.write_new(root/'prepared.json',value); collector.inventory(root,version='v2',preparation_only=True)
        return collector.PreparedInput(root/'prepared.json',collector.sha(root/'prepared.json'),
            collector.sha(root/'artifact-files.json'),'a'*40,'b'*40)

    def output(self, parent, name='execute'):
        root = parent/name; root.mkdir()
        return collector.CollectorIO(root,'v2')

    def test_real_marker_once_retains_both_bundles_and_passes_only_component_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory); source=self.prepared(parent); io=self.output(parent)
            owner=collector.ClaimOwner(io,source); marker=io.output/'marker'
            try:
                command=[str(io.output/'frozen'/(collector.TARGET+'.bin')),str(marker)]
                row=owner.run_once(command,{},timeout=2); self.assertTrue(row['complete_success'])
                with self.assertRaisesRegex(ValueError,'ONE_SHOT'): owner.run_once(command,{},timeout=2)
                self.assertEqual(marker.read_text(),'X'); owner.finish(True,returncode=row['returncode'])
            finally: owner.close()
            self.assertTrue(io.finish('results.json',dict(complete_success=True,qualification=False),True))
            bundle=reader.IdentityBundle(io.output,collector.sha(io.output/'artifact-files.json'),version='v2')
            try:
                result=reader.validate_prepared_claim_link(bundle,source,native=False)
                self.assertTrue(result['component_claim_readback_pass']); self.assertFalse(result['full_campaign_qualified'])
                other=self.output(parent,'retry')
                with self.assertRaises(FileExistsError): collector.ClaimOwner(other,source)
                self.assertFalse(other.finish('results.json',dict(complete_success=False),False))
                self.assertEqual(marker.read_text(),'X')
                (source.root/'artifact-files.json').unlink()
                with self.assertRaises(OSError): reader.validate_prepared_claim_link(bundle,source,native=False)
            finally: bundle.close(); source.close()

    def test_preexisting_empty_or_partial_claim_blocks_without_copy_or_child(self):
        for mode in ('empty','partial'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                parent=Path(directory); source=self.prepared(parent); io=self.output(parent)
                claim=source.root.with_name(collector.claim_basename(source)); claim.mkdir()
                if mode=='partial': (claim/'claim.json.partial.json').write_bytes(b'historical partial')
                try:
                    with patch.object(collector,'run_bounded') as child,self.assertRaises(FileExistsError):
                        collector.ClaimOwner(io,source)
                    child.assert_not_called(); self.assertFalse((io.output/'frozen').exists())
                    if mode=='partial': self.assertEqual((claim/'claim.json.partial.json').read_bytes(),b'historical partial')
                    self.assertFalse(io.finish('results.json',dict(complete_success=False),False))
                finally: source.close()

    def test_copy_failure_and_partial_claim_publish_permanently_block_reentry(self):
        for mode in ('copy','publish'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                parent=Path(directory); source=self.prepared(parent); io=self.output(parent); publish=collector.publish_new
                def inject(fd,temporary,destination):
                    if destination=='claim.json': raise OSError(5,'injected claim publish failure')
                    return publish(fd,temporary,destination)
                patcher=(patch.object(io.writer,'copy',side_effect=OSError(5,'injected frozen copy failure'))
                         if mode=='copy' else patch.object(collector,'publish_new',side_effect=inject))
                try:
                    before=len(collector.os.listdir('/proc/self/fd'))
                    with patcher,self.assertRaises(OSError): collector.ClaimOwner(io,source)
                    self.assertEqual(len(collector.os.listdir('/proc/self/fd')),before)
                    claim=source.root.with_name(collector.claim_basename(source))
                    self.assertTrue((claim/'owner.lock').exists()); self.assertTrue((claim/'terminal.json').exists())
                    if mode=='publish': self.assertGreater((claim/'claim.json.partial.json').stat().st_size,0)
                    self.assertFalse(io.finish('results.json',dict(complete_success=False),False))
                    other=self.output(parent,'retry')
                    with self.assertRaises(FileExistsError): collector.ClaimOwner(other,source)
                    self.assertFalse(other.finish('results.json',dict(complete_success=False),False))
                finally: source.close()

    def test_replaced_execution_or_mutated_external_claim_rejects_marker_and_same_owner_retry(self):
        for mode in ('directory','claim'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                parent=Path(directory); source=self.prepared(parent); io=self.output(parent); owner=collector.ClaimOwner(io,source)
                marker=parent/'marker'
                try:
                    if mode=='directory': io.output.rename(parent/'old-execute'); io.output.mkdir()
                    else: (source.root.with_name(collector.claim_basename(source))/'claim.json').write_text('{}')
                    command=[str(io.output/'frozen'/(collector.TARGET+'.bin')),str(marker)]
                    with patch.object(collector,'run_bounded') as child,self.assertRaises(ValueError):
                        owner.run_once(command,{},timeout=2)
                    child.assert_not_called(); self.assertFalse(marker.exists())
                    with self.assertRaisesRegex(ValueError,'ONE_SHOT'): owner.run_once(command,{},timeout=2)
                    owner.finish(False,error='retained pre-child identity failure')
                finally: owner.close(); source.close(); io.writer.close()


class LinkedEntryV1Tests(unittest.TestCase):
    def test_real_v2_full_guard_still_stops_before_any_input_or_claim_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); output=root/'out'; output.mkdir()
            args=SimpleNamespace(profile='v2',prepared=root/'absent/prepared.json',prepared_sha256='0'*64,
                expected_head='a'*40,expected_tree='b'*40)
            with patch.object(collector,'environment',return_value={}),patch.object(collector,'ClaimOwner') as owner:
                self.assertFalse(collector.execute(args,output)); owner.assert_not_called()
            row=reader.read_json(output/'results.json')
            self.assertFalse(row['selector_executed']); self.assertEqual(row['failure'],'V2_FULL_IO_BOUNDARY_NOT_IMPLEMENTED')
            self.assertEqual(row['schema'],'pon-identity-churn-execution-v2-one-shot-v1')

    def test_strict_entry_requires_explicit_original_root_before_following_any_link(self):
        selected=collector.profile('v2'); selected['execution_enabled']=True
        with patch.object(reader,'profile',return_value=selected),patch.object(reader,'IdentityBundle') as bundle, \
             self.assertRaisesRegex(ValueError,'explicit original preparation root'):
            reader.validate_bundle('/not-opened','0'*64,'a'*40,'b'*40,version='v2')
        bundle.assert_not_called()

    def test_linked_sealing_counts_all_actual_paths_and_marker_cannot_become_native_campaign(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory); fixture=OneShotClaimOwnerV1Tests(); source=fixture.prepared(parent); io=fixture.output(parent)
            owner=collector.ClaimOwner(io,source)
            try:
                step=owner.run_once([str(io.output/'frozen'/(collector.TARGET+'.bin')),str(io.output/'marker')],{},timeout=2)
                owner.finish(True,returncode=step['returncode'])
            finally: owner.close()
            self.assertTrue(io.finish('results.json',dict(complete_success=True,qualification=False),True))
            manifest=collector.sha(io.output/'artifact-files.json')
            bundle=reader.IdentityBundle(io.output,manifest,version='v2')
            try:
                view=reader.validate_prepared_claim_link(bundle,source,native=False)
                claim=source.root.with_name(collector.claim_basename(source))
                total=sum(p.stat().st_size for root in (source.root,io.output,claim) for p in root.rglob('*') if p.is_file())
                self.assertEqual(view['evidence_ledger']['total_bytes'],total)
                self.assertEqual(view['evidence_ledger']['bucket_bytes']['binary'],2*source.binding['binary_bytes'])
                with self.assertRaises(ValueError): reader.validate_prepared_claim_link(bundle,source,native=True)
                with self.assertRaisesRegex(ValueError,'HELD_ORIGINAL_PREPARATION_REQUIRED'):
                    collector.inventory(io.output,version='v2')
                self.assertEqual(collector.sha(io.output/'artifact-files.json'),manifest)
            finally: bundle.close(); source.close()


class FirstExecFdBindingV1Tests(unittest.TestCase):
    """Actual ancestor rebinding; only an owned Python marker, never native W1."""
    def prepared(self,parent):
        root=parent/'prepared';root.mkdir();binary=root/(collector.TARGET+'.bin')
        binary.write_bytes(b'#!/usr/bin/python3\nimport os,sys,json\n'
            b'def ident(p):\n s=os.stat(p);return dict(device=s.st_dev,inode=s.st_ino)\n'
            b'raw=os.environ["TRNM_IDENTITY_CAMPAIGN_DIR"];os.mkdir(raw)\n'
            b'value=dict(cwd_identity=ident("."),raw_parent_identity=ident(os.path.dirname(raw)),'
            b'executable_identity=ident(sys.argv[0]),qualification=False)\n'
            b'with open(raw+"/report.json","x") as f:json.dump(value,f)\n'
            b'with open(sys.argv[1],"x") as f:f.write("X")\nprint(json.dumps(value))\n')
        binary.chmod(0o500);files={binary.name:dict(bytes=binary.stat().st_size,sha256=collector.sha(binary))}
        value=dict(schema=collector.profile('v2')['prepared_schema'],prepared=True,selector_executed=False,
            plan=collector.PLAN,acceptance=collector.ACCEPTANCE,head='a'*40,tree='b'*40,
            evidence_caps=collector.profile('v2')['evidence_caps'],runner_sha256=collector.sha(collector.__file__),
            collector_seconds=2,files=files,binary=dict(path=str(binary),**files[binary.name]),
            scope='owned Python FD marker only; not native W1 or full qualification')
        collector.write_new(root/'prepared.json',value);collector.inventory(root,version='v2',preparation_only=True)
        return collector.PreparedInput(root/'prepared.json',collector.sha(root/'prepared.json'),
            collector.sha(root/'artifact-files.json'),'a'*40,'b'*40)

    def adversarial_case(self, parent, mode):
        active=parent/'active';active.mkdir();cwd=active/'source';cwd.mkdir()
        fixture=OneShotClaimOwnerV1Tests()
        with patch.object(collector,'ROOT',cwd):
            source=self.prepared(active);io=fixture.output(active);owner=collector.ClaimOwner(io,source)
        moved=parent/'moved';original_cwd=collector.identity(collector.os.fstat(owner.cwd_fd))
        bundle_fd=collector.os.dup(io.writer.fd);cwd_fd=collector.os.dup(owner.cwd_fd)
        real_run=collector.run_bounded
        def rebind():
            active.rename(moved);(active/'source').mkdir(parents=True)
            shadow=active/'execute'/'frozen';shadow.mkdir(parents=True)
            (shadow/(collector.TARGET+'.bin')).write_bytes(
                b'#!/usr/bin/python3\nimport sys\nwith open(sys.argv[1],"a") as f:f.write("WRONG")\n')
            (shadow/(collector.TARGET+'.bin')).chmod(0o500)
        def launch(*args,**kwargs):
            if mode=='after-check':rebind()
            self.assertEqual(kwargs['cwd'],'/proc/self/fd/'+str(owner.cwd_fd))
            self.assertEqual(kwargs['executable_fd'],owner.executable_fd)
            self.assertEqual(collector.os.stat(kwargs['cwd']).st_ino,original_cwd['inode'])
            self.assertEqual(kwargs['env']['TRNM_IDENTITY_CAMPAIGN_DIR'],
                             '/proc/self/fd/'+str(io.writer.fd)+'/raw')
            return real_run(*args,**kwargs)
        try:
            if mode=='before-check':rebind()
            with patch.object(collector,'run_bounded',side_effect=launch):
                row=owner.run_once([str(io.output/'frozen'/(collector.TARGET+'.bin')),str(io.output/'marker')],{},timeout=2)
            self.assertTrue(row['complete_success']);self.assertEqual((moved/'execute'/'marker').read_text(),'X')
            self.assertFalse((active/'execute'/'marker').exists())
            self.assertEqual(collector.os.listdir(active/'execute'),['frozen'])
            self.assertEqual(row['fd_dispatch']['cwd_identity'],original_cwd)
            observed=reader.read_json(moved/'execute/raw/report.json')
            self.assertEqual(observed['cwd_identity'],original_cwd)
            self.assertEqual(observed['raw_parent_identity'],collector.identity(collector.os.fstat(io.writer.fd)))
            self.assertEqual(observed['executable_identity'],owner.executable_identity)
            owner.finish(True,returncode=row['returncode']);owner.close()
            self.assertTrue(io.finish('results.json',dict(complete_success=True,qualification=False),True))
            manifest=collector.checked_member(bundle_fd,'artifact-files.json')[0]['sha256']
            bundle=reader.IdentityBundle(io.output,manifest,version='v2',directory_fd=bundle_fd)
            try:
                view=reader.validate_prepared_claim_link(bundle,source,native=False,cwd_directory_fd=cwd_fd)
                self.assertTrue(view['first_exec_output_fd_binding_readback'])
                self.assertFalse(view['native_descendant_path_binding_complete'])
                self.assertFalse(view['full_campaign_qualified'])
                self.assertEqual(bundle.json('campaign.step.json')['fd_dispatch'],row['fd_dispatch'])
                return dict(schema='pn1-first-exec-fd-marker-control-v1',mode=mode,
                    source_cwd_identity=original_cwd,retained_root=str(moved/'execute'),
                    shadow_root=str(active/'execute'),marker='X',shadow_marker_exists=False,
                    manifest_sha256=manifest,readback=view,native_w1_executed=False,
                    full_guard_enabled=collector.V2_FULL_IO_BOUNDARY_IMPLEMENTED)
            finally:bundle.close()
        finally:
            owner.close();source.close();io.writer.close()
            collector.os.close(bundle_fd);collector.os.close(cwd_fd)

    def test_actual_ancestor_rebind_before_checks_uses_original_exec_and_output_fds(self):
        with tempfile.TemporaryDirectory() as directory:self.adversarial_case(Path(directory),'before-check')

    def test_actual_ancestor_rebind_after_checks_uses_original_exec_and_output_fds(self):
        with tempfile.TemporaryDirectory() as directory:self.adversarial_case(Path(directory),'after-check')


class HeldInventoryOwnerV1Tests(unittest.TestCase):
    def test_standalone_v2_inventory_retains_one_fd_across_ancestor_rebinding(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory);active=parent/'active';root=active/'bundle';root.mkdir(parents=True)
            (root/'original.json').write_bytes(b'original');moved=parent/'moved'
            names=collector.held_file_names
            def rebind(fd):
                result=names(fd);active.rename(moved);root.mkdir(parents=True)
                (root/'shadow.json').write_bytes(b'shadow');return result
            with patch.object(collector,'held_file_names',side_effect=rebind), \
                 patch.object(collector,'V2Writer',wraps=collector.V2Writer) as owners:
                collector.inventory(root,version='v2',preparation_only=True)
            self.assertEqual(owners.call_count,1)
            self.assertFalse((root/'artifact-files.json').exists())
            self.assertEqual((root/'shadow.json').read_bytes(),b'shadow')
            manifest=moved/'bundle/artifact-files.json'
            bundle=reader.IdentityBundle(moved/'bundle',collector.sha(manifest),version='v2')
            try:self.assertEqual(set(bundle.files),{'original.json'})
            finally:bundle.close()


class DescendantFdReadbackV1Tests(unittest.TestCase):
    """Bounded record/file controls; never execute W1 or assert a campaign pass."""
    def fixture(self, directory):
        import json
        import os
        root = Path(directory)
        phase = root/'raw/fresh-identities'
        actor = phase/'actor-00'
        actor.mkdir(parents=True, mode=0o700)
        phase.chmod(0o700)
        job = dict(worker=0, mode='fresh-identities', plan=copy.deepcopy(collector.PLAN),
            binary_sha256='a'*64, output='/proc/self/fd/11/raw/fresh-identities/actor-00',
            prefix_marker='/proc/self/fd/11/raw/fresh-identities/prefix-start.json',
            pressure_marker='/proc/self/fd/11/raw/fresh-identities/pressure-start.json')
        raw = json.dumps(job, sort_keys=True, separators=(',', ':')).encode()
        path = actor/'job.json'
        path.write_bytes(raw)
        path.chmod(0o600)
        identity = lambda p: dict(device=p.stat().st_dev, inode=p.stat().st_ino)
        pin = dict(identity=dict(device=root.stat().st_dev, inode=1), bytes=100, sha256='a'*64)
        caller = dict(schema=reader.DESCENDANT_SCHEMA, kind='caller-scope', scope=reader.DESCENDANT_SCOPE,
            parent_pid=101, python_inputs=[dict(fd=fd, kind=kind, identity=id, before_cloexec=False)
                for fd,kind,id in [(10,'executable',pin['identity']),(11,'output',identity(root)),
                                   (12,'source-cwd',dict(device=1,inode=999))]],
            remaining_inheritable=[], external_library_concurrent_spawn_supported=False,
            full_campaign_qualified=False)
        dispatch = dict(schema=collector.FD_DISPATCH_SCHEMA, qualification=False,
            native_descendant_path_binding_complete=False, executable_fd=10, execution_directory_fd=11,
            cwd_directory_fd=12, inherited_fds=[10,11,12], executable_identity=pin['identity'],
            executable_bytes=100, executable_sha256='a'*64, execution_identity=identity(root),
            cwd_identity=dict(device=1,inode=999), actual_executable='/proc/self/fd/10',
            actual_cwd='/proc/self/fd/12', actual_raw_root='/proc/self/fd/11/raw')
        binding = dict(schema=reader.DESCENDANT_SCHEMA, scope=reader.DESCENDANT_SCOPE,
            parent_pid=101, executable=pin, fds=[20,21,22,23], phase=identity(phase), output=identity(actor),
            job_identity=identity(path), job_bytes=len(raw), job_sha256=reader.sha(raw),
            plan_sha256=reader.sha(json.dumps(job['plan'],sort_keys=True,separators=(',',':')).encode()))
        parent = dict(schema=reader.DESCENDANT_SCHEMA, kind='parent-dispatch', binding=binding,
            inherited_nonstdio=[20,21,22,23], parent_restored_cloexec=True, caller=caller,
            full_campaign_qualified=False)
        child = dict(schema=reader.DESCENDANT_SCHEMA, kind='child-verified', binding=copy.deepcopy(binding),
            actual_executable=copy.deepcopy(pin), inherited_nonstdio_after_quarantine=[],
            job_raw_and_plan_checked=True, input_lifetime='process-lifetime-cloexec-quarantine-os-close-on-exit',
            scope=reader.DESCENDANT_SCOPE, general_process_sandbox=False, full_campaign_qualified=False)
        return dict(root=root, caller=caller, dispatch=dispatch, parent=parent, child=child, job=job, pin=pin)

    def check(self, row, bundle, *, original=False):
        return reader.descendant_actor_record(bundle, 'raw/fresh-identities/actor-00/',
            'raw/fresh-identities/', row['parent'], row['child'], row['job'], caller=row['caller'],
            executable=row['pin'], parent_pid=101,
            original_root_identity=row['dispatch']['execution_identity'] if original else None)

    def test_first_exec_to_caller_requires_exact_original_three_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            row=self.fixture(directory)
            result=reader.descendant_caller_binding(row['caller'],row['dispatch'],101,row['pin'])
            self.assertEqual(result['executable'],row['pin'])
            mutations=[lambda r:r['caller']['python_inputs'].pop(),
                lambda r:r['caller']['python_inputs'][0].__setitem__('fd',0),
                lambda r:r['caller']['python_inputs'][1].__setitem__('kind','executable'),
                lambda r:r['caller']['python_inputs'][2].__setitem__('identity',dict(device=1,inode=1)),
                lambda r:r['caller'].__setitem__('remaining_inheritable',[99]),
                lambda r:r['dispatch'].__setitem__('executable_sha256','b'*64),
                lambda r:r['caller'].__setitem__('parent_pid',102)]
            for mutate in mutations:
                bad=copy.deepcopy(row);mutate(bad)
                with self.subTest(mutate=mutate),self.assertRaises(ValueError):
                    reader.descendant_caller_binding(bad['caller'],bad['dispatch'],101,bad['pin'])

    def test_record_continuity_and_explicit_original_live_identity_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            row=self.fixture(directory)
            with closing(reader.ObservedControlBundle(row['root'])) as bundle:
                archived=self.check(row,bundle)
                live=self.check(row,bundle,original=True)
            self.assertTrue(archived['recorded_binding_continuity'])
            self.assertFalse(archived['live_original_inode_checked'])
            self.assertFalse(archived['archive_inode_authentication'])
            self.assertTrue(live['live_original_inode_checked'])
            self.assertFalse(live['full_campaign_qualified'])

    def test_all_four_fds_restore_child_quarantine_and_scope_are_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            row=self.fixture(directory)
            mutations=[lambda r:r['parent']['binding']['fds'].__setitem__(3,0),
                lambda r:r['parent']['binding']['fds'].__setitem__(3,22),
                lambda r:r['parent'].__setitem__('parent_restored_cloexec',False),
                lambda r:r['parent']['inherited_nonstdio'].append(99),
                lambda r:r['child']['inherited_nonstdio_after_quarantine'].append(99),
                lambda r:r['child'].__setitem__('scope','arbitrary-library-spawn'),
                lambda r:r['child'].__setitem__('input_lifetime','already-closed'),
                lambda r:r['child']['binding'].__setitem__('parent_pid',102),
                lambda r:r['child']['actual_executable']['identity'].__setitem__('inode',2),
                lambda r:r['child']['actual_executable'].__setitem__('sha256','b'*64),
                lambda r:r['parent']['binding'].__setitem__('schema','old-raw-v2'),
                lambda r:r['parent'].__setitem__('full_campaign_qualified',True)]
            with closing(reader.ObservedControlBundle(row['root'])) as bundle:
                for mutate in mutations:
                    bad=copy.deepcopy(row);mutate(bad)
                    with self.subTest(mutate=mutate),self.assertRaises(ValueError):self.check(bad,bundle)

    def test_actual_job_bytes_plan_digest_and_source_binary_cannot_borrow_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            row=self.fixture(directory)
            mutations=[lambda r:r['parent']['binding'].__setitem__('job_sha256','0'*64),
                lambda r:r['parent']['binding'].__setitem__('job_bytes',1),
                lambda r:r['parent']['binding'].__setitem__('plan_sha256','0'*64),
                lambda r:r['job']['plan'].__setitem__('actors',2),
                lambda r:r['job'].__setitem__('binary_sha256','b'*64)]
            with closing(reader.ObservedControlBundle(row['root'])) as bundle:
                for mutate in mutations:
                    bad=copy.deepcopy(row);mutate(bad)
                    # Make parent and child agree, so independent raw checks
                    # rather than simple receipt equality must reject this.
                    bad['child']['binding']=copy.deepcopy(bad['parent']['binding'])
                    with self.subTest(mutate=mutate),self.assertRaises(ValueError):self.check(bad,bundle)

    def test_cross_worker_phase_marker_replays_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            row=self.fixture(directory)
            reader.descendant_job_location(row['job'],row['dispatch']['actual_raw_root'],'fresh-identities',0)
            for key,value in [('worker',1),('mode','replay-only'),
                    ('output','/proc/self/fd/11/raw/fresh-identities/actor-01'),
                    ('prefix_marker','/proc/self/fd/11/raw/replay-only/prefix-start.json'),
                    ('pressure_marker','/proc/self/fd/12/raw/fresh-identities/pressure-start.json')]:
                job=copy.deepcopy(row['job']);job[key]=value
                with self.subTest(key=key),self.assertRaises(ValueError):
                    reader.descendant_job_location(job,row['dispatch']['actual_raw_root'],'fresh-identities',0)

    def test_archive_copies_do_not_authenticate_original_inode_or_create_live_authority(self):
        import shutil
        with tempfile.TemporaryDirectory() as directory:
            row=self.fixture(Path(directory)/'original')
            archive=Path(directory)/'archive'
            shutil.copytree(row['root'],archive)
            with closing(reader.ObservedControlBundle(archive)) as bundle:
                self.assertFalse(self.check(row,bundle)['live_original_inode_checked'])
                with self.assertRaisesRegex(ValueError,'copied archive'):
                    self.check(row,bundle,original=True)
                bad=copy.deepcopy(row)
                bad['dispatch']['execution_identity']=dict(device=archive.stat().st_dev,inode=archive.stat().st_ino)
                with self.assertRaisesRegex(ValueError,'original held actor'):
                    self.check(bad,bundle,original=True)

    def test_missing_binding_and_boolean_fd_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            row=self.fixture(directory)
            with closing(reader.ObservedControlBundle(row['root'])) as bundle:
                for target,key in [('parent','binding'),('child','binding')]:
                    bad=copy.deepcopy(row);del bad[target][key]
                    with self.subTest(target=target),self.assertRaises(ValueError):self.check(bad,bundle)
                bad=copy.deepcopy(row);bad['parent']['binding']['fds'][0]=True
                with self.assertRaises(ValueError):self.check(bad,bundle)


class ActualDescendantFdReadbackV1Tests(unittest.TestCase):
    def test_frozen_ordinary_fd_control_records_are_read_without_new_process_or_inode_claim(self):
        import hashlib
        if ACTUAL_DESCENDANT_FD_CONTROL is None:self.skipTest('explicit retained ordinary control required')
        root=ACTUAL_DESCENDANT_FD_CONTROL
        pin=reader.read_json(root/'frozen-input.json')
        result=reader.read_json(root/'result.json')
        self.assertTrue(result['native_complete_success'])
        image=Path(result['actual_binary_path'])
        with image.open('rb') as stream:
            actual=hashlib.file_digest(stream,'sha256').hexdigest()
        self.assertEqual(actual,pin['binary']['sha256'])
        with closing(reader.ObservedControlBundle(root/'raw')) as bundle:
            report=bundle.json('report.json')
            positive=report['rows'][0]
            self.assertEqual(positive['mode'],'ancestor-shadow')
            self.assertTrue(positive['success'])
            self.assertFalse(positive['forced_kill'])
            job=bundle.json('moved/phase/actor-00/job.json')
            observed=reader.descendant_actor_record(bundle,'moved/phase/actor-00/','moved/phase/',
                positive['parent'],positive['ready']['execution'],job,caller=report['caller'],
                executable=report['actual_parent_executable'],parent_pid=report['caller']['parent_pid'])
            self.assertEqual(report['actual_parent_executable']['sha256'],actual)
            self.assertTrue(observed['actual_job_bytes_checked'])
            self.assertFalse(observed['live_original_inode_checked'])
            self.assertFalse(observed['full_campaign_qualified'])
            self.assertTrue(report['all_children_joined'])
            self.assertEqual(report['native_w1_calls'],0)
            self.assertEqual(report['node_opens'],0)
            self.assertFalse(report['full_campaign_qualified'])


class DescendantFieldTypeV1Tests(unittest.TestCase):
    fixture = DescendantFdReadbackV1Tests.fixture
    check = DescendantFdReadbackV1Tests.check

    def test_job_worker_zero_and_one_are_ints_not_boolean_or_float_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            row=self.fixture(directory)
            for worker in (0,1):
                job=copy.deepcopy(row['job'])
                job['worker']=worker
                job['output']=f'/proc/self/fd/11/raw/fresh-identities/actor-{worker:02}'
                reader.descendant_job_location(job,row['dispatch']['actual_raw_root'],'fresh-identities',worker)
                aliases=(False,0.0) if worker==0 else (True,1.0)
                for alias in aliases:
                    bad=copy.deepcopy(job);bad['worker']=alias
                    with self.subTest(alias=repr(alias)),self.assertRaises(ValueError):
                        reader.descendant_job_location(bad,row['dispatch']['actual_raw_root'],'fresh-identities',worker)

    def test_phase_parent_pid_cannot_use_same_value_float(self):
        with tempfile.TemporaryDirectory() as directory:
            row=self.fixture(directory)
            with closing(reader.ObservedControlBundle(row['root'])) as bundle:
                self.check(row,bundle)
                for actual,alias in [(101,101.0),(1,True)]:
                    bad=copy.deepcopy(row)
                    bad['caller']['parent_pid']=actual
                    bad['parent']['binding']['parent_pid']=actual
                    bad['child']['binding']['parent_pid']=actual
                    with self.subTest(alias=repr(alias)),self.assertRaises(ValueError):
                        reader.descendant_actor_record(bundle,'raw/fresh-identities/actor-00/',
                            'raw/fresh-identities/',bad['parent'],bad['child'],bad['job'],caller=bad['caller'],
                            executable=bad['pin'],parent_pid=alias)

    def test_plan_exact_keys_and_types_reject_independently_consistent_alias_bytes(self):
        import json
        mutations=[lambda p:p.__setitem__('actors',24.0),
            lambda p:p.__setitem__('qualification',1),
            lambda p:p.__setitem__('pressure_seconds',30.0),
            lambda p:p.__setitem__('pressure_schedule',False),
            lambda p:p.pop('rounds'),lambda p:p.__setitem__('unknown',0)]
        for mutate in mutations:
            with self.subTest(mutate=mutate),tempfile.TemporaryDirectory() as directory:
                row=self.fixture(directory)
                mutate(row['job']['plan'])
                raw=json.dumps(row['job'],sort_keys=True,separators=(',',':')).encode()
                (row['root']/'raw/fresh-identities/actor-00/job.json').write_bytes(raw)
                binding=row['parent']['binding']
                binding.update(job_bytes=len(raw),job_sha256=reader.sha(raw),
                    plan_sha256=reader.sha(json.dumps(row['job']['plan'],sort_keys=True,
                        separators=(',',':')).encode()))
                row['child']['binding']=copy.deepcopy(binding)
                with closing(reader.ObservedControlBundle(row['root'])) as bundle:
                    with self.assertRaisesRegex(ValueError,'Plan'):self.check(row,bundle)


class V2PhaseIdentityTypesTests(unittest.TestCase):
    fixture = DescendantFdReadbackV1Tests.fixture
    check = DescendantFdReadbackV1Tests.check

    def test_declared_identity_positions_refuse_equal_boolean_float_and_unknown_aliases(self):
        # These are field-boundary vectors, not measurements or native rounds.
        for kind, fields in reader.V2_INTEGER_IDENTITY_FIELDS.items():
            row={key:0 for key in fields.split()}
            reader.v2_identity_types(kind,row)
            for key in fields.split():
                for alias in (False,0.0,None):
                    bad=copy.deepcopy(row);bad[key]=alias
                    with self.subTest(kind=kind,key=key,alias=repr(alias)),self.assertRaises(ValueError):
                        reader.v2_identity_types(kind,bad)

    def test_inherited_census_and_duplicate_caller_do_not_borrow_binding_integer_types(self):
        with tempfile.TemporaryDirectory() as directory:
            row=self.fixture(directory)
            with closing(reader.ObservedControlBundle(row['root'])) as bundle:
                self.check(row,bundle)
                bad=copy.deepcopy(row)
                bad['parent']['inherited_nonstdio']=[float(fd) for fd in bad['parent']['inherited_nonstdio']]
                self.assertEqual(bad['parent']['inherited_nonstdio'],row['parent']['inherited_nonstdio'])
                with self.assertRaises(ValueError):self.check(bad,bundle)
                for key,alias in [('parent_pid',101.0),('full_campaign_qualified',0)]:
                    bad=copy.deepcopy(row)
                    bad['parent']['caller']=copy.deepcopy(bad['caller'])
                    bad['parent']['caller'][key]=alias
                    self.assertEqual(bad['parent']['caller'],bad['caller'])
                    with self.assertRaises(ValueError):self.check(bad,bundle)
            bad=copy.deepcopy(row)
            bad['dispatch']['inherited_fds']=[float(fd) for fd in bad['dispatch']['inherited_fds']]
            with self.assertRaises(ValueError):
                reader.descendant_caller_binding(bad['caller'],bad['dispatch'],101,bad['pin'])
            # Preserve the old first-exec component's legitimate minimum 0;
            # its boolean/float aliases still cannot stand in for integer FDs.
            reader.v2_fd_census([0,1,2],minimum=0)
            for aliases in ([False,1,2],[0.0,1,2]):
                with self.assertRaises(ValueError):reader.v2_fd_census(aliases,minimum=0)

    def test_copy_type_continuity_catches_nested_sample_and_child_scalar_aliases(self):
        for expected,actual in [({'pid':101},{'pid':101.0}),({'worker':0},{'worker':False}),
                ({'Ok':{'credit':0}},{'Ok':{'credit':0.0}}),
                ({'ready':{'flags':[False]}},{'ready':{'flags':[0]}})]:
            self.assertEqual(actual,expected)
            with self.assertRaises(ValueError):reader.v2_copy_types(actual,expected)
        reader.v2_copy_types({'operation':None},{'operation':None})

    def test_nested_sample_owner_is_required_and_unknown_values_are_never_zeroed(self):
        owner={key:1 for key in reader.V2_INTEGER_IDENTITY_FIELDS['sample_owner'].split()}
        owner.update(sampler_thread_joined=True,sampler_thread_panicked=False)
        phase={'samples':owner}
        self.assertIs(reader.v2_sample_owner(phase),owner)
        for bad in [{}, {'sample_count':1,'sample_files':['samples-00.jsonl']}, {'samples':None}]:
            with self.assertRaises(ValueError):reader.v2_sample_owner(bad)
        for key,alias in [('sample_count',True),('sample_bytes',1.0),('sample_count',None),
                ('sampler_thread_joined',False),('sampler_thread_panicked',True)]:
            bad=copy.deepcopy(phase);bad['samples'][key]=alias
            with self.subTest(key=key),self.assertRaises(ValueError):reader.v2_sample_owner(bad)
            self.assertIs(bad['samples'][key],alias)

    def test_nullable_receiver_operation_preserves_unknown_and_refuses_numeric_alias(self):
        records=dict(records_not_retained=0,measurement_failures=0,accepted_connections_seen=1,
            capacity=4096,records=[dict(operation=None,body_digest=[0]*32)])
        metrics=dict(mutation_cpu_charged_ns=0,mutation_cpu_clock_failures=0)
        reader.v2_receiver_types(records,metrics)
        self.assertIsNone(records['records'][0]['operation'])
        for alias in (True,1.0):
            bad=copy.deepcopy(records);bad['records'][0]['operation']=alias
            with self.assertRaises(ValueError):reader.v2_receiver_types(bad,metrics)
        bad=copy.deepcopy(records);bad['records'][0]['body_digest'][0]=False
        with self.assertRaises(ValueError):reader.v2_receiver_types(bad,metrics)


class ActualV2PhaseIdentityTypesTests(unittest.TestCase):
    def test_original_cdb_finite_pass_records_and_nested_samples_are_read_without_requalification(self):
        if ACTUAL_V2_FINITE_CAMPAIGN is None:self.skipTest('explicit retained cdb finite result required')
        root=ACTUAL_V2_FINITE_CAMPAIGN
        result=reader.read_json(root/'result.json')
        step=reader.read_json(root/'native.step.json')
        pin=reader.read_json(root/'input-pin.json')
        self.assertTrue(result['native_complete_success'])
        self.assertEqual(step['returncode'],0)
        self.assertEqual(pin['binary']['sha256'],'cdb1509b21e074db2f3cd40073c1df5d404e8f53b02c75809de1b760f907ae3e')
        with closing(reader.ObservedControlBundle(root/'raw')) as bundle:
            phase=bundle.json('fresh-identities/report.json')
            reader.v2_identity_types('phase',phase)
            self.assertNotIn('sample_count',phase)
            self.assertNotIn('sample_files',phase)
            owner=reader.v2_sample_owner(phase)
            self.assertIs(owner,phase['samples'])
            samples=[reader.strict_json(line) for line in
                reader.sample_lines(bundle,'fresh-identities/',owner,version='v2')]
            self.assertEqual(len(samples),owner['sample_count'])
            self.assertGreater(len(samples),0)
            for sample in samples:
                reader.v2_identity_types('sample',sample)
                reader.v2_identity_types('meter',sample['meter'])
                reader.v2_identity_types('freshness',sample['credit_freshness'])
            reader.v2_receiver_types(phase['receiver_observation'],phase['service_outcome']['Ok'])
            for worker,child in enumerate(phase['children']):
                reader.v2_identity_types('child',child)
                path=f'fresh-identities/actor-{worker:02}/'
                for kind,name in [('ready','ready.json'),('result','report.json'),('finished','prefix-finished.json')]:
                    reader.v2_identity_types(kind,bundle.json(path+name))
                actor=bundle.json(path+'report.json')
                for stage in ('prefix','pressure'):
                    for slot in actor[stage+'_slots']:
                        reader.v2_identity_types('slot',slot)
                for name in bundle.files:
                    if name.startswith(path) and name.endswith('-started.json'):
                        reader.v2_identity_types('started',bundle.json(name))
                    if name.startswith(path) and name.endswith('-construction.json'):
                        construction=bundle.json(name)
                        reader.v2_identity_types('construction',construction)
                        reader.v2_identity_types('construction_budget',construction['evidence_budget'])
                        for attempt in construction['attempts']:reader.v2_identity_types('attempt',attempt)
                    if name.startswith(path) and name.endswith('-call.json'):
                        reader.v2_identity_types('wrapper',bundle.json(name))
            self.assertFalse(bundle.json('report.json')['full_v2_io_boundary_implemented'])
            self.assertFalse(bundle.json('report.json')['finite_service_qualified'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--actual-prefix-control', type=Path)
    parser.add_argument('--actual-small-campaign', type=Path)
    parser.add_argument('--actual-v2-acquisition', type=Path)
    parser.add_argument('--actual-v2-descriptor', type=Path)
    parser.add_argument('--actual-descendant-fd-control', type=Path)
    parser.add_argument('--actual-v2-finite-campaign', type=Path)
    parser.add_argument('--actual-claim-debug-binary', type=Path, action='append', default=[])
    args, remaining = parser.parse_known_args()
    ACTUAL_CONTROL = args.actual_prefix_control
    ACTUAL_SMALL_CAMPAIGN = args.actual_small_campaign
    ACTUAL_V2_ACQUISITION = args.actual_v2_acquisition
    ACTUAL_V2_DESCRIPTOR = args.actual_v2_descriptor
    ACTUAL_DESCENDANT_FD_CONTROL = args.actual_descendant_fd_control
    ACTUAL_V2_FINITE_CAMPAIGN = args.actual_v2_finite_campaign
    ACTUAL_CLAIM_DEBUG_BINARIES = args.actual_claim_debug_binary
    unittest.main(argv=[__file__, *remaining])
