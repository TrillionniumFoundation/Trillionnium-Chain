#!/usr/bin/env python3
"""Reader counterexamples use real supplied DAA evidence; mutations stay in memory."""
import argparse
import copy
import hashlib
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_daa_schedule_reader as reader

RAW_DIR = None


class RetainedDaaCounterexamples(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (RAW_DIR / 'daa-bounds.json').read_bytes()
        cls.report = reader.load_report(cls.raw)
        cls.packets = {'packets/' + path.name: path.read_bytes() for path in (RAW_DIR / 'packets').iterdir()}
        cls.original = {'daa-bounds.json': reader.sha(cls.raw),
                        **{name: reader.sha(raw) for name, raw in cls.packets.items()}}
        cls.validated = reader.analyze(RAW_DIR, reader.sha(cls.raw))

    @classmethod
    def tearDownClass(cls):
        for name, expected in cls.original.items():
            if reader.sha((RAW_DIR / name).read_bytes()) != expected:
                raise ValueError('original native evidence changed: ' + name)

    def reject(self, change, pattern):
        report, packets = copy.deepcopy(self.report), dict(self.packets)
        change(report, packets)
        with self.assertRaisesRegex(ValueError, pattern):
            reader.analyze_report(report, packets)

    def test_actual_source_packets_replay_all_work_and_retain_native_scope(self):
        self.assertEqual(self.validated['record_and_oracle_consistency'], 'PASS')
        self.assertEqual(self.validated['unique_full_python_verified_proofs'], 84)
        self.assertEqual(self.validated['unique_native_admitted_packets_observed'], 83)
        self.assertEqual(self.validated['native_time_rejections_observed'], 2)
        self.assertTrue(self.validated['full_python_transcript_and_product_recomputed'])
        self.assertFalse(self.validated['reader_performed_native_admission'])
        self.assertFalse(self.validated['proof_hardness_or_timestamp_attack_profitability_qualified'])

    def test_missing_rejection_cannot_improve_admission_fraction(self):
        self.reject(lambda report, _: report['records'].pop(-2), '85-observation')

    def test_missing_packet_and_changed_wire_bytes_are_rejected(self):
        self.reject(lambda _, packets: packets.pop(next(iter(packets))), 'retained packet required')
        def change(_, packets):
            name = next(iter(packets))
            packets[name] = packets[name][:-1] + bytes([packets[name][-1] ^ 1])
        self.reject(change, 'packet bytes changed')

    def test_parent_median_must_come_from_exact_admitted_ancestry(self):
        def change(report, _):
            report['records'][20]['ancestor_timestamps_parent_first'][0] += 1
        self.reject(change, 'median ancestry')

    def test_expected_target_required_work_cannot_use_lucky_ticket_credit(self):
        def change(report, _):
            row = report['records'][0]
            row['required_work_hex'] = (int(row['required_work_hex'], 16) + 1).to_bytes(64, 'big').hex()
        self.reject(change, 'packet work must use expected target')

    def test_chainwork_and_reopen_selection_cannot_be_edited_in_report(self):
        def chainwork(report, _):
            report['records'][0]['admission']['cumulative_required_work_hex'] = '00' * 64
        self.reject(chainwork, 'cumulative branch work')
        self.reject(lambda report, _: report['after_authenticated_reopen'].update(chainwork_hex='00' * 64),
                    'reopen changed')

    def test_future_rejection_and_same_packet_clock_retry_cannot_be_relabelled(self):
        def future(report, _):
            row = next(row for row in report['records'] if row['admission'].get('error') == 'TIME_DEFERRED')
            row['admission'] = {'kind': 'admitted', 'cumulative_required_work_hex': '00' * 64}
        self.reject(future, 'admitted timestamp fails')
        def retry(report, _):
            row = next(row for row in report['records'] if row['schedule'] == 'future-clock-retry')
            row['observed_now'] += 1
        self.reject(retry, 'one clock second later')

    def test_schema_boolean_and_qualification_cannot_supply_evidence(self):
        self.reject(lambda report, _: report.update(public_network_qualification=True), 'unsupported qualification')
        self.reject(lambda report, _: report['records'][0].update(height=True), 'bounded integer')

    def test_external_report_digest_is_required_before_packet_processing(self):
        with self.assertRaisesRegex(ValueError, 'externally recorded DAA report digest'):
            reader.analyze(RAW_DIR, '00' * 32)

    def test_cheap_ticket_valid_false_trace_still_fails_full_python_relation(self):
        def forge(report, packets):
            # This is deliberately only an in-memory counterexample. The actual
            # packet and native report retain their original bytes on disk.
            row = next(row for row in report['records'] if row['admission'].get('error') == 'TIME')
            previous = row['packet_file']
            raw = packets.pop(previous)
            header = raw[:318]
            challenge = reader.wire.H('challenge', header)
            target = bytes.fromhex(row['target'])
            for nonce in range(4096):
                trace = hashlib.sha256(b'DAA-reader-false-trace-only' + nonce.to_bytes(8, 'little')).digest()
                if reader.wire.H('ticket', challenge, trace) <= target:
                    break
            else:
                raise AssertionError('bounded manufactured ticket search exhausted')
            raw = raw[:-32] + trace
            identifier = reader.wire.H('block', header, trace).hex()
            row.update(id=identifier, packet_file='packets/' + identifier + '.pnk', trace=trace.hex(),
                       packet_sha256=reader.sha(raw), proof_sha256=reader.sha(raw[320:]))
            packets[row['packet_file']] = raw
        self.reject(forge, 'full Python PNW1 replay .*TRANSCRIPT')



class RetainedForkChoiceCounterexamples(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (RAW_DIR / 'daa-fork-choice.json').read_bytes()
        cls.report = reader.load_report(cls.raw)
        cls.packets = {'packets/' + path.name: path.read_bytes() for path in (RAW_DIR / 'packets').iterdir()}
        cls.original = {'daa-fork-choice.json': reader.sha(cls.raw),
                        **{name: reader.sha(raw) for name, raw in cls.packets.items()}}
        cls.validated = reader.analyze(RAW_DIR, reader.sha(cls.raw), 'fork-choice')

    @classmethod
    def tearDownClass(cls):
        for name, expected in cls.original.items():
            if reader.sha((RAW_DIR / name).read_bytes()) != expected:
                raise ValueError('original native fork-choice evidence changed: ' + name)

    def reject(self, change, pattern):
        report, packets = copy.deepcopy(self.report), dict(self.packets)
        change(report, packets)
        with self.assertRaisesRegex(ValueError, pattern):
            reader.analyze_report(report, packets)

    def test_full_proofs_support_shorter_harder_and_equal_work_control_only(self):
        self.assertEqual(self.validated['unique_full_python_verified_proofs'], 67)
        self.assertEqual(self.validated['unique_native_admitted_packets_observed'], 67)
        self.assertEqual(self.validated['longer_easier_height'], 49)
        self.assertEqual(self.validated['shorter_harder_height'], 48)
        self.assertGreater(self.validated['shorter_harder_required_chainwork'],
                           self.validated['longer_easier_required_chainwork'])
        self.assertEqual(self.validated['non_winning_activation_attempts_observed'], 4)
        self.assertTrue(self.validated['selected_larger_id_equal_work_sibling'])
        self.assertTrue(self.validated['full_python_transcript_and_product_recomputed'])
        self.assertFalse(self.validated['reader_performed_native_admission'])
        self.assertFalse(self.validated['reader_reopened_native_database'])
        self.assertFalse(self.validated['proof_hardness_or_timestamp_attack_profitability_qualified'])

    def test_no_packet_or_observation_can_be_dropped(self):
        self.reject(lambda report, _: report['records'].pop(), '67-observation')
        self.reject(lambda _, packets: packets.pop(next(iter(packets))), 'retained packet required')

    def test_selected_chainwork_must_equal_target_required_work_sum(self):
        self.reject(lambda report, _: report['longer_easier_selected'].update(chainwork_hex='00' * 64),
                    'selected cumulative work mismatch')
        self.reject(lambda report, _: report['records'][0]['admission'].update(cumulative_required_work_hex='00' * 64),
                    'cumulative branch work mismatch')

    def test_equal_candidate_must_be_a_distinct_same_parent_full_work_sibling(self):
        self.reject(lambda report, _: report.update(equal_work_candidate=report['shorter_harder_selected']['tip']),
                    'selected hard sibling must oppose recovery id ordering')

    def test_nonwinning_attempt_cannot_change_tip_root_or_generation(self):
        self.reject(lambda report, _: report['non_winning_candidates'][0].update(
            returned_tip=report['longer_easier_selected']['tip']), 'lower or equal work changed')
        self.reject(lambda report, _: report['non_winning_candidates'][1]['stats'].update(generation=34),
                    'lower or equal work changed')
        self.reject(lambda report, _: report['non_winning_candidates'][2]['stats'].update(state_root='00' * 32),
                    'lower or equal work changed')

    def test_each_candidate_must_be_tested_before_and_after_authenticated_reopen(self):
        self.reject(lambda report, _: report['non_winning_candidates'].pop(), 'both candidates must be retried')
        self.reject(lambda report, _: report['non_winning_candidates'][3].update(stage='before-reopen'),
                    'non-winning activation grid changed')
        self.reject(lambda report, _: report['after_authenticated_reopen'].update(generation=34),
                    'authenticated reopen changed')

    def test_longer_height_cannot_be_relabelled_and_synthetic_clock_cannot_be_qualified(self):
        self.reject(lambda report, _: report['longer_easier_selected'].update(height=48), 'active height or generation')
        self.reject(lambda report, _: report.update(attacker_work_fraction_measured=True), 'unsupported qualification')
        self.reject(lambda report, _: report.update(equal_work_replaces_active_tip=True), 'unsupported fork-choice claim')

    def test_external_digest_and_explicit_schema_selection_are_required(self):
        with self.assertRaisesRegex(ValueError, 'externally recorded DAA report digest'):
            reader.analyze(RAW_DIR, '00' * 32, 'fork-choice')
        self.reject(lambda report, _: report.update(schema='pon-native-daa-fork-choice-v2'), 'unsupported native DAA report')

    def test_forged_leaf_trace_with_valid_cheap_ticket_fails_full_python_relation(self):
        def forge(report, packets):
            row = next(row for row in report['records'] if row['schedule'] == 'longer-easier' and row['height'] == 49)
            old_id = row['id']
            raw = packets.pop(row['packet_file'])
            header = raw[:318]
            challenge = reader.wire.H('challenge', header)
            target = bytes.fromhex(row['target'])
            for nonce in range(4096):
                trace = hashlib.sha256(b'DAA-fork-choice-false-trace-only' + nonce.to_bytes(8, 'little')).digest()
                if reader.wire.H('ticket', challenge, trace) <= target:
                    break
            else:
                raise AssertionError('bounded manufactured ticket search exhausted')
            raw = raw[:-32] + trace
            identifier = reader.wire.H('block', header, trace).hex()
            row.update(id=identifier, packet_file='packets/' + identifier + '.pnk', trace=trace.hex(),
                       packet_sha256=reader.sha(raw), proof_sha256=reader.sha(raw[320:]))
            packets[row['packet_file']] = raw
            report['longer_easier_selected']['tip'] = identifier
            for attempt in report['non_winning_candidates']:
                if attempt['candidate'] == old_id:
                    attempt['candidate'] = identifier
        self.reject(forge, 'full Python PNW1 replay .*TRANSCRIPT')

def main():
    global RAW_DIR
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-dir', required=True, type=Path)
    parser.add_argument('--report-kind', choices=('bounds', 'fork-choice'), default='bounds')
    args, remaining = parser.parse_known_args()
    RAW_DIR = args.raw_dir
    selected = RetainedForkChoiceCounterexamples if args.report_kind == 'fork-choice' else RetainedDaaCounterexamples
    result = unittest.main(argv=[sys.argv[0], *remaining], defaultTest=selected.__name__, exit=False)
    return 0 if result.result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
