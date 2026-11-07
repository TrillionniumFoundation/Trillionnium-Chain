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


def main():
    global RAW_DIR
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-dir', required=True, type=Path)
    args, remaining = parser.parse_known_args()
    RAW_DIR = args.raw_dir
    result = unittest.main(argv=[sys.argv[0], *remaining], exit=False)
    return 0 if result.result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
