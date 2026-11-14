#!/usr/bin/env python3
"""Retained DAA head/context counterexamples using unchanged real PNW1 packets.

One positive control replays every complete proof. Mutations then exercise the
same analyze_report entry point and must be rejected before the full replay.
This verifies evidence consistency; it does not run or qualify a native node.
"""
import argparse
import copy
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_daa_schedule_reader as reader

ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = ROOT / 'evidence/pon-joint-consensus-daa-20261108/native-retained-final'


class RetainedDaaHeadBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = reader.read_bounded(RAW_DIR / 'daa-bounds.json', 2 * 1024 * 1024)
        cls.report = reader.load_report(cls.raw)
        cls.packets = {'packets/' + path.name: reader.read_bounded(path, reader.PACKET_BYTES)
                       for path in (RAW_DIR / 'packets').iterdir()}
        cls.original = {'daa-bounds.json': reader.sha(cls.raw),
                        **{name: reader.sha(raw) for name, raw in cls.packets.items()}}
        cls.validated = reader.analyze(RAW_DIR, reader.sha(cls.raw))

    @classmethod
    def tearDownClass(cls):
        actual_names = {'packets/' + path.name for path in (RAW_DIR / 'packets').iterdir()}
        if actual_names != set(cls.packets):
            raise ValueError('original native packet inventory changed')
        for name, expected in cls.original.items():
            if reader.sha((RAW_DIR / name).read_bytes()) != expected:
                raise ValueError('original native evidence changed: ' + name)

    @staticmethod
    def heads(report):
        return [item['stats'] for item in report['activations']] + [
            report['selected_before_negative_checks'], report['after_authenticated_reopen']]

    def reject_heads(self, mutate, pattern):
        report = copy.deepcopy(self.report)
        for head in self.heads(report):
            mutate(head)
        with self.assertRaisesRegex(ValueError, pattern):
            reader.analyze_report(report, self.packets)

    def test_actual_packets_keep_full_work_and_limited_scope(self):
        self.assertEqual(self.validated['record_and_oracle_consistency'], 'PASS')
        self.assertEqual(self.validated['observations'], 85)
        self.assertEqual(self.validated['unique_full_python_verified_proofs'], 84)
        self.assertEqual(self.validated['unique_native_admitted_packets_observed'], 83)
        self.assertEqual(self.validated['native_time_rejections_observed'], 2)
        self.assertEqual(self.validated['selected_required_chainwork'], 761)
        self.assertTrue(self.validated['full_python_transcript_and_product_recomputed'])
        for name in ('reader_performed_native_admission', 'reader_reopened_native_database',
                     'host_and_source_provenance_checked_by_reader',
                     'proof_hardness_or_timestamp_attack_profitability_qualified',
                     'public_network_qualification'):
            self.assertIs(self.validated[name], False)

    def test_all_snapshot_contexts_cannot_be_consistently_relabelled(self):
        for name in ('network', 'parameters', 'genesis'):
            with self.subTest(field=name):
                self.reject_heads(lambda head: head.__setitem__(name, '00' * 32),
                                  'native head context mismatch: ' + name)

    def test_production_activation_cannot_be_injected_into_every_snapshot(self):
        for value in (True, 0, None):
            with self.subTest(value=value):
                self.reject_heads(lambda head: head.__setitem__('production_activation', value),
                                  'cannot grant production activation')

    def test_every_authenticated_counter_must_remain_zero(self):
        for name in sorted(reader.AUTHENTICATED_FIELDS):
            with self.subTest(field=name):
                self.reject_heads(lambda head: head.__setitem__(name, 9),
                                  'cannot claim authenticated state')

    def test_boolean_zero_cannot_alias_authenticated_counts(self):
        for name in sorted(reader.AUTHENTICATED_FIELDS):
            with self.subTest(field=name):
                self.reject_heads(lambda head: head.__setitem__(name, False), 'bounded integer')

    def test_unknown_or_missing_head_fields_cannot_hide_new_authority(self):
        self.reject_heads(lambda head: head.__setitem__('execution_authority', True),
                          'native head fields')
        self.reject_heads(lambda head: head.pop('genesis'), 'native head fields')

    def test_nonterminal_activation_inventory_is_checked(self):
        report = copy.deepcopy(self.report)
        report['activations'][0]['stats']['stored_blocks'] = 999
        with self.assertRaisesRegex(ValueError, 'stored-block inventory mismatch'):
            reader.analyze_report(report, self.packets)

    def test_fabricated_reorg_event_counts_cannot_survive_cold_copy(self):
        self.reject_heads(lambda head: head.__setitem__('events', 0), 'reorg-event count mismatch')

    def test_invalid_state_key_count_cannot_survive_cold_copy(self):
        for value in (0, True, '27'):
            with self.subTest(value=value):
                self.reject_heads(lambda head: head.__setitem__('state_keys', value), 'bounded integer')

    def test_activation_envelope_has_exact_fields(self):
        report = copy.deepcopy(self.report)
        report['activations'][0]['authority'] = True
        with self.assertRaisesRegex(ValueError, 'native activation fields'):
            reader.analyze_report(report, self.packets)

    def test_the_reproduced_combined_mutation_is_rejected(self):
        self.reject_heads(lambda head: head.update(network='00' * 32,
                          production_activation=True, authenticated_sessions=9),
                          'native head context mismatch')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-dir', default=RAW_DIR, type=Path,
                        help='retained native evidence directory; missing evidence is an error')
    args, remaining = parser.parse_known_args()
    RAW_DIR = args.raw_dir
    unittest.main(argv=[sys.argv[0], *remaining])
