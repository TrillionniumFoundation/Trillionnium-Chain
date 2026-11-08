#!/usr/bin/env python3
"""Reject in-memory mutations of supplied real joint DAA native evidence.

The original profile directory is never edited. One class-level positive run
replays all 114 complete PNW1 relations. Most counterexamples fail their exact
metadata/arithmetic boundary before that expensive replay; the false-product
counterexample deliberately passes the cheap W1 filter and reaches full replay.
"""
import argparse
import copy
import math
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_joint_daa_reader as reader

RAW_DIR = None


class RetainedJointDaaCounterexamples(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = reader.read_bounded(RAW_DIR / 'joint-daa.json', 2 * 1024 * 1024)
        cls.report = reader.load_report(cls.raw)
        cls.packets = {'packets/' + path.name: reader.read_bounded(path, reader.MAX_PACKET_BYTES)
                       for path in (RAW_DIR / 'packets').iterdir()}
        cls.original = {'joint-daa.json': reader.sha(cls.raw),
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

    def reject(self, change, pattern):
        report, packets = copy.deepcopy(self.report), dict(self.packets)
        change(report, packets)
        with self.assertRaisesRegex(ValueError, pattern):
            reader.analyze_report(report, packets)

    def leaf(self, report):
        row = report['records'][-1]
        self.assertEqual((row['schedule'], row['height']), ('ordinary', 65))
        return row

    def reobserve(self, report, packets, row, raw):
        """Refresh byte observations, not authority, for one deliberately forged row."""
        previous = row['packet_file']
        decoded = reader.decode_packet(report['header_profile'], raw)
        header, proof = decoded['header'], decoded['proof']
        identifier = decoded['id'].hex()
        row.update(id=identifier, packet_file='packets/' + identifier + '.pnk',
                   packet_bytes=len(raw), packet_sha256=reader.sha(raw),
                   header_hex=decoded['header_raw'].hex(), challenge=decoded['challenge'].hex(),
                   proof_bytes=len(proof), proof_sha256=reader.sha(proof), trace=proof[-32:].hex())
        for name in ('height', 'timestamp', 'nonce'):
            row[name] = header[name]
        for name in ('parent', 'target'):
            row[name] = header[name].hex()
        row['attempts'] = header['nonce'] + 1
        target_work = reader.reference.work(int.from_bytes(header['target'], 'big'))
        row['required_work_hex'] = target_work.to_bytes(64, 'big').hex()
        parent = next((item for item in report['records'] if item['id'] == row['parent']), None)
        parent_work = (int(parent['admission']['cumulative_required_work_hex'], 16)
                       if parent is not None else int(report['genesis_chainwork_hex'], 16))
        row['admission']['cumulative_required_work_hex'] = (parent_work + target_work).to_bytes(64, 'big').hex()
        del packets[previous]
        packets[row['packet_file']] = raw

    def test_actual_packets_replay_full_work_and_keep_native_observation_scope(self):
        result = self.validated
        self.assertEqual(result['record_and_oracle_consistency'], 'PASS')
        self.assertEqual(result['observations'], 114)
        self.assertEqual(result['unique_full_python_verified_proofs'], 114)
        self.assertEqual(result['unique_native_admitted_packets_observed'], 114)
        self.assertEqual(result['ordinary_required_chainwork'], 130)
        self.assertEqual(result['selected_required_chainwork'], 793)
        self.assertEqual(result['selected_height'], 64)
        self.assertEqual(result['ordinary_height'], 65)
        self.assertEqual(result['native_time_rejections_observed'], 0)
        self.assertEqual([row['signed_span_seconds'] for row in result['retargets']], ['-42', '-199', '-356'])
        growth = self.report['header_profile'] == 'PGH2'
        self.assertEqual(result['complete_changed_header_probes'], 5 if growth else 4)
        self.assertEqual(result['permissive_filter_full_transcript_rejections'], 5 if growth else 4)
        self.assertEqual(result['growth_witness_hashes_recomputed'], 114 if growth else 0)
        self.assertEqual(result['native_activation_observed_clock_api'], not growth)
        self.assertTrue(result['full_python_transcript_and_product_recomputed'])
        for field in ('permissive_filter_is_consensus_target', 'reader_replayed_all_failed_nonce_attempts',
                      'reader_verified_aam1_account_proofs', 'reader_replayed_native_task_eligibility_or_m06_execution',
                      'reader_performed_native_admission', 'reader_reopened_native_database',
                      'host_and_source_provenance_checked_by_reader', 'native_growth_activation_clock_checked',
                      'proof_hardness_or_quantum_attack_profitability_qualified', 'public_network_qualification'):
            self.assertIs(result[field], False, field)

    def test_missing_or_reordered_records_cannot_shrink_the_trajectory(self):
        self.reject(lambda report, _: report['records'].pop(), '114-record')
        def reorder(report, _):
            report['records'][15:17] = reversed(report['records'][15:17])
        self.reject(reorder, 'fixed trajectory order')

    def test_missing_or_extra_packet_cannot_change_the_denominator(self):
        self.reject(lambda _, packets: packets.pop(next(iter(packets))), '114-packet inventory')
        self.reject(lambda _, packets: packets.update({'packets/' + '00' * 32 + '.pnk': b''}), '114-packet inventory')

    def test_record_digest_pins_actual_packet_bytes(self):
        def change(report, packets):
            name = report['records'][0]['packet_file']
            packets[name] = packets[name][:-1] + bytes([packets[name][-1] ^ 1])
        self.reject(change, 'packet bytes changed')
        self.reject(lambda report, _: report['records'][0].update(packet_sha256='00' * 32), 'packet bytes changed')

    def test_parent_median_uses_exact_branch_not_reported_ancestors(self):
        def change(report, _):
            report['records'][20]['ancestor_timestamps_parent_first'][0] += 1
        self.reject(change, 'median ancestry')
        self.reject(lambda report, _: report['records'][20].update(median_time_past=0), 'median mismatch')

    def test_wrong_target_cannot_pass_after_rewriting_required_and_cumulative_work(self):
        def change(report, packets):
            row = self.leaf(report)
            decoded = reader.decode_packet(report['header_profile'], packets[row['packet_file']])
            header = dict(decoded['header'])
            header['target'] = (int.from_bytes(header['target'], 'big') // 2).to_bytes(32, 'big')
            ledger = reader.wire.header_encode(header)
            raw = bytearray(packets[row['packet_file']])
            start = 0 if report['header_profile'] == 'PNH1' else 8
            raw[start:start + 318] = ledger
            self.reobserve(report, packets, row, bytes(raw))
        self.reject(change, 'branch retarget differs from independent integer arithmetic')

    def test_sqrt_credit_cannot_replace_linear_chainwork(self):
        def change(report, _):
            row = next(item for item in report['records'] if item['schedule'] == reader.ALTERED and item['height'] == 64)
            weight = int(row['required_work_hex'], 16)
            altered_weight = math.isqrt(weight)
            self.assertNotEqual(weight, altered_weight)
            total = int(row['admission']['cumulative_required_work_hex'], 16) - weight + altered_weight
            row['required_work_hex'] = altered_weight.to_bytes(64, 'big').hex()
            row['admission']['cumulative_required_work_hex'] = total.to_bytes(64, 'big').hex()
            report['altered_chainwork_hex'] = total.to_bytes(64, 'big').hex()
        self.reject(change, 'packet work must use linear required_work')

    def test_cumulative_work_is_recomputed_from_each_actual_parent(self):
        self.reject(lambda report, _: report['records'][30]['admission'].update(cumulative_required_work_hex='00' * 64),
                    'cumulative branch work')

    def test_fake_retarget_summary_cannot_override_real_endpoints(self):
        self.reject(lambda report, _: report['retargets'][0].update(saturating_span_seconds=1), 'retarget observation differs')
        self.reject(lambda report, _: report['retargets'][1].update(effective_span_seconds=37), 'retarget observation differs')
        self.reject(lambda report, _: report['retargets'][2].update(signed_span_seconds='-355'), 'retarget observation differs')

    def test_logical_clock_and_full_verification_scope_cannot_be_removed(self):
        self.reject(lambda report, _: report.update(logical_validation_clock_schedule=False), 'required finite native observation scope')
        self.reject(lambda report, _: report.pop('attacker_work_fraction_measured'), 'exact fields required')
        self.reject(lambda report, _: report['records'][0].update(complete_native_work_verification=False),
                    'native full work verification scope')
        self.reject(lambda report, _: report.update(public_network_qualification=True), 'unsupported qualification')

    def test_header_profile_and_domain_are_not_interchangeable(self):
        def wrong_profile(report, _):
            report['header_profile'] = 'PGH2' if report['header_profile'] == 'PNH1' else 'PNH1'
        self.reject(wrong_profile, 'backend/header/work profile mismatch')
        def wrong_domain(report, _):
            row = report['records'][0]
            domain = 'permanent-account-growth-challenge-v2' if report['header_profile'] == 'PNH1' else 'challenge'
            row['challenge'] = reader.wire.H(domain, bytes.fromhex(row['header_hex'])).hex()
        self.reject(wrong_domain, 'challenge differs from selected header domain')

    def test_growth_activation_cannot_claim_the_pnh1_global_clock_gate(self):
        self.reject(lambda report, _: report.update(growth_activation_clock_checked=True),
                    'unsupported qualification or activation-clock claim')
        self.reject(lambda report, _: report.update(activation_observed_clock_api=not report['activation_observed_clock_api']),
                    'activation observed-clock API must match')

    def test_nonce_implied_attempts_cannot_be_underreported(self):
        def change(report, _):
            row = next(item for item in report['records'] if item['nonce'] > 0)
            row['attempts'] = row['nonce']
        self.reject(change, 'attempt count differs from bounded nonce-zero native search')

    def test_activation_order_cannot_choose_the_lower_work_longer_branch(self):
        def change(report, _):
            report['activations'].reverse()
        self.reject(change, 'activation does not select its actual branch')
        self.reject(lambda report, _: report['activations'][1].update(chainwork_hex=report['ordinary_chainwork_hex']),
                    'activation chainwork differs from linear branch work')

    def test_cold_reopen_cannot_change_selected_generation_or_root(self):
        self.reject(lambda report, _: report['after_cold_reopen'].update(generation=3), 'activation height/generation mismatch')
        self.reject(lambda report, _: report['after_cold_reopen'].update(state_root='00' * 32), 'active root differs')

    def test_binding_probe_grid_and_permissive_filter_scope_are_mandatory(self):
        self.reject(lambda report, _: report['binding_rejections'].pop(), 'complete changed-header binding probes')
        self.reject(lambda report, _: report['binding_rejections'][0].update(diagnostic_filter_is_not_consensus=False),
                    'full transcript diagnostic must retain')
        self.reject(lambda report, _: report['binding_rejections'][0].update(full_transcript_error_with_permissive_filter='Target'),
                    'full transcript diagnostic must retain')
        self.reject(lambda report, _: report['binding_rejections'][0].update(changed_challenge='00' * 32),
                    'binding probe challenge differs')

    def test_target_passing_false_product_reaches_full_relation_replay(self):
        def change(report, packets):
            row = report['records'][0]
            raw = bytearray(packets[row['packet_file']])
            decoded = reader.decode_packet(report['header_profile'], bytes(raw))
            position = decoded['proof_offset'] + 4 + 2 * reader.work_oracle.CELLS * 4
            product = int.from_bytes(raw[position:position + 4], 'little')
            raw[position:position + 4] = ((product + 1) % reader.work_oracle.Q).to_bytes(4, 'little')
            self.reobserve(report, packets, row, bytes(raw))
            forged = reader.decode_packet(report['header_profile'], bytes(raw))
            # A canonical C mutation leaves the header, TaskId, trace and ticket
            # unchanged, so only the complete relation can reject this forgery.
            reader.work_oracle.precheck(forged['challenge'], forged['header']['work_task'],
                                        forged['header']['target'], forged['proof'])
        self.reject(change, 'full Python PNW1 replay .*PRODUCT')

    def test_growth_witness_bytes_cannot_change_under_the_same_commitment(self):
        if self.report['header_profile'] != 'PGH2':
            self.skipTest('AAM1 witness commitment exists only in the separate PGH2 profile')
        def change(report, packets):
            row = report['records'][0]
            raw = bytearray(packets[row['packet_file']])
            raw[364 + 4] ^= 1  # Checkpoint bytes; framing and full PNW1 are unchanged.
            packets[row['packet_file']] = bytes(raw)
            row['packet_sha256'] = reader.sha(bytes(raw))
        self.reject(change, 'PGH2 witness commitment differs')

    def test_integer_and_schema_types_reject_boolean_aliases(self):
        self.reject(lambda report, _: report['records'][0].update(height=True), 'bounded integer')
        self.reject(lambda report, _: report.update(activation_observed_clock_api=int(report['activation_observed_clock_api'])),
                    'activation observed-clock API must match')
        self.reject(lambda report, _: report.update(reader_verified_aam1_account_proofs=True), 'exact fields required')

    def test_json_duplicate_keys_and_noninteger_numbers_are_rejected(self):
        for raw in (b'{"schema":1,"schema":2}', b'{"number":0.5}', b'{"number":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                reader.load_report(raw)

    def test_external_report_digest_is_checked_before_packet_processing(self):
        with self.assertRaisesRegex(ValueError, 'externally recorded joint DAA report digest'):
            reader.analyze(RAW_DIR, '00' * 32)


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
