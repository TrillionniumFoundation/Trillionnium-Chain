#!/usr/bin/env python3
"""Mutation controls for retained research packets, with explicit test fixtures.

Default tests build genuine W1 proofs on synthetic headers; they do not claim
native execution. --raw-dir and --report-sha256 instead exercise one externally
pinned native export without changing any original evidence bytes.
"""
import argparse
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_branch_work_schedule_reader as reader

RAW_DIR = None
REPORT_SHA256 = None


def synthetic_fixture(header_profile):
    """Actual complete W1 bytes, synthetic state and external-observation fields."""
    backend = 'pnh1-authenticated' if header_profile == 'PNH1' else 'pgh2-growth'
    profile = {
        'schema': reader.PROFILE_SCHEMA, 'network': '01' * 32, 'parameters': '02' * 32,
        'genesis': '03' * 32, 'genesis_timestamp': reader.GENESIS_TIME,
        'initial_target': reader.POW_LIMIT.to_bytes(32, 'big').hex(),
        'pow_limit': reader.POW_LIMIT.to_bytes(32, 'big').hex(), 'legacy_interval': 16,
        'spacing_seconds': 10, 'future_skew_seconds': 120, 'median_window': 11,
        'max_research_height': 4096, 'activation_height': 1, 'half_life_seconds': 160,
    }
    profile['id'] = reader.profile_id(profile, header_profile).hex()
    matrices = [0] * reader.work_oracle.CELLS
    task = reader.work_oracle.task_id(matrices, matrices)
    # Only the AAM1 envelope/commitment is checked by this reader. This synthetic
    # absent account is not a native authenticated-state execution claim.
    witness = b'AAM1' + bytes(32) + struct.pack('<II', 1, 0) + bytes(33)
    witness_root = reader.wire.H('native-growth-account-witness-v2', witness)
    built, records, packets, chains = {}, [], {}, {}
    for label, parent_label, height, offset in reader.COHORT:
        parent = bytes.fromhex(profile['genesis']) if parent_label is None else built[parent_label]['id']
        target = (bytes.fromhex('7b1d7' + 'f' * 59) if label == 'fresh_adjusted' else
                  reader.POW_LIMIT.to_bytes(32, 'big'))
        header = {'network': bytes.fromhex(profile['network']), 'parameters': bytes.fromhex(profile['parameters']),
                  'parent': parent, 'height': height, 'timestamp': reader.GENESIS_TIME + offset,
                  'target': target, 'miner': reader.wire.H('synthetic-miner', label.encode()),
                  'transactions': reader.wire.sequence_root('transactions', []),
                  'state': bytes(32), 'receipts': bytes(32), 'work_task': task, 'nonce': 0}
        for nonce in range(4096):
            header['nonce'] = nonce
            ledger = reader.wire.header_encode(header)
            encoded = ledger if header_profile == 'PNH1' else b'PGH2' + ledger + witness_root
            challenge = reader.retained.header_challenge(header_profile, encoded)
            proof = reader.work_oracle.prove(challenge, matrices, matrices)
            if reader.wire.H('ticket', challenge, proof[-32:]) <= target:
                break
        else:
            raise AssertionError('synthetic complete-W1 search exhausted')
        raw = (encoded + b'\0\0' + proof if header_profile == 'PNH1' else
               b'PNP2' + encoded + b'\0\0' + struct.pack('<I', len(witness)) + witness + proof)
        packet = reader.retained.decode_packet(header_profile, raw)
        built[label] = packet
        chain = [] if parent_label is None else [built[parent_label]] + chains[parent_label]
        chains[label] = chain
        times = [item['header']['timestamp'] for item in chain] + [reader.GENESIS_TIME]
        median = sorted(times)[len(times) // 2]
        anchor = None if not chain else {
            'profile': profile['id'], 'block': chain[-1]['id'].hex(), 'height': 1,
            'target': profile['initial_target'], 'parent_time': reader.GENESIS_TIME}
        parent_work = len(chain) * 2
        verdict = 'SCHEDULE_TIME_NONDECREASING' if label == 'backwards' else 'PASS'
        filename = 'packets/' + label + '.pnk'
        packets[filename] = raw
        records.append({
            'label': label, 'packet_file': filename, 'packet_bytes': len(raw), 'packet_sha256': reader.sha(raw),
            'id': packet['id'].hex(), 'header_hex': encoded.hex(), 'challenge': challenge.hex(),
            'proof_bytes': len(proof), 'proof_sha256': reader.sha(proof), 'trace': proof[-32:].hex(),
            'parent': parent.hex(), 'height': height, 'timestamp': header['timestamp'],
            'actual_target': target.hex(), 'required_target': target.hex(),
            'parent_branch': [item['id'].hex() for item in chain], 'anchor': anchor,
            'median_time_past': median, 'parent_cumulative_work_hex': reader.work_hex(parent_work),
            'block_work_hex': reader.work_hex(2),
            'candidate_cumulative_work_hex': None if label == 'backwards' else reader.work_hex(parent_work + 2),
            'expected_research_verdict': verdict, 'observed_research_verdict': verdict,
            'complete_native_work_verification': True,
            'native_admission_observed': 'TARGET' if label == 'fresh_adjusted' else 'admitted',
            'cold_storage_observation': 'not-retained' if label == 'fresh_adjusted' else 'retained-byte-identical',
        })
    report = {
        'schema': reader.SCHEMA, 'backend': backend, 'header_profile': header_profile,
        'settings_scope': 'actual-schedule-inputs-and-task-profile-only',
        'task_profile': 'synthetic-fixture-only', 'profile': profile, 'records': records,
        'native_observations': {
            'original_fresh_refusal': 'TARGET', 'wrong_product_refusal': 'WORK:Product',
            'cancellation_refusal': 'SCHEDULE_TEST_CANCELLED',
            'backwards_research_refusal': 'SCHEDULE_TIME_NONDECREASING',
            'cross_fork_anchor_refusal': 'SCHEDULE_ANCHOR_MISMATCH',
            'cold_nonmonotone_refusal': 'SCHEDULE_TIME_NONDECREASING',
            'cold_fast_context_equal': True, 'cold_c0_context_equal': True,
            'c0_profile_id': reader.profile_id(profile, header_profile, fixed=True).hex(),
            'c0_parent': built['fast']['id'].hex(), 'c0_required_target': profile['initial_target'],
            'c0_parent_cumulative_work_hex': reader.work_hex(4),
        }, **{name: False for name in reader.QUALIFICATIONS},
    }
    return report, packets


class BranchScheduleCounterexamples(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures, cls.results, cls.original = [], [], None
        if RAW_DIR is None:
            cls.fixtures = [synthetic_fixture(profile) for profile in ('PNH1', 'PGH2')]
            cls.results = [reader.analyze_report(report, packets) for report, packets in cls.fixtures]
        else:
            raw = reader.read_bounded(RAW_DIR / 'report.json', reader.MAX_REPORT_BYTES)
            report = reader.load_report(raw)
            packets = {'packets/' + path.name: reader.read_bounded(path, reader.retained.MAX_PACKET_BYTES)
                       for path in (RAW_DIR / 'packets').iterdir()}
            cls.fixtures = [(report, packets)]
            cls.results = [reader.analyze(RAW_DIR, REPORT_SHA256)]
            cls.original = {'report.json': reader.sha(raw), **{name: reader.sha(data) for name, data in packets.items()}}

    @classmethod
    def tearDownClass(cls):
        if cls.original is not None:
            for name, digest in cls.original.items():
                if reader.sha((RAW_DIR / name).read_bytes()) != digest:
                    raise AssertionError('original evidence was changed: ' + name)

    def reject(self, change, pattern):
        for original, original_packets in self.fixtures:
            with self.subTest(backend=original['backend']):
                report, packets = copy.deepcopy(original), dict(original_packets)
                change(report, packets)
                with self.assertRaisesRegex(ValueError, pattern):
                    reader.analyze_report(report, packets)

    @staticmethod
    def row(report, label):
        return next(row for row in report['records'] if row['label'] == label)

    @staticmethod
    def reobserve(report, packets, row, raw):
        packet = reader.retained.decode_packet(report['header_profile'], raw)
        header, proof = packet['header'], packet['proof']
        row.update(packet_bytes=len(raw), packet_sha256=reader.sha(raw), id=packet['id'].hex(),
                   header_hex=packet['header_raw'].hex(), challenge=packet['challenge'].hex(),
                   proof_bytes=len(proof), proof_sha256=reader.sha(proof), trace=proof[-32:].hex(),
                   parent=header['parent'].hex(), height=header['height'], timestamp=header['timestamp'],
                   actual_target=header['target'].hex(), required_target=header['target'].hex())
        packets[row['packet_file']] = raw

    def test_complete_proofs_preserve_explicit_scope(self):
        for result in self.results:
            self.assertEqual(result['unique_full_python_verified_proofs'], 7)
            self.assertEqual(result['independent_research_time_refusals'], 1)
            self.assertTrue(result['actual_target_correct_for_time_rejected_proof'])
            for name in reader.QUALIFICATIONS:
                self.assertIs(result[name], False)
            self.assertFalse(result['reader_performed_native_admission'])
            self.assertFalse(result['reader_reopened_native_database'])

    def test_schema_inventory_and_order_are_fixed(self):
        self.reject(lambda report, _: report.update(extra_scope=True), 'exact fields')
        self.reject(lambda _, packets: packets.pop('packets/first.pnk'), 'seven-packet inventory')
        self.reject(lambda report, _: report['records'].reverse(), 'fixed seven-packet order')
        self.reject(lambda report, _: report['profile'].update(activation_height=True), 'bounded integer')

    def test_anchor_branch_median_and_profile_are_recomputed(self):
        self.reject(lambda report, _: self.row(report, 'high')['anchor'].update(block=self.row(report, 'other_anchor')['id']),
                    'actual branch anchor')
        self.reject(lambda report, _: self.row(report, 'fresh_adjusted').update(parent_branch=[]), 'parent-first branch')
        self.reject(lambda report, _: self.row(report, 'backwards').update(median_time_past=0), 'median mismatch')
        self.reject(lambda report, _: report['profile'].update(id='00' * 32), 'profile digest mismatch')

    def test_wrong_actual_target_fails_even_when_all_byte_observations_are_refreshed(self):
        def change(report, packets):
            row = self.row(report, 'fresh_adjusted')
            raw = bytearray(packets[row['packet_file']])
            decoded = reader.retained.decode_packet(report['header_profile'], bytes(raw))
            header = dict(decoded['header'])
            header['target'] = reader.POW_LIMIT.to_bytes(32, 'big')
            start = 0 if report['header_profile'] == 'PNH1' else 8
            raw[start:start + 318] = reader.wire.header_encode(header)
            self.reobserve(report, packets, row, bytes(raw))
        self.reject(change, 'actual target differs from parent-anchored ASERT')

    def test_time_refusal_cannot_be_relabelled_or_awarded_credit(self):
        self.reject(lambda report, _: self.row(report, 'backwards').update(observed_research_verdict='PASS'),
                    'research verdict mismatch')
        self.reject(lambda report, _: self.row(report, 'backwards').update(candidate_cumulative_work_hex=reader.work_hex(6)),
                    'rejected candidate cannot acquire')
        self.reject(lambda report, _: self.row(report, 'fresh_adjusted').update(native_admission_observed='admitted'),
                    'original-policy admission observation')

    def test_ticket_valid_false_product_reaches_and_fails_complete_w1_replay(self):
        def change(report, packets):
            row = self.row(report, 'equal')
            raw = bytearray(packets[row['packet_file']])
            decoded = reader.retained.decode_packet(report['header_profile'], bytes(raw))
            offset = decoded['proof_offset'] + 4 + 2 * reader.work_oracle.CELLS * 4
            previous = int.from_bytes(raw[offset:offset + 4], 'little')
            raw[offset:offset + 4] = ((previous + 1) % reader.work_oracle.Q).to_bytes(4, 'little')
            self.reobserve(report, packets, row, bytes(raw))
            changed = reader.retained.decode_packet(report['header_profile'], bytes(raw))
            reader.work_oracle.precheck(changed['challenge'], changed['header']['work_task'],
                                       changed['header']['target'], changed['proof'])
        self.reject(change, 'full W1 equal: PRODUCT')

    def test_challenge_and_scope_claims_are_not_evidence(self):
        self.reject(lambda report, _: self.row(report, 'first').update(challenge='00' * 32), 'actual challenge mismatch')
        self.reject(lambda report, _: report.update(native_new_profile_installed=True), 'unsupported qualification')
        self.reject(lambda report, _: report['native_observations'].update(cold_fast_context_equal=False), 'cold context')

    def test_external_digest_directory_and_file_bounds_fail_closed(self):
        report, packets = self.fixtures[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / report['backend']
            (root / 'packets').mkdir(parents=True)
            raw = json.dumps(report).encode()
            (root / 'report.json').write_bytes(raw)
            (root / 'report.sha256').write_text(reader.sha(raw) + '\n')
            for name, data in packets.items():
                (root / name).write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'externally recorded research report digest'):
                reader.analyze(root, '00' * 32)
            wrong_backend = 'pgh2-growth' if report['backend'] == 'pnh1-authenticated' else 'pnh1-authenticated'
            moved = root.rename(root.parent / wrong_backend)
            with self.assertRaisesRegex(ValueError, 'export directory does not match'):
                reader.analyze(moved, reader.sha(raw))
            (moved / 'report.json').write_bytes(b' ' * (reader.MAX_REPORT_BYTES + 1))
            with self.assertRaisesRegex(ValueError, 'exceeds byte limit'):
                reader.analyze(moved, reader.sha(raw))

    def test_checked_work_rejects_overflow_and_boolean_values(self):
        for value in (1 << 512, -1, True):
            with self.assertRaisesRegex(ValueError, 'checked 512-bit'):
                reader.checked_work(value)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-dir', type=Path)
    parser.add_argument('--report-sha256')
    args, remaining = parser.parse_known_args()
    if (args.raw_dir is None) != (args.report_sha256 is None):
        parser.error('--raw-dir and --report-sha256 must be supplied together')
    RAW_DIR, REPORT_SHA256 = args.raw_dir, args.report_sha256
    unittest.main(argv=[sys.argv[0], *remaining])
