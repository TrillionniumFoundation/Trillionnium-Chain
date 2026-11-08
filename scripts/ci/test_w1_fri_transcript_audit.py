#!/usr/bin/env python3
"""Encoding/source-map controls; none of these tests is a STARK proof trial."""
from __future__ import annotations

import gzip
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import w1_fri_transcript_audit as audit

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / 'evidence/pon-w1-qrom-implementation-20261107/upstream-sources.json.gz'
RECEIPT = ROOT / 'evidence/pon-w1-full-v2-20261105/succinct.bin'


class FriTranscriptAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        snapshot = json.loads(gzip.decompress(SNAPSHOT.read_bytes()))
        cls.sources = {row['path']: row['content'] for row in snapshot['files']}
        cls.receipt = RECEIPT.read_bytes()

    def changed_word(self, index: int, value: int) -> bytes:
        data = bytearray(self.receipt)
        struct.pack_into('<I', data, audit.SEAL_OFFSET + 4 * index, value)
        return bytes(data)

    def test_actual_saved_seal_geometry_and_security_boundary(self):
        report = audit.audit_sources(self.sources, self.receipt)
        geometry = report['saved_v2_geometry']
        self.assertEqual((geometry['po2'], geometry['N'], geometry['D'], geometry['R']),
                         (18, 262144, 1048576, 3))
        self.assertEqual((geometry['prequery_words'], geometry['per_query_words'],
                          geometry['seal_words'], geometry['seal_bytes']),
                         (4717, 1019, 55667, 222668))
        self.assertEqual(geometry['query_end_word_exclusive'], geometry['seal_words'])
        self.assertEqual([row['sibling_digest_count'] for row in geometry['query_template']],
                         [15, 15, 15, 15, 11, 7, 3])
        self.assertEqual([row['oracle'] for row in geometry['query_template']],
                         ['accum', 'code', 'data', 'check', 'fri0', 'fri1', 'fri2'])
        self.assertTrue(geometry['all_seal_words_canonical'])
        self.assertTrue(geometry['all_seal_words_accounted_for'])
        self.assertTrue(all(value is False or value is None
                            for value in report['qualification'].values()))
        self.assertFalse(report['po2_boundary']['reachable_outer_po2_set_proved'])
        self.assertEqual(report['grinding']['credited_grinding_bits'], 0)
        costs = report['rng']['derived_rng_cost']
        self.assertEqual((costs['base_squeezes'], costs['rng_permutation_calls']), (244, 32))
        self.assertIsNone(costs['qrom_queries_inferred'])

    def test_missing_or_changed_upstream_source_is_refused(self):
        missing = dict(self.sources)
        del missing[audit.MERKLE_PARAMS]
        with self.assertRaisesRegex(audit.TranscriptAuditError, 'missing source text'):
            audit.audit_sources(missing, self.receipt)
        changed = dict(self.sources)
        changed[audit.LIB] = changed[audit.LIB].replace('QUERIES: usize = 50', 'QUERIES: usize = 49')
        self.assertNotEqual(changed[audit.LIB], self.sources[audit.LIB])
        with self.assertRaisesRegex(audit.TranscriptAuditError, 'source SHA-256 mismatch'):
            audit.audit_sources(changed, self.receipt)

    def test_truncated_u_coefficient_section_and_trailing_word_are_refused(self):
        at = audit.SEAL_OFFSET + 4 * 1057
        shortened = self.receipt[:at] + self.receipt[at + 4:]
        for data in (shortened, self.receipt + b'\0' * 4):
            with self.subTest(bytes=len(data)):
                with self.assertRaisesRegex(audit.TranscriptAuditError, 'receipt length mismatch'):
                    audit.audit_sources(self.sources, data)

    def test_changed_declared_seal_length_cannot_hide_in_outer_suffix(self):
        # Keep the full receipt size unchanged: move one word into/out of the
        # declared seal. The independently derived seal geometry must reject it.
        at = audit.SEAL_OFFSET + 4 * 4717
        for delta in (-1, 1):
            if delta == 1:
                data = bytearray(self.receipt[:at] + b'\0' * 4 + self.receipt[at:-4])
            else:
                data = bytearray(self.receipt[:at] + self.receipt[at + 4:] + b'\0' * 4)
            struct.pack_into('<Q', data, 4, 55667 + delta)
            self.assertEqual(len(data), len(self.receipt))
            with self.subTest(delta=delta):
                with self.assertRaisesRegex(audit.TranscriptAuditError, 'derived geometry'):
                    audit.audit_sources(self.sources, bytes(data))

    def test_noncanonical_words_in_cap_coefficients_and_last_opening_are_refused(self):
        for index in (33, 1057, 55666):
            with self.subTest(index=index):
                with self.assertRaisesRegex(audit.TranscriptAuditError, f'word at index {index}'):
                    audit.audit_sources(self.sources, self.changed_word(index, audit.P))

    def test_raw_po2_scope_does_not_confuse_lift_limit_with_seal_acceptance(self):
        for value in (22, 18 * (1 << 32) % audit.P):
            with self.subTest(raw_po2=value):
                with self.assertRaisesRegex(audit.TranscriptAuditError, 'raw po2=18 scope'):
                    audit.audit_sources(self.sources, self.changed_word(32, value))

    def test_canonical_value_change_does_not_become_a_proof_verification(self):
        old = struct.unpack_from('<I', self.receipt, audit.SEAL_OFFSET + 4 * 1057)[0]
        changed = self.changed_word(1057, (old + 1) % audit.P)
        original = audit.audit_sources(self.sources, self.receipt)
        report = audit.audit_sources(self.sources, changed)
        self.assertNotEqual(report['saved_v2_geometry']['seal_sha256'],
                            original['saved_v2_geometry']['seal_sha256'])
        self.assertFalse(report['qualification']['fresh_cryptographic_verification'])
        self.assertFalse(report['qualification']['whole_receipt_identity_enforced_here'])
        self.assertFalse(report['qualification']['qrom_instantiated'])


if __name__ == '__main__':
    unittest.main()
