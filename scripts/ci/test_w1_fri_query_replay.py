#!/usr/bin/env python3
"""Actual-seal hash/RNG/path controls; none is an AIR or QROM proof trial."""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import w1_fri_query_replay as replay


ROOT = Path(__file__).resolve().parents[2]


class RawMatrixReferenceRng:
    """Independent raw-Montgomery arithmetic with the upstream full matrices.

    This deliberately does not call the optimized helper's permutation, sponge,
    conversion helpers or TranscriptRng methods. The matrix/constant arrays are
    data from the SHA-256-checked upstream source. It checks the entire actual
    transcript, including rate exhaustion and squeeze-to-absorb transitions.
    It does not establish formal equivalence for every possible execution.
    """

    def __init__(self, engine):
        source = engine.sources[engine.control.CONST_PATH]
        parse = engine.control._field_array
        self.external = parse(source, '_M_EXT', 24 * 24)
        self.diagonal = parse(source, 'M_INT_DIAG_HZN', 24)
        self.constants = parse(source, 'ROUND_CONSTANTS', 24 * 29)
        self.cells = [0] * 24
        self.next_cell = 0
        self.permutations = self.squeezes = 0
        self.p = 2013265921
        self.r = pow(2, 32, self.p)
        self.inv_r = pow(self.r, -1, self.p)
        self.sbox_scale = pow(self.inv_r, 6, self.p)

    def external_layer(self, values):
        return [sum(self.external[24 * i + j] * values[j] for j in range(24)) % self.p
                for i in range(24)]

    def mix(self):
        state = self.external_layer(self.cells)
        for round_number in range(29):
            if round_number in range(4, 25):
                state[0] = (state[0] + self.constants[24 * round_number] * self.r) % self.p
                state[0] = pow(state[0], 7, self.p) * self.sbox_scale % self.p
                state = [sum(((self.diagonal[i] + 1) if i == j else 1) * state[j]
                             for j in range(24)) % self.p for i in range(24)]
            else:
                state = [pow((state[i] + self.constants[24 * round_number + i] * self.r)
                             % self.p, 7, self.p) * self.sbox_scale % self.p
                         for i in range(24)]
                state = self.external_layer(state)
        self.cells = state
        self.permutations += 1

    def commit(self, raw_digest):
        if self.next_cell:
            self.mix()
            self.next_cell = 0
        for index in range(8):
            self.cells[index] = (self.cells[index] + raw_digest[index]) % self.p
        self.mix()

    def take(self, count):
        normal = []
        for _ in range(count):
            if self.next_cell == 16:
                self.mix()
                self.next_cell = 0
            normal.append(self.cells[self.next_cell] * self.inv_r % self.p)
            self.next_cell += 1
            self.squeezes += 1
        return normal

    def state(self):
        return {'pool_used': self.next_cell, 'base_squeezes': self.squeezes,
                'rng_permutation_calls': self.permutations,
                'cells_raw_montgomery_le_sha256':
                    hashlib.sha256(struct.pack('<24I', *self.cells)).hexdigest()}


class FriQueryReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = replay.load_snapshot(ROOT)
        cls.receipt = (ROOT / replay.RECEIPT_PATH).read_bytes()
        cls.engine = replay.ReplayEngine(cls.sources, ROOT)
        cls.report = cls.engine.run(cls.receipt)

    def changed_word(self, index, value=None):
        data = bytearray(self.receipt)
        offset = 12 + 4 * index
        old = struct.unpack_from('<I', data, offset)[0]
        struct.pack_into('<I', data, offset, (old + 1) % replay.P if value is None else value)
        return bytes(data)

    def test_actual_seal_all_paths_and_qualification_boundary(self):
        report = self.report
        self.assertEqual(report['result'], 'FIXED_TRANSCRIPT_AND_MERKLE_OPENINGS_REPLAYED_SECURITY_HOLD')
        self.assertEqual(report['input_profile_source_head'],
                         '0c830e0be8939ce80c8443c9ad68021b87343a00')
        self.assertNotIn('source_head', report)
        self.assertEqual(report['generator_sha256'],
                         hashlib.sha256((ROOT / 'scripts/w1_fri_query_replay.py').read_bytes()).hexdigest())
        self.assertTrue(all(value is False or value is None for value in report['qualification'].values()))
        self.assertEqual(report['receipt']['seal_words'], 55667)
        self.assertEqual(report['receipt']['seal_file_offset_bytes'], 12)
        self.assertEqual(report['receipt']['raw_po2'], 18)
        self.assertNotEqual(report['receipt']['po2_word_normal_field_value_when_hashed'], 18)
        self.assertEqual(len(report['ordered_transcript_events']), 69)
        self.assertEqual(report['reproduced_checks']['merkle_openings_verified'], 350)
        self.assertEqual(sum(tree['checked_sibling_nodes'] for tree in report['merkle_trees']), 4050)
        self.assertEqual(sum(len(level) for tree in report['merkle_trees']
                             for level in tree['cap_levels_leaf_to_root_raw_le_hex'][1:]), 217)
        code = next(tree for tree in report['merkle_trees'] if tree['oracle'] == 'code')
        self.assertEqual(code['root_raw_le_hex'], replay.JOIN)
        self.assertEqual(report['queries'][0]['seal_word_range_half_open'][0], 4717)
        self.assertEqual(report['queries'][-1]['seal_word_range_half_open'][1], 55667)
        self.assertEqual(report['rng_cost']['base_squeezes'], 244)
        self.assertEqual(report['rng_cost']['rng_permutation_calls'], 32)
        self.assertIsNone(report['rng_cost']['qrom_queries_inferred'])

    def test_all_actual_transcript_events_match_independent_raw_matrix_reference(self):
        reference = RawMatrixReferenceRng(self.engine)
        for event in self.report['ordered_transcript_events']:
            with self.subTest(event=event['id']):
                self.assertEqual(reference.state(), event['before'])
                if event['kind'] == 'commit':
                    reference.commit(struct.unpack('<8I', bytes.fromhex(event['digest_raw_le_hex'])))
                else:
                    values = reference.take(len(event['normal_words']))
                    self.assertEqual(values, event['normal_words'])
                    if event['id'].startswith('query_'):
                        # All four are consumed before selecting the first nonzero.
                        chosen = next((value for value in values if value), 0)
                        self.assertEqual(chosen & (2 ** 20 - 1), event['index'])
                self.assertEqual(reference.state(), event['after'])
        self.assertEqual(reference.state(), self.report['rng_state_after_query_loop'])

    def test_upstream_golden_vectors_are_real_external_expected_values(self):
        checks = self.report['upstream_golden_checks']['checks']
        self.assertEqual([check['input_elements'] for check in checks], [24, 32, 17])
        self.assertTrue(all(check['matched'] for check in checks))
        # A changed round constant must be caught without consulting the receipt.
        hasher = self.engine.control.Poseidon2.from_source(self.sources[self.engine.control.CONST_PATH])
        hasher.constants = ((hasher.constants[0] + 1) % replay.P,) + hasher.constants[1:]
        with self.assertRaisesRegex(replay.ReplayError, 'permutation golden mismatch'):
            replay.upstream_golden_checks(hasher, self.sources[replay.HASH_SOURCE])

    def test_folded_index_duplicates_are_reported_without_replacing_query_count(self):
        report = self.report
        self.assertEqual([report['index_multiplicities'][name]['distinct_indices']
                          for name in ('accum', 'code', 'data', 'check', 'fri0', 'fri1', 'fri2')],
                         [50, 50, 50, 50, 50, 49, 44])
        self.assertEqual(report['index_multiplicities']['fri1']['repeated_indices'],
                         [{'index': 2233, 'multiplicity': 2, 'query_numbers': [23, 30]}])
        self.assertEqual(report['index_multiplicities']['fri2']['colliding_pairs'], 6)
        self.assertEqual(report['query_interpretation']['query_draw_count'], 50)
        self.assertFalse(report['query_interpretation']['distinct_indices_substituted_for_theorem_query_count'])
        for query in report['queries']:
            position = query['initial_index']
            for folding in query['folding_positions']:
                self.assertEqual(folding['input_position'], position)
                self.assertEqual(divmod(position, folding['domain_rows']),
                                 (folding['quotient'], folding['group']))
                position = folding['group']
            self.assertEqual(position, query['initial_index'] % 256)
        # These are actual repeated serialized openings, not independent draws
        # at each layer and not evidence for a repeated-index extractor theorem.
        for tree in ('fri1', 'fri2'):
            for duplicate in report['index_multiplicities'][tree]['repeated_indices']:
                payloads = []
                for number in duplicate['query_numbers']:
                    opening = next(item for item in report['queries'][number]['openings']
                                   if item['oracle'] == tree)
                    a = opening['leaf_word_range_half_open'][0]
                    b = opening['sibling_word_range_half_open'][1]
                    payloads.append(self.receipt[12 + 4 * a:12 + 4 * b])
                self.assertTrue(all(payload == payloads[0] for payload in payloads))

    def test_sampler_consumes_four_values_including_zero_fallback_cases(self):
        for samples, expected in (((17, 18, 19, 20), 1), ((0, 0, 17, 19), 1),
                                  ((0, 0, 0, 0), 0), ((0, 0, 0, 31), 15)):
            rng = replay.TranscriptRng(self.engine.hasher)
            rng.cells = samples + (0,) * 20
            index, actual = rng.query(0, 4)
            self.assertEqual((index, actual, rng.pool_used, rng.squeezes),
                             (expected, list(samples), 4, 4))
        for bits in (0, 28, True):
            with self.assertRaisesRegex(replay.ReplayError, 'random_bits width'):
                replay.TranscriptRng(self.engine.hasher).query(0, bits)

    def test_canonical_changes_to_public_values_coefficients_or_any_cap_fail_real_replay(self):
        # These mutations preserve lengths and canonical field encodings. The
        # failure must be a code-root/path mismatch, not the final fixture SHA.
        for index, expected in ((0, 'query 0 accum: Merkle opening mismatch'),
                                (33, 'code root differs'), (289, 'query 0 accum: Merkle opening mismatch'),
                                (545, 'query 0 accum: Merkle opening mismatch'),
                                (801, 'query 0 accum: Merkle opening mismatch'),
                                (1057, 'query 0 accum: Merkle opening mismatch'),
                                (3693, 'query 0 accum: Merkle opening mismatch'),
                                (3949, 'query 0 accum: Merkle opening mismatch'),
                                (4205, 'query 0 accum: Merkle opening mismatch'),
                                (4461, 'query 0 accum: Merkle opening mismatch')):
            with self.subTest(seal_word=index):
                with self.assertRaisesRegex(replay.ReplayError, expected):
                    self.engine.run(self.changed_word(index))

    def test_each_oracle_leaf_or_path_and_final_sibling_are_checked(self):
        first = self.report['queries'][0]
        for opening in first['openings']:
            for key in ('leaf_word_range_half_open', 'sibling_word_range_half_open'):
                with self.subTest(tree=opening['oracle'], part=key):
                    with self.assertRaisesRegex(replay.ReplayError,
                                                'query 0 ' + opening['oracle'] + ': Merkle opening mismatch'):
                        self.engine.run(self.changed_word(opening[key][0]))
        with self.assertRaisesRegex(replay.ReplayError, 'query 49 fri2: Merkle opening mismatch'):
            self.engine.run(self.changed_word(55666))

    def test_path_order_and_query_position_are_not_interchangeable(self):
        opening = self.report['queries'][0]['openings'][0]
        a = opening['sibling_word_range_half_open'][0]
        data = bytearray(self.receipt)
        offset = 12 + 4 * a
        data[offset:offset + 64] = data[offset + 32:offset + 64] + data[offset:offset + 32]
        with self.assertRaisesRegex(replay.ReplayError, 'query 0 accum: Merkle opening mismatch'):
            self.engine.run(bytes(data))
        original_query = replay.TranscriptRng.query

        def wrong_index(rng, number, bits):
            value, samples = original_query(rng, number, bits)
            return value ^ 1, samples

        with patch.object(replay.TranscriptRng, 'query', wrong_index):
            with self.assertRaisesRegex(replay.ReplayError, 'query 0 accum: Merkle opening mismatch'):
                self.engine.run(self.receipt)

    def test_wrong_montgomery_interpretation_and_context_order_are_detected(self):
        def wrong_raw_hash(values):
            return replay.raw_words(self.engine.hasher.hash_elements(tuple(values)))

        with patch.object(self.engine, 'hash_raw', wrong_raw_hash):
            with self.assertRaisesRegex(replay.ReplayError, 'code root differs'):
                self.engine.run(self.receipt)
        proof, circuit = self.engine.proof_context, self.engine.circuit_context
        with patch.object(self.engine, 'proof_context', circuit), \
                patch.object(self.engine, 'circuit_context', proof):
            with self.assertRaisesRegex(replay.ReplayError, 'query 0 accum: Merkle opening mismatch'):
                self.engine.run(self.receipt)
        # The trace-size integer is not the normal field value 18 encoded in R.
        with self.assertRaisesRegex(ValueError, 'raw po2=18 scope'):
            self.engine.run(self.changed_word(32, 18 * replay.MONTGOMERY_R % replay.P))

    def test_skipping_squeeze_to_absorb_permutation_is_detected(self):
        original_commit = replay.TranscriptRng.commit

        def wrong_commit(rng, name, digest, **details):
            rng.pool_used = 0
            original_commit(rng, name, digest, **details)

        with patch.object(replay.TranscriptRng, 'commit', wrong_commit):
            with self.assertRaisesRegex(replay.ReplayError, 'query 0 accum: Merkle opening mismatch'):
                self.engine.run(self.receipt)

    def test_noncanonical_endian_truncation_and_surplus_encodings_are_refused(self):
        for index in (33, 1057, 55666):
            with self.subTest(index=index):
                with self.assertRaisesRegex(ValueError, f'noncanonical seal word at index {index}'):
                    self.engine.run(self.changed_word(index, replay.P))
        for data in (self.receipt[:-4], self.receipt + b'\0\0\0\0'):
            with self.assertRaisesRegex(ValueError, 'receipt length mismatch'):
                self.engine.run(data)
        # A foreign byte order cannot be accepted as an alternate encoding.
        data = bytearray(self.receipt)
        data[:4] = (1).to_bytes(4, 'big')
        with self.assertRaisesRegex(ValueError, 'Succinct variant'):
            self.engine.run(bytes(data))
        for delta in (-1, 1):
            data = bytearray(self.receipt)
            struct.pack_into('<Q', data, 4, 55667 + delta)
            with self.assertRaisesRegex(ValueError, 'derived geometry'):
                self.engine.run(bytes(data))
        reader = replay.SealReader((1, 2))
        reader.read(1, 'sample')
        with self.assertRaisesRegex(replay.ReplayError, 'surplus seal words'):
            reader.complete()

    def test_unparsed_outer_suffix_is_still_identity_bound(self):
        data = bytearray(self.receipt)
        data[-1] ^= 1
        with self.assertRaisesRegex(replay.ReplayError, 'fixed receipt SHA-256 mismatch after replay'):
            self.engine.run(bytes(data))

    def test_changed_upstream_source_or_local_helper_cannot_repin_the_replay(self):
        changed = dict(self.sources)
        changed[replay.RNG_SOURCE] += '\n'
        with self.assertRaisesRegex(ValueError, 'source SHA-256 mismatch'):
            replay.ReplayEngine(changed, ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for path in replay.HELPERS:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / path).read_bytes())
            first = root / next(iter(replay.HELPERS))
            first.write_bytes(first.read_bytes() + b'\nraise RuntimeError("must not execute")\n')
            with self.assertRaisesRegex(replay.ReplayError, 'fixed helper SHA-256 mismatch'):
                replay.load_helpers(root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / replay.SNAPSHOT_PATH
            target.parent.mkdir(parents=True, exist_ok=True)
            blob = bytearray((ROOT / replay.SNAPSHOT_PATH).read_bytes())
            blob[-1] ^= 1
            target.write_bytes(blob)
            with self.assertRaisesRegex(replay.ReplayError, 'source snapshot identity mismatch'):
                replay.load_snapshot(root)


if __name__ == '__main__':
    unittest.main()
