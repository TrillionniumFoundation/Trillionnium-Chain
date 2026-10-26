"""Differential algorithm and finite compression-graph controls; no benchmarks."""
from fractions import Fraction
from itertools import product
from pathlib import Path
import hashlib
import struct
import sys
import unittest

import w1_multi_instance_cost_v2 as model

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import work_oracle
import contract_wire


def naive(a, b):
    return tuple(tuple(sum(a[i][k] * b[k][j] for k in range(len(b))) % model.Q
                       for j in range(len(b[0]))) for i in range(len(a)))


def canonical_words(el, er, fl, fr):
    a, b = naive(el, er), naive(fl, fr)
    n, r = len(el), len(fr)
    words = []
    for bi in range(0, n, r):
        for bj in range(0, n, r):
            for end in range(r, n + 1, r):
                for i in range(bi, bi + r):
                    for j in range(bj, bj + r):
                        words.append(sum(a[i][k] * b[k][j] for k in range(end)) % model.Q)
    return tuple(words)


class MessageGeometryTests(unittest.TestCase):
    def test_actual_lengths_and_padding(self):
        self.assertEqual(model.actual_message_geometry(), {
            'challenge_bytes': 343, 'challenge_blocks': 6,
            'noise_bytes': 66, 'noise_blocks': 2,
            'ticket_bytes': 90, 'ticket_blocks': 2,
            'trace_bytes': 131120, 'trace_blocks': 2049})
        self.assertEqual(model.pon_message(b'noise', bytes(32), b'\0', bytes(4))[62:66], bytes(4))
        for length in (0, 1, 55, 56, 63, 64, 65, 66, 131120):
            blocks = model.sha_blocks(bytes(length))
            self.assertEqual(len(b''.join(blocks)) % 64, 0)
            self.assertEqual(blocks[-1][-8:], (8 * length).to_bytes(8, 'big'))

    def test_header_nonce_reuses_five_blocks_exactly(self):
        fields = {row['name']: bytes([index + 1]) * 32 if row['type'] == 'hash32' else index + 1
                  for index, row in enumerate(contract_wire.SCHEMA['header'])}
        first = model.pon_message(b'challenge', contract_wire.header_encode(fields))
        prefix = first[:320]
        prepared = hashlib.sha256(prefix)
        for nonce in (0, 1, 2**64 - 1):
            fields['nonce'] = nonce
            encoded = contract_wire.header_encode(fields)
            current = model.pon_message(b'challenge', encoded)
            self.assertEqual(current[:320], prefix)
            state = prepared.copy()
            state.update(current[320:])
            self.assertEqual(state.digest(), contract_wire.H('challenge', encoded))
        self.assertEqual(len(prefix), 5 * 64)

    def test_noise_suffix_and_prefix_round_inputs(self):
        challenge = bytes(range(32))
        suffixes = set()
        first14words = set()
        for label in range(4):
            first15words = set()
            for counter in range(128):
                blocks = model.sha_blocks(model.noise_message(challenge, label, counter))
                first14words.add(blocks[0][:56])
                first15words.add(blocks[0][:60])
                suffixes.add(blocks[1])
            self.assertEqual(len(first15words), 1)
        self.assertEqual(len(first14words), 1)
        self.assertEqual(len(suffixes), 1)
        self.assertEqual(model.noise_message(challenge, 0, 1)[62], 1)
        self.assertEqual(model.noise_message(challenge, 0, 0)[62], 0)
        # Different challenges still have exactly the same second message block.
        self.assertIn(model.sha_blocks(model.noise_message(b'\xff' * 32, 3, 127))[1], suffixes)

    def test_distinct_full_challenges_change_first_trace_block(self):
        body = bytes(4 * model.N * model.N * (model.N // model.R))
        blocks = [model.sha_blocks(model.TRACE_DOMAIN + bytes([x]) * 32 + body) for x in (0, 1)]
        self.assertNotEqual(blocks[0][0], blocks[1][0])
        self.assertEqual(blocks[0][1:], blocks[1][1:])
        # Equal suffix bytes do not imply equal SHA chaining states.
        self.assertNotEqual(hashlib.sha256(model.TRACE_DOMAIN + bytes(32) + body).digest(),
                            hashlib.sha256(model.TRACE_DOMAIN + b'\1' * 32 + body).digest())

    def test_noise_and_input_strictness(self):
        challenge = bytes(range(32))
        for label in range(4):
            self.assertEqual(model.expand(challenge, label, 512), tuple(work_oracle.expand(challenge, label, 512)))
        for counter in (-1, 128, True):
            with self.assertRaises(ValueError):
                model.noise_message(challenge, 0, counter)
        for label in (-1, 4, False):
            with self.assertRaises(ValueError):
                model.noise_message(challenge, label, 0)


class StrassenPairedTests(unittest.TestCase):
    def test_all_two_by_two_near_boundary_inputs(self):
        values = (0, 1, model.Q - 1)
        # Cartesian sides sampled exhaustively across three entries and linked
        # fourth entries, including signed linear transforms after reduction.
        for a0, a1, b0, b1 in product(values, repeat=4):
            a = ((a0, a1), (a1, a0))
            b = ((b0, b1), (b1, b0))
            count = model.Arithmetic()
            result = model.prepared_product(model.prepare(a, 0, 'left', count),
                                            model.prepare(b, 0, 'right', count), count)
            self.assertEqual(result, naive(a, b))

    def test_recursive_depths_match_independent_naive_products(self):
        for size in (4, 8):
            a = tuple(tuple((model.Q - 1 - 17 * i - j) % model.Q for j in range(size)) for i in range(size))
            b = tuple(tuple((13 * i + 7 * j) % model.Q for j in range(size)) for i in range(size))
            for depth in range(size.bit_length() - 1):
                count = model.Arithmetic()
                result = model.prepared_product(model.prepare(a, depth, 'left', count),
                                                model.prepare(b, depth, 'right', count), count)
                self.assertEqual(result, naive(a, b))

    def test_every_small_prefix_in_actual_order(self):
        n, r = 16, 8
        matrices = []
        for label, rows, cols in ((0, n, r), (1, r, n), (2, n, r), (3, r, n)):
            values = tuple((model.Q - 1 - label * 11 - i * 3) % model.Q for i in range(rows * cols))
            matrices.append(model.matrix(values, rows, cols))
        expected = canonical_words(*matrices)
        for depth in (0, 1, 2):
            result, _ = model.zero_prefixes(*matrices, depth=depth)
            self.assertEqual(result, expected)
            self.assertEqual(len(result), n * n * (n // r))

    def test_actual_w1_complete_bytes_and_executed_product_counts(self):
        challenge = bytes(range(32))
        zero = [0] * work_oracle.CELLS
        expected = work_oracle.prove(challenge, zero, zero)
        task = work_oracle.task_id(zero, zero)
        for depth in (0, 1, 2):
            proof, counts = model.zero_proof(challenge, depth=depth)
            self.assertEqual(proof, expected)
            self.assertEqual(len(proof), work_oracle.PROOF_BYTES)
            self.assertEqual(work_oracle.precheck(challenge, task, b'\xff' * 32, proof)[3],
                             contract_wire.H('ticket', challenge, expected[-32:]))
            schedule = model.multiplication_schedule(depth)
            self.assertEqual(counts['middle']['products'], schedule['middle_products'])
            self.assertEqual(counts['left']['products'], schedule['left_products'])
            self.assertEqual(counts['output-left-prepare']['products'], schedule['output_left_factor_products'])
            self.assertEqual(counts['output-right-prepare']['products'], schedule['output_right_factor_products'])
            self.assertEqual(counts['output-products']['products'], schedule['output_cross_products'])
            self.assertEqual(sum(c['products'] for c in counts.values()), schedule['total_products'])
        self.assertEqual([model.multiplication_schedule(d)['total_products'] for d in range(3)],
                         [152832, 138176, 126864])

    def test_product_savings_are_not_an_unweighted_total_cost_saving(self):
        factors = [model.matrix(model.expand(bytes(32), label, 512), rows, cols)
                   for label, rows, cols in ((0, 64, 8), (1, 8, 64), (2, 64, 8), (3, 8, 64))]
        _, baseline = model.zero_prefixes(*factors, depth=0)
        _, split = model.zero_prefixes(*factors, depth=2)
        total = lambda counts, key: sum(row[key] for row in counts.values())
        self.assertLess(total(split, 'products'), total(baseline, 'products'))
        self.assertGreater(total(split, 'additions'), total(baseline, 'additions'))
        self.assertGreater(total(split, 'reductions'), total(baseline, 'reductions'))
        self.assertGreater(sum(total(split, kind) for kind in ('products', 'additions', 'reductions')),
                           sum(total(baseline, kind) for kind in ('products', 'additions', 'reductions')))

    def test_invalid_depths_and_noncanonical_factors_reject(self):
        a = ((0, 0), (0, 0))
        for depth in (-1, 1, True):
            with self.assertRaises(ValueError):
                model.prepare(a, depth, 'left', model.Arithmetic())
        with self.assertRaises(ValueError):
            model.prepare(((model.Q, 0), (0, 0)), 0, 'left', model.Arithmetic())
        with self.assertRaises(ValueError):
            model.matrix((0, 0, -1, 0), 2, 2)


class CompressionGraphTests(unittest.TestCase):
    def test_disjoint_paths_and_temporal_coverage(self):
        graph = model.QueryGraph()
        graph.query(0, b'A', 1, origin='prep')
        graph.query(1, b'C', 2, origin='prep')
        graph.query(2, b'D', 3)
        first = graph.reference(3)
        graph.query(0, b'B', 4)
        graph.query(4, b'C', 5)
        graph.query(5, b'D', 6)
        second = graph.reference(6)
        result = graph.canonical_coverage((((b'A', b'C', b'D'), 3, first),
                                           ((b'B', b'C', b'D'), 6, second)))
        self.assertEqual(result, dict(paths=2, path_edges=6, distinct_edges=6,
            edge_disjoint=True, complete_before_reference=True, bad_event=False, captured_distinct_queries=6))
        graph.query(5, b'D', 6)
        self.assertEqual(len(graph.table), 6)

    def test_prequeried_suffix_is_a_forward_chaining_guess(self):
        graph = model.QueryGraph()
        graph.query(9, b'last', 10, origin='prep')
        at = graph.reference(10)
        graph.query(0, b'first', 9)
        result = graph.canonical_coverage((((b'first', b'last'), 10, at),))
        self.assertIn('prior-chaining-address-or-IV', graph.bad_events)
        self.assertFalse(result['complete_before_reference'])

    def test_collision_merges_two_distinct_first_blocks(self):
        graph = model.QueryGraph()
        graph.query(0, b'A', 1)
        graph.query(0, b'B', 1)
        graph.query(1, b'C', 2)
        graph.query(2, b'D', 3)
        at = graph.reference(3)
        result = graph.canonical_coverage((((b'A', b'C', b'D'), 3, at),
                                           ((b'B', b'C', b'D'), 3, at)))
        self.assertFalse(result['edge_disjoint'])
        self.assertEqual(result['distinct_edges'], 4)
        self.assertIn('output-collision', graph.bad_events)

    def test_late_audit_hits_earlier_digest_and_supplies_no_miner_queries(self):
        graph = model.QueryGraph()
        at = graph.reference(7)
        graph.query(0, b'first', 1, origin='audit')
        graph.query(1, b'last', 7, origin='audit')
        result = graph.canonical_coverage((((b'first', b'last'), 7, at),))
        self.assertIn('prior-full-digest-reference', graph.bad_events)
        self.assertEqual(result['captured_distinct_queries'], 0)
        self.assertFalse(result['complete_before_reference'])
        bound = model.compression_failure_bound(captured_queries=0, audit_queries=2,
                                               digest_references=1, state_bits=4)
        self.assertEqual(bound['union_bound'], Fraction(1, 2))

    def test_all_guess_references_and_opaque_advice_change_the_bound(self):
        bound = model.compression_failure_bound(captured_queries=8, audit_queries=4, digest_references=2)
        self.assertEqual(bound['numerator_without_advice'], 180)
        self.assertEqual(bound['union_bound'], Fraction(180, 1 << 256))
        wider = model.compression_failure_bound(captured_queries=8, audit_queries=4, digest_references=100)
        self.assertGreater(wider['union_bound'], bound['union_bound'])
        advised = model.compression_failure_bound(captured_queries=8, audit_queries=4,
                                                  digest_references=2, opaque_advice_bits=256)
        self.assertEqual(advised['union_bound'], 1)
        for wrong in (-1, True):
            with self.assertRaises(ValueError):
                model.compression_failure_bound(captured_queries=wrong, audit_queries=0, digest_references=0)

    def test_prefix_bank_full_partial_and_exposed_paths(self):
        self.assertEqual(model.prefix_bank_cap((2048, 2047), 3), 2)
        self.assertEqual(model.prefix_bank_cap((2049, 2049), 0), 2)
        self.assertEqual(model.prefix_bank_cap((0, 0), 2048), 0)
        self.assertEqual(model.compression_opportunity_cap(preprocessing_queries=4095, online_queries=3), 2)
        self.assertEqual(model.compression_opportunity_cap(preprocessing_queries=4098, online_queries=2049,
                                                          previously_exposed_trace_paths=1), 2)
        with self.assertRaises(ValueError):
            model.compression_opportunity_cap(preprocessing_queries=0, online_queries=9999,
                                              previously_exposed_trace_paths=1)

    def test_bank_greedy_matches_exhaustive_subset_completions(self):
        for lengths in product(range(4), repeat=3):
            for budget in range(7):
                expected = 0
                for selected in product((False, True), repeat=3):
                    cost = sum(3 - length for length, choose in zip(lengths, selected) if choose)
                    if cost <= budget:
                        expected = max(expected, sum(selected) + (budget - cost) // 3)
                self.assertEqual(model.prefix_bank_cap(lengths, budget, blocks_per_trace=3), expected)

    def test_repeated_salt_and_truncation_do_not_inherit_full_path_claim(self):
        self.assertEqual(model.repeated_salt_control(paths=2, prefix_blocks=3, suffix_blocks=1),
                         dict(independent_count=8, reusable_prefix_count=5))
        graph = model.QueryGraph()
        graph.query(0, b'A', 1)
        at = graph.reference(1)
        with self.assertRaises(ValueError):
            graph.canonical_coverage((((b'A',), 1, at), ((b'A',), 1, at)))
        # Truncating a 4-bit digest to one bit accepts 8 of 16 blind guesses.
        self.assertEqual(Fraction(sum(value >> 3 == 0 for value in range(16)), 16), Fraction(1, 2))
        self.assertGreater(Fraction(1, 2), Fraction(1, 16))

    def test_ticket_parser_registers_complete_digest_before_final_answer(self):
        challenge, trace = bytes(range(32)), b'\x17' * 32
        first, last = model.sha_blocks(model.pon_message(b'ticket', challenge, trace))
        self.assertEqual(model.parse_ticket_blocks(first, last), (challenge, trace))
        graph = model.QueryGraph()
        graph.query(0, first, 9, origin='prep')
        self.assertEqual(graph.ticket_query(9, last, 11), (challenge, trace))
        self.assertEqual(graph.references, [(1, int.from_bytes(trace, 'big'))])
        self.assertEqual(graph.first_at[(9, last)], 2)
        self.assertFalse(graph.bad_events)
        for index in (0, 18, 54):
            changed = bytearray(first)
            changed[index] ^= 1
            self.assertIsNone(model.parse_ticket_blocks(bytes(changed), last))
        for index in (26, 55, 63):
            changed = bytearray(last)
            changed[index] ^= 1
            self.assertIsNone(model.parse_ticket_blocks(first, bytes(changed)))

    def test_late_ticket_first_block_is_a_previous_cv_hit(self):
        first, last = model.sha_blocks(model.pon_message(b'ticket', bytes(32), b'\x21' * 32))
        graph = model.QueryGraph()
        self.assertIsNone(graph.ticket_query(9, last, 11))
        self.assertEqual(graph.references, [])
        graph.query(0, first, 9)
        self.assertIn('prior-chaining-address-or-IV', graph.bad_events)

    def test_invalid_old_trace_is_not_a_retirable_canonical_path(self):
        graph = model.QueryGraph()
        graph.query(0, b'first', 1, origin='prep')
        graph.query(1, b'middle', 2, origin='prep')
        graph.query(2, b'invalid-last', 3, origin='prep')
        graph.reference(3)
        graph.query(2, b'canonical-last', 4)
        at = graph.reference(4)
        checked = graph.canonical_coverage((((b'first', b'middle', b'canonical-last'), 4, at),))
        self.assertFalse(checked['bad_event'])
        self.assertTrue(checked['complete_before_reference'])
        correct = model.compression_opportunity_cap(preprocessing_queries=3, online_queries=1,
            previously_exposed_trace_paths=0, blocks_per_trace=3)
        invalid_retirement = model.compression_opportunity_cap(preprocessing_queries=3, online_queries=1,
            previously_exposed_trace_paths=1, blocks_per_trace=3)
        self.assertEqual(correct, 1)
        self.assertEqual(invalid_retirement, 0)  # caller has violated the canonical-path precondition

    def test_fabricated_reference_time_is_rejected(self):
        graph = model.QueryGraph()
        graph.query(0, b'A', 1)
        with self.assertRaises(ValueError):
            graph.canonical_coverage((((b'A',), 1, 1),))
        graph.reference(1)
        with self.assertRaises(ValueError):
            graph.canonical_coverage((((b'A',), 1, 2),))

    def test_qualification_flags_remain_false(self):
        self.assertTrue(all(value is False for value in model.summary()['qualifications'].values()))


if __name__ == '__main__':
    unittest.main()
