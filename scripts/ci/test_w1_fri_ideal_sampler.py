#!/usr/bin/env python3
"""Independent finite-counting controls; actual transcript security stays open."""
from __future__ import annotations

from collections import Counter
from fractions import Fraction
import io
import itertools
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import w1_fri_query_replay as replay

ROOT = Path(__file__).resolve().parents[2]


class IdealSamplerLawTests(unittest.TestCase):
    @staticmethod
    def exhaustive_counts(prime, bits):
        # Independent explicit decision chain; no formula or transcript helper.
        counts = Counter()
        for a, b, c, d in itertools.product(range(prime), repeat=4):
            if a:
                chosen = a
            elif b:
                chosen = b
            elif c:
                chosen = c
            else:
                chosen = d
            counts[chosen % (2 ** bits)] += 1
        return counts

    def test_exact_law_matches_all_four_draw_tuples_for_small_primes(self):
        for prime, widths in ((3, (1,)), (5, (1, 2)), (7, (1,)),
                              (13, (1, 2)), (17, (1, 2, 3, 4))):
            for bits in widths:
                with self.subTest(prime=prime, bits=bits):
                    law = replay.ideal_four_draw_index_law(prime, bits)
                    counts = self.exhaustive_counts(prime, bits)
                    size = 2 ** bits
                    actual = [Fraction(counts[i], prime ** 4) for i in range(size)]
                    self.assertEqual(actual[0], law['zero_index_probability'])
                    self.assertEqual(actual[1:], [law['each_nonzero_index_probability']] * (size - 1))
                    self.assertEqual(sum(actual), 1)
                    tv = sum(abs(x - Fraction(1, size)) for x in actual) / 2
                    self.assertEqual(tv, law['single_query_total_variation'])
                    self.assertEqual(max(actual), law['maximum_index_probability'])

    def test_small_prime_two_query_product_tv_obeys_both_bounds(self):
        counts = self.exhaustive_counts(3, 1)
        probabilities = [Fraction(counts[a] * counts[b], 3 ** 8)
                         for a, b in itertools.product(range(2), repeat=2)]
        actual_tv = sum(abs(x - Fraction(1, 4)) for x in probabilities) / 2
        bounds = replay.ideal_sampler_product_tv_bounds(3, 2)
        self.assertLess(actual_tv, bounds['coupling_total_variation_upper_bound'])
        self.assertLessEqual(bounds['coupling_total_variation_upper_bound'],
                             bounds['union_total_variation_upper_bound'])
        empty = replay.ideal_sampler_product_tv_bounds(3, 0)
        self.assertEqual(empty['coupling_total_variation_upper_bound'], 0)
        self.assertEqual(empty['union_total_variation_upper_bound'], 0)

    def test_uniform_marginals_with_dependent_draws_do_not_satisfy_iid_law(self):
        # Reuse one uniform F5 draw four times; each marginal remains uniform.
        counts = Counter(value % 4 for value in range(5))
        tv = sum(abs(Fraction(counts[i], 5) - Fraction(1, 4)) for i in range(4)) / 2
        law = replay.ideal_four_draw_index_law(5, 2)
        self.assertEqual(tv, Fraction(3, 20))
        self.assertNotEqual(Fraction(counts[0], 5), law['zero_index_probability'])
        self.assertGreater(tv, law['single_query_total_variation'])

    def test_fixed_babybear_widths_and_exact_reduced_json(self):
        for bits in range(1, 28):
            law = replay.ideal_four_draw_index_law(replay.P, bits)
            self.assertEqual(law['nonzero_values_per_residue'] * 2 ** bits, replay.P - 1)
            self.assertEqual(law['all_zero_draw_probability'], Fraction(1, replay.P ** 4))
            self.assertEqual(law['zero_index_probability']
                             + (2 ** bits - 1) * law['each_nonzero_index_probability'], 1)
            encoded = replay.exact_probability_json(law)['single_query_total_variation']
            self.assertEqual(Fraction(int(encoded['numerator']), int(encoded['denominator'])),
                             law['single_query_total_variation'])
        self.assertEqual(replay.exact_probability_json(Fraction(6, 8)),
                         {'numerator': '3', 'denominator': '4'})

    def test_unequal_residue_counts_and_type_confusion_are_refused(self):
        for modulus, bits in ((5, 3), (7, 2), (True, 1), (2, 1), (3, True),
                              (3, 0), (replay.P, 28), (3, 1.0)):
            with self.subTest(modulus=modulus, bits=bits):
                with self.assertRaises(replay.ReplayError):
                    replay.ideal_four_draw_index_law(modulus, bits)
        for count in (-1, True, 1.0):
            with self.assertRaises(replay.ReplayError):
                replay.ideal_sampler_product_tv_bounds(replay.P, count)

    def test_source_bound_report_keeps_actual_security_unproved(self):
        report = replay.build_ideal_sampler_report(ROOT)
        self.assertEqual(report['schema'], 'TRNM-W1-CONDITIONAL-IID-QUERY-SAMPLER1')
        self.assertEqual([row['bits'] for row in report['conditional_index_laws']], [20, 26])
        self.assertFalse(report['hypotheses']['hypotheses_established_for_actual_poseidon2_transcript'])
        self.assertFalse(report['hypotheses']['uniform_marginals_alone_suffice'])
        self.assertTrue(all(x is False or x is None for x in report['qualification'].values()))
        self.assertFalse(report['source_correspondence']['receipt_bytes_read_or_verified'])
        self.assertFalse(report['source_correspondence']['all_declared_trace_sizes_reachable_or_accepted_proved'])
        self.assertNotIn('ordered_transcript_events', report)
        self.assertEqual(json.loads(json.dumps(report, allow_nan=False)), report)
        sources = replay.load_snapshot(ROOT)
        sources[replay.RNG_SOURCE] += '\n'
        with patch.object(replay, 'load_snapshot', return_value=sources):
            with self.assertRaisesRegex(ValueError, 'fixed source SHA-256 mismatch'):
                replay.build_ideal_sampler_report(ROOT)

    def test_cli_ideal_mode_does_not_run_receipt_replay_or_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'conditional.json'
            argv = ['w1_fri_query_replay.py', '--ideal-sampler-law', '--output', str(output)]
            with patch.object(sys, 'argv', argv), \
                    patch.object(replay, 'build_report', side_effect=AssertionError('replay called')):
                self.assertEqual(replay.main(), 0)
                original = output.read_bytes()
                self.assertEqual(json.loads(original)['schema'], 'TRNM-W1-CONDITIONAL-IID-QUERY-SAMPLER1')
                with patch.object(sys, 'stderr', io.StringIO()):
                    self.assertEqual(replay.main(), 2)
                self.assertEqual(output.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
