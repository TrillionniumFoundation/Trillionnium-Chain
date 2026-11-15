#!/usr/bin/env python3
from fractions import Fraction as F
from itertools import product
import unittest
from research_core import (BASE, baseline, ref, FieldMeter, GlobalAffineProducts,
                           recognize_global_affine, Gate, bank_order)
from bank_policy import (optimal_batch, exhaustive_batch_value,
                         online_penalty_identity_search)
from upstream.selector_policy_r3 import CacheModel, finite_penalty


def family(coefficients):
    origin, x0, x1, x2, x3 = coefficients
    return tuple(tuple((origin+x0*i+x1*k+x2*r+x3*t) % ref.Q
                       for r in range(8) for t in range(8))
                 for i in range(8) for k in range(8))


class GlobalCompilerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = baseline.decode_task((BASE/'upstream/reference/structured-a.bin').read_bytes())
        cls.b = baseline.decode_task((BASE/'upstream/reference/structured-b.bin').read_bytes())

    def assert_all_products(self, a, b):
        meter = FieldMeter()
        compiled = GlobalAffineProducts(a, b, meter)
        self.assertEqual((meter.multiplications, meter.additions, meter.comparisons),
                         (26, 8533, 8192))
        for i, k, j in product(range(8), repeat=3):
            self.assertEqual(compiled.product(i, k, j), ref.block_mul(a[i*8+k], b[k*8+j]))
        self.assertEqual(meter.multiplications, 26)
        self.assertEqual(meter.additions, 8533+512*73)
        self.assertEqual(meter.table_field_reads, 512*7)
        self.assertEqual(compiled.PAYLOAD_BYTES, 1316)

    def test_exact_original_coefficients(self):
        self.assertEqual(recognize_global_affine(self.a, FieldMeter()), (0,136,17,104,13))
        self.assertEqual(recognize_global_affine(self.b, FieldMeter()), (0,88,11,56,7))

    def test_original_all_512_products(self):
        self.assert_all_products(self.a, self.b)

    def test_wrapping_nontrivial_family_all_512(self):
        self.assert_all_products(family((ref.Q-1,ref.Q-2,19,ref.Q-5,37)),
                                 family((ref.Q-9,31,ref.Q-11,47,ref.Q-13)))

    def test_zero_and_rank_one_degeneracy(self):
        self.assert_all_products(family((0,0,0,0,0)), family((17,5,7,11,13)))
        self.assert_all_products(family((17,0,0,0,0)), family((19,0,0,0,0)))

    def test_preserved_block_affine_but_not_global_is_refused(self):
        a = list(self.a)
        a[10] = tuple((x+1) % ref.Q for x in a[10])
        with self.assertRaisesRegex(ValueError, 'NON_GLOBAL_AFFINE_INPUT'):
            GlobalAffineProducts(a, self.b)

    def test_last_word_corruption_is_refused(self):
        a = [list(block) for block in self.a]
        a[-1][-1] += 1
        with self.assertRaisesRegex(ValueError, 'NON_GLOBAL_AFFINE_INPUT'):
            GlobalAffineProducts(a, self.b)

    def test_noncanonical_input_is_refused(self):
        a = [list(block) for block in self.a]
        a[-1][-1] = ref.Q
        with self.assertRaisesRegex(ValueError, 'FIELD'):
            GlobalAffineProducts(a, self.b)

    def test_bad_coordinate_and_shape_refused(self):
        compiled = GlobalAffineProducts(self.a, self.b)
        for coordinate in ((8,0,0), (-1,0,0), (False,0,0)):
            with self.assertRaisesRegex(ValueError, 'COORDINATE'):
                compiled.product(*coordinate)
        with self.assertRaisesRegex(ValueError, 'MATRIX_BLOCKS'):
            GlobalAffineProducts(self.a[:-1], self.b)


class BankTheoremTests(unittest.TestCase):
    def test_every_small_schedule_and_eviction(self):
        # Independent state search includes every next coordinate, interleaving,
        # retain/discard decision, and cache identity at capacities 1,2,3.
        cases = 0
        for counts in product(range(1,4), repeat=3):
            for costs in ((1,1,1), (0,7,2), (3,1,9)):
                for capacity in (1,2,3):
                    got = optimal_batch(counts, costs, F(2,5), F(11,3))
                    independent = exhaustive_batch_value(counts, costs, F(2,5), F(11,3), capacity)
                    self.assertEqual(got['expected_cost'], independent)
                    cases += 1
        self.assertEqual(cases, 243)

    def test_empty_coordinates_are_not_purchased(self):
        got = optimal_batch((0,2,0,1), (100,4,100,1), F(1,2), 2)
        self.assertEqual(set(got['order']), {1,3})
        self.assertEqual(got['success'], F(7,8))

    def test_uniform_price_descending_occupancy(self):
        self.assertEqual(optimal_batch((1,5,3,2), (7,7,7,7), F(1,64))['order'], (1,2,3,0))

    def test_nonuniform_setup_changes_order(self):
        self.assertEqual(optimal_batch((5,1), (100,1), F(1,2))['order'], (1,0))

    def test_zero_cost_and_empty_batch(self):
        got = optimal_batch((), (), F(1,2), 1)
        self.assertEqual(got['expected_cost'], 0)
        self.assertEqual(got['success'], 0)
        self.assertEqual(optimal_batch((1,2), (0,0), F(1,2), 0)['expected_cost'], 0)

    def test_invalid_model_parameters(self):
        for args in (((1,), (1,), 1, 0), ((-1,), (1,), F(1,2), 0),
                     ((1,), (-1,), F(1,2), 0), ((1,), (), F(1,2), 0)):
            with self.assertRaises(ValueError):
                optimal_batch(*args)

    def test_strict_old_online_lower_certificate(self):
        model = CacheModel(2,1,F(1,2),F(1),F(1),F(100))
        old = finite_penalty(model,3,F(202))[0]['value']
        independent = online_penalty_identity_search(2,3,F(1,2),1,1,100,1,202)
        self.assertEqual(old, F(1281,8))
        self.assertEqual(independent, old)
        lower = old-F(202,4)
        batch = F(3)+100+F(3,2)
        self.assertEqual(lower, F(877,8))
        self.assertEqual(batch, F(209,2))
        self.assertGreater(lower, batch)

    def test_three_selectors_two_coordinates_bank_success(self):
        total_cost, total_success = F(0), F(0)
        for selectors in product(range(2), repeat=3):
            selected = min(range(2), key=lambda i: (-selectors.count(i), i))
            self.assertGreaterEqual(selectors.count(selected), 2)
            for tickets in product((False,True), repeat=2):
                attempts = 1 if tickets[0] else 2
                total_cost += F(3+100+attempts,32)
                total_success += F(any(tickets),32)
        self.assertEqual(total_cost, F(209,2))
        self.assertEqual(total_success, F(3,4))

    def test_bank_order_only_accepts_prepaid_gate_fields(self):
        gates = [Gate(9, bytes([9])*32, (1,0,0)), Gate(7, bytes([7])*32, (0,0,0)),
                 Gate(8, bytes([8])*32, (1,0,0))]
        operations = {}
        ordered, buckets = bank_order(gates, operations)
        self.assertEqual([g.nonce for g in ordered], [8,9,7])
        self.assertEqual(len(gates[0].encode()), 43)
        self.assertEqual(operations['bucket_appends'], 3)
        self.assertEqual(len(buckets), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
