"""Factor-preserving execution controls; explicit dense expansion is test-only."""
import copy
from dataclasses import FrozenInstanceError, replace
import unittest
from contract_wire import canonical
from grouped_low_rank_v0 import apply_factors, apply_existing_adapter, prepare_existing_adapter
from model_attribution import integer_linear_contract, contract_id, normalize_adapter
from test_model_attribution import fixture_parent


class GroupedLowRankTests(unittest.TestCase):
    def test_exact_factors_match_dense_math_without_charging_dense_macs(self):
        up = [[1, 2], [-3, 4], [5, -6]]
        down = [[(k % 5) - 2 for k in range(257)], [(k % 7) - 3 for k in range(257)]]
        rows = [[((k + i) % 17) - 8 for k in range(257)] for i in range(4)]
        dense = [[sum(up[o][r] * down[r][k] for r in range(2)) for k in range(257)] for o in range(3)]
        expected = [[sum(a * x for a, x in zip(weight, row)) for weight in dense] for row in rows]
        result = apply_factors(up, down, rows)
        self.assertEqual(result['outputs'], expected)
        self.assertEqual(result['executed_macs'], 4 * 2 * (257 + 3))
        self.assertEqual(result['dense_equivalent_macs_for_comparison'], 4 * 3 * 257)
        self.assertFalse(result['dense_expansion_executed'])
        self.assertEqual(result['business_credit_awarded'], 0)

    def test_identity_binds_factorization_even_with_equal_dense_function(self):
        first = apply_factors([[2]], [[1, 3]], [[2, 1]])
        other = apply_factors([[1]], [[2, 6]], [[2, 1]])
        self.assertEqual(first['outputs'], other['outputs'])
        self.assertNotEqual(first['factor_commitment'], other['factor_commitment'])

    def test_invalid_shapes_ranges_types_and_work_cap_refuse(self):
        cases = [([], [[1]], [[1]]), ([[1]], [[1, 2]], [[1]]),
                 ([[True]], [[1]], [[1]]), ([[32768]], [[1]], [[1]]),
                 ([[1]], [[1]], [[9]]), ([[1]], [[]], [[]]),
                 ([[1]], [[1]], [[1]] * 65)]
        for args in cases:
            with self.subTest(args=str(args)[:50]), self.assertRaises(ValueError):
                apply_factors(*args)
        with self.assertRaisesRegex(ValueError, 'FACTOR_MAC_LIMIT'):
            apply_factors([[1] * 64 for _ in range(1024)], [[1] * 1024 for _ in range(64)],
                          [[1] * 1024 for _ in range(64)])

    def test_existing_admission_is_reused_and_normalization_is_separate(self):
        contract = integer_linear_contract(fixture_parent())
        adapter = {'schema': 'pon-integer-linear-adapter-v1', 'contract': contract_id(contract),
                   'A': [[1] * 257], 'B': [[1], [1], [1]]}
        expected = normalize_adapter(adapter, contract)
        prepared = prepare_existing_adapter(adapter, contract)
        adapter['B'][0][0] = 2  # Caller mutation cannot change the captured factors.
        result = apply_existing_adapter(prepared, [[1] * 256 + [8]])
        self.assertEqual(result['outputs'], [[264, 264, 264]])
        self.assertEqual(result['executed_macs'], 260)
        self.assertEqual(result['one_time_normalization_macs'], 771)
        self.assertEqual(result['existing_adapter_artifact'], expected['artifact'])
        self.assertEqual(result['existing_function_fingerprint'], expected['function_fingerprint'])
        with self.assertRaises(FrozenInstanceError):
            prepared.adapter_bytes = canonical(adapter)
        with self.assertRaisesRegex(ValueError, 'ADAPTER_PREPARATION_BINDING'):
            apply_existing_adapter(replace(prepared, adapter_bytes=canonical(adapter)), [[1] * 257])
        with self.assertRaisesRegex(ValueError, 'ADAPTER_PREPARATION'):
            apply_existing_adapter({'up': [[2], [1], [1]], 'down': [[1] * 257]}, [[1] * 257])

    def test_existing_rank_four_through_eight_are_legal_but_not_claimed_cheaper(self):
        contract = integer_linear_contract(fixture_parent())
        for rank in (4, 8):
            adapter = {'schema': 'pon-integer-linear-adapter-v1', 'contract': contract_id(contract),
                       'A': [[1] * 257 for _ in range(rank)], 'B': [[1] * rank for _ in range(3)]}
            result = apply_existing_adapter(prepare_existing_adapter(adapter, contract), [[1] * 256 + [8]])
            self.assertEqual(result['outputs'], [[rank * 264] * 3])
            self.assertGreater(result['executed_macs'], result['dense_equivalent_macs_for_comparison'])
            self.assertEqual(result['executed_macs'], rank * 260)
            self.assertFalse(result['pow_qualified'])

    def test_existing_admission_still_rejects_illegal_dense_update(self):
        contract = integer_linear_contract(fixture_parent())
        adapter = {'schema': 'pon-integer-linear-adapter-v1', 'contract': contract_id(contract),
                   'A': [[32767] * 257], 'B': [[32767], [32767], [32767]]}
        with self.assertRaises(ValueError):
            prepare_existing_adapter(adapter, contract)


if __name__ == '__main__':
    unittest.main()
