"""Pure arithmetic oracle regression; Rust consumes the same committed vector."""
import json
from pathlib import Path
import unittest
import model_evolution_oracle as oracle


class ModelEvolutionOracleTests(unittest.TestCase):
    def test_committed_context_wire_model_and_successor_vectors(self):
        committed = json.loads((Path(__file__).with_name('vectors') / 'model-evolution-v5.json').read_text())
        self.assertEqual(oracle.vector(), committed)
        self.assertEqual([committed[name]['correct'] for name in ['first', 'second', 'neutral']], [24, 25, 25])
        self.assertEqual(committed['neutral']['score'], 0)

    def test_enabled_graph_ties_and_disabled_router_maximum(self):
        coefficients = [0] * oracle.COEFFICIENTS
        coefficients[771 + 256] = 32767
        coefficients[3 * 771 + 2 * 257 + 256] = 1
        coefficients[4 * 771 + 257 + 256] = 2
        rows = [[0] * 256 + [8]]
        self.assertEqual(oracle.predictions(coefficients, 7, rows), [0])
        self.assertEqual(oracle.predictions(coefficients, 6, rows), [2])
        self.assertEqual(oracle.predictions(coefficients, 4, rows), [1])
        for mask in [0, 8, True]:
            with self.assertRaises(ValueError): oracle.predictions(coefficients, mask, rows)

    def test_checked_normalization_noop_range_and_basis_equivalence(self):
        parent = [0] * oracle.COEFFICIENTS
        values = [1] * 260
        operation = dict(target=0, rank=1, factors=values)
        output = oracle.derive(parent, 7, 7, [operation])
        equivalent = dict(target=0, rank=1, factors=[-x for x in values])
        self.assertEqual(output, oracle.derive(parent, 7, 7, [equivalent]))
        with self.assertRaisesRegex(ValueError, 'EVOLUTION_NOOP$'): oracle.derive(parent, 7, 7, [])
        with self.assertRaisesRegex(ValueError, 'EVOLUTION_ENCODING'):
            oracle.derive(parent, 7, 7, [operation, operation])
        with self.assertRaisesRegex(ValueError, 'EVOLUTION_DELTA_RANGE'):
            oracle.derive(parent, 7, 7, [dict(target=0, rank=1, factors=[32767] * 260)])
        parent[0] = 32767
        with self.assertRaisesRegex(ValueError, 'EVOLUTION_MODEL_RANGE'):
            oracle.derive(parent, 7, 7, [operation])

    def test_complete_model_canonical_reserved_byte_and_old_magic(self):
        family, values = bytes(32), [0] * oracle.COEFFICIENTS
        raw = oracle.encode_model(family, values, 2)
        self.assertEqual(oracle.decode_model(raw, family), (tuple(values), 2))
        for index, value in [(3, ord('2')), (4, 2), (46, 0), (47, 1)]:
            altered = bytearray(raw); altered[index] = value
            with self.assertRaises(ValueError): oracle.decode_model(bytes(altered), family)


if __name__ == '__main__':
    unittest.main(verbosity=2)
