import math
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from quantum_difficulty_screen import ratios

class QuantumToyScreenTests(unittest.TestCase):
    def test_asymmetry(self):
        self.assertEqual(ratios(16)["credited_work_per_quantum_query_multiplier"], 4)
        self.assertEqual(ratios(256)["idealized_quantum_queries_multiplier"], 16)
    def test_unity(self):
        self.assertEqual(ratios(1)["credited_work_per_quantum_query_multiplier"], 1)
    def test_bad_inputs(self):
        for x in (-1, 0, float("nan"), float("inf")):
            with self.subTest(x=x), self.assertRaises(ValueError):
                ratios(x)

if __name__ == '__main__':
    unittest.main()
