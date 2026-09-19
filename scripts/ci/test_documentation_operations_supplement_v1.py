#!/usr/bin/env python3
"""Mutation tests for the supplemental operation-design validator."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_documentation_operations_supplement_v1 as gate


class SupplementalOperationMutants(unittest.TestCase):
    def setUp(self) -> None:
        self.data = json.loads(gate.CONFIG.read_text(encoding="utf-8"))

    def test_positive_scope(self) -> None:
        report = gate.validate(self.data)
        self.assertEqual(report["operation_count"], 3)
        self.assertEqual(report["source_regression_case_count"], 7)
        self.assertEqual(report["recovery_case_count"], 1)
        self.assertTrue(report["catalog_complete_for_declared_scope"])
        self.assertFalse(report["production_authority"])

    def test_operation_substitution_is_rejected(self) -> None:
        mutated = deepcopy(self.data)
        mutated["operations"][0]["implementation"]["symbol"] = "not_a_real_successor_composer"
        with self.assertRaises(gate.SupplementError):
            gate.validate(mutated)

    def test_missing_negative_case_is_rejected(self) -> None:
        mutated = deepcopy(self.data)
        mutated["operations"][2]["cases"] = [
            case for case in mutated["operations"][2]["cases"] if case["kind"] != "negative"
        ]
        with self.assertRaises(gate.SupplementError):
            gate.validate(mutated)

    def test_promotion_is_rejected(self) -> None:
        mutated = deepcopy(self.data)
        mutated["production_authority"] = True
        with self.assertRaises(gate.SupplementError):
            gate.validate(mutated)


if __name__ == "__main__":
    unittest.main()
