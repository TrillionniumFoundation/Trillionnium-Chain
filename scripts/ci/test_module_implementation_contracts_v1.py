#!/usr/bin/env python3
"""Focused mutation tests for the per-module implementation matrix gate."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_module_implementation_contracts_v1 as gate


class ModuleImplementationMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = gate.MATRIX.read_text(encoding="utf-8")
        cls.registry = gate.load_registry()

    def test_positive_matrix_has_all_modules_and_requirements(self) -> None:
        report = gate.validate_matrix(self.text, self.registry)
        self.assertEqual(report["module_count"], 18)
        self.assertEqual(report["requirement_count"], 90)
        self.assertEqual(report["result"], "PASS")

    def test_missing_module_is_rejected(self) -> None:
        mutated = self.text.replace("### M17 — Evidence / Benchmark / Security\n", "", 1)
        with self.assertRaises(gate.MatrixError):
            gate.validate_matrix(mutated, self.registry)

    def test_source_symbol_drift_is_rejected(self) -> None:
        mutated = self.text.replace(
            "::decode_consensus_parameters_v0_exact`",
            "::missing_symbol`",
            1,
        )
        with self.assertRaises(gate.MatrixError):
            gate.validate_matrix(mutated, self.registry)

    def test_regression_symbol_drift_is_rejected(self) -> None:
        mutated = self.text.replace(
            "::test_local_accepted_state`",
            "::missing_regression`",
            1,
        )
        with self.assertRaises(gate.MatrixError):
            gate.validate_matrix(mutated, self.registry)

    def test_transition_cannot_be_a_single_label(self) -> None:
        mutated = self.text.replace(
            "`AuthenticatedContext -> BoundedDecode -> SemanticValidate -> CanonicalReencode -> AdmittedValue`",
            "`AdmittedValue`",
            1,
        )
        with self.assertRaises(gate.MatrixError):
            gate.validate_matrix(mutated, self.registry)

    def test_requirement_substitution_is_rejected(self) -> None:
        mutated = self.text.replace("`M13-STAGE`", "`M13-FAKE`", 1)
        with self.assertRaises(gate.MatrixError):
            gate.validate_matrix(mutated, self.registry)

    def test_direct_transition_and_untemplated_evidence_are_allowed(self) -> None:
        mutated = self.text.replace(
            "`AuthenticatedContext -> BoundedDecode -> SemanticValidate -> CanonicalReencode -> AdmittedValue`",
            "`AuthenticatedContext -> AdmittedValue`",
            1,
        ).replace(
            "independent vectors for every reachable CEV0/CEV1 object and parser/error review remain required.",
            "Still pending: independent vectors for all reachable CEV0/CEV1 objects and parser/error review.",
            1,
        )
        report = gate.validate_matrix(mutated, self.registry)
        self.assertEqual(report["semantic_acceptance"], "not-assessed")
        self.assertEqual(report["status"], "source-regression-open")

    def test_absent_open_evidence_is_rejected(self) -> None:
        mutated = self.text.replace(
            "- **Open evidence:** independent vectors for every reachable CEV0/CEV1 object and parser/error review remain required.\n",
            "",
            1,
        )
        with self.assertRaises(gate.MatrixError):
            gate.validate_matrix(mutated, self.registry)

    def test_acceptance_promotion_is_rejected(self) -> None:
        mutated = self.text.replace(
            "- **Acceptance status:** `source-regression-open`",
            "- **Acceptance status:** `accepted`",
            1,
        )
        with self.assertRaises(gate.MatrixError):
            gate.validate_matrix(mutated, self.registry)


if __name__ == "__main__":
    unittest.main()
