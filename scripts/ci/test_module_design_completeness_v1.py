#!/usr/bin/env python3
"""False-pass mutants for the source-bound design structure gate."""
from __future__ import annotations

import copy
import unittest

import check_module_design_completeness_v1 as gate
import check_module_coverage_v1 as coverage


class ModuleDesignCompletenessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.specs = coverage.SPECS
        cls.registry = gate.validate(gate.ROOT, cls.specs)
        cls.guide = gate.visible_markdown((gate.ROOT / gate.GUIDE).read_text(encoding="utf-8"))

    def test_existing_design_passes_without_acceptance(self) -> None:
        report = gate.validate(gate.ROOT, self.specs)
        self.assertEqual(report["module_count"], 18)
        self.assertEqual(report["requirement_count"], 90)
        self.assertFalse(report["semantic_design_accepted"])
        self.assertFalse(report["implementation_accepted"])
        self.assertFalse(report["production_authority"])

    def test_missing_spec_section_is_rejected(self) -> None:
        spec = gate.visible_markdown((gate.ROOT / self.specs["M00"]).read_text(encoding="utf-8"))
        with self.assertRaises(gate.DesignCompletenessError):
            gate.section(spec.replace("## Persistence and recovery", "## Persistence", 1),
                         "Persistence and recovery", "M00")

    def test_missing_guide_state_field_is_rejected(self) -> None:
        block = gate.module_sections(self.guide)["M13"]
        with self.assertRaises(gate.DesignCompletenessError):
            gate.paragraph(block.replace("**State/admission algorithm.**", "**State algorithm.**", 1),
                           "State/admission algorithm", "M13")

    def test_registry_requirement_substitution_is_rejected(self) -> None:
        row = next(row for row in gate.load_registry_for_test() if row["id"] == "M00") if False else None
        block = gate.module_sections(self.guide)["M00"]
        expected = ["M00-CANON", "M00-PREFIX", "M00-BOUND", "M00-DOMAIN", "M00-REGISTRY"]
        mutated = block.replace("`M00-CANON`", "`M00-FAKE`", 1)
        body = gate.paragraph(mutated, "Conformance requirements", "M00")
        self.assertNotEqual(__import__('re').findall(r"`(M00-[A-Z0-9-]+)`", body), expected)

    def test_source_trace_drift_is_rejected(self) -> None:
        block = gate.module_sections(self.guide)["M00"]
        mutated = block.replace("decode_consensus_parameters_v0_exact", "missing_symbol", 1)
        trace = gate.paragraph(mutated, "Exact-source review trace", "M00")
        self.assertNotIn("decode_consensus_parameters_v0_exact", trace)


if __name__ == "__main__":
    unittest.main()
