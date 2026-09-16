#!/usr/bin/env python3
"""Mutate required-workflow wiring; Git-tree semantics have a separate test suite."""
from pathlib import Path
import unittest
from check_required_baseline_closure_v1 import BaselineClosureError, validate_scope_wiring

ROOT = Path(__file__).resolve().parents[2]


class WiringTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / ".github/workflows/trnm-required-baseline.yml").read_text()

    def test_current_wiring(self):
        validate_scope_wiring(self.workflow)

    def test_wrong_source_base_or_missing_compiler_test_is_rejected(self):
        for before, after in (
            ('args=(--expected-head "$TRNM_EXPECTED_SOURCE_SHA"', 'args=(--expected-head "main"'),
            ("TRNM_BASE_SHA: ${{ github.event.pull_request.base.sha }}", "TRNM_BASE_SHA: user-controlled"),
            ("cargo test -p trnm-poco-node-production-v0 --doc --locked", "echo source inspection only"),
            ('cmp "${RUNNER_TEMP}/trnm-validation-scope-v1.json"', 'echo "${RUNNER_TEMP}/trnm-validation-scope-v1.json"'),
            ("python3 scripts/ci/test_validation_scope_v1.py", "echo omitted selector tests"),
        ):
            with self.subTest(before=before), self.assertRaises(BaselineClosureError):
                validate_scope_wiring(self.workflow.replace(before, after))

    def test_broad_or_inverted_guard_is_rejected(self):
        for replacement in ("'false'", "'true' || true"):
            value = self.workflow.replace("steps.rust_scope.outputs.run_rust == 'true'", "steps.rust_scope.outputs.run_rust == " + replacement, 1)
            with self.subTest(replacement=replacement), self.assertRaises(BaselineClosureError):
                validate_scope_wiring(value)

    def test_other_required_jobs_cannot_use_rust_scope(self):
        with self.assertRaises(BaselineClosureError):
            validate_scope_wiring(self.workflow.replace("  protocol-contract:\n", "  protocol-contract:\n    if: steps.rust_scope.outputs.run_rust\n"))

    def test_selector_cannot_be_skipped(self):
        with self.assertRaises(BaselineClosureError):
            validate_scope_wiring(self.workflow.replace("        id: rust_scope\n", "        id: rust_scope\n        if: false\n"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
