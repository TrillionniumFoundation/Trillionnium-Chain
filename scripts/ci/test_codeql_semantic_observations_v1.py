#!/usr/bin/env python3
"""Original pure semantic controls; synthetic logs do not certify a scan."""
from pathlib import Path
import unittest
from unittest.mock import patch

import read_codeql_semantic_observations_v1 as reader


class AnalysisControls(unittest.TestCase):
    def test_info_semantic_failures_are_located_without_excusing_source_classes(self):
        lines = [
            b"[build-stdout] \x1b[32m INFO\x1b[0m /source/current.rs:1:1: semantic analyzer unavailable (not included as a module): macro expansion will be skipped.",
            b"[build-stdout] WARN /source/evidence/original.rs:2:3: semantic analyzer unavailable (no manifest found): macro expansion will be skipped.",
            b"ERROR failed to load workspace for /source/evidence/Cargo.toml",
        ]
        streams = {"stdout": b"\n".join(lines), "stderr": b""}
        result = reader.semantic_extraction_observations(streams, ["current.rs", "evidence/original.rs"], Path("/source"))
        self.assertEqual(result["diagnostic_line_count"], 3)
        self.assertTrue(result["diagnostic_inventory_complete"])
        self.assertEqual(result["affected_tracked_files"], ["current.rs", "evidence/original.rs"])
        self.assertEqual(result["reason_counts"], {"no manifest found": 1, "not included as a module": 1})
        self.assertEqual(result["unlocated_diagnostic_count"], 1)
        self.assertEqual(result["diagnostics"][1]["source_line"], 2)
        self.assertEqual(result["diagnostics"][1]["source_column"], 3)
        self.assertFalse(result["semantic_coverage_qualified"])
        self.assertFalse(result["official_security_gate_qualified"])

    def test_unmapped_and_unknown_semantic_failure_still_remain_failures(self):
        lines = [
            b"/source/../elsewhere.rs:1:1: semantic analyzer unavailable (unknown future reason): macro expansion will be skipped.",
            b"SEMANTIC ANALYZER UNAVAILABLE without a source location",
        ]
        result = reader.semantic_extraction_observations(
            {"stdout": b"\n".join(lines), "stderr": b""}, ["elsewhere.rs"], Path("/source"))
        self.assertEqual(result["affected_tracked_files"], [])
        self.assertEqual(result["marker_line_counts"]["semantic analyzer unavailable"], 2)
        self.assertIsNone(result["diagnostics"][0]["source_path"])
        self.assertEqual(result["unlocated_diagnostic_count"], 2)
        self.assertEqual(result["reason_counts"], {"unknown future reason": 1})
        self.assertTrue(result["failure_markers"])

    def test_semantic_inventory_bound_never_erases_failure_counts(self):
        raw = b"failed to load workspace\n" * 4
        with patch.object(reader, "SEMANTIC_DIAGNOSTIC_LIMIT", 2):
            result = reader.semantic_extraction_observations({"stdout": raw, "stderr": b""}, [], Path("/source"))
        self.assertEqual(result["diagnostic_line_count"], 4)
        self.assertEqual(result["retained_diagnostic_count"], 2)
        self.assertFalse(result["diagnostic_inventory_complete"])
        self.assertEqual(result["marker_line_counts"], {"failed to load workspace": 4})

    def test_empty_log_inventory_does_not_certify_semantics(self):
        result = reader.semantic_extraction_observations({"stdout": b"", "stderr": b""}, ["current.rs"], Path("/source"))
        self.assertEqual(result["failure_markers"], [])
        self.assertFalse(result["semantic_coverage_qualified"])
        with self.assertRaisesRegex(ValueError, "both retained"):
            reader.semantic_extraction_observations({"stdout": b""}, [], Path("/source"))



if __name__ == "__main__":
    unittest.main()
