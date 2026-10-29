#!/usr/bin/env python3
"""Pure-data controls for the scratch proposal; not a CodeQL/native run."""
import copy
import importlib.util
import json
from pathlib import Path
import time
import unittest

spec = importlib.util.spec_from_file_location("publisher", Path(__file__).with_name("prepare_codeql_publication_v1.py"))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def doc():
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL"}},
        "automationDetails": {"id": "retained/original/category/"},
        "artifacts": [
            {"location": {"uri": "project/src/a.c", "uriBaseId": "%SRCROOT%", "index": 0}},
            {"location": {"uri": "build/kernel-owned-original.c", "uriBaseId": "%SRCROOT%", "index": 1}}],
        "invocations": [{"executionSuccessful": True,
            "toolExecutionNotifications": [{"message": {"text": "project/src/a.c must remain prose"},
            "locations": [{"physicalLocation": {"artifactLocation":
                {"uri": "build/kernel-owned-original.c", "uriBaseId": "%SRCROOT%", "index": 1}}}]}]}],
        "results": [{"ruleId": "unchanged", "message": {"text": "Keep every result"},
            "locations": [{"physicalLocation": {"artifactLocation":
                {"uri": "project/src/a.c", "uriBaseId": "%SRCROOT%", "index": 0},
                "region": {"startLine": 7}}}],
            "codeFlows": [{"threadFlows": [{"locations": [{"location": {"physicalLocation":
                {"artifactLocation": {"uri": "project/src/a.c", "uriBaseId": "%SRCROOT%", "index": 0}}}}]}]}]}]}]}


class Controls(unittest.TestCase):
    def setUp(self):
        p.DEADLINE = time.monotonic() + 15

    def map(self, d):
        return p.rewrite(d, "cpp", {"src/a.c": {}},
                         "file:///old-analysis/cpp-scope/build/kernel-owned-original.c")

    def test_mapping_preserves_non_location_values(self):
        original = doc()
        derived, edits = self.map(original)
        self.assertEqual(original["runs"][0]["artifacts"][0]["location"]["uri"], "project/src/a.c")
        self.assertEqual(derived["runs"][0]["artifacts"][0]["location"]["uri"], "src/a.c")
        self.assertEqual(len(edits), 5)
        self.assertEqual(derived["runs"][0]["automationDetails"], original["runs"][0]["automationDetails"])
        self.assertEqual(derived["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["message"],
                         original["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["message"])

    def test_generated_is_absolute_and_stays_untracked(self):
        derived, _ = self.map(doc())
        loc = derived["runs"][0]["artifacts"][1]["location"]
        self.assertEqual(loc, {"uri": "file:///old-analysis/cpp-scope/build/kernel-owned-original.c", "index": 1})

    def test_tool_model_locations_remain_byte_value_identical(self):
        original = doc()
        original["runs"][0]["tool"]["extensions"] = [{"taxa": [{"properties": {
            "CodeQL/DataExtensionLocation": {"artifactLocation": {"uri": "codeql/rust/frameworks/log.model.yml"}}}}]}]
        derived, _ = self.map(original)
        self.assertEqual(derived["runs"][0]["tool"], original["runs"][0]["tool"])

    def test_fix_target_is_mapped_and_other_fix_fields_preserved(self):
        original = doc()
        original["runs"][0]["results"][0]["fixes"] = [{"description": {"text": "keep"}, "artifactChanges": [{
            "artifactLocation": {"uri": "project/src/a.c", "uriBaseId": "%SRCROOT%", "index": 0},
            "replacements": [{"deletedRegion": {"startLine": 7}, "insertedContent": {"text": "keep"}}]}]}]
        derived, _ = self.map(original)
        change = derived["runs"][0]["results"][0]["fixes"][0]["artifactChanges"][0]
        self.assertEqual(change["artifactLocation"]["uri"], "src/a.c")
        self.assertEqual(change["replacements"], original["runs"][0]["results"][0]["fixes"][0]["artifactChanges"][0]["replacements"])

    def test_unknown_tracked_path_rejected(self):
        d = doc()
        d["runs"][0]["artifacts"][0]["location"]["uri"] = "project/src/foreign.c"
        with self.assertRaises(ValueError):
            self.map(d)

    def test_unknown_generated_path_rejected(self):
        d = doc()
        d["runs"][0]["artifacts"][1]["location"]["uri"] = "build/not-the-bound-file.c"
        with self.assertRaises(ValueError):
            self.map(d)

    def test_index_uri_disagreement_rejected(self):
        d = doc()
        d["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["index"] = 1
        with self.assertRaisesRegex(ValueError, "inline/index"):
            self.map(d)

    def test_bool_index_rejected(self):
        d = doc()
        d["runs"][0]["artifacts"][0]["location"]["index"] = True
        with self.assertRaisesRegex(ValueError, "index"):
            self.map(d)

    def test_new_uri_base_rejected(self):
        d = doc()
        d["runs"][0]["artifacts"][0]["location"]["uriBaseId"] = "UNBOUND"
        with self.assertRaises(ValueError):
            self.map(d)

    def test_encoded_traversal_rejected(self):
        d = doc()
        loc = d["runs"][0]["artifacts"][0]["location"]
        loc["uri"] = "project/%2e%2e/key"
        with self.assertRaises(ValueError):
            self.map(d)

    def test_duplicate_json_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            p.loads(b'{"a":1,"a":2}')

    def test_nonfinite_json_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-finite"):
            p.loads(b'{"a":NaN}')

    def test_postprocess_allows_only_additive_fingerprint(self):
        original = doc()
        processed = copy.deepcopy(original)
        processed["runs"][0]["results"][0]["partialFingerprints"] = {"primaryLocationLineHash": "abc:1"}
        result = p.compare_postprocessed(p.serialized(original), p.serialized(processed))
        self.assertEqual(len(result["additive_fingerprints"]), 1)
        self.assertIs(result["official_security_gate_qualified"], False)

    def test_postprocess_rejects_filtering(self):
        processed = doc()
        processed["runs"][0]["results"] = []
        with self.assertRaisesRegex(ValueError, "filtered"):
            p.compare_postprocessed(p.serialized(doc()), p.serialized(processed))

    def test_postprocess_rejects_existing_fingerprint_changes(self):
        original = doc()
        original["runs"][0]["results"][0]["partialFingerprints"] = {"primaryLocationLineHash": "abc:1"}
        processed = copy.deepcopy(original)
        processed["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"] = "def:1"
        with self.assertRaisesRegex(ValueError, "existing"):
            p.compare_postprocessed(p.serialized(original), p.serialized(processed))

    def test_postprocess_rejects_category_severity_diagnostics_changes(self):
        for field in ("category", "severity", "diagnostic"):
            processed = doc()
            if field == "category":
                processed["runs"][0]["automationDetails"]["id"] = "fake/"
            elif field == "severity":
                processed["runs"][0]["results"][0]["level"] = "none"
            else:
                processed["runs"][0]["invocations"][0]["toolExecutionNotifications"] = []
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "more than"):
                p.compare_postprocessed(p.serialized(doc()), p.serialized(processed))


if __name__ == "__main__":
    unittest.main()
