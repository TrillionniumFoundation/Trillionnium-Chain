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

    def metric_raw(self, number):
        value = doc()
        value["runs"][0]["properties"] = {"metricResults": [
            {"ruleId": "unchanged-metric", "value": "RAW_METRIC_NUMBER"}]}
        return p.serialized(value).replace(b'"RAW_METRIC_NUMBER"', number.encode("ascii"))

    def test_metric_exact_safe_integer_spellings_are_recorded(self):
        cases = (("100.0", "100"), ("1e2", "100"), ("-100.0", "-100"),
                 ("0.0", "0"), ("-0.0", "0"),
                 ("9007199254740991.0", "9007199254740991"),
                 ("-9007199254740991.0", "-9007199254740991"))
        for old, new in cases:
            with self.subTest(old=old, new=new):
                left, right = self.metric_raw(old), self.metric_raw(new)
                observation = p.compare_postprocessed(left, right)
                self.assertEqual(observation["metric_number_serializations"], [{
                    "pointer": "/runs/0/properties/metricResults/0/value",
                    "original_decimal": str(p.Decimal(old)), "processed_integer": int(new)}])
                self.assertEqual(observation["publication_sarif"], p.digest(left))
                self.assertEqual(observation["official_postprocessed_sarif"], p.digest(right))
                self.assertIs(observation["official_security_gate_qualified"], False)
                self.assertIs(observation["production_qualified"], False)

    def test_metric_noninteger_and_exact_decimal_value_changes_rejected(self):
        cases = (("100.0", "101"), ("100.5", "100"), ("-100.0", "100"),
                 ("1e-400", "0"), ("9007199254740990.5", "9007199254740990"),
                 ("-9007199254740990.5", "-9007199254740990"),
                 ("9007199254740991.1", "9007199254740991"))
        for old, new in cases:
            with self.subTest(old=old, new=new), self.assertRaisesRegex(ValueError, "exact finite"):
                p.compare_postprocessed(self.metric_raw(old), self.metric_raw(new))

    def test_metric_unsafe_integer_range_and_nonfinite_rejected(self):
        for old, new in (("9007199254740992.0", "9007199254740992"),
                         ("-9007199254740992.0", "-9007199254740992"),
                         ("1e309", "0"), ("-1e309", "0"),
                         ("NaN", "0"), ("Infinity", "0"), ("-Infinity", "0")):
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                p.compare_postprocessed(self.metric_raw(old), self.metric_raw(new))

    def test_metric_bool_string_null_and_reverse_type_changes_rejected(self):
        for old, new in (("1.0", "true"), ("false", "0"), ("true", "1"),
                         ("1", "1.0"), ('"1.0"', "1"), ("1.0", '"1"'),
                         ("null", "0"), ("1.0", "null")):
            with self.subTest(old=old, new=new), self.assertRaisesRegex(ValueError, "more than"):
                p.compare_postprocessed(self.metric_raw(old), self.metric_raw(new))

    def test_metric_exception_does_not_apply_to_other_paths(self):
        for where in ("run-property", "result-property", "notification-property"):
            original = doc()
            if where == "run-property":
                target = original["runs"][0]
                target["properties"] = {"anotherMetric": {"value": 100.0}}
                route = ("properties", "anotherMetric", "value")
            elif where == "result-property":
                target = original["runs"][0]["results"][0]
                target["properties"] = {"metricResults": [{"value": 100.0}]}
                route = ("properties", "metricResults", 0, "value")
            else:
                target = original["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]
                target["properties"] = {"metricResults": [{"value": 100.0}]}
                route = ("properties", "metricResults", 0, "value")
            left = p.serialized(original)
            for component in route[:-1]:
                target = target[component]
            target[route[-1]] = 100
            with self.subTest(where=where), self.assertRaisesRegex(ValueError, "more than"):
                p.compare_postprocessed(left, p.serialized(original))

    def test_exact_decimal_changes_cannot_hide_behind_equal_binary_floats(self):
        old, new = "0.1000000000000000001", "0.1000000000000000002"
        self.assertEqual(float(old), float(new))
        with self.assertRaisesRegex(ValueError, "more than"):
            p.compare_postprocessed(self.metric_raw(old), self.metric_raw(new))
        # The same guarantee holds when original fingerprint values are restored.
        left = doc()
        left["runs"][0]["results"][0]["partialFingerprints"] = {"old": "EXACT_NUMBER"}
        left = p.serialized(left)
        with self.assertRaisesRegex(ValueError, "existing fingerprint"):
            p.compare_postprocessed(left.replace(b'"EXACT_NUMBER"', old.encode()),
                                    left.replace(b'"EXACT_NUMBER"', new.encode()))

    def test_metric_normalization_does_not_hide_other_changes(self):
        left = self.metric_raw("100.0")
        for changed in ("metric-rule", "metric-added", "metric-removed", "metric-value-missing",
                        "findings", "diagnostics", "category", "severity"):
            right = json.loads(self.metric_raw("100"))
            run = right["runs"][0]
            metric = run["properties"]["metricResults"][0]
            if changed == "metric-rule":
                metric["ruleId"] = "different"
            elif changed == "metric-added":
                run["properties"]["metricResults"].append(copy.deepcopy(metric))
            elif changed == "metric-removed":
                run["properties"]["metricResults"] = []
            elif changed == "metric-value-missing":
                del metric["value"]
            elif changed == "findings":
                run["results"] = []
            elif changed == "diagnostics":
                run["invocations"][0]["toolExecutionNotifications"] = []
            elif changed == "category":
                run["automationDetails"]["id"] = "changed/"
            else:
                run["results"][0]["level"] = "none"
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                p.compare_postprocessed(left, p.serialized(right))

    def test_metric_serialization_and_additive_fingerprint_remain_separate(self):
        left = self.metric_raw("100.0")
        right = json.loads(self.metric_raw("100"))
        right["runs"][0]["results"][0]["partialFingerprints"] = {"primaryLocationLineHash": "abc:1"}
        observation = p.compare_postprocessed(left, p.serialized(right))
        self.assertEqual(len(observation["additive_fingerprints"]), 1)
        self.assertEqual(len(observation["metric_number_serializations"]), 1)
        self.assertIs(observation["all_results_rules_diagnostics_and_invocations_preserved"], True)
        self.assertIs(observation["official_security_gate_qualified"], False)


if __name__ == "__main__":
    unittest.main()
