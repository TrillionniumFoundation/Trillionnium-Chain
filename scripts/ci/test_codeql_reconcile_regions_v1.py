#!/usr/bin/env python3
"""M17 full-region regressions; synthetic fixtures are not security acceptance."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest

from codeql_reconcile_regions_v1 import reconcile_regions

SHA = "1" * 40
TREE = "2" * 40
REF = "refs/pull/125/head"


def fixture():
    records, alerts = [], []
    for ordinal, column in enumerate((62, 78), 1):
        primary = {"path": "synthetic/example.rs", "line": 7, "end_line": 7,
                   "column": column, "end_column": column + 3}
        records.append({
            "exact_source_sha": SHA, "exact_source_tree": TREE,
            "accepted": False, "acceptance_state": "candidate-unreviewed",
            "independent_security_review_required": True,
            "inventory_id": hashlib.sha256(f"synthetic-{ordinal}".encode()).hexdigest(),
            "finding_id": f"synthetic-{ordinal}",
            "rule_id": "rust/hard-coded-cryptographic-value", "primary": primary,
            "partialFingerprints": {"same-test-fingerprint": "not-a-global-key"},
        })
        alerts.append({
            "alert_number": ordinal, "tool_name": "CodeQL", "state": "open",
            "rule_id": "rust/hard-coded-cryptographic-value",
            "most_recent_instance": {
                "commit_sha": SHA, "category": "/language:rust",
                "analysis_key": "dynamic/github-code-scanning/codeql:analyze",
                "ref": REF, "state": "open",
                "location": {"path": primary["path"], "start_line": 7, "end_line": 7,
                             "start_column": column, "end_column": column + 3},
            },
        })
    return records, alerts


class RegionTests(unittest.TestCase):
    def setUp(self):
        self.records, self.alerts = fixture()

    def mapped(self, sha=SHA, tree=TREE, ref=REF):
        return reconcile_regions(self.records, self.alerts, sha, tree, expected_ref=ref)

    def test_same_line_distinct_columns_and_repeated_partial_fingerprint(self):
        rows, ids, counts = self.mapped()
        self.assertEqual(len(ids), 2)
        self.assertEqual(counts, {"unique-rule-path-region": 2})
        self.assertEqual({row["start_column"] for row in rows}, {62, 78})

    def test_inputs_remain_byte_equivalent(self):
        before = json.dumps((self.records, self.alerts), sort_keys=True)
        self.mapped()
        self.assertEqual(json.dumps((self.records, self.alerts), sort_keys=True), before)

    def test_duplicate_full_regions_remain_ambiguous(self):
        self.records[1]["primary"] = copy.deepcopy(self.records[0]["primary"])
        _, ids, counts = self.mapped()
        self.assertEqual(counts, {"ambiguous": 1, "unmapped": 1})
        self.assertFalse(ids)

    def test_sarif_defined_defaults(self):
        self.records[0]["primary"].update(column=None, end_line=None)
        self.alerts[0]["most_recent_instance"]["location"]["start_column"] = 1
        self.assertEqual(len(self.mapped()[1]), 2)

    def test_missing_ghas_coordinates_rejected(self):
        for key in ("start_line", "end_line", "start_column", "end_column"):
            with self.subTest(key=key):
                self.records, self.alerts = fixture()
                del self.alerts[0]["most_recent_instance"]["location"][key]
                with self.assertRaises(ValueError):
                    self.mapped()

    def test_missing_sarif_end_column_rejected(self):
        del self.records[0]["primary"]["end_column"]
        with self.assertRaises(ValueError):
            self.mapped()

    def test_boolean_and_nonpositive_coordinates_rejected(self):
        for value in (True, False, 0, -1, "7", 1.5):
            with self.subTest(value=value):
                self.records, self.alerts = fixture()
                self.alerts[0]["most_recent_instance"]["location"]["start_line"] = value
                with self.assertRaises(ValueError):
                    self.mapped()

    def test_reversed_region_rejected(self):
        self.alerts[0]["most_recent_instance"]["location"]["end_column"] = 1
        with self.assertRaises(ValueError):
            self.mapped()

    def test_distinct_end_line_is_not_a_match(self):
        self.alerts[0]["most_recent_instance"]["location"]["end_line"] += 1
        self.assertEqual(self.mapped()[2]["unmapped"], 1)

    def test_distinct_end_column_is_not_a_match(self):
        self.alerts[0]["most_recent_instance"]["location"]["end_column"] += 1
        self.assertEqual(self.mapped()[2]["unmapped"], 1)

    def test_duplicate_alert_number_rejected(self):
        self.alerts[1]["alert_number"] = self.alerts[0]["alert_number"]
        with self.assertRaises(ValueError):
            self.mapped()

    def test_duplicate_immutable_inventory_id_rejected(self):
        self.records[1]["inventory_id"] = self.records[0]["inventory_id"]
        with self.assertRaises(ValueError):
            self.mapped()

    def test_multiple_alerts_cannot_consume_one_result(self):
        self.alerts[1]["most_recent_instance"] = copy.deepcopy(self.alerts[0]["most_recent_instance"])
        with self.assertRaises(ValueError):
            self.mapped()

    def test_head_and_tree_drift_rejected(self):
        for sha, tree in (("3" * 40, TREE), (SHA, "4" * 40), ("short", TREE)):
            with self.subTest(sha=sha, tree=tree), self.assertRaises(ValueError):
                self.mapped(sha=sha, tree=tree)

    def test_instance_identity_drift_rejected(self):
        for key, value in (("commit_sha", "3" * 40), ("category", "/language:python"),
                           ("ref", "refs/pull/62/head"), ("state", "fixed"),
                           ("analysis_key", "untrusted:analyze")):
            with self.subTest(key=key):
                self.records, self.alerts = fixture()
                self.alerts[0]["most_recent_instance"][key] = value
                with self.assertRaises(ValueError):
                    self.mapped()

    def test_explicit_ref_supports_other_pr_without_cross_ref_composition(self):
        for alert in self.alerts:
            alert["most_recent_instance"]["ref"] = "refs/pull/62/head"
        self.assertEqual(len(self.mapped(ref="refs/pull/62/head")[1]), 2)
        with self.assertRaises(ValueError):
            self.mapped()

    def test_invalid_expected_ref_rejected(self):
        for ref in ("", "refs/pull/0/head", "refs/pull/125/merge", "refs/heads/main"):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                self.mapped(ref=ref)

    def test_producer_and_candidate_acceptance_flags_fail_closed(self):
        mutations = [("alert", "tool_name", "Other"), ("alert", "state", "dismissed"),
                     ("record", "accepted", True), ("record", "acceptance_state", "accepted"),
                     ("record", "independent_security_review_required", False)]
        for target, key, value in mutations:
            with self.subTest(target=target, key=key):
                self.records, self.alerts = fixture()
                (self.alerts if target == "alert" else self.records)[0][key] = value
                with self.assertRaises(ValueError):
                    self.mapped()

    def test_traversal_and_absolute_paths_rejected(self):
        for path in ("../x.rs", "/x.rs", "a/../x.rs", "a\\x.rs", "a//x.rs", "C:x.rs"):
            with self.subTest(path=path):
                self.records, self.alerts = fixture()
                self.records[0]["primary"]["path"] = path
                with self.assertRaises(ValueError):
                    self.mapped()

    def test_missing_records_and_empty_inventories_rejected(self):
        self.records.pop()
        with self.assertRaises(ValueError):
            self.mapped()
        self.records, self.alerts = [], []
        with self.assertRaises(ValueError):
            self.mapped()


class WorkflowCoverageTests(unittest.TestCase):
    def test_source_and_merge_baseline_execute_region_regressions(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/trnm-required-baseline.yml").read_text()
        command = "python3 -B scripts/ci/test_codeql_reconcile_regions_v1.py"
        self.assertEqual(workflow.count(command), 2)
        self.assertNotIn("continue-on-error:", workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)
