#!/usr/bin/env python3
"""M17 deterministic regressions. Fixtures are synthetic, never acceptance evidence."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from codeql_reconcile_regions_v1 import reconcile_regions
from documentation_binding_log_v1 import emit_binding, recover_binding, strict_json

ROOT = Path(__file__).resolve().parents[2]
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


class BindingTests(unittest.TestCase):
    def emit(self, data, mode="source", digest=None):
        digest = hashlib.sha256(data).hexdigest() if digest is None else digest
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "binding.json"
            path.write_bytes(data)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                emit_binding(path, digest, mode)
            return out.getvalue(), digest

    def test_exact_bytes_and_unicode_round_trip(self):
        for data in (b'{ "synthetic": true, "nested": {"n":1} }\n',
                     json.dumps({"synthetic": "中文\n::warning::not-a-command"}, ensure_ascii=False).encode()):
            for mode in ("source", "merge"):
                with self.subTest(mode=mode):
                    log, digest = self.emit(data, mode)
                    self.assertEqual(recover_binding(log, digest, mode), data)

    def test_multi_chunk_and_timestamped_log(self):
        data = json.dumps({"synthetic": "x" * 14000}).encode()
        log, digest = self.emit(data)
        stamped = "\n".join("2026-09-13T00:00:00.1234567Z " + row for row in log.splitlines())
        self.assertEqual(recover_binding(stamped, digest, "source"), data)

    def test_missing_duplicate_reordered_and_mixed_frames_rejected(self):
        log, digest = self.emit(json.dumps({"synthetic": "x" * 14000}).encode())
        lines = log.splitlines()
        bad_logs = ("\n".join(lines[:-1]), log + log,
                    "\n".join(reversed(lines)), log.replace("source " + digest, "source " + "f" * 64, 1))
        for bad in bad_logs:
            with self.subTest(log_length=len(bad)), self.assertRaises(ValueError):
                recover_binding(bad, digest, "source")

    def test_payload_tamper_rejected(self):
        log, digest = self.emit(b'{"synthetic":true}')
        log = log.rstrip()[:-1] + "A\n"
        with self.assertRaises(ValueError):
            recover_binding(log, digest, "source")

    def test_wrong_digest_or_mode_rejected(self):
        log, digest = self.emit(b'{"synthetic":true}')
        for expected, mode in (("f" * 64, "source"), (digest, "merge"), (digest, "bad")):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                recover_binding(log, expected, mode)

    def test_digest_only_log_is_not_recoverable(self):
        with self.assertRaises(ValueError):
            recover_binding("TRNM_DOCUMENTATION_SOURCE_BINDING_SHA256=" + "f" * 64, "f" * 64, "source")

    def test_post_digest_mutation_and_bounds_rejected_before_output(self):
        for data, digest in ((b'{"synthetic":true}', "f" * 64), (b"", None),
                             (json.dumps({"synthetic": "x" * 65536}).encode(), None)):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                self.emit(data, digest=digest)

    def test_exact_maximum_binding_round_trip(self):
        data = b'{"x":"' + b"a" * (65536 - 8) + b'"}'
        self.assertEqual(len(data), 65536)
        log, digest = self.emit(data)
        self.assertEqual(len(log.splitlines()), 23)
        self.assertEqual(recover_binding(log, digest, "source"), data)

    def test_nonobject_duplicates_and_nonfinite_json_rejected(self):
        for data in (b"[]", b"null", b'{"accepted":false,"accepted":true}', b'{"n":NaN}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.emit(data)

    def test_strict_json_rejects_nested_duplicate_and_infinity(self):
        for data in ('{"x":{"n":1,"n":2}}', '{"n":Infinity}', '{"n":-Infinity}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                strict_json(data)

    def test_cli_round_trip_and_no_overwrite(self):
        script = Path(__file__).with_name("documentation_binding_log_v1.py")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            raw = b'{"synthetic-cli":true}\n'
            (root / "binding.json").write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            emit = subprocess.run([sys.executable, "-B", str(script), "emit", "--binding", str(root / "binding.json"),
                                   "--expected-sha256", digest, "--mode", "source"], capture_output=True, check=True)
            (root / "job.log").write_bytes(emit.stdout)
            command = [sys.executable, "-B", str(script), "recover", "--log", str(root / "job.log"),
                       "--output", str(root / "recovered.json"), "--expected-sha256", digest, "--mode", "source"]
            subprocess.run(command, capture_output=True, check=True)
            self.assertEqual((root / "recovered.json").read_bytes(), raw)
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 2)
            self.assertEqual((root / "recovered.json").read_bytes(), raw)

    def test_workflow_executes_tests_and_both_binding_emitters(self):
        workflow = (ROOT / ".github/workflows/trnm-documentation-truth.yml").read_text()
        self.assertIn("run: python3 -B scripts/ci/test_m17_evidence_tools_v1.py", workflow)
        self.assertEqual(workflow.count("python3 -B scripts/ci/documentation_binding_log_v1.py emit"), 2)
        self.assertIn("--mode source", workflow)
        self.assertIn("--mode merge", workflow)
        for filename in ("documentation_binding_log_v1.py", "codeql_reconcile_regions_v1.py", "test_m17_evidence_tools_v1.py"):
            self.assertEqual(workflow.count("      - 'scripts/ci/" + filename + "'"), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
