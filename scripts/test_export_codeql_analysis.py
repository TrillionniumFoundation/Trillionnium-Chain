#!/usr/bin/env python3
"""Offline regressions for exact PR refs, incomplete CodeQL checks and evidence."""

import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse

sys.dont_write_bytecode = True
import export_codeql_analysis as export

REPO = "TrillionniumFoundation/Trillionnium-Chain"
HEAD, BASE, MERGE, STALE = (char * 40 for char in "abcd")
HEAD_REF, MERGE_REF = "refs/pull/323/head", "refs/pull/323/merge"
TOKEN = "offline-fixture-secret-must-never-appear-in-evidence-982517"
PR = {"state": "open", "head": {"sha": HEAD, "repo": {"full_name": REPO}},
      "base": {"sha": BASE}, "merge_commit_sha": MERGE}
MISSING = {
    "title": "1 configuration not found",
    "summary": "**Warning**: Code scanning cannot determine the alerts introduced by this pull request, "
               "because 1 configuration present on \x60refs/heads/main\x60 was not found:\n\n"
               "### Default setup\n\n* :question:&nbsp;&nbsp;\x60/language:rust\x60\n",
    "text": None,
}


def analysis(ident=1, ref=HEAD_REF, commit=HEAD, category="language:rust"):
    return {"id": ident, "ref": ref, "commit_sha": commit,
            "tool": {"name": "CodeQL", "version": "fixture"},
            "category": category, "environment": json.dumps({"language": category}),
            "error": "", "results_count": 1}


def check(status="completed", conclusion="failure", output=None, ident=501, commit=HEAD):
    return {"id": ident, "name": "CodeQL", "app": {"id": 57789, "slug": "github-advanced-security"},
            "head_sha": commit, "status": status, "conclusion": conclusion,
            "pull_requests": [{"number": 323, "head": {"sha": HEAD, "repo": {"url": API_BASE}},
                               "base": {"sha": BASE, "repo": {"url": API_BASE}}}],
            "output": output or {"title": "Security alerts", "summary": "Existing failing gate",
                                 "annotations_count": 0,
                                 "annotations_url": f"{API_BASE}/check-runs/{ident}/annotations"}}


API_BASE = "https://api.github.com/repos/" + REPO


def annotation(line):
    # Documented Checks API shape: no annotation ID or guaranteed alert number.
    return {"path": "src/fixture.rs", "start_line": line, "end_line": line,
            "annotation_level": "failure", "title": "Fixture rule",
            "message": "Fixture source to sink", "raw_details": "Fixture detail"}


class Clock:
    def __init__(self):
        self.now = 0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class Server:
    """Serve only the actual read endpoints; unexpected requests fail the test."""

    def __init__(self, rows=None, checks=None):
        self.rows = rows if rows is not None else [analysis()]
        self.checks = checks or [check()]
        self.merge_checks = []
        self.polls = 0
        self.requests = []
        self.pr = PR
        self.parents = [BASE, HEAD]
        self.forbidden = False
        self.rows_at_poll = lambda _: self.rows
        self.annotations = {501: []}
        self.annotation_forbidden_page = None
        self.check_reads = {}
        self.metadata_at_read = lambda ident, _: next(
            row for row in [self.checks[min(self.polls - 1, len(self.checks) - 1)],
                            *self.merge_checks] if row["id"] == ident)

    def open(self, request, timeout):
        assert request.method == "GET"
        url = urllib.parse.urlsplit(request.full_url)
        assert url.netloc == "api.github.com" and url.scheme == "https"
        self.requests.append(request.full_url)
        path, query = url.path, urllib.parse.parse_qs(url.query)
        if path.endswith("/pulls/323"):
            value = self.pr
        elif path.endswith("/git/commits/" + MERGE):
            value = {"sha": MERGE, "parents": [{"sha": item} for item in self.parents]}
        elif path.endswith("/check-runs"):
            value = {"check_runs": []}
            if HEAD in path:
                self.polls += 1
                value["check_runs"] = [self.checks[min(self.polls - 1, len(self.checks) - 1)]]
            else:
                value["check_runs"] = self.merge_checks
        elif "/check-runs/" in path:
            parts = path.rsplit("/check-runs/", 1)[1].split("/")
            ident = int(parts[0])
            if len(parts) == 2 and parts[1] == "annotations":
                assert query["per_page"] == ["100"]
                page = int(query["page"][0])
                if page == self.annotation_forbidden_page:
                    raise urllib.error.HTTPError(request.full_url, 403, TOKEN, {}, None)
                value = self.annotations.get(ident, [])[(page - 1) * 100:page * 100]
            else:
                assert len(parts) == 1
                self.check_reads[ident] = self.check_reads.get(ident, 0) + 1
                value = self.metadata_at_read(ident, self.check_reads[ident])
        elif path.endswith("/code-scanning/analyses"):
            if self.forbidden:
                raise urllib.error.HTTPError(request.full_url, 403, TOKEN, {}, None)
            assert query["pr"] == ["323"] and query["tool_name"] == ["CodeQL"]
            assert "ref" not in query, "A merge-only query loses actual default-setup head analyses"
            page = int(query["page"][0])
            value = self.rows_at_poll(self.polls)[(page - 1) * 100:page * 100]
        elif "/code-scanning/analyses/" in path:
            ident = int(path.rsplit("/", 1)[1])
            value = next(row for row in self.rows if row["id"] == ident)
            if request.get_header("Accept") == "application/sarif+json":
                value = {"version": "2.1.0", "runs": [{"results": [{"ruleId": "fixture-rule"}]}]}
        else:
            raise AssertionError("Unexpected endpoint: " + path)
        return Response(json.dumps(value).encode())


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="trnm-codeql-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        event = self.root / "event.json"
        event.write_text(json.dumps({"number": 323, "pull_request": PR}))
        self.env = {"GITHUB_REPOSITORY": REPO, "GITHUB_EVENT_NAME": "pull_request",
                    "GITHUB_EVENT_PATH": str(event), "GITHUB_SHA": MERGE,
                    "GITHUB_REF": MERGE_REF, "GITHUB_TOKEN": TOKEN}
        self.attempt = 0

    def run_export(self, server):
        self.attempt += 1
        out = self.root / f"export-{self.attempt}"
        args = ["export", "--out", str(out), "--wait-seconds", "5", "--poll-seconds", "1"]
        logs = io.StringIO()
        with patch.dict(os.environ, self.env), patch.object(sys, "argv", args), \
                patch.object(export, "time", Clock()), \
                patch.object(export.urllib.request, "build_opener", return_value=server), \
                contextlib.redirect_stdout(logs), contextlib.redirect_stderr(logs):
            code = export.main()
        self.assertNotIn(TOKEN, logs.getvalue())
        for path in out.rglob("*"):
            if path.is_file():
                self.assertNotIn(TOKEN.encode(), path.read_bytes())
        result = json.loads((out / "result.json").read_text())
        self.assertEqual(code == 0, result["complete"])
        self.assertTrue((out / "sha256.json").is_file())
        return code, result, out

    def test_default_setup_head_ref_exports_all_pages_and_categories(self):
        rows = [analysis(i, category=f"language:{i % 4}") for i in range(1, 104)]
        rows.append(analysis(104, commit=STALE))
        server = Server(rows)
        code, result, out = self.run_export(server)
        self.assertEqual(code, 0)
        self.assertEqual(len(result["analyses"]), 103)
        self.assertEqual(len(list((out / "analyses").glob("*.sarif"))), 103)
        self.assertTrue(any("page=2" in request for request in server.requests))
        self.assertEqual({(row["ref_kind"], row["source_kind"]) for row in result["analyses"]},
                         {("head", "head")})
        self.assertEqual(result["last_checks"][0]["conclusion"], "failure")

    def test_merge_ref_keeps_actual_commit_provenance(self):
        rows = [analysis(1), analysis(2, MERGE_REF, MERGE), analysis(3, MERGE_REF, HEAD)]
        code, result, _ = self.run_export(Server(rows))
        self.assertEqual(code, 0)
        self.assertEqual([(row["ref_kind"], row["source_kind"]) for row in result["analyses"]],
                         [("head", "head"), ("merge", "prospective-merge"), ("merge", "head")])

    def test_head_ref_cannot_claim_merge_commit(self):
        code, result, _ = self.run_export(Server([analysis(commit=MERGE)]))
        self.assertEqual(code, 1)
        self.assertIn("not bound to the frozen head", result["error"])

    def test_wrong_ref_and_stale_only_source_cannot_complete(self):
        for row in [analysis(ref="refs/heads/main"), analysis(commit=STALE)]:
            with self.subTest(row=row):
                code, result, _ = self.run_export(Server([row]))
                self.assertEqual(code, 1)
                self.assertEqual(result["analyses"], [])

    def test_real_neutral_missing_configuration_updates_in_place(self):
        server = Server(checks=[check(conclusion="neutral", output=MISSING), check()])
        code, result, out = self.run_export(server)
        self.assertEqual(code, 0)
        self.assertGreaterEqual(server.polls, 4)
        first = json.loads((out / "poll-001/selection.json").read_text())
        self.assertFalse(first["ready"])
        self.assertEqual(first["checks"][0]["output"], MISSING)
        self.assertEqual(result["last_checks"][0]["conclusion"], "failure")

    def test_pending_or_missing_configurations_wait_then_fail(self):
        for pending in [check("in_progress", None), check(conclusion="neutral", output=MISSING),
                        check(output=MISSING), check(conclusion="cancelled")]:
            with self.subTest(pending=pending):
                server = Server(checks=[pending])
                code, result, _ = self.run_export(server)
                self.assertEqual(code, 1)
                self.assertGreater(server.polls, 1)
                self.assertIn("deadline", result["error"])

    def test_permission_denial_and_processing_error_fail_with_evidence(self):
        denied = Server()
        denied.forbidden = True
        broken = Server([{**analysis(), "error": "Processing failed"}])
        for server, reason in [(denied, "HTTP 403"), (broken, "processing error")]:
            with self.subTest(reason=reason):
                code, result, out = self.run_export(server)
                self.assertEqual(code, 1)
                self.assertIn(reason, result["error"])
                self.assertTrue((out / "initial-pr.json").exists())

    def test_changed_snapshot_after_export_cannot_claim_completion(self):
        server = Server()
        server.rows_at_poll = lambda poll: server.rows if poll <= 2 else [
            analysis(category=f"changed-category-{poll}")]
        code, result, out = self.run_export(server)
        self.assertEqual(code, 1)
        self.assertIn("deadline", result["error"])
        self.assertTrue((out / "analyses/1.sarif").exists())
        self.assertTrue((out / "poll-002-after-export/selection.json").exists())

    def test_pr_source_drift_and_wrong_merge_parents_fail(self):
        moved = Server()
        moved.pr = {**PR, "head": {**PR["head"], "sha": STALE}}
        wrong_merge = Server()
        wrong_merge.parents.reverse()
        for server, reason in [(moved, "head/base moved"), (wrong_merge, "ordered base/head parents")]:
            with self.subTest(reason=reason):
                code, result, _ = self.run_export(server)
                self.assertEqual(code, 1)
                self.assertIn(reason, result["error"])

    def test_annotations_without_ids_keep_pages_duplicates_and_gate_subset_limit(self):
        for count in (100, 103):
            with self.subTest(count=count):
                current = check()
                current["output"].update({
                    "annotations_count": count,
                    "title": "142 new alerts including 121 critical severity security vulnerabilities",
                    "summary": "Security Alerts: 121 critical, 21 high",
                })
                server = Server(checks=[current])
                rows = [annotation(line) for line in range(1, count + 1)]
                rows[-1] = rows[0].copy()  # Repeated annotations must not be deduplicated.
                server.annotations[501] = rows
                code, result, out = self.run_export(server)
                self.assertEqual(code, 0)
                evidence = result["check_annotations"][0]
                self.assertEqual(evidence["reported_annotations_count"], count)
                self.assertEqual(evidence["exported_annotations_count"], count)
                self.assertEqual(evidence["gate_alert_count_from_title"], 142)
                self.assertTrue(evidence["all_reported_check_annotations_exported"])
                self.assertFalse(evidence["complete_pr_gate_alert_mapping"])
                prefix = evidence["raw_pages_prefix"]
                self.assertEqual(json.loads((out / (prefix + "1.json")).read_text()), rows[:100])
                self.assertEqual(json.loads((out / (prefix + "2.json")).read_text()), rows[100:])
                self.assertTrue((out / "analyses/1.sarif").is_file())

    def test_annotation_metadata_cannot_change_source_pr_or_endpoint(self):
        wrong_source = check(commit=STALE)
        wrong_pr = check()
        wrong_pr["pull_requests"][0]["base"]["sha"] = STALE
        wrong_endpoint = check()
        wrong_endpoint["output"]["annotations_url"] = "https://other.invalid/annotations"
        wrong_app = check()
        wrong_app["app"]["slug"] = "different-check-owner"
        wrong_app_id = check()
        wrong_app_id["app"]["id"] = 1
        for metadata in (wrong_source, wrong_pr, wrong_endpoint, wrong_app, wrong_app_id):
            with self.subTest(metadata=metadata):
                server = Server()
                server.metadata_at_read = lambda _, __: metadata
                code, result, out = self.run_export(server)
                self.assertEqual(code, 1)
                self.assertEqual(result["check_annotations"], [])
                self.assertFalse(any("/annotations?" in request for request in server.requests))
                self.assertTrue((out / "poll-002-annotations/501/before.json").is_file())

    def test_absent_pr_association_is_source_only_never_a_pr_gate_claim(self):
        current = check()
        current["pull_requests"] = []
        current["output"].update(annotations_count=1, title="35 new alerts")
        server = Server(checks=[current])
        server.annotations[501] = [annotation(7)]
        code, result, _ = self.run_export(server)
        self.assertEqual(code, 0)
        self.assertEqual(result["schema"], "codeql-exact-source-analysis-export-v2")
        self.assertFalse(result["target_pr_gate_authenticated"])
        self.assertIsNone(result["target_pr_gate_verdict"])
        evidence = result["check_annotations"][0]
        self.assertIsNone(evidence["pr"])
        self.assertEqual(evidence["requested_pr"], 323)
        self.assertEqual(evidence["pr_association"], "unavailable-source-only")
        self.assertIsNone(evidence["check_alert_count_from_title"])
        self.assertIsNone(evidence["gate_alert_count_from_title"])
        self.assertEqual(evidence["annotation_analysis_association"], "unproven")
        self.assertFalse(evidence["complete_pr_gate_alert_mapping"])
        self.assertEqual(evidence["exported_annotations_count"], 1)

    def test_absent_pr_binding_cannot_hide_metadata_change_or_malformed_associations(self):
        current = check()
        current["pull_requests"] = []
        missing = dict(current)
        del missing["pull_requests"]
        for altered in (check(), {**current, "pull_requests": None}, missing):
            with self.subTest(altered=altered):
                server = Server(checks=[current])
                server.metadata_at_read = lambda _, __: altered
                code, result, _ = self.run_export(server)
                self.assertEqual(code, 1)
                self.assertEqual(result["check_annotations"], [])
                self.assertFalse(any("/annotations?" in request for request in server.requests))

    def test_annotation_count_change_or_short_page_cannot_claim_completion(self):
        current = check()
        current["output"]["annotations_count"] = 1
        for changed_after in (False, True):
            with self.subTest(changed_after=changed_after):
                server = Server(checks=[current])
                if changed_after:
                    server.annotations[501] = [annotation(1)]
                    altered = {**current, "output": {**current["output"], "annotations_count": 2}}
                    server.metadata_at_read = lambda _, read: current if read == 1 else altered
                code, result, out = self.run_export(server)
                self.assertEqual(code, 1)
                self.assertFalse(result["complete"])
                self.assertTrue((out / "poll-002-annotations/501/page-1.json").is_file())
                self.assertTrue((out / "poll-002-annotations/501/after.json").is_file())
                self.assertTrue((out / "analyses/1.sarif").is_file())

    def test_annotation_later_page_permission_failure_preserves_partial_evidence(self):
        current = check()
        current["output"]["annotations_count"] = 101
        server = Server(checks=[current])
        server.annotations[501] = [annotation(line) for line in range(1, 102)]
        server.annotation_forbidden_page = 2
        code, result, out = self.run_export(server)
        self.assertEqual(code, 1)
        self.assertIn("HTTP 403", result["error"])
        self.assertEqual(len(json.loads((out / "poll-002-annotations/501/page-1.json").read_text())), 100)
        self.assertFalse((out / "poll-002-annotations/501/page-2.json").exists())
        self.assertTrue((out / "analyses/1.sarif").is_file())

    def test_annotation_checks_keep_head_and_verified_merge_provenance_separate(self):
        server = Server([analysis(1), analysis(2, MERGE_REF, MERGE)])
        server.merge_checks = [check(ident=502, commit=MERGE)]
        code, result, _ = self.run_export(server)
        self.assertEqual(code, 0)
        self.assertEqual([(row["id"], row["head_sha"], row["source_kind"])
                          for row in result["check_annotations"]],
                         [(501, HEAD, "head"), (502, MERGE, "prospective-merge")])
        self.assertTrue(all(row["gate_alert_count_from_title"] is None
                            for row in result["check_annotations"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
