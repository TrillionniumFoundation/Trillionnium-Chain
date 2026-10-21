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


def check(status="completed", conclusion="failure", output=None):
    return {"id": 501, "name": "CodeQL", "app": {"slug": "github-advanced-security"},
            "head_sha": HEAD, "status": status, "conclusion": conclusion,
            "output": output or {"title": "Security alerts", "summary": "Existing failing gate"}}


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
        self.polls = 0
        self.requests = []
        self.pr = PR
        self.parents = [BASE, HEAD]
        self.forbidden = False
        self.rows_at_poll = lambda _: self.rows

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
