#!/usr/bin/env python3
"""Regression corpus for the guarded CodeQL default-setup command."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/admin/apply_codeql_default_setup_v1.py"
SPEC = importlib.util.spec_from_file_location("trnm_codeql_default_setup_v1", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load CodeQL setup module")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FakeApi:
    responses: dict[tuple[str, str], list[MODULE.ApiResponse]] = {}
    calls: list[tuple[str, str, object]] = []

    def __init__(self, token: str | None, *, api_version: str, api_root: str = "ignored") -> None:
        self.token = token
        self.api_version = api_version
        self.api_root = api_root

    def request(self, path: str, *, method: str = "GET", body=None, expected=(200,)) -> MODULE.ApiResponse:
        self.calls.append((method, path, body))
        key = (method, path)
        queue = self.responses.get(key)
        if not queue:
            raise MODULE.CodeqlSetupError(f"unexpected fake request: {key}")
        response = queue.pop(0) if len(queue) > 1 else queue[0]
        if response.status not in set(expected):
            raise MODULE.CodeqlSetupError(
                f"fake request {key} returned {response.status}: {response.value}"
            )
        return response


class CodeqlDefaultSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeApi.responses = {}
        FakeApi.calls = []
        self.config = MODULE.load_config(ROOT / "config/codeql-default-setup-v1.json")
        self.repository = self.config["repository"]
        self.main_sha = "1" * 40
        self.evidence_sha = "2" * 40

    @staticmethod
    def response(status: int, value) -> MODULE.ApiResponse:
        return MODULE.ApiResponse(status, value, {})

    def setup_path(self) -> str:
        return f"/repos/{self.repository}/code-scanning/default-setup"

    def branch_path(self) -> str:
        return f"/repos/{self.repository}/branches/main"

    def checks_path(self) -> str:
        return (
            f"/repos/{self.repository}/commits/{self.evidence_sha}/check-runs"
            "?filter=all&per_page=100&page=1"
        )

    def live_shape(self) -> dict[str, object]:
        value = MODULE.update_payload(self.config)
        return {**value, "updated_at": "2026-09-09T00:00:00Z", "schedule": "weekly"}

    def successful_checks(self) -> list[dict[str, object]]:
        return [
            {
                "id": index + 1,
                "name": name,
                "head_sha": self.evidence_sha,
                "status": "completed",
                "conclusion": "success",
                "completed_at": "2026-09-09T00:00:00Z",
            }
            for index, name in enumerate(self.config["required_check_names"])
        ]

    def test_config_is_closed_world_and_requires_rust_extended_local_sources(self) -> None:
        self.assertEqual(set(self.config["required_languages"]), MODULE.REQUIRED_LANGUAGES)
        self.assertIn("rust", self.config["required_languages"])
        self.assertEqual(self.config["query_suite"], "extended")
        self.assertEqual(self.config["threat_model"], "remote_and_local")
        for field in (
            "production_candidate",
            "production_consensus_activation",
            "public_testnet_ready",
            "release_ready",
        ):
            self.assertIs(self.config[field], False)

    def test_dry_run_performs_no_network_calls(self) -> None:
        stdout = io.StringIO()
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ, {}, clear=True
        ), contextlib.redirect_stdout(stdout):
            self.assertEqual(MODULE.main([]), 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["result"], "DRY_RUN_VALID")
        self.assertEqual(FakeApi.calls, [])
        self.assertIn("rust", report["payload"]["languages"])

    def test_live_verification_rejects_missing_rust_and_weaker_suite(self) -> None:
        for label, mutate in (
            ("missing-rust", lambda value: value["languages"].remove("rust")),
            ("default-suite", lambda value: value.__setitem__("query_suite", "default")),
            ("remote-only", lambda value: value.__setitem__("threat_model", "remote")),
        ):
            with self.subTest(label=label):
                live = self.live_shape()
                mutate(live)
                FakeApi.responses = {
                    ("GET", self.setup_path()): [self.response(200, live)]
                }
                with self.assertRaises(MODULE.CodeqlSetupError):
                    MODULE.verify_live_setup(
                        FakeApi("token", api_version=self.config["api_version"]),
                        self.repository,
                        self.config,
                    )

    def test_exact_source_verification_rejects_neutral_or_missing_rust(self) -> None:
        cases = ("neutral-aggregate", "missing-rust")
        for label in cases:
            with self.subTest(label=label):
                checks = self.successful_checks()
                if label == "neutral-aggregate":
                    checks[0]["conclusion"] = "neutral"
                else:
                    checks = [item for item in checks if item["name"] != "Analyze (rust)"]
                FakeApi.responses = {
                    ("GET", self.checks_path()): [
                        self.response(200, {"check_runs": checks})
                    ]
                }
                with self.assertRaises(MODULE.CodeqlSetupError):
                    MODULE.verify_exact_source_checks(
                        FakeApi("token", api_version=self.config["api_version"]),
                        self.repository,
                        self.evidence_sha,
                        self.config["required_check_names"],
                    )

    def test_exact_source_verification_accepts_only_all_success(self) -> None:
        FakeApi.responses = {
            ("GET", self.checks_path()): [
                self.response(200, {"check_runs": self.successful_checks()})
            ]
        }
        report = MODULE.verify_exact_source_checks(
            FakeApi("token", api_version=self.config["api_version"]),
            self.repository,
            self.evidence_sha,
            self.config["required_check_names"],
        )
        self.assertEqual(report["evidence_sha"], self.evidence_sha)
        self.assertEqual(set(report["required"]), MODULE.REQUIRED_CHECK_NAMES)

    def test_apply_requires_acknowledgement_and_ticket(self) -> None:
        argv = ["--apply", "--expected-current-main-sha", self.main_sha]
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ, {"GH_TOKEN": "token"}, clear=True
        ), self.assertRaisesRegex(MODULE.CodeqlSetupError, "acknowledge-admin-mutation"):
            MODULE.main(argv)
        argv.append("--acknowledge-admin-mutation")
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ, {"GH_TOKEN": "token"}, clear=True
        ), self.assertRaisesRegex(MODULE.CodeqlSetupError, "TRNM_CODEQL_ADMIN_CHANGE_TICKET"):
            MODULE.main(argv)

    def test_apply_rejects_moved_main_before_settings_read_or_patch(self) -> None:
        FakeApi.responses = {
            ("GET", self.branch_path()): [
                self.response(200, {"commit": {"sha": "3" * 40}})
            ]
        }
        argv = [
            "--apply",
            "--acknowledge-admin-mutation",
            "--expected-current-main-sha",
            self.main_sha,
        ]
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ,
            {"GH_TOKEN": "token", "TRNM_CODEQL_ADMIN_CHANGE_TICKET": "issue-88"},
            clear=True,
        ), self.assertRaisesRegex(MODULE.CodeqlSetupError, "main branch moved"):
            MODULE.main(argv)
        self.assertFalse(any(method == "PATCH" for method, _path, _body in FakeApi.calls))

    def test_apply_patches_exact_contract_and_verifies_readback(self) -> None:
        before = self.live_shape()
        before["languages"] = ["actions", "javascript-typescript", "python"]
        after = self.live_shape()
        FakeApi.responses = {
            ("GET", self.branch_path()): [
                self.response(200, {"commit": {"sha": self.main_sha}})
            ],
            ("GET", self.setup_path()): [
                self.response(200, before),
                self.response(200, after),
            ],
            ("PATCH", self.setup_path()): [
                self.response(202, {"run_id": 42, "run_url": "https://example.invalid/42"})
            ],
        }
        argv = [
            "--apply",
            "--acknowledge-admin-mutation",
            "--expected-current-main-sha",
            self.main_sha,
            "--timeout-seconds",
            "0",
            "--poll-seconds",
            "0",
        ]
        stdout = io.StringIO()
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ,
            {"GH_TOKEN": "token", "TRNM_CODEQL_ADMIN_CHANGE_TICKET": "issue-88"},
            clear=True,
        ), contextlib.redirect_stdout(stdout):
            self.assertEqual(MODULE.main(argv), 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["result"], "APPLIED_AND_LIVE_SHAPE_VERIFIED")
        self.assertEqual(report["validation_run"]["id"], 42)
        patches = [call for call in FakeApi.calls if call[0] == "PATCH"]
        self.assertEqual(
            patches,
            [("PATCH", self.setup_path(), MODULE.update_payload(self.config))],
        )

    def test_unknown_or_duplicate_configuration_member_is_rejected(self) -> None:
        original = json.loads(
            (ROOT / "config/codeql-default-setup-v1.json").read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "bad.json"
            value = dict(original)
            value["allow_missing_rust"] = True
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(MODULE.CodeqlSetupError, "configuration keys drift"):
                MODULE.load_config(path)
            path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(MODULE.CodeqlSetupError, "duplicate JSON member"):
                MODULE.load_config(path)


if __name__ == "__main__":
    unittest.main()
