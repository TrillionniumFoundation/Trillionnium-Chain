#!/usr/bin/env python3
"""Adversarial regression corpus for guarded CodeQL default setup."""

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
SPEC = importlib.util.spec_from_file_location(
    "trnm_codeql_default_setup_v1", SCRIPT
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load CodeQL setup module")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FakeApi:
    responses: dict[tuple[str, str], list[MODULE.ApiResponse]] = {}
    calls: list[tuple[str, str, object]] = []

    def __init__(
        self,
        token: str | None,
        *,
        api_version: str,
        api_root: str = "ignored",
    ) -> None:
        self.token = token
        self.api_version = api_version
        self.api_root = api_root

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        body=None,
        expected=(200,),
    ) -> MODULE.ApiResponse:
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
        self.config = MODULE.load_config(
            ROOT / "config/codeql-default-setup-v1.json"
        )
        self.repository = self.config["repository"]
        self.main_sha = "1" * 40
        self.evidence_sha = "2" * 40
        self.validation_run_id = 42
        self.analysis_suite_id = 800
        self.aggregate_suite_id = 700
        self.live_updated_at = "2026-09-09T00:00:00Z"

    @staticmethod
    def response(status: int, value) -> MODULE.ApiResponse:
        return MODULE.ApiResponse(status, value, {})

    def setup_path(self) -> str:
        return f"/repos/{self.repository}/code-scanning/default-setup"

    def branch_path(self) -> str:
        return f"/repos/{self.repository}/branches/main"

    def checks_path(self, page: int = 1) -> str:
        return (
            f"/repos/{self.repository}/commits/{self.evidence_sha}/check-runs"
            f"?filter=all&per_page=100&page={page}"
        )

    def suite_path(self, suite_id: int) -> str:
        return f"/repos/{self.repository}/check-suites/{suite_id}"

    def validation_path(self, run_id: int | None = None) -> str:
        return (
            f"/repos/{self.repository}/actions/runs/"
            f"{run_id or self.validation_run_id}"
        )

    def live_shape(self) -> dict[str, object]:
        value = MODULE.update_payload(self.config)
        return {
            **value,
            "updated_at": self.live_updated_at,
            "schedule": "weekly",
        }

    def app(self, kind: str) -> dict[str, object]:
        expected = self.config["trusted_check_producers"][kind]
        return {
            "id": expected["app_id"],
            "slug": expected["slug"],
            "owner": {"login": expected["owner"]},
        }

    def check(
        self,
        name: str,
        *,
        run_id: int | None = None,
        check_id: int | None = None,
        suite_id: int | None = None,
        app_kind: str | None = None,
        head_sha: object = ...,
        status: str = "completed",
        conclusion: str | None = "success",
        started_at: str | None = None,
        completed_at: str | None = None,
    ) -> dict[str, object]:
        aggregate = name == "CodeQL"
        run_id = self.validation_run_id if run_id is None else run_id
        check_id = (
            check_id
            if check_id is not None
            else (
                900
                if aggregate
                else 100 + sorted(MODULE.ANALYZE_CHECK_NAMES).index(name)
            )
        )
        suite_id = (
            suite_id
            if suite_id is not None
            else self.aggregate_suite_id
            if aggregate
            else self.analysis_suite_id
        )
        app_kind = app_kind or ("aggregate" if aggregate else "analysis")
        actual_head = self.evidence_sha if head_sha is ... else head_sha
        if started_at is None:
            started_at = (
                "2026-09-09T00:02:00Z"
                if aggregate
                else "2026-09-09T00:01:00Z"
            )
        if completed_at is None:
            completed_at = (
                "2026-09-09T00:03:00Z"
                if aggregate
                else "2026-09-09T00:02:00Z"
            )
        details = (
            f"https://github.com/{self.repository}/runs/{check_id}"
            if aggregate
            else (
                f"https://github.com/{self.repository}/actions/runs/"
                f"{run_id}/job/{check_id}"
            )
        )
        return {
            "id": check_id,
            "name": name,
            "head_sha": actual_head,
            "details_url": details,
            "status": status,
            "conclusion": conclusion,
            "started_at": started_at,
            "completed_at": completed_at,
            "check_suite": {"id": suite_id},
            "app": self.app(app_kind),
        }

    def successful_checks(self) -> list[dict[str, object]]:
        checks = [
            self.check(name) for name in sorted(MODULE.ANALYZE_CHECK_NAMES)
        ]
        checks.append(self.check("CodeQL"))
        return checks

    def suite(self, suite_id: int, kind: str) -> dict[str, object]:
        return {
            "id": suite_id,
            "head_sha": self.evidence_sha,
            "status": "completed",
            "conclusion": "success",
            "repository": {"full_name": self.repository},
            "app": self.app(kind),
        }

    def validation_run(
        self,
        *,
        run_id: int | None = None,
        suite_id: int | None = None,
        head_sha: str | None = None,
        path: str | None = None,
        created_at: str = "2026-09-09T00:00:30Z",
    ) -> dict[str, object]:
        run_id = run_id or self.validation_run_id
        suite_id = suite_id or self.analysis_suite_id
        return {
            "id": run_id,
            "head_sha": head_sha or self.evidence_sha,
            "check_suite_id": suite_id,
            "path": path or self.config["analysis_workflow_path"],
            "status": "completed",
            "conclusion": "success",
            "created_at": created_at,
            "run_started_at": created_at,
            "repository": {"full_name": self.repository},
            "head_repository": {"full_name": self.repository},
        }

    def configure_evidence(
        self,
        checks: list[dict[str, object]] | None = None,
    ) -> None:
        checks = checks or self.successful_checks()
        FakeApi.responses = {
            ("GET", self.checks_path()): [
                self.response(
                    200,
                    {"total_count": len(checks), "check_runs": checks},
                )
            ],
            ("GET", self.suite_path(self.analysis_suite_id)): [
                self.response(
                    200,
                    self.suite(self.analysis_suite_id, "analysis"),
                )
            ],
            ("GET", self.suite_path(self.aggregate_suite_id)): [
                self.response(
                    200,
                    self.suite(self.aggregate_suite_id, "aggregate"),
                )
            ],
            ("GET", self.validation_path()): [
                self.response(200, self.validation_run())
            ],
        }

    def verify_evidence(self):
        return MODULE.verify_exact_source_checks(
            FakeApi("token", api_version=self.config["api_version"]),
            self.repository,
            self.evidence_sha,
            self.config["required_check_names"],
            live_updated_at=self.live_updated_at,
            validation_run_id=self.validation_run_id,
            trusted_producers=self.config["trusted_check_producers"],
            analysis_workflow_path=self.config["analysis_workflow_path"],
        )

    def test_config_is_closed_world_and_binds_trusted_producers(self) -> None:
        self.assertEqual(
            set(self.config["required_languages"]),
            MODULE.REQUIRED_LANGUAGES,
        )
        self.assertIn("rust", self.config["required_languages"])
        self.assertEqual(self.config["query_suite"], "extended")
        self.assertEqual(self.config["threat_model"], "remote_and_local")
        self.assertEqual(
            self.config["trusted_check_producers"]["aggregate"]["slug"],
            "github-advanced-security",
        )
        self.assertEqual(
            self.config["trusted_check_producers"]["analysis"]["slug"],
            "github-actions",
        )
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

    def test_live_verification_rejects_missing_rust_or_weaker_policy(self) -> None:
        for label, mutate in (
            (
                "missing-rust",
                lambda value: value["languages"].remove("rust"),
            ),
            (
                "default-suite",
                lambda value: value.__setitem__("query_suite", "default"),
            ),
            (
                "remote-only",
                lambda value: value.__setitem__("threat_model", "remote"),
            ),
        ):
            with self.subTest(label=label):
                live = self.live_shape()
                mutate(live)
                FakeApi.responses = {
                    ("GET", self.setup_path()): [self.response(200, live)]
                }
                with self.assertRaises(MODULE.CodeqlSetupError):
                    MODULE.verify_live_setup(
                        FakeApi(
                            "token",
                            api_version=self.config["api_version"],
                        ),
                        self.repository,
                        self.config,
                    )

    def test_live_verification_rejects_missing_or_mistyped_members(self) -> None:
        for label, mutate in (
            ("missing-runner", lambda value: value.pop("runner_type")),
            ("missing-updated", lambda value: value.pop("updated_at")),
            (
                "wrong-languages-type",
                lambda value: value.__setitem__("languages", "rust"),
            ),
        ):
            with self.subTest(label=label):
                live = self.live_shape()
                mutate(live)
                FakeApi.responses = {
                    ("GET", self.setup_path()): [self.response(200, live)]
                }
                with self.assertRaises(MODULE.CodeqlSetupError):
                    MODULE.verify_live_setup(
                        FakeApi(
                            "token",
                            api_version=self.config["api_version"],
                        ),
                        self.repository,
                        self.config,
                    )

    def test_exact_source_accepts_one_trusted_validation_generation(self) -> None:
        self.configure_evidence()
        report = self.verify_evidence()
        self.assertEqual(report["evidence_sha"], self.evidence_sha)
        self.assertEqual(
            report["validation_run"]["id"],
            self.validation_run_id,
        )
        self.assertEqual(set(report["required"]), MODULE.REQUIRED_CHECK_NAMES)
        self.assertEqual(
            report["required"]["CodeQL"]["app"]["slug"],
            "github-advanced-security",
        )

    def test_exact_source_rejects_neutral_or_missing_rust(self) -> None:
        for label in ("neutral-aggregate", "missing-rust"):
            with self.subTest(label=label):
                checks = self.successful_checks()
                if label == "neutral-aggregate":
                    next(
                        item for item in checks if item["name"] == "CodeQL"
                    )["conclusion"] = "neutral"
                else:
                    checks = [
                        item
                        for item in checks
                        if item["name"] != "Analyze (rust)"
                    ]
                self.configure_evidence(checks)
                with self.assertRaises(MODULE.CodeqlSetupError):
                    self.verify_evidence()

    def test_exact_source_rejects_spoofed_producer(self) -> None:
        checks = self.successful_checks()
        target = next(
            item for item in checks if item["name"] == "Analyze (rust)"
        )
        target["app"] = {
            "id": 999,
            "slug": "evil-checks",
            "owner": {"login": "attacker"},
        }
        self.configure_evidence(checks)
        with self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "producer identity mismatch",
        ):
            self.verify_evidence()

    def test_exact_source_rejects_null_or_mismatched_head_sha(self) -> None:
        for bad in (None, "3" * 40):
            with self.subTest(head_sha=bad):
                checks = self.successful_checks()
                next(
                    item
                    for item in checks
                    if item["name"] == "Analyze (rust)"
                )["head_sha"] = bad
                self.configure_evidence(checks)
                with self.assertRaisesRegex(
                    MODULE.CodeqlSetupError,
                    "head SHA",
                ):
                    self.verify_evidence()

    def test_exact_source_rejects_cross_suite_or_cross_run_splicing(self) -> None:
        checks = self.successful_checks()
        next(
            item for item in checks if item["name"] == "Analyze (rust)"
        )["check_suite"] = {"id": 801}
        self.configure_evidence(checks)
        with self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "multiple check suites",
        ):
            self.verify_evidence()

        checks = self.successful_checks()
        target = next(
            item for item in checks if item["name"] == "Analyze (rust)"
        )
        target["details_url"] = (
            f"https://github.com/{self.repository}/actions/runs/43/job/"
            f"{target['id']}"
        )
        self.configure_evidence(checks)
        with self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "not bound to validation run",
        ):
            self.verify_evidence()

    def test_exact_source_rejects_stale_preconfiguration_success(self) -> None:
        checks = self.successful_checks()
        target = next(
            item for item in checks if item["name"] == "Analyze (rust)"
        )
        target["started_at"] = "2026-09-08T23:59:59Z"
        self.configure_evidence(checks)
        with self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "predates live configuration",
        ):
            self.verify_evidence()

    def test_exact_source_rejects_wrong_workflow_or_repository_identity(self) -> None:
        self.configure_evidence()
        FakeApi.responses[("GET", self.validation_path())] = [
            self.response(
                200,
                self.validation_run(path=".github/workflows/spoof.yml"),
            )
        ]
        with self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "workflow path",
        ):
            self.verify_evidence()

        self.configure_evidence()
        bad = self.validation_run()
        bad["repository"] = {"full_name": "attacker/repo"}
        FakeApi.responses[("GET", self.validation_path())] = [
            self.response(200, bad)
        ]
        with self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "repository identity mismatch",
        ):
            self.verify_evidence()

    def test_paginated_newer_failure_supersedes_older_success(self) -> None:
        base = self.successful_checks()
        old_aggregate = next(
            item for item in base if item["name"] == "CodeQL"
        )
        old_aggregate["id"] = 900
        filler = [
            {
                "id": 10_000 + index,
                "name": f"irrelevant-{index}",
                "head_sha": self.evidence_sha,
            }
            for index in range(95)
        ]
        page_one = base + filler
        self.assertEqual(len(page_one), 100)
        newer_failure = self.check(
            "CodeQL",
            check_id=901,
            started_at="2026-09-09T00:04:00Z",
            completed_at="2026-09-09T00:05:00Z",
            conclusion="failure",
        )
        FakeApi.responses = {
            ("GET", self.checks_path(1)): [
                self.response(
                    200,
                    {"total_count": 101, "check_runs": page_one},
                )
            ],
            ("GET", self.checks_path(2)): [
                self.response(
                    200,
                    {"total_count": 101, "check_runs": [newer_failure]},
                )
            ],
            ("GET", self.suite_path(self.analysis_suite_id)): [
                self.response(
                    200,
                    self.suite(self.analysis_suite_id, "analysis"),
                )
            ],
            ("GET", self.suite_path(self.aggregate_suite_id)): [
                self.response(
                    200,
                    self.suite(self.aggregate_suite_id, "aggregate"),
                )
            ],
            ("GET", self.validation_path()): [
                self.response(200, self.validation_run())
            ],
        }
        with self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "not successful: CodeQL=failure",
        ):
            self.verify_evidence()

    def test_pagination_duplicate_run_id_is_rejected(self) -> None:
        page_one = self.successful_checks() + [
            {
                "id": 10_000 + index,
                "name": f"irrelevant-{index}",
                "head_sha": self.evidence_sha,
            }
            for index in range(95)
        ]
        duplicate = dict(page_one[0])
        FakeApi.responses = {
            ("GET", self.checks_path(1)): [
                self.response(
                    200,
                    {"total_count": 101, "check_runs": page_one},
                )
            ],
            ("GET", self.checks_path(2)): [
                self.response(
                    200,
                    {"total_count": 101, "check_runs": [duplicate]},
                )
            ],
        }
        with self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "duplicate check-run id",
        ):
            self.verify_evidence()

    def test_cli_forbids_unbound_or_same_invocation_evidence(self) -> None:
        with self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "requires --verify-live",
        ):
            MODULE.main(
                [
                    "--verify-evidence",
                    "--evidence-sha",
                    self.evidence_sha,
                    "--validation-run-id",
                    "42",
                ]
            )
        with self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "cannot be combined",
        ):
            MODULE.main(
                [
                    "--apply",
                    "--verify-evidence",
                    "--verify-live",
                    "--evidence-sha",
                    self.evidence_sha,
                    "--validation-run-id",
                    "42",
                ]
            )

    def evidence_argv(self) -> list[str]:
        return [
            "--verify-live",
            "--verify-evidence",
            "--acknowledge-settings-verification-freeze",
            "--evidence-sha",
            self.evidence_sha,
            "--validation-run-id",
            str(self.validation_run_id),
        ]

    def evidence_env(self) -> dict[str, str]:
        return {
            "GH_TOKEN": "token",
            "TRNM_CODEQL_SETTINGS_VERIFICATION_TICKET": "issue-88/read-window",
        }

    def test_cli_evidence_requires_settings_freeze_and_ticket(self) -> None:
        argv = [
            "--verify-live",
            "--verify-evidence",
            "--evidence-sha",
            self.evidence_sha,
            "--validation-run-id",
            str(self.validation_run_id),
        ]
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ, {"GH_TOKEN": "token"}, clear=True
        ), self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "acknowledge-settings-verification-freeze",
        ):
            MODULE.main(argv)
        argv.insert(2, "--acknowledge-settings-verification-freeze")
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ, {"GH_TOKEN": "token"}, clear=True
        ), self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "TRNM_CODEQL_SETTINGS_VERIFICATION_TICKET",
        ):
            MODULE.main(argv)

    def test_cli_evidence_accepts_stable_verification_window(self) -> None:
        live = {
            "normalized": {"stable": True},
            "updated_at": self.live_updated_at,
        }
        evidence = {
            "evidence_sha": self.evidence_sha,
            "required": {"stable": True},
        }
        inventory = {
            "evidence_sha": self.evidence_sha,
            "required_runs": [{"id": 1}],
        }
        stdout = io.StringIO()
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.object(
            MODULE, "verify_live_setup", side_effect=[live, live]
        ), mock.patch.object(
            MODULE,
            "required_check_inventory_snapshot",
            side_effect=[inventory, inventory],
        ), mock.patch.object(
            MODULE,
            "verify_exact_source_checks",
            side_effect=[evidence, evidence],
        ), mock.patch.dict(
            os.environ, self.evidence_env(), clear=True
        ), contextlib.redirect_stdout(stdout):
            self.assertEqual(MODULE.main(self.evidence_argv()), 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["result"], "VERIFIED")
        self.assertEqual(report["live_before"], report["live_after"])
        self.assertEqual(
            report["evidence_inventory_before"],
            report["evidence_inventory_after"],
        )
        self.assertEqual(report["evidence"], evidence)
        self.assertTrue(
            report["settings_verification_freeze_acknowledged"]
        )

    def test_cli_evidence_rejects_live_generation_drift(self) -> None:
        initial = {
            "normalized": {"stable": True},
            "updated_at": self.live_updated_at,
        }
        changed = {
            "normalized": {"stable": True},
            "updated_at": "2026-09-09T00:10:00Z",
        }
        evidence = {
            "evidence_sha": self.evidence_sha,
            "required": {"stable": True},
        }
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.object(
            MODULE, "verify_live_setup", side_effect=[initial, changed]
        ), mock.patch.object(
            MODULE,
            "required_check_inventory_snapshot",
            return_value={"required_runs": [{"id": 1}]},
        ), mock.patch.object(
            MODULE, "verify_exact_source_checks", return_value=evidence
        ), mock.patch.dict(
            os.environ, self.evidence_env(), clear=True
        ), self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "changed during evidence verification",
        ):
            MODULE.main(self.evidence_argv())

    def test_cli_evidence_rejects_check_inventory_drift(self) -> None:
        live = {
            "normalized": {"stable": True},
            "updated_at": self.live_updated_at,
        }
        evidence = {
            "evidence_sha": self.evidence_sha,
            "required": {"stable": True},
        }
        before = {"required_runs": [{"id": 1}]}
        after = {"required_runs": [{"id": 1}, {"id": 2}]}
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.object(
            MODULE, "verify_live_setup", side_effect=[live, live]
        ), mock.patch.object(
            MODULE,
            "required_check_inventory_snapshot",
            side_effect=[before, after],
        ), mock.patch.object(
            MODULE,
            "verify_exact_source_checks",
            side_effect=[evidence, evidence],
        ), mock.patch.dict(
            os.environ, self.evidence_env(), clear=True
        ), self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "check inventory changed",
        ):
            MODULE.main(self.evidence_argv())

    def test_cli_evidence_rejects_semantic_evidence_drift(self) -> None:
        live = {
            "normalized": {"stable": True},
            "updated_at": self.live_updated_at,
        }
        first = {
            "evidence_sha": self.evidence_sha,
            "required": {"stable": True},
        }
        changed = {
            "evidence_sha": self.evidence_sha,
            "required": {"stable": False},
        }
        inventory = {"required_runs": [{"id": 1}]}
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.object(
            MODULE, "verify_live_setup", side_effect=[live, live]
        ), mock.patch.object(
            MODULE,
            "required_check_inventory_snapshot",
            side_effect=[inventory, inventory],
        ), mock.patch.object(
            MODULE,
            "verify_exact_source_checks",
            side_effect=[first, changed],
        ), mock.patch.dict(
            os.environ, self.evidence_env(), clear=True
        ), self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "evidence changed during verification",
        ):
            MODULE.main(self.evidence_argv())

    def test_apply_requires_mutation_freeze_and_ticket(self) -> None:
        argv = [
            "--apply",
            "--expected-current-main-sha",
            self.main_sha,
        ]
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ, {"GH_TOKEN": "token"}, clear=True
        ), self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "acknowledge-admin-mutation",
        ):
            MODULE.main(argv)
        argv.append("--acknowledge-admin-mutation")
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ, {"GH_TOKEN": "token"}, clear=True
        ), self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "acknowledge-change-freeze",
        ):
            MODULE.main(argv)
        argv.append("--acknowledge-change-freeze")
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ, {"GH_TOKEN": "token"}, clear=True
        ), self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "TRNM_CODEQL_ADMIN_CHANGE_TICKET",
        ):
            MODULE.main(argv)

    def apply_argv(self) -> list[str]:
        return [
            "--apply",
            "--acknowledge-admin-mutation",
            "--acknowledge-change-freeze",
            "--expected-current-main-sha",
            self.main_sha,
            "--timeout-seconds",
            "0",
            "--poll-seconds",
            "0",
        ]

    def env(self) -> dict[str, str]:
        return {
            "GH_TOKEN": "token",
            "TRNM_CODEQL_ADMIN_CHANGE_TICKET": "issue-88",
        }

    def test_apply_rejects_movement_before_patch(self) -> None:
        before = self.live_shape()
        before["languages"] = [
            "actions",
            "javascript-typescript",
            "python",
        ]
        FakeApi.responses = {
            ("GET", self.branch_path()): [
                self.response(200, {"commit": {"sha": self.main_sha}}),
                self.response(200, {"commit": {"sha": "3" * 40}}),
            ],
            ("GET", self.setup_path()): [self.response(200, before)],
        }
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ, self.env(), clear=True
        ), self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "immediately-before-patch",
        ):
            MODULE.main(self.apply_argv())
        self.assertFalse(
            any(method == "PATCH" for method, _path, _body in FakeApi.calls)
        )

    def test_apply_detects_movement_after_patch(self) -> None:
        before = self.live_shape()
        before["languages"] = [
            "actions",
            "javascript-typescript",
            "python",
        ]
        FakeApi.responses = {
            ("GET", self.branch_path()): [
                self.response(200, {"commit": {"sha": self.main_sha}}),
                self.response(200, {"commit": {"sha": self.main_sha}}),
                self.response(200, {"commit": {"sha": "3" * 40}}),
            ],
            ("GET", self.setup_path()): [self.response(200, before)],
            ("PATCH", self.setup_path()): [
                self.response(
                    202,
                    {
                        "run_id": 42,
                        "run_url": (
                            f"https://api.github.com/repos/{self.repository}/"
                            "actions/runs/42"
                        ),
                    },
                )
            ],
        }
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ, self.env(), clear=True
        ), self.assertRaisesRegex(
            MODULE.CodeqlSetupError,
            "immediately-after-patch",
        ):
            MODULE.main(self.apply_argv())
        self.assertTrue(
            any(method == "PATCH" for method, _path, _body in FakeApi.calls)
        )

    def test_apply_patches_exact_contract_and_observes_four_sha_barriers(self) -> None:
        before = self.live_shape()
        before["languages"] = [
            "actions",
            "javascript-typescript",
            "python",
        ]
        after = self.live_shape()
        FakeApi.responses = {
            ("GET", self.branch_path()): [
                self.response(200, {"commit": {"sha": self.main_sha}})
                for _ in range(4)
            ],
            ("GET", self.setup_path()): [
                self.response(200, before),
                self.response(200, after),
            ],
            ("PATCH", self.setup_path()): [
                self.response(
                    202,
                    {
                        "run_id": 42,
                        "run_url": (
                            f"https://api.github.com/repos/{self.repository}/"
                            "actions/runs/42"
                        ),
                    },
                )
            ],
        }
        stdout = io.StringIO()
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ, self.env(), clear=True
        ), contextlib.redirect_stdout(stdout):
            self.assertEqual(MODULE.main(self.apply_argv()), 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(
            report["result"],
            "APPLIED_AND_LIVE_SHAPE_VERIFIED_VALIDATION_PENDING",
        )
        self.assertEqual(report["validation_run"]["id"], 42)
        self.assertEqual(len(report["branch_observations"]), 4)
        patches = [call for call in FakeApi.calls if call[0] == "PATCH"]
        self.assertEqual(
            patches,
            [
                (
                    "PATCH",
                    self.setup_path(),
                    MODULE.update_payload(self.config),
                )
            ],
        )

    def test_unknown_or_duplicate_configuration_member_is_rejected(self) -> None:
        original = json.loads(
            (
                ROOT / "config/codeql-default-setup-v1.json"
            ).read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "bad.json"
            value = dict(original)
            value["allow_missing_rust"] = True
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(
                MODULE.CodeqlSetupError,
                "configuration keys drift",
            ):
                MODULE.load_config(path)
            path.write_text(
                '{"schema":"a","schema":"b"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                MODULE.CodeqlSetupError,
                "duplicate JSON member",
            ):
                MODULE.load_config(path)


if __name__ == "__main__":
    unittest.main()
