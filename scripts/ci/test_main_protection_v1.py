#!/usr/bin/env python3
"""Regression corpus for the guarded main-protection command."""

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
SCRIPT = ROOT / "scripts/admin/apply_main_protection_v1.py"
SPEC = importlib.util.spec_from_file_location("trnm_main_protection_v1", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load main protection module")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FakeApi:
    responses: dict[tuple[str, str], MODULE.ApiResponse] = {}
    calls: list[tuple[str, str, object]] = []

    def __init__(self, token: str | None, api_root: str = "ignored") -> None:
        self.token = token
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
        if key not in self.responses:
            raise MODULE.ProtectionError(f"unexpected fake request: {key}")
        response = self.responses[key]
        if response.status not in set(expected):
            raise MODULE.ProtectionError(
                f"fake request {key} returned {response.status}: {response.value}"
            )
        return response


class MainProtectionTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeApi.responses = {}
        FakeApi.calls = []
        self.config = MODULE.load_config(
            ROOT / "config/main-branch-protection-v1.json"
        )
        self.repository = self.config["repository"]
        self.branch = self.config["branch"]
        self.evidence_sha = "1" * 40
        self.main_sha = self.evidence_sha
        self.stale_sha = "2" * 40

    @staticmethod
    def response(status: int, value) -> MODULE.ApiResponse:
        return MODULE.ApiResponse(status, value, {})

    def successful_runs(self) -> list[dict[str, object]]:
        return [
            {
                "id": index + 1,
                "name": name,
                "status": "completed",
                "conclusion": "success",
                "completed_at": "2026-09-08T00:00:00Z",
            }
            for index, name in enumerate(self.config["required_status_contexts"])
        ]

    def check_path(self) -> str:
        return (
            f"/repos/{self.repository}/commits/{self.evidence_sha}/check-runs"
            "?filter=all&per_page=100&page=1"
        )

    def branch_path(self) -> str:
        return f"/repos/{self.repository}/branches/main"

    def protection_path(self) -> str:
        return f"/repos/{self.repository}/branches/main/protection"

    def live_shape(self) -> dict[str, object]:
        payload = MODULE.protection_payload(self.config)
        return {
            "required_status_checks": {
                "strict": payload["required_status_checks"]["strict"],
                "contexts": payload["required_status_checks"]["contexts"],
            },
            "enforce_admins": {"enabled": payload["enforce_admins"]},
            "required_pull_request_reviews": payload[
                "required_pull_request_reviews"
            ],
            "restrictions": None,
            "required_linear_history": {
                "enabled": payload["required_linear_history"]
            },
            "allow_force_pushes": {"enabled": payload["allow_force_pushes"]},
            "allow_deletions": {"enabled": payload["allow_deletions"]},
            "block_creations": {"enabled": payload["block_creations"]},
            "required_conversation_resolution": {
                "enabled": payload["required_conversation_resolution"]
            },
            "lock_branch": {"enabled": payload["lock_branch"]},
            "allow_fork_syncing": {"enabled": payload["allow_fork_syncing"]},
        }

    def test_config_is_closed_world_and_fail_closed(self) -> None:
        self.assertEqual(
            self.config["schema"], "trnm-main-branch-protection-v1"
        )
        policy = json.loads(
            (ROOT / "config/repository-policy-v1.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            self.config["required_status_contexts"],
            [*policy["required_check_names"], "CodeQL"],
        )
        review = policy["required_review_policy"]
        self.assertEqual(
            self.config["required_approving_review_count"], review["approvals"]
        )
        self.assertIs(
            self.config["require_code_owner_reviews"], review["code_owner_review"]
        )
        self.assertIs(
            self.config["require_last_push_approval"], review["last_push_approval"]
        )
        self.assertIs(
            self.config["dismiss_stale_reviews"], review["dismiss_stale_reviews"]
        )
        self.assertIn("CodeQL", self.config["required_status_contexts"])
        self.assertGreaterEqual(
            self.config["required_approving_review_count"], 2
        )
        for field in (
            "production_candidate",
            "production_consensus_activation",
            "public_testnet_ready",
            "release_ready",
            "allow_force_pushes",
            "allow_deletions",
        ):
            self.assertIs(self.config[field], False)

    def test_dry_run_never_constructs_an_authenticated_api_mutation(self) -> None:
        stdout = io.StringIO()
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ, {}, clear=True
        ), contextlib.redirect_stdout(stdout):
            result = MODULE.main([])
        self.assertEqual(result, 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["result"], "DRY_RUN_VALID")
        self.assertFalse(report["changed"])
        self.assertEqual(FakeApi.calls, [])

    def test_required_check_rejects_missing_neutral_skipped_or_pending(self) -> None:
        mutations = (
            ("missing", None, None),
            ("neutral", "completed", "neutral"),
            ("skipped", "completed", "skipped"),
            ("pending", "in_progress", None),
        )
        for label, status, conclusion in mutations:
            with self.subTest(label=label):
                runs = self.successful_runs()
                target = self.config["required_status_contexts"][0]
                if label == "missing":
                    runs = [run for run in runs if run["name"] != target]
                else:
                    runs[0]["status"] = status
                    runs[0]["conclusion"] = conclusion
                FakeApi.responses = {
                    ("GET", self.check_path()): self.response(
                        200, {"check_runs": runs}
                    )
                }
                FakeApi.calls = []
                with self.assertRaises(MODULE.ProtectionError):
                    MODULE.verify_required_checks(
                        FakeApi("token"),
                        self.repository,
                        self.evidence_sha,
                        self.config["required_status_contexts"],
                    )

    def test_apply_requires_two_explicit_mutation_acknowledgements(self) -> None:
        argv = [
            "--apply",
            "--evidence-sha",
            self.evidence_sha,
            "--expected-current-main-sha",
            self.main_sha,
        ]
        FakeApi.responses = {
            ("GET", self.check_path()): self.response(
                200, {"check_runs": self.successful_runs()}
            )
        }
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ, {"GH_TOKEN": "token"}, clear=True
        ), self.assertRaisesRegex(
            MODULE.ProtectionError, "acknowledge-admin-mutation"
        ):
            MODULE.main(argv)

        argv.append("--acknowledge-admin-mutation")
        FakeApi.calls = []
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ, {"GH_TOKEN": "token"}, clear=True
        ), self.assertRaisesRegex(
            MODULE.ProtectionError, "TRNM_ADMIN_CHANGE_TICKET"
        ):
            MODULE.main(argv)

    def test_apply_rejects_stale_evidence_before_reading_or_mutating_main(self) -> None:
        FakeApi.responses = {
            ("GET", self.check_path()): self.response(
                200, {"check_runs": self.successful_runs()}
            )
        }
        argv = [
            "--apply",
            "--acknowledge-admin-mutation",
            "--evidence-sha",
            self.evidence_sha,
            "--expected-current-main-sha",
            self.stale_sha,
        ]
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ,
            {"GH_TOKEN": "token", "TRNM_ADMIN_CHANGE_TICKET": "issue-40"},
            clear=True,
        ), self.assertRaisesRegex(
            MODULE.ProtectionError, "evidence SHA must equal"
        ):
            MODULE.main(argv)
        self.assertFalse(
            any(path == self.branch_path() or method == "PUT" for method, path, _body in FakeApi.calls)
        )

    def test_apply_rejects_a_moved_main_branch_before_mutation(self) -> None:
        FakeApi.responses = {
            ("GET", self.check_path()): self.response(
                200, {"check_runs": self.successful_runs()}
            ),
            ("GET", self.branch_path()): self.response(
                200, {"commit": {"sha": "3" * 40}}
            ),
        }
        argv = [
            "--apply",
            "--acknowledge-admin-mutation",
            "--evidence-sha",
            self.evidence_sha,
            "--expected-current-main-sha",
            self.main_sha,
        ]
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ,
            {"GH_TOKEN": "token", "TRNM_ADMIN_CHANGE_TICKET": "issue-40"},
            clear=True,
        ), self.assertRaisesRegex(MODULE.ProtectionError, "main branch moved"):
            MODULE.main(argv)
        self.assertFalse(
            any(method == "PUT" for method, _path, _body in FakeApi.calls)
        )

    def test_apply_writes_once_and_verifies_the_exact_live_shape(self) -> None:
        payload = MODULE.protection_payload(self.config)
        FakeApi.responses = {
            ("GET", self.check_path()): self.response(
                200, {"check_runs": self.successful_runs()}
            ),
            ("GET", self.branch_path()): self.response(
                200, {"commit": {"sha": self.main_sha}}
            ),
            ("GET", self.protection_path()): self.response(
                200, self.live_shape()
            ),
            ("PUT", self.protection_path()): self.response(
                200, self.live_shape()
            ),
        }
        argv = [
            "--apply",
            "--acknowledge-admin-mutation",
            "--evidence-sha",
            self.evidence_sha,
            "--expected-current-main-sha",
            self.main_sha,
        ]
        stdout = io.StringIO()
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ,
            {"GH_TOKEN": "token", "TRNM_ADMIN_CHANGE_TICKET": "issue-40"},
            clear=True,
        ), contextlib.redirect_stdout(stdout):
            result = MODULE.main(argv)
        self.assertEqual(result, 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["result"], "APPLIED_AND_VERIFIED")
        puts = [call for call in FakeApi.calls if call[0] == "PUT"]
        self.assertEqual(puts, [("PUT", self.protection_path(), payload)])

    def test_live_shape_drift_is_detected_after_put(self) -> None:
        bad_live = self.live_shape()
        bad_live["allow_force_pushes"] = {"enabled": True}
        FakeApi.responses = {
            ("GET", self.check_path()): self.response(
                200, {"check_runs": self.successful_runs()}
            ),
            ("GET", self.branch_path()): self.response(
                200, {"commit": {"sha": self.main_sha}}
            ),
            ("GET", self.protection_path()): self.response(200, bad_live),
            ("PUT", self.protection_path()): self.response(200, bad_live),
        }
        argv = [
            "--apply",
            "--acknowledge-admin-mutation",
            "--evidence-sha",
            self.evidence_sha,
            "--expected-current-main-sha",
            self.main_sha,
        ]
        with mock.patch.object(MODULE, "GitHubApi", FakeApi), mock.patch.dict(
            os.environ,
            {"GH_TOKEN": "token", "TRNM_ADMIN_CHANGE_TICKET": "issue-40"},
            clear=True,
        ), self.assertRaisesRegex(
            MODULE.ProtectionError, "does not match canonical payload"
        ):
            MODULE.main(argv)

    def test_configuration_rejects_an_unknown_member(self) -> None:
        value = json.loads(
            (ROOT / "config/main-branch-protection-v1.json").read_text(
                encoding="utf-8"
            )
        )
        value["bypass_for_admin"] = True
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "bad.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(
                MODULE.ProtectionError, "configuration keys drift"
            ):
                MODULE.load_config(path)


if __name__ == "__main__":
    unittest.main()
