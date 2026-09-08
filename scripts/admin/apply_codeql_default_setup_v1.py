#!/usr/bin/env python3
"""Verify and optionally repair the repository CodeQL default-setup contract.

Dry-run is the default and performs no network calls. A live mutation requires
an exact main SHA, an explicit acknowledgement, a change-control ticket and a
GitHub token with repository Administration(write). The command never treats a
settings update as security acceptance: exact-source CodeQL and per-language
checks must be verified separately after GitHub finishes the validation run.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / "config/codeql-default-setup-v1.json"
API_ROOT = "https://api.github.com"


class CodeqlSetupError(RuntimeError):
    """Raised when a CodeQL setup precondition or verification fails."""


CONFIG_KEYS = {
    "schema",
    "repository",
    "branch",
    "api_version",
    "state",
    "runner_type",
    "runner_label",
    "query_suite",
    "threat_model",
    "required_languages",
    "required_check_names",
    "production_candidate",
    "production_consensus_activation",
    "public_testnet_ready",
    "release_ready",
}
REQUIRED_LANGUAGES = {
    "actions",
    "javascript-typescript",
    "python",
    "rust",
}
REQUIRED_CHECK_NAMES = {
    "CodeQL",
    "Analyze (actions)",
    "Analyze (javascript-typescript)",
    "Analyze (python)",
    "Analyze (rust)",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CodeqlSetupError(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CodeqlSetupError(f"duplicate JSON member: {key}")
        value[key] = item
    return value


def load_config(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=strict_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CodeqlSetupError(f"cannot load {path}: {error}") from error
    require(isinstance(value, dict), "configuration must be an object")
    require(
        set(value) == CONFIG_KEYS,
        f"configuration keys drift: {sorted(set(value) ^ CONFIG_KEYS)}",
    )
    require(value["schema"] == "trnm-codeql-default-setup-v1", "schema drift")
    require(
        isinstance(value["repository"], str)
        and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value["repository"])
        is not None,
        "repository must be owner/name",
    )
    require(value["branch"] == "main", "canonical branch must be main")
    require(
        isinstance(value["api_version"], str)
        and re.fullmatch(r"20\d{2}-\d{2}-\d{2}", value["api_version"])
        is not None,
        "api_version must be YYYY-MM-DD",
    )
    require(value["state"] == "configured", "default setup must be configured")
    require(value["runner_type"] == "standard", "runner_type must be standard")
    require(value["runner_label"] is None, "standard runner cannot carry a label")
    require(value["query_suite"] == "extended", "query_suite must be extended")
    require(
        value["threat_model"] == "remote_and_local",
        "threat_model must include remote and local sources",
    )
    languages = value["required_languages"]
    require(
        isinstance(languages, list)
        and all(isinstance(item, str) and item for item in languages),
        "required_languages must contain non-empty strings",
    )
    require(len(languages) == len(set(languages)), "duplicate required language")
    require(set(languages) == REQUIRED_LANGUAGES, "required language coverage drift")
    checks = value["required_check_names"]
    require(
        isinstance(checks, list)
        and all(isinstance(item, str) and item for item in checks),
        "required_check_names must contain non-empty strings",
    )
    require(len(checks) == len(set(checks)), "duplicate required check")
    require(set(checks) == REQUIRED_CHECK_NAMES, "required check coverage drift")
    for field in (
        "production_candidate",
        "production_consensus_activation",
        "public_testnet_ready",
        "release_ready",
    ):
        require(value[field] is False, f"{field} must remain false")
    return value


def update_payload(config: dict[str, Any]) -> dict[str, Any]:
    """Return the exact fail-closed PATCH payload.

    Rust is intentionally explicit. If the live GitHub API does not accept the
    language identifier, the request must fail rather than silently preserving
    a configuration that omits Rust coverage.
    """

    return {
        "state": config["state"],
        "runner_type": config["runner_type"],
        "runner_label": config["runner_label"],
        "query_suite": config["query_suite"],
        "threat_model": config["threat_model"],
        "languages": list(config["required_languages"]),
    }


def normalize_live(value: dict[str, Any]) -> dict[str, Any]:
    languages = value.get("languages")
    if not isinstance(languages, list):
        languages = []
    runner_type = value.get("runner_type")
    if runner_type is None:
        runner_type = "standard"
    runner_label = value.get("runner_label")
    return {
        "state": value.get("state"),
        "runner_type": runner_type,
        "runner_label": runner_label,
        "query_suite": value.get("query_suite"),
        "threat_model": value.get("threat_model"),
        "languages": sorted(
            item for item in languages if isinstance(item, str) and item
        ),
    }


def expected_live(config: dict[str, Any]) -> dict[str, Any]:
    payload = update_payload(config)
    payload["languages"] = sorted(payload["languages"])
    return payload


@dataclass(frozen=True)
class ApiResponse:
    status: int
    value: Any
    headers: dict[str, str]


class GitHubApi:
    def __init__(
        self,
        token: str | None,
        *,
        api_version: str,
        api_root: str = API_ROOT,
    ) -> None:
        self._token = token
        self._api_version = api_version
        self._api_root = api_root.rstrip("/")

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: Any = None,
        expected: Iterable[int] = (200,),
    ) -> ApiResponse:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self._api_version,
            "User-Agent": "trnm-codeql-default-setup-v1",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self._api_root + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = response.read()
                value = json.loads(raw) if raw else None
                result = ApiResponse(
                    response.status,
                    value,
                    {key.lower(): item for key, item in response.headers.items()},
                )
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                value = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                value = {"raw": raw.decode("utf-8", "replace")[:2000]}
            result = ApiResponse(
                error.code,
                value,
                {key.lower(): item for key, item in error.headers.items()},
            )
        require(
            result.status in set(expected),
            f"GitHub API {method} {path} returned {result.status}: {result.value}",
        )
        return result


def branch_sha(api: GitHubApi, repository: str, branch: str) -> str:
    encoded = urllib.parse.quote(branch, safe="")
    value = api.request(f"/repos/{repository}/branches/{encoded}").value
    require(isinstance(value, dict), "branch response must be an object")
    sha = (value.get("commit") or {}).get("sha")
    require(
        isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha) is not None,
        "live branch SHA missing",
    )
    return sha


def setup_path(repository: str) -> str:
    return f"/repos/{repository}/code-scanning/default-setup"


def read_live_setup(api: GitHubApi, repository: str) -> dict[str, Any]:
    value = api.request(setup_path(repository)).value
    require(isinstance(value, dict), "default-setup response must be an object")
    return value


def verify_live_setup(
    api: GitHubApi, repository: str, config: dict[str, Any]
) -> dict[str, Any]:
    raw = read_live_setup(api, repository)
    actual = normalize_live(raw)
    expected = expected_live(config)
    require(
        actual == expected,
        "live default setup does not match canonical contract: "
        f"expected={expected!r} actual={actual!r}",
    )
    return {"normalized": actual, "updated_at": raw.get("updated_at")}


def latest_check_runs(
    api: GitHubApi, repository: str, evidence_sha: str
) -> tuple[dict[str, dict[str, Any]], int]:
    require(
        re.fullmatch(r"[0-9a-f]{40}", evidence_sha) is not None,
        "evidence SHA must be a full lowercase Git object ID",
    )
    all_runs: list[dict[str, Any]] = []
    for page in range(1, 21):
        value = api.request(
            f"/repos/{repository}/commits/{evidence_sha}/check-runs"
            f"?filter=all&per_page=100&page={page}"
        ).value
        require(isinstance(value, dict), "check-runs response must be an object")
        batch = value.get("check_runs")
        require(isinstance(batch, list), "check-runs list missing")
        all_runs.extend(item for item in batch if isinstance(item, dict))
        if len(batch) < 100:
            break
    else:
        raise CodeqlSetupError("unexpected check-runs pagination depth")
    latest: dict[str, dict[str, Any]] = {}
    for run in all_runs:
        name = run.get("name")
        if not isinstance(name, str) or not name:
            continue
        previous = latest.get(name)
        if previous is None or int(run.get("id") or 0) > int(previous.get("id") or 0):
            latest[name] = run
    return latest, len(all_runs)


def verify_exact_source_checks(
    api: GitHubApi,
    repository: str,
    evidence_sha: str,
    required_names: list[str],
) -> dict[str, Any]:
    latest, count = latest_check_runs(api, repository, evidence_sha)
    report: dict[str, Any] = {}
    for name in required_names:
        run = latest.get(name)
        require(run is not None, f"required CodeQL check is absent: {name}")
        require(
            run.get("head_sha") in (None, evidence_sha),
            f"required CodeQL check is attached to another SHA: {name}",
        )
        require(
            run.get("status") == "completed",
            f"required CodeQL check is not complete: {name}={run.get('status')}",
        )
        require(
            run.get("conclusion") == "success",
            f"required CodeQL check is not successful: {name}={run.get('conclusion')}",
        )
        report[name] = {
            "id": run.get("id"),
            "status": run.get("status"),
            "conclusion": run.get("conclusion"),
            "completed_at": run.get("completed_at"),
        }
    return {
        "evidence_sha": evidence_sha,
        "required": report,
        "total_check_runs": count,
    }


def wait_for_live_setup(
    api: GitHubApi,
    repository: str,
    config: dict[str, Any],
    *,
    timeout_seconds: int,
    poll_seconds: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_error: CodeqlSetupError | None = None
    while True:
        try:
            return verify_live_setup(api, repository, config)
        except CodeqlSetupError as error:
            last_error = error
        if time.monotonic() >= deadline:
            raise CodeqlSetupError(
                f"default setup did not converge before timeout: {last_error}"
            )
        time.sleep(poll_seconds)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=pathlib.Path, default=DEFAULT_CONFIG)
    parser.add_argument("--repository")
    parser.add_argument("--branch")
    parser.add_argument("--verify-live", action="store_true")
    parser.add_argument("--verify-evidence", action="store_true")
    parser.add_argument("--evidence-sha")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--acknowledge-admin-mutation", action="store_true")
    parser.add_argument("--expected-current-main-sha")
    parser.add_argument("--timeout-seconds", type=int, default=600)
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--output", type=pathlib.Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    config = load_config(args.config)
    repository = args.repository or config["repository"]
    branch = args.branch or config["branch"]
    require(repository == config["repository"], "repository override contradicts contract")
    require(branch == config["branch"], "branch override contradicts contract")
    require(args.timeout_seconds >= 0, "timeout-seconds must be non-negative")
    require(args.poll_seconds >= 0, "poll-seconds must be non-negative")

    report: dict[str, Any] = {
        "schema": "trnm-codeql-default-setup-report-v1",
        "repository": repository,
        "branch": branch,
        "mode": "apply" if args.apply else "verify" if (args.verify_live or args.verify_evidence) else "dry-run",
        "payload": update_payload(config),
        "live_before": None,
        "live_after": None,
        "evidence": None,
        "changed": False,
        "validation_run": None,
        "production_candidate": False,
        "production_consensus_activation": False,
        "public_testnet_ready": False,
        "release_ready": False,
    }

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    needs_api = args.verify_live or args.verify_evidence or args.apply
    if needs_api:
        require(token is not None, "GitHub token required for live verification")
    api = GitHubApi(token, api_version=config["api_version"])

    if args.verify_live and not args.apply:
        report["live_after"] = verify_live_setup(api, repository, config)

    if args.verify_evidence:
        require(args.evidence_sha is not None, "--evidence-sha required")
        report["evidence"] = verify_exact_source_checks(
            api,
            repository,
            args.evidence_sha,
            config["required_check_names"],
        )

    if args.apply:
        require(
            args.acknowledge_admin_mutation,
            "--acknowledge-admin-mutation is required with --apply",
        )
        ticket = os.environ.get("TRNM_CODEQL_ADMIN_CHANGE_TICKET", "")
        require(ticket.strip() != "", "TRNM_CODEQL_ADMIN_CHANGE_TICKET is required")
        require(
            args.expected_current_main_sha is not None,
            "--expected-current-main-sha is required with --apply",
        )
        require(
            re.fullmatch(r"[0-9a-f]{40}", args.expected_current_main_sha) is not None,
            "expected current main SHA must be a full lowercase Git object ID",
        )
        current_sha = branch_sha(api, repository, branch)
        require(
            current_sha == args.expected_current_main_sha,
            f"main branch moved: expected {args.expected_current_main_sha}, found {current_sha}",
        )
        before_raw = read_live_setup(api, repository)
        report["live_before"] = {
            "normalized": normalize_live(before_raw),
            "updated_at": before_raw.get("updated_at"),
        }
        response = api.request(
            setup_path(repository),
            method="PATCH",
            body=update_payload(config),
            expected=(200, 202),
        )
        if isinstance(response.value, dict) and response.value.get("run_id") is not None:
            report["validation_run"] = {
                "id": response.value.get("run_id"),
                "url": response.value.get("run_url"),
            }
        report["live_after"] = wait_for_live_setup(
            api,
            repository,
            config,
            timeout_seconds=args.timeout_seconds,
            poll_seconds=args.poll_seconds,
        )
        report["changed"] = report["live_before"] != report["live_after"]
        report["admin_change_ticket"] = ticket
        report["expected_current_main_sha"] = args.expected_current_main_sha
        report["result"] = "APPLIED_AND_LIVE_SHAPE_VERIFIED"
    elif args.verify_live or args.verify_evidence:
        report["result"] = "VERIFIED"
    else:
        report["result"] = "DRY_RUN_VALID"

    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CodeqlSetupError as error:
        print(f"CodeQL default setup failed: {error}", file=sys.stderr)
        raise SystemExit(2)
