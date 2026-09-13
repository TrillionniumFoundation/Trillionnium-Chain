#!/usr/bin/env python3
"""Verify and optionally repair the repository CodeQL default-setup contract.

Dry-run performs no network calls. Live evidence is fail closed: configuration
readback, exact source identity, trusted producer identity, one validation
workflow/suite, and post-configuration timestamps must all agree. A settings
mutation is never security acceptance and cannot be combined with evidence
acceptance in the same invocation.
"""

from __future__ import annotations

import argparse
import datetime as dt
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
    "trusted_check_producers",
    "analysis_workflow_path",
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
ANALYZE_CHECK_NAMES = REQUIRED_CHECK_NAMES - {"CodeQL"}
LIVE_REQUIRED_KEYS = {
    "state",
    "runner_type",
    "runner_label",
    "query_suite",
    "threat_model",
    "languages",
    "updated_at",
}
PRODUCER_KEYS = {"app_id", "slug", "owner"}
TRUSTED_PRODUCER_KEYS = {"aggregate", "analysis"}
SHA_RE = re.compile(r"[0-9a-f]{40}")


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


def parse_timestamp(value: Any, field: str) -> dt.datetime:
    require(isinstance(value, str) and value != "", f"{field} must be a timestamp")
    require(value.endswith("Z"), f"{field} must be UTC and end in Z")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise CodeqlSetupError(f"{field} is not a valid timestamp: {value}") from error
    require(parsed.tzinfo is not None, f"{field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def validate_producer(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} producer must be an object")
    require(set(value) == PRODUCER_KEYS, f"{label} producer keys drift")
    require(
        isinstance(value["app_id"], int) and value["app_id"] > 0,
        f"{label} app_id invalid",
    )
    for field in ("slug", "owner"):
        require(
            isinstance(value[field], str) and value[field] != "",
            f"{label} {field} invalid",
        )
    return dict(value)


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
    producers = value["trusted_check_producers"]
    require(
        isinstance(producers, dict),
        "trusted_check_producers must be an object",
    )
    require(
        set(producers) == TRUSTED_PRODUCER_KEYS,
        "trusted producer classes drift",
    )
    value["trusted_check_producers"] = {
        label: validate_producer(producers[label], label)
        for label in sorted(TRUSTED_PRODUCER_KEYS)
    }
    require(
        value["trusted_check_producers"]["aggregate"]
        != value["trusted_check_producers"]["analysis"],
        "aggregate and analysis producer identities must be distinct",
    )
    require(
        value["analysis_workflow_path"] == "dynamic/github-code-scanning/codeql",
        "analysis workflow path drift",
    )
    for field in (
        "production_candidate",
        "production_consensus_activation",
        "public_testnet_ready",
        "release_ready",
    ):
        require(value[field] is False, f"{field} must remain false")
    return value


def update_payload(config: dict[str, Any]) -> dict[str, Any]:
    """Return the exact fail-closed PATCH payload."""

    return {
        "state": config["state"],
        "runner_type": config["runner_type"],
        "runner_label": config["runner_label"],
        "query_suite": config["query_suite"],
        "threat_model": config["threat_model"],
        "languages": list(config["required_languages"]),
    }


def normalize_live(value: dict[str, Any]) -> dict[str, Any]:
    """Validate the live response without manufacturing absent settings."""

    require(isinstance(value, dict), "default-setup response must be an object")
    missing = sorted(LIVE_REQUIRED_KEYS - set(value))
    require(
        not missing,
        f"default-setup response missing required members: {missing}",
    )
    require(isinstance(value["state"], str), "live state must be a string")
    require(
        isinstance(value["runner_type"], str),
        "live runner_type must be a string",
    )
    require(
        value["runner_label"] is None or isinstance(value["runner_label"], str),
        "live runner_label must be a string or null",
    )
    require(
        isinstance(value["query_suite"], str),
        "live query_suite must be a string",
    )
    require(
        isinstance(value["threat_model"], str),
        "live threat_model must be a string",
    )
    languages = value["languages"]
    require(
        isinstance(languages, list)
        and all(isinstance(item, str) and item for item in languages),
        "live languages must contain non-empty strings",
    )
    require(len(languages) == len(set(languages)), "live languages contain duplicates")
    parse_timestamp(value["updated_at"], "live updated_at")
    return {
        "state": value["state"],
        "runner_type": value["runner_type"],
        "runner_label": value["runner_label"],
        "query_suite": value["query_suite"],
        "threat_model": value["threat_model"],
        "languages": sorted(languages),
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
    commit = value.get("commit")
    require(isinstance(commit, dict), "branch commit object missing")
    sha = commit.get("sha")
    require(
        isinstance(sha, str) and SHA_RE.fullmatch(sha) is not None,
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
    return {"normalized": actual, "updated_at": raw["updated_at"]}


def _list_check_runs(
    api: GitHubApi, repository: str, evidence_sha: str
) -> tuple[list[dict[str, Any]], int]:
    require(
        isinstance(evidence_sha, str) and SHA_RE.fullmatch(evidence_sha) is not None,
        "evidence SHA must be a full lowercase Git object ID",
    )
    all_runs: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    expected_total: int | None = None
    for page in range(1, 101):
        value = api.request(
            f"/repos/{repository}/commits/{evidence_sha}/check-runs"
            f"?filter=all&per_page=100&page={page}"
        ).value
        require(isinstance(value, dict), "check-runs response must be an object")
        total = value.get("total_count")
        require(
            isinstance(total, int) and total >= 0,
            "check-runs total_count missing",
        )
        if expected_total is None:
            expected_total = total
        else:
            require(
                total == expected_total,
                "check-runs pagination total_count drift",
            )
        batch = value.get("check_runs")
        require(isinstance(batch, list), "check-runs list missing")
        for item in batch:
            require(isinstance(item, dict), "check-run entry must be an object")
            run_id = item.get("id")
            require(
                isinstance(run_id, int) and run_id > 0,
                "check-run id missing",
            )
            require(
                run_id not in seen_ids,
                f"duplicate check-run id across pagination: {run_id}",
            )
            seen_ids.add(run_id)
            all_runs.append(item)
        if len(batch) < 100:
            break
    else:
        raise CodeqlSetupError("unexpected check-runs pagination depth")
    require(
        expected_total == len(all_runs),
        f"check-runs pagination incomplete: expected {expected_total}, got {len(all_runs)}",
    )
    return all_runs, len(all_runs)


def required_check_inventory_snapshot(
    api: GitHubApi,
    repository: str,
    evidence_sha: str,
    required_names: list[str],
) -> dict[str, Any]:
    # Capture every authority-bearing required check in one complete generation.
    require(set(required_names) == REQUIRED_CHECK_NAMES, "required check set drift")
    all_runs, total_count = _list_check_runs(api, repository, evidence_sha)
    snapshot: list[dict[str, Any]] = []
    for run in all_runs:
        name = run.get("name")
        if name not in REQUIRED_CHECK_NAMES:
            continue
        run_id = run.get("id")
        require(
            isinstance(run_id, int) and run_id > 0,
            f"check {name} id missing",
        )
        require(
            run.get("head_sha") == evidence_sha,
            f"check {name} head SHA mismatch",
        )
        app = run.get("app")
        require(isinstance(app, dict), f"check {name} app identity missing")
        owner = app.get("owner")
        require(isinstance(owner, dict), f"check {name} app owner missing")
        snapshot.append(
            {
                "id": run_id,
                "name": name,
                "head_sha": run.get("head_sha"),
                "status": run.get("status"),
                "conclusion": run.get("conclusion"),
                "started_at": run.get("started_at"),
                "completed_at": run.get("completed_at"),
                "details_url": run.get("details_url"),
                "external_id": run.get("external_id"),
                "check_suite_id": _suite_id(run, str(name)),
                "app": {
                    "id": app.get("id"),
                    "slug": app.get("slug"),
                    "owner": owner.get("login"),
                },
            }
        )
    snapshot.sort(key=lambda item: (str(item["name"]), int(item["id"])))
    return {
        "evidence_sha": evidence_sha,
        "total_check_runs": total_count,
        "required_run_count": len(snapshot),
        "required_runs": snapshot,
    }


def latest_check_runs(
    api: GitHubApi, repository: str, evidence_sha: str
) -> tuple[dict[str, dict[str, Any]], int]:
    """Return latest-by-time/id runs for compatibility and diagnostics."""

    all_runs, count = _list_check_runs(api, repository, evidence_sha)
    latest: dict[str, dict[str, Any]] = {}
    for run in all_runs:
        name = run.get("name")
        if not isinstance(name, str) or not name:
            continue
        previous = latest.get(name)
        key = (str(run.get("started_at") or ""), int(run["id"]))
        previous_key = (
            (str(previous.get("started_at") or ""), int(previous["id"]))
            if previous is not None
            else ("", -1)
        )
        if key > previous_key:
            latest[name] = run
    return latest, count


def _require_app_identity(
    run_or_suite: dict[str, Any], expected: dict[str, Any], label: str
) -> None:
    app = run_or_suite.get("app")
    require(isinstance(app, dict), f"{label} app identity missing")
    owner = app.get("owner")
    require(isinstance(owner, dict), f"{label} app owner missing")
    actual = {
        "app_id": app.get("id"),
        "slug": app.get("slug"),
        "owner": owner.get("login"),
    }
    require(
        actual == expected,
        f"{label} producer identity mismatch: expected={expected!r} actual={actual!r}",
    )


def _require_repository_identity(
    value: dict[str, Any], repository: str, label: str
) -> None:
    repo = value.get("repository")
    require(isinstance(repo, dict), f"{label} repository identity missing")
    require(
        repo.get("full_name") == repository,
        f"{label} repository identity mismatch",
    )


def _suite_id(run: dict[str, Any], label: str) -> int:
    suite = run.get("check_suite")
    require(isinstance(suite, dict), f"{label} check_suite missing")
    suite_id = suite.get("id")
    require(
        isinstance(suite_id, int) and suite_id > 0,
        f"{label} check_suite id missing",
    )
    return suite_id


def _workflow_run_id(run: dict[str, Any], repository: str, label: str) -> int:
    details = run.get("details_url")
    require(isinstance(details, str), f"{label} details_url missing")
    owner, repo = repository.split("/", 1)
    pattern = re.compile(
        rf"^https://github\.com/{re.escape(owner)}/{re.escape(repo)}/actions/runs/(\d+)(?:/job/\d+)?$"
    )
    match = pattern.fullmatch(details)
    require(
        match is not None,
        f"{label} details_url is not an in-repository Actions run",
    )
    return int(match.group(1))


def _verify_suite(
    api: GitHubApi,
    repository: str,
    suite_id: int,
    evidence_sha: str,
    expected_app: dict[str, Any],
    cache: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    if suite_id not in cache:
        value = api.request(f"/repos/{repository}/check-suites/{suite_id}").value
        require(isinstance(value, dict), "check-suite response must be an object")
        cache[suite_id] = value
    value = cache[suite_id]
    require(value.get("id") == suite_id, "check-suite id mismatch")
    require(value.get("head_sha") == evidence_sha, "check-suite head SHA mismatch")
    _require_repository_identity(value, repository, "check-suite")
    _require_app_identity(value, expected_app, "check-suite")
    return value


def _verify_validation_run(
    api: GitHubApi,
    repository: str,
    validation_run_id: int,
    evidence_sha: str,
    expected_suite_id: int,
    workflow_path: str,
    live_updated_at: dt.datetime,
) -> dict[str, Any]:
    value = api.request(
        f"/repos/{repository}/actions/runs/{validation_run_id}"
    ).value
    require(
        isinstance(value, dict),
        "validation workflow response must be an object",
    )
    require(value.get("id") == validation_run_id, "validation workflow id mismatch")
    require(
        value.get("head_sha") == evidence_sha,
        "validation workflow head SHA mismatch",
    )
    require(
        value.get("check_suite_id") == expected_suite_id,
        "validation workflow suite mismatch",
    )
    require(value.get("path") == workflow_path, "validation workflow path mismatch")
    require(value.get("status") == "completed", "validation workflow is not complete")
    require(
        value.get("conclusion") == "success",
        "validation workflow is not successful",
    )
    _require_repository_identity(value, repository, "validation workflow")
    head_repo = value.get("head_repository")
    require(
        isinstance(head_repo, dict),
        "validation workflow head repository missing",
    )
    require(
        head_repo.get("full_name") == repository,
        "validation workflow head repository mismatch",
    )
    created_at = parse_timestamp(
        value.get("created_at"),
        "validation workflow created_at",
    )
    started_at = parse_timestamp(
        value.get("run_started_at"),
        "validation workflow run_started_at",
    )
    require(
        created_at >= live_updated_at,
        "validation workflow predates live configuration",
    )
    require(
        started_at >= live_updated_at,
        "validation workflow start predates live configuration",
    )
    return {
        "id": validation_run_id,
        "path": value["path"],
        "check_suite_id": expected_suite_id,
        "created_at": value["created_at"],
        "run_started_at": value["run_started_at"],
        "status": value["status"],
        "conclusion": value["conclusion"],
    }


def _check_sort_key(run: dict[str, Any]) -> tuple[dt.datetime, int]:
    return (
        parse_timestamp(run.get("started_at"), "check started_at"),
        int(run["id"]),
    )


def verify_exact_source_checks(
    api: GitHubApi,
    repository: str,
    evidence_sha: str,
    required_names: list[str],
    *,
    live_updated_at: str,
    validation_run_id: int,
    trusted_producers: dict[str, dict[str, Any]],
    analysis_workflow_path: str,
) -> dict[str, Any]:
    require(set(required_names) == REQUIRED_CHECK_NAMES, "required check set drift")
    require(
        isinstance(validation_run_id, int) and validation_run_id > 0,
        "validation run id must be positive",
    )
    live_time = parse_timestamp(live_updated_at, "live updated_at")
    all_runs, count = _list_check_runs(api, repository, evidence_sha)
    candidates: dict[str, list[dict[str, Any]]] = {
        name: [] for name in required_names
    }
    for run in all_runs:
        name = run.get("name")
        if name not in candidates:
            continue
        require(
            run.get("head_sha") == evidence_sha,
            f"required CodeQL check has missing or mismatched head SHA: {name}",
        )
        expected_app = trusted_producers[
            "aggregate" if name == "CodeQL" else "analysis"
        ]
        _require_app_identity(run, expected_app, f"check {name}")
        started = parse_timestamp(
            run.get("started_at"),
            f"check {name} started_at",
        )
        completed = parse_timestamp(
            run.get("completed_at"),
            f"check {name} completed_at",
        )
        require(
            started >= live_time,
            f"required CodeQL check predates live configuration: {name}",
        )
        require(
            completed >= started,
            f"required CodeQL check completion precedes start: {name}",
        )
        candidates[name].append(run)

    selected: dict[str, dict[str, Any]] = {}
    analysis_suite_ids: set[int] = set()
    for name in sorted(ANALYZE_CHECK_NAMES):
        runs = candidates[name]
        require(runs, f"required CodeQL check is absent: {name}")
        bound = [
            run
            for run in runs
            if _workflow_run_id(run, repository, name) == validation_run_id
        ]
        require(
            len(bound) == 1,
            "required CodeQL check is ambiguous or not bound to validation run "
            f"{validation_run_id}: {name}",
        )
        selected[name] = bound[0]
        analysis_suite_ids.add(_suite_id(bound[0], name))
    require(
        len(analysis_suite_ids) == 1,
        "Analyze checks span multiple check suites",
    )
    analysis_suite_id = next(iter(analysis_suite_ids))

    aggregate_runs = candidates["CodeQL"]
    require(aggregate_runs, "required CodeQL check is absent: CodeQL")
    aggregate = max(aggregate_runs, key=_check_sort_key)
    selected["CodeQL"] = aggregate

    suite_cache: dict[int, dict[str, Any]] = {}
    _verify_suite(
        api,
        repository,
        analysis_suite_id,
        evidence_sha,
        trusted_producers["analysis"],
        suite_cache,
    )
    aggregate_suite_id = _suite_id(aggregate, "CodeQL")
    _verify_suite(
        api,
        repository,
        aggregate_suite_id,
        evidence_sha,
        trusted_producers["aggregate"],
        suite_cache,
    )
    validation = _verify_validation_run(
        api,
        repository,
        validation_run_id,
        evidence_sha,
        analysis_suite_id,
        analysis_workflow_path,
        live_time,
    )

    report: dict[str, Any] = {}
    latest_analysis_completion = live_time
    for name in required_names:
        run = selected[name]
        require(
            run.get("status") == "completed",
            f"required CodeQL check is not complete: {name}={run.get('status')}",
        )
        require(
            run.get("conclusion") == "success",
            f"required CodeQL check is not successful: {name}={run.get('conclusion')}",
        )
        completed = parse_timestamp(
            run["completed_at"],
            f"check {name} completed_at",
        )
        if name != "CodeQL":
            latest_analysis_completion = max(latest_analysis_completion, completed)
        report[name] = {
            "id": run["id"],
            "head_sha": run["head_sha"],
            "status": run["status"],
            "conclusion": run["conclusion"],
            "started_at": run["started_at"],
            "completed_at": run["completed_at"],
            "check_suite_id": _suite_id(run, name),
            "app": {
                "id": run["app"]["id"],
                "slug": run["app"]["slug"],
                "owner": run["app"]["owner"]["login"],
            },
        }
    aggregate_started = parse_timestamp(
        aggregate["started_at"],
        "CodeQL aggregate started_at",
    )
    require(
        aggregate_started >= latest_analysis_completion,
        "CodeQL aggregate predates completion of its Analyze checks",
    )
    return {
        "evidence_sha": evidence_sha,
        "live_updated_at": live_updated_at,
        "validation_run": validation,
        "required": report,
        "total_check_runs": count,
        "aggregate_candidates": [
            run["id"] for run in sorted(aggregate_runs, key=_check_sort_key)
        ],
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
    parser.add_argument("--validation-run-id", type=int)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--acknowledge-admin-mutation", action="store_true")
    parser.add_argument("--acknowledge-change-freeze", action="store_true")
    parser.add_argument(
        "--acknowledge-settings-verification-freeze", action="store_true"
    )
    parser.add_argument("--expected-current-main-sha")
    parser.add_argument("--timeout-seconds", type=int, default=600)
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--output", type=pathlib.Path)
    return parser.parse_args(argv)


def _snapshot_raw_setup(raw: dict[str, Any]) -> dict[str, Any]:
    """Retain exact observed fields without supplying defaults."""

    return {
        key: raw.get(key)
        for key in sorted(set(raw) & (LIVE_REQUIRED_KEYS | {"schedule"}))
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    config = load_config(args.config)
    repository = args.repository or config["repository"]
    branch = args.branch or config["branch"]
    require(
        repository == config["repository"],
        "repository override contradicts contract",
    )
    require(branch == config["branch"], "branch override contradicts contract")
    require(args.timeout_seconds >= 0, "timeout-seconds must be non-negative")
    require(args.poll_seconds >= 0, "poll-seconds must be non-negative")
    require(
        not (args.apply and args.verify_evidence),
        "--apply and --verify-evidence cannot be combined",
    )
    if args.verify_evidence:
        require(
            args.verify_live,
            "--verify-evidence requires --verify-live in the same invocation",
        )
        require(args.evidence_sha is not None, "--evidence-sha required")
        require(args.validation_run_id is not None, "--validation-run-id required")
        require(
            args.acknowledge_settings_verification_freeze,
            "--acknowledge-settings-verification-freeze is required with "
            "--verify-evidence",
        )
        verification_ticket = os.environ.get(
            "TRNM_CODEQL_SETTINGS_VERIFICATION_TICKET", ""
        )
        require(
            verification_ticket.strip() != "",
            "TRNM_CODEQL_SETTINGS_VERIFICATION_TICKET is required",
        )
    else:
        verification_ticket = ""

    report: dict[str, Any] = {
        "schema": "trnm-codeql-default-setup-report-v2",
        "repository": repository,
        "branch": branch,
        "mode": (
            "apply"
            if args.apply
            else "verify"
            if (args.verify_live or args.verify_evidence)
            else "dry-run"
        ),
        "payload": update_payload(config),
        "live_before": None,
        "live_after": None,
        "evidence": None,
        "evidence_inventory_before": None,
        "evidence_inventory_after": None,
        "changed": False,
        "validation_run": None,
        "branch_observations": [],
        "settings_verification_ticket": None,
        "settings_verification_freeze_acknowledged": False,
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
        assert report["live_after"] is not None
        initial_live = report["live_after"]
        report["live_before"] = initial_live
        report["settings_verification_ticket"] = verification_ticket
        report["settings_verification_freeze_acknowledged"] = True
        report["evidence_inventory_before"] = required_check_inventory_snapshot(
            api,
            repository,
            args.evidence_sha,
            config["required_check_names"],
        )
        first_evidence = verify_exact_source_checks(
            api,
            repository,
            args.evidence_sha,
            config["required_check_names"],
            live_updated_at=initial_live["updated_at"],
            validation_run_id=args.validation_run_id,
            trusted_producers=config["trusted_check_producers"],
            analysis_workflow_path=config["analysis_workflow_path"],
        )
        final_live = verify_live_setup(api, repository, config)
        require(
            final_live == initial_live,
            "live default setup changed during evidence verification",
        )
        final_evidence = verify_exact_source_checks(
            api,
            repository,
            args.evidence_sha,
            config["required_check_names"],
            live_updated_at=final_live["updated_at"],
            validation_run_id=args.validation_run_id,
            trusted_producers=config["trusted_check_producers"],
            analysis_workflow_path=config["analysis_workflow_path"],
        )
        report["evidence_inventory_after"] = required_check_inventory_snapshot(
            api,
            repository,
            args.evidence_sha,
            config["required_check_names"],
        )
        require(
            report["evidence_inventory_after"]
            == report["evidence_inventory_before"],
            "required CodeQL check inventory changed during evidence verification",
        )
        require(
            final_evidence == first_evidence,
            "required CodeQL evidence changed during verification",
        )
        report["evidence"] = final_evidence
        report["live_after"] = final_live

    if args.apply:
        require(
            args.acknowledge_admin_mutation,
            "--acknowledge-admin-mutation is required with --apply",
        )
        require(
            args.acknowledge_change_freeze,
            "--acknowledge-change-freeze is required with --apply",
        )
        ticket = os.environ.get("TRNM_CODEQL_ADMIN_CHANGE_TICKET", "")
        require(
            ticket.strip() != "",
            "TRNM_CODEQL_ADMIN_CHANGE_TICKET is required",
        )
        require(
            args.expected_current_main_sha is not None,
            "--expected-current-main-sha is required with --apply",
        )
        require(
            SHA_RE.fullmatch(args.expected_current_main_sha) is not None,
            "expected current main SHA must be a full lowercase Git object ID",
        )

        def observe_branch(phase: str) -> str:
            observed = branch_sha(api, repository, branch)
            report["branch_observations"].append(
                {"phase": phase, "sha": observed}
            )
            require(
                observed == args.expected_current_main_sha,
                "main branch moved during change window at "
                f"{phase}: expected {args.expected_current_main_sha}, "
                f"found {observed}",
            )
            return observed

        observe_branch("before-live-read")
        before_raw = read_live_setup(api, repository)
        report["live_before"] = _snapshot_raw_setup(before_raw)
        observe_branch("immediately-before-patch")
        response = api.request(
            setup_path(repository),
            method="PATCH",
            body=update_payload(config),
            expected=(200, 202),
        )
        require(isinstance(response.value, dict), "PATCH response must be an object")
        run_id = response.value.get("run_id")
        run_url = response.value.get("run_url")
        require(
            isinstance(run_id, int) and run_id > 0,
            "PATCH response validation run_id missing",
        )
        require(
            run_url
            == f"https://api.github.com/repos/{repository}/actions/runs/{run_id}",
            "PATCH response validation run_url mismatch",
        )
        report["validation_run"] = {"id": run_id, "url": run_url}
        observe_branch("immediately-after-patch")
        report["live_after"] = wait_for_live_setup(
            api,
            repository,
            config,
            timeout_seconds=args.timeout_seconds,
            poll_seconds=args.poll_seconds,
        )
        observe_branch("after-live-readback")
        report["changed"] = report["live_before"] != report["live_after"]
        report["admin_change_ticket"] = ticket
        report["expected_current_main_sha"] = args.expected_current_main_sha
        report["change_freeze_acknowledged"] = True
        report["result"] = (
            "APPLIED_AND_LIVE_SHAPE_VERIFIED_VALIDATION_PENDING"
        )
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
