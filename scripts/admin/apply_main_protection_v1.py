#!/usr/bin/env python3
"""Generate, verify, and optionally apply the canonical main-branch protection.

The command is dry-run by default. A live mutation requires all of:

* ``--apply``;
* ``--acknowledge-admin-mutation``;
* an exact ``--evidence-sha`` whose required checks all completed successfully;
* ``--expected-current-main-sha`` matching the live branch tip;
* ``TRNM_ADMIN_CHANGE_TICKET`` and an administration-capable GitHub token.

No production, release, audit, or external-evidence claim is made by changing
repository settings. The command deliberately treats skipped, neutral, stale,
missing, queued, and in-progress checks as failures for required contexts.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / "config/main-branch-protection-v1.json"
API_ROOT = "https://api.github.com"


class ProtectionError(RuntimeError):
    """Raised when a protection precondition or verification fails."""


CONFIG_KEYS = {
    "schema",
    "repository",
    "branch",
    "required_status_contexts",
    "required_approving_review_count",
    "dismiss_stale_reviews",
    "require_code_owner_reviews",
    "require_last_push_approval",
    "require_conversation_resolution",
    "require_linear_history",
    "require_branches_to_be_up_to_date",
    "enforce_admins",
    "allow_force_pushes",
    "allow_deletions",
    "allow_fork_syncing",
    "lock_branch",
    "block_creations",
    "required_signatures",
    "production_candidate",
    "production_consensus_activation",
    "public_testnet_ready",
    "release_ready",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProtectionError(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProtectionError(f"duplicate JSON member: {key}")
        value[key] = item
    return value


def load_config(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=strict_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProtectionError(f"cannot load {path}: {error}") from error
    require(isinstance(value, dict), "configuration must be an object")
    require(set(value) == CONFIG_KEYS, f"configuration keys drift: {sorted(set(value) ^ CONFIG_KEYS)}")
    require(value["schema"] == "trnm-main-branch-protection-v1", "schema drift")
    require(
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value["repository"])
        is not None,
        "repository must be owner/name",
    )
    require(
        isinstance(value["branch"], str)
        and value["branch"]
        and value["branch"] == "main",
        "canonical branch must be main",
    )
    contexts = value["required_status_contexts"]
    require(
        isinstance(contexts, list)
        and contexts
        and all(isinstance(item, str) and item for item in contexts),
        "required_status_contexts must be non-empty strings",
    )
    require(len(contexts) == len(set(contexts)), "duplicate required context")
    require("CodeQL" in contexts, "CodeQL must remain a required context")
    review_count = value["required_approving_review_count"]
    require(
        isinstance(review_count, int) and not isinstance(review_count, bool)
        and 2 <= review_count <= 6,
        "two to six approvals required",
    )
    true_fields = (
        "dismiss_stale_reviews",
        "require_code_owner_reviews",
        "require_last_push_approval",
        "require_conversation_resolution",
        "require_linear_history",
        "require_branches_to_be_up_to_date",
        "enforce_admins",
    )
    false_fields = (
        "allow_force_pushes",
        "allow_deletions",
        "allow_fork_syncing",
        "lock_branch",
        "block_creations",
        "required_signatures",
        "production_candidate",
        "production_consensus_activation",
        "public_testnet_ready",
        "release_ready",
    )
    for field in true_fields:
        require(value[field] is True, f"{field} must be true")
    for field in false_fields:
        require(value[field] is False, f"{field} must be false")
    return value


def protection_payload(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "required_status_checks": {
            "strict": config["require_branches_to_be_up_to_date"],
            "contexts": list(config["required_status_contexts"]),
        },
        "enforce_admins": config["enforce_admins"],
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": config["dismiss_stale_reviews"],
            "require_code_owner_reviews": config["require_code_owner_reviews"],
            "required_approving_review_count": config[
                "required_approving_review_count"
            ],
            "require_last_push_approval": config["require_last_push_approval"],
        },
        "restrictions": None,
        "required_linear_history": config["require_linear_history"],
        "allow_force_pushes": config["allow_force_pushes"],
        "allow_deletions": config["allow_deletions"],
        "block_creations": config["block_creations"],
        "required_conversation_resolution": config[
            "require_conversation_resolution"
        ],
        "lock_branch": config["lock_branch"],
        "allow_fork_syncing": config["allow_fork_syncing"],
    }


def _enabled(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        if "enabled" in value:
            return value.get("enabled") is True
        return True
    return False


def normalize_live_protection(value: dict[str, Any]) -> dict[str, Any]:
    checks = value.get("required_status_checks") or {}
    contexts = checks.get("contexts")
    if not isinstance(contexts, list):
        contexts = [
            item.get("context")
            for item in checks.get("checks") or []
            if isinstance(item, dict) and isinstance(item.get("context"), str)
        ]
    reviews = value.get("required_pull_request_reviews") or {}
    return {
        "required_status_checks": {
            "strict": checks.get("strict") is True,
            "contexts": sorted(
                item for item in contexts if isinstance(item, str) and item
            ),
        },
        "enforce_admins": _enabled(value.get("enforce_admins")),
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": reviews.get("dismiss_stale_reviews") is True,
            "require_code_owner_reviews": reviews.get("require_code_owner_reviews")
            is True,
            "required_approving_review_count": reviews.get(
                "required_approving_review_count"
            ),
            "require_last_push_approval": reviews.get("require_last_push_approval")
            is True,
        },
        "restrictions": None if value.get("restrictions") is None else "present",
        "required_linear_history": _enabled(value.get("required_linear_history")),
        "allow_force_pushes": _enabled(value.get("allow_force_pushes")),
        "allow_deletions": _enabled(value.get("allow_deletions")),
        "block_creations": _enabled(value.get("block_creations")),
        "required_conversation_resolution": _enabled(
            value.get("required_conversation_resolution")
        ),
        "lock_branch": _enabled(value.get("lock_branch")),
        "allow_fork_syncing": _enabled(value.get("allow_fork_syncing")),
    }


def normalize_expected(payload: dict[str, Any]) -> dict[str, Any]:
    expected = json.loads(json.dumps(payload))
    expected["required_status_checks"]["contexts"] = sorted(
        expected["required_status_checks"]["contexts"]
    )
    return expected


@dataclass(frozen=True)
class ApiResponse:
    status: int
    value: Any
    headers: dict[str, str]


class GitHubApi:
    def __init__(self, token: str | None, api_root: str = API_ROOT) -> None:
        self._token = token
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
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "trnm-main-protection-v1",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self._api_root + path, data=data, headers=headers, method=method
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


def successful_check_contexts(
    api: GitHubApi, repository: str, evidence_sha: str
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    require(
        re.fullmatch(r"[0-9a-f]{40}", evidence_sha) is not None,
        "evidence SHA must be a full lowercase Git object ID",
    )
    check_runs: list[dict[str, Any]] = []
    page = 1
    while True:
        response = api.request(
            f"/repos/{repository}/commits/{evidence_sha}/check-runs"
            f"?filter=all&per_page=100&page={page}"
        ).value
        require(isinstance(response, dict), "check-runs response must be object")
        batch = response.get("check_runs")
        require(isinstance(batch, list), "check-runs list missing")
        check_runs.extend(item for item in batch if isinstance(item, dict))
        if len(batch) < 100:
            break
        page += 1
        require(page <= 20, "unexpected check-runs pagination depth")
    latest: dict[str, dict[str, Any]] = {}
    for run in check_runs:
        name = run.get("name")
        if not isinstance(name, str) or not name:
            continue
        previous = latest.get(name)
        if previous is None or int(run.get("id") or 0) > int(previous.get("id") or 0):
            latest[name] = run
    return latest, check_runs


def verify_required_checks(
    api: GitHubApi,
    repository: str,
    evidence_sha: str,
    required: list[str],
) -> dict[str, Any]:
    latest, all_runs = successful_check_contexts(api, repository, evidence_sha)
    report: dict[str, Any] = {}
    for context in required:
        run = latest.get(context)
        require(run is not None, f"required context is absent: {context}")
        status = run.get("status")
        conclusion = run.get("conclusion")
        require(status == "completed", f"required context is not complete: {context}={status}")
        require(
            conclusion == "success",
            f"required context is not successful: {context}={conclusion}",
        )
        report[context] = {
            "id": run.get("id"),
            "status": status,
            "conclusion": conclusion,
            "completed_at": run.get("completed_at"),
        }
    return {
        "evidence_sha": evidence_sha,
        "required": report,
        "total_check_runs": len(all_runs),
    }


def live_protection(
    api: GitHubApi, repository: str, branch: str
) -> dict[str, Any] | None:
    encoded = urllib.parse.quote(branch, safe="")
    response = api.request(
        f"/repos/{repository}/branches/{encoded}/protection",
        expected=(200, 404),
    )
    if response.status == 404:
        return None
    require(isinstance(response.value, dict), "protection response must be object")
    return response.value


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=pathlib.Path, default=DEFAULT_CONFIG)
    parser.add_argument("--repository")
    parser.add_argument("--branch")
    parser.add_argument("--evidence-sha")
    parser.add_argument("--expected-current-main-sha")
    parser.add_argument("--verify-evidence", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--acknowledge-admin-mutation", action="store_true")
    parser.add_argument("--output", type=pathlib.Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    config = load_config(args.config)
    repository = args.repository or config["repository"]
    branch = args.branch or config["branch"]
    require(repository == config["repository"], "repository override contradicts contract")
    require(branch == config["branch"], "branch override contradicts contract")
    payload = protection_payload(config)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    api = GitHubApi(token)

    report: dict[str, Any] = {
        "schema": "trnm-main-branch-protection-report-v1",
        "repository": repository,
        "branch": branch,
        "mode": "apply" if args.apply else "dry-run",
        "payload": payload,
        "evidence": None,
        "live_before": None,
        "live_after": None,
        "changed": False,
        "production_candidate": False,
        "production_consensus_activation": False,
        "public_testnet_ready": False,
        "release_ready": False,
    }

    if args.verify_evidence or args.apply:
        require(token is not None, "GitHub token required for evidence verification")
        require(args.evidence_sha is not None, "--evidence-sha required")
        report["evidence"] = verify_required_checks(
            api,
            repository,
            args.evidence_sha,
            config["required_status_contexts"],
        )

    if args.apply:
        require(
            args.acknowledge_admin_mutation,
            "--acknowledge-admin-mutation is required with --apply",
        )
        ticket = os.environ.get("TRNM_ADMIN_CHANGE_TICKET", "")
        require(ticket.strip() != "", "TRNM_ADMIN_CHANGE_TICKET is required")
        require(
            args.expected_current_main_sha is not None,
            "--expected-current-main-sha is required with --apply",
        )
        require(
            args.evidence_sha == args.expected_current_main_sha,
            "apply evidence SHA must equal the expected current main SHA",
        )
        current_sha = branch_sha(api, repository, branch)
        require(
            current_sha == args.expected_current_main_sha,
            f"main branch moved: expected {args.expected_current_main_sha}, found {current_sha}",
        )
        before = live_protection(api, repository, branch)
        report["live_before"] = (
            None if before is None else normalize_live_protection(before)
        )
        encoded = urllib.parse.quote(branch, safe="")
        applied = api.request(
            f"/repos/{repository}/branches/{encoded}/protection",
            method="PUT",
            body=payload,
            expected=(200,),
        ).value
        require(isinstance(applied, dict), "apply response must be object")
        after = live_protection(api, repository, branch)
        require(after is not None, "protection absent after apply")
        normalized_after = normalize_live_protection(after)
        expected = normalize_expected(payload)
        require(
            normalized_after == expected,
            "live protection does not match canonical payload: "
            f"expected={expected!r} actual={normalized_after!r}",
        )
        report["live_after"] = normalized_after
        report["changed"] = report["live_before"] != normalized_after
        report["admin_change_ticket"] = ticket
        report["expected_current_main_sha"] = args.expected_current_main_sha
        report["result"] = "APPLIED_AND_VERIFIED"
    else:
        report["result"] = "DRY_RUN_VALID"

    encoded_report = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded_report, encoding="utf-8")
    sys.stdout.write(encoded_report)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProtectionError as error:
        print(f"main protection failed: {error}", file=sys.stderr)
        raise SystemExit(2)
