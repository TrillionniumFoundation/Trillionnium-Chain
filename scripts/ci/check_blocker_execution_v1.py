#!/usr/bin/env python3
"""Validate that every canonical blocker has an executable, fail-closed row."""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]


class LedgerError(RuntimeError):
    pass


def load(path: str) -> dict[str, Any]:
    try:
        value = json.loads((ROOT / path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LedgerError(f"{path}: {exc}") from exc
    if not isinstance(value, dict):
        raise LedgerError(f"{path}: top level must be object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LedgerError(message)


def validate_row(row: dict[str, Any], group: str) -> None:
    blocker_id = row.get("id")
    require(isinstance(blocker_id, str) and blocker_id, f"{group}: missing id")
    require(isinstance(row.get("status"), str) and row["status"], f"{blocker_id}: missing status")
    require(isinstance(row.get("owner_class"), str) and row["owner_class"],
            f"{blocker_id}: missing owner_class")
    for field in ("dependencies", "acceptance_predicates", "evidence_outputs",
                  "invalidation_triggers", "next_actions"):
        value = row.get(field)
        require(isinstance(value, list), f"{blocker_id}: {field} must be list")
        if field != "dependencies":
            require(value and all(isinstance(item, str) and item for item in value),
                    f"{blocker_id}: {field} must contain non-empty strings")


def main() -> int:
    ledger = load("config/blocker-execution-v1.json")
    truth = load("config/consensus-mainline.json")
    policy = load("config/repository-policy-v1.json")

    require(ledger.get("schema") == "trnm-blocker-execution-v1", "unsupported ledger schema")
    require(ledger.get("canonical_register") == "config/consensus-mainline.json",
            "ledger canonical register drift")
    require(ledger.get("repository_policy") == "config/repository-policy-v1.json",
            "ledger repository policy drift")
    require(ledger.get("source_binding") == "runtime-git-commit-and-tree",
            "ledger must bind exact source at verification time")

    repository_rows = ledger.get("repository_blockers")
    settings_rows = ledger.get("settings_gates")
    external_rows = ledger.get("external_blockers")
    require(isinstance(repository_rows, list), "repository_blockers must be list")
    require(isinstance(settings_rows, list), "settings_gates must be list")
    require(isinstance(external_rows, list), "external_blockers must be list")

    for row in repository_rows:
        require(isinstance(row, dict), "repository blocker row must be object")
        validate_row(row, "repository_blockers")
        require(isinstance(row.get("severity"), str) and row["severity"],
                f"{row.get('id')}: missing severity")
    for row in settings_rows:
        require(isinstance(row, dict), "settings gate row must be object")
        validate_row(row, "settings_gates")
    for row in external_rows:
        require(isinstance(row, dict), "external blocker row must be object")
        validate_row(row, "external_blockers")

    truth_by_id = {row["id"]: row for row in truth.get("blockers", [])}
    ledger_by_id = {row["id"]: row for row in repository_rows}
    require(len(truth_by_id) == len(truth.get("blockers", [])),
            "canonical blocker register has duplicate IDs")
    require(len(ledger_by_id) == len(repository_rows), "execution ledger has duplicate IDs")
    require(set(truth_by_id) == set(ledger_by_id),
            "execution ledger IDs differ from canonical blocker register: "
            f"missing={sorted(set(truth_by_id) - set(ledger_by_id))} "
            f"extra={sorted(set(ledger_by_id) - set(truth_by_id))}")
    for blocker_id, truth_row in truth_by_id.items():
        ledger_row = ledger_by_id[blocker_id]
        require(ledger_row["severity"] == truth_row["severity"],
                f"{blocker_id}: severity drift")
        if ledger_row["status"] == "closed":
            require(truth_row.get("status") == "closed",
                    f"{blocker_id}: ledger cannot close an open canonical blocker")

    expected_external = set(policy.get("external_blockers", []))
    actual_external = {row["id"] for row in external_rows}
    require(len(actual_external) == len(external_rows), "external ledger has duplicate IDs")
    require(actual_external == expected_external,
            "external execution rows differ from repository policy")

    all_ids = set(ledger_by_id) | actual_external | {row["id"] for row in settings_rows}
    for row in [*repository_rows, *settings_rows, *external_rows]:
        unknown = sorted(set(row["dependencies"]) - all_ids)
        require(not unknown, f"{row['id']}: unknown dependencies {unknown}")
        require(row["id"] not in row["dependencies"], f"{row['id']}: self dependency")

    summary = ledger.get("release_summary")
    require(isinstance(summary, dict), "release_summary must be object")
    canonical_open = [row for row in truth_by_id.values() if row.get("status") != "closed"]
    external_open = [row for row in external_rows if row.get("status") != "closed"]
    settings_open = [row for row in settings_rows if row.get("status") != "closed"]
    require(summary.get("all_repository_blockers_closed") is (not canonical_open),
            "repository closure summary contradicts canonical register")
    require(summary.get("all_external_blockers_closed") is (not external_open),
            "external closure summary contradicts execution rows")
    require(summary.get("all_settings_gates_closed") is (not settings_open),
            "settings closure summary contradicts execution rows")
    if canonical_open or external_open or settings_open:
        for claim in ("public_testnet_ready", "production_candidate",
                      "production_consensus_activation", "release_ready"):
            require(summary.get(claim) is False,
                    f"{claim} must remain false while blockers are open")

    report = {
        "schema": "trnm-blocker-execution-validation-v1",
        "repository_blockers": len(repository_rows),
        "repository_open": len(canonical_open),
        "settings_open": len(settings_open),
        "external_open": len(external_open),
        "all_gaps_closed": not (canonical_open or settings_open or external_open),
        "result": "PASS",
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LedgerError as exc:
        print(f"blocker execution validation failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
