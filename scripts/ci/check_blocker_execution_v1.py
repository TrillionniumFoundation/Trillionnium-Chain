#!/usr/bin/env python3
"""Validate exact-source blocker execution and implementation/evidence separation."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tomllib
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]


class LedgerError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LedgerError(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LedgerError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_json(path: str) -> dict[str, Any]:
    try:
        value = json.loads(
            (ROOT / path).read_text(encoding="utf-8"),
            object_pairs_hook=strict_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LedgerError(f"{path}: {error}") from error
    require(isinstance(value, dict), f"{path}: top level must be object")
    return value


def load_toml(path: str) -> dict[str, Any]:
    try:
        with (ROOT / path).open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise LedgerError(f"{path}: {error}") from error
    require(isinstance(value, dict), f"{path}: top level must be table")
    return value


def validate_row(row: dict[str, Any], group: str) -> None:
    blocker_id = row.get("id")
    require(isinstance(blocker_id, str) and blocker_id, f"{group}: missing id")
    require(
        isinstance(row.get("status"), str) and row["status"],
        f"{blocker_id}: missing status",
    )
    require(
        isinstance(row.get("owner_class"), str) and row["owner_class"],
        f"{blocker_id}: missing owner_class",
    )
    for field in (
        "dependencies",
        "acceptance_predicates",
        "evidence_outputs",
        "invalidation_triggers",
        "next_actions",
    ):
        value = row.get(field)
        require(isinstance(value, list), f"{blocker_id}: {field} must be list")
        if field != "dependencies":
            require(
                value and all(isinstance(item, str) and item for item in value),
                f"{blocker_id}: {field} must contain non-empty strings",
            )
    implementation = row.get("implementation")
    if implementation is not None:
        require(
            isinstance(implementation, dict) and implementation,
            f"{blocker_id}: implementation must be a non-empty object",
        )


def main() -> int:
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/ci/check_plan_manifest_pins_v1.py")],
        cwd=ROOT,
        check=True,
    )
    ledger = load_json("config/blocker-execution-v1.json")
    truth = load_json("config/consensus-mainline.json")
    policy = load_json("config/repository-policy-v1.json")
    snapshot = load_json("docs/development/CURRENT_SNAPSHOT_V1.json")
    release_train = load_toml("docs/development/release-train-v1.toml")
    cargo = load_toml("trillionnium/Cargo.toml")

    require(
        ledger.get("schema") == "trnm-blocker-execution-v1",
        "unsupported ledger schema",
    )
    require(
        ledger.get("canonical_register") == "config/consensus-mainline.json",
        "ledger canonical register drift",
    )
    require(
        ledger.get("repository_policy") == "config/repository-policy-v1.json",
        "ledger repository policy drift",
    )
    require(
        ledger.get("source_binding") == "runtime-git-commit-and-tree",
        "ledger must bind exact source at verification time",
    )
    require(
        ledger.get("plan")
        == "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md",
        "ledger plan binding drift",
    )
    require(
        ledger.get("release_train") == "docs/development/release-train-v1.toml",
        "ledger release-train binding drift",
    )
    require(
        ledger.get("current_snapshot")
        == "docs/development/CURRENT_SNAPSHOT_V1.json",
        "ledger snapshot binding drift",
    )
    require(
        ledger.get("as_of") == snapshot.get("as_of") == release_train.get("as_of"),
        "ledger, snapshot and release train must share one observation date",
    )

    implementation = ledger.get("implementation")
    require(isinstance(implementation, dict), "ledger implementation summary missing")
    snapshot_implementation = snapshot.get("repository_implementation", {})
    snapshot_coverage = snapshot_implementation.get("module_coverage", {})
    members = cargo.get("workspace", {}).get("members")
    require(isinstance(members, list) and members, "Cargo workspace members missing")
    require(
        implementation.get("selected_successor")
        == snapshot.get("selected_successor", {}).get("pull_request")
        == release_train.get("source", {}).get("selected_successor_pull_request")
        == 62,
        "selected successor drift",
    )
    require(
        implementation.get("workspace_crates")
        == snapshot_coverage.get("workspace_crates_uniquely_mapped")
        == len(members),
        "workspace crate count drift",
    )
    require(
        implementation.get("overlay_commit")
        == snapshot_implementation.get("repository_core_overlay", {}).get("source_commit"),
        "repository-core overlay commit drift",
    )
    require(
        implementation.get("overlay_tree")
        == "a4480623afae1bedee9f03fcf83ce31ec00a2bb7",
        "repository-core overlay tree drift",
    )
    for claim in (
        "production_candidate",
        "production_consensus_activation",
        "public_testnet_ready",
        "release_ready",
    ):
        require(
            implementation.get(claim) is False,
            f"implementation summary may not promote {claim}",
        )

    repository_rows = ledger.get("repository_blockers")
    settings_rows = ledger.get("settings_gates")
    external_rows = ledger.get("external_blockers")
    require(isinstance(repository_rows, list), "repository_blockers must be list")
    require(isinstance(settings_rows, list), "settings_gates must be list")
    require(isinstance(external_rows, list), "external_blockers must be list")

    for row in repository_rows:
        require(isinstance(row, dict), "repository blocker row must be object")
        validate_row(row, "repository_blockers")
        require(
            isinstance(row.get("severity"), str) and row["severity"],
            f"{row.get('id')}: missing severity",
        )
    for row in settings_rows:
        require(isinstance(row, dict), "settings gate row must be object")
        validate_row(row, "settings_gates")
    for row in external_rows:
        require(isinstance(row, dict), "external blocker row must be object")
        validate_row(row, "external_blockers")

    truth_rows = truth.get("blockers")
    require(isinstance(truth_rows, list), "canonical blocker register missing")
    truth_by_id = {row["id"]: row for row in truth_rows}
    ledger_by_id = {row["id"]: row for row in repository_rows}
    require(
        len(truth_by_id) == len(truth_rows),
        "canonical blocker register has duplicate IDs",
    )
    require(
        len(ledger_by_id) == len(repository_rows),
        "execution ledger has duplicate IDs",
    )
    require(
        set(truth_by_id) == set(ledger_by_id),
        "execution ledger IDs differ from canonical blocker register: "
        f"missing={sorted(set(truth_by_id) - set(ledger_by_id))} "
        f"extra={sorted(set(ledger_by_id) - set(truth_by_id))}",
    )
    for blocker_id, truth_row in truth_by_id.items():
        ledger_row = ledger_by_id[blocker_id]
        require(
            ledger_row["severity"] == truth_row["severity"],
            f"{blocker_id}: severity drift",
        )
        if ledger_row["status"] == "closed":
            require(
                truth_row.get("status") == "closed",
                f"{blocker_id}: ledger cannot close an open canonical blocker",
            )

    expected_external = set(policy.get("external_blockers", []))
    actual_external = {row["id"] for row in external_rows}
    require(
        len(actual_external) == len(external_rows),
        "external ledger has duplicate IDs",
    )
    require(
        actual_external == expected_external,
        "external execution rows differ from repository policy",
    )

    all_ids = (
        set(ledger_by_id)
        | actual_external
        | {row["id"] for row in settings_rows}
    )
    for row in [*repository_rows, *settings_rows, *external_rows]:
        unknown = sorted(set(row["dependencies"]) - all_ids)
        require(not unknown, f"{row['id']}: unknown dependencies {unknown}")
        require(
            row["id"] not in row["dependencies"],
            f"{row['id']}: self dependency",
        )

    stale_actions = (
        "integrate the A19",
        "integrate the A20",
        "integrate the A21",
        "add a non-production persistent devnet constructor",
        "implement the cross-store commit protocol",
    )
    serialized_actions = "\n".join(
        action
        for row in repository_rows
        for action in row["next_actions"]
    )
    for stale in stale_actions:
        require(
            stale not in serialized_actions,
            f"stale repository next action remains after implementation absorption: {stale}",
        )

    required_implementation = {
        "P0-TRUTH-001": ("single_plan", "workspace_crates"),
        "P1-CORE-001": ("core", "safety_owner", "live_host"),
        "P1-EXEC-001": ("terminal_history", "worker_invariance", "live_binding"),
        "P2-NODE-001": ("decomposition", "production_composition", "live_validator"),
        "P2-TX-001": ("tx_lifecycle", "tombstone_gc", "live_sign_broadcast"),
        "P2-STORE-001": ("node_commit_ledger", "durable_file_adapters", "power_loss"),
        "MIG-ROOT-001": ("migration_core", "trusted_source_evidence"),
    }
    for blocker_id, keys in required_implementation.items():
        values = ledger_by_id[blocker_id].get("implementation", {})
        for key in keys:
            require(key in values, f"{blocker_id}: implementation fact missing {key}")

    require(
        ledger_by_id["P1-CORE-001"]["implementation"]["live_host"] is False,
        "live host cannot be promoted before exact-source integration evidence",
    )
    require(
        ledger_by_id["P2-NODE-001"]["implementation"]["live_validator"] is False,
        "live validator cannot be promoted before exact-source integration evidence",
    )
    require(
        ledger_by_id["P2-TX-001"]["implementation"]["live_sign_broadcast"] is False,
        "live transaction signing/broadcast cannot be promoted",
    )
    require(
        ledger_by_id["P2-STORE-001"]["implementation"]["power_loss"] is False,
        "physical power-loss evidence cannot be synthesized by repository code",
    )
    require(
        ledger_by_id["MIG-ROOT-001"]["implementation"]["trusted_source_evidence"]
        is False,
        "trusted migration source evidence cannot be synthesized",
    )

    summary = ledger.get("release_summary")
    require(isinstance(summary, dict), "release_summary must be object")
    canonical_open = [
        row for row in truth_by_id.values() if row.get("status") != "closed"
    ]
    external_open = [
        row for row in external_rows if row.get("status") != "closed"
    ]
    settings_open = [
        row for row in settings_rows if row.get("status") != "closed"
    ]
    require(
        summary.get("all_repository_blockers_closed") is (not canonical_open),
        "repository closure summary contradicts canonical register",
    )
    require(
        summary.get("all_external_blockers_closed") is (not external_open),
        "external closure summary contradicts execution rows",
    )
    require(
        summary.get("all_settings_gates_closed") is (not settings_open),
        "settings closure summary contradicts execution rows",
    )
    if canonical_open or external_open or settings_open:
        for claim in (
            "public_testnet_ready",
            "production_candidate",
            "production_consensus_activation",
            "release_ready",
        ):
            require(
                summary.get(claim) is False,
                f"{claim} must remain false while blockers are open",
            )

    report = {
        "schema": "trnm-blocker-execution-validation-v1",
        "observation_date": ledger["as_of"],
        "selected_successor": implementation["selected_successor"],
        "workspace_crates": implementation["workspace_crates"],
        "repository_blockers": len(repository_rows),
        "repository_open": len(canonical_open),
        "settings_open": len(settings_open),
        "external_open": len(external_open),
        "implementation_evidence_separated": True,
        "stale_next_actions": 0,
        "all_gaps_closed": not (
            canonical_open or settings_open or external_open
        ),
        "production_candidate": False,
        "production_consensus_activation": False,
        "release_ready": False,
        "result": "PASS",
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LedgerError, subprocess.CalledProcessError) as error:
        print(f"blocker execution validation failed: {error}", file=sys.stderr)
        raise SystemExit(2)
