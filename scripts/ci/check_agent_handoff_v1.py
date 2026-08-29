#!/usr/bin/env python3
"""Strict standard-library validator for TRNM agent-handoff-v1 envelopes."""
from __future__ import annotations

import argparse
import copy
import json
import re
from pathlib import Path
from typing import Any

SHA40 = re.compile(r"^[0-9a-f]{40}$")
AGENT = re.compile(r"^A(0[0-9]|1[0-7])$")
PACKAGE = re.compile(r"^[A-Z0-9][A-Z0-9_-]{2,127}$")
STATUSES = {
    "WORKING", "MODULE_CLOSED_CANDIDATE", "BLOCKED_UPSTREAM",
    "BASE_DRIFT", "STOP_CONDITION", "RESUME_REQUIRED",
}
AUTHORITIES = {"candidate", "simulation", "normative", "production"}
CLASSIFICATIONS = {
    "candidate-non-normative", "reproducible", "reviewed", "accepted",
    "superseded", "invalidated", "reopened",
}
SCOPE_TOKENS = {
    "crate", "model", "fixture", "simulation", "contract",
    "process-candidate", "process", "host", "network", "production",
}
REQUIRED = {
    "schema", "agent_id", "package_id", "status", "base_commit", "base_tree",
    "head_commit", "changed_paths", "gaps_closed", "gaps_open", "commands",
    "failed_tests", "retained_mutants", "evidence_scope", "authority",
    "classification", "known_gaps", "interface_requests",
    "downstream_invalidation", "next_action",
}
OPTIONAL_SHA = {
    "implementation_commit", "implementation_tree", "implementation_parent",
    "metadata_commit", "base_sync_parent", "control_replay_commit",
    "frozen_workflow_tree", "durable_rust_evidence_head",
    "application_tree_candidate_evidence_head", "publication_commit",
    "publication_tree",
}
ARRAY_FIELDS = {
    "changed_paths", "gaps_closed", "gaps_open", "commands", "failed_tests",
    "retained_mutants", "known_gaps", "interface_requests",
    "downstream_invalidation",
}
ALLOWED = REQUIRED | OPTIONAL_SHA


class HandoffError(ValueError):
    pass


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise HandoffError(f"duplicate-json-key:{key}")
        out[key] = value
    return out


def loads(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=strict_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                HandoffError(f"non-finite-number:{token}")
            ),
        )
    except json.JSONDecodeError as exc:
        raise HandoffError(f"invalid-json:{exc}") from exc
    if not isinstance(value, dict):
        raise HandoffError("root-must-be-object")
    return value


def require_sha(value: Any, field: str) -> None:
    if not isinstance(value, str) or not SHA40.fullmatch(value):
        raise HandoffError(f"invalid-sha40:{field}")


def require_string_array(value: Any, field: str) -> None:
    if not isinstance(value, list):
        raise HandoffError(f"not-array:{field}")
    if any(not isinstance(item, str) or not item for item in value):
        raise HandoffError(f"empty-or-non-string:{field}")
    if len(value) != len(set(value)):
        raise HandoffError(f"duplicate-array-item:{field}")


def validate(value: dict[str, Any]) -> None:
    missing = REQUIRED - value.keys()
    unknown = value.keys() - ALLOWED
    if missing:
        raise HandoffError(f"missing-fields:{','.join(sorted(missing))}")
    if unknown:
        raise HandoffError(f"unknown-fields:{','.join(sorted(unknown))}")
    if value["schema"] != "trnm-agent-handoff-v1":
        raise HandoffError("schema")
    if not isinstance(value["agent_id"], str) or not AGENT.fullmatch(value["agent_id"]):
        raise HandoffError("agent-id")
    if not isinstance(value["package_id"], str) or not PACKAGE.fullmatch(value["package_id"]):
        raise HandoffError("package-id")
    if value["status"] not in STATUSES:
        raise HandoffError("status")
    require_sha(value["base_commit"], "base_commit")
    require_sha(value["base_tree"], "base_tree")
    if value["head_commit"] is None:
        if value["status"] != "WORKING":
            raise HandoffError("null-head-only-allowed-while-working")
    else:
        require_sha(value["head_commit"], "head_commit")
    for field in OPTIONAL_SHA:
        if field in value:
            require_sha(value[field], field)
    if ("implementation_tree" in value) != ("implementation_commit" in value):
        raise HandoffError("implementation-commit-tree-must-be-paired")
    if ("publication_tree" in value) != ("publication_commit" in value):
        raise HandoffError("publication-commit-tree-must-be-paired")
    if ("frozen_workflow_tree" in value) != ("control_replay_commit" in value):
        raise HandoffError("control-commit-workflow-tree-must-be-paired")
    for field in ARRAY_FIELDS:
        require_string_array(value[field], field)
    if value["status"] == "MODULE_CLOSED_CANDIDATE" and not value["gaps_closed"]:
        raise HandoffError("candidate-closure-needs-closed-gap")
    if value["status"] in {"BLOCKED_UPSTREAM", "STOP_CONDITION", "BASE_DRIFT", "RESUME_REQUIRED"} and not value["gaps_open"]:
        raise HandoffError("non-success-terminal-needs-open-gap")
    scope = value["evidence_scope"]
    if not isinstance(scope, str) or not scope:
        raise HandoffError("evidence-scope")
    tokens = scope.split("|")
    if len(tokens) != len(set(tokens)):
        raise HandoffError("duplicate-evidence-scope-token")
    unknown_tokens = set(tokens) - SCOPE_TOKENS
    if unknown_tokens:
        raise HandoffError(f"unknown-evidence-scope:{','.join(sorted(unknown_tokens))}")
    if value["authority"] not in AUTHORITIES:
        raise HandoffError("authority")
    if value["classification"] not in CLASSIFICATIONS:
        raise HandoffError("classification")
    if value["classification"] == "candidate-non-normative" and value["authority"] != "candidate":
        raise HandoffError("candidate-classification-requires-candidate-authority")
    if not isinstance(value["next_action"], str) or not value["next_action"].strip():
        raise HandoffError("next-action")


def valid_fixture() -> dict[str, Any]:
    return {
        "schema": "trnm-agent-handoff-v1",
        "agent_id": "A12",
        "package_id": "G2B_AGENT_MARKET_V1",
        "status": "MODULE_CLOSED_CANDIDATE",
        "base_commit": "1" * 40,
        "base_tree": "2" * 40,
        "head_commit": "3" * 40,
        "implementation_commit": "3" * 40,
        "implementation_tree": "4" * 40,
        "control_replay_commit": "5" * 40,
        "frozen_workflow_tree": "6" * 40,
        "changed_paths": ["a"],
        "gaps_closed": ["GAP-CLOSED"],
        "gaps_open": ["GAP-OPEN"],
        "commands": ["command"],
        "failed_tests": [],
        "retained_mutants": ["mutant"],
        "evidence_scope": "crate|model|fixture",
        "authority": "candidate",
        "classification": "candidate-non-normative",
        "known_gaps": ["gap"],
        "interface_requests": ["request"],
        "downstream_invalidation": ["downstream"],
        "next_action": "independent review",
    }


def self_test() -> None:
    fixture = valid_fixture()
    validate(fixture)
    mutants: list[dict[str, Any]] = []
    for mutate in (
        lambda x: x.update({"unknown": True}),
        lambda x: x.update({"base_commit": "x" * 40}),
        lambda x: x.update({"status": "COMPLETE"}),
        lambda x: x.update({"evidence_scope": "crate|crate"}),
        lambda x: x.update({"evidence_scope": "crate|unbounded"}),
        lambda x: x.update({"authority": "production"}),
        lambda x: x.pop("next_action"),
        lambda x: x.update({"gaps_closed": []}),
        lambda x: x.pop("implementation_tree"),
        lambda x: x.pop("frozen_workflow_tree"),
    ):
        mutant = copy.deepcopy(fixture)
        mutate(mutant)
        mutants.append(mutant)
    for index, mutant in enumerate(mutants):
        try:
            validate(mutant)
        except HandoffError:
            continue
        raise HandoffError(f"mutant-accepted:{index}")
    try:
        loads('{"schema":"trnm-agent-handoff-v1","schema":"duplicate"}')
    except HandoffError:
        pass
    else:
        raise HandoffError("duplicate-key-mutant-accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", action="append", type=Path, default=[])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    if not args.path and not args.self_test:
        parser.error("at least one --path or --self-test is required")
    for path in args.path:
        validate(loads(path.read_text(encoding="utf-8")))
        print(f"agent-handoff-v1: ok: {path}")
    if args.self_test:
        print("agent-handoff-v1 self-test: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
