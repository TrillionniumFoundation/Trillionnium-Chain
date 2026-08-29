#!/usr/bin/env python3
"""Candidate-only independent package review decision evaluator."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable


class Reject(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def commitment(domain: str, value: object) -> str:
    raw = canonical(value)
    digest = hashlib.sha256()
    digest.update(domain.encode("ascii"))
    digest.update(b"\x00")
    digest.update(len(raw).to_bytes(8, "big"))
    digest.update(raw)
    return digest.hexdigest()


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def load_unique(path: Path) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise Reject(f"duplicate-key:{key}")
            result[key] = value
        return result
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise Reject("root-object")
    return value


def is_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)


def require_hex(value: object, length: int, label: str) -> str:
    if not is_hex(value, length):
        raise Reject(label)
    return str(value)


def require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise Reject(label)
    return value


def validate_template(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("schema") != "trnm-independent-package-review-decision-v1":
        raise Reject("schema")
    if value.get("classification") != "candidate-non-normative":
        raise Reject("classification")
    if value.get("decision_id") != "UNASSIGNED" or value.get("status") != "NOT_REVIEWED":
        raise Reject("template-status")
    if value["replay"]["exact_head_completed_success"] is not False:
        raise Reject("template-replay")
    if value["mutants"]["all_p0_replayed"] is not False:
        raise Reject("template-mutants")
    for key, field in value["decision"].items():
        if key in {"reason", "decision_root"}:
            if field is not None:
                raise Reject(f"template-decision:{key}")
        elif field is not False:
            raise Reject(f"template-decision:{key}")
    if value["signatures"] != []:
        raise Reject("template-signatures")
    return {
        "schema": "trnm-independent-review-template-validation-v1",
        "valid": True,
        "real_review_present": False,
        "package_candidate_accepted": False,
        "interface_candidate_accepted": False,
    }


def evaluate(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("schema") != "trnm-independent-package-review-decision-v1":
        raise Reject("schema")
    if value.get("classification") != "candidate-non-normative":
        raise Reject("classification")
    decision_id = require_text(value.get("decision_id"), "decision-id")
    if decision_id == "UNASSIGNED" or value.get("status") != "REVIEWED_CANDIDATE_DECISION":
        raise Reject("decision-status")
    if value.get("repository") != "TrillionniumFoundation/Trillionnium-Chain":
        raise Reject("repository")

    package = value["package"]
    agent = require_text(package.get("agent_id"), "agent-id")
    package_id = require_text(package.get("package_id"), "package-id")
    if not agent.startswith("A") or len(agent) != 3 or not agent[1:].isdigit():
        raise Reject("agent-id")
    pr = package.get("pull_request")
    if not isinstance(pr, int) or isinstance(pr, bool) or pr <= 0:
        raise Reject("pull-request")
    require_text(package.get("branch"), "branch")
    for key in ("commit", "tree", "base_commit", "base_tree"):
        require_hex(package.get(key), 40, f"package:{key}")
    for key in ("handoff_path", "source_manifest_path"):
        require_text(package.get(key), f"package:{key}")
    for key in ("handoff_git_blob", "source_manifest_git_blob"):
        require_hex(package.get(key), 40, f"package:{key}")
    for key in ("handoff_sha256", "source_manifest_sha256"):
        require_hex(package.get(key), 64, f"package:{key}")

    reviewer = value["reviewer"]
    reviewer_identity = require_text(reviewer.get("identity"), "reviewer-identity")
    require_text(reviewer.get("organization"), "reviewer-organization")
    require_text(reviewer.get("role"), "reviewer-role")
    if reviewer.get("is_package_author") is not False or reviewer.get("is_package_committer") is not False:
        raise Reject("reviewer-not-independent")
    if reviewer.get("is_campaign_operator") is not False:
        raise Reject("reviewer-campaign-conflict")
    require_text(reviewer.get("conflict_disclosure"), "conflict-disclosure")
    require_hex(reviewer.get("independence_declaration_sha256"), 64, "independence-root")

    replay = value["replay"]
    require_text(replay.get("workflow_name"), "workflow-name")
    run_id = replay.get("workflow_run_id")
    if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
        raise Reject("workflow-run-id")
    if replay.get("workflow_head_sha") != package["commit"]:
        raise Reject("workflow-head")
    if replay.get("workflow_status") != "completed" or replay.get("workflow_conclusion") != "success":
        raise Reject("workflow-result")
    require_text(replay.get("runner_identity"), "runner-identity")
    require_text(replay.get("toolchain_identity"), "toolchain-identity")
    require_hex(replay.get("command_manifest_root"), 64, "command-manifest-root")
    require_hex(replay.get("raw_log_sha256"), 64, "raw-log-root")
    if replay.get("exact_head_completed_success") is not True:
        raise Reject("exact-head-success")

    mutants = value["mutants"]
    require_hex(mutants.get("corpus_root"), 64, "mutant-corpus-root")
    p0_ids = mutants.get("p0_ids")
    if not isinstance(p0_ids, list) or not p0_ids or not all(isinstance(item, str) and item for item in p0_ids):
        raise Reject("p0-mutants")
    if len(p0_ids) != len(set(p0_ids)):
        raise Reject("duplicate-p0-mutant")
    if mutants.get("all_p0_replayed") is not True:
        raise Reject("p0-replay-incomplete")
    accepted = mutants.get("accepted_mutants")
    if accepted != []:
        raise Reject("accepted-mutant")
    rejected = mutants.get("rejected_mutants")
    if not isinstance(rejected, list) or set(rejected) != set(p0_ids):
        raise Reject("p0-rejection-set")
    require_hex(mutants.get("replay_evidence_root"), 64, "mutant-replay-root")

    interfaces = value["interfaces"]
    requested = interfaces.get("requested")
    accepted_interfaces = interfaces.get("accepted")
    rejected_interfaces = interfaces.get("rejected")
    if not all(isinstance(items, list) for items in (requested, accepted_interfaces, rejected_interfaces)):
        raise Reject("interface-lists")
    if set(accepted_interfaces) & set(rejected_interfaces):
        raise Reject("interface-decision-conflict")
    if not set(accepted_interfaces).issubset(set(requested)) or not set(rejected_interfaces).issubset(set(requested)):
        raise Reject("interface-not-requested")
    if set(accepted_interfaces) | set(rejected_interfaces) != set(requested):
        raise Reject("interface-undecided")
    bundle_root = interfaces.get("accepted_interface_bundle_root")
    if accepted_interfaces:
        require_hex(bundle_root, 64, "accepted-interface-bundle-root")
    elif bundle_root is not None:
        raise Reject("unexpected-interface-bundle-root")

    findings = value["findings"]
    for key in ("open_critical", "open_high", "open_medium", "open_low"):
        count = findings.get(key)
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise Reject(f"finding-count:{key}")
    if findings["open_critical"] != 0 or findings["open_high"] != 0:
        raise Reject("open-critical-high")
    require_hex(findings.get("finding_ledger_root"), 64, "finding-ledger-root")

    decision = value["decision"]
    if decision.get("package_candidate_accepted") is not True:
        raise Reject("package-candidate-not-accepted")
    interface_accepted = bool(accepted_interfaces)
    if decision.get("interface_candidate_accepted") is not interface_accepted:
        raise Reject("interface-candidate-decision")
    for key in ("gate_exit_authorized", "merge_authorized", "release_authorized", "production_activation_authorized"):
        if decision.get(key) is not False:
            raise Reject(f"forbidden-authority:{key}")
    reason = require_text(decision.get("reason"), "decision-reason")

    invalidation = value.get("downstream_invalidation")
    if not isinstance(invalidation, list) or not invalidation or not all(isinstance(item, str) and item for item in invalidation):
        raise Reject("downstream-invalidation")
    reopen = value.get("reopen_on")
    if not isinstance(reopen, list) or len(reopen) < 8:
        raise Reject("reopen-set")

    signatures = value.get("signatures")
    if not isinstance(signatures, list) or len(signatures) < 2:
        raise Reject("signature-count")
    roles: set[str] = set()
    signers: set[str] = set()
    for signature in signatures:
        if not isinstance(signature, dict):
            raise Reject("signature-shape")
        role = require_text(signature.get("role"), "signature-role")
        signer = require_text(signature.get("signer"), "signature-signer")
        require_hex(signature.get("statement_sha256"), 64, "signature-statement")
        require_hex(signature.get("signature_sha256"), 64, "signature-digest")
        if role in roles or signer in signers:
            raise Reject("duplicate-signature-role-or-signer")
        roles.add(role)
        signers.add(signer)
    if "independent-reviewer" not in roles or "control-witness" not in roles:
        raise Reject("signature-role-set")
    if reviewer_identity not in signers:
        raise Reject("reviewer-signature-missing")

    committed = copy.deepcopy(value)
    committed["decision"]["decision_root"] = None
    committed.pop("notes", None)
    root = commitment("trnm.independent-package-review.v1", committed)
    supplied = decision.get("decision_root")
    if supplied not in {None, root}:
        raise Reject("decision-root")
    return {
        "schema": "trnm-independent-package-review-result-v1",
        "decision_id": decision_id,
        "agent_id": agent,
        "package_id": package_id,
        "package_commit": package["commit"],
        "package_tree": package["tree"],
        "package_candidate_accepted": True,
        "interface_candidate_accepted": interface_accepted,
        "gate_exit_authorized": False,
        "merge_authorized": False,
        "release_authorized": False,
        "production_activation_authorized": False,
        "decision_root": root,
        "reason": reason,
    }


def fixture() -> dict[str, Any]:
    commit = hashlib.sha1(b"package-commit").hexdigest()
    requested = ["ICR-A", "ICR-B"]
    return {
        "schema": "trnm-independent-package-review-decision-v1",
        "classification": "candidate-non-normative",
        "decision_id": "synthetic-review-self-test",
        "status": "REVIEWED_CANDIDATE_DECISION",
        "repository": "TrillionniumFoundation/Trillionnium-Chain",
        "package": {
            "agent_id": "A16", "package_id": "G2F_WHOLE_NODE_LIGHT_CLIENT_V1",
            "pull_request": 37, "branch": "feature/example", "commit": commit,
            "tree": hashlib.sha1(b"package-tree").hexdigest(),
            "base_commit": hashlib.sha1(b"base-commit").hexdigest(),
            "base_tree": hashlib.sha1(b"base-tree").hexdigest(),
            "handoff_path": "docs/evidence/handoff.json",
            "handoff_git_blob": hashlib.sha1(b"handoff-blob").hexdigest(),
            "handoff_sha256": digest("handoff"),
            "source_manifest_path": "docs/evidence/source.json",
            "source_manifest_git_blob": hashlib.sha1(b"source-blob").hexdigest(),
            "source_manifest_sha256": digest("source"),
        },
        "reviewer": {
            "identity": "reviewer-1", "organization": "review-org", "role": "independent-reviewer",
            "is_package_author": False, "is_package_committer": False,
            "is_campaign_operator": False, "conflict_disclosure": "no-conflict",
            "independence_declaration_sha256": digest("independence"),
        },
        "replay": {
            "workflow_name": "TRNM payload replay recovery v1 gate", "workflow_run_id": 1,
            "workflow_head_sha": commit, "workflow_status": "completed", "workflow_conclusion": "success",
            "runner_identity": "runner-1", "toolchain_identity": "rust-1.95.0",
            "command_manifest_root": digest("commands"), "raw_log_sha256": digest("logs"),
            "exact_head_completed_success": True,
        },
        "mutants": {
            "corpus_root": digest("mutants"), "p0_ids": ["M-1", "M-2"],
            "all_p0_replayed": True, "accepted_mutants": [], "rejected_mutants": ["M-1", "M-2"],
            "replay_evidence_root": digest("mutant-replay"),
        },
        "interfaces": {
            "requested": requested, "accepted": ["ICR-A"], "rejected": ["ICR-B"],
            "accepted_interface_bundle_root": digest("interface-bundle"),
        },
        "findings": {
            "open_critical": 0, "open_high": 0, "open_medium": 1, "open_low": 2,
            "finding_ledger_root": digest("finding-ledger"),
        },
        "decision": {
            "package_candidate_accepted": True, "interface_candidate_accepted": True,
            "gate_exit_authorized": False, "merge_authorized": False,
            "release_authorized": False, "production_activation_authorized": False,
            "reason": "synthetic candidate acceptance only", "decision_root": None,
        },
        "downstream_invalidation": ["A17 evidence", "release evidence"],
        "reopen_on": [
            "package commit or tree change", "base commit or tree change", "handoff change",
            "source manifest change", "mutant corpus change", "workflow change",
            "toolchain change", "finding reopened",
        ],
        "signatures": [
            {"role": "independent-reviewer", "signer": "reviewer-1", "statement_sha256": digest("review-statement"), "signature_sha256": digest("review-signature")},
            {"role": "control-witness", "signer": "witness-2", "statement_sha256": digest("witness-statement"), "signature_sha256": digest("witness-signature")},
        ],
        "notes": ["synthetic self-test only"],
    }


def set_path(value: dict[str, Any], path: str, replacement: Any) -> dict[str, Any]:
    changed = copy.deepcopy(value)
    current: Any = changed
    parts = path.split(".")
    for part in parts[:-1]:
        current = current[part]
    current[parts[-1]] = replacement
    return changed


def self_test(template_path: Path) -> dict[str, Any]:
    template = validate_template(load_unique(template_path))
    complete = fixture()
    first = evaluate(complete)
    second = evaluate(copy.deepcopy(complete))
    if first != second:
        raise AssertionError("nondeterministic-review")
    negatives: list[dict[str, str]] = []
    def reject(name: str, operation: Callable[[], object]) -> None:
        try:
            operation()
        except Reject as error:
            negatives.append({"case": name, "error": str(error)})
        else:
            raise AssertionError(f"accepted:{name}")
    cases = [
        ("unassigned", "decision_id", "UNASSIGNED"),
        ("wrong-status", "status", "NOT_REVIEWED"),
        ("bad-commit", "package.commit", "0" * 39),
        ("reviewer-is-author", "reviewer.is_package_author", True),
        ("reviewer-is-committer", "reviewer.is_package_committer", True),
        ("reviewer-campaign-conflict", "reviewer.is_campaign_operator", True),
        ("stale-workflow-head", "replay.workflow_head_sha", hashlib.sha1(b"other").hexdigest()),
        ("workflow-failed", "replay.workflow_conclusion", "failure"),
        ("not-exact-success", "replay.exact_head_completed_success", False),
        ("p0-not-replayed", "mutants.all_p0_replayed", False),
        ("accepted-mutant", "mutants.accepted_mutants", ["M-1"]),
        ("missing-p0-rejection", "mutants.rejected_mutants", ["M-1"]),
        ("interface-conflict", "interfaces.rejected", ["ICR-A", "ICR-B"]),
        ("missing-interface-root", "interfaces.accepted_interface_bundle_root", None),
        ("open-critical", "findings.open_critical", 1),
        ("open-high", "findings.open_high", 1),
        ("gate-authorized", "decision.gate_exit_authorized", True),
        ("merge-authorized", "decision.merge_authorized", True),
        ("release-authorized", "decision.release_authorized", True),
        ("production-authorized", "decision.production_activation_authorized", True),
        ("candidate-not-accepted", "decision.package_candidate_accepted", False),
        ("missing-invalidation", "downstream_invalidation", []),
        ("missing-witness", "signatures", complete["signatures"][:1]),
    ]
    for name, path, replacement in cases:
        reject(name, lambda p=path, r=replacement: evaluate(set_path(complete, p, r)))
    rooted = copy.deepcopy(complete)
    rooted["decision"]["decision_root"] = first["decision_root"]
    if evaluate(rooted)["decision_root"] != first["decision_root"]:
        raise AssertionError("rooted-decision-drift")
    reject("wrong-decision-root", lambda: evaluate(set_path(complete, "decision.decision_root", "0" * 64)))
    return {
        "schema": "trnm-independent-package-review-gate-self-test-v1",
        "template": template,
        "synthetic_positive": 3,
        "negative": negatives,
        "synthetic_decision_root": first["decision_root"],
        "real_review_present": False,
        "package_candidate_accepted": False,
        "interface_candidate_accepted": False,
        "gate_exit_authorized": False,
        "merge_authorized": False,
        "release_authorized": False,
        "production_activation_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=Path, default=Path("docs/development/agents/INDEPENDENT_PACKAGE_REVIEW_DECISION_V1.json"))
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--evaluate", type=Path)
    parser.add_argument("--allow-candidate-review-evaluation", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        output = self_test(args.template)
    elif args.evaluate is not None:
        if not args.allow_candidate_review_evaluation:
            raise SystemExit("--allow-candidate-review-evaluation is required")
        output = evaluate(load_unique(args.evaluate))
    else:
        output = validate_template(load_unique(args.template))
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
