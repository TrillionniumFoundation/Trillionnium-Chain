#!/usr/bin/env python3
"""Fail-closed evaluator for real external-evidence campaign envelopes.

The self-test uses synthetic complete evidence solely to exercise deterministic
validation and retained negative mutants. It does not create benchmark,
public-testnet, release, production, HSM, audit or governance evidence.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any, Callable


class Reject(ValueError):
    pass


def load_unique(path: Path) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in rows:
            if key in value:
                raise Reject(f"duplicate-key:{key}")
            value[key] = item
        return value
    raw = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    if not isinstance(raw, dict):
        raise Reject("root-object")
    return raw


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def commitment(domain: str, value: object) -> str:
    raw = canonical(value)
    digest = hashlib.sha256()
    digest.update(domain.encode("ascii"))
    digest.update(b"\x00")
    digest.update(len(raw).to_bytes(8, "big"))
    digest.update(raw)
    return digest.hexdigest()


def is_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(
        character in "0123456789abcdef" for character in value
    )


def require_hex(value: object, length: int, label: str) -> str:
    if not is_hex(value, length):
        raise Reject(label)
    return str(value)


def require_true(value: object, label: str) -> None:
    if value is not True:
        raise Reject(label)


def require_false(value: object, label: str) -> None:
    if value is not False:
        raise Reject(label)


def require_nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise Reject(label)
    return value


def parse_time(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str):
        raise Reject(label)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as error:
        raise Reject(label) from error
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise Reject(label)
    return parsed


def duration_hours(start: object, end: object, label: str) -> float:
    start_value = parse_time(start, f"{label}-start")
    end_value = parse_time(end, f"{label}-end")
    if end_value < start_value:
        raise Reject(f"{label}-order")
    return (end_value - start_value).total_seconds() / 3600.0


def validate_template(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("schema") != "trnm-external-evidence-campaign-v1":
        raise Reject("schema")
    if value.get("classification") != "candidate-non-normative":
        raise Reject("classification")
    if value.get("campaign_id") != "UNASSIGNED" or value.get("status") != "NOT_STARTED":
        raise Reject("template-status")

    source = value["source"]
    for key in (
        "release_commit", "release_tree", "binary_sha256", "sbom_sha256",
        "genesis_sha256", "configuration_root", "toolchain_identity",
    ):
        if source[key] is not None:
            raise Reject(f"template-source:{key}")

    for key, enabled in value["prerequisites"].items():
        require_false(enabled, f"template-prerequisite:{key}")

    topology = value["topology"]
    for key in ("validator_processes", "physical_hosts", "operators", "regions", "custody_domains"):
        if topology[key] != 0:
            raise Reject(f"template-topology:{key}")

    hsm = value["external_anchor_hsm"]
    for key in ("non_exportable_key", "quorum_custody", "monotonic_authority_external_to_node_namespace"):
        require_false(hsm[key], f"template-hsm:{key}")

    faults = value["physical_faults"]
    for key in (
        "power_loss_executed", "host_reboot_executed", "controller_cache_loss_executed",
        "disk_full_executed", "torn_write_executed", "independent_recovery_process",
    ):
        require_false(faults[key], f"template-fault:{key}")

    network = value["network_campaign"]
    for key in (
        "four_validator_run", "seven_validator_run", "partition_3_1", "partition_2_2",
        "partition_5_2", "weighted_partition_4_3", "offline_rejoin",
        "leader_crash_timeout_certificate", "restart_catchup", "state_sync",
        "epoch_rotation", "signer_rotation", "signer_outage",
    ):
        require_false(network[key], f"template-network:{key}")

    for key, enabled in value["claims"].items():
        require_false(enabled, f"template-claim:{key}")
    if value["signatures"] != []:
        raise Reject("template-signatures")
    return {
        "schema": "trnm-external-evidence-template-validation-v1",
        "valid": True,
        "real_evidence_present": False,
        "claim_authorized": False,
    }


def evaluate(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("schema") != "trnm-external-evidence-campaign-v1":
        raise Reject("schema")
    if value.get("classification") != "candidate-non-normative":
        raise Reject("classification")
    campaign_id = require_nonempty(value.get("campaign_id"), "campaign-id")
    if campaign_id == "UNASSIGNED" or value.get("status") != "COMPLETED_CANDIDATE_EVIDENCE":
        raise Reject("campaign-status")

    source = value["source"]
    if source.get("repository") != "TrillionniumFoundation/Trillionnium-Chain":
        raise Reject("repository")
    require_hex(source.get("release_commit"), 40, "release-commit")
    require_hex(source.get("release_tree"), 40, "release-tree")
    for key in ("binary_sha256", "sbom_sha256", "genesis_sha256", "configuration_root"):
        require_hex(source.get(key), 64, key)
    require_nonempty(source.get("toolchain_identity"), "toolchain-identity")

    independence = value["independence"]
    author = require_nonempty(independence.get("package_author"), "package-author")
    operator = require_nonempty(independence.get("campaign_operator"), "campaign-operator")
    reviewer = require_nonempty(independence.get("reviewer"), "reviewer")
    require_nonempty(independence.get("auditor_organization"), "auditor-organization")
    if len({author, operator, reviewer}) != 3:
        raise Reject("role-separation")
    require_false(independence.get("operator_is_package_author"), "operator-independence")
    require_false(independence.get("reviewer_is_package_author"), "reviewer-independence")
    require_nonempty(independence.get("conflict_disclosure"), "conflict-disclosure")
    require_hex(independence.get("independence_declaration_sha256"), 64, "independence-root")

    prerequisites = value["prerequisites"]
    required_prerequisites = (
        "accepted_g0", "accepted_g1", "accepted_g15", "accepted_g20",
        "accepted_g2a", "accepted_g2b", "accepted_g2c", "accepted_g2d",
        "accepted_g2e", "accepted_g2f", "all_p0_mutants_independently_replayed",
        "zero_open_critical", "zero_open_high",
    )
    if set(prerequisites) != set(required_prerequisites):
        raise Reject("prerequisite-set")
    for key in required_prerequisites:
        require_true(prerequisites[key], f"prerequisite:{key}")

    topology = value["topology"]
    counts = {
        key: topology[key]
        for key in ("validator_processes", "physical_hosts", "operators", "regions", "custody_domains")
    }
    if not all(isinstance(item, int) and not isinstance(item, bool) for item in counts.values()):
        raise Reject("topology-type")
    if (
        counts["validator_processes"] < 100
        or counts["physical_hosts"] < 7
        or counts["operators"] < 5
        or counts["regions"] < 3
        or counts["custody_domains"] < 3
    ):
        raise Reject("topology-insufficient")
    if (
        counts["physical_hosts"] > counts["validator_processes"]
        or counts["operators"] > counts["validator_processes"]
        or counts["regions"] > counts["physical_hosts"]
        or counts["custody_domains"] > counts["operators"]
    ):
        raise Reject("topology-overclaim")
    for key in ("host_inventory_sha256", "operator_identity_root", "custody_identity_root", "network_topology_root"):
        require_hex(topology.get(key), 64, key)

    hsm = value["external_anchor_hsm"]
    for key in ("provider", "device_or_service_model", "firmware_or_service_version"):
        require_nonempty(hsm.get(key), f"hsm:{key}")
    for key in ("non_exportable_key", "quorum_custody", "monotonic_authority_external_to_node_namespace"):
        require_true(hsm.get(key), f"hsm:{key}")
    for key in (
        "key_generation_ceremony_root", "rotation_ceremony_root", "revocation_ceremony_root",
        "rollback_rejection_trace_root", "cloned_namespace_rejection_trace_root",
        "disaster_recovery_trace_root", "custody_audit_root",
    ):
        require_hex(hsm.get(key), 64, f"hsm:{key}")

    faults = value["physical_faults"]
    for key in (
        "power_loss_executed", "host_reboot_executed", "controller_cache_loss_executed",
        "disk_full_executed", "torn_write_executed", "independent_recovery_process",
    ):
        require_true(faults.get(key), f"fault:{key}")
    for key in ("fault_schedule_root", "raw_trace_root", "recovery_or_quarantine_decision_root"):
        require_hex(faults.get(key), 64, f"fault:{key}")

    network = value["network_campaign"]
    required_network = (
        "four_validator_run", "seven_validator_run", "partition_3_1", "partition_2_2",
        "partition_5_2", "weighted_partition_4_3", "offline_rejoin",
        "leader_crash_timeout_certificate", "restart_catchup", "state_sync",
        "epoch_rotation", "signer_rotation", "signer_outage",
    )
    for key in required_network:
        require_true(network.get(key), f"network:{key}")
    for key in ("conflicting_finality_observed", "double_sign_observed", "state_root_divergence_observed"):
        require_false(network.get(key), f"network:{key}")
    for key in ("signed_raw_trace_root", "result_root"):
        require_hex(network.get(key), 64, f"network:{key}")

    benchmark = value["benchmark"]
    for key in ("workload_root", "comparator_root", "raw_trace_root"):
        require_hex(benchmark.get(key), 64, f"benchmark:{key}")
    require_true(benchmark.get("same_hardware"), "benchmark:same-hardware")
    require_true(benchmark.get("same_workload"), "benchmark:same-workload")
    for key in ("submitted_tps", "committed_goodput"):
        metric = benchmark.get(key)
        if not isinstance(metric, (int, float)) or isinstance(metric, bool) or metric <= 0:
            raise Reject(f"benchmark:{key}")
    if benchmark["committed_goodput"] > benchmark["submitted_tps"]:
        raise Reject("benchmark:goodput-over-ingress")
    for key in (
        "order_p50_ms", "order_p99_ms", "result_p50_ms", "result_p99_ms",
        "settlement_p50_ms", "settlement_p99_ms",
    ):
        metric = benchmark.get(key)
        if not isinstance(metric, int) or isinstance(metric, bool) or metric <= 0:
            raise Reject(f"benchmark:{key}")
    for median, tail in (
        ("order_p50_ms", "order_p99_ms"),
        ("result_p50_ms", "result_p99_ms"),
        ("settlement_p50_ms", "settlement_p99_ms"),
    ):
        if benchmark[median] > benchmark[tail]:
            raise Reject(f"benchmark:percentile-order:{median}")
    repetitions = benchmark.get("repetition_roots")
    if not isinstance(repetitions, list) or len(repetitions) < 3:
        raise Reject("benchmark:repetitions")
    if len(repetitions) != len(set(repetitions)):
        raise Reject("benchmark:duplicate-repetition")
    for root in repetitions:
        require_hex(root, 64, "benchmark:repetition-root")

    security = value["security_review"]
    for key in ("consensus_audit_complete", "cryptography_audit_complete", "economic_review_complete", "red_team_complete"):
        require_true(security.get(key), f"security:{key}")
    for key in (
        "consensus_report_sha256", "cryptography_report_sha256", "economic_report_sha256",
        "red_team_report_sha256", "finding_ledger_root",
    ):
        require_hex(security.get(key), 64, f"security:{key}")
    if security.get("open_critical") != 0 or security.get("open_high") != 0:
        raise Reject("security:open-critical-high")

    operations = value["operations"]
    if duration_hours(operations.get("chaos_72h_started_at"), operations.get("chaos_72h_completed_at"), "chaos") < 72:
        raise Reject("operations:chaos-duration")
    if duration_hours(operations.get("public_testnet_7d_started_at"), operations.get("public_testnet_7d_completed_at"), "testnet") < 168:
        raise Reject("operations:testnet-duration")
    if duration_hours(operations.get("production_candidate_30d_started_at"), operations.get("production_candidate_30d_completed_at"), "production-candidate") < 720:
        raise Reject("operations:production-candidate-duration")
    for key in ("incident_drill", "restore_drill", "key_rotation_drill", "state_sync_drill", "observability_drill"):
        require_true(operations.get(key), f"operations:{key}")
    for key in (
        "slo_report_root", "incident_report_root", "restore_report_root",
        "key_rotation_report_root", "state_sync_report_root", "observability_report_root",
    ):
        require_hex(operations.get(key), 64, f"operations:{key}")

    governance = value["governance"]
    for key in ("proposal_id",):
        require_nonempty(governance.get(key), f"governance:{key}")
    for key in ("proposal_root", "voter_set_root", "approval_root", "activation_ceremony_root"):
        require_hex(governance.get(key), 64, f"governance:{key}")
    require_true(governance.get("authorized"), "governance:authorized")
    height = governance.get("activation_height")
    if not isinstance(height, int) or isinstance(height, bool) or height <= 0:
        raise Reject("governance:activation-height")

    claims = value["claims"]
    for key in (
        "benchmark_results_present", "scoped_surpass_claim_allowed", "public_testnet_ready",
        "production_candidate", "production_consensus_activation", "release_ready",
    ):
        require_true(claims.get(key), f"claim:{key}")

    signatures = value.get("signatures")
    if not isinstance(signatures, list) or len(signatures) < 5:
        raise Reject("signatures-count")
    roles: set[str] = set()
    for signature in signatures:
        if not isinstance(signature, dict):
            raise Reject("signature-shape")
        role = require_nonempty(signature.get("role"), "signature-role")
        require_nonempty(signature.get("signer"), "signature-signer")
        require_hex(signature.get("statement_sha256"), 64, "signature-statement")
        require_hex(signature.get("signature_sha256"), 64, "signature-digest")
        if role in roles:
            raise Reject("signature-role-duplicate")
        roles.add(role)
    required_roles = {"independent-reviewer", "campaign-operator", "security-custodian", "external-auditor", "governance-authority"}
    if not required_roles.issubset(roles):
        raise Reject("signature-role-set")

    committed = copy.deepcopy(value)
    committed.pop("notes", None)
    evidence_root = commitment("trnm.external-evidence-campaign.v1", committed)
    return {
        "schema": "trnm-external-evidence-campaign-decision-v1",
        "campaign_id": campaign_id,
        "authorized": True,
        "evidence_root": evidence_root,
        "release_commit": source["release_commit"],
        "release_tree": source["release_tree"],
        "activation_height": height,
    }


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def fixture() -> dict[str, Any]:
    start = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
    def stamp(hours: int) -> str:
        return (start + dt.timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    roots = lambda prefix, count: [digest(f"{prefix}-{index}") for index in range(count)]
    return {
        "schema": "trnm-external-evidence-campaign-v1",
        "classification": "candidate-non-normative",
        "campaign_id": "synthetic-self-test-campaign",
        "status": "COMPLETED_CANDIDATE_EVIDENCE",
        "source": {
            "repository": "TrillionniumFoundation/Trillionnium-Chain",
            "release_commit": hashlib.sha1(b"release-commit").hexdigest(),
            "release_tree": hashlib.sha1(b"release-tree").hexdigest(),
            "binary_sha256": digest("binary"), "sbom_sha256": digest("sbom"),
            "genesis_sha256": digest("genesis"), "configuration_root": digest("configuration"),
            "toolchain_identity": "rust-1.95.0-x86_64-unknown-linux-gnu",
        },
        "independence": {
            "package_author": "author-a", "campaign_operator": "operator-b",
            "reviewer": "reviewer-c", "auditor_organization": "auditor-d",
            "operator_is_package_author": False, "reviewer_is_package_author": False,
            "conflict_disclosure": "no-conflict", "independence_declaration_sha256": digest("independence"),
        },
        "prerequisites": {
            "accepted_g0": True, "accepted_g1": True, "accepted_g15": True,
            "accepted_g20": True, "accepted_g2a": True, "accepted_g2b": True,
            "accepted_g2c": True, "accepted_g2d": True, "accepted_g2e": True,
            "accepted_g2f": True, "all_p0_mutants_independently_replayed": True,
            "zero_open_critical": True, "zero_open_high": True,
        },
        "topology": {
            "validator_processes": 100, "physical_hosts": 20, "operators": 10,
            "regions": 5, "custody_domains": 5, "host_inventory_sha256": digest("hosts"),
            "operator_identity_root": digest("operators"), "custody_identity_root": digest("custody"),
            "network_topology_root": digest("topology"),
        },
        "external_anchor_hsm": {
            "provider": "synthetic-provider", "device_or_service_model": "synthetic-model",
            "firmware_or_service_version": "synthetic-version", "non_exportable_key": True,
            "quorum_custody": True, "monotonic_authority_external_to_node_namespace": True,
            "key_generation_ceremony_root": digest("keygen"), "rotation_ceremony_root": digest("rotation"),
            "revocation_ceremony_root": digest("revocation"), "rollback_rejection_trace_root": digest("rollback"),
            "cloned_namespace_rejection_trace_root": digest("clone"), "disaster_recovery_trace_root": digest("dr"),
            "custody_audit_root": digest("custody-audit"),
        },
        "physical_faults": {
            "power_loss_executed": True, "host_reboot_executed": True,
            "controller_cache_loss_executed": True, "disk_full_executed": True,
            "torn_write_executed": True, "independent_recovery_process": True,
            "fault_schedule_root": digest("fault-schedule"), "raw_trace_root": digest("fault-traces"),
            "recovery_or_quarantine_decision_root": digest("fault-decisions"),
        },
        "network_campaign": {
            "four_validator_run": True, "seven_validator_run": True,
            "partition_3_1": True, "partition_2_2": True, "partition_5_2": True,
            "weighted_partition_4_3": True, "offline_rejoin": True,
            "leader_crash_timeout_certificate": True, "restart_catchup": True,
            "state_sync": True, "epoch_rotation": True, "signer_rotation": True,
            "signer_outage": True, "conflicting_finality_observed": False,
            "double_sign_observed": False, "state_root_divergence_observed": False,
            "signed_raw_trace_root": digest("network-traces"), "result_root": digest("network-result"),
        },
        "benchmark": {
            "workload_root": digest("workload"), "comparator_root": digest("comparator"),
            "same_hardware": True, "same_workload": True, "submitted_tps": 120.0,
            "committed_goodput": 100.0, "order_p50_ms": 200, "order_p99_ms": 500,
            "result_p50_ms": 2000, "result_p99_ms": 5000,
            "settlement_p50_ms": 5000, "settlement_p99_ms": 10000,
            "raw_trace_root": digest("benchmark-traces"), "repetition_roots": roots("repetition", 3),
        },
        "security_review": {
            "consensus_audit_complete": True, "cryptography_audit_complete": True,
            "economic_review_complete": True, "red_team_complete": True,
            "consensus_report_sha256": digest("consensus-report"),
            "cryptography_report_sha256": digest("crypto-report"),
            "economic_report_sha256": digest("economic-report"),
            "red_team_report_sha256": digest("redteam-report"),
            "finding_ledger_root": digest("findings"), "open_critical": 0, "open_high": 0,
        },
        "operations": {
            "chaos_72h_started_at": stamp(0), "chaos_72h_completed_at": stamp(72),
            "public_testnet_7d_started_at": stamp(100), "public_testnet_7d_completed_at": stamp(268),
            "production_candidate_30d_started_at": stamp(300), "production_candidate_30d_completed_at": stamp(1020),
            "incident_drill": True, "restore_drill": True, "key_rotation_drill": True,
            "state_sync_drill": True, "observability_drill": True,
            "slo_report_root": digest("slo"), "incident_report_root": digest("incident"),
            "restore_report_root": digest("restore"), "key_rotation_report_root": digest("key-rotation"),
            "state_sync_report_root": digest("state-sync"), "observability_report_root": digest("observability"),
        },
        "governance": {
            "proposal_id": "synthetic-proposal", "proposal_root": digest("proposal"),
            "voter_set_root": digest("voters"), "approval_root": digest("approval"),
            "activation_ceremony_root": digest("activation"), "authorized": True,
            "activation_height": 100000,
        },
        "claims": {
            "benchmark_results_present": True, "scoped_surpass_claim_allowed": True,
            "public_testnet_ready": True, "production_candidate": True,
            "production_consensus_activation": True, "release_ready": True,
        },
        "signatures": [
            {"role": role, "signer": f"{role}-signer", "statement_sha256": digest(f"{role}-statement"), "signature_sha256": digest(f"{role}-signature")}
            for role in (
                "independent-reviewer", "campaign-operator", "security-custodian",
                "external-auditor", "governance-authority",
            )
        ],
        "notes": ["synthetic self-test only"],
    }


def set_path(value: dict[str, Any], path: str, replacement: Any) -> dict[str, Any]:
    changed = copy.deepcopy(value)
    current: Any = changed
    parts = path.split(".")
    for item in parts[:-1]:
        current = current[item]
    current[parts[-1]] = replacement
    return changed


def self_test(template_path: Path) -> dict[str, Any]:
    template = validate_template(load_unique(template_path))
    complete = fixture()
    first = evaluate(complete)
    second = evaluate(copy.deepcopy(complete))
    if first != second:
        raise AssertionError("nondeterministic-decision")

    negatives: list[dict[str, str]] = []
    def reject(name: str, operation: Callable[[], object]) -> None:
        try:
            operation()
        except Reject as error:
            negatives.append({"case": name, "error": str(error)})
        else:
            raise AssertionError(f"accepted:{name}")

    cases = [
        ("unassigned-campaign", "campaign_id", "UNASSIGNED"),
        ("wrong-status", "status", "NOT_STARTED"),
        ("bad-commit", "source.release_commit", "0" * 39),
        ("same-reviewer-author", "independence.reviewer", "author-a"),
        ("operator-is-author", "independence.operator_is_package_author", True),
        ("missing-g1", "prerequisites.accepted_g1", False),
        ("p0-not-replayed", "prerequisites.all_p0_mutants_independently_replayed", False),
        ("too-few-processes", "topology.validator_processes", 99),
        ("too-few-hosts", "topology.physical_hosts", 6),
        ("topology-overclaim", "topology.regions", 21),
        ("exportable-key", "external_anchor_hsm.non_exportable_key", False),
        ("node-local-anchor", "external_anchor_hsm.monotonic_authority_external_to_node_namespace", False),
        ("no-power-loss", "physical_faults.power_loss_executed", False),
        ("same-process-recovery", "physical_faults.independent_recovery_process", False),
        ("missing-seven-validator", "network_campaign.seven_validator_run", False),
        ("conflicting-finality", "network_campaign.conflicting_finality_observed", True),
        ("double-sign", "network_campaign.double_sign_observed", True),
        ("root-divergence", "network_campaign.state_root_divergence_observed", True),
        ("hardware-mismatch", "benchmark.same_hardware", False),
        ("workload-mismatch", "benchmark.same_workload", False),
        ("zero-goodput", "benchmark.committed_goodput", 0),
        ("goodput-over-ingress", "benchmark.committed_goodput", 121.0),
        ("percentile-inversion", "benchmark.order_p50_ms", 501),
        ("single-repetition", "benchmark.repetition_roots", [digest("one")]),
        ("duplicate-repetition", "benchmark.repetition_roots", [digest("same")] * 3),
        ("consensus-audit-missing", "security_review.consensus_audit_complete", False),
        ("open-critical", "security_review.open_critical", 1),
        ("open-high", "security_review.open_high", 1),
        ("chaos-short", "operations.chaos_72h_completed_at", "2030-01-03T23:00:00Z"),
        ("testnet-short", "operations.public_testnet_7d_completed_at", "2030-01-12T03:00:00Z"),
        ("production-soak-short", "operations.production_candidate_30d_completed_at", "2030-02-12T11:00:00Z"),
        ("restore-drill-missing", "operations.restore_drill", False),
        ("governance-unauthorized", "governance.authorized", False),
        ("bad-activation-height", "governance.activation_height", 0),
        ("production-claim-false", "claims.production_candidate", False),
        ("too-few-signatures", "signatures", complete["signatures"][:4]),
    ]
    for name, path, replacement in cases:
        reject(name, lambda p=path, r=replacement: evaluate(set_path(complete, p, r)))

    mutated = set_path(complete, "source.configuration_root", digest("changed-configuration"))
    if evaluate(mutated)["evidence_root"] == first["evidence_root"]:
        raise AssertionError("source-mutation-not-committed")

    return {
        "schema": "trnm-external-evidence-gate-self-test-v1",
        "template": template,
        "synthetic_positive": 2,
        "negative": negatives,
        "synthetic_decision_root": first["evidence_root"],
        "real_evidence_present": False,
        "real_claim_authorized": False,
        "public_testnet_ready": False,
        "production_candidate": False,
        "production_activation": False,
        "release_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=Path, default=Path("docs/evidence/g3-g5/EXTERNAL_EVIDENCE_CAMPAIGN_TEMPLATE_V1.json"))
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--evaluate", type=Path)
    parser.add_argument("--allow-claim-evaluation", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        output = self_test(args.template)
    elif args.evaluate is not None:
        if not args.allow_claim_evaluation:
            raise SystemExit("--allow-claim-evaluation is required")
        output = evaluate(load_unique(args.evaluate))
    else:
        output = validate_template(load_unique(args.template))
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
