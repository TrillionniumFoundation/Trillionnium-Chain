#!/usr/bin/env python3
"""Fail-closed, offline PQ-128 evidence preflight for Trillionnium-Chain.

This checks local claim/evidence consistency; it is NOT a cryptographic
security proof, a FIPS validation, or a production deployment certification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
SHA_40 = re.compile(r"^[0-9a-f]{40}$")
SHA_64 = re.compile(r"^[0-9a-f]{64}$")

GATES = (
    "G1_authority",
    "G2_migration",
    "G3_w1_proof",
    "G4_quantum_consensus",
    "G5_capacity_dos",
    "G6_recovery_activations",
)

# These are audit inventory categories, NOT assertions they exist on main.
REQUIRED_SURFACES = (
    "account_transactions",
    "account_key_rotation",
    "account_recovery",
    "task_origin",
    "evaluator_verdict",
    "model_release",
    "hepta_admission",
    "hepta_handoff",
    "cell_provider_discovery",
    "node_ingress",
    "governance",
    "protocol_upgrade",
    "release_finality",
    "snapshot_import",
    "evidence_attestation",
)

MIGRATION_CONTROLS = (
    "pre_quantum_owner_commitment",
    "pq_key_binding",
    "migration_nonce_monotonicity",
    "epoch_and_domain_separation",
    "classic_fallback_disabled",
    "signature_algorithm_no_downgrade",
    "key_revocation_and_rotation",
    "migration_reorg_safety",
)

W1_CONTROLS = (
    "complete_relation_fixed",
    "qrom_fiat_shamir_assessed",
    "fri_parameters_assessed",
    "hash_security_assessed",
    "recursive_composition_assessed",
    "invalid_receipt_cost_bounded",
    "production_consensus_activation",
)

MINING_CASES = (
    "zero_and_low_rank",
    "structured_matrices",
    "precomputation",
    "multi_challenge",
    "batching",
    "gpu_asic_optimization",
    "quantum_oracle_full_w1",
    "difficulty_timestamp_manipulation",
    "fork_choice_deep_reorg",
)

PERF_CASES = (
    "pq_tx_payload_and_network",
    "pq_verification_cpu_and_p99",
    "invalid_signature_worst_case",
    "invalid_w1_receipt_worst_case",
    "block_propagation",
    "mempool_admission_and_bounding",
    "state_growth_and_pruning",
    "reorg_and_restart",
)

OPERATIONS_CONTROLS = (
    "external_monotonic_anchor",
    "snapshot_rollback_rejected",
    "old_classic_key_reactivation_rejected",
    "cross_node_consensus_agreement",
    "crash_restart_consistent",
    "rotation_and_revocation_persist",
    "governance_activation_non_bypassable",
    "old_transaction_replay_rejected",
    "storage_schema_migration_safe",
)


def template() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "project": "TrillionniumFoundation/Trillionnium-Chain",
        "baseline": {"main_sha": None, "target_network": None, "evaluated_at": None},
        "evidence": [],
        "authority_surfaces": [
            {
                "id": name,
                "source_path": None,
                "reachability": "unknown",   # reachable | unreachable | unknown
                "authority_effect": "unknown",  # yes | no | unknown
                "policy": "unknown",  # pq_only | hybrid_and | classic_only | hybrid_or | unknown
                "owner_binding": "unknown",  # precommitted_pq | verified_dual_owner | unknown
                "context_bound": False,
                "replay_bound": False,
                "downgrade_rejected": False,
                "inaccessible_activation_guard": False,
                "reachability_evidence": None,
                "authorization_evidence": None,
            }
            for name in REQUIRED_SURFACES
        ],
        "migration": {name: {"verified": False, "evidence": None} for name in MIGRATION_CONTROLS},
        "w1_proof": {
            "backend": "unknown",
            "pq_128_security_qualified": False,
            "soundness_bits_quantum": None,
            "groth16_enabled": None,
            "fake_or_remote_receipts_enabled": None,
            "controls": {name: {"verified": False, "evidence": None} for name in W1_CONTROLS},
            "independent_review_evidence": None,
            "backend_manifest_evidence": None,
        },
        "quantum_consensus": {
            "cheapest_legal_solver_benchmark": False,
            "quantum_attack_lower_bound_justified": False,
            "difficulty_attack_safety_verified": False,
            "cases": {name: {"verified": False, "evidence": None} for name in MINING_CASES},
            "independent_review_evidence": None,
        },
        "capacity_dos": {
            "cases": {name: {"budget_met": False, "evidence": None} for name in PERF_CASES},
        },
        "recovery_activations": {
            "controls": {name: {"verified": False, "evidence": None} for name in OPERATIONS_CONTROLS},
            "independent_review_evidence": None,
        },
    }


def _mapping(obj: Any) -> dict[str, Any]:
    return obj if isinstance(obj, dict) else {}


def _find_json_values(data: Any, key: str) -> list[Any]:
    if isinstance(data, dict):
        values = [value for k, value in data.items() if k == key]
        for value in data.values():
            values.extend(_find_json_values(value, key))
        return values
    if isinstance(data, list):
        values = []
        for item in data:
            values.extend(_find_json_values(item, key))
        return values
    return []


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for k, v in pairs:
        if k in seen:
            raise ValueError(f"duplicate JSON key: {k}")
        seen[k] = v
    return seen


def _valid_local_evidence(
    item: Any,
    baseline_sha: str | None,
    root: Path,
) -> str | None:
    e = _mapping(item)
    if not e:
        return "not an evidence object"
    if e.get("status") != "passed":
        return "test or review is not recorded as passed"
    if e.get("commit_sha") != baseline_sha:
        return "evidence commit does not equal evaluated baseline"
    digest = e.get("sha256")
    if not isinstance(digest, str) or not SHA_64.fullmatch(digest):
        return "missing/invalid SHA-256 digest"
    rel = e.get("path")
    if not isinstance(rel, str) or not rel.strip():
        return "missing relative evidence path"
    try:
        p = (root / rel).resolve(strict=True)
        p.relative_to(root)
        if not p.is_file():
            return "evidence path is not a regular file"
        # Avoid allocating the whole artifact; bound this tool's memory use.
        d = hashlib.sha256()
        with p.open("rb") as f:
            while block := f.read(1024 * 1024):
                d.update(block)
        if d.hexdigest() != digest:
            return "evidence file digest mismatch"
    except (OSError, ValueError, RuntimeError):
        return "missing evidence file or path escaped evidence directory"
    return None


def evaluate(data: Any, evidence_dir: Path) -> dict[str, list[str]]:
    """Return six lists of blockers. No claim here implies independent PQ assurance."""
    errors = {gate: [] for gate in GATES}
    root = evidence_dir.resolve()
    d = _mapping(data)
    if d.get("schema_version") != SCHEMA_VERSION:
        for gate in GATES:
            errors[gate].append("schema_version must be 1")
        return errors
    baseline = _mapping(d.get("baseline"))
    sha = baseline.get("main_sha")
    baseline_valid = isinstance(sha, str) and SHA_40.fullmatch(sha) is not None
    network = baseline.get("target_network")
    if not baseline_valid or not isinstance(network, str) or not network.strip():
        for gate in GATES:
            errors[gate].append("must pin exact 40-hex baseline main SHA and target network")
    ev = d.get("evidence", [])
    evidence: dict[str, Any] = {}
    if isinstance(ev, list):
        for i, entry in enumerate(ev):
            if not isinstance(entry, dict):
                errors[GATES[0]].append(f"evidence[{i}] is not an object")
                continue
            key = entry.get("id")
            if not isinstance(key, str) or not key:
                errors[GATES[0]].append(f"evidence[{i}] missing id")
            elif key in evidence:
                errors[GATES[0]].append(f"duplicate evidence id: {key}")
            else:
                evidence[key] = entry
    else:
        errors[GATES[0]].append("evidence must be a list")

    verified_ids: dict[str, str | None] = {}
    def check_ev(gate: str, ref: Any, label: str, independent: bool = False) -> None:
        if not isinstance(ref, str) or not ref or ref not in evidence:
            errors[gate].append(f"{label}: missing evidence reference")
            return
        if ref not in verified_ids:
            verified_ids[ref] = _valid_local_evidence(evidence[ref], sha if baseline_valid else None, root)
        problem = verified_ids[ref]
        if problem:
            errors[gate].append(f"{label}: {problem}")
        if label not in (evidence[ref].get("claims") if isinstance(evidence[ref].get("claims"), list) else []):
            errors[gate].append(f"{label}: evidence does not identify this exact claim")
        if independent and (evidence[ref].get("independent") is not True
                            or not isinstance(evidence[ref].get("reviewer_id"), str)
                            or not evidence[ref].get("reviewer_id")):
            errors[gate].append(f"{label}: named independent reviewer required")

    # G1: Require a complete, provenance-linked surface inventory. An
    # explicitly proved unreachable/observational route is not equivalent
    # to a reachable authority route; do not treat it as an active flaw.
    surfaces = d.get("authority_surfaces")
    if not isinstance(surfaces, list):
        surfaces = []
        errors[GATES[0]].append("authority_surfaces must be a list")
    ids = [s.get("id") for s in surfaces if isinstance(s, dict)]
    for name in REQUIRED_SURFACES:
        if ids.count(name) != 1:
            errors[GATES[0]].append(f"expected exactly one authority surface: {name}")
    for s in surfaces:
        if not isinstance(s, dict):
            errors[GATES[0]].append("invalid authority surface record")
            continue
        name = s.get("id", "<missing-id>")
        if name not in REQUIRED_SURFACES:
            errors[GATES[0]].append(f"unexpected surface id (must review inventory extension): {name}")
        if not isinstance(s.get("source_path"), str) or not s.get("source_path"):
            errors[GATES[0]].append(f"{name}: no source path")
        reach = s.get("reachability")
        effect = s.get("authority_effect")
        if reach not in ("reachable", "unreachable") or effect not in ("yes", "no"):
            errors[GATES[0]].append(f"{name}: reachability and authority effect remain unknown")
        check_ev(GATES[0], s.get("reachability_evidence"), f"{name} reachability")
        check_ev(GATES[0], s.get("authorization_evidence"), f"{name} authorization")
        if reach == "unreachable":
            if s.get("inaccessible_activation_guard") is not True:
                errors[GATES[0]].append(f"{name}: inactive path is not proven fail-closed")
            continue
        if effect == "yes":
            if s.get("policy") not in ("pq_only", "hybrid_and"):
                errors[GATES[0]].append(f"{name}: reachable authority accepts classic-only, OR, or unknown policy")
            if s.get("owner_binding") not in ("precommitted_pq", "verified_dual_owner"):
                errors[GATES[0]].append(f"{name}: PQ owner provenance not demonstrated")
            for field in ("context_bound", "replay_bound", "downgrade_rejected"):
                if s.get(field) is not True:
                    errors[GATES[0]].append(f"{name}: {field} not established")

    def checked_controls(gate: str, section: Any, keys: tuple[str, ...], positive: str = "verified") -> None:
        obj = _mapping(section)
        for name in keys:
            c = _mapping(obj.get(name))
            if c.get(positive) is not True:
                errors[gate].append(f"{name}: not verified")
            check_ev(gate, c.get("evidence"), name)

    # G2
    checked_controls(GATES[1], d.get("migration"), MIGRATION_CONTROLS)

    # G3
    proof = _mapping(d.get("w1_proof"))
    if proof.get("backend") != "transparent_stark_composite":
        errors[GATES[2]].append("proof backend must be explicitly verified transparent STARK/Composite")
    if proof.get("pq_128_security_qualified") is not True:
        errors[GATES[2]].append("explicit PQ-128 proof qualification is absent/false")
    bits = proof.get("soundness_bits_quantum")
    if not isinstance(bits, (int, float)) or isinstance(bits, bool) or not (128 <= bits < 10000):
        errors[GATES[2]].append("quantum soundness bound below 128 or undocumented")
    if proof.get("groth16_enabled") is not False:
        errors[GATES[2]].append("Groth16 must be provably absent from production acceptance")
    if proof.get("fake_or_remote_receipts_enabled") is not False:
        errors[GATES[2]].append("fake/remote proof substitution not definitively excluded")
    checked_controls(GATES[2], proof.get("controls"), W1_CONTROLS)
    check_ev(GATES[2], proof.get("independent_review_evidence"), "W1 independent proof review", True)
    backend_ref = proof.get("backend_manifest_evidence")
    check_ev(GATES[2], backend_ref, "W1 backend manifest exact")
    if isinstance(backend_ref, str) and backend_ref in evidence and verified_ids.get(backend_ref) is None:
        try:
            backend_path = (root / evidence[backend_ref]["path"]).resolve(strict=True)
            backend_data = json.loads(backend_path.read_text(encoding="utf-8"),
                                      object_pairs_hook=_reject_duplicate_json_keys)
            for flag in ("pq_128_security_qualified", "production_consensus_activation"):
                values = _find_json_values(backend_data, flag)
                if values != [True]:
                    errors[GATES[2]].append(f"W1 backend manifest: {flag} must appear exactly once as true")
        except (OSError, ValueError, UnicodeError, TypeError) as exc:
            errors[GATES[2]].append(f"W1 backend manifest cannot be validated: {exc}")

    # G4
    q = _mapping(d.get("quantum_consensus"))
    for field in ("cheapest_legal_solver_benchmark", "quantum_attack_lower_bound_justified", "difficulty_attack_safety_verified"):
        if q.get(field) is not True:
            errors[GATES[3]].append(f"{field}: no qualified evidence")
    checked_controls(GATES[3], q.get("cases"), MINING_CASES)
    check_ev(GATES[3], q.get("independent_review_evidence"), "independent mining review", True)

    # G5
    c = _mapping(d.get("capacity_dos"))
    checked_controls(GATES[4], c.get("cases"), PERF_CASES, "budget_met")

    # G6
    o = _mapping(d.get("recovery_activations"))
    checked_controls(GATES[5], o.get("controls"), OPERATIONS_CONTROLS)
    check_ev(GATES[5], o.get("independent_review_evidence"), "independent recovery review", True)
    return errors


def _run() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?", type=Path, help="JSON evidence manifest")
    parser.add_argument("--evidence-dir", type=Path, help="root for hash-checked local evidence files")
    parser.add_argument("--json", action="store_true", help="machine-readable result")
    parser.add_argument("--write-template", type=Path, help="write intentionally blocked empty manifest")
    args = parser.parse_args()
    if args.write_template:
        args.write_template.write_text(json.dumps(template(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return 0
    if args.manifest is None:
        parser.error("manifest is required unless --write-template is used")
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"),
                              object_pairs_hook=_reject_duplicate_json_keys)
    except (OSError, ValueError) as exc:
        print(f"Cannot parse manifest: {exc}", file=sys.stderr)
        return 2
    evidence_root = args.evidence_dir or args.manifest.parent
    result = evaluate(manifest, evidence_root)
    clear = all(not problems for problems in result.values())
    if args.json:
        print(json.dumps({
            "status": "EVIDENCE_PRECHECK_ONLY_NOT_PQ_CERTIFICATION" if clear else "NO_GO",
            "gates": {gate: {"complete": not bool(errs), "blockers": errs} for gate, errs in result.items()},
        }, indent=2, ensure_ascii=False))
    else:
        print("TRNM PQ-128 evidence preflight — NOT a cryptographic certification")
        for gate, problems in result.items():
            print(f"{'PRECHECK COMPLETE' if not problems else 'BLOCKED'}: {gate} ({len(problems)} blockers)")
            for issue in problems:
                print(f"    - {issue}")
        print("RESULT:", "EVIDENCE PRECHECK COMPLETE — independent PQ review STILL REQUIRED" if clear else "NO-GO — do not claim whole-chain PQ-128")
    return 0 if clear else 1


if __name__ == "__main__":
    sys.exit(_run())
