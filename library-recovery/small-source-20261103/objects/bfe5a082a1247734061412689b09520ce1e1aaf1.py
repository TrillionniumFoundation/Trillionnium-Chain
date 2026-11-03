#!/usr/bin/env python3
"""Fail-closed PQ-128 *readiness evidence* audit for a Trillionnium-Chain checkout.

This is NOT a consensus verifier, cryptographic proof, or certification tool. It
helps prevent unsupported activation/qualification declarations and records
where independent security evidence is still required. Stdlib only.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

GATES = (
    "authorization", "proof_soundness", "quantum_work", "migration",
    "resource_resilience", "rollback_recovery",
)
SURFACES = (
    "account", "transaction", "node_ingress", "task_source", "evaluator",
    "model_release", "hepta_handoff", "provider_discovery",
    "protocol_upgrade", "governance", "recovery",
)
EXPECTED_PATHS = {
    "pq_auth": "trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs",
    "pq_tasks_v5": "trillionnium/crates/trnm-pon-node/src/pq_tasks_v5.rs",
    "ingress": "trillionnium/crates/trnm-pon-node/src/ingress.rs",
    "hepta_handoff": "trillionnium/crates/trnm-research-protocol/src/hepta_handoff.rs",
    "provider_discovery": "trillionnium/crates/trnm-data-availability/src/cell/discovery.rs",
    "w1_backend_manifest": "trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/backend-manifest.json",
}
SIGNATURE_TERMS = re.compile(r"(?i)\b(ed25519|secp256k1|ecdsa|groth16|ml[-_]?dsa|dilithium)\b")
SCAN_SUFFIXES = frozenset({".rs", ".toml", ".json", ".yaml", ".yml"})
SKIP_DIRS = frozenset({".git", "target", "node_modules", ".venv", "vendor", "dist", "build"})
MAX_SCAN_FILES = 100_000
MAX_FILE_BYTES = 2_000_000


def problem(gate: str, code: str, detail: str, severity: str = "blocker") -> dict[str, str]:
    return {"gate": gate, "severity": severity, "code": code, "detail": detail}


def safe_existing_file(root: Path, relative: str) -> Path | None:
    """Only regular files strictly within root; reject traversal and symlinks."""
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        return None
    path = Path(relative)
    if ".." in path.parts:
        return None
    root = root.resolve()
    candidate = root
    for part in path.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            return None
    if not candidate.is_file():
        return None
    try:
        candidate.resolve().relative_to(root)
    except ValueError:
        return None
    return candidate


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def get_checkout_sha(root: Path) -> tuple[str | None, bool | None]:
    """Return (HEAD, clean). Repository checked out at exact commit is required for claims."""
    def command(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            check=True, capture_output=True, text=True, timeout=8,
        ).stdout.strip()
    try:
        sha = command("rev-parse", "--verify", "HEAD")
        top = command("rev-parse", "--show-toplevel")
        if Path(top).resolve() != root.resolve():
            return None, None
        clean = command("status", "--porcelain", "--untracked-files=normal") == ""
        return sha, clean
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None, None


def find_key(node: Any, key: str) -> list[Any]:
    if isinstance(node, dict):
        matches = ([node[key]] if key in node else [])
        for v in node.values():
            matches.extend(find_key(v, key))
        return matches
    if isinstance(node, list):
        result = []
        for item in node:
            result.extend(find_key(item, key))
        return result
    return []


def scan_references(root: Path) -> dict[str, Any]:
    """Unclassified references only: no claim that source paths are active/exploitable."""
    counts: Counter[str] = Counter()
    selected: list[dict[str, Any]] = []
    scanned = 0
    truncated = False
    for directory, subdirs, filenames in os.walk(root, followlinks=False):
        subdirs[:] = [d for d in subdirs if d not in SKIP_DIRS and
                      not (Path(directory) / d).is_symlink()]
        for filename in filenames:
            path = Path(directory) / filename
            if path.suffix.lower() not in SCAN_SUFFIXES or path.is_symlink():
                continue
            if scanned >= MAX_SCAN_FILES:
                truncated = True
                break
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                relative = path.relative_to(root).as_posix()
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    for no, line in enumerate(f, 1):
                        for m in SIGNATURE_TERMS.finditer(line):
                            term = m.group(1).lower().replace("_", "-")
                            counts[term] += 1
                            if len(selected) < 1000:
                                selected.append({"file": relative, "line": no, "term": term,
                                                 "sample": line.strip()[:200]})
                scanned += 1
            except OSError:
                truncated = True
        if truncated:
            break
    return {"files_scanned": scanned, "scan_truncated": truncated,
            "counts": dict(sorted(counts.items())), "references": selected,
            "note": "Occurrences are NOT evidence of an active trust path or vulnerability."}


def require_true(obj: Any, keys: tuple[str, ...], gate: str,
                 issues: list[dict[str, str]]) -> None:
    if not isinstance(obj, dict):
        issues.append(problem(gate, "missing_policy", "Policy object missing"))
        return
    for key in keys:
        if obj.get(key) is not True:
            issues.append(problem(gate, "missing_" + key, f"{key} must be explicitly true and evidenced"))


def check_evidence(root: Path, gate: str, entry: Any, issues: list[dict[str, str]]) -> None:
    """Validate SHA256 and independently attributed reviewer metadata.

    This is provenance bookkeeping; signatures/reviewer authority are not validated.
    """
    if not isinstance(entry, dict):
        issues.append(problem(gate, "no_evidence", "No independent evidence record"))
        return
    if entry.get("verdict") != "pass":
        issues.append(problem(gate, "evidence_not_passed", "Evidence verdict is not pass"))
    author = entry.get("author")
    reviewer = entry.get("reviewer")
    if not (isinstance(author, str) and author.strip() and
            isinstance(reviewer, str) and reviewer.strip() and reviewer != author):
        issues.append(problem(gate, "independent_reviewer_missing", "Non-identical author and reviewer required"))
    if entry.get("independent_reproduction") is not True:
        issues.append(problem(gate, "independent_reproduction_missing", "Independent reproduction required"))
    path = safe_existing_file(root, entry.get("artifact", ""))
    if path is None:
        issues.append(problem(gate, "artifact_unavailable", "Evidence artifact absent/unsafe"))
        return
    digest = entry.get("sha256", "")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        issues.append(problem(gate, "artifact_digest_missing", "SHA256 digest missing or malformed"))
    elif sha256_file(path) != digest:
        issues.append(problem(gate, "artifact_digest_mismatch", "Artifact content differs from reviewed digest"))


def check_policy(root: Path, policy: Any, sha: str | None, clean: bool | None,
                 backend_manifest: Any, issues: list[dict[str, str]]) -> None:
    if not isinstance(policy, dict) or policy.get("schema_version") != 1:
        issues.append(problem("global", "policy_schema", "schema_version 1 required"))
        return
    if policy.get("target") != "PQ-128":
        issues.append(problem("global", "target_missing", "Explicit PQ-128 target required"))
    if policy.get("repo") != "TrillionniumFoundation/Trillionnium-Chain":
        issues.append(problem("global", "repo_mismatch", "Target repo must match"))
    expected = policy.get("expected_head_sha")
    if (not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{40}", expected)
            or sha is None or sha != expected or not clean):
        issues.append(problem("global", "source_baseline_unverified",
                              "Exact clean git HEAD must match expected_head_sha"))
    authority = policy.get("authority_surfaces")
    if not isinstance(authority, dict):
        authority = {}
    for surface in SURFACES:
        item = authority.get(surface)
        if not isinstance(item, dict) or item.get("verification") not in ("pq_only", "hybrid_both"):
            issues.append(problem("authorization", "unmapped_" + surface,
                                  f"{surface}: runtime authority-to-trust-root trace absent"))
    down = policy.get("downgrade_policy", {})
    if not isinstance(down, dict):
        down = {}
    if down.get("hybrid_acceptance") != "both":
        issues.append(problem("migration", "hybrid_or_downgrade",
                              "Hybrid policy must require BOTH classical AND PQ proofs"))
    if down.get("legacy_after_activation") != "reject":
        issues.append(problem("migration", "classic_fallback",
                              "Legacy-only acceptance must be rejected after activation"))
    require_true(down, ("pre_quantum_ownership_committed", "domain_separated",
                        "chain_and_nonce_bound", "reorg_replay_tested"), "migration", issues)
    proof = policy.get("proof_policy", {})
    if not isinstance(proof, dict):
        proof = {}
    for item in ("allow_groth16", "allow_fake_receipt", "allow_remote_substitution"):
        if proof.get(item) is not False:
            issues.append(problem("proof_soundness", "unsafe_" + item,
                                  f"{item} must be explicitly false"))
    min_bits = proof.get("independently_reviewed_quantum_bits")
    if (not isinstance(min_bits, int) or isinstance(min_bits, bool) or min_bits < 128):
        issues.append(problem("proof_soundness", "pq128_not_reviewed",
                              "Independent quantum soundness bound >=128 bits missing"))
    if proof.get("complete_w1_relation_verified") is not True:
        issues.append(problem("proof_soundness", "relation_not_verified",
                              "Exact W1 guest/receipt/chain binding unverified"))
    if proof.get("fiat_shamir_quantum_model_reviewed") is not True:
        issues.append(problem("proof_soundness", "fiat_shamir_unreviewed",
                              "Quantum random-oracle / Fiat-Shamir treatment absent"))
    if isinstance(backend_manifest, dict):
        ver = find_key(backend_manifest, "risc0_version") + find_key(backend_manifest, "risc_zero_version")
        backend_terms = find_key(backend_manifest, "version")
        backend_name = str(backend_manifest.get("backend", "")).lower()
        all_versions = [str(v) for v in (ver + (backend_terms if "risc" in backend_name else []))]
        # Manifest layouts vary; detect both explicit version keys and nested
        # backend description. Ambiguous matches block claim, not deployment.
        manifest_text = json.dumps(backend_manifest, ensure_ascii=False).lower()
        risc_v306 = (any(x == "3.0.6" for x in all_versions)
                      or ("3.0.6" in manifest_text and "risc" in manifest_text))
        if risc_v306:
            issues.append(problem("proof_soundness", "risc0_3_0_6_insufficient",
                                  "RISC Zero 3.0 model 96/99-bit STARK components do not establish PQ-128"))
    require_true(policy.get("quantum_work_policy"),
                 ("full_w1_oracle_costed", "cheapest_legal_solver_benchmarked",
                  "precomputation_batch_hardware_challenged", "retarget_fork_choice_analyzed",
                  "independently_reproduced"), "quantum_work", issues)
    require_true(policy.get("resource_policy"),
                 ("packet_budget_tested", "invalid_signature_bounded",
                  "cpu_memory_storage_benchmarked", "broadcast_propagation_tested"),
                 "resource_resilience", issues)
    require_true(policy.get("rollback_policy"),
                 ("external_monotonic_anchor", "snapshot_rollback_rejected",
                  "recovery_migration_policy_tested", "crash_reorg_rotation_tested"),
                 "rollback_recovery", issues)
    evidence = policy.get("evidence")
    if not isinstance(evidence, dict):
        evidence = {}
    for gate in GATES:
        check_evidence(root, gate, evidence.get(gate), issues)


def audit(root: Path, policy_path: Path) -> dict[str, Any]:
    root = root.resolve()
    issues: list[dict[str, str]] = []
    sha, clean = get_checkout_sha(root)
    known = {}
    for name, rel in EXPECTED_PATHS.items():
        path = safe_existing_file(root, rel)
        known[name] = {"path": rel, "exists": bool(path),
                       "sha256": sha256_file(path) if path else None}
        if path is None:
            issues.append(problem("inventory", "missing_" + name,
                                  f"Expected original file missing/relocated: {rel}"))

    backend = None
    backend_file = safe_existing_file(root, EXPECTED_PATHS["w1_backend_manifest"])
    if backend_file:
        try:
            backend = json.loads(backend_file.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            issues.append(problem("proof_soundness", "invalid_backend_manifest", "Malformed W1 backend JSON"))

    policy = None
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        issues.append(problem("global", "policy_unavailable", "Policy JSON missing or malformed"))
    if policy is not None:
        check_policy(root, policy, sha, clean, backend, issues)

    # Independent of policy attestations, deployment flags cannot be auto-promoted.
    flags: dict[str, Any] = {}
    if backend is not None:
        for key in ("pq_128_security_qualified", "production_consensus_activation"):
            values = find_key(backend, key)
            flags[key] = values if values else None
            if values is None:
                issues.append(problem("proof_soundness", "missing_" + key,
                                      f"Backend manifest missing {key}; never infer qualification"))
            elif any(type(x) is not bool for x in values):
                issues.append(problem("proof_soundness", "nonboolean_" + key,
                                      f"{key} must contain boolean values"))
        if True in (flags.get("production_consensus_activation") or []):
            issues.append(problem("global", "production_activation_detected",
                                  "Production consensus activation requires independent end-to-end review",
                                  severity="critical"))
        if True in (flags.get("pq_128_security_qualified") or []):
            issues.append(problem("global", "pq128_qualification_claim_detected",
                                  "Backend self-declared PQ-128 requires independent crypto review",
                                  severity="critical"))

    if isinstance(policy, dict) and policy.get("activation_requested") is True:
        issues.append(problem("global", "activation_requested",
                              "Manual security signoff required before activating production",
                              severity="critical"))

    references = scan_references(root) if root.is_dir() else {}
    if references.get("scan_truncated"):
        issues.append(problem("inventory", "scan_truncated", "Scanner did not cover all eligible sources"))
    return {
        "schema_version": 1, "repo": str(root), "head_sha": sha, "clean": clean,
        "status": "NOT_QUALIFIED" if issues else "EVIDENCE_PRECHECK_PASSED_NOT_CERTIFIED",
        "pq128_certified": False,  # Intentionally never certified by automated self-reporting.
        "production_approved": False,
        "backend_flags": flags, "known_files": known,
        "classical_and_pq_references": references,
        "issues": sorted(issues, key=lambda x: (x["gate"], x["code"])),
        "limitations": [
            "Source text matching does not establish live authority/control flow.",
            "Policy JSON and reviewer names are not cryptographically authenticated.",
            "Proof security, miner lower bounds, and rollback safety require independent review.",
            "This tool is NOT connected to runtime consensus or upgrade admission.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Trillionnium-Chain PQ readiness evidence audit; no certification")
    p.add_argument("--repo", type=Path, required=True, help="Exact Trillionnium-Chain git checkout")
    p.add_argument("--policy", type=Path, required=True, help="PQ evidence/policy JSON")
    p.add_argument("--output", type=Path, help="Save full JSON report to this path")
    p.add_argument("--strict", action="store_true", help="Fail if any issue remains (expected during development)")
    args = p.parse_args(argv)
    report = audit(args.repo, args.policy)
    output = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    print(f"{report['status']} | issues={len(report['issues'])} | sha={report['head_sha'] or 'unavailable'}")
    for issue in report["issues"][:35]:
        print(f"  [{issue['severity']}] {issue['gate']}/{issue['code']}: {issue['detail']}")
    if len(report["issues"]) > 35:
        print(f"  ... {len(report['issues'])-35} more; use --output for all")
    if args.strict and report["issues"]:
        return 2
    # A non-strict audit is diagnostic, unless a claim or activation was detected.
    if any(x["severity"] == "critical" for x in report["issues"]):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
