#!/usr/bin/env python3
"""Conservative, source-bound PQ claim gate; not a cryptographic security proof.

This gate reports known open authorities. It NEVER promotes the system to PQ
qualified, including when known classical markers disappear: an independent
complete authority inventory and external acceptance are still required.
Self-asserted W1 PQ-128 flags are refused, not treated as external review.
"""
import argparse
import json
from pathlib import Path

PATHS = {
    "hepta_handoff": "trillionnium/crates/trnm-research-protocol/src/hepta_handoff.rs",
    "cell_discovery": "trillionnium/crates/trnm-data-availability/src/cell/discovery.rs",
    "w1_backend": "trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/backend-manifest.json",
    "consensus": "config/consensus-mainline.json",
}
CLASSICAL_MARKERS = {
    "hepta_handoff": ("ed25519_dalek", "SignedHeptaAdmissionV1"),
    "cell_discovery": ("ed25519_dalek", "CellProviderRecordV1"),
}
PRODUCTION_FLAGS = ("production_candidate", "production_consensus_activation", "public_testnet_ready", "release_ready")

def inspect(root: Path) -> dict:
    blockers = []
    for label, rel in PATHS.items():
        file = root / rel
        if not file.is_file():
            blockers.append({"kind": "missing_source", "path": rel})
            continue
        if label in CLASSICAL_MARKERS:
            try:
                source = file.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                blockers.append({"kind": "unreadable_source", "path": rel})
                continue
            if all(marker in source for marker in CLASSICAL_MARKERS[label]):
                blockers.append({"kind": "classical_authority", "path": rel})
        elif label == "w1_backend":
            try:
                profile = json.loads(file.read_text(encoding="utf-8"))
                if not isinstance(profile, dict):
                    blockers.append({"kind": "invalid_proof_profile_shape", "path": rel})
                elif type(profile.get("pq_128_security_qualified")) is not bool:
                    blockers.append({"kind": "invalid_proof_qualification_flag_type", "path": rel})
                elif profile["pq_128_security_qualified"] is True:
                    # A self-set flag is not an independently reviewed
                    # quantum-security proof. Refuse promotion until an
                    # external assessment with pinned parameters exists.
                    blockers.append({"kind": "unreviewed_pq128_proof_claim", "path": rel})
                else:
                    blockers.append({"kind": "unqualified_proof", "path": rel})
            except (ValueError, OSError, UnicodeError):
                blockers.append({"kind": "unreadable_proof_profile", "path": rel})
    config_path = root / PATHS["consensus"]
    production = {}
    if config_path.is_file():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
            if not isinstance(config, dict):
                blockers.append({"kind": "invalid_consensus_profile_shape", "path": PATHS["consensus"]})
            else:
                production = {flag: config.get(flag) for flag in PRODUCTION_FLAGS}
                # JSON numbers and strings must never be coerced to a boolean
                # activation decision by some other consumer.
                if any(type(value) is not bool for value in production.values()):
                    blockers.append({"kind": "invalid_production_flag_type", "path": PATHS["consensus"]})
                if any(value is True for value in production.values()):
                    blockers.append({"kind": "production_claim_requires_independent_pq_review", "path": PATHS["consensus"]})
        except (ValueError, OSError, UnicodeError):
            blockers.append({"kind": "unreadable_consensus_profile", "path": PATHS["consensus"]})
    return {
        "schema": "trnm-pq-claim-audit-v1",
        "pq_chain_qualified": False,
        "complete_authority_inventory_reviewed": False,
        "quantum_work_lower_bound_proven": False,
        "independent_cryptographic_acceptance": False,
        "production_flags": production,
        "known_open_findings": blockers,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--assert-unqualified", action="store_true",
                        help="Fail if an unsafe production claim or missing/malformed source is found")
    args = parser.parse_args()
    report = inspect(args.root)
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.assert_unqualified and any(item["kind"] in (
        "missing_source", "unreadable_source", "unreadable_proof_profile",
        "unreadable_consensus_profile", "invalid_proof_profile_shape",
        "invalid_proof_qualification_flag_type", "invalid_consensus_profile_shape",
        "invalid_production_flag_type", "unreviewed_pq128_proof_claim",
        "production_claim_requires_independent_pq_review") for item in report["known_open_findings"]):
        raise SystemExit(2)

if __name__ == "__main__":
    main()
