#!/usr/bin/env python3
"""Conservative, source-bound PQ claim gate; not a cryptographic security proof.

This gate reports known open authorities. It NEVER promotes the system to PQ
qualified, including when known classical markers disappear: an independent
complete authority inventory and external acceptance are still required.
Self-asserted W1 PQ-128 flags are refused, not treated as external review.
"""
import argparse
import hashlib
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
# These must remain explicit Boolean false in the pinned research-only W1 backend.
# Turning one on, removing it, or changing its type cannot be an implicit
# production-proof policy migration; a separately reviewed revision is needed.
PROOF_RESEARCH_ONLY_FALSE_FLAGS = (
    "fake_receipts_allowed",
    "groth16_receipts_allowed",
    "remote_proving_allowed",
    "production_consensus_activation",
    "independent_hashcash_grinding",
)
RESEARCH_PROOF_RECEIPT_KIND = "Composite"

# Frozen research identity, not a PQ128 endorsement. Changing any of these
# proof-relation, backend, FRI or transcript assumptions requires a separately
# reviewed versioned research profile; a silent manifest edit must fail CI.
PINNED_W1_RESEARCH_PARAMETERS = {
    "schema": "pon-w1-risc0-research-backend-v1",
    "status": "research-only-not-consensus-qualified",
    "backend": "risc0-zkvm",
    "backend_version": "3.0.6",
    "backend_source_commit": "1cc70cf05033a79ebc90f07c679cb4bd1cd301b9",
    "guest_image_id": "3ea1bcbf7900a32be73d7e78102de085562893732473667e1f3af07e585696b4",
    "guest_raw_elf_sha256": "651d8efabd091811fbf11b78e80793a4acb02b3c2eec95260373c58636d774b5",
    "guest_program_sha256": "b8f32cd9c1b1edbb0cde04acf9aab146b7ff1aeeeaee0188e4d6e80d077b0c0a",
    "backend_source_url": "https://github.com/risc0/risc0/tree/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9",
    "official_linux_tools_sha256": "615d961bfb81d318db5071d7548389c850e324ac7f421c075176daf26082a60a",
    "guest_compiler_release": "r0.1.97.0",
    "official_linux_guest_compiler_archive_sha256": "100b597d605b706bec94e1d32bfaaf5851df8d75173f986d4b56a3e90916be53",
    "sha256_guest_accelerator_commit": "7fd6900c4f637bd15ee2642dfa77110f8f1ad065",
    "guest_relation_source_commit": None,
    "compatibility_kernel_crate": "risc0-zkos-v1compat = 2.2.3",
    "proof_grinding_review_scope": "pinned core, zkp prover/verifier, zkvm and rv32im/recursion circuit source; not an independent cryptographic audit",
    "guest_source_sha256": {
        "../../src/pon_work/full_relation.rs": "ed51cb82d417d35a0f8af636422d10abff913c868032dc3e414af63f30449c97",
        "relation/src/lib.rs": "afe2f2cb5a0605eae3b6cd643e4a7bbb09fa0b0fe4db36fd2fe1155875152fb7",
        "relation/src/parameters.rs": "53d9d680fe76ac57203e10c7642b5add2da07dd05f2c76d036d59cb420360428",
        "guest/src/main.rs": "02567b1388b074138c2993bc5769692bff0d81ddc1207f2091df91dfc1d8f22e",
        "Cargo.toml": "315b2227e5dc453328a4627727911ebcf4df7ada2d024dacd838d4864faf3861",
        "guest/Cargo.toml": "c750dd4c1551df139880dda3583c6f1af27b3d01e3aadfc6a84441c06710104c",
        "relation/Cargo.toml": "d54c76ef1f5d5a5682ad63e1b3d9afb87b869551d113ff0718bdd0d6904faeb5",
        "Cargo.lock": "b3bb8518308ee9a175d878e5cafaab269be20f2bf990ec3fbb4d6e49bf110996",
    },
    "guest_native_differential_source": "../../src/pon_work/full_relation_tests.rs",
    "guest_relation_source_identity": "exact SHA-256 entries in guest_source_sha256; optimization and thin adapter pending review",
    "work_profile": "pon-matmul-transcript-64-v1",
    "work_n": 64,
    "work_r": 8,
    "work_q": 4294967291,
    "work_intermediate_tiles": 512,
    "work_transcript_hash": "SHA-256",
    "proof_commitment_hash": "Poseidon2",
    "proof_fri_queries": 50,
    "proof_fri_inverse_rate": 4,
    "backend_claimed_conjectured_security_bits": 98,
}

class DuplicateJSONMemberError(ValueError):
    """Refuse cross-parser ambiguous JSON, including nested duplicate members."""
    pass

def load_unique_json(path: Path) -> dict:
    def require_unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise DuplicateJSONMemberError(name)
            result[name] = value
        return result

    def reject_nonstandard_number(token):
        # Python accepts NaN/Infinity by default; RFC 8259 JSON does not.
        # A different authority/consensus parser could reject or reinterpret it.
        raise ValueError(f"non-standard JSON numeric constant: {token}")

    return json.loads(path.read_text(encoding="utf-8"),
                      object_pairs_hook=require_unique,
                      parse_constant=reject_nonstandard_number)

def verify_frozen_w1_guest_bytes(root: Path, blockers: list) -> None:
    """Bind the known research manifest to actual local guest source bytes.

    This does not attest a RISC Zero proof or the external build toolchain.
    All eight allowed relative paths and expected hashes are independently
    frozen above; the guest cannot self-authorize a changed digest map.
    """
    manifest_directory = Path(PATHS["w1_backend"]).parent
    trusted_root = root.resolve()
    for source_rel, expected in PINNED_W1_RESEARCH_PARAMETERS["guest_source_sha256"].items():
        path = root / manifest_directory / source_rel
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(trusted_root):
                blockers.append({
                    "kind": "escaped_w1_guest_source", "path": str(path),
                })
                continue
            observed = hashlib.sha256(resolved.read_bytes()).hexdigest()
        except (OSError, RuntimeError):
            blockers.append({
                "kind": "unreadable_w1_guest_source", "path": str(path),
            })
            continue
        if observed != expected:
            blockers.append({
                "kind": "w1_guest_source_digest_mismatch",
                "path": str(path),
                "source": source_rel,
            })


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
                profile = load_unique_json(file)
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
                # Flag consistency alone does not freeze a proof system.
                # Reject missing, changed and type-confused security-relevant
                # parameters before the original research profile is reused.
                if isinstance(profile, dict):
                    for field, expected in PINNED_W1_RESEARCH_PARAMETERS.items():
                        observed = profile.get(field)
                        if type(observed) is not type(expected) or observed != expected:
                            blockers.append({
                                "kind": "unreviewed_w1_research_parameter_change",
                                "path": rel,
                                "field": field,
                            })
                    verify_frozen_w1_guest_bytes(root, blockers)
                # A truthful pq_128=false is not enough: a changed receipt
                # type or a permissive fallback could silently weaken the
                # research proof boundary while the public flags remain false.
                if isinstance(profile, dict):
                    if profile.get("proof_receipt_kind") != RESEARCH_PROOF_RECEIPT_KIND:
                        blockers.append({"kind": "unsupported_proof_receipt_kind", "path": rel})
                    for flag in PROOF_RESEARCH_ONLY_FALSE_FLAGS:
                        value = profile.get(flag)
                        if type(value) is not bool:
                            blockers.append({"kind": "invalid_proof_policy_flag_type",
                                             "path": rel, "field": flag})
                        elif value:
                            blockers.append({"kind": "unsafe_proof_policy_enabled",
                                             "path": rel, "field": flag})
            except DuplicateJSONMemberError as err:
                blockers.append({"kind": "duplicate_proof_json_member",
                                 "path": rel, "member": str(err)})
            except (ValueError, OSError, UnicodeError):
                blockers.append({"kind": "unreadable_proof_profile", "path": rel})
    config_path = root / PATHS["consensus"]
    production = {}
    if config_path.is_file():
        try:
            config = load_unique_json(config_path)
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
        except DuplicateJSONMemberError as err:
            blockers.append({"kind": "duplicate_consensus_json_member",
                             "path": PATHS["consensus"], "member": str(err)})
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
        "duplicate_proof_json_member", "duplicate_consensus_json_member",
        "unreviewed_w1_research_parameter_change",
        "unreadable_w1_guest_source", "escaped_w1_guest_source",
        "w1_guest_source_digest_mismatch",
        "unsupported_proof_receipt_kind", "invalid_proof_policy_flag_type",
        "unsafe_proof_policy_enabled",
        "production_claim_requires_independent_pq_review") for item in report["known_open_findings"]):
        raise SystemExit(2)

if __name__ == "__main__":
    main()
