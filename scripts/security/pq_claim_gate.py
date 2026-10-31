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
import os
from pathlib import Path

PATHS = {
    "hepta_handoff": "trillionnium/crates/trnm-research-protocol/src/hepta_handoff.rs",
    "cell_discovery": "trillionnium/crates/trnm-data-availability/src/cell/discovery.rs",
    "da_auth": "trillionnium/crates/trnm-data-availability/src/types.rs",
    "da_retrieval": "trillionnium/crates/trnm-data-availability/src/retrieval.rs",
    "transport_ingress": "trillionnium/crates/trnm-pon-node/src/ingress.rs",
    "legacy_transfer": "trillionnium/crates/trnm-types/src/transfer.rs",
    "native_m06_envelope": "trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs",
    "research_command": "trillionnium/crates/trnm-research-protocol/src/command.rs",
    "research_state": "trillionnium/crates/trnm-research-protocol/src/state.rs",
    "task_store": "trillionnium/crates/trnm-task-kernel/src/store.rs",
    "service_settlement": "trillionnium/crates/trnm-service-settlement/src/engine.rs",
    "w1_backend": "trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/backend-manifest.json",
    "consensus": "config/consensus-mainline.json",
}
CLASSICAL_MARKERS = {
    "hepta_handoff": ("ed25519_dalek", "SignedHeptaAdmissionV1"),
    "cell_discovery": ("ed25519_dalek", "CellProviderRecordV1"),
    "da_auth": ("DaCommitteeDescriptorV1", "DaBatchAuthorV1",
                "author_key_scheme: STRICT_ED25519_SCHEME_V1",
                "pub(crate) fn verify_strict("),
    "da_retrieval": ("RetrievalRequesterAuthorityV1",
                     "requester_key_scheme: STRICT_ED25519_SCHEME_V1",
                     "responder_key_scheme: STRICT_ED25519_SCHEME_V1",
                     "verify_strict("),
    "transport_ingress": ("verify_hex_strict", "fn authenticate_request("),
    "legacy_transfer": ("ed25519_dalek", 'algo != "ed25519"', "impl TransferTx"),
    "native_m06_envelope": ("pub fn validate_main_envelope(",
                            "if pq_accounts_v2::enabled(cfg) {",
                            "if pq_native_v1::enabled(cfg) {", "verify_hex_strict("),
    "research_command": ("ed25519_dalek", "SignedResearchCommandV1"),
    "research_state": ("pub fn authorizes_identity(", "signed.validate()?;",
                       "self.authorities.authorizes(signed)"),
    "task_store": ("ed25519_dalek", "verify_strict("),
    "service_settlement": ("SIGNATURE_SCHEME_ED25519_V1", "verify_signature_entry("),
}
# These are code-level candidate trust boundaries, not evidence that a
# production network currently routes through any of the paths.
CLASSICAL_BOUNDARY_ROLES = {
    "hepta_handoff": "hepta_artifact_admission_v1",
    "cell_discovery": "cell_provider_advertising_v1",
    "da_auth": "data_availability_committee_batch_author_attestation_v1",
    "da_retrieval": "data_availability_retrieval_request_and_response_v1",
    "transport_ingress": "allowlisted_development_node_transport",
    "legacy_transfer": "transfer_transaction_signature",
    "native_m06_envelope": "native_m06_pnx1_classical_signature_profile",
    "research_command": "research_command_nakama_hepta_authority",
    "research_state": "research_state_classical_nakama_hepta_authority_set",
    "task_store": "agent_market_controller_session_auth",
    "service_settlement": "bilateral_settlement_authorization",
}
# These two findings describe the known unqualified baseline, not successful
# PQ migration. Every *other* finding, including new future kinds, is fatal
# for --assert-unqualified unless explicitly reviewed and classified here.
EXPECTED_UNQUALIFIED_FINDINGS = frozenset(("classical_authority", "unqualified_proof"))
UNQUALIFIED_ASSERTIONS = (
    "pq_chain_qualified", "complete_authority_inventory_reviewed",
    "quantum_work_lower_bound_proven", "independent_cryptographic_acceptance",
)
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
        "../../src/pon_work/full_relation_tests.rs": "3c85efae06acc62d5fdbce3d8b1e0f8a65e59675da0a6e741885952ccaad513b",
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

# Fail closed on *new* W1 research fields as well as changes to pinned values.
# A downstream proof/receipt reader may interpret unknown fields as active
# policy even while the frozen research profile still says PQ128=false.
# Any extension requires an independently reviewed, versioned profile.
ALLOWED_W1_RESEARCH_FIELDS = (
    frozenset(PINNED_W1_RESEARCH_PARAMETERS)
    | frozenset(PROOF_RESEARCH_ONLY_FALSE_FLAGS)
    | frozenset(("pq_128_security_qualified", "proof_receipt_kind"))
)

# The non-production consensus declaration is also authority-bearing metadata.
# Preserve its known research-only keys and explicit negative assertions; a
# newly added activation/PQ-claim alias must not bypass the four old flags.
# This is an audit schema pin, NOT a deployed consensus or PQ certificate.
PINNED_CONSENSUS_UNQUALIFIED_PARAMETERS = {
    "schema": "trnm-consensus-mainline-truth-v2",
    "development_target": "pon-nakamoto-v1",
    "stage": "invariant-driven-native-application-candidate",
    "runtime_implemented": False,
    "work_profile_qualified": False,
    "active_consensus_implementation": None,
    "historical_consensus_sources_present": False,
    "source_inventory": "config/portability-inventory-v1.json",
    "experimental_contracts": "config/pon/module-contracts-v1.json",
    "module_maturity": "config/pon/module-maturity-v1.json",
    "invariant_contract": "config/pon/invariants-v2.json",
}
# The checked-out consensus declaration is explicitly research-only. A nonempty
# scope is not sufficient: changing this text can turn the same false flags
# into an apparent production assertion for a downstream parser.
PINNED_NATIVE_APPLICATION_SCOPE = (
    "profile-gated-native-ledger-model-evidence-and-recovery-not-publicly-qualified"
)

ALLOWED_CONSENSUS_FIELDS = (
    frozenset(PINNED_CONSENSUS_UNQUALIFIED_PARAMETERS)
    | frozenset(PRODUCTION_FLAGS)
    | frozenset(("native_application_scope",))
)

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
        path = trusted_root / manifest_directory / source_rel
        try:
            resolved = path.resolve(strict=True)
            # Frozen guest bytes must be *real* checked-out source objects,
            # not a symlink to byte-identical content elsewhere in the tree.
            # abspath normalizes the legitimate ../../ source references;
            # resolve additionally follows symlinks. A mismatch is a redirect.
            lexical = Path(os.path.abspath(path))
            if (not resolved.is_relative_to(trusted_root)
                    or resolved != lexical or not resolved.is_file()):
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



def checkout_regular_source(root: Path, relative: str) -> bool:
    """Only audit real checkout files, never a redirected policy/authority path.

    A symlink to a *valid-looking* file inside the checkout is still a different
    Git source object. Resolve the root once; reject every symbolic-link hop,
    including parent directories, before trusting the bytes being inspected.
    """
    rel = Path(relative)
    if rel.is_absolute() or not rel.parts or ".." in rel.parts:
        return False
    try:
        trusted_root = root.resolve(strict=True)
        if not trusted_root.is_dir():
            return False
        candidate = trusted_root
        for component in rel.parts:
            candidate = candidate / component
            if candidate.is_symlink():
                return False
        return (candidate.is_file()
                and candidate.resolve(strict=True).is_relative_to(trusted_root))
    except (OSError, RuntimeError):
        return False


def inspect(root: Path) -> dict:
    blockers = []
    for label, rel in PATHS.items():
        file = root / rel
        if not file.is_file():
            blockers.append({"kind": "missing_source", "path": rel})
            continue
        if not checkout_regular_source(root, rel):
            blockers.append({"kind": "untrusted_checkout_source_path", "path": rel})
            continue
        if label in CLASSICAL_MARKERS:
            try:
                source = file.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                blockers.append({"kind": "unreadable_source", "path": rel})
                continue
            if all(marker in source for marker in CLASSICAL_MARKERS[label]):
                blockers.append({
                    "kind": "classical_authority", "path": rel,
                    "boundary": CLASSICAL_BOUNDARY_ROLES[label],
                })
            else:
                # An unreviewed rename/removal is NOT evidence that a classical
                # authority has been replaced by an effective PQ trust root.
                # Keep the boundary in the report and refuse claim-gate success.
                blockers.append({
                    "kind": "unreviewed_classical_authority_boundary_change",
                    "path": rel,
                    "boundary": CLASSICAL_BOUNDARY_ROLES[label],
                })
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
                    for field in sorted(set(profile) - ALLOWED_W1_RESEARCH_FIELDS):
                        blockers.append({
                            "kind": "unreviewed_w1_research_field",
                            "path": rel,
                            "field": field,
                        })
                    for field, expected in PINNED_W1_RESEARCH_PARAMETERS.items():
                        observed = profile.get(field)
                        if field not in profile or type(observed) is not type(expected) or observed != expected:
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
                # Unknown fields may be interpreted as authority/activation
                # policy by a future consumer, even with known flags false.
                for field in sorted(set(config) - ALLOWED_CONSENSUS_FIELDS):
                    blockers.append({
                        "kind": "unreviewed_consensus_profile_field",
                        "path": PATHS["consensus"], "field": field,
                    })
                for field, expected in PINNED_CONSENSUS_UNQUALIFIED_PARAMETERS.items():
                    observed = config.get(field)
                    if (field not in config or type(observed) is not type(expected)
                            or observed != expected):
                        blockers.append({
                            "kind": "unreviewed_consensus_unqualified_parameter_change",
                            "path": PATHS["consensus"], "field": field,
                        })
                scope = config.get("native_application_scope")
                if type(scope) is not str or not scope:
                    blockers.append({
                        "kind": "invalid_consensus_scope", "path": PATHS["consensus"],
                    })
                elif scope != PINNED_NATIVE_APPLICATION_SCOPE:
                    blockers.append({
                        "kind": "unreviewed_consensus_scope_change",
                        "path": PATHS["consensus"],
                        "field": "native_application_scope",
                    })
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

def has_unreviewed_findings(report: dict) -> bool:
    """Default-deny newly introduced audit findings or accidental PQ claims."""
    if any(report.get(field) is not False for field in UNQUALIFIED_ASSERTIONS):
        return True
    findings = report.get("known_open_findings")
    if not isinstance(findings, list):
        return True
    return any(
        not isinstance(item, dict)
        or item.get("kind") not in EXPECTED_UNQUALIFIED_FINDINGS
        for item in findings
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--assert-unqualified", action="store_true",
                        help="Fail if an unsafe production claim or missing/malformed source is found")
    args = parser.parse_args()
    report = inspect(args.root)
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.assert_unqualified and has_unreviewed_findings(report):
        raise SystemExit(2)

if __name__ == "__main__":
    main()
