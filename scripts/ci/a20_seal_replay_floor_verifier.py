#!/usr/bin/env python3
"""Seal and publish the A20 replay-floor verifier authority boundary.

This is a one-shot source transform. The exact-head workflow removes this file
and itself before publishing the tested candidate.
"""

from pathlib import Path


INC = Path(
    "trillionnium/crates/trnm-poco-node/src/tx_admission_wal_tombstone_gc_v1.inc"
)
LIB = Path("trillionnium/crates/trnm-poco-node/src/lib.rs")
CARGO = Path("trillionnium/crates/trnm-poco-node/Cargo.toml")
DOC = Path("docs/development/packages/TRNM_A20_P2_TX_TOMBSTONE_GC_V1.md")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label} drift: expected exactly one marker, got {count}")
    return text.replace(old, new)


def seal_verifier() -> None:
    text = INC.read_text(encoding="utf-8")
    if "TX_ADMISSION_REPLAY_FLOOR_VERIFIER_SEALED_V1" in text:
        raise SystemExit("replay-floor verifier is already sealed")

    truth_marker = "\n".join(
        [
            "/// A typed authenticated purge boundary exists for compact tombstones.",
            "pub const TX_ADMISSION_TOMBSTONE_AUTHENTICATED_PURGE_V1: bool = true;",
            "/// Neither compaction nor purge activates production transaction admission.",
        ]
    )
    truth_replacement = "\n".join(
        [
            "/// A typed authenticated purge boundary exists for compact tombstones.",
            "pub const TX_ADMISSION_TOMBSTONE_AUTHENTICATED_PURGE_V1: bool = true;",
            "/// Replay-floor verification is sealed to implementations owned by this crate.",
            "pub const TX_ADMISSION_REPLAY_FLOOR_VERIFIER_SEALED_V1: bool = true;",
            "/// Neither compaction nor purge activates production transaction admission.",
        ]
    )
    text = replace_once(text, truth_marker, truth_replacement, "sealed truth flag")

    contract_marker = "\n".join(
        [
            "    TX_ADMISSION_TOMBSTONE_COMPACTION_V1",
            "        && TX_ADMISSION_TOMBSTONE_AUTHENTICATED_PURGE_V1",
            "        && !TX_ADMISSION_TOMBSTONE_PRODUCTION_ACTIVATION_V1",
        ]
    )
    contract_replacement = "\n".join(
        [
            "    TX_ADMISSION_TOMBSTONE_COMPACTION_V1",
            "        && TX_ADMISSION_TOMBSTONE_AUTHENTICATED_PURGE_V1",
            "        && TX_ADMISSION_REPLAY_FLOOR_VERIFIER_SEALED_V1",
            "        && !TX_ADMISSION_TOMBSTONE_PRODUCTION_ACTIVATION_V1",
        ]
    )
    text = replace_once(
        text, contract_marker, contract_replacement, "candidate contract truth"
    )

    trait_marker = """pub trait TxAdmissionReplayFloorVerifierV1: fmt::Debug {
    fn verify_replay_floor_v1(
        &self,
        evidence: &TxAdmissionReplayFloorEvidenceV1,
    ) -> Result<(), TxAdmissionWalErrorV0>;
}"""
    trait_replacement = """mod replay_floor_verifier_seal_v1 {
    pub trait Sealed {}
}

/// Crate-owned authority that validates an application/finality replay floor.
///
/// The trait is intentionally sealed. Downstream crates may consume the
/// public evidence and verified-token API, but cannot install an always-accept
/// verifier or mint a purge capability from caller assertions.
///
/// ```compile_fail
/// use trnm_poco_node::{
///     TxAdmissionReplayFloorEvidenceV1, TxAdmissionReplayFloorVerifierV1,
///     TxAdmissionWalErrorV0,
/// };
///
/// #[derive(Debug)]
/// struct ForgedAlwaysAcceptVerifier;
///
/// impl TxAdmissionReplayFloorVerifierV1 for ForgedAlwaysAcceptVerifier {
///     fn verify_replay_floor_v1(
///         &self,
///         _evidence: &TxAdmissionReplayFloorEvidenceV1,
///     ) -> Result<(), TxAdmissionWalErrorV0> {
///         Ok(())
///     }
/// }
/// ```
pub trait TxAdmissionReplayFloorVerifierV1:
    replay_floor_verifier_seal_v1::Sealed + fmt::Debug
{
    fn verify_replay_floor_v1(
        &self,
        evidence: &TxAdmissionReplayFloorEvidenceV1,
    ) -> Result<(), TxAdmissionWalErrorV0>;
}"""
    text = replace_once(text, trait_marker, trait_replacement, "sealed verifier trait")

    accept_marker = """    #[derive(Debug)]
    struct AcceptFloorV1;

    impl TxAdmissionReplayFloorVerifierV1 for AcceptFloorV1 {"""
    accept_replacement = """    #[derive(Debug)]
    struct AcceptFloorV1;

    impl super::replay_floor_verifier_seal_v1::Sealed for AcceptFloorV1 {}

    impl TxAdmissionReplayFloorVerifierV1 for AcceptFloorV1 {"""
    text = replace_once(
        text, accept_marker, accept_replacement, "accepted test verifier sealing"
    )

    reject_marker = """    #[derive(Debug)]
    struct RejectFloorV1;

    impl TxAdmissionReplayFloorVerifierV1 for RejectFloorV1 {"""
    reject_replacement = """    #[derive(Debug)]
    struct RejectFloorV1;

    impl super::replay_floor_verifier_seal_v1::Sealed for RejectFloorV1 {}

    impl TxAdmissionReplayFloorVerifierV1 for RejectFloorV1 {"""
    text = replace_once(
        text, reject_marker, reject_replacement, "rejected test verifier sealing"
    )

    test_marker = """    fn temp_path_v1() -> PathBuf {"""
    test_replacement = """    #[test]
    fn replay_floor_verifier_authority_is_sealed_v1() {
        assert!(TX_ADMISSION_REPLAY_FLOOR_VERIFIER_SEALED_V1);
        assert!(tombstone_gc_candidate_contract_v1());
        assert!(!TX_ADMISSION_TOMBSTONE_PRODUCTION_ACTIVATION_V1);
    }

    fn temp_path_v1() -> PathBuf {"""
    text = replace_once(text, test_marker, test_replacement, "sealed authority regression")
    INC.write_text(text, encoding="utf-8")


def expose_safe_root_api() -> None:
    text = LIB.read_text(encoding="utf-8")
    type_marker = """    SqlitePendingNonceAuthorityV0, TxAdmissionWalErrorV0, VerifiedNativeCommitReceiptV0,"""
    type_replacement = """    SqlitePendingNonceAuthorityV0, TxAdmissionReplayFloorEvidenceV1,
    TxAdmissionReplayFloorVerifierV1, TxAdmissionTombstoneGcResultV1,
    TxAdmissionWalErrorV0, VerifiedNativeCommitReceiptV0, VerifiedTxAdmissionReplayFloorV1,"""
    text = replace_once(text, type_marker, type_replacement, "A20 root type exports")

    constant_marker = """    TX_ADMISSION_BOUNDARY_SIGNING_V0, TX_ADMISSION_WAL_PRODUCTION_ACTIVATION_V0,
    TX_ADMISSION_WAL_RUNTIME_COMPOSITION_V0,"""
    constant_replacement = """    TX_ADMISSION_BOUNDARY_SIGNING_V0, TX_ADMISSION_REPLAY_FLOOR_VERIFIER_SEALED_V1,
    TX_ADMISSION_TOMBSTONE_AUTHENTICATED_PURGE_V1,
    TX_ADMISSION_TOMBSTONE_COMPACTION_V1, TX_ADMISSION_TOMBSTONE_PRODUCTION_ACTIVATION_V1,
    TX_ADMISSION_WAL_PRODUCTION_ACTIVATION_V0, TX_ADMISSION_WAL_RUNTIME_COMPOSITION_V0,"""
    text = replace_once(
        text, constant_marker, constant_replacement, "A20 root truth exports"
    )
    LIB.write_text(text, encoding="utf-8")


def update_metadata() -> None:
    text = CARGO.read_text(encoding="utf-8")
    marker = """tx_admission_tombstone_authenticated_purge = true
tx_admission_tombstone_gc_production = false"""
    replacement = """tx_admission_tombstone_authenticated_purge = true
tx_admission_replay_floor_verifier_sealed = true
tx_admission_tombstone_gc_production = false"""
    text = replace_once(text, marker, replacement, "A20 sealed metadata")
    CARGO.write_text(text, encoding="utf-8")


def update_documentation() -> None:
    text = DOC.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "Status: **candidate-implemented / verification pending / no production activation**",
        "Status: **candidate-implemented / exact-head verification required / no production activation**",
        "A20 package status",
    )
    marker = """A compact tombstone can be physically deleted only with a private
`VerifiedTxAdmissionReplayFloorV1` token. The token is minted only after an
owner-installed `TxAdmissionReplayFloorVerifierV1` accepts evidence binding:"""
    replacement = """A compact tombstone can be physically deleted only with a private
`VerifiedTxAdmissionReplayFloorV1` token. The token is minted only after a
crate-owned `TxAdmissionReplayFloorVerifierV1` accepts evidence binding. The
verifier trait is sealed: downstream crates can inspect the public contract but
cannot implement an always-accept verifier or mint their own purge capability.
The evidence binds:"""
    text = replace_once(text, marker, replacement, "sealed verifier documentation")
    text = replace_once(
        text,
        "The generic verifier seam is an\nintegration point, not permission to accept caller assertions.",
        "The sealed verifier seam is an integration point for a future node-owned\napplication/finality adapter, not permission to accept caller assertions.",
        "A20 non-claim wording",
    )
    DOC.write_text(text, encoding="utf-8")


def main() -> None:
    seal_verifier()
    expose_safe_root_api()
    update_metadata()
    update_documentation()


if __name__ == "__main__":
    main()
