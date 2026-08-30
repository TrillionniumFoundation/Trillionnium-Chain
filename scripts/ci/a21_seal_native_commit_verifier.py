#!/usr/bin/env python3
"""Seal the native commit-receipt verifier authority boundary.

This is an intentionally one-shot source transform. The exact-head workflow
removes both this script and itself before publishing the tested source commit.
"""

from pathlib import Path


SOURCE = Path("trillionnium/crates/trnm-poco-node/src/tx_admission_wal.rs")
LIB = Path("trillionnium/crates/trnm-poco-node/src/lib.rs")
CARGO = Path("trillionnium/crates/trnm-poco-node/Cargo.toml")
DOC = Path(
    "docs/development/packages/TRNM_A21_P1_SEAL_NATIVE_COMMIT_VERIFIER_V1.md"
)


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label} drift: expected exactly one marker, got {count}")
    return text.replace(old, new)


def seal_source() -> None:
    text = SOURCE.read_text(encoding="utf-8")
    if "TX_ADMISSION_NATIVE_COMMIT_VERIFIER_SEALED_V1" in text:
        raise SystemExit("native commit verifier is already sealed")

    truth_marker = "\n".join(
        [
            "pub const TX_ADMISSION_BOUNDARY_NATIVE_READBACK_V0: bool = true;",
            "pub const TX_ADMISSION_BOUNDARY_NATIVE_READBACK_PRODUCTION_V0: bool = false;",
            "",
            "const SCHEMA_VERSION_V0",
        ]
    )
    truth_replacement = "\n".join(
        [
            "pub const TX_ADMISSION_BOUNDARY_NATIVE_READBACK_V0: bool = true;",
            "pub const TX_ADMISSION_BOUNDARY_NATIVE_READBACK_PRODUCTION_V0: bool = false;",
            "/// Native commit-receipt verification is sealed to implementations owned by this crate.",
            "pub const TX_ADMISSION_NATIVE_COMMIT_VERIFIER_SEALED_V1: bool = true;",
            "",
            "const SCHEMA_VERSION_V0",
        ]
    )
    text = replace_once(text, truth_marker, truth_replacement, "sealed truth flag")

    trait_marker = """/// Explicit verifier boundary for the application store and native PoCO
/// finality proof. A production implementation must read back the exact
/// transaction/result from durable application state and independently verify
/// the finalized block/QC before returning `Ok(())`.
pub trait NativeCommitReceiptVerifierV0 {
    fn verify_application_and_finality_v0(
        &self,
        metadata: &SignedEnvelopeMetadata,
        evidence: &NativeCommitReceiptEvidenceV0,
    ) -> Result<(), TxAdmissionWalErrorV0>;
}"""
    trait_replacement = """mod native_commit_receipt_verifier_seal_v1 {
    pub trait Sealed {}
}

/// Crate-owned verifier boundary for the application store and native PoCO
/// finality proof. A production implementation must read back the exact
/// transaction/result from durable application state and independently verify
/// the finalized block/QC before returning `Ok(())`.
///
/// The supertrait is private by design: downstream crates may call the public
/// verification API but cannot install an always-accept verifier and mint a
/// durable commit capability from caller assertions.
///
/// ```compile_fail
/// use trnm_poco_node::{
///     NativeCommitReceiptEvidenceV0, NativeCommitReceiptVerifierV0,
///     TxAdmissionWalErrorV0,
/// };
/// use trnm_mempool::SignedEnvelopeMetadata;
///
/// struct ForgedAlwaysAcceptCommitVerifier;
///
/// impl NativeCommitReceiptVerifierV0 for ForgedAlwaysAcceptCommitVerifier {
///     fn verify_application_and_finality_v0(
///         &self,
///         _metadata: &SignedEnvelopeMetadata,
///         _evidence: &NativeCommitReceiptEvidenceV0,
///     ) -> Result<(), TxAdmissionWalErrorV0> {
///         Ok(())
///     }
/// }
/// ```
#[allow(private_bounds)]
pub trait NativeCommitReceiptVerifierV0:
    native_commit_receipt_verifier_seal_v1::Sealed
{
    fn verify_application_and_finality_v0(
        &self,
        metadata: &SignedEnvelopeMetadata,
        evidence: &NativeCommitReceiptEvidenceV0,
    ) -> Result<(), TxAdmissionWalErrorV0>;
}"""
    text = replace_once(text, trait_marker, trait_replacement, "sealed verifier trait")

    durable_marker = """impl NativeCommitReceiptVerifierV0 for DurableNativeCommitReceiptVerifierV0<'_> {"""
    durable_replacement = """impl native_commit_receipt_verifier_seal_v1::Sealed
    for DurableNativeCommitReceiptVerifierV0<'_>
{
}

impl NativeCommitReceiptVerifierV0 for DurableNativeCommitReceiptVerifierV0<'_> {"""
    text = replace_once(text, durable_marker, durable_replacement, "durable verifier seal")

    accept_marker = """    struct AcceptingCommitVerifier;

    impl NativeCommitReceiptVerifierV0 for AcceptingCommitVerifier {"""
    accept_replacement = """    struct AcceptingCommitVerifier;

    impl super::native_commit_receipt_verifier_seal_v1::Sealed for AcceptingCommitVerifier {}

    impl NativeCommitReceiptVerifierV0 for AcceptingCommitVerifier {"""
    text = replace_once(text, accept_marker, accept_replacement, "accepting test seal")

    reject_marker = """    struct RejectingCommitVerifier;

    impl NativeCommitReceiptVerifierV0 for RejectingCommitVerifier {"""
    reject_replacement = """    struct RejectingCommitVerifier;

    impl super::native_commit_receipt_verifier_seal_v1::Sealed for RejectingCommitVerifier {}

    impl NativeCommitReceiptVerifierV0 for RejectingCommitVerifier {"""
    text = replace_once(text, reject_marker, reject_replacement, "rejecting test seal")

    test_marker = """    fn fixture() -> FixtureEnvelope {"""
    test_replacement = """    #[test]
    fn native_commit_verifier_authority_is_sealed_v1() {
        assert!(TX_ADMISSION_NATIVE_COMMIT_VERIFIER_SEALED_V1);
        assert!(TX_ADMISSION_BOUNDARY_NATIVE_READBACK_V0);
        assert!(!TX_ADMISSION_BOUNDARY_NATIVE_READBACK_PRODUCTION_V0);
    }

    fn fixture() -> FixtureEnvelope {"""
    text = replace_once(text, test_marker, test_replacement, "sealed authority regression")

    SOURCE.write_text(text, encoding="utf-8")


def expose_truth() -> None:
    text = LIB.read_text(encoding="utf-8")
    marker = """    TX_ADMISSION_BOUNDARY_NATIVE_READBACK_V0, TX_ADMISSION_BOUNDARY_PRODUCTION_ACTIVATION_V0,
    TX_ADMISSION_BOUNDARY_RUNTIME_COMPOSITION_V0,"""
    replacement = """    TX_ADMISSION_BOUNDARY_NATIVE_READBACK_V0, TX_ADMISSION_BOUNDARY_PRODUCTION_ACTIVATION_V0,
    TX_ADMISSION_BOUNDARY_RUNTIME_COMPOSITION_V0, TX_ADMISSION_NATIVE_COMMIT_VERIFIER_SEALED_V1,"""
    text = replace_once(text, marker, replacement, "root sealed truth export")
    LIB.write_text(text, encoding="utf-8")


def update_metadata() -> None:
    text = CARGO.read_text(encoding="utf-8")
    marker = """tx_admission_handoff_readback = false
tx_admission_tombstone_gc = true"""
    replacement = """tx_admission_handoff_readback = false
tx_admission_native_commit_verifier_sealed = true
tx_admission_tombstone_gc = true"""
    text = replace_once(text, marker, replacement, "sealed verifier metadata")
    CARGO.write_text(text, encoding="utf-8")


def create_documentation() -> None:
    if DOC.exists():
        raise SystemExit(f"documentation already exists: {DOC}")
    DOC.parent.mkdir(parents=True, exist_ok=True)
    DOC.write_text(
        """# A21 / P1 seal native commit-receipt verifier v1

Status: **candidate implementation generated; exact-head verification required; no production activation**

## Security defect

`NativeCommitReceiptEvidenceV0::verify_with` returns the private
`VerifiedNativeCommitReceiptV0` capability consumed by the durable handed-off
commit transition. Before this package, any downstream crate could implement
`NativeCommitReceiptVerifierV0` as an always-accept verifier and mint that
capability from shape-valid caller assertions.

## Candidate repair

- make `NativeCommitReceiptVerifierV0` extend a private sealed supertrait;
- implement the seal only for the real `DurableNativeCommitReceiptVerifierV0`
  and explicitly named in-module test verifiers;
- retain the public read-only verifier contract and private token fields;
- add a downstream `compile_fail` proof that an external always-accept verifier
  cannot implement the authority;
- expose a machine truth constant and Cargo metadata bit for the sealed boundary;
- leave native readback production activation, CheckTx, signing, broadcast,
  production candidacy and consensus activation false.

## Required exact-head evidence

```text
workspace all-targets compile
trnm-poco-node tx-admission-wal Clippy -D warnings
downstream verifier-forgery compile-fail doctest
new sealed-authority regression
all retained transaction-admission WAL regressions
canonical Plan and Native PoCO pre-cutover truth
clean source tree with no write-capable one-shot workflow or transform script
```

## Non-claims

```text
tx_admission_native_commit_verifier_sealed = true
tx_admission_boundary_native_readback = true
tx_admission_boundary_native_readback_production = false
tx_admission_handoff_readback = false
tx_admission_boundary_production_activation = false
tx_admission_boundary_signing = false
tx_admission_boundary_broadcast = false
independent_review_closed = false
g1_exit = false
production_candidate = false
production_consensus_activation = false
release_ready = false
```

The repair prevents downstream capability forgery. It does not prove that the
real durable verifier is production-owned, does not create a production
application/finality lifetime owner, and does not resolve external review,
HSM/anchor, physical power-loss, multi-host, audit or soak blockers.
""",
        encoding="utf-8",
    )


def main() -> None:
    seal_source()
    expose_truth()
    update_metadata()
    create_documentation()


if __name__ == "__main__":
    main()
