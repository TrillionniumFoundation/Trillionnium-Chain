//! The only accepted full-receipt profile for this isolated experiment.
//!
//! These pins identify a construction, not a claimed quantum security level.
//! Neither caller metadata nor an SDK upgrade may widen the accepted suite.
use anyhow::{ensure, Context, Result};
use risc0_zkvm::{
    sha::Digestible, Receipt, ReceiptClaim, SuccinctReceipt, SuccinctReceiptVerifierParameters,
    VerifierContext,
};

pub const PROFILE_ID: &str = "trnm-w1-risc0-3.0.6-poseidon2-join-v1";
pub const HASH_SUITE: &str = "poseidon2";
pub const CONTROL_ID: &str = "7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e";
pub const PARAMETERS: &str = "ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013";
pub const CONTROL_MERKLE_DEPTH: usize = 8;
pub const IMAGE_ID: [u32; 8] = [
    4203990569, 1706128024, 889896351, 2751765305, 3434005897, 1411617246, 870515685, 3215144349,
];

pub fn context() -> Result<VerifierContext> {
    // The digest commits to the SDK's exact outer/inner control roots and
    // protocol/circuit identifiers. A changed default fails, never migrates.
    let parameters = SuccinctReceiptVerifierParameters::default();
    ensure!(
        parameters.digest().to_string() == PARAMETERS,
        "compiled verifier parameters differ from frozen profile"
    );
    ensure!(
        parameters.inner_control_root.is_none(),
        "hash-changing recursive wrapper is outside frozen profile"
    );
    let mut suites = VerifierContext::default_hash_suites();
    suites.retain(|name, _| name == HASH_SUITE);
    ensure!(suites.len() == 1, "frozen hash suite unavailable");
    // Empty means no segment, Groth16, Composite or dev-mode verification
    // capability. Only this explicitly pinned recursive STARK is installed.
    Ok(VerifierContext::empty()
        .with_suites(suites)
        .with_succinct_verifier_parameters(parameters))
}

fn check_control_inclusion(
    inner: &SuccinctReceipt<ReceiptClaim>,
    context: &VerifierContext,
) -> Result<()> {
    ensure!(
        inner.hashfn == HASH_SUITE,
        "proof hash suite outside frozen profile"
    );
    let proof = &inner.control_inclusion_proof;
    ensure!(
        proof.digests.len() == CONTROL_MERKLE_DEPTH && proof.index < (1u32 << CONTROL_MERKLE_DEPTH),
        "noncanonical control inclusion path"
    );
    let suite = context
        .suites
        .get(HASH_SUITE)
        .context("frozen hash suite")?;
    // The SDK's control Merkle path calls hash_pair directly, unlike its
    // STARK Merkle verifier. Poseidon2 asserts on unreduced digest words.
    // Reject all caller-supplied leaves/siblings before entering that path.
    ensure!(
        suite.hashfn.is_digest_valid(&inner.control_id)
            && proof
                .digests
                .iter()
                .all(|digest| suite.hashfn.is_digest_valid(digest)),
        "noncanonical control inclusion digest"
    );
    Ok(())
}

/// Integrity-only diagnostic; it does not establish the complete W1 claim.
pub fn verify_recursion(inner: &SuccinctReceipt<ReceiptClaim>) -> Result<()> {
    ensure!(
        inner.verifier_parameters.to_string() == PARAMETERS,
        "receipt verifier parameters outside frozen profile"
    );
    let context = context()?;
    check_control_inclusion(inner, &context)?;
    inner
        .verify_integrity_with_context(&context)
        .context("recursive integrity diagnostic")
}

pub fn verify(receipt: &Receipt) -> Result<()> {
    verify_image(receipt, IMAGE_ID)
}

/// The caller must pin the image in its own reviewed profile; receipt metadata
/// and untrusted command-line input must never select this value.
pub fn verify_image(receipt: &Receipt, image_id: [u32; 8]) -> Result<()> {
    let inner = receipt
        .inner
        .succinct()
        .context("recursive STARK required")?;
    ensure!(
        inner.hashfn == HASH_SUITE,
        "proof hash suite outside frozen profile"
    );
    ensure!(
        inner.control_id.to_string() == CONTROL_ID,
        "final recursion control outside frozen profile"
    );
    ensure!(
        inner.verifier_parameters.to_string() == PARAMETERS
            && receipt.metadata.verifier_parameters.to_string() == PARAMETERS,
        "receipt verifier parameters outside frozen profile"
    );
    let context = context()?;
    check_control_inclusion(inner, &context)?;
    // Full successful image/claim/journal verification remains mandatory.
    // Integrity-only verification of a prefix can never satisfy this call.
    receipt
        .verify_with_context(&context, image_id)
        .context("full frozen image proof")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_has_only_the_named_transparent_construction() {
        let context = context().unwrap();
        assert_eq!(context.suites.keys().collect::<Vec<_>>(), vec![HASH_SUITE]);
        assert!(context.segment_verifier_parameters.is_none());
        assert!(context.groth16_verifier_parameters.is_none());
        assert!(!context.dev_mode());
        assert_eq!(
            context
                .succinct_verifier_parameters
                .unwrap()
                .digest()
                .to_string(),
            PARAMETERS
        );
    }
}
