//! One existing full leaf, one real conditional proof, one actual resolve.
//!
//! Expected claims below are comparison targets only. They are never submitted
//! as assumptions or substituted for a cryptographic receipt.
use super::{
    bounded, decode, event, sha, write_new, LoadedLeaf, MAX_BATCH_RECEIPT, TRNM_W1_BATCH_GUEST_ELF,
    TRNM_W1_BATCH_GUEST_ID,
};
use anyhow::{bail, ensure, Context, Result};
use risc0_zkp::verify::VerificationError;
use risc0_zkvm::{
    sha::Digestible as _, ApiClient, AssetRequest, Assumption, Digest, InnerAssumptionReceipt,
    InnerReceipt, Output, ProverOpts, Receipt, ReceiptClaim, SuccinctReceipt,
};
use serde_json::json;
use std::{path::Path, time::Instant};

const PINNED_GUEST_SHA256: &str =
    "734eb42893951b0915f86e4517a231b04279ace8f8d81ca2dd79d6ed95771219";
const PINNED_BATCH_IMAGE: [u32; 8] = [
    1000984451, 3139256748, 3364805072, 2363167537, 26593440, 771198122, 3700220126, 2888495343,
];
const ORIGINAL_RECEIPT_SHA256: &str =
    "ca4d3c9f5159b7001abae7491604cadbbbfa97c0f93d90d5943e48936813ca2b";
const ORIGINAL_WORK_ID: &str = "ccf544056c6df13a5ab4e6c021e587ff0008d92388270e64f72a6e2168a326cd";
const MAX_COMPOSITE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SESSION_SEGMENTS: usize = 64;

pub(super) fn require_pinned_leaf(loaded: &[LoadedLeaf]) -> Result<()> {
    ensure!(
        loaded.len() == 1,
        "staged calibration requires exactly one work"
    );
    ensure!(
        loaded[0].receipt_sha256 == ORIGINAL_RECEIPT_SHA256
            && hex::encode(loaded[0].identity) == ORIGINAL_WORK_ID,
        "staged calibration must reuse the exact existing full leaf"
    );
    ensure!(
        sha(TRNM_W1_BATCH_GUEST_ELF) == PINNED_GUEST_SHA256
            && TRNM_W1_BATCH_GUEST_ID == PINNED_BATCH_IMAGE,
        "staged host must retain the actually compiled attempt5 guest"
    );
    Ok(())
}

fn expected_conditional(leaf: &LoadedLeaf, journal: &[u8]) -> Result<ReceiptClaim> {
    let assumption = Assumption {
        // load_leaves has already verified this actual receipt with the frozen
        // original image and empty assumptions. A manifest supplies no claim.
        claim: leaf.receipt.claim()?.digest(),
        control_root: Digest::ZERO,
    };
    let mut expected = ReceiptClaim::ok(TRNM_W1_BATCH_GUEST_ID, journal.to_vec());
    expected.output = Some(Output {
        journal: journal.to_vec().into(),
        assumptions: vec![assumption].into(),
    })
    .into();
    Ok(expected)
}

fn record_inner(
    out: &Path,
    stage: &str,
    filename: &str,
    receipt: &SuccinctReceipt<ReceiptClaim>,
    wall_ns: u128,
) -> Result<()> {
    let bytes = bincode::serialize(receipt)?;
    ensure!(
        bytes.len() as u64 <= MAX_BATCH_RECEIPT,
        "inner receipt bound"
    );
    write_new(&out.join(filename), &bytes)?;
    receipt
        .verify_integrity()
        .context("actual recursive STARK integrity")?;
    event(
        out,
        json!({"stage":stage,"artifact":filename,"operation_wall_ns":wall_ns,
            "receipt_bytes":bytes.len(),"receipt_sha256":sha(&bytes),
            "claim_digest":receipt.claim.digest().to_string(),
            "inner_stark_integrity_verified":true,"distinct_work_count":1}),
    )
}

fn require_claim_mismatch(
    result: std::result::Result<(), VerificationError>,
    expected_digest: Digest,
    received_digest: Digest,
) -> Result<String> {
    // The pinned SDK implements Debug via Display. Diagnostic text is not
    // an enum discriminant; match the type and both independently bound fields.
    match result {
        Err(error @ VerificationError::ClaimDigestMismatch { expected, received })
            if expected == expected_digest && received == received_digest =>
        {
            ensure!(
                expected != received,
                "claim mismatch must have distinct digests"
            );
            Ok(format!("{error:?}"))
        }
        Err(error) => bail!("unexpected final-verifier rejection: {error:?}"),
        Ok(()) => bail!("final verifier accepted a required negative control"),
    }
}

fn reject_valid_conditional(
    receipt: &Receipt,
    leaf: &LoadedLeaf,
    expected_journal: &[u8],
) -> Result<String> {
    let inner = receipt.inner.succinct().context("conditional STARK kind")?;
    ensure!(
        receipt.metadata.verifier_parameters == inner.verifier_parameters,
        "conditional metadata must match the genuine inner proof"
    );
    // Receipt::verify_integrity_with_context currently requires empty
    // assumptions too. Use the actual inner STARK verifier, then check every
    // application claim field ourselves before exercising final verify().
    inner
        .verify_integrity()
        .context("valid conditional STARK")?;
    let expected = expected_conditional(leaf, expected_journal)?;
    ensure!(
        receipt.journal.bytes == expected_journal && inner.claim.digest() == expected.digest(),
        "complete conditional claim: exact image/input/post/halt/journal/one leaf"
    );
    let claim = inner
        .claim
        .as_value()
        .context("open actual conditional claim")?;
    let output = claim
        .output
        .as_value()
        .context("open actual conditional output")?
        .as_ref()
        .context("conditional output exists")?;
    let assumptions = output
        .assumptions
        .as_value()
        .context("open actual assumptions")?;
    ensure!(
        assumptions.len() == 1,
        "exactly one real unresolved assumption"
    );
    let assumption = assumptions[0]
        .as_value()
        .context("open actual assumption")?;
    ensure!(
        assumption.claim == leaf.receipt.claim()?.digest()
            && assumption.control_root == Digest::ZERO,
        "actual assumption must be the verified original leaf, self-composition"
    );
    // This typed error check cannot replace the successful inner STARK and
    // whole-claim checks above. Neither digest comes from diagnostic text.
    require_claim_mismatch(
        receipt.verify(TRNM_W1_BATCH_GUEST_ID),
        ReceiptClaim::ok(TRNM_W1_BATCH_GUEST_ID, expected_journal.to_vec()).digest(),
        expected.digest(),
    )
}

pub(super) fn resolve_one(
    r0vm: &Path,
    leaf: &LoadedLeaf,
    composite_receipt: Receipt,
    expected_journal: &[u8],
    out: &Path,
) -> Result<Receipt> {
    // Preserve a bounded returned artifact before interpreting it, including
    // genuine prover outputs later rejected by these checks.
    let composite_bytes = bincode::serialize(&composite_receipt)?;
    ensure!(
        composite_bytes.len() <= MAX_COMPOSITE_BYTES,
        "composite receipt bound"
    );
    write_new(&out.join("composite.bin"), &composite_bytes)?;
    ensure!(
        composite_receipt.journal.bytes == expected_journal,
        "composite full journal"
    );
    let composite = match &composite_receipt.inner {
        InnerReceipt::Composite(value) => value,
        _ => bail!("actual composite receipt required before manual compression"),
    };
    ensure!(
        (1..=MAX_SESSION_SEGMENTS).contains(&composite.segments.len()),
        "batch-session segment count bound"
    );
    ensure!(
        matches!(
            composite.assumption_receipts.as_slice(),
            [InnerAssumptionReceipt::Succinct(_)]
        ),
        "one attached real succinct leaf receipt required"
    );
    // Composite verify checks its attached assumption proof. Its claim() then
    // erases that assumption, so this is a positive composite check only.
    composite_receipt.verify(TRNM_W1_BATCH_GUEST_ID)?;
    ensure!(
        composite
            .segments
            .last()
            .context("last actual segment")?
            .claim
            .output
            .digest()
            == expected_conditional(leaf, expected_journal)?
                .output
                .digest(),
        "last segment must bind the full journal and exact original leaf assumption"
    );
    event(
        out,
        json!({"stage":"REAL_COMPOSITE_VERIFIED","segments":composite.segments.len(),
            "receipt_bytes":composite_bytes.len(),"receipt_sha256":sha(&composite_bytes),
            "composite_is_not_the_conditional_negative":true,"distinct_work_count":1}),
    )?;

    // Normal narrow SDK version checks; no default/remote connector or override.
    let api = ApiClient::new_sub_process(r0vm)?;
    let opts = ProverOpts::succinct();
    let mut rollup: Option<SuccinctReceipt<ReceiptClaim>> = None;
    for (index, segment) in composite.segments.iter().enumerate() {
        let started = Instant::now();
        event(out, json!({"stage":"LIFT_STARTED","segment_index":index}))?;
        let lifted = api.lift(&opts, segment.clone().try_into()?, AssetRequest::Inline)?;
        record_inner(
            out,
            "LIFT_VERIFIED",
            &format!("lift-{index:04}.inner.bin"),
            &lifted,
            started.elapsed().as_nanos(),
        )?;
        ensure!(
            lifted.claim.digest() == segment.claim.digest(),
            "lift preserves segment claim"
        );
        rollup = Some(match rollup {
            None => lifted,
            Some(left) => {
                // Only consecutive segments from this single batch session are
                // joined. Independent original leaf proofs are never joined.
                let expected_join = left.claim.join(&lifted.claim)?.digest();
                let started = Instant::now();
                event(
                    out,
                    json!({"stage":"JOIN_STARTED","right_segment_index":index}),
                )?;
                let joined = api.join(
                    &opts,
                    left.try_into()?,
                    lifted.try_into()?,
                    AssetRequest::Inline,
                )?;
                record_inner(
                    out,
                    "JOIN_VERIFIED",
                    &format!("join-{index:04}.inner.bin"),
                    &joined,
                    started.elapsed().as_nanos(),
                )?;
                ensure!(
                    joined.claim.digest() == expected_join,
                    "join preserves continuation claim"
                );
                joined
            }
        });
    }
    let conditional = Receipt::new(
        InnerReceipt::Succinct(rollup.context("nonempty batch session")?),
        expected_journal.to_vec(),
    );
    let conditional_bytes = bincode::serialize(&conditional)?;
    ensure!(
        conditional_bytes.len() as u64 <= MAX_BATCH_RECEIPT,
        "conditional receipt bound"
    );
    write_new(&out.join("conditional.bin"), &conditional_bytes)?;
    // Test the real retained wire artifact, not an altered claim or bad seal.
    let conditional = decode(
        &bounded(&out.join("conditional.bin"), MAX_BATCH_RECEIPT)?,
        MAX_BATCH_RECEIPT,
    )?;
    let rejection = reject_valid_conditional(&conditional, leaf, expected_journal)?;
    event(
        out,
        json!({"stage":"VALID_CONDITIONAL_REJECTED","receipt_sha256":sha(&conditional_bytes),
            "receipt_bytes":conditional_bytes.len(),"inner_stark_integrity_verified":true,
            "complete_conditional_claim_verified":true,"actual_assumption_count":1,
            "actual_verify_error":rejection,"work_id":ORIGINAL_WORK_ID}),
    )?;

    // A second real negative uses the already verified original leaf under
    // the wrong final image. This generates no new proof or work identity.
    let wrong_image_bytes = bincode::serialize(&leaf.receipt)?;
    write_new(&out.join("wrong-image-real-leaf.bin"), &wrong_image_bytes)?;
    let wrong_image_error = require_claim_mismatch(
        leaf.receipt.verify(TRNM_W1_BATCH_GUEST_ID),
        ReceiptClaim::ok(TRNM_W1_BATCH_GUEST_ID, leaf.receipt.journal.bytes.clone()).digest(),
        leaf.receipt.claim()?.digest(),
    )?;
    event(
        out,
        json!({"stage":"VALID_LEAF_WRONG_IMAGE_REJECTED",
        "receipt_sha256":sha(&wrong_image_bytes),"actual_verify_error":wrong_image_error,
        "original_leaf_already_verified":true,"distinct_work_count":1}),
    )?;

    let started = Instant::now();
    event(
        out,
        json!({"stage":"RESOLVE_STARTED","original_leaf_sha256":ORIGINAL_RECEIPT_SHA256}),
    )?;
    // The API server expects typed SuccinctReceipt<ReceiptClaim> bincode and
    // performs into_unknown internally. Supply the actual already-verified
    // original receipt, never a ReceiptClaim or a claim-only assumption.
    let resolved = api.resolve(
        &opts,
        conditional.inner.succinct()?.clone().try_into()?,
        leaf.receipt.inner.succinct()?.clone().try_into()?,
        AssetRequest::Inline,
    )?;
    record_inner(
        out,
        "RESOLVE_INNER_VERIFIED",
        "resolved.inner.bin",
        &resolved,
        started.elapsed().as_nanos(),
    )?;
    ensure!(
        resolved.claim.digest()
            == ReceiptClaim::ok(TRNM_W1_BATCH_GUEST_ID, expected_journal.to_vec()).digest(),
        "resolve must preserve all fields and remove the sole assumption"
    );
    let resolved_output = resolved.claim.as_value()?.output.as_value()?;
    ensure!(
        resolved_output
            .as_ref()
            .context("resolved output")?
            .assumptions
            .is_empty(),
        "resolved actual assumptions must be empty"
    );
    let receipt = Receipt::new(InnerReceipt::Succinct(resolved), expected_journal.to_vec());
    receipt
        .verify(TRNM_W1_BATCH_GUEST_ID)
        .context("actual resolved final verify")?;
    event(
        out,
        json!({"stage":"ACTUAL_RESOLVE_FINAL_VERIFY_PASSED","distinct_work_count":1,
            "new_full_leaf_proofs":0,"benefit_gate":"NOT_EVALUATED",
            "original_leaf_prover_costs_included":false,"production_activation":false}),
    )?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_negative_requires_the_exact_category_and_both_digests() {
        let expected = Digest::from([1_u32; 8]);
        let received = Digest::from([2_u32; 8]);
        let other = Digest::from([3_u32; 8]);
        let mismatch =
            |expected, received| Err(VerificationError::ClaimDigestMismatch { expected, received });
        assert!(require_claim_mismatch(mismatch(expected, received), expected, received).is_ok());
        for result in [
            Ok(()),
            Err(VerificationError::InvalidProof),
            Err(VerificationError::ReceiptFormatError),
            Err(VerificationError::JournalDigestMismatch),
            mismatch(other, received),
            mismatch(expected, other),
            mismatch(received, expected),
        ] {
            assert!(require_claim_mismatch(result, expected, received).is_err());
        }
        assert!(require_claim_mismatch(mismatch(expected, expected), expected, expected).is_err());
    }
}
