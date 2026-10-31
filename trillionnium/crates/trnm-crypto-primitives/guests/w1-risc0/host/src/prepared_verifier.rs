//! Immutable, locally pinned verifier state. Public claims can only reject;
//! every successful call still executes the original complete SDK verifier.
use super::receipt_bounds::{self, BoundaryError};
use anyhow::{ensure, Context, Result};
use risc0_binfmt::Digestible;
use risc0_zkvm::sha::{Digest, Impl};
use risc0_zkvm::{
    CompositeReceipt, ExitCode, InnerReceipt, MaybePruned, Receipt, ReceiptClaim, VerifierContext,
};

pub(super) struct PreparedVerifier {
    image: Digest,
    context: VerifierContext,
    composite_parameters: Digest,
    segment_parameters: Digest,
}

#[derive(Default)]
pub(super) struct Progress {
    pub public_claims_entered: bool,
    pub sdk_entered: bool,
}

impl PreparedVerifier {
    /// No constructor accepts a caller-supplied image or verifier parameters.
    pub(super) fn new(elf: &[u8]) -> Result<Self> {
        let image = super::require_pinned_image(elf)?;
        let context = VerifierContext::default().with_dev_mode(false);
        let composite_parameters = context
            .composite_verifier_parameters()
            .context("pinned Composite verifier parameters missing")?
            .digest::<Impl>();
        let segment_parameters = context
            .segment_verifier_parameters
            .as_ref()
            .context("pinned segment verifier parameters missing")?
            .digest::<Impl>();
        Ok(Self {
            image,
            context,
            composite_parameters,
            segment_parameters,
        })
    }

    fn profile<'a>(
        &self,
        receipt: &'a Receipt,
        expected_journal: &[u8],
    ) -> Result<&'a CompositeReceipt> {
        ensure!(
            receipt.journal.bytes == expected_journal,
            "public journal does not match the complete bound W1 statement"
        );
        let composite = match &receipt.inner {
            InnerReceipt::Composite(value) => value,
            _ => {
                return Err(BoundaryError::Refused(
                    "only actual transparent Composite receipts are supported",
                )
                .into())
            }
        };
        if composite.segments.is_empty() || composite.segments.len() > receipt_bounds::MAX_SEGMENTS
        {
            return Err(BoundaryError::Refused("segment count budget").into());
        }
        let mut padded_cycles = 0u64;
        for segment in &composite.segments {
            padded_cycles += receipt_bounds::check_seal(&segment.seal)?;
            receipt_bounds::check_padded_cycles(padded_cycles)?;
        }
        ensure!(
            composite.assumption_receipts.is_empty(),
            "no unproven assumptions permitted"
        );
        ensure!(
            composite.segments.iter().all(|s| s.hashfn == "poseidon2"),
            "pinned v3.0.6 segment verifier supports only Poseidon2 commitments"
        );
        ensure!(
            composite.verifier_parameters == self.composite_parameters,
            "Composite parameters differ from the fixed backend profile"
        );
        ensure!(
            composite
                .segments
                .iter()
                .all(|s| s.verifier_parameters == self.segment_parameters),
            "segment proof parameters differ from the fixed backend profile"
        );
        Ok(composite)
    }

    fn public_claims(&self, receipt: &Receipt, composite: &CompositeReceipt) -> Result<()> {
        // Repeat the SDK's necessary public-claim predicates *before* proving
        // anything. Their eventual authenticated checks remain in the SDK.
        let expected = ReceiptClaim::ok(
            self.image,
            MaybePruned::Pruned(receipt.journal.digest::<Impl>()),
        );
        ensure!(
            receipt.claim()?.digest::<Impl>() == expected.digest::<Impl>(),
            "public aggregate claim differs from the pinned image and complete journal"
        );
        for pair in composite.segments.windows(2) {
            let previous = &pair[0].claim;
            let next = &pair[1].claim;
            ensure!(
                previous.exit_code == ExitCode::SystemSplit,
                "public nonfinal claim is not a system split"
            );
            ensure!(
                previous.output.is_none(),
                "public nonfinal claim has output"
            );
            let post = previous
                .post
                .as_value()
                .context("public continuation post-state is pruned")?;
            ensure!(
                post.digest::<Impl>() == next.pre.digest::<Impl>(),
                "public continuation states do not link"
            );
        }
        Ok(())
    }

    pub(super) fn verify(&self, receipt: &Receipt, expected_journal: &[u8]) -> Result<()> {
        self.verify_traced(receipt, expected_journal, &mut Progress::default())
    }

    pub(super) fn verify_traced(
        &self,
        receipt: &Receipt,
        expected_journal: &[u8],
        progress: &mut Progress,
    ) -> Result<()> {
        *progress = Progress::default();
        let composite = self.profile(receipt, expected_journal)?;
        progress.public_claims_entered = true;
        self.public_claims(receipt, composite)?;
        progress.sdk_entered = true;
        receipt.verify_with_context(&self.context, self.image)?;
        Ok(())
    }

    /// Research comparison only: same pinned context and original profile
    /// checks, then the SDK's original authentication-before-claim order.
    pub(super) fn reference_traced(
        &self,
        receipt: &Receipt,
        expected_journal: &[u8],
        progress: &mut Progress,
    ) -> Result<()> {
        *progress = Progress::default();
        self.profile(receipt, expected_journal)?;
        progress.sdk_entered = true;
        receipt.verify_with_context(&self.context, self.image)?;
        Ok(())
    }

    pub(super) fn image(&self) -> Digest {
        self.image
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic data is deliberately not a proof and uses a test-only image.
    // This bypasses no production constructor and never reports acceptance.
    fn synthetic() -> (PreparedVerifier, Receipt, Vec<u8>) {
        let context = VerifierContext::default().with_dev_mode(false);
        let composite_parameters = context
            .composite_verifier_parameters()
            .unwrap()
            .digest::<Impl>();
        let segment_parameters = context
            .segment_verifier_parameters
            .as_ref()
            .unwrap()
            .digest::<Impl>();
        let prepared = PreparedVerifier {
            image: Digest::ZERO,
            context,
            composite_parameters,
            segment_parameters,
        };
        let (encoded, _) = receipt_bounds::tests::skeleton(2, 13, false);
        let mut receipt = super::super::deserialize_receipt(&encoded).unwrap();
        let journal = receipt.journal.bytes.clone();
        let journal_digest = receipt.journal.digest::<Impl>();
        let InnerReceipt::Composite(composite) = &mut receipt.inner else {
            unreachable!()
        };
        composite.verifier_parameters = composite_parameters;
        receipt.metadata.verifier_parameters = composite_parameters;
        for segment in &mut composite.segments {
            segment.verifier_parameters = segment_parameters;
            segment.claim = ReceiptClaim::ok(Digest::ZERO, MaybePruned::Pruned(journal_digest));
        }
        composite.segments[0].claim.exit_code = ExitCode::SystemSplit;
        composite.segments[0].claim.output = None.into();
        let link = composite.segments[0].claim.post.digest::<Impl>();
        composite.segments[1].claim.pre = MaybePruned::Pruned(link);
        (prepared, receipt, journal)
    }

    #[test]
    fn matching_public_claims_still_execute_and_fail_the_real_sdk() {
        let (prepared, receipt, journal) = synthetic();
        let mut progress = Progress::default();
        assert!(prepared
            .verify_traced(&receipt, &journal, &mut progress)
            .is_err());
        assert!(progress.public_claims_entered && progress.sdk_entered);
    }

    #[test]
    fn outer_rebinding_is_rejected_but_coordinated_claim_forgery_still_reaches_sdk() {
        let (prepared, mut receipt, mut journal) = synthetic();
        journal[0] ^= 1;
        receipt.journal.bytes = journal.clone();
        let mut progress = Progress {
            public_claims_entered: true,
            sdk_entered: true,
        };
        assert!(prepared
            .verify_traced(&receipt, &journal, &mut progress)
            .is_err());
        assert!(progress.public_claims_entered && !progress.sdk_entered);
        let digest = receipt.journal.digest::<Impl>();
        let InnerReceipt::Composite(composite) = &mut receipt.inner else {
            unreachable!()
        };
        let last = &mut composite.segments.last_mut().unwrap().claim;
        let mut output = last.output.as_value().unwrap().clone().unwrap();
        output.journal = MaybePruned::Pruned(digest);
        last.output = Some(output).into();
        assert!(prepared
            .verify_traced(&receipt, &journal, &mut progress)
            .is_err());
        assert!(progress.public_claims_entered && progress.sdk_entered);
    }

    #[test]
    fn public_continuation_errors_are_rejected_before_any_sdk_proof_check() {
        for mutate_exit in [false, true] {
            let (prepared, mut receipt, journal) = synthetic();
            let InnerReceipt::Composite(composite) = &mut receipt.inner else {
                unreachable!()
            };
            if mutate_exit {
                composite.segments[0].claim.exit_code = ExitCode::Halted(0);
            } else {
                composite.segments[1].claim.pre = MaybePruned::Pruned(Digest::from([u32::MAX; 8]));
            }
            let mut progress = Progress::default();
            assert!(prepared
                .verify_traced(&receipt, &journal, &mut progress)
                .is_err());
            assert!(progress.public_claims_entered && !progress.sdk_entered);
        }
    }

    #[test]
    fn arbitrary_program_bytes_cannot_create_a_prepared_verifier() {
        for elf in [b"".as_slice(), b"not-an-elf", &[0u8; 256]] {
            assert!(PreparedVerifier::new(elf).is_err());
        }
    }
}
