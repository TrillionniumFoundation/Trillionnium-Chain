//! Explicit read-only schema11 evidence bridge. No candidate storage feature,
//! native owner, local receipt or installer is needed to verify remote bytes.
use trnm_consensus_crypto::FinalityExpectationV0;
use trnm_consensus_types::{decode_block_header_v0_exact, Cev0AdmissionBudgetV0};
pub use trnm_native_execution_v0::{
    NativeIncrementalFinalityPathV2, NativeIncrementalFinalityStepV2,
};
use trnm_native_execution_v0::{
    MAX_INCREMENTAL_FINALITY_BYTES_V2, MAX_INCREMENTAL_FINALITY_EPOCHS_V2,
    MAX_INCREMENTAL_FINALITY_HEADER_BYTES_V2, MAX_INCREMENTAL_FINALITY_LINKS_V2,
    MAX_INCREMENTAL_FINALITY_ROOT_BYTES_V2,
};
use trnm_state_sync_v0::{
    verify_native_trust_path_v1, NativeTrustAnchorV1, NativeTrustErrorV1, NativeTrustPathLimitsV1,
    NativeTrustStepV1, VerifiedNativeTrustPathV1,
};

#[derive(Debug)]
pub enum NativeIncrementalFinalityConsumerErrorV2 {
    Bounds,
    Decode(trnm_consensus_types::DecodeError),
    AnchorMismatch,
    TargetMismatch,
    Trust(NativeTrustErrorV1),
}
impl std::fmt::Display for NativeIncrementalFinalityConsumerErrorV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "incremental finality consumer: {self:?}")
    }
}
impl std::error::Error for NativeIncrementalFinalityConsumerErrorV2 {}
type Result<T> = std::result::Result<T, NativeIncrementalFinalityConsumerErrorV2>;
use NativeIncrementalFinalityConsumerErrorV2 as Error;

fn count(total: &mut usize, bytes: &[u8], cap: usize, maximum: usize) -> Result<()> {
    if bytes.is_empty() || bytes.len() > cap {
        return Err(Error::Bounds);
    }
    *total = total.checked_add(bytes.len()).ok_or(Error::Bounds)?;
    if *total > maximum {
        return Err(Error::Bounds);
    }
    Ok(())
}

/// Verify original application proofs using only the independently configured
/// M13 anchor. Public vector fields and claimed headers remain untrusted until
/// the unchanged strict M13 verifier has authenticated every complete link.
pub fn verify_incremental_native_finality_path_v2(
    anchor: &NativeTrustAnchorV1,
    path: &NativeIncrementalFinalityPathV2,
    limits: NativeTrustPathLimitsV1,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<VerifiedNativeTrustPathV1> {
    if path.steps.is_empty()
        || path.steps.len() > limits.maximum_links.min(MAX_INCREMENTAL_FINALITY_LINKS_V2)
    {
        return Err(Error::Bounds);
    }
    let maximum = limits
        .maximum_total_bytes
        .min(MAX_INCREMENTAL_FINALITY_BYTES_V2);
    let mut total = 0;
    let mut epochs = 0;
    count(
        &mut total,
        &path.anchor_header_cev0,
        MAX_INCREMENTAL_FINALITY_HEADER_BYTES_V2,
        maximum,
    )?;
    count(
        &mut total,
        &path.target_header_cev0,
        MAX_INCREMENTAL_FINALITY_HEADER_BYTES_V2,
        maximum,
    )?;
    for step in &path.steps {
        count(
            &mut total,
            &step.header_cev0,
            MAX_INCREMENTAL_FINALITY_HEADER_BYTES_V2,
            maximum,
        )?;
        count(
            &mut total,
            &step.consensus_parent_header_cev0,
            MAX_INCREMENTAL_FINALITY_HEADER_BYTES_V2,
            maximum,
        )?;
        count(
            &mut total,
            &step.proof,
            MAX_INCREMENTAL_FINALITY_ROOT_BYTES_V2,
            maximum,
        )?;
        if let Some(e) = &step.epoch_evidence {
            epochs += 1;
            if epochs > MAX_INCREMENTAL_FINALITY_EPOCHS_V2 {
                return Err(Error::Bounds);
            }
            for root in [
                &e.old_checkpoint_finality,
                &e.next_epoch_commitment,
                &e.authorization_kernel,
                &e.old_validator_set,
                &e.old_consensus_parameters,
                &e.new_validator_set,
                &e.new_consensus_parameters,
                &e.authenticated_checkpoint_parent_header,
            ] {
                count(
                    &mut total,
                    root,
                    MAX_INCREMENTAL_FINALITY_ROOT_BYTES_V2,
                    maximum,
                )?;
            }
        }
    }
    let exported_anchor =
        decode_block_header_v0_exact(&path.anchor_header_cev0).map_err(Error::Decode)?;
    if &exported_anchor != anchor.header() {
        return Err(Error::AnchorMismatch);
    }
    let target = decode_block_header_v0_exact(&path.target_header_cev0).map_err(Error::Decode)?;
    if target.height() <= anchor.header().height()
        || target.genesis_hash() != anchor.header().genesis_hash()
        || target.chain_id() != anchor.header().chain_id()
        || target.protocol_version() != anchor.header().protocol_version()
    {
        return Err(Error::TargetMismatch);
    }
    let mut steps = Vec::with_capacity(path.steps.len());
    for step in &path.steps {
        let h = decode_block_header_v0_exact(&step.header_cev0).map_err(Error::Decode)?;
        let parent = decode_block_header_v0_exact(&step.consensus_parent_header_cev0)
            .map_err(Error::Decode)?;
        if h.parent_id() != parent.id()
            || h.genesis_hash() != anchor.header().genesis_hash()
            || h.chain_id() != anchor.header().chain_id()
            || h.protocol_version() != anchor.header().protocol_version()
        {
            return Err(Error::TargetMismatch);
        }
        let expected = FinalityExpectationV0 {
            block_id: h.id(),
            height: h.height(),
            state_root: h.state_root(),
            receipts_root: h.receipts_root(),
            evidence_root: h.evidence_root(),
            parent_id: parent.id(),
            parent_height: parent.height(),
            parent_timestamp_ms: parent.timestamp_ms(),
        };
        steps.push(match &step.epoch_evidence {
            Some(evidence) => NativeTrustStepV1::EpochFirst {
                evidence: evidence.as_preimages(),
                proof: &step.proof,
                expected,
            },
            None => NativeTrustStepV1::Ordinary {
                proof: &step.proof,
                expected,
            },
        });
    }
    let verified =
        verify_native_trust_path_v1(anchor, &steps, limits, budget).map_err(Error::Trust)?;
    if verified.terminal_header() != &target {
        return Err(Error::TargetMismatch);
    }
    Ok(verified)
}
