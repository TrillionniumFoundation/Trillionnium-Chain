//! M15's read-only consumer for the M08 retained finality path.
//!
//! This module verifies consensus evidence only. It does not install an
//! application snapshot, consume an M08 proof row, or create signer authority.

use std::{error::Error, fmt};

use trnm_consensus_crypto::FinalityExpectationV0;
use trnm_consensus_types::{
    decode_block_header_v0_exact, Cev0AdmissionBudgetV0, EpochActivationEvidenceBytesV0,
};
pub use trnm_native_execution_v0::{NativeEpochFinalityPathV1, NativeEpochFinalityStepV1};
use trnm_state_sync_v0::{
    verify_native_trust_path_v1, NativeTrustAnchorV1, NativeTrustErrorV1, NativeTrustPathLimitsV1,
    NativeTrustStepV1, VerifiedNativeTrustPathV1,
};

const MAX_BRIDGE_BYTES_V1: usize = 64 * 1024 * 1024;
const MAX_BRIDGE_LINKS_V1: usize = 128;
const MAX_BRIDGE_HEADER_BYTES_V1: usize = 4096;
const MAX_BRIDGE_ROOT_BYTES_V1: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub enum NativeEpochFinalityConsumerErrorV1 {
    Bounds,
    Decode(String),
    Trust(NativeTrustErrorV1),
    AnchorMismatch,
    TargetMismatch,
    MetadataMismatch,
}

impl fmt::Display for NativeEpochFinalityConsumerErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bounds => f.write_str("retained finality path exceeds M15 bounds"),
            Self::Decode(error) => write!(f, "retained finality header decode failed: {error}"),
            Self::Trust(error) => write!(f, "retained finality trust verification failed: {error}"),
            Self::AnchorMismatch => f.write_str("retained finality anchor mismatch"),
            Self::TargetMismatch => f.write_str("retained finality target mismatch"),
            Self::MetadataMismatch => f.write_str("retained finality metadata mismatch"),
        }
    }
}

impl Error for NativeEpochFinalityConsumerErrorV1 {}

fn decode_header(
    bytes: &[u8],
) -> Result<trnm_consensus_types::BlockHeader, NativeEpochFinalityConsumerErrorV1> {
    decode_block_header_v0_exact(bytes)
        .map_err(|error| NativeEpochFinalityConsumerErrorV1::Decode(format!("{error:?}")))
}

fn expectation(
    header: &trnm_consensus_types::BlockHeader,
    parent: &trnm_consensus_types::BlockHeader,
) -> FinalityExpectationV0 {
    FinalityExpectationV0 {
        block_id: header.id(),
        height: header.height(),
        state_root: header.state_root(),
        receipts_root: header.receipts_root(),
        evidence_root: header.evidence_root(),
        parent_id: parent.id(),
        parent_height: parent.height(),
        parent_timestamp_ms: parent.timestamp_ms(),
    }
}

fn evidence_size(evidence: &EpochActivationEvidenceBytesV0) -> Option<usize> {
    [
        &evidence.old_checkpoint_finality,
        &evidence.next_epoch_commitment,
        &evidence.authorization_kernel,
        &evidence.old_validator_set,
        &evidence.old_consensus_parameters,
        &evidence.new_validator_set,
        &evidence.new_consensus_parameters,
        &evidence.authenticated_checkpoint_parent_header,
    ]
    .into_iter()
    .try_fold(0usize, |total, bytes| {
        (!bytes.is_empty() && bytes.len() <= MAX_BRIDGE_ROOT_BYTES_V1)
            .then_some(())
            .and_then(|()| total.checked_add(bytes.len()))
    })
}

/// Verify an M08 retained path against an independently configured M13 anchor.
///
/// The P digest, commit sequence and record digest are local storage metadata;
/// they are never used as remote authority. Every target and consensus-parent
/// header is decoded and supplied as the strict verifier's exact expectation.
pub fn verify_retained_native_finality_path_v1(
    anchor: &NativeTrustAnchorV1,
    path: &NativeEpochFinalityPathV1,
    limits: NativeTrustPathLimitsV1,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<VerifiedNativeTrustPathV1, NativeEpochFinalityConsumerErrorV1> {
    // Local M08 metadata is screened before any M13 signature work. It is a
    // shape/integrity gate only and never becomes remote authority.
    if !matches!(path.target_schema_version, 10 | 13)
        || path.target_p_digest == [0; 32]
        || path.target_commit_sequence == 0
    {
        return Err(NativeEpochFinalityConsumerErrorV1::MetadataMismatch);
    }
    if path.steps.is_empty()
        || path.steps.len() > limits.maximum_links
        || path.steps.len() > MAX_BRIDGE_LINKS_V1
    {
        return Err(NativeEpochFinalityConsumerErrorV1::Bounds);
    }
    if path.anchor_header_cev0.len() > MAX_BRIDGE_HEADER_BYTES_V1
        || path.target_header_cev0.len() > MAX_BRIDGE_HEADER_BYTES_V1
    {
        return Err(NativeEpochFinalityConsumerErrorV1::Bounds);
    }
    let mut total = path
        .anchor_header_cev0
        .len()
        .checked_add(path.target_header_cev0.len())
        .ok_or(NativeEpochFinalityConsumerErrorV1::Bounds)?;
    for step in &path.steps {
        let evidence_bytes = match step.epoch_evidence.as_ref() {
            Some(evidence) => {
                evidence_size(evidence).ok_or(NativeEpochFinalityConsumerErrorV1::Bounds)?
            }
            None => 0,
        };
        if step.header_cev0.len() > MAX_BRIDGE_HEADER_BYTES_V1
            || step.consensus_parent_header_cev0.len() > MAX_BRIDGE_HEADER_BYTES_V1
            || step.proof.is_empty()
            || step.proof.len() > MAX_BRIDGE_ROOT_BYTES_V1
            || step.record_digest == [0; 32]
        {
            return Err(NativeEpochFinalityConsumerErrorV1::Bounds);
        }
        total = total
            .checked_add(step.header_cev0.len())
            .and_then(|value| value.checked_add(step.consensus_parent_header_cev0.len()))
            .and_then(|value| value.checked_add(step.proof.len()))
            .and_then(|value| value.checked_add(evidence_bytes))
            .ok_or(NativeEpochFinalityConsumerErrorV1::Bounds)?;
    }
    if total > limits.maximum_total_bytes.min(MAX_BRIDGE_BYTES_V1) {
        return Err(NativeEpochFinalityConsumerErrorV1::Bounds);
    }
    let target = decode_header(&path.target_header_cev0)?;
    let exported_anchor = decode_header(&path.anchor_header_cev0)?;
    if exported_anchor != *anchor.header() {
        return Err(NativeEpochFinalityConsumerErrorV1::AnchorMismatch);
    }
    if target.height().get() <= anchor.header().height().get()
        || target.genesis_hash() != anchor.header().genesis_hash()
        || target.chain_id() != anchor.header().chain_id()
        || target.protocol_version() != anchor.header().protocol_version()
    {
        return Err(NativeEpochFinalityConsumerErrorV1::TargetMismatch);
    }
    let mut steps = Vec::with_capacity(path.steps.len());
    for step in &path.steps {
        let header = decode_header(&step.header_cev0)?;
        let consensus_parent = decode_header(&step.consensus_parent_header_cev0)?;
        if header.parent_id() != consensus_parent.id()
            || header.genesis_hash() != anchor.header().genesis_hash()
            || header.chain_id() != anchor.header().chain_id()
            || header.protocol_version() != anchor.header().protocol_version()
        {
            return Err(NativeEpochFinalityConsumerErrorV1::TargetMismatch);
        }
        let expected = expectation(&header, &consensus_parent);
        steps.push(match step.epoch_evidence.as_ref() {
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
    let verified = verify_native_trust_path_v1(anchor, &steps, limits, budget)
        .map_err(NativeEpochFinalityConsumerErrorV1::Trust)?;
    if verified.terminal_header() != &target {
        return Err(NativeEpochFinalityConsumerErrorV1::TargetMismatch);
    }
    Ok(verified)
}
