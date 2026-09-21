//! Strict terminal-authenticated ancestry; no application or signing authority.
use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_epoch_activation_evidence_v0_exact,
    decode_epoch_activation_evidence_with_context_v1_exact, validate_historical_header_link_v1,
    BlockHeader, BlockKind, Cev0AdmissionBudgetV0, ConsensusParametersV0, DecodeError,
    DecodedEpochActivationEvidenceV0, EpochActivationEvidenceErrorV0,
    EpochActivationEvidencePreimagesV0, EpochGeometryV0, HistoricalAncestryLimitsV1,
    ValidationError, ValidatorSet,
};

use crate::{
    decode_verify_finality_proof_strict_v0,
    epoch_transition::verify_decoded_epoch_activation_strict_v0,
    validate_validator_set_strict_ed25519_v0, FinalityExpectationV0, StrictFinalityErrorV0,
    StrictSameVersionEpochActivationAuthorityV0, POCO_THREE_CHAIN_PROOF_CLASS_V0,
};

#[derive(Debug)]
pub enum HistoricalAncestryErrorV1 {
    Invalid(&'static str),
    Decode(DecodeError),
    Consensus(ValidationError),
    ActivationEvidence(EpochActivationEvidenceErrorV0),
    Activation(JointHandoffKernelError),
    Successor(crate::StrictSuccessorEpochActivationErrorV1),
    Finality(StrictFinalityErrorV0),
}
use trnm_consensus_types::JointHandoffKernelError;

impl fmt::Display for HistoricalAncestryErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "historical ancestry: {reason}"),
            Self::Decode(error) => write!(f, "historical decoding: {error}"),
            Self::Consensus(error) => write!(f, "historical context: {error}"),
            Self::ActivationEvidence(error) => write!(f, "historical activation bytes: {error}"),
            Self::Activation(error) => write!(f, "historical activation signatures: {error}"),
            Self::Successor(error) => write!(f, "historical successor activation: {error}"),
            Self::Finality(error) => write!(f, "historical terminal finality: {error}"),
        }
    }
}

/// Only complete strict verification issues these immutable header facts.
/// This is not a P record, replay state, installation or signer capability.
///
/// ```compile_fail
/// use trnm_consensus_crypto::StrictHistoricalHeaderPathV1;
/// let forged = StrictHistoricalHeaderPathV1 {};
/// ```
/// ```compile_fail
/// use trnm_consensus_crypto::StrictHistoricalHeaderPathV1;
/// fn require_clone<T: Clone>() {}
/// require_clone::<StrictHistoricalHeaderPathV1>();
/// ```
#[derive(Debug)]
pub struct StrictHistoricalHeaderPathV1 {
    headers: Vec<BlockHeader>,
    activations: Vec<Box<StrictSameVersionEpochActivationAuthorityV0>>,
    terminal_proof: trnm_consensus_types::FinalityProofV0,
    terminal_validator_set: ValidatorSet,
    terminal_parameters: ConsensusParametersV0,
}

impl StrictHistoricalHeaderPathV1 {
    pub fn headers(&self) -> &[BlockHeader] {
        &self.headers
    }
    pub fn activations(&self) -> &[Box<StrictSameVersionEpochActivationAuthorityV0>] {
        &self.activations
    }
    pub fn terminal_proof(&self) -> &trnm_consensus_types::FinalityProofV0 {
        &self.terminal_proof
    }
    pub fn terminal_header(&self) -> &BlockHeader {
        self.headers.last().expect("path nonempty")
    }
    pub fn terminal_validator_set(&self) -> &ValidatorSet {
        &self.terminal_validator_set
    }
    pub fn terminal_parameters(&self) -> &ConsensusParametersV0 {
        &self.terminal_parameters
    }
}

fn evidence_roots(e: EpochActivationEvidencePreimagesV0<'_>) -> [&[u8]; 8] {
    [
        e.old_checkpoint_finality,
        e.next_epoch_commitment,
        e.authorization_kernel,
        e.old_validator_set,
        e.old_consensus_parameters,
        e.new_validator_set,
        e.new_consensus_parameters,
        e.authenticated_checkpoint_parent_header,
    ]
}

fn screen_inputs(
    headers: &[&[u8]],
    activations: &[EpochActivationEvidencePreimagesV0<'_>],
    proof: &[u8],
    limits: HistoricalAncestryLimitsV1,
    budget: &Cev0AdmissionBudgetV0,
) -> Result<(), HistoricalAncestryErrorV1> {
    if headers.is_empty()
        || headers.len() > limits.maximum_headers.min(256)
        || activations.len() > limits.maximum_transitions.min(32)
        || proof.is_empty()
        || proof.len() > 8 * 1024 * 1024
    {
        return Err(HistoricalAncestryErrorV1::Invalid(
            "history count/proof bound",
        ));
    }
    budget
        .admit_root_bytes(proof.len())
        .map_err(HistoricalAncestryErrorV1::Decode)?;
    let mut total = proof.len();
    let mut add = |size: usize| -> Result<(), HistoricalAncestryErrorV1> {
        total = total
            .checked_add(size)
            .ok_or(HistoricalAncestryErrorV1::Invalid("history byte overflow"))?;
        if total > limits.maximum_total_bytes.min(64 * 1024 * 1024) {
            return Err(HistoricalAncestryErrorV1::Invalid(
                "history aggregate bytes",
            ));
        }
        Ok(())
    };
    for header in headers {
        if header.is_empty() || header.len() > 4096 {
            return Err(HistoricalAncestryErrorV1::Invalid("history header bound"));
        }
        budget
            .admit_root_bytes(header.len())
            .map_err(HistoricalAncestryErrorV1::Decode)?;
        add(header.len())?;
    }
    for evidence in activations {
        let mut root_total = 0usize;
        for (root, maximum) in evidence_roots(*evidence).into_iter().zip([
            8 * 1024 * 1024,
            4096,
            8 * 1024 * 1024,
            1024 * 1024,
            4096,
            1024 * 1024,
            4096,
            4096,
        ]) {
            if root.is_empty() || root.len() > maximum {
                return Err(HistoricalAncestryErrorV1::Invalid(
                    "history activation root bound",
                ));
            }
            add(root.len())?;
            root_total =
                root_total
                    .checked_add(root.len())
                    .ok_or(HistoricalAncestryErrorV1::Invalid(
                        "history activation byte overflow",
                    ))?;
        }
        // An activation is already one bounded logical root in the frozen
        // decoder. A longer history does not enlarge that per-root allowance.
        budget
            .admit_root_bytes(root_total)
            .map_err(HistoricalAncestryErrorV1::Decode)?;
    }
    Ok(())
}

fn validate_anchor(
    header: &BlockHeader,
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
) -> Result<(), HistoricalAncestryErrorV1> {
    header
        .validate_shape()
        .map_err(HistoricalAncestryErrorV1::Consensus)?;
    set.validate_against_parameters(parameters)
        .map_err(HistoricalAncestryErrorV1::Consensus)?;
    validate_validator_set_strict_ed25519_v0(set).map_err(HistoricalAncestryErrorV1::Consensus)?;
    let geometry = EpochGeometryV0::new(set.epoch(), parameters)
        .map_err(HistoricalAncestryErrorV1::Consensus)?;
    if matches!(
        header.block_kind(),
        BlockKind::EpochSeal1 | BlockKind::EpochSeal2
    ) || header.state_root().as_bytes() == &[0; 32]
        || header.genesis_hash() != set.genesis_hash()
        || header.chain_id() != set.chain_id()
        || header.protocol_version() != set.protocol_version()
        || header.epoch() != set.epoch()
        || header.validator_set_id() != set.id()
        || header.consensus_parameters_hash() != parameters.hash()
        || geometry
            .expected_block_kind(header.height())
            .map_err(HistoricalAncestryErrorV1::Consensus)?
            != header.block_kind()
    {
        return Err(HistoricalAncestryErrorV1::Invalid(
            "historical anchor context",
        ));
    }
    Ok(())
}

/// Authenticate the complete ordered ancestry using one original terminal
/// proof and strictly verified transition evidence. All trust inputs must come
/// from the caller's independent anchor. Bodies and replay state are not checked.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn verify_historical_header_ancestry_v1(
    anchor: &BlockHeader,
    anchor_set: &ValidatorSet,
    anchor_params: &ConsensusParametersV0,
    headers: &[&[u8]],
    activations: &[EpochActivationEvidencePreimagesV0<'_>],
    terminal_proof: &[u8],
    limits: HistoricalAncestryLimitsV1,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<StrictHistoricalHeaderPathV1, HistoricalAncestryErrorV1> {
    screen_inputs(headers, activations, terminal_proof, limits, budget)?;
    validate_anchor(anchor, anchor_set, anchor_params)?;
    let mut decoded = Vec::with_capacity(headers.len());
    for bytes in headers {
        let header =
            decode_block_header_v0_exact(bytes).map_err(HistoricalAncestryErrorV1::Decode)?;
        if header.state_root().as_bytes() == &[0; 32] {
            return Err(HistoricalAncestryErrorV1::Invalid(
                "zero historical state root",
            ));
        }
        decoded.push(header);
    }
    let target = decoded.last().expect("checked nonempty");
    if matches!(
        target.block_kind(),
        BlockKind::EpochSeal1 | BlockKind::EpochSeal2
    ) {
        return Err(HistoricalAncestryErrorV1::Invalid("terminal seal"));
    }
    let mut set = anchor_set.clone();
    let mut params = *anchor_params;
    let mut boxed: Vec<Box<StrictSameVersionEpochActivationAuthorityV0>> =
        Vec::with_capacity(activations.len());
    let mut predecessor_terminal_index = None;
    let mut next_activation = 0usize;
    let mut previous = anchor;
    let mut last_decoded_activation: Option<Box<DecodedEpochActivationEvidenceV0>> = None;
    for (index, header) in decoded.iter().enumerate() {
        if header.block_kind() == BlockKind::EpochHandoff {
            let evidence = activations
                .get(next_activation)
                .ok_or(HistoricalAncestryErrorV1::Invalid("missing activation"))?;
            let decoded_evidence = if let Some(predecessor) = boxed.last() {
                decode_epoch_activation_evidence_with_context_v1_exact(
                    *evidence,
                    predecessor.runtime_data_v1(),
                    budget,
                )
            } else {
                decode_epoch_activation_evidence_v0_exact(*evidence, &set, &params, budget)
            }
            .map_err(HistoricalAncestryErrorV1::ActivationEvidence)?;
            let authority = if let Some(predecessor) = boxed.last() {
                let start = predecessor_terminal_index.ok_or(
                    HistoricalAncestryErrorV1::Invalid("missing predecessor terminal position"),
                )?;
                let end = index
                    .checked_sub(4)
                    .ok_or(HistoricalAncestryErrorV1::Invalid(
                        "successor checkpoint parent position",
                    ))?;
                let ancestry =
                    decoded
                        .get(start..=end)
                        .ok_or(HistoricalAncestryErrorV1::Invalid(
                            "successor ancestry interval",
                        ))?;
                crate::epoch_transition::verify_decoded_successor_epoch_activation_v1(
                    predecessor,
                    ancestry,
                    &decoded_evidence,
                )
                .map_err(HistoricalAncestryErrorV1::Successor)?
            } else {
                verify_decoded_epoch_activation_strict_v0(&decoded_evidence)
                    .map_err(HistoricalAncestryErrorV1::Activation)?
            };
            validate_historical_header_link_v1(
                header,
                previous,
                authority.new_validator_set(),
                authority.new_consensus_parameters(),
            )
            .map_err(HistoricalAncestryErrorV1::Consensus)?;
            let checkpoint = authority
                .old_checkpoint_finality()
                .finalized_block()
                .header();
            let seal1 = authority.old_checkpoint_finality().child().header();
            let seal2 = authority.old_checkpoint_finality().grandchild().header();
            // Positions are relative to this handoff, never a search that
            // could accept an unrelated or future occurrence of a header.
            let prior = |distance: usize| -> Option<&BlockHeader> {
                if let Some(position) = index.checked_sub(distance) {
                    decoded.get(position)
                } else if index.checked_add(1) == Some(distance) {
                    Some(anchor)
                } else {
                    None
                }
            };
            if prior(1) != Some(seal2)
                || prior(2) != Some(seal1)
                || prior(3) != Some(checkpoint)
                || authority.terminal_old_header() != seal2
            {
                return Err(HistoricalAncestryErrorV1::Invalid(
                    "activation ancestry position",
                ));
            }
            let checkpoint_parent = authority.authenticated_checkpoint_parent_header();
            if let Some(parent) = prior(4) {
                if checkpoint_parent != parent {
                    return Err(HistoricalAncestryErrorV1::Invalid(
                        "activation checkpoint parent",
                    ));
                }
            } else if checkpoint != anchor
                || checkpoint_parent.id() != anchor.parent_id()
                || checkpoint_parent.height().get().checked_add(1) != Some(anchor.height().get())
            {
                return Err(HistoricalAncestryErrorV1::Invalid(
                    "pinned checkpoint parent",
                ));
            }
            last_decoded_activation = Some(Box::new(decoded_evidence));
            set = authority.new_validator_set().clone();
            params = *authority.new_consensus_parameters();
            predecessor_terminal_index = index.checked_sub(1);
            boxed.push(Box::new(authority));
            next_activation += 1;
        } else {
            validate_historical_header_link_v1(header, previous, &set, &params)
                .map_err(HistoricalAncestryErrorV1::Consensus)?;
        }
        previous = header;
    }
    if next_activation != activations.len() {
        return Err(HistoricalAncestryErrorV1::Invalid("unused activation"));
    }
    let parent_header = if decoded.len() == 1 {
        anchor
    } else {
        &decoded[decoded.len() - 2]
    };
    let expected = FinalityExpectationV0 {
        block_id: target.id(),
        height: target.height(),
        state_root: target.state_root(),
        receipts_root: target.receipts_root(),
        evidence_root: target.evidence_root(),
        parent_id: target.parent_id(),
        parent_height: parent_header.height(),
        parent_timestamp_ms: parent_header.timestamp_ms(),
    };
    let proof = if let Some(decoded_activation) = last_decoded_activation.as_deref() {
        let authority = boxed.last().expect("decoded activation has strict owner");
        crate::strict_finality::decode_verify_historical_epoch_finality_v1(
            decoded_activation,
            authority,
            terminal_proof,
            expected,
            budget,
        )
        .map_err(HistoricalAncestryErrorV1::Finality)?
    } else {
        decode_verify_finality_proof_strict_v0(
            POCO_THREE_CHAIN_PROOF_CLASS_V0,
            terminal_proof,
            &set,
            &params,
            expected,
            budget,
        )
        .map_err(HistoricalAncestryErrorV1::Finality)?
        .proof()
        .clone()
    };
    if proof.finalized_block().header() != target {
        return Err(HistoricalAncestryErrorV1::Invalid("terminal proof target"));
    }
    Ok(StrictHistoricalHeaderPathV1 {
        headers: decoded,
        activations: boxed,
        terminal_proof: proof,
        terminal_validator_set: set,
        terminal_parameters: params,
    })
}
