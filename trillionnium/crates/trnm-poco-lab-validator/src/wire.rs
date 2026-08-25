//! Exact, bounded consensus payloads carried inside authenticated G3 frames.
//!
//! The transport envelope authenticates the connection sender.  These
//! projections additionally reconstruct the frozen PoCO-BFT v0 objects and
//! perform their ordinary strict Ed25519 admission.  They intentionally cover
//! only the epoch-zero laboratory profile; epoch handoff belongs to a later
//! versioned transport profile and is rejected here.

use std::fmt;

use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_application_payload_v0_exact, decode_block_header_v0_exact,
    decode_double_vote_evidence_v0_exact, decode_ordinary_qc_v0_exact_with_budget,
    decode_qc_reference_v0_exact_with_trusted_genesis_and_budget,
    decode_timeout_certificate_v0_exact_with_trusted_genesis_and_budget, Block, BlockId,
    Cev0AdmissionBudgetV0, ConsensusParametersV0, ContextAuthorizedQcV0, Epoch, Height,
    ProposalWitnessV0, QcRef, QcReferenceV0, QuorumCertificate, SignatureBytes, SignatureVerifier,
    SignedProposalV0, TimeoutCertificateV0, TimeoutVote, ValidatorId, ValidatorSet, View, Vote,
};

const PROPOSAL_MAGIC: &[u8; 8] = b"TRNMPPV1";
const PROPOSAL_VERSION: u16 = 1;
const VOTE_VERSION: u16 = 1;
const TIMEOUT_VOTE_VERSION: u16 = 1;
const VOTE_WIRE_BYTES: usize = 2 + 8 + 8 + 32 + 32 + 64;
const TIMEOUT_VOTE_WIRE_BYTES: usize = 2 + 8 + (32 + 8 + 8 + 8 + 32 + 32) + 32 + 64;
const MAX_PROPOSAL_PAYLOAD_BYTES: usize = 6 * 1024 * 1024;
const MAX_PROPOSAL_EVIDENCE_ITEMS: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusWireError {
    TooLarge,
    Truncated(&'static str),
    Malformed(&'static str),
    Invalid(String),
}

impl fmt::Display for ConsensusWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => formatter.write_str("consensus payload exceeds its bounded profile"),
            Self::Truncated(field) => write!(formatter, "truncated consensus field: {field}"),
            Self::Malformed(reason) => write!(formatter, "malformed consensus payload: {reason}"),
            Self::Invalid(reason) => write!(formatter, "invalid consensus payload: {reason}"),
        }
    }
}

impl std::error::Error for ConsensusWireError {}

/// Epoch-zero proposal projection awaiting locally authenticated parent time.
///
/// Parent time is deliberately absent from the wire.  A receiver must recover
/// it from its authenticated block/overlay ancestry before this value can
/// become a Core input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnboundProposalV0 {
    block: Block,
    justify_qc: QcReferenceV0,
    timeout_certificate: Option<TimeoutCertificateV0>,
    proposer_signature: SignatureBytes,
}

impl UnboundProposalV0 {
    pub fn from_signed(proposal: &SignedProposalV0) -> Result<Self, ConsensusWireError> {
        if proposal.block().header().epoch() != Epoch::new(0)
            || proposal.witness().epoch_anchor_authorization().is_some()
        {
            return Err(ConsensusWireError::Malformed(
                "G3 v0 wire accepts epoch-zero proposals only",
            ));
        }
        Ok(Self {
            block: proposal.block().clone(),
            justify_qc: proposal.witness().justify_qc().clone(),
            timeout_certificate: proposal.witness().timeout_certificate().cloned(),
            proposer_signature: *proposal.witness().proposer_signature(),
        })
    }

    pub const fn block(&self) -> &Block {
        &self.block
    }

    pub fn justify_qc(&self) -> &QcReferenceV0 {
        &self.justify_qc
    }

    pub fn timeout_certificate(&self) -> Option<&TimeoutCertificateV0> {
        self.timeout_certificate.as_ref()
    }

    /// Verifies the proposer witness before this carrier is allowed to drive
    /// any certificate/state transition.  Parent time is intentionally not a
    /// part of the proposal signing root, so this check is safe to perform at
    /// the wire boundary before local parent binding.
    pub fn verify_proposer_signature(
        &self,
        validator_set: &ValidatorSet,
    ) -> Result<(), ConsensusWireError> {
        let proposer = validator_set
            .validator(self.block.header().proposer_id())
            .ok_or(ConsensusWireError::Invalid(
                "proposal proposer is absent from validator set".to_owned(),
            ))?;
        let signing_root = ProposalWitnessV0::signing_root_for(
            self.block.header(),
            &self.justify_qc,
            self.timeout_certificate.as_ref(),
            None,
        )
        .map_err(invalid_debug)?;
        if !StrictEd25519Verifier.verify(proposer, &signing_root, &self.proposer_signature) {
            return Err(ConsensusWireError::Invalid(
                "proposal proposer signature failed strict verification".to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn with_proposer_signature_for_test(mut self, signature: SignatureBytes) -> Self {
        self.proposer_signature = signature;
        self
    }

    pub fn bind_authenticated_parent(
        self,
        validator_set: &ValidatorSet,
        consensus_parameters: &ConsensusParametersV0,
        authenticated_parent_timestamp_ms: u64,
    ) -> Result<SignedProposalV0, ConsensusWireError> {
        let witness = ProposalWitnessV0::new(
            self.block.header(),
            self.justify_qc,
            self.timeout_certificate,
            None,
            self.proposer_signature,
            validator_set,
            None,
            consensus_parameters,
            authenticated_parent_timestamp_ms,
        )
        .map_err(invalid_debug)?;
        let proposal = SignedProposalV0::new(
            self.block,
            witness,
            validator_set,
            None,
            consensus_parameters,
            authenticated_parent_timestamp_ms,
        )
        .map_err(invalid_debug)?;
        proposal
            .verify(
                validator_set,
                None,
                consensus_parameters,
                authenticated_parent_timestamp_ms,
                &StrictEd25519Verifier,
            )
            .map_err(invalid_debug)?;
        Ok(proposal)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ConsensusWireError> {
        if self.block.header().epoch() != Epoch::new(0) {
            return Err(ConsensusWireError::Malformed("proposal is not epoch zero"));
        }
        let header = self
            .block
            .header()
            .try_cev0_bytes()
            .map_err(invalid_debug)?;
        let justify = qc_reference_bytes(&self.justify_qc)?;
        let timeout = self
            .timeout_certificate
            .as_ref()
            .map(|value| value.try_cev0_bytes().map_err(invalid_debug))
            .transpose()?;
        let mut output = Vec::new();
        output.extend_from_slice(PROPOSAL_MAGIC);
        output.extend_from_slice(&PROPOSAL_VERSION.to_be_bytes());
        push_bytes(&mut output, &header)?;
        push_bytes(&mut output, self.block.application_payload())?;
        push_count(&mut output, self.block.evidence_objects().len())?;
        for evidence in self.block.evidence_objects() {
            push_bytes(&mut output, evidence)?;
        }
        push_bytes(&mut output, &justify)?;
        match timeout {
            None => output.push(0),
            Some(bytes) => {
                output.push(1);
                push_bytes(&mut output, &bytes)?;
            }
        }
        output.extend_from_slice(self.proposer_signature.as_bytes());
        if output.len() > MAX_PROPOSAL_PAYLOAD_BYTES {
            return Err(ConsensusWireError::TooLarge);
        }
        Ok(output)
    }

    pub fn decode(
        bytes: &[u8],
        validator_set: &ValidatorSet,
        consensus_parameters: &ConsensusParametersV0,
    ) -> Result<Self, ConsensusWireError> {
        let mut budget =
            Cev0AdmissionBudgetV0::for_validator_set(consensus_parameters, validator_set);
        Self::decode_with_budget(bytes, validator_set, consensus_parameters, &mut budget)
    }

    /// Decodes and strictly verifies one proposal while consuming the shared
    /// CEV0 admission budget.  The root ceiling is checked before any framed
    /// field is copied; nested certificate/evidence work is charged before its
    /// strict signature verifier is called.
    pub fn decode_with_budget(
        bytes: &[u8],
        validator_set: &ValidatorSet,
        consensus_parameters: &ConsensusParametersV0,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<Self, ConsensusWireError> {
        budget
            .admit_root_bytes(bytes.len())
            .map_err(invalid_debug)?;
        if bytes.len() > MAX_PROPOSAL_PAYLOAD_BYTES {
            return Err(ConsensusWireError::TooLarge);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8, "proposal magic")? != PROPOSAL_MAGIC {
            return Err(ConsensusWireError::Malformed("wrong proposal magic"));
        }
        if cursor.u16("proposal version")? != PROPOSAL_VERSION {
            return Err(ConsensusWireError::Malformed("wrong proposal version"));
        }
        let header_bytes = cursor.bytes("header")?;
        let header = decode_block_header_v0_exact(header_bytes).map_err(invalid_debug)?;
        if header.epoch() != Epoch::new(0)
            || header.genesis_hash() != validator_set.genesis_hash()
            || header.chain_id() != validator_set.chain_id()
            || header.protocol_version() != validator_set.protocol_version()
            || header.validator_set_id() != validator_set.id()
            || header.consensus_parameters_hash() != consensus_parameters.hash()
        {
            return Err(ConsensusWireError::Malformed(
                "proposal header differs from the run context",
            ));
        }
        let application_payload = cursor.bytes("application payload")?.to_vec();
        let decoded_payload =
            decode_application_payload_v0_exact(&application_payload, consensus_parameters)
                .map_err(invalid_debug)?;
        if decoded_payload.try_cev0_bytes().map_err(invalid_debug)? != application_payload {
            return Err(ConsensusWireError::Malformed(
                "application payload is not an exact canonical value",
            ));
        }
        let evidence_count = cursor.count("evidence count")?;
        if evidence_count > MAX_PROPOSAL_EVIDENCE_ITEMS {
            return Err(ConsensusWireError::TooLarge);
        }
        let mut evidence_objects = Vec::with_capacity(evidence_count);
        for _ in 0..evidence_count {
            let evidence_bytes = cursor.bytes("evidence object")?.to_vec();
            let evidence = decode_double_vote_evidence_v0_exact(&evidence_bytes, validator_set)
                .map_err(invalid_debug)?;
            // Double-vote evidence carries two independently signed records.
            budget.charge_signature_work(2).map_err(invalid_debug)?;
            evidence
                .verify(validator_set, &StrictEd25519Verifier)
                .map_err(invalid_debug)?;
            if evidence.try_cev0_bytes().map_err(invalid_debug)? != evidence_bytes {
                return Err(ConsensusWireError::Malformed(
                    "evidence is not an exact canonical value",
                ));
            }
            evidence_objects.push(evidence_bytes);
        }
        let justify_qc = decode_qc_reference_v0_exact_with_trusted_genesis_and_budget(
            cursor.bytes("justify QC")?,
            validator_set,
            budget,
        )
        .map_err(invalid_debug)?;
        verify_qc_reference(&justify_qc, validator_set)?;
        let timeout_certificate = match cursor.u8("timeout presence")? {
            0 => None,
            1 => {
                let value = decode_timeout_certificate_v0_exact_with_trusted_genesis_and_budget(
                    cursor.bytes("timeout certificate")?,
                    validator_set,
                    budget,
                )
                .map_err(invalid_debug)?;
                value
                    .verify(validator_set, None, &StrictEd25519Verifier)
                    .map_err(invalid_debug)?;
                Some(value)
            }
            _ => {
                return Err(ConsensusWireError::Malformed(
                    "non-canonical timeout presence tag",
                ));
            }
        };
        let proposer_signature = SignatureBytes::from_array(cursor.array("proposer signature")?);
        budget.charge_signature_work(1).map_err(invalid_debug)?;
        cursor.finish()?;
        let block =
            Block::new(header, application_payload, evidence_objects).map_err(invalid_debug)?;
        let proposal = Self {
            block,
            justify_qc,
            timeout_certificate,
            proposer_signature,
        };
        proposal.verify_proposer_signature(validator_set)?;
        Ok(proposal)
    }
}

pub fn encode_vote(vote: &Vote) -> Vec<u8> {
    let mut output = Vec::with_capacity(VOTE_WIRE_BYTES);
    output.extend_from_slice(&VOTE_VERSION.to_be_bytes());
    output.extend_from_slice(&vote.view().get().to_be_bytes());
    output.extend_from_slice(&vote.height().get().to_be_bytes());
    output.extend_from_slice(vote.block_id().as_bytes());
    output.extend_from_slice(vote.author().as_bytes());
    output.extend_from_slice(vote.signature().as_bytes());
    output
}

pub fn decode_vote(bytes: &[u8], validator_set: &ValidatorSet) -> Result<Vote, ConsensusWireError> {
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    decode_vote_with_budget(bytes, validator_set, &mut budget)
}

pub(crate) fn decode_vote_with_budget(
    bytes: &[u8],
    validator_set: &ValidatorSet,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<Vote, ConsensusWireError> {
    budget
        .admit_root_bytes(bytes.len())
        .map_err(invalid_debug)?;
    if bytes.len() != VOTE_WIRE_BYTES {
        return Err(ConsensusWireError::Malformed("wrong vote payload length"));
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.u16("vote version")? != VOTE_VERSION {
        return Err(ConsensusWireError::Malformed("wrong vote version"));
    }
    let vote = Vote::new(
        validator_set.chain_id(),
        validator_set.protocol_version(),
        validator_set.epoch(),
        View::new(cursor.u64("vote view")?),
        Height::new(cursor.u64("vote height")?),
        BlockId::new(cursor.array("vote block ID")?),
        validator_set.id(),
        ValidatorId::new(cursor.array("vote author")?),
        SignatureBytes::from_array(cursor.array("vote signature")?),
        validator_set,
    )
    .map_err(invalid_debug)?;
    cursor.finish()?;
    budget.charge_signature_work(1).map_err(invalid_debug)?;
    vote.verify(validator_set, &StrictEd25519Verifier)
        .map_err(invalid_debug)?;
    Ok(vote)
}

pub fn encode_timeout_vote(vote: &TimeoutVote) -> Vec<u8> {
    let high = vote.high_qc();
    let mut output = Vec::with_capacity(TIMEOUT_VOTE_WIRE_BYTES);
    output.extend_from_slice(&TIMEOUT_VOTE_VERSION.to_be_bytes());
    output.extend_from_slice(&vote.view().get().to_be_bytes());
    output.extend_from_slice(high.qc_digest().as_bytes());
    output.extend_from_slice(&high.epoch().get().to_be_bytes());
    output.extend_from_slice(&high.view().get().to_be_bytes());
    output.extend_from_slice(&high.height().get().to_be_bytes());
    output.extend_from_slice(high.block_id().as_bytes());
    output.extend_from_slice(high.validator_set_id().as_bytes());
    output.extend_from_slice(vote.author().as_bytes());
    output.extend_from_slice(vote.signature().as_bytes());
    output
}

pub fn decode_timeout_vote(
    bytes: &[u8],
    validator_set: &ValidatorSet,
) -> Result<TimeoutVote, ConsensusWireError> {
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    decode_timeout_vote_with_budget(bytes, validator_set, &mut budget)
}

pub(crate) fn decode_timeout_vote_with_budget(
    bytes: &[u8],
    validator_set: &ValidatorSet,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<TimeoutVote, ConsensusWireError> {
    budget
        .admit_root_bytes(bytes.len())
        .map_err(invalid_debug)?;
    if bytes.len() != TIMEOUT_VOTE_WIRE_BYTES {
        return Err(ConsensusWireError::Malformed(
            "wrong timeout-vote payload length",
        ));
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.u16("timeout-vote version")? != TIMEOUT_VOTE_VERSION {
        return Err(ConsensusWireError::Malformed("wrong timeout-vote version"));
    }
    let view = View::new(cursor.u64("timeout-vote view")?);
    let high_qc = QcRef::new(
        trnm_consensus_types::CertificateId::new(cursor.array("high-QC digest")?),
        Epoch::new(cursor.u64("high-QC epoch")?),
        View::new(cursor.u64("high-QC view")?),
        Height::new(cursor.u64("high-QC height")?),
        BlockId::new(cursor.array("high-QC block")?),
        trnm_consensus_types::ValidatorSetId::new(cursor.array("high-QC set")?),
    );
    let vote = TimeoutVote::new(
        validator_set.chain_id(),
        validator_set.protocol_version(),
        validator_set.epoch(),
        view,
        validator_set.id(),
        high_qc,
        ValidatorId::new(cursor.array("timeout-vote author")?),
        SignatureBytes::from_array(cursor.array("timeout-vote signature")?),
        validator_set,
    )
    .map_err(invalid_debug)?;
    cursor.finish()?;
    budget.charge_signature_work(1).map_err(invalid_debug)?;
    vote.verify(validator_set, &StrictEd25519Verifier)
        .map_err(invalid_debug)?;
    Ok(vote)
}

pub fn encode_quorum_certificate(
    certificate: &QuorumCertificate,
) -> Result<Vec<u8>, ConsensusWireError> {
    certificate.try_cev0_bytes().map_err(invalid_debug)
}

pub fn decode_quorum_certificate(
    bytes: &[u8],
    validator_set: &ValidatorSet,
) -> Result<QuorumCertificate, ConsensusWireError> {
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    decode_quorum_certificate_with_budget(bytes, validator_set, &mut budget)
}

pub(crate) fn decode_quorum_certificate_with_budget(
    bytes: &[u8],
    validator_set: &ValidatorSet,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<QuorumCertificate, ConsensusWireError> {
    decode_quorum_certificate_with_budget_and_verifier(
        bytes,
        validator_set,
        budget,
        &StrictEd25519Verifier,
    )
}

fn decode_quorum_certificate_with_budget_and_verifier<V: SignatureVerifier>(
    bytes: &[u8],
    validator_set: &ValidatorSet,
    budget: &mut Cev0AdmissionBudgetV0,
    verifier: &V,
) -> Result<QuorumCertificate, ConsensusWireError> {
    let certificate = decode_ordinary_qc_v0_exact_with_budget(bytes, validator_set, budget)
        .map_err(invalid_debug)?;
    certificate
        .verify(validator_set, verifier)
        .map_err(invalid_debug)?;
    Ok(certificate)
}

pub fn encode_timeout_certificate(
    certificate: &TimeoutCertificateV0,
) -> Result<Vec<u8>, ConsensusWireError> {
    certificate.try_cev0_bytes().map_err(invalid_debug)
}

pub fn decode_timeout_certificate(
    bytes: &[u8],
    validator_set: &ValidatorSet,
) -> Result<TimeoutCertificateV0, ConsensusWireError> {
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    decode_timeout_certificate_with_budget(bytes, validator_set, &mut budget)
}

pub(crate) fn decode_timeout_certificate_with_budget(
    bytes: &[u8],
    validator_set: &ValidatorSet,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<TimeoutCertificateV0, ConsensusWireError> {
    decode_timeout_certificate_with_budget_and_verifier(
        bytes,
        validator_set,
        budget,
        &StrictEd25519Verifier,
    )
}

fn decode_timeout_certificate_with_budget_and_verifier<V: SignatureVerifier>(
    bytes: &[u8],
    validator_set: &ValidatorSet,
    budget: &mut Cev0AdmissionBudgetV0,
    verifier: &V,
) -> Result<TimeoutCertificateV0, ConsensusWireError> {
    let certificate = decode_timeout_certificate_v0_exact_with_trusted_genesis_and_budget(
        bytes,
        validator_set,
        budget,
    )
    .map_err(invalid_debug)?;
    certificate
        .verify(validator_set, None, verifier)
        .map_err(invalid_debug)?;
    Ok(certificate)
}

fn verify_qc_reference(
    reference: &QcReferenceV0,
    validator_set: &ValidatorSet,
) -> Result<(), ConsensusWireError> {
    match reference {
        QcReferenceV0::Ordinary(certificate) => certificate
            .verify(validator_set, &StrictEd25519Verifier)
            .map_err(invalid_debug),
        QcReferenceV0::Synthetic(value) => match value.as_ref() {
            ContextAuthorizedQcV0::Genesis(anchor) => anchor
                .matches_trusted_set(validator_set)
                .map_err(invalid_debug),
            ContextAuthorizedQcV0::Epoch(_) => Err(ConsensusWireError::Malformed(
                "epoch-anchor QC is outside the G3 epoch-zero profile",
            )),
        },
    }
}

fn qc_reference_bytes(reference: &QcReferenceV0) -> Result<Vec<u8>, ConsensusWireError> {
    match reference {
        QcReferenceV0::Ordinary(certificate) => certificate.try_cev0_bytes().map_err(invalid_debug),
        QcReferenceV0::Synthetic(value) => match value.as_ref() {
            ContextAuthorizedQcV0::Genesis(anchor) => {
                anchor.try_cev0_bytes().map_err(invalid_debug)
            }
            ContextAuthorizedQcV0::Epoch(_) => Err(ConsensusWireError::Malformed(
                "epoch-anchor QC is outside the G3 epoch-zero profile",
            )),
        },
    }
}

fn invalid_debug(error: impl fmt::Debug) -> ConsensusWireError {
    ConsensusWireError::Invalid(format!("{error:?}"))
}

fn push_count(output: &mut Vec<u8>, count: usize) -> Result<(), ConsensusWireError> {
    let count = u32::try_from(count).map_err(|_| ConsensusWireError::TooLarge)?;
    output.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn push_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ConsensusWireError> {
    push_count(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], ConsensusWireError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ConsensusWireError::TooLarge)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ConsensusWireError::Truncated(field))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], ConsensusWireError> {
        self.take(N, field)?
            .try_into()
            .map_err(|_| ConsensusWireError::Truncated(field))
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, ConsensusWireError> {
        Ok(self.array::<1>(field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, ConsensusWireError> {
        Ok(u16::from_be_bytes(self.array(field)?))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, ConsensusWireError> {
        Ok(u32::from_be_bytes(self.array(field)?))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, ConsensusWireError> {
        Ok(u64::from_be_bytes(self.array(field)?))
    }

    fn count(&mut self, field: &'static str) -> Result<usize, ConsensusWireError> {
        usize::try_from(self.u32(field)?).map_err(|_| ConsensusWireError::TooLarge)
    }

    fn bytes(&mut self, field: &'static str) -> Result<&'a [u8], ConsensusWireError> {
        let length = self.count(field)?;
        self.take(length, field)
    }

    fn finish(self) -> Result<(), ConsensusWireError> {
        if self.offset != self.bytes.len() {
            return Err(ConsensusWireError::Malformed("trailing consensus bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use ed25519_dalek::{Signer, SigningKey};
    use trnm_consensus_types::{
        ApplicationPayloadV0, BlockHeader, BlockKind, ChainId, ConsensusPublicKey, EvidenceRoot,
        GenesisHash, PayloadDigest, ProtocolVersion, ReceiptsRoot, SignatureBytes, StateRoot,
        TimeoutEntryV0, Validator, VotingPower,
    };

    use super::*;

    fn fixture() -> (Vec<SigningKey>, ValidatorSet) {
        let keys: Vec<_> = (1u8..=4)
            .map(|seed| SigningKey::from_bytes(&[seed; 32]))
            .collect();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                Validator::new(
                    ValidatorId::new([u8::try_from(index + 1).unwrap(); 32]),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = ValidatorSet::new(
            GenesisHash::new([0x91; 32]),
            ChainId::new("trnm-poco-wire-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        (keys, set)
    }

    fn signed_vote(
        keys: &[SigningKey],
        set: &ValidatorSet,
        index: usize,
        view: u64,
        height: u64,
        block: BlockId,
    ) -> Vote {
        let root =
            Vote::signing_root_for_set(set, View::new(view), Height::new(height), block).unwrap();
        Vote::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            Height::new(height),
            block,
            set.id(),
            set.validators()[index].id(),
            SignatureBytes::from_array(keys[index].sign(root.as_bytes()).to_bytes()),
            set,
        )
        .unwrap()
    }

    struct CountingVerifier {
        calls: Cell<usize>,
    }

    impl SignatureVerifier for CountingVerifier {
        fn verify(
            &self,
            _validator: &Validator,
            _signing_root: &trnm_consensus_types::SigningRoot,
            _signature: &SignatureBytes,
        ) -> bool {
            self.calls.set(self.calls.get() + 1);
            true
        }
    }

    fn signed_timeout_certificate(keys: &[SigningKey], set: &ValidatorSet) -> TimeoutCertificateV0 {
        let block = BlockId::new([0x44; 32]);
        let votes = (0..3)
            .map(|index| signed_vote(keys, set, index, 1, 1, block))
            .collect();
        let qc = QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(1),
            Height::new(1),
            block,
            set.id(),
            votes,
            set,
        )
        .unwrap();
        let high_qc = QcRef::from(&qc);
        let entries = (0..3)
            .map(|index| {
                TimeoutEntryV0::new(
                    set.validators()[index].id(),
                    high_qc,
                    SignatureBytes::from_array([0x70 + index as u8; 64]),
                )
                .unwrap()
            })
            .collect();
        TimeoutCertificateV0::new(
            View::new(2),
            entries,
            vec![QcReferenceV0::ordinary(qc.clone())],
            qc.id(),
            set,
        )
        .unwrap()
    }

    #[test]
    fn vote_and_qc_roundtrip_are_strict() {
        let (keys, set) = fixture();
        let block = BlockId::new([0x33; 32]);
        let vote = signed_vote(&keys, &set, 0, 1, 1, block);
        assert_eq!(decode_vote(&encode_vote(&vote), &set).unwrap(), vote);

        let votes = (0..3)
            .map(|index| signed_vote(&keys, &set, index, 1, 1, block))
            .collect();
        let qc = QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(1),
            Height::new(1),
            block,
            set.id(),
            votes,
            &set,
        )
        .unwrap();
        let bytes = encode_quorum_certificate(&qc).unwrap();
        assert_eq!(decode_quorum_certificate(&bytes, &set).unwrap(), qc);
        let mut corrupt = bytes;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(decode_quorum_certificate(&corrupt, &set).is_err());
    }

    #[test]
    fn oversized_root_is_rejected_before_strict_verifier() {
        let (_, set) = fixture();
        let verifier = CountingVerifier {
            calls: Cell::new(0),
        };
        let mut budget = Cev0AdmissionBudgetV0::with_limits(8, 128, 128);
        let error = decode_timeout_certificate_with_budget_and_verifier(
            &[0; 9],
            &set,
            &mut budget,
            &verifier,
        )
        .unwrap_err();
        assert!(matches!(error, ConsensusWireError::Invalid(_)));
        assert_eq!(verifier.calls.get(), 0);
    }

    #[test]
    fn tc_aggregate_budget_is_checked_before_strict_verifier() {
        let (keys, set) = fixture();
        let certificate = signed_timeout_certificate(&keys, &set);
        let bytes = encode_timeout_certificate(&certificate).unwrap();
        let verifier = CountingVerifier {
            calls: Cell::new(0),
        };
        // The nested QC has three shares; a two-share authenticated budget
        // must reject before any QC or timeout-entry signature is checked.
        let mut budget = Cev0AdmissionBudgetV0::with_limits(4096, 128, 2);
        let error = decode_timeout_certificate_with_budget_and_verifier(
            &bytes,
            &set,
            &mut budget,
            &verifier,
        )
        .unwrap_err();
        assert!(matches!(error, ConsensusWireError::Invalid(_)));
        assert_eq!(verifier.calls.get(), 0);
    }

    #[test]
    fn qc_work_budget_rejects_before_any_signature_call() {
        let (keys, set) = fixture();
        let block = BlockId::new([0x55; 32]);
        let votes = (0..3)
            .map(|index| signed_vote(&keys, &set, index, 1, 1, block))
            .collect();
        let certificate = QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(1),
            Height::new(1),
            block,
            set.id(),
            votes,
            &set,
        )
        .unwrap();
        let bytes = encode_quorum_certificate(&certificate).unwrap();
        let verifier = CountingVerifier {
            calls: Cell::new(0),
        };
        let mut budget = Cev0AdmissionBudgetV0::with_limits(4096, 2, 128);
        let error = decode_quorum_certificate_with_budget_and_verifier(
            &bytes,
            &set,
            &mut budget,
            &verifier,
        )
        .unwrap_err();
        assert!(matches!(error, ConsensusWireError::Invalid(_)));
        assert_eq!(verifier.calls.get(), 0);
    }

    #[test]
    fn timeout_vote_roundtrip_binds_full_high_qc_reference() {
        let (keys, set) = fixture();
        let high = QcRef::new(
            trnm_consensus_types::CertificateId::new([0x12; 32]),
            set.epoch(),
            View::new(1),
            Height::new(1),
            BlockId::new([0x34; 32]),
            set.id(),
        );
        let root = TimeoutVote::signing_root_for_set(&set, View::new(2), high).unwrap();
        let vote = TimeoutVote::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(2),
            set.id(),
            high,
            set.validators()[0].id(),
            SignatureBytes::from_array(keys[0].sign(root.as_bytes()).to_bytes()),
            &set,
        )
        .unwrap();
        assert_eq!(
            decode_timeout_vote(&encode_timeout_vote(&vote), &set).unwrap(),
            vote
        );
    }

    #[test]
    fn proposal_roundtrip_requires_local_parent_binding_and_strict_signature() {
        let (keys, set) = fixture();
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let payload = ApplicationPayloadV0::new(vec![b"real-lab-transaction".to_vec()]).unwrap();
        let payload_bytes = payload.try_cev0_bytes().unwrap();
        let header = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(1),
            Height::new(1),
            BlockKind::Regular,
            BlockId::new(*set.genesis_hash().as_bytes()),
            set.validators()[0].id(),
            set.id(),
            parameters.hash(),
            payload.payload_root().unwrap(),
            StateRoot::new([0x45; 32]),
            ReceiptsRoot::new([0x46; 32]),
            EvidenceRoot::new([0x47; 32]),
            1,
            None,
        )
        .unwrap();
        assert_ne!(header.payload_digest(), PayloadDigest::new([0; 32]));
        let justify = QcReferenceV0::genesis_anchor(
            trnm_consensus_types::GenesisQcV0::new(set.genesis_hash(), set.chain_id(), &set)
                .unwrap(),
        );
        let signing_root =
            ProposalWitnessV0::signing_root_for(&header, &justify, None, None).unwrap();
        let witness = ProposalWitnessV0::new(
            &header,
            justify,
            None,
            None,
            SignatureBytes::from_array(keys[0].sign(signing_root.as_bytes()).to_bytes()),
            &set,
            None,
            &parameters,
            0,
        )
        .unwrap();
        let proposal = SignedProposalV0::new(
            Block::new(header, payload_bytes, Vec::new()).unwrap(),
            witness,
            &set,
            None,
            &parameters,
            0,
        )
        .unwrap();
        let encoded = UnboundProposalV0::from_signed(&proposal)
            .unwrap()
            .encode()
            .unwrap();
        let decoded = UnboundProposalV0::decode(&encoded, &set, &parameters).unwrap();
        assert_eq!(
            decoded
                .bind_authenticated_parent(&set, &parameters, 0)
                .unwrap(),
            proposal
        );
        assert!(UnboundProposalV0::decode(
            &{
                let mut corrupt = encoded;
                let last = corrupt.len() - 1;
                corrupt[last] ^= 1;
                corrupt
            },
            &set,
            &parameters,
        )
        .is_err());
    }
}
