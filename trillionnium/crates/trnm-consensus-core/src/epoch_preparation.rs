//! Versioned, I/O-free preparation of strictly authenticated epoch evidence.
//!
//! This record is separate from SafetyState schema 13. Its sole closed phase
//! is EvidenceVerified: the checkpoint has cryptographic finality, but this
//! record does not attest native checkpoint application, seal signing custody,
//! an active anchor, a signer namespace, or a live Core. The corresponding
//! SafetyStore owns durable creation and fresh reopen verification.

use alloc::vec::Vec;
use core::fmt;
use trnm_consensus_crypto::{
    recover_epoch_activation_authority_strict_v0, EpochActivationRecoveryErrorV0,
    StrictSameVersionEpochActivationAuthorityV0,
};
use trnm_consensus_types::{
    Cev0AdmissionBudgetV0, ConsensusParametersV0, EpochActivationEvidenceBytesV0,
    EpochActivationEvidencePreimagesV0, ValidationError, ValidatorSet, MAX_CEV0_ROOT_BYTES_V0,
};

const MAGIC: &[u8; 8] = b"TRNMEP01";
pub const EPOCH_PREPARATION_RECORD_SCHEMA_V1: u16 = 1;
pub const EPOCH_PREPARATION_RECORD_OVERHEAD_V1: usize = 8 + 2 + 1 + 32 + 8 * 4;
pub const MAX_EPOCH_PREPARATION_RECORD_BYTES_V1: usize =
    MAX_CEV0_ROOT_BYTES_V0 + EPOCH_PREPARATION_RECORD_OVERHEAD_V1;

pub fn maximum_epoch_preparation_record_bytes_v1(parameters: &ConsensusParametersV0) -> usize {
    Cev0AdmissionBudgetV0::for_parameters(parameters).maximum_root_bytes()
        + EPOCH_PREPARATION_RECORD_OVERHEAD_V1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochPreparationPhaseV1 {
    EvidenceVerified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochPreparationErrorV1 {
    InvalidEncoding(&'static str),
    LengthLimitExceeded,
    ExpectedBindingMismatch,
    Evidence(EpochActivationRecoveryErrorV0),
    Canonical(ValidationError),
}

impl fmt::Display for EpochPreparationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding(reason) => {
                write!(formatter, "epoch preparation encoding: {reason}")
            }
            Self::LengthLimitExceeded => {
                formatter.write_str("epoch preparation record exceeds its bound")
            }
            Self::ExpectedBindingMismatch => {
                formatter.write_str("epoch preparation expected binding differs")
            }
            Self::Evidence(error) => write!(formatter, "epoch preparation evidence: {error}"),
            Self::Canonical(error) => {
                write!(formatter, "epoch preparation canonical preimage: {error}")
            }
        }
    }
}
impl core::error::Error for EpochPreparationErrorV1 {}

/// Inert persistence representation. Its bytes cannot reconstruct authority
/// without the complete strict recovery function and an independent old trust
/// context. This local storage framing is not an EpochHandoffProof wire
/// encoding and introduces no protocol hash or signature domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochPreparationRecordV1 {
    binding_ref: [u8; 32],
    evidence: EpochActivationEvidenceBytesV0,
}

impl EpochPreparationRecordV1 {
    pub const fn phase_v1(&self) -> EpochPreparationPhaseV1 {
        EpochPreparationPhaseV1::EvidenceVerified
    }
    pub const fn binding_ref_v1(&self) -> [u8; 32] {
        self.binding_ref
    }
    pub fn evidence_preimages_v1(&self) -> EpochActivationEvidencePreimagesV0<'_> {
        self.evidence.as_preimages()
    }
    pub fn encode_v1(&self) -> Result<Vec<u8>, EpochPreparationErrorV1> {
        let roots = roots(self.evidence.as_preimages());
        let total = roots
            .iter()
            .try_fold(EPOCH_PREPARATION_RECORD_OVERHEAD_V1, |size, root| {
                size.checked_add(root.len())
                    .ok_or(EpochPreparationErrorV1::LengthLimitExceeded)
            })?;
        if total > MAX_EPOCH_PREPARATION_RECORD_BYTES_V1 || self.binding_ref == [0; 32] {
            return Err(EpochPreparationErrorV1::LengthLimitExceeded);
        }
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&EPOCH_PREPARATION_RECORD_SCHEMA_V1.to_be_bytes());
        bytes.push(0); // EvidenceVerified; every other phase is unsupported.
        bytes.extend_from_slice(&self.binding_ref);
        for root in roots {
            let length = u32::try_from(root.len())
                .map_err(|_| EpochPreparationErrorV1::LengthLimitExceeded)?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(root);
        }
        Ok(bytes)
    }
}

/// Consumes a complete strict authority into an explicit preparation phase.
/// This owner is non-cloneable and contains no Core step, Vote/Timeout signer,
/// timer or native-application mutation interface.
#[derive(Debug)]
#[must_use = "epoch preparation must be durably stored or remain non-activating"]
pub struct EpochPreparationV1 {
    authority: StrictSameVersionEpochActivationAuthorityV0,
    record: EpochPreparationRecordV1,
}
impl EpochPreparationV1 {
    pub const fn record_v1(&self) -> &EpochPreparationRecordV1 {
        &self.record
    }
    pub const fn authority_v1(&self) -> &StrictSameVersionEpochActivationAuthorityV0 {
        &self.authority
    }
}

pub fn prepare_epoch_handoff_evidence_v1(
    authority: StrictSameVersionEpochActivationAuthorityV0,
) -> Result<EpochPreparationV1, EpochPreparationErrorV1> {
    let evidence = EpochActivationEvidenceBytesV0 {
        old_checkpoint_finality: authority
            .old_checkpoint_finality()
            .try_cev0_bytes()
            .map_err(EpochPreparationErrorV1::Canonical)?,
        next_epoch_commitment: authority
            .next_epoch_commitment()
            .try_cev0_bytes()
            .map_err(EpochPreparationErrorV1::Canonical)?,
        authorization_kernel: authority
            .authorization_kernel()
            .try_cev0_bytes()
            .map_err(EpochPreparationErrorV1::Canonical)?,
        old_validator_set: authority
            .old_validator_set()
            .try_cev0_bytes()
            .map_err(EpochPreparationErrorV1::Canonical)?,
        old_consensus_parameters: authority.old_consensus_parameters().canonical_bytes(),
        new_validator_set: authority
            .new_validator_set()
            .try_cev0_bytes()
            .map_err(EpochPreparationErrorV1::Canonical)?,
        new_consensus_parameters: authority.new_consensus_parameters().canonical_bytes(),
        authenticated_checkpoint_parent_header: authority
            .authenticated_checkpoint_parent_header()
            .try_cev0_bytes()
            .map_err(EpochPreparationErrorV1::Canonical)?,
    };
    let record = EpochPreparationRecordV1 {
        binding_ref: *authority.binding_ref().as_bytes(),
        evidence,
    };
    record.encode_v1()?;
    Ok(EpochPreparationV1 { authority, record })
}

/// Reopens one exact preparation record by reloading every canonical root and
/// strictly rechecking all signatures against independent trust inputs. This
/// returns an actual new preparation owner; it never marks the native
/// checkpoint applied or releases live consensus. Work reserved before strict
/// verification remains charged if verification or subsequent checks fail.
pub fn recover_epoch_preparation_v1(
    bytes: &[u8],
    trusted_old_set: &ValidatorSet,
    trusted_old_parameters: &ConsensusParametersV0,
    expected_binding: [u8; 32],
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<EpochPreparationV1, EpochPreparationErrorV1> {
    let maximum_record_bytes = budget
        .maximum_root_bytes()
        .checked_add(EPOCH_PREPARATION_RECORD_OVERHEAD_V1)
        .ok_or(EpochPreparationErrorV1::LengthLimitExceeded)?;
    if bytes.len() > maximum_record_bytes || bytes.len() > MAX_EPOCH_PREPARATION_RECORD_BYTES_V1 {
        return Err(EpochPreparationErrorV1::LengthLimitExceeded);
    }
    let mut cursor = Cursor { bytes, offset: 0 };
    if cursor.take(8)? != MAGIC
        || cursor.take(2)? != EPOCH_PREPARATION_RECORD_SCHEMA_V1.to_be_bytes()
        || cursor.take(1)? != [0]
    {
        return Err(EpochPreparationErrorV1::InvalidEncoding(
            "unsupported magic, schema or phase",
        ));
    }
    if expected_binding == [0; 32] || cursor.take(32)? != expected_binding {
        return Err(EpochPreparationErrorV1::ExpectedBindingMismatch);
    }
    // Borrow all eight roots and exhaust framing before allocating or verifying.
    let fields = EpochActivationEvidencePreimagesV0 {
        old_checkpoint_finality: cursor.blob()?,
        next_epoch_commitment: cursor.blob()?,
        authorization_kernel: cursor.blob()?,
        old_validator_set: cursor.blob()?,
        old_consensus_parameters: cursor.blob()?,
        new_validator_set: cursor.blob()?,
        new_consensus_parameters: cursor.blob()?,
        authenticated_checkpoint_parent_header: cursor.blob()?,
    };
    if cursor.offset != bytes.len() {
        return Err(EpochPreparationErrorV1::InvalidEncoding("trailing bytes"));
    }
    let authority = recover_epoch_activation_authority_strict_v0(
        fields,
        trusted_old_set,
        trusted_old_parameters,
        expected_binding,
        budget,
    )
    .map_err(EpochPreparationErrorV1::Evidence)?;
    let preparation = prepare_epoch_handoff_evidence_v1(authority)?;
    if preparation.record.encode_v1()? != bytes {
        return Err(EpochPreparationErrorV1::InvalidEncoding(
            "noncanonical record",
        ));
    }
    Ok(preparation)
}

fn roots(fields: EpochActivationEvidencePreimagesV0<'_>) -> [&[u8]; 8] {
    [
        fields.old_checkpoint_finality,
        fields.next_epoch_commitment,
        fields.authorization_kernel,
        fields.old_validator_set,
        fields.old_consensus_parameters,
        fields.new_validator_set,
        fields.new_consensus_parameters,
        fields.authenticated_checkpoint_parent_header,
    ]
}
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], EpochPreparationErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(EpochPreparationErrorV1::LengthLimitExceeded)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(EpochPreparationErrorV1::InvalidEncoding("truncated record"))?;
        self.offset = end;
        Ok(value)
    }
    fn blob(&mut self) -> Result<&'a [u8], EpochPreparationErrorV1> {
        let length =
            u32::from_be_bytes(self.take(4)?.try_into().expect("exact four bytes")) as usize;
        if length == 0 || length > MAX_CEV0_ROOT_BYTES_V0 {
            return Err(EpochPreparationErrorV1::LengthLimitExceeded);
        }
        self.take(length)
    }
}
