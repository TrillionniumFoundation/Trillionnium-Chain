//! Bounded semantic decoding for the protobuf `WireEnvelope` body.
//!
//! [`crate::decode_wire_envelope_v0_preflight`] deliberately stops at the
//! outer protobuf boundary.  That is useful for cheap transport admission,
//! but it is not a protocol proof: a peer could otherwise put an arbitrary
//! protobuf message behind a correctly labelled oneof.  This module closes
//! the next boundary for the four v0 consensus messages that can be decoded
//! without an application/runtime adapter (`Vote`, `TimeoutVote`, `QC`, and
//! `TC`).  It uses a small allocation-bounded protobuf reader, checks every
//! redundant scope field against an authenticated validator set and parameter
//! value, and then constructs the existing typed CEV0 values.  Signatures are
//! shape checked here; cryptographic verification remains an explicit caller
//! operation.
//!
//! The other transport body kinds are rejected with an explicit
//! `unsupported_body_kind` result until their complete typed adapters exist.
//! Rejecting them is intentional: a successful outer preflight must never be
//! mistaken for global wire conformance.

use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest, Sha256};

use crate::{
    canonical::CanonicalSignable, decode_wire_envelope_v0_preflight, BlockId, CertificateId,
    Cev0AdmissionBudgetV0, ConsensusParametersV0, Epoch, Height, MessageKind, QcRef, QcReferenceV0,
    QuorumCertificate, SignatureBytes, SignatureVerifier, TimeoutCertificateV0, TimeoutEntryV0,
    TimeoutVote, ValidationError, ValidatorId, ValidatorSet, View, Vote, WireBodyKindV0,
    WireEnvelopeDecodeError, WireEnvelopeDecodeErrorCode, WireEnvelopePreflight,
    MAX_CEV0_CERTIFICATE_ITEMS, MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES, MAX_CONSENSUS_STRING_BYTES,
    MAX_VALIDATOR_ID_BYTES, SIGNATURE_BYTES,
};

/// Maximum recursion depth for nested protobuf messages in the v0 transport
/// profile.  A TC contains QCs and a QC contains signature-share messages;
/// future body adapters must stay below this same bound.
pub const MAX_WIRE_NESTED_DEPTH_V0: usize = 8;

/// Maximum number of fields visited in one nested message.  This is separate
/// from the byte ceiling so a tiny duplicate-field bomb cannot consume an
/// unbounded amount of parser work.
pub const MAX_WIRE_NESTED_FIELDS_V0: usize = 4096;

/// Stable upper bound for every repeated consensus list in the transport
/// profile.  The authenticated validator set can impose a smaller effective
/// bound; no list is ever allocated before this cap is checked.
pub const MAX_WIRE_NESTED_LIST_ITEMS_V0: usize = MAX_CEV0_CERTIFICATE_ITEMS;

/// A semantically decoded body kind.  The enum intentionally contains only
/// kinds with a complete typed CEV0 adapter in this tranche.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WireSemanticBodyKindV0 {
    Vote = 1,
    TimeoutVote = 2,
    QuorumCertificate = 3,
    TimeoutCertificate = 4,
}

/// Stable machine-readable failures for nested semantic transport decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireSemanticDecodeErrorCode {
    OuterPreflight,
    Empty,
    NestedTooLarge,
    UnexpectedEof,
    VarintOverflow,
    NonCanonicalVarint,
    InvalidFieldKey,
    UnsupportedWireType,
    UnknownField,
    DuplicateField,
    NonCanonicalFieldOrder,
    FieldTypeMismatch,
    LengthOverflow,
    FieldTooLarge,
    MissingField,
    InvalidValue,
    ScopeMismatch,
    MessageKindMismatch,
    BodyKindMismatch,
    InvalidSignature,
    InvalidSigner,
    InvalidQuorum,
    DigestMismatch,
    NestedDepthExceeded,
    AggregateLimitExceeded,
    ValidationFailed,
    UnsupportedBodyKind,
}

impl WireSemanticDecodeErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OuterPreflight => "outer_preflight",
            Self::Empty => "empty",
            Self::NestedTooLarge => "nested_too_large",
            Self::UnexpectedEof => "unexpected_eof",
            Self::VarintOverflow => "varint_overflow",
            Self::NonCanonicalVarint => "noncanonical_varint",
            Self::InvalidFieldKey => "invalid_field_key",
            Self::UnsupportedWireType => "unsupported_wire_type",
            Self::UnknownField => "unknown_field",
            Self::DuplicateField => "duplicate_field",
            Self::NonCanonicalFieldOrder => "noncanonical_field_order",
            Self::FieldTypeMismatch => "field_type_mismatch",
            Self::LengthOverflow => "length_overflow",
            Self::FieldTooLarge => "field_too_large",
            Self::MissingField => "missing_field",
            Self::InvalidValue => "invalid_value",
            Self::ScopeMismatch => "scope_mismatch",
            Self::MessageKindMismatch => "message_kind_mismatch",
            Self::BodyKindMismatch => "body_kind_mismatch",
            Self::InvalidSignature => "invalid_signature",
            Self::InvalidSigner => "invalid_signer",
            Self::InvalidQuorum => "invalid_quorum",
            Self::DigestMismatch => "digest_mismatch",
            Self::NestedDepthExceeded => "nested_depth_exceeded",
            Self::AggregateLimitExceeded => "aggregate_limit_exceeded",
            Self::ValidationFailed => "validation_failed",
            Self::UnsupportedBodyKind => "unsupported_body_kind",
        }
    }
}

/// A bounded nested-wire failure at an offset relative to the offending body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireSemanticDecodeError {
    code: WireSemanticDecodeErrorCode,
    byte_offset: usize,
}

impl WireSemanticDecodeError {
    const fn new(code: WireSemanticDecodeErrorCode, byte_offset: usize) -> Self {
        Self { code, byte_offset }
    }

    pub const fn code(self) -> WireSemanticDecodeErrorCode {
        self.code
    }

    pub const fn byte_offset(self) -> usize {
        self.byte_offset
    }
}

impl fmt::Display for WireSemanticDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "WireEnvelope semantic decode error {} at byte {}",
            self.code.as_str(),
            self.byte_offset
        )
    }
}

impl core::error::Error for WireSemanticDecodeError {}

/// The owned typed body retained by a semantic proof.  Keeping the exact
/// typed value is important: a transport caller must be able to run the
/// existing CEV0 cryptographic verifier over every nested signature instead
/// of treating a shape-checked protobuf as an authenticated QC/TC.
#[derive(Debug, Clone, PartialEq, Eq)]
enum WireSemanticBodyV0 {
    Vote(Vote),
    TimeoutVote(TimeoutVote),
    QuorumCertificate(QuorumCertificate),
    TimeoutCertificate(TimeoutCertificateV0),
}

/// The useful, typed result of semantic body decoding.  `semantic_digest` is
/// the existing CEV0 signing root (for Vote/TimeoutVote) or certificate ID
/// (for QC/TC), never a hash of unverified protobuf bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireEnvelopeSemanticProof<'a> {
    preflight: WireEnvelopePreflight<'a>,
    body_kind: WireSemanticBodyKindV0,
    body: WireSemanticBodyV0,
    semantic_digest: [u8; 32],
    signer_count: usize,
    nested_qc_count: usize,
    aggregate_signature_shares: usize,
}

impl<'a> WireEnvelopeSemanticProof<'a> {
    pub const fn preflight(&self) -> WireEnvelopePreflight<'a> {
        self.preflight
    }

    pub const fn body_kind(&self) -> WireSemanticBodyKindV0 {
        self.body_kind
    }

    pub const fn semantic_digest(&self) -> &[u8; 32] {
        &self.semantic_digest
    }

    pub const fn signer_count(&self) -> usize {
        self.signer_count
    }

    pub const fn nested_qc_count(&self) -> usize {
        self.nested_qc_count
    }

    /// For a QC this is its signature-share count.  For a TC it is the sum of
    /// all nested QC shares plus timeout-entry signatures, exactly the work
    /// charged to [`Cev0AdmissionBudgetV0`].
    pub const fn aggregate_signature_shares(&self) -> usize {
        self.aggregate_signature_shares
    }

    /// Verify every signature-bearing object in the decoded body against the
    /// supplied validator set.  Semantic decoding intentionally remains
    /// cryptographically backend-neutral; callers that cross an authenticated
    /// network boundary must invoke this method with their concrete verifier
    /// before accepting the proof.  The method re-runs typed shape checks as a
    /// defensive context binding, then verifies all Vote/TimeoutVote shares,
    /// including every nested QC and TC timeout entry.
    pub fn verify_signatures<V: SignatureVerifier>(
        &self,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> core::result::Result<(), WireSemanticDecodeError> {
        let result = match &self.body {
            WireSemanticBodyV0::Vote(vote) => vote.verify(validator_set, verifier),
            WireSemanticBodyV0::TimeoutVote(vote) => vote.verify(validator_set, verifier),
            WireSemanticBodyV0::QuorumCertificate(certificate) => {
                certificate.verify(validator_set, verifier)
            }
            WireSemanticBodyV0::TimeoutCertificate(certificate) => {
                certificate.verify(validator_set, None, verifier)
            }
        };
        result.map_err(|error| semantic_error(map_validation_error(error), 0))
    }
}

fn map_validation_error(error: ValidationError) -> WireSemanticDecodeErrorCode {
    match error {
        ValidationError::InvalidSignature(_) => WireSemanticDecodeErrorCode::InvalidSignature,
        ValidationError::UnknownValidator(_)
        | ValidationError::DuplicateSigner(_)
        | ValidationError::NonCanonicalSignerOrder => WireSemanticDecodeErrorCode::InvalidSigner,
        ValidationError::InsufficientQuorum { .. }
        | ValidationError::NonCanonicalQcOrder
        | ValidationError::ConflictingSameViewQc
        | ValidationError::InvalidCertificate(_) => WireSemanticDecodeErrorCode::InvalidQuorum,
        _ => WireSemanticDecodeErrorCode::ValidationFailed,
    }
}

/// Semantically decodes a bounded v0 `WireEnvelope` body.
///
/// The supplied validator set and parameters are authenticated caller context;
/// all nested redundant scope fields must byte/value-match them.  The budget
/// is charged only after a complete typed value has been constructed, while a
/// local aggregate tracker rejects a TC before a nested QC can exceed the
/// authenticated share ceiling.
pub fn decode_wire_envelope_v0_semantic<'a>(
    bytes: &'a [u8],
    validator_set: &ValidatorSet,
    consensus_parameters: &ConsensusParametersV0,
    budget: &mut Cev0AdmissionBudgetV0,
) -> core::result::Result<WireEnvelopeSemanticProof<'a>, WireSemanticDecodeError> {
    let preflight = decode_wire_envelope_v0_preflight(bytes).map_err(map_outer_error)?;
    // Apply the caller's root-byte budget immediately after the allocation-free
    // outer preflight.  A rejected oversized body must not spend validator-set
    // validation, hashing, or nested parser work first.
    budget
        .admit_root_bytes(preflight.body().len())
        .map_err(|_| semantic_error(WireSemanticDecodeErrorCode::NestedTooLarge, 0))?;
    validator_set
        .validate_against_parameters(consensus_parameters)
        .map_err(|_| semantic_error(WireSemanticDecodeErrorCode::ScopeMismatch, 0))?;
    check_outer_scope(&preflight, validator_set, consensus_parameters)?;

    if let Some(expected) = preflight.body_semantic_hash() {
        let actual: [u8; 32] = Sha256::digest(preflight.body()).into();
        if expected != actual {
            return Err(semantic_error(
                WireSemanticDecodeErrorCode::DigestMismatch,
                0,
            ));
        }
    }

    match preflight.body_kind() {
        WireBodyKindV0::Vote => {
            if budget.signature_work() >= budget.maximum_signature_work() {
                return Err(semantic_error(
                    WireSemanticDecodeErrorCode::AggregateLimitExceeded,
                    0,
                ));
            }
            let vote = parse_vote(
                preflight.body(),
                &preflight,
                validator_set,
                consensus_parameters,
            )?;
            let semantic_digest = vote.signing_root().into_bytes();
            budget.charge_signature_work(1).map_err(|_| {
                semantic_error(WireSemanticDecodeErrorCode::AggregateLimitExceeded, 0)
            })?;
            Ok(WireEnvelopeSemanticProof {
                preflight,
                body_kind: WireSemanticBodyKindV0::Vote,
                body: WireSemanticBodyV0::Vote(vote),
                semantic_digest,
                signer_count: 1,
                nested_qc_count: 0,
                aggregate_signature_shares: 1,
            })
        }
        WireBodyKindV0::TimeoutVote => {
            if budget.signature_work() >= budget.maximum_signature_work() {
                return Err(semantic_error(
                    WireSemanticDecodeErrorCode::AggregateLimitExceeded,
                    0,
                ));
            }
            let vote = parse_timeout_vote(
                preflight.body(),
                &preflight,
                validator_set,
                consensus_parameters,
                None,
                0,
            )?;
            let semantic_digest = vote.signing_root().into_bytes();
            budget.charge_signature_work(1).map_err(|_| {
                semantic_error(WireSemanticDecodeErrorCode::AggregateLimitExceeded, 0)
            })?;
            Ok(WireEnvelopeSemanticProof {
                preflight,
                body_kind: WireSemanticBodyKindV0::TimeoutVote,
                body: WireSemanticBodyV0::TimeoutVote(vote),
                semantic_digest,
                signer_count: 1,
                nested_qc_count: 0,
                aggregate_signature_shares: 1,
            })
        }
        WireBodyKindV0::QuorumCertificate => {
            let remaining_work = budget
                .maximum_signature_work()
                .saturating_sub(budget.signature_work());
            let mut tracker = AggregateTracker::new(
                budget
                    .maximum_tc_aggregate_signature_shares()
                    .min(remaining_work),
                remaining_work,
            );
            let (certificate, shares) = parse_qc(
                preflight.body(),
                &preflight,
                validator_set,
                consensus_parameters,
                &mut tracker,
                Some(preflight.view()),
                0,
            )?;
            let semantic_digest = certificate.id().into_bytes();
            budget.charge_qc(&certificate).map_err(|_| {
                semantic_error(WireSemanticDecodeErrorCode::AggregateLimitExceeded, 0)
            })?;
            Ok(WireEnvelopeSemanticProof {
                preflight,
                body_kind: WireSemanticBodyKindV0::QuorumCertificate,
                body: WireSemanticBodyV0::QuorumCertificate(certificate),
                semantic_digest,
                signer_count: shares,
                nested_qc_count: 0,
                aggregate_signature_shares: shares,
            })
        }
        WireBodyKindV0::TimeoutCertificate => {
            let remaining_work = budget
                .maximum_signature_work()
                .saturating_sub(budget.signature_work());
            let mut tracker = AggregateTracker::new(
                budget
                    .maximum_tc_aggregate_signature_shares()
                    .min(remaining_work),
                remaining_work,
            );
            let (certificate, entry_count, qc_count) = parse_tc(
                preflight.body(),
                &preflight,
                validator_set,
                consensus_parameters,
                &mut tracker,
                0,
            )?;
            let semantic_digest = certificate.id().into_bytes();
            budget
                .charge_timeout_certificate(&certificate)
                .map_err(|_| {
                    semantic_error(WireSemanticDecodeErrorCode::AggregateLimitExceeded, 0)
                })?;
            let work = tracker.total_work();
            Ok(WireEnvelopeSemanticProof {
                preflight,
                body_kind: WireSemanticBodyKindV0::TimeoutCertificate,
                body: WireSemanticBodyV0::TimeoutCertificate(certificate),
                semantic_digest,
                signer_count: entry_count,
                nested_qc_count: qc_count,
                aggregate_signature_shares: work,
            })
        }
        _ => Err(semantic_error(
            WireSemanticDecodeErrorCode::UnsupportedBodyKind,
            0,
        )),
    }
}

fn semantic_error(code: WireSemanticDecodeErrorCode, offset: usize) -> WireSemanticDecodeError {
    WireSemanticDecodeError::new(code, offset)
}

fn map_outer_error(error: WireEnvelopeDecodeError) -> WireSemanticDecodeError {
    let code = match error.code() {
        WireEnvelopeDecodeErrorCode::Empty => WireSemanticDecodeErrorCode::Empty,
        WireEnvelopeDecodeErrorCode::EnvelopeTooLarge
        | WireEnvelopeDecodeErrorCode::FieldTooLarge => WireSemanticDecodeErrorCode::NestedTooLarge,
        WireEnvelopeDecodeErrorCode::UnexpectedEof => WireSemanticDecodeErrorCode::UnexpectedEof,
        WireEnvelopeDecodeErrorCode::VarintOverflow => WireSemanticDecodeErrorCode::VarintOverflow,
        WireEnvelopeDecodeErrorCode::NonCanonicalVarint => {
            WireSemanticDecodeErrorCode::NonCanonicalVarint
        }
        WireEnvelopeDecodeErrorCode::InvalidFieldKey => {
            WireSemanticDecodeErrorCode::InvalidFieldKey
        }
        WireEnvelopeDecodeErrorCode::UnsupportedWireType => {
            WireSemanticDecodeErrorCode::UnsupportedWireType
        }
        WireEnvelopeDecodeErrorCode::UnknownField => WireSemanticDecodeErrorCode::UnknownField,
        WireEnvelopeDecodeErrorCode::DuplicateField => WireSemanticDecodeErrorCode::DuplicateField,
        WireEnvelopeDecodeErrorCode::FieldTypeMismatch => {
            WireSemanticDecodeErrorCode::FieldTypeMismatch
        }
        WireEnvelopeDecodeErrorCode::LengthOverflow => WireSemanticDecodeErrorCode::LengthOverflow,
        WireEnvelopeDecodeErrorCode::MissingField => WireSemanticDecodeErrorCode::MissingField,
        WireEnvelopeDecodeErrorCode::InvalidValue
        | WireEnvelopeDecodeErrorCode::InvalidChainId
        | WireEnvelopeDecodeErrorCode::InvalidBodyKind
        | WireEnvelopeDecodeErrorCode::InvalidConsensusMessageKind => {
            WireSemanticDecodeErrorCode::InvalidValue
        }
        WireEnvelopeDecodeErrorCode::BodyKindMismatch => {
            WireSemanticDecodeErrorCode::BodyKindMismatch
        }
    };
    semantic_error(code, error.byte_offset())
}

fn check_outer_scope(
    preflight: &WireEnvelopePreflight<'_>,
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
) -> core::result::Result<(), WireSemanticDecodeError> {
    if preflight.genesis_hash() != validator_set.genesis_hash().as_bytes()
        || preflight.chain_id() != validator_set.chain_id().as_bytes()
        || preflight.protocol_version() != validator_set.protocol_version().get()
        || preflight.epoch() != validator_set.epoch().get()
        || preflight.validator_set_hash() != validator_set.id().as_bytes()
        || preflight.consensus_parameters_hash() != parameters.hash().as_bytes()
    {
        return Err(semantic_error(
            WireSemanticDecodeErrorCode::ScopeMismatch,
            0,
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ParsedScope<'a> {
    schema_version: u32,
    genesis_hash: &'a [u8],
    chain_id: &'a [u8],
    protocol_version: u32,
    epoch: u64,
    validator_set_hash: &'a [u8],
    consensus_parameters_hash: &'a [u8],
}

#[derive(Clone, Copy)]
struct ParsedContext<'a> {
    scope: ParsedScope<'a>,
    view: u64,
    message_kind: u32,
}

fn check_scope(
    scope: ParsedScope<'_>,
    preflight: &WireEnvelopePreflight<'_>,
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
) -> core::result::Result<(), WireSemanticDecodeError> {
    if scope.schema_version != 0
        || scope.protocol_version != 0
        || scope.genesis_hash != validator_set.genesis_hash().as_bytes()
        || scope.chain_id != validator_set.chain_id().as_bytes()
        || scope.protocol_version != validator_set.protocol_version().get()
        || scope.epoch != validator_set.epoch().get()
        || scope.validator_set_hash != validator_set.id().as_bytes()
        || scope.consensus_parameters_hash != parameters.hash().as_bytes()
        || scope.genesis_hash != preflight.genesis_hash()
        || scope.chain_id != preflight.chain_id()
        || scope.epoch != preflight.epoch()
        || scope.validator_set_hash != preflight.validator_set_hash()
    {
        return Err(semantic_error(
            WireSemanticDecodeErrorCode::ScopeMismatch,
            0,
        ));
    }
    Ok(())
}

fn check_context(
    context: ParsedContext<'_>,
    preflight: &WireEnvelopePreflight<'_>,
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    expected_kind: u32,
) -> core::result::Result<(), WireSemanticDecodeError> {
    check_scope(context.scope, preflight, validator_set, parameters)?;
    if context.view != preflight.view() {
        return Err(semantic_error(
            WireSemanticDecodeErrorCode::ScopeMismatch,
            0,
        ));
    }
    if context.message_kind != expected_kind {
        return Err(semantic_error(
            WireSemanticDecodeErrorCode::MessageKindMismatch,
            0,
        ));
    }
    Ok(())
}

fn parse_vote(
    bytes: &[u8],
    preflight: &WireEnvelopePreflight<'_>,
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
) -> core::result::Result<Vote, WireSemanticDecodeError> {
    let mut cursor = ProtoCursor::new(bytes, 0)?;
    let mut fields = FieldState::new();
    let mut context = None;
    let mut height = None;
    let mut block_id = None;
    let mut author = None;
    let mut signature = None;
    while !cursor.done() {
        let (offset, field, wire_type) = cursor.field()?;
        fields.accept(field, false, 5, offset)?;
        match field {
            1 => context = Some(parse_common_context(cursor.nested(offset, wire_type)?, 1)?),
            2 => height = Some(cursor.scalar_u64(offset, wire_type)?),
            3 => block_id = Some(cursor.fixed32(offset, wire_type)?),
            4 => author = Some(cursor.bytes(offset, wire_type, MAX_VALIDATOR_ID_BYTES)?),
            5 => signature = Some(cursor.signature(offset, wire_type)?),
            _ => {
                return Err(semantic_error(
                    WireSemanticDecodeErrorCode::UnknownField,
                    offset,
                ))
            }
        }
    }
    fields.finish()?;
    let context = required(context, 1, cursor.offset())?;
    check_context(
        context,
        preflight,
        validator_set,
        parameters,
        u32::from(MessageKind::Vote as u8),
    )?;
    let height = Height::new(required(height, 2, cursor.offset())?);
    let block_id = BlockId::new(required(block_id, 3, cursor.offset())?);
    let author = ValidatorId::from_bytes(required(author, 4, cursor.offset())?)
        .map_err(|_| semantic_error(WireSemanticDecodeErrorCode::InvalidSigner, 0))?;
    let signature = SignatureBytes::from_array(required(signature, 5, cursor.offset())?);
    Vote::new(
        validator_set.chain_id(),
        validator_set.protocol_version(),
        validator_set.epoch(),
        View::new(context.view),
        height,
        block_id,
        validator_set.id(),
        author,
        signature,
        validator_set,
    )
    .map_err(|_| semantic_error(WireSemanticDecodeErrorCode::ValidationFailed, 0))
}

fn parse_timeout_vote(
    bytes: &[u8],
    preflight: &WireEnvelopePreflight<'_>,
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    expected_view: Option<u64>,
    depth: usize,
) -> core::result::Result<TimeoutVote, WireSemanticDecodeError> {
    let mut cursor = ProtoCursor::new(bytes, depth)?;
    let mut fields = FieldState::new();
    let mut context = None;
    let mut high_qc = None;
    let mut author = None;
    let mut signature = None;
    while !cursor.done() {
        let (offset, field, wire_type) = cursor.field()?;
        fields.accept(field, false, 4, offset)?;
        match field {
            1 => {
                context = Some(parse_common_context(
                    cursor.nested(offset, wire_type)?,
                    depth + 1,
                )?)
            }
            2 => {
                high_qc = Some(parse_high_qc_summary(
                    cursor.nested(offset, wire_type)?,
                    depth + 1,
                    validator_set.id(),
                )?)
            }
            3 => author = Some(cursor.bytes(offset, wire_type, MAX_VALIDATOR_ID_BYTES)?),
            4 => signature = Some(cursor.signature(offset, wire_type)?),
            _ => {
                return Err(semantic_error(
                    WireSemanticDecodeErrorCode::UnknownField,
                    offset,
                ))
            }
        }
    }
    fields.finish()?;
    let context = required(context, 1, cursor.offset())?;
    check_context(
        context,
        preflight,
        validator_set,
        parameters,
        u32::from(MessageKind::Timeout as u8),
    )?;
    if expected_view.is_some_and(|view| view != context.view) {
        return Err(semantic_error(
            WireSemanticDecodeErrorCode::ScopeMismatch,
            0,
        ));
    }
    let high_qc = required(high_qc, 2, cursor.offset())?;
    let author = ValidatorId::from_bytes(required(author, 3, cursor.offset())?)
        .map_err(|_| semantic_error(WireSemanticDecodeErrorCode::InvalidSigner, 0))?;
    let signature = SignatureBytes::from_array(required(signature, 4, cursor.offset())?);
    TimeoutVote::new(
        validator_set.chain_id(),
        validator_set.protocol_version(),
        validator_set.epoch(),
        View::new(context.view),
        validator_set.id(),
        high_qc,
        author,
        signature,
        validator_set,
    )
    .map_err(|_| semantic_error(WireSemanticDecodeErrorCode::ValidationFailed, 0))
}

fn parse_common_context(
    bytes: &[u8],
    depth: usize,
) -> core::result::Result<ParsedContext<'_>, WireSemanticDecodeError> {
    let mut cursor = ProtoCursor::new(bytes, depth)?;
    let mut fields = FieldState::new();
    let mut schema_version = None;
    let mut genesis_hash = None;
    let mut chain_id = None;
    let mut protocol_version = None;
    let mut epoch = None;
    let mut validator_set_hash = None;
    let mut view = None;
    let mut message_kind = None;
    let mut consensus_parameters_hash = None;
    while !cursor.done() {
        let (offset, field, wire_type) = cursor.field()?;
        fields.accept(field, false, 9, offset)?;
        match field {
            1 => schema_version = Some(cursor.scalar_u32(offset, wire_type)?),
            2 => genesis_hash = Some(cursor.bytes(offset, wire_type, 32)?),
            3 => chain_id = Some(cursor.bytes(offset, wire_type, MAX_CONSENSUS_STRING_BYTES)?),
            4 => protocol_version = Some(cursor.scalar_u32(offset, wire_type)?),
            5 => epoch = Some(cursor.scalar_u64(offset, wire_type)?),
            6 => validator_set_hash = Some(cursor.bytes(offset, wire_type, 32)?),
            7 => view = Some(cursor.scalar_u64(offset, wire_type)?),
            8 => message_kind = Some(cursor.scalar_u32(offset, wire_type)?),
            9 => consensus_parameters_hash = Some(cursor.bytes(offset, wire_type, 32)?),
            _ => {
                return Err(semantic_error(
                    WireSemanticDecodeErrorCode::UnknownField,
                    offset,
                ))
            }
        }
    }
    fields.finish()?;
    let scope = ParsedScope {
        schema_version: required(schema_version, 1, cursor.offset())?,
        genesis_hash: required(genesis_hash, 2, cursor.offset())?,
        chain_id: required(chain_id, 3, cursor.offset())?,
        protocol_version: required(protocol_version, 4, cursor.offset())?,
        epoch: required(epoch, 5, cursor.offset())?,
        validator_set_hash: required(validator_set_hash, 6, cursor.offset())?,
        consensus_parameters_hash: required(consensus_parameters_hash, 9, cursor.offset())?,
    };
    let message_kind = required(message_kind, 8, cursor.offset())?;
    if message_kind > 4 {
        return Err(semantic_error(WireSemanticDecodeErrorCode::InvalidValue, 0));
    }
    Ok(ParsedContext {
        scope,
        view: required(view, 7, cursor.offset())?,
        message_kind,
    })
}

fn parse_high_qc_summary(
    bytes: &[u8],
    depth: usize,
    validator_set_id: crate::ValidatorSetId,
) -> core::result::Result<QcRef, WireSemanticDecodeError> {
    let mut cursor = ProtoCursor::new(bytes, depth)?;
    let mut fields = FieldState::new();
    let mut digest = None;
    let mut epoch = None;
    let mut view = None;
    let mut height = None;
    let mut block_id = None;
    while !cursor.done() {
        let (offset, field, wire_type) = cursor.field()?;
        fields.accept(field, false, 5, offset)?;
        match field {
            1 => digest = Some(cursor.fixed32(offset, wire_type)?),
            2 => epoch = Some(cursor.scalar_u64(offset, wire_type)?),
            3 => view = Some(cursor.scalar_u64(offset, wire_type)?),
            4 => height = Some(cursor.scalar_u64(offset, wire_type)?),
            5 => block_id = Some(cursor.fixed32(offset, wire_type)?),
            _ => {
                return Err(semantic_error(
                    WireSemanticDecodeErrorCode::UnknownField,
                    offset,
                ))
            }
        }
    }
    fields.finish()?;
    Ok(QcRef::new(
        CertificateId::new(required(digest, 1, cursor.offset())?),
        Epoch::new(required(epoch, 2, cursor.offset())?),
        View::new(required(view, 3, cursor.offset())?),
        Height::new(required(height, 4, cursor.offset())?),
        BlockId::new(required(block_id, 5, cursor.offset())?),
        validator_set_id,
    ))
}

#[derive(Clone, Copy)]
struct SignatureShare<'a> {
    author: &'a [u8],
    signature: [u8; SIGNATURE_BYTES],
}

fn parse_signature_share(
    bytes: &[u8],
    depth: usize,
) -> core::result::Result<SignatureShare<'_>, WireSemanticDecodeError> {
    let mut cursor = ProtoCursor::new(bytes, depth)?;
    let mut fields = FieldState::new();
    let mut author = None;
    let mut signature = None;
    while !cursor.done() {
        let (offset, field, wire_type) = cursor.field()?;
        fields.accept(field, false, 2, offset)?;
        match field {
            1 => author = Some(cursor.bytes(offset, wire_type, MAX_VALIDATOR_ID_BYTES)?),
            2 => signature = Some(cursor.signature(offset, wire_type)?),
            _ => {
                return Err(semantic_error(
                    WireSemanticDecodeErrorCode::UnknownField,
                    offset,
                ))
            }
        }
    }
    fields.finish()?;
    let author = required(author, 1, cursor.offset())?;
    if author.is_empty() {
        return Err(semantic_error(
            WireSemanticDecodeErrorCode::InvalidSigner,
            0,
        ));
    }
    Ok(SignatureShare {
        author,
        signature: required(signature, 2, cursor.offset())?,
    })
}

struct AggregateTracker {
    maximum: usize,
    used: usize,
    work_maximum: usize,
    work_used: usize,
}

impl AggregateTracker {
    const fn new(maximum: usize, work_maximum: usize) -> Self {
        Self {
            maximum: if maximum > MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES {
                MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES
            } else {
                maximum
            },
            used: 0,
            work_maximum,
            work_used: 0,
        }
    }

    fn reserve(
        &mut self,
        additional: usize,
        offset: usize,
    ) -> core::result::Result<(), WireSemanticDecodeError> {
        let total = self.used.checked_add(additional).ok_or_else(|| {
            semantic_error(WireSemanticDecodeErrorCode::AggregateLimitExceeded, offset)
        })?;
        let work_total = self.work_used.checked_add(additional).ok_or_else(|| {
            semantic_error(WireSemanticDecodeErrorCode::AggregateLimitExceeded, offset)
        })?;
        if total > self.maximum {
            return Err(semantic_error(
                WireSemanticDecodeErrorCode::AggregateLimitExceeded,
                offset,
            ));
        }
        if work_total > self.work_maximum {
            return Err(semantic_error(
                WireSemanticDecodeErrorCode::AggregateLimitExceeded,
                offset,
            ));
        }
        self.used = total;
        self.work_used = work_total;
        Ok(())
    }

    fn reserve_entry(
        &mut self,
        offset: usize,
    ) -> core::result::Result<(), WireSemanticDecodeError> {
        let total = self.work_used.checked_add(1).ok_or_else(|| {
            semantic_error(WireSemanticDecodeErrorCode::AggregateLimitExceeded, offset)
        })?;
        if total > self.work_maximum {
            return Err(semantic_error(
                WireSemanticDecodeErrorCode::AggregateLimitExceeded,
                offset,
            ));
        }
        self.work_used = total;
        Ok(())
    }

    const fn total_work(&self) -> usize {
        self.work_used
    }
}

fn parse_qc(
    bytes: &[u8],
    preflight: &WireEnvelopePreflight<'_>,
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    tracker: &mut AggregateTracker,
    expected_view: Option<u64>,
    depth: usize,
) -> core::result::Result<(QuorumCertificate, usize), WireSemanticDecodeError> {
    let mut cursor = ProtoCursor::new(bytes, depth)?;
    let mut fields = FieldState::new();
    let mut schema_version = None;
    let mut genesis_hash = None;
    let mut chain_id = None;
    let mut protocol_version = None;
    let mut epoch = None;
    let mut validator_set_hash = None;
    let mut parameters_hash = None;
    let mut view = None;
    let mut height = None;
    let mut block_id = None;
    let mut digest = None;
    let mut shares: Vec<SignatureShare<'_>> = Vec::new();
    while !cursor.done() {
        let (offset, field, wire_type) = cursor.field()?;
        fields.accept(field, field == 11, 12, offset)?;
        match field {
            1 => schema_version = Some(cursor.scalar_u32(offset, wire_type)?),
            2 => genesis_hash = Some(cursor.bytes(offset, wire_type, 32)?),
            3 => chain_id = Some(cursor.bytes(offset, wire_type, MAX_CONSENSUS_STRING_BYTES)?),
            4 => protocol_version = Some(cursor.scalar_u32(offset, wire_type)?),
            5 => epoch = Some(cursor.scalar_u64(offset, wire_type)?),
            6 => validator_set_hash = Some(cursor.bytes(offset, wire_type, 32)?),
            7 => parameters_hash = Some(cursor.bytes(offset, wire_type, 32)?),
            8 => {
                let parsed_view = cursor.scalar_u64(offset, wire_type)?;
                // Field order puts the redundant view before the share list.
                // Reject a top-level routing mismatch before walking any
                // attacker-controlled nested signature-share payloads.
                if expected_view.is_some_and(|expected| parsed_view != expected) {
                    return Err(semantic_error(
                        WireSemanticDecodeErrorCode::ScopeMismatch,
                        offset,
                    ));
                }
                view = Some(parsed_view);
            }
            9 => height = Some(cursor.scalar_u64(offset, wire_type)?),
            10 => block_id = Some(cursor.fixed32(offset, wire_type)?),
            11 => {
                if shares.len() >= MAX_WIRE_NESTED_LIST_ITEMS_V0
                    || shares.len() >= validator_set.validators().len()
                {
                    return Err(semantic_error(
                        WireSemanticDecodeErrorCode::AggregateLimitExceeded,
                        offset,
                    ));
                }
                // Reserve before descending into the nested message.  A
                // hostile TC/QC therefore cannot spend parser work or create
                // a nested share allocation after its authenticated aggregate
                // ceiling has already been reached.
                tracker.reserve(1, offset)?;
                let share = parse_signature_share(cursor.nested(offset, wire_type)?, depth + 1)?;
                shares.push(share);
            }
            12 => digest = Some(cursor.fixed32(offset, wire_type)?),
            _ => {
                return Err(semantic_error(
                    WireSemanticDecodeErrorCode::UnknownField,
                    offset,
                ))
            }
        }
    }
    fields.finish()?;
    let scope = ParsedScope {
        schema_version: required(schema_version, 1, cursor.offset())?,
        genesis_hash: required(genesis_hash, 2, cursor.offset())?,
        chain_id: required(chain_id, 3, cursor.offset())?,
        protocol_version: required(protocol_version, 4, cursor.offset())?,
        epoch: required(epoch, 5, cursor.offset())?,
        validator_set_hash: required(validator_set_hash, 6, cursor.offset())?,
        consensus_parameters_hash: required(parameters_hash, 7, cursor.offset())?,
    };
    check_scope(scope, preflight, validator_set, parameters)?;
    let epoch = Epoch::new(scope.epoch);
    let view = View::new(required(view, 8, cursor.offset())?);
    // A top-level QC is routed by the envelope view.  A QC nested inside a
    // timeout certificate is a high-QC reference and may (and usually does)
    // certify an earlier view; in that context parse_tc supplies `None` and
    // the TC relation checks bind it to the timed-out view instead.
    if expected_view.is_some_and(|expected| view != View::new(expected)) {
        return Err(semantic_error(
            WireSemanticDecodeErrorCode::ScopeMismatch,
            0,
        ));
    }
    let height = Height::new(required(height, 9, cursor.offset())?);
    let block_id = BlockId::new(required(block_id, 10, cursor.offset())?);
    let mut votes = Vec::with_capacity(shares.len());
    for share in shares {
        let author = ValidatorId::from_bytes(share.author)
            .map_err(|_| semantic_error(WireSemanticDecodeErrorCode::InvalidSigner, 0))?;
        let signature = SignatureBytes::from_array(share.signature);
        votes.push(
            Vote::new(
                validator_set.chain_id(),
                validator_set.protocol_version(),
                epoch,
                view,
                height,
                block_id,
                validator_set.id(),
                author,
                signature,
                validator_set,
            )
            .map_err(|_| semantic_error(WireSemanticDecodeErrorCode::InvalidSigner, 0))?,
        );
    }
    let certificate = QuorumCertificate::new(
        validator_set.chain_id(),
        validator_set.protocol_version(),
        epoch,
        view,
        height,
        block_id,
        validator_set.id(),
        votes,
        validator_set,
    )
    .map_err(|_| semantic_error(WireSemanticDecodeErrorCode::InvalidQuorum, 0))?;
    let supplied_digest = required(digest, 12, cursor.offset())?;
    if supplied_digest != *certificate.id().as_bytes() {
        return Err(semantic_error(
            WireSemanticDecodeErrorCode::DigestMismatch,
            0,
        ));
    }
    let share_count = certificate.votes().len();
    Ok((certificate, share_count))
}

fn parse_tc(
    bytes: &[u8],
    preflight: &WireEnvelopePreflight<'_>,
    validator_set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    tracker: &mut AggregateTracker,
    depth: usize,
) -> core::result::Result<(TimeoutCertificateV0, usize, usize), WireSemanticDecodeError> {
    let mut cursor = ProtoCursor::new(bytes, depth)?;
    let mut fields = FieldState::new();
    let mut schema_version = None;
    let mut genesis_hash = None;
    let mut chain_id = None;
    let mut protocol_version = None;
    let mut epoch = None;
    let mut validator_set_hash = None;
    let mut parameters_hash = None;
    let mut timed_out_view = None;
    let mut entries: Vec<TimeoutVote> = Vec::new();
    let mut referenced_qcs: Vec<QuorumCertificate> = Vec::new();
    let mut selected_high_qc_digest = None;
    let mut tc_digest = None;
    while !cursor.done() {
        let (offset, field, wire_type) = cursor.field()?;
        fields.accept(field, field == 9 || field == 10, 13, offset)?;
        match field {
            1 => schema_version = Some(cursor.scalar_u32(offset, wire_type)?),
            2 => genesis_hash = Some(cursor.bytes(offset, wire_type, 32)?),
            3 => chain_id = Some(cursor.bytes(offset, wire_type, MAX_CONSENSUS_STRING_BYTES)?),
            4 => protocol_version = Some(cursor.scalar_u32(offset, wire_type)?),
            5 => epoch = Some(cursor.scalar_u64(offset, wire_type)?),
            6 => validator_set_hash = Some(cursor.bytes(offset, wire_type, 32)?),
            7 => parameters_hash = Some(cursor.bytes(offset, wire_type, 32)?),
            8 => {
                let parsed_view = cursor.scalar_u64(offset, wire_type)?;
                // The TC timeout view is the envelope's authenticated
                // routing scope and precedes all entry/QC payloads.  Bind it
                // before descending so a mismatched frame cannot buy parser
                // work with a large nested certificate list.
                if parsed_view != preflight.view() {
                    return Err(semantic_error(
                        WireSemanticDecodeErrorCode::ScopeMismatch,
                        offset,
                    ));
                }
                timed_out_view = Some(parsed_view);
            }
            9 => {
                if entries.len() >= MAX_WIRE_NESTED_LIST_ITEMS_V0
                    || entries.len() >= validator_set.validators().len()
                {
                    return Err(semantic_error(
                        WireSemanticDecodeErrorCode::AggregateLimitExceeded,
                        offset,
                    ));
                }
                // A timeout-entry signature is part of the same authenticated
                // work budget as nested QC shares.  Reserve it before
                // descending so a zero/tiny work budget cannot force parsing
                // an entire entry list before failing closed.
                tracker.reserve_entry(offset)?;
                let entry = parse_timeout_vote(
                    cursor.nested(offset, wire_type)?,
                    preflight,
                    validator_set,
                    parameters,
                    timed_out_view,
                    depth + 1,
                )?;
                entries.push(entry);
            }
            10 => {
                if referenced_qcs.len() >= MAX_WIRE_NESTED_LIST_ITEMS_V0
                    || referenced_qcs.len() >= validator_set.validators().len()
                {
                    return Err(semantic_error(
                        WireSemanticDecodeErrorCode::AggregateLimitExceeded,
                        offset,
                    ));
                }
                let (certificate, _) = parse_qc(
                    cursor.nested(offset, wire_type)?,
                    preflight,
                    validator_set,
                    parameters,
                    tracker,
                    None,
                    depth + 1,
                )?;
                referenced_qcs.push(certificate);
            }
            11 => selected_high_qc_digest = Some(cursor.fixed32(offset, wire_type)?),
            12 => tc_digest = Some(cursor.fixed32(offset, wire_type)?),
            // The sidecar is an epoch-anchor authorization and needs a
            // complete handoff adapter.  Never accept it as an opaque blob.
            13 => {
                return Err(semantic_error(
                    WireSemanticDecodeErrorCode::UnsupportedBodyKind,
                    offset,
                ))
            }
            _ => {
                return Err(semantic_error(
                    WireSemanticDecodeErrorCode::UnknownField,
                    offset,
                ))
            }
        }
    }
    fields.finish()?;
    let scope = ParsedScope {
        schema_version: required(schema_version, 1, cursor.offset())?,
        genesis_hash: required(genesis_hash, 2, cursor.offset())?,
        chain_id: required(chain_id, 3, cursor.offset())?,
        protocol_version: required(protocol_version, 4, cursor.offset())?,
        epoch: required(epoch, 5, cursor.offset())?,
        validator_set_hash: required(validator_set_hash, 6, cursor.offset())?,
        consensus_parameters_hash: required(parameters_hash, 7, cursor.offset())?,
    };
    check_scope(scope, preflight, validator_set, parameters)?;
    let timed_out_view = View::new(required(timed_out_view, 8, cursor.offset())?);
    if timed_out_view != View::new(preflight.view()) {
        return Err(semantic_error(
            WireSemanticDecodeErrorCode::ScopeMismatch,
            0,
        ));
    }
    if entries.is_empty() || referenced_qcs.is_empty() {
        return Err(semantic_error(
            WireSemanticDecodeErrorCode::InvalidQuorum,
            0,
        ));
    }
    let mut typed_entries = Vec::with_capacity(entries.len());
    for entry in &entries {
        if entry.epoch() != validator_set.epoch()
            || entry.view() != timed_out_view
            || entry.context().message_kind() != MessageKind::Timeout
        {
            return Err(semantic_error(
                WireSemanticDecodeErrorCode::ScopeMismatch,
                0,
            ));
        }
        typed_entries.push(
            TimeoutEntryV0::new(entry.author(), entry.high_qc(), *entry.signature())
                .map_err(|_| semantic_error(WireSemanticDecodeErrorCode::ValidationFailed, 0))?,
        );
    }
    let references = referenced_qcs
        .into_iter()
        .map(QcReferenceV0::ordinary)
        .collect();
    let selected = CertificateId::new(required(selected_high_qc_digest, 11, cursor.offset())?);
    let certificate = TimeoutCertificateV0::new(
        timed_out_view,
        typed_entries,
        references,
        selected,
        validator_set,
    )
    .map_err(|_| semantic_error(WireSemanticDecodeErrorCode::InvalidQuorum, 0))?;
    let supplied_digest = required(tc_digest, 12, cursor.offset())?;
    if supplied_digest != *certificate.id().as_bytes() {
        return Err(semantic_error(
            WireSemanticDecodeErrorCode::DigestMismatch,
            0,
        ));
    }
    let entry_count = entries.len();
    let qc_count = certificate.referenced_qcs().len();
    Ok((certificate, entry_count, qc_count))
}

fn required<T: Copy>(
    value: Option<T>,
    field: u32,
    offset: usize,
) -> core::result::Result<T, WireSemanticDecodeError> {
    value.ok_or_else(|| {
        semantic_error(
            WireSemanticDecodeErrorCode::MissingField,
            offset.max(field as usize),
        )
    })
}

struct FieldState {
    last: u32,
    seen: [bool; 64],
    count: usize,
}

impl FieldState {
    const fn new() -> Self {
        Self {
            last: 0,
            seen: [false; 64],
            count: 0,
        }
    }

    fn accept(
        &mut self,
        field: u32,
        repeated: bool,
        maximum: u32,
        offset: usize,
    ) -> core::result::Result<(), WireSemanticDecodeError> {
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| semantic_error(WireSemanticDecodeErrorCode::NestedTooLarge, offset))?;
        if self.count > MAX_WIRE_NESTED_FIELDS_V0 {
            return Err(semantic_error(
                WireSemanticDecodeErrorCode::NestedTooLarge,
                offset,
            ));
        }
        if field == 0 || field > maximum || field >= self.seen.len() as u32 {
            return Err(semantic_error(
                WireSemanticDecodeErrorCode::UnknownField,
                offset,
            ));
        }
        if field < self.last {
            return Err(semantic_error(
                WireSemanticDecodeErrorCode::NonCanonicalFieldOrder,
                offset,
            ));
        }
        if self.seen[field as usize] && (!repeated || field != self.last) {
            return Err(semantic_error(
                WireSemanticDecodeErrorCode::DuplicateField,
                offset,
            ));
        }
        self.seen[field as usize] = true;
        self.last = field;
        Ok(())
    }

    const fn finish(&self) -> core::result::Result<(), WireSemanticDecodeError> {
        Ok(())
    }
}

struct ProtoCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    depth: usize,
}

impl<'a> ProtoCursor<'a> {
    fn new(bytes: &'a [u8], depth: usize) -> core::result::Result<Self, WireSemanticDecodeError> {
        if bytes.is_empty() {
            return Err(semantic_error(WireSemanticDecodeErrorCode::Empty, 0));
        }
        if bytes.len() > crate::MAX_PROTOBUF_WIRE_BODY_BYTES_V0 {
            return Err(semantic_error(
                WireSemanticDecodeErrorCode::NestedTooLarge,
                0,
            ));
        }
        if depth > MAX_WIRE_NESTED_DEPTH_V0 {
            return Err(semantic_error(
                WireSemanticDecodeErrorCode::NestedDepthExceeded,
                0,
            ));
        }
        Ok(Self {
            bytes,
            offset: 0,
            depth,
        })
    }

    const fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }

    const fn offset(&self) -> usize {
        self.offset
    }

    fn field(&mut self) -> core::result::Result<(usize, u32, u8), WireSemanticDecodeError> {
        let offset = self.offset;
        let key = self.varint()?;
        let field = key >> 3;
        let wire_type = (key & 7) as u8;
        if field == 0 || field > 0x1fff {
            return Err(semantic_error(
                WireSemanticDecodeErrorCode::InvalidFieldKey,
                offset,
            ));
        }
        if !matches!(wire_type, 0 | 2) {
            return Err(semantic_error(
                WireSemanticDecodeErrorCode::UnsupportedWireType,
                offset,
            ));
        }
        Ok((offset, field as u32, wire_type))
    }

    fn varint(&mut self) -> core::result::Result<u64, WireSemanticDecodeError> {
        let start = self.offset;
        let mut value = 0u64;
        let mut index = 0u32;
        while index < 10 {
            let byte = *self
                .bytes
                .get(self.offset)
                .ok_or_else(|| semantic_error(WireSemanticDecodeErrorCode::UnexpectedEof, start))?;
            self.offset += 1;
            if index == 9 && byte > 1 {
                return Err(semantic_error(
                    WireSemanticDecodeErrorCode::VarintOverflow,
                    start,
                ));
            }
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                if varint_len(value) != self.offset - start {
                    return Err(semantic_error(
                        WireSemanticDecodeErrorCode::NonCanonicalVarint,
                        start,
                    ));
                }
                return Ok(value);
            }
            index += 1;
        }
        Err(semantic_error(
            WireSemanticDecodeErrorCode::VarintOverflow,
            start,
        ))
    }

    fn scalar_u32(
        &mut self,
        offset: usize,
        wire_type: u8,
    ) -> core::result::Result<u32, WireSemanticDecodeError> {
        self.expect_wire_type(offset, wire_type, 0)?;
        u32::try_from(self.varint()?)
            .map_err(|_| semantic_error(WireSemanticDecodeErrorCode::InvalidValue, offset))
    }

    fn scalar_u64(
        &mut self,
        offset: usize,
        wire_type: u8,
    ) -> core::result::Result<u64, WireSemanticDecodeError> {
        self.expect_wire_type(offset, wire_type, 0)?;
        self.varint()
    }

    fn bytes(
        &mut self,
        offset: usize,
        wire_type: u8,
        maximum: usize,
    ) -> core::result::Result<&'a [u8], WireSemanticDecodeError> {
        self.expect_wire_type(offset, wire_type, 2)?;
        let length = usize::try_from(self.varint()?)
            .map_err(|_| semantic_error(WireSemanticDecodeErrorCode::LengthOverflow, offset))?;
        if length > maximum || length > crate::MAX_PROTOBUF_WIRE_BODY_BYTES_V0 {
            return Err(semantic_error(
                WireSemanticDecodeErrorCode::FieldTooLarge,
                offset,
            ));
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| semantic_error(WireSemanticDecodeErrorCode::LengthOverflow, offset))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| semantic_error(WireSemanticDecodeErrorCode::UnexpectedEof, offset))?;
        self.offset = end;
        Ok(value)
    }

    fn nested(
        &mut self,
        offset: usize,
        wire_type: u8,
    ) -> core::result::Result<&'a [u8], WireSemanticDecodeError> {
        let value = self.bytes(offset, wire_type, crate::MAX_PROTOBUF_WIRE_BODY_BYTES_V0)?;
        if self.depth >= MAX_WIRE_NESTED_DEPTH_V0 {
            return Err(semantic_error(
                WireSemanticDecodeErrorCode::NestedDepthExceeded,
                offset,
            ));
        }
        Ok(value)
    }

    fn fixed32(
        &mut self,
        offset: usize,
        wire_type: u8,
    ) -> core::result::Result<[u8; 32], WireSemanticDecodeError> {
        let value = self.bytes(offset, wire_type, 32)?;
        value
            .try_into()
            .map_err(|_| semantic_error(WireSemanticDecodeErrorCode::InvalidValue, offset))
    }

    fn signature(
        &mut self,
        offset: usize,
        wire_type: u8,
    ) -> core::result::Result<[u8; SIGNATURE_BYTES], WireSemanticDecodeError> {
        let value = self.bytes(offset, wire_type, SIGNATURE_BYTES)?;
        value
            .try_into()
            .map_err(|_| semantic_error(WireSemanticDecodeErrorCode::InvalidSignature, offset))
    }

    fn expect_wire_type(
        &self,
        offset: usize,
        actual: u8,
        expected: u8,
    ) -> core::result::Result<(), WireSemanticDecodeError> {
        if actual == expected {
            Ok(())
        } else {
            Err(semantic_error(
                WireSemanticDecodeErrorCode::FieldTypeMismatch,
                offset,
            ))
        }
    }
}

const fn varint_len(value: u64) -> usize {
    if value < (1 << 7) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 21) {
        3
    } else if value < (1 << 28) {
        4
    } else if value < (1 << 35) {
        5
    } else if value < (1 << 42) {
        6
    } else if value < (1 << 49) {
        7
    } else if value < (1 << 56) {
        8
    } else if value < (1 << 63) {
        9
    } else {
        10
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChainId, ConsensusPublicKey, ProtocolVersion, Validator, VotingPower};
    use std::format;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::vec;
    use std::vec::Vec;

    /// Small hand-built protobuf fixtures intentionally live beside the
    /// parser.  They do not use a generated protobuf implementation, which
    /// keeps this test a genuinely independent check of field order, lengths,
    /// and oneof framing.
    struct Fixture {
        parameters: ConsensusParametersV0,
        validator_set: ValidatorSet,
        qc: QuorumCertificate,
        tc: TimeoutCertificateV0,
        vote_body: Vec<u8>,
        timeout_vote_body: Vec<u8>,
        qc_body: Vec<u8>,
        tc_body: Vec<u8>,
    }

    fn varint(mut value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            bytes.push(byte);
            if value == 0 {
                return bytes;
            }
        }
    }

    fn field_varint(field: u32, value: u64) -> Vec<u8> {
        let mut bytes = varint(u64::from(field << 3));
        bytes.extend(varint(value));
        bytes
    }

    fn field_bytes(field: u32, value: &[u8]) -> Vec<u8> {
        let mut bytes = varint(u64::from((field << 3) | 2));
        bytes.extend(varint(value.len() as u64));
        bytes.extend(value);
        bytes
    }

    fn append_field(target: &mut Vec<u8>, field: u32, value: &[u8]) {
        target.extend(field_bytes(field, value));
    }

    fn validator_id(byte: u8) -> ValidatorId {
        ValidatorId::new([byte; 32])
    }

    fn signature(byte: u8) -> SignatureBytes {
        SignatureBytes::from_array([byte; SIGNATURE_BYTES])
    }

    fn hex32(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        let bytes = value.as_bytes();
        let mut result = [0u8; 32];
        let mut index = 0;
        while index < 32 {
            result[index] = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
            index += 1;
        }
        result
    }

    fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid test hex"),
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        let bytes = value.as_bytes();
        let mut result = Vec::with_capacity(value.len() / 2);
        let mut index = 0;
        while index < bytes.len() {
            result.push((hex_nibble(bytes[index]) << 4) | hex_nibble(bytes[index + 1]));
            index += 2;
        }
        result
    }

    fn vector_frame(case_id: &str) -> Vec<u8> {
        let vector =
            include_str!("../../../../docs/protocol/poco-bft-v0/vectors/wire-semantic-v0.json");
        let marker = format!("\"id\": \"{case_id}\"");
        let case_start = vector.find(&marker).expect("semantic vector case");
        let case = &vector[case_start..];
        let key = "\"frame_hex\": \"";
        let value_start = case.find(key).expect("semantic vector frame") + key.len();
        let value = &case[value_start..];
        let value_end = value.find('"').expect("semantic vector frame end");
        decode_hex(&value[..value_end])
    }

    fn common_context(set: &ValidatorSet, view: u64, message_kind: MessageKind) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(field_varint(1, 0));
        append_field(&mut bytes, 2, set.genesis_hash().as_bytes());
        append_field(&mut bytes, 3, set.chain_id().as_bytes());
        bytes.extend(field_varint(4, 0));
        bytes.extend(field_varint(5, set.epoch().get()));
        append_field(&mut bytes, 6, set.id().as_bytes());
        bytes.extend(field_varint(7, view));
        bytes.extend(field_varint(8, message_kind as u64));
        append_field(&mut bytes, 9, set.consensus_parameters_hash().as_bytes());
        bytes
    }

    fn scope_prefix(set: &ValidatorSet) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(field_varint(1, 0));
        append_field(&mut bytes, 2, set.genesis_hash().as_bytes());
        append_field(&mut bytes, 3, set.chain_id().as_bytes());
        bytes.extend(field_varint(4, 0));
        bytes.extend(field_varint(5, set.epoch().get()));
        append_field(&mut bytes, 6, set.id().as_bytes());
        append_field(&mut bytes, 7, set.consensus_parameters_hash().as_bytes());
        bytes
    }

    fn high_qc_summary(reference: QcRef) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_field(&mut bytes, 1, reference.qc_digest().as_bytes());
        bytes.extend(field_varint(2, reference.epoch().get()));
        bytes.extend(field_varint(3, reference.view().get()));
        bytes.extend(field_varint(4, reference.height().get()));
        append_field(&mut bytes, 5, reference.block_id().as_bytes());
        bytes
    }

    fn encode_vote_body(
        set: &ValidatorSet,
        view: u64,
        height: u64,
        block_id: BlockId,
        author: ValidatorId,
        sig: SignatureBytes,
        context_kind: MessageKind,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_field(&mut bytes, 1, &common_context(set, view, context_kind));
        bytes.extend(field_varint(2, height));
        append_field(&mut bytes, 3, block_id.as_bytes());
        append_field(&mut bytes, 4, author.as_bytes());
        append_field(&mut bytes, 5, sig.as_bytes());
        bytes
    }

    fn encode_timeout_vote_body(
        set: &ValidatorSet,
        view: u64,
        reference: QcRef,
        author: ValidatorId,
        sig: SignatureBytes,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_field(
            &mut bytes,
            1,
            &common_context(set, view, MessageKind::Timeout),
        );
        append_field(&mut bytes, 2, &high_qc_summary(reference));
        append_field(&mut bytes, 3, author.as_bytes());
        append_field(&mut bytes, 4, sig.as_bytes());
        bytes
    }

    fn encode_signature_share(author: ValidatorId, sig: SignatureBytes) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_field(&mut bytes, 1, author.as_bytes());
        append_field(&mut bytes, 2, sig.as_bytes());
        bytes
    }

    fn encode_qc_body(set: &ValidatorSet, certificate: &QuorumCertificate) -> Vec<u8> {
        let mut bytes = scope_prefix(set);
        bytes.extend(field_varint(8, certificate.view().get()));
        bytes.extend(field_varint(9, certificate.height().get()));
        append_field(&mut bytes, 10, certificate.block_id().as_bytes());
        for vote in certificate.votes() {
            append_field(
                &mut bytes,
                11,
                &encode_signature_share(vote.author(), *vote.signature()),
            );
        }
        append_field(&mut bytes, 12, certificate.id().as_bytes());
        bytes
    }

    fn encode_timeout_certificate_body(
        set: &ValidatorSet,
        certificate: &TimeoutCertificateV0,
        timeout_votes: &[TimeoutVote],
        qcs: &[QuorumCertificate],
    ) -> Vec<u8> {
        let mut bytes = scope_prefix(set);
        bytes.extend(field_varint(8, certificate.timed_out_view().get()));
        for vote in timeout_votes {
            append_field(
                &mut bytes,
                9,
                &encode_timeout_vote_body(
                    set,
                    vote.view().get(),
                    vote.high_qc(),
                    vote.author(),
                    *vote.signature(),
                ),
            );
        }
        for qc in qcs {
            append_field(&mut bytes, 10, &encode_qc_body(set, qc));
        }
        append_field(
            &mut bytes,
            11,
            certificate.selected_high_qc_digest().as_bytes(),
        );
        append_field(&mut bytes, 12, certificate.id().as_bytes());
        bytes
    }

    fn envelope(
        set: &ValidatorSet,
        body_kind: WireBodyKindV0,
        view: u64,
        body: &[u8],
        message_kind: Option<MessageKind>,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(field_varint(1, 0));
        bytes.extend(field_varint(2, 0));
        append_field(&mut bytes, 3, set.genesis_hash().as_bytes());
        append_field(&mut bytes, 4, set.chain_id().as_bytes());
        bytes.extend(field_varint(5, 0));
        bytes.extend(field_varint(6, set.epoch().get()));
        bytes.extend(field_varint(7, view));
        append_field(&mut bytes, 8, set.id().as_bytes());
        append_field(&mut bytes, 9, set.consensus_parameters_hash().as_bytes());
        bytes.extend(field_varint(10, u64::from(message_kind.is_some())));
        if let Some(kind) = message_kind {
            bytes.extend(field_varint(11, kind as u64));
        }
        bytes.extend(field_varint(12, body_kind as u64));
        append_field(&mut bytes, 13, &[0x81; 32]);
        append_field(&mut bytes, 14, &[0x71; 16]);
        bytes.extend(field_varint(15, 0));
        let hash: [u8; 32] = Sha256::digest(body).into();
        append_field(&mut bytes, 16, &hash);
        append_field(&mut bytes, 31 + body_kind as u32, body);
        bytes
    }

    impl Fixture {
        fn new() -> Self {
            let parameters = ConsensusParametersV0::reference_shadow_v0();
            let genesis = crate::GenesisHash::new([0x99; 32]);
            let chain = ChainId::from_static("trnm-wire-semantic");
            let validators = (1u8..=4)
                .map(|id| {
                    Validator::new(
                        validator_id(id),
                        ConsensusPublicKey::new([0x10 + id; 32]),
                        VotingPower::new(1).expect("positive power"),
                    )
                    .expect("valid validator")
                })
                .collect();
            let validator_set = ValidatorSet::new(
                genesis,
                chain,
                ProtocolVersion::V0,
                Epoch::new(0),
                parameters.hash(),
                validators,
            )
            .expect("valid validator set");
            let block_id = BlockId::new([0x42; 32]);
            let votes = (1u8..=3)
                .map(|id| {
                    Vote::new(
                        chain,
                        ProtocolVersion::V0,
                        Epoch::new(0),
                        View::new(1),
                        Height::new(1),
                        block_id,
                        validator_set.id(),
                        validator_id(id),
                        signature(0xa0 + id),
                        &validator_set,
                    )
                    .expect("valid vote")
                })
                .collect();
            let qc = QuorumCertificate::new(
                chain,
                ProtocolVersion::V0,
                Epoch::new(0),
                View::new(1),
                Height::new(1),
                block_id,
                validator_set.id(),
                votes,
                &validator_set,
            )
            .expect("valid QC");
            let high_qc = QcRef::from(&qc);
            let timeout_votes: Vec<TimeoutVote> = (1u8..=3)
                .map(|id| {
                    TimeoutVote::new(
                        chain,
                        ProtocolVersion::V0,
                        Epoch::new(0),
                        View::new(2),
                        validator_set.id(),
                        high_qc,
                        validator_id(id),
                        signature(0xd0 + id),
                        &validator_set,
                    )
                    .expect("valid timeout vote")
                })
                .collect();
            let entries = timeout_votes
                .iter()
                .map(|vote| {
                    TimeoutEntryV0::new(vote.author(), vote.high_qc(), *vote.signature())
                        .expect("valid timeout entry")
                })
                .collect();
            let tc = TimeoutCertificateV0::new(
                View::new(2),
                entries,
                vec![QcReferenceV0::ordinary(qc.clone())],
                qc.id(),
                &validator_set,
            )
            .expect("valid TC");
            let vote_body = encode_vote_body(
                &validator_set,
                1,
                1,
                block_id,
                validator_id(1),
                signature(0xa1),
                MessageKind::Vote,
            );
            let timeout_vote_body = encode_timeout_vote_body(
                &validator_set,
                2,
                high_qc,
                validator_id(1),
                signature(0xd1),
            );
            let qc_body = encode_qc_body(&validator_set, &qc);
            let tc_body = encode_timeout_certificate_body(
                &validator_set,
                &tc,
                &timeout_votes,
                core::slice::from_ref(&qc),
            );
            // Independently generated by the standard-library reference
            // parser; these assertions bind both implementations to one
            // canonical fixture rather than merely testing self-round-trips.
            assert_eq!(
                *validator_set.id().as_bytes(),
                hex32("a1173b3a48a239b3d16b2e192f542b8890dc2d8fe632bf7e52638d4582f60167")
            );
            assert_eq!(
                qc.id().into_bytes(),
                hex32("9af99de60812fe276174fae4c6c3d5a7882e0b278b2e6bb20d61cf42a2a205ec")
            );
            assert_eq!(
                tc.id().into_bytes(),
                hex32("1d6abc3054693741bd016cecf21111dd427127d550841070908422c172e80e37")
            );
            Self {
                parameters,
                validator_set,
                qc,
                tc,
                vote_body,
                timeout_vote_body,
                qc_body,
                tc_body,
            }
        }

        fn budget(&self) -> Cev0AdmissionBudgetV0 {
            Cev0AdmissionBudgetV0::for_validator_set(&self.parameters, &self.validator_set)
        }
    }

    #[test]
    fn semantic_vote_round_trip_binds_outer_and_nested_scope() {
        let fixture = Fixture::new();
        let bytes = envelope(
            &fixture.validator_set,
            WireBodyKindV0::Vote,
            1,
            &fixture.vote_body,
            Some(MessageKind::Vote),
        );
        let mut budget = fixture.budget();
        let proof = decode_wire_envelope_v0_semantic(
            &bytes,
            &fixture.validator_set,
            &fixture.parameters,
            &mut budget,
        )
        .expect("semantic vote");
        assert_eq!(proof.body_kind(), WireSemanticBodyKindV0::Vote);
        assert_eq!(proof.signer_count(), 1);
        assert_eq!(proof.nested_qc_count(), 0);
        assert_eq!(proof.aggregate_signature_shares(), 1);
        assert_eq!(budget.signature_work(), 1);

        let mut wrong_outer = bytes.clone();
        let needle = field_bytes(4, fixture.validator_set.chain_id().as_bytes());
        let replacement = field_bytes(4, b"trnm-wire-semantic-x");
        let start = wrong_outer
            .windows(needle.len())
            .position(|window| window == needle.as_slice())
            .expect("outer chain field");
        wrong_outer.splice(start..start + needle.len(), replacement);
        let mut budget = fixture.budget();
        assert_eq!(
            decode_wire_envelope_v0_semantic(
                &wrong_outer,
                &fixture.validator_set,
                &fixture.parameters,
                &mut budget,
            )
            .unwrap_err()
            .code(),
            WireSemanticDecodeErrorCode::ScopeMismatch
        );

        let wrong_context = encode_vote_body(
            &fixture.validator_set,
            1,
            1,
            BlockId::new([0x42; 32]),
            validator_id(1),
            signature(0xa1),
            MessageKind::Timeout,
        );
        let wrong_context_envelope = envelope(
            &fixture.validator_set,
            WireBodyKindV0::Vote,
            1,
            &wrong_context,
            Some(MessageKind::Vote),
        );
        let mut budget = fixture.budget();
        assert_eq!(
            decode_wire_envelope_v0_semantic(
                &wrong_context_envelope,
                &fixture.validator_set,
                &fixture.parameters,
                &mut budget,
            )
            .unwrap_err()
            .code(),
            WireSemanticDecodeErrorCode::MessageKindMismatch
        );
    }

    #[test]
    fn semantic_qc_recomputes_digest_and_enforces_weighted_quorum() {
        let fixture = Fixture::new();
        let bytes = envelope(
            &fixture.validator_set,
            WireBodyKindV0::QuorumCertificate,
            1,
            &fixture.qc_body,
            None,
        );
        let mut budget = fixture.budget();
        let proof = decode_wire_envelope_v0_semantic(
            &bytes,
            &fixture.validator_set,
            &fixture.parameters,
            &mut budget,
        )
        .expect("semantic QC");
        assert_eq!(proof.body_kind(), WireSemanticBodyKindV0::QuorumCertificate);
        assert_eq!(proof.signer_count(), 3);
        assert_eq!(proof.semantic_digest(), fixture.qc.id().as_bytes());
        assert_eq!(budget.signature_work(), 3);

        // The outer routing view is redundant transport scope, not an
        // independent value.  A QC body carrying view 1 must not be wrapped
        // in an envelope claiming view 2.
        let mismatched_outer_view = envelope(
            &fixture.validator_set,
            WireBodyKindV0::QuorumCertificate,
            2,
            &fixture.qc_body,
            None,
        );
        let mut budget = fixture.budget();
        assert_eq!(
            decode_wire_envelope_v0_semantic(
                &mismatched_outer_view,
                &fixture.validator_set,
                &fixture.parameters,
                &mut budget,
            )
            .unwrap_err()
            .code(),
            WireSemanticDecodeErrorCode::ScopeMismatch
        );

        let mut bad_digest_body = fixture.qc_body.clone();
        let digest_field = field_bytes(12, fixture.qc.id().as_bytes());
        let replacement = field_bytes(12, &[0xee; 32]);
        let start = bad_digest_body
            .windows(digest_field.len())
            .position(|window| window == digest_field.as_slice())
            .expect("QC digest field");
        bad_digest_body.splice(start..start + digest_field.len(), replacement);
        let bad_digest = envelope(
            &fixture.validator_set,
            WireBodyKindV0::QuorumCertificate,
            1,
            &bad_digest_body,
            None,
        );
        let mut budget = fixture.budget();
        assert_eq!(
            decode_wire_envelope_v0_semantic(
                &bad_digest,
                &fixture.validator_set,
                &fixture.parameters,
                &mut budget,
            )
            .unwrap_err()
            .code(),
            WireSemanticDecodeErrorCode::DigestMismatch
        );

        let mut under_quorum_body = scope_prefix(&fixture.validator_set);
        under_quorum_body.extend(field_varint(8, 1));
        under_quorum_body.extend(field_varint(9, 1));
        append_field(&mut under_quorum_body, 10, &[0x42; 32]);
        for vote in fixture.qc.votes().iter().take(2) {
            append_field(
                &mut under_quorum_body,
                11,
                &encode_signature_share(vote.author(), *vote.signature()),
            );
        }
        append_field(&mut under_quorum_body, 12, &[0; 32]);
        let under_quorum = envelope(
            &fixture.validator_set,
            WireBodyKindV0::QuorumCertificate,
            1,
            &under_quorum_body,
            None,
        );
        let mut budget = fixture.budget();
        assert_eq!(
            decode_wire_envelope_v0_semantic(
                &under_quorum,
                &fixture.validator_set,
                &fixture.parameters,
                &mut budget,
            )
            .unwrap_err()
            .code(),
            WireSemanticDecodeErrorCode::InvalidQuorum
        );
    }

    #[test]
    fn semantic_timeout_vote_and_tc_validate_nested_relations_and_bounds() {
        let fixture = Fixture::new();
        let timeout_bytes = envelope(
            &fixture.validator_set,
            WireBodyKindV0::TimeoutVote,
            2,
            &fixture.timeout_vote_body,
            Some(MessageKind::Timeout),
        );
        let mut budget = fixture.budget();
        let timeout_proof = decode_wire_envelope_v0_semantic(
            &timeout_bytes,
            &fixture.validator_set,
            &fixture.parameters,
            &mut budget,
        )
        .expect("semantic timeout vote");
        assert_eq!(
            timeout_proof.body_kind(),
            WireSemanticBodyKindV0::TimeoutVote
        );

        let tc_bytes = envelope(
            &fixture.validator_set,
            WireBodyKindV0::TimeoutCertificate,
            2,
            &fixture.tc_body,
            None,
        );
        let mut budget = fixture.budget();
        let tc_proof = decode_wire_envelope_v0_semantic(
            &tc_bytes,
            &fixture.validator_set,
            &fixture.parameters,
            &mut budget,
        )
        .expect("semantic TC");
        assert_eq!(
            tc_proof.body_kind(),
            WireSemanticBodyKindV0::TimeoutCertificate
        );
        assert_eq!(tc_proof.signer_count(), 3);
        assert_eq!(tc_proof.nested_qc_count(), 1);
        assert_eq!(tc_proof.aggregate_signature_shares(), 6);
        assert_eq!(tc_proof.semantic_digest(), fixture.tc.id().as_bytes());
        assert_eq!(budget.signature_work(), 6);

        let mismatched_tc_view = envelope(
            &fixture.validator_set,
            WireBodyKindV0::TimeoutCertificate,
            1,
            &fixture.tc_body,
            None,
        );
        let mut budget = fixture.budget();
        assert_eq!(
            decode_wire_envelope_v0_semantic(
                &mismatched_tc_view,
                &fixture.validator_set,
                &fixture.parameters,
                &mut budget,
            )
            .unwrap_err()
            .code(),
            WireSemanticDecodeErrorCode::ScopeMismatch
        );

        let mut narrow = Cev0AdmissionBudgetV0::with_limits(usize::MAX, usize::MAX, 2);
        assert_eq!(
            decode_wire_envelope_v0_semantic(
                &tc_bytes,
                &fixture.validator_set,
                &fixture.parameters,
                &mut narrow,
            )
            .unwrap_err()
            .code(),
            WireSemanticDecodeErrorCode::AggregateLimitExceeded
        );

        // Signature-work is a separate authenticated limit from the nested
        // TC-share ceiling.  The decoder must apply it before descending into
        // a QC's share payload, rather than allocating/parsing a full QC and
        // only then discovering that the caller had no work budget left.
        let mut work_limited = Cev0AdmissionBudgetV0::with_limits(usize::MAX, 2, usize::MAX);
        assert_eq!(
            decode_wire_envelope_v0_semantic(
                &envelope(
                    &fixture.validator_set,
                    WireBodyKindV0::QuorumCertificate,
                    1,
                    &fixture.qc_body,
                    None,
                ),
                &fixture.validator_set,
                &fixture.parameters,
                &mut work_limited,
            )
            .unwrap_err()
            .code(),
            WireSemanticDecodeErrorCode::AggregateLimitExceeded
        );

        let mut tc_work_limited = Cev0AdmissionBudgetV0::with_limits(usize::MAX, 5, usize::MAX);
        assert_eq!(
            decode_wire_envelope_v0_semantic(
                &tc_bytes,
                &fixture.validator_set,
                &fixture.parameters,
                &mut tc_work_limited,
            )
            .unwrap_err()
            .code(),
            WireSemanticDecodeErrorCode::AggregateLimitExceeded
        );

        let vote_bytes = envelope(
            &fixture.validator_set,
            WireBodyKindV0::Vote,
            1,
            &fixture.vote_body,
            Some(MessageKind::Vote),
        );
        let mut root_limited = Cev0AdmissionBudgetV0::with_limits(1, usize::MAX, usize::MAX);
        assert_eq!(
            decode_wire_envelope_v0_semantic(
                &vote_bytes,
                &fixture.validator_set,
                &fixture.parameters,
                &mut root_limited,
            )
            .unwrap_err()
            .code(),
            WireSemanticDecodeErrorCode::NestedTooLarge
        );
    }

    #[test]
    fn semantic_nested_decoder_is_total_over_truncation_and_rejects_duplicates() {
        let fixture = Fixture::new();
        let frames = [
            envelope(
                &fixture.validator_set,
                WireBodyKindV0::Vote,
                1,
                &fixture.vote_body,
                Some(MessageKind::Vote),
            ),
            envelope(
                &fixture.validator_set,
                WireBodyKindV0::QuorumCertificate,
                1,
                &fixture.qc_body,
                None,
            ),
            envelope(
                &fixture.validator_set,
                WireBodyKindV0::TimeoutCertificate,
                2,
                &fixture.tc_body,
                None,
            ),
        ];
        for frame in &frames {
            for length in 0..=frame.len() {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let mut budget = fixture.budget();
                    let _ = decode_wire_envelope_v0_semantic(
                        &frame[..length],
                        &fixture.validator_set,
                        &fixture.parameters,
                        &mut budget,
                    );
                }));
                assert!(result.is_ok(), "panic at truncation length {length}");
            }
            // Bounded mutation corpus: signatures and transport metadata are
            // intentionally crypto-inert, so a few mutations may still be
            // structurally accepted; the invariant here is totality and no
            // out-of-budget allocation/panic for every byte position.
            for offset in 0..frame.len() {
                for mask in [0x01u8, 0x80, 0xff] {
                    let mut mutated = frame.clone();
                    mutated[offset] ^= mask;
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        let mut budget = fixture.budget();
                        let _ = decode_wire_envelope_v0_semantic(
                            &mutated,
                            &fixture.validator_set,
                            &fixture.parameters,
                            &mut budget,
                        );
                    }));
                    assert!(
                        result.is_ok(),
                        "panic at mutation offset {offset}, mask {mask:#x}"
                    );
                }
            }
        }

        let duplicate_context = {
            let mut context = common_context(&fixture.validator_set, 1, MessageKind::Vote);
            let view_field = field_varint(7, 1);
            let view_start = context
                .windows(view_field.len())
                .position(|window| window == view_field.as_slice())
                .expect("context view field");
            context.splice(
                view_start + view_field.len()..view_start + view_field.len(),
                view_field,
            );
            context
        };
        let mut duplicate_vote = Vec::new();
        append_field(&mut duplicate_vote, 1, &duplicate_context);
        duplicate_vote.extend(field_varint(2, 1));
        append_field(&mut duplicate_vote, 3, &[0x42; 32]);
        append_field(&mut duplicate_vote, 4, validator_id(1).as_bytes());
        append_field(&mut duplicate_vote, 5, signature(0xa1).as_bytes());
        let duplicate_frame = envelope(
            &fixture.validator_set,
            WireBodyKindV0::Vote,
            1,
            &duplicate_vote,
            Some(MessageKind::Vote),
        );
        let mut budget = fixture.budget();
        assert_eq!(
            decode_wire_envelope_v0_semantic(
                &duplicate_frame,
                &fixture.validator_set,
                &fixture.parameters,
                &mut budget,
            )
            .unwrap_err()
            .code(),
            WireSemanticDecodeErrorCode::DuplicateField
        );
    }

    #[test]
    fn rust_decoder_matches_complete_independent_wire_frames() {
        let fixture = Fixture::new();
        let cases = [
            (
                "vote",
                WireBodyKindV0::Vote,
                1,
                &fixture.vote_body,
                Some(MessageKind::Vote),
            ),
            (
                "timeout_vote",
                WireBodyKindV0::TimeoutVote,
                2,
                &fixture.timeout_vote_body,
                Some(MessageKind::Timeout),
            ),
            (
                "quorum_certificate",
                WireBodyKindV0::QuorumCertificate,
                1,
                &fixture.qc_body,
                None,
            ),
            (
                "timeout_certificate",
                WireBodyKindV0::TimeoutCertificate,
                2,
                &fixture.tc_body,
                None,
            ),
        ];
        for (case_id, kind, view, body, message_kind) in cases {
            let expected = envelope(&fixture.validator_set, kind, view, body, message_kind);
            assert_eq!(
                vector_frame(case_id),
                expected,
                "fixture drift for {case_id}"
            );
            let mut budget = fixture.budget();
            let proof = decode_wire_envelope_v0_semantic(
                &expected,
                &fixture.validator_set,
                &fixture.parameters,
                &mut budget,
            )
            .expect("independent frame must decode");
            assert_eq!(
                proof.body_kind(),
                match kind {
                    WireBodyKindV0::Vote => WireSemanticBodyKindV0::Vote,
                    WireBodyKindV0::TimeoutVote => WireSemanticBodyKindV0::TimeoutVote,
                    WireBodyKindV0::QuorumCertificate => WireSemanticBodyKindV0::QuorumCertificate,
                    WireBodyKindV0::TimeoutCertificate =>
                        WireSemanticBodyKindV0::TimeoutCertificate,
                    _ => unreachable!(),
                }
            );
        }
    }

    #[test]
    fn nested_cursor_rejects_noncanonical_varints_depth_and_field_bombs() {
        let noncanonical = [0x08, 0x81, 0x00];
        let noncanonical_error = match ProtoCursor::new(&noncanonical, 0) {
            Ok(mut cursor) => {
                let (offset, _field, wire_type) = cursor.field().expect("field key");
                cursor
                    .scalar_u64(offset, wire_type)
                    .expect_err("noncanonical varint")
            }
            Err(error) => error,
        };
        assert_eq!(
            noncanonical_error.code(),
            WireSemanticDecodeErrorCode::NonCanonicalVarint
        );
        let depth_error = match ProtoCursor::new(&[0x08, 0x01], MAX_WIRE_NESTED_DEPTH_V0 + 1) {
            Ok(_) => panic!("nested depth must reject"),
            Err(error) => error,
        };
        assert_eq!(
            depth_error.code(),
            WireSemanticDecodeErrorCode::NestedDepthExceeded
        );

        let mut bomb = Vec::new();
        for _ in 0..(MAX_WIRE_NESTED_FIELDS_V0 + 1) {
            bomb.extend(field_varint(1, 0));
        }
        let mut cursor = ProtoCursor::new(&bomb, 0).expect("bounded test input");
        let mut fields = FieldState::new();
        let mut last_error = None;
        while !cursor.done() {
            let (offset, field, wire_type) = cursor.field().expect("field key");
            if let Err(error) = fields.accept(field, true, 1, offset) {
                last_error = Some(error);
                break;
            }
            cursor
                .scalar_u64(offset, wire_type)
                .expect("repeated varint value");
        }
        assert_eq!(
            last_error.expect("field bomb must reject").code(),
            WireSemanticDecodeErrorCode::NestedTooLarge
        );
    }
}
