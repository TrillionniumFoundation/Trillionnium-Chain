//! Strict, allocation-free protobuf `WireEnvelope` ingress preflight.
//!
//! The frozen protobuf files are transport projections only; nested messages
//! still need their own exact CEV0 decoders and authenticated context.  This
//! module closes the narrow outer-envelope boundary: it bounds the complete
//! frame before any caller can allocate, rejects unknown/duplicate fields and
//! non-canonical varints, requires the envelope scope fields, and enforces
//! exactly one body whose tag agrees with `body_kind`.
//!
//! It deliberately returns borrowed byte slices rather than generated prost
//! values.  No semantic or cryptographic authority is released by a
//! successful preflight.  In particular this helper does not set
//! `wire_conformance`, activate networking, or decode a nested body.

use core::fmt;

use crate::{ChainId, MAX_CONSENSUS_STRING_BYTES};

/// Maximum decoded body bytes admitted by the reference v0 transport profile.
pub const MAX_PROTOBUF_WIRE_BODY_BYTES_V0: usize = 8 * 1024 * 1024;

/// Maximum complete `WireEnvelope` bytes.  The body limit excludes the small
/// bounded outer header, so the complete frame receives a separate ceiling.
pub const MAX_PROTOBUF_WIRE_ENVELOPE_BYTES_V0: usize = MAX_PROTOBUF_WIRE_BODY_BYTES_V0 + 1024;

/// Reference bound for the transport node identity.  This is intentionally a
/// candidate profile bound; authenticated P2P commissioning remains open.
pub const MAX_PROTOBUF_WIRE_SENDER_NODE_ID_BYTES_V0: usize = 32;

/// Reference bound for transport deduplication identifiers.
pub const MAX_PROTOBUF_WIRE_MESSAGE_ID_BYTES_V0: usize = 64;

const HASH_BYTES: usize = 32;

/// The oneof body discriminants frozen by `wire.proto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WireBodyKindV0 {
    Proposal = 1,
    Vote = 2,
    TimeoutVote = 3,
    QuorumCertificate = 4,
    TimeoutCertificate = 5,
    SyncInfo = 6,
    EquivocationEvidence = 7,
    HandoffVote = 8,
    JointHandoffCertificate = 9,
    ProtocolUpgradePlan = 10,
    NextEpochCommitment = 11,
    ValidatorSet = 12,
    ConsensusParameters = 13,
    LightClientProof = 14,
}

impl WireBodyKindV0 {
    const fn from_wire(value: u64) -> Option<Self> {
        Some(match value {
            1 => Self::Proposal,
            2 => Self::Vote,
            3 => Self::TimeoutVote,
            4 => Self::QuorumCertificate,
            5 => Self::TimeoutCertificate,
            6 => Self::SyncInfo,
            7 => Self::EquivocationEvidence,
            8 => Self::HandoffVote,
            9 => Self::JointHandoffCertificate,
            10 => Self::ProtocolUpgradePlan,
            11 => Self::NextEpochCommitment,
            12 => Self::ValidatorSet,
            13 => Self::ConsensusParameters,
            14 => Self::LightClientProof,
            _ => return None,
        })
    }

    const fn from_body_field(field: u32) -> Option<Self> {
        Self::from_wire((field - 31) as u64)
    }

    const fn body_field(self) -> u32 {
        31 + self as u32
    }
}

/// Stable machine-readable failures for the outer protobuf boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireEnvelopeDecodeErrorCode {
    Empty,
    EnvelopeTooLarge,
    UnexpectedEof,
    VarintOverflow,
    NonCanonicalVarint,
    InvalidFieldKey,
    UnsupportedWireType,
    UnknownField,
    DuplicateField,
    FieldTypeMismatch,
    LengthOverflow,
    FieldTooLarge,
    MissingField,
    InvalidValue,
    InvalidChainId,
    InvalidBodyKind,
    BodyKindMismatch,
    InvalidConsensusMessageKind,
}

impl WireEnvelopeDecodeErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::EnvelopeTooLarge => "envelope_too_large",
            Self::UnexpectedEof => "unexpected_eof",
            Self::VarintOverflow => "varint_overflow",
            Self::NonCanonicalVarint => "noncanonical_varint",
            Self::InvalidFieldKey => "invalid_field_key",
            Self::UnsupportedWireType => "unsupported_wire_type",
            Self::UnknownField => "unknown_field",
            Self::DuplicateField => "duplicate_field",
            Self::FieldTypeMismatch => "field_type_mismatch",
            Self::LengthOverflow => "length_overflow",
            Self::FieldTooLarge => "field_too_large",
            Self::MissingField => "missing_field",
            Self::InvalidValue => "invalid_value",
            Self::InvalidChainId => "invalid_chain_id",
            Self::InvalidBodyKind => "invalid_body_kind",
            Self::BodyKindMismatch => "body_kind_mismatch",
            Self::InvalidConsensusMessageKind => "invalid_consensus_message_kind",
        }
    }
}

/// A bounded outer-envelope failure at an exact input offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireEnvelopeDecodeError {
    code: WireEnvelopeDecodeErrorCode,
    byte_offset: usize,
}

impl WireEnvelopeDecodeError {
    const fn new(code: WireEnvelopeDecodeErrorCode, byte_offset: usize) -> Self {
        Self { code, byte_offset }
    }

    pub const fn code(self) -> WireEnvelopeDecodeErrorCode {
        self.code
    }

    pub const fn byte_offset(self) -> usize {
        self.byte_offset
    }
}

impl fmt::Display for WireEnvelopeDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "WireEnvelope preflight error {} at byte {}",
            self.code.as_str(),
            self.byte_offset
        )
    }
}

impl core::error::Error for WireEnvelopeDecodeError {}

/// Borrowed, shape-checked outer envelope.  The nested `body` bytes remain
/// opaque and must be passed to the body-specific exact decoder only after an
/// authenticated validator-set/parameter context is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireEnvelopePreflight<'a> {
    schema_version: u32,
    wire_version: u32,
    genesis_hash: &'a [u8],
    chain_id: &'a [u8],
    protocol_version: u32,
    epoch: u64,
    view: u64,
    validator_set_hash: &'a [u8],
    consensus_parameters_hash: &'a [u8],
    has_consensus_message_kind: bool,
    consensus_message_kind: Option<u32>,
    body_kind: WireBodyKindV0,
    sender_node_id: &'a [u8],
    message_id: &'a [u8],
    sender_sequence: u64,
    body_semantic_hash: Option<&'a [u8]>,
    body: &'a [u8],
}

impl<'a> WireEnvelopePreflight<'a> {
    pub const fn schema_version(self) -> u32 {
        self.schema_version
    }

    pub const fn wire_version(self) -> u32 {
        self.wire_version
    }

    pub const fn genesis_hash(self) -> &'a [u8] {
        self.genesis_hash
    }

    pub const fn chain_id(self) -> &'a [u8] {
        self.chain_id
    }

    pub const fn protocol_version(self) -> u32 {
        self.protocol_version
    }

    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    pub const fn view(self) -> u64 {
        self.view
    }

    pub const fn validator_set_hash(self) -> &'a [u8] {
        self.validator_set_hash
    }

    pub const fn consensus_parameters_hash(self) -> &'a [u8] {
        self.consensus_parameters_hash
    }

    pub const fn has_consensus_message_kind(self) -> bool {
        self.has_consensus_message_kind
    }

    pub const fn consensus_message_kind(self) -> Option<u32> {
        self.consensus_message_kind
    }

    pub const fn body_kind(self) -> WireBodyKindV0 {
        self.body_kind
    }

    pub const fn sender_node_id(self) -> &'a [u8] {
        self.sender_node_id
    }

    pub const fn message_id(self) -> &'a [u8] {
        self.message_id
    }

    pub const fn sender_sequence(self) -> u64 {
        self.sender_sequence
    }

    pub const fn body_semantic_hash(self) -> Option<&'a [u8]> {
        self.body_semantic_hash
    }

    pub const fn body(self) -> &'a [u8] {
        self.body
    }
}

/// Performs the bounded outer `WireEnvelope` preflight without allocating or
/// decoding any nested protobuf message.
pub fn decode_wire_envelope_v0_preflight(
    bytes: &[u8],
) -> Result<WireEnvelopePreflight<'_>, WireEnvelopeDecodeError> {
    if bytes.is_empty() {
        return Err(error(WireEnvelopeDecodeErrorCode::Empty, 0));
    }
    if bytes.len() > MAX_PROTOBUF_WIRE_ENVELOPE_BYTES_V0 {
        return Err(error(WireEnvelopeDecodeErrorCode::EnvelopeTooLarge, 0));
    }

    let mut cursor = Cursor::new(bytes);
    let mut seen = [false; 46];
    let mut schema_version = None;
    let mut wire_version = None;
    let mut genesis_hash = None;
    let mut chain_id = None;
    let mut protocol_version = None;
    let mut epoch = None;
    let mut view = None;
    let mut validator_set_hash = None;
    let mut consensus_parameters_hash = None;
    let mut has_consensus_message_kind = None;
    let mut consensus_message_kind = None;
    let mut body_kind = None;
    let mut sender_node_id = None;
    let mut message_id = None;
    let mut sender_sequence = None;
    let mut body_semantic_hash = None;
    let mut body = None;
    let mut body_field = None;

    while !cursor.done() {
        let field_offset = cursor.offset();
        let key = cursor.varint()?;
        let wire_type = (key & 0x07) as u8;
        let field = key >> 3;
        if field == 0 || field > 45 {
            return Err(error(
                WireEnvelopeDecodeErrorCode::UnknownField,
                field_offset,
            ));
        }
        if !matches!(wire_type, 0 | 2) {
            return Err(error(
                WireEnvelopeDecodeErrorCode::UnsupportedWireType,
                field_offset,
            ));
        }
        let field = field as usize;
        if seen[field] {
            return Err(error(
                WireEnvelopeDecodeErrorCode::DuplicateField,
                field_offset,
            ));
        }
        seen[field] = true;

        match field {
            1 => schema_version = Some(cursor.u32(field_offset, wire_type)?),
            2 => wire_version = Some(cursor.u32(field_offset, wire_type)?),
            3 => genesis_hash = Some(cursor.bytes(field_offset, wire_type, HASH_BYTES)?),
            4 => {
                chain_id =
                    Some(cursor.bytes(field_offset, wire_type, MAX_CONSENSUS_STRING_BYTES)?)
            }
            5 => protocol_version = Some(cursor.u32(field_offset, wire_type)?),
            6 => epoch = Some(cursor.u64(field_offset, wire_type)?),
            7 => view = Some(cursor.u64(field_offset, wire_type)?),
            8 => validator_set_hash = Some(cursor.bytes(field_offset, wire_type, HASH_BYTES)?),
            9 => {
                consensus_parameters_hash =
                    Some(cursor.bytes(field_offset, wire_type, HASH_BYTES)?)
            }
            10 => {
                let value = cursor.u64(field_offset, wire_type)?;
                if value > 1 {
                    return Err(error(
                        WireEnvelopeDecodeErrorCode::InvalidValue,
                        field_offset,
                    ));
                }
                has_consensus_message_kind = Some(value == 1);
            }
            11 => {
                let value = cursor.u64(field_offset, wire_type)?;
                if value > 4 {
                    return Err(error(
                        WireEnvelopeDecodeErrorCode::InvalidConsensusMessageKind,
                        field_offset,
                    ));
                }
                consensus_message_kind = Some(value as u32);
            }
            12 => {
                let value = cursor.u64(field_offset, wire_type)?;
                body_kind = Some(WireBodyKindV0::from_wire(value).ok_or_else(|| {
                    error(WireEnvelopeDecodeErrorCode::InvalidBodyKind, field_offset)
                })?);
            }
            13 => {
                sender_node_id = Some(cursor.bytes(
                    field_offset,
                    wire_type,
                    MAX_PROTOBUF_WIRE_SENDER_NODE_ID_BYTES_V0,
                )?)
            }
            14 => {
                message_id = Some(cursor.bytes(
                    field_offset,
                    wire_type,
                    MAX_PROTOBUF_WIRE_MESSAGE_ID_BYTES_V0,
                )?)
            }
            15 => sender_sequence = Some(cursor.u64(field_offset, wire_type)?),
            16 => body_semantic_hash = Some(cursor.bytes(field_offset, wire_type, HASH_BYTES)?),
            32..=45 => {
                let kind = WireBodyKindV0::from_body_field(field as u32).ok_or_else(|| {
                    error(WireEnvelopeDecodeErrorCode::InvalidBodyKind, field_offset)
                })?;
                if body.is_some() {
                    return Err(error(
                        WireEnvelopeDecodeErrorCode::DuplicateField,
                        field_offset,
                    ));
                }
                body =
                    Some(cursor.bytes(field_offset, wire_type, MAX_PROTOBUF_WIRE_BODY_BYTES_V0)?);
                body_field = Some(kind);
            }
            _ => {
                return Err(error(
                    WireEnvelopeDecodeErrorCode::UnknownField,
                    field_offset,
                ))
            }
        }
    }

    let schema_version = required(schema_version, 1, bytes.len())?;
    if schema_version != 0 {
        return Err(error(WireEnvelopeDecodeErrorCode::InvalidValue, 0));
    }
    let wire_version = required(wire_version, 2, bytes.len())?;
    if wire_version != 0 {
        return Err(error(WireEnvelopeDecodeErrorCode::InvalidValue, 0));
    }
    let genesis_hash = required(genesis_hash, 3, bytes.len())?;
    if genesis_hash.len() != HASH_BYTES || genesis_hash.iter().all(|byte| *byte == 0) {
        return Err(error(WireEnvelopeDecodeErrorCode::InvalidValue, 0));
    }
    let chain_id = required(chain_id, 4, bytes.len())?;
    if ChainId::from_bytes(chain_id).is_err() {
        return Err(error(WireEnvelopeDecodeErrorCode::InvalidChainId, 0));
    }
    let protocol_version = required(protocol_version, 5, bytes.len())?;
    if protocol_version != 0 {
        return Err(error(WireEnvelopeDecodeErrorCode::InvalidValue, 0));
    }
    let epoch = required(epoch, 6, bytes.len())?;
    let view = required(view, 7, bytes.len())?;
    let validator_set_hash = required(validator_set_hash, 8, bytes.len())?;
    if validator_set_hash.iter().all(|byte| *byte == 0) {
        return Err(error(WireEnvelopeDecodeErrorCode::InvalidValue, 0));
    }
    let consensus_parameters_hash = required(consensus_parameters_hash, 9, bytes.len())?;
    if consensus_parameters_hash.iter().all(|byte| *byte == 0) {
        return Err(error(WireEnvelopeDecodeErrorCode::InvalidValue, 0));
    }
    let has_consensus_message_kind = required(has_consensus_message_kind, 10, bytes.len())?;
    let consensus_message_kind = if has_consensus_message_kind {
        Some(required(consensus_message_kind, 11, bytes.len())?)
    } else {
        if consensus_message_kind.is_some() {
            return Err(error(
                WireEnvelopeDecodeErrorCode::InvalidConsensusMessageKind,
                0,
            ));
        }
        None
    };
    let body_kind = required(body_kind, 12, bytes.len())?;
    let body_field = required(body_field, 32, bytes.len())?;
    if body_kind != body_field {
        return Err(error(WireEnvelopeDecodeErrorCode::BodyKindMismatch, 0));
    }
    let sender_node_id = required(sender_node_id, 13, bytes.len())?;
    let message_id = required(message_id, 14, bytes.len())?;
    let sender_sequence = required(sender_sequence, 15, bytes.len())?;
    let body = required(body, body_field.body_field(), bytes.len())?;

    if sender_node_id.len() != MAX_PROTOBUF_WIRE_SENDER_NODE_ID_BYTES_V0
        || sender_node_id.iter().all(|byte| *byte == 0)
        || message_id.is_empty()
    {
        return Err(error(WireEnvelopeDecodeErrorCode::InvalidValue, 0));
    }
    if let Some(hash) = body_semantic_hash {
        if hash.len() != HASH_BYTES {
            return Err(error(WireEnvelopeDecodeErrorCode::InvalidValue, 0));
        }
    }
    if body.is_empty() {
        return Err(error(WireEnvelopeDecodeErrorCode::InvalidValue, 0));
    }

    match (body_kind, consensus_message_kind) {
        (WireBodyKindV0::Proposal, Some(0))
        | (WireBodyKindV0::Vote, Some(1))
        | (WireBodyKindV0::TimeoutVote, Some(2)) => {}
        (WireBodyKindV0::HandoffVote, Some(3 | 4)) => {}
        (WireBodyKindV0::Proposal, _)
        | (WireBodyKindV0::Vote, _)
        | (WireBodyKindV0::TimeoutVote, _)
        | (WireBodyKindV0::HandoffVote, _) => {
            return Err(error(
                WireEnvelopeDecodeErrorCode::InvalidConsensusMessageKind,
                0,
            ))
        }
        (_, None) => {}
        (_, Some(_)) => {
            return Err(error(
                WireEnvelopeDecodeErrorCode::InvalidConsensusMessageKind,
                0,
            ))
        }
    }

    Ok(WireEnvelopePreflight {
        schema_version,
        wire_version,
        genesis_hash,
        chain_id,
        protocol_version,
        epoch,
        view,
        validator_set_hash,
        consensus_parameters_hash,
        has_consensus_message_kind,
        consensus_message_kind,
        body_kind,
        sender_node_id,
        message_id,
        sender_sequence,
        body_semantic_hash,
        body,
    })
}

const fn error(code: WireEnvelopeDecodeErrorCode, offset: usize) -> WireEnvelopeDecodeError {
    WireEnvelopeDecodeError::new(code, offset)
}

fn required<T: Copy>(
    value: Option<T>,
    field: u32,
    offset: usize,
) -> Result<T, WireEnvelopeDecodeError> {
    value.ok_or_else(|| {
        error(
            WireEnvelopeDecodeErrorCode::MissingField,
            offset.max(field as usize),
        )
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }

    const fn offset(&self) -> usize {
        self.offset
    }

    fn varint(&mut self) -> Result<u64, WireEnvelopeDecodeError> {
        let start = self.offset;
        let mut value = 0u64;
        let mut index = 0u32;
        while index < 10 {
            let byte = *self
                .bytes
                .get(self.offset)
                .ok_or_else(|| error(WireEnvelopeDecodeErrorCode::UnexpectedEof, start))?;
            self.offset += 1;
            if index == 9 && byte > 1 {
                return Err(error(WireEnvelopeDecodeErrorCode::VarintOverflow, start));
            }
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                if varint_len(value) != self.offset - start {
                    return Err(error(
                        WireEnvelopeDecodeErrorCode::NonCanonicalVarint,
                        start,
                    ));
                }
                return Ok(value);
            }
            index += 1;
        }
        Err(error(WireEnvelopeDecodeErrorCode::VarintOverflow, start))
    }

    fn u32(&mut self, field_offset: usize, wire_type: u8) -> Result<u32, WireEnvelopeDecodeError> {
        expect_wire_type(wire_type, 0, field_offset)?;
        let value = self.varint()?;
        u32::try_from(value)
            .map_err(|_| error(WireEnvelopeDecodeErrorCode::InvalidValue, field_offset))
    }

    fn u64(&mut self, field_offset: usize, wire_type: u8) -> Result<u64, WireEnvelopeDecodeError> {
        expect_wire_type(wire_type, 0, field_offset)?;
        self.varint()
    }

    fn bytes(
        &mut self,
        field_offset: usize,
        wire_type: u8,
        maximum: usize,
    ) -> Result<&'a [u8], WireEnvelopeDecodeError> {
        expect_wire_type(wire_type, 2, field_offset)?;
        let length = self.varint()?;
        let length = usize::try_from(length)
            .map_err(|_| error(WireEnvelopeDecodeErrorCode::LengthOverflow, field_offset))?;
        if length > maximum {
            return Err(error(
                WireEnvelopeDecodeErrorCode::FieldTooLarge,
                field_offset,
            ));
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| error(WireEnvelopeDecodeErrorCode::LengthOverflow, field_offset))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| error(WireEnvelopeDecodeErrorCode::UnexpectedEof, field_offset))?;
        self.offset = end;
        Ok(value)
    }
}

const fn expect_wire_type(
    actual: u8,
    expected: u8,
    offset: usize,
) -> Result<(), WireEnvelopeDecodeError> {
    if actual == expected {
        Ok(())
    } else {
        Err(error(
            WireEnvelopeDecodeErrorCode::FieldTypeMismatch,
            offset,
        ))
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
    use std::vec::Vec;

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                return out;
            }
        }
    }

    fn field_varint(field: u32, value: u64) -> Vec<u8> {
        let mut out = varint(u64::from(field << 3));
        out.extend(varint(value));
        out
    }

    fn field_bytes(field: u32, value: &[u8]) -> Vec<u8> {
        let mut out = varint(u64::from((field << 3) | 2));
        out.extend(varint(value.len() as u64));
        out.extend(value);
        out
    }

    fn valid_envelope() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(field_varint(1, 0));
        out.extend(field_varint(2, 0));
        out.extend(field_bytes(3, &[1; 32]));
        out.extend(field_bytes(4, b"trnm-wire-test"));
        out.extend(field_varint(5, 0));
        out.extend(field_varint(6, 0));
        out.extend(field_varint(7, 0));
        out.extend(field_bytes(8, &[2; 32]));
        out.extend(field_bytes(9, &[3; 32]));
        out.extend(field_varint(10, 1));
        out.extend(field_varint(11, 0));
        out.extend(field_varint(12, 1));
        out.extend(field_bytes(13, &[4; 32]));
        out.extend(field_bytes(14, &[5; 16]));
        out.extend(field_varint(15, 0));
        out.extend(field_bytes(32, &[0xaa, 0xbb]));
        out
    }

    #[test]
    fn preflight_binds_scope_and_oneof_without_allocating_body() {
        let bytes = valid_envelope();
        let value = decode_wire_envelope_v0_preflight(&bytes).expect("valid envelope");
        assert_eq!(value.body_kind(), WireBodyKindV0::Proposal);
        assert_eq!(value.body(), &[0xaa, 0xbb]);
        assert_eq!(value.chain_id(), b"trnm-wire-test");
        assert_eq!(value.consensus_message_kind(), Some(0));
    }

    #[test]
    fn preflight_rejects_unknown_duplicate_and_mismatched_body() {
        let mut unknown = valid_envelope();
        unknown.extend(field_varint(17, 1));
        assert_eq!(
            decode_wire_envelope_v0_preflight(&unknown)
                .unwrap_err()
                .code(),
            WireEnvelopeDecodeErrorCode::UnknownField
        );

        let mut duplicate = valid_envelope();
        duplicate.extend(field_varint(15, 1));
        assert_eq!(
            decode_wire_envelope_v0_preflight(&duplicate)
                .unwrap_err()
                .code(),
            WireEnvelopeDecodeErrorCode::DuplicateField
        );

        let mut mismatch = valid_envelope();
        let body_kind = field_varint(12, 2);
        // Replace the one-byte body-kind field (0x60, 0x01) in this fixture.
        let position = mismatch
            .windows(body_kind.len())
            .position(|window| window == field_varint(12, 1).as_slice())
            .expect("body kind");
        mismatch.splice(position..position + 2, body_kind);
        assert_eq!(
            decode_wire_envelope_v0_preflight(&mismatch)
                .unwrap_err()
                .code(),
            WireEnvelopeDecodeErrorCode::BodyKindMismatch
        );
    }

    #[test]
    fn preflight_rejects_noncanonical_varints_and_oversized_nested_body_before_slice() {
        let mut noncanonical = valid_envelope();
        noncanonical.splice(0..2, [0x88, 0x80, 0x00, 0x00]);
        assert_eq!(
            decode_wire_envelope_v0_preflight(&noncanonical)
                .unwrap_err()
                .code(),
            WireEnvelopeDecodeErrorCode::NonCanonicalVarint
        );

        let mut oversized = valid_envelope();
        let body_start = oversized
            .windows(2)
            .position(|window| window == [0x82, 0x02])
            .expect("body field")
            + 2;
        oversized.splice(
            body_start..body_start + 1,
            varint((MAX_PROTOBUF_WIRE_BODY_BYTES_V0 + 1) as u64),
        );
        assert_eq!(
            decode_wire_envelope_v0_preflight(&oversized)
                .unwrap_err()
                .code(),
            WireEnvelopeDecodeErrorCode::FieldTooLarge
        );
    }

    #[test]
    fn preflight_requires_message_kind_only_for_consensus_statements() {
        let mut value = valid_envelope();
        let old = field_varint(10, 1);
        let position = value
            .windows(old.len())
            .position(|window| window == old.as_slice())
            .expect("has kind");
        value.splice(position..position + old.len(), field_varint(10, 0));
        assert_eq!(
            decode_wire_envelope_v0_preflight(&value)
                .unwrap_err()
                .code(),
            WireEnvelopeDecodeErrorCode::InvalidConsensusMessageKind
        );

        let mut non_consensus = valid_envelope();
        let old_body_kind = field_varint(12, 1);
        let position = non_consensus
            .windows(old_body_kind.len())
            .position(|window| window == old_body_kind.as_slice())
            .expect("body kind");
        non_consensus.splice(
            position..position + old_body_kind.len(),
            field_varint(12, 6),
        );
        let old_has_kind = field_varint(10, 1);
        let position = non_consensus
            .windows(old_has_kind.len())
            .position(|window| window == old_has_kind.as_slice())
            .expect("has kind");
        non_consensus.splice(position..position + old_has_kind.len(), field_varint(10, 0));
        let old_message_kind = field_varint(11, 0);
        let position = non_consensus
            .windows(old_message_kind.len())
            .position(|window| window == old_message_kind.as_slice())
            .expect("message kind");
        non_consensus.splice(position..position + old_message_kind.len(), []);
        // The body tag still names Proposal; alter it to SyncInfo too.
        let old_body_tag = field_bytes(32, &[0xaa, 0xbb]);
        let position = non_consensus
            .windows(old_body_tag.len())
            .position(|window| window == old_body_tag.as_slice())
            .expect("body tag");
        non_consensus.splice(
            position..position + old_body_tag.len(),
            field_bytes(37, &[0xaa, 0xbb]),
        );
        let decoded = decode_wire_envelope_v0_preflight(&non_consensus)
            .expect("non-consensus body may omit message kind");
        assert_eq!(decoded.body_kind(), WireBodyKindV0::SyncInfo);
        assert!(!decoded.has_consensus_message_kind());
    }

    #[test]
    fn preflight_rejects_present_but_empty_oneof_body() {
        let mut bytes = valid_envelope();
        let body = field_bytes(32, &[0xaa, 0xbb]);
        let position = bytes
            .windows(body.len())
            .position(|window| window == body.as_slice())
            .expect("body");
        bytes.splice(position..position + body.len(), field_bytes(32, &[]));
        assert_eq!(
            decode_wire_envelope_v0_preflight(&bytes)
                .unwrap_err()
                .code(),
            WireEnvelopeDecodeErrorCode::InvalidValue
        );
    }
}
