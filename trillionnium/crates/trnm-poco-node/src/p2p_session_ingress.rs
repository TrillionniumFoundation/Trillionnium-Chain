//! Candidate-only authenticated PoCO transport session ingress.
//!
//! The frozen `WireEnvelope` is an authenticated consensus payload, but its
//! `sender_node_id` and `sender_sequence` fields are not, by themselves, a
//! peer session.  This module adds the smallest useful node-owned boundary:
//! an exact bounded handshake, a strict field-framed data record, a
//! domain-separated Ed25519 signature over each record, and a 64-entry
//! replay window.  A successfully accepted record is then passed through the
//! nested semantic decoder for the adapted Vote/TimeoutVote/QC/TC bodies.
//!
//! This is deliberately a candidate composition seam.  It owns no socket,
//! lease, validator-set update, broadcast, Core input, or production flag.
//! The consensus validator key is used as the peer identity key in this
//! tranche; a separately administered transport-key profile must replace
//! that choice before network activation.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_wire_envelope_v0_preflight, decode_wire_envelope_v0_semantic, Cev0AdmissionBudgetV0,
    ConsensusParametersV0, SignatureBytes, SignatureVerifier, SigningRoot, ValidatorId,
    ValidatorSet, WireBodyKindV0, WireEnvelopeDecodeError, WireEnvelopeSemanticProof,
    WireSemanticDecodeError, MAX_CONSENSUS_STRING_BYTES, MAX_PROTOBUF_WIRE_ENVELOPE_BYTES_V0,
    MAX_PROTOBUF_WIRE_SENDER_NODE_ID_BYTES_V0, SIGNATURE_BYTES,
};

/// Candidate-only status constants.  Neither constant is a production
/// activation decision; they are intentionally false/true facts about this
/// isolated module's composition boundary.
pub const P2P_SESSION_INGRESS_RUNTIME_COMPOSITION_V0: bool = true;
pub const P2P_SESSION_INGRESS_PRODUCTION_ACTIVATION_V0: bool = false;

/// Maximum handshake record size, including its four-byte magic prefix.
pub const P2P_SESSION_MAX_HANDSHAKE_BYTES_V0: usize = 1024;

/// The payload is itself a bounded `WireEnvelope`.
pub const P2P_SESSION_MAX_PAYLOAD_BYTES_V0: usize = MAX_PROTOBUF_WIRE_ENVELOPE_BYTES_V0;

/// Maximum complete data record size.  The fixed framing overhead is kept
/// separate from the nested protobuf ceiling so a length declaration cannot
/// widen the payload bound.
pub const P2P_SESSION_MAX_FRAME_BYTES_V0: usize = P2P_SESSION_MAX_PAYLOAD_BYTES_V0 + 256;

/// Number of sequence positions retained by the anti-replay bitmap.
pub const P2P_SESSION_REPLAY_WINDOW_V0: u64 = 64;

const HANDSHAKE_MAGIC: &[u8; 4] = b"TRNH";
const FRAME_MAGIC: &[u8; 4] = b"TRNF";
const PROTOCOL_VERSION_V0: u16 = 0;
const HANDSHAKE_MAX_TAG_V0: u8 = 9;
const FRAME_MAX_TAG_V0: u8 = 5;
const HANDSHAKE_FIELD_COUNT_V0: usize = 9;
const FRAME_FIELD_COUNT_V0: usize = 5;
const TLV_HEADER_BYTES_V0: usize = 5;
const HASH_BYTES_V0: usize = 32;
const DOMAIN_HANDSHAKE_V0: &[u8] = b"trnm.poco.p2p.handshake.v0\0";
const DOMAIN_SESSION_ID_V0: &[u8] = b"trnm.poco.p2p.session-id.v0\0";
const DOMAIN_FRAME_V0: &[u8] = b"trnm.poco.p2p.frame.v0\0";

/// Stable machine-readable errors for both handshake and data ingress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P2pSessionIngressErrorCodeV0 {
    Empty,
    BadMagic,
    HandshakeTooLarge,
    FrameTooLarge,
    UnexpectedEof,
    TrailingBytes,
    UnknownField,
    DuplicateField,
    NonCanonicalFieldOrder,
    FieldTooLarge,
    InvalidFieldLength,
    InvalidValue,
    ContextMismatch,
    UnknownPeer,
    PeerKeyMismatch,
    InvalidHandshakeSignature,
    InvalidFrameSignature,
    SessionMismatch,
    PeerIdentityMismatch,
    SequenceBindingMismatch,
    SequenceReplay,
    SequenceTooOld,
    UnsupportedBodyKind,
    WirePreflight,
    SemanticDecode,
}

impl P2pSessionIngressErrorCodeV0 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::BadMagic => "bad_magic",
            Self::HandshakeTooLarge => "handshake_too_large",
            Self::FrameTooLarge => "frame_too_large",
            Self::UnexpectedEof => "unexpected_eof",
            Self::TrailingBytes => "trailing_bytes",
            Self::UnknownField => "unknown_field",
            Self::DuplicateField => "duplicate_field",
            Self::NonCanonicalFieldOrder => "noncanonical_field_order",
            Self::FieldTooLarge => "field_too_large",
            Self::InvalidFieldLength => "invalid_field_length",
            Self::InvalidValue => "invalid_value",
            Self::ContextMismatch => "context_mismatch",
            Self::UnknownPeer => "unknown_peer",
            Self::PeerKeyMismatch => "peer_key_mismatch",
            Self::InvalidHandshakeSignature => "invalid_handshake_signature",
            Self::InvalidFrameSignature => "invalid_frame_signature",
            Self::SessionMismatch => "session_mismatch",
            Self::PeerIdentityMismatch => "peer_identity_mismatch",
            Self::SequenceBindingMismatch => "sequence_binding_mismatch",
            Self::SequenceReplay => "sequence_replay",
            Self::SequenceTooOld => "sequence_too_old",
            Self::UnsupportedBodyKind => "unsupported_body_kind",
            Self::WirePreflight => "wire_preflight",
            Self::SemanticDecode => "semantic_decode",
        }
    }
}

/// Candidate ingress error with an exact byte offset where one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeP2pSessionErrorV0 {
    code: P2pSessionIngressErrorCodeV0,
    offset: usize,
    sequence: Option<u64>,
    previous_sequence: Option<u64>,
    wire_code: Option<trnm_consensus_types::WireEnvelopeDecodeErrorCode>,
    semantic_code: Option<trnm_consensus_types::WireSemanticDecodeErrorCode>,
}

impl PocoNodeP2pSessionErrorV0 {
    const fn simple(code: P2pSessionIngressErrorCodeV0, offset: usize) -> Self {
        Self {
            code,
            offset,
            sequence: None,
            previous_sequence: None,
            wire_code: None,
            semantic_code: None,
        }
    }

    const fn sequence_error(
        code: P2pSessionIngressErrorCodeV0,
        sequence: u64,
        previous_sequence: Option<u64>,
    ) -> Self {
        Self {
            code,
            offset: 0,
            sequence: Some(sequence),
            previous_sequence,
            wire_code: None,
            semantic_code: None,
        }
    }

    const fn wire(error: WireEnvelopeDecodeError) -> Self {
        Self {
            code: P2pSessionIngressErrorCodeV0::WirePreflight,
            offset: error.byte_offset(),
            sequence: None,
            previous_sequence: None,
            wire_code: Some(error.code()),
            semantic_code: None,
        }
    }

    const fn semantic(error: WireSemanticDecodeError) -> Self {
        Self {
            code: P2pSessionIngressErrorCodeV0::SemanticDecode,
            offset: error.byte_offset(),
            sequence: None,
            previous_sequence: None,
            wire_code: None,
            semantic_code: Some(error.code()),
        }
    }

    pub const fn code(self) -> P2pSessionIngressErrorCodeV0 {
        self.code
    }

    pub const fn offset(self) -> usize {
        self.offset
    }

    pub const fn sequence(self) -> Option<u64> {
        self.sequence
    }

    pub const fn previous_sequence(self) -> Option<u64> {
        self.previous_sequence
    }

    pub const fn wire_code(self) -> Option<trnm_consensus_types::WireEnvelopeDecodeErrorCode> {
        self.wire_code
    }

    pub const fn semantic_code(self) -> Option<trnm_consensus_types::WireSemanticDecodeErrorCode> {
        self.semantic_code
    }
}

impl fmt::Display for PocoNodeP2pSessionErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "PoCO P2P session ingress error {} at byte {}",
            self.code.as_str(),
            self.offset
        )
    }
}

impl Error for PocoNodeP2pSessionErrorV0 {}

/// One accepted, borrowed candidate frame.  It carries semantic proof facts
/// but no Core input or network send capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoNodeP2pAcceptedFrameV0<'a> {
    peer_id: ValidatorId,
    session_id: [u8; HASH_BYTES_V0],
    sequence: u64,
    proof: WireEnvelopeSemanticProof<'a>,
}

impl<'a> PocoNodeP2pAcceptedFrameV0<'a> {
    pub const fn peer_id(&self) -> ValidatorId {
        self.peer_id
    }

    pub const fn session_id(&self) -> [u8; HASH_BYTES_V0] {
        self.session_id
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn proof(&self) -> &WireEnvelopeSemanticProof<'a> {
        &self.proof
    }
}

/// A candidate authenticated session bound to one exact validator set.
#[derive(Debug, Clone)]
pub struct PocoNodeP2pSessionV0 {
    validator_set: ValidatorSet,
    parameters: ConsensusParametersV0,
    peer_id: ValidatorId,
    session_id: [u8; HASH_BYTES_V0],
    replay: ReplayWindowV0,
}

impl PocoNodeP2pSessionV0 {
    /// Opens a session from a complete, signed handshake.  The handshake's
    /// peer identity is deliberately a 32-byte consensus-validator ID in
    /// this candidate tranche; its public key must equal that validator's
    /// strictly admitted Ed25519 consensus key.
    pub fn open(
        handshake: &[u8],
        validator_set: &ValidatorSet,
        parameters: &ConsensusParametersV0,
    ) -> Result<Self, PocoNodeP2pSessionErrorV0> {
        validator_set
            .validate_against_parameters(parameters)
            .map_err(|_| err(P2pSessionIngressErrorCodeV0::ContextMismatch, 0))?;
        StrictEd25519Verifier
            .validate_validator_set_v0(validator_set)
            .map_err(|_| err(P2pSessionIngressErrorCodeV0::ContextMismatch, 0))?;
        let parsed = parse_handshake(handshake)?;
        if parsed.protocol_version != PROTOCOL_VERSION_V0
            || parsed.genesis_hash != validator_set.genesis_hash().into_bytes()
            || parsed.chain_id != validator_set.chain_id().as_bytes()
            || parsed.validator_set_id != validator_set.id().into_bytes()
            || parsed.epoch != validator_set.epoch().get()
        {
            return Err(err(P2pSessionIngressErrorCodeV0::ContextMismatch, 0));
        }
        let peer_id = ValidatorId::from_bytes(parsed.peer_id).map_err(|_| {
            err(
                P2pSessionIngressErrorCodeV0::InvalidValue,
                parsed.peer_offset,
            )
        })?;
        let validator = validator_set.validator(peer_id).ok_or_else(|| {
            err(
                P2pSessionIngressErrorCodeV0::UnknownPeer,
                parsed.peer_offset,
            )
        })?;
        if validator.consensus_key().as_bytes() != &parsed.public_key {
            return Err(err(
                P2pSessionIngressErrorCodeV0::PeerKeyMismatch,
                parsed.public_key_offset,
            ));
        }
        let root = handshake_signing_root(parsed.unsigned);
        let signature = SignatureBytes::from_array(parsed.signature);
        if !StrictEd25519Verifier.verify(validator, &root, &signature) {
            return Err(err(
                P2pSessionIngressErrorCodeV0::InvalidHandshakeSignature,
                parsed.signature_offset,
            ));
        }
        let session_id = session_id(parsed.raw);
        Ok(Self {
            validator_set: validator_set.clone(),
            parameters: *parameters,
            peer_id,
            session_id,
            replay: ReplayWindowV0::default(),
        })
    }

    pub const fn peer_id(&self) -> ValidatorId {
        self.peer_id
    }

    pub const fn session_id(&self) -> [u8; HASH_BYTES_V0] {
        self.session_id
    }

    pub const fn highest_sequence(&self) -> Option<u64> {
        self.replay.highest
    }

    /// Verifies one exact data frame, checks its sender/sequence binding,
    /// applies the replay window only after semantic validation succeeds, and
    /// delegates the payload to the nested Vote/TimeoutVote/QC/TC decoder.
    pub fn accept_frame<'a>(
        &mut self,
        frame: &'a [u8],
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<PocoNodeP2pAcceptedFrameV0<'a>, PocoNodeP2pSessionErrorV0> {
        let parsed = parse_frame(frame)?;
        if parsed.protocol_version != PROTOCOL_VERSION_V0 {
            return Err(err(
                P2pSessionIngressErrorCodeV0::InvalidValue,
                parsed.protocol_offset,
            ));
        }
        if parsed.session_id != self.session_id {
            return Err(err(
                P2pSessionIngressErrorCodeV0::SessionMismatch,
                parsed.session_offset,
            ));
        }
        let validator = self
            .validator_set
            .validator(self.peer_id)
            .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::UnknownPeer, 0))?;
        let root = frame_signing_root(
            parsed.unsigned,
            parsed.session_id,
            parsed.sequence,
            parsed.payload,
        );
        let signature = SignatureBytes::from_array(parsed.signature);
        if !StrictEd25519Verifier.verify(validator, &root, &signature) {
            return Err(err(
                P2pSessionIngressErrorCodeV0::InvalidFrameSignature,
                parsed.signature_offset,
            ));
        }

        // The cheap outer preflight runs before the nested parser and binds
        // the transport record to the authenticated peer and sequence.
        let preflight = decode_wire_envelope_v0_preflight(parsed.payload)
            .map_err(PocoNodeP2pSessionErrorV0::wire)?;
        if preflight.sender_node_id() != self.peer_id.as_bytes() {
            return Err(err(P2pSessionIngressErrorCodeV0::PeerIdentityMismatch, 0));
        }
        if preflight.sender_sequence() != parsed.sequence {
            return Err(err(
                P2pSessionIngressErrorCodeV0::SequenceBindingMismatch,
                0,
            ));
        }
        if !matches!(
            preflight.body_kind(),
            WireBodyKindV0::Vote
                | WireBodyKindV0::TimeoutVote
                | WireBodyKindV0::QuorumCertificate
                | WireBodyKindV0::TimeoutCertificate
        ) {
            return Err(err(P2pSessionIngressErrorCodeV0::UnsupportedBodyKind, 0));
        }

        let next_replay = self.replay.preview(parsed.sequence)?;
        let proof = decode_wire_envelope_v0_semantic(
            parsed.payload,
            &self.validator_set,
            &self.parameters,
            budget,
        )
        .map_err(PocoNodeP2pSessionErrorV0::semantic)?;
        self.replay = next_replay;
        Ok(PocoNodeP2pAcceptedFrameV0 {
            peer_id: self.peer_id,
            session_id: self.session_id,
            sequence: parsed.sequence,
            proof,
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ReplayWindowV0 {
    highest: Option<u64>,
    bitmap: u64,
}

impl ReplayWindowV0 {
    fn preview(&self, sequence: u64) -> Result<Self, PocoNodeP2pSessionErrorV0> {
        let Some(highest) = self.highest else {
            return Ok(Self {
                highest: Some(sequence),
                bitmap: 1,
            });
        };
        if sequence > highest {
            let shift = sequence - highest;
            let bitmap = if shift >= P2P_SESSION_REPLAY_WINDOW_V0 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            return Ok(Self {
                highest: Some(sequence),
                bitmap,
            });
        }
        let age = highest - sequence;
        if age >= P2P_SESSION_REPLAY_WINDOW_V0 {
            return Err(PocoNodeP2pSessionErrorV0::sequence_error(
                P2pSessionIngressErrorCodeV0::SequenceTooOld,
                sequence,
                Some(highest),
            ));
        }
        let mask = 1u64 << age;
        if self.bitmap & mask != 0 {
            return Err(PocoNodeP2pSessionErrorV0::sequence_error(
                P2pSessionIngressErrorCodeV0::SequenceReplay,
                sequence,
                Some(highest),
            ));
        }
        Ok(Self {
            highest: Some(highest),
            bitmap: self.bitmap | mask,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct HandshakeView<'a> {
    raw: &'a [u8],
    unsigned: &'a [u8],
    protocol_version: u16,
    genesis_hash: [u8; HASH_BYTES_V0],
    chain_id: &'a [u8],
    validator_set_id: [u8; HASH_BYTES_V0],
    epoch: u64,
    peer_id: &'a [u8],
    public_key: [u8; HASH_BYTES_V0],
    signature: [u8; SIGNATURE_BYTES],
    peer_offset: usize,
    public_key_offset: usize,
    signature_offset: usize,
}

#[derive(Debug, Clone, Copy)]
struct FrameView<'a> {
    unsigned: &'a [u8],
    protocol_version: u16,
    session_id: [u8; HASH_BYTES_V0],
    sequence: u64,
    payload: &'a [u8],
    signature: [u8; SIGNATURE_BYTES],
    protocol_offset: usize,
    session_offset: usize,
    signature_offset: usize,
}

fn parse_handshake(bytes: &[u8]) -> Result<HandshakeView<'_>, PocoNodeP2pSessionErrorV0> {
    let mut cursor = TlvCursor::new(
        bytes,
        HANDSHAKE_MAGIC,
        P2P_SESSION_MAX_HANDSHAKE_BYTES_V0,
        HANDSHAKE_MAX_TAG_V0,
        HANDSHAKE_FIELD_COUNT_V0,
    )?;
    let mut protocol_version = None;
    let mut genesis_hash = None;
    let mut chain_id = None;
    let mut validator_set_id = None;
    let mut epoch = None;
    let mut peer_id = None;
    let mut public_key = None;
    let mut nonce = None;
    let mut signature = None;
    let mut peer_offset = 0;
    let mut public_key_offset = 0;
    let mut signature_offset = 0;
    let mut unsigned_end = None;
    while let Some((offset, tag, value)) = cursor.next()? {
        match tag {
            1 => protocol_version = Some(exact_u16(value, offset)?),
            2 => genesis_hash = Some(exact_array(value, offset)?),
            3 => {
                if value.is_empty() || value.len() > MAX_CONSENSUS_STRING_BYTES {
                    return Err(err(
                        P2pSessionIngressErrorCodeV0::InvalidFieldLength,
                        offset,
                    ));
                }
                chain_id = Some(value);
            }
            4 => validator_set_id = Some(exact_array(value, offset)?),
            5 => epoch = Some(exact_u64(value, offset)?),
            6 => {
                if value.len() != MAX_PROTOBUF_WIRE_SENDER_NODE_ID_BYTES_V0
                    || value.iter().all(|byte| *byte == 0)
                {
                    return Err(err(
                        P2pSessionIngressErrorCodeV0::InvalidFieldLength,
                        offset,
                    ));
                }
                peer_id = Some(value);
                peer_offset = offset;
            }
            7 => {
                public_key = Some(exact_array(value, offset)?);
                public_key_offset = offset;
            }
            8 => {
                let value = exact_array(value, offset)?;
                if value == [0; HASH_BYTES_V0] {
                    return Err(err(P2pSessionIngressErrorCodeV0::InvalidValue, offset));
                }
                nonce = Some(value);
            }
            9 => {
                unsigned_end = Some(offset);
                signature = Some(exact_signature(value, offset)?);
                signature_offset = offset;
            }
            _ => return Err(err(P2pSessionIngressErrorCodeV0::UnknownField, offset)),
        }
    }
    let raw = bytes;
    let _nonce =
        nonce.ok_or_else(|| err(P2pSessionIngressErrorCodeV0::InvalidValue, bytes.len()))?;
    let unsigned = &bytes[..unsigned_end
        .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::InvalidValue, bytes.len()))?];
    Ok(HandshakeView {
        raw,
        unsigned,
        protocol_version: protocol_version
            .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::InvalidValue, bytes.len()))?,
        genesis_hash: genesis_hash
            .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::InvalidValue, bytes.len()))?,
        chain_id: chain_id
            .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::InvalidValue, bytes.len()))?,
        validator_set_id: validator_set_id
            .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::InvalidValue, bytes.len()))?,
        epoch: epoch.ok_or_else(|| err(P2pSessionIngressErrorCodeV0::InvalidValue, bytes.len()))?,
        peer_id: peer_id
            .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::InvalidValue, bytes.len()))?,
        public_key: public_key
            .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::InvalidValue, bytes.len()))?,
        signature: signature
            .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::InvalidValue, bytes.len()))?,
        peer_offset,
        public_key_offset,
        signature_offset,
    })
}

fn parse_frame(bytes: &[u8]) -> Result<FrameView<'_>, PocoNodeP2pSessionErrorV0> {
    let mut cursor = TlvCursor::new(
        bytes,
        FRAME_MAGIC,
        P2P_SESSION_MAX_FRAME_BYTES_V0,
        FRAME_MAX_TAG_V0,
        FRAME_FIELD_COUNT_V0,
    )?;
    let mut protocol_version = None;
    let mut session_id = None;
    let mut sequence = None;
    let mut payload = None;
    let mut signature = None;
    let mut protocol_offset = 0;
    let mut session_offset = 0;
    let mut signature_offset = 0;
    let mut unsigned_end = None;
    while let Some((offset, tag, value)) = cursor.next()? {
        match tag {
            1 => {
                protocol_version = Some(exact_u16(value, offset)?);
                protocol_offset = offset;
            }
            2 => {
                let value = exact_array(value, offset)?;
                if value == [0; HASH_BYTES_V0] {
                    return Err(err(P2pSessionIngressErrorCodeV0::InvalidValue, offset));
                }
                session_id = Some(value);
                session_offset = offset;
            }
            3 => sequence = Some(exact_u64(value, offset)?),
            4 => {
                if value.is_empty() || value.len() > P2P_SESSION_MAX_PAYLOAD_BYTES_V0 {
                    return Err(err(P2pSessionIngressErrorCodeV0::FieldTooLarge, offset));
                }
                payload = Some(value);
            }
            5 => {
                unsigned_end = Some(offset);
                signature = Some(exact_signature(value, offset)?);
                signature_offset = offset;
            }
            _ => return Err(err(P2pSessionIngressErrorCodeV0::UnknownField, offset)),
        }
    }
    Ok(FrameView {
        unsigned: &bytes[..unsigned_end
            .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::InvalidValue, bytes.len()))?],
        protocol_version: protocol_version
            .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::InvalidValue, bytes.len()))?,
        session_id: session_id
            .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::InvalidValue, bytes.len()))?,
        sequence: sequence
            .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::InvalidValue, bytes.len()))?,
        payload: payload
            .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::InvalidValue, bytes.len()))?,
        signature: signature
            .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::InvalidValue, bytes.len()))?,
        protocol_offset,
        session_offset,
        signature_offset,
    })
}

struct TlvCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    last_tag: u8,
    max_bytes: usize,
    max_tag: u8,
    max_fields: usize,
    fields: usize,
}

type TlvField<'a> = (usize, u8, &'a [u8]);

impl<'a> TlvCursor<'a> {
    fn new(
        bytes: &'a [u8],
        magic: &[u8; 4],
        max_bytes: usize,
        max_tag: u8,
        max_fields: usize,
    ) -> Result<Self, PocoNodeP2pSessionErrorV0> {
        if bytes.is_empty() {
            return Err(err(P2pSessionIngressErrorCodeV0::Empty, 0));
        }
        if bytes.len() > max_bytes {
            let code = if magic == HANDSHAKE_MAGIC {
                P2pSessionIngressErrorCodeV0::HandshakeTooLarge
            } else {
                P2pSessionIngressErrorCodeV0::FrameTooLarge
            };
            return Err(err(code, 0));
        }
        if bytes.len() < magic.len() || &bytes[..magic.len()] != magic {
            return Err(err(P2pSessionIngressErrorCodeV0::BadMagic, 0));
        }
        Ok(Self {
            bytes,
            offset: magic.len(),
            last_tag: 0,
            max_bytes,
            max_tag,
            max_fields,
            fields: 0,
        })
    }

    fn next(&mut self) -> Result<Option<TlvField<'a>>, PocoNodeP2pSessionErrorV0> {
        if self.offset == self.bytes.len() {
            return Ok(None);
        }
        let offset = self.offset;
        let remaining = self.bytes.len() - offset;
        if remaining < TLV_HEADER_BYTES_V0 {
            return Err(err(P2pSessionIngressErrorCodeV0::TrailingBytes, offset));
        }
        let tag = self.bytes[offset];
        if tag == 0 || tag > self.max_tag {
            return Err(err(P2pSessionIngressErrorCodeV0::UnknownField, offset));
        }
        if tag == self.last_tag {
            return Err(err(P2pSessionIngressErrorCodeV0::DuplicateField, offset));
        }
        if tag < self.last_tag {
            return Err(err(
                P2pSessionIngressErrorCodeV0::NonCanonicalFieldOrder,
                offset,
            ));
        }
        self.fields = self
            .fields
            .checked_add(1)
            .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::FieldTooLarge, offset))?;
        if self.fields > self.max_fields {
            return Err(err(P2pSessionIngressErrorCodeV0::FieldTooLarge, offset));
        }
        let length_start = offset + 1;
        let length_bytes: [u8; 4] = self.bytes[length_start..length_start + 4]
            .try_into()
            .map_err(|_| err(P2pSessionIngressErrorCodeV0::UnexpectedEof, offset))?;
        let length = usize::try_from(u32::from_be_bytes(length_bytes))
            .map_err(|_| err(P2pSessionIngressErrorCodeV0::FieldTooLarge, offset))?;
        if length > self.max_bytes {
            return Err(err(P2pSessionIngressErrorCodeV0::FieldTooLarge, offset));
        }
        let value_start = offset + TLV_HEADER_BYTES_V0;
        let value_end = value_start
            .checked_add(length)
            .ok_or_else(|| err(P2pSessionIngressErrorCodeV0::FieldTooLarge, offset))?;
        if value_end > self.bytes.len() {
            return Err(err(P2pSessionIngressErrorCodeV0::UnexpectedEof, offset));
        }
        self.offset = value_end;
        self.last_tag = tag;
        Ok(Some((offset, tag, &self.bytes[value_start..value_end])))
    }
}

fn exact_array(
    value: &[u8],
    offset: usize,
) -> Result<[u8; HASH_BYTES_V0], PocoNodeP2pSessionErrorV0> {
    value
        .try_into()
        .map_err(|_| err(P2pSessionIngressErrorCodeV0::InvalidFieldLength, offset))
}

fn exact_signature(
    value: &[u8],
    offset: usize,
) -> Result<[u8; SIGNATURE_BYTES], PocoNodeP2pSessionErrorV0> {
    value
        .try_into()
        .map_err(|_| err(P2pSessionIngressErrorCodeV0::InvalidFieldLength, offset))
}

fn exact_u16(value: &[u8], offset: usize) -> Result<u16, PocoNodeP2pSessionErrorV0> {
    value
        .try_into()
        .map(u16::from_be_bytes)
        .map_err(|_| err(P2pSessionIngressErrorCodeV0::InvalidFieldLength, offset))
}

fn exact_u64(value: &[u8], offset: usize) -> Result<u64, PocoNodeP2pSessionErrorV0> {
    value
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| err(P2pSessionIngressErrorCodeV0::InvalidFieldLength, offset))
}

fn err(code: P2pSessionIngressErrorCodeV0, offset: usize) -> PocoNodeP2pSessionErrorV0 {
    PocoNodeP2pSessionErrorV0::simple(code, offset)
}

fn handshake_signing_root(unsigned: &[u8]) -> SigningRoot {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_HANDSHAKE_V0);
    hasher.update((unsigned.len() as u64).to_be_bytes());
    hasher.update(unsigned);
    SigningRoot::new(hasher.finalize().into())
}

fn session_id(handshake: &[u8]) -> [u8; HASH_BYTES_V0] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SESSION_ID_V0);
    hasher.update((handshake.len() as u64).to_be_bytes());
    hasher.update(handshake);
    hasher.finalize().into()
}

fn frame_signing_root(
    unsigned: &[u8],
    session_id: [u8; HASH_BYTES_V0],
    sequence: u64,
    payload: &[u8],
) -> SigningRoot {
    let payload_hash: [u8; HASH_BYTES_V0] = Sha256::digest(payload).into();
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_FRAME_V0);
    hasher.update(session_id);
    hasher.update(sequence.to_be_bytes());
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload_hash);
    // Including the canonical unsigned record prevents a field-reordering
    // implementation from accidentally sharing a signature domain with this
    // parser.  The repeated values above make the signed intent explicit.
    hasher.update((unsigned.len() as u64).to_be_bytes());
    hasher.update(unsigned);
    SigningRoot::new(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use trnm_consensus_types::{
        BlockId, ChainId, ConsensusPublicKey, Epoch, Height, MessageKind, ProtocolVersion, QcRef,
        QuorumCertificate, TimeoutCertificateV0, TimeoutEntryV0, TimeoutVote, Validator, Vote,
        VotingPower, WireSemanticBodyKindV0,
    };

    fn tlv(target: &mut Vec<u8>, tag: u8, value: &[u8]) {
        target.push(tag);
        target.extend((value.len() as u32).to_be_bytes());
        target.extend(value);
    }

    fn pvarint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break out;
            }
        }
    }

    fn pfield_varint(target: &mut Vec<u8>, field: u32, value: u64) {
        target.extend(pvarint(u64::from(field << 3)));
        target.extend(pvarint(value));
    }

    fn pfield_bytes(target: &mut Vec<u8>, field: u32, value: &[u8]) {
        target.extend(pvarint(u64::from((field << 3) | 2)));
        target.extend(pvarint(value.len() as u64));
        target.extend(value);
    }

    fn handshake_unsigned(
        set: &ValidatorSet,
        peer: ValidatorId,
        public_key: [u8; 32],
        nonce: [u8; 32],
    ) -> Vec<u8> {
        let mut bytes = HANDSHAKE_MAGIC.to_vec();
        tlv(&mut bytes, 1, &PROTOCOL_VERSION_V0.to_be_bytes());
        tlv(&mut bytes, 2, set.genesis_hash().as_bytes());
        tlv(&mut bytes, 3, set.chain_id().as_bytes());
        tlv(&mut bytes, 4, set.id().as_bytes());
        tlv(&mut bytes, 5, &set.epoch().get().to_be_bytes());
        tlv(&mut bytes, 6, peer.as_bytes());
        tlv(&mut bytes, 7, &public_key);
        tlv(&mut bytes, 8, &nonce);
        bytes
    }

    fn signed_handshake(set: &ValidatorSet, key: &SigningKey, peer: ValidatorId) -> Vec<u8> {
        let unsigned = handshake_unsigned(set, peer, key.verifying_key().to_bytes(), [0xA5; 32]);
        let sig = key
            .sign(handshake_signing_root(&unsigned).as_bytes())
            .to_bytes();
        let mut bytes = unsigned;
        tlv(&mut bytes, 9, &sig);
        bytes
    }

    fn common_context(set: &ValidatorSet, view: u64, kind: MessageKind) -> Vec<u8> {
        let mut bytes = Vec::new();
        pfield_varint(&mut bytes, 1, 0);
        pfield_bytes(&mut bytes, 2, set.genesis_hash().as_bytes());
        pfield_bytes(&mut bytes, 3, set.chain_id().as_bytes());
        pfield_varint(&mut bytes, 4, 0);
        pfield_varint(&mut bytes, 5, set.epoch().get());
        pfield_bytes(&mut bytes, 6, set.id().as_bytes());
        pfield_varint(&mut bytes, 7, view);
        pfield_varint(&mut bytes, 8, kind as u64);
        pfield_bytes(&mut bytes, 9, set.consensus_parameters_hash().as_bytes());
        bytes
    }

    fn signature_share(author: ValidatorId, byte: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        pfield_bytes(&mut bytes, 1, author.as_bytes());
        pfield_bytes(&mut bytes, 2, &[byte; SIGNATURE_BYTES]);
        bytes
    }

    fn scope_prefix(set: &ValidatorSet) -> Vec<u8> {
        let mut bytes = Vec::new();
        pfield_varint(&mut bytes, 1, 0);
        pfield_bytes(&mut bytes, 2, set.genesis_hash().as_bytes());
        pfield_bytes(&mut bytes, 3, set.chain_id().as_bytes());
        pfield_varint(&mut bytes, 4, 0);
        pfield_varint(&mut bytes, 5, set.epoch().get());
        pfield_bytes(&mut bytes, 6, set.id().as_bytes());
        pfield_bytes(&mut bytes, 7, set.consensus_parameters_hash().as_bytes());
        bytes
    }

    fn vote_body(set: &ValidatorSet, view: u64, author: ValidatorId, signature: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        pfield_bytes(&mut bytes, 1, &common_context(set, view, MessageKind::Vote));
        pfield_varint(&mut bytes, 2, 1);
        pfield_bytes(&mut bytes, 3, &[0x42; 32]);
        pfield_bytes(&mut bytes, 4, author.as_bytes());
        pfield_bytes(&mut bytes, 5, &[signature; SIGNATURE_BYTES]);
        bytes
    }

    fn outer(
        set: &ValidatorSet,
        peer: ValidatorId,
        sequence: u64,
        body_kind: WireBodyKindV0,
        body: &[u8],
        message_kind: Option<MessageKind>,
    ) -> Vec<u8> {
        // This helper emits the same protobuf wire bytes as the frozen
        // WireEnvelope schema, without importing a generated serializer.
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
                    break out;
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
        let mut bytes = Vec::new();
        bytes.extend(field_varint(1, 0));
        bytes.extend(field_varint(2, 0));
        bytes.extend(field_bytes(3, set.genesis_hash().as_bytes()));
        bytes.extend(field_bytes(4, set.chain_id().as_bytes()));
        bytes.extend(field_varint(5, 0));
        bytes.extend(field_varint(6, set.epoch().get()));
        let view = if matches!(body_kind, WireBodyKindV0::TimeoutCertificate) {
            2
        } else {
            1
        };
        bytes.extend(field_varint(7, view));
        bytes.extend(field_bytes(8, set.id().as_bytes()));
        bytes.extend(field_bytes(9, set.consensus_parameters_hash().as_bytes()));
        bytes.extend(field_varint(10, u64::from(message_kind.is_some())));
        if let Some(kind) = message_kind {
            bytes.extend(field_varint(11, kind as u64));
        }
        bytes.extend(field_varint(12, body_kind as u64));
        bytes.extend(field_bytes(13, peer.as_bytes()));
        bytes.extend(field_bytes(14, &[0x71; 16]));
        bytes.extend(field_varint(15, sequence));
        let hash: [u8; 32] = Sha256::digest(body).into();
        bytes.extend(field_bytes(16, &hash));
        bytes.extend(field_bytes(31 + body_kind as u32, body));
        bytes
    }

    fn signed_frame(
        session_id: [u8; 32],
        sequence: u64,
        payload: &[u8],
        key: &SigningKey,
    ) -> Vec<u8> {
        let mut unsigned = FRAME_MAGIC.to_vec();
        tlv(&mut unsigned, 1, &PROTOCOL_VERSION_V0.to_be_bytes());
        tlv(&mut unsigned, 2, &session_id);
        tlv(&mut unsigned, 3, &sequence.to_be_bytes());
        tlv(&mut unsigned, 4, payload);
        let sig = key
            .sign(frame_signing_root(&unsigned, session_id, sequence, payload).as_bytes())
            .to_bytes();
        let mut frame = unsigned;
        tlv(&mut frame, 5, &sig);
        frame
    }

    struct Fixture {
        parameters: ConsensusParametersV0,
        set: ValidatorSet,
        key: SigningKey,
        peer: ValidatorId,
        vote_payload: Vec<u8>,
        qc_payload: Vec<u8>,
        tc_payload: Vec<u8>,
        handshake: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            let parameters = ConsensusParametersV0::reference_shadow_v0();
            let keys: Vec<SigningKey> = (1u8..=4)
                .map(|byte| SigningKey::from_bytes(&[byte; 32]))
                .collect();
            let validators = keys
                .iter()
                .enumerate()
                .map(|(index, key)| {
                    Validator::new(
                        ValidatorId::new([(index + 1) as u8; 32]),
                        ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                        VotingPower::new(1).expect("power"),
                    )
                    .expect("validator")
                })
                .collect();
            let set = ValidatorSet::new(
                trnm_consensus_types::GenesisHash::new([0x99; 32]),
                ChainId::from_static("trnm-p2p-session"),
                ProtocolVersion::V0,
                Epoch::new(0),
                parameters.hash(),
                validators,
            )
            .expect("set");
            let peer = ValidatorId::new([1; 32]);
            let vote_payload = outer(
                &set,
                peer,
                1,
                WireBodyKindV0::Vote,
                &vote_body(&set, 1, peer, 0xA1),
                Some(MessageKind::Vote),
            );

            let block = BlockId::new([0x42; 32]);
            let votes = (1u8..=3)
                .map(|id| {
                    Vote::new(
                        set.chain_id(),
                        ProtocolVersion::V0,
                        Epoch::new(0),
                        trnm_consensus_types::View::new(1),
                        Height::new(1),
                        block,
                        set.id(),
                        ValidatorId::new([id; 32]),
                        SignatureBytes::from_array([0xA0 + id; SIGNATURE_BYTES]),
                        &set,
                    )
                    .expect("vote")
                })
                .collect();
            let qc = QuorumCertificate::new(
                set.chain_id(),
                ProtocolVersion::V0,
                Epoch::new(0),
                trnm_consensus_types::View::new(1),
                Height::new(1),
                block,
                set.id(),
                votes,
                &set,
            )
            .expect("qc");
            let mut qc_body = scope_prefix(&set);
            pfield_varint(&mut qc_body, 8, 1);
            pfield_varint(&mut qc_body, 9, 1);
            pfield_bytes(&mut qc_body, 10, block.as_bytes());
            for id in 1u8..=3 {
                pfield_bytes(
                    &mut qc_body,
                    11,
                    &signature_share(ValidatorId::new([id; 32]), 0xA0 + id),
                );
            }
            pfield_bytes(&mut qc_body, 12, qc.id().as_bytes());
            let qc_payload = outer(
                &set,
                peer,
                2,
                WireBodyKindV0::QuorumCertificate,
                &qc_body,
                None,
            );

            let high = QcRef::from(&qc);
            let timeout_votes: Vec<TimeoutVote> = (1u8..=3)
                .map(|id| {
                    TimeoutVote::new(
                        set.chain_id(),
                        ProtocolVersion::V0,
                        Epoch::new(0),
                        trnm_consensus_types::View::new(2),
                        set.id(),
                        high,
                        ValidatorId::new([id; 32]),
                        SignatureBytes::from_array([0xD0 + id; SIGNATURE_BYTES]),
                        &set,
                    )
                    .expect("timeout vote")
                })
                .collect();
            let entries = timeout_votes
                .iter()
                .map(|vote| {
                    TimeoutEntryV0::new(vote.author(), vote.high_qc(), *vote.signature())
                        .expect("entry")
                })
                .collect();
            let tc = TimeoutCertificateV0::new(
                trnm_consensus_types::View::new(2),
                entries,
                vec![trnm_consensus_types::QcReferenceV0::ordinary(qc.clone())],
                qc.id(),
                &set,
            )
            .expect("tc");
            let mut tc_body = scope_prefix(&set);
            pfield_varint(&mut tc_body, 8, 2);
            for id in 1u8..=3 {
                let mut entry = Vec::new();
                pfield_bytes(
                    &mut entry,
                    1,
                    &common_context(&set, 2, MessageKind::Timeout),
                );
                pfield_bytes(&mut entry, 2, &high_qc_summary(high));
                pfield_bytes(&mut entry, 3, ValidatorId::new([id; 32]).as_bytes());
                pfield_bytes(&mut entry, 4, &[0xD0 + id; SIGNATURE_BYTES]);
                pfield_bytes(&mut tc_body, 9, &entry);
            }
            pfield_bytes(&mut tc_body, 10, &qc_body);
            pfield_bytes(&mut tc_body, 11, qc.id().as_bytes());
            pfield_bytes(&mut tc_body, 12, tc.id().as_bytes());
            let tc_payload = outer(
                &set,
                peer,
                3,
                WireBodyKindV0::TimeoutCertificate,
                &tc_body,
                None,
            );
            let handshake = signed_handshake(&set, &keys[0], peer);
            Self {
                parameters,
                set,
                key: keys[0].clone(),
                peer,
                vote_payload,
                qc_payload,
                tc_payload,
                handshake,
            }
        }
    }

    fn high_qc_summary(reference: QcRef) -> Vec<u8> {
        let mut bytes = Vec::new();
        pfield_bytes(&mut bytes, 1, reference.qc_digest().as_bytes());
        pfield_varint(&mut bytes, 2, reference.epoch().get());
        pfield_varint(&mut bytes, 3, reference.view().get());
        pfield_varint(&mut bytes, 4, reference.height().get());
        pfield_bytes(&mut bytes, 5, reference.block_id().as_bytes());
        bytes
    }

    #[test]
    fn signed_session_accepts_vote_qc_and_tc_and_advances_replay_window() {
        let fixture = Fixture::new();
        let mut session =
            PocoNodeP2pSessionV0::open(&fixture.handshake, &fixture.set, &fixture.parameters)
                .expect("handshake");
        for (sequence, payload, kind) in [
            (1, &fixture.vote_payload, WireSemanticBodyKindV0::Vote),
            (
                2,
                &fixture.qc_payload,
                WireSemanticBodyKindV0::QuorumCertificate,
            ),
            (
                3,
                &fixture.tc_payload,
                WireSemanticBodyKindV0::TimeoutCertificate,
            ),
        ] {
            let frame = signed_frame(session.session_id(), sequence, payload, &fixture.key);
            let mut budget =
                Cev0AdmissionBudgetV0::for_validator_set(&fixture.parameters, &fixture.set);
            let accepted = session.accept_frame(&frame, &mut budget).expect("frame");
            assert_eq!(accepted.peer_id(), fixture.peer);
            assert_eq!(accepted.sequence(), sequence);
            assert_eq!(accepted.proof().body_kind(), kind);
        }
        assert_eq!(session.highest_sequence(), Some(3));
    }

    #[test]
    fn handshake_rejects_duplicate_unknown_trailing_oversize_and_bad_signature() {
        let fixture = Fixture::new();
        let mut duplicate = fixture.handshake.clone();
        // A duplicate field 8 follows the canonical field 9 only as a
        // noncanonical/duplicate attempt; either rejection is fail-closed.
        tlv(&mut duplicate, 8, &[0xA5; 32]);
        assert!(matches!(
            PocoNodeP2pSessionV0::open(&duplicate, &fixture.set, &fixture.parameters)
                .unwrap_err()
                .code(),
            P2pSessionIngressErrorCodeV0::UnknownField
                | P2pSessionIngressErrorCodeV0::NonCanonicalFieldOrder
                | P2pSessionIngressErrorCodeV0::DuplicateField
        ));
        let mut unknown = fixture.handshake
            [..fixture.handshake.len() - (TLV_HEADER_BYTES_V0 + SIGNATURE_BYTES)]
            .to_vec();
        tlv(&mut unknown, 10, &[1]);
        assert_eq!(
            PocoNodeP2pSessionV0::open(&unknown, &fixture.set, &fixture.parameters)
                .unwrap_err()
                .code(),
            P2pSessionIngressErrorCodeV0::UnknownField
        );
        let mut trailing = fixture.handshake.clone();
        trailing.push(0xFF);
        assert_eq!(
            PocoNodeP2pSessionV0::open(&trailing, &fixture.set, &fixture.parameters)
                .unwrap_err()
                .code(),
            P2pSessionIngressErrorCodeV0::TrailingBytes
        );
        let oversize = vec![0u8; P2P_SESSION_MAX_HANDSHAKE_BYTES_V0 + 1];
        assert_eq!(
            PocoNodeP2pSessionV0::open(&oversize, &fixture.set, &fixture.parameters)
                .unwrap_err()
                .code(),
            P2pSessionIngressErrorCodeV0::HandshakeTooLarge
        );
        let mut bad = fixture.handshake.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_eq!(
            PocoNodeP2pSessionV0::open(&bad, &fixture.set, &fixture.parameters)
                .unwrap_err()
                .code(),
            P2pSessionIngressErrorCodeV0::InvalidHandshakeSignature
        );
    }

    #[test]
    fn frame_rejects_duplicate_unknown_trailing_signature_replay_and_binding_mutants() {
        let fixture = Fixture::new();
        let mut session =
            PocoNodeP2pSessionV0::open(&fixture.handshake, &fixture.set, &fixture.parameters)
                .expect("handshake");
        let frame = signed_frame(session.session_id(), 1, &fixture.vote_payload, &fixture.key);
        let mut budget =
            Cev0AdmissionBudgetV0::for_validator_set(&fixture.parameters, &fixture.set);
        session.accept_frame(&frame, &mut budget).expect("first");
        let mut replay_budget =
            Cev0AdmissionBudgetV0::for_validator_set(&fixture.parameters, &fixture.set);
        assert_eq!(
            session
                .accept_frame(&frame, &mut replay_budget)
                .unwrap_err()
                .code(),
            P2pSessionIngressErrorCodeV0::SequenceReplay
        );

        let mut duplicate = frame.clone();
        tlv(&mut duplicate, 5, &[0; SIGNATURE_BYTES]);
        let mut budget =
            Cev0AdmissionBudgetV0::for_validator_set(&fixture.parameters, &fixture.set);
        assert_eq!(
            session
                .accept_frame(&duplicate, &mut budget)
                .unwrap_err()
                .code(),
            P2pSessionIngressErrorCodeV0::DuplicateField
        );

        let mut trailing = frame.clone();
        trailing.push(0xFF);
        let mut budget =
            Cev0AdmissionBudgetV0::for_validator_set(&fixture.parameters, &fixture.set);
        assert_eq!(
            session
                .accept_frame(&trailing, &mut budget)
                .unwrap_err()
                .code(),
            P2pSessionIngressErrorCodeV0::TrailingBytes
        );

        let mut session_mutant =
            PocoNodeP2pSessionV0::open(&fixture.handshake, &fixture.set, &fixture.parameters)
                .expect("handshake");
        // Keep the frame signature valid while changing the payload's
        // sender/sequence binding; the outer preflight must reject it.
        let wrong_payload = outer(
            &fixture.set,
            fixture.peer,
            9,
            WireBodyKindV0::Vote,
            &vote_body(&fixture.set, 1, fixture.peer, 0xA1),
            Some(MessageKind::Vote),
        );
        let frame = signed_frame(session_mutant.session_id(), 1, &wrong_payload, &fixture.key);
        let mut budget =
            Cev0AdmissionBudgetV0::for_validator_set(&fixture.parameters, &fixture.set);
        assert_eq!(
            session_mutant
                .accept_frame(&frame, &mut budget)
                .unwrap_err()
                .code(),
            P2pSessionIngressErrorCodeV0::SequenceBindingMismatch
        );

        let mut unknown = frame.clone();
        // Insert an unsupported tag before the signature field.  Structural
        // rejection must happen before signature or payload semantics.
        let signature_start = unknown.len() - (TLV_HEADER_BYTES_V0 + SIGNATURE_BYTES);
        let signature = unknown.split_off(signature_start);
        tlv(&mut unknown, 6, &[1]);
        unknown.extend(signature);
        let mut budget =
            Cev0AdmissionBudgetV0::for_validator_set(&fixture.parameters, &fixture.set);
        assert_eq!(
            session_mutant
                .accept_frame(&unknown, &mut budget)
                .unwrap_err()
                .code(),
            P2pSessionIngressErrorCodeV0::UnknownField
        );

        let mut bad_sig = signed_frame(
            session_mutant.session_id(),
            2,
            &fixture.vote_payload,
            &fixture.key,
        );
        let index = bad_sig.len() - 1;
        bad_sig[index] ^= 0x80;
        let mut budget =
            Cev0AdmissionBudgetV0::for_validator_set(&fixture.parameters, &fixture.set);
        assert_eq!(
            session_mutant
                .accept_frame(&bad_sig, &mut budget)
                .unwrap_err()
                .code(),
            P2pSessionIngressErrorCodeV0::InvalidFrameSignature
        );
    }

    #[test]
    fn replay_window_allows_reordering_but_rejects_old_positions() {
        let mut window = ReplayWindowV0::default();
        window = window.preview(10).expect("first");
        window = window.preview(8).expect("within window");
        assert_eq!(
            window.preview(8).unwrap_err().code(),
            P2pSessionIngressErrorCodeV0::SequenceReplay
        );
        let window = window.preview(100).expect("advance");
        assert_eq!(
            window.preview(10).unwrap_err().code(),
            P2pSessionIngressErrorCodeV0::SequenceTooOld
        );
    }
}
