//! Candidate state-sync transport ingress binding.
//!
//! `WireEnvelope` preflight proves only the bounded protobuf outer shape.  It
//! does not prove that a frame belongs to this chain, this epoch, or this
//! authenticated peer.  This module closes that narrow node-owned seam for
//! the non-consensus `SyncInfo` body: a caller supplies the exact semantic
//! hash obtained from the nested decoder, and the owner binds the frame to
//! the local Core scope and a strictly increasing sender sequence.
//!
//! The returned frame is still a borrowed transport token.  It carries no
//! Core input, application write capability, signer capability, or network
//! socket.  Sequence state is process-local and intentionally not durable;
//! authenticated P2P lease ownership, restart replay protection, and full
//! state-sync execution remain production blockers.

use std::{error::Error, fmt};

use trnm_consensus_core::CoreConfig;
use trnm_consensus_types::{
    decode_wire_envelope_v0_preflight, WireBodyKindV0, WireEnvelopeDecodeError,
    WireEnvelopePreflight,
};

/// This is a bounded composition seam, not a production network activation.
pub const STATE_SYNC_WIRE_INGRESS_RUNTIME_COMPOSITION_V0: bool = true;
pub const STATE_SYNC_WIRE_INGRESS_PRODUCTION_ACTIVATION_V0: bool = false;
pub const STATE_SYNC_WIRE_INGRESS_DURABLE_REPLAY_PROTECTION_V0: bool = false;

/// The exact scope component which failed node-owned ingress binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeStateSyncWireIngressFieldV0 {
    GenesisHash,
    ChainId,
    ProtocolVersion,
    Epoch,
    ValidatorSetHash,
    ConsensusParametersHash,
    BodyKind,
    ConsensusMessageKind,
    SenderNodeId,
    BodySemanticHash,
}

impl PocoNodeStateSyncWireIngressFieldV0 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GenesisHash => "genesis_hash",
            Self::ChainId => "chain_id",
            Self::ProtocolVersion => "protocol_version",
            Self::Epoch => "epoch",
            Self::ValidatorSetHash => "validator_set_hash",
            Self::ConsensusParametersHash => "consensus_parameters_hash",
            Self::BodyKind => "body_kind",
            Self::ConsensusMessageKind => "consensus_message_kind",
            Self::SenderNodeId => "sender_node_id",
            Self::BodySemanticHash => "body_semantic_hash",
        }
    }
}

/// Fail-closed errors for the candidate state-sync transport binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeStateSyncWireIngressErrorV0 {
    Wire(WireEnvelopeDecodeError),
    InvalidContext(PocoNodeStateSyncWireIngressFieldV0),
    ScopeMismatch(PocoNodeStateSyncWireIngressFieldV0),
    ConsensusMessageKindPresent,
    BodySemanticHashMismatch,
    SenderSequenceReplay { previous: u64, received: u64 },
}

impl fmt::Display for PocoNodeStateSyncWireIngressErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "state-sync WireEnvelope rejected: {error}"),
            Self::InvalidContext(field) => {
                write!(formatter, "invalid state-sync ingress context: {}", field.as_str())
            }
            Self::ScopeMismatch(field) => {
                write!(formatter, "state-sync ingress scope mismatch: {}", field.as_str())
            }
            Self::ConsensusMessageKindPresent => {
                formatter.write_str("state-sync SyncInfo carries a consensus message kind")
            }
            Self::BodySemanticHashMismatch => {
                formatter.write_str("state-sync body semantic hash mismatch")
            }
            Self::SenderSequenceReplay { previous, received } => write!(
                formatter,
                "state-sync sender sequence is not increasing: previous={previous} received={received}"
            ),
        }
    }
}

impl Error for PocoNodeStateSyncWireIngressErrorV0 {}

impl From<WireEnvelopeDecodeError> for PocoNodeStateSyncWireIngressErrorV0 {
    fn from(value: WireEnvelopeDecodeError) -> Self {
        Self::Wire(value)
    }
}

/// Authenticated local scope for one state-sync peer stream.
///
/// The sender identity is a transport identity, not a consensus validator
/// authority.  It is nevertheless pinned here so a frame from another peer
/// cannot be handed to this stream's nested state-sync decoder by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoNodeStateSyncWireIngressContextV0 {
    genesis_hash: [u8; 32],
    chain_id: String,
    protocol_version: u32,
    epoch: u64,
    validator_set_hash: [u8; 32],
    consensus_parameters_hash: [u8; 32],
    sender_node_id: [u8; 32],
}

impl PocoNodeStateSyncWireIngressContextV0 {
    /// Derive the immutable chain/epoch scope from the same CoreConfig which
    /// owns the eventual state-sync recovery transition.
    pub fn from_core_config(
        config: &CoreConfig,
        sender_node_id: [u8; 32],
    ) -> Result<Self, PocoNodeStateSyncWireIngressErrorV0> {
        if sender_node_id == [0; 32] {
            return Err(PocoNodeStateSyncWireIngressErrorV0::InvalidContext(
                PocoNodeStateSyncWireIngressFieldV0::SenderNodeId,
            ));
        }
        let validator_set = config.validator_set();
        let chain_id_value = validator_set.chain_id();
        let chain_id = chain_id_value.as_str();
        if chain_id.is_empty() {
            return Err(PocoNodeStateSyncWireIngressErrorV0::InvalidContext(
                PocoNodeStateSyncWireIngressFieldV0::ChainId,
            ));
        }
        let genesis_hash = *validator_set.genesis_hash().as_bytes();
        let validator_set_hash = *validator_set.id().as_bytes();
        let consensus_parameters_hash = *config.consensus_parameters().hash().as_bytes();
        if genesis_hash == [0; 32]
            || validator_set_hash == [0; 32]
            || consensus_parameters_hash == [0; 32]
        {
            return Err(PocoNodeStateSyncWireIngressErrorV0::InvalidContext(
                PocoNodeStateSyncWireIngressFieldV0::GenesisHash,
            ));
        }
        Ok(Self {
            genesis_hash,
            chain_id: chain_id.to_owned(),
            protocol_version: validator_set.protocol_version().get(),
            epoch: validator_set.epoch().get(),
            validator_set_hash,
            consensus_parameters_hash,
            sender_node_id,
        })
    }

    pub const fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    pub fn chain_id(&self) -> &str {
        self.chain_id.as_str()
    }

    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn validator_set_hash(&self) -> [u8; 32] {
        self.validator_set_hash
    }

    pub const fn consensus_parameters_hash(&self) -> [u8; 32] {
        self.consensus_parameters_hash
    }

    pub const fn sender_node_id(&self) -> [u8; 32] {
        self.sender_node_id
    }
}

/// Borrowed, scope-bound SyncInfo frame returned after ingress checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeStateSyncWireFrameV0<'a> {
    preflight: WireEnvelopePreflight<'a>,
    body_semantic_hash: [u8; 32],
}

impl<'a> PocoNodeStateSyncWireFrameV0<'a> {
    pub const fn body(&self) -> &'a [u8] {
        self.preflight.body()
    }

    pub const fn message_id(&self) -> &'a [u8] {
        self.preflight.message_id()
    }

    pub const fn sender_sequence(&self) -> u64 {
        self.preflight.sender_sequence()
    }

    pub const fn view(&self) -> u64 {
        self.preflight.view()
    }

    pub const fn body_semantic_hash(&self) -> [u8; 32] {
        self.body_semantic_hash
    }

    /// Retain access to the outer preflight facts for the nested decoder.
    /// This does not expose a mutable envelope or any Core capability.
    pub const fn preflight(&self) -> WireEnvelopePreflight<'a> {
        self.preflight
    }
}

/// Single-owner candidate state-sync ingress stream.
///
/// `accept_sync_info_v0` advances the sequence only after every scope and
/// semantic-hash check succeeds.  A malformed or foreign frame therefore
/// cannot consume the next valid sequence, while a replayed sequence cannot
/// be retried through this owner.  The sequence is intentionally process-local
/// until an authenticated durable peer lease/replay journal exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoNodeStateSyncWireIngressOwnerV0 {
    context: PocoNodeStateSyncWireIngressContextV0,
    last_sender_sequence: Option<u64>,
}

impl PocoNodeStateSyncWireIngressOwnerV0 {
    pub fn new(
        context: PocoNodeStateSyncWireIngressContextV0,
    ) -> Result<Self, PocoNodeStateSyncWireIngressErrorV0> {
        if context.sender_node_id == [0; 32] {
            return Err(PocoNodeStateSyncWireIngressErrorV0::InvalidContext(
                PocoNodeStateSyncWireIngressFieldV0::SenderNodeId,
            ));
        }
        Ok(Self {
            context,
            last_sender_sequence: None,
        })
    }

    pub fn from_core_config(
        config: &CoreConfig,
        sender_node_id: [u8; 32],
    ) -> Result<Self, PocoNodeStateSyncWireIngressErrorV0> {
        Self::new(PocoNodeStateSyncWireIngressContextV0::from_core_config(
            config,
            sender_node_id,
        )?)
    }

    pub const fn context(&self) -> &PocoNodeStateSyncWireIngressContextV0 {
        &self.context
    }

    pub const fn last_sender_sequence(&self) -> Option<u64> {
        self.last_sender_sequence
    }

    pub fn accept_sync_info_v0<'a>(
        &mut self,
        bytes: &'a [u8],
        expected_body_semantic_hash: [u8; 32],
    ) -> Result<PocoNodeStateSyncWireFrameV0<'a>, PocoNodeStateSyncWireIngressErrorV0> {
        if expected_body_semantic_hash == [0; 32] {
            return Err(PocoNodeStateSyncWireIngressErrorV0::InvalidContext(
                PocoNodeStateSyncWireIngressFieldV0::BodySemanticHash,
            ));
        }
        let preflight = decode_wire_envelope_v0_preflight(bytes)?;
        self.validate_scope_v0(preflight, expected_body_semantic_hash)?;
        if let Some(previous) = self.last_sender_sequence {
            if preflight.sender_sequence() <= previous {
                return Err(PocoNodeStateSyncWireIngressErrorV0::SenderSequenceReplay {
                    previous,
                    received: preflight.sender_sequence(),
                });
            }
        }
        self.last_sender_sequence = Some(preflight.sender_sequence());
        Ok(PocoNodeStateSyncWireFrameV0 {
            preflight,
            body_semantic_hash: expected_body_semantic_hash,
        })
    }

    fn validate_scope_v0(
        &self,
        preflight: WireEnvelopePreflight<'_>,
        expected_body_semantic_hash: [u8; 32],
    ) -> Result<(), PocoNodeStateSyncWireIngressErrorV0> {
        if preflight.genesis_hash() != self.context.genesis_hash
            || preflight.genesis_hash().len() != self.context.genesis_hash.len()
        {
            return Err(PocoNodeStateSyncWireIngressErrorV0::ScopeMismatch(
                PocoNodeStateSyncWireIngressFieldV0::GenesisHash,
            ));
        }
        if preflight.chain_id() != self.context.chain_id.as_bytes() {
            return Err(PocoNodeStateSyncWireIngressErrorV0::ScopeMismatch(
                PocoNodeStateSyncWireIngressFieldV0::ChainId,
            ));
        }
        if preflight.protocol_version() != self.context.protocol_version {
            return Err(PocoNodeStateSyncWireIngressErrorV0::ScopeMismatch(
                PocoNodeStateSyncWireIngressFieldV0::ProtocolVersion,
            ));
        }
        if preflight.epoch() != self.context.epoch {
            return Err(PocoNodeStateSyncWireIngressErrorV0::ScopeMismatch(
                PocoNodeStateSyncWireIngressFieldV0::Epoch,
            ));
        }
        if preflight.validator_set_hash() != self.context.validator_set_hash {
            return Err(PocoNodeStateSyncWireIngressErrorV0::ScopeMismatch(
                PocoNodeStateSyncWireIngressFieldV0::ValidatorSetHash,
            ));
        }
        if preflight.consensus_parameters_hash() != self.context.consensus_parameters_hash {
            return Err(PocoNodeStateSyncWireIngressErrorV0::ScopeMismatch(
                PocoNodeStateSyncWireIngressFieldV0::ConsensusParametersHash,
            ));
        }
        if preflight.body_kind() != WireBodyKindV0::SyncInfo {
            return Err(PocoNodeStateSyncWireIngressErrorV0::ScopeMismatch(
                PocoNodeStateSyncWireIngressFieldV0::BodyKind,
            ));
        }
        if preflight.has_consensus_message_kind() || preflight.consensus_message_kind().is_some() {
            return Err(PocoNodeStateSyncWireIngressErrorV0::ConsensusMessageKindPresent);
        }
        if preflight.sender_node_id() != self.context.sender_node_id {
            return Err(PocoNodeStateSyncWireIngressErrorV0::ScopeMismatch(
                PocoNodeStateSyncWireIngressFieldV0::SenderNodeId,
            ));
        }
        if preflight.body_semantic_hash() != Some(expected_body_semantic_hash.as_slice()) {
            return Err(PocoNodeStateSyncWireIngressErrorV0::BodySemanticHashMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        Validator, ValidatorId, ValidatorSet, VotingPower,
    };

    fn config() -> CoreConfig {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = (1_u8..=4)
            .map(|id| {
                Validator::new(
                    ValidatorId::new([id; 32]),
                    ConsensusPublicKey::new([id.saturating_add(10); 32]),
                    VotingPower::new(1).expect("positive voting power"),
                )
                .expect("valid validator")
            })
            .collect();
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0x11; 32]),
            ChainId::from_static("state-sync-test"),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .expect("valid validator set");
        CoreConfig::new(
            ValidatorId::new([1; 32]),
            validator_set,
            parameters,
            0,
            16,
            16,
        )
        .expect("valid core config")
    }

    fn varint(mut value: u64) -> Vec<u8> {
        let mut output = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            output.push(byte);
            if value == 0 {
                return output;
            }
        }
    }

    fn field_varint(field: u32, value: u64) -> Vec<u8> {
        let mut output = varint(u64::from(field << 3));
        output.extend(varint(value));
        output
    }

    fn field_bytes(field: u32, value: &[u8]) -> Vec<u8> {
        let mut output = varint(u64::from((field << 3) | 2));
        output.extend(varint(value.len() as u64));
        output.extend(value);
        output
    }

    fn frame(config: &CoreConfig, sender: [u8; 32], sequence: u64, hash: [u8; 32]) -> Vec<u8> {
        let validator_set = config.validator_set();
        let mut output = Vec::new();
        output.extend(field_varint(1, 0));
        output.extend(field_varint(2, 0));
        output.extend(field_bytes(3, validator_set.genesis_hash().as_bytes()));
        output.extend(field_bytes(4, validator_set.chain_id().as_bytes()));
        output.extend(field_varint(
            5,
            validator_set.protocol_version().get() as u64,
        ));
        output.extend(field_varint(6, validator_set.epoch().get()));
        output.extend(field_varint(7, sequence));
        output.extend(field_bytes(8, validator_set.id().as_bytes()));
        output.extend(field_bytes(
            9,
            config.consensus_parameters().hash().as_bytes(),
        ));
        output.extend(field_varint(10, 0));
        output.extend(field_varint(12, WireBodyKindV0::SyncInfo as u64));
        output.extend(field_bytes(13, &sender));
        output.extend(field_bytes(14, &[0x44; 16]));
        output.extend(field_varint(15, sequence));
        output.extend(field_bytes(16, &hash));
        output.extend(field_bytes(37, b"sync-info-body"));
        output
    }

    #[test]
    fn exact_scope_and_monotonic_sequence_produce_borrowed_frame() {
        let config = config();
        let sender = [0x22; 32];
        let hash = [0x33; 32];
        let mut owner = PocoNodeStateSyncWireIngressOwnerV0::from_core_config(&config, sender)
            .expect("context");
        let bytes = frame(&config, sender, 7, hash);
        let accepted = owner
            .accept_sync_info_v0(&bytes, hash)
            .expect("exact frame accepted");
        assert_eq!(accepted.body(), b"sync-info-body");
        assert_eq!(accepted.sender_sequence(), 7);
        assert_eq!(owner.last_sender_sequence(), Some(7));
    }

    #[test]
    fn foreign_scope_and_hash_fail_without_consuming_sequence() {
        let config = config();
        let sender = [0x22; 32];
        let hash = [0x33; 32];
        let mut owner = PocoNodeStateSyncWireIngressOwnerV0::from_core_config(&config, sender)
            .expect("context");
        let foreign = frame(&config, [0x23; 32], 7, hash);
        assert!(matches!(
            owner.accept_sync_info_v0(&foreign, hash),
            Err(PocoNodeStateSyncWireIngressErrorV0::ScopeMismatch(
                PocoNodeStateSyncWireIngressFieldV0::SenderNodeId
            ))
        ));
        let wrong_hash = frame(&config, sender, 7, [0x34; 32]);
        assert!(matches!(
            owner.accept_sync_info_v0(&wrong_hash, hash),
            Err(PocoNodeStateSyncWireIngressErrorV0::BodySemanticHashMismatch)
        ));
        assert_eq!(owner.last_sender_sequence(), None);
        owner
            .accept_sync_info_v0(&frame(&config, sender, 7, hash), hash)
            .expect("valid retry remains admissible");
    }

    #[test]
    fn sequence_replay_and_consensus_kind_fail_closed() {
        let config = config();
        let sender = [0x22; 32];
        let hash = [0x33; 32];
        let mut owner = PocoNodeStateSyncWireIngressOwnerV0::from_core_config(&config, sender)
            .expect("context");
        let first = frame(&config, sender, 9, hash);
        owner
            .accept_sync_info_v0(&first, hash)
            .expect("first frame accepted");
        assert!(matches!(
            owner.accept_sync_info_v0(&first, hash),
            Err(PocoNodeStateSyncWireIngressErrorV0::SenderSequenceReplay {
                previous: 9,
                received: 9
            })
        ));

        let mut consensus_kind = frame(&config, sender, 10, hash);
        let kind = field_varint(10, 0);
        let position = consensus_kind
            .windows(kind.len())
            .position(|window| window == kind.as_slice())
            .expect("has false kind");
        consensus_kind.splice(position..position + kind.len(), field_varint(10, 1));
        assert!(matches!(
            owner.accept_sync_info_v0(&consensus_kind, hash),
            Err(PocoNodeStateSyncWireIngressErrorV0::Wire(error))
                if error.code()
                    == trnm_consensus_types::WireEnvelopeDecodeErrorCode::MissingField
        ));
        assert_eq!(owner.last_sender_sequence(), Some(9));
    }
}
