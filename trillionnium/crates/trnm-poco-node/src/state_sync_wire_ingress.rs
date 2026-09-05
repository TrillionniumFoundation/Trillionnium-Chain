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
//! socket.  The base owner keeps sequence state process-local; the separate
//! candidate durable owner below adds an exact-pin append-only journal, but
//! authenticated P2P lease ownership, atomic lease-plus-append, and full
//! state-sync execution remain production blockers.

use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use sha2::{Digest, Sha256};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use trnm_consensus_core::CoreConfig;
use trnm_consensus_types::{
    decode_wire_envelope_v0_preflight, WireBodyKindV0, WireEnvelopeDecodeError,
    WireEnvelopePreflight,
};

/// This is a bounded composition seam, not a production network activation.
pub const STATE_SYNC_WIRE_INGRESS_RUNTIME_COMPOSITION_V0: bool = true;
pub const STATE_SYNC_WIRE_INGRESS_PRODUCTION_ACTIVATION_V0: bool = false;
pub const STATE_SYNC_WIRE_INGRESS_DURABLE_REPLAY_PROTECTION_V0: bool = false;
/// The durable owner below is a candidate-only typed gate.  It is deliberately
/// separate from the production activation flag because the lease authority
/// and sequence append are not one atomic operation yet.
pub const STATE_SYNC_WIRE_INGRESS_DURABLE_SEQUENCE_JOURNAL_CANDIDATE_V0: bool = true;
/// An explicit, trusted-pin-gated recovery path may discard only an
/// incomplete final journal frame after a power-loss-style torn append.  It is
/// deliberately separate from durable replay protection and remains
/// candidate-only until peer-lease ownership and the append are one atomic
/// authority transaction.
pub const STATE_SYNC_WIRE_INGRESS_DURABLE_CRASH_RECOVERY_CANDIDATE_V0: bool = true;

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

/// The minimum external lease facts which a durable state-sync sequence
/// journal accepts.  This is intentionally an opaque, typed copy of the
/// facts returned by the peer-lease authority; this crate does not own a
/// socket, call the lease daemon, or mint a lease.  A caller must obtain and
/// revalidate these facts through that authority before opening this owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeStateSyncWireIngressLeaseBindingV0 {
    session_id: [u8; 32],
    generation: u64,
    record_hash: [u8; 32],
}

impl PocoNodeStateSyncWireIngressLeaseBindingV0 {
    pub fn new(
        session_id: [u8; 32],
        generation: u64,
        record_hash: [u8; 32],
    ) -> Result<Self, PocoNodeStateSyncWireIngressDurableErrorV0> {
        if session_id == [0; 32] || generation == 0 || record_hash == [0; 32] {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidLeaseBinding);
        }
        Ok(Self {
            session_id,
            generation,
            record_hash,
        })
    }

    pub const fn session_id(self) -> [u8; 32] {
        self.session_id
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn record_hash(self) -> [u8; 32] {
        self.record_hash
    }

    fn digest_v0(self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"trnm.poco-node.state-sync-lease-binding.v0\0");
        hasher.update(self.session_id);
        hasher.update(self.generation.to_be_bytes());
        hasher.update(self.record_hash);
        hasher.finalize().into()
    }
}

/// Trusted reopen pin for the candidate sequence journal.  Reopen requires
/// this exact pin for an existing file; without an external pin, truncating a
/// valid prefix would be indistinguishable from a legitimate old journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoNodeStateSyncWireIngressJournalPinV0 {
    context_digest: [u8; 32],
    lease_binding_digest: [u8; 32],
    record_count: u64,
    last_sender_sequence: Option<u64>,
    head: [u8; 32],
}

impl PocoNodeStateSyncWireIngressJournalPinV0 {
    pub const fn record_count(self) -> u64 {
        self.record_count
    }

    pub const fn last_sender_sequence(self) -> Option<u64> {
        self.last_sender_sequence
    }

    pub const fn head(self) -> [u8; 32] {
        self.head
    }
}

/// Errors from the candidate durable sequence owner.  The error surface is
/// intentionally coarse so callers cannot turn filesystem detail into an
/// authority signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeStateSyncWireIngressDurableErrorV0 {
    Ingress(PocoNodeStateSyncWireIngressErrorV0),
    InvalidLeaseBinding,
    LeaseBindingMismatch,
    PinRequired,
    PinMismatch,
    Io,
    InvalidPath,
    Corrupt,
    Truncated,
    SequenceReplay { previous: u64, received: u64 },
    SequenceOverflow,
    TooLarge,
}

impl fmt::Display for PocoNodeStateSyncWireIngressDurableErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ingress(error) => error.fmt(formatter),
            Self::InvalidLeaseBinding => formatter.write_str("invalid state-sync lease binding"),
            Self::LeaseBindingMismatch => {
                formatter.write_str("state-sync lease binding differs from durable journal")
            }
            Self::PinRequired => formatter.write_str(
                "state-sync durable journal reopen requires an exact trusted head pin",
            ),
            Self::PinMismatch => {
                formatter.write_str("state-sync durable journal head differs from trusted pin")
            }
            Self::Io => formatter.write_str("state-sync durable journal I/O failed"),
            Self::InvalidPath => formatter.write_str("state-sync durable journal path is invalid"),
            Self::Corrupt => formatter.write_str("state-sync durable journal is corrupt"),
            Self::Truncated => formatter.write_str("state-sync durable journal is truncated"),
            Self::SequenceReplay { previous, received } => write!(
                formatter,
                "state-sync durable sequence is not increasing: previous={previous} received={received}"
            ),
            Self::SequenceOverflow => formatter.write_str("state-sync durable sequence overflow"),
            Self::TooLarge => formatter.write_str("state-sync durable journal exceeds its bound"),
        }
    }
}

impl Error for PocoNodeStateSyncWireIngressDurableErrorV0 {}

impl From<PocoNodeStateSyncWireIngressErrorV0> for PocoNodeStateSyncWireIngressDurableErrorV0 {
    fn from(value: PocoNodeStateSyncWireIngressErrorV0) -> Self {
        Self::Ingress(value)
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

    fn digest_v0(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"trnm.poco-node.state-sync-ingress-context.v0\0");
        hasher.update(self.genesis_hash);
        hasher.update((self.chain_id.len() as u32).to_be_bytes());
        hasher.update(self.chain_id.as_bytes());
        hasher.update(self.protocol_version.to_be_bytes());
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.validator_set_hash);
        hasher.update(self.consensus_parameters_hash);
        hasher.update(self.sender_node_id);
        hasher.finalize().into()
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
#[derive(Debug, PartialEq, Eq)]
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
        let frame = self.preflight_sync_info_v0(bytes, expected_body_semantic_hash)?;
        if let Some(previous) = self.last_sender_sequence {
            if frame.sender_sequence() <= previous {
                return Err(PocoNodeStateSyncWireIngressErrorV0::SenderSequenceReplay {
                    previous,
                    received: frame.sender_sequence(),
                });
            }
        }
        self.last_sender_sequence = Some(frame.sender_sequence());
        Ok(frame)
    }

    fn preflight_sync_info_v0<'a>(
        &self,
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

const STATE_SYNC_SEQUENCE_JOURNAL_MAGIC_V0: [u8; 8] = *b"TRNMSQJ1";
const STATE_SYNC_SEQUENCE_JOURNAL_VERSION_V0: u8 = 1;
const STATE_SYNC_SEQUENCE_JOURNAL_GENESIS_KIND_V0: u8 = 0;
const STATE_SYNC_SEQUENCE_JOURNAL_ENTRY_KIND_V0: u8 = 1;
const STATE_SYNC_SEQUENCE_JOURNAL_FRAME_BYTES_V0: usize = 212;
const STATE_SYNC_SEQUENCE_JOURNAL_MAX_ENTRIES_V0: u64 = 1_048_576;
#[cfg(unix)]
const STATE_SYNC_SEQUENCE_JOURNAL_PRIVATE_FILE_MODE_V0: u32 = 0o600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StateSyncSequencePathIdentityV0 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl StateSyncSequencePathIdentityV0 {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Self {}
        }
    }
}

/// One bounded, node-owned append-only sender-sequence journal.  It is kept
/// separate from the transaction/event WALs because a transport sequence has
/// no application commit semantics.  Existing-file reopen requires the exact
/// caller-held [`PocoNodeStateSyncWireIngressJournalPinV0`]; this is what makes
/// a valid-prefix rollback fail closed without pretending the peer-lease
/// daemon and this append are atomic.
#[derive(Debug)]
struct StateSyncSequenceJournalV0 {
    path: PathBuf,
    parent_file: File,
    file: File,
    parent_identity: StateSyncSequencePathIdentityV0,
    file_identity: StateSyncSequencePathIdentityV0,
    context_digest: [u8; 32],
    lease_binding_digest: [u8; 32],
    head: [u8; 32],
    record_count: u64,
    last_sender_sequence: Option<u64>,
    poisoned: bool,
}

impl StateSyncSequenceJournalV0 {
    fn open(
        path: impl AsRef<Path>,
        context_digest: [u8; 32],
        lease_binding: PocoNodeStateSyncWireIngressLeaseBindingV0,
        trusted_pin: Option<PocoNodeStateSyncWireIngressJournalPinV0>,
    ) -> Result<Self, PocoNodeStateSyncWireIngressDurableErrorV0> {
        if context_digest == [0; 32] {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath);
        }
        let path = path.as_ref().to_path_buf();
        let parent = path
            .parent()
            .ok_or(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath)?;
        let parent_metadata = fs::symlink_metadata(parent)
            .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath)?;
        if !parent_metadata.is_dir() {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath);
        }
        if !private_sequence_parent_v0(&parent_metadata) {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath);
        }
        let parent_file =
            File::open(parent).map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
        let parent_identity = StateSyncSequencePathIdentityV0::from_metadata(
            &parent_file
                .metadata()
                .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?,
        );
        let existing_metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    return Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath);
                }
                Some(metadata)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath),
        };
        let virgin = existing_metadata.is_none();
        let mut options = OpenOptions::new();
        options.read(true).write(true).append(true);
        if virgin {
            options.create_new(true);
        } else {
            options.create(false);
        }
        let file = options
            .open(&path)
            .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
        if virgin {
            set_private_sequence_file_v0(&file)?;
        }
        file.try_lock_exclusive()
            .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
        let file_metadata = file
            .metadata()
            .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
        if !private_sequence_file_v0(&file_metadata) {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath);
        }
        let file_identity = StateSyncSequencePathIdentityV0::from_metadata(&file_metadata);
        if existing_metadata.is_some_and(|metadata| {
            StateSyncSequencePathIdentityV0::from_metadata(&metadata) != file_identity
        }) || !path_binding_matches_v0(&path, parent_identity, file_identity)
        {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath);
        }
        if !virgin && file_metadata.len() == 0 {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::Truncated);
        }
        let lease_binding_digest = lease_binding.digest_v0();
        let mut journal = Self {
            path,
            parent_file,
            file,
            parent_identity,
            file_identity,
            context_digest,
            lease_binding_digest,
            head: [0; 32],
            record_count: 0,
            last_sender_sequence: None,
            poisoned: false,
        };
        if virgin {
            let frame = encode_state_sync_sequence_frame_v0(
                STATE_SYNC_SEQUENCE_JOURNAL_GENESIS_KIND_V0,
                context_digest,
                lease_binding_digest,
                0,
                [0; 32],
                [0; 32],
                [0; 32],
            );
            journal
                .file
                .write_all(&frame)
                .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
            journal
                .file
                .sync_all()
                .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
            journal
                .parent_file
                .sync_all()
                .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
        }
        journal.reload_v0()?;
        if !virgin {
            let trusted_pin =
                trusted_pin.ok_or(PocoNodeStateSyncWireIngressDurableErrorV0::PinRequired)?;
            if journal.pin_v0() != trusted_pin {
                return Err(PocoNodeStateSyncWireIngressDurableErrorV0::PinMismatch);
            }
        } else if trusted_pin.is_some() {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::PinMismatch);
        }
        Ok(journal)
    }

    const fn pin_v0(&self) -> PocoNodeStateSyncWireIngressJournalPinV0 {
        PocoNodeStateSyncWireIngressJournalPinV0 {
            context_digest: self.context_digest,
            lease_binding_digest: self.lease_binding_digest,
            record_count: self.record_count,
            last_sender_sequence: self.last_sender_sequence,
            head: self.head,
        }
    }

    fn append_frame_v0(
        &mut self,
        frame: PocoNodeStateSyncWireFrameV0<'_>,
    ) -> Result<(), PocoNodeStateSyncWireIngressDurableErrorV0> {
        if self.poisoned {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::Corrupt);
        }
        if self.record_count >= STATE_SYNC_SEQUENCE_JOURNAL_MAX_ENTRIES_V0 {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::TooLarge);
        }
        if self
            .last_sender_sequence
            .is_some_and(|previous| frame.sender_sequence() <= previous)
        {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::SequenceReplay {
                previous: self.last_sender_sequence.expect("checked above"),
                received: frame.sender_sequence(),
            });
        }
        let message_digest = digest_bytes_v0(
            b"trnm.poco-node.state-sync-message-id.v0\0",
            frame.message_id(),
        );
        let encoded = encode_state_sync_sequence_frame_v0(
            STATE_SYNC_SEQUENCE_JOURNAL_ENTRY_KIND_V0,
            self.context_digest,
            self.lease_binding_digest,
            frame.sender_sequence(),
            message_digest,
            frame.body_semantic_hash(),
            self.head,
        );
        self.file
            .write_all(&encoded)
            .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
        self.file
            .sync_all()
            .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
        self.parent_file
            .sync_all()
            .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
        if !path_binding_matches_v0(&self.path, self.parent_identity, self.file_identity) {
            self.poisoned = true;
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath);
        }
        if let Err(error) = self.reload_v0() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn reload_v0(&mut self) -> Result<(), PocoNodeStateSyncWireIngressDurableErrorV0> {
        if !path_binding_matches_v0(&self.path, self.parent_identity, self.file_identity) {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath);
        }
        let maximum_bytes = (STATE_SYNC_SEQUENCE_JOURNAL_MAX_ENTRIES_V0 + 1)
            .checked_mul(STATE_SYNC_SEQUENCE_JOURNAL_FRAME_BYTES_V0 as u64)
            .ok_or(PocoNodeStateSyncWireIngressDurableErrorV0::TooLarge)?;
        let file_len = self
            .file
            .metadata()
            .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?
            .len();
        if file_len > maximum_bytes {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::TooLarge);
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut self.file)
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
        if bytes.len() as u64 > maximum_bytes {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::TooLarge);
        }
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
        let (head, record_count, last_sender_sequence) = parse_state_sync_sequence_bytes_v0(
            &bytes,
            self.context_digest,
            self.lease_binding_digest,
        )?;
        self.head = head;
        self.record_count = record_count;
        self.last_sender_sequence = last_sender_sequence;
        Ok(())
    }
}

/// Parse one complete sequence journal image without mutating a live owner.
///
/// Keeping this parser independent from the file descriptor is important for
/// crash recovery: the recovery path must authenticate the complete prefix
/// against the caller's trusted pin before it is allowed to truncate a torn
/// final frame.
fn parse_state_sync_sequence_bytes_v0(
    bytes: &[u8],
    context_digest: [u8; 32],
    lease_binding_digest: [u8; 32],
) -> Result<([u8; 32], u64, Option<u64>), PocoNodeStateSyncWireIngressDurableErrorV0> {
    if bytes.is_empty() {
        return Err(PocoNodeStateSyncWireIngressDurableErrorV0::Truncated);
    }
    if !bytes
        .len()
        .is_multiple_of(STATE_SYNC_SEQUENCE_JOURNAL_FRAME_BYTES_V0)
    {
        return Err(PocoNodeStateSyncWireIngressDurableErrorV0::Truncated);
    }
    let frame_count = bytes.len() / STATE_SYNC_SEQUENCE_JOURNAL_FRAME_BYTES_V0;
    if frame_count == 0 || frame_count - 1 > STATE_SYNC_SEQUENCE_JOURNAL_MAX_ENTRIES_V0 as usize {
        return Err(PocoNodeStateSyncWireIngressDurableErrorV0::TooLarge);
    }
    let mut head = [0; 32];
    let mut last_sequence = None;
    for (index, chunk) in bytes
        .chunks_exact(STATE_SYNC_SEQUENCE_JOURNAL_FRAME_BYTES_V0)
        .enumerate()
    {
        let kind = chunk[9];
        if chunk[..8] != STATE_SYNC_SEQUENCE_JOURNAL_MAGIC_V0
            || chunk[8] != STATE_SYNC_SEQUENCE_JOURNAL_VERSION_V0
            || chunk[10..12] != [0, 0]
        {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::Corrupt);
        }
        if chunk[12..44] != context_digest {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::Corrupt);
        }
        if chunk[44..76] != lease_binding_digest {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::LeaseBindingMismatch);
        }
        if chunk[148..180] != head
            || chunk[180..] != state_sync_sequence_frame_digest_v0(&chunk[..180])
        {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::Corrupt);
        }
        let sequence = u64::from_be_bytes(
            chunk[76..84]
                .try_into()
                .expect("fixed sequence journal field"),
        );
        if index == 0 {
            if kind != STATE_SYNC_SEQUENCE_JOURNAL_GENESIS_KIND_V0
                || sequence != 0
                || chunk[84..148] != [0; 64]
                || head != [0; 32]
            {
                return Err(PocoNodeStateSyncWireIngressDurableErrorV0::Corrupt);
            }
        } else {
            if kind != STATE_SYNC_SEQUENCE_JOURNAL_ENTRY_KIND_V0
                || last_sequence.is_some_and(|previous| sequence <= previous)
                || chunk[84..148] == [0; 64]
            {
                return Err(PocoNodeStateSyncWireIngressDurableErrorV0::Corrupt);
            }
            last_sequence = Some(sequence);
        }
        head = chunk[180..].try_into().expect("fixed frame digest");
    }
    Ok((head, (frame_count - 1) as u64, last_sequence))
}

/// Remove one torn final frame only after the complete prefix is authenticated
/// by an exact external pin.  This is a candidate recovery helper, not an
/// automatic rollback mechanism: callers must deliberately opt into it after
/// a process-crash/power-loss classification and hold the same trusted pin
/// that was persisted before the append began.
fn repair_state_sync_sequence_tail_v0(
    path: impl AsRef<Path>,
    context_digest: [u8; 32],
    lease_binding: PocoNodeStateSyncWireIngressLeaseBindingV0,
    trusted_pin: PocoNodeStateSyncWireIngressJournalPinV0,
) -> Result<(), PocoNodeStateSyncWireIngressDurableErrorV0> {
    if context_digest == [0; 32] {
        return Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath);
    }
    let path = path.as_ref().to_path_buf();
    let parent = path
        .parent()
        .ok_or(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath)?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath)?;
    if !parent_metadata.is_dir() || !private_sequence_parent_v0(&parent_metadata) {
        return Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath);
    }
    let parent_file =
        File::open(parent).map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
    let parent_identity = StateSyncSequencePathIdentityV0::from_metadata(
        &parent_file
            .metadata()
            .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?,
    );
    let file_metadata = fs::symlink_metadata(&path)
        .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath)?;
    if !file_metadata.is_file() || !private_sequence_file_v0(&file_metadata) {
        return Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath);
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
    file.try_lock_exclusive()
        .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
    let file_identity = StateSyncSequencePathIdentityV0::from_metadata(
        &file
            .metadata()
            .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?,
    );
    if StateSyncSequencePathIdentityV0::from_metadata(&file_metadata) != file_identity
        || !path_binding_matches_v0(&path, parent_identity, file_identity)
    {
        return Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath);
    }
    let maximum_bytes = (STATE_SYNC_SEQUENCE_JOURNAL_MAX_ENTRIES_V0 + 1)
        .checked_mul(STATE_SYNC_SEQUENCE_JOURNAL_FRAME_BYTES_V0 as u64)
        .ok_or(PocoNodeStateSyncWireIngressDurableErrorV0::TooLarge)?;
    let file_len = file
        .metadata()
        .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?
        .len();
    if file_len > maximum_bytes {
        return Err(PocoNodeStateSyncWireIngressDurableErrorV0::TooLarge);
    }
    let mut bytes = Vec::new();
    (&file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(PocoNodeStateSyncWireIngressDurableErrorV0::TooLarge);
    }
    let remainder = bytes.len() % STATE_SYNC_SEQUENCE_JOURNAL_FRAME_BYTES_V0;
    if remainder == 0 {
        return Err(PocoNodeStateSyncWireIngressDurableErrorV0::Truncated);
    }
    let prefix_len = bytes.len() - remainder;
    let lease_binding_digest = lease_binding.digest_v0();
    let (head, record_count, last_sender_sequence) = parse_state_sync_sequence_bytes_v0(
        &bytes[..prefix_len],
        context_digest,
        lease_binding_digest,
    )?;
    let prefix_pin = PocoNodeStateSyncWireIngressJournalPinV0 {
        context_digest,
        lease_binding_digest,
        record_count,
        last_sender_sequence,
        head,
    };
    if prefix_pin != trusted_pin {
        return Err(PocoNodeStateSyncWireIngressDurableErrorV0::PinMismatch);
    }
    file.set_len(prefix_len as u64)
        .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
    file.sync_all()
        .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
    parent_file
        .sync_all()
        .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)?;
    if !path_binding_matches_v0(&path, parent_identity, file_identity) {
        return Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath);
    }
    Ok(())
}

fn path_binding_matches_v0(
    path: &Path,
    parent_identity: StateSyncSequencePathIdentityV0,
    file_identity: StateSyncSequencePathIdentityV0,
) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(parent_metadata) = fs::symlink_metadata(parent) else {
        return false;
    };
    let Ok(file_metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    parent_metadata.is_dir()
        && file_metadata.is_file()
        && StateSyncSequencePathIdentityV0::from_metadata(&parent_metadata) == parent_identity
        && StateSyncSequencePathIdentityV0::from_metadata(&file_metadata) == file_identity
}

#[cfg(unix)]
fn private_sequence_parent_v0(metadata: &fs::Metadata) -> bool {
    metadata.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_sequence_parent_v0(_metadata: &fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn private_sequence_file_v0(metadata: &fs::Metadata) -> bool {
    metadata.nlink() == 1
        && metadata.permissions().mode() & 0o7777
            == STATE_SYNC_SEQUENCE_JOURNAL_PRIVATE_FILE_MODE_V0
}

#[cfg(not(unix))]
fn private_sequence_file_v0(_metadata: &fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn set_private_sequence_file_v0(
    file: &File,
) -> Result<(), PocoNodeStateSyncWireIngressDurableErrorV0> {
    file.set_permissions(fs::Permissions::from_mode(
        STATE_SYNC_SEQUENCE_JOURNAL_PRIVATE_FILE_MODE_V0,
    ))
    .map_err(|_| PocoNodeStateSyncWireIngressDurableErrorV0::Io)
}

#[cfg(not(unix))]
fn set_private_sequence_file_v0(
    _file: &File,
) -> Result<(), PocoNodeStateSyncWireIngressDurableErrorV0> {
    Ok(())
}

fn digest_bytes_v0(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn state_sync_sequence_frame_digest_v0(prefix: &[u8]) -> [u8; 32] {
    digest_bytes_v0(b"trnm.poco-node.state-sync-sequence-frame.v0\0", prefix)
}

fn encode_state_sync_sequence_frame_v0(
    kind: u8,
    context_digest: [u8; 32],
    lease_binding_digest: [u8; 32],
    sequence: u64,
    message_digest: [u8; 32],
    body_semantic_hash: [u8; 32],
    predecessor: [u8; 32],
) -> [u8; STATE_SYNC_SEQUENCE_JOURNAL_FRAME_BYTES_V0] {
    let mut frame = [0u8; STATE_SYNC_SEQUENCE_JOURNAL_FRAME_BYTES_V0];
    frame[..8].copy_from_slice(&STATE_SYNC_SEQUENCE_JOURNAL_MAGIC_V0);
    frame[8] = STATE_SYNC_SEQUENCE_JOURNAL_VERSION_V0;
    frame[9] = kind;
    frame[12..44].copy_from_slice(&context_digest);
    frame[44..76].copy_from_slice(&lease_binding_digest);
    frame[76..84].copy_from_slice(&sequence.to_be_bytes());
    frame[84..116].copy_from_slice(&message_digest);
    frame[116..148].copy_from_slice(&body_semantic_hash);
    frame[148..180].copy_from_slice(&predecessor);
    let digest = state_sync_sequence_frame_digest_v0(&frame[..180]);
    frame[180..].copy_from_slice(&digest);
    frame
}

/// Candidate-only durable state-sync ingress owner.  It binds the existing
/// borrowed `WireEnvelope` fence to a node-owned sequence journal and an
/// externally supplied lease token fact.  No lease daemon, network socket,
/// nested state-sync decoder, Core input, or application effect is exposed.
#[derive(Debug)]
pub struct PocoNodeStateSyncWireIngressDurableOwnerV0 {
    owner: PocoNodeStateSyncWireIngressOwnerV0,
    journal: StateSyncSequenceJournalV0,
    lease_binding: PocoNodeStateSyncWireIngressLeaseBindingV0,
}

impl PocoNodeStateSyncWireIngressDurableOwnerV0 {
    pub fn open(
        path: impl AsRef<Path>,
        context: PocoNodeStateSyncWireIngressContextV0,
        lease_binding: PocoNodeStateSyncWireIngressLeaseBindingV0,
        trusted_pin: Option<PocoNodeStateSyncWireIngressJournalPinV0>,
    ) -> Result<Self, PocoNodeStateSyncWireIngressDurableErrorV0> {
        let journal = StateSyncSequenceJournalV0::open(
            path,
            context.digest_v0(),
            lease_binding,
            trusted_pin,
        )?;
        let mut owner = PocoNodeStateSyncWireIngressOwnerV0::new(context)?;
        owner.last_sender_sequence = journal.last_sender_sequence;
        Ok(Self {
            owner,
            journal,
            lease_binding,
        })
    }

    /// Reopen after an explicitly classified crash/power-loss boundary.
    ///
    /// The normal [`Self::open`] path never repairs bytes.  This opt-in path
    /// first requires a torn (incomplete) final frame, authenticates every
    /// complete predecessor against the exact caller-held pin, truncates only
    /// that uncommitted tail, and fsyncs both the journal and its parent before
    /// doing a normal pinned reopen.  A complete extra frame, interior
    /// corruption, lease mismatch, or a stale pin remains fail-closed.
    pub fn open_after_crash_v0(
        path: impl AsRef<Path>,
        context: PocoNodeStateSyncWireIngressContextV0,
        lease_binding: PocoNodeStateSyncWireIngressLeaseBindingV0,
        trusted_pin: PocoNodeStateSyncWireIngressJournalPinV0,
    ) -> Result<Self, PocoNodeStateSyncWireIngressDurableErrorV0> {
        repair_state_sync_sequence_tail_v0(
            path.as_ref(),
            context.digest_v0(),
            lease_binding,
            trusted_pin,
        )?;
        Self::open(path, context, lease_binding, Some(trusted_pin))
    }

    pub const fn context(&self) -> &PocoNodeStateSyncWireIngressContextV0 {
        self.owner.context()
    }

    pub const fn lease_binding(&self) -> PocoNodeStateSyncWireIngressLeaseBindingV0 {
        self.lease_binding
    }

    pub const fn last_sender_sequence(&self) -> Option<u64> {
        self.journal.last_sender_sequence
    }

    pub const fn pin_v0(&self) -> PocoNodeStateSyncWireIngressJournalPinV0 {
        self.journal.pin_v0()
    }

    pub fn accept_sync_info_v0<'a>(
        &mut self,
        revalidated_lease_binding: PocoNodeStateSyncWireIngressLeaseBindingV0,
        bytes: &'a [u8],
        expected_body_semantic_hash: [u8; 32],
    ) -> Result<PocoNodeStateSyncWireFrameV0<'a>, PocoNodeStateSyncWireIngressDurableErrorV0> {
        if revalidated_lease_binding != self.lease_binding {
            return Err(PocoNodeStateSyncWireIngressDurableErrorV0::LeaseBindingMismatch);
        }
        let frame = self
            .owner
            .preflight_sync_info_v0(bytes, expected_body_semantic_hash)?;
        self.journal.append_frame_v0(frame)?;
        self.owner.last_sender_sequence = Some(frame.sender_sequence());
        Ok(frame)
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

    fn lease_binding() -> PocoNodeStateSyncWireIngressLeaseBindingV0 {
        PocoNodeStateSyncWireIngressLeaseBindingV0::new([0x51; 32], 1, [0x52; 32])
            .expect("lease binding")
    }

    fn private_journal_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("journal directory");
        #[cfg(unix)]
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private journal directory");
        directory
    }

    #[cfg(unix)]
    #[test]
    fn durable_sequence_rejects_non_private_parent_and_file_modes() {
        let config = config();
        let sender = [0x22; 32];
        let context = PocoNodeStateSyncWireIngressContextV0::from_core_config(&config, sender)
            .expect("context");
        let directory = tempfile::tempdir().expect("journal directory");
        let path = directory.path().join("state-sync-sequence.journal");
        let binding = lease_binding();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))
            .expect("shared parent fixture");
        assert!(matches!(
            PocoNodeStateSyncWireIngressDurableOwnerV0::open(&path, context.clone(), binding, None,),
            Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath)
        ));

        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private parent fixture");
        let owner =
            PocoNodeStateSyncWireIngressDurableOwnerV0::open(&path, context.clone(), binding, None)
                .expect("private journal");
        let pin = owner.pin_v0();
        drop(owner);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("shared file fixture");
        assert!(matches!(
            PocoNodeStateSyncWireIngressDurableOwnerV0::open(&path, context, binding, Some(pin),),
            Err(PocoNodeStateSyncWireIngressDurableErrorV0::InvalidPath)
        ));
    }

    #[test]
    fn durable_sequence_reopens_only_with_exact_pin_and_rejects_replay() {
        let config = config();
        let sender = [0x22; 32];
        let hash = [0x33; 32];
        let context = PocoNodeStateSyncWireIngressContextV0::from_core_config(&config, sender)
            .expect("context");
        let directory = private_journal_directory();
        let path = directory.path().join("state-sync-sequence.journal");
        let binding = lease_binding();
        let mut owner =
            PocoNodeStateSyncWireIngressDurableOwnerV0::open(&path, context.clone(), binding, None)
                .expect("fresh durable owner");
        owner
            .accept_sync_info_v0(binding, &frame(&config, sender, 7, hash), hash)
            .expect("first durable frame");
        let pin = owner.pin_v0();
        drop(owner);

        let mut reopened = PocoNodeStateSyncWireIngressDurableOwnerV0::open(
            &path,
            context.clone(),
            binding,
            Some(pin),
        )
        .expect("exact pinned reopen");
        assert_eq!(reopened.last_sender_sequence(), Some(7));
        assert!(matches!(
            reopened.accept_sync_info_v0(binding, &frame(&config, sender, 7, hash), hash),
            Err(PocoNodeStateSyncWireIngressDurableErrorV0::SequenceReplay {
                previous: 7,
                received: 7
            })
        ));
        reopened
            .accept_sync_info_v0(binding, &frame(&config, sender, 8, hash), hash)
            .expect("strictly newer durable frame");
    }

    #[test]
    fn durable_sequence_failed_ingress_does_not_append() {
        let config = config();
        let sender = [0x22; 32];
        let hash = [0x33; 32];
        let context = PocoNodeStateSyncWireIngressContextV0::from_core_config(&config, sender)
            .expect("context");
        let directory = private_journal_directory();
        let path = directory.path().join("state-sync-sequence.journal");
        let binding = lease_binding();
        let mut owner =
            PocoNodeStateSyncWireIngressDurableOwnerV0::open(&path, context.clone(), binding, None)
                .expect("fresh durable owner");
        let before = owner.pin_v0();
        assert!(matches!(
            owner.accept_sync_info_v0(binding, &frame(&config, sender, 7, [0x34; 32]), hash,),
            Err(PocoNodeStateSyncWireIngressDurableErrorV0::Ingress(
                PocoNodeStateSyncWireIngressErrorV0::BodySemanticHashMismatch
            ))
        ));
        assert_eq!(owner.pin_v0(), before);
        owner
            .accept_sync_info_v0(binding, &frame(&config, sender, 7, hash), hash)
            .expect("valid frame remains admissible");
    }

    #[test]
    fn durable_sequence_rejects_lease_change_and_valid_prefix_rollback() {
        let config = config();
        let sender = [0x22; 32];
        let hash = [0x33; 32];
        let context = PocoNodeStateSyncWireIngressContextV0::from_core_config(&config, sender)
            .expect("context");
        let directory = private_journal_directory();
        let path = directory.path().join("state-sync-sequence.journal");
        let binding = lease_binding();
        let mut owner =
            PocoNodeStateSyncWireIngressDurableOwnerV0::open(&path, context.clone(), binding, None)
                .expect("fresh durable owner");
        owner
            .accept_sync_info_v0(binding, &frame(&config, sender, 7, hash), hash)
            .expect("first durable frame");
        let first_pin = owner.pin_v0();
        owner
            .accept_sync_info_v0(binding, &frame(&config, sender, 8, hash), hash)
            .expect("second durable frame");
        let second_pin = owner.pin_v0();
        drop(owner);

        let changed_binding =
            PocoNodeStateSyncWireIngressLeaseBindingV0::new([0x51; 32], 2, [0x53; 32])
                .expect("changed binding");
        assert!(matches!(
            PocoNodeStateSyncWireIngressDurableOwnerV0::open(
                &path,
                context.clone(),
                changed_binding,
                Some(second_pin),
            ),
            Err(PocoNodeStateSyncWireIngressDurableErrorV0::LeaseBindingMismatch)
        ));

        let file = OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open journal for rollback fixture");
        file.set_len((STATE_SYNC_SEQUENCE_JOURNAL_FRAME_BYTES_V0 * 2) as u64)
            .expect("truncate to valid prefix");
        drop(file);
        assert!(matches!(
            PocoNodeStateSyncWireIngressDurableOwnerV0::open(
                &path,
                context.clone(),
                binding,
                Some(second_pin),
            ),
            Err(PocoNodeStateSyncWireIngressDurableErrorV0::PinMismatch)
        ));
        assert!(PocoNodeStateSyncWireIngressDurableOwnerV0::open(
            &path,
            context.clone(),
            binding,
            Some(first_pin),
        )
        .is_ok());
    }

    #[test]
    fn durable_sequence_rejects_tampered_frame_and_unpinned_reopen() {
        let config = config();
        let sender = [0x22; 32];
        let hash = [0x33; 32];
        let context = PocoNodeStateSyncWireIngressContextV0::from_core_config(&config, sender)
            .expect("context");
        let directory = private_journal_directory();
        let path = directory.path().join("state-sync-sequence.journal");
        let binding = lease_binding();
        let mut owner =
            PocoNodeStateSyncWireIngressDurableOwnerV0::open(&path, context.clone(), binding, None)
                .expect("fresh durable owner");
        owner
            .accept_sync_info_v0(binding, &frame(&config, sender, 7, hash), hash)
            .expect("durable frame");
        let pin = owner.pin_v0();
        drop(owner);

        assert!(matches!(
            PocoNodeStateSyncWireIngressDurableOwnerV0::open(&path, context.clone(), binding, None),
            Err(PocoNodeStateSyncWireIngressDurableErrorV0::PinRequired)
        ));
        let mut bytes = fs::read(&path).expect("read journal");
        bytes[STATE_SYNC_SEQUENCE_JOURNAL_FRAME_BYTES_V0 + 84] ^= 0x01;
        fs::write(&path, bytes).expect("tamper journal");
        assert!(matches!(
            PocoNodeStateSyncWireIngressDurableOwnerV0::open(&path, context, binding, Some(pin),),
            Err(PocoNodeStateSyncWireIngressDurableErrorV0::Corrupt)
        ));
    }

    #[test]
    fn durable_sequence_crash_recovery_discards_only_torn_tail_with_exact_pin() {
        let config = config();
        let sender = [0x22; 32];
        let hash = [0x33; 32];
        let context = PocoNodeStateSyncWireIngressContextV0::from_core_config(&config, sender)
            .expect("context");
        let directory = private_journal_directory();
        let path = directory.path().join("state-sync-sequence.journal");
        let binding = lease_binding();
        let mut owner =
            PocoNodeStateSyncWireIngressDurableOwnerV0::open(&path, context.clone(), binding, None)
                .expect("fresh durable owner");
        owner
            .accept_sync_info_v0(binding, &frame(&config, sender, 7, hash), hash)
            .expect("committed prefix frame");
        let trusted_pin = owner.pin_v0();
        drop(owner);

        // Simulate a power loss after part of the next fixed journal frame
        // reached stable storage.  The prefix is complete and authenticated,
        // but the tail is not a record which can be replayed.
        let next_wire = frame(&config, sender, 8, hash);
        let next_preflight =
            decode_wire_envelope_v0_preflight(&next_wire).expect("next wire preflight");
        let next_message_digest = digest_bytes_v0(
            b"trnm.poco-node.state-sync-message-id.v0\0",
            next_preflight.message_id(),
        );
        let torn = encode_state_sync_sequence_frame_v0(
            STATE_SYNC_SEQUENCE_JOURNAL_ENTRY_KIND_V0,
            context.digest_v0(),
            binding.digest_v0(),
            8,
            next_message_digest,
            hash,
            trusted_pin.head(),
        );
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open journal for torn append");
        file.write_all(&torn[..73]).expect("write torn tail");
        file.sync_all().expect("sync torn tail");
        drop(file);

        assert!(matches!(
            PocoNodeStateSyncWireIngressDurableOwnerV0::open(
                &path,
                context.clone(),
                binding,
                Some(trusted_pin),
            ),
            Err(PocoNodeStateSyncWireIngressDurableErrorV0::Truncated)
        ));

        let mut wrong_pin = trusted_pin;
        wrong_pin.head[0] ^= 1;
        assert!(matches!(
            PocoNodeStateSyncWireIngressDurableOwnerV0::open_after_crash_v0(
                &path,
                context.clone(),
                binding,
                wrong_pin,
            ),
            Err(PocoNodeStateSyncWireIngressDurableErrorV0::PinMismatch)
        ));

        let mut recovered = PocoNodeStateSyncWireIngressDurableOwnerV0::open_after_crash_v0(
            &path,
            context,
            binding,
            trusted_pin,
        )
        .expect("exact pin permits dropping only torn tail");
        assert_eq!(recovered.pin_v0(), trusted_pin);
        recovered
            .accept_sync_info_v0(binding, &next_wire, hash)
            .expect("next sequence remains admissible after recovery");
        assert_eq!(recovered.last_sender_sequence(), Some(8));
    }
}
