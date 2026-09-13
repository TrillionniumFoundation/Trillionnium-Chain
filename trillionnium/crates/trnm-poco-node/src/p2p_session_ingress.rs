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

use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use sha2::{Digest, Sha256};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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

/// Candidate-only durable handshake/session replay anchor.  The anchor is an
/// opt-in owner for callers which can provision a private persistent path;
/// `PocoNodeP2pSessionV0::open` remains the process-local compatibility path.
/// This boundary does not provide a socket, peer lease, Core input, or
/// production activation.
pub const P2P_SESSION_REPLAY_ANCHOR_CANDIDATE_V0: bool = true;
pub const P2P_SESSION_REPLAY_ANCHOR_PRODUCTION_ACTIVATION_V0: bool = false;

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
const DOMAIN_REPLAY_ANCHOR_CONTEXT_V0: &[u8] = b"trnm.poco.p2p.replay-anchor-context.v0\0";
const DOMAIN_REPLAY_ANCHOR_FRAME_V0: &[u8] = b"trnm.poco.p2p.replay-anchor-frame.v0\0";
const DOMAIN_REPLAY_ANCHOR_HEAD_V0: &[u8] = b"trnm.poco.p2p.replay-anchor-head.v0\0";

const REPLAY_ANCHOR_MAGIC_V0: [u8; 8] = *b"TRNMP2RA";
const REPLAY_ANCHOR_HEAD_MAGIC_V0: [u8; 8] = *b"TRNMP2HD";
const REPLAY_ANCHOR_VERSION_V0: u8 = 1;
const REPLAY_ANCHOR_GENESIS_KIND_V0: u8 = 0;
const REPLAY_ANCHOR_SESSION_KIND_V0: u8 = 1;
const REPLAY_ANCHOR_FRAME_BYTES_V0: usize = 172;
const REPLAY_ANCHOR_HEAD_BYTES_V0: usize = 84;
const REPLAY_ANCHOR_MAX_ENTRIES_V0: u64 = 1_048_576;
#[cfg(unix)]
const REPLAY_ANCHOR_PRIVATE_FILE_MODE_V0: u32 = 0o600;

type ReplayAnchorDecodedV0 = ([u8; HASH_BYTES_V0], u64, BTreeSet<[u8; HASH_BYTES_V0]>);

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
    SessionReplay,
    ReplayAnchor,
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
            Self::SessionReplay => "session_replay",
            Self::ReplayAnchor => "replay_anchor",
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

/// Errors returned by the candidate durable session replay anchor.  The
/// anchor deliberately has no recovery/repair operation: a damaged or
/// ambiguous journal is a hard stop for the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeP2pReplayAnchorErrorV0 {
    ContextMismatch,
    InvalidPath,
    Io,
    Corrupt,
    Truncated,
    SessionReplay,
    TooLarge,
}

impl fmt::Display for PocoNodeP2pReplayAnchorErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ContextMismatch => "P2P replay anchor context mismatch",
            Self::InvalidPath => "P2P replay anchor path is invalid",
            Self::Io => "P2P replay anchor I/O failure",
            Self::Corrupt => "P2P replay anchor is corrupt",
            Self::Truncated => "P2P replay anchor is truncated",
            Self::SessionReplay => "P2P handshake session was already anchored",
            Self::TooLarge => "P2P replay anchor exceeds its bound",
        })
    }
}

impl Error for PocoNodeP2pReplayAnchorErrorV0 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplayAnchorPathIdentityV0 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl ReplayAnchorPathIdentityV0 {
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

/// Candidate-only durable fence for authenticated P2P handshake sessions.
///
/// `PocoNodeP2pSessionV0::open` intentionally remains process-local for
/// compatibility.  Callers which need restart/cross-session replay safety
/// opt into [`PocoNodeP2pSessionV0::open_with_replay_anchor`].  This owner
/// records every accepted handshake session ID in a private, fsynced
/// append-only hash chain and publishes a separate fsynced head.  Reopening
/// after a process restart therefore rejects an old handshake before any data
/// frame can be admitted.  It does not replace an authenticated peer lease,
/// socket transport, Core/SafetyRules authority, or whole-node CAS.
#[derive(Debug)]
pub struct PocoNodeP2pReplayAnchorV0 {
    path: PathBuf,
    head_path: PathBuf,
    parent_file: File,
    file: File,
    parent_identity: ReplayAnchorPathIdentityV0,
    file_identity: ReplayAnchorPathIdentityV0,
    context_digest: [u8; HASH_BYTES_V0],
    peer_id: ValidatorId,
    head: [u8; HASH_BYTES_V0],
    record_count: u64,
    seen_sessions: BTreeSet<[u8; HASH_BYTES_V0]>,
    poisoned: bool,
}

impl PocoNodeP2pReplayAnchorV0 {
    /// Opens or creates a private replay anchor scoped to one validator set
    /// and one remote peer. Existing files are fully replayed and require a
    /// matching sidecar head; a prefix is rejected when the sidecar still
    /// proves the larger journal. This candidate anchor has no external
    /// monotonic anti-rollback authority if both files are restored together.
    pub fn open(
        path: impl AsRef<Path>,
        validator_set: &ValidatorSet,
        peer_id: ValidatorId,
    ) -> Result<Self, PocoNodeP2pReplayAnchorErrorV0> {
        validator_set
            .validate_shape()
            .map_err(|_| PocoNodeP2pReplayAnchorErrorV0::ContextMismatch)?;
        if validator_set.validator(peer_id).is_none() {
            return Err(PocoNodeP2pReplayAnchorErrorV0::ContextMismatch);
        }
        // The frozen transport envelope carries a fixed 32-byte node ID.
        // `ValidatorId` itself is a variable-length consensus identifier, so
        // reject a valid-but-non-wire-sized member before any fixed-frame
        // encoding can panic or silently truncate it.
        if peer_id.as_bytes().len() != MAX_PROTOBUF_WIRE_SENDER_NODE_ID_BYTES_V0 {
            return Err(PocoNodeP2pReplayAnchorErrorV0::ContextMismatch);
        }
        let path = path.as_ref().to_path_buf();
        let parent = path
            .parent()
            .ok_or(PocoNodeP2pReplayAnchorErrorV0::InvalidPath)?;
        let parent_metadata = fs::symlink_metadata(parent)
            .map_err(|_| PocoNodeP2pReplayAnchorErrorV0::InvalidPath)?;
        if !parent_metadata.is_dir() || !replay_anchor_private_parent_v0(&parent_metadata) {
            return Err(PocoNodeP2pReplayAnchorErrorV0::InvalidPath);
        }
        let parent_file = File::open(parent).map_err(|_| PocoNodeP2pReplayAnchorErrorV0::Io)?;
        let parent_identity = ReplayAnchorPathIdentityV0::from_metadata(
            &parent_file
                .metadata()
                .map_err(|_| PocoNodeP2pReplayAnchorErrorV0::Io)?,
        );
        let existing_metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() || !replay_anchor_private_file_v0(&metadata) {
                    return Err(PocoNodeP2pReplayAnchorErrorV0::InvalidPath);
                }
                Some(metadata)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(PocoNodeP2pReplayAnchorErrorV0::InvalidPath),
        };
        let virgin = existing_metadata.is_none();
        let mut options = OpenOptions::new();
        options.read(true).write(true).append(true);
        if virgin {
            options.create_new(true);
            #[cfg(unix)]
            options.mode(REPLAY_ANCHOR_PRIVATE_FILE_MODE_V0);
        } else {
            options.create(false);
        }
        let file = options
            .open(&path)
            .map_err(|_| PocoNodeP2pReplayAnchorErrorV0::Io)?;
        if virgin {
            set_replay_anchor_private_file_v0(&file)?;
        }
        file.try_lock_exclusive()
            .map_err(|_| PocoNodeP2pReplayAnchorErrorV0::Io)?;
        let file_metadata = file
            .metadata()
            .map_err(|_| PocoNodeP2pReplayAnchorErrorV0::Io)?;
        if !replay_anchor_private_file_v0(&file_metadata) {
            return Err(PocoNodeP2pReplayAnchorErrorV0::InvalidPath);
        }
        let file_identity = ReplayAnchorPathIdentityV0::from_metadata(&file_metadata);
        if existing_metadata.is_some_and(|metadata| {
            ReplayAnchorPathIdentityV0::from_metadata(&metadata) != file_identity
        }) || !replay_anchor_path_binding_matches_v0(&path, parent_identity, file_identity)
        {
            return Err(PocoNodeP2pReplayAnchorErrorV0::InvalidPath);
        }
        if !virgin && file_metadata.len() == 0 {
            return Err(PocoNodeP2pReplayAnchorErrorV0::Truncated);
        }
        let head_path = replay_anchor_head_path_v0(&path)?;
        if virgin && fs::symlink_metadata(&head_path).is_ok() {
            return Err(PocoNodeP2pReplayAnchorErrorV0::InvalidPath);
        }
        let mut anchor = Self {
            path,
            head_path,
            parent_file,
            file,
            parent_identity,
            file_identity,
            context_digest: replay_anchor_context_digest_v0(validator_set, peer_id),
            peer_id,
            head: [0; HASH_BYTES_V0],
            record_count: 0,
            seen_sessions: BTreeSet::new(),
            poisoned: false,
        };
        if virgin {
            let genesis = encode_replay_anchor_frame_v0(
                REPLAY_ANCHOR_GENESIS_KIND_V0,
                anchor.context_digest,
                peer_id,
                [0; HASH_BYTES_V0],
                [0; HASH_BYTES_V0],
            );
            anchor
                .file
                .write_all(&genesis)
                .map_err(|_| PocoNodeP2pReplayAnchorErrorV0::Io)?;
            anchor
                .file
                .sync_all()
                .map_err(|_| PocoNodeP2pReplayAnchorErrorV0::Io)?;
            anchor
                .parent_file
                .sync_all()
                .map_err(|_| PocoNodeP2pReplayAnchorErrorV0::Io)?;
        }
        anchor.reload_v0()?;
        anchor.reconcile_head_v0(virgin)?;
        Ok(anchor)
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub const fn peer_id(&self) -> ValidatorId {
        self.peer_id
    }

    pub const fn context_digest(&self) -> [u8; HASH_BYTES_V0] {
        self.context_digest
    }

    pub const fn head(&self) -> [u8; HASH_BYTES_V0] {
        self.head
    }

    pub const fn record_count(&self) -> u64 {
        self.record_count
    }

    pub fn contains_session(&self, session_id: [u8; HASH_BYTES_V0]) -> bool {
        self.seen_sessions.contains(&session_id)
    }

    /// Durably reserves one authenticated handshake session ID.  A duplicate
    /// is rejected even if the original process has exited and the owner has
    /// been reopened by a new process.
    fn reserve_session(
        &mut self,
        session_id: [u8; HASH_BYTES_V0],
    ) -> Result<(), PocoNodeP2pReplayAnchorErrorV0> {
        if self.poisoned {
            return Err(PocoNodeP2pReplayAnchorErrorV0::Corrupt);
        }
        // Re-read the authenticated journal before every reservation.  This
        // closes the in-process TOCTOU where an external rollback/tamper could
        // otherwise leave a live owner using a stale in-memory head.
        let expected_head = self.head;
        let expected_count = self.record_count;
        if let Err(error) = self.reload_v0() {
            self.poisoned = true;
            return Err(error);
        }
        if self.head != expected_head || self.record_count != expected_count {
            self.poisoned = true;
            return Err(PocoNodeP2pReplayAnchorErrorV0::Corrupt);
        }
        if session_id == [0; HASH_BYTES_V0] {
            return Err(PocoNodeP2pReplayAnchorErrorV0::ContextMismatch);
        }
        if self.seen_sessions.contains(&session_id) {
            return Err(PocoNodeP2pReplayAnchorErrorV0::SessionReplay);
        }
        if self.record_count >= REPLAY_ANCHOR_MAX_ENTRIES_V0 {
            return Err(PocoNodeP2pReplayAnchorErrorV0::TooLarge);
        }
        let frame = encode_replay_anchor_frame_v0(
            REPLAY_ANCHOR_SESSION_KIND_V0,
            self.context_digest,
            self.peer_id,
            session_id,
            self.head,
        );
        if self.file.write_all(&frame).is_err()
            || self.file.sync_all().is_err()
            || self.parent_file.sync_all().is_err()
        {
            self.poisoned = true;
            return Err(PocoNodeP2pReplayAnchorErrorV0::Io);
        }
        if !replay_anchor_path_binding_matches_v0(
            &self.path,
            self.parent_identity,
            self.file_identity,
        ) {
            self.poisoned = true;
            return Err(PocoNodeP2pReplayAnchorErrorV0::InvalidPath);
        }
        self.head = replay_anchor_frame_digest_v0(&frame[..140]);
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or(PocoNodeP2pReplayAnchorErrorV0::TooLarge)?;
        self.seen_sessions.insert(session_id);
        if self.persist_head_v0().is_err() {
            self.poisoned = true;
            return Err(PocoNodeP2pReplayAnchorErrorV0::Io);
        }
        Ok(())
    }

    fn reload_v0(&mut self) -> Result<(), PocoNodeP2pReplayAnchorErrorV0> {
        if !replay_anchor_path_binding_matches_v0(
            &self.path,
            self.parent_identity,
            self.file_identity,
        ) {
            return Err(PocoNodeP2pReplayAnchorErrorV0::InvalidPath);
        }
        let maximum_bytes = (REPLAY_ANCHOR_MAX_ENTRIES_V0 + 1)
            .checked_mul(REPLAY_ANCHOR_FRAME_BYTES_V0 as u64)
            .ok_or(PocoNodeP2pReplayAnchorErrorV0::TooLarge)?;
        let file_len = self
            .file
            .metadata()
            .map_err(|_| PocoNodeP2pReplayAnchorErrorV0::Io)?
            .len();
        if file_len > maximum_bytes {
            return Err(PocoNodeP2pReplayAnchorErrorV0::TooLarge);
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| PocoNodeP2pReplayAnchorErrorV0::Io)?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut self.file)
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| PocoNodeP2pReplayAnchorErrorV0::Io)?;
        if bytes.len() as u64 > maximum_bytes {
            return Err(PocoNodeP2pReplayAnchorErrorV0::TooLarge);
        }
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|_| PocoNodeP2pReplayAnchorErrorV0::Io)?;
        let (head, record_count, seen_sessions) =
            parse_replay_anchor_bytes_v0(&bytes, self.context_digest, self.peer_id)?;
        self.head = head;
        self.record_count = record_count;
        self.seen_sessions = seen_sessions;
        Ok(())
    }

    fn reconcile_head_v0(&self, virgin: bool) -> Result<(), PocoNodeP2pReplayAnchorErrorV0> {
        let anchored = match read_replay_anchor_head_v0(&self.head_path) {
            Ok(value) => Some(value),
            Err(PocoNodeP2pReplayAnchorErrorV0::Io) if !self.head_path.exists() && virgin => None,
            Err(error) => return Err(error),
        };
        match anchored {
            None if virgin && self.record_count == 0 => self.persist_head_v0(),
            None => Err(PocoNodeP2pReplayAnchorErrorV0::Corrupt),
            Some((count, _head)) if count > self.record_count => {
                Err(PocoNodeP2pReplayAnchorErrorV0::Corrupt)
            }
            Some((count, head)) if count == self.record_count && head != self.head => {
                Err(PocoNodeP2pReplayAnchorErrorV0::Corrupt)
            }
            Some((count, _)) if count < self.record_count => self.persist_head_v0(),
            Some(_) => Ok(()),
        }
    }

    fn persist_head_v0(&self) -> Result<(), PocoNodeP2pReplayAnchorErrorV0> {
        if !replay_anchor_path_binding_matches_v0(
            &self.path,
            self.parent_identity,
            self.file_identity,
        ) {
            return Err(PocoNodeP2pReplayAnchorErrorV0::InvalidPath);
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.head_path) {
            if !metadata.is_file() || !replay_anchor_private_file_v0(&metadata) {
                return Err(PocoNodeP2pReplayAnchorErrorV0::InvalidPath);
            }
        }
        let name = self
            .head_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(PocoNodeP2pReplayAnchorErrorV0::InvalidPath)?;
        let temporary = self.head_path.with_file_name(format!(
            ".{name}.tmp-{}-{}",
            std::process::id(),
            self.record_count
        ));
        let bytes = encode_replay_anchor_head_v0(self.record_count, self.head);
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                options.mode(REPLAY_ANCHOR_PRIVATE_FILE_MODE_V0);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.head_path)?;
            self.parent_file.sync_all()?;
            Ok::<(), std::io::Error>(())
        })();
        if let Err(_error) = result {
            let _ = fs::remove_file(&temporary);
            return Err(PocoNodeP2pReplayAnchorErrorV0::Io);
        }
        Ok(())
    }
}

fn parse_replay_anchor_bytes_v0(
    bytes: &[u8],
    context_digest: [u8; HASH_BYTES_V0],
    peer_id: ValidatorId,
) -> Result<ReplayAnchorDecodedV0, PocoNodeP2pReplayAnchorErrorV0> {
    if bytes.is_empty() {
        return Err(PocoNodeP2pReplayAnchorErrorV0::Truncated);
    }
    if !bytes.len().is_multiple_of(REPLAY_ANCHOR_FRAME_BYTES_V0) {
        return Err(PocoNodeP2pReplayAnchorErrorV0::Truncated);
    }
    let frame_count = bytes.len() / REPLAY_ANCHOR_FRAME_BYTES_V0;
    if frame_count == 0 || frame_count - 1 > REPLAY_ANCHOR_MAX_ENTRIES_V0 as usize {
        return Err(PocoNodeP2pReplayAnchorErrorV0::TooLarge);
    }
    let mut head = [0; HASH_BYTES_V0];
    let mut record_count = 0u64;
    let mut seen_sessions = BTreeSet::new();
    for (index, frame) in bytes.chunks_exact(REPLAY_ANCHOR_FRAME_BYTES_V0).enumerate() {
        if frame[..8] != REPLAY_ANCHOR_MAGIC_V0
            || frame[8] != REPLAY_ANCHOR_VERSION_V0
            || frame[10..12] != [0, 0]
        {
            return Err(PocoNodeP2pReplayAnchorErrorV0::Corrupt);
        }
        if &frame[12..44] != context_digest.as_slice() || &frame[44..76] != peer_id.as_bytes() {
            return Err(PocoNodeP2pReplayAnchorErrorV0::ContextMismatch);
        }
        let stored_digest: [u8; HASH_BYTES_V0] = frame[140..172]
            .try_into()
            .expect("fixed replay anchor digest");
        if stored_digest != replay_anchor_frame_digest_v0(&frame[..140]) {
            return Err(PocoNodeP2pReplayAnchorErrorV0::Corrupt);
        }
        let session_id: [u8; HASH_BYTES_V0] = frame[76..108]
            .try_into()
            .expect("fixed replay anchor session");
        let predecessor: [u8; HASH_BYTES_V0] = frame[108..140]
            .try_into()
            .expect("fixed replay anchor predecessor");
        if index == 0 {
            if frame[9] != REPLAY_ANCHOR_GENESIS_KIND_V0
                || session_id != [0; HASH_BYTES_V0]
                || predecessor != [0; HASH_BYTES_V0]
            {
                return Err(PocoNodeP2pReplayAnchorErrorV0::Corrupt);
            }
        } else {
            if frame[9] != REPLAY_ANCHOR_SESSION_KIND_V0
                || session_id == [0; HASH_BYTES_V0]
                || predecessor != head
                || !seen_sessions.insert(session_id)
            {
                return Err(PocoNodeP2pReplayAnchorErrorV0::Corrupt);
            }
            record_count = record_count
                .checked_add(1)
                .ok_or(PocoNodeP2pReplayAnchorErrorV0::TooLarge)?;
        }
        head = stored_digest;
    }
    Ok((head, record_count, seen_sessions))
}

fn encode_replay_anchor_frame_v0(
    kind: u8,
    context_digest: [u8; HASH_BYTES_V0],
    peer_id: ValidatorId,
    session_id: [u8; HASH_BYTES_V0],
    predecessor: [u8; HASH_BYTES_V0],
) -> [u8; REPLAY_ANCHOR_FRAME_BYTES_V0] {
    let mut frame = [0u8; REPLAY_ANCHOR_FRAME_BYTES_V0];
    frame[..8].copy_from_slice(&REPLAY_ANCHOR_MAGIC_V0);
    frame[8] = REPLAY_ANCHOR_VERSION_V0;
    frame[9] = kind;
    frame[12..44].copy_from_slice(&context_digest);
    frame[44..76].copy_from_slice(peer_id.as_bytes());
    frame[76..108].copy_from_slice(&session_id);
    frame[108..140].copy_from_slice(&predecessor);
    let digest = replay_anchor_frame_digest_v0(&frame[..140]);
    frame[140..].copy_from_slice(&digest);
    frame
}

fn replay_anchor_frame_digest_v0(prefix: &[u8]) -> [u8; HASH_BYTES_V0] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_REPLAY_ANCHOR_FRAME_V0);
    hasher.update((prefix.len() as u64).to_be_bytes());
    hasher.update(prefix);
    hasher.finalize().into()
}

fn encode_replay_anchor_head_v0(
    record_count: u64,
    head: [u8; HASH_BYTES_V0],
) -> [u8; REPLAY_ANCHOR_HEAD_BYTES_V0] {
    let mut bytes = [0u8; REPLAY_ANCHOR_HEAD_BYTES_V0];
    bytes[..8].copy_from_slice(&REPLAY_ANCHOR_HEAD_MAGIC_V0);
    bytes[8] = REPLAY_ANCHOR_VERSION_V0;
    bytes[12..20].copy_from_slice(&record_count.to_be_bytes());
    bytes[20..52].copy_from_slice(&head);
    let digest = replay_anchor_head_digest_v0(&bytes[..52]);
    bytes[52..].copy_from_slice(&digest);
    bytes
}

fn read_replay_anchor_head_v0(
    path: &Path,
) -> Result<(u64, [u8; HASH_BYTES_V0]), PocoNodeP2pReplayAnchorErrorV0> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            PocoNodeP2pReplayAnchorErrorV0::Io
        } else {
            PocoNodeP2pReplayAnchorErrorV0::InvalidPath
        }
    })?;
    if !metadata.is_file() || !replay_anchor_private_file_v0(&metadata) {
        return Err(PocoNodeP2pReplayAnchorErrorV0::InvalidPath);
    }
    if metadata.len() != REPLAY_ANCHOR_HEAD_BYTES_V0 as u64 {
        return Err(PocoNodeP2pReplayAnchorErrorV0::Corrupt);
    }
    let bytes = fs::read(path).map_err(|_| PocoNodeP2pReplayAnchorErrorV0::Io)?;
    if bytes.len() != REPLAY_ANCHOR_HEAD_BYTES_V0 {
        return Err(PocoNodeP2pReplayAnchorErrorV0::Corrupt);
    }
    if bytes[..8] != REPLAY_ANCHOR_HEAD_MAGIC_V0
        || bytes[8] != REPLAY_ANCHOR_VERSION_V0
        || bytes[9..12] != [0, 0, 0]
        || bytes[52..] != replay_anchor_head_digest_v0(&bytes[..52])
    {
        return Err(PocoNodeP2pReplayAnchorErrorV0::Corrupt);
    }
    let count = u64::from_be_bytes(bytes[12..20].try_into().expect("fixed replay head count"));
    let head = bytes[20..52].try_into().expect("fixed replay anchor head");
    Ok((count, head))
}

fn replay_anchor_head_digest_v0(prefix: &[u8]) -> [u8; HASH_BYTES_V0] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_REPLAY_ANCHOR_HEAD_V0);
    hasher.update((prefix.len() as u64).to_be_bytes());
    hasher.update(prefix);
    hasher.finalize().into()
}

fn replay_anchor_context_digest_v0(
    validator_set: &ValidatorSet,
    peer_id: ValidatorId,
) -> [u8; HASH_BYTES_V0] {
    let chain_id_value = validator_set.chain_id();
    let chain_id = chain_id_value.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_REPLAY_ANCHOR_CONTEXT_V0);
    hasher.update(validator_set.protocol_version().get().to_be_bytes());
    hasher.update(validator_set.genesis_hash().as_bytes());
    hasher.update((chain_id.len() as u64).to_be_bytes());
    hasher.update(chain_id);
    hasher.update(validator_set.id().as_bytes());
    hasher.update(validator_set.consensus_parameters_hash().as_bytes());
    hasher.update(validator_set.epoch().get().to_be_bytes());
    hasher.update(peer_id.as_bytes());
    hasher.finalize().into()
}

fn replay_anchor_head_path_v0(path: &Path) -> Result<PathBuf, PocoNodeP2pReplayAnchorErrorV0> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(PocoNodeP2pReplayAnchorErrorV0::InvalidPath)?;
    Ok(path.with_file_name(format!(".{name}.head")))
}

fn replay_anchor_path_binding_matches_v0(
    path: &Path,
    parent_identity: ReplayAnchorPathIdentityV0,
    file_identity: ReplayAnchorPathIdentityV0,
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
        && replay_anchor_private_parent_v0(&parent_metadata)
        && file_metadata.is_file()
        && replay_anchor_private_file_v0(&file_metadata)
        && ReplayAnchorPathIdentityV0::from_metadata(&parent_metadata) == parent_identity
        && ReplayAnchorPathIdentityV0::from_metadata(&file_metadata) == file_identity
}

#[cfg(unix)]
fn replay_anchor_private_parent_v0(metadata: &fs::Metadata) -> bool {
    metadata.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn replay_anchor_private_parent_v0(_metadata: &fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn replay_anchor_private_file_v0(metadata: &fs::Metadata) -> bool {
    metadata.nlink() == 1
        && metadata.permissions().mode() & 0o7777 == REPLAY_ANCHOR_PRIVATE_FILE_MODE_V0
}

#[cfg(not(unix))]
fn replay_anchor_private_file_v0(_metadata: &fs::Metadata) -> bool {
    true
}

fn set_replay_anchor_private_file_v0(file: &File) -> Result<(), PocoNodeP2pReplayAnchorErrorV0> {
    #[cfg(unix)]
    {
        file.set_permissions(fs::Permissions::from_mode(
            REPLAY_ANCHOR_PRIVATE_FILE_MODE_V0,
        ))
        .map_err(|_| PocoNodeP2pReplayAnchorErrorV0::Io)
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(())
    }
}

/// One accepted, borrowed candidate frame.  Its nested consensus signatures
/// have passed the strict Ed25519 verifier used by the session, but it still
/// carries no Core input or network-send capability.
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

    /// Opens a session and durably reserves its authenticated handshake in a
    /// caller-owned replay anchor.  This opt-in candidate path is the narrow
    /// cross-session/restart fence: replaying the exact old handshake after a
    /// process restart fails before a data frame is exposed.  The anchor must
    /// have been opened for the same validator set and peer; it does not grant
    /// socket, lease, Core, SafetyRules, or broadcast authority.
    pub fn open_with_replay_anchor(
        handshake: &[u8],
        validator_set: &ValidatorSet,
        parameters: &ConsensusParametersV0,
        replay_anchor: &mut PocoNodeP2pReplayAnchorV0,
    ) -> Result<Self, PocoNodeP2pSessionErrorV0> {
        let session = Self::open(handshake, validator_set, parameters)?;
        if replay_anchor.peer_id != session.peer_id
            || replay_anchor.context_digest
                != replay_anchor_context_digest_v0(validator_set, session.peer_id)
        {
            return Err(err(P2pSessionIngressErrorCodeV0::ContextMismatch, 0));
        }
        replay_anchor
            .reserve_session(session.session_id)
            .map_err(map_replay_anchor_error_v0)?;
        Ok(session)
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
    /// applies the replay window only after semantic and nested cryptographic
    /// validation succeeds, and delegates the payload to the nested
    /// Vote/TimeoutVote/QC/TC decoder.
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
        // The nested semantic decoder is deliberately crypto-backend
        // neutral.  Crossing this authenticated peer boundary requires the
        // concrete strict Ed25519 profile to verify every Vote/TimeoutVote
        // share, including all shares in nested QCs and TC timeout entries,
        // before replay state can advance or the frame is exposed as
        // accepted evidence.
        proof
            .verify_signatures(&self.validator_set, &StrictEd25519Verifier)
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

fn map_replay_anchor_error_v0(error: PocoNodeP2pReplayAnchorErrorV0) -> PocoNodeP2pSessionErrorV0 {
    let code = match error {
        PocoNodeP2pReplayAnchorErrorV0::ContextMismatch => {
            P2pSessionIngressErrorCodeV0::ContextMismatch
        }
        PocoNodeP2pReplayAnchorErrorV0::SessionReplay => {
            P2pSessionIngressErrorCodeV0::SessionReplay
        }
        PocoNodeP2pReplayAnchorErrorV0::InvalidPath
        | PocoNodeP2pReplayAnchorErrorV0::Io
        | PocoNodeP2pReplayAnchorErrorV0::Corrupt
        | PocoNodeP2pReplayAnchorErrorV0::Truncated
        | PocoNodeP2pReplayAnchorErrorV0::TooLarge => P2pSessionIngressErrorCodeV0::ReplayAnchor,
    };
    err(code, 0)
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
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use trnm_consensus_types::{
        BlockId, CanonicalSignable, ChainId, ConsensusPublicKey, Epoch, Height, MessageKind,
        ProtocolVersion, QcRef, QuorumCertificate, TimeoutCertificateV0, TimeoutEntryV0,
        TimeoutVote, Validator, View, Vote, VotingPower, WireSemanticBodyKindV0,
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

    fn signed_handshake_with_nonce(
        set: &ValidatorSet,
        key: &SigningKey,
        peer: ValidatorId,
        nonce: [u8; 32],
    ) -> Vec<u8> {
        let unsigned = handshake_unsigned(set, peer, key.verifying_key().to_bytes(), nonce);
        let sig = key
            .sign(handshake_signing_root(&unsigned).as_bytes())
            .to_bytes();
        let mut bytes = unsigned;
        tlv(&mut bytes, 9, &sig);
        bytes
    }

    fn signed_handshake(set: &ValidatorSet, key: &SigningKey, peer: ValidatorId) -> Vec<u8> {
        signed_handshake_with_nonce(set, key, peer, [0xA5; 32])
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

    fn signature_share(author: ValidatorId, signature: &[u8; SIGNATURE_BYTES]) -> Vec<u8> {
        let mut bytes = Vec::new();
        pfield_bytes(&mut bytes, 1, author.as_bytes());
        pfield_bytes(&mut bytes, 2, signature);
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

    fn qc_body(set: &ValidatorSet, certificate: &QuorumCertificate) -> Vec<u8> {
        let mut bytes = scope_prefix(set);
        pfield_varint(&mut bytes, 8, certificate.view().get());
        pfield_varint(&mut bytes, 9, certificate.height().get());
        pfield_bytes(&mut bytes, 10, certificate.block_id().as_bytes());
        for vote in certificate.votes() {
            pfield_bytes(
                &mut bytes,
                11,
                &signature_share(vote.author(), vote.signature().as_bytes()),
            );
        }
        pfield_bytes(&mut bytes, 12, certificate.id().as_bytes());
        bytes
    }

    fn tc_body(set: &ValidatorSet, certificate: &TimeoutCertificateV0) -> Vec<u8> {
        let mut bytes = scope_prefix(set);
        pfield_varint(&mut bytes, 8, certificate.timed_out_view().get());
        for entry in certificate.entries() {
            let mut encoded = Vec::new();
            pfield_bytes(
                &mut encoded,
                1,
                &common_context(
                    set,
                    certificate.timed_out_view().get(),
                    MessageKind::Timeout,
                ),
            );
            pfield_bytes(&mut encoded, 2, &high_qc_summary(entry.high_qc()));
            pfield_bytes(&mut encoded, 3, entry.signer_id().as_bytes());
            pfield_bytes(&mut encoded, 4, entry.signature().as_bytes());
            pfield_bytes(&mut bytes, 9, &encoded);
        }
        for reference in certificate.referenced_qcs() {
            let ordinary = reference.as_ordinary().expect("ordinary test QC");
            pfield_bytes(&mut bytes, 10, &qc_body(set, ordinary));
        }
        pfield_bytes(
            &mut bytes,
            11,
            certificate.selected_high_qc_digest().as_bytes(),
        );
        pfield_bytes(&mut bytes, 12, certificate.id().as_bytes());
        bytes
    }

    fn vote_body_with_signature(
        set: &ValidatorSet,
        view: u64,
        author: ValidatorId,
        signature: &[u8; SIGNATURE_BYTES],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        pfield_bytes(&mut bytes, 1, &common_context(set, view, MessageKind::Vote));
        pfield_varint(&mut bytes, 2, 1);
        pfield_bytes(&mut bytes, 3, &[0x42; 32]);
        pfield_bytes(&mut bytes, 4, author.as_bytes());
        pfield_bytes(&mut bytes, 5, signature);
        bytes
    }

    fn vote_body_pattern(set: &ValidatorSet, view: u64, author: ValidatorId, byte: u8) -> Vec<u8> {
        vote_body_with_signature(set, view, author, &[byte; SIGNATURE_BYTES])
    }

    fn signed_vote(
        set: &ValidatorSet,
        key: &SigningKey,
        author: ValidatorId,
        view: View,
        height: Height,
        block_id: BlockId,
    ) -> Vote {
        let unsigned = Vote::new(
            set.chain_id(),
            ProtocolVersion::V0,
            Epoch::new(0),
            view,
            height,
            block_id,
            set.id(),
            author,
            SignatureBytes::from_array([0; SIGNATURE_BYTES]),
            set,
        )
        .expect("vote shape");
        let signature = key.sign(unsigned.signing_root().as_bytes()).to_bytes();
        Vote::new(
            set.chain_id(),
            ProtocolVersion::V0,
            Epoch::new(0),
            view,
            height,
            block_id,
            set.id(),
            author,
            SignatureBytes::from_array(signature),
            set,
        )
        .expect("signed vote shape")
    }

    fn signed_timeout_vote(
        set: &ValidatorSet,
        key: &SigningKey,
        author: ValidatorId,
        view: View,
        high_qc: QcRef,
    ) -> TimeoutVote {
        let unsigned = TimeoutVote::new(
            set.chain_id(),
            ProtocolVersion::V0,
            Epoch::new(0),
            view,
            set.id(),
            high_qc,
            author,
            SignatureBytes::from_array([0; SIGNATURE_BYTES]),
            set,
        )
        .expect("timeout vote shape");
        let signature = key.sign(unsigned.signing_root().as_bytes()).to_bytes();
        TimeoutVote::new(
            set.chain_id(),
            ProtocolVersion::V0,
            Epoch::new(0),
            view,
            set.id(),
            high_qc,
            author,
            SignatureBytes::from_array(signature),
            set,
        )
        .expect("signed timeout vote shape")
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
        qc: QuorumCertificate,
        tc: TimeoutCertificateV0,
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
            let vote_height = Height::new(1);
            let vote_view = View::new(1);
            let block = BlockId::new([0x42; 32]);
            let signed_peer_vote = signed_vote(&set, &keys[0], peer, vote_view, vote_height, block);
            let vote_payload = outer(
                &set,
                peer,
                1,
                WireBodyKindV0::Vote,
                &vote_body_with_signature(
                    &set,
                    vote_view.get(),
                    peer,
                    signed_peer_vote.signature().as_bytes(),
                ),
                Some(MessageKind::Vote),
            );

            let votes = (1u8..=3)
                .map(|id| {
                    signed_vote(
                        &set,
                        &keys[usize::from(id - 1)],
                        ValidatorId::new([id; 32]),
                        vote_view,
                        vote_height,
                        block,
                    )
                })
                .collect();
            let qc = QuorumCertificate::new(
                set.chain_id(),
                ProtocolVersion::V0,
                Epoch::new(0),
                vote_view,
                vote_height,
                block,
                set.id(),
                votes,
                &set,
            )
            .expect("qc");
            let qc_body = qc_body(&set, &qc);
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
                    signed_timeout_vote(
                        &set,
                        &keys[usize::from(id - 1)],
                        ValidatorId::new([id; 32]),
                        View::new(2),
                        high,
                    )
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
            let tc_body = tc_body(&set, &tc);
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
                qc,
                tc,
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

    fn qc_with_one_mutated_signature(
        set: &ValidatorSet,
        certificate: &QuorumCertificate,
    ) -> QuorumCertificate {
        let votes = certificate
            .votes()
            .iter()
            .enumerate()
            .map(|(index, vote)| {
                let mut signature = *vote.signature().as_bytes();
                if index == 0 {
                    // Preserve the exact shape while making the signature
                    // cryptographically invalid for this vote root.
                    signature[0] ^= 0x01;
                }
                Vote::new(
                    vote.chain_id(),
                    vote.protocol_version(),
                    vote.epoch(),
                    vote.view(),
                    vote.height(),
                    vote.block_id(),
                    vote.validator_set_id(),
                    vote.author(),
                    SignatureBytes::from_array(signature),
                    set,
                )
                .expect("mutated vote shape")
            })
            .collect();
        QuorumCertificate::new(
            certificate.chain_id(),
            certificate.protocol_version(),
            certificate.epoch(),
            certificate.view(),
            certificate.height(),
            certificate.block_id(),
            certificate.validator_set_id(),
            votes,
            set,
        )
        .expect("mutated QC shape")
    }

    fn tc_with_one_mutated_entry_signature(
        set: &ValidatorSet,
        certificate: &TimeoutCertificateV0,
    ) -> TimeoutCertificateV0 {
        let entries = certificate
            .entries()
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let mut signature = *entry.signature().as_bytes();
                if index == 0 {
                    // Keep the entry shape and signer intact while making
                    // only its timeout-vote signature invalid.
                    signature[0] ^= 0x01;
                }
                TimeoutEntryV0::new(
                    entry.signer_id(),
                    entry.high_qc(),
                    SignatureBytes::from_array(signature),
                )
                .expect("mutated timeout entry shape")
            })
            .collect();
        TimeoutCertificateV0::new(
            certificate.timed_out_view(),
            entries,
            certificate.referenced_qcs().to_vec(),
            certificate.selected_high_qc_digest(),
            set,
        )
        .expect("mutated TC shape")
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
    fn nested_qc_signature_is_verified_before_frame_acceptance() {
        let fixture = Fixture::new();
        let mut session =
            PocoNodeP2pSessionV0::open(&fixture.handshake, &fixture.set, &fixture.parameters)
                .expect("handshake");
        let invalid_qc = qc_with_one_mutated_signature(&fixture.set, &fixture.qc);
        let payload = outer(
            &fixture.set,
            fixture.peer,
            4,
            WireBodyKindV0::QuorumCertificate,
            &qc_body(&fixture.set, &invalid_qc),
            None,
        );
        let frame = signed_frame(session.session_id(), 4, &payload, &fixture.key);
        let mut budget =
            Cev0AdmissionBudgetV0::for_validator_set(&fixture.parameters, &fixture.set);
        let error = session.accept_frame(&frame, &mut budget).unwrap_err();
        assert_eq!(error.code(), P2pSessionIngressErrorCodeV0::SemanticDecode);
        assert_eq!(
            error.semantic_code(),
            Some(trnm_consensus_types::WireSemanticDecodeErrorCode::InvalidSignature)
        );
        // A failed nested signature must not consume a replay position.
        assert_eq!(session.highest_sequence(), None);
    }

    #[test]
    fn nested_tc_entry_signature_is_verified_before_frame_acceptance() {
        let fixture = Fixture::new();
        let mut session =
            PocoNodeP2pSessionV0::open(&fixture.handshake, &fixture.set, &fixture.parameters)
                .expect("handshake");
        let invalid_tc = tc_with_one_mutated_entry_signature(&fixture.set, &fixture.tc);
        let payload = outer(
            &fixture.set,
            fixture.peer,
            5,
            WireBodyKindV0::TimeoutCertificate,
            &tc_body(&fixture.set, &invalid_tc),
            None,
        );
        let frame = signed_frame(session.session_id(), 5, &payload, &fixture.key);
        let mut budget =
            Cev0AdmissionBudgetV0::for_validator_set(&fixture.parameters, &fixture.set);
        let error = session.accept_frame(&frame, &mut budget).unwrap_err();
        assert_eq!(error.code(), P2pSessionIngressErrorCodeV0::SemanticDecode);
        assert_eq!(
            error.semantic_code(),
            Some(trnm_consensus_types::WireSemanticDecodeErrorCode::InvalidSignature)
        );
        assert_eq!(session.highest_sequence(), None);
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
            &vote_body_pattern(&fixture.set, 1, fixture.peer, 0xA1),
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

    fn private_replay_anchor_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("replay anchor directory");
        #[cfg(unix)]
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private replay anchor directory");
        directory
    }

    #[test]
    fn replay_anchor_remains_candidate_only() {
        const {
            assert!(P2P_SESSION_REPLAY_ANCHOR_CANDIDATE_V0);
            assert!(!P2P_SESSION_REPLAY_ANCHOR_PRODUCTION_ACTIVATION_V0);
            assert!(!P2P_SESSION_INGRESS_PRODUCTION_ACTIVATION_V0);
        }
    }

    #[test]
    fn replay_anchor_rejects_variable_length_validator_id_before_fixed_encoding() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let peer = ValidatorId::from_bytes(&[0x31; 31]).expect("bounded variable id");
        let validator = Validator::new(
            peer,
            ConsensusPublicKey::new([0x41; 32]),
            VotingPower::new(1).expect("power"),
        )
        .expect("validator");
        let set = ValidatorSet::new(
            trnm_consensus_types::GenesisHash::new([0x92; 32]),
            ChainId::from_static("trnm-p2p-variable-id"),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            vec![validator],
        )
        .expect("validator set");
        let directory = private_replay_anchor_directory();
        let error =
            PocoNodeP2pReplayAnchorV0::open(directory.path().join("variable.replay"), &set, peer)
                .unwrap_err();
        assert_eq!(error, PocoNodeP2pReplayAnchorErrorV0::ContextMismatch);
    }

    #[test]
    fn replay_anchor_rejects_old_handshake_after_restart_and_allows_fresh_session() {
        let fixture = Fixture::new();
        let directory = private_replay_anchor_directory();
        let path = directory.path().join("p2p-session.replay");
        let mut anchor = PocoNodeP2pReplayAnchorV0::open(&path, &fixture.set, fixture.peer)
            .expect("fresh replay anchor");
        let mut session = PocoNodeP2pSessionV0::open_with_replay_anchor(
            &fixture.handshake,
            &fixture.set,
            &fixture.parameters,
            &mut anchor,
        )
        .expect("first anchored session");
        assert_eq!(anchor.record_count(), 1);
        let frame = signed_frame(session.session_id(), 1, &fixture.vote_payload, &fixture.key);
        let mut budget =
            Cev0AdmissionBudgetV0::for_validator_set(&fixture.parameters, &fixture.set);
        session
            .accept_frame(&frame, &mut budget)
            .expect("first frame");
        drop(session);
        drop(anchor);

        // A new process reopening the same durable anchor cannot replay the
        // old valid handshake, even though the in-memory replay bitmap starts
        // empty again.
        let mut reopened = PocoNodeP2pReplayAnchorV0::open(&path, &fixture.set, fixture.peer)
            .expect("reopen replay anchor");
        let error = PocoNodeP2pSessionV0::open_with_replay_anchor(
            &fixture.handshake,
            &fixture.set,
            &fixture.parameters,
            &mut reopened,
        )
        .unwrap_err();
        assert_eq!(error.code(), P2pSessionIngressErrorCodeV0::SessionReplay);
        assert_eq!(reopened.record_count(), 1);

        let fresh_handshake =
            signed_handshake_with_nonce(&fixture.set, &fixture.key, fixture.peer, [0xA6; 32]);
        let fresh_session = PocoNodeP2pSessionV0::open_with_replay_anchor(
            &fresh_handshake,
            &fixture.set,
            &fixture.parameters,
            &mut reopened,
        )
        .expect("fresh handshake gets a new durable session");
        assert_ne!(fresh_session.session_id(), session_id(&fixture.handshake));
        assert_eq!(reopened.record_count(), 2);

        // A frame from the old session cannot cross the fresh session even
        // after the durable handshake reservation succeeds.
        let mut fresh_session = fresh_session;
        let mut budget =
            Cev0AdmissionBudgetV0::for_validator_set(&fixture.parameters, &fixture.set);
        assert_eq!(
            fresh_session
                .accept_frame(&frame, &mut budget)
                .unwrap_err()
                .code(),
            P2pSessionIngressErrorCodeV0::SessionMismatch
        );
    }

    #[test]
    fn replay_anchor_rejects_tamper_and_valid_prefix_rollback() {
        let fixture = Fixture::new();
        let directory = private_replay_anchor_directory();
        let path = directory.path().join("p2p-session.replay");
        let mut anchor = PocoNodeP2pReplayAnchorV0::open(&path, &fixture.set, fixture.peer)
            .expect("fresh replay anchor");
        anchor
            .reserve_session(session_id(&fixture.handshake))
            .expect("first reservation");
        let second_handshake =
            signed_handshake_with_nonce(&fixture.set, &fixture.key, fixture.peer, [0xA6; 32]);
        anchor
            .reserve_session(session_id(&second_handshake))
            .expect("second reservation");
        assert_eq!(anchor.record_count(), 2);
        drop(anchor);
        let original = std::fs::read(&path).expect("read complete replay anchor");

        // The sidecar head is ahead of a valid prefix, so a rollback cannot
        // silently erase the first durable reservation.
        let file = OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open anchor for rollback mutant");
        file.set_len((REPLAY_ANCHOR_FRAME_BYTES_V0 * 2) as u64)
            .expect("truncate to valid prefix");
        drop(file);
        assert_eq!(
            PocoNodeP2pReplayAnchorV0::open(&path, &fixture.set, fixture.peer).unwrap_err(),
            PocoNodeP2pReplayAnchorErrorV0::Corrupt
        );

        // Restore the complete journal from the fixture's two reservations,
        // then mutate a committed byte; the hash chain must reject it.
        std::fs::write(&path, &original).expect("restore complete replay anchor");
        let mut tampered = original;
        tampered[REPLAY_ANCHOR_FRAME_BYTES_V0 + 76] ^= 0x01;
        std::fs::write(&path, tampered).expect("tamper replay anchor");
        assert_eq!(
            PocoNodeP2pReplayAnchorV0::open(&path, &fixture.set, fixture.peer).unwrap_err(),
            PocoNodeP2pReplayAnchorErrorV0::Corrupt
        );
    }

    #[cfg(unix)]
    #[test]
    fn replay_anchor_enforces_private_path_lock_and_head_integrity() {
        let fixture = Fixture::new();
        let directory = private_replay_anchor_directory();
        let path = directory.path().join("p2p-session.replay");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))
            .expect("shared parent mutant");
        assert_eq!(
            PocoNodeP2pReplayAnchorV0::open(&path, &fixture.set, fixture.peer).unwrap_err(),
            PocoNodeP2pReplayAnchorErrorV0::InvalidPath
        );
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restore private parent");

        let mut anchor = PocoNodeP2pReplayAnchorV0::open(&path, &fixture.set, fixture.peer)
            .expect("private replay anchor");
        anchor
            .reserve_session(session_id(&fixture.handshake))
            .expect("reserve session");
        let head_path = path.with_file_name(".p2p-session.replay.head");
        let second_open = PocoNodeP2pReplayAnchorV0::open(&path, &fixture.set, fixture.peer);
        assert_eq!(second_open.unwrap_err(), PocoNodeP2pReplayAnchorErrorV0::Io);
        drop(anchor);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("shared journal mutant");
        assert_eq!(
            PocoNodeP2pReplayAnchorV0::open(&path, &fixture.set, fixture.peer).unwrap_err(),
            PocoNodeP2pReplayAnchorErrorV0::InvalidPath
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("restore private journal");

        let mut head = std::fs::read(&head_path).expect("read replay head");
        head[20] ^= 0x01;
        std::fs::write(&head_path, head).expect("tamper replay head");
        assert_eq!(
            PocoNodeP2pReplayAnchorV0::open(&path, &fixture.set, fixture.peer).unwrap_err(),
            PocoNodeP2pReplayAnchorErrorV0::Corrupt
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
