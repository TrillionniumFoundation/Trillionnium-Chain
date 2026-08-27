//! Candidate-only durable replay fencing for authenticated consensus payloads.
//!
//! The peer-lease journal fences *which session generation* owns a directed
//! edge.  It intentionally does not remember the payload sequence that was
//! consumed by that edge.  This module supplies that missing, narrow seam: a
//! node-owned append-only journal records the authenticated frame identity
//! (`peer/session/generation/sequence`) and a digest of the canonical frame
//! payload.  A receiver must durably admit a frame before exposing it to a
//! consensus consumer.
//!
//! This is deliberately not a network socket, a signer, a Core/SafetyRules
//! authority, or an activation path.  The journal can be rolled back together
//! with its sidecar by an owner with filesystem authority; the external peer
//! lease remains the independent generation fence for that threat model.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use fs2::FileExt;
use sha2::{Digest, Sha256};

use crate::protocol::{PeerLeaseDirectionV1, PeerLeaseScopeV1};

/// Candidate-only metadata.  This journal does not imply consensus-runtime
/// or production activation truth.
pub const PAYLOAD_REPLAY_CANDIDATE_V1: bool = true;
pub const PAYLOAD_REPLAY_APPEND_ONLY_HASH_CHAIN_V1: bool = true;
pub const PAYLOAD_REPLAY_PRODUCTION_ACTIVATION_V1: bool = false;

/// A payload digest is bounded to the same order as the authenticated mesh
/// envelope.  The journal stores the digest, not an unbounded copy of the
/// payload itself.
pub const PAYLOAD_REPLAY_MAX_PAYLOAD_BYTES_V1: usize = 8 * 1024 * 1024;
pub const PAYLOAD_REPLAY_MAX_RECORDS_V1: u64 = 1_048_576;

const LOG_MAGIC_V1: [u8; 8] = *b"TRNPRW01";
const LOG_VERSION_V1: u8 = 1;
const LOG_GENESIS_KIND_V1: u8 = 0;
const LOG_FRAME_KIND_V1: u8 = 1;
const HEAD_MAGIC_V1: [u8; 8] = *b"TRNPRH01";
const HEAD_VERSION_V1: u8 = 1;
const PRIVATE_MODE_V1: u32 = 0o600;
const NAMESPACE_DOMAIN_V1: &[u8] = b"trnm.poco-g3.payload-replay.namespace.v1";
const RECORD_DOMAIN_V1: &[u8] = b"trnm.poco-g3.payload-replay.record.v1";
const HEAD_DOMAIN_V1: &[u8] = b"trnm.poco-g3.payload-replay.head.v1";
const RUN_ID_DOMAIN_V1: &[u8] = b"trnm.poco-g3.payload-replay.run-id.v1";

// Fixed record layout.  Keeping every field in every record makes a copied
// record, cross-context splice, reordering, and byte mutation observable
// before any replay state is reconstructed.
const RECORD_PREFIX_BYTES_V1: usize = 348;
const RECORD_BYTES_V1: usize = RECORD_PREFIX_BYTES_V1 + 32;
const HEAD_PREFIX_BYTES_V1: usize = 8 + 1 + 3 + 8 + 32 + 32;
const HEAD_BYTES_V1: usize = HEAD_PREFIX_BYTES_V1 + 32;

/// Re-export the lease direction under a payload-specific name.  Using the
/// exact lease enum prevents an inbound and outbound journal key from being
/// accidentally aliased by a caller.
pub type PayloadReplayDirectionV1 = PeerLeaseDirectionV1;

/// Computes the run binding used by [`PayloadReplayNamespaceV1`].  Keeping
/// this helper in the authority crate prevents mesh adapters from inventing a
/// second, subtly different run-id hash.
pub fn payload_replay_run_id_hash_v1(run_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RUN_ID_DOMAIN_V1);
    hasher.update((run_id.len() as u64).to_be_bytes());
    hasher.update(run_id.as_bytes());
    hasher.finalize().into()
}

/// Immutable namespace shared by every record in one node's replay journal.
/// The run and network-context digests are included in the hash-chain
/// genesis, so a journal cannot be attached to another deployment bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadReplayNamespaceV1 {
    local_id: [u8; 32],
    epoch: u64,
    validator_set_id: [u8; 32],
    run_id_hash: [u8; 32],
    network_context_hash: [u8; 32],
}

impl PayloadReplayNamespaceV1 {
    pub fn new(
        local_id: [u8; 32],
        epoch: u64,
        validator_set_id: [u8; 32],
        run_id_hash: [u8; 32],
        network_context_hash: [u8; 32],
    ) -> Result<Self, PayloadReplayErrorV1> {
        if local_id == [0; 32]
            || validator_set_id == [0; 32]
            || run_id_hash == [0; 32]
            || network_context_hash == [0; 32]
        {
            return Err(PayloadReplayErrorV1::InvalidRequest(
                "payload replay namespace contains a zero identity",
            ));
        }
        Ok(Self {
            local_id,
            epoch,
            validator_set_id,
            run_id_hash,
            network_context_hash,
        })
    }

    pub const fn local_id(self) -> [u8; 32] {
        self.local_id
    }

    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    pub const fn validator_set_id(self) -> [u8; 32] {
        self.validator_set_id
    }

    pub const fn run_id_hash(self) -> [u8; 32] {
        self.run_id_hash
    }

    pub const fn network_context_hash(self) -> [u8; 32] {
        self.network_context_hash
    }

    /// Builds the exact peer-lease scope used by one directed payload edge.
    pub fn scope_for(
        self,
        remote_id: [u8; 32],
        direction: PayloadReplayDirectionV1,
    ) -> Result<PeerLeaseScopeV1, PayloadReplayErrorV1> {
        PeerLeaseScopeV1::new(
            self.local_id,
            remote_id,
            direction,
            self.epoch,
            self.validator_set_id,
        )
        .map_err(|_| PayloadReplayErrorV1::InvalidRequest("invalid payload replay peer scope"))
    }

    fn digest(self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(NAMESPACE_DOMAIN_V1);
        hasher.update(self.local_id);
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.validator_set_id);
        hasher.update(self.run_id_hash);
        hasher.update(self.network_context_hash);
        hasher.finalize().into()
    }
}

/// One authenticated frame identity ready for durable admission.  The frame
/// signature and nested consensus signatures must already have been verified
/// by the transport/collector. `frame_fingerprint` is the canonical digest of
/// the complete authenticated frame fields and payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadReplayFrameV1 {
    scope: PeerLeaseScopeV1,
    run_id_hash: [u8; 32],
    network_context_hash: [u8; 32],
    session_id: [u8; 32],
    generation: u64,
    sequence: u64,
    frame_kind: u8,
    payload_len: u32,
    frame_fingerprint: [u8; 32],
}

impl PayloadReplayFrameV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: PeerLeaseScopeV1,
        run_id_hash: [u8; 32],
        network_context_hash: [u8; 32],
        session_id: [u8; 32],
        generation: u64,
        sequence: u64,
        frame_kind: u8,
        payload_len: usize,
        frame_fingerprint: [u8; 32],
    ) -> Result<Self, PayloadReplayErrorV1> {
        if run_id_hash == [0; 32] || network_context_hash == [0; 32] {
            return Err(PayloadReplayErrorV1::InvalidRequest(
                "payload replay frame has a zero context digest",
            ));
        }
        if session_id == [0; 32] {
            return Err(PayloadReplayErrorV1::InvalidRequest(
                "payload replay frame has a zero session",
            ));
        }
        if generation == 0 {
            return Err(PayloadReplayErrorV1::InvalidRequest(
                "payload replay generation must be positive",
            ));
        }
        if frame_kind == 0 {
            return Err(PayloadReplayErrorV1::InvalidRequest(
                "payload replay frame kind must be nonzero",
            ));
        }
        if payload_len > PAYLOAD_REPLAY_MAX_PAYLOAD_BYTES_V1 {
            return Err(PayloadReplayErrorV1::TooLarge);
        }
        let payload_len = u32::try_from(payload_len).map_err(|_| PayloadReplayErrorV1::TooLarge)?;
        if frame_fingerprint == [0; 32] {
            return Err(PayloadReplayErrorV1::InvalidRequest(
                "payload replay frame fingerprint is zero",
            ));
        }
        Ok(Self {
            scope,
            run_id_hash,
            network_context_hash,
            session_id,
            generation,
            sequence,
            frame_kind,
            payload_len,
            frame_fingerprint,
        })
    }

    pub const fn scope(self) -> PeerLeaseScopeV1 {
        self.scope
    }

    pub const fn run_id_hash(self) -> [u8; 32] {
        self.run_id_hash
    }

    pub const fn network_context_hash(self) -> [u8; 32] {
        self.network_context_hash
    }

    pub const fn session_id(self) -> [u8; 32] {
        self.session_id
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub const fn frame_kind(self) -> u8 {
        self.frame_kind
    }

    pub const fn payload_len(self) -> u32 {
        self.payload_len
    }

    pub const fn frame_fingerprint(self) -> [u8; 32] {
        self.frame_fingerprint
    }
}

/// Receipt returned only after the frame record and head sidecar are synced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadReplayReceiptV1 {
    record_index: u64,
    record_hash: [u8; 32],
}

impl PayloadReplayReceiptV1 {
    pub const fn record_index(self) -> u64 {
        self.record_index
    }

    pub const fn record_hash(self) -> [u8; 32] {
        self.record_hash
    }
}

/// Errors from the candidate durable payload replay owner.
#[derive(Debug)]
pub enum PayloadReplayErrorV1 {
    InvalidRequest(&'static str),
    Io(io::Error),
    Protocol(&'static str),
    ContextMismatch,
    Replay,
    StaleGeneration,
    SequenceGap,
    Corrupt,
    Truncated,
    TooLarge,
    Poisoned,
}

impl fmt::Display for PayloadReplayErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(reason) | Self::Protocol(reason) => formatter.write_str(reason),
            Self::Io(error) => write!(formatter, "payload replay I/O error: {error}"),
            Self::ContextMismatch => formatter.write_str("payload replay context mismatch"),
            Self::Replay => formatter.write_str("authenticated payload frame was replayed"),
            Self::StaleGeneration => formatter.write_str("payload frame generation is stale"),
            Self::SequenceGap => formatter.write_str("payload frame sequence is not contiguous"),
            Self::Corrupt => formatter.write_str("payload replay journal is corrupt"),
            Self::Truncated => formatter.write_str("payload replay journal is truncated"),
            Self::TooLarge => formatter.write_str("payload replay journal exceeds its bound"),
            Self::Poisoned => formatter.write_str("payload replay owner is permanently poisoned"),
        }
    }
}

impl std::error::Error for PayloadReplayErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for PayloadReplayErrorV1 {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PeerKeyV1 {
    remote_id: [u8; 32],
    direction: PeerLeaseDirectionV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplayStateV1 {
    session_id: [u8; 32],
    generation: u64,
    last_sequence: u64,
    last_fingerprint: [u8; 32],
}

#[derive(Debug)]
struct ReplaySnapshotV1 {
    states: BTreeMap<PeerKeyV1, ReplayStateV1>,
    seen_sessions: BTreeSet<(PeerKeyV1, [u8; 32])>,
    last_hash: [u8; 32],
    record_count: u64,
}

/// Node-owned append-only payload replay journal.  One exclusive lock covers
/// the whole namespace; a second process cannot open the same owner while it
/// is live.  Reopening replays every record and requires an exact sidecar
/// head, so truncation to a valid prefix is rejected rather than silently
/// accepted.
#[derive(Debug)]
pub struct PayloadReplayStoreV1 {
    path: PathBuf,
    head_path: PathBuf,
    directory: File,
    file: File,
    _lock: File,
    namespace: PayloadReplayNamespaceV1,
    namespace_digest: [u8; 32],
    states: BTreeMap<PeerKeyV1, ReplayStateV1>,
    seen_sessions: BTreeSet<(PeerKeyV1, [u8; 32])>,
    last_hash: [u8; 32],
    record_count: u64,
    poisoned: bool,
}

impl PayloadReplayStoreV1 {
    /// Opens and fully authenticates a replay journal.  No repair or
    /// truncation is attempted; an absent head, partial record, or prefix
    /// mismatch is a hard failure.
    pub fn open(
        path: impl AsRef<Path>,
        namespace: PayloadReplayNamespaceV1,
    ) -> Result<Self, PayloadReplayErrorV1> {
        let path = path.as_ref().to_path_buf();
        let (directory, _parent) = private_parent(&path)?;
        let lock_path = sidecar_path(&path, "lock-v1")?;
        let head_path = sidecar_path(&path, "head-v1")?;
        let lock = open_private_lock(&lock_path)?;
        lock.try_lock_exclusive()
            .map_err(PayloadReplayErrorV1::Io)?;

        let existing = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() || !private_file_mode(&metadata) {
                    return Err(PayloadReplayErrorV1::InvalidRequest(
                        "payload replay journal path is not a private regular file",
                    ));
                }
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(PayloadReplayErrorV1::Io(error)),
        };
        let mut options = OpenOptions::new();
        options.read(true).write(true).append(true);
        if existing {
            options.create(false);
        } else {
            options.create_new(true);
            set_private_mode_options(&mut options);
        }
        let file = options.open(&path).map_err(PayloadReplayErrorV1::Io)?;
        if !existing {
            set_private_mode(&file)?;
        }
        validate_private_file(&file)?;
        file.try_lock_exclusive()
            .map_err(PayloadReplayErrorV1::Io)?;
        if existing && file.metadata()?.len() == 0 {
            return Err(PayloadReplayErrorV1::Truncated);
        }
        if !existing && fs::symlink_metadata(&head_path).is_ok() {
            return Err(PayloadReplayErrorV1::InvalidRequest(
                "payload replay head exists for a virgin journal",
            ));
        }

        let namespace_digest = namespace.digest();
        let mut store = Self {
            path,
            head_path,
            directory,
            file,
            _lock: lock,
            namespace,
            namespace_digest,
            states: BTreeMap::new(),
            seen_sessions: BTreeSet::new(),
            last_hash: [0; 32],
            record_count: 0,
            poisoned: false,
        };
        if !existing {
            let genesis = encode_record(None, namespace, namespace_digest, 0, [0; 32]);
            store.file.write_all(&genesis)?;
            store.file.sync_all()?;
            store.directory.sync_all()?;
        }
        store.reload_from_disk()?;
        store.reconcile_head(!existing)?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn head_path(&self) -> &Path {
        &self.head_path
    }

    pub const fn namespace(&self) -> PayloadReplayNamespaceV1 {
        self.namespace
    }

    pub const fn last_hash(&self) -> [u8; 32] {
        self.last_hash
    }

    /// Includes the genesis record.  `accepted_frame_count` excludes it.
    pub const fn record_count(&self) -> u64 {
        self.record_count
    }

    pub const fn accepted_frame_count(&self) -> u64 {
        self.record_count.saturating_sub(1)
    }

    pub fn contains_session(
        &self,
        remote_id: [u8; 32],
        direction: PayloadReplayDirectionV1,
        session_id: [u8; 32],
    ) -> bool {
        self.seen_sessions.contains(&(
            PeerKeyV1 {
                remote_id,
                direction,
            },
            session_id,
        ))
    }

    pub fn latest_generation(
        &self,
        remote_id: [u8; 32],
        direction: PayloadReplayDirectionV1,
    ) -> Option<u64> {
        self.states
            .get(&PeerKeyV1 {
                remote_id,
                direction,
            })
            .map(|state| state.generation)
    }

    /// Durably admits one already-authenticated frame.  The frame is never
    /// exposed as accepted until both the WAL record and exact head sidecar
    /// have been synced.
    pub fn admit(
        &mut self,
        frame: &PayloadReplayFrameV1,
    ) -> Result<PayloadReplayReceiptV1, PayloadReplayErrorV1> {
        if self.poisoned {
            return Err(PayloadReplayErrorV1::Poisoned);
        }
        if let Err(error) = self.verify_live_head() {
            self.poisoned = true;
            return Err(error);
        }
        self.validate_frame_context(frame)?;
        let key = PeerKeyV1 {
            remote_id: frame.scope.remote_id(),
            direction: frame.scope.direction(),
        };
        let next_state = self.preview_state(key, *frame)?;
        if self.record_count >= PAYLOAD_REPLAY_MAX_RECORDS_V1 {
            return Err(PayloadReplayErrorV1::TooLarge);
        }
        let index = self.record_count;
        let record = encode_record(
            Some(frame),
            self.namespace,
            self.namespace_digest,
            index,
            self.last_hash,
        );
        self.file.write_all(&record)?;
        if let Err(error) = self.file.sync_all().and_then(|_| self.directory.sync_all()) {
            self.poisoned = true;
            return Err(PayloadReplayErrorV1::Io(error));
        }
        let record_hash = record_digest(&record[..RECORD_PREFIX_BYTES_V1]);
        let new_count = match self.record_count.checked_add(1) {
            Some(value) => value,
            None => {
                self.poisoned = true;
                return Err(PayloadReplayErrorV1::TooLarge);
            }
        };
        if let Err(error) = persist_head(
            &self.head_path,
            &self.directory,
            new_count,
            record_hash,
            self.namespace_digest,
        ) {
            self.poisoned = true;
            return Err(error);
        }
        self.states.insert(key, next_state);
        self.seen_sessions.insert((key, frame.session_id));
        self.last_hash = record_hash;
        self.record_count = new_count;
        Ok(PayloadReplayReceiptV1 {
            record_index: index,
            record_hash,
        })
    }

    fn validate_frame_context(
        &self,
        frame: &PayloadReplayFrameV1,
    ) -> Result<(), PayloadReplayErrorV1> {
        let scope = frame.scope;
        if scope.local_id() != self.namespace.local_id()
            || scope.epoch() != self.namespace.epoch()
            || scope.validator_set_id() != self.namespace.validator_set_id()
            || frame.run_id_hash != self.namespace.run_id_hash()
            || frame.network_context_hash != self.namespace.network_context_hash()
        {
            return Err(PayloadReplayErrorV1::ContextMismatch);
        }
        if scope.remote_id() == [0; 32] || scope.remote_id() == scope.local_id() {
            return Err(PayloadReplayErrorV1::ContextMismatch);
        }
        Ok(())
    }

    fn preview_state(
        &self,
        key: PeerKeyV1,
        frame: PayloadReplayFrameV1,
    ) -> Result<ReplayStateV1, PayloadReplayErrorV1> {
        let current_session = self.states.get(&key).map(|state| state.session_id);
        if current_session != Some(frame.session_id)
            && self.seen_sessions.contains(&(key, frame.session_id))
        {
            return Err(PayloadReplayErrorV1::Replay);
        }
        match self.states.get(&key).copied() {
            None => {
                if frame.generation != 1 || frame.sequence != 0 {
                    return Err(PayloadReplayErrorV1::StaleGeneration);
                }
            }
            Some(previous) if frame.generation == previous.generation => {
                if frame.session_id != previous.session_id {
                    return Err(PayloadReplayErrorV1::Replay);
                }
                let expected = previous
                    .last_sequence
                    .checked_add(1)
                    .ok_or(PayloadReplayErrorV1::TooLarge)?;
                if frame.sequence < expected {
                    return Err(PayloadReplayErrorV1::Replay);
                }
                if frame.sequence != expected {
                    return Err(PayloadReplayErrorV1::SequenceGap);
                }
            }
            Some(previous) if frame.generation == previous.generation.saturating_add(1) => {
                if frame.session_id == previous.session_id || frame.sequence != 0 {
                    return Err(PayloadReplayErrorV1::Replay);
                }
            }
            Some(previous) if frame.generation < previous.generation => {
                return Err(PayloadReplayErrorV1::StaleGeneration)
            }
            Some(_) => return Err(PayloadReplayErrorV1::StaleGeneration),
        }
        Ok(ReplayStateV1 {
            session_id: frame.session_id,
            generation: frame.generation,
            last_sequence: frame.sequence,
            last_fingerprint: frame.frame_fingerprint,
        })
    }

    fn verify_live_head(&mut self) -> Result<(), PayloadReplayErrorV1> {
        let bytes = self.read_log_bytes()?;
        let snapshot = parse_log(&bytes, self.namespace, self.namespace_digest)?;
        if snapshot.record_count != self.record_count
            || snapshot.last_hash != self.last_hash
            || snapshot.states != self.states
            || snapshot.seen_sessions != self.seen_sessions
        {
            return Err(PayloadReplayErrorV1::Corrupt);
        }
        let head_metadata =
            fs::symlink_metadata(&self.head_path).map_err(PayloadReplayErrorV1::Io)?;
        if !head_metadata.is_file() || !private_file_mode(&head_metadata) {
            return Err(PayloadReplayErrorV1::InvalidRequest(
                "payload replay head path is not a private regular file",
            ));
        }
        let head_bytes = fs::read(&self.head_path).map_err(PayloadReplayErrorV1::Io)?;
        let (head_count, head_hash, head_namespace) = decode_head(&head_bytes)?;
        if head_count != self.record_count
            || head_hash != self.last_hash
            || head_namespace != self.namespace_digest
        {
            return Err(PayloadReplayErrorV1::Corrupt);
        }
        Ok(())
    }

    fn reload_from_disk(&mut self) -> Result<(), PayloadReplayErrorV1> {
        let bytes = self.read_log_bytes()?;
        let snapshot = parse_log(&bytes, self.namespace, self.namespace_digest)?;
        self.states = snapshot.states;
        self.seen_sessions = snapshot.seen_sessions;
        self.last_hash = snapshot.last_hash;
        self.record_count = snapshot.record_count;
        Ok(())
    }

    fn read_log_bytes(&mut self) -> Result<Vec<u8>, PayloadReplayErrorV1> {
        let length = self.file.metadata()?.len();
        let maximum = PAYLOAD_REPLAY_MAX_RECORDS_V1
            .checked_add(1)
            .and_then(|count| count.checked_mul(RECORD_BYTES_V1 as u64))
            .ok_or(PayloadReplayErrorV1::TooLarge)?;
        if length > maximum {
            return Err(PayloadReplayErrorV1::TooLarge);
        }
        self.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut self.file)
            .take(maximum.saturating_add(1))
            .read_to_end(&mut bytes)?;
        self.file.seek(SeekFrom::End(0))?;
        if bytes.len() as u64 > maximum {
            return Err(PayloadReplayErrorV1::TooLarge);
        }
        Ok(bytes)
    }

    fn reconcile_head(&self, virgin: bool) -> Result<(), PayloadReplayErrorV1> {
        if let Ok(metadata) = fs::symlink_metadata(&self.head_path) {
            if !metadata.is_file() || !private_file_mode(&metadata) {
                return Err(PayloadReplayErrorV1::InvalidRequest(
                    "payload replay head path is not a private regular file",
                ));
            }
        }
        let bytes = match fs::read(&self.head_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound && virgin => {
                return persist_head(
                    &self.head_path,
                    &self.directory,
                    self.record_count,
                    self.last_hash,
                    self.namespace_digest,
                )
            }
            Err(error) => return Err(PayloadReplayErrorV1::Io(error)),
        };
        let (count, hash, namespace_digest) = decode_head(&bytes)?;
        if namespace_digest != self.namespace_digest
            || count != self.record_count
            || hash != self.last_hash
        {
            // Exact equality is intentional.  A valid prefix is not a
            // recoverable state: accepting it would make an old authenticated
            // frame appear new after a rollback.
            return Err(PayloadReplayErrorV1::Corrupt);
        }
        Ok(())
    }
}

fn encode_record(
    frame: Option<&PayloadReplayFrameV1>,
    namespace: PayloadReplayNamespaceV1,
    namespace_digest: [u8; 32],
    index: u64,
    predecessor: [u8; 32],
) -> [u8; RECORD_BYTES_V1] {
    let mut bytes = Vec::with_capacity(RECORD_BYTES_V1);
    bytes.extend_from_slice(&LOG_MAGIC_V1);
    bytes.push(LOG_VERSION_V1);
    bytes.push(if frame.is_some() {
        LOG_FRAME_KIND_V1
    } else {
        LOG_GENESIS_KIND_V1
    });
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&index.to_be_bytes());
    bytes.extend_from_slice(&namespace_digest);
    bytes.extend_from_slice(&namespace.local_id());
    if let Some(frame) = frame {
        let scope = frame.scope;
        bytes.extend_from_slice(&scope.remote_id());
        bytes.push(scope.direction() as u8);
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(&scope.epoch().to_be_bytes());
        bytes.extend_from_slice(&scope.validator_set_id());
        bytes.extend_from_slice(&frame.run_id_hash);
        bytes.extend_from_slice(&frame.network_context_hash);
        bytes.extend_from_slice(&frame.session_id);
        bytes.extend_from_slice(&frame.generation.to_be_bytes());
        bytes.extend_from_slice(&frame.sequence.to_be_bytes());
        bytes.push(frame.frame_kind);
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(&frame.payload_len.to_be_bytes());
        bytes.extend_from_slice(&frame.frame_fingerprint);
    } else {
        bytes.extend_from_slice(&[0; 32]); // remote
        bytes.push(0); // direction
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(&namespace.epoch().to_be_bytes());
        bytes.extend_from_slice(&namespace.validator_set_id());
        bytes.extend_from_slice(&namespace.run_id_hash());
        bytes.extend_from_slice(&namespace.network_context_hash());
        bytes.extend_from_slice(&[0; 32]); // session
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&[0; 32]);
    }
    bytes.extend_from_slice(&predecessor);
    debug_assert_eq!(bytes.len(), RECORD_PREFIX_BYTES_V1);
    let digest = record_digest(&bytes);
    bytes.extend_from_slice(&digest);
    bytes.try_into().expect("fixed payload replay record")
}

fn record_digest(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_DOMAIN_V1);
    hasher.update((prefix.len() as u64).to_be_bytes());
    hasher.update(prefix);
    hasher.finalize().into()
}

fn parse_log(
    bytes: &[u8],
    namespace: PayloadReplayNamespaceV1,
    namespace_digest: [u8; 32],
) -> Result<ReplaySnapshotV1, PayloadReplayErrorV1> {
    if bytes.is_empty() {
        return Err(PayloadReplayErrorV1::Truncated);
    }
    if bytes.len() % RECORD_BYTES_V1 != 0 {
        return Err(PayloadReplayErrorV1::Truncated);
    }
    let count = bytes.len() / RECORD_BYTES_V1;
    if count == 0 || count as u64 > PAYLOAD_REPLAY_MAX_RECORDS_V1 {
        return Err(PayloadReplayErrorV1::TooLarge);
    }
    let mut states = BTreeMap::<PeerKeyV1, ReplayStateV1>::new();
    let mut seen_sessions = BTreeSet::<(PeerKeyV1, [u8; 32])>::new();
    let mut last_hash = [0; 32];
    for (index, bytes) in bytes.chunks_exact(RECORD_BYTES_V1).enumerate() {
        let decoded = decode_record(bytes)?;
        if decoded.index != index as u64
            || decoded.namespace_digest != namespace_digest
            || decoded.local_id != namespace.local_id()
            || decoded.epoch != namespace.epoch()
            || decoded.validator_set_id != namespace.validator_set_id()
            || decoded.run_id_hash != namespace.run_id_hash()
            || decoded.network_context_hash != namespace.network_context_hash()
            || decoded.predecessor != last_hash
        {
            return Err(PayloadReplayErrorV1::ContextMismatch);
        }
        if index == 0 {
            if decoded.operation != LOG_GENESIS_KIND_V1
                || decoded.remote_id != [0; 32]
                || decoded.direction.is_some()
                || decoded.session_id != [0; 32]
                || decoded.generation != 0
                || decoded.sequence != 0
                || decoded.frame_kind != 0
                || decoded.payload_len != 0
                || decoded.frame_fingerprint != [0; 32]
                || decoded.predecessor != [0; 32]
            {
                return Err(PayloadReplayErrorV1::Corrupt);
            }
        } else {
            if decoded.operation != LOG_FRAME_KIND_V1 {
                return Err(PayloadReplayErrorV1::Corrupt);
            }
            let direction = decoded.direction.ok_or(PayloadReplayErrorV1::Corrupt)?;
            if decoded.remote_id == [0; 32]
                || decoded.remote_id == decoded.local_id
                || decoded.session_id == [0; 32]
                || decoded.generation == 0
                || decoded.frame_kind == 0
                || decoded.payload_len as usize > PAYLOAD_REPLAY_MAX_PAYLOAD_BYTES_V1
                || decoded.frame_fingerprint == [0; 32]
            {
                return Err(PayloadReplayErrorV1::Corrupt);
            }
            let key = PeerKeyV1 {
                remote_id: decoded.remote_id,
                direction,
            };
            let frame = PayloadReplayFrameV1 {
                scope: PeerLeaseScopeV1::new(
                    decoded.local_id,
                    decoded.remote_id,
                    direction,
                    decoded.epoch,
                    decoded.validator_set_id,
                )
                .map_err(|_| PayloadReplayErrorV1::Corrupt)?,
                run_id_hash: decoded.run_id_hash,
                network_context_hash: decoded.network_context_hash,
                session_id: decoded.session_id,
                generation: decoded.generation,
                sequence: decoded.sequence,
                frame_kind: decoded.frame_kind,
                payload_len: decoded.payload_len,
                frame_fingerprint: decoded.frame_fingerprint,
            };
            let new_session = states
                .get(&key)
                .map(|state| state.session_id != frame.session_id)
                .unwrap_or(true);
            if new_session && !seen_sessions.insert((key, decoded.session_id)) {
                return Err(PayloadReplayErrorV1::Corrupt);
            }
            let next = preview_replayed_state(states.get(&key).copied(), frame)?;
            states.insert(key, next);
        }
        last_hash = decoded.record_hash;
    }
    Ok(ReplaySnapshotV1 {
        states,
        seen_sessions,
        last_hash,
        record_count: count as u64,
    })
}

fn preview_replayed_state(
    previous: Option<ReplayStateV1>,
    frame: PayloadReplayFrameV1,
) -> Result<ReplayStateV1, PayloadReplayErrorV1> {
    match previous {
        None => {
            if frame.generation != 1 || frame.sequence != 0 {
                return Err(PayloadReplayErrorV1::Corrupt);
            }
        }
        Some(previous) if frame.generation == previous.generation => {
            if frame.session_id != previous.session_id
                || frame.sequence
                    != previous
                        .last_sequence
                        .checked_add(1)
                        .ok_or(PayloadReplayErrorV1::Corrupt)?
            {
                return Err(PayloadReplayErrorV1::Corrupt);
            }
        }
        Some(previous) if frame.generation == previous.generation.saturating_add(1) => {
            if frame.session_id == previous.session_id || frame.sequence != 0 {
                return Err(PayloadReplayErrorV1::Corrupt);
            }
        }
        Some(_) => return Err(PayloadReplayErrorV1::Corrupt),
    }
    Ok(ReplayStateV1 {
        session_id: frame.session_id,
        generation: frame.generation,
        last_sequence: frame.sequence,
        last_fingerprint: frame.frame_fingerprint,
    })
}

#[derive(Debug, Clone, Copy)]
struct DecodedRecordV1 {
    operation: u8,
    index: u64,
    namespace_digest: [u8; 32],
    local_id: [u8; 32],
    remote_id: [u8; 32],
    direction: Option<PeerLeaseDirectionV1>,
    epoch: u64,
    validator_set_id: [u8; 32],
    run_id_hash: [u8; 32],
    network_context_hash: [u8; 32],
    session_id: [u8; 32],
    generation: u64,
    sequence: u64,
    frame_kind: u8,
    payload_len: u32,
    frame_fingerprint: [u8; 32],
    predecessor: [u8; 32],
    record_hash: [u8; 32],
}

fn decode_record(bytes: &[u8]) -> Result<DecodedRecordV1, PayloadReplayErrorV1> {
    if bytes.len() != RECORD_BYTES_V1 {
        return Err(PayloadReplayErrorV1::Truncated);
    }
    if bytes[..8] != LOG_MAGIC_V1 || bytes[8] != LOG_VERSION_V1 {
        return Err(PayloadReplayErrorV1::Corrupt);
    }
    if bytes[10..12] != [0, 0]
        || bytes[117..124].iter().any(|byte| *byte != 0)
        || bytes[277..280].iter().any(|byte| *byte != 0)
    {
        return Err(PayloadReplayErrorV1::Corrupt);
    }
    let stored: [u8; 32] = bytes[RECORD_PREFIX_BYTES_V1..]
        .try_into()
        .expect("fixed payload replay digest");
    if stored != record_digest(&bytes[..RECORD_PREFIX_BYTES_V1]) {
        return Err(PayloadReplayErrorV1::Corrupt);
    }
    let direction = match bytes[116] {
        0 => None,
        1 => Some(PeerLeaseDirectionV1::Outbound),
        2 => Some(PeerLeaseDirectionV1::Inbound),
        _ => return Err(PayloadReplayErrorV1::Corrupt),
    };
    Ok(DecodedRecordV1 {
        operation: bytes[9],
        index: u64::from_be_bytes(bytes[12..20].try_into().expect("record index")),
        namespace_digest: bytes[20..52].try_into().expect("namespace digest"),
        local_id: bytes[52..84].try_into().expect("local id"),
        remote_id: bytes[84..116].try_into().expect("remote id"),
        direction,
        epoch: u64::from_be_bytes(bytes[124..132].try_into().expect("epoch")),
        validator_set_id: bytes[132..164].try_into().expect("validator set"),
        run_id_hash: bytes[164..196].try_into().expect("run hash"),
        network_context_hash: bytes[196..228].try_into().expect("network context"),
        session_id: bytes[228..260].try_into().expect("session"),
        generation: u64::from_be_bytes(bytes[260..268].try_into().expect("generation")),
        sequence: u64::from_be_bytes(bytes[268..276].try_into().expect("sequence")),
        frame_kind: bytes[276],
        payload_len: u32::from_be_bytes(bytes[280..284].try_into().expect("payload length")),
        frame_fingerprint: bytes[284..316].try_into().expect("frame fingerprint"),
        predecessor: bytes[316..348].try_into().expect("predecessor"),
        record_hash: stored,
    })
}

fn encode_head(
    record_count: u64,
    record_hash: [u8; 32],
    namespace_digest: [u8; 32],
) -> [u8; HEAD_BYTES_V1] {
    let mut bytes = Vec::with_capacity(HEAD_BYTES_V1);
    bytes.extend_from_slice(&HEAD_MAGIC_V1);
    bytes.push(HEAD_VERSION_V1);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&record_count.to_be_bytes());
    bytes.extend_from_slice(&record_hash);
    bytes.extend_from_slice(&namespace_digest);
    let mut hasher = Sha256::new();
    hasher.update(HEAD_DOMAIN_V1);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(&bytes);
    bytes.extend_from_slice(&hasher.finalize());
    bytes.try_into().expect("fixed payload replay head")
}

fn decode_head(bytes: &[u8]) -> Result<(u64, [u8; 32], [u8; 32]), PayloadReplayErrorV1> {
    if bytes.len() != HEAD_BYTES_V1
        || bytes[..8] != HEAD_MAGIC_V1
        || bytes[8] != HEAD_VERSION_V1
        || bytes[9..12] != [0, 0, 0]
    {
        return Err(PayloadReplayErrorV1::Corrupt);
    }
    let mut hasher = Sha256::new();
    hasher.update(HEAD_DOMAIN_V1);
    hasher.update((HEAD_PREFIX_BYTES_V1 as u64).to_be_bytes());
    hasher.update(&bytes[..HEAD_PREFIX_BYTES_V1]);
    if bytes[HEAD_PREFIX_BYTES_V1..] != hasher.finalize()[..] {
        return Err(PayloadReplayErrorV1::Corrupt);
    }
    Ok((
        u64::from_be_bytes(bytes[12..20].try_into().expect("head count")),
        bytes[20..52].try_into().expect("head hash"),
        bytes[52..84].try_into().expect("head namespace"),
    ))
}

fn persist_head(
    path: &Path,
    directory: &File,
    record_count: u64,
    record_hash: [u8; 32],
    namespace_digest: [u8; 32],
) -> Result<(), PayloadReplayErrorV1> {
    let name = path.file_name().and_then(|value| value.to_str()).ok_or(
        PayloadReplayErrorV1::InvalidRequest("payload replay head filename"),
    )?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.is_file() || !private_file_mode(&metadata) {
            return Err(PayloadReplayErrorV1::InvalidRequest(
                "payload replay head is not private",
            ));
        }
    }
    let temporary =
        path.with_file_name(format!(".{name}.tmp-{}-{record_count}", std::process::id()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        set_private_mode_options(&mut options);
        let mut file = options.open(&temporary)?;
        file.write_all(&encode_head(record_count, record_hash, namespace_digest))?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        directory.sync_all()?;
        Ok::<(), io::Error>(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(PayloadReplayErrorV1::Io(error));
    }
    Ok(())
}

fn sidecar_path(path: &Path, suffix: &str) -> Result<PathBuf, PayloadReplayErrorV1> {
    let name = path.file_name().and_then(|value| value.to_str()).ok_or(
        PayloadReplayErrorV1::InvalidRequest("payload replay path filename"),
    )?;
    Ok(path.with_file_name(format!(".{name}.{suffix}")))
}

fn private_parent(path: &Path) -> Result<(File, PathBuf), PayloadReplayErrorV1> {
    let parent = path
        .parent()
        .ok_or(PayloadReplayErrorV1::InvalidRequest(
            "payload replay path has no parent",
        ))?
        .to_path_buf();
    let metadata = fs::symlink_metadata(&parent).map_err(PayloadReplayErrorV1::Io)?;
    if !metadata.is_dir() || !private_parent_mode(&metadata) {
        return Err(PayloadReplayErrorV1::InvalidRequest(
            "payload replay parent directory is not private",
        ));
    }
    let directory = File::open(&parent).map_err(PayloadReplayErrorV1::Io)?;
    Ok((directory, parent))
}

fn open_private_lock(path: &Path) -> Result<File, PayloadReplayErrorV1> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    set_private_mode_options(&mut options);
    let file = options.open(path).map_err(PayloadReplayErrorV1::Io)?;
    validate_private_file(&file)?;
    Ok(file)
}

fn validate_private_file(file: &File) -> Result<(), PayloadReplayErrorV1> {
    let metadata = file.metadata().map_err(PayloadReplayErrorV1::Io)?;
    if !private_file_mode(&metadata) {
        return Err(PayloadReplayErrorV1::InvalidRequest(
            "payload replay file permissions are not private",
        ));
    }
    Ok(())
}

fn set_private_mode(file: &File) -> Result<(), PayloadReplayErrorV1> {
    #[cfg(unix)]
    {
        file.set_permissions(fs::Permissions::from_mode(PRIVATE_MODE_V1))
            .map_err(PayloadReplayErrorV1::Io)
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(())
    }
}

fn set_private_mode_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        options.mode(PRIVATE_MODE_V1);
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
}

fn private_parent_mode(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        metadata.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

fn private_file_mode(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        metadata.nlink() == 1 && metadata.permissions().mode() & 0o7777 == PRIVATE_MODE_V1
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn namespace() -> PayloadReplayNamespaceV1 {
        PayloadReplayNamespaceV1::new([1; 32], 7, [2; 32], [3; 32], [4; 32]).unwrap()
    }

    fn frame(
        ns: PayloadReplayNamespaceV1,
        remote: [u8; 32],
        direction: PayloadReplayDirectionV1,
        session: [u8; 32],
        generation: u64,
        sequence: u64,
        fingerprint: [u8; 32],
    ) -> PayloadReplayFrameV1 {
        PayloadReplayFrameV1::new(
            ns.scope_for(remote, direction).unwrap(),
            ns.run_id_hash(),
            ns.network_context_hash(),
            session,
            generation,
            sequence,
            2,
            11,
            fingerprint,
        )
        .unwrap()
    }

    fn private_tempdir() -> TempDir {
        let directory = tempfile::Builder::new()
            .prefix("trnm-payload-replay-")
            .tempdir()
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        directory
    }

    #[test]
    fn generation_and_sequence_are_durable_and_strict() {
        let dir = private_tempdir();
        let path = dir.path().join("frames.wal");
        let ns = namespace();
        let mut store = PayloadReplayStoreV1::open(&path, ns).unwrap();
        let first = frame(
            ns,
            [9; 32],
            PeerLeaseDirectionV1::Inbound,
            [5; 32],
            1,
            0,
            [10; 32],
        );
        let second = frame(
            ns,
            [9; 32],
            PeerLeaseDirectionV1::Inbound,
            [5; 32],
            1,
            1,
            [11; 32],
        );
        store.admit(&first).unwrap();
        store.admit(&second).unwrap();
        assert!(matches!(
            store.admit(&second),
            Err(PayloadReplayErrorV1::Replay)
        ));
        let gap = frame(
            ns,
            [9; 32],
            PeerLeaseDirectionV1::Inbound,
            [5; 32],
            1,
            3,
            [12; 32],
        );
        assert!(matches!(
            store.admit(&gap),
            Err(PayloadReplayErrorV1::SequenceGap)
        ));
        drop(store);
        let mut reopened = PayloadReplayStoreV1::open(&path, ns).unwrap();
        assert_eq!(reopened.accepted_frame_count(), 2);
        let next = frame(
            ns,
            [9; 32],
            PeerLeaseDirectionV1::Inbound,
            [6; 32],
            2,
            0,
            [13; 32],
        );
        reopened.admit(&next).unwrap();
        assert_eq!(
            reopened.latest_generation([9; 32], PeerLeaseDirectionV1::Inbound),
            Some(2)
        );
        let old = frame(
            ns,
            [9; 32],
            PeerLeaseDirectionV1::Inbound,
            [5; 32],
            1,
            2,
            [14; 32],
        );
        assert!(matches!(
            reopened.admit(&old),
            Err(PayloadReplayErrorV1::Replay)
        ));
    }

    #[test]
    fn truncation_mutation_and_prefix_sidecar_fail_closed() {
        let dir = private_tempdir();
        let path = dir.path().join("frames.wal");
        let ns = namespace();
        let mut store = PayloadReplayStoreV1::open(&path, ns).unwrap();
        store
            .admit(&frame(
                ns,
                [9; 32],
                PeerLeaseDirectionV1::Outbound,
                [5; 32],
                1,
                0,
                [10; 32],
            ))
            .unwrap();
        store
            .admit(&frame(
                ns,
                [9; 32],
                PeerLeaseDirectionV1::Outbound,
                [5; 32],
                1,
                1,
                [11; 32],
            ))
            .unwrap();
        drop(store);

        let original = fs::read(&path).unwrap();
        fs::write(&path, &original[..original.len() - RECORD_BYTES_V1]).unwrap();
        assert!(matches!(
            PayloadReplayStoreV1::open(&path, ns),
            Err(PayloadReplayErrorV1::Corrupt) | Err(PayloadReplayErrorV1::Truncated)
        ));
        fs::write(&path, &original).unwrap();
        let mut mutated = original.clone();
        mutated[RECORD_PREFIX_BYTES_V1 + 4] ^= 1;
        fs::write(&path, mutated).unwrap();
        assert!(matches!(
            PayloadReplayStoreV1::open(&path, ns),
            Err(PayloadReplayErrorV1::Corrupt)
        ));
        fs::write(&path, &original).unwrap();
        let mut prefix_head = fs::read(dir.path().join(".frames.wal.head-v1")).unwrap();
        prefix_head[12..20].copy_from_slice(&2u64.to_be_bytes());
        fs::write(dir.path().join(".frames.wal.head-v1"), prefix_head).unwrap();
        assert!(matches!(
            PayloadReplayStoreV1::open(&path, ns),
            Err(PayloadReplayErrorV1::Corrupt)
        ));
    }

    #[test]
    fn context_and_direction_are_part_of_the_fence() {
        let dir = private_tempdir();
        let path = dir.path().join("frames.wal");
        let ns = namespace();
        let mut store = PayloadReplayStoreV1::open(&path, ns).unwrap();
        let wrong_scope =
            PayloadReplayNamespaceV1::new([8; 32], 7, [2; 32], [3; 32], [4; 32]).unwrap();
        let wrong = frame(
            wrong_scope,
            [9; 32],
            PeerLeaseDirectionV1::Inbound,
            [5; 32],
            1,
            0,
            [10; 32],
        );
        assert!(matches!(
            store.admit(&wrong),
            Err(PayloadReplayErrorV1::ContextMismatch)
        ));
        let inbound = frame(
            ns,
            [9; 32],
            PeerLeaseDirectionV1::Inbound,
            [5; 32],
            1,
            0,
            [11; 32],
        );
        let outbound = frame(
            ns,
            [9; 32],
            PeerLeaseDirectionV1::Outbound,
            [5; 32],
            1,
            0,
            [12; 32],
        );
        store.admit(&inbound).unwrap();
        store.admit(&outbound).unwrap();
        assert!(store.contains_session([9; 32], PeerLeaseDirectionV1::Inbound, [5; 32]));
        assert!(store.contains_session([9; 32], PeerLeaseDirectionV1::Outbound, [5; 32]));
    }
}
