//! Durable host event/commit WAL seam.
//!
//! This module is intentionally independent from `RuntimeEventJournalV1`.
//! The latter records runtime observations and signed response replay; this
//! journal records the smaller, earlier host boundary: an event intent is
//! durably prepared before an application/commit effect, and the exact
//! committed result is durably acknowledged afterwards.  A restart can then
//! distinguish "the effect was never prepared" from "the effect may have
//! landed and needs an exact readback" without guessing from a log tail.
//!
//! The module is composition-only (`node-event-wal` feature).  It does not
//! drive Core, an application store, networking, or a signer, and it does not
//! change any activation flag.  Callers must bind the three digests to their
//! own authenticated host state and only append the commit record after that
//! state has a durable readback.

#![cfg(feature = "node-event-wal")]

use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::PocoNodeHostErrorV0;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

/// The WAL is a runnable composition seam, not a production authority.
pub const NODE_EVENT_WAL_RUNTIME_COMPOSITION_V1: bool = true;
pub const NODE_EVENT_WAL_PRODUCTION_ACTIVATION_V1: bool = false;

/// Host-facing name for the bounded WAL owner.  The alias is intentionally
/// explicit about its scope: it is an event/commit authority seam, not a
/// complete application or consensus effect driver.
pub type PocoNodeHostEventCommitWalV1 = NodeEventWalV1;

const DOMAIN_V1: &[u8] = b"trnm.poco-node.host-event-wal.v1\0";
const MAGIC_V1: [u8; 8] = *b"TRNMEVW1";
const FRAME_BYTES_V1: usize = 248;
const CHECKSUM_OFFSET_V1: usize = 216;
const MAX_FRAMES_V1: usize = 1_048_576;

const KIND_GENESIS_V1: u8 = 0;
const KIND_INTENT_V1: u8 = 1;
const KIND_COMMIT_V1: u8 = 2;

/// Errors are deliberately coarse: callers must not use an I/O error's text
/// as an authority signal.  Every malformed, truncated, forked, or poisoned
/// WAL is handled as a fail-closed error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeEventWalErrorV1 {
    Io,
    InvalidPath,
    InvalidField,
    Malformed,
    Truncated,
    NamespaceMismatch,
    ChainMismatch,
    SequenceMismatch,
    PendingConflict,
    NoPending,
    PendingMismatch,
    CommitMismatch,
    PredecessorMismatch,
    AlreadyCommitted,
    RecoveryReadbackRequired,
    Poisoned,
    TooLarge,
}

/// Error boundary for the concrete, feature-gated adapter which binds this
/// WAL to [`crate::PocoNodeHostV0`].  The WAL itself remains usable without the
/// adapter; keeping host errors in a separate arm prevents a caller from
/// mistaking an application/consensus failure for a successfully committed
/// event.
#[derive(Debug)]
pub enum PocoNodeHostEventWalErrorV1 {
    Wal(NodeEventWalErrorV1),
    Host(PocoNodeHostErrorV0),
    StrictValidatorSetAdmission,
    BindingMismatch,
    RecoveryReadbackRequired,
}

impl fmt::Display for PocoNodeHostEventWalErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wal(error) => write!(formatter, "node-event WAL error: {error}"),
            Self::Host(error) => write!(formatter, "PocoNodeHost event boundary failed: {error}"),
            Self::StrictValidatorSetAdmission => formatter.write_str(
                "PocoNodeHost event owner requires strict Ed25519 validator-set admission",
            ),
            Self::BindingMismatch => formatter.write_str(
                "PocoNodeHost event tuple does not match the authenticated durable predecessor",
            ),
            Self::RecoveryReadbackRequired => formatter.write_str(
                "PocoNodeHost event effect is uncertain and requires an explicit durable readback",
            ),
        }
    }
}

impl Error for PocoNodeHostEventWalErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wal(error) => Some(error),
            Self::Host(error) => Some(error),
            Self::StrictValidatorSetAdmission
            | Self::BindingMismatch
            | Self::RecoveryReadbackRequired => None,
        }
    }
}

impl From<NodeEventWalErrorV1> for PocoNodeHostEventWalErrorV1 {
    fn from(error: NodeEventWalErrorV1) -> Self {
        Self::Wal(error)
    }
}

impl fmt::Display for NodeEventWalErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Io => "node-event WAL I/O failed",
            Self::InvalidPath => "node-event WAL path is invalid",
            Self::InvalidField => "node-event WAL field is invalid",
            Self::Malformed => "node-event WAL record is malformed",
            Self::Truncated => "node-event WAL has a partial record",
            Self::NamespaceMismatch => "node-event WAL namespace differs",
            Self::ChainMismatch => "node-event WAL hash chain differs",
            Self::SequenceMismatch => "node-event WAL sequence is not contiguous",
            Self::PendingConflict => "node-event WAL already has a pending intent",
            Self::NoPending => "node-event WAL has no pending intent",
            Self::PendingMismatch => "node-event WAL pending intent differs",
            Self::CommitMismatch => "node-event WAL commit differs from its intent",
            Self::PredecessorMismatch => {
                "node-event WAL predecessor does not follow the last commit"
            }
            Self::AlreadyCommitted => "node-event WAL event is already committed",
            Self::RecoveryReadbackRequired => {
                "node-event WAL pending event requires an explicit durable readback"
            }
            Self::Poisoned => "node-event WAL is poisoned",
            Self::TooLarge => "node-event WAL exceeds its bounded record count",
        })
    }
}

impl Error for NodeEventWalErrorV1 {}

/// A durable host-side event intent.  The event payload itself remains in the
/// owning application store; this tuple is the authenticated binding to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeEventIntentV1 {
    sequence: u64,
    event_id: [u8; 32],
    predecessor_digest: [u8; 32],
    payload_digest: [u8; 32],
    intent_checksum: [u8; 32],
}

impl NodeEventIntentV1 {
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub const fn event_id(self) -> [u8; 32] {
        self.event_id
    }

    pub const fn predecessor_digest(self) -> [u8; 32] {
        self.predecessor_digest
    }

    pub const fn payload_digest(self) -> [u8; 32] {
        self.payload_digest
    }

    pub const fn intent_checksum(self) -> [u8; 32] {
        self.intent_checksum
    }
}

/// Durable acknowledgement that the host/application commit was read back
/// exactly.  `commit_digest` is supplied by the owning commit authority and
/// must cover its complete canonical post-commit tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeEventCommitReceiptV1 {
    intent_sequence: u64,
    event_id: [u8; 32],
    commit_digest: [u8; 32],
    commit_checksum: [u8; 32],
}

/// Minimal adapter owned by the host/application commit path.
///
/// Implementations must perform the actual application (or host event) write
/// and then return the digest of a fresh durable readback.  The WAL never
/// accepts a caller-supplied receipt before this callback has returned.
pub trait NodeEventCommitDriverV1 {
    fn apply_and_readback_event_v1(
        &mut self,
        intent: NodeEventIntentV1,
    ) -> Result<[u8; 32], NodeEventWalErrorV1>;

    /// Read back an event after a restart without assuming that the write was
    /// lost.  A pending intent is never auto-cleared: the host must provide a
    /// fresh digest from its durable store, and only that digest may advance
    /// the WAL.  Drivers which cannot perform restart readback remain usable
    /// for the forward path but fail closed on recovery.
    fn readback_event_v1(
        &mut self,
        _intent: NodeEventIntentV1,
    ) -> Result<[u8; 32], NodeEventWalErrorV1> {
        Err(NodeEventWalErrorV1::RecoveryReadbackRequired)
    }
}

impl NodeEventCommitReceiptV1 {
    pub const fn intent_sequence(self) -> u64 {
        self.intent_sequence
    }

    pub const fn event_id(self) -> [u8; 32] {
        self.event_id
    }

    pub const fn commit_digest(self) -> [u8; 32] {
        self.commit_digest
    }

    pub const fn commit_checksum(self) -> [u8; 32] {
        self.commit_checksum
    }
}

/// Recovery classification for a host event after reopening the WAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeEventRecoveryV1 {
    Clean {
        last_commit: Option<NodeEventCommitReceiptV1>,
    },
    Pending(NodeEventIntentV1),
}

/// Stable identity of the directory and WAL inode admitted at open.  The
/// path is intentionally not treated as an authority: a same-UID caller can
/// rename a directory or replace a regular file while retaining the textual
/// path.  On Unix, device/inode binding plus held directory/file descriptors
/// prevents that replacement from becoming an invisible new journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NodeEventPathIdentityV1 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

#[cfg(unix)]
impl NodeEventPathIdentityV1 {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[cfg(not(unix))]
impl NodeEventPathIdentityV1 {
    fn from_metadata(_metadata: &fs::Metadata) -> Self {
        Self {}
    }
}

/// A linear owner of one append-only host event WAL.
///
/// The owner is intentionally non-`Clone`; two owners must not race the same
/// event namespace.  Every frame is fixed-size, checksummed, and linked to
/// the previous frame.  A partial frame, changed namespace, interior rewrite,
/// or sequence fork poisons startup instead of being silently repaired.
#[derive(Debug)]
pub struct NodeEventWalV1 {
    path: PathBuf,
    parent_file: File,
    file: File,
    parent_identity: NodeEventPathIdentityV1,
    file_identity: NodeEventPathIdentityV1,
    namespace: [u8; 32],
    head: [u8; 32],
    next_sequence: u64,
    pending: Option<NodeEventIntentV1>,
    last_commit: Option<NodeEventCommitReceiptV1>,
    poisoned: bool,
}

impl NodeEventWalV1 {
    /// Open an existing WAL or create its authenticated genesis frame.
    pub fn open(path: impl AsRef<Path>, namespace: [u8; 32]) -> Result<Self, NodeEventWalErrorV1> {
        if namespace == [0; 32] {
            return Err(NodeEventWalErrorV1::InvalidField);
        }
        let path = path.as_ref().to_path_buf();
        validate_path_v1(&path)?;
        let parent_file = open_parent_v1(&path)?;
        let parent_identity = path_identity_from_file_v1(&parent_file)?;
        let existing_file_identity = match fs::symlink_metadata(&path) {
            Ok(metadata) => Some(NodeEventPathIdentityV1::from_metadata(&metadata)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(NodeEventWalErrorV1::InvalidPath),
        };
        let mut options = OpenOptions::new();
        options.read(true).write(true).append(true);
        if existing_file_identity.is_some() {
            // An already admitted WAL must never be recreated if it
            // disappears between lstat and open; that would turn deletion
            // into a silent genesis/rollback on restart.
            options.create(false);
        } else {
            // A virgin path is claimed atomically.  A competing creator
            // loses with an error instead of having its bytes adopted as the
            // authority journal.
            options.create_new(true);
        }
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = options.open(&path).map_err(|_| NodeEventWalErrorV1::Io)?;
        let metadata = file.metadata().map_err(|_| NodeEventWalErrorV1::Io)?;
        validate_open_file_v1(&file, &path, metadata.len() == 0)?;
        let file_identity = NodeEventPathIdentityV1::from_metadata(&metadata);
        if existing_file_identity.is_some_and(|identity| identity != file_identity) {
            return Err(NodeEventWalErrorV1::InvalidPath);
        }
        validate_path_binding_v1(&path, parent_identity, file_identity)?;
        if metadata.len() == 0 {
            let frame = encode_frame_v1(
                KIND_GENESIS_V1,
                0,
                [0; 32],
                namespace,
                [0; 32],
                [0; 32],
                [0; 32],
                [0; 32],
            );
            file.write_all(&frame)
                .map_err(|_| NodeEventWalErrorV1::Io)?;
            file.sync_all().map_err(|_| NodeEventWalErrorV1::Io)?;
            parent_file
                .sync_all()
                .map_err(|_| NodeEventWalErrorV1::Io)?;
        }
        let mut wal = Self {
            path,
            parent_file,
            file,
            parent_identity,
            file_identity,
            namespace,
            head: [0; 32],
            next_sequence: 0,
            pending: None,
            last_commit: None,
            poisoned: false,
        };
        wal.reload_v1()?;
        Ok(wal)
    }

    pub const fn namespace(&self) -> [u8; 32] {
        self.namespace
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn head(&self) -> [u8; 32] {
        self.head
    }

    pub const fn pending(&self) -> Option<NodeEventIntentV1> {
        self.pending
    }

    pub const fn last_commit(&self) -> Option<NodeEventCommitReceiptV1> {
        self.last_commit
    }

    pub const fn recovery(&self) -> NodeEventRecoveryV1 {
        match self.pending {
            Some(intent) => NodeEventRecoveryV1::Pending(intent),
            None => NodeEventRecoveryV1::Clean {
                last_commit: self.last_commit,
            },
        }
    }

    /// Append the pre-effect host intent.  Only one unresolved intent is
    /// admitted; this keeps recovery deterministic and prevents a caller from
    /// hiding an older application commit behind a newer event.
    pub fn prepare_event_v1(
        &mut self,
        event_id: [u8; 32],
        predecessor_digest: [u8; 32],
        payload_digest: [u8; 32],
    ) -> Result<NodeEventIntentV1, NodeEventWalErrorV1> {
        self.ensure_live_v1()?;
        if event_id == [0; 32] || predecessor_digest == [0; 32] || payload_digest == [0; 32] {
            return Err(NodeEventWalErrorV1::InvalidField);
        }
        if self.pending.is_some() {
            return Err(NodeEventWalErrorV1::PendingConflict);
        }
        if self
            .last_commit
            .is_some_and(|receipt| receipt.commit_digest != predecessor_digest)
        {
            return Err(NodeEventWalErrorV1::PredecessorMismatch);
        }
        if self
            .last_commit
            .is_some_and(|receipt| receipt.event_id == event_id)
        {
            return Err(NodeEventWalErrorV1::AlreadyCommitted);
        }
        let sequence = self.next_sequence;
        let frame = encode_frame_v1(
            KIND_INTENT_V1,
            sequence,
            self.head,
            self.namespace,
            event_id,
            predecessor_digest,
            payload_digest,
            [0; 32],
        );
        let checksum = frame_checksum_v1(&frame);
        self.append_frame_v1(&frame)?;
        let intent = NodeEventIntentV1 {
            sequence,
            event_id,
            predecessor_digest,
            payload_digest,
            intent_checksum: checksum,
        };
        self.pending = Some(intent);
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or(NodeEventWalErrorV1::SequenceMismatch)?;
        self.head = checksum;
        Ok(intent)
    }

    /// Append the post-effect commit receipt for the currently pending event.
    pub fn commit_event_v1(
        &mut self,
        intent: NodeEventIntentV1,
        commit_digest: [u8; 32],
    ) -> Result<NodeEventCommitReceiptV1, NodeEventWalErrorV1> {
        self.ensure_live_v1()?;
        if commit_digest == [0; 32] {
            return Err(NodeEventWalErrorV1::InvalidField);
        }
        let Some(pending) = self.pending else {
            return Err(NodeEventWalErrorV1::NoPending);
        };
        if pending != intent {
            return Err(NodeEventWalErrorV1::PendingMismatch);
        }
        let sequence = self.next_sequence;
        let frame = encode_frame_v1(
            KIND_COMMIT_V1,
            sequence,
            self.head,
            self.namespace,
            intent.event_id,
            intent.predecessor_digest,
            intent.payload_digest,
            commit_digest,
        );
        let checksum = frame_checksum_v1(&frame);
        self.append_frame_v1(&frame)?;
        let receipt = NodeEventCommitReceiptV1 {
            intent_sequence: intent.sequence,
            event_id: intent.event_id,
            commit_digest,
            commit_checksum: checksum,
        };
        self.pending = None;
        self.last_commit = Some(receipt);
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or(NodeEventWalErrorV1::SequenceMismatch)?;
        self.head = checksum;
        Ok(receipt)
    }

    /// Execute the narrow host event commit ordering:
    ///
    /// `intent WAL fsync → driver apply → driver durable readback → commit WAL
    /// fsync`.
    ///
    /// If the driver returns an error (including an uncertain I/O result), the
    /// intent deliberately remains pending.  Recovery must inspect the
    /// driver's store and call [`Self::commit_event_v1`] with the exact
    /// readback digest; it may not silently append a different event.
    pub fn commit_with_driver_v1<D: NodeEventCommitDriverV1>(
        &mut self,
        intent: NodeEventIntentV1,
        driver: &mut D,
    ) -> Result<NodeEventCommitReceiptV1, NodeEventWalErrorV1> {
        let commit_digest = driver.apply_and_readback_event_v1(intent)?;
        self.commit_event_v1(intent, commit_digest)
    }

    /// Exact replay check used after a crash where the commit append may have
    /// succeeded but the caller did not observe the return value.  It never
    /// advances the WAL and rejects a same-event/different-result substitution.
    pub fn confirm_committed_event_v1(
        &self,
        event_id: [u8; 32],
        commit_digest: [u8; 32],
    ) -> Result<NodeEventCommitReceiptV1, NodeEventWalErrorV1> {
        self.ensure_live_v1()?;
        let Some(receipt) = self.last_commit else {
            return Err(NodeEventWalErrorV1::NoPending);
        };
        if receipt.event_id != event_id {
            return Err(NodeEventWalErrorV1::CommitMismatch);
        }
        if receipt.commit_digest != commit_digest {
            return Err(NodeEventWalErrorV1::CommitMismatch);
        }
        Ok(receipt)
    }

    /// Re-read the file and re-validate every frame.  This is useful for a
    /// caller that has just reopened its application store and wants an
    /// explicit fresh WAL observation rather than cached facts.
    pub fn revalidate_v1(&mut self) -> Result<NodeEventRecoveryV1, NodeEventWalErrorV1> {
        self.ensure_live_v1()?;
        if let Err(error) = self.reload_v1() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(self.recovery())
    }

    fn ensure_live_v1(&self) -> Result<(), NodeEventWalErrorV1> {
        if self.poisoned {
            return Err(NodeEventWalErrorV1::Poisoned);
        }
        if self.head == [0; 32] || self.next_sequence == 0 {
            return Err(NodeEventWalErrorV1::Poisoned);
        }
        Ok(())
    }

    fn append_frame_v1(&mut self, frame: &[u8; FRAME_BYTES_V1]) -> Result<(), NodeEventWalErrorV1> {
        let result = (|| {
            self.validate_path_binding_v1()?;
            let mut file = self.file.try_clone().map_err(|_| NodeEventWalErrorV1::Io)?;
            validate_open_file_v1(&file, &self.path, false)?;
            let metadata = file.metadata().map_err(|_| NodeEventWalErrorV1::Io)?;
            if NodeEventPathIdentityV1::from_metadata(&metadata) != self.file_identity {
                return Err(NodeEventWalErrorV1::InvalidPath);
            }
            file.write_all(frame).map_err(|_| NodeEventWalErrorV1::Io)?;
            file.sync_all().map_err(|_| NodeEventWalErrorV1::Io)?;
            self.parent_file
                .sync_all()
                .map_err(|_| NodeEventWalErrorV1::Io)?;
            self.validate_path_binding_v1()
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn reload_v1(&mut self) -> Result<(), NodeEventWalErrorV1> {
        self.validate_path_binding_v1()?;
        let mut file = self.file.try_clone().map_err(|_| NodeEventWalErrorV1::Io)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| NodeEventWalErrorV1::Io)?;
        validate_open_file_v1(&file, &self.path, false)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| NodeEventWalErrorV1::Io)?;
        let metadata = file.metadata().map_err(|_| NodeEventWalErrorV1::Io)?;
        if NodeEventPathIdentityV1::from_metadata(&metadata) != self.file_identity {
            return Err(NodeEventWalErrorV1::InvalidPath);
        }
        if bytes.is_empty() || bytes.len() % FRAME_BYTES_V1 != 0 {
            return Err(NodeEventWalErrorV1::Truncated);
        }
        let frame_count = bytes.len() / FRAME_BYTES_V1;
        if frame_count > MAX_FRAMES_V1 {
            return Err(NodeEventWalErrorV1::TooLarge);
        }
        let mut expected_sequence = 0_u64;
        let mut previous_checksum = [0_u8; 32];
        let mut pending: Option<NodeEventIntentV1> = None;
        let mut last_commit: Option<NodeEventCommitReceiptV1> = None;
        for chunk in bytes.chunks_exact(FRAME_BYTES_V1) {
            let frame: &[u8; FRAME_BYTES_V1] = chunk.try_into().expect("fixed frame");
            let decoded = decode_frame_v1(frame)?;
            if decoded.namespace != self.namespace {
                return Err(NodeEventWalErrorV1::NamespaceMismatch);
            }
            if decoded.sequence != expected_sequence {
                return Err(NodeEventWalErrorV1::SequenceMismatch);
            }
            if decoded.previous != previous_checksum {
                return Err(NodeEventWalErrorV1::ChainMismatch);
            }
            let checksum = frame_checksum_v1(frame);
            if checksum != decoded.checksum {
                return Err(NodeEventWalErrorV1::Malformed);
            }
            if expected_sequence == 0 {
                if decoded.kind != KIND_GENESIS_V1
                    || decoded.event_id != [0; 32]
                    || decoded.commit_digest != [0; 32]
                {
                    return Err(NodeEventWalErrorV1::Malformed);
                }
            } else {
                match decoded.kind {
                    KIND_INTENT_V1 => {
                        if pending.is_some()
                            || decoded.event_id == [0; 32]
                            || decoded.predecessor_digest == [0; 32]
                            || decoded.payload_digest == [0; 32]
                            || decoded.commit_digest != [0; 32]
                        {
                            return Err(NodeEventWalErrorV1::PendingConflict);
                        }
                        if last_commit.is_some_and(|receipt| {
                            receipt.commit_digest != decoded.predecessor_digest
                        }) {
                            return Err(NodeEventWalErrorV1::PredecessorMismatch);
                        }
                        pending = Some(NodeEventIntentV1 {
                            sequence: decoded.sequence,
                            event_id: decoded.event_id,
                            predecessor_digest: decoded.predecessor_digest,
                            payload_digest: decoded.payload_digest,
                            intent_checksum: checksum,
                        });
                    }
                    KIND_COMMIT_V1 => {
                        let Some(intent) = pending.take() else {
                            return Err(NodeEventWalErrorV1::NoPending);
                        };
                        if decoded.event_id != intent.event_id
                            || decoded.predecessor_digest != intent.predecessor_digest
                            || decoded.payload_digest != intent.payload_digest
                            || decoded.commit_digest == [0; 32]
                        {
                            return Err(NodeEventWalErrorV1::CommitMismatch);
                        }
                        last_commit = Some(NodeEventCommitReceiptV1 {
                            intent_sequence: intent.sequence,
                            event_id: intent.event_id,
                            commit_digest: decoded.commit_digest,
                            commit_checksum: checksum,
                        });
                    }
                    _ => return Err(NodeEventWalErrorV1::Malformed),
                }
            }
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(NodeEventWalErrorV1::SequenceMismatch)?;
            previous_checksum = checksum;
        }
        self.head = previous_checksum;
        self.next_sequence = expected_sequence;
        self.pending = pending;
        self.last_commit = last_commit;
        self.validate_path_binding_v1()
    }

    fn validate_path_binding_v1(&self) -> Result<(), NodeEventWalErrorV1> {
        validate_path_binding_v1(&self.path, self.parent_identity, self.file_identity)
    }
}

/// Feature-gated bounded host composition for the event/commit boundary.
///
/// This owner is the first caller-facing path that actually owns the WAL and
/// the durable commit driver together.  A new event is ordered as:
///
/// `prepare intent + WAL fsync → driver durable write/readback → commit WAL
/// fsync`.
///
/// Reopening the owner performs a fresh WAL validation.  A pending intent is
/// surfaced as [`NodeEventRecoveryV1::Pending`] and can only be closed by the
/// driver's explicit durable readback; no guessed success, local cache, or
/// caller-supplied replacement digest is accepted.  This is a bounded
/// composition seam, not a Core effect driver or a production activation.
pub struct PocoNodeHostEventCommitOwnerV1<D> {
    wal: NodeEventWalV1,
    driver: D,
}

impl<D: NodeEventCommitDriverV1> PocoNodeHostEventCommitOwnerV1<D> {
    /// Open one exclusive host event namespace and retain its commit driver.
    /// The returned owner is the sole object that can advance this WAL in the
    /// composed path.
    pub fn open(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        driver: D,
    ) -> Result<Self, NodeEventWalErrorV1> {
        Ok(Self {
            wal: NodeEventWalV1::open(path, namespace)?,
            driver,
        })
    }

    /// Freshly revalidate the WAL and classify the restart state.
    pub fn restart_recovery_v1(&mut self) -> Result<NodeEventRecoveryV1, NodeEventWalErrorV1> {
        self.wal.revalidate_v1()
    }

    /// Return the cached classification from the last successful open or
    /// revalidation.  Call [`Self::restart_recovery_v1`] at a restart boundary
    /// when the application store has also been reopened.
    pub const fn recovery(&self) -> NodeEventRecoveryV1 {
        self.wal.recovery()
    }

    /// Expose only an immutable WAL view for evidence and readback binding;
    /// callers cannot replace the owner or mutate the journal behind it.
    pub const fn wal(&self) -> &NodeEventWalV1 {
        &self.wal
    }

    /// Prepare an intent before an externally controlled effect.  This small
    /// method is useful when the host needs to hand the exact tuple to a
    /// lower-level bounded driver; normal callers should prefer
    /// [`Self::apply_and_commit_event_v1`].
    pub fn prepare_event_v1(
        &mut self,
        event_id: [u8; 32],
        predecessor_digest: [u8; 32],
        payload_digest: [u8; 32],
    ) -> Result<NodeEventIntentV1, NodeEventWalErrorV1> {
        self.wal
            .prepare_event_v1(event_id, predecessor_digest, payload_digest)
    }

    /// Execute one bounded host event through the durable ordering contract.
    pub fn apply_and_commit_event_v1(
        &mut self,
        event_id: [u8; 32],
        predecessor_digest: [u8; 32],
        payload_digest: [u8; 32],
    ) -> Result<NodeEventCommitReceiptV1, NodeEventWalErrorV1> {
        let intent = self
            .wal
            .prepare_event_v1(event_id, predecessor_digest, payload_digest)?;
        self.wal.commit_with_driver_v1(intent, &mut self.driver)
    }

    /// Resolve a pending intent after restart using only a fresh durable
    /// readback from the owned driver.  If the driver reports uncertainty or a
    /// different digest, the intent remains pending and the owner fails
    /// closed; it is never silently replaced.
    pub fn recover_pending_event_v1(
        &mut self,
    ) -> Result<Option<NodeEventCommitReceiptV1>, NodeEventWalErrorV1> {
        let recovery = self.wal.revalidate_v1()?;
        let NodeEventRecoveryV1::Pending(intent) = recovery else {
            return Ok(None);
        };
        let commit_digest = self.driver.readback_event_v1(intent)?;
        self.wal.commit_event_v1(intent, commit_digest).map(Some)
    }
}

#[derive(Debug, Clone, Copy)]
struct DecodedFrameV1 {
    kind: u8,
    sequence: u64,
    previous: [u8; 32],
    namespace: [u8; 32],
    event_id: [u8; 32],
    predecessor_digest: [u8; 32],
    payload_digest: [u8; 32],
    commit_digest: [u8; 32],
    checksum: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
fn encode_frame_v1(
    kind: u8,
    sequence: u64,
    previous: [u8; 32],
    namespace: [u8; 32],
    event_id: [u8; 32],
    predecessor_digest: [u8; 32],
    payload_digest: [u8; 32],
    commit_digest: [u8; 32],
) -> [u8; FRAME_BYTES_V1] {
    let mut out = [0_u8; FRAME_BYTES_V1];
    out[..8].copy_from_slice(&MAGIC_V1);
    out[8] = kind;
    out[16..24].copy_from_slice(&sequence.to_be_bytes());
    out[24..56].copy_from_slice(&namespace);
    out[56..88].copy_from_slice(&previous);
    out[88..120].copy_from_slice(&event_id);
    out[120..152].copy_from_slice(&predecessor_digest);
    out[152..184].copy_from_slice(&payload_digest);
    out[184..216].copy_from_slice(&commit_digest);
    let checksum = frame_checksum_v1(&out);
    out[CHECKSUM_OFFSET_V1..].copy_from_slice(&checksum);
    out
}

fn decode_frame_v1(frame: &[u8; FRAME_BYTES_V1]) -> Result<DecodedFrameV1, NodeEventWalErrorV1> {
    if frame[..8] != MAGIC_V1 || frame[9..16].iter().any(|byte| *byte != 0) {
        return Err(NodeEventWalErrorV1::Malformed);
    }
    Ok(DecodedFrameV1 {
        kind: frame[8],
        sequence: u64::from_be_bytes(frame[16..24].try_into().expect("fixed sequence")),
        namespace: frame[24..56].try_into().expect("fixed namespace"),
        previous: frame[56..88].try_into().expect("fixed previous"),
        event_id: frame[88..120].try_into().expect("fixed event"),
        predecessor_digest: frame[120..152].try_into().expect("fixed predecessor"),
        payload_digest: frame[152..184].try_into().expect("fixed payload"),
        commit_digest: frame[184..216].try_into().expect("fixed commit"),
        checksum: frame[CHECKSUM_OFFSET_V1..]
            .try_into()
            .expect("fixed checksum"),
    })
}

fn frame_checksum_v1(frame: &[u8; FRAME_BYTES_V1]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_V1);
    hasher.update(&frame[..CHECKSUM_OFFSET_V1]);
    hasher.finalize().into()
}

fn validate_path_v1(path: &Path) -> Result<(), NodeEventWalErrorV1> {
    let Some(parent) = path.parent() else {
        return Err(NodeEventWalErrorV1::InvalidPath);
    };
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(NodeEventWalErrorV1::InvalidPath);
    }
    let metadata = fs::symlink_metadata(parent).map_err(|_| NodeEventWalErrorV1::InvalidPath)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(NodeEventWalErrorV1::InvalidPath);
    }
    // Reject an indirect symlink (or an unresolved `..`) in the parent path
    // as well.  The held parent/file descriptors below then keep the admitted
    // directory and inode stable for the lifetime of the WAL owner.
    if fs::canonicalize(parent).map_err(|_| NodeEventWalErrorV1::InvalidPath)? != parent {
        return Err(NodeEventWalErrorV1::InvalidPath);
    }
    if let Ok(existing) = fs::symlink_metadata(path) {
        if existing.file_type().is_symlink() || !existing.file_type().is_file() {
            return Err(NodeEventWalErrorV1::InvalidPath);
        }
    }
    Ok(())
}

fn open_parent_v1(path: &Path) -> Result<File, NodeEventWalErrorV1> {
    let parent = path.parent().ok_or(NodeEventWalErrorV1::InvalidPath)?;
    #[cfg(unix)]
    {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY);
        let file = options
            .open(parent)
            .map_err(|_| NodeEventWalErrorV1::InvalidPath)?;
        let metadata = file
            .metadata()
            .map_err(|_| NodeEventWalErrorV1::InvalidPath)?;
        if !metadata.is_dir() {
            return Err(NodeEventWalErrorV1::InvalidPath);
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let file = File::open(parent).map_err(|_| NodeEventWalErrorV1::InvalidPath)?;
        if !file
            .metadata()
            .map_err(|_| NodeEventWalErrorV1::InvalidPath)?
            .is_dir()
        {
            return Err(NodeEventWalErrorV1::InvalidPath);
        }
        Ok(file)
    }
}

fn path_identity_from_file_v1(file: &File) -> Result<NodeEventPathIdentityV1, NodeEventWalErrorV1> {
    file.metadata()
        .map(|metadata| NodeEventPathIdentityV1::from_metadata(&metadata))
        .map_err(|_| NodeEventWalErrorV1::Io)
}

fn validate_path_binding_v1(
    path: &Path,
    parent_identity: NodeEventPathIdentityV1,
    file_identity: NodeEventPathIdentityV1,
) -> Result<(), NodeEventWalErrorV1> {
    validate_path_v1(path)?;
    let parent = path.parent().ok_or(NodeEventWalErrorV1::InvalidPath)?;
    let parent_metadata = fs::metadata(parent).map_err(|_| NodeEventWalErrorV1::InvalidPath)?;
    if NodeEventPathIdentityV1::from_metadata(&parent_metadata) != parent_identity {
        return Err(NodeEventWalErrorV1::InvalidPath);
    }
    let file_metadata = fs::metadata(path).map_err(|_| NodeEventWalErrorV1::InvalidPath)?;
    if NodeEventPathIdentityV1::from_metadata(&file_metadata) != file_identity {
        return Err(NodeEventWalErrorV1::InvalidPath);
    }
    Ok(())
}

/// Re-opening through an unchecked path would let a same-UID replacement or
/// symlink redirect the WAL after the initial admission.  Every descriptor
/// used for reload/append is therefore checked as a unique, private regular
/// file; aliases and permissive modes fail closed instead of being repaired.
fn validate_open_file_v1(
    file: &File,
    path: &Path,
    allow_empty: bool,
) -> Result<(), NodeEventWalErrorV1> {
    let metadata = file.metadata().map_err(|_| NodeEventWalErrorV1::Io)?;
    if !metadata.is_file() || (!allow_empty && metadata.len() == 0) || !path.is_absolute() {
        return Err(NodeEventWalErrorV1::InvalidPath);
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
        return Err(NodeEventWalErrorV1::InvalidPath);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[cfg(unix)]
    use std::{env, os::unix::fs::PermissionsExt, process::Command, thread, time::Duration};

    struct FakeCommitDriver {
        digest: [u8; 32],
        fail: bool,
    }

    impl NodeEventCommitDriverV1 for FakeCommitDriver {
        fn apply_and_readback_event_v1(
            &mut self,
            _intent: NodeEventIntentV1,
        ) -> Result<[u8; 32], NodeEventWalErrorV1> {
            if self.fail {
                return Err(NodeEventWalErrorV1::Io);
            }
            Ok(self.digest)
        }
    }

    struct OwnerCommitDriver {
        digest: [u8; 32],
        readback_digest: Option<[u8; 32]>,
        fail_readback: bool,
        wal_path: PathBuf,
        observed_wal_len_during_apply: u64,
        calls: Vec<&'static str>,
    }

    impl NodeEventCommitDriverV1 for OwnerCommitDriver {
        fn apply_and_readback_event_v1(
            &mut self,
            _intent: NodeEventIntentV1,
        ) -> Result<[u8; 32], NodeEventWalErrorV1> {
            self.calls.push("apply-and-readback");
            self.observed_wal_len_during_apply = fs::metadata(&self.wal_path)
                .map_err(|_| NodeEventWalErrorV1::Io)?
                .len();
            Ok(self.digest)
        }

        fn readback_event_v1(
            &mut self,
            _intent: NodeEventIntentV1,
        ) -> Result<[u8; 32], NodeEventWalErrorV1> {
            self.calls.push("restart-readback");
            if self.fail_readback {
                return Err(NodeEventWalErrorV1::Io);
            }
            self.readback_digest
                .ok_or(NodeEventWalErrorV1::RecoveryReadbackRequired)
        }
    }

    fn digest(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn open(temp: &TempDir) -> NodeEventWalV1 {
        NodeEventWalV1::open(temp.path().join("node-events.wal"), digest(1)).unwrap()
    }

    #[test]
    fn intent_reopen_and_exact_commit_replay() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("node-events.wal");
        let intent = {
            let mut wal = NodeEventWalV1::open(&path, digest(1)).unwrap();
            wal.prepare_event_v1(digest(2), digest(3), digest(4))
                .unwrap()
        };
        let mut reopened = NodeEventWalV1::open(&path, digest(1)).unwrap();
        assert_eq!(reopened.recovery(), NodeEventRecoveryV1::Pending(intent));
        let receipt = reopened.commit_event_v1(intent, digest(5)).unwrap();
        assert_eq!(receipt.intent_sequence(), intent.sequence());
        drop(reopened);
        let reopened = NodeEventWalV1::open(&path, digest(1)).unwrap();
        assert!(matches!(
            reopened.recovery(),
            NodeEventRecoveryV1::Clean {
                last_commit: Some(_)
            }
        ));
        assert_eq!(
            reopened.confirm_committed_event_v1(digest(2), digest(5)),
            Ok(receipt)
        );
        assert_eq!(
            reopened.confirm_committed_event_v1(digest(2), digest(6)),
            Err(NodeEventWalErrorV1::CommitMismatch)
        );
    }

    #[test]
    fn driver_order_keeps_intent_when_commit_readback_is_uncertain() {
        let temp = TempDir::new().unwrap();
        let mut wal = open(&temp);
        let intent = wal
            .prepare_event_v1(digest(2), digest(3), digest(4))
            .unwrap();
        let mut failing = FakeCommitDriver {
            digest: digest(5),
            fail: true,
        };
        assert_eq!(
            wal.commit_with_driver_v1(intent, &mut failing),
            Err(NodeEventWalErrorV1::Io)
        );
        assert_eq!(wal.pending(), Some(intent));
        failing.fail = false;
        let receipt = wal.commit_with_driver_v1(intent, &mut failing).unwrap();
        assert_eq!(receipt.commit_digest(), digest(5));
        assert!(wal.pending().is_none());
    }

    #[test]
    fn bounded_owner_orders_durable_intent_before_driver_and_classifies_restart_pending() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("owner-events.wal");
        let mut owner = PocoNodeHostEventCommitOwnerV1::open(
            &path,
            digest(1),
            OwnerCommitDriver {
                digest: digest(5),
                readback_digest: Some(digest(5)),
                fail_readback: false,
                wal_path: path.clone(),
                observed_wal_len_during_apply: 0,
                calls: Vec::new(),
            },
        )
        .unwrap();
        assert!(matches!(
            owner.recovery(),
            NodeEventRecoveryV1::Clean { last_commit: None }
        ));
        let receipt = owner
            .apply_and_commit_event_v1(digest(2), digest(3), digest(4))
            .unwrap();
        assert_eq!(receipt.commit_digest(), digest(5));
        assert_eq!(owner.wal().pending(), None);
        assert_eq!(owner.wal().last_commit(), Some(receipt));
        assert_eq!(owner.wal().path(), path.as_path());
        assert_eq!(owner.wal().head(), receipt.commit_checksum());
        // Genesis + intent are already durable when the actual driver runs;
        // the commit frame is appended only after the callback returns.
        assert_eq!(
            owner.driver.observed_wal_len_during_apply,
            (FRAME_BYTES_V1 * 2) as u64
        );
        assert_eq!(owner.driver.calls, vec!["apply-and-readback"]);
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            (FRAME_BYTES_V1 * 3) as u64
        );

        let pending_path = temp.path().join("pending-owner-events.wal");
        let intent = {
            let mut pending_owner = PocoNodeHostEventCommitOwnerV1::open(
                &pending_path,
                digest(1),
                OwnerCommitDriver {
                    digest: digest(5),
                    readback_digest: Some(digest(5)),
                    fail_readback: false,
                    wal_path: pending_path.clone(),
                    observed_wal_len_during_apply: 0,
                    calls: Vec::new(),
                },
            )
            .unwrap();
            pending_owner
                .prepare_event_v1(digest(6), digest(7), digest(8))
                .unwrap()
        };
        let mut reopened = PocoNodeHostEventCommitOwnerV1::open(
            &pending_path,
            digest(1),
            OwnerCommitDriver {
                digest: digest(9),
                readback_digest: Some(digest(9)),
                fail_readback: false,
                wal_path: pending_path.clone(),
                observed_wal_len_during_apply: 0,
                calls: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(
            reopened.restart_recovery_v1().unwrap(),
            NodeEventRecoveryV1::Pending(intent)
        );
        let recovered = reopened.recover_pending_event_v1().unwrap().unwrap();
        assert_eq!(recovered.event_id(), digest(6));
        assert_eq!(recovered.commit_digest(), digest(9));
        assert_eq!(reopened.driver.calls, vec!["restart-readback"]);
        assert!(matches!(
            reopened.restart_recovery_v1().unwrap(),
            NodeEventRecoveryV1::Clean {
                last_commit: Some(_)
            }
        ));
    }

    #[test]
    fn bounded_owner_keeps_pending_when_restart_readback_is_uncertain() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("uncertain-owner-events.wal");
        let intent = {
            let mut owner = PocoNodeHostEventCommitOwnerV1::open(
                &path,
                digest(1),
                OwnerCommitDriver {
                    digest: digest(5),
                    readback_digest: None,
                    fail_readback: false,
                    wal_path: path.clone(),
                    observed_wal_len_during_apply: 0,
                    calls: Vec::new(),
                },
            )
            .unwrap();
            owner
                .prepare_event_v1(digest(2), digest(3), digest(4))
                .unwrap()
        };
        let mut reopened = PocoNodeHostEventCommitOwnerV1::open(
            &path,
            digest(1),
            OwnerCommitDriver {
                digest: digest(5),
                readback_digest: Some(digest(5)),
                fail_readback: true,
                wal_path: path.clone(),
                observed_wal_len_during_apply: 0,
                calls: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(
            reopened.recover_pending_event_v1(),
            Err(NodeEventWalErrorV1::Io)
        );
        assert_eq!(reopened.wal().pending(), Some(intent));
        assert_eq!(reopened.driver.calls, vec!["restart-readback"]);
    }

    #[test]
    fn pending_and_duplicate_intents_fail_closed() {
        let temp = TempDir::new().unwrap();
        let mut wal = open(&temp);
        let intent = wal
            .prepare_event_v1(digest(2), digest(3), digest(4))
            .unwrap();
        assert_eq!(
            wal.prepare_event_v1(digest(6), digest(7), digest(8)),
            Err(NodeEventWalErrorV1::PendingConflict)
        );
        assert_eq!(
            wal.commit_event_v1(
                NodeEventIntentV1 {
                    event_id: digest(9),
                    ..intent
                },
                digest(5)
            ),
            Err(NodeEventWalErrorV1::PendingMismatch)
        );
        wal.commit_event_v1(intent, digest(5)).unwrap();
        assert_eq!(
            wal.prepare_event_v1(digest(2), digest(5), digest(4)),
            Err(NodeEventWalErrorV1::AlreadyCommitted)
        );
        assert_eq!(
            wal.prepare_event_v1(digest(6), digest(7), digest(8)),
            Err(NodeEventWalErrorV1::PredecessorMismatch)
        );
        let next = wal
            .prepare_event_v1(digest(6), digest(5), digest(8))
            .unwrap();
        wal.commit_event_v1(next, digest(9)).unwrap();
    }

    #[test]
    fn truncation_and_interior_rewrite_are_rejected_on_reopen() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("node-events.wal");
        {
            let mut wal = NodeEventWalV1::open(&path, digest(1)).unwrap();
            let intent = wal
                .prepare_event_v1(digest(2), digest(3), digest(4))
                .unwrap();
            wal.commit_event_v1(intent, digest(5)).unwrap();
        }
        let original = fs::read(&path).unwrap();
        fs::write(&path, &original[..original.len() - 1]).unwrap();
        assert_eq!(
            NodeEventWalV1::open(&path, digest(1)).unwrap_err(),
            NodeEventWalErrorV1::Truncated
        );
        fs::write(&path, &original).unwrap();
        let mut rewritten = original.clone();
        rewritten[100] ^= 0x40;
        fs::write(&path, rewritten).unwrap();
        assert!(matches!(
            NodeEventWalV1::open(&path, digest(1)),
            Err(NodeEventWalErrorV1::Malformed | NodeEventWalErrorV1::ChainMismatch)
        ));
    }

    #[test]
    fn foreign_namespace_and_partial_tail_never_auto_repair() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("node-events.wal");
        let mut wal = NodeEventWalV1::open(&path, digest(1)).unwrap();
        wal.prepare_event_v1(digest(2), digest(3), digest(4))
            .unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes.extend_from_slice(&[0xaa, 0xbb]);
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        assert_eq!(
            NodeEventWalV1::open(&path, digest(1)).unwrap_err(),
            NodeEventWalErrorV1::Truncated
        );
        let mut foreign = path.clone();
        foreign.set_file_name("foreign.wal");
        fs::copy(&path, &foreign).unwrap();
        assert_eq!(
            NodeEventWalV1::open(&foreign, digest(9)).unwrap_err(),
            NodeEventWalErrorV1::Truncated
        );
    }

    #[test]
    fn fresh_revalidation_poisoned_after_external_rewrite() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("node-events.wal");
        let mut wal = NodeEventWalV1::open(&path, digest(1)).unwrap();
        wal.prepare_event_v1(digest(2), digest(3), digest(4))
            .unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[100] ^= 0x80;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            wal.revalidate_v1(),
            Err(NodeEventWalErrorV1::Malformed | NodeEventWalErrorV1::ChainMismatch)
        ));
        assert_eq!(
            wal.prepare_event_v1(digest(6), digest(7), digest(8)),
            Err(NodeEventWalErrorV1::Poisoned)
        );
    }

    #[cfg(unix)]
    #[test]
    fn hard_link_alias_and_path_replacement_fail_closed() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let path = temp.path().join("node-events.wal");
        let mut wal = NodeEventWalV1::open(&path, digest(1)).unwrap();
        let intent = wal
            .prepare_event_v1(digest(2), digest(3), digest(4))
            .unwrap();
        wal.commit_event_v1(intent, digest(5)).unwrap();

        let alias = temp.path().join("node-events.alias.wal");
        std::fs::hard_link(&path, &alias).unwrap();
        assert_eq!(
            NodeEventWalV1::open(&alias, digest(1)).unwrap_err(),
            NodeEventWalErrorV1::InvalidPath
        );

        let moved = temp.path().join("node-events.moved.wal");
        std::fs::rename(&path, &moved).unwrap();
        symlink(&moved, &path).unwrap();
        assert!(matches!(
            wal.revalidate_v1(),
            Err(NodeEventWalErrorV1::Io | NodeEventWalErrorV1::InvalidPath)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn parent_symlink_and_inode_replacement_fail_closed() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let real_parent = temp.path().join("real-events");
        fs::create_dir(&real_parent).unwrap();
        let parent_alias = temp.path().join("events-alias");
        symlink(&real_parent, &parent_alias).unwrap();
        assert_eq!(
            NodeEventWalV1::open(parent_alias.join("node-events.wal"), digest(1)).unwrap_err(),
            NodeEventWalErrorV1::InvalidPath
        );

        let path = real_parent.join("node-events.wal");
        let mut wal = NodeEventWalV1::open(&path, digest(1)).unwrap();
        let intent = wal
            .prepare_event_v1(digest(2), digest(3), digest(4))
            .unwrap();
        wal.commit_event_v1(intent, digest(5)).unwrap();
        let moved_parent = temp.path().join("real-events-moved");
        fs::rename(&real_parent, &moved_parent).unwrap();
        fs::create_dir(&real_parent).unwrap();
        assert_eq!(wal.revalidate_v1(), Err(NodeEventWalErrorV1::InvalidPath));

        let replacement_parent = temp.path().join("replacement-events");
        fs::create_dir(&replacement_parent).unwrap();
        let replacement_path = replacement_parent.join("node-events.wal");
        let mut replaced_wal = NodeEventWalV1::open(&replacement_path, digest(1)).unwrap();
        let intent = replaced_wal
            .prepare_event_v1(digest(6), digest(7), digest(8))
            .unwrap();
        replaced_wal.commit_event_v1(intent, digest(9)).unwrap();
        let original = fs::read(&replacement_path).unwrap();
        let displaced = replacement_parent.join("node-events.displaced.wal");
        fs::rename(&replacement_path, &displaced).unwrap();
        fs::write(&replacement_path, original).unwrap();
        fs::set_permissions(&replacement_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            replaced_wal.revalidate_v1(),
            Err(NodeEventWalErrorV1::InvalidPath)
        );
    }

    /// Kill a real child after the intent frame has been synced, before any
    /// application effect.  Reopening must expose the exact pending tuple;
    /// it may not infer success from process death or silently repair it.
    #[cfg(unix)]
    #[test]
    fn sigkill_after_intent_leaves_pending_for_exact_recovery() {
        const CHILD_WAL_ENV_V1: &str = "TRNM_NODE_EVENT_WAL_SIGKILL_CHILD_V1";
        const CHILD_READY_ENV_V1: &str = "TRNM_NODE_EVENT_WAL_SIGKILL_READY_V1";
        if let Ok(path) = env::var(CHILD_WAL_ENV_V1) {
            let ready = PathBuf::from(env::var(CHILD_READY_ENV_V1).expect("child readiness path"));
            let mut wal = NodeEventWalV1::open(path, digest(1)).expect("child WAL open");
            wal.prepare_event_v1(digest(2), digest(3), digest(4))
                .expect("child intent prepare");
            let marker = File::create(ready).expect("child readiness marker");
            marker.sync_all().expect("child readiness sync");
            loop {
                thread::sleep(Duration::from_millis(25));
            }
        }

        let temp = TempDir::new().unwrap();
        let path = temp.path().join("sigkill-events.wal");
        let ready = temp.path().join("sigkill-ready");
        let mut child = Command::new(env::current_exe().unwrap())
            .arg("--exact")
            .arg("node_event_wal::tests::sigkill_after_intent_leaves_pending_for_exact_recovery")
            .env(CHILD_WAL_ENV_V1, &path)
            .env(CHILD_READY_ENV_V1, &ready)
            .spawn()
            .expect("spawn WAL crash child");
        let mut ready_seen = false;
        for _ in 0..200 {
            if ready.exists() {
                ready_seen = true;
                break;
            }
            if let Some(status) = child.try_wait().expect("poll WAL crash child") {
                let _ = child.kill();
                panic!("WAL crash child exited before readiness: {status}");
            }
            thread::sleep(Duration::from_millis(10));
        }
        if !ready_seen {
            let _ = child.kill();
            let _ = child.wait();
            panic!("WAL crash child did not reach synced intent");
        }
        child.kill().expect("SIGKILL WAL crash child");
        let _ = child.wait().expect("wait WAL crash child");

        let reopened = NodeEventWalV1::open(&path, digest(1)).unwrap();
        let NodeEventRecoveryV1::Pending(intent) = reopened.recovery() else {
            panic!("SIGKILL after intent must leave a pending WAL intent");
        };
        assert_eq!(intent.sequence(), 1);
        assert_eq!(intent.event_id(), digest(2));
        assert_eq!(intent.predecessor_digest(), digest(3));
        assert_eq!(intent.payload_digest(), digest(4));
    }
}
