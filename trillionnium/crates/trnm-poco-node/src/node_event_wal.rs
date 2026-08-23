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
    io::{Read, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

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
    Poisoned,
    TooLarge,
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

/// A linear owner of one append-only host event WAL.
///
/// The owner is intentionally non-`Clone`; two owners must not race the same
/// event namespace.  Every frame is fixed-size, checksummed, and linked to
/// the previous frame.  A partial frame, changed namespace, interior rewrite,
/// or sequence fork poisons startup instead of being silently repaired.
#[derive(Debug)]
pub struct NodeEventWalV1 {
    path: PathBuf,
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
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = options.open(&path).map_err(|_| NodeEventWalErrorV1::Io)?;
        let metadata = file.metadata().map_err(|_| NodeEventWalErrorV1::Io)?;
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
            sync_parent_v1(&path)?;
        } else {
            #[cfg(unix)]
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| NodeEventWalErrorV1::Io)?;
        }
        drop(file);
        let mut wal = Self {
            path,
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
            let mut options = OpenOptions::new();
            options.append(true);
            #[cfg(unix)]
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            let mut file = options
                .open(&self.path)
                .map_err(|_| NodeEventWalErrorV1::Io)?;
            file.write_all(frame).map_err(|_| NodeEventWalErrorV1::Io)?;
            file.sync_all().map_err(|_| NodeEventWalErrorV1::Io)?;
            sync_parent_v1(&self.path)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn reload_v1(&mut self) -> Result<(), NodeEventWalErrorV1> {
        let mut file = File::open(&self.path).map_err(|_| NodeEventWalErrorV1::Io)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| NodeEventWalErrorV1::Io)?;
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
        Ok(())
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
    let metadata = fs::metadata(parent).map_err(|_| NodeEventWalErrorV1::InvalidPath)?;
    if !metadata.is_dir() || path.file_name().is_none() {
        return Err(NodeEventWalErrorV1::InvalidPath);
    }
    if let Ok(existing) = fs::symlink_metadata(path) {
        if existing.file_type().is_symlink() || !existing.file_type().is_file() {
            return Err(NodeEventWalErrorV1::InvalidPath);
        }
    }
    Ok(())
}

fn sync_parent_v1(path: &Path) -> Result<(), NodeEventWalErrorV1> {
    let parent = path.parent().ok_or(NodeEventWalErrorV1::InvalidPath)?;
    File::open(parent)
        .map_err(|_| NodeEventWalErrorV1::Io)?
        .sync_all()
        .map_err(|_| NodeEventWalErrorV1::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

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
}
