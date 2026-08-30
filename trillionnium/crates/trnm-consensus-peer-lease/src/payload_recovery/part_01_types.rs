// Candidate-only external recovery and status authority for payload replay.
//
// The payload replay store durably appends an authenticated frame before a
// consensus consumer sees it. A process may still stop after the WAL append
// but before the exact head sidecar is published, or after admission but
// before Core durably acknowledges the input. This module closes that bounded
// observability gap:
//
// - it independently replays and verifies the complete fixed-record WAL;
// - it accepts only an exact target record supplied by the caller;
// - it repairs only an exact one-record head lag and preserves retained
//   publication temporaries as quarantined evidence; and
// - it records an immutable target-bound Core acknowledgement after the caller
//   supplies a positive Core safety revision and acknowledgement digest.
//
// The acknowledgement record is not atomic with Core. A future Node owner
// must call it only after the real Core acknowledgement is durable and must
// bind both stores to a whole-node anti-rollback authority. Production and
// consensus activation remain false.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use fs2::FileExt;
use sha2::{Digest, Sha256};

use crate::{
    payload::{
        payload_replay_generation_successor_v1, PayloadReplayDirectionV1, PayloadReplayFrameV1,
        PayloadReplayNamespaceV1, PayloadReplayReceiptV1, PAYLOAD_REPLAY_MAX_PAYLOAD_BYTES_V1,
        PAYLOAD_REPLAY_MAX_RECORDS_V1, PAYLOAD_REPLAY_MAX_TEMPORARY_FILES_V1,
        PAYLOAD_REPLAY_MAX_TEMPORARY_SCAN_ENTRIES_V1, PAYLOAD_REPLAY_MAX_WAL_BYTES_V1,
    },
    protocol::PeerLeaseDirectionV1,
    store::ensure_private_directory,
};

pub const PAYLOAD_REPLAY_EXTERNAL_RECOVERY_OWNER_CANDIDATE_V1: bool = true;
pub const PAYLOAD_REPLAY_CORE_ACK_LEDGER_CANDIDATE_V1: bool = true;
pub const PAYLOAD_REPLAY_CORE_ACK_ATOMIC_WITH_CORE_V1: bool = false;
pub const PAYLOAD_REPLAY_RECOVERY_PRODUCTION_ACTIVATION_V1: bool = false;
/// Schema/domain used for the opaque descriptor-bound endpoint identity
/// returned by the candidate socket owner.  The digest is an identity pin,
/// not a signature, anti-rollback proof, or Core authority token.
pub const PAYLOAD_REPLAY_RECOVERY_ENDPOINT_IDENTITY_SCHEMA_V1: &str =
    "trnm.payload-replay-recovery-endpoint-identity.v1";

const LOG_MAGIC_V1: [u8; 8] = *b"TRNPRW01";
const LOG_VERSION_V1: u8 = 1;
const LOG_GENESIS_KIND_V1: u8 = 0;
const LOG_FRAME_KIND_V1: u8 = 1;
const HEAD_MAGIC_V1: [u8; 8] = *b"TRNPRH01";
const HEAD_VERSION_V1: u8 = 1;
const NAMESPACE_DOMAIN_V1: &[u8] = b"trnm.poco-g3.payload-replay.namespace.v1";
const RECORD_DOMAIN_V1: &[u8] = b"trnm.poco-g3.payload-replay.record.v1";
const HEAD_DOMAIN_V1: &[u8] = b"trnm.poco-g3.payload-replay.head.v1";
const RECORD_PREFIX_BYTES_V1: usize = 348;
const RECORD_BYTES_V1: usize = RECORD_PREFIX_BYTES_V1 + 32;
const HEAD_PREFIX_BYTES_V1: usize = 84;
const HEAD_BYTES_V1: usize = HEAD_PREFIX_BYTES_V1 + 32;

const ACK_MAGIC_V1: [u8; 8] = *b"TRNPACK1";
const ACK_VERSION_V1: u8 = 1;
const ACK_DOMAIN_V1: &[u8] = b"trnm.poco-g1.payload-core-ack.v1";
const ACK_PREFIX_BYTES_V1: usize = 156;
const ACK_BYTES_V1: usize = ACK_PREFIX_BYTES_V1 + 32;
const ACK_LOCK_NAME_V1: &str = ".payload-core-ack.lock-v1";
const PRIVATE_FILE_MODE_V1: u32 = 0o600;

static TEMP_NONCE_V1: AtomicU64 = AtomicU64::new(0);

/// A descriptor/path identity captured when the candidate recovery owner is
/// opened.  The owner keeps the descriptor locked, but pathname operations
/// (head repair and acknowledgement publication) still need a post-open
/// identity fence: a same-UID process can otherwise rename a replacement
/// artifact into the authority pathname while the original descriptor stays
/// valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthorityPathIdentityV1 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    nlink: u64,
    #[cfg(not(unix))]
    is_file: bool,
    #[cfg(not(unix))]
    is_directory: bool,
    #[cfg(not(unix))]
    length: u64,
}

impl AuthorityPathIdentityV1 {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                uid: metadata.uid(),
                mode: metadata.mode(),
                nlink: metadata.nlink(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                is_file: metadata.is_file(),
                is_directory: metadata.is_dir(),
                length: metadata.len(),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadReplayRecoveryTargetV1 {
    record_index: u64,
    record_hash: [u8; 32],
    remote_id: [u8; 32],
    direction: PayloadReplayDirectionV1,
    session_id: [u8; 32],
    generation: u64,
    sequence: u64,
    frame_kind: u8,
    payload_len: u32,
    frame_fingerprint: [u8; 32],
}

impl PayloadReplayRecoveryTargetV1 {
    pub fn from_admission(frame: PayloadReplayFrameV1, receipt: PayloadReplayReceiptV1) -> Self {
        let scope = frame.scope();
        Self {
            record_index: receipt.record_index(),
            record_hash: receipt.record_hash(),
            remote_id: scope.remote_id(),
            direction: scope.direction(),
            session_id: frame.session_id(),
            generation: frame.generation(),
            sequence: frame.sequence(),
            frame_kind: frame.frame_kind(),
            payload_len: frame.payload_len(),
            frame_fingerprint: frame.frame_fingerprint(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        record_index: u64,
        record_hash: [u8; 32],
        remote_id: [u8; 32],
        direction: PayloadReplayDirectionV1,
        session_id: [u8; 32],
        generation: u64,
        sequence: u64,
        frame_kind: u8,
        payload_len: u32,
        frame_fingerprint: [u8; 32],
    ) -> Result<Self, PayloadReplayRecoveryErrorV1> {
        let value = Self {
            record_index,
            record_hash,
            remote_id,
            direction,
            session_id,
            generation,
            sequence,
            frame_kind,
            payload_len,
            frame_fingerprint,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(self) -> Result<(), PayloadReplayRecoveryErrorV1> {
        if self.record_index == 0
            || self.record_hash == [0; 32]
            || self.remote_id == [0; 32]
            || self.session_id == [0; 32]
            || self.generation == 0
            || self.frame_kind == 0
            || self.payload_len as usize > PAYLOAD_REPLAY_MAX_PAYLOAD_BYTES_V1
            || self.frame_fingerprint == [0; 32]
        {
            return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
                "payload replay recovery target is incomplete",
            ));
        }
        Ok(())
    }

    pub const fn record_index(self) -> u64 {
        self.record_index
    }

    pub const fn record_hash(self) -> [u8; 32] {
        self.record_hash
    }

    pub const fn remote_id(self) -> [u8; 32] {
        self.remote_id
    }

    pub const fn direction(self) -> PayloadReplayDirectionV1 {
        self.direction
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadReplayCoreAcknowledgementV1 {
    target: PayloadReplayRecoveryTargetV1,
    core_safety_revision: u64,
    core_ack_digest: [u8; 32],
}

impl PayloadReplayCoreAcknowledgementV1 {
    pub fn new(
        target: PayloadReplayRecoveryTargetV1,
        core_safety_revision: u64,
        core_ack_digest: [u8; 32],
    ) -> Result<Self, PayloadReplayRecoveryErrorV1> {
        target.validate()?;
        if core_safety_revision == 0 || core_ack_digest == [0; 32] {
            return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
                "Core acknowledgement requires a positive revision and digest",
            ));
        }
        Ok(Self {
            target,
            core_safety_revision,
            core_ack_digest,
        })
    }

    pub const fn target(self) -> PayloadReplayRecoveryTargetV1 {
        self.target
    }

    pub const fn core_safety_revision(self) -> u64 {
        self.core_safety_revision
    }

    pub const fn core_ack_digest(self) -> [u8; 32] {
        self.core_ack_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadReplayCoreAckReceiptV1 {
    acknowledgement_hash: [u8; 32],
    idempotent_replay: bool,
}

impl PayloadReplayCoreAckReceiptV1 {
    pub const fn acknowledgement_hash(self) -> [u8; 32] {
        self.acknowledgement_hash
    }

    pub const fn idempotent_replay(self) -> bool {
        self.idempotent_replay
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadReplayRecoveryStatusV1 {
    RecoverableHeadLag {
        payload_record_count: u64,
        payload_head_count: u64,
        retained_temporary_count: u32,
    },
    RecoverableResidualTemporaries {
        payload_record_count: u64,
        retained_temporary_count: u32,
    },
    AdmittedUnacknowledged {
        payload_record_count: u64,
        payload_head_hash: [u8; 32],
    },
    CoreAcknowledged {
        payload_record_count: u64,
        payload_head_hash: [u8; 32],
        core_safety_revision: u64,
        core_ack_digest: [u8; 32],
        acknowledgement_hash: [u8; 32],
    },
}

impl PayloadReplayRecoveryStatusV1 {
    pub const fn kind(self) -> &'static str {
        match self {
            Self::RecoverableHeadLag { .. } => "recoverable_head_lag",
            Self::RecoverableResidualTemporaries { .. } => "recoverable_residual_temporaries",
            Self::AdmittedUnacknowledged { .. } => "admitted_unacknowledged",
            Self::CoreAcknowledged { .. } => "core_acknowledged",
        }
    }

    pub const fn payload_publication_recoverable(self) -> bool {
        matches!(
            self,
            Self::RecoverableHeadLag { .. } | Self::RecoverableResidualTemporaries { .. }
        )
    }

    pub const fn core_acknowledged(self) -> bool {
        matches!(self, Self::CoreAcknowledged { .. })
    }
}

#[derive(Debug)]
pub enum PayloadReplayRecoveryErrorV1 {
    InvalidRequest(&'static str),
    Io(io::Error),
    PayloadJournalMissing,
    PayloadJournalBusy,
    PayloadJournalCorrupt,
    PayloadRecordMismatch,
    PayloadHeadDiverged,
    AckLedgerBusy,
    AckLedgerCorrupt,
    AckConflict,
    AckCommitAmbiguous(Box<PayloadReplayRecoveryErrorV1>),
    RecoveryRequired,
}

impl fmt::Display for PayloadReplayRecoveryErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(reason) => formatter.write_str(reason),
            Self::Io(error) => write!(formatter, "payload replay recovery I/O error: {error}"),
            Self::PayloadJournalMissing => formatter.write_str("payload replay journal is missing"),
            Self::PayloadJournalBusy => {
                formatter.write_str("payload replay journal is owned by a live process")
            }
            Self::PayloadJournalCorrupt => formatter.write_str("payload replay journal is corrupt"),
            Self::PayloadRecordMismatch => formatter
                .write_str("payload replay recovery target does not match the durable record"),
            Self::PayloadHeadDiverged => formatter
                .write_str("payload replay head is not the exact durable tip or one-target prefix"),
            Self::AckLedgerBusy => {
                formatter.write_str("payload replay Core acknowledgement ledger is busy")
            }
            Self::AckLedgerCorrupt => {
                formatter.write_str("payload replay Core acknowledgement ledger is corrupt")
            }
            Self::AckConflict => formatter
                .write_str("payload replay target already has a conflicting Core acknowledgement"),
            Self::AckCommitAmbiguous(error) => write!(
                formatter,
                "payload replay Core acknowledgement commit is ambiguous: {error}"
            ),
            Self::RecoveryRequired => formatter.write_str(
                "payload replay publication must be recovered before Core acknowledgement",
            ),
        }
    }
}

impl Error for PayloadReplayRecoveryErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::AckCommitAmbiguous(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<io::Error> for PayloadReplayRecoveryErrorV1 {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn descriptor_identity(
    file: &File,
) -> Result<AuthorityPathIdentityV1, PayloadReplayRecoveryErrorV1> {
    Ok(AuthorityPathIdentityV1::from_metadata(&file.metadata()?))
}

fn path_identity(path: &Path) -> Result<AuthorityPathIdentityV1, PayloadReplayRecoveryErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "recovery authority path is a symlink",
        ));
    }
    Ok(AuthorityPathIdentityV1::from_metadata(&metadata))
}

fn verify_bound_file_identity(
    path: &Path,
    file: &File,
    expected: AuthorityPathIdentityV1,
) -> Result<(), PayloadReplayRecoveryErrorV1> {
    validate_private_file(file)?;
    let descriptor = descriptor_identity(file)?;
    let named = path_identity(path)?;
    if !file.metadata()?.is_file() || descriptor != expected || named != expected {
        return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "recovery authority file identity changed",
        ));
    }
    Ok(())
}

fn verify_bound_path_identity(
    path: &Path,
    expected: AuthorityPathIdentityV1,
) -> Result<(), PayloadReplayRecoveryErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || !private_file_mode(&metadata)
        || AuthorityPathIdentityV1::from_metadata(&metadata) != expected
    {
        return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "recovery authority path identity changed",
        ));
    }
    Ok(())
}

fn verify_bound_directory_identity(
    path: &Path,
    directory: &File,
    expected: AuthorityPathIdentityV1,
) -> Result<(), PayloadReplayRecoveryErrorV1> {
    let descriptor_metadata = directory.metadata()?;
    let named_metadata = fs::symlink_metadata(path)?;
    if named_metadata.file_type().is_symlink()
        || !descriptor_metadata.is_dir()
        || !named_metadata.is_dir()
        || !private_parent_mode(&descriptor_metadata)
        || !private_parent_mode(&named_metadata)
        || AuthorityPathIdentityV1::from_metadata(&descriptor_metadata) != expected
        || AuthorityPathIdentityV1::from_metadata(&named_metadata) != expected
        || fs::canonicalize(path)? != path
    {
        return Err(PayloadReplayRecoveryErrorV1::InvalidRequest(
            "recovery authority directory identity changed",
        ));
    }
    ensure_private_directory(path).map_err(map_peer_lease_error)?;
    Ok(())
}
