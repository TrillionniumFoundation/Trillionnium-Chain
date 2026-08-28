#![cfg(unix)]
#![forbid(unsafe_code)]

//! Candidate-only G1-R2A replay-to-Core durable-delivery coordinator.
//!
//! This compilation unit deliberately has no live Core adapter.  It proves
//! the recoverable pending/ack/completion state machine while making a durable
//! Core receipt impossible to construct through a public API.  The real Core
//! process adapter is the separately reviewed G1-R2B tranche.

use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use fs2::FileExt;
use sha2::{Digest, Sha256};
use trnm_consensus_peer_lease::{
    PayloadReplayCoreAcknowledgementV1, PayloadReplayNamespaceV1,
    PayloadReplayRecoveryErrorV1, PayloadReplayRecoveryOwnerV1,
    PayloadReplayRecoveryStatusV1, PayloadReplayRecoveryTargetV1,
};

const PRIVATE_DIRECTORY_MODE_V1: u32 = 0o700;
const PRIVATE_FILE_MODE_V1: u32 = 0o600;
const LOCK_NAME_V1: &str = ".replay-to-core.lock-v1";

const NAMESPACE_DOMAIN_V1: &[u8] = b"trnm.poco-g3.payload-replay.namespace.v1";
const TARGET_DOMAIN_V1: &[u8] = b"trnm.g1-r2.replay-core.target.v1";
const REQUEST_DOMAIN_V1: &[u8] = b"trnm.g1-r2.replay-core.request.v1";
const IDEMPOTENCY_DOMAIN_V1: &[u8] = b"trnm.g1-r2.replay-core.idempotency.v1";
const PENDING_DOMAIN_V1: &[u8] = b"trnm.g1-r2.replay-core.pending-record.v1";
const COMPLETED_DOMAIN_V1: &[u8] = b"trnm.g1-r2.replay-core.completed-record.v1";

const PENDING_MAGIC_V1: [u8; 8] = *b"TRNR2PN1";
const COMPLETED_MAGIC_V1: [u8; 8] = *b"TRNR2CM1";
const RECORD_VERSION_V1: u8 = 1;
const PENDING_PREFIX_BYTES_V1: usize = 244;
const PENDING_BYTES_V1: usize = PENDING_PREFIX_BYTES_V1 + 32;
const COMPLETED_PREFIX_BYTES_V1: usize = 316;
const COMPLETED_BYTES_V1: usize = COMPLETED_PREFIX_BYTES_V1 + 32;

static TEMP_NONCE_V1: AtomicU64 = AtomicU64::new(0);

pub const REPLAY_TO_CORE_COORDINATOR_CANDIDATE_V1: bool = true;
pub const REPLAY_TO_CORE_PENDING_BEFORE_CORE_V1: bool = true;
pub const REPLAY_TO_CORE_SEALED_AUTHORITY_V1: bool = true;
pub const REPLAY_TO_CORE_LIVE_CORE_ADAPTER_V1: bool = false;
pub const REPLAY_TO_CORE_ACK_GENERATED_BY_CORE_V1: bool = false;
pub const REPLAY_TO_CORE_ACK_ATOMIC_WITH_CORE_V1: bool = false;
pub const REPLAY_TO_CORE_NODE_PROCESS_INTEGRATION_V1: bool = false;
pub const REPLAY_TO_CORE_PRODUCTION_ACTIVATION_V1: bool = false;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreReplayRequestV1 {
    namespace_digest: [u8; 32],
    target: PayloadReplayRecoveryTargetV1,
    target_digest: [u8; 32],
    input_digest: [u8; 32],
    predecessor_checkpoint: [u8; 32],
    request_digest: [u8; 32],
    idempotency_key: [u8; 32],
}

impl CoreReplayRequestV1 {
    fn new(
        namespace: PayloadReplayNamespaceV1,
        target: PayloadReplayRecoveryTargetV1,
        input_digest: [u8; 32],
        predecessor_checkpoint: [u8; 32],
    ) -> Result<Self, ReplayToCoreCoordinatorErrorV1> {
        if input_digest == [0; 32] || predecessor_checkpoint == [0; 32] {
            return Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(
                "Core input and predecessor checkpoint digests must be nonzero",
            ));
        }
        let namespace_digest = payload_namespace_digest(namespace);
        let target_digest = payload_target_digest(target);
        let request_digest = replay_request_digest(
            namespace_digest,
            target_digest,
            input_digest,
            predecessor_checkpoint,
        );
        let idempotency_key = replay_idempotency_key(request_digest);
        Ok(Self {
            namespace_digest,
            target,
            target_digest,
            input_digest,
            predecessor_checkpoint,
            request_digest,
            idempotency_key,
        })
    }

    pub const fn target(self) -> PayloadReplayRecoveryTargetV1 {
        self.target
    }

    pub const fn target_digest(self) -> [u8; 32] {
        self.target_digest
    }

    pub const fn input_digest(self) -> [u8; 32] {
        self.input_digest
    }

    pub const fn predecessor_checkpoint(self) -> [u8; 32] {
        self.predecessor_checkpoint
    }

    pub const fn request_digest(self) -> [u8; 32] {
        self.request_digest
    }

    pub const fn idempotency_key(self) -> [u8; 32] {
        self.idempotency_key
    }
}

/// A receipt that can be constructed only inside this compilation unit.
/// G1-R2B must add the real Core implementation next to this private
/// constructor after the actual persistence/readback barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreDurableReplayReceiptV1 {
    target_digest: [u8; 32],
    idempotency_key: [u8; 32],
    predecessor_checkpoint: [u8; 32],
    core_safety_revision: u64,
    core_ack_digest: [u8; 32],
}

impl CoreDurableReplayReceiptV1 {
    fn new_after_durable_core(
        request: CoreReplayRequestV1,
        core_safety_revision: u64,
        core_ack_digest: [u8; 32],
    ) -> Result<Self, ReplayToCoreCoordinatorErrorV1> {
        if core_safety_revision == 0 || core_ack_digest == [0; 32] {
            return Err(ReplayToCoreCoordinatorErrorV1::CoreReceiptMismatch);
        }
        Ok(Self {
            target_digest: request.target_digest,
            idempotency_key: request.idempotency_key,
            predecessor_checkpoint: request.predecessor_checkpoint,
            core_safety_revision,
            core_ack_digest,
        })
    }

    fn validate_for(
        self,
        request: CoreReplayRequestV1,
    ) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
        if self.target_digest != request.target_digest
            || self.idempotency_key != request.idempotency_key
            || self.predecessor_checkpoint != request.predecessor_checkpoint
            || self.core_safety_revision == 0
            || self.core_ack_digest == [0; 32]
        {
            return Err(ReplayToCoreCoordinatorErrorV1::CoreReceiptMismatch);
        }
        Ok(())
    }
}

mod sealed {
    pub trait SealedReplayToCoreAuthorityV1 {}
}

/// Sealed on purpose.  A generic caller cannot implement this trait and mint
/// a durable-Core fact.  R2-B must add the concrete implementation in this
/// trusted compilation boundary.
pub trait ReplayToCoreAuthorityV1: sealed::SealedReplayToCoreAuthorityV1 {
    fn deliver_durably(
        &mut self,
        request: CoreReplayRequestV1,
    ) -> Result<CoreDurableReplayReceiptV1, CoreDeliveryErrorV1>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreDeliveryErrorV1 {
    reason: &'static str,
}

impl CoreDeliveryErrorV1 {
    const fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

impl fmt::Display for CoreDeliveryErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl Error for CoreDeliveryErrorV1 {}

#[derive(Debug)]
pub enum ReplayToCoreCoordinatorErrorV1 {
    InvalidRequest(&'static str),
    Io(io::Error),
    Busy,
    Corrupt,
    Conflict,
    EarlierDeliveryPending,
    AmbiguousPublication,
    ReplayRecovery(Box<PayloadReplayRecoveryErrorV1>),
    CoreDelivery(CoreDeliveryErrorV1),
    CoreReceiptMismatch,
    PayloadPublicationNotDurable,
}

impl fmt::Display for ReplayToCoreCoordinatorErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(reason) => formatter.write_str(reason),
            Self::Io(error) => write!(formatter, "replay-to-Core I/O error: {error}"),
            Self::Busy => formatter.write_str("replay-to-Core coordinator is busy"),
            Self::Corrupt => formatter.write_str("replay-to-Core coordinator state is corrupt"),
            Self::Conflict => formatter.write_str("replay-to-Core request conflicts with durable state"),
            Self::EarlierDeliveryPending => formatter.write_str(
                "an earlier replay-to-Core target remains unresolved",
            ),
            Self::AmbiguousPublication => formatter.write_str(
                "replay-to-Core completion publication is ambiguous",
            ),
            Self::ReplayRecovery(error) => write!(
                formatter,
                "payload replay recovery rejected the transition: {error}"
            ),
            Self::CoreDelivery(error) => write!(formatter, "Core delivery failed: {error}"),
            Self::CoreReceiptMismatch => formatter.write_str(
                "Core durable receipt does not bind the exact pending request",
            ),
            Self::PayloadPublicationNotDurable => formatter.write_str(
                "payload publication is not durable after bounded recovery",
            ),
        }
    }
}

impl Error for ReplayToCoreCoordinatorErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::ReplayRecovery(error) => Some(error.as_ref()),
            Self::CoreDelivery(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ReplayToCoreCoordinatorErrorV1 {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayToCoreCompletionReceiptV1 {
    request_digest: [u8; 32],
    idempotency_key: [u8; 32],
    core_safety_revision: u64,
    core_ack_digest: [u8; 32],
    replay_ack_hash: [u8; 32],
    idempotent_replay: bool,
}

impl ReplayToCoreCompletionReceiptV1 {
    pub const fn request_digest(self) -> [u8; 32] {
        self.request_digest
    }

    pub const fn idempotency_key(self) -> [u8; 32] {
        self.idempotency_key
    }

    pub const fn core_safety_revision(self) -> u64 {
        self.core_safety_revision
    }

    pub const fn core_ack_digest(self) -> [u8; 32] {
        self.core_ack_digest
    }

    pub const fn replay_ack_hash(self) -> [u8; 32] {
        self.replay_ack_hash
    }

    pub const fn idempotent_replay(self) -> bool {
        self.idempotent_replay
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingFactsV1 {
    namespace_digest: [u8; 32],
    target_digest: [u8; 32],
    record_index: u64,
    record_hash: [u8; 32],
    frame_fingerprint: [u8; 32],
    input_digest: [u8; 32],
    predecessor_checkpoint: [u8; 32],
    idempotency_key: [u8; 32],
}

impl PendingFactsV1 {
    fn from_request(request: CoreReplayRequestV1) -> Self {
        let target = request.target;
        Self {
            namespace_digest: request.namespace_digest,
            target_digest: request.target_digest,
            record_index: target.record_index(),
            record_hash: target.record_hash(),
            frame_fingerprint: target.frame_fingerprint(),
            input_digest: request.input_digest,
            predecessor_checkpoint: request.predecessor_checkpoint,
            idempotency_key: request.idempotency_key,
        }
    }

    fn matches(self, request: CoreReplayRequestV1) -> bool {
        self == Self::from_request(request)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompletedFactsV1 {
    pending: PendingFactsV1,
    core_safety_revision: u64,
    core_ack_digest: [u8; 32],
    replay_ack_hash: [u8; 32],
}

impl CompletedFactsV1 {
    fn receipt(self, request: CoreReplayRequestV1, idempotent_replay: bool) -> ReplayToCoreCompletionReceiptV1 {
        ReplayToCoreCompletionReceiptV1 {
            request_digest: request.request_digest,
            idempotency_key: request.idempotency_key,
            core_safety_revision: self.core_safety_revision,
            core_ack_digest: self.core_ack_digest,
            replay_ack_hash: self.replay_ack_hash,
            idempotent_replay,
        }
    }
}

#[derive(Debug)]
pub struct ReplayToCoreCoordinatorV1 {
    root: PathBuf,
    directory: File,
    _lock: File,
}

impl ReplayToCoreCoordinatorV1 {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ReplayToCoreCoordinatorErrorV1> {
        let root = root.as_ref().to_path_buf();
        validate_private_root(&root)?;
        let directory = File::open(&root)?;
        let lock_path = root.join(LOCK_NAME_V1);
        let lock = open_or_create_private_file(&lock_path)?;
        match lock.try_lock_exclusive() {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(ReplayToCoreCoordinatorErrorV1::Busy)
            }
            Err(error) => return Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
        }
        Ok(Self {
            root,
            directory,
            _lock: lock,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn drive<A: ReplayToCoreAuthorityV1>(
        &mut self,
        authority: &mut A,
        payload_wal: impl AsRef<Path>,
        replay_ack_root: impl AsRef<Path>,
        namespace: PayloadReplayNamespaceV1,
        target: PayloadReplayRecoveryTargetV1,
        core_input_digest: [u8; 32],
        predecessor_checkpoint: [u8; 32],
    ) -> Result<ReplayToCoreCompletionReceiptV1, ReplayToCoreCoordinatorErrorV1> {
        let request = CoreReplayRequestV1::new(
            namespace,
            target,
            core_input_digest,
            predecessor_checkpoint,
        )?;
        self.reject_retained_completion_temporaries()?;

        if let Some(completed) = self.read_completed_if_present(request)? {
            self.reconcile_pending_residue(request)?;
            return Ok(completed.receipt(request, true));
        }

        self.reject_other_pending_targets(request)?;
        self.ensure_pending(request)?;

        let mut replay_owner = PayloadReplayRecoveryOwnerV1::open(
            payload_wal,
            replay_ack_root,
            namespace,
            target,
        )
        .map_err(|error| ReplayToCoreCoordinatorErrorV1::ReplayRecovery(Box::new(error)))?;

        let mut status = replay_owner
            .status()
            .map_err(|error| ReplayToCoreCoordinatorErrorV1::ReplayRecovery(Box::new(error)))?;
        if status.payload_publication_recoverable() {
            status = replay_owner
                .recover_payload_publication()
                .map_err(|error| ReplayToCoreCoordinatorErrorV1::ReplayRecovery(Box::new(error)))?;
        }

        let completed = match status {
            PayloadReplayRecoveryStatusV1::CoreAcknowledged {
                core_safety_revision,
                core_ack_digest,
                acknowledgement_hash,
                ..
            } => CompletedFactsV1 {
                pending: PendingFactsV1::from_request(request),
                core_safety_revision,
                core_ack_digest,
                replay_ack_hash: acknowledgement_hash,
            },
            PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged { .. } => {
                let core_receipt = authority
                    .deliver_durably(request)
                    .map_err(ReplayToCoreCoordinatorErrorV1::CoreDelivery)?;
                core_receipt.validate_for(request)?;
                let acknowledgement = PayloadReplayCoreAcknowledgementV1::new(
                    target,
                    core_receipt.core_safety_revision,
                    core_receipt.core_ack_digest,
                )
                .map_err(|error| {
                    ReplayToCoreCoordinatorErrorV1::ReplayRecovery(Box::new(error))
                })?;
                let replay_receipt = replay_owner
                    .acknowledge_core(acknowledgement)
                    .map_err(|error| {
                        ReplayToCoreCoordinatorErrorV1::ReplayRecovery(Box::new(error))
                    })?;
                CompletedFactsV1 {
                    pending: PendingFactsV1::from_request(request),
                    core_safety_revision: core_receipt.core_safety_revision,
                    core_ack_digest: core_receipt.core_ack_digest,
                    replay_ack_hash: replay_receipt.acknowledgement_hash(),
                }
            }
            PayloadReplayRecoveryStatusV1::RecoverableHeadLag { .. }
            | PayloadReplayRecoveryStatusV1::RecoverableResidualTemporaries { .. } => {
                return Err(ReplayToCoreCoordinatorErrorV1::PayloadPublicationNotDurable)
            }
        };

        self.publish_completed(request, completed)?;
        Ok(completed.receipt(request, false))
    }

    fn pending_path(&self, request: CoreReplayRequestV1) -> PathBuf {
        self.root.join(format!(
            "pending-{:020}-{}.v1",
            request.target.record_index(),
            hex32(request.target.record_hash())
        ))
    }

    fn completed_path(&self, request: CoreReplayRequestV1) -> PathBuf {
        self.root.join(format!(
            "completed-{:020}-{}.v1",
            request.target.record_index(),
            hex32(request.target.record_hash())
        ))
    }

    fn ensure_pending(
        &self,
        request: CoreReplayRequestV1,
    ) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
        let path = self.pending_path(request);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let facts = read_pending(&path)?;
                if !facts.matches(request) {
                    return Err(ReplayToCoreCoordinatorErrorV1::Conflict);
                }
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let bytes = encode_pending(PendingFactsV1::from_request(request));
                write_private_new(&path, &bytes)?;
                self.directory.sync_all()?;
                Ok(())
            }
            Err(error) => Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
        }
    }

    fn reject_other_pending_targets(
        &self,
        request: CoreReplayRequestV1,
    ) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
        let expected = self.pending_path(request);
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
            };
            if name.starts_with("pending-") && name.ends_with(".v1") {
                let metadata = fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink() || !private_regular_file(&metadata) {
                    return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
                }
                if entry.path() != expected {
                    return Err(ReplayToCoreCoordinatorErrorV1::EarlierDeliveryPending);
                }
            }
        }
        Ok(())
    }

    fn reject_retained_completion_temporaries(
        &self,
    ) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
            };
            if name.starts_with(".completed-") && name.contains(".tmp-") {
                let metadata = fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || !matches!(metadata.nlink(), 1 | 2)
                    || metadata.permissions().mode() & 0o7777 != PRIVATE_FILE_MODE_V1
                    || metadata.uid() != rustix::process::geteuid().as_raw()
                {
                    return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
                }
                return Err(ReplayToCoreCoordinatorErrorV1::AmbiguousPublication);
            }
        }
        Ok(())
    }

    fn read_completed_if_present(
        &self,
        request: CoreReplayRequestV1,
    ) -> Result<Option<CompletedFactsV1>, ReplayToCoreCoordinatorErrorV1> {
        let path = self.completed_path(request);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let completed = read_completed(&path)?;
                if !completed.pending.matches(request) {
                    return Err(ReplayToCoreCoordinatorErrorV1::Conflict);
                }
                Ok(Some(completed))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
        }
    }

    fn reconcile_pending_residue(
        &self,
        request: CoreReplayRequestV1,
    ) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
        let pending_path = self.pending_path(request);
        match fs::symlink_metadata(&pending_path) {
            Ok(_) => {
                let pending = read_pending(&pending_path)?;
                if !pending.matches(request) {
                    return Err(ReplayToCoreCoordinatorErrorV1::Conflict);
                }
                fs::remove_file(pending_path)?;
                self.directory.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
        }
    }

    fn publish_completed(
        &self,
        request: CoreReplayRequestV1,
        completed: CompletedFactsV1,
    ) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
        if !completed.pending.matches(request)
            || completed.core_safety_revision == 0
            || completed.core_ack_digest == [0; 32]
            || completed.replay_ack_hash == [0; 32]
        {
            return Err(ReplayToCoreCoordinatorErrorV1::Conflict);
        }
        if let Some(existing) = self.read_completed_if_present(request)? {
            if existing != completed {
                return Err(ReplayToCoreCoordinatorErrorV1::Conflict);
            }
            return self.reconcile_pending_residue(request);
        }

        let final_path = self.completed_path(request);
        let final_name = final_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(ReplayToCoreCoordinatorErrorV1::InvalidRequest(
                "completed path requires a UTF-8 filename",
            ))?;
        let temporary = final_path.with_file_name(format!(
            ".{final_name}.tmp-{}-{}",
            std::process::id(),
            TEMP_NONCE_V1.fetch_add(1, Ordering::Relaxed)
        ));
        let bytes = encode_completed(completed);
        write_private_new(&temporary, &bytes)?;
        match fs::hard_link(&temporary, &final_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(ReplayToCoreCoordinatorErrorV1::Conflict)
            }
            Err(error) => return Err(ReplayToCoreCoordinatorErrorV1::Io(error)),
        }
        if let Err(error) = self.directory.sync_all() {
            return Err(ReplayToCoreCoordinatorErrorV1::Io(error));
        }
        if let Err(error) = fs::remove_file(&temporary) {
            return Err(ReplayToCoreCoordinatorErrorV1::Io(error));
        }
        self.directory.sync_all()?;
        let reread = read_completed(&final_path)?;
        if reread != completed {
            return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
        }
        self.reconcile_pending_residue(request)
    }
}

fn payload_namespace_digest(namespace: PayloadReplayNamespaceV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NAMESPACE_DOMAIN_V1);
    hasher.update(namespace.local_id());
    hasher.update(namespace.epoch().to_be_bytes());
    hasher.update(namespace.validator_set_id());
    hasher.update(namespace.run_id_hash());
    hasher.update(namespace.network_context_hash());
    hasher.finalize().into()
}

fn payload_target_digest(target: PayloadReplayRecoveryTargetV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TARGET_DOMAIN_V1);
    hasher.update(target.record_index().to_be_bytes());
    hasher.update(target.record_hash());
    hasher.update(target.remote_id());
    hasher.update([target.direction() as u8]);
    hasher.update(target.session_id());
    hasher.update(target.generation().to_be_bytes());
    hasher.update(target.sequence().to_be_bytes());
    hasher.update([target.frame_kind()]);
    hasher.update(target.payload_len().to_be_bytes());
    hasher.update(target.frame_fingerprint());
    hasher.finalize().into()
}

fn replay_request_digest(
    namespace_digest: [u8; 32],
    target_digest: [u8; 32],
    input_digest: [u8; 32],
    predecessor_checkpoint: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DOMAIN_V1);
    hasher.update(namespace_digest);
    hasher.update(target_digest);
    hasher.update(input_digest);
    hasher.update(predecessor_checkpoint);
    hasher.finalize().into()
}

fn replay_idempotency_key(request_digest: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(IDEMPOTENCY_DOMAIN_V1);
    hasher.update(request_digest);
    hasher.finalize().into()
}

fn encode_pending(facts: PendingFactsV1) -> [u8; PENDING_BYTES_V1] {
    let mut bytes = Vec::with_capacity(PENDING_BYTES_V1);
    bytes.extend_from_slice(&PENDING_MAGIC_V1);
    bytes.push(RECORD_VERSION_V1);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&facts.namespace_digest);
    bytes.extend_from_slice(&facts.target_digest);
    bytes.extend_from_slice(&facts.record_index.to_be_bytes());
    bytes.extend_from_slice(&facts.record_hash);
    bytes.extend_from_slice(&facts.frame_fingerprint);
    bytes.extend_from_slice(&facts.input_digest);
    bytes.extend_from_slice(&facts.predecessor_checkpoint);
    bytes.extend_from_slice(&facts.idempotency_key);
    debug_assert_eq!(bytes.len(), PENDING_PREFIX_BYTES_V1);
    bytes.extend_from_slice(&record_checksum(PENDING_DOMAIN_V1, &bytes));
    bytes.try_into().expect("fixed pending replay-to-Core record")
}

fn decode_pending(bytes: &[u8]) -> Result<PendingFactsV1, ReplayToCoreCoordinatorErrorV1> {
    if bytes.len() != PENDING_BYTES_V1
        || bytes[..8] != PENDING_MAGIC_V1
        || bytes[8] != RECORD_VERSION_V1
        || bytes[9..12] != [0, 0, 0]
        || bytes[PENDING_PREFIX_BYTES_V1..]
            != record_checksum(PENDING_DOMAIN_V1, &bytes[..PENDING_PREFIX_BYTES_V1])
    {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    Ok(PendingFactsV1 {
        namespace_digest: bytes[12..44].try_into().expect("namespace digest"),
        target_digest: bytes[44..76].try_into().expect("target digest"),
        record_index: u64::from_be_bytes(bytes[76..84].try_into().expect("record index")),
        record_hash: bytes[84..116].try_into().expect("record hash"),
        frame_fingerprint: bytes[116..148].try_into().expect("frame fingerprint"),
        input_digest: bytes[148..180].try_into().expect("input digest"),
        predecessor_checkpoint: bytes[180..212]
            .try_into()
            .expect("predecessor checkpoint"),
        idempotency_key: bytes[212..244].try_into().expect("idempotency key"),
    })
}

fn encode_completed(facts: CompletedFactsV1) -> [u8; COMPLETED_BYTES_V1] {
    let pending = facts.pending;
    let mut bytes = Vec::with_capacity(COMPLETED_BYTES_V1);
    bytes.extend_from_slice(&COMPLETED_MAGIC_V1);
    bytes.push(RECORD_VERSION_V1);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&pending.namespace_digest);
    bytes.extend_from_slice(&pending.target_digest);
    bytes.extend_from_slice(&pending.record_index.to_be_bytes());
    bytes.extend_from_slice(&pending.record_hash);
    bytes.extend_from_slice(&pending.frame_fingerprint);
    bytes.extend_from_slice(&pending.input_digest);
    bytes.extend_from_slice(&pending.predecessor_checkpoint);
    bytes.extend_from_slice(&pending.idempotency_key);
    bytes.extend_from_slice(&facts.core_safety_revision.to_be_bytes());
    bytes.extend_from_slice(&facts.core_ack_digest);
    bytes.extend_from_slice(&facts.replay_ack_hash);
    debug_assert_eq!(bytes.len(), COMPLETED_PREFIX_BYTES_V1);
    bytes.extend_from_slice(&record_checksum(COMPLETED_DOMAIN_V1, &bytes));
    bytes
        .try_into()
        .expect("fixed completed replay-to-Core record")
}

fn decode_completed(bytes: &[u8]) -> Result<CompletedFactsV1, ReplayToCoreCoordinatorErrorV1> {
    if bytes.len() != COMPLETED_BYTES_V1
        || bytes[..8] != COMPLETED_MAGIC_V1
        || bytes[8] != RECORD_VERSION_V1
        || bytes[9..12] != [0, 0, 0]
        || bytes[COMPLETED_PREFIX_BYTES_V1..]
            != record_checksum(COMPLETED_DOMAIN_V1, &bytes[..COMPLETED_PREFIX_BYTES_V1])
    {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    let core_safety_revision =
        u64::from_be_bytes(bytes[244..252].try_into().expect("Core safety revision"));
    let core_ack_digest = bytes[252..284].try_into().expect("Core ack digest");
    let replay_ack_hash = bytes[284..316].try_into().expect("replay ack hash");
    if core_safety_revision == 0 || core_ack_digest == [0; 32] || replay_ack_hash == [0; 32] {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    Ok(CompletedFactsV1 {
        pending: PendingFactsV1 {
            namespace_digest: bytes[12..44].try_into().expect("namespace digest"),
            target_digest: bytes[44..76].try_into().expect("target digest"),
            record_index: u64::from_be_bytes(bytes[76..84].try_into().expect("record index")),
            record_hash: bytes[84..116].try_into().expect("record hash"),
            frame_fingerprint: bytes[116..148].try_into().expect("frame fingerprint"),
            input_digest: bytes[148..180].try_into().expect("input digest"),
            predecessor_checkpoint: bytes[180..212]
                .try_into()
                .expect("predecessor checkpoint"),
            idempotency_key: bytes[212..244].try_into().expect("idempotency key"),
        },
        core_safety_revision,
        core_ack_digest,
        replay_ack_hash,
    })
}

fn record_checksum(domain: &[u8], prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((prefix.len() as u64).to_be_bytes());
    hasher.update(prefix);
    hasher.finalize().into()
}

fn read_pending(path: &Path) -> Result<PendingFactsV1, ReplayToCoreCoordinatorErrorV1> {
    let bytes = read_private_exact(path, PENDING_BYTES_V1)?;
    decode_pending(&bytes)
}

fn read_completed(path: &Path) -> Result<CompletedFactsV1, ReplayToCoreCoordinatorErrorV1> {
    let bytes = read_private_exact(path, COMPLETED_BYTES_V1)?;
    decode_completed(&bytes)
}

fn read_private_exact(
    path: &Path,
    expected: usize,
) -> Result<Vec<u8>, ReplayToCoreCoordinatorErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !private_regular_file(&metadata)
        || metadata.len() != expected as u64
    {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    let mut file = OpenOptions::new().read(true).open(path)?;
    let descriptor = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if descriptor.dev() != named.dev()
        || descriptor.ino() != named.ino()
        || descriptor.uid() != named.uid()
    {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    let mut bytes = Vec::with_capacity(expected);
    Read::by_ref(&mut file)
        .take(expected as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() != expected {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    Ok(bytes)
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(PRIVATE_FILE_MODE_V1);
    let mut file = options.open(path)?;
    file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE_V1))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn open_or_create_private_file(path: &Path) -> Result<File, ReplayToCoreCoordinatorErrorV1> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .mode(PRIVATE_FILE_MODE_V1);
    let file = options.open(path)?;
    file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE_V1))?;
    let metadata = file.metadata()?;
    if !private_regular_file(&metadata) {
        return Err(ReplayToCoreCoordinatorErrorV1::Corrupt);
    }
    Ok(file)
}

fn validate_private_root(path: &Path) -> Result<(), ReplayToCoreCoordinatorErrorV1> {
    if !path.is_absolute() {
        return Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(
            "coordinator root must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o7777 != PRIVATE_DIRECTORY_MODE_V1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || fs::canonicalize(path)? != path
    {
        return Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(
            "coordinator root must be a canonical owner-only directory",
        ));
    }
    Ok(())
}

fn private_regular_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o7777 == PRIVATE_FILE_MODE_V1
        && metadata.uid() == rustix::process::geteuid().as_raw()
}

fn hex32(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn main() {
    println!(
        "status=g1-r2a-candidate pending_before_core=true sealed_core_authority=true live_core_adapter=false core_ack_generated_by_core=false atomic_with_core=false node_process_integration=false production=false"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::TempDir;
    use trnm_consensus_peer_lease::{
        PayloadReplayFrameV1, PayloadReplayStoreV1, PeerLeaseDirectionV1,
    };

    fn private_tempdir(prefix: &str) -> TempDir {
        let directory = tempfile::Builder::new().prefix(prefix).tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn private_child(root: &Path, name: &str) -> PathBuf {
        let path = root.join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn namespace() -> PayloadReplayNamespaceV1 {
        PayloadReplayNamespaceV1::new([1; 32], 7, [2; 32], [3; 32], [4; 32]).unwrap()
    }

    fn frame(
        namespace: PayloadReplayNamespaceV1,
        sequence: u64,
        fingerprint: [u8; 32],
    ) -> PayloadReplayFrameV1 {
        PayloadReplayFrameV1::new(
            namespace
                .scope_for([9; 32], PeerLeaseDirectionV1::Inbound)
                .unwrap(),
            namespace.run_id_hash(),
            namespace.network_context_hash(),
            [5; 32],
            1,
            sequence,
            2,
            11,
            fingerprint,
        )
        .unwrap()
    }

    fn admit(
        wal: &Path,
        namespace: PayloadReplayNamespaceV1,
        frame: PayloadReplayFrameV1,
    ) -> PayloadReplayRecoveryTargetV1 {
        let receipt = {
            let mut store = PayloadReplayStoreV1::open(wal, namespace).unwrap();
            store.admit(&frame).unwrap()
        };
        PayloadReplayRecoveryTargetV1::from_admission(frame, receipt)
    }

    #[derive(Debug, Default)]
    struct FakeCoreV1 {
        calls: usize,
        fail: bool,
        expected_pending: Option<PathBuf>,
        receipts: BTreeMap<[u8; 32], CoreDurableReplayReceiptV1>,
    }

    impl sealed::SealedReplayToCoreAuthorityV1 for FakeCoreV1 {}

    impl ReplayToCoreAuthorityV1 for FakeCoreV1 {
        fn deliver_durably(
            &mut self,
            request: CoreReplayRequestV1,
        ) -> Result<CoreDurableReplayReceiptV1, CoreDeliveryErrorV1> {
            if let Some(path) = &self.expected_pending {
                assert!(path.exists(), "Core was called before pending durability");
            }
            self.calls += 1;
            if self.fail {
                return Err(CoreDeliveryErrorV1::new("synthetic durable Core refusal"));
            }
            if let Some(receipt) = self.receipts.get(&request.idempotency_key).copied() {
                return Ok(receipt);
            }
            let receipt = CoreDurableReplayReceiptV1::new_after_durable_core(
                request,
                19,
                [21; 32],
            )
            .unwrap();
            self.receipts.insert(request.idempotency_key, receipt);
            Ok(receipt)
        }
    }

    struct FixtureV1 {
        _root: TempDir,
        wal: PathBuf,
        replay_ack_root: PathBuf,
        coordinator_root: PathBuf,
        namespace: PayloadReplayNamespaceV1,
        target: PayloadReplayRecoveryTargetV1,
    }

    fn fixture(prefix: &str) -> FixtureV1 {
        let root = private_tempdir(prefix);
        let wal = root.path().join("payload.wal");
        let replay_ack_root = private_child(root.path(), "replay-acks");
        let coordinator_root = private_child(root.path(), "coordinator");
        let namespace = namespace();
        let target = admit(&wal, namespace, frame(namespace, 0, [10; 32]));
        FixtureV1 {
            _root: root,
            wal,
            replay_ack_root,
            coordinator_root,
            namespace,
            target,
        }
    }

    #[test]
    fn pending_is_durable_before_core_and_completion_is_idempotent() {
        let fixture = fixture("trnm-r2-normal-");
        let mut coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let request = CoreReplayRequestV1::new(
            fixture.namespace,
            fixture.target,
            [30; 32],
            [31; 32],
        )
        .unwrap();
        let mut core = FakeCoreV1 {
            expected_pending: Some(coordinator.pending_path(request)),
            ..FakeCoreV1::default()
        };
        let first = coordinator
            .drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
                [30; 32],
                [31; 32],
            )
            .unwrap();
        assert_eq!(core.calls, 1);
        assert!(!first.idempotent_replay());
        assert!(!coordinator.pending_path(request).exists());
        drop(coordinator);

        let mut reopened = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let second = reopened
            .drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
                [30; 32],
                [31; 32],
            )
            .unwrap();
        assert_eq!(core.calls, 1);
        assert!(second.idempotent_replay());
        assert_eq!(first.replay_ack_hash(), second.replay_ack_hash());
    }

    #[test]
    fn core_failure_retains_pending_and_blocks_a_later_target() {
        let fixture = fixture("trnm-r2-pending-block-");
        let mut coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let mut core = FakeCoreV1 {
            fail: true,
            ..FakeCoreV1::default()
        };
        assert!(matches!(
            coordinator.drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
                [30; 32],
                [31; 32],
            ),
            Err(ReplayToCoreCoordinatorErrorV1::CoreDelivery(_))
        ));
        drop(coordinator);

        let second_frame = frame(fixture.namespace, 1, [11; 32]);
        let second_target = admit(&fixture.wal, fixture.namespace, second_frame);
        let mut reopened = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        assert!(matches!(
            reopened.drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                second_target,
                [32; 32],
                [33; 32],
            ),
            Err(ReplayToCoreCoordinatorErrorV1::EarlierDeliveryPending)
        ));
    }

    #[test]
    fn exact_existing_replay_ack_completes_without_core_redelivery() {
        let fixture = fixture("trnm-r2-existing-ack-");
        let request = CoreReplayRequestV1::new(
            fixture.namespace,
            fixture.target,
            [30; 32],
            [31; 32],
        )
        .unwrap();
        {
            let coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
            coordinator.ensure_pending(request).unwrap();
        }
        {
            let mut replay_owner = PayloadReplayRecoveryOwnerV1::open(
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
            )
            .unwrap();
            replay_owner
                .acknowledge_core(
                    PayloadReplayCoreAcknowledgementV1::new(
                        fixture.target,
                        19,
                        [21; 32],
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        let mut core = FakeCoreV1 {
            fail: true,
            ..FakeCoreV1::default()
        };
        let mut coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let completion = coordinator
            .drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
                [30; 32],
                [31; 32],
            )
            .unwrap();
        assert_eq!(core.calls, 0);
        assert_eq!(completion.core_safety_revision(), 19);
        assert!(!coordinator.pending_path(request).exists());
    }

    #[test]
    fn conflicting_request_for_existing_pending_fails_closed() {
        let fixture = fixture("trnm-r2-pending-conflict-");
        let request = CoreReplayRequestV1::new(
            fixture.namespace,
            fixture.target,
            [30; 32],
            [31; 32],
        )
        .unwrap();
        {
            let coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
            coordinator.ensure_pending(request).unwrap();
        }
        let mut coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let mut core = FakeCoreV1::default();
        assert!(matches!(
            coordinator.drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
                [99; 32],
                [31; 32],
            ),
            Err(ReplayToCoreCoordinatorErrorV1::Conflict)
        ));
        assert_eq!(core.calls, 0);
    }

    #[test]
    fn tampered_pending_record_is_rejected() {
        let fixture = fixture("trnm-r2-pending-tamper-");
        let request = CoreReplayRequestV1::new(
            fixture.namespace,
            fixture.target,
            [30; 32],
            [31; 32],
        )
        .unwrap();
        {
            let coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
            coordinator.ensure_pending(request).unwrap();
            let path = coordinator.pending_path(request);
            let mut bytes = fs::read(&path).unwrap();
            bytes[148] ^= 1;
            fs::write(path, bytes).unwrap();
        }
        let mut coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let mut core = FakeCoreV1::default();
        assert!(matches!(
            coordinator.drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
                [30; 32],
                [31; 32],
            ),
            Err(ReplayToCoreCoordinatorErrorV1::Corrupt)
        ));
    }

    #[test]
    fn live_coordinator_lock_excludes_a_second_owner() {
        let fixture = fixture("trnm-r2-lock-");
        let _first = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        assert!(matches!(
            ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root),
            Err(ReplayToCoreCoordinatorErrorV1::Busy)
        ));
    }

    #[test]
    fn retained_completion_temporary_is_an_ambiguous_stop() {
        let fixture = fixture("trnm-r2-completion-temp-");
        let path = fixture
            .coordinator_root
            .join(".completed-retained.v1.tmp-1-1");
        fs::write(&path, b"retained").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let mut core = FakeCoreV1::default();
        assert!(matches!(
            coordinator.drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
                [30; 32],
                [31; 32],
            ),
            Err(ReplayToCoreCoordinatorErrorV1::AmbiguousPublication)
        ));
    }

    #[test]
    fn completed_and_exact_pending_residue_reconcile_without_core() {
        let fixture = fixture("trnm-r2-completed-residue-");
        let mut core = FakeCoreV1::default();
        let request = CoreReplayRequestV1::new(
            fixture.namespace,
            fixture.target,
            [30; 32],
            [31; 32],
        )
        .unwrap();
        {
            let mut coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
            coordinator
                .drive(
                    &mut core,
                    &fixture.wal,
                    &fixture.replay_ack_root,
                    fixture.namespace,
                    fixture.target,
                    [30; 32],
                    [31; 32],
                )
                .unwrap();
            write_private_new(
                &coordinator.pending_path(request),
                &encode_pending(PendingFactsV1::from_request(request)),
            )
            .unwrap();
        }
        let prior_calls = core.calls;
        let mut reopened = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let receipt = reopened
            .drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                fixture.namespace,
                fixture.target,
                [30; 32],
                [31; 32],
            )
            .unwrap();
        assert!(receipt.idempotent_replay());
        assert_eq!(core.calls, prior_calls);
        assert!(!reopened.pending_path(request).exists());
    }

    #[test]
    fn wrong_namespace_cannot_reuse_pending_target() {
        let fixture = fixture("trnm-r2-namespace-");
        let request = CoreReplayRequestV1::new(
            fixture.namespace,
            fixture.target,
            [30; 32],
            [31; 32],
        )
        .unwrap();
        {
            let coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
            coordinator.ensure_pending(request).unwrap();
        }
        let wrong_namespace =
            PayloadReplayNamespaceV1::new([1; 32], 7, [2; 32], [3; 32], [44; 32]).unwrap();
        let mut coordinator = ReplayToCoreCoordinatorV1::open(&fixture.coordinator_root).unwrap();
        let mut core = FakeCoreV1::default();
        assert!(matches!(
            coordinator.drive(
                &mut core,
                &fixture.wal,
                &fixture.replay_ack_root,
                wrong_namespace,
                fixture.target,
                [30; 32],
                [31; 32],
            ),
            Err(ReplayToCoreCoordinatorErrorV1::Conflict)
        ));
    }

    #[test]
    fn broad_or_relative_coordinator_root_is_rejected() {
        let root = private_tempdir("trnm-r2-root-mode-");
        let broad = root.path().join("broad");
        fs::create_dir(&broad).unwrap();
        fs::set_permissions(&broad, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            ReplayToCoreCoordinatorV1::open(&broad),
            Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(_))
        ));
        assert!(matches!(
            ReplayToCoreCoordinatorV1::open(Path::new("relative-root")),
            Err(ReplayToCoreCoordinatorErrorV1::InvalidRequest(_))
        ));
    }

    #[test]
    fn core_receipt_must_bind_exact_request() {
        let fixture = fixture("trnm-r2-receipt-bind-");
        let request = CoreReplayRequestV1::new(
            fixture.namespace,
            fixture.target,
            [30; 32],
            [31; 32],
        )
        .unwrap();
        let other = CoreReplayRequestV1::new(
            fixture.namespace,
            fixture.target,
            [32; 32],
            [31; 32],
        )
        .unwrap();
        let receipt =
            CoreDurableReplayReceiptV1::new_after_durable_core(request, 19, [21; 32]).unwrap();
        assert!(matches!(
            receipt.validate_for(other),
            Err(ReplayToCoreCoordinatorErrorV1::CoreReceiptMismatch)
        ));
    }
}
