#![forbid(unsafe_code)]

//! Minimal, independently runnable PoCO-BFT signer P0 slice.
//!
//! The service consumes the existing exact protocol-1 request envelope over a
//! length-delimited Unix stream.  Before touching its local signing key it
//! atomically reserves `(epoch, view, purpose, nonce, request fingerprint)` in
//! a separate SQLite watermark store.  The transaction advances a persistent
//! sequence with compare-and-advance semantics and rejects a nonce, request,
//! purpose/round, or `(epoch, view)` rollback that has already been observed.
//!
//! This is intentionally a development slice, not a consensus-runtime
//! adapter.  It has no Core/SafetyRules admission, no lease resolver, no HSM or
//! KMS integration, and no process-generation reconciliation.  The key is
//! held by this independent process only to prove the transport and durable
//! admission boundary.  All activation and production truth values remain
//! false.

mod fixture;

use std::{
    collections::BTreeMap,
    error::Error,
    fmt, fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::Duration,
};

use ed25519_dalek::{Signer, SigningKey, Verifier};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use trnm_consensus_external_watermark::{
    ExternalWatermarkAuthorityError, ExternalWatermarkSemanticBindingV1,
    ExternalWatermarkSemanticFactsV1, ExternalWatermarkSemanticLifecycleModeV1,
    ReplayBindingErrorV1, ReplayBindingStoreV1, UnixWatermarkClient,
};
use trnm_consensus_remote_signer_protocol::{
    decode_remote_proposal_signer_request_v1_exact, decode_remote_signer_request_v1_exact,
    is_remote_proposal_request_v1, RemoteConsensusCommandKindV1, RemoteProposalSignatureRequestV1,
    RemoteSignerProtocolErrorV1, RemoteSignerRequestBindingV1,
    UnverifiedRemoteProposalSignerResponseV1, UnverifiedRemoteSignerResponseV1,
    MAX_REMOTE_SIGNER_REQUEST_BYTES_V1,
};
use trnm_consensus_signer_journal::SignerWatermarkV0;
use trnm_consensus_types::{SignatureBytes, ValidatorSet};

pub use fixture::{
    fixture_proposal_service_config, fixture_request, fixture_service_config,
    fixture_service_config_with_binding, Fixture,
};

/// Runtime activation is deliberately closed for this P0 slice.
pub const REMOTE_SIGNER_SERVICE_RUNTIME_ACTIVATION_V1: bool = false;
/// The service is not a production signature producer.
pub const REMOTE_SIGNER_SERVICE_PRODUCTION_SIGNATURE_PRODUCER_V1: bool = false;
/// No poco consensus runtime consumes this service yet.
pub const REMOTE_SIGNER_SERVICE_CONSENSUS_RUNTIME_INTEGRATION_V1: bool = false;

const WATERMARK_SCHEMA_VERSION: i64 = 2;
const WATERMARK_SCOPE_DOMAIN: &[u8] = b"trnm.remote-signer.service.p0-watermark-scope.v1\0";
const MAX_SERVICE_FRAME_BYTES: usize = MAX_REMOTE_SIGNER_REQUEST_BYTES_V1;
const FRAME_OK: u8 = 0;
const FRAME_REJECT: u8 = 1;

/// Maximum request/response frame payload accepted by the Unix transport.
pub const MAX_REMOTE_SIGNER_SERVICE_FRAME_BYTES_V1: usize = MAX_SERVICE_FRAME_BYTES;

/// Purpose policy configured for one signer process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurposePolicyV1 {
    allow_vote: bool,
    allow_timeout_vote: bool,
    allow_proposal: bool,
}

impl PurposePolicyV1 {
    pub const fn both() -> Self {
        Self {
            allow_vote: true,
            allow_timeout_vote: true,
            allow_proposal: false,
        }
    }

    pub const fn vote_only() -> Self {
        Self {
            allow_vote: true,
            allow_timeout_vote: false,
            allow_proposal: false,
        }
    }

    pub const fn timeout_vote_only() -> Self {
        Self {
            allow_vote: false,
            allow_timeout_vote: true,
            allow_proposal: false,
        }
    }

    /// Explicit proposal-only policy. Existing `both`, `vote_only`, and
    /// `timeout_vote_only` policies remain proposal-disabled for compatibility.
    pub const fn proposal_only() -> Self {
        Self {
            allow_vote: false,
            allow_timeout_vote: false,
            allow_proposal: true,
        }
    }

    pub const fn allows_proposal(self) -> bool {
        self.allow_proposal
    }

    pub const fn allows(self, kind: RemoteConsensusCommandKindV1) -> bool {
        match kind {
            RemoteConsensusCommandKindV1::Vote => self.allow_vote,
            RemoteConsensusCommandKindV1::TimeoutVote => self.allow_timeout_vote,
        }
    }
}

/// Configuration for one independent signer process.
pub struct RemoteSignerServiceConfig {
    pub validator_set: ValidatorSet,
    pub binding: RemoteSignerRequestBindingV1,
    pub signing_key: SigningKey,
    pub watermark_path: PathBuf,
    pub purpose_policy: PurposePolicyV1,
}

/// Request facts an independently administered authority must bind before a
/// private key can be reached.
///
/// This is deliberately a data-only seam. The bounded timeout-mode entry
/// point below passes these facts to an independently durable adapter; Core,
/// SafetyRules, and production vote authority remain outside this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalAuthorityRequestV1 {
    pub scope: [u8; 32],
    pub process_generation: u64,
    pub lease_id: [u8; 32],
    pub signer_profile_ref: [u8; 32],
    pub request_fingerprint: [u8; 32],
    pub signing_root: [u8; 32],
    pub nonce: [u8; 32],
    pub command_kind: RemoteConsensusCommandKindV1,
    pub epoch: u64,
    pub view: u64,
    pub safety_revision: u64,
}

/// Opaque external reservation returned by a compare-and-advance authority.
/// The token must be bound to the exact request and must not be reconstructed
/// from the local SQLite sequence after a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalAuthorityReservationV1 {
    sequence: u64,
    request_fingerprint: [u8; 32],
    token_digest: [u8; 32],
}

impl ExternalAuthorityReservationV1 {
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub const fn request_fingerprint(self) -> [u8; 32] {
        self.request_fingerprint
    }

    pub const fn token_digest(self) -> [u8; 32] {
        self.token_digest
    }

    /// Constructs a token for an adapter implementation after its durable CAS
    /// has succeeded.  Calling this constructor grants no signer authority.
    pub const fn from_parts(
        sequence: u64,
        request_fingerprint: [u8; 32],
        token_digest: [u8; 32],
    ) -> Self {
        Self {
            sequence,
            request_fingerprint,
            token_digest,
        }
    }
}

/// Stable failure classes for the bounded external timeout authority bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalAuthorityErrorV1 {
    Required,
    Unavailable,
    CompareFailed,
    ReplayConflict,
    InvalidState,
    Protocol,
}

impl fmt::Display for ExternalAuthorityErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Required => "external authority is required for this command",
            Self::Unavailable => "external authority is unavailable",
            Self::CompareFailed => "external authority compare-and-advance failed",
            Self::ReplayConflict => "external response replay binding conflicted",
            Self::InvalidState => "external authority persisted state is invalid",
            Self::Protocol => "external authority protocol was invalid",
        })
    }
}

impl Error for ExternalAuthorityErrorV1 {}

/// Adapter contract for an external watermark/fencing authority.
///
/// Implementations must be a different failure domain from the service's
/// SQLite file and must provide cross-process durable CAS semantics.  The
/// service integration order is intentionally fixed:
///
/// 1. `replay_response_v1` is checked first; an exact durable response must be
///    returned without touching the private key.
/// 2. `reserve_v1` performs an external compare-and-advance bound to every
///    request fact above (including generation and lease) before signing.
/// 3. `bind_response_v1` durably records the exact response before local
///    reservation completion.
///
/// Any unavailable, stale, corrupt, or ambiguous result must fail closed.
/// This trait does not itself grant Core/SafetyRules authority.
pub trait ExternalAuthorityAdapterV1: Send {
    /// Returns the exact 64-byte signature payload for a previously bound
    /// request. The service reconstructs and verifies the protocol response
    /// envelope from the original request; an adapter must never return a
    /// caller-selected or partially decoded response.
    fn replay_response_v1(
        &mut self,
        request: ExternalAuthorityRequestV1,
    ) -> Result<Option<Vec<u8>>, ExternalAuthorityErrorV1>;

    fn reserve_v1(
        &mut self,
        request: ExternalAuthorityRequestV1,
    ) -> Result<ExternalAuthorityReservationV1, ExternalAuthorityErrorV1>;

    fn bind_response_v1(
        &mut self,
        reservation: ExternalAuthorityReservationV1,
        response: &[u8],
    ) -> Result<(), ExternalAuthorityErrorV1>;
}

const EXTERNAL_ADAPTER_JOURNAL_DOMAIN_V1: &[u8] =
    b"trnm.remote-signer.external-timeout-adapter.journal.v1\0";
const EXTERNAL_ADAPTER_CHECKSUM_DOMAIN_V1: &[u8] =
    b"trnm.remote-signer.external-timeout-adapter.checksum.v1\0";
const EXTERNAL_ADAPTER_TOKEN_DOMAIN_V1: &[u8] =
    b"trnm.remote-signer.external-timeout-adapter.reservation-token.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingExternalReservationV1 {
    request: ExternalAuthorityRequestV1,
    target: SignerWatermarkV0,
}

/// A reservation is written to a separate, private intent sidecar before the
/// external CAS is attempted.  This closes the otherwise ambiguous window in
/// which the authority has advanced but the signer process died before its
/// response log was bound.  The sidecar is never a signature or an authority
/// grant; it only makes the exact request retryable after a process restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DurablePendingExternalReservationV1 {
    pending: PendingExternalReservationV1,
    previous: Option<SignerWatermarkV0>,
}

// Keep the service-side scan bounded to the same hard ceiling enforced by
// ReplayBindingStoreV1.  The external-store constant is intentionally private
// to its crate, so this mirror is part of the service guard's local contract.
const MAX_REPLAY_LOG_BYTES_V1: u64 = 64 * 1024 * 1024;

/// A live integrity snapshot for the response-binding log.
///
/// `ReplayBindingStoreV1` authenticates and replays its log when it opens, but
/// its lookup/count APIs intentionally expose only the in-memory projection.
/// The external adapter must not continue using that projection after the
/// pathname has been replaced or the file has been edited while the process
/// remains alive.  Keep this guard in the service crate so the current topic
/// can close that process-lifetime seam without changing the external-store
/// API.  Both the response log and its durable response-head anchor are
/// pinned. The digest is over the raw file image (not caller data), and the
/// descriptor/path checks make replacement and same-length edits fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplayLogSnapshotV1 {
    device: u64,
    inode: u64,
    length: u64,
    digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayLogGuardV1 {
    path: PathBuf,
    parent: PathBuf,
    parent_device: u64,
    parent_inode: u64,
    snapshot: ReplayLogSnapshotV1,
    anchor_path: PathBuf,
    anchor_snapshot: ReplayLogSnapshotV1,
    record_count: u64,
}

impl ReplayLogGuardV1 {
    fn open(replay: &ReplayBindingStoreV1) -> Result<Self, ExternalAuthorityErrorV1> {
        let path = replay.log_path().to_path_buf();
        let parent = path
            .parent()
            .ok_or(ExternalAuthorityErrorV1::InvalidState)?
            .to_path_buf();
        let (parent_device, parent_inode) = replay_directory_identity_v1(&parent)?;
        let snapshot = replay_log_snapshot_v1(&path)?;
        let anchor_path = replay_anchor_path_v1(&path)?;
        let anchor_snapshot = replay_log_snapshot_v1(&anchor_path)?;
        Ok(Self {
            path,
            parent,
            parent_device,
            parent_inode,
            snapshot,
            anchor_path,
            anchor_snapshot,
            record_count: replay.record_count_v1(),
        })
    }

    fn preflight(&self, replay: &ReplayBindingStoreV1) -> Result<(), ExternalAuthorityErrorV1> {
        if replay.log_path() != self.path || replay.record_count_v1() != self.record_count {
            return Err(ExternalAuthorityErrorV1::InvalidState);
        }
        let (parent_device, parent_inode) = replay_directory_identity_v1(&self.parent)?;
        if parent_device != self.parent_device || parent_inode != self.parent_inode {
            return Err(ExternalAuthorityErrorV1::InvalidState);
        }
        if replay_log_snapshot_v1(&self.path)? != self.snapshot {
            return Err(ExternalAuthorityErrorV1::InvalidState);
        }
        if replay_log_snapshot_v1(&self.anchor_path)? != self.anchor_snapshot {
            return Err(ExternalAuthorityErrorV1::InvalidState);
        }
        Ok(())
    }

    fn refresh_after_record(
        &mut self,
        replay: &ReplayBindingStoreV1,
    ) -> Result<(), ExternalAuthorityErrorV1> {
        let old_count = self.record_count;
        let new_count = replay.record_count_v1();
        if new_count < old_count || new_count > old_count.saturating_add(1) {
            return Err(ExternalAuthorityErrorV1::InvalidState);
        }
        let (parent_device, parent_inode) = replay_directory_identity_v1(&self.parent)?;
        if parent_device != self.parent_device || parent_inode != self.parent_inode {
            return Err(ExternalAuthorityErrorV1::InvalidState);
        }
        let snapshot = replay_log_snapshot_v1(&self.path)?;
        let anchor_snapshot = replay_log_snapshot_v1(&self.anchor_path)?;
        if new_count == old_count {
            // An idempotent duplicate must not alter the durable image.
            if snapshot != self.snapshot || anchor_snapshot != self.anchor_snapshot {
                return Err(ExternalAuthorityErrorV1::InvalidState);
            }
        } else if snapshot.device != self.snapshot.device
            || snapshot.inode != self.snapshot.inode
            || snapshot.length <= self.snapshot.length
            || snapshot.digest == self.snapshot.digest
            || anchor_snapshot.length != self.anchor_snapshot.length
            || anchor_snapshot.digest == self.anchor_snapshot.digest
        {
            return Err(ExternalAuthorityErrorV1::InvalidState);
        }
        self.snapshot = snapshot;
        self.anchor_snapshot = anchor_snapshot;
        self.record_count = new_count;
        Ok(())
    }
}

const PENDING_RESERVATION_MAGIC_V1: &[u8; 8] = b"TRNMPD01";
const PENDING_RESERVATION_DOMAIN_V1: &[u8] = b"trnm.remote-signer.external-timeout.pending.v1\0";
const PENDING_RESERVATION_VERSION_V1: u8 = 1;

fn pending_reservation_path_v1(
    response_log_path: &Path,
) -> Result<PathBuf, ExternalAuthorityErrorV1> {
    let parent = response_log_path
        .parent()
        .ok_or(ExternalAuthorityErrorV1::InvalidState)?;
    let name = response_log_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(ExternalAuthorityErrorV1::InvalidState)?;
    Ok(parent.join(format!(".{name}.pending")))
}

fn replay_anchor_path_v1(response_log_path: &Path) -> Result<PathBuf, ExternalAuthorityErrorV1> {
    // This mirrors ReplayBindingStoreV1's private path convention.  A future
    // public integrity-preflight API in that crate should replace this local
    // derivation so the two namespaces cannot drift independently.
    let parent = response_log_path
        .parent()
        .ok_or(ExternalAuthorityErrorV1::InvalidState)?;
    let name = response_log_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(ExternalAuthorityErrorV1::InvalidState)?;
    Ok(parent.join(format!(".{name}.response-head-v1")))
}

fn replay_directory_identity_v1(path: &Path) -> Result<(u64, u64), ExternalAuthorityErrorV1> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ExternalAuthorityErrorV1::InvalidState);
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn replay_log_snapshot_v1(path: &Path) -> Result<ReplayLogSnapshotV1, ExternalAuthorityErrorV1> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.nlink() != 1
        || path_metadata.mode() & 0o777 != 0o600
        || path_metadata.len() > MAX_REPLAY_LOG_BYTES_V1
    {
        return Err(ExternalAuthorityErrorV1::InvalidState);
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
    let before = file
        .metadata()
        .map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
    if !before.is_file()
        || before.nlink() != 1
        || before.mode() & 0o777 != 0o600
        || before.len() > MAX_REPLAY_LOG_BYTES_V1
        || before.dev() != path_metadata.dev()
        || before.ino() != path_metadata.ino()
        || before.len() != path_metadata.len()
    {
        return Err(ExternalAuthorityErrorV1::InvalidState);
    }

    let mut reader = file
        .try_clone()
        .map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
    let mut hasher = Sha256::new();
    let mut bytes_read = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(read as u64)
            .ok_or(ExternalAuthorityErrorV1::InvalidState)?;
        if bytes_read > before.len() {
            return Err(ExternalAuthorityErrorV1::InvalidState);
        }
        hasher.update(&buffer[..read]);
    }
    let after = file
        .metadata()
        .map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
    let final_path_metadata =
        fs::symlink_metadata(path).map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
    if bytes_read != before.len()
        || after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.len() != before.len()
        || final_path_metadata.file_type().is_symlink()
        || !final_path_metadata.is_file()
        || final_path_metadata.nlink() != 1
        || final_path_metadata.mode() & 0o777 != 0o600
        || final_path_metadata.dev() != before.dev()
        || final_path_metadata.ino() != before.ino()
        || final_path_metadata.len() != before.len()
    {
        return Err(ExternalAuthorityErrorV1::InvalidState);
    }
    Ok(ReplayLogSnapshotV1 {
        device: before.dev(),
        inode: before.ino(),
        length: before.len(),
        digest: hasher.finalize().into(),
    })
}

fn pending_put_bytes_v1(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(value);
}

fn pending_put_u64_v1(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn pending_take_v1<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], ExternalAuthorityErrorV1> {
    let end = offset
        .checked_add(length)
        .ok_or(ExternalAuthorityErrorV1::InvalidState)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(ExternalAuthorityErrorV1::InvalidState)?;
    *offset = end;
    Ok(value)
}

fn pending_take_u8_v1(bytes: &[u8], offset: &mut usize) -> Result<u8, ExternalAuthorityErrorV1> {
    Ok(pending_take_v1(bytes, offset, 1)?[0])
}

fn pending_take_u64_v1(bytes: &[u8], offset: &mut usize) -> Result<u64, ExternalAuthorityErrorV1> {
    Ok(u64::from_be_bytes(
        pending_take_v1(bytes, offset, 8)?
            .try_into()
            .map_err(|_| ExternalAuthorityErrorV1::InvalidState)?,
    ))
}

fn pending_checksum_v1(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PENDING_RESERVATION_DOMAIN_V1);
    hash.update(bytes);
    hash.finalize().into()
}

fn encode_pending_reservation_v1(
    pending: DurablePendingExternalReservationV1,
) -> Result<Vec<u8>, ExternalAuthorityErrorV1> {
    let request = pending.pending.request;
    let target = pending.pending.target;
    if request.command_kind != RemoteConsensusCommandKindV1::TimeoutVote
        || request.scope == [0; 32]
        || request.lease_id == [0; 32]
        || request.signer_profile_ref == [0; 32]
        || request.request_fingerprint == [0; 32]
        || request.signing_root == [0; 32]
        || request.nonce == [0; 32]
        || target.scope() != request.scope
        || target.journal_id() == [0; 32]
        || target.chain_checksum() == [0; 32]
        || request.process_generation == 0
        || request.safety_revision == 0
    {
        return Err(ExternalAuthorityErrorV1::InvalidState);
    }
    if let Some(previous) = pending.previous {
        if previous.scope() != target.scope()
            || previous.journal_id() != target.journal_id()
            || previous.sequence().checked_add(1) != Some(target.sequence())
        {
            return Err(ExternalAuthorityErrorV1::InvalidState);
        }
    } else if target.sequence() != 0 {
        return Err(ExternalAuthorityErrorV1::InvalidState);
    }
    let mut bytes = Vec::with_capacity(512);
    pending_put_bytes_v1(&mut bytes, PENDING_RESERVATION_MAGIC_V1);
    pending_put_bytes_v1(&mut bytes, &[PENDING_RESERVATION_VERSION_V1, 0, 0, 0]);
    pending_put_bytes_v1(&mut bytes, &request.scope);
    pending_put_u64_v1(&mut bytes, request.process_generation);
    pending_put_bytes_v1(&mut bytes, &request.lease_id);
    pending_put_bytes_v1(&mut bytes, &request.signer_profile_ref);
    pending_put_bytes_v1(&mut bytes, &request.request_fingerprint);
    pending_put_bytes_v1(&mut bytes, &request.signing_root);
    pending_put_bytes_v1(&mut bytes, &request.nonce);
    pending_put_bytes_v1(&mut bytes, &[1]); // TimeoutVote only in this sidecar.
    pending_put_u64_v1(&mut bytes, request.epoch);
    pending_put_u64_v1(&mut bytes, request.view);
    pending_put_u64_v1(&mut bytes, request.safety_revision);
    pending_put_bytes_v1(&mut bytes, &target.scope());
    pending_put_bytes_v1(&mut bytes, &target.journal_id());
    pending_put_u64_v1(&mut bytes, target.sequence());
    pending_put_bytes_v1(&mut bytes, &target.chain_checksum());
    match pending.previous {
        Some(previous) => {
            pending_put_bytes_v1(&mut bytes, &[1]);
            pending_put_bytes_v1(&mut bytes, &previous.scope());
            pending_put_bytes_v1(&mut bytes, &previous.journal_id());
            pending_put_u64_v1(&mut bytes, previous.sequence());
            pending_put_bytes_v1(&mut bytes, &previous.chain_checksum());
        }
        None => pending_put_bytes_v1(&mut bytes, &[0]),
    }
    let checksum = pending_checksum_v1(&bytes);
    pending_put_bytes_v1(&mut bytes, &checksum);
    Ok(bytes)
}

fn decode_pending_reservation_v1(
    bytes: &[u8],
) -> Result<DurablePendingExternalReservationV1, ExternalAuthorityErrorV1> {
    let mut offset = 0;
    if pending_take_v1(bytes, &mut offset, PENDING_RESERVATION_MAGIC_V1.len())?
        != PENDING_RESERVATION_MAGIC_V1
    {
        return Err(ExternalAuthorityErrorV1::InvalidState);
    }
    if pending_take_u8_v1(bytes, &mut offset)? != PENDING_RESERVATION_VERSION_V1
        || pending_take_v1(bytes, &mut offset, 3)? != [0, 0, 0]
    {
        return Err(ExternalAuthorityErrorV1::InvalidState);
    }
    let scope = pending_take_v1(bytes, &mut offset, 32)?.try_into().unwrap();
    let process_generation = pending_take_u64_v1(bytes, &mut offset)?;
    let lease_id = pending_take_v1(bytes, &mut offset, 32)?.try_into().unwrap();
    let signer_profile_ref = pending_take_v1(bytes, &mut offset, 32)?.try_into().unwrap();
    let request_fingerprint = pending_take_v1(bytes, &mut offset, 32)?.try_into().unwrap();
    let signing_root = pending_take_v1(bytes, &mut offset, 32)?.try_into().unwrap();
    let nonce = pending_take_v1(bytes, &mut offset, 32)?.try_into().unwrap();
    if pending_take_u8_v1(bytes, &mut offset)? != 1 {
        return Err(ExternalAuthorityErrorV1::InvalidState);
    }
    let epoch = pending_take_u64_v1(bytes, &mut offset)?;
    let view = pending_take_u64_v1(bytes, &mut offset)?;
    let safety_revision = pending_take_u64_v1(bytes, &mut offset)?;
    let target_scope = pending_take_v1(bytes, &mut offset, 32)?.try_into().unwrap();
    let target_journal = pending_take_v1(bytes, &mut offset, 32)?.try_into().unwrap();
    let target_sequence = pending_take_u64_v1(bytes, &mut offset)?;
    let target_checksum = pending_take_v1(bytes, &mut offset, 32)?.try_into().unwrap();
    let previous = if pending_take_u8_v1(bytes, &mut offset)? == 1 {
        let previous_scope = pending_take_v1(bytes, &mut offset, 32)?.try_into().unwrap();
        let previous_journal = pending_take_v1(bytes, &mut offset, 32)?.try_into().unwrap();
        let previous_sequence = pending_take_u64_v1(bytes, &mut offset)?;
        let previous_checksum = pending_take_v1(bytes, &mut offset, 32)?.try_into().unwrap();
        Some(
            SignerWatermarkV0::from_persisted_parts(
                previous_scope,
                previous_journal,
                previous_sequence,
                previous_checksum,
            )
            .map_err(|_| ExternalAuthorityErrorV1::InvalidState)?,
        )
    } else {
        None
    };
    let checksum_offset = offset;
    let stored_checksum = pending_take_v1(bytes, &mut offset, 32)?;
    if offset != bytes.len() || pending_checksum_v1(&bytes[..checksum_offset]) != stored_checksum {
        return Err(ExternalAuthorityErrorV1::InvalidState);
    }
    let target = SignerWatermarkV0::from_persisted_parts(
        target_scope,
        target_journal,
        target_sequence,
        target_checksum,
    )
    .map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
    let pending = DurablePendingExternalReservationV1 {
        pending: PendingExternalReservationV1 {
            request: ExternalAuthorityRequestV1 {
                scope,
                process_generation,
                lease_id,
                signer_profile_ref,
                request_fingerprint,
                signing_root,
                nonce,
                command_kind: RemoteConsensusCommandKindV1::TimeoutVote,
                epoch,
                view,
                safety_revision,
            },
            target,
        },
        previous,
    };
    // Re-encode performs all structural and namespace-independent checks.
    encode_pending_reservation_v1(pending)?;
    Ok(pending)
}

fn load_pending_reservation_v1(
    path: &Path,
) -> Result<Option<DurablePendingExternalReservationV1>, ExternalAuthorityErrorV1> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ExternalAuthorityErrorV1::InvalidState),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(ExternalAuthorityErrorV1::InvalidState);
    }
    let bytes = fs::read(path).map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
    Ok(Some(decode_pending_reservation_v1(&bytes)?))
}

fn persist_pending_reservation_v1(
    path: &Path,
    pending: DurablePendingExternalReservationV1,
) -> Result<(), ExternalAuthorityErrorV1> {
    let bytes = encode_pending_reservation_v1(pending)?;
    let parent = path
        .parent()
        .ok_or(ExternalAuthorityErrorV1::InvalidState)?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(ExternalAuthorityErrorV1::InvalidState)?;
    let temporary = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    if temporary.exists() {
        let metadata =
            fs::symlink_metadata(&temporary).map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ExternalAuthorityErrorV1::InvalidState);
        }
        fs::remove_file(&temporary).map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
    }
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
        file.write_all(&bytes)
            .map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
        file.sync_all()
            .map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
        fs::rename(&temporary, path).map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
        fs::File::open(parent)
            .map_err(|_| ExternalAuthorityErrorV1::InvalidState)?
            .sync_data()
            .map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
        Ok::<(), ExternalAuthorityErrorV1>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn clear_pending_reservation_v1(path: &Path) -> Result<(), ExternalAuthorityErrorV1> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ExternalAuthorityErrorV1::InvalidState);
            }
            fs::remove_file(path).map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
            if let Some(parent) = path.parent() {
                fs::File::open(parent)
                    .map_err(|_| ExternalAuthorityErrorV1::InvalidState)?
                    .sync_data()
                    .map_err(|_| ExternalAuthorityErrorV1::InvalidState)?;
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ExternalAuthorityErrorV1::InvalidState),
    }
}

/// Minimal Unix adapter for the external CAS and independent response log.
///
/// This adapter intentionally admits timeout votes only. It is useful for a
/// bounded process-boundary test and for proving the ordering of the two
/// independent durable authorities; it is not a Core/SafetyRules signer and
/// carries no production activation. A request is accepted only when the
/// response log count and external watermark head agree. A CAS reservation is
/// first recorded in a private pending-intent sidecar, so a process restart
/// can retry that exact request; any head that does not match the sidecar is
/// still treated as ambiguous and fails closed.
pub struct UnixExternalTimeoutAuthorityV1 {
    watermark: UnixWatermarkClient,
    replay: ReplayBindingStoreV1,
    replay_log_guard: ReplayLogGuardV1,
    pending_path: PathBuf,
    scope: [u8; 32],
    process_generation: u64,
    lease_id: [u8; 32],
    signer_profile_ref: [u8; 32],
    journal_id: [u8; 32],
    capability: [u8; 32],
    semantic_lifecycle_mode: ExternalWatermarkSemanticLifecycleModeV1,
    pending: BTreeMap<[u8; 32], PendingExternalReservationV1>,
    durable_pending: Option<DurablePendingExternalReservationV1>,
    pending_external_reserved: bool,
    poisoned: bool,
}

impl UnixExternalTimeoutAuthorityV1 {
    pub fn scope_for_binding(binding: RemoteSignerRequestBindingV1) -> [u8; 32] {
        watermark_scope_v1(&binding)
    }

    pub fn journal_id_for_binding(binding: RemoteSignerRequestBindingV1) -> [u8; 32] {
        external_adapter_journal_id_v1(
            watermark_scope_v1(&binding),
            binding.process_generation().get(),
            *binding.lease_id().as_bytes(),
            *binding.service_profile_ref().as_bytes(),
        )
    }

    /// Opens an adapter bound to one immutable process-generation/lease
    /// namespace. Changing either value requires a newly provisioned external
    /// watermark namespace; silently attaching to an old head is rejected.
    pub fn open(
        authority_socket: impl AsRef<Path>,
        response_log_path: impl AsRef<Path>,
        scope: [u8; 32],
        process_generation: u64,
        lease_id: [u8; 32],
        signer_profile_ref: [u8; 32],
    ) -> Result<Self, ExternalAuthorityErrorV1> {
        if scope == [0; 32]
            || process_generation == 0
            || lease_id == [0; 32]
            || signer_profile_ref == [0; 32]
        {
            return Err(ExternalAuthorityErrorV1::InvalidState);
        }
        let watermark =
            UnixWatermarkClient::new(authority_socket).map_err(map_external_watermark_error_v1)?;
        let response_log_path = response_log_path.as_ref();
        let replay =
            ReplayBindingStoreV1::open(response_log_path).map_err(map_replay_binding_error_v1)?;
        let replay_log_guard = ReplayLogGuardV1::open(&replay)?;
        let pending_path = pending_reservation_path_v1(response_log_path)?;
        let durable_pending = load_pending_reservation_v1(&pending_path)?;
        let journal_id =
            external_adapter_journal_id_v1(scope, process_generation, lease_id, signer_profile_ref);
        Ok(Self {
            watermark,
            replay,
            replay_log_guard,
            pending_path,
            scope,
            process_generation,
            lease_id,
            signer_profile_ref,
            journal_id,
            capability: [0; 32],
            semantic_lifecycle_mode: ExternalWatermarkSemanticLifecycleModeV1::SignerJournalPair,
            pending: BTreeMap::new(),
            durable_pending,
            pending_external_reserved: false,
            poisoned: false,
        })
    }

    /// Binds this adapter to the immutable capability provisioned by the
    /// semantic watermark daemon. A zero token is never accepted on the wire.
    pub const fn with_capability(mut self, capability: [u8; 32]) -> Self {
        self.capability = capability;
        self
    }

    /// Selects the explicit one-CAS-per-reservation semantic protocol.  The
    /// default remains the strict signer-journal pair mode.
    pub const fn with_semantic_lifecycle_mode(
        mut self,
        mode: ExternalWatermarkSemanticLifecycleModeV1,
    ) -> Self {
        self.semantic_lifecycle_mode = mode;
        self
    }

    /// Constructs the adapter from the exact public binding used by the
    /// protocol request. This does not grant or validate the lease; the
    /// external authority remains responsible for its own process/host
    /// admission.
    pub fn from_binding(
        binding: RemoteSignerRequestBindingV1,
        authority_socket: impl AsRef<Path>,
        response_log_path: impl AsRef<Path>,
    ) -> Result<Self, ExternalAuthorityErrorV1> {
        Self::open(
            authority_socket,
            response_log_path,
            watermark_scope_v1(&binding),
            binding.process_generation().get(),
            *binding.lease_id().as_bytes(),
            *binding.service_profile_ref().as_bytes(),
        )
    }

    pub fn from_binding_per_reservation(
        binding: RemoteSignerRequestBindingV1,
        authority_socket: impl AsRef<Path>,
        response_log_path: impl AsRef<Path>,
    ) -> Result<Self, ExternalAuthorityErrorV1> {
        Self::from_binding(binding, authority_socket, response_log_path).map(|adapter| {
            adapter.with_semantic_lifecycle_mode(
                ExternalWatermarkSemanticLifecycleModeV1::PerReservation,
            )
        })
    }

    pub const fn journal_id(&self) -> [u8; 32] {
        self.journal_id
    }

    pub const fn scope(&self) -> [u8; 32] {
        self.scope
    }

    /// Performs the external-authority startup handshake before a signer
    /// socket is published.
    ///
    /// The adapter must be able to read the exact semantic namespace that it
    /// was provisioned for, and both durable heads must already agree.  This
    /// is intentionally read/reconcile-only: it does not reserve a round and
    /// cannot advance the authority.  A missing, mismatched, or ambiguous
    /// authority is therefore a process-start failure instead of a service
    /// which appears ready and only fails on its first signing request.
    pub fn preflight_v1(&mut self) -> Result<(), ExternalAuthorityErrorV1> {
        self.reconcile_heads_v1().map(|_| ())
    }

    fn semantic_binding_v1(
        &self,
    ) -> Result<ExternalWatermarkSemanticBindingV1, ExternalAuthorityErrorV1> {
        ExternalWatermarkSemanticBindingV1::new(self.scope, self.journal_id, self.capability)
            .map(|binding| binding.with_lifecycle_mode(self.semantic_lifecycle_mode))
            .ok_or(ExternalAuthorityErrorV1::InvalidState)
    }

    fn ensure_replay_integrity_v1(&mut self) -> Result<(), ExternalAuthorityErrorV1> {
        if let Err(error) = self.replay_log_guard.preflight(&self.replay) {
            // A live journal image change is ambiguity, even if the file is
            // later restored.  Keep this adapter poisoned for its lifetime;
            // callers must reopen against a freshly authenticated namespace.
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn validate_request_v1(
        &self,
        request: ExternalAuthorityRequestV1,
    ) -> Result<(), ExternalAuthorityErrorV1> {
        if self.poisoned {
            return Err(ExternalAuthorityErrorV1::Unavailable);
        }
        if request.scope != self.scope
            || request.process_generation != self.process_generation
            || request.lease_id != self.lease_id
            || request.signer_profile_ref != self.signer_profile_ref
            || request.request_fingerprint == [0; 32]
            || request.signing_root == [0; 32]
            || request.nonce == [0; 32]
            || self.capability == [0; 32]
        {
            return Err(ExternalAuthorityErrorV1::InvalidState);
        }
        if request.command_kind != RemoteConsensusCommandKindV1::TimeoutVote {
            return Err(ExternalAuthorityErrorV1::Protocol);
        }
        Ok(())
    }

    /// Reconciles the two independent durable heads. The first CAS value is
    /// sequence zero; every response record increments the replay count, so a
    /// healthy head satisfies `replay_count == external_sequence + 1`.
    ///
    /// A durable pending sidecar permits exactly one additional state: the
    /// external head may be one reservation ahead of the response log. The
    /// request and target are authenticated by the sidecar checksum and must
    /// match the semantic authority head byte-for-byte. Any other gap remains
    /// an ambiguity and fails closed.
    fn reconcile_heads_v1(
        &mut self,
    ) -> Result<Option<SignerWatermarkV0>, ExternalAuthorityErrorV1> {
        self.ensure_replay_integrity_v1()?;
        self.pending_external_reserved = false;
        // `open` deliberately starts with an unbound client because the
        // capability is provisioned by the later `with_capability` step.
        // Every semantic read must nevertheless carry the exact challenge
        // binding; otherwise the daemon waits for EWA1 authentication while
        // this client sends a request frame and the authority looks
        // unavailable.  Bind a short-lived clone for each read so startup,
        // replay, and recovery all use the same fail-closed seam.
        let watermark = self
            .watermark
            .clone()
            .with_semantic_binding(self.semantic_binding_v1()?);
        let semantic_head = watermark
            .load_semantic_checked(self.semantic_binding_v1()?)
            .map_err(map_external_watermark_error_v1)?;
        let records = self.replay.record_count_v1();

        if let Some(durable) = self.durable_pending {
            let request = durable.pending.request;
            self.validate_request_v1(request)?;
            let target = durable.pending.target;
            let target_facts_match = semantic_head.is_some_and(|(value, facts)| {
                value == target
                    && facts.epoch == request.epoch
                    && facts.view == request.view
                    && facts.safety_revision == request.safety_revision
                    && facts.request_nonce == request.nonce
                    && facts.request_fingerprint == request.request_fingerprint
                    && facts.signing_root == request.signing_root
                    && facts.capability == self.capability
            });
            let previous_matches = match (semantic_head, durable.previous) {
                (None, None) => records == 0,
                (Some((value, _)), Some(previous)) => value == previous,
                _ => false,
            };
            let response_complete = target.sequence().checked_add(1) == Some(records)
                && target_facts_match
                && self.replay.latest_binding_v1()
                    == Some((
                        request.request_fingerprint,
                        request.signer_profile_ref,
                        request.signing_root,
                    ));
            if response_complete {
                clear_pending_reservation_v1(&self.pending_path)?;
                self.durable_pending = None;
            } else if records == target.sequence() && target_facts_match {
                self.pending_external_reserved = true;
                return Ok(Some(target));
            } else if records == target.sequence() && previous_matches {
                return Ok(durable.previous);
            } else {
                return Err(ExternalAuthorityErrorV1::InvalidState);
            }
        }
        match semantic_head {
            None if records == 0 => Ok(None),
            None => Err(ExternalAuthorityErrorV1::InvalidState),
            Some((value, facts)) => {
                if value.scope() != self.scope || value.journal_id() != self.journal_id {
                    return Err(ExternalAuthorityErrorV1::InvalidState);
                }
                let expected_records = value
                    .sequence()
                    .checked_add(1)
                    .ok_or(ExternalAuthorityErrorV1::InvalidState)?;
                if records != expected_records {
                    return Err(ExternalAuthorityErrorV1::InvalidState);
                }
                let Some((fingerprint, profile, root)) = self.replay.latest_binding_v1() else {
                    return Err(ExternalAuthorityErrorV1::InvalidState);
                };
                if fingerprint != facts.request_fingerprint
                    || profile != self.signer_profile_ref
                    || root != facts.signing_root
                    || facts.capability != self.capability
                    || facts.capability == [0; 32]
                {
                    return Err(ExternalAuthorityErrorV1::InvalidState);
                }
                Ok(Some(value))
            }
        }
    }

    fn target_for_v1(
        &self,
        previous: Option<SignerWatermarkV0>,
        request: ExternalAuthorityRequestV1,
    ) -> Result<SignerWatermarkV0, ExternalAuthorityErrorV1> {
        let (sequence, previous_checksum) = previous
            .map(|value| {
                value
                    .sequence()
                    .checked_add(1)
                    .map(|next| (next, value.chain_checksum()))
                    .ok_or(ExternalAuthorityErrorV1::InvalidState)
            })
            .unwrap_or(Ok((0, [0; 32])))?;
        let checksum =
            external_adapter_checksum_v1(self.journal_id, previous_checksum, sequence, request);
        SignerWatermarkV0::from_persisted_parts(self.scope, self.journal_id, sequence, checksum)
            .map_err(|_| ExternalAuthorityErrorV1::InvalidState)
    }
}

impl ExternalAuthorityAdapterV1 for UnixExternalTimeoutAuthorityV1 {
    fn replay_response_v1(
        &mut self,
        request: ExternalAuthorityRequestV1,
    ) -> Result<Option<Vec<u8>>, ExternalAuthorityErrorV1> {
        self.validate_request_v1(request)?;
        // Reconcile before lookup as well: a tampered/ambiguous external head
        // must not be bypassed merely because a response entry is present.
        self.reconcile_heads_v1()?;
        let signature = self
            .replay
            .lookup_signature_v1(
                request.request_fingerprint,
                request.signer_profile_ref,
                request.signing_root,
            )
            .map_err(map_replay_binding_error_v1)?;
        // Check again after the projection lookup so a replacement/edit that
        // happens during the external reconciliation window cannot yield a
        // stale in-memory response.
        self.ensure_replay_integrity_v1()?;
        Ok(signature.map(|value| value.as_bytes().to_vec()))
    }

    fn reserve_v1(
        &mut self,
        request: ExternalAuthorityRequestV1,
    ) -> Result<ExternalAuthorityReservationV1, ExternalAuthorityErrorV1> {
        self.validate_request_v1(request)?;
        let previous = self.reconcile_heads_v1()?;
        let durable = self.durable_pending;
        if let Some(durable) = durable {
            if durable.pending.request != request {
                return Err(ExternalAuthorityErrorV1::InvalidState);
            }
            if self.pending_external_reserved {
                let token_digest = external_adapter_token_v1(durable.pending.target, request);
                if self
                    .pending
                    .insert(
                        token_digest,
                        PendingExternalReservationV1 {
                            request,
                            target: durable.pending.target,
                        },
                    )
                    .is_some()
                {
                    self.poisoned = true;
                    return Err(ExternalAuthorityErrorV1::InvalidState);
                }
                return Ok(ExternalAuthorityReservationV1::from_parts(
                    durable.pending.target.sequence(),
                    request.request_fingerprint,
                    token_digest,
                ));
            }
            if previous != durable.previous {
                self.poisoned = true;
                return Err(ExternalAuthorityErrorV1::InvalidState);
            }
        }
        let target = durable
            .map(|pending| pending.pending.target)
            .unwrap_or(self.target_for_v1(previous, request)?);
        let facts = ExternalWatermarkSemanticFactsV1::new(
            request.epoch,
            request.view,
            request.safety_revision,
        )
        .and_then(|facts| {
            facts.with_request(
                request.nonce,
                request.request_fingerprint,
                request.signing_root,
                self.capability,
            )
        })
        .ok_or(ExternalAuthorityErrorV1::InvalidState)?;
        let watermark = self
            .watermark
            .clone()
            .with_semantic_binding(self.semantic_binding_v1()?);
        if durable.is_none() {
            persist_pending_reservation_v1(
                &self.pending_path,
                DurablePendingExternalReservationV1 {
                    pending: PendingExternalReservationV1 { request, target },
                    previous,
                },
            )?;
            self.durable_pending = Some(DurablePendingExternalReservationV1 {
                pending: PendingExternalReservationV1 { request, target },
                previous,
            });
        }
        if let Err(error) = watermark.compare_and_advance_semantic_checked(previous, target, facts)
        {
            // A normal semantic CompareFailed (for example, a caller's
            // lower round) is a policy rejection and must not poison a
            // healthy namespace; higher independent requests remain
            // admissible.  Corruption, scope changes, I/O, or unavailable
            // authorities are ambiguity and permanently fail closed.
            if matches!(error, ExternalWatermarkAuthorityError::CompareFailed) {
                let current = watermark
                    .load_semantic_checked(self.semantic_binding_v1()?)
                    .map_err(|load_error| {
                        self.poisoned = true;
                        map_external_watermark_error_v1(load_error)
                    })?
                    .map(|(value, _)| value);
                if current != previous {
                    self.poisoned = true;
                } else {
                    clear_pending_reservation_v1(&self.pending_path)?;
                    self.durable_pending = None;
                }
            } else {
                self.poisoned = true;
            }
            return Err(map_external_watermark_error_v1(error));
        }
        self.pending_external_reserved = true;
        let token_digest = external_adapter_token_v1(target, request);
        if self
            .pending
            .insert(
                token_digest,
                PendingExternalReservationV1 { request, target },
            )
            .is_some()
        {
            self.poisoned = true;
            return Err(ExternalAuthorityErrorV1::InvalidState);
        }
        Ok(ExternalAuthorityReservationV1::from_parts(
            target.sequence(),
            request.request_fingerprint,
            token_digest,
        ))
    }

    fn bind_response_v1(
        &mut self,
        reservation: ExternalAuthorityReservationV1,
        response: &[u8],
    ) -> Result<(), ExternalAuthorityErrorV1> {
        if self.poisoned {
            return Err(ExternalAuthorityErrorV1::Unavailable);
        }
        self.ensure_replay_integrity_v1()?;
        let pending = self
            .pending
            .get(&reservation.token_digest())
            .copied()
            .ok_or(ExternalAuthorityErrorV1::ReplayConflict)?;
        if pending.target.sequence() != reservation.sequence()
            || pending.request.request_fingerprint != reservation.request_fingerprint()
            || response.len() != 64
        {
            return Err(ExternalAuthorityErrorV1::Protocol);
        }
        let signature = SignatureBytes::from_array(
            response
                .try_into()
                .map_err(|_| ExternalAuthorityErrorV1::Protocol)?,
        );
        if signature.as_bytes() == &[0; 64] {
            return Err(ExternalAuthorityErrorV1::Protocol);
        }
        self.replay
            .record_signature_v1(
                pending.request.request_fingerprint,
                pending.request.signer_profile_ref,
                pending.request.signing_root,
                signature,
            )
            .map_err(map_replay_binding_error_v1)?;
        if let Err(error) = self.replay_log_guard.refresh_after_record(&self.replay) {
            self.poisoned = true;
            return Err(error);
        }
        // The semantic sidecar is the authority record for this adapter.  Do
        // not use the opaque load path here: an opaque response can hide a
        // scope/journal mismatch and, more importantly, cannot prove that the
        // CAS head still describes the exact request whose response we just
        // appended.  A response-log append without a matching semantic head
        // is ambiguous and permanently poisons this process.
        let watermark = self
            .watermark
            .clone()
            .with_semantic_binding(self.semantic_binding_v1()?);
        let Some((current, facts)) = watermark
            .load_semantic_checked(self.semantic_binding_v1()?)
            .map_err(map_external_watermark_error_v1)?
        else {
            self.poisoned = true;
            return Err(ExternalAuthorityErrorV1::InvalidState);
        };
        let request = pending.request;
        let Some((replay_fingerprint, replay_profile, replay_root)) =
            self.replay.latest_binding_v1()
        else {
            self.poisoned = true;
            return Err(ExternalAuthorityErrorV1::InvalidState);
        };
        let expected_records = current
            .sequence()
            .checked_add(1)
            .ok_or(ExternalAuthorityErrorV1::InvalidState)?;
        let valid = current == pending.target
            && current.scope() == self.scope
            && current.journal_id() == self.journal_id
            && self.replay.record_count_v1() == expected_records
            && facts.epoch == request.epoch
            && facts.view == request.view
            && facts.safety_revision == request.safety_revision
            && facts.request_nonce == request.nonce
            && facts.request_fingerprint == request.request_fingerprint
            && facts.signing_root == request.signing_root
            && facts.capability == self.capability
            && facts.capability != [0; 32]
            && replay_fingerprint == request.request_fingerprint
            && replay_profile == request.signer_profile_ref
            && replay_root == request.signing_root;
        if !valid {
            self.poisoned = true;
            return Err(ExternalAuthorityErrorV1::InvalidState);
        }
        let durable = self.durable_pending.ok_or_else(|| {
            self.poisoned = true;
            ExternalAuthorityErrorV1::InvalidState
        })?;
        if durable.pending != pending {
            self.poisoned = true;
            return Err(ExternalAuthorityErrorV1::InvalidState);
        }
        if let Err(error) = clear_pending_reservation_v1(&self.pending_path) {
            self.poisoned = true;
            return Err(error);
        }
        self.durable_pending = None;
        self.pending_external_reserved = false;
        self.pending.remove(&reservation.token_digest());
        Ok(())
    }
}

fn map_external_watermark_error_v1(
    error: ExternalWatermarkAuthorityError,
) -> ExternalAuthorityErrorV1 {
    match error {
        ExternalWatermarkAuthorityError::CompareFailed
        | ExternalWatermarkAuthorityError::ScopeConflict => ExternalAuthorityErrorV1::CompareFailed,
        ExternalWatermarkAuthorityError::InvalidLog(_) => ExternalAuthorityErrorV1::InvalidState,
        ExternalWatermarkAuthorityError::InvalidConfig(_) => ExternalAuthorityErrorV1::InvalidState,
        ExternalWatermarkAuthorityError::Protocol(_) => ExternalAuthorityErrorV1::Protocol,
        ExternalWatermarkAuthorityError::Io { .. }
        | ExternalWatermarkAuthorityError::Unavailable => ExternalAuthorityErrorV1::Unavailable,
    }
}

fn map_replay_binding_error_v1(error: ReplayBindingErrorV1) -> ExternalAuthorityErrorV1 {
    match error {
        ReplayBindingErrorV1::InvalidLog(_) | ReplayBindingErrorV1::InvalidConfig(_) => {
            ExternalAuthorityErrorV1::InvalidState
        }
        ReplayBindingErrorV1::Io { .. } | ReplayBindingErrorV1::Poisoned => {
            ExternalAuthorityErrorV1::Unavailable
        }
        ReplayBindingErrorV1::Conflict(_) => ExternalAuthorityErrorV1::ReplayConflict,
    }
}

fn external_adapter_journal_id_v1(
    scope: [u8; 32],
    process_generation: u64,
    lease_id: [u8; 32],
    signer_profile_ref: [u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(EXTERNAL_ADAPTER_JOURNAL_DOMAIN_V1);
    hash.update(scope);
    hash.update(process_generation.to_be_bytes());
    hash.update(lease_id);
    hash.update(signer_profile_ref);
    hash.finalize().into()
}

fn external_adapter_checksum_v1(
    journal_id: [u8; 32],
    previous_checksum: [u8; 32],
    sequence: u64,
    request: ExternalAuthorityRequestV1,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(EXTERNAL_ADAPTER_CHECKSUM_DOMAIN_V1);
    hash.update(journal_id);
    hash.update(previous_checksum);
    hash.update(sequence.to_be_bytes());
    hash.update(request.scope);
    hash.update(request.process_generation.to_be_bytes());
    hash.update(request.lease_id);
    hash.update(request.signer_profile_ref);
    hash.update(request.request_fingerprint);
    hash.update(request.signing_root);
    hash.update(request.nonce);
    hash.update([request.command_kind as u8]);
    hash.update(request.epoch.to_be_bytes());
    hash.update(request.view.to_be_bytes());
    hash.update(request.safety_revision.to_be_bytes());
    hash.finalize().into()
}

fn external_adapter_token_v1(
    target: SignerWatermarkV0,
    request: ExternalAuthorityRequestV1,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(EXTERNAL_ADAPTER_TOKEN_DOMAIN_V1);
    hash.update(target.scope());
    hash.update(target.journal_id());
    hash.update(target.sequence().to_be_bytes());
    hash.update(target.chain_checksum());
    hash.update(request.request_fingerprint);
    hash.update(request.signing_root);
    hash.finalize().into()
}

/// Durable state exposed for diagnostics and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatermarkSnapshotV1 {
    pub sequence: u64,
    pub epoch: Option<u64>,
    pub view: Option<u64>,
    pub safety_revision: u64,
}

/// Stable rejection classes returned by the framed transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ServiceRejectCodeV1 {
    InvalidFrame = 1,
    InvalidProtocol = 2,
    WrongPurpose = 3,
    DuplicateNonce = 4,
    DuplicateRequest = 5,
    DuplicateRoundPurpose = 6,
    Rollback = 7,
    WatermarkExhausted = 8,
    SignatureFailure = 9,
    DurableStoreFailure = 10,
    ReservationFailure = 11,
}

impl ServiceRejectCodeV1 {
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

#[derive(Debug)]
enum ServiceFailure {
    InvalidConfig(&'static str),
    Io(&'static str, io::Error),
    Sqlite(&'static str, rusqlite::Error),
    Protocol(RemoteSignerProtocolErrorV1),
    WrongPurpose(RemoteConsensusCommandKindV1),
    ProposalPurposeDisabled,
    DuplicateNonce,
    DuplicateRequest,
    DuplicateRoundPurpose,
    Rollback {
        maximum_epoch: u64,
        maximum_view: u64,
    },
    WatermarkExhausted,
    SignatureFailure,
    ReservationFailure,
    ExternalAuthorityRequired,
    SafetyRevisionRollback {
        maximum: u64,
        incoming: u64,
    },
    InvalidFrame,
}

impl fmt::Display for ServiceFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(f, "invalid signer service config: {reason}"),
            Self::Io(stage, source) => write!(f, "signer service I/O at {stage}: {source}"),
            Self::Sqlite(stage, source) => write!(f, "signer service SQLite at {stage}: {source}"),
            Self::Protocol(source) => write!(f, "signer protocol rejected request: {source}"),
            Self::WrongPurpose(kind) => write!(f, "signer purpose is not enabled: {kind:?}"),
            Self::ProposalPurposeDisabled => {
                f.write_str("signer proposal purpose is not enabled")
            }
            Self::DuplicateNonce => f.write_str("signer request nonce was already used"),
            Self::DuplicateRequest => f.write_str("signer request fingerprint was already used"),
            Self::DuplicateRoundPurpose => {
                f.write_str("signer epoch/view/purpose was already reserved")
            }
            Self::Rollback {
                maximum_epoch,
                maximum_view,
            } => write!(
                f,
                "signer request rolls back watermark (maximum epoch {maximum_epoch}, view {maximum_view})"
            ),
            Self::WatermarkExhausted => f.write_str("signer watermark sequence is exhausted"),
            Self::SignatureFailure => f.write_str("signer key produced an invalid signature"),
            Self::ReservationFailure => f.write_str("signer reservation is not in pending state"),
            Self::ExternalAuthorityRequired => {
                f.write_str("external authority is required for this command")
            }
            Self::SafetyRevisionRollback { maximum, incoming } => write!(
                f,
                "signer Safety revision regresses watermark (maximum {maximum}, incoming {incoming})"
            ),
            Self::InvalidFrame => f.write_str("invalid signer transport frame"),
        }
    }
}

impl Error for ServiceFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(_, source) => Some(source),
            Self::Sqlite(_, source) => Some(source),
            _ => None,
        }
    }
}

/// Public error returned when opening or driving the service in-process.
#[derive(Debug)]
pub struct RemoteSignerServiceError(ServiceFailure);

impl fmt::Display for RemoteSignerServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl RemoteSignerServiceError {
    /// Returns true when the external authority path rejected the request.
    /// Callers must not fall back to [`RemoteSignerService::process_request`]
    /// when this is true; that path is local fixture state by design.
    pub fn is_external_authority_required(&self) -> bool {
        matches!(self.0, ServiceFailure::ExternalAuthorityRequired)
    }
}

impl Error for RemoteSignerServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

impl From<ServiceFailure> for RemoteSignerServiceError {
    fn from(value: ServiceFailure) -> Self {
        Self(value)
    }
}

/// One independent signer process and its durable admission store.
pub struct RemoteSignerService {
    validator_set: ValidatorSet,
    binding: RemoteSignerRequestBindingV1,
    signing_key: Option<SigningKey>,
    purpose_policy: PurposePolicyV1,
    scope: [u8; 32],
    watermark_path: PathBuf,
    watermark_identity: FileIdentityV1,
    watermark_directory_identity: FileIdentityV1,
    connection: Connection,
    /// When present, Unix transport is permanently in external-authority
    /// mode. The local SQLite request path is rejected rather than used as a
    /// fallback, even if a caller holds the service object in-process.
    external_authority: Option<Box<dyn ExternalAuthorityAdapterV1>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentityV1 {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReservationDispositionV1 {
    New,
    Pending,
}

#[derive(Debug, Clone, Copy)]
struct ReservationInputV1 {
    nonce: [u8; 32],
    fingerprint: [u8; 32],
    epoch: u64,
    view: u64,
    safety_revision: u64,
    kind: RemoteConsensusCommandKindV1,
    signing_root: [u8; 32],
}

type ExistingReservationRowV1 = (Vec<u8>, i64, i64, i64, i64, Vec<u8>);
type PersistedWatermarkRowV1 = (Vec<u8>, i64, i64, i64, i64, i64, Vec<u8>, Vec<u8>);
type ExistingProposalReservationRowV1 = (Vec<u8>, i64, i64, i64, Vec<u8>);

impl RemoteSignerService {
    /// Opens or creates the independent watermark namespace.
    pub fn open(config: RemoteSignerServiceConfig) -> Result<Self, RemoteSignerServiceError> {
        config
            .validator_set
            .validate_shape()
            .map_err(|_| ServiceFailure::InvalidConfig("validator set shape"))?;
        let validator = config
            .validator_set
            .validator(config.binding.author())
            .ok_or(ServiceFailure::InvalidConfig("binding author is absent"))?;
        if validator.consensus_key().as_bytes() != config.signing_key.verifying_key().as_bytes() {
            return Err(ServiceFailure::InvalidConfig(
                "signing key does not match configured validator consensus key",
            )
            .into());
        }
        if config.binding.genesis_hash() != config.validator_set.genesis_hash()
            || config.binding.chain_id() != config.validator_set.chain_id()
            || config.binding.protocol_version() != config.validator_set.protocol_version()
            || config.binding.epoch() != config.validator_set.epoch()
            || config.binding.validator_set_id() != config.validator_set.id()
        {
            return Err(ServiceFailure::InvalidConfig(
                "binding context differs from validator set",
            )
            .into());
        }
        let expected_profile = if config.purpose_policy.allow_proposal {
            // Proposal signing is an explicitly separate fixture purpose. Do
            // not let a policy bit reinterpret an old Vote/Timeout binding.
            if config.purpose_policy.allow_vote || config.purpose_policy.allow_timeout_vote {
                return Err(ServiceFailure::InvalidConfig(
                    "proposal purpose cannot be combined with vote/timeout purpose",
                )
                .into());
            }
            trnm_consensus_remote_signer_protocol::proposal_purpose_profile_digest_v1()
        } else {
            trnm_consensus_remote_signer_protocol::vote_timeout_purpose_profile_digest_v1()
        };
        if config.binding.purpose_profile_digest() != expected_profile {
            return Err(ServiceFailure::InvalidConfig("unsupported purpose profile").into());
        }
        let scope = watermark_scope_v1(&config.binding);
        let (watermark_path, directory_identity, existed) =
            canonical_watermark_path(&config.watermark_path)?;
        let connection = Connection::open_with_flags(
            &watermark_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| ServiceFailure::Sqlite("open watermark", error))?;
        if existed {
            validate_private_watermark_file(&watermark_path)?;
        } else {
            fs::set_permissions(&watermark_path, fs::Permissions::from_mode(0o600))
                .map_err(|error| ServiceFailure::Io("protect watermark", error))?;
        }
        let watermark_identity = file_identity_v1(&watermark_path)?;
        connection
            .busy_timeout(Duration::from_secs(2))
            .map_err(|error| ServiceFailure::Sqlite("set busy timeout", error))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA foreign_keys = ON;
                 PRAGMA wal_autocheckpoint = 1;
                 CREATE TABLE IF NOT EXISTS signer_metadata (
                     key TEXT PRIMARY KEY NOT NULL,
                     value BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS signer_watermark (
                     scope BLOB PRIMARY KEY NOT NULL,
                     sequence INTEGER NOT NULL,
                     has_round INTEGER NOT NULL,
                     maximum_epoch INTEGER NOT NULL,
                     maximum_view INTEGER NOT NULL,
                     maximum_safety_revision INTEGER NOT NULL,
                     last_nonce BLOB NOT NULL,
                     last_fingerprint BLOB NOT NULL,
                     CHECK (sequence >= 0),
                     CHECK (has_round IN (0, 1)),
                     CHECK (maximum_epoch >= 0),
                     CHECK (maximum_view >= 0),
                     CHECK (maximum_safety_revision >= 0),
                     CHECK (length(last_nonce) = 32),
                     CHECK (length(last_fingerprint) = 32)
                 );
                 CREATE TABLE IF NOT EXISTS signer_reservation (
                     scope BLOB NOT NULL,
                     nonce BLOB NOT NULL,
                     request_fingerprint BLOB NOT NULL,
                     epoch INTEGER NOT NULL,
                     view INTEGER NOT NULL,
                     safety_revision INTEGER NOT NULL,
                     purpose INTEGER NOT NULL,
                     state INTEGER NOT NULL,
                     signing_root BLOB NOT NULL,
                     PRIMARY KEY (scope, nonce),
                     UNIQUE (scope, request_fingerprint),
                     UNIQUE (scope, epoch, view, purpose),
                     CHECK (length(nonce) = 32),
                     CHECK (length(request_fingerprint) = 32),
                     CHECK (epoch >= 0),
                     CHECK (view >= 0),
                     CHECK (safety_revision > 0),
                     CHECK (purpose IN (0, 1)),
                     CHECK (state IN (0, 1)),
                     CHECK (length(signing_root) = 32),
                     FOREIGN KEY (scope) REFERENCES signer_watermark(scope)
                 );
                 CREATE TABLE IF NOT EXISTS proposal_reservation (
                     scope BLOB NOT NULL,
                     nonce BLOB NOT NULL,
                     request_fingerprint BLOB NOT NULL,
                     proposal_id BLOB NOT NULL,
                     parent_id BLOB NOT NULL,
                     validator_set_id BLOB NOT NULL,
                     epoch INTEGER NOT NULL,
                     view INTEGER NOT NULL,
                     height INTEGER NOT NULL,
                     state INTEGER NOT NULL,
                     signing_root BLOB NOT NULL,
                     signer_profile_ref BLOB NOT NULL,
                     PRIMARY KEY (scope, nonce),
                     UNIQUE (scope, request_fingerprint),
                     UNIQUE (scope, proposal_id),
                     CHECK (length(nonce) = 32),
                     CHECK (length(request_fingerprint) = 32),
                     CHECK (length(proposal_id) = 32),
                     CHECK (length(parent_id) = 32),
                     CHECK (length(validator_set_id) = 32),
                     CHECK (epoch >= 0),
                     CHECK (view > 0),
                     CHECK (height > 0),
                     CHECK (state IN (0, 1)),
                     CHECK (length(signing_root) = 32),
                     CHECK (length(signer_profile_ref) = 32),
                     FOREIGN KEY (scope) REFERENCES signer_watermark(scope)
                 );",
            )
            .map_err(|error| ServiceFailure::Sqlite("initialize watermark schema", error))?;
        validate_schema_v1(&connection)?;
        // A watermark file is one immutable signer namespace.  Before any
        // migration/INSERT, reject a non-empty database whose existing scope
        // differs from this process binding.  Without this preflight a
        // changed generation/lease could add a second scope row and appear
        // to start cleanly until a later invariant check.
        validate_namespace_scope_v1(&connection, scope)?;
        ensure_metadata_v1(
            &connection,
            scope,
            &config.binding,
            &config.signing_key,
            config.purpose_policy,
        )
        .map_err(RemoteSignerServiceError)?;
        connection
            .execute(
                "INSERT OR IGNORE INTO signer_watermark
                 (scope, sequence, has_round, maximum_epoch, maximum_view,
                  maximum_safety_revision, last_nonce, last_fingerprint)
                 VALUES (?1, 0, 0, 0, 0, 0, zeroblob(32), zeroblob(32))",
                params![scope.as_slice()],
            )
            .map_err(|error| ServiceFailure::Sqlite("initialize watermark row", error))?;
        connection
            .execute_batch("PRAGMA user_version = 2;")
            .map_err(|error| ServiceFailure::Sqlite("set watermark schema version", error))?;
        validate_persisted_state_v1(&connection, scope)?;
        Ok(Self {
            validator_set: config.validator_set,
            binding: config.binding,
            signing_key: Some(config.signing_key),
            purpose_policy: config.purpose_policy,
            scope,
            watermark_path,
            watermark_identity,
            watermark_directory_identity: directory_identity,
            connection,
            external_authority: None,
        })
    }

    /// Opens the timeout-only Unix service in explicit external-authority
    /// mode. The service still owns its local namespace for identity and
    /// startup checks, but every request is routed through the independent
    /// external CAS/response adapter; the local SQLite reservation path is
    /// permanently unavailable for this instance.
    pub fn open_with_external_timeout_authority(
        config: RemoteSignerServiceConfig,
        authority_socket: impl AsRef<Path>,
        response_log_path: impl AsRef<Path>,
        capability: [u8; 32],
    ) -> Result<Self, RemoteSignerServiceError> {
        if config.purpose_policy != PurposePolicyV1::timeout_vote_only() {
            return Err(ServiceFailure::InvalidConfig(
                "external timeout service requires timeout-only purpose policy",
            )
            .into());
        }
        let binding = config.binding;
        if capability == [0; 32] {
            return Err(ServiceFailure::InvalidConfig("external authority capability").into());
        }
        // Establish the independent authority binding before opening the
        // local signer namespace or publishing a Unix socket.  A process
        // which cannot prove the exact semantic `(scope, journal, capability)`
        // namespace must fail during startup; otherwise a supervisor could
        // mistake a socket-ready fixture for an admitted signer and only
        // discover the mismatch after the first consensus request.
        let mut adapter = UnixExternalTimeoutAuthorityV1::from_binding_per_reservation(
            binding,
            authority_socket,
            response_log_path,
        )
        .map_err(external_authority_failure_v1)?
        .with_capability(capability);
        adapter
            .preflight_v1()
            .map_err(external_authority_failure_v1)?;
        let mut service = Self::open(config)?;
        // This process is the dedicated remote-signer boundary: the node and
        // consensus runtime never receive this key.  The external authority
        // fences every request before this process reaches the key, while the
        // validator-set public key is used for response verification.  Do not
        // confuse this isolated signer process with a node carrying a raw
        // consensus key.
        service.external_authority = Some(Box::new(adapter));
        Ok(service)
    }

    pub const fn binding(&self) -> RemoteSignerRequestBindingV1 {
        self.binding
    }

    pub const fn scope(&self) -> [u8; 32] {
        self.scope
    }

    /// Decodes an exact request into the facts an external authority must
    /// fence.  No local reservation, key access, or response side effect is
    /// performed by this method.
    pub fn external_authority_request_v1(
        &self,
        encoded_request: &[u8],
    ) -> Result<ExternalAuthorityRequestV1, RemoteSignerServiceError> {
        let request = decode_remote_signer_request_v1_exact(
            encoded_request,
            &self.validator_set,
            self.binding,
        )
        .map_err(ServiceFailure::Protocol)?;
        let intent = request.command().intent();
        let (epoch, view) = intent_round_v1(intent);
        Ok(ExternalAuthorityRequestV1 {
            scope: self.scope,
            process_generation: self.binding.process_generation().get(),
            lease_id: *self.binding.lease_id().as_bytes(),
            signer_profile_ref: *self.binding.service_profile_ref().as_bytes(),
            request_fingerprint: *request.fingerprint().as_bytes(),
            signing_root: *intent.signing_root().as_bytes(),
            nonce: *request.nonce().as_bytes(),
            command_kind: request.command().kind(),
            epoch,
            view,
            safety_revision: intent.authorizing_safety_revision(),
        })
    }

    /// Bounded external-authority entry point for timeout votes. The external
    /// CAS and semantic sidecar reserve the exact request before the fixture
    /// key is reached; the independent response log is bound before bytes are
    /// returned. Vote/Core/SafetyRules authority remains deliberately absent.
    pub fn process_request_with_external_authority_v1(
        &mut self,
        encoded_request: &[u8],
        authority: &mut dyn ExternalAuthorityAdapterV1,
    ) -> Result<Vec<u8>, RemoteSignerServiceError> {
        self.ensure_file_identity_v1()?;
        let request = decode_remote_signer_request_v1_exact(
            encoded_request,
            &self.validator_set,
            self.binding,
        )
        .map_err(ServiceFailure::Protocol)?;
        let kind = request.command().kind();
        if !self.purpose_policy.allows(kind) {
            return Err(ServiceFailure::WrongPurpose(kind).into());
        }
        // Core/SafetyRules are not wired into this service. Keep the only
        // executable external bridge timeout-only until an unforgeable safe
        // vote authorization is present.
        if kind != RemoteConsensusCommandKindV1::TimeoutVote {
            return Err(ServiceFailure::ExternalAuthorityRequired.into());
        }
        let facts = self.external_authority_request_v1(encoded_request)?;
        if let Some(response_bytes) = authority
            .replay_response_v1(facts)
            .map_err(external_authority_failure_v1)?
        {
            let signature = signature_from_external_response_v1(&response_bytes)?;
            self.verify_external_signature_v1(&request, signature)?;
            return UnverifiedRemoteSignerResponseV1::from_unverified_signature_bytes(
                &request,
                SignatureBytes::from_array(signature),
            )
            .and_then(|response| response.try_exact_bytes())
            .map_err(|error| ServiceFailure::Protocol(error).into());
        }
        let reservation = authority
            .reserve_v1(facts)
            .map_err(external_authority_failure_v1)?;
        if reservation.request_fingerprint() != facts.request_fingerprint {
            return Err(ServiceFailure::ReservationFailure.into());
        }
        let signature = self.sign_and_verify_v1(&facts.signing_root)?;
        // The adapter durably binds before this method returns. Any error is
        // deliberately surfaced; callers must not retry through local mode.
        authority
            .bind_response_v1(reservation, &signature)
            .map_err(external_authority_failure_v1)?;
        UnverifiedRemoteSignerResponseV1::from_unverified_signature_bytes(
            &request,
            SignatureBytes::from_array(signature),
        )
        .and_then(|response| response.try_exact_bytes())
        .map_err(|error| ServiceFailure::Protocol(error).into())
    }

    /// Processes one explicitly provisioned proposal-purpose request. Proposal
    /// reservations use a separate table so enabling this purpose cannot
    /// reinterpret or migrate existing Vote/Timeout rows. The default policy
    /// keeps this path closed.
    pub fn process_proposal_request(
        &mut self,
        encoded_request: &[u8],
    ) -> Result<Vec<u8>, RemoteSignerServiceError> {
        if self.external_authority.is_some() {
            return Err(ServiceFailure::ExternalAuthorityRequired.into());
        }
        if !self.purpose_policy.allow_proposal {
            return Err(ServiceFailure::ProposalPurposeDisabled.into());
        }
        self.ensure_file_identity_v1()?;
        let request = decode_remote_proposal_signer_request_v1_exact(
            encoded_request,
            &self.validator_set,
            self.binding,
        )
        .map_err(ServiceFailure::Protocol)?;
        let revision = request.height().get();
        let nonce = *request.nonce().as_bytes();
        let fingerprint = *request.fingerprint().as_bytes();
        self.reserve_proposal_v1(&request, revision)?;
        let signature = self.sign_and_verify_v1(request.signing_root().as_bytes())?;
        self.complete_proposal_v1(nonce, fingerprint)?;
        UnverifiedRemoteProposalSignerResponseV1::from_unverified_signature_bytes(
            &request,
            SignatureBytes::from_array(signature),
        )
        .and_then(|response| response.try_exact_bytes())
        .map_err(|error| ServiceFailure::Protocol(error).into())
    }

    /// Processes one exact protocol request and returns an exact protocol
    /// response.  This method is the smallest in-process adapter used by the
    /// Unix transport and intentionally does not call Core or SafetyRules.
    pub fn process_request(
        &mut self,
        encoded_request: &[u8],
    ) -> Result<Vec<u8>, RemoteSignerServiceError> {
        if self.external_authority.is_some() {
            return Err(ServiceFailure::ExternalAuthorityRequired.into());
        }
        self.ensure_file_identity_v1()?;
        let request = decode_remote_signer_request_v1_exact(
            encoded_request,
            &self.validator_set,
            self.binding,
        )
        .map_err(ServiceFailure::Protocol)?;
        let kind = request.command().kind();
        if !self.purpose_policy.allows(kind) {
            return Err(ServiceFailure::WrongPurpose(kind).into());
        }
        let intent = request.command().intent();
        let (epoch, view) = intent_round_v1(intent);
        let safety_revision = intent.authorizing_safety_revision();
        let signing_root = *intent.signing_root().as_bytes();
        let nonce = *request.nonce().as_bytes();
        let fingerprint = *request.fingerprint().as_bytes();
        let _reservation = self.reserve_v1(ReservationInputV1 {
            nonce,
            fingerprint,
            epoch,
            view,
            safety_revision,
            kind,
            signing_root,
        })?;

        let signature = self.sign_and_verify_v1(&signing_root)?;
        self.complete_reservation_v1(nonce, fingerprint)?;
        UnverifiedRemoteSignerResponseV1::from_unverified_signature_bytes(
            &request,
            SignatureBytes::from_array(signature),
        )
        .and_then(|response| response.try_exact_bytes())
        .map_err(|error| ServiceFailure::Protocol(error).into())
    }

    /// Reads the current durable sequence and maximum observed round.
    pub fn watermark_snapshot(&self) -> Result<WatermarkSnapshotV1, RemoteSignerServiceError> {
        self.ensure_file_identity_v1()?;
        let row = self
            .connection
            .query_row(
                "SELECT sequence, has_round, maximum_epoch, maximum_view,
                        maximum_safety_revision
                 FROM signer_watermark WHERE scope = ?1",
                params![self.scope.as_slice()],
                |row| {
                    let sequence = decode_i64_u64(row.get::<_, i64>(0)?, "sequence")?;
                    let has_round = row.get::<_, i64>(1)? != 0;
                    let epoch = decode_i64_u64(row.get::<_, i64>(2)?, "maximum epoch")?;
                    let view = decode_i64_u64(row.get::<_, i64>(3)?, "maximum view")?;
                    let safety_revision =
                        decode_i64_u64(row.get::<_, i64>(4)?, "maximum Safety revision")?;
                    Ok((sequence, has_round, epoch, view, safety_revision))
                },
            )
            .map_err(|error| ServiceFailure::Sqlite("read watermark", error))?;
        Ok(WatermarkSnapshotV1 {
            sequence: row.0,
            epoch: row.1.then_some(row.2),
            view: row.1.then_some(row.3),
            safety_revision: row.4,
        })
    }

    /// Serves one request per accepted Unix connection until the process is
    /// terminated.  A stale socket path is removed only when it is itself a
    /// socket; arbitrary files are never overwritten.
    pub fn serve_unix(&mut self, socket_path: &Path) -> Result<(), RemoteSignerServiceError> {
        let listener = self.bind_unix(socket_path)?;
        for incoming in listener.incoming() {
            match incoming {
                Ok(mut stream) => self.handle_stream(&mut stream)?,
                Err(error) => {
                    return Err(ServiceFailure::Io("accept Unix connection", error).into())
                }
            }
        }
        Ok(())
    }

    /// Binds a socket, handles exactly one connection, and then removes the
    /// socket.  This is used by deterministic in-process tests; the daemon
    /// uses [`Self::serve_unix`] instead.
    pub fn serve_unix_once(&mut self, socket_path: &Path) -> Result<(), RemoteSignerServiceError> {
        let listener = self.bind_unix(socket_path)?;
        let (mut stream, _) = listener
            .accept()
            .map_err(|error| ServiceFailure::Io("accept Unix connection", error))?;
        self.handle_stream(&mut stream)?;
        drop(listener);
        let _ = fs::remove_file(socket_path);
        Ok(())
    }

    fn bind_unix(&self, socket_path: &Path) -> Result<UnixListener, RemoteSignerServiceError> {
        if socket_path.exists() {
            let metadata = fs::symlink_metadata(socket_path)
                .map_err(|error| ServiceFailure::Io("inspect socket path", error))?;
            if !metadata.file_type().is_socket() {
                return Err(
                    ServiceFailure::InvalidConfig("socket path is not a Unix socket").into(),
                );
            }
            fs::remove_file(socket_path)
                .map_err(|error| ServiceFailure::Io("remove stale socket", error))?;
        }
        let listener = UnixListener::bind(socket_path)
            .map_err(|error| ServiceFailure::Io("bind Unix socket", error))?;
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))
            .map_err(|error| ServiceFailure::Io("protect Unix socket", error))?;
        Ok(listener)
    }

    fn handle_stream(&mut self, stream: &mut UnixStream) -> Result<(), RemoteSignerServiceError> {
        let request = match read_frame_v1(stream) {
            Ok(Some(request)) => request,
            Ok(None) => return Ok(()),
            Err(ServiceFailure::InvalidFrame) => {
                write_reject_frame_v1(stream, ServiceRejectCodeV1::InvalidFrame)?;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let result = if is_remote_proposal_request_v1(&request) {
            self.process_proposal_request(&request)
        } else if self.external_authority.is_some() {
            // Temporarily move the adapter out to satisfy Rust's aliasing
            // rules while the service validates and reconstructs the exact
            // response. It is restored even when the request fails closed.
            let mut authority = self
                .external_authority
                .take()
                .ok_or(ServiceFailure::ExternalAuthorityRequired)?;
            let result = self.process_request_with_external_authority_v1(&request, &mut *authority);
            self.external_authority = Some(authority);
            result
        } else {
            self.process_request(&request)
        };
        match result {
            Ok(response) => write_ok_frame_v1(stream, &response)?,
            Err(error) => write_reject_frame_v1(stream, classify_reject_v1(&error.0))?,
        }
        Ok(())
    }

    fn reserve_v1(
        &mut self,
        input: ReservationInputV1,
    ) -> Result<ReservationDispositionV1, RemoteSignerServiceError> {
        let ReservationInputV1 {
            nonce,
            fingerprint,
            epoch,
            view,
            safety_revision,
            kind,
            signing_root,
        } = input;
        let epoch_sql = to_sql_i64(epoch, "epoch")?;
        let view_sql = to_sql_i64(view, "view")?;
        let safety_revision_sql = to_sql_i64(safety_revision, "safety revision")?;
        let purpose = purpose_tag_v1(kind);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ServiceFailure::Sqlite("begin watermark CAS", error))?;
        let existing_nonce: Option<ExistingReservationRowV1> = tx
            .query_row(
                "SELECT request_fingerprint, epoch, view, safety_revision, state, signing_root
                 FROM signer_reservation
                 WHERE scope = ?1 AND nonce = ?2",
                params![self.scope.as_slice(), nonce.as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| ServiceFailure::Sqlite("check nonce replay", error))?;
        if let Some((
            existing_fingerprint,
            existing_epoch,
            existing_view,
            existing_revision,
            state,
            existing_root,
        )) = existing_nonce
        {
            let exact_pending = existing_fingerprint.as_slice() == fingerprint
                && existing_epoch == epoch_sql
                && existing_view == view_sql
                && existing_revision == safety_revision_sql
                && existing_root.as_slice() == signing_root
                && state == 0;
            if exact_pending {
                return Ok(ReservationDispositionV1::Pending);
            }
            if existing_fingerprint.as_slice() == fingerprint {
                return Err(ServiceFailure::DuplicateRequest.into());
            }
            return Err(ServiceFailure::DuplicateNonce.into());
        }
        let existing_fingerprint: Option<Vec<u8>> = tx
            .query_row(
                "SELECT nonce FROM signer_reservation
                 WHERE scope = ?1 AND request_fingerprint = ?2",
                params![self.scope.as_slice(), fingerprint.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| ServiceFailure::Sqlite("check request replay", error))?;
        if existing_fingerprint.is_some() {
            return Err(ServiceFailure::DuplicateRequest.into());
        }
        let state = tx
            .query_row(
                "SELECT sequence, has_round, maximum_epoch, maximum_view,
                        maximum_safety_revision
                 FROM signer_watermark WHERE scope = ?1",
                params![self.scope.as_slice()],
                |row| {
                    Ok((
                        decode_i64_u64(row.get::<_, i64>(0)?, "sequence")?,
                        row.get::<_, i64>(1)? != 0,
                        decode_i64_u64(row.get::<_, i64>(2)?, "maximum epoch")?,
                        decode_i64_u64(row.get::<_, i64>(3)?, "maximum view")?,
                        decode_i64_u64(row.get::<_, i64>(4)?, "maximum Safety revision")?,
                    ))
                },
            )
            .map_err(|error| ServiceFailure::Sqlite("read watermark CAS source", error))?;
        if state.1 && (epoch < state.2 || (epoch == state.2 && view < state.3)) {
            return Err(ServiceFailure::Rollback {
                maximum_epoch: state.2,
                maximum_view: state.3,
            }
            .into());
        }
        // SafetyState revisions are a strictly increasing admission fence for
        // new intents.  Exact pending retries were handled above, so an equal
        // revision here is also a regression rather than a second admission.
        if safety_revision <= state.4 {
            return Err(ServiceFailure::SafetyRevisionRollback {
                maximum: state.4,
                incoming: safety_revision,
            }
            .into());
        }
        let existing_round: Option<i64> = tx
            .query_row(
                "SELECT state FROM signer_reservation
                 WHERE scope = ?1 AND epoch = ?2 AND view = ?3 AND purpose = ?4",
                params![self.scope.as_slice(), epoch_sql, view_sql, purpose],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| ServiceFailure::Sqlite("check purpose replay", error))?;
        if existing_round.is_some() {
            return Err(ServiceFailure::DuplicateRoundPurpose.into());
        }
        let next_sequence = state
            .0
            .checked_add(1)
            .ok_or(ServiceFailure::WatermarkExhausted)?;
        let next_sequence_sql = to_sql_i64(next_sequence, "sequence")?;
        let maximum_safety_revision_sql =
            to_sql_i64(std::cmp::max(state.4, safety_revision), "safety revision")?;
        let (next_has_round, next_epoch, next_view) =
            if !state.1 || epoch > state.2 || (epoch == state.2 && view > state.3) {
                (1_i64, epoch_sql, view_sql)
            } else {
                (
                    1_i64,
                    to_sql_i64(state.2, "maximum epoch")?,
                    to_sql_i64(state.3, "maximum view")?,
                )
            };
        let updated = tx
            .execute(
                "UPDATE signer_watermark
                 SET sequence = ?2, has_round = ?3, maximum_epoch = ?4,
                     maximum_view = ?5, maximum_safety_revision = ?6,
                     last_nonce = ?7, last_fingerprint = ?8
                 WHERE scope = ?1 AND sequence = ?9",
                params![
                    self.scope.as_slice(),
                    next_sequence_sql,
                    next_has_round,
                    next_epoch,
                    next_view,
                    maximum_safety_revision_sql,
                    nonce.as_slice(),
                    fingerprint.as_slice(),
                    to_sql_i64(state.0, "sequence")?,
                ],
            )
            .map_err(|error| ServiceFailure::Sqlite("advance watermark CAS", error))?;
        if updated != 1 {
            return Err(ServiceFailure::Sqlite(
                "advance watermark CAS",
                rusqlite::Error::QueryReturnedNoRows,
            )
            .into());
        }
        tx.execute(
            "INSERT INTO signer_reservation
             (scope, nonce, request_fingerprint, epoch, view, safety_revision,
              purpose, state, signing_root)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)",
            params![
                self.scope.as_slice(),
                nonce.as_slice(),
                fingerprint.as_slice(),
                epoch_sql,
                view_sql,
                safety_revision_sql,
                purpose,
                signing_root.as_slice(),
            ],
        )
        .map_err(|error| ServiceFailure::Sqlite("persist signer reservation", error))?;
        tx.commit()
            .map_err(|error| ServiceFailure::Sqlite("commit watermark CAS", error))?;
        Ok(ReservationDispositionV1::New)
    }

    fn complete_reservation_v1(
        &mut self,
        nonce: [u8; 32],
        fingerprint: [u8; 32],
    ) -> Result<(), RemoteSignerServiceError> {
        self.ensure_file_identity_v1()?;
        let changed = self
            .connection
            .execute(
                "UPDATE signer_reservation SET state = 1
                 WHERE scope = ?1 AND nonce = ?2 AND request_fingerprint = ?3 AND state = 0",
                params![
                    self.scope.as_slice(),
                    nonce.as_slice(),
                    fingerprint.as_slice()
                ],
            )
            .map_err(|error| ServiceFailure::Sqlite("complete signer reservation", error))?;
        if changed != 1 {
            return Err(ServiceFailure::ReservationFailure.into());
        }
        let state: i64 = self
            .connection
            .query_row(
                "SELECT state FROM signer_reservation
                 WHERE scope = ?1 AND nonce = ?2 AND request_fingerprint = ?3",
                params![
                    self.scope.as_slice(),
                    nonce.as_slice(),
                    fingerprint.as_slice()
                ],
                |row| row.get(0),
            )
            .map_err(|error| ServiceFailure::Sqlite("read completed reservation", error))?;
        if state != 1 {
            return Err(ServiceFailure::ReservationFailure.into());
        }
        Ok(())
    }

    fn reserve_proposal_v1(
        &mut self,
        request: &RemoteProposalSignatureRequestV1,
        safety_revision: u64,
    ) -> Result<ReservationDispositionV1, RemoteSignerServiceError> {
        let nonce = *request.nonce().as_bytes();
        let fingerprint = *request.fingerprint().as_bytes();
        let epoch_sql = to_sql_i64(request.epoch().get(), "proposal epoch")?;
        let view_sql = to_sql_i64(request.view().get(), "proposal view")?;
        let height_sql = to_sql_i64(request.height().get(), "proposal height")?;
        let revision_sql = to_sql_i64(safety_revision, "proposal safety revision")?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ServiceFailure::Sqlite("begin proposal watermark CAS", error))?;
        let existing: Option<ExistingProposalReservationRowV1> = tx
            .query_row(
                "SELECT request_fingerprint, epoch, view, state, signing_root
                 FROM proposal_reservation
                 WHERE scope = ?1 AND nonce = ?2",
                params![self.scope.as_slice(), nonce.as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| ServiceFailure::Sqlite("check proposal nonce replay", error))?;
        if let Some((existing_fp, existing_epoch, existing_view, state, existing_root)) = existing {
            if existing_fp.as_slice() == fingerprint
                && existing_epoch == epoch_sql
                && existing_view == view_sql
                && existing_root.as_slice() == request.signing_root().as_bytes()
                && state == 0
            {
                return Ok(ReservationDispositionV1::Pending);
            }
            if existing_fp.as_slice() == fingerprint {
                return Err(ServiceFailure::DuplicateRequest.into());
            }
            return Err(ServiceFailure::DuplicateNonce.into());
        }
        let duplicate_fingerprint: Option<Vec<u8>> = tx
            .query_row(
                "SELECT nonce FROM proposal_reservation
                 WHERE scope = ?1 AND request_fingerprint = ?2",
                params![self.scope.as_slice(), fingerprint.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| ServiceFailure::Sqlite("check proposal request replay", error))?;
        if duplicate_fingerprint.is_some() {
            return Err(ServiceFailure::DuplicateRequest.into());
        }
        let duplicate_proposal: Option<Vec<u8>> = tx
            .query_row(
                "SELECT nonce FROM proposal_reservation
                 WHERE scope = ?1 AND proposal_id = ?2",
                params![self.scope.as_slice(), request.proposal_id().as_bytes()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| ServiceFailure::Sqlite("check proposal identity replay", error))?;
        if duplicate_proposal.is_some() {
            return Err(ServiceFailure::DuplicateRequest.into());
        }
        let state = tx
            .query_row(
                "SELECT sequence, has_round, maximum_epoch, maximum_view,
                        maximum_safety_revision
                 FROM signer_watermark WHERE scope = ?1",
                params![self.scope.as_slice()],
                |row| {
                    Ok((
                        decode_i64_u64(row.get::<_, i64>(0)?, "sequence")?,
                        row.get::<_, i64>(1)? != 0,
                        decode_i64_u64(row.get::<_, i64>(2)?, "maximum epoch")?,
                        decode_i64_u64(row.get::<_, i64>(3)?, "maximum view")?,
                        decode_i64_u64(row.get::<_, i64>(4)?, "maximum Safety revision")?,
                    ))
                },
            )
            .map_err(|error| ServiceFailure::Sqlite("read proposal watermark", error))?;
        if state.1
            && (request.epoch().get() < state.2
                || (request.epoch().get() == state.2 && request.view().get() < state.3))
        {
            return Err(ServiceFailure::Rollback {
                maximum_epoch: state.2,
                maximum_view: state.3,
            }
            .into());
        }
        if safety_revision <= state.4 {
            return Err(ServiceFailure::SafetyRevisionRollback {
                maximum: state.4,
                incoming: safety_revision,
            }
            .into());
        }
        let next_sequence = state
            .0
            .checked_add(1)
            .ok_or(ServiceFailure::WatermarkExhausted)?;
        let next_sequence_sql = to_sql_i64(next_sequence, "sequence")?;
        let (next_epoch, next_view) = if !state.1
            || request.epoch().get() > state.2
            || (request.epoch().get() == state.2 && request.view().get() > state.3)
        {
            (epoch_sql, view_sql)
        } else {
            (
                to_sql_i64(state.2, "maximum epoch")?,
                to_sql_i64(state.3, "maximum view")?,
            )
        };
        let updated = tx
            .execute(
                "UPDATE signer_watermark
                 SET sequence = ?2, has_round = 1, maximum_epoch = ?3,
                     maximum_view = ?4, maximum_safety_revision = ?5,
                     last_nonce = ?6, last_fingerprint = ?7
                 WHERE scope = ?1 AND sequence = ?8",
                params![
                    self.scope.as_slice(),
                    next_sequence_sql,
                    next_epoch,
                    next_view,
                    revision_sql,
                    nonce.as_slice(),
                    fingerprint.as_slice(),
                    to_sql_i64(state.0, "sequence")?,
                ],
            )
            .map_err(|error| ServiceFailure::Sqlite("advance proposal watermark", error))?;
        if updated != 1 {
            return Err(ServiceFailure::Sqlite(
                "advance proposal watermark",
                rusqlite::Error::QueryReturnedNoRows,
            )
            .into());
        }
        tx.execute(
            "INSERT INTO proposal_reservation
             (scope, nonce, request_fingerprint, proposal_id, parent_id,
              validator_set_id, epoch, view, height, state, signing_root,
              signer_profile_ref)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, ?11)",
            params![
                self.scope.as_slice(),
                nonce.as_slice(),
                fingerprint.as_slice(),
                request.proposal_id().as_bytes(),
                request.parent_id().as_bytes(),
                request.validator_set_id().as_bytes(),
                epoch_sql,
                view_sql,
                height_sql,
                request.signing_root().as_bytes(),
                request.signer_profile_ref().as_slice(),
            ],
        )
        .map_err(|error| ServiceFailure::Sqlite("persist proposal reservation", error))?;
        tx.commit()
            .map_err(|error| ServiceFailure::Sqlite("commit proposal watermark", error))?;
        Ok(ReservationDispositionV1::New)
    }

    fn complete_proposal_v1(
        &mut self,
        nonce: [u8; 32],
        fingerprint: [u8; 32],
    ) -> Result<(), RemoteSignerServiceError> {
        self.ensure_file_identity_v1()?;
        let changed = self
            .connection
            .execute(
                "UPDATE proposal_reservation SET state = 1
                 WHERE scope = ?1 AND nonce = ?2 AND request_fingerprint = ?3 AND state = 0",
                params![
                    self.scope.as_slice(),
                    nonce.as_slice(),
                    fingerprint.as_slice()
                ],
            )
            .map_err(|error| ServiceFailure::Sqlite("complete proposal reservation", error))?;
        if changed != 1 {
            return Err(ServiceFailure::ReservationFailure.into());
        }
        Ok(())
    }

    fn sign_and_verify_v1(&self, signing_root: &[u8; 32]) -> Result<[u8; 64], ServiceFailure> {
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or(ServiceFailure::ExternalAuthorityRequired)?;
        let signature = signing_key.sign(signing_root);
        signing_key
            .verifying_key()
            .verify(signing_root, &signature)
            .map_err(|_| ServiceFailure::SignatureFailure)?;
        Ok(signature.to_bytes())
    }

    fn verify_external_signature_v1(
        &self,
        request: &trnm_consensus_remote_signer_protocol::RemoteSignerRequestV1,
        signature: [u8; 64],
    ) -> Result<(), RemoteSignerServiceError> {
        let validator = self
            .validator_set
            .validator(self.binding.author())
            .ok_or(ServiceFailure::InvalidConfig("binding author is absent"))?;
        let verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(validator.consensus_key().as_bytes())
                .map_err(|_| ServiceFailure::SignatureFailure)?;
        verifying_key
            .verify(
                request.command().intent().signing_root().as_bytes(),
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .map_err(|_| ServiceFailure::SignatureFailure.into())
    }

    fn ensure_file_identity_v1(&self) -> Result<(), RemoteSignerServiceError> {
        if file_identity_v1(&self.watermark_path)? != self.watermark_identity
            || file_identity_v1(
                self.watermark_path
                    .parent()
                    .ok_or(ServiceFailure::InvalidConfig("watermark parent"))?,
            )? != self.watermark_directory_identity
        {
            return Err(
                ServiceFailure::InvalidConfig("watermark file or parent identity changed").into(),
            );
        }
        Ok(())
    }
}

fn signature_from_external_response_v1(
    response: &[u8],
) -> Result<[u8; 64], RemoteSignerServiceError> {
    response
        .try_into()
        .map_err(|_| ServiceFailure::Protocol(RemoteSignerProtocolErrorV1::InvalidSignature).into())
}

fn external_authority_failure_v1(_error: ExternalAuthorityErrorV1) -> RemoteSignerServiceError {
    // Every external bridge failure is deliberately collapsed to the
    // fail-closed class. Callers must not fall back to the local SQLite path.
    ServiceFailure::ExternalAuthorityRequired.into()
}

fn canonical_watermark_path(
    requested: &Path,
) -> Result<(PathBuf, FileIdentityV1, bool), RemoteSignerServiceError> {
    let absolute = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| ServiceFailure::Io("resolve watermark path", error))?
            .join(requested)
    };
    let file_name = absolute
        .file_name()
        .ok_or(ServiceFailure::InvalidConfig("watermark file name"))?;
    let lowered = file_name.to_string_lossy().to_ascii_lowercase();
    if ["-wal", "-shm", "-journal", ".lock"]
        .iter()
        .any(|suffix| lowered.ends_with(suffix))
    {
        return Err(ServiceFailure::InvalidConfig(
            "watermark path collides with SQLite auxiliary namespace",
        )
        .into());
    }
    let parent = absolute
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or(ServiceFailure::InvalidConfig("watermark parent"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| ServiceFailure::Io("canonicalize watermark parent", error))?;
    let directory_identity = file_identity_v1(&parent)?;
    let path = parent.join(file_name);
    let existed = match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(
                    ServiceFailure::InvalidConfig("watermark path is not a regular file").into(),
                );
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(ServiceFailure::Io("inspect watermark path", error).into());
        }
    };
    Ok((path, directory_identity, existed))
}

fn file_identity_v1(path: &Path) -> Result<FileIdentityV1, RemoteSignerServiceError> {
    let metadata = fs::metadata(path)
        .map_err(|error| ServiceFailure::Io("stat watermark namespace", error))?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(ServiceFailure::InvalidConfig(
            "watermark namespace is neither file nor directory",
        )
        .into());
    }
    Ok(FileIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn validate_private_watermark_file(path: &Path) -> Result<(), RemoteSignerServiceError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| ServiceFailure::Io("stat watermark file", error))?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 || metadata.mode() & 0o777 != 0o600
    {
        return Err(ServiceFailure::InvalidConfig(
            "watermark file must be a private single-link 0600 file",
        )
        .into());
    }
    Ok(())
}

fn validate_schema_v1(connection: &Connection) -> Result<(), RemoteSignerServiceError> {
    let user_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| ServiceFailure::Sqlite("read watermark schema version", error))?;
    if user_version != 0 && user_version != WATERMARK_SCHEMA_VERSION {
        return Err(ServiceFailure::InvalidConfig("unsupported watermark schema version").into());
    }
    for (table, expected) in [
        ("signer_metadata", &["key", "value"][..]),
        (
            "signer_watermark",
            &[
                "scope",
                "sequence",
                "has_round",
                "maximum_epoch",
                "maximum_view",
                "maximum_safety_revision",
                "last_nonce",
                "last_fingerprint",
            ][..],
        ),
        (
            "signer_reservation",
            &[
                "scope",
                "nonce",
                "request_fingerprint",
                "epoch",
                "view",
                "safety_revision",
                "purpose",
                "state",
                "signing_root",
            ][..],
        ),
        (
            "proposal_reservation",
            &[
                "scope",
                "nonce",
                "request_fingerprint",
                "proposal_id",
                "parent_id",
                "validator_set_id",
                "epoch",
                "view",
                "height",
                "state",
                "signing_root",
                "signer_profile_ref",
            ][..],
        ),
    ] {
        let mut statement = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(|error| ServiceFailure::Sqlite("inspect watermark schema", error))?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| ServiceFailure::Sqlite("read watermark schema", error))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| ServiceFailure::Sqlite("collect watermark schema", error))?;
        if columns != expected {
            return Err(ServiceFailure::InvalidConfig("watermark schema columns differ").into());
        }
    }
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|error| ServiceFailure::Sqlite("check watermark integrity", error))?;
    if integrity != "ok" {
        return Err(ServiceFailure::InvalidConfig("watermark integrity check failed").into());
    }
    let foreign_keys: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|error| ServiceFailure::Sqlite("check watermark foreign keys", error))?;
    if foreign_keys != 0 {
        return Err(ServiceFailure::InvalidConfig("watermark foreign-key check failed").into());
    }
    Ok(())
}

fn validate_namespace_scope_v1(
    connection: &Connection,
    expected_scope: [u8; 32],
) -> Result<(), RemoteSignerServiceError> {
    let mut statement = connection
        .prepare("SELECT scope FROM signer_watermark")
        .map_err(|error| ServiceFailure::Sqlite("read watermark namespace scopes", error))?;
    let scopes = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|error| ServiceFailure::Sqlite("iterate watermark namespace scopes", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ServiceFailure::Sqlite("decode watermark namespace scope", error))?;
    if scopes.len() > 1 {
        return Err(
            ServiceFailure::InvalidConfig("watermark namespace contains multiple scopes").into(),
        );
    }
    if let Some(scope) = scopes.first() {
        if scope.as_slice() != expected_scope {
            return Err(ServiceFailure::InvalidConfig("watermark namespace scope mismatch").into());
        }
    }
    if let Some(scope) = connection
        .query_row(
            "SELECT value FROM signer_metadata WHERE key = 'scope'",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|error| ServiceFailure::Sqlite("read watermark metadata scope", error))?
    {
        if scope.as_slice() != expected_scope {
            return Err(ServiceFailure::InvalidConfig("watermark metadata scope mismatch").into());
        }
    }
    Ok(())
}

fn ensure_metadata_v1(
    connection: &Connection,
    scope: [u8; 32],
    binding: &RemoteSignerRequestBindingV1,
    signing_key: &SigningKey,
    purpose_policy: PurposePolicyV1,
) -> Result<(), ServiceFailure> {
    let values = [
        ("schema", WATERMARK_SCHEMA_VERSION.to_be_bytes().to_vec()),
        ("scope", scope.to_vec()),
        (
            "validator_set_id",
            binding.validator_set_id().as_bytes().to_vec(),
        ),
        ("author", binding.author().as_bytes().to_vec()),
        (
            "public_key",
            signing_key.verifying_key().to_bytes().to_vec(),
        ),
        ("binding_digest", binding_digest_v1(binding).to_vec()),
        (
            "purpose_policy",
            if purpose_policy.allow_proposal {
                vec![
                    u8::from(purpose_policy.allow_vote),
                    u8::from(purpose_policy.allow_timeout_vote),
                    1,
                ]
            } else {
                vec![
                    u8::from(purpose_policy.allow_vote),
                    u8::from(purpose_policy.allow_timeout_vote),
                ]
            },
        ),
    ];
    for (key, value) in values {
        let existing: Option<Vec<u8>> = connection
            .query_row(
                "SELECT value FROM signer_metadata WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| ServiceFailure::Sqlite("read signer metadata", error))?;
        match existing {
            Some(existing) if existing != value => {
                return Err(ServiceFailure::InvalidConfig("watermark metadata mismatch"));
            }
            Some(_) => {}
            None => {
                connection
                    .execute(
                        "INSERT INTO signer_metadata (key, value) VALUES (?1, ?2)",
                        params![key, value],
                    )
                    .map_err(|error| ServiceFailure::Sqlite("write signer metadata", error))?;
            }
        }
    }
    let metadata_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM signer_metadata", [], |row| row.get(0))
        .map_err(|error| ServiceFailure::Sqlite("count signer metadata", error))?;
    if metadata_count != 7 {
        return Err(ServiceFailure::InvalidConfig(
            "unexpected signer metadata keys",
        ));
    }
    Ok(())
}

fn validate_persisted_state_v1(
    connection: &Connection,
    scope: [u8; 32],
) -> Result<(), RemoteSignerServiceError> {
    let watermark: Option<PersistedWatermarkRowV1> = connection
        .query_row(
            "SELECT scope, sequence, has_round, maximum_epoch, maximum_view,
                    maximum_safety_revision, last_nonce, last_fingerprint
             FROM signer_watermark",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()
        .map_err(|error| ServiceFailure::Sqlite("read persisted watermark", error))?;
    let Some((stored_scope, sequence, has_round, epoch, view, safety_revision, nonce, fingerprint)) =
        watermark
    else {
        return Err(ServiceFailure::InvalidConfig("missing persisted watermark row").into());
    };
    let watermark_rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM signer_watermark", [], |row| {
            row.get(0)
        })
        .map_err(|error| ServiceFailure::Sqlite("count persisted watermark rows", error))?;
    if watermark_rows != 1
        || stored_scope.as_slice() != scope
        || sequence < 0
        || !matches!(has_round, 0 | 1)
        || epoch < 0
        || view < 0
        || safety_revision < 0
        || nonce.len() != 32
        || fingerprint.len() != 32
    {
        return Err(ServiceFailure::InvalidConfig("persisted watermark row is malformed").into());
    }
    let mut statement = connection
        .prepare(
            "SELECT scope, nonce, request_fingerprint, epoch, view,
                    safety_revision, purpose, state, signing_root
             FROM signer_reservation",
        )
        .map_err(|error| ServiceFailure::Sqlite("read persisted reservations", error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Vec<u8>>(8)?,
            ))
        })
        .map_err(|error| ServiceFailure::Sqlite("iterate persisted reservations", error))?;
    for row in rows {
        let (
            row_scope,
            row_nonce,
            row_fingerprint,
            row_epoch,
            row_view,
            row_revision,
            purpose,
            state,
            root,
        ) = row.map_err(|error| ServiceFailure::Sqlite("decode persisted reservation", error))?;
        if row_scope.as_slice() != scope
            || row_nonce.len() != 32
            || row_fingerprint.len() != 32
            || row_epoch < 0
            || row_view < 0
            || row_revision <= 0
            || !matches!(purpose, 0 | 1)
            || !matches!(state, 0 | 1)
            || root.len() != 32
        {
            return Err(
                ServiceFailure::InvalidConfig("persisted reservation row is malformed").into(),
            );
        }
    }
    let mut proposal_statement = connection
        .prepare(
            "SELECT scope, nonce, request_fingerprint, proposal_id, parent_id,
                    validator_set_id, epoch, view, height, state, signing_root,
                    signer_profile_ref
             FROM proposal_reservation",
        )
        .map_err(|error| ServiceFailure::Sqlite("read persisted proposal reservations", error))?;
    let proposal_rows = proposal_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, Vec<u8>>(10)?,
                row.get::<_, Vec<u8>>(11)?,
            ))
        })
        .map_err(|error| {
            ServiceFailure::Sqlite("iterate persisted proposal reservations", error)
        })?;
    for row in proposal_rows {
        let (
            row_scope,
            row_nonce,
            row_fingerprint,
            proposal_id,
            parent_id,
            validator_set_id,
            epoch,
            view,
            height,
            state,
            root,
            profile,
        ) = row.map_err(|error| {
            ServiceFailure::Sqlite("decode persisted proposal reservation", error)
        })?;
        if row_scope.as_slice() != scope
            || row_nonce.len() != 32
            || row_fingerprint.len() != 32
            || proposal_id.len() != 32
            || parent_id.len() != 32
            || validator_set_id.len() != 32
            || epoch < 0
            || view <= 0
            || height <= 0
            || !matches!(state, 0 | 1)
            || root.len() != 32
            || profile.len() != 32
        {
            return Err(ServiceFailure::InvalidConfig(
                "persisted proposal reservation row is malformed",
            )
            .into());
        }
    }
    Ok(())
}

fn watermark_scope_v1(binding: &RemoteSignerRequestBindingV1) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(WATERMARK_SCOPE_DOMAIN);
    hash.update(binding.role_profile_ref().as_bytes());
    hash.update(binding.service_profile_ref().as_bytes());
    hash.update(binding.client_profile_ref().as_bytes());
    hash.update(binding.process_generation().get().to_be_bytes());
    hash.update(binding.lease_id().as_bytes());
    hash.update(binding.checkpoint_witness().witness_digest());
    hash.update(binding.validator_set_id().as_bytes());
    hash.update(binding.author().as_bytes());
    hash.finalize().into()
}

fn binding_digest_v1(binding: &RemoteSignerRequestBindingV1) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"trnm.remote-signer.service.p0-binding.v1\0");
    hash.update(binding.purpose_profile_digest().as_bytes());
    hash.update(binding.role_profile_ref().as_bytes());
    hash.update(binding.service_profile_ref().as_bytes());
    hash.update(binding.client_profile_ref().as_bytes());
    hash.update(binding.process_generation().get().to_be_bytes());
    hash.update(binding.lease_id().as_bytes());
    hash.update(binding.checkpoint_witness().generation().to_be_bytes());
    hash.update(binding.checkpoint_witness().checkpoint_checksum());
    hash.update(binding.checkpoint_witness().witness_digest());
    hash.update(binding.genesis_hash().as_bytes());
    hash.update((binding.chain_id().as_bytes().len() as u32).to_be_bytes());
    hash.update(binding.chain_id().as_bytes());
    hash.update(binding.protocol_version().get().to_be_bytes());
    hash.update(binding.epoch().get().to_be_bytes());
    hash.update(binding.validator_set_id().as_bytes());
    hash.update((binding.author().as_bytes().len() as u32).to_be_bytes());
    hash.update(binding.author().as_bytes());
    hash.finalize().into()
}

fn intent_round_v1(intent: &trnm_consensus_types::CanonicalSignIntentV0) -> (u64, u64) {
    (
        intent.epoch().get(),
        intent.preimage().context().view().get(),
    )
}

fn purpose_tag_v1(kind: RemoteConsensusCommandKindV1) -> i64 {
    match kind {
        RemoteConsensusCommandKindV1::Vote => 0,
        RemoteConsensusCommandKindV1::TimeoutVote => 1,
    }
}

fn to_sql_i64(value: u64, field: &'static str) -> Result<i64, RemoteSignerServiceError> {
    i64::try_from(value).map_err(|_| {
        ServiceFailure::InvalidConfig(match field {
            "epoch" => "epoch exceeds SQLite integer range",
            "view" => "view exceeds SQLite integer range",
            "sequence" => "sequence exceeds SQLite integer range",
            _ => "numeric field exceeds SQLite integer range",
        })
        .into()
    })
}

fn decode_i64_u64(value: i64, _field: &'static str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

fn classify_reject_v1(error: &ServiceFailure) -> ServiceRejectCodeV1 {
    match error {
        ServiceFailure::Protocol(_) => ServiceRejectCodeV1::InvalidProtocol,
        ServiceFailure::WrongPurpose(_) | ServiceFailure::ProposalPurposeDisabled => {
            ServiceRejectCodeV1::WrongPurpose
        }
        ServiceFailure::DuplicateNonce => ServiceRejectCodeV1::DuplicateNonce,
        ServiceFailure::DuplicateRequest => ServiceRejectCodeV1::DuplicateRequest,
        ServiceFailure::DuplicateRoundPurpose => ServiceRejectCodeV1::DuplicateRoundPurpose,
        ServiceFailure::Rollback { .. } | ServiceFailure::SafetyRevisionRollback { .. } => {
            ServiceRejectCodeV1::Rollback
        }
        ServiceFailure::WatermarkExhausted => ServiceRejectCodeV1::WatermarkExhausted,
        ServiceFailure::SignatureFailure => ServiceRejectCodeV1::SignatureFailure,
        ServiceFailure::ReservationFailure => ServiceRejectCodeV1::ReservationFailure,
        ServiceFailure::ExternalAuthorityRequired => ServiceRejectCodeV1::DurableStoreFailure,
        ServiceFailure::InvalidFrame => ServiceRejectCodeV1::InvalidFrame,
        ServiceFailure::InvalidConfig(_)
        | ServiceFailure::Io(_, _)
        | ServiceFailure::Sqlite(_, _) => ServiceRejectCodeV1::DurableStoreFailure,
    }
}

fn read_frame_v1(stream: &mut UnixStream) -> Result<Option<Vec<u8>>, ServiceFailure> {
    let mut length_bytes = [0u8; 4];
    match read_exact_or_eof(stream, &mut length_bytes) {
        Ok(false) => return Ok(None),
        Ok(true) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(ServiceFailure::InvalidFrame)
        }
        Err(error) => return Err(ServiceFailure::Io("read frame length", error)),
    }
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_SERVICE_FRAME_BYTES {
        return Err(ServiceFailure::InvalidFrame);
    }
    let mut payload = vec![0u8; length];
    match stream.read_exact(&mut payload) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(ServiceFailure::InvalidFrame)
        }
        Err(error) => return Err(ServiceFailure::Io("read frame payload", error)),
    }
    Ok(Some(payload))
}

fn read_exact_or_eof(stream: &mut UnixStream, bytes: &mut [u8]) -> io::Result<bool> {
    let mut offset = 0;
    while offset < bytes.len() {
        match std::io::Read::read(stream, &mut bytes[offset..])? {
            0 if offset == 0 => return Ok(false),
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated frame",
                ))
            }
            read => offset += read,
        }
    }
    Ok(true)
}

fn write_ok_frame_v1(
    stream: &mut UnixStream,
    response: &[u8],
) -> Result<(), RemoteSignerServiceError> {
    let mut payload = Vec::with_capacity(response.len() + 1);
    payload.push(FRAME_OK);
    payload.extend_from_slice(response);
    write_frame_v1(stream, &payload)
}

fn write_reject_frame_v1(
    stream: &mut UnixStream,
    code: ServiceRejectCodeV1,
) -> Result<(), RemoteSignerServiceError> {
    write_frame_v1(stream, &[FRAME_REJECT, code.as_byte()])
}

fn write_frame_v1(stream: &mut UnixStream, payload: &[u8]) -> Result<(), RemoteSignerServiceError> {
    let length = u32::try_from(payload.len()).map_err(|_| ServiceFailure::InvalidFrame)?;
    std::io::Write::write_all(stream, &length.to_be_bytes())
        .and_then(|_| std::io::Write::write_all(stream, payload))
        .map_err(|error| ServiceFailure::Io("write signer response", error).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};
    use std::{fs, os::unix::net::UnixStream, thread};
    use tempfile::TempDir;
    use trnm_consensus_remote_signer_protocol::{
        decode_unverified_remote_proposal_signer_response_v1_exact,
        decode_unverified_remote_signer_response_v1_exact, RemoteProposalSignatureRequestV1,
        RemoteSignerRequestNonceV1,
    };
    use trnm_consensus_signer_journal::ProposalSignatureRequestV0;

    #[test]
    fn service_binds_round_purpose_nonce_and_persists_cas_watermark() {
        let temporary = TempDir::new().expect("temporary signer directory");
        let path = temporary.path().join("watermark.sqlite3");
        let fixture = Fixture::new();
        let config = fixture_service_config(&path, PurposePolicyV1::both());
        let mut service = RemoteSignerService::open(config).expect("open signer service");
        let first = fixture_request(&fixture, "vote", 10, b"first").expect("first request");
        let response = service
            .process_request(&first.try_exact_bytes().unwrap())
            .unwrap();
        assert!(!response.is_empty());
        let decoded_response = decode_unverified_remote_signer_response_v1_exact(&response, &first)
            .expect("exact response binding");
        fixture
            .signing_key
            .verifying_key()
            .verify(
                first.command().intent().signing_root().as_bytes(),
                &Signature::from_bytes(decoded_response.unverified_signature_bytes().as_bytes()),
            )
            .expect("service signature verifies against exact intent root");
        let snapshot = service.watermark_snapshot().unwrap();
        assert_eq!(snapshot.sequence, 1);
        assert_eq!(snapshot.epoch, Some(fixture.validator_set.epoch().get()));
        assert_eq!(snapshot.view, Some(10));
        assert!(matches!(
            service.process_request(&first.try_exact_bytes().unwrap()),
            Err(RemoteSignerServiceError(ServiceFailure::DuplicateRequest))
        ));

        let rollback = fixture_request(&fixture, "vote", 9, b"rollback").unwrap();
        assert!(matches!(
            service.process_request(&rollback.try_exact_bytes().unwrap()),
            Err(RemoteSignerServiceError(ServiceFailure::Rollback { .. }))
        ));

        let timeout = fixture_request(&fixture, "timeout", 10, b"timeout").unwrap();
        let timeout_response = service
            .process_request(&timeout.try_exact_bytes().unwrap())
            .unwrap();
        assert!(!timeout_response.is_empty());
        assert_eq!(service.watermark_snapshot().unwrap().sequence, 2);

        drop(service);
        let mut reopened =
            RemoteSignerService::open(fixture_service_config(&path, PurposePolicyV1::both()))
                .expect("reopen signer service");
        assert_eq!(reopened.watermark_snapshot().unwrap().sequence, 2);
        let stale = fixture_request(&fixture, "vote", 9, b"stale-after-restart").unwrap();
        assert!(matches!(
            reopened.process_request(&stale.try_exact_bytes().unwrap()),
            Err(RemoteSignerServiceError(ServiceFailure::Rollback { .. }))
        ));
        assert!(fs::metadata(&path).is_ok());
    }

    #[test]
    fn service_rejects_disabled_purpose_before_reserving_watermark() {
        let temporary = TempDir::new().expect("temporary signer directory");
        let fixture = Fixture::new();
        let mut service = RemoteSignerService::open(fixture_service_config(
            &temporary.path().join("watermark.sqlite3"),
            PurposePolicyV1::vote_only(),
        ))
        .expect("open signer service");
        let timeout = fixture_request(&fixture, "timeout", 4, b"wrong-purpose").unwrap();
        assert!(matches!(
            service.process_request(&timeout.try_exact_bytes().unwrap()),
            Err(RemoteSignerServiceError(ServiceFailure::WrongPurpose(
                RemoteConsensusCommandKindV1::TimeoutVote
            )))
        ));
        assert_eq!(service.watermark_snapshot().unwrap().sequence, 0);
    }

    #[test]
    fn proposal_purpose_isolated_and_replays_exactly() {
        let temporary = TempDir::new().expect("temporary signer directory");
        let path = temporary.path().join("proposal-watermark.sqlite3");
        let fixture = Fixture::new();
        let proposal = ProposalSignatureRequestV0::new(
            trnm_consensus_types::BlockId::new([0x81; 32]),
            trnm_consensus_types::BlockId::new([0x82; 32]),
            fixture.validator_set.id(),
            fixture.binding.author(),
            fixture.validator_set.epoch(),
            trnm_consensus_types::View::new(1),
            trnm_consensus_types::Height::new(1),
            trnm_consensus_types::SigningRoot::new([0x83; 32]),
            *fixture
                .validator_set
                .validator(fixture.binding.author())
                .unwrap()
                .consensus_key()
                .as_bytes(),
            [0x84; 32],
        )
        .expect("proposal request shape");
        let binding = fixture.proposal_binding().expect("proposal binding");
        let wire = RemoteProposalSignatureRequestV1::new(
            binding,
            proposal.proposal_id(),
            proposal.parent_id(),
            proposal.validator_set_id(),
            proposal.author(),
            proposal.epoch(),
            proposal.view(),
            proposal.height(),
            proposal.signing_root(),
            proposal.expected_consensus_public_key(),
            proposal.signer_profile_ref(),
            RemoteSignerRequestNonceV1::from_public_nonce_material(b"proposal-service-test")
                .unwrap(),
            &fixture.validator_set,
        )
        .expect("wire proposal request");
        let encoded = wire.try_exact_bytes().unwrap();
        decode_remote_proposal_signer_request_v1_exact(&encoded, &fixture.validator_set, binding)
            .expect("proposal request decodes before service");
        let mut service = RemoteSignerService::open(
            fixture_proposal_service_config(&path).expect("proposal config"),
        )
        .expect("open proposal-only fixture service");
        let response = service
            .process_proposal_request(&encoded)
            .expect("proposal signature response");
        let decoded = decode_unverified_remote_proposal_signer_response_v1_exact(&response, &wire)
            .expect("exact proposal response");
        fixture
            .signing_key
            .verifying_key()
            .verify(
                proposal.signing_root().as_bytes(),
                &Signature::from_bytes(decoded.unverified_signature_bytes().as_bytes()),
            )
            .expect("proposal signature verifies");
        assert!(matches!(
            service.process_proposal_request(&encoded),
            Err(RemoteSignerServiceError(ServiceFailure::DuplicateRequest))
        ));

        // An old Vote/Timeout service must not reinterpret the proposal magic
        // or accept the separate purpose profile.
        let old_path = temporary.path().join("old-watermark.sqlite3");
        let mut old_service =
            RemoteSignerService::open(fixture_service_config(&old_path, PurposePolicyV1::both()))
                .expect("open old-purpose fixture service");
        assert!(matches!(
            old_service.process_proposal_request(&encoded),
            Err(RemoteSignerServiceError(
                ServiceFailure::ProposalPurposeDisabled
            )) | Err(RemoteSignerServiceError(ServiceFailure::Protocol(_)))
        ));
    }

    #[test]
    fn service_rejects_multiple_watermark_scopes_before_namespace_migration() {
        let temporary = TempDir::new().expect("temporary signer directory");
        let path = temporary.path().join("watermark.sqlite3");
        let fixture = Fixture::new();
        // Create the normal one-scope fixture first.  Reopening that exact
        // namespace is the supported migration shape (covered above).
        drop(
            RemoteSignerService::open(fixture_service_config(&path, PurposePolicyV1::both()))
                .expect("create one-scope fixture namespace"),
        );

        // Simulate a legacy/operator-modified file containing a second scope.
        // The service must reject before INSERT OR IGNORE can make the new
        // binding appear valid; accepting it would permit generation/lease
        // confusion inside one local SQLite file.
        let connection = Connection::open(&path).expect("open fixture database");
        connection
            .execute(
                "INSERT INTO signer_watermark
                 (scope, sequence, has_round, maximum_epoch, maximum_view,
                  maximum_safety_revision, last_nonce, last_fingerprint)
                 VALUES (?1, 0, 0, 0, 0, 0, zeroblob(32), zeroblob(32))",
                params![[0xa5_u8; 32].as_slice()],
            )
            .expect("insert second fixture scope");
        drop(connection);

        let error =
            match RemoteSignerService::open(fixture_service_config(&path, PurposePolicyV1::both()))
            {
                Ok(_) => panic!("multiple watermark scopes must fail closed"),
                Err(error) => error,
            };
        assert!(
            error.to_string().contains("multiple scopes"),
            "unexpected namespace rejection: {error}"
        );
        // Keep the fixture referenced so this test documents that the
        // expected binding is the original one-scope namespace.
        assert_eq!(fixture.binding.process_generation().get(), 1);
    }

    #[test]
    fn service_migrates_existing_single_scope_namespace() {
        let temporary = TempDir::new().expect("temporary signer directory");
        let path = temporary.path().join("watermark.sqlite3");
        let fixture = Fixture::new();
        drop(
            RemoteSignerService::open(fixture_service_config(&path, PurposePolicyV1::both()))
                .expect("create one-scope fixture namespace"),
        );

        // A pre-metadata fixture still has exactly one durable scope.  The
        // migration may fill the immutable metadata key, but it must not
        // create a second scope row or silently switch bindings.
        let connection = Connection::open(&path).expect("open fixture database");
        connection
            .execute("DELETE FROM signer_metadata WHERE key = 'scope'", [])
            .expect("remove legacy scope metadata");
        drop(connection);

        let reopened =
            RemoteSignerService::open(fixture_service_config(&path, PurposePolicyV1::both()))
                .expect("single-scope fixture migration succeeds");
        assert_eq!(reopened.scope(), watermark_scope_v1(&fixture.binding));
        let connection = Connection::open(&path).expect("reopen migrated database");
        let metadata_scope: Vec<u8> = connection
            .query_row(
                "SELECT value FROM signer_metadata WHERE key = 'scope'",
                [],
                |row| row.get(0),
            )
            .expect("migrated scope metadata");
        assert_eq!(metadata_scope.as_slice(), reopened.scope().as_slice());
    }

    #[test]
    fn pending_reservation_retries_after_restart_without_advancing_twice() {
        let temporary = TempDir::new().expect("temporary signer directory");
        let path = temporary.path().join("watermark.sqlite3");
        let fixture = Fixture::new();
        let request = fixture_request(&fixture, "vote", 6, b"crash-window").unwrap();
        let encoded = request.try_exact_bytes().unwrap();
        let intent = request.command().intent();
        let (epoch, view) = intent_round_v1(intent);
        let input = ReservationInputV1 {
            nonce: *request.nonce().as_bytes(),
            fingerprint: *request.fingerprint().as_bytes(),
            epoch,
            view,
            safety_revision: intent.authorizing_safety_revision(),
            kind: request.command().kind(),
            signing_root: *intent.signing_root().as_bytes(),
        };
        let mut service =
            RemoteSignerService::open(fixture_service_config(&path, PurposePolicyV1::both()))
                .unwrap();
        assert_eq!(
            service.reserve_v1(input).unwrap(),
            ReservationDispositionV1::New
        );
        assert_eq!(service.watermark_snapshot().unwrap().sequence, 1);
        drop(service);

        let mut restarted =
            RemoteSignerService::open(fixture_service_config(&path, PurposePolicyV1::both()))
                .unwrap();
        let response = restarted.process_request(&encoded).unwrap();
        decode_unverified_remote_signer_response_v1_exact(&response, &request)
            .expect("pending reservation retry response");
        assert_eq!(restarted.watermark_snapshot().unwrap().sequence, 1);
        assert!(matches!(
            restarted.process_request(&encoded),
            Err(RemoteSignerServiceError(ServiceFailure::DuplicateRequest))
        ));
    }

    #[test]
    fn service_rejects_non_increasing_safety_revision_at_a_newer_round() {
        let temporary = TempDir::new().expect("temporary signer directory");
        let path = temporary.path().join("watermark.sqlite3");
        let fixture = Fixture::new();
        let mut service =
            RemoteSignerService::open(fixture_service_config(&path, PurposePolicyV1::both()))
                .unwrap();
        let first = fixture_request(&fixture, "vote", 10, b"revision-high").unwrap();
        service
            .process_request(&first.try_exact_bytes().unwrap())
            .unwrap();

        let lower_revision_intent = trnm_consensus_types::CanonicalSignIntentV0::vote(
            &fixture.validator_set,
            fixture.binding.author(),
            21,
            trnm_consensus_types::View::new(11),
            trnm_consensus_types::Height::new(12),
            trnm_consensus_types::BlockId::new([0x91; 32]),
        )
        .unwrap();
        let lower_revision = trnm_consensus_remote_signer_protocol::RemoteSignerRequestV1::new(
            trnm_consensus_remote_signer_protocol::RemoteConsensusCommandV1::from_canonical_intent(
                lower_revision_intent,
                &fixture.validator_set,
            )
            .unwrap(),
            &fixture.validator_set,
            fixture.binding,
            trnm_consensus_remote_signer_protocol::RemoteSignerRequestNonceV1::from_public_nonce_material(
                b"revision-low",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            service.process_request(&lower_revision.try_exact_bytes().unwrap()),
            Err(RemoteSignerServiceError(
                ServiceFailure::SafetyRevisionRollback { .. }
            ))
        ));
        assert_eq!(service.watermark_snapshot().unwrap().sequence, 1);
    }

    #[test]
    fn unix_transport_returns_framed_success_and_reject() {
        let temporary = TempDir::new().expect("temporary signer directory");
        let socket_path = temporary.path().join("signer.sock");
        let watermark_path = temporary.path().join("watermark.sqlite3");
        let fixture = Fixture::new();
        let mut service = RemoteSignerService::open(fixture_service_config(
            &watermark_path,
            PurposePolicyV1::both(),
        ))
        .expect("open signer service");
        let socket_for_thread = socket_path.clone();
        let handle = thread::spawn(move || service.serve_unix_once(&socket_for_thread));
        for _ in 0..100 {
            if socket_path.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        let request = fixture_request(&fixture, "vote", 2, b"socket").unwrap();
        let mut stream = UnixStream::connect(&socket_path).expect("connect signer socket");
        let bytes = request.try_exact_bytes().unwrap();
        let length = u32::try_from(bytes.len()).unwrap();
        std::io::Write::write_all(&mut stream, &length.to_be_bytes()).unwrap();
        std::io::Write::write_all(&mut stream, &bytes).unwrap();
        let mut response_length = [0u8; 4];
        std::io::Read::read_exact(&mut stream, &mut response_length).unwrap();
        let response_length = u32::from_be_bytes(response_length) as usize;
        let mut response = vec![0; response_length];
        std::io::Read::read_exact(&mut stream, &mut response).unwrap();
        assert_eq!(response[0], FRAME_OK);
        drop(stream);
        handle
            .join()
            .expect("single-request signer thread")
            .unwrap();

        // A second process/connection with the exact request is a durable duplicate.
        let mut duplicate_service = RemoteSignerService::open(fixture_service_config(
            &watermark_path,
            PurposePolicyV1::both(),
        ))
        .expect("reopen duplicate signer");
        let socket_for_duplicate = socket_path.clone();
        let duplicate_handle =
            thread::spawn(move || duplicate_service.serve_unix_once(&socket_for_duplicate));
        for _ in 0..100 {
            if socket_path.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        let mut duplicate = UnixStream::connect(&socket_path).expect("connect duplicate");
        std::io::Write::write_all(&mut duplicate, &length.to_be_bytes()).unwrap();
        std::io::Write::write_all(&mut duplicate, &bytes).unwrap();
        let mut duplicate_response_length = [0u8; 4];
        std::io::Read::read_exact(&mut duplicate, &mut duplicate_response_length).unwrap();
        let duplicate_response_length = u32::from_be_bytes(duplicate_response_length) as usize;
        let mut rejection = vec![0; duplicate_response_length];
        std::io::Read::read_exact(&mut duplicate, &mut rejection).unwrap();
        assert_eq!(
            rejection,
            vec![
                FRAME_REJECT,
                ServiceRejectCodeV1::DuplicateRequest.as_byte()
            ]
        );
        drop(duplicate);
        duplicate_handle
            .join()
            .expect("duplicate signer thread")
            .unwrap();
    }
}
