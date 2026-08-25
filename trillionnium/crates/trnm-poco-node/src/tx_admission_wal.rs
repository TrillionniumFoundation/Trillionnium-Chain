//! Candidate node-owned durable pending-nonce admission authority.
//!
//! This module is deliberately feature-gated.  It is the first concrete
//! persistence boundary for the native PoCO transaction path, but it is not a
//! CheckTx implementation, an executor, a signer, or a broadcast loop.  The
//! default `trnm-poco-node` build does not compile this module and all package
//! production/activation flags remain false.
//!
//! The authority owns a SQLite database in WAL/FULL mode and an exclusive
//! sidecar lock.  A reservation row binds the complete key-free admission
//! metadata (`signer, nonce, tx digest, body digest, fee and resource limits`)
//! before the row is returned to the in-memory typed mempool.  Lifecycle
//! transitions are conditional and idempotent at the durable boundary:
//!
//! ```text
//! Reserved --handoff--> HandedOff --commit--> Committed
//!      \____________________release________________/  Released
//! ```
//!
//! A restart may retry an exact `Reserved` row.  A durable `HandedOff` row is
//! intentionally ambiguous because execution may have happened after the
//! handoff and before its commit acknowledgement; opening the authority then
//! fails closed.  A future node recovery owner must perform an application
//! readback before adding an explicit resolution API.  This module does not
//! guess, delete, or rewrite such rows.

#![cfg(feature = "tx-admission-wal")]

use std::{
    cell::RefCell,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
    rc::Rc,
    time::Duration,
};

use fs2::FileExt;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use trnm_application_tx_builder_v0::{BuiltCanonicalTxAdmissionViewV0, BuiltCanonicalTxV0};
use trnm_consensus_types::{BlockId, Height, StateRoot};
use trnm_mempool::{
    AdmissionReject, CanonicalSignerId, IngressClass, PendingNonceAdmission, PendingNonceAuthority,
    PendingNonceReservation, PendingNonceReservationState, SignedAdmissionHooks,
    SignedEnvelopeMetadata, SignedEnvelopeView, TypedAdmissionGate, TypedAdmitOutcome,
    DEFAULT_MAX_ADMISSION_BODY_BYTES,
};

/// This is a runnable composition seam only.  It does not imply a node
/// runtime or a production admission path.
pub const TX_ADMISSION_WAL_RUNTIME_COMPOSITION_V0: bool = true;
pub const TX_ADMISSION_WAL_PRODUCTION_ACTIVATION_V0: bool = false;

/// The node-owned boundary composes the typed builder view, the in-memory
/// admission gate, and this durable nonce authority.  It intentionally does
/// not expose a CheckTx, signer, executor, RPC, or broadcast operation.
pub const TX_ADMISSION_BOUNDARY_RUNTIME_COMPOSITION_V0: bool = true;
pub const TX_ADMISSION_BOUNDARY_PRODUCTION_ACTIVATION_V0: bool = false;
pub const TX_ADMISSION_BOUNDARY_CHECKTX_V0: bool = false;
/// The candidate owner now exposes a real, signature-checked CheckTx seam.
/// This is deliberately distinct from the production activation flag above:
/// it still requires an explicit node owner, durable WAL, and later execution
/// readback before it can be considered a production contract.
#[allow(dead_code)]
pub const TX_ADMISSION_BOUNDARY_CHECKTX_CANDIDATE_V0: bool = true;
/// An explicit node-owned signer identity resolver is required for the
/// candidate CheckTx seam. The resolver is composition-only and does not
/// imply that a production account registry or signer runtime is wired.
pub const TX_ADMISSION_BOUNDARY_SIGNER_RESOLVER_V0: bool = true;
pub const TX_ADMISSION_BOUNDARY_SIGNER_RESOLVER_PRODUCTION_V0: bool = false;
pub const TX_ADMISSION_BOUNDARY_SIGNING_V0: bool = false;
pub const TX_ADMISSION_BOUNDARY_BROADCAST_V0: bool = false;
/// A typed application/finality readback boundary exists behind the candidate
/// feature. It is not wired into CheckTx, broadcast, or production startup.
#[allow(dead_code)]
pub const TX_ADMISSION_BOUNDARY_COMMIT_RECEIPT_V0: bool = true;
#[allow(dead_code)]
pub const TX_ADMISSION_BOUNDARY_COMMIT_RECEIPT_PRODUCTION_V0: bool = false;

const SCHEMA_VERSION_V0: i64 = 1;
const WAL_DOMAIN_V0: &[u8] = b"trnm.poco-node.tx-admission-wal.v0";
const LOCK_SUFFIX_V0: &str = ".tx-admission.lock.v0";
const MAX_RESERVATION_ROWS_V0: usize = 1_000_000;

const STATE_RESERVED_V0: i64 = 0;
const STATE_HANDED_OFF_V0: i64 = 1;
const STATE_COMMITTED_V0: i64 = 2;
const STATE_RELEASED_V0: i64 = 3;
const COMMIT_RECEIPT_DOMAIN_V0: &[u8] = b"trnm.poco-node.tx-commit-receipt.v0";

type RawAdmissionRowV0 = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);

/// Coarse fail-closed errors for the candidate WAL.  The error text is not an
/// authority signal; callers should branch on the variant only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxAdmissionWalErrorV0 {
    Io,
    InvalidPath,
    InvalidNamespace,
    LockUnavailable,
    PathReplaced,
    Sqlite,
    SchemaMismatch,
    NamespaceMismatch,
    Malformed,
    TooLarge,
    Replay,
    ReservationConflict,
    AmbiguousHandoff,
    CommitReceiptMismatch,
    CommitReceiptConflict,
    CommitReadbackUnavailable,
}

impl fmt::Display for TxAdmissionWalErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Io => "transaction admission WAL I/O failed",
            Self::InvalidPath => "transaction admission WAL path is invalid",
            Self::InvalidNamespace => "transaction admission WAL namespace is invalid",
            Self::LockUnavailable => "transaction admission WAL is already owned",
            Self::PathReplaced => "transaction admission WAL path identity changed",
            Self::Sqlite => "transaction admission WAL SQLite operation failed",
            Self::SchemaMismatch => "transaction admission WAL schema mismatch",
            Self::NamespaceMismatch => "transaction admission WAL namespace mismatch",
            Self::Malformed => "transaction admission WAL row is malformed",
            Self::TooLarge => "transaction admission WAL row bound exceeded",
            Self::Replay => "transaction admission nonce or digest is already used",
            Self::ReservationConflict => "transaction admission reservation state conflict",
            Self::AmbiguousHandoff => {
                "transaction admission WAL has an unresolved handed-off reservation"
            }
            Self::CommitReceiptMismatch => "transaction commit receipt does not match admission",
            Self::CommitReceiptConflict => "transaction commit receipt conflicts with durable row",
            Self::CommitReadbackUnavailable => {
                "transaction commit requires an authenticated application/finality readback"
            }
        })
    }
}

impl Error for TxAdmissionWalErrorV0 {}

impl From<io::Error> for TxAdmissionWalErrorV0 {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathIdentityV0 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

#[cfg(unix)]
impl PathIdentityV0 {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn from_file(file: &File) -> Result<Self, TxAdmissionWalErrorV0> {
        let metadata = file.metadata().map_err(|_| TxAdmissionWalErrorV0::Io)?;
        Ok(Self::from_metadata(&metadata))
    }
}

#[cfg(not(unix))]
impl PathIdentityV0 {
    fn from_metadata(_metadata: &fs::Metadata) -> Self {
        Self {}
    }

    fn from_file(file: &File) -> Result<Self, TxAdmissionWalErrorV0> {
        file.metadata()
            .map_err(|_| TxAdmissionWalErrorV0::Io)
            .map(|_| Self {})
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AdmissionRecordV0 {
    signer: [u8; 32],
    nonce: u64,
    digest: [u8; 32],
    body_digest: [u8; 32],
    fee_limit: u128,
    max_gas: u64,
    max_bytes: u64,
}

impl AdmissionRecordV0 {
    fn from_metadata(metadata: &SignedEnvelopeMetadata) -> Result<Self, TxAdmissionWalErrorV0> {
        let signer = metadata.signer_id().as_bytes();
        let digest = metadata.digest().as_bytes();
        if signer == [0; 32] || digest == [0; 32] || metadata.body().is_empty() {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
        let body_digest = body_digest_v0(metadata.body());
        let limits = metadata.resource_limits();
        let body_len =
            u64::try_from(metadata.body().len()).map_err(|_| TxAdmissionWalErrorV0::TooLarge)?;
        if limits.max_gas == 0
            || limits.max_bytes == 0
            || body_len > limits.max_bytes
            || metadata.fee_limit() == 0
            || metadata.nonce() == 0
        {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
        Ok(Self {
            signer,
            nonce: metadata.nonce(),
            digest,
            body_digest,
            fee_limit: metadata.fee_limit(),
            max_gas: limits.max_gas,
            max_bytes: limits.max_bytes,
        })
    }
}

/// Candidate-only application/finality evidence for one admitted transaction.
/// The distinct consensus types prevent a legacy Comet AppHash or an
/// untyped height from being silently used as native commit evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeCommitReceiptEvidenceV0 {
    tx_digest: [u8; 32],
    block_id: BlockId,
    block_height: Height,
    state_root: StateRoot,
    receipt_digest: [u8; 32],
    finality_proof_digest: [u8; 32],
}

impl NativeCommitReceiptEvidenceV0 {
    /// Construct an unverified candidate statement. It becomes usable for a
    /// durable commit only after [`Self::verify_with`] returns the private
    /// type-state token.
    pub fn new(
        tx_digest: [u8; 32],
        block_id: BlockId,
        block_height: Height,
        state_root: StateRoot,
        receipt_digest: [u8; 32],
        finality_proof_digest: [u8; 32],
    ) -> Result<Self, TxAdmissionWalErrorV0> {
        if tx_digest == [0; 32]
            || block_id.is_zero()
            || block_height.get() == 0
            || state_root.is_zero()
            || receipt_digest == [0; 32]
            || finality_proof_digest == [0; 32]
        {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
        Ok(Self {
            tx_digest,
            block_id,
            block_height,
            state_root,
            receipt_digest,
            finality_proof_digest,
        })
    }

    pub const fn tx_digest(&self) -> [u8; 32] {
        self.tx_digest
    }

    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub const fn block_height(&self) -> Height {
        self.block_height
    }

    pub const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    pub const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }

    pub const fn finality_proof_digest(&self) -> [u8; 32] {
        self.finality_proof_digest
    }

    fn canonical_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(COMMIT_RECEIPT_DOMAIN_V0);
        hasher.update(self.tx_digest);
        hasher.update(self.block_id.as_bytes());
        hasher.update(self.block_height.get().to_be_bytes());
        hasher.update(self.state_root.as_bytes());
        hasher.update(self.receipt_digest);
        hasher.update(self.finality_proof_digest);
        hasher.finalize().into()
    }

    /// Authenticate the statement against the exact admitted metadata and an
    /// importer/application-owned verifier. There is intentionally no default
    /// verifier: shape-valid bytes alone never authorize a durable commit.
    pub fn verify_with<V: NativeCommitReceiptVerifierV0>(
        &self,
        metadata: &SignedEnvelopeMetadata,
        verifier: &V,
    ) -> Result<VerifiedNativeCommitReceiptV0, TxAdmissionWalErrorV0> {
        if self.tx_digest != metadata.digest().as_bytes() {
            return Err(TxAdmissionWalErrorV0::CommitReceiptMismatch);
        }
        verifier.verify_application_and_finality_v0(metadata, self)?;
        Ok(VerifiedNativeCommitReceiptV0 {
            evidence: *self,
            commitment: self.canonical_commitment(),
        })
    }
}

/// Explicit verifier boundary for the application store and native PoCO
/// finality proof. A production implementation must read back the exact
/// transaction/result from durable application state and independently verify
/// the finalized block/QC before returning `Ok(())`.
pub trait NativeCommitReceiptVerifierV0 {
    fn verify_application_and_finality_v0(
        &self,
        metadata: &SignedEnvelopeMetadata,
        evidence: &NativeCommitReceiptEvidenceV0,
    ) -> Result<(), TxAdmissionWalErrorV0>;
}

/// Node-owned mapping from the authenticated transaction envelope to the
/// canonical replay identity used by the pending-nonce authority.
///
/// The resolver is intentionally installed when the node boundary is opened,
/// rather than supplied alongside each transaction. A caller-provided
/// CanonicalSignerId is therefore only an assertion checked against this
/// owner; it can never choose the WAL replay key. Implementations must read
/// an authenticated account/key registry (or an equivalent remote authority)
/// and must not trust an unverified request parameter.
pub trait CanonicalSignerIdentityResolverV0: fmt::Debug {
    fn resolve_canonical_signer_id_v0(
        &self,
        transaction: &BuiltCanonicalTxV0,
    ) -> Result<CanonicalSignerId, AdmissionReject>;
}

/// Type-state token returned only after the explicit verifier succeeds. The
/// token is still candidate-only: it does not activate a node or provide a
/// network/broadcast capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedNativeCommitReceiptV0 {
    evidence: NativeCommitReceiptEvidenceV0,
    commitment: [u8; 32],
}

impl VerifiedNativeCommitReceiptV0 {
    pub const fn evidence(&self) -> &NativeCommitReceiptEvidenceV0 {
        &self.evidence
    }

    pub const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }
}

/// Strict CheckTx hooks for the canonical builder carrier.
///
/// The builder has already produced byte-stable inner/outer envelopes, but a
/// node must still authenticate the exact envelope at ingress time.  Keeping
/// this check in the node owner closes the common gap where a caller validates
/// a builder result once and later admits a different time/chain context.  No
/// private key crosses this hook: `validate_at_strict` verifies the Ed25519
/// signature carried by the envelope.
#[derive(Debug, Clone)]
struct CanonicalCheckTxHooksV0 {
    chain_id: String,
    now_unix_ms: u64,
}

impl<'a> SignedAdmissionHooks<BuiltCanonicalTxAdmissionViewV0<'a>> for CanonicalCheckTxHooksV0 {
    fn verify_signature(
        &mut self,
        envelope: &BuiltCanonicalTxAdmissionViewV0<'a>,
        metadata: &SignedEnvelopeMetadata,
    ) -> Result<(), AdmissionReject> {
        let transaction = envelope.transaction();
        transaction
            .envelope()
            .validate_at_strict(&self.chain_id, self.now_unix_ms)
            .map_err(|_| AdmissionReject::SignatureRejected)?;
        if transaction.protocol_tx_hash_v1() != metadata.digest().as_bytes()
            || transaction.exact_inner_bytes() != metadata.body()
        {
            return Err(AdmissionReject::SignatureRejected);
        }
        Ok(())
    }

    fn recheck(&mut self, metadata: &SignedEnvelopeMetadata) -> Result<(), AdmissionReject> {
        if metadata.nonce() == 0
            || metadata.fee_limit() == 0
            || metadata.resource_limits().max_gas == 0
        {
            return Err(AdmissionReject::RecheckFailed);
        }
        Ok(())
    }
}

fn body_digest_v0(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(WAL_DOMAIN_V0);
    hasher.update(b"body\0");
    hasher.update((body.len() as u64).to_be_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

fn lock_path_v0(path: &Path) -> Result<PathBuf, TxAdmissionWalErrorV0> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(TxAdmissionWalErrorV0::InvalidPath)?;
    Ok(path
        .parent()
        .ok_or(TxAdmissionWalErrorV0::InvalidPath)?
        .join(format!(".{name}{LOCK_SUFFIX_V0}")))
}

fn validate_parent_v0(path: &Path) -> Result<&Path, TxAdmissionWalErrorV0> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(TxAdmissionWalErrorV0::InvalidPath);
    }
    let parent = path.parent().ok_or(TxAdmissionWalErrorV0::InvalidPath)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| TxAdmissionWalErrorV0::InvalidPath)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(TxAdmissionWalErrorV0::InvalidPath);
    }
    let canonical = fs::canonicalize(parent).map_err(|_| TxAdmissionWalErrorV0::InvalidPath)?;
    if canonical != parent {
        return Err(TxAdmissionWalErrorV0::InvalidPath);
    }
    Ok(parent)
}

fn ensure_regular_db_v0(path: &Path) -> Result<PathIdentityV0, TxAdmissionWalErrorV0> {
    validate_parent_v0(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || !is_private_mode_v0(&metadata)
            {
                return Err(TxAdmissionWalErrorV0::InvalidPath);
            }
            Ok(PathIdentityV0::from_metadata(&metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).read(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
                options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            }
            let file = options.open(path).map_err(|_| TxAdmissionWalErrorV0::Io)?;
            file.sync_all().map_err(|_| TxAdmissionWalErrorV0::Io)?;
            drop(file);
            File::open(path.parent().ok_or(TxAdmissionWalErrorV0::InvalidPath)?)
                .map_err(|_| TxAdmissionWalErrorV0::Io)?
                .sync_data()
                .map_err(|_| TxAdmissionWalErrorV0::Io)?;
            let metadata = fs::symlink_metadata(path).map_err(|_| TxAdmissionWalErrorV0::Io)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || !is_private_mode_v0(&metadata)
            {
                return Err(TxAdmissionWalErrorV0::InvalidPath);
            }
            Ok(PathIdentityV0::from_metadata(&metadata))
        }
        Err(_) => Err(TxAdmissionWalErrorV0::Io),
    }
}

fn open_lock_v0(path: &Path) -> Result<(Rc<File>, PathBuf, PathIdentityV0), TxAdmissionWalErrorV0> {
    let lock_path = lock_path_v0(path)?;
    if let Ok(metadata) = fs::symlink_metadata(&lock_path) {
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || !is_private_mode_v0(&metadata)
        {
            return Err(TxAdmissionWalErrorV0::InvalidPath);
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options
        .open(&lock_path)
        .map_err(|_| TxAdmissionWalErrorV0::Io)?;
    file.try_lock_exclusive()
        .map_err(|_| TxAdmissionWalErrorV0::LockUnavailable)?;
    let lock_identity = PathIdentityV0::from_file(&file)?;
    ensure_identity_v0(&lock_path, lock_identity)?;
    Ok((Rc::new(file), lock_path, lock_identity))
}

#[cfg(unix)]
fn is_private_mode_v0(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn is_private_mode_v0(_metadata: &fs::Metadata) -> bool {
    true
}

fn ensure_identity_v0(path: &Path, expected: PathIdentityV0) -> Result<(), TxAdmissionWalErrorV0> {
    let metadata = fs::symlink_metadata(path).map_err(|_| TxAdmissionWalErrorV0::PathReplaced)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || PathIdentityV0::from_metadata(&metadata) != expected
    {
        return Err(TxAdmissionWalErrorV0::PathReplaced);
    }
    Ok(())
}

fn ensure_open_lock_identity_v0(
    path: &Path,
    expected: PathIdentityV0,
    lock: &File,
) -> Result<(), TxAdmissionWalErrorV0> {
    if PathIdentityV0::from_file(lock).map_err(|_| TxAdmissionWalErrorV0::PathReplaced)? != expected
    {
        return Err(TxAdmissionWalErrorV0::PathReplaced);
    }
    ensure_identity_v0(path, expected)
}

fn sqlite_error(_: rusqlite::Error) -> TxAdmissionWalErrorV0 {
    TxAdmissionWalErrorV0::Sqlite
}

fn map_insert_error_v0(error: rusqlite::Error) -> TxAdmissionWalErrorV0 {
    if error.sqlite_error_code() == Some(rusqlite::ffi::ErrorCode::ConstraintViolation) {
        TxAdmissionWalErrorV0::Replay
    } else {
        sqlite_error(error)
    }
}

fn to_blob_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn to_blob_u128(value: u128) -> [u8; 16] {
    value.to_be_bytes()
}

fn decode_fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], TxAdmissionWalErrorV0> {
    value
        .try_into()
        .map_err(|_| TxAdmissionWalErrorV0::Malformed)
}

fn decode_state(value: i64) -> Result<i64, TxAdmissionWalErrorV0> {
    match value {
        STATE_RESERVED_V0 | STATE_HANDED_OFF_V0 | STATE_COMMITTED_V0 | STATE_RELEASED_V0 => {
            Ok(value)
        }
        _ => Err(TxAdmissionWalErrorV0::Malformed),
    }
}

fn read_row_v0(
    connection: &Connection,
    namespace: [u8; 32],
    signer: [u8; 32],
    nonce: u64,
) -> Result<Option<(AdmissionRecordV0, i64)>, TxAdmissionWalErrorV0> {
    let nonce_blob = to_blob_u64(nonce);
    let raw: Option<RawAdmissionRowV0> = connection
        .query_row(
            "SELECT digest, body_digest, fee_limit, max_gas, max_bytes, state
             FROM pending_nonce
             WHERE namespace = ?1 AND signer = ?2 AND nonce = ?3",
            params![
                namespace.as_slice(),
                signer.as_slice(),
                nonce_blob.as_slice()
            ],
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
        .map_err(sqlite_error)?;
    raw.map_or(
        Ok(None),
        |(digest, body_digest, fee_limit, max_gas, max_bytes, state)| {
            Ok(Some((
                AdmissionRecordV0 {
                    signer,
                    nonce,
                    digest: decode_fixed::<32>(digest)?,
                    body_digest: decode_fixed::<32>(body_digest)?,
                    fee_limit: u128::from_be_bytes(decode_fixed::<16>(fee_limit)?),
                    max_gas: u64::from_be_bytes(decode_fixed::<8>(max_gas)?),
                    max_bytes: u64::from_be_bytes(decode_fixed::<8>(max_bytes)?),
                },
                decode_state(state)?,
            )))
        },
    )
}

fn read_state_by_digest_v0(
    connection: &Connection,
    namespace: [u8; 32],
    digest: [u8; 32],
) -> Result<Option<(Vec<u8>, i64)>, TxAdmissionWalErrorV0> {
    let raw: Option<(Vec<u8>, i64)> = connection
        .query_row(
            "SELECT nonce, state FROM pending_nonce
             WHERE namespace = ?1 AND digest = ?2",
            params![namespace.as_slice(), digest.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map_or(Ok(None), |(nonce, state)| {
        Ok(Some((nonce, decode_state(state)?)))
    })
}

fn row_matches_v0(row: AdmissionRecordV0, expected: AdmissionRecordV0) -> bool {
    row == expected
}

fn read_receipt_commitment_v0(
    connection: &Connection,
    namespace: [u8; 32],
    signer: [u8; 32],
    nonce: u64,
) -> Result<Option<[u8; 32]>, TxAdmissionWalErrorV0> {
    let nonce_blob = to_blob_u64(nonce);
    let raw: Option<Vec<u8>> = connection
        .query_row(
            "SELECT commitment FROM tx_commit_receipt_v0
             WHERE namespace = ?1 AND signer = ?2 AND nonce = ?3",
            params![
                namespace.as_slice(),
                signer.as_slice(),
                nonce_blob.as_slice()
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    raw.map_or(Ok(None), |value| decode_fixed::<32>(value).map(Some))
}

/// A node-owned SQLite pending-nonce authority.
///
/// The authority is intentionally not `Clone` and its lock is held for its
/// entire lifetime (also by outstanding reservation tokens).  It is therefore
/// safe only as a single local owner; cross-process attempts fail at open.
pub struct SqlitePendingNonceAuthorityV0 {
    connection: Rc<RefCell<Connection>>,
    lock: Rc<File>,
    lock_path: PathBuf,
    lock_identity: PathIdentityV0,
    path: PathBuf,
    path_identity: PathIdentityV0,
    namespace: [u8; 32],
}

/// The candidate node-owned transaction-admission boundary.
///
/// A canonical builder supplies a [`SignedEnvelopeView`] (the current builder
/// crate exposes `BuiltCanonicalTxAdmissionViewV0`).  The node owner supplies
/// read-only signature/recheck hooks, and this boundary then performs the
/// following ordered, candidate-only operation:
///
/// ```text
/// typed builder view -> canonical metadata -> durable reserve
///     -> ready item -> handoff -> commit/release
/// ```
///
/// The returned [`PendingNonceAdmission`] owns the durable lifecycle token.
/// Dropping an unresolved item releases its reservation; callers should use
/// `handoff` followed by `commit`, or explicitly `release`/`cancel`.
///
/// This type is deliberately not a node runtime.  It does not call a signer,
/// execute a transaction, invoke CheckTx, publish an RPC result, or broadcast
/// bytes.  Its feature and package activation flags remain false.
#[derive(Debug)]
pub struct NodeOwnedTxAdmissionBoundaryV0 {
    gate: TypedAdmissionGate,
    authority: SqlitePendingNonceAuthorityV0,
    signer_resolver: Option<Box<dyn CanonicalSignerIdentityResolverV0>>,
}

impl NodeOwnedTxAdmissionBoundaryV0 {
    /// Open the node-owned WAL and create an in-memory typed admission gate.
    ///
    /// `namespace` must be bound by the future chain/epoch owner; this method
    /// does not infer it from a transaction or a local path.
    pub fn open(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        total_capacity: usize,
        critical_reserve: usize,
        max_body_bytes: u64,
    ) -> Result<Self, TxAdmissionWalErrorV0> {
        Self::open_inner(path, namespace, total_capacity, critical_reserve, max_body_bytes, None)
    }

    fn open_inner(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        total_capacity: usize,
        critical_reserve: usize,
        max_body_bytes: u64,
        signer_resolver: Option<Box<dyn CanonicalSignerIdentityResolverV0>>,
    ) -> Result<Self, TxAdmissionWalErrorV0> {
        Ok(Self {
            gate: TypedAdmissionGate::new(total_capacity, critical_reserve, max_body_bytes),
            authority: SqlitePendingNonceAuthorityV0::open(path, namespace)?,
            signer_resolver,
        })
    }

    /// Open a boundary with the immutable signer/account resolver owned by the
    /// node admission authority. Candidate CheckTx calls fail closed until
    /// this constructor is used; generic typed admission remains available via
    /// admit_signed_candidate.
    pub fn open_with_signer_resolver<R>(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        total_capacity: usize,
        critical_reserve: usize,
        max_body_bytes: u64,
        resolver: R,
    ) -> Result<Self, TxAdmissionWalErrorV0>
    where
        R: CanonicalSignerIdentityResolverV0 + 'static,
    {
        Self::open_inner(
            path,
            namespace,
            total_capacity,
            critical_reserve,
            max_body_bytes,
            Some(Box::new(resolver)),
        )
    }

    /// Open with the typed mempool's canonical default body bound.
    pub fn with_default_body_limit(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        total_capacity: usize,
        critical_reserve: usize,
    ) -> Result<Self, TxAdmissionWalErrorV0> {
        Self::open(
            path,
            namespace,
            total_capacity,
            critical_reserve,
            DEFAULT_MAX_ADMISSION_BODY_BYTES,
        )
    }

    /// Open with the canonical builder body bound and an authority-owned
    /// signer/account resolver.
    pub fn with_default_body_limit_and_signer_resolver<R>(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        total_capacity: usize,
        critical_reserve: usize,
        resolver: R,
    ) -> Result<Self, TxAdmissionWalErrorV0>
    where
        R: CanonicalSignerIdentityResolverV0 + 'static,
    {
        Self::open_with_signer_resolver(
            path,
            namespace,
            total_capacity,
            critical_reserve,
            DEFAULT_MAX_ADMISSION_BODY_BYTES,
            resolver,
        )
    }

    pub const fn namespace(&self) -> [u8; 32] {
        self.authority.namespace()
    }

    /// Admit one already-authenticated canonical view into the candidate
    /// queue.  This is an admission-boundary operation, not CheckTx.
    pub fn admit_signed_candidate<E, H>(
        &mut self,
        envelope: &E,
        class: IngressClass,
        hooks: &mut H,
    ) -> TypedAdmitOutcome
    where
        E: SignedEnvelopeView + ?Sized,
        H: SignedAdmissionHooks<E>,
    {
        self.gate
            .admit_signed_with_pending_nonce(envelope, class, hooks, &mut self.authority)
    }

    fn resolve_signer_id_v0(
        &self,
        transaction: &BuiltCanonicalTxV0,
    ) -> Result<CanonicalSignerId, AdmissionReject> {
        self.signer_resolver
            .as_ref()
            .ok_or(AdmissionReject::SignerIdentityUnavailable)?
            .resolve_canonical_signer_id_v0(transaction)
    }

    fn check_tx_candidate_resolved_v0(
        &mut self,
        transaction: &BuiltCanonicalTxV0,
        signer_id: CanonicalSignerId,
        class: IngressClass,
        chain_id: &str,
        now_unix_ms: u64,
    ) -> TypedAdmitOutcome {
        let view = transaction.admission_view_v0(signer_id);
        let mut hooks = CanonicalCheckTxHooksV0 {
            chain_id: chain_id.to_owned(),
            now_unix_ms,
        };
        self.admit_signed_candidate(&view, class, &mut hooks)
    }

    /// Run the concrete candidate CheckTx path for one builder-produced
    /// canonical transaction using the resolver installed by the node owner.
    /// No caller-supplied signer identity is accepted by this API.
    pub fn check_tx_candidate_with_resolver(
        &mut self,
        transaction: &BuiltCanonicalTxV0,
        class: IngressClass,
        chain_id: &str,
        now_unix_ms: u64,
    ) -> TypedAdmitOutcome {
        let signer_id = match self.resolve_signer_id_v0(transaction) {
            Ok(signer_id) => signer_id,
            Err(reason) => return TypedAdmitOutcome::Rejected(reason),
        };
        self.check_tx_candidate_resolved_v0(
            transaction,
            signer_id,
            class,
            chain_id,
            now_unix_ms,
        )
    }

    /// Compatibility assertion for callers migrating from the old API. The
    /// supplied identity is never used as authority: it must equal the
    /// resolver-owned result or the candidate is rejected before WAL access.
    ///
    /// The operation authenticates the exact signed outer envelope against the
    /// supplied chain/time context, re-checks the builder's inner bytes and
    /// protocol hash, and only then reserves `(canonical signer, nonce)` in the
    /// durable WAL.  It therefore closes the builder -> signature-check ->
    /// pending-nonce boundary without pretending to execute or broadcast the
    /// transaction.  `TX_ADMISSION_BOUNDARY_CHECKTX_V0` remains false because
    /// this is still an explicitly feature-gated candidate owner.
    pub fn check_tx_candidate(
        &mut self,
        transaction: &BuiltCanonicalTxV0,
        signer_id: CanonicalSignerId,
        class: IngressClass,
        chain_id: &str,
        now_unix_ms: u64,
    ) -> TypedAdmitOutcome {
        let resolved = match self.resolve_signer_id_v0(transaction) {
            Ok(resolved) => resolved,
            Err(reason) => return TypedAdmitOutcome::Rejected(reason),
        };
        if resolved != signer_id {
            return TypedAdmitOutcome::Rejected(AdmissionReject::CanonicalValidationFailed);
        }
        self.check_tx_candidate_resolved_v0(
            transaction,
            resolved,
            class,
            chain_id,
            now_unix_ms,
        )
    }

    /// Return the next item with its node-owned handoff/commit/release token.
    pub fn pop_ready_with_lifecycle(&mut self) -> Option<PendingNonceAdmission> {
        self.gate.pop_ready_with_lifecycle()
    }

    /// Commit a handed-off candidate only after an application/finality
    /// verifier has produced the private receipt token. The durable receipt
    /// write and WAL state transition are one SQLite transaction; resolving
    /// the erased in-memory token afterwards is a separate fail-closed step.
    pub fn commit_candidate_with_receipt(
        &mut self,
        admission: &mut PendingNonceAdmission,
        receipt: &VerifiedNativeCommitReceiptV0,
    ) -> Result<(), AdmissionReject> {
        // `PendingNonceAdmission` is intentionally opaque, but it can still
        // be passed across two local boundary values. Require the
        // process-local authority binding before touching this WAL; otherwise
        // boundary A could persist a receipt while boundary B commits the
        // token's reservation, leaving split durable state.
        if admission.owner_binding() != Some(self.authority.owner_binding()) {
            return Err(AdmissionReject::InconsistentState);
        }
        if admission.reservation_state()? != PendingNonceReservationState::HandedOff {
            return Err(AdmissionReject::ReservationStateConflict);
        }
        self.authority
            .commit_handed_off_with_receipt(admission.metadata(), receipt)
            .map_err(map_reject_v0)?;
        admission.commit()
    }

    pub fn queued_counts(&self) -> (usize, usize, usize) {
        self.gate.queued_counts()
    }

    /// Retained rows include committed/released replay tombstones.  No GC API
    /// is exposed until an authenticated retention policy exists.
    pub fn retained_rows(&self) -> Result<usize, TxAdmissionWalErrorV0> {
        self.authority.retained_rows()
    }
}

impl fmt::Debug for SqlitePendingNonceAuthorityV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqlitePendingNonceAuthorityV0")
            .field("path", &self.path)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl SqlitePendingNonceAuthorityV0 {
    /// Open or initialize a namespace-bound WAL database.
    pub fn open(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
    ) -> Result<Self, TxAdmissionWalErrorV0> {
        if namespace == [0; 32] {
            return Err(TxAdmissionWalErrorV0::InvalidNamespace);
        }
        let path = path.as_ref().to_path_buf();
        let path_identity = ensure_regular_db_v0(&path)?;
        let (lock, lock_path, lock_identity) = open_lock_v0(&path)?;
        ensure_identity_v0(&path, path_identity)?;
        ensure_open_lock_identity_v0(&lock_path, lock_identity, &lock)?;
        let connection = Connection::open(&path).map_err(sqlite_error)?;
        // The first identity check protects the name-to-inode transition around
        // SQLite open. A second fence below catches a replacement which raced
        // that open before any schema/WAL write is attempted.
        ensure_identity_v0(&path, path_identity)?;
        ensure_open_lock_identity_v0(&lock_path, lock_identity, &lock)?;
        connection
            .busy_timeout(Duration::from_millis(750))
            .map_err(sqlite_error)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA foreign_keys = ON;
                 PRAGMA wal_autocheckpoint = 1;
                 CREATE TABLE IF NOT EXISTS tx_admission_meta (
                     singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                     schema_version INTEGER NOT NULL,
                     namespace BLOB NOT NULL CHECK(length(namespace) = 32)
                 );
                 CREATE TABLE IF NOT EXISTS pending_nonce (
                     namespace BLOB NOT NULL CHECK(length(namespace) = 32),
                     signer BLOB NOT NULL CHECK(length(signer) = 32),
                     nonce BLOB NOT NULL CHECK(length(nonce) = 8),
                     digest BLOB NOT NULL CHECK(length(digest) = 32),
                     body_digest BLOB NOT NULL CHECK(length(body_digest) = 32),
                     fee_limit BLOB NOT NULL CHECK(length(fee_limit) = 16),
                     max_gas BLOB NOT NULL CHECK(length(max_gas) = 8),
                     max_bytes BLOB NOT NULL CHECK(length(max_bytes) = 8),
                     state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3)),
                     PRIMARY KEY(namespace, signer, nonce),
                     UNIQUE(namespace, digest)
                 );
                 CREATE TABLE IF NOT EXISTS tx_commit_receipt_v0 (
                     namespace BLOB NOT NULL CHECK(length(namespace) = 32),
                     signer BLOB NOT NULL CHECK(length(signer) = 32),
                     nonce BLOB NOT NULL CHECK(length(nonce) = 8),
                     tx_digest BLOB NOT NULL CHECK(length(tx_digest) = 32),
                     block_id BLOB NOT NULL CHECK(length(block_id) = 32),
                     block_height BLOB NOT NULL CHECK(length(block_height) = 8),
                     state_root BLOB NOT NULL CHECK(length(state_root) = 32),
                     receipt_digest BLOB NOT NULL CHECK(length(receipt_digest) = 32),
                     finality_proof_digest BLOB NOT NULL CHECK(length(finality_proof_digest) = 32),
                     commitment BLOB NOT NULL CHECK(length(commitment) = 32),
                     PRIMARY KEY(namespace, signer, nonce),
                     UNIQUE(namespace, tx_digest)
                 );
                 PRAGMA user_version = 1;",
            )
            .map_err(sqlite_error)?;
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(sqlite_error)?;
        let synchronous: i64 = connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .map_err(sqlite_error)?;
        if !journal_mode.eq_ignore_ascii_case("wal") || synchronous != 2 {
            return Err(TxAdmissionWalErrorV0::Sqlite);
        }
        ensure_identity_v0(&path, path_identity)?;
        ensure_open_lock_identity_v0(&lock_path, lock_identity, &lock)?;
        let persisted: Option<(i64, Vec<u8>)> = connection
            .query_row(
                "SELECT schema_version, namespace FROM tx_admission_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        match persisted {
            Some((schema, stored_namespace)) => {
                if schema != SCHEMA_VERSION_V0 {
                    return Err(TxAdmissionWalErrorV0::SchemaMismatch);
                }
                if stored_namespace.as_slice() != namespace {
                    return Err(TxAdmissionWalErrorV0::NamespaceMismatch);
                }
            }
            None => {
                connection
                    .execute(
                        "INSERT INTO tx_admission_meta(singleton, schema_version, namespace)
                         VALUES (1, ?1, ?2)",
                        params![SCHEMA_VERSION_V0, namespace.as_slice()],
                    )
                    .map_err(sqlite_error)?;
                // The metadata insert is part of the same FULL-synchronous
                // SQLite transaction boundary as subsequent reservations. Do
                // not issue a standalone checkpoint here: `execute_batch`
                // rejects PRAGMAs which return rows, and SQLite owns WAL
                // checkpoint scheduling after this point.
            }
        }
        let handed_off: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pending_nonce WHERE namespace = ?1 AND state = ?2",
                params![namespace.as_slice(), STATE_HANDED_OFF_V0],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if handed_off != 0 {
            return Err(TxAdmissionWalErrorV0::AmbiguousHandoff);
        }
        let row_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pending_nonce WHERE namespace = ?1",
                params![namespace.as_slice()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let row_count = usize::try_from(row_count).map_err(|_| TxAdmissionWalErrorV0::TooLarge)?;
        if row_count > MAX_RESERVATION_ROWS_V0 {
            return Err(TxAdmissionWalErrorV0::TooLarge);
        }
        ensure_identity_v0(&path, path_identity)?;
        ensure_open_lock_identity_v0(&lock_path, lock_identity, &lock)?;
        Ok(Self {
            connection: Rc::new(RefCell::new(connection)),
            lock,
            lock_path,
            lock_identity,
            path,
            path_identity,
            namespace,
        })
    }

    pub const fn namespace(&self) -> [u8; 32] {
        self.namespace
    }

    /// Opaque process-local identity for this live SQLite authority. It is
    /// used only to prevent a lifecycle token from being committed through a
    /// different boundary instance; it is not a persisted or consensus ID.
    fn owner_binding(&self) -> u64 {
        Rc::as_ptr(&self.connection) as usize as u64
    }

    /// Number of rows retained for this namespace.  Released/committed rows
    /// are deliberately retained as replay tombstones until a future,
    /// authenticated GC policy exists.
    pub fn retained_rows(&self) -> Result<usize, TxAdmissionWalErrorV0> {
        self.ensure_identity()?;
        let connection = self
            .connection
            .try_borrow()
            .map_err(|_| TxAdmissionWalErrorV0::Sqlite)?;
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pending_nonce WHERE namespace = ?1",
                params![self.namespace.as_slice()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        drop(connection);
        self.ensure_identity()?;
        usize::try_from(count).map_err(|_| TxAdmissionWalErrorV0::Malformed)
    }

    fn ensure_identity(&self) -> Result<(), TxAdmissionWalErrorV0> {
        ensure_identity_v0(&self.path, self.path_identity)?;
        ensure_open_lock_identity_v0(&self.lock_path, self.lock_identity, &self.lock)
    }

    fn reserve_record<E: ?Sized>(
        &mut self,
        _envelope: &E,
        metadata: &SignedEnvelopeMetadata,
    ) -> Result<SqlitePendingNonceReservationV0, TxAdmissionWalErrorV0> {
        self.ensure_identity()?;
        let expected = AdmissionRecordV0::from_metadata(metadata)?;
        let mut connection = self
            .connection
            .try_borrow_mut()
            .map_err(|_| TxAdmissionWalErrorV0::Sqlite)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some((existing, state)) = read_row_v0(
            &transaction,
            self.namespace,
            expected.signer,
            expected.nonce,
        )? {
            if !row_matches_v0(existing, expected) {
                return Err(TxAdmissionWalErrorV0::Replay);
            }
            if state != STATE_RESERVED_V0 {
                return Err(TxAdmissionWalErrorV0::Replay);
            }
            transaction.commit().map_err(sqlite_error)?;
            self.ensure_identity()?;
            return Ok(SqlitePendingNonceReservationV0 {
                connection: Rc::clone(&self.connection),
                _lock: Rc::clone(&self.lock),
                lock_path: self.lock_path.clone(),
                lock_identity: self.lock_identity,
                path: self.path.clone(),
                path_identity: self.path_identity,
                namespace: self.namespace,
                record: expected,
                state: STATE_RESERVED_V0,
            });
        }
        if read_state_by_digest_v0(&transaction, self.namespace, expected.digest)?.is_some() {
            return Err(TxAdmissionWalErrorV0::Replay);
        }
        let row_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM pending_nonce WHERE namespace = ?1",
                params![self.namespace.as_slice()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let row_count = usize::try_from(row_count).map_err(|_| TxAdmissionWalErrorV0::TooLarge)?;
        if row_count >= MAX_RESERVATION_ROWS_V0 {
            return Err(TxAdmissionWalErrorV0::TooLarge);
        }
        let nonce_blob = to_blob_u64(expected.nonce);
        let fee_blob = to_blob_u128(expected.fee_limit);
        let gas_blob = to_blob_u64(expected.max_gas);
        let bytes_blob = to_blob_u64(expected.max_bytes);
        transaction
            .execute(
                "INSERT INTO pending_nonce
                 (namespace, signer, nonce, digest, body_digest, fee_limit,
                  max_gas, max_bytes, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    self.namespace.as_slice(),
                    expected.signer.as_slice(),
                    nonce_blob.as_slice(),
                    expected.digest.as_slice(),
                    expected.body_digest.as_slice(),
                    fee_blob.as_slice(),
                    gas_blob.as_slice(),
                    bytes_blob.as_slice(),
                    STATE_RESERVED_V0,
                ],
            )
            .map_err(map_insert_error_v0)?;
        transaction.commit().map_err(sqlite_error)?;
        self.ensure_identity()?;
        Ok(SqlitePendingNonceReservationV0 {
            connection: Rc::clone(&self.connection),
            _lock: Rc::clone(&self.lock),
            lock_path: self.lock_path.clone(),
            lock_identity: self.lock_identity,
            path: self.path.clone(),
            path_identity: self.path_identity,
            namespace: self.namespace,
            record: expected,
            state: STATE_RESERVED_V0,
        })
    }

    /// Persist an authenticated application/finality readback and advance the
    /// exact handed-off row in one SQLite transaction. This method is a
    /// candidate boundary; it does not invoke execution, networking, signing,
    /// or broadcast. A caller must still resolve the in-memory admission token
    /// after this durable operation returns.
    pub fn commit_handed_off_with_receipt(
        &mut self,
        metadata: &SignedEnvelopeMetadata,
        receipt: &VerifiedNativeCommitReceiptV0,
    ) -> Result<(), TxAdmissionWalErrorV0> {
        self.ensure_identity()?;
        let expected = AdmissionRecordV0::from_metadata(metadata)?;
        if receipt.evidence.tx_digest != expected.digest {
            return Err(TxAdmissionWalErrorV0::CommitReceiptMismatch);
        }
        let mut connection = self
            .connection
            .try_borrow_mut()
            .map_err(|_| TxAdmissionWalErrorV0::Sqlite)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let Some((existing, state)) = read_row_v0(
            &transaction,
            self.namespace,
            expected.signer,
            expected.nonce,
        )?
        else {
            return Err(TxAdmissionWalErrorV0::CommitReceiptMismatch);
        };
        if !row_matches_v0(existing, expected) {
            return Err(TxAdmissionWalErrorV0::CommitReceiptMismatch);
        }
        if state == STATE_COMMITTED_V0 {
            let Some(commitment) = read_receipt_commitment_v0(
                &transaction,
                self.namespace,
                expected.signer,
                expected.nonce,
            )?
            else {
                return Err(TxAdmissionWalErrorV0::CommitReceiptConflict);
            };
            if commitment != receipt.commitment {
                return Err(TxAdmissionWalErrorV0::CommitReceiptConflict);
            }
            transaction.commit().map_err(sqlite_error)?;
            self.ensure_identity()?;
            return Ok(());
        }
        if state != STATE_HANDED_OFF_V0 {
            return Err(TxAdmissionWalErrorV0::ReservationConflict);
        }
        if read_receipt_commitment_v0(
            &transaction,
            self.namespace,
            expected.signer,
            expected.nonce,
        )?
        .is_some()
        {
            return Err(TxAdmissionWalErrorV0::CommitReceiptConflict);
        }
        let evidence = receipt.evidence;
        let nonce_blob = to_blob_u64(expected.nonce);
        let height_blob = to_blob_u64(evidence.block_height.get());
        transaction
            .execute(
                "INSERT INTO tx_commit_receipt_v0
                 (namespace, signer, nonce, tx_digest, block_id, block_height,
                  state_root, receipt_digest, finality_proof_digest, commitment)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    self.namespace.as_slice(),
                    expected.signer.as_slice(),
                    nonce_blob.as_slice(),
                    evidence.tx_digest.as_slice(),
                    evidence.block_id.as_bytes(),
                    height_blob.as_slice(),
                    evidence.state_root.as_bytes(),
                    evidence.receipt_digest.as_slice(),
                    evidence.finality_proof_digest.as_slice(),
                    receipt.commitment.as_slice(),
                ],
            )
            .map_err(|error| match error.sqlite_error_code() {
                Some(rusqlite::ffi::ErrorCode::ConstraintViolation) => {
                    TxAdmissionWalErrorV0::CommitReceiptConflict
                }
                _ => sqlite_error(error),
            })?;
        let changed = transaction
            .execute(
                "UPDATE pending_nonce SET state = ?1
                 WHERE namespace = ?2 AND signer = ?3 AND nonce = ?4 AND state = ?5",
                params![
                    STATE_COMMITTED_V0,
                    self.namespace.as_slice(),
                    expected.signer.as_slice(),
                    nonce_blob.as_slice(),
                    STATE_HANDED_OFF_V0,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(TxAdmissionWalErrorV0::ReservationConflict);
        }
        transaction.commit().map_err(sqlite_error)?;
        self.ensure_identity()?;
        Ok(())
    }
}

impl<E: ?Sized> PendingNonceAuthority<E> for SqlitePendingNonceAuthorityV0 {
    fn reserve_pending_nonce(
        &mut self,
        envelope: &E,
        metadata: &SignedEnvelopeMetadata,
    ) -> Result<Box<dyn PendingNonceReservation>, AdmissionReject> {
        self.reserve_record(envelope, metadata)
            .map(|reservation| Box::new(reservation) as Box<dyn PendingNonceReservation>)
            .map_err(map_reject_v0)
    }
}

#[derive(Debug)]
struct SqlitePendingNonceReservationV0 {
    // The Rc lock keeps the single-owner file lock held while a token is live,
    // even if the authority value itself is dropped by the caller.
    connection: Rc<RefCell<Connection>>,
    // Retain the sidecar lock while this token is alive, even if the authority
    // value itself is moved or dropped by its caller.
    _lock: Rc<File>,
    lock_path: PathBuf,
    lock_identity: PathIdentityV0,
    path: PathBuf,
    path_identity: PathIdentityV0,
    namespace: [u8; 32],
    record: AdmissionRecordV0,
    state: i64,
}

impl SqlitePendingNonceReservationV0 {
    fn ensure_identity(&self) -> Result<(), AdmissionReject> {
        ensure_identity_v0(&self.path, self.path_identity)
            .and_then(|()| {
                ensure_open_lock_identity_v0(&self.lock_path, self.lock_identity, &self._lock)
            })
            .map_err(|_| AdmissionReject::InconsistentState)
    }

    fn transition(&mut self, target_state: i64) -> Result<(), AdmissionReject> {
        if self.state == target_state {
            return Ok(());
        }
        self.ensure_identity()?;
        let mut connection = self
            .connection
            .try_borrow_mut()
            .map_err(|_| AdmissionReject::InconsistentState)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AdmissionReject::InconsistentState)?;
        let Some((existing, state)) = read_row_v0(
            &transaction,
            self.namespace,
            self.record.signer,
            self.record.nonce,
        )
        .map_err(map_reject_v0)?
        else {
            return Err(AdmissionReject::InconsistentState);
        };
        if !row_matches_v0(existing, self.record) {
            return Err(AdmissionReject::InconsistentState);
        }
        let idempotent = matches!(
            (target_state, state),
            (STATE_HANDED_OFF_V0, STATE_HANDED_OFF_V0)
                | (STATE_COMMITTED_V0, STATE_COMMITTED_V0)
                | (STATE_RELEASED_V0, STATE_RELEASED_V0)
        );
        if !idempotent {
            let allowed = match target_state {
                STATE_HANDED_OFF_V0 => state == STATE_RESERVED_V0,
                STATE_COMMITTED_V0 => state == STATE_HANDED_OFF_V0,
                STATE_RELEASED_V0 => state == STATE_RESERVED_V0 || state == STATE_HANDED_OFF_V0,
                _ => false,
            };
            if !allowed {
                return Err(AdmissionReject::ReservationStateConflict);
            }
            let changed = transaction
                .execute(
                    "UPDATE pending_nonce SET state = ?1
                     WHERE namespace = ?2 AND signer = ?3 AND nonce = ?4 AND state = ?5",
                    params![
                        target_state,
                        self.namespace.as_slice(),
                        self.record.signer.as_slice(),
                        to_blob_u64(self.record.nonce).as_slice(),
                        state,
                    ],
                )
                .map_err(|_| AdmissionReject::InconsistentState)?;
            if changed != 1 {
                return Err(AdmissionReject::InconsistentState);
            }
        }
        transaction
            .commit()
            .map_err(|_| AdmissionReject::InconsistentState)?;
        self.ensure_identity()?;
        self.state = target_state;
        Ok(())
    }
}

impl PendingNonceReservation for SqlitePendingNonceReservationV0 {
    fn owner_binding(&self) -> Option<u64> {
        Some(Rc::as_ptr(&self.connection) as usize as u64)
    }

    fn handoff(&mut self) -> Result<(), AdmissionReject> {
        if self.state != STATE_RESERVED_V0 {
            return Err(AdmissionReject::ReservationStateConflict);
        }
        self.transition(STATE_HANDED_OFF_V0)
    }

    fn commit(&mut self) -> Result<(), AdmissionReject> {
        if self.state != STATE_HANDED_OFF_V0 {
            return Err(AdmissionReject::ReservationStateConflict);
        }
        self.transition(STATE_COMMITTED_V0)
    }

    fn release(&mut self) -> Result<(), AdmissionReject> {
        if self.state != STATE_RESERVED_V0 && self.state != STATE_HANDED_OFF_V0 {
            return Err(AdmissionReject::ReservationStateConflict);
        }
        self.transition(STATE_RELEASED_V0)
    }
}

fn map_reject_v0(error: TxAdmissionWalErrorV0) -> AdmissionReject {
    match error {
        TxAdmissionWalErrorV0::Replay => AdmissionReject::Replay,
        TxAdmissionWalErrorV0::ReservationConflict => AdmissionReject::ReservationStateConflict,
        TxAdmissionWalErrorV0::AmbiguousHandoff => AdmissionReject::InconsistentState,
        TxAdmissionWalErrorV0::CommitReceiptMismatch
        | TxAdmissionWalErrorV0::CommitReceiptConflict
        | TxAdmissionWalErrorV0::CommitReadbackUnavailable => AdmissionReject::InconsistentState,
        TxAdmissionWalErrorV0::InvalidPath
        | TxAdmissionWalErrorV0::InvalidNamespace
        | TxAdmissionWalErrorV0::LockUnavailable
        | TxAdmissionWalErrorV0::PathReplaced
        | TxAdmissionWalErrorV0::Io
        | TxAdmissionWalErrorV0::Sqlite
        | TxAdmissionWalErrorV0::SchemaMismatch
        | TxAdmissionWalErrorV0::NamespaceMismatch
        | TxAdmissionWalErrorV0::Malformed
        | TxAdmissionWalErrorV0::TooLarge => AdmissionReject::InconsistentState,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    use trnm_application_tx_builder_v0::{
        build_signed_canonical_tx_v0, ApplicationSignerV0, CanonicalTxBuildContextV0,
        TxBuilderLimitsV0,
    };
    use trnm_mempool::{
        CanonicalSignerId, CanonicalTxDigest, IngressClass, PendingNonceReservationState,
        ResourceLimits, SignedAdmissionHooks, SignedEnvelopeView, TypedAdmissionGate,
        TypedAdmitOutcome,
    };
    use trnm_protocol::CanonicalCommandV1;

    static NEXT_PATH_V0: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    struct FixtureEnvelope {
        digest: CanonicalTxDigest,
        signer: CanonicalSignerId,
        body: Vec<u8>,
        nonce: u64,
    }

    impl SignedEnvelopeView for FixtureEnvelope {
        fn canonical_digest(&self) -> CanonicalTxDigest {
            self.digest
        }

        fn canonical_signer_id(&self) -> Result<CanonicalSignerId, AdmissionReject> {
            Ok(self.signer)
        }

        fn canonical_body(&self) -> &[u8] {
            &self.body
        }

        fn nonce(&self) -> u64 {
            self.nonce
        }

        fn fee_limit(&self) -> u128 {
            17
        }

        fn resource_limits(&self) -> ResourceLimits {
            ResourceLimits {
                max_gas: 10_000,
                max_bytes: self.body.len() as u64,
            }
        }

        fn validate_canonical(&self) -> Result<(), AdmissionReject> {
            Ok(())
        }
    }

    struct Hooks;

    impl SignedAdmissionHooks<FixtureEnvelope> for Hooks {
        fn verify_signature(
            &mut self,
            _envelope: &FixtureEnvelope,
            _metadata: &SignedEnvelopeMetadata,
        ) -> Result<(), AdmissionReject> {
            Ok(())
        }

        fn recheck(&mut self, _metadata: &SignedEnvelopeMetadata) -> Result<(), AdmissionReject> {
            Ok(())
        }
    }

    struct BuilderFixtureSigner {
        key: SigningKey,
        id: String,
        public_key: String,
    }

    impl ApplicationSignerV0 for BuilderFixtureSigner {
        fn signer_id(&self) -> &str {
            &self.id
        }

        fn signer_role(&self) -> &str {
            "account"
        }

        fn public_key_hex(&self) -> &str {
            &self.public_key
        }

        fn sign(&self, preimage: &[u8]) -> anyhow::Result<[u8; 64]> {
            Ok(self.key.sign(preimage).to_bytes())
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct BuilderFixtureSignerResolver {
        signer: CanonicalSignerId,
    }

    impl CanonicalSignerIdentityResolverV0 for BuilderFixtureSignerResolver {
        fn resolve_canonical_signer_id_v0(
            &self,
            transaction: &BuiltCanonicalTxV0,
        ) -> Result<CanonicalSignerId, AdmissionReject> {
            if transaction.envelope().signer_id != "did:trnm:alice" {
                return Err(AdmissionReject::SignerIdentityUnavailable);
            }
            Ok(self.signer)
        }
    }

    struct AcceptingCommitVerifier;

    impl NativeCommitReceiptVerifierV0 for AcceptingCommitVerifier {
        fn verify_application_and_finality_v0(
            &self,
            _metadata: &SignedEnvelopeMetadata,
            evidence: &NativeCommitReceiptEvidenceV0,
        ) -> Result<(), TxAdmissionWalErrorV0> {
            if evidence.block_height.get() == 0 {
                return Err(TxAdmissionWalErrorV0::CommitReadbackUnavailable);
            }
            Ok(())
        }
    }

    struct RejectingCommitVerifier;

    impl NativeCommitReceiptVerifierV0 for RejectingCommitVerifier {
        fn verify_application_and_finality_v0(
            &self,
            _metadata: &SignedEnvelopeMetadata,
            _evidence: &NativeCommitReceiptEvidenceV0,
        ) -> Result<(), TxAdmissionWalErrorV0> {
            Err(TxAdmissionWalErrorV0::CommitReadbackUnavailable)
        }
    }

    fn fixture() -> FixtureEnvelope {
        FixtureEnvelope {
            digest: CanonicalTxDigest::from_bytes([0x11; 32]).unwrap(),
            signer: CanonicalSignerId::from_bytes([0x22; 32]).unwrap(),
            body: b"canonical-body".to_vec(),
            nonce: 7,
        }
    }

    fn builder_fixture_transaction() -> BuiltCanonicalTxV0 {
        let key = SigningKey::from_bytes(&[0x47; 32]);
        let signer = BuilderFixtureSigner {
            public_key: hex::encode(key.verifying_key().to_bytes()),
            key,
            id: "did:trnm:alice".to_owned(),
        };
        build_signed_canonical_tx_v0(
            CanonicalTxBuildContextV0 {
                chain_id: "trnm-devnet".to_owned(),
                sender: signer.id.clone(),
                command_id: None,
                nonce: 7,
                issued_at_unix_ms: 1_000,
                expires_at_unix_ms: 2_000,
                max_gas: 10_000,
                fee_limit: 17,
                limits: TxBuilderLimitsV0::candidate_v0(),
            },
            CanonicalCommandV1::CreditAccount {
                account: signer.id.clone(),
                amount: 1,
            },
            &signer,
        )
        .unwrap()
    }

    fn commit_evidence_for(envelope: &FixtureEnvelope) -> NativeCommitReceiptEvidenceV0 {
        NativeCommitReceiptEvidenceV0::new(
            envelope.digest.as_bytes(),
            BlockId::new([0x31; 32]),
            Height::new(12),
            StateRoot::new([0x32; 32]),
            [0x33; 32],
            [0x34; 32],
        )
        .unwrap()
    }

    fn temp_path() -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let id = NEXT_PATH_V0.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "trnm-poco-tx-admission-{stamp}-{}-{id}.sqlite",
            std::process::id()
        ))
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
        if let Ok(lock) = lock_path_v0(path) {
            let _ = fs::remove_file(lock);
        }
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
    }

    #[cfg(unix)]
    fn replace_lock_path_for_test(path: &Path) -> PathBuf {
        use std::os::unix::fs::OpenOptionsExt;

        let lock_path = lock_path_v0(path).unwrap();
        let moved_path = lock_path.with_file_name(format!(
            "{}.moved-{}",
            lock_path.file_name().unwrap().to_string_lossy(),
            NEXT_PATH_V0.fetch_add(1, Ordering::Relaxed)
        ));
        fs::rename(&lock_path, &moved_path).unwrap();
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        options.open(&lock_path).unwrap();
        moved_path
    }

    fn seed_row(path: &Path, namespace: [u8; 32], state: i64) {
        let authority = SqlitePendingNonceAuthorityV0::open(path, namespace).unwrap();
        let record = AdmissionRecordV0 {
            signer: [0x22; 32],
            nonce: 7,
            digest: [0x11; 32],
            body_digest: body_digest_v0(b"canonical-body"),
            fee_limit: 17,
            max_gas: 10_000,
            max_bytes: b"canonical-body".len() as u64,
        };
        let nonce_blob = to_blob_u64(record.nonce);
        let fee_blob = to_blob_u128(record.fee_limit);
        let gas_blob = to_blob_u64(record.max_gas);
        let bytes_blob = to_blob_u64(record.max_bytes);
        let connection = authority.connection.borrow();
        connection
            .execute(
                "INSERT INTO pending_nonce
                 (namespace, signer, nonce, digest, body_digest, fee_limit,
                  max_gas, max_bytes, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    namespace.as_slice(),
                    record.signer.as_slice(),
                    nonce_blob.as_slice(),
                    record.digest.as_slice(),
                    record.body_digest.as_slice(),
                    fee_blob.as_slice(),
                    gas_blob.as_slice(),
                    bytes_blob.as_slice(),
                    state,
                ],
            )
            .unwrap();
        drop(connection);
        drop(authority);
    }

    #[test]
    fn reserve_lifecycle_is_durable_and_idempotent() {
        let path = temp_path();
        let envelope = fixture();
        let mut authority = SqlitePendingNonceAuthorityV0::open(&path, [0x33; 32]).unwrap();
        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let mut hooks = Hooks;
        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &envelope,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = gate.pop_ready_with_lifecycle().unwrap();
        assert_eq!(
            ready.reservation_state(),
            Ok(PendingNonceReservationState::Reserved)
        );
        ready.handoff().unwrap();
        ready.commit().unwrap();
        assert_eq!(authority.retained_rows().unwrap(), 1);
        drop(ready);
        drop(authority);

        let reopened = SqlitePendingNonceAuthorityV0::open(&path, [0x33; 32]).unwrap();
        assert_eq!(reopened.retained_rows().unwrap(), 1);
        drop(reopened);
        cleanup(&path);
    }

    #[test]
    fn exact_reserved_row_retries_after_restart_and_conflicts_fail_closed() {
        let path = temp_path();
        let envelope = fixture();
        seed_row(&path, [0x44; 32], STATE_RESERVED_V0);
        let mut authority = SqlitePendingNonceAuthorityV0::open(&path, [0x44; 32]).unwrap();
        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let mut hooks = Hooks;
        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &envelope,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = gate.pop_ready_with_lifecycle().unwrap();
        ready.handoff().unwrap();
        ready.commit().unwrap();

        let mut changed = fixture();
        changed.digest = CanonicalTxDigest::from_bytes([0x55; 32]).unwrap();
        let mut gate2 = TypedAdmissionGate::with_default_body_limit(2, 0);
        assert_eq!(
            gate2.admit_signed_with_pending_nonce(
                &changed,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Rejected(AdmissionReject::Replay)
        );
        cleanup(&path);
    }

    #[test]
    fn handed_off_restart_is_ambiguous_and_second_owner_is_locked() {
        let path = temp_path();
        seed_row(&path, [0x66; 32], STATE_HANDED_OFF_V0);
        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&path, [0x66; 32]).unwrap_err(),
            TxAdmissionWalErrorV0::AmbiguousHandoff
        );
        cleanup(&path);
    }

    #[test]
    fn wrong_namespace_and_concurrent_owner_are_rejected() {
        let path = temp_path();
        let authority = SqlitePendingNonceAuthorityV0::open(&path, [0x77; 32]).unwrap();
        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&path, [0x78; 32]).unwrap_err(),
            TxAdmissionWalErrorV0::LockUnavailable
        );
        drop(authority);
        let authority = SqlitePendingNonceAuthorityV0::open(&path, [0x77; 32]).unwrap();
        drop(authority);
        // Namespace mismatch is observable after the first owner releases the
        // lock and does not rewrite the existing database.
        assert_eq!(
            SqlitePendingNonceAuthorityV0::open(&path, [0x78; 32]).unwrap_err(),
            TxAdmissionWalErrorV0::NamespaceMismatch
        );
        cleanup(&path);
    }

    #[test]
    fn insert_error_mapping_only_treats_constraint_as_replay() {
        fn sqlite_failure(code: rusqlite::ffi::ErrorCode) -> rusqlite::Error {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code,
                    extended_code: 0,
                },
                None,
            )
        }

        assert_eq!(
            map_insert_error_v0(sqlite_failure(
                rusqlite::ffi::ErrorCode::ConstraintViolation
            )),
            TxAdmissionWalErrorV0::Replay
        );
        assert_eq!(
            map_insert_error_v0(sqlite_failure(rusqlite::ffi::ErrorCode::DatabaseBusy)),
            TxAdmissionWalErrorV0::Sqlite
        );
        assert_eq!(
            map_insert_error_v0(sqlite_failure(rusqlite::ffi::ErrorCode::SystemIoFailure)),
            TxAdmissionWalErrorV0::Sqlite
        );
        assert_eq!(
            map_insert_error_v0(rusqlite::Error::InvalidQuery),
            TxAdmissionWalErrorV0::Sqlite
        );
    }

    #[cfg(unix)]
    #[test]
    fn lock_path_replacement_fails_closed_for_authority_and_reservation() {
        let path = temp_path();
        let envelope = fixture();
        let mut authority = SqlitePendingNonceAuthorityV0::open(&path, [0xAB; 32]).unwrap();
        let mut gate = TypedAdmissionGate::with_default_body_limit(2, 0);
        let mut hooks = Hooks;
        assert_eq!(
            gate.admit_signed_with_pending_nonce(
                &envelope,
                IngressClass::Normal,
                &mut hooks,
                &mut authority,
            ),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = gate.pop_ready_with_lifecycle().expect("ready candidate");
        let moved_path = replace_lock_path_for_test(&path);

        assert_eq!(
            ensure_open_lock_identity_v0(
                &lock_path_v0(&path).unwrap(),
                authority.lock_identity,
                &authority.lock,
            )
            .unwrap_err(),
            TxAdmissionWalErrorV0::PathReplaced
        );
        assert_eq!(
            authority.retained_rows().unwrap_err(),
            TxAdmissionWalErrorV0::PathReplaced
        );
        assert_eq!(
            ready.handoff().unwrap_err(),
            AdmissionReject::InconsistentState
        );

        drop(ready);
        drop(authority);
        cleanup(&path);
        let _ = fs::remove_file(moved_path);
    }

    #[test]
    fn node_owned_boundary_routes_typed_admission_and_lifecycle() {
        let path = temp_path();
        let envelope = fixture();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit(&path, [0x88; 32], 2, 0)
                .unwrap();
        let mut hooks = Hooks;

        const {
            assert!(TX_ADMISSION_BOUNDARY_RUNTIME_COMPOSITION_V0);
            assert!(!TX_ADMISSION_BOUNDARY_PRODUCTION_ACTIVATION_V0);
            assert!(!TX_ADMISSION_BOUNDARY_CHECKTX_V0);
            assert!(!TX_ADMISSION_BOUNDARY_SIGNING_V0);
            assert!(!TX_ADMISSION_BOUNDARY_BROADCAST_V0);
            assert!(TX_ADMISSION_BOUNDARY_COMMIT_RECEIPT_V0);
            assert!(!TX_ADMISSION_BOUNDARY_COMMIT_RECEIPT_PRODUCTION_V0);
        }
        assert_eq!(boundary.namespace(), [0x88; 32]);
        assert_eq!(
            boundary.admit_signed_candidate(&envelope, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Accepted
        );
        assert_eq!(boundary.queued_counts(), (1, 0, 1));

        let mut ready = boundary
            .pop_ready_with_lifecycle()
            .expect("ready candidate");
        assert_eq!(
            ready.reservation_state(),
            Ok(PendingNonceReservationState::Reserved)
        );
        assert_eq!(
            ready.commit(),
            Err(AdmissionReject::ReservationStateConflict)
        );
        ready.handoff().unwrap();
        assert_eq!(
            ready.handoff(),
            Err(AdmissionReject::ReservationStateConflict)
        );
        ready.commit().unwrap();
        assert_eq!(
            ready.commit(),
            Err(AdmissionReject::ReservationStateConflict)
        );
        assert_eq!(boundary.retained_rows().unwrap(), 1);

        // A committed tombstone is a durable replay rejection, not a second
        // candidate admission.  The node boundary still has no broadcast or
        // application-commit readback behavior.
        assert_eq!(
            boundary.admit_signed_candidate(&envelope, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::Replay)
        );
        drop(ready);
        drop(boundary);
        cleanup(&path);
    }

    #[test]
    fn builder_check_tx_authenticates_before_wal_and_commit_receipt() {
        let path = temp_path();
        let transaction = builder_fixture_transaction();
        let signer_id = CanonicalSignerId::from_bytes([0xA5; 32]).unwrap();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit_and_signer_resolver(
                &path,
                [0x8C; 32],
                2,
                0,
                BuilderFixtureSignerResolver { signer: signer_id },
            )
            .unwrap();

        const {
            assert!(TX_ADMISSION_BOUNDARY_CHECKTX_CANDIDATE_V0);
            assert!(!TX_ADMISSION_BOUNDARY_CHECKTX_V0);
            assert!(TX_ADMISSION_BOUNDARY_SIGNER_RESOLVER_V0);
            assert!(!TX_ADMISSION_BOUNDARY_SIGNER_RESOLVER_PRODUCTION_V0);
            assert!(!TX_ADMISSION_BOUNDARY_SIGNING_V0);
            assert!(!TX_ADMISSION_BOUNDARY_BROADCAST_V0);
        }
        assert_eq!(
            boundary.check_tx_candidate_with_resolver(
                &transaction,
                IngressClass::Normal,
                "trnm-devnet",
                1_000,
            ),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = boundary.pop_ready_with_lifecycle().unwrap();
        assert_eq!(ready.metadata().nonce(), 7);
        ready.handoff().unwrap();
        let evidence = NativeCommitReceiptEvidenceV0::new(
            transaction.protocol_tx_hash_v1(),
            BlockId::new([0x51; 32]),
            Height::new(1),
            StateRoot::new([0x52; 32]),
            [0x53; 32],
            [0x54; 32],
        )
        .unwrap();
        let verified = evidence
            .verify_with(ready.metadata(), &AcceptingCommitVerifier)
            .unwrap();
        boundary
            .commit_candidate_with_receipt(&mut ready, &verified)
            .unwrap();
        assert_eq!(boundary.retained_rows().unwrap(), 1);
        drop(ready);
        drop(boundary);

        // A wrong chain context fails before the nonce authority is touched.
        let bad_path = temp_path();
        let mut bad_boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit_and_signer_resolver(
                &bad_path,
                [0x8D; 32],
                2,
                0,
                BuilderFixtureSignerResolver { signer: signer_id },
            )
            .unwrap();
        assert_eq!(
            bad_boundary.check_tx_candidate_with_resolver(
                &transaction,
                IngressClass::Normal,
                "trnm-wrong-chain",
                1_000,
            ),
            TypedAdmitOutcome::Rejected(AdmissionReject::SignatureRejected)
        );
        assert_eq!(bad_boundary.retained_rows().unwrap(), 0);
        drop(bad_boundary);
        cleanup(&bad_path);
        cleanup(&path);
    }

    #[test]
    fn caller_supplied_signer_mismatch_cannot_choose_wal_replay_key() {
        let path = temp_path();
        let transaction = builder_fixture_transaction();
        let authority_signer = CanonicalSignerId::from_bytes([0xA5; 32]).unwrap();
        let caller_signer = CanonicalSignerId::from_bytes([0xA6; 32]).unwrap();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit_and_signer_resolver(
                &path,
                [0x8F; 32],
                2,
                0,
                BuilderFixtureSignerResolver {
                    signer: authority_signer,
                },
            )
            .unwrap();

        assert_eq!(
            boundary.check_tx_candidate(
                &transaction,
                caller_signer,
                IngressClass::Normal,
                "trnm-devnet",
                1_000,
            ),
            TypedAdmitOutcome::Rejected(AdmissionReject::CanonicalValidationFailed)
        );
        assert_eq!(boundary.retained_rows().unwrap(), 0);

        assert_eq!(
            boundary.check_tx_candidate(
                &transaction,
                authority_signer,
                IngressClass::Normal,
                "trnm-devnet",
                1_000,
            ),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = boundary.pop_ready_with_lifecycle().unwrap();
        ready.release().unwrap();
        drop(ready);
        drop(boundary);
        cleanup(&path);
    }

    #[test]
    fn candidate_checktx_without_authority_resolver_fails_before_wal() {
        let path = temp_path();
        let transaction = builder_fixture_transaction();
        let caller_signer = CanonicalSignerId::from_bytes([0xA5; 32]).unwrap();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit(&path, [0x90; 32], 2, 0)
                .unwrap();

        assert_eq!(
            boundary.check_tx_candidate_with_resolver(
                &transaction,
                IngressClass::Normal,
                "trnm-devnet",
                1_000,
            ),
            TypedAdmitOutcome::Rejected(AdmissionReject::SignerIdentityUnavailable)
        );
        assert_eq!(
            boundary.check_tx_candidate(
                &transaction,
                caller_signer,
                IngressClass::Normal,
                "trnm-devnet",
                1_000,
            ),
            TypedAdmitOutcome::Rejected(AdmissionReject::SignerIdentityUnavailable)
        );
        assert_eq!(boundary.retained_rows().unwrap(), 0);
        drop(boundary);
        cleanup(&path);
    }

    #[test]
    fn verified_commit_receipt_binds_and_persists_before_token_resolution() {
        let path = temp_path();
        let envelope = fixture();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit(&path, [0x8A; 32], 2, 0)
                .unwrap();
        let mut hooks = Hooks;
        assert_eq!(
            boundary.admit_signed_candidate(&envelope, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = boundary.pop_ready_with_lifecycle().unwrap();
        ready.handoff().unwrap();
        let evidence = commit_evidence_for(&envelope);
        let verified = evidence
            .verify_with(ready.metadata(), &AcceptingCommitVerifier)
            .unwrap();
        assert_ne!(verified.commitment(), [0; 32]);
        boundary
            .commit_candidate_with_receipt(&mut ready, &verified)
            .unwrap();
        assert_eq!(
            ready.reservation_state(),
            Ok(PendingNonceReservationState::Committed)
        );
        assert_eq!(boundary.retained_rows().unwrap(), 1);
        drop(ready);
        drop(boundary);
        assert!(SqlitePendingNonceAuthorityV0::open(&path, [0x8A; 32]).is_ok());
        cleanup(&path);
    }

    #[test]
    fn commit_rejects_a_token_owned_by_another_boundary_instance() {
        let path_a = temp_path();
        let path_b = temp_path();
        let transaction = builder_fixture_transaction();
        let signer_id = CanonicalSignerId::from_bytes([0xA6; 32]).unwrap();
        let mut boundary_a =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit_and_signer_resolver(
                &path_a,
                [0x8E; 32],
                2,
                0,
                BuilderFixtureSignerResolver { signer: signer_id },
            )
            .unwrap();
        let mut boundary_b =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit_and_signer_resolver(
                &path_b,
                [0x8E; 32],
                2,
                0,
                BuilderFixtureSignerResolver { signer: signer_id },
            )
            .unwrap();
        assert_eq!(
            boundary_a.check_tx_candidate_with_resolver(
                &transaction,
                IngressClass::Normal,
                "trnm-devnet",
                1_000,
            ),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = boundary_a.pop_ready_with_lifecycle().unwrap();
        ready.handoff().unwrap();
        let evidence = NativeCommitReceiptEvidenceV0::new(
            transaction.protocol_tx_hash_v1(),
            BlockId::new([0x61; 32]),
            Height::new(2),
            StateRoot::new([0x62; 32]),
            [0x63; 32],
            [0x64; 32],
        )
        .unwrap();
        let verified = evidence
            .verify_with(ready.metadata(), &AcceptingCommitVerifier)
            .unwrap();
        assert_eq!(
            boundary_b.commit_candidate_with_receipt(&mut ready, &verified),
            Err(AdmissionReject::InconsistentState)
        );
        assert_eq!(boundary_b.retained_rows().unwrap(), 0);
        assert_eq!(
            ready.reservation_state(),
            Ok(PendingNonceReservationState::HandedOff)
        );
        drop(ready);
        drop(boundary_a);
        drop(boundary_b);
        cleanup(&path_a);
        cleanup(&path_b);
    }

    #[test]
    fn unverified_or_foreign_receipt_never_advances_handoff() {
        let path = temp_path();
        let envelope = fixture();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit(&path, [0x8B; 32], 2, 0)
                .unwrap();
        let mut hooks = Hooks;
        assert_eq!(
            boundary.admit_signed_candidate(&envelope, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Accepted
        );
        let mut ready = boundary.pop_ready_with_lifecycle().unwrap();
        ready.handoff().unwrap();
        let mut foreign = commit_evidence_for(&envelope);
        foreign.tx_digest = [0xFE; 32];
        assert_eq!(
            foreign.verify_with(ready.metadata(), &AcceptingCommitVerifier),
            Err(TxAdmissionWalErrorV0::CommitReceiptMismatch)
        );
        let rejected = NativeCommitReceiptEvidenceV0::new(
            envelope.digest.as_bytes(),
            BlockId::new([0x41; 32]),
            Height::new(13),
            StateRoot::new([0x42; 32]),
            [0x43; 32],
            [0x44; 32],
        )
        .unwrap()
        .verify_with(ready.metadata(), &RejectingCommitVerifier);
        assert_eq!(
            rejected,
            Err(TxAdmissionWalErrorV0::CommitReadbackUnavailable)
        );
        // The verifier rejection path above cannot produce a token; the
        // handed-off row remains unresolved and therefore blocks restart.
        assert_eq!(
            ready.reservation_state(),
            Ok(PendingNonceReservationState::HandedOff)
        );
        drop(ready);
        drop(boundary);
        cleanup(&path);
    }

    #[test]
    fn node_owned_boundary_rejects_before_reserving_on_invalid_metadata() {
        let path = temp_path();
        let mut envelope = fixture();
        envelope.body.clear();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit(&path, [0x99; 32], 2, 0)
                .unwrap();
        let mut hooks = Hooks;
        assert_eq!(
            boundary.admit_signed_candidate(&envelope, IngressClass::Normal, &mut hooks),
            TypedAdmitOutcome::Rejected(AdmissionReject::EmptyBody)
        );
        assert_eq!(boundary.queued_counts(), (0, 0, 0));
        assert_eq!(boundary.retained_rows().unwrap(), 0);
        drop(boundary);
        cleanup(&path);
    }
}
