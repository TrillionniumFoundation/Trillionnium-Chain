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
use trnm_mempool::{
    AdmissionReject, IngressClass, PendingNonceAdmission, PendingNonceAuthority,
    PendingNonceReservation, SignedAdmissionHooks, SignedEnvelopeMetadata, SignedEnvelopeView,
    TypedAdmissionGate, TypedAdmitOutcome, DEFAULT_MAX_ADMISSION_BODY_BYTES,
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
pub const TX_ADMISSION_BOUNDARY_SIGNING_V0: bool = false;
pub const TX_ADMISSION_BOUNDARY_BROADCAST_V0: bool = false;

const SCHEMA_VERSION_V0: i64 = 1;
const WAL_DOMAIN_V0: &[u8] = b"trnm.poco-node.tx-admission-wal.v0";
const LOCK_SUFFIX_V0: &str = ".tx-admission.lock.v0";
const MAX_RESERVATION_ROWS_V0: usize = 1_000_000;

const STATE_RESERVED_V0: i64 = 0;
const STATE_HANDED_OFF_V0: i64 = 1;
const STATE_COMMITTED_V0: i64 = 2;
const STATE_RELEASED_V0: i64 = 3;

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
}

#[cfg(not(unix))]
impl PathIdentityV0 {
    fn from_metadata(_metadata: &fs::Metadata) -> Self {
        Self {}
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

fn open_lock_v0(path: &Path) -> Result<Rc<File>, TxAdmissionWalErrorV0> {
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
    Ok(Rc::new(file))
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

/// A node-owned SQLite pending-nonce authority.
///
/// The authority is intentionally not `Clone` and its lock is held for its
/// entire lifetime (also by outstanding reservation tokens).  It is therefore
/// safe only as a single local owner; cross-process attempts fail at open.
pub struct SqlitePendingNonceAuthorityV0 {
    connection: Rc<RefCell<Connection>>,
    lock: Rc<File>,
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
        Ok(Self {
            gate: TypedAdmissionGate::new(total_capacity, critical_reserve, max_body_bytes),
            authority: SqlitePendingNonceAuthorityV0::open(path, namespace)?,
        })
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

    /// Return the next item with its node-owned handoff/commit/release token.
    pub fn pop_ready_with_lifecycle(&mut self) -> Option<PendingNonceAdmission> {
        self.gate.pop_ready_with_lifecycle()
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
        let lock = open_lock_v0(&path)?;
        ensure_identity_v0(&path, path_identity)?;
        let connection = Connection::open(&path).map_err(sqlite_error)?;
        // The first identity check protects the name-to-inode transition around
        // SQLite open. A second fence below catches a replacement which raced
        // that open before any schema/WAL write is attempted.
        ensure_identity_v0(&path, path_identity)?;
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
        Ok(Self {
            connection: Rc::new(RefCell::new(connection)),
            lock,
            path,
            path_identity,
            namespace,
        })
    }

    pub const fn namespace(&self) -> [u8; 32] {
        self.namespace
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
        ensure_identity_v0(&self.path, self.path_identity)
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
            path: self.path.clone(),
            path_identity: self.path_identity,
            namespace: self.namespace,
            record: expected,
            state: STATE_RESERVED_V0,
        })
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
    path: PathBuf,
    path_identity: PathIdentityV0,
    namespace: [u8; 32],
    record: AdmissionRecordV0,
    state: i64,
}

impl SqlitePendingNonceReservationV0 {
    fn transition(&mut self, target_state: i64) -> Result<(), AdmissionReject> {
        if self.state == target_state {
            return Ok(());
        }
        let metadata =
            fs::symlink_metadata(&self.path).map_err(|_| AdmissionReject::InconsistentState)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || PathIdentityV0::from_metadata(&metadata) != self.path_identity
        {
            return Err(AdmissionReject::InconsistentState);
        }
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
        if ensure_identity_v0(&self.path, self.path_identity).is_err() {
            return Err(AdmissionReject::InconsistentState);
        }
        self.state = target_state;
        Ok(())
    }
}

impl PendingNonceReservation for SqlitePendingNonceReservationV0 {
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
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    use trnm_mempool::{
        CanonicalSignerId, CanonicalTxDigest, IngressClass, PendingNonceReservationState,
        ResourceLimits, SignedAdmissionHooks, SignedEnvelopeView, TypedAdmissionGate,
        TypedAdmitOutcome,
    };

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

    fn fixture() -> FixtureEnvelope {
        FixtureEnvelope {
            digest: CanonicalTxDigest::from_bytes([0x11; 32]).unwrap(),
            signer: CanonicalSignerId::from_bytes([0x22; 32]).unwrap(),
            body: b"canonical-body".to_vec(),
            nonce: 7,
        }
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

    #[test]
    fn node_owned_boundary_routes_typed_admission_and_lifecycle() {
        let path = temp_path();
        let envelope = fixture();
        let mut boundary =
            NodeOwnedTxAdmissionBoundaryV0::with_default_body_limit(&path, [0x88; 32], 2, 0)
                .unwrap();
        let mut hooks = Hooks;

        assert!(TX_ADMISSION_BOUNDARY_RUNTIME_COMPOSITION_V0);
        assert!(!TX_ADMISSION_BOUNDARY_PRODUCTION_ACTIVATION_V0);
        assert!(!TX_ADMISSION_BOUNDARY_CHECKTX_V0);
        assert!(!TX_ADMISSION_BOUNDARY_SIGNING_V0);
        assert!(!TX_ADMISSION_BOUNDARY_BROADCAST_V0);
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
