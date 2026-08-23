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
    error::Error,
    fmt, fs,
    io::{self, Read},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::Duration,
};

use ed25519_dalek::{Signer, SigningKey, Verifier};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use trnm_consensus_remote_signer_protocol::{
    decode_remote_signer_request_v1_exact, RemoteConsensusCommandKindV1,
    RemoteSignerProtocolErrorV1, RemoteSignerRequestBindingV1, UnverifiedRemoteSignerResponseV1,
    MAX_REMOTE_SIGNER_REQUEST_BYTES_V1,
};
use trnm_consensus_types::{SignatureBytes, ValidatorSet};

pub use fixture::{fixture_request, fixture_service_config, Fixture};

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
}

impl PurposePolicyV1 {
    pub const fn both() -> Self {
        Self {
            allow_vote: true,
            allow_timeout_vote: true,
        }
    }

    pub const fn vote_only() -> Self {
        Self {
            allow_vote: true,
            allow_timeout_vote: false,
        }
    }

    pub const fn timeout_vote_only() -> Self {
        Self {
            allow_vote: false,
            allow_timeout_vote: true,
        }
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
    signing_key: SigningKey,
    purpose_policy: PurposePolicyV1,
    scope: [u8; 32],
    watermark_path: PathBuf,
    watermark_identity: FileIdentityV1,
    watermark_directory_identity: FileIdentityV1,
    connection: Connection,
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
        if config.binding.purpose_profile_digest()
            != trnm_consensus_remote_signer_protocol::vote_timeout_purpose_profile_digest_v1()
        {
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
                 );",
            )
            .map_err(|error| ServiceFailure::Sqlite("initialize watermark schema", error))?;
        validate_schema_v1(&connection)?;
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
            signing_key: config.signing_key,
            purpose_policy: config.purpose_policy,
            scope,
            watermark_path,
            watermark_identity,
            watermark_directory_identity: directory_identity,
            connection,
        })
    }

    pub const fn binding(&self) -> RemoteSignerRequestBindingV1 {
        self.binding
    }

    pub const fn scope(&self) -> [u8; 32] {
        self.scope
    }

    /// Processes one exact protocol request and returns an exact protocol
    /// response.  This method is the smallest in-process adapter used by the
    /// Unix transport and intentionally does not call Core or SafetyRules.
    pub fn process_request(
        &mut self,
        encoded_request: &[u8],
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
        match self.process_request(&request) {
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

    fn sign_and_verify_v1(&self, signing_root: &[u8; 32]) -> Result<[u8; 64], ServiceFailure> {
        let signature = self.signing_key.sign(signing_root);
        self.signing_key
            .verifying_key()
            .verify(signing_root, &signature)
            .map_err(|_| ServiceFailure::SignatureFailure)?;
        Ok(signature.to_bytes())
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
            vec![
                u8::from(purpose_policy.allow_vote),
                u8::from(purpose_policy.allow_timeout_vote),
            ],
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
        ServiceFailure::WrongPurpose(_) => ServiceRejectCodeV1::WrongPurpose,
        ServiceFailure::DuplicateNonce => ServiceRejectCodeV1::DuplicateNonce,
        ServiceFailure::DuplicateRequest => ServiceRejectCodeV1::DuplicateRequest,
        ServiceFailure::DuplicateRoundPurpose => ServiceRejectCodeV1::DuplicateRoundPurpose,
        ServiceFailure::Rollback { .. } | ServiceFailure::SafetyRevisionRollback { .. } => {
            ServiceRejectCodeV1::Rollback
        }
        ServiceFailure::WatermarkExhausted => ServiceRejectCodeV1::WatermarkExhausted,
        ServiceFailure::SignatureFailure => ServiceRejectCodeV1::SignatureFailure,
        ServiceFailure::ReservationFailure => ServiceRejectCodeV1::ReservationFailure,
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
    use trnm_consensus_remote_signer_protocol::decode_unverified_remote_signer_response_v1_exact;

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
