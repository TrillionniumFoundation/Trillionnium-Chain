//! Independent whole-node anti-rollback checkpoint contract.
//!
//! The signer journal's external watermark intentionally advances only with
//! signer events.  It therefore cannot detect a rollback of SafetyStore and
//! ApplicationStore state which happened after the most recent signer event.
//! This module defines a second, independently administered CAS domain which
//! binds the exact Safety, Application, and signer heads together.
//!
//! This remains a development-time type, codec, and startup-policy boundary.
//! A durable, independently namespaced SQLite CAS backend and one private,
//! successor-only native K/Safety/signer coordinator are supplied. The latter
//! may release only an inert Core signing request after exact CAS readback; no
//! HSM/KMS adapter, process effect driver, signer invocation, broadcast, or
//! production activation is supplied. In particular, the current h1
//! state-sync host is permanently replay-fenced and does not create or advance
//! this checkpoint.

use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    path::{Component, Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use rusqlite::{params, Connection, ErrorCode, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
#[cfg(feature = "legacy-consensus-app")]
use trnm_consensus_app::{
    ConfirmedNativeApplicationNodeCheckpointFactsV0, NativeConsensusApplicationHostV0,
};
#[cfg(feature = "legacy-consensus-app")]
use trnm_consensus_core::SafetyState;
use trnm_consensus_core::SignIntent;
#[cfg(feature = "legacy-consensus-app")]
use trnm_consensus_core::{safety_state_record_config_ref_v0, SafetyStateRecordContextV0};
#[cfg(feature = "legacy-consensus-app")]
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::{
    ConfirmedSafetyNodeCheckpointFactsV0, SafetyStoreErrorV0, SqliteSafetyStateStoreV0,
};
use trnm_consensus_signer_journal::{
    ConfirmedSignerNodeCheckpointFactsV0, ExternalMonotonicWatermarkV0, SignerJournalErrorV0,
    SignerWatermarkV0, SqliteSignerJournalV0,
};
#[cfg(feature = "legacy-consensus-app")]
use trnm_consensus_signer_journal::{
    PinnedSqliteSignerJournalV0, SignerJournalTailFactsV0, SignerPreparedIntentFactsV0,
};
use trnm_consensus_types::SignatureVerifier;
use trnm_consensus_types::{BlockId, StateRoot};
#[cfg(feature = "legacy-consensus-app")]
use trnm_consensus_types::{
    CanonicalSignIntentV0, ChainId, Epoch, ProtocolVersion, ValidatorId, ValidatorSetId,
};
use trnm_native_application_sqlite::{
    ConfirmedProposalValidationCheckpointFactsV0, ProposalValidationBindingV0,
    SqliteProposalValidationStoreV0, ValidationStoreErrorV0,
};

#[cfg(feature = "legacy-consensus-app")]
use crate::process_host::PocoNodeProcessConfigV0;

const RECORD_MAGIC_V0: [u8; 8] = *b"TRNMNCP0";
const CHECKSUM_DOMAIN_V0: &[u8] = b"trnm.external-node-checkpoint.value.v0";
const SQLITE_APPLICATION_ID_V0: i64 = 0x5452_4e43;
const SQLITE_SCHEMA_VERSION_V0: i64 = 1;
const SQLITE_TABLE_V0: &str = "trnm_external_node_checkpoint_v0";
const SQLITE_BUSY_TIMEOUT_V0: Duration = Duration::from_secs(5);
type SqliteCheckpointRowV0 = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
const SQLITE_CREATE_TABLE_V0: &str = concat!(
    "CREATE TABLE trnm_external_node_checkpoint_v0 (",
    "scope BLOB NOT NULL PRIMARY KEY ",
    "CHECK(typeof(scope) = 'blob' AND length(scope) = 32), ",
    "generation BLOB NOT NULL ",
    "CHECK(typeof(generation) = 'blob' AND length(generation) = 8), ",
    "checkpoint_checksum BLOB NOT NULL ",
    "CHECK(typeof(checkpoint_checksum) = 'blob' AND length(checkpoint_checksum) = 32), ",
    "record BLOB NOT NULL ",
    "CHECK(typeof(record) = 'blob' AND length(record) = 672)",
    ") STRICT, WITHOUT ROWID",
);

/// Frozen schema carried inside every canonical node-checkpoint value.
pub const EXTERNAL_NODE_CHECKPOINT_SCHEMA_V0: u64 = 0;

/// Exact byte length of the canonical v0 value, including its checksum.
pub const EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0: usize = 672;

/// There is deliberately no operational host integration in this slice.
pub const EXTERNAL_NODE_CHECKPOINT_OPERATIONAL_INTEGRATION_V0: bool = false;

/// The private native K owner can construct and fresh-confirm one exact
/// successor in the independent whole-node CAS domain. This is deliberately
/// narrower than process-host or production activation.
pub const NATIVE_K_SUCCESSOR_CHECKPOINT_CAS_INTEGRATION_V0: bool = true;

/// The independent checkpoint must not be interpreted as production-ready.
pub const EXTERNAL_NODE_CHECKPOINT_PRODUCTION_ACTIVATION_V0: bool = false;

/// Canonical fields committed by one whole-node external checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalNodeCheckpointFieldsV0 {
    pub scope: [u8; 32],
    pub generation: u64,
    pub predecessor_checksum: [u8; 32],

    pub safety_journal_id: [u8; 32],
    pub safety_verifier_profile_ref: [u8; 32],
    pub safety_revision: u64,
    pub safety_state_record_checksum: [u8; 32],
    pub safety_record_chain_checksum: [u8; 32],

    pub application_host_config_ref: [u8; 32],
    pub application_projection_profile_ref: [u8; 32],
    pub application_safety_binding_manifest_checksum: [u8; 32],
    pub application_committed_head_row_checksum: [u8; 32],
    pub application_recovery_closure_checksum: [u8; 32],
    pub application_block_id: BlockId,
    pub application_height: u64,
    pub application_state_root: StateRoot,
    pub application_view: u64,
    pub application_timestamp_ms: u64,

    pub signer_journal_id: [u8; 32],
    pub signer_profile_checksum: [u8; 32],
    pub signer_exact_watermark: SignerWatermarkV0,
}

/// Versioned, checksummed value stored in the independent CAS domain.
///
/// Constructing this value validates its canonical shape, but does not prove
/// that any local store actually has the committed heads.  Only the non-Clone
/// [`ConfirmedNodeCheckpointCandidateV0`] represents that later trusted join.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalNodeCheckpointV0 {
    fields: ExternalNodeCheckpointFieldsV0,
    checkpoint_checksum: [u8; 32],
}

impl ExternalNodeCheckpointV0 {
    pub fn new(
        fields: ExternalNodeCheckpointFieldsV0,
    ) -> Result<Self, ExternalNodeCheckpointDecodeErrorV0> {
        validate_fields_v0(&fields)?;
        let mut encoded = [0u8; EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0];
        encode_prefix_v0(&fields, &mut encoded);
        let checkpoint_checksum = checkpoint_checksum_v0(&encoded[..640]);
        Ok(Self {
            fields,
            checkpoint_checksum,
        })
    }

    pub fn decode_canonical_exact(
        encoded: &[u8],
    ) -> Result<Self, ExternalNodeCheckpointDecodeErrorV0> {
        if encoded.len() != EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0 {
            return Err(ExternalNodeCheckpointDecodeErrorV0::WrongLength);
        }
        if encoded[..8] != RECORD_MAGIC_V0 {
            return Err(ExternalNodeCheckpointDecodeErrorV0::WrongMagic);
        }
        if read_u64_v0(encoded, 8) != EXTERNAL_NODE_CHECKPOINT_SCHEMA_V0 {
            return Err(ExternalNodeCheckpointDecodeErrorV0::UnsupportedSchema);
        }

        let signer_exact_watermark = SignerWatermarkV0::from_persisted_parts(
            read_array_v0(encoded, 536),
            read_array_v0(encoded, 568),
            read_u64_v0(encoded, 600),
            read_array_v0(encoded, 608),
        )
        .map_err(|_| ExternalNodeCheckpointDecodeErrorV0::InvalidField("signer watermark"))?;

        let fields = ExternalNodeCheckpointFieldsV0 {
            scope: read_array_v0(encoded, 16),
            generation: read_u64_v0(encoded, 48),
            predecessor_checksum: read_array_v0(encoded, 56),
            safety_journal_id: read_array_v0(encoded, 88),
            safety_verifier_profile_ref: read_array_v0(encoded, 120),
            safety_revision: read_u64_v0(encoded, 152),
            safety_state_record_checksum: read_array_v0(encoded, 160),
            safety_record_chain_checksum: read_array_v0(encoded, 192),
            application_host_config_ref: read_array_v0(encoded, 224),
            application_projection_profile_ref: read_array_v0(encoded, 256),
            application_safety_binding_manifest_checksum: read_array_v0(encoded, 288),
            application_committed_head_row_checksum: read_array_v0(encoded, 320),
            application_recovery_closure_checksum: read_array_v0(encoded, 352),
            application_block_id: BlockId::new(read_array_v0(encoded, 384)),
            application_height: read_u64_v0(encoded, 416),
            application_state_root: StateRoot::new(read_array_v0(encoded, 424)),
            application_view: read_u64_v0(encoded, 456),
            application_timestamp_ms: read_u64_v0(encoded, 464),
            signer_journal_id: read_array_v0(encoded, 472),
            signer_profile_checksum: read_array_v0(encoded, 504),
            signer_exact_watermark,
        };
        let value = Self::new(fields)?;
        let persisted_checksum: [u8; 32] = read_array_v0(encoded, 640);
        if persisted_checksum != value.checkpoint_checksum {
            return Err(ExternalNodeCheckpointDecodeErrorV0::ChecksumMismatch);
        }
        Ok(value)
    }

    pub fn encode_canonical(&self) -> [u8; EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0] {
        let mut encoded = [0u8; EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0];
        encode_prefix_v0(&self.fields, &mut encoded);
        encoded[640..].copy_from_slice(&self.checkpoint_checksum);
        encoded
    }

    pub const fn schema(&self) -> u64 {
        EXTERNAL_NODE_CHECKPOINT_SCHEMA_V0
    }

    pub const fn fields(&self) -> &ExternalNodeCheckpointFieldsV0 {
        &self.fields
    }

    pub const fn scope(&self) -> [u8; 32] {
        self.fields.scope
    }

    pub const fn generation(&self) -> u64 {
        self.fields.generation
    }

    pub const fn predecessor_checksum(&self) -> [u8; 32] {
        self.fields.predecessor_checksum
    }

    pub const fn checkpoint_checksum(&self) -> [u8; 32] {
        self.checkpoint_checksum
    }

    pub const fn signer_exact_watermark(&self) -> SignerWatermarkV0 {
        self.fields.signer_exact_watermark
    }

    /// Validate the monotonic link required for a non-initial CAS target.
    pub fn validate_successor_of(
        &self,
        predecessor: &Self,
    ) -> Result<(), ExternalNodeCheckpointDecodeErrorV0> {
        if self.scope() != predecessor.scope() {
            return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
                "successor scope",
            ));
        }
        let expected_generation = predecessor.generation().checked_add(1).ok_or(
            ExternalNodeCheckpointDecodeErrorV0::InvalidField("successor generation overflow"),
        )?;
        if self.generation() != expected_generation {
            return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
                "successor generation",
            ));
        }
        if self.predecessor_checksum() != predecessor.checkpoint_checksum() {
            return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
                "successor checkpoint checksum",
            ));
        }
        Ok(())
    }
}

/// Exact canonical decoding failures.  No decoding failure is retryable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalNodeCheckpointDecodeErrorV0 {
    WrongLength,
    WrongMagic,
    UnsupportedSchema,
    InvalidField(&'static str),
    ChecksumMismatch,
}

impl fmt::Display for ExternalNodeCheckpointDecodeErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength => formatter.write_str("external node checkpoint length differs"),
            Self::WrongMagic => formatter.write_str("external node checkpoint magic differs"),
            Self::UnsupportedSchema => {
                formatter.write_str("external node checkpoint schema is unsupported")
            }
            Self::InvalidField(field) => {
                write!(formatter, "external node checkpoint has invalid {field}")
            }
            Self::ChecksumMismatch => {
                formatter.write_str("external node checkpoint checksum differs")
            }
        }
    }
}

impl Error for ExternalNodeCheckpointDecodeErrorV0 {}

/// Closed errors supplied by an independently administered node-checkpoint
/// backend.  This interface is not an HSM/KMS contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalNodeCheckpointStoreErrorV0 {
    Unavailable,
    CompareFailed,
    InvalidPersistedState,
}

impl fmt::Display for ExternalNodeCheckpointStoreErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("external node checkpoint is unavailable"),
            Self::CompareFailed => {
                formatter.write_str("external node checkpoint compare-and-advance failed")
            }
            Self::InvalidPersistedState => {
                formatter.write_str("external node checkpoint persisted state is invalid")
            }
        }
    }
}

impl Error for ExternalNodeCheckpointStoreErrorV0 {}

/// Independently administered CAS storage for whole-node checkpoints.
///
/// This is a second CAS domain and must not be implemented by delegating to
/// `ExternalMonotonicWatermarkV0`.  Implementations must durably isolate one
/// value per scope from the Safety/App/signer namespaces.  For a first value,
/// `expected` must be `None`, `target.generation()` must be zero, and its
/// predecessor must be zero.  For a successor, the target must preserve scope,
/// advance generation by exactly one, and name `expected.checkpoint_checksum()`
/// as predecessor; implementations should call
/// [`ExternalNodeCheckpointV0::validate_successor_of`] or enforce the same
/// checks.  An uncertain result must be resolved by a fresh `load`.
pub trait ExternalNodeCheckpointStoreV0 {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<ExternalNodeCheckpointV0>, ExternalNodeCheckpointStoreErrorV0>;

    fn compare_and_advance(
        &mut self,
        expected: Option<ExternalNodeCheckpointV0>,
        target: ExternalNodeCheckpointV0,
    ) -> Result<(), ExternalNodeCheckpointStoreErrorV0>;
}

/// Durable SQLite implementation of the independent whole-node checkpoint CAS.
///
/// The caller must give this store its own absolute database path.  New stores
/// use a dedicated SQLite `application_id` and one exact `STRICT` table; an
/// existing database with any other application id, schema version, or user
/// schema is rejected.  This prevents accidentally attaching the checkpoint
/// table to a SafetyStore, ApplicationStore, signer journal, or unrelated
/// SQLite namespace.  On Unix, the database must remain one regular 0600 file
/// with link count one in a canonical, same-owner directory that is not group
/// or world writable.  The backend pins its device/inode identity and checks
/// the path before and after every open, load, and CAS operation.  Other
/// platforms fail closed because the standard library does not expose this
/// identity contract there.
///
/// Each scope owns one current canonical checkpoint row.  `compare_and_advance`
/// begins an `IMMEDIATE` transaction, strictly decodes the current row, compares
/// all canonical bytes with `expected`, and inserts or updates exactly one row.
/// A commit error is deliberately collapsed to [`ExternalNodeCheckpointStoreErrorV0::Unavailable`]:
/// the possibly transaction-bearing connection is discarded, and the handle
/// refuses every further CAS until an exact-scope `load` opens a new connection
/// to the pinned inode and observes either the durable source or target.
///
/// This backend is not connected to the process host and does not change the
/// development-only or production-activation gates in this crate.
pub struct SqliteExternalNodeCheckpointStoreV0 {
    database_path: PathBuf,
    path_identity: SqliteCheckpointPathIdentityV0,
    connection: Option<Connection>,
    uncertain_commit: Option<SqliteUncertainCommitV0>,
    #[cfg(test)]
    report_unavailable_after_next_commit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SqliteCheckpointPathIdentityV0 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    owner: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SqliteUncertainCommitV0 {
    scope: [u8; 32],
    expected: Option<ExternalNodeCheckpointV0>,
    target: ExternalNodeCheckpointV0,
}

impl SqliteExternalNodeCheckpointStoreV0 {
    /// Create and durably initialize a new independent checkpoint database.
    ///
    /// The database path must be absolute and must not already exist.  A failed
    /// initialization is never retried in place by this method; callers should
    /// quarantine the incomplete file and choose an explicit recovery action.
    pub fn initialize_new(
        database_path: impl AsRef<Path>,
    ) -> Result<Self, ExternalNodeCheckpointStoreErrorV0> {
        let database_path = validate_sqlite_database_path_v0(database_path.as_ref())?;
        let (created_file, path_identity) = create_private_sqlite_file_v0(&database_path)?;

        let mut connection = open_sqlite_checkpoint_connection_v0(&database_path)?;
        validate_sqlite_path_identity_v0(&database_path, path_identity)?;
        configure_sqlite_checkpoint_connection_v0(&connection, true)?;
        connection
            .pragma_update(None, "application_id", SQLITE_APPLICATION_ID_V0)
            .map_err(map_sqlite_checkpoint_error_v0)?;
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION_V0)
            .map_err(map_sqlite_checkpoint_error_v0)?;

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_checkpoint_error_v0)?;
        transaction
            .execute(SQLITE_CREATE_TABLE_V0, [])
            .map_err(map_sqlite_checkpoint_error_v0)?;
        transaction
            .commit()
            .map_err(|_| ExternalNodeCheckpointStoreErrorV0::Unavailable)?;

        validate_sqlite_checkpoint_schema_v0(&connection)?;
        sync_initialized_sqlite_checkpoint_v0(&connection, &database_path)?;
        validate_sqlite_path_identity_v0(&database_path, path_identity)?;
        drop(created_file);
        Ok(Self {
            database_path,
            path_identity,
            connection: Some(connection),
            uncertain_commit: None,
            #[cfg(test)]
            report_unavailable_after_next_commit: false,
        })
    }

    /// Open an existing independently initialized checkpoint database.
    pub fn open_existing(
        database_path: impl AsRef<Path>,
    ) -> Result<Self, ExternalNodeCheckpointStoreErrorV0> {
        let database_path = validate_sqlite_database_path_v0(database_path.as_ref())?;
        let path_identity = inspect_sqlite_path_identity_v0(&database_path)?;
        let connection = open_sqlite_checkpoint_connection_v0(&database_path)?;
        validate_sqlite_path_identity_v0(&database_path, path_identity)?;
        configure_sqlite_checkpoint_connection_v0(&connection, false)?;
        validate_sqlite_checkpoint_schema_v0(&connection)?;
        validate_sqlite_path_identity_v0(&database_path, path_identity)?;
        Ok(Self {
            database_path,
            path_identity,
            connection: Some(connection),
            uncertain_commit: None,
            #[cfg(test)]
            report_unavailable_after_next_commit: false,
        })
    }

    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    #[cfg(test)]
    fn report_unavailable_after_next_commit_v0(&mut self) {
        self.report_unavailable_after_next_commit = true;
    }
}

impl ExternalNodeCheckpointStoreV0 for SqliteExternalNodeCheckpointStoreV0 {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<ExternalNodeCheckpointV0>, ExternalNodeCheckpointStoreErrorV0> {
        if let Some(uncertain) = self.uncertain_commit {
            if uncertain.scope != scope {
                return Err(ExternalNodeCheckpointStoreErrorV0::Unavailable);
            }
            // The connection that reported an uncertain commit is never
            // reused.  Reopen the pinned inode and accept only one of the two
            // states which SQLite could durably have selected.
            let connection =
                reopen_sqlite_checkpoint_connection_v0(&self.database_path, self.path_identity)?;
            let loaded = load_sqlite_checkpoint_row_v0(&connection, scope)?;
            if loaded != uncertain.expected && loaded != Some(uncertain.target) {
                return Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState);
            }
            validate_sqlite_path_identity_v0(&self.database_path, self.path_identity)?;
            self.connection = Some(connection);
            self.uncertain_commit = None;
            return Ok(loaded);
        }

        if validate_sqlite_path_identity_v0(&self.database_path, self.path_identity).is_err() {
            self.connection = None;
            return Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState);
        }
        let loaded = self
            .connection
            .as_ref()
            .ok_or(ExternalNodeCheckpointStoreErrorV0::Unavailable)
            .and_then(validate_sqlite_checkpoint_schema_v0)
            .and_then(|()| {
                load_sqlite_checkpoint_row_v0(
                    self.connection
                        .as_ref()
                        .ok_or(ExternalNodeCheckpointStoreErrorV0::Unavailable)?,
                    scope,
                )
            });
        if validate_sqlite_path_identity_v0(&self.database_path, self.path_identity).is_err() {
            self.connection = None;
            return Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState);
        }
        loaded
    }

    fn compare_and_advance(
        &mut self,
        expected: Option<ExternalNodeCheckpointV0>,
        target: ExternalNodeCheckpointV0,
    ) -> Result<(), ExternalNodeCheckpointStoreErrorV0> {
        if self.uncertain_commit.is_some() {
            return Err(ExternalNodeCheckpointStoreErrorV0::Unavailable);
        }
        validate_sqlite_cas_shape_v0(expected.as_ref(), &target)?;
        if validate_sqlite_path_identity_v0(&self.database_path, self.path_identity).is_err() {
            self.connection = None;
            return Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState);
        }

        let scope = target.scope();
        let target_generation = target.generation().to_be_bytes();
        let target_checksum = target.checkpoint_checksum();
        let target_record = target.encode_canonical();
        #[cfg(test)]
        let report_unavailable = self.report_unavailable_after_next_commit;

        let transaction = self
            .connection
            .as_mut()
            .ok_or(ExternalNodeCheckpointStoreErrorV0::Unavailable)?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_checkpoint_error_v0)?;
        validate_sqlite_checkpoint_schema_v0(&transaction)?;
        let observed = load_sqlite_checkpoint_row_v0(&transaction, scope)?;
        if observed != expected {
            return Err(ExternalNodeCheckpointStoreErrorV0::CompareFailed);
        }

        let changed = match expected {
            None => transaction.execute(
                "INSERT INTO trnm_external_node_checkpoint_v0 \
                 (scope, generation, checkpoint_checksum, record) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    &scope[..],
                    &target_generation[..],
                    &target_checksum[..],
                    &target_record[..],
                ],
            ),
            Some(expected) => {
                let expected_generation = expected.generation().to_be_bytes();
                let expected_checksum = expected.checkpoint_checksum();
                let expected_record = expected.encode_canonical();
                transaction.execute(
                    "UPDATE trnm_external_node_checkpoint_v0 \
                     SET generation = ?1, checkpoint_checksum = ?2, record = ?3 \
                     WHERE scope = ?4 AND generation = ?5 \
                       AND checkpoint_checksum = ?6 AND record = ?7",
                    params![
                        &target_generation[..],
                        &target_checksum[..],
                        &target_record[..],
                        &scope[..],
                        &expected_generation[..],
                        &expected_checksum[..],
                        &expected_record[..],
                    ],
                )
            }
        }
        .map_err(map_sqlite_checkpoint_error_v0)?;
        if changed != 1 {
            return Err(ExternalNodeCheckpointStoreErrorV0::CompareFailed);
        }

        if validate_sqlite_path_identity_v0(&self.database_path, self.path_identity).is_err() {
            drop(transaction);
            self.connection = None;
            return Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState);
        }

        let commit_result = transaction.commit();
        #[cfg(test)]
        {
            self.report_unavailable_after_next_commit = false;
        }
        if commit_result.is_err() {
            self.uncertain_commit = Some(SqliteUncertainCommitV0 {
                scope,
                expected,
                target,
            });
            self.connection = None;
            return Err(ExternalNodeCheckpointStoreErrorV0::Unavailable);
        }
        if validate_sqlite_path_identity_v0(&self.database_path, self.path_identity).is_err() {
            self.uncertain_commit = Some(SqliteUncertainCommitV0 {
                scope,
                expected,
                target,
            });
            self.connection = None;
            return Err(ExternalNodeCheckpointStoreErrorV0::Unavailable);
        }
        #[cfg(test)]
        if report_unavailable {
            // Model an applied commit whose acknowledgement was lost.  The
            // production branch above applies the same freshness latch for an
            // actual SQLite commit error.
            self.uncertain_commit = Some(SqliteUncertainCommitV0 {
                scope,
                expected,
                target,
            });
            self.connection = None;
            return Err(ExternalNodeCheckpointStoreErrorV0::Unavailable);
        }
        Ok(())
    }
}

fn validate_sqlite_cas_shape_v0(
    expected: Option<&ExternalNodeCheckpointV0>,
    target: &ExternalNodeCheckpointV0,
) -> Result<(), ExternalNodeCheckpointStoreErrorV0> {
    match expected {
        None if target.generation() == 0 && target.predecessor_checksum() == [0; 32] => Ok(()),
        None => Err(ExternalNodeCheckpointStoreErrorV0::CompareFailed),
        Some(expected) => target
            .validate_successor_of(expected)
            .map_err(|_| ExternalNodeCheckpointStoreErrorV0::CompareFailed),
    }
}

fn validate_sqlite_database_path_v0(
    database_path: &Path,
) -> Result<PathBuf, ExternalNodeCheckpointStoreErrorV0> {
    if !database_path.is_absolute()
        || database_path.file_name().is_none()
        || database_path.parent().is_none()
        || database_path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ExternalNodeCheckpointStoreErrorV0::Unavailable);
    }
    validate_sqlite_parent_directory_v0(
        database_path
            .parent()
            .ok_or(ExternalNodeCheckpointStoreErrorV0::Unavailable)?,
        None,
    )?;
    Ok(database_path.to_path_buf())
}

fn create_private_sqlite_file_v0(
    database_path: &Path,
) -> Result<(File, SqliteCheckpointPathIdentityV0), ExternalNodeCheckpointStoreErrorV0> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options
        .open(database_path)
        .map_err(|_| ExternalNodeCheckpointStoreErrorV0::Unavailable)?;
    file.sync_all()
        .map_err(|_| ExternalNodeCheckpointStoreErrorV0::Unavailable)?;
    let identity = inspect_sqlite_file_identity_v0(&file)?;
    validate_sqlite_path_identity_v0(database_path, identity)?;
    Ok((file, identity))
}

#[cfg(unix)]
fn inspect_sqlite_file_identity_v0(
    file: &File,
) -> Result<SqliteCheckpointPathIdentityV0, ExternalNodeCheckpointStoreErrorV0> {
    let metadata = file
        .metadata()
        .map_err(|_| ExternalNodeCheckpointStoreErrorV0::Unavailable)?;
    validate_sqlite_file_metadata_v0(&metadata)?;
    Ok(SqliteCheckpointPathIdentityV0 {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
    })
}

#[cfg(not(unix))]
fn inspect_sqlite_file_identity_v0(
    _file: &File,
) -> Result<SqliteCheckpointPathIdentityV0, ExternalNodeCheckpointStoreErrorV0> {
    // The development backend deliberately fails closed where the standard
    // library cannot expose the Unix identity and permission contract.
    Err(ExternalNodeCheckpointStoreErrorV0::Unavailable)
}

#[cfg(unix)]
fn inspect_sqlite_path_identity_v0(
    database_path: &Path,
) -> Result<SqliteCheckpointPathIdentityV0, ExternalNodeCheckpointStoreErrorV0> {
    let metadata = fs::symlink_metadata(database_path)
        .map_err(|_| ExternalNodeCheckpointStoreErrorV0::Unavailable)?;
    validate_sqlite_file_metadata_v0(&metadata)?;
    let identity = SqliteCheckpointPathIdentityV0 {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
    };
    validate_sqlite_parent_directory_v0(
        database_path
            .parent()
            .ok_or(ExternalNodeCheckpointStoreErrorV0::Unavailable)?,
        Some(identity.owner),
    )?;
    Ok(identity)
}

#[cfg(not(unix))]
fn inspect_sqlite_path_identity_v0(
    _database_path: &Path,
) -> Result<SqliteCheckpointPathIdentityV0, ExternalNodeCheckpointStoreErrorV0> {
    Err(ExternalNodeCheckpointStoreErrorV0::Unavailable)
}

#[cfg(unix)]
fn validate_sqlite_file_metadata_v0(
    metadata: &fs::Metadata,
) -> Result<(), ExternalNodeCheckpointStoreErrorV0> {
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_sqlite_parent_directory_v0(
    parent: &Path,
    expected_owner: Option<u32>,
) -> Result<(), ExternalNodeCheckpointStoreErrorV0> {
    let metadata = fs::symlink_metadata(parent)
        .map_err(|_| ExternalNodeCheckpointStoreErrorV0::Unavailable)?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|_| ExternalNodeCheckpointStoreErrorV0::Unavailable)?;
    if !metadata.file_type().is_dir()
        || canonical_parent != parent
        || metadata.permissions().mode() & 0o022 != 0
        || expected_owner.is_some_and(|owner| metadata.uid() != owner)
    {
        return Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_sqlite_parent_directory_v0(
    _parent: &Path,
    _expected_owner: Option<u32>,
) -> Result<(), ExternalNodeCheckpointStoreErrorV0> {
    Err(ExternalNodeCheckpointStoreErrorV0::Unavailable)
}

fn validate_sqlite_path_identity_v0(
    database_path: &Path,
    expected: SqliteCheckpointPathIdentityV0,
) -> Result<(), ExternalNodeCheckpointStoreErrorV0> {
    let observed = inspect_sqlite_path_identity_v0(database_path)?;
    if observed != expected {
        return Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState);
    }
    Ok(())
}

fn open_sqlite_checkpoint_connection_v0(
    database_path: &Path,
) -> Result<Connection, ExternalNodeCheckpointStoreErrorV0> {
    Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(map_sqlite_checkpoint_error_v0)
}

fn reopen_sqlite_checkpoint_connection_v0(
    database_path: &Path,
    expected_identity: SqliteCheckpointPathIdentityV0,
) -> Result<Connection, ExternalNodeCheckpointStoreErrorV0> {
    validate_sqlite_path_identity_v0(database_path, expected_identity)?;
    let connection = open_sqlite_checkpoint_connection_v0(database_path)?;
    validate_sqlite_path_identity_v0(database_path, expected_identity)?;
    configure_sqlite_checkpoint_connection_v0(&connection, false)?;
    validate_sqlite_checkpoint_schema_v0(&connection)?;
    validate_sqlite_path_identity_v0(database_path, expected_identity)?;
    Ok(connection)
}

fn configure_sqlite_checkpoint_connection_v0(
    connection: &Connection,
    initialize: bool,
) -> Result<(), ExternalNodeCheckpointStoreErrorV0> {
    connection
        .busy_timeout(SQLITE_BUSY_TIMEOUT_V0)
        .map_err(map_sqlite_checkpoint_error_v0)?;
    if initialize {
        connection
            .execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=WAL;")
            .map_err(map_sqlite_checkpoint_error_v0)?;
    }
    connection
        .execute_batch(
            "PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;
             PRAGMA recursive_triggers=OFF;",
        )
        .map_err(map_sqlite_checkpoint_error_v0)?;

    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(map_sqlite_checkpoint_error_v0)?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(map_sqlite_checkpoint_error_v0)?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(map_sqlite_checkpoint_error_v0)?;
    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(map_sqlite_checkpoint_error_v0)?;
    if !journal_mode.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || foreign_keys != 1
        || trusted_schema != 0
    {
        return Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState);
    }
    Ok(())
}

fn validate_sqlite_checkpoint_schema_v0(
    connection: &Connection,
) -> Result<(), ExternalNodeCheckpointStoreErrorV0> {
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(map_sqlite_checkpoint_error_v0)?;
    let user_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(map_sqlite_checkpoint_error_v0)?;
    if application_id != SQLITE_APPLICATION_ID_V0 || user_version != SQLITE_SCHEMA_VERSION_V0 {
        return Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState);
    }

    let object_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema \
             WHERE type IN ('table', 'index', 'trigger', 'view') \
               AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(map_sqlite_checkpoint_error_v0)?;
    let create_sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
            params![SQLITE_TABLE_V0],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sqlite_checkpoint_error_v0)?;
    if object_count != 1 || create_sql.as_deref() != Some(SQLITE_CREATE_TABLE_V0) {
        return Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState);
    }
    Ok(())
}

fn sync_initialized_sqlite_checkpoint_v0(
    connection: &Connection,
    database_path: &Path,
) -> Result<(), ExternalNodeCheckpointStoreErrorV0> {
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(map_sqlite_checkpoint_error_v0)?;
    File::open(database_path)
        .and_then(|file| file.sync_all())
        .map_err(|_| ExternalNodeCheckpointStoreErrorV0::Unavailable)?;
    #[cfg(unix)]
    File::open(
        database_path
            .parent()
            .ok_or(ExternalNodeCheckpointStoreErrorV0::Unavailable)?,
    )
    .and_then(|directory| directory.sync_all())
    .map_err(|_| ExternalNodeCheckpointStoreErrorV0::Unavailable)?;
    Ok(())
}

fn load_sqlite_checkpoint_row_v0(
    connection: &Connection,
    requested_scope: [u8; 32],
) -> Result<Option<ExternalNodeCheckpointV0>, ExternalNodeCheckpointStoreErrorV0> {
    let row: Option<SqliteCheckpointRowV0> = connection
        .query_row(
            "SELECT scope, generation, checkpoint_checksum, record \
             FROM trnm_external_node_checkpoint_v0 WHERE scope = ?1",
            params![&requested_scope[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(map_sqlite_checkpoint_error_v0)?;
    row.map(|row| decode_sqlite_checkpoint_row_v0(requested_scope, row))
        .transpose()
}

fn decode_sqlite_checkpoint_row_v0(
    requested_scope: [u8; 32],
    row: SqliteCheckpointRowV0,
) -> Result<ExternalNodeCheckpointV0, ExternalNodeCheckpointStoreErrorV0> {
    let (stored_scope, stored_generation, stored_checksum, stored_record) = row;
    let stored_scope: [u8; 32] = stored_scope
        .try_into()
        .map_err(|_| ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState)?;
    let stored_generation: [u8; 8] = stored_generation
        .try_into()
        .map_err(|_| ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState)?;
    let stored_checksum: [u8; 32] = stored_checksum
        .try_into()
        .map_err(|_| ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState)?;
    if stored_scope != requested_scope {
        return Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState);
    }

    let checkpoint = ExternalNodeCheckpointV0::decode_canonical_exact(&stored_record)
        .map_err(|_| ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState)?;
    if checkpoint.scope() != stored_scope
        || checkpoint.generation() != u64::from_be_bytes(stored_generation)
        || checkpoint.checkpoint_checksum() != stored_checksum
        || checkpoint.encode_canonical().as_slice() != stored_record.as_slice()
    {
        return Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState);
    }
    Ok(checkpoint)
}

fn map_sqlite_checkpoint_error_v0(error: rusqlite::Error) -> ExternalNodeCheckpointStoreErrorV0 {
    match error {
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                ErrorCode::DatabaseCorrupt
                    | ErrorCode::NotADatabase
                    | ErrorCode::SchemaChanged
                    | ErrorCode::ConstraintViolation
                    | ErrorCode::TypeMismatch
            ) =>
        {
            ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState
        }
        rusqlite::Error::FromSqlConversionFailure(_, _, _)
        | rusqlite::Error::IntegralValueOutOfRange(_, _)
        | rusqlite::Error::InvalidColumnIndex(_)
        | rusqlite::Error::InvalidColumnName(_)
        | rusqlite::Error::InvalidColumnType(_, _, _) => {
            ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState
        }
        _ => ExternalNodeCheckpointStoreErrorV0::Unavailable,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfirmedNodeCheckpointOriginV0 {
    VirginGenesis,
    #[cfg_attr(not(any(test, feature = "legacy-consensus-app")), allow(dead_code))]
    ExistingNamespace,
}

/// One-shot evidence that trusted Safety/App/signer facts were joined.
///
/// The capability intentionally implements neither `Clone` nor `Copy`, has no
/// public constructor, and has no serde representation.  The crate-private
/// existing-namespace constructor consumes the three authenticated store
/// capabilities; a decoded [`ExternalNodeCheckpointV0`] alone cannot create
/// this capability.
///
/// ```compile_fail
/// use trnm_poco_node::ConfirmedNodeCheckpointCandidateV0;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<ConfirmedNodeCheckpointCandidateV0>();
/// ```
///
/// ```compile_fail
/// use trnm_poco_node::{ConfirmedNodeCheckpointCandidateV0, ExternalNodeCheckpointV0};
/// fn forge(checkpoint: ExternalNodeCheckpointV0) -> ConfirmedNodeCheckpointCandidateV0 {
///     ConfirmedNodeCheckpointCandidateV0 { checkpoint }
/// }
/// ```
#[derive(Debug)]
pub struct ConfirmedNodeCheckpointCandidateV0 {
    checkpoint: ExternalNodeCheckpointV0,
    origin: ConfirmedNodeCheckpointOriginV0,
}

impl ConfirmedNodeCheckpointCandidateV0 {
    pub const fn checkpoint(&self) -> &ExternalNodeCheckpointV0 {
        &self.checkpoint
    }
}

/// Non-forgeable result of a freshly joined native K/Safety/signer successor
/// and its exact independent-CAS readback.
///
/// This capability is intentionally private to the Node crate, non-Clone, and
/// cannot be decoded or reconstructed from the public checkpoint value. It is
/// not Core StorageAck authority and cannot release a signing request.
#[derive(Debug)]
pub(crate) struct ConfirmedNativeKNodeCheckpointV0 {
    checkpoint: ExternalNodeCheckpointV0,
    application_store_sequence: u64,
    application_row_checksum: [u8; 32],
}

impl ConfirmedNativeKNodeCheckpointV0 {
    pub(crate) const fn checkpoint_v0(&self) -> &ExternalNodeCheckpointV0 {
        &self.checkpoint
    }

    pub(crate) const fn application_store_sequence_v0(&self) -> u64 {
        self.application_store_sequence
    }

    pub(crate) const fn application_row_checksum_v0(&self) -> [u8; 32] {
        self.application_row_checksum
    }
}

/// Closed failures for the bounded native terminal-K successor coordinator.
#[derive(Debug)]
pub(crate) enum NativeKNodeCheckpointAdvanceErrorV0 {
    ExpectedExternalMismatch,
    CompareNotApplied,
    ThirdExternalState,
    SafetyOwnerMismatch,
    ApplicationOwnerMismatch,
    SignerOwnerMismatch,
    SafetyApplicationMismatch,
    SafetySignerMismatch,
    SignerAheadOfPendingVote,
    CandidateEncodingUnavailable,
    Safety(SafetyStoreErrorV0),
    Application(ValidationStoreErrorV0),
    Signer(SignerJournalErrorV0),
    Checkpoint(ExternalNodeCheckpointStoreErrorV0),
}

impl NativeKNodeCheckpointAdvanceErrorV0 {
    pub(crate) const fn is_compare_not_applied_v0(&self) -> bool {
        matches!(self, Self::CompareNotApplied)
    }
}

impl fmt::Display for NativeKNodeCheckpointAdvanceErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpectedExternalMismatch => formatter
                .write_str("independent whole-node checkpoint differs from the expected source"),
            Self::CompareNotApplied => {
                formatter.write_str("whole-node checkpoint successor CAS was proven not applied")
            }
            Self::ThirdExternalState => formatter
                .write_str("whole-node checkpoint fresh readback is neither source nor target"),
            Self::SafetyOwnerMismatch => {
                formatter.write_str("fresh Safety facts do not belong to the pinned Safety owner")
            }
            Self::ApplicationOwnerMismatch => formatter
                .write_str("fresh terminal-K facts do not belong to the pinned application owner"),
            Self::SignerOwnerMismatch => formatter
                .write_str("fresh signer facts do not belong to the operational signer owner"),
            Self::SafetyApplicationMismatch => formatter
                .write_str("terminal K differs from the exact authenticated Safety Vote head"),
            Self::SafetySignerMismatch => {
                formatter.write_str("operational signer identity differs from the Safety epoch")
            }
            Self::SignerAheadOfPendingVote => {
                formatter.write_str("signer journal is not strictly before the pending Safety Vote")
            }
            Self::CandidateEncodingUnavailable => {
                formatter.write_str("native whole-node checkpoint candidate is not canonical")
            }
            Self::Safety(source) => write!(formatter, "Safety checkpoint head: {source}"),
            Self::Application(source) => {
                write!(formatter, "application K checkpoint head: {source}")
            }
            Self::Signer(source) => write!(formatter, "signer checkpoint head: {source}"),
            Self::Checkpoint(source) => write!(formatter, "whole-node checkpoint store: {source}"),
        }
    }
}

impl Error for NativeKNodeCheckpointAdvanceErrorV0 {}

/// Freshly join one terminal application K, the exact authenticated Safety
/// Vote head, and an already-exact operational signer head, then advance the
/// independent whole-node CAS by exactly one successor.
///
/// The coordinator performs no signer-watermark repair, no Core callback, and
/// no signature operation.  A CAS error receives one mandatory fresh read:
/// only the exact target is accepted, the exact source is reported as safely
/// retryable, and every third state permanently fails closed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn advance_native_k_whole_node_checkpoint_v0<V, W, S>(
    checkpoint_store: &mut S,
    expected_external: ExternalNodeCheckpointV0,
    safety_store: &SqliteSafetyStateStoreV0<V>,
    expected_safety_path: &Path,
    application_store: &mut SqliteProposalValidationStoreV0,
    expected_application_path: &Path,
    binding: &ProposalValidationBindingV0,
    signer_journal: &mut SqliteSignerJournalV0<W>,
    expected_signer_path: &Path,
) -> Result<ConfirmedNativeKNodeCheckpointV0, NativeKNodeCheckpointAdvanceErrorV0>
where
    V: SignatureVerifier,
    W: ExternalMonotonicWatermarkV0,
    S: ExternalNodeCheckpointStoreV0,
{
    let scope = expected_external.scope();
    if checkpoint_store
        .load(scope)
        .map_err(NativeKNodeCheckpointAdvanceErrorV0::Checkpoint)?
        != Some(expected_external)
    {
        return Err(NativeKNodeCheckpointAdvanceErrorV0::ExpectedExternalMismatch);
    }

    // Confirm signer first because it is the only observation which crosses
    // another external monotonic namespace. Safety and K are authenticated
    // after it, immediately before the independent whole-node CAS.
    let signer = signer_journal
        .confirm_node_checkpoint_head_exact_v0()
        .map_err(NativeKNodeCheckpointAdvanceErrorV0::Signer)?;
    if !signer.belongs_to_operational_journal_at_path_v0(signer_journal, expected_signer_path) {
        return Err(NativeKNodeCheckpointAdvanceErrorV0::SignerOwnerMismatch);
    }
    let safety_head = safety_store
        .head()
        .map_err(NativeKNodeCheckpointAdvanceErrorV0::Safety)?;
    let safety = safety_store
        .confirm_node_checkpoint_head_exact_v0(safety_head.state())
        .map_err(NativeKNodeCheckpointAdvanceErrorV0::Safety)?;
    if !safety.belongs_to_store_at_path_v0(safety_store, expected_safety_path) {
        return Err(NativeKNodeCheckpointAdvanceErrorV0::SafetyOwnerMismatch);
    }
    let application = application_store
        .confirm_proposal_validation_checkpoint_facts_exact_v0(binding)
        .map_err(NativeKNodeCheckpointAdvanceErrorV0::Application)?;
    if !application.belongs_to_store_at_path_v0(application_store, expected_application_path) {
        return Err(NativeKNodeCheckpointAdvanceErrorV0::ApplicationOwnerMismatch);
    }

    validate_native_checkpoint_predecessor_v0(expected_external, &safety, &application, &signer)?;
    validate_native_k_checkpoint_join_v0(&safety, &application, &signer, signer_journal)?;
    let target =
        native_k_checkpoint_successor_v0(expected_external, &safety, &application, &signer)?;

    let compare_result = checkpoint_store.compare_and_advance(Some(expected_external), target);
    let observed = checkpoint_store
        .load(scope)
        .map_err(NativeKNodeCheckpointAdvanceErrorV0::Checkpoint)?;
    match observed {
        Some(value) if value == target => Ok(ConfirmedNativeKNodeCheckpointV0 {
            checkpoint: value,
            application_store_sequence: application.store_sequence_v0(),
            application_row_checksum: *application.row_checksum_v0().as_bytes(),
        }),
        Some(value) if value == expected_external => {
            let _ = compare_result;
            Err(NativeKNodeCheckpointAdvanceErrorV0::CompareNotApplied)
        }
        _ => Err(NativeKNodeCheckpointAdvanceErrorV0::ThirdExternalState),
    }
}

fn validate_native_checkpoint_predecessor_v0(
    predecessor: ExternalNodeCheckpointV0,
    safety: &ConfirmedSafetyNodeCheckpointFactsV0,
    application: &ConfirmedProposalValidationCheckpointFactsV0,
    signer: &ConfirmedSignerNodeCheckpointFactsV0,
) -> Result<(), NativeKNodeCheckpointAdvanceErrorV0> {
    let fields = predecessor.fields();
    let binding = application.binding_v0();
    if fields.scope != signer.exact_watermark().scope()
        || fields.signer_journal_id != signer.journal_id()
        || fields.signer_profile_checksum != signer.profile_checksum()
        || fields.signer_exact_watermark != signer.exact_watermark()
        || fields.safety_journal_id != safety.journal_id_v0()
        || fields.safety_verifier_profile_ref != safety.verifier_profile_ref_v0()
        || fields.safety_revision >= safety.revision_v0()
        || fields.application_height >= binding.height().get()
        || fields.application_view >= binding.view()
    {
        return Err(NativeKNodeCheckpointAdvanceErrorV0::ExpectedExternalMismatch);
    }
    Ok(())
}

fn validate_native_k_checkpoint_join_v0<W: ExternalMonotonicWatermarkV0>(
    safety: &ConfirmedSafetyNodeCheckpointFactsV0,
    application: &ConfirmedProposalValidationCheckpointFactsV0,
    signer: &ConfirmedSignerNodeCheckpointFactsV0,
    signer_journal: &SqliteSignerJournalV0<W>,
) -> Result<(), NativeKNodeCheckpointAdvanceErrorV0> {
    let state = safety.state_v0();
    let binding = application.binding_v0();
    let closure = application.safety_closure_v0();
    let pending = state
        .pending_sign()
        .ok_or(NativeKNodeCheckpointAdvanceErrorV0::SafetyApplicationMismatch)?;
    let SignIntent::Vote {
        authorizing_safety_revision,
        view,
        height,
        block_id,
        signing_root,
    } = pending
    else {
        return Err(NativeKNodeCheckpointAdvanceErrorV0::SafetyApplicationMismatch);
    };
    if binding.chain_id().as_str() != state.chain_id().as_str()
        || binding.active_validator_set_id().as_bytes() != state.validator_set_id().as_bytes()
        || binding.validation_id() != closure.validation_id()
        || application.core_delivery_digest_v0() != closure.core_delivery_digest()
        || safety.revision_v0() != closure.safety_revision()
        || safety.state_record_checksum_v0() != *closure.safety_record_digest().as_bytes()
        || *authorizing_safety_revision != closure.safety_revision()
        || binding.block_id().as_bytes() != block_id.as_bytes()
        || binding.height().get() != height.get()
        || binding.view() != view.get()
        || closure.vote_intent_digest().as_bytes() != signing_root.as_bytes()
        || state.last_voted_view() != Some(*view)
    {
        return Err(NativeKNodeCheckpointAdvanceErrorV0::SafetyApplicationMismatch);
    }

    let identity = signer.identity();
    let profile = signer_journal.profile();
    if identity.chain_id() != state.chain_id()
        || identity.protocol_version() != state.protocol_version()
        || identity.epoch() != state.epoch()
        || identity.validator_set_id() != state.validator_set_id()
        || profile.chain_id() != state.chain_id()
        || profile.protocol_version() != state.protocol_version()
        || profile.epoch() != state.epoch()
        || profile.validator_set_id() != state.validator_set_id()
        || profile.author() != identity.author()
        || profile.profile_checksum() != signer.profile_checksum()
        || profile.external_watermark_scope() != identity.external_watermark_scope()
        || signer.exact_watermark().scope() != identity.external_watermark_scope()
        || signer.exact_watermark().journal_id() != signer.journal_id()
    {
        return Err(NativeKNodeCheckpointAdvanceErrorV0::SafetySignerMismatch);
    }
    let capacity = signer.capacity();
    if signer.pending_intent().is_some()
        || capacity
            .maximum_safety_revision()
            .is_some_and(|revision| revision >= safety.revision_v0())
        || capacity
            .maximum_vote_view()
            .is_some_and(|signed_view| signed_view >= view.get())
        || capacity.maximum_timeout_view().is_some_and(|signed_view| {
            state
                .last_timeout_view()
                .is_none_or(|timeout_view| signed_view > timeout_view.get())
        })
    {
        return Err(NativeKNodeCheckpointAdvanceErrorV0::SignerAheadOfPendingVote);
    }
    Ok(())
}

fn native_k_checkpoint_successor_v0(
    predecessor: ExternalNodeCheckpointV0,
    safety: &ConfirmedSafetyNodeCheckpointFactsV0,
    application: &ConfirmedProposalValidationCheckpointFactsV0,
    signer: &ConfirmedSignerNodeCheckpointFactsV0,
) -> Result<ExternalNodeCheckpointV0, NativeKNodeCheckpointAdvanceErrorV0> {
    let binding = application.binding_v0();
    let closure = application.safety_closure_v0();
    let generation = predecessor
        .generation()
        .checked_add(1)
        .ok_or(NativeKNodeCheckpointAdvanceErrorV0::CandidateEncodingUnavailable)?;
    let store_sequence = application.store_sequence_v0().to_be_bytes();
    let row_revision = application.row_revision_v0().to_be_bytes();
    let safety_revision = closure.safety_revision().to_be_bytes();
    let application_host_config_ref = native_checkpoint_hash_v0(
        b"trnm.native-k-checkpoint.application-owner.v0",
        &[
            application.scope_v0().as_bytes(),
            &application.store_id_v0(),
            binding.chain_id().as_str().as_bytes(),
            binding.genesis_hash().as_bytes(),
        ],
    );
    let application_projection_profile_ref = native_checkpoint_hash_v0(
        b"trnm.native-k-checkpoint.projection-profile.v0",
        &[b"proposal-validation-schema-3", b"terminal-k"],
    );
    let application_safety_binding_manifest_checksum = native_checkpoint_hash_v0(
        b"trnm.native-k-checkpoint.safety-binding.v0",
        &[
            &safety.journal_id_v0(),
            &safety.verifier_profile_ref_v0(),
            &safety.core_config_ref_v0(),
            &safety_revision,
            &safety.state_record_checksum_v0(),
            &safety.chain_checksum_v0(),
            closure.core_delivery_digest().as_bytes(),
            closure.safety_record_digest().as_bytes(),
            closure.vote_intent_digest().as_bytes(),
        ],
    );
    let application_recovery_closure_checksum = native_checkpoint_hash_v0(
        b"trnm.native-k-checkpoint.recovery-closure.v0",
        &[
            application.scope_v0().as_bytes(),
            &application.store_id_v0(),
            binding.validation_id().as_bytes(),
            &store_sequence,
            &row_revision,
            application.row_checksum_v0().as_bytes(),
            application.artifact_digest_v0().as_bytes(),
            application.core_delivery_digest_v0().as_bytes(),
            closure.safety_record_digest().as_bytes(),
            closure.vote_intent_digest().as_bytes(),
        ],
    );
    ExternalNodeCheckpointV0::new(ExternalNodeCheckpointFieldsV0 {
        scope: signer.exact_watermark().scope(),
        generation,
        predecessor_checksum: predecessor.checkpoint_checksum(),
        safety_journal_id: safety.journal_id_v0(),
        safety_verifier_profile_ref: safety.verifier_profile_ref_v0(),
        safety_revision: safety.revision_v0(),
        safety_state_record_checksum: safety.state_record_checksum_v0(),
        safety_record_chain_checksum: safety.chain_checksum_v0(),
        application_host_config_ref,
        application_projection_profile_ref,
        application_safety_binding_manifest_checksum,
        application_committed_head_row_checksum: *application.row_checksum_v0().as_bytes(),
        application_recovery_closure_checksum,
        application_block_id: BlockId::new(*binding.block_id().as_bytes()),
        application_height: binding.height().get(),
        application_state_root: StateRoot::new(*binding.commitments().post_state_root().as_bytes()),
        application_view: binding.view(),
        application_timestamp_ms: binding.timestamp_ms(),
        signer_journal_id: signer.journal_id(),
        signer_profile_checksum: signer.profile_checksum(),
        signer_exact_watermark: signer.exact_watermark(),
    })
    .map_err(|_| NativeKNodeCheckpointAdvanceErrorV0::CandidateEncodingUnavailable)
}

fn native_checkpoint_hash_v0(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Closed failures from the authority-free existing-namespace trusted join.
///
/// The join consumes all three store capabilities even when it refuses their
/// projections.  No variant grants commissioning, successor construction,
/// CAS access, store ownership, signing, or application authority.
#[cfg(feature = "legacy-consensus-app")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExistingNodeCheckpointJoinErrorV0 {
    AuthenticatedGenesisCommissioningRequiresDedicatedHost,
    ReplayFencedStateUnavailable,
    SafetyScopeMismatch,
    SafetyOwnerMismatch,
    SafetyHeadReconfirmationUnavailable,
    SafetyVerifierProfileMismatch,
    SafetyConfigurationMismatch,
    ApplicationOwnerMismatch,
    ApplicationHeadReconfirmationUnavailable,
    ApplicationSafetyProvenanceMismatch,
    ApplicationConfigurationMismatch,
    ApplicationAppliedMismatch,
    ApplicationAppliedRootUnavailable,
    SignerOwnerMismatch,
    SignerHeadReconfirmationUnavailable,
    SignerIdentityMismatch,
    SignerProfileMismatch,
    SignerWatermarkMismatch,
    SignerAheadOfSafety,
    SignerVoteViewMismatch,
    SignerTimeoutViewMismatch,
    PreparedSignerWithoutSafetyIntent,
    PreparedSignerIntentMismatch,
    PendingSignerTailMismatch,
    PendingSafetyIntentWithoutSignerTail,
    CandidateEncodingUnavailable,
    ObservedExternalMismatch,
}

#[cfg(feature = "legacy-consensus-app")]
impl fmt::Display for ExistingNodeCheckpointJoinErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::AuthenticatedGenesisCommissioningRequiresDedicatedHost => {
                "authenticated genesis application commissioning requires its dedicated inert host"
            }
            Self::ReplayFencedStateUnavailable => {
                "replay-fenced state cannot mint an existing node checkpoint candidate"
            }
            Self::SafetyScopeMismatch => "SafetyState scope differs from the node configuration",
            Self::SafetyOwnerMismatch => {
                "Safety facts do not belong to the configured live SafetyStore owner"
            }
            Self::SafetyHeadReconfirmationUnavailable => {
                "configured live SafetyStore head no longer matches the consumed facts"
            }
            Self::SafetyVerifierProfileMismatch => {
                "Safety verifier profile differs from the node configuration"
            }
            Self::SafetyConfigurationMismatch => {
                "SafetyStore record configuration differs from the node configuration"
            }
            Self::ApplicationSafetyProvenanceMismatch => {
                "ApplicationStore Safety provenance differs from the authenticated Safety head"
            }
            Self::ApplicationOwnerMismatch => {
                "application facts do not belong to the configured live application owner"
            }
            Self::ApplicationHeadReconfirmationUnavailable => {
                "configured live application head cannot be freshly joined to SafetyStore"
            }
            Self::ApplicationConfigurationMismatch => {
                "ApplicationStore host configuration differs from the node process configuration"
            }
            Self::ApplicationAppliedMismatch => {
                "ApplicationStore head differs from Safety application_applied"
            }
            Self::ApplicationAppliedRootUnavailable => {
                "SafetyStore has no retained authenticated proof for application_applied root"
            }
            Self::SignerOwnerMismatch => {
                "signer facts do not belong to the configured live pinned signer owner"
            }
            Self::SignerHeadReconfirmationUnavailable => {
                "configured live signer head cannot be freshly confirmed against its external watermark"
            }
            Self::SignerIdentityMismatch => {
                "signer identity differs from the node and Safety configuration"
            }
            Self::SignerProfileMismatch => "signer profile differs from the node configuration",
            Self::SignerWatermarkMismatch => {
                "signer watermark differs from its authenticated identity or journal"
            }
            Self::SignerAheadOfSafety => "signer Safety revision is ahead of SafetyStore",
            Self::SignerVoteViewMismatch => "signer vote watermark differs from SafetyState",
            Self::SignerTimeoutViewMismatch => "signer timeout watermark differs from SafetyState",
            Self::PreparedSignerWithoutSafetyIntent => {
                "signer has a prepared intent without a SafetyState sign intent"
            }
            Self::PreparedSignerIntentMismatch => {
                "prepared signer intent differs from the canonical SafetyState intent"
            }
            Self::PendingSignerTailMismatch => {
                "signer journal tail differs from the canonical SafetyState intent"
            }
            Self::PendingSafetyIntentWithoutSignerTail => {
                "journaled SafetyState intent has no exact signer tail"
            }
            Self::CandidateEncodingUnavailable => {
                "capability-derived node checkpoint fields are not canonical"
            }
            Self::ObservedExternalMismatch => {
                "capability-derived node checkpoint differs from the observed external value"
            }
        };
        formatter.write_str(message)
    }
}

#[cfg(feature = "legacy-consensus-app")]
impl Error for ExistingNodeCheckpointJoinErrorV0 {}

#[cfg(feature = "legacy-consensus-app")]
#[derive(Debug, Clone, Copy)]
struct SafetyNodeCheckpointProjectionV0<'a> {
    state: &'a SafetyState,
    application_applied_state_root: Option<StateRoot>,
    journal_id: [u8; 32],
    verifier_profile_ref: [u8; 32],
    core_config_ref: [u8; 32],
    revision: u64,
    state_record_checksum: [u8; 32],
    chain_checksum: [u8; 32],
}

#[cfg(feature = "legacy-consensus-app")]
#[derive(Debug, Clone, Copy)]
struct ApplicationNodeCheckpointProjectionV0 {
    host_config_ref: [u8; 32],
    projection_profile_ref: [u8; 32],
    safety_journal_id: [u8; 32],
    safety_verifier_profile_ref: [u8; 32],
    safety_revision: u64,
    safety_state_record_checksum: [u8; 32],
    safety_chain_checksum: [u8; 32],
    safety_binding_manifest_checksum: [u8; 32],
    committed_head_row_checksum: [u8; 32],
    recovery_closure_checksum: [u8; 32],
    block_id: BlockId,
    height: u64,
    state_root: StateRoot,
    view: u64,
    timestamp_ms: u64,
}

#[cfg(feature = "legacy-consensus-app")]
#[derive(Debug, Clone, Copy)]
struct SignerNodeCheckpointProjectionV0 {
    journal_id: [u8; 32],
    profile_checksum: [u8; 32],
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_id: ValidatorSetId,
    author: ValidatorId,
    signer_profile_ref: [u8; 32],
    external_watermark_scope: [u8; 32],
    exact_watermark: SignerWatermarkV0,
    capacity: SignerLifecycleCapacityProjectionV0,
    tail: Option<SignerJournalTailFactsV0>,
    pending_intent: Option<SignerPreparedIntentFactsV0>,
}

#[cfg(feature = "legacy-consensus-app")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SignerLifecycleCapacityProjectionV0 {
    maximum_safety_revision: Option<u64>,
    maximum_vote_view: Option<u64>,
    maximum_timeout_view: Option<u64>,
}

#[cfg(feature = "legacy-consensus-app")]
pub(crate) type ExistingNodeCheckpointJoinCapabilitiesV0 = (
    ConfirmedSafetyNodeCheckpointFactsV0,
    ConfirmedNativeApplicationNodeCheckpointFactsV0,
    ConfirmedSignerNodeCheckpointFactsV0,
);

/// Consume exact Safety, Application, and signer heads and mint only a
/// read-only candidate for an already-observed external checkpoint.
///
/// Generation and predecessor are copied from `observed_external`; they are
/// never selected from local state.  The complete capability-derived value
/// must then equal `observed_external` before the ExistingNamespace candidate
/// is released.  This boundary cannot commission a namespace or construct a
/// successor, performs only fresh read-only store/watermark confirmation with
/// no write/CAS/effect, and rejects the permanent h1 replay fence.
#[cfg(feature = "legacy-consensus-app")]
#[allow(dead_code)] // The production host and external backend remain deliberately unwired.
pub(crate) fn confirm_existing_node_checkpoint_candidate_v0<W: ExternalMonotonicWatermarkV0>(
    observed_external: ExternalNodeCheckpointV0,
    config: &PocoNodeProcessConfigV0,
    safety_store: &mut SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    application_host: &mut NativeConsensusApplicationHostV0,
    pinned_signer: &mut PinnedSqliteSignerJournalV0<W>,
    capabilities: ExistingNodeCheckpointJoinCapabilitiesV0,
) -> Result<ConfirmedNodeCheckpointCandidateV0, ExistingNodeCheckpointJoinErrorV0> {
    if config
        .node_config()
        .core_config()
        .authenticated_genesis_application_parent_v0()
        .is_some()
    {
        return Err(
            ExistingNodeCheckpointJoinErrorV0::
                AuthenticatedGenesisCommissioningRequiresDedicatedHost,
        );
    }
    let (prior_safety, prior_application, prior_signer) = capabilities;
    let node_config = config.node_config();
    let core_config = node_config.core_config();
    if !prior_safety.belongs_to_store_at_path_v0(safety_store, node_config.safety_store_path()) {
        return Err(ExistingNodeCheckpointJoinErrorV0::SafetyOwnerMismatch);
    }
    let application_path = config
        .application_config()
        .state_path
        .as_deref()
        .expect("validated process config retains its application path");
    if !prior_application.belongs_to_host_at_path_v0(application_host, application_path) {
        return Err(ExistingNodeCheckpointJoinErrorV0::ApplicationOwnerMismatch);
    }
    if !prior_signer
        .belongs_to_pinned_journal_at_path_v0(pinned_signer, node_config.signer_journal_path())
    {
        return Err(ExistingNodeCheckpointJoinErrorV0::SignerOwnerMismatch);
    }

    // Owner affinity alone is not a freshness proof: each owner can advance
    // after minting a detached capability. Reconfirm all three live heads in
    // signer -> Safety -> Application order and use only the fresh facts for
    // the candidate. The signer callback is the only observation outside the
    // two local store owners, so the local heads are deliberately confirmed
    // after it. A stale consumed capability therefore cannot authorize its
    // old cut.
    let signer = pinned_signer
        .confirm_node_checkpoint_head_exact_v0()
        .map_err(|_| ExistingNodeCheckpointJoinErrorV0::SignerHeadReconfirmationUnavailable)?;
    let safety = safety_store
        .confirm_node_checkpoint_head_exact_v0(prior_safety.state_v0())
        .map_err(|_| ExistingNodeCheckpointJoinErrorV0::SafetyHeadReconfirmationUnavailable)?;
    let application = application_host
        .confirm_node_checkpoint_facts_v0(&safety)
        .map_err(|_| ExistingNodeCheckpointJoinErrorV0::ApplicationHeadReconfirmationUnavailable)?;

    let safety_projection = SafetyNodeCheckpointProjectionV0 {
        state: safety.state_v0(),
        application_applied_state_root: safety_application_applied_state_root_v0(safety.state_v0()),
        journal_id: safety.journal_id_v0(),
        verifier_profile_ref: safety.verifier_profile_ref_v0(),
        core_config_ref: safety.core_config_ref_v0(),
        revision: safety.revision_v0(),
        state_record_checksum: safety.state_record_checksum_v0(),
        chain_checksum: safety.chain_checksum_v0(),
    };
    let application_projection = ApplicationNodeCheckpointProjectionV0 {
        host_config_ref: application.host_config_ref_v0(),
        projection_profile_ref: application.projection_profile_ref_v0(),
        safety_journal_id: application.safety_journal_id_v0(),
        safety_verifier_profile_ref: application.safety_verifier_profile_ref_v0(),
        safety_revision: application.safety_revision_v0(),
        safety_state_record_checksum: application.safety_state_record_checksum_v0(),
        safety_chain_checksum: application.safety_chain_checksum_v0(),
        safety_binding_manifest_checksum: application.safety_binding_manifest_checksum_v0(),
        committed_head_row_checksum: application.committed_head_row_checksum_v0(),
        recovery_closure_checksum: application.recovery_closure_checksum_v0(),
        block_id: application.block_id_v0(),
        height: application.height_v0(),
        state_root: StateRoot::new(application.state_root_v0()),
        view: application.view_v0(),
        timestamp_ms: application.timestamp_ms_v0(),
    };
    if !application.matches_application_config_v0(config.application_config()) {
        return Err(ExistingNodeCheckpointJoinErrorV0::ApplicationConfigurationMismatch);
    }
    let signer_identity = signer.identity();
    let signer_projection = SignerNodeCheckpointProjectionV0 {
        journal_id: signer.journal_id(),
        profile_checksum: signer.profile_checksum(),
        chain_id: signer_identity.chain_id(),
        protocol_version: signer_identity.protocol_version(),
        epoch: signer_identity.epoch(),
        validator_set_id: signer_identity.validator_set_id(),
        author: signer_identity.author(),
        signer_profile_ref: signer_identity.signer_profile_ref(),
        external_watermark_scope: signer_identity.external_watermark_scope(),
        exact_watermark: signer.exact_watermark(),
        capacity: SignerLifecycleCapacityProjectionV0 {
            maximum_safety_revision: signer.capacity().maximum_safety_revision(),
            maximum_vote_view: signer.capacity().maximum_vote_view(),
            maximum_timeout_view: signer.capacity().maximum_timeout_view(),
        },
        tail: signer.tail(),
        pending_intent: signer.pending_intent(),
    };
    confirm_existing_node_checkpoint_projected_v0(
        observed_external,
        core_config,
        node_config.record_limits(),
        node_config.safety_verifier_profile_ref_v0(),
        &node_config.signer_journal_profile,
        safety_projection,
        application_projection,
        signer_projection,
    )
}

#[cfg(feature = "legacy-consensus-app")]
#[allow(clippy::too_many_arguments)]
fn confirm_existing_node_checkpoint_projected_v0(
    observed_external: ExternalNodeCheckpointV0,
    core_config: &trnm_consensus_core::CoreConfig,
    record_limits: trnm_consensus_core::SafetyStateRecordLimitsV0,
    configured_safety_verifier_profile_ref: [u8; 32],
    signer_profile: &trnm_consensus_signer_journal::SignerJournalProfileV0,
    safety: SafetyNodeCheckpointProjectionV0<'_>,
    application: ApplicationNodeCheckpointProjectionV0,
    signer: SignerNodeCheckpointProjectionV0,
) -> Result<ConfirmedNodeCheckpointCandidateV0, ExistingNodeCheckpointJoinErrorV0> {
    if safety.state.state_sync_anchor().is_some() {
        return Err(ExistingNodeCheckpointJoinErrorV0::ReplayFencedStateUnavailable);
    }
    let validator_set = core_config.validator_set();
    if safety.state.chain_id() != validator_set.chain_id()
        || safety.state.protocol_version() != validator_set.protocol_version()
        || safety.state.epoch() != validator_set.epoch()
        || safety.state.validator_set_id() != validator_set.id()
        || safety.state.genesis_block_id() != core_config.genesis_block_id()
        || safety.state.revision() != safety.revision
    {
        return Err(ExistingNodeCheckpointJoinErrorV0::SafetyScopeMismatch);
    }
    if safety.verifier_profile_ref != configured_safety_verifier_profile_ref {
        return Err(ExistingNodeCheckpointJoinErrorV0::SafetyVerifierProfileMismatch);
    }
    let record_context = SafetyStateRecordContextV0::new(
        core_config,
        configured_safety_verifier_profile_ref,
        record_limits,
    )
    .map_err(|_| ExistingNodeCheckpointJoinErrorV0::SafetyConfigurationMismatch)?;
    let expected_core_config_ref = safety_state_record_config_ref_v0(&record_context)
        .map_err(|_| ExistingNodeCheckpointJoinErrorV0::SafetyConfigurationMismatch)?;
    if safety.core_config_ref != expected_core_config_ref {
        return Err(ExistingNodeCheckpointJoinErrorV0::SafetyConfigurationMismatch);
    }

    if application.safety_journal_id != safety.journal_id
        || application.safety_verifier_profile_ref != safety.verifier_profile_ref
        || application.safety_revision != safety.revision
        || application.safety_state_record_checksum != safety.state_record_checksum
        || application.safety_chain_checksum != safety.chain_checksum
    {
        return Err(ExistingNodeCheckpointJoinErrorV0::ApplicationSafetyProvenanceMismatch);
    }
    let applied = safety.state.application_applied();
    let authenticated_applied_root = safety
        .application_applied_state_root
        .ok_or(ExistingNodeCheckpointJoinErrorV0::ApplicationAppliedRootUnavailable)?;
    if application.block_id != applied.block_id()
        || application.height != applied.height().get()
        || authenticated_applied_root != application.state_root
        || application.view != applied.view().get()
        || application.timestamp_ms != applied.timestamp_ms()
    {
        return Err(ExistingNodeCheckpointJoinErrorV0::ApplicationAppliedMismatch);
    }

    if signer.chain_id != validator_set.chain_id()
        || signer.protocol_version != validator_set.protocol_version()
        || signer.epoch != validator_set.epoch()
        || signer.validator_set_id != validator_set.id()
        || signer.author != core_config.local_validator()
        || signer_profile.validator_set() != validator_set
        || signer_profile.author() != core_config.local_validator()
    {
        return Err(ExistingNodeCheckpointJoinErrorV0::SignerIdentityMismatch);
    }
    if signer.signer_profile_ref != signer_profile.signer_profile_ref()
        || signer.external_watermark_scope != signer_profile.external_watermark_scope()
        || signer.profile_checksum != signer_profile.profile_checksum()
    {
        return Err(ExistingNodeCheckpointJoinErrorV0::SignerProfileMismatch);
    }
    if signer.exact_watermark.scope() != signer.external_watermark_scope
        || signer.exact_watermark.journal_id() != signer.journal_id
    {
        return Err(ExistingNodeCheckpointJoinErrorV0::SignerWatermarkMismatch);
    }
    validate_signer_lifecycle_against_safety_v0(
        signer.capacity,
        signer.tail,
        signer.pending_intent,
        safety.state,
        core_config,
    )?;

    let candidate = ExternalNodeCheckpointV0::new(ExternalNodeCheckpointFieldsV0 {
        scope: signer.external_watermark_scope,
        generation: observed_external.generation(),
        predecessor_checksum: observed_external.predecessor_checksum(),
        safety_journal_id: safety.journal_id,
        safety_verifier_profile_ref: safety.verifier_profile_ref,
        safety_revision: safety.revision,
        safety_state_record_checksum: safety.state_record_checksum,
        safety_record_chain_checksum: safety.chain_checksum,
        application_host_config_ref: application.host_config_ref,
        application_projection_profile_ref: application.projection_profile_ref,
        application_safety_binding_manifest_checksum: application.safety_binding_manifest_checksum,
        application_committed_head_row_checksum: application.committed_head_row_checksum,
        application_recovery_closure_checksum: application.recovery_closure_checksum,
        application_block_id: application.block_id,
        application_height: application.height,
        application_state_root: application.state_root,
        application_view: application.view,
        application_timestamp_ms: application.timestamp_ms,
        signer_journal_id: signer.journal_id,
        signer_profile_checksum: signer.profile_checksum,
        signer_exact_watermark: signer.exact_watermark,
    })
    .map_err(|_| ExistingNodeCheckpointJoinErrorV0::CandidateEncodingUnavailable)?;
    if candidate != observed_external {
        return Err(ExistingNodeCheckpointJoinErrorV0::ObservedExternalMismatch);
    }
    Ok(ConfirmedNodeCheckpointCandidateV0 {
        checkpoint: candidate,
        origin: ConfirmedNodeCheckpointOriginV0::ExistingNamespace,
    })
}

#[cfg(feature = "legacy-consensus-app")]
fn safety_application_applied_state_root_v0(safety: &SafetyState) -> Option<StateRoot> {
    let applied = safety.application_applied();
    if let Some(anchor) = safety
        .state_sync_anchor()
        .filter(|anchor| anchor.proof().finalized_block().header().id() == applied.block_id())
    {
        return Some(anchor.proof().finalized_block().header().state_root());
    }
    if let Some(finalization) = safety.last_finalization().filter(|finalization| {
        finalization.proof().finalized_block().header().id() == applied.block_id()
    }) {
        return Some(finalization.proof().finalized_block().header().state_root());
    }
    safety
        .finalization_queue()
        .iter()
        .find(|finalization| {
            finalization.proof().finalized_block().header().id() == applied.block_id()
        })
        .map(|finalization| finalization.proof().finalized_block().header().state_root())
}

#[cfg(feature = "legacy-consensus-app")]
fn validate_signer_lifecycle_against_safety_v0(
    capacity: SignerLifecycleCapacityProjectionV0,
    tail: Option<SignerJournalTailFactsV0>,
    pending_intent: Option<SignerPreparedIntentFactsV0>,
    safety: &SafetyState,
    core_config: &trnm_consensus_core::CoreConfig,
) -> Result<(), ExistingNodeCheckpointJoinErrorV0> {
    if capacity
        .maximum_safety_revision
        .is_some_and(|revision| revision > safety.revision())
    {
        return Err(ExistingNodeCheckpointJoinErrorV0::SignerAheadOfSafety);
    }
    let canonical_pending = safety
        .pending_sign()
        .map(|intent| canonical_sign_intent_v0(core_config, intent))
        .transpose()?;
    let expected_vote_view = safety.last_voted_view().map(|view| view.get());
    let expected_timeout_view = safety.last_timeout_view().map(|view| view.get());
    let maximum_vote_view = capacity.maximum_vote_view;
    let maximum_timeout_view = capacity.maximum_timeout_view;
    let journaled_pending = match canonical_pending.as_ref().map(|intent| intent.preimage()) {
        None => {
            require_signer_view_exact_v0(maximum_vote_view, expected_vote_view, true)?;
            require_signer_view_exact_v0(maximum_timeout_view, expected_timeout_view, false)?;
            false
        }
        Some(trnm_consensus_types::CanonicalSignPreimageV0::Vote(value)) => {
            let pending_view = value.view().get();
            if expected_vote_view != Some(pending_view)
                || maximum_vote_view.is_some_and(|view| view > pending_view)
            {
                return Err(ExistingNodeCheckpointJoinErrorV0::SignerVoteViewMismatch);
            }
            require_signer_view_exact_v0(maximum_timeout_view, expected_timeout_view, false)?;
            maximum_vote_view == Some(pending_view)
        }
        Some(trnm_consensus_types::CanonicalSignPreimageV0::TimeoutVote(value)) => {
            let pending_view = value.view().get();
            if expected_timeout_view != Some(pending_view)
                || maximum_timeout_view.is_some_and(|view| view > pending_view)
            {
                return Err(ExistingNodeCheckpointJoinErrorV0::SignerTimeoutViewMismatch);
            }
            require_signer_view_exact_v0(maximum_vote_view, expected_vote_view, true)?;
            maximum_timeout_view == Some(pending_view)
        }
    };
    match (pending_intent, canonical_pending.as_ref()) {
        (Some(pending), Some(intent)) if prepared_intent_matches_v0(pending, intent) => {}
        (None, _) => {}
        (Some(_), None) => {
            return Err(ExistingNodeCheckpointJoinErrorV0::PreparedSignerWithoutSafetyIntent)
        }
        (Some(_), Some(_)) => {
            return Err(ExistingNodeCheckpointJoinErrorV0::PreparedSignerIntentMismatch)
        }
    }
    if canonical_pending.is_some() && !journaled_pending && pending_intent.is_some() {
        return Err(ExistingNodeCheckpointJoinErrorV0::PendingSignerTailMismatch);
    }
    if let Some(intent) = canonical_pending.as_ref().filter(|_| journaled_pending) {
        let tail =
            tail.ok_or(ExistingNodeCheckpointJoinErrorV0::PendingSafetyIntentWithoutSignerTail)?;
        if !signer_tail_matches_v0(tail, intent) {
            return Err(ExistingNodeCheckpointJoinErrorV0::PendingSignerTailMismatch);
        }
    }
    Ok(())
}

#[cfg(feature = "legacy-consensus-app")]
fn canonical_sign_intent_v0(
    config: &trnm_consensus_core::CoreConfig,
    intent: &SignIntent,
) -> Result<CanonicalSignIntentV0, ExistingNodeCheckpointJoinErrorV0> {
    match intent {
        SignIntent::Vote {
            authorizing_safety_revision,
            view,
            height,
            block_id,
            ..
        } => CanonicalSignIntentV0::vote(
            config.validator_set(),
            config.local_validator(),
            *authorizing_safety_revision,
            *view,
            *height,
            *block_id,
        ),
        SignIntent::TimeoutVote {
            authorizing_safety_revision,
            view,
            high_qc,
            ..
        } => CanonicalSignIntentV0::timeout_vote(
            config.validator_set(),
            config.local_validator(),
            *authorizing_safety_revision,
            *view,
            *high_qc,
        ),
    }
    .map_err(|_| ExistingNodeCheckpointJoinErrorV0::PreparedSignerIntentMismatch)
}

#[cfg(feature = "legacy-consensus-app")]
fn require_signer_view_exact_v0(
    signer_view: Option<u64>,
    safety_view: Option<u64>,
    vote: bool,
) -> Result<(), ExistingNodeCheckpointJoinErrorV0> {
    if signer_view == safety_view {
        return Ok(());
    }
    Err(if vote {
        ExistingNodeCheckpointJoinErrorV0::SignerVoteViewMismatch
    } else {
        ExistingNodeCheckpointJoinErrorV0::SignerTimeoutViewMismatch
    })
}

#[cfg(feature = "legacy-consensus-app")]
fn prepared_intent_matches_v0(
    pending: SignerPreparedIntentFactsV0,
    intent: &CanonicalSignIntentV0,
) -> bool {
    let (view, kind) = canonical_intent_view_kind_v0(intent);
    pending.fingerprint() == intent.fingerprint().into_bytes()
        && pending.epoch() == intent.epoch().get()
        && pending.view() == view
        && pending.kind() == kind
        && pending.safety_revision() == intent.authorizing_safety_revision()
        && pending.signing_root() == intent.signing_root().into_bytes()
}

#[cfg(feature = "legacy-consensus-app")]
fn signer_tail_matches_v0(tail: SignerJournalTailFactsV0, intent: &CanonicalSignIntentV0) -> bool {
    let (view, kind) = canonical_intent_view_kind_v0(intent);
    tail.fingerprint() == intent.fingerprint().into_bytes()
        && tail.epoch() == intent.epoch().get()
        && tail.view() == view
        && tail.kind() == kind
        && tail.safety_revision() == intent.authorizing_safety_revision()
        && tail.signing_root() == intent.signing_root().into_bytes()
}

#[cfg(feature = "legacy-consensus-app")]
fn canonical_intent_view_kind_v0(intent: &CanonicalSignIntentV0) -> (u64, u8) {
    match intent.preimage() {
        trnm_consensus_types::CanonicalSignPreimageV0::Vote(value) => (value.view().get(), 0),
        trnm_consensus_types::CanonicalSignPreimageV0::TimeoutVote(value) => {
            (value.view().get(), 1)
        }
    }
}

/// Narrow test-model construction boundary for commissioning and startup-policy
/// tests.  Existing namespaces use the non-test capability-consuming join
/// above; this helper cannot model or replace that trusted cross-store join.
#[cfg(test)]
fn confirm_test_node_checkpoint_candidate_v0(
    checkpoint: ExternalNodeCheckpointV0,
    confirmed_local_signer_watermark: SignerWatermarkV0,
    confirmed_external_signer_watermark: SignerWatermarkV0,
    origin: ConfirmedNodeCheckpointOriginV0,
) -> Result<ConfirmedNodeCheckpointCandidateV0, NodeCheckpointJoinErrorV0> {
    if confirmed_local_signer_watermark != confirmed_external_signer_watermark {
        return Err(NodeCheckpointJoinErrorV0::SignerWatermarkNotExact);
    }
    if checkpoint.signer_exact_watermark() != confirmed_local_signer_watermark {
        return Err(NodeCheckpointJoinErrorV0::SignerWatermarkMismatch);
    }
    Ok(ConfirmedNodeCheckpointCandidateV0 { checkpoint, origin })
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeCheckpointJoinErrorV0 {
    SignerWatermarkNotExact,
    SignerWatermarkMismatch,
}

/// Development-only startup modes.  None grants runtime advancement rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalNodeCheckpointStartupModeV0 {
    /// Explicit first commissioning of a capability-confirmed virgin genesis.
    ExplicitVirginGenesisCommissioning,
    /// An existing local namespace must equal an already externalized value.
    ExistingNamespaceExactComparison,
    /// Current h1 host: permanently replay-fenced and unable to mutate state.
    H1ReplayFencedOffline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalNodeCheckpointStartupOutcomeV0 {
    CommissionedVirginGenesis,
    ExactExisting,
    NotRequiredForH1ReplayFence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalNodeCheckpointStartupErrorV0 {
    ProductionActivationBlocked,
    CandidateRequired,
    CandidateForbiddenForReplayFence,
    CommissioningRequiresVirginGenesis,
    MissingExternalCheckpoint,
    ExternalCheckpointMismatch,
    Store(ExternalNodeCheckpointStoreErrorV0),
}

impl fmt::Display for ExternalNodeCheckpointStartupErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProductionActivationBlocked => formatter.write_str(
                "external node checkpoint startup is development-only; production is blocked",
            ),
            Self::CandidateRequired => {
                formatter.write_str("confirmed node checkpoint candidate is required")
            }
            Self::CandidateForbiddenForReplayFence => formatter.write_str(
                "h1 replay-fenced startup must not commission or compare a node checkpoint",
            ),
            Self::CommissioningRequiresVirginGenesis => formatter.write_str(
                "external node checkpoint commissioning requires confirmed virgin genesis",
            ),
            Self::MissingExternalCheckpoint => formatter
                .write_str("existing node namespace has no independent external checkpoint"),
            Self::ExternalCheckpointMismatch => formatter.write_str(
                "local joined node checkpoint differs from the independent external checkpoint",
            ),
            Self::Store(source) => write!(formatter, "external node checkpoint store: {source}"),
        }
    }
}

impl Error for ExternalNodeCheckpointStartupErrorV0 {}

/// Perform only development-time commissioning or exact startup comparison.
///
/// This helper never advances an existing checkpoint.  The only write it can
/// request is `None -> generation 0` for an explicitly confirmed virgin
/// genesis.  Existing namespaces with a missing or different external value
/// fail closed.  A failed commissioning CAS receives one fresh exact readback:
/// only the exact target is accepted as a resolved poststate; the prestate or
/// any third value remains an error.  The h1 replay-fenced mode returns before
/// `load` or CAS and therefore neither creates nor advances the independent
/// checkpoint.
pub fn reconcile_development_only_external_node_checkpoint_startup_v0<S>(
    store: &mut S,
    mode: ExternalNodeCheckpointStartupModeV0,
    production_activation: bool,
    candidate: Option<ConfirmedNodeCheckpointCandidateV0>,
) -> Result<ExternalNodeCheckpointStartupOutcomeV0, ExternalNodeCheckpointStartupErrorV0>
where
    S: ExternalNodeCheckpointStoreV0,
{
    if production_activation {
        return Err(ExternalNodeCheckpointStartupErrorV0::ProductionActivationBlocked);
    }

    if mode == ExternalNodeCheckpointStartupModeV0::H1ReplayFencedOffline {
        if candidate.is_some() {
            return Err(ExternalNodeCheckpointStartupErrorV0::CandidateForbiddenForReplayFence);
        }
        return Ok(ExternalNodeCheckpointStartupOutcomeV0::NotRequiredForH1ReplayFence);
    }

    let candidate = candidate.ok_or(ExternalNodeCheckpointStartupErrorV0::CandidateRequired)?;
    let checkpoint = candidate.checkpoint;
    if mode == ExternalNodeCheckpointStartupModeV0::ExplicitVirginGenesisCommissioning
        && (candidate.origin != ConfirmedNodeCheckpointOriginV0::VirginGenesis
            || checkpoint.generation() != 0
            || checkpoint.predecessor_checksum() != [0; 32]
            || checkpoint.fields().safety_revision != 0
            || checkpoint.fields().application_height != 0
            || checkpoint.fields().application_view != 0
            || checkpoint.signer_exact_watermark().sequence() != 0)
    {
        return Err(ExternalNodeCheckpointStartupErrorV0::CommissioningRequiresVirginGenesis);
    }
    let observed = store
        .load(checkpoint.scope())
        .map_err(ExternalNodeCheckpointStartupErrorV0::Store)?;
    if observed
        .as_ref()
        .is_some_and(|value| value.scope() != checkpoint.scope())
    {
        return Err(ExternalNodeCheckpointStartupErrorV0::Store(
            ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState,
        ));
    }

    match mode {
        ExternalNodeCheckpointStartupModeV0::ExplicitVirginGenesisCommissioning => match observed {
            None => match store.compare_and_advance(None, checkpoint) {
                Ok(()) => Ok(ExternalNodeCheckpointStartupOutcomeV0::CommissionedVirginGenesis),
                Err(source) => {
                    let resolved = store
                        .load(checkpoint.scope())
                        .map_err(ExternalNodeCheckpointStartupErrorV0::Store)?;
                    match resolved {
                        Some(value)
                            if value.scope() == checkpoint.scope() && value == checkpoint =>
                        {
                            Ok(ExternalNodeCheckpointStartupOutcomeV0::ExactExisting)
                        }
                        None => Err(ExternalNodeCheckpointStartupErrorV0::Store(source)),
                        Some(value) if value.scope() != checkpoint.scope() => {
                            Err(ExternalNodeCheckpointStartupErrorV0::Store(
                                ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState,
                            ))
                        }
                        Some(_) => {
                            Err(ExternalNodeCheckpointStartupErrorV0::ExternalCheckpointMismatch)
                        }
                    }
                }
            },
            Some(value) if value == checkpoint => {
                Ok(ExternalNodeCheckpointStartupOutcomeV0::ExactExisting)
            }
            Some(_) => Err(ExternalNodeCheckpointStartupErrorV0::ExternalCheckpointMismatch),
        },
        ExternalNodeCheckpointStartupModeV0::ExistingNamespaceExactComparison => match observed {
            None => Err(ExternalNodeCheckpointStartupErrorV0::MissingExternalCheckpoint),
            Some(value) if value == checkpoint => {
                Ok(ExternalNodeCheckpointStartupOutcomeV0::ExactExisting)
            }
            Some(_) => Err(ExternalNodeCheckpointStartupErrorV0::ExternalCheckpointMismatch),
        },
        ExternalNodeCheckpointStartupModeV0::H1ReplayFencedOffline => {
            unreachable!("replay-fenced mode returned before touching the store")
        }
    }
}

fn validate_fields_v0(
    fields: &ExternalNodeCheckpointFieldsV0,
) -> Result<(), ExternalNodeCheckpointDecodeErrorV0> {
    let nonzero = [
        (fields.scope, "scope"),
        (fields.safety_journal_id, "safety journal id"),
        (
            fields.safety_verifier_profile_ref,
            "safety verifier profile",
        ),
        (
            fields.safety_state_record_checksum,
            "safety state record checksum",
        ),
        (
            fields.safety_record_chain_checksum,
            "safety record chain checksum",
        ),
        (
            fields.application_host_config_ref,
            "application host config",
        ),
        (
            fields.application_projection_profile_ref,
            "application projection profile",
        ),
        (
            fields.application_safety_binding_manifest_checksum,
            "application safety binding manifest checksum",
        ),
        (
            fields.application_committed_head_row_checksum,
            "application committed head row checksum",
        ),
        (
            fields.application_recovery_closure_checksum,
            "application recovery closure checksum",
        ),
        (fields.signer_journal_id, "signer journal id"),
        (fields.signer_profile_checksum, "signer profile checksum"),
    ];
    for (value, name) in nonzero {
        if value == [0; 32] {
            return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(name));
        }
    }
    if fields.application_block_id.is_zero() {
        return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
            "application block id",
        ));
    }
    if fields.application_state_root.is_zero() {
        return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
            "application state root",
        ));
    }
    if fields.generation == 0 && fields.predecessor_checksum != [0; 32] {
        return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
            "generation-zero predecessor",
        ));
    }
    if fields.generation != 0 && fields.predecessor_checksum == [0; 32] {
        return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
            "successor predecessor",
        ));
    }
    if fields.signer_exact_watermark.scope() != fields.scope {
        return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
            "signer watermark scope",
        ));
    }
    if fields.signer_exact_watermark.journal_id() != fields.signer_journal_id {
        return Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
            "signer watermark journal id",
        ));
    }
    Ok(())
}

fn encode_prefix_v0(
    fields: &ExternalNodeCheckpointFieldsV0,
    encoded: &mut [u8; EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0],
) {
    encoded[..8].copy_from_slice(&RECORD_MAGIC_V0);
    write_u64_v0(encoded, 8, EXTERNAL_NODE_CHECKPOINT_SCHEMA_V0);
    write_array_v0(encoded, 16, fields.scope);
    write_u64_v0(encoded, 48, fields.generation);
    write_array_v0(encoded, 56, fields.predecessor_checksum);
    write_array_v0(encoded, 88, fields.safety_journal_id);
    write_array_v0(encoded, 120, fields.safety_verifier_profile_ref);
    write_u64_v0(encoded, 152, fields.safety_revision);
    write_array_v0(encoded, 160, fields.safety_state_record_checksum);
    write_array_v0(encoded, 192, fields.safety_record_chain_checksum);
    write_array_v0(encoded, 224, fields.application_host_config_ref);
    write_array_v0(encoded, 256, fields.application_projection_profile_ref);
    write_array_v0(
        encoded,
        288,
        fields.application_safety_binding_manifest_checksum,
    );
    write_array_v0(encoded, 320, fields.application_committed_head_row_checksum);
    write_array_v0(encoded, 352, fields.application_recovery_closure_checksum);
    write_array_v0(encoded, 384, fields.application_block_id.into_bytes());
    write_u64_v0(encoded, 416, fields.application_height);
    write_array_v0(encoded, 424, fields.application_state_root.into_bytes());
    write_u64_v0(encoded, 456, fields.application_view);
    write_u64_v0(encoded, 464, fields.application_timestamp_ms);
    write_array_v0(encoded, 472, fields.signer_journal_id);
    write_array_v0(encoded, 504, fields.signer_profile_checksum);
    write_array_v0(encoded, 536, fields.signer_exact_watermark.scope());
    write_array_v0(encoded, 568, fields.signer_exact_watermark.journal_id());
    write_u64_v0(encoded, 600, fields.signer_exact_watermark.sequence());
    write_array_v0(encoded, 608, fields.signer_exact_watermark.chain_checksum());
}

fn checkpoint_checksum_v0(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((CHECKSUM_DOMAIN_V0.len() as u64).to_be_bytes());
    hasher.update(CHECKSUM_DOMAIN_V0);
    hasher.update((prefix.len() as u64).to_be_bytes());
    hasher.update(prefix);
    hasher.finalize().into()
}

fn read_array_v0(encoded: &[u8], offset: usize) -> [u8; 32] {
    let mut value = [0u8; 32];
    value.copy_from_slice(&encoded[offset..offset + 32]);
    value
}

fn read_u64_v0(encoded: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&encoded[offset..offset + 8]);
    u64::from_be_bytes(value)
}

fn write_array_v0(
    encoded: &mut [u8; EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0],
    offset: usize,
    value: [u8; 32],
) {
    encoded[offset..offset + 32].copy_from_slice(&value);
}

fn write_u64_v0(
    encoded: &mut [u8; EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0],
    offset: usize,
    value: u64,
) {
    encoded[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[cfg(feature = "legacy-consensus-app")]
    use crate::PocoNodeStartConfigV0;
    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::TempDir;
    use trnm_consensus_core::{
        leader_for, BlockIdOverlayRefV0, Core, CoreConfig, Effect, Input, PayloadValidationRouteV0,
        SafetyStateRecordLimitsV0, ValidatedPayloadArtifactRefV0,
    };
    use trnm_consensus_crypto::StrictEd25519Verifier;
    use trnm_consensus_safety_store::{
        SafetyPersistDispositionV0, SafetyStateStoreProfileV0, SafetyTransitionContextV0,
    };
    use trnm_consensus_signer_journal::{ExternalWatermarkErrorV0, SignerJournalProfileV0};
    use trnm_consensus_types::{
        ApplicationPayloadV0, Block, BlockBodyV0, BlockHeader, BlockKind, ChainId,
        ConsensusParametersV0, ConsensusPublicKey, Epoch, ExecutionReceiptCommitmentV0,
        ExecutionReceiptsV0, GenesisHash, GenesisQcV0, Height, ProposalWitnessV0, ProtocolVersion,
        QcReferenceV0, SignatureBytes, SignedProposalV0, Validator, ValidatorId, ValidatorSet,
        View, VotingPower,
    };
    use trnm_native_application::{
        ApplicationCommitIdV0, ApplicationHeadV0, BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0,
        HeightV0, NativeBlockExecutionRequestV0, NativeExecutedBlockV0, NativeExecutionReceiptV0,
        NativeExpectedBlockCommitmentsV0, ReceiptsRootV0, StateRootV0, ValidatorSetIdV0,
    };
    use trnm_native_application_sqlite::{
        AckTransitionOutcomeV0, DeliverTransitionOutcomeV0, ProposalRouteV0,
        ProposalValidationOwnerIdV0, ProposalValidationStoreScopeV0, ReservationOutcomeV0,
    };

    #[cfg(unix)]
    fn secure_checkpoint_temp_dir_v0(message: &'static str) -> TempDir {
        let root = TempDir::new().expect(message);
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("secure checkpoint test namespace");
        root
    }

    #[derive(Default)]
    struct MemoryNodeCheckpointStoreV0 {
        value: Option<ExternalNodeCheckpointV0>,
        loads: u64,
        advances: u64,
        error_after_apply_once: Option<ExternalNodeCheckpointStoreErrorV0>,
    }

    impl ExternalNodeCheckpointStoreV0 for MemoryNodeCheckpointStoreV0 {
        fn load(
            &mut self,
            _scope: [u8; 32],
        ) -> Result<Option<ExternalNodeCheckpointV0>, ExternalNodeCheckpointStoreErrorV0> {
            self.loads += 1;
            Ok(self.value)
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<ExternalNodeCheckpointV0>,
            target: ExternalNodeCheckpointV0,
        ) -> Result<(), ExternalNodeCheckpointStoreErrorV0> {
            self.advances += 1;
            if self.value != expected {
                return Err(ExternalNodeCheckpointStoreErrorV0::CompareFailed);
            }
            self.value = Some(target);
            if let Some(error) = self.error_after_apply_once.take() {
                return Err(error);
            }
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct MemorySignerWatermarkStateV0 {
        value: Option<SignerWatermarkV0>,
        compare_calls: u64,
    }

    #[derive(Debug, Clone, Default)]
    struct MemorySignerWatermarkV0 {
        state: Arc<Mutex<MemorySignerWatermarkStateV0>>,
    }

    impl MemorySignerWatermarkV0 {
        fn current_v0(&self) -> Option<SignerWatermarkV0> {
            self.state
                .lock()
                .expect("signer watermark test mutex")
                .value
        }

        fn compare_calls_v0(&self) -> u64 {
            self.state
                .lock()
                .expect("signer watermark test mutex")
                .compare_calls
        }
    }

    impl ExternalMonotonicWatermarkV0 for MemorySignerWatermarkV0 {
        fn load(
            &mut self,
            scope: [u8; 32],
        ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
            let value = self
                .state
                .lock()
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?
                .value;
            if value.is_some_and(|watermark| watermark.scope() != scope) {
                return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
            }
            Ok(value)
        }

        fn compare_and_advance(
            &mut self,
            expected: Option<SignerWatermarkV0>,
            target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ExternalWatermarkErrorV0::Unavailable)?;
            state.compare_calls = state
                .compare_calls
                .checked_add(1)
                .ok_or(ExternalWatermarkErrorV0::InvalidPersistedState)?;
            if state.value != expected {
                return Err(ExternalWatermarkErrorV0::CompareFailed);
            }
            match expected {
                None if target.sequence() == 0 => {}
                Some(source)
                    if source.scope() == target.scope()
                        && source.journal_id() == target.journal_id()
                        && source.sequence().checked_add(1) == Some(target.sequence()) => {}
                _ => return Err(ExternalWatermarkErrorV0::InvalidPersistedState),
            }
            state.value = Some(target);
            Ok(())
        }
    }

    const REAL_NATIVE_K_CHAIN_V0: ChainId = ChainId::from_static("trnm-native-k-cas-test");

    struct RealNativeKFixtureV0 {
        keys: Vec<(ValidatorId, SigningKey)>,
        parameters: ConsensusParametersV0,
        validator_set: ValidatorSet,
        config: CoreConfig,
    }

    impl RealNativeKFixtureV0 {
        fn new() -> Self {
            let parameters = ConsensusParametersV0::reference_shadow_v0();
            let keys = (1_u8..=4)
                .map(|index| {
                    (
                        ValidatorId::new([index; 32]),
                        SigningKey::from_bytes(&[index.saturating_add(90); 32]),
                    )
                })
                .collect::<Vec<_>>();
            let validators = keys
                .iter()
                .map(|(id, key)| {
                    Validator::new(
                        *id,
                        ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                        VotingPower::new(1).expect("positive voting power"),
                    )
                    .expect("valid validator")
                })
                .collect::<Vec<_>>();
            let validator_set = ValidatorSet::new(
                GenesisHash::new([0xD1; 32]),
                REAL_NATIVE_K_CHAIN_V0,
                ProtocolVersion::V0,
                Epoch::new(0),
                parameters.hash(),
                validators,
            )
            .expect("valid validator set");
            let config = CoreConfig::new(keys[0].0, validator_set.clone(), parameters, 0, 32, 64)
                .expect("valid Core config");
            Self {
                keys,
                parameters,
                validator_set,
                config,
            }
        }

        fn proposal_v0(&self) -> (SignedProposalV0, ApplicationPayloadV0, ExecutionReceiptsV0) {
            let payload = ApplicationPayloadV0::new(vec![b"native-k-cas".to_vec()])
                .expect("non-empty payload");
            let receipt =
                ExecutionReceiptCommitmentV0::for_transaction(&payload, 0, 19, 5, Vec::new())
                    .expect("canonical receipt");
            let receipts =
                ExecutionReceiptsV0::new(&payload, vec![receipt]).expect("canonical receipts");
            let body = BlockBodyV0::new(payload.clone(), Vec::new()).expect("canonical body");
            let view = View::new(1);
            let proposer = leader_for(&self.validator_set, view);
            let header = BlockHeader::new(
                self.validator_set.genesis_hash(),
                self.validator_set.chain_id(),
                self.validator_set.protocol_version(),
                self.validator_set.epoch(),
                view,
                Height::new(1),
                BlockKind::Regular,
                BlockId::new(*self.validator_set.genesis_hash().as_bytes()),
                proposer,
                self.validator_set.id(),
                self.validator_set.consensus_parameters_hash(),
                body.payload_root().expect("payload root"),
                StateRoot::new([0xD2; 32]),
                receipts.receipts_root().expect("receipts root"),
                body.evidence_root().expect("evidence root"),
                101,
                None,
            )
            .expect("valid header");
            let block = Block::new(
                header,
                body.application_payload()
                    .try_cev0_bytes()
                    .expect("canonical payload bytes"),
                Vec::new(),
            )
            .expect("valid block");
            let justify = QcReferenceV0::genesis_anchor(
                GenesisQcV0::new(
                    self.validator_set.genesis_hash(),
                    self.validator_set.chain_id(),
                    &self.validator_set,
                )
                .expect("valid genesis QC"),
            );
            let signing_root =
                ProposalWitnessV0::signing_root_for(block.header(), &justify, None, None)
                    .expect("proposal signing root");
            let key = self
                .keys
                .iter()
                .find_map(|(id, key)| (*id == proposer).then_some(key))
                .expect("leader key");
            let witness = ProposalWitnessV0::new(
                block.header(),
                justify,
                None,
                None,
                SignatureBytes::from_array(key.sign(signing_root.as_bytes()).to_bytes()),
                &self.validator_set,
                None,
                &self.parameters,
                0,
            )
            .expect("strict proposal witness");
            let proposal = SignedProposalV0::new(
                block,
                witness,
                &self.validator_set,
                None,
                &self.parameters,
                0,
            )
            .expect("strict signed proposal");
            (proposal, payload, receipts)
        }
    }

    fn exact_native_execution_v0(
        binding: &ProposalValidationBindingV0,
        payload: &ApplicationPayloadV0,
        receipts: &ExecutionReceiptsV0,
    ) -> NativeExecutedBlockV0 {
        let request = NativeBlockExecutionRequestV0::new(
            binding.chain_id().clone(),
            binding.genesis_hash(),
            binding.parent().clone(),
            binding.block_id(),
            binding.height(),
            binding.timestamp_ms(),
            binding.active_validator_set_id(),
            payload.transactions().to_vec(),
            binding.commitments(),
        )
        .expect("exact native execution request");
        let canonical = &receipts.receipts()[0];
        let encoded = canonical.try_cev0_bytes().expect("canonical receipt bytes");
        let commitment =
            native_checkpoint_hash_v0(b"trnm.native-application.execution-receipt.v0", &[&encoded]);
        let native_receipt = NativeExecutionReceiptV0::new(
            0,
            Hash32V0::new(*canonical.payload_leaf_hash()),
            canonical.gas_used(),
            canonical.fee_charged(),
            Vec::new(),
            Hash32V0::new(commitment),
        )
        .expect("exact native receipt");
        NativeExecutedBlockV0::new(
            request,
            binding.commitments().payload_root(),
            binding.commitments().post_state_root(),
            binding.commitments().receipts_root(),
            binding.commitments().evidence_root(),
            vec![native_receipt],
        )
        .expect("exact native execution")
    }

    fn watermark_v0(sequence: u64) -> SignerWatermarkV0 {
        watermark_for_scope_v0([1; 32], sequence)
    }

    fn watermark_for_scope_v0(scope: [u8; 32], sequence: u64) -> SignerWatermarkV0 {
        SignerWatermarkV0::from_persisted_parts(scope, [19; 32], sequence, [20; 32])
            .expect("fixed watermark")
    }

    fn checkpoint_v0(
        generation: u64,
        predecessor_checksum: [u8; 32],
        safety_revision: u64,
        application_height: u64,
        application_view: u64,
        signer_sequence: u64,
    ) -> ExternalNodeCheckpointV0 {
        checkpoint_for_scope_v0(
            [1; 32],
            generation,
            predecessor_checksum,
            safety_revision,
            application_height,
            application_view,
            signer_sequence,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn checkpoint_for_scope_v0(
        scope: [u8; 32],
        generation: u64,
        predecessor_checksum: [u8; 32],
        safety_revision: u64,
        application_height: u64,
        application_view: u64,
        signer_sequence: u64,
    ) -> ExternalNodeCheckpointV0 {
        ExternalNodeCheckpointV0::new(ExternalNodeCheckpointFieldsV0 {
            scope,
            generation,
            predecessor_checksum,
            safety_journal_id: [2; 32],
            safety_verifier_profile_ref: [3; 32],
            safety_revision,
            safety_state_record_checksum: [4; 32],
            safety_record_chain_checksum: [5; 32],
            application_host_config_ref: [6; 32],
            application_projection_profile_ref: [7; 32],
            application_safety_binding_manifest_checksum: [8; 32],
            application_committed_head_row_checksum: [9; 32],
            application_recovery_closure_checksum: [10; 32],
            application_block_id: BlockId::new([11; 32]),
            application_height,
            application_state_root: StateRoot::new([12; 32]),
            application_view,
            application_timestamp_ms: 14,
            signer_journal_id: [19; 32],
            signer_profile_checksum: [18; 32],
            signer_exact_watermark: watermark_for_scope_v0(scope, signer_sequence),
        })
        .expect("fixed checkpoint")
    }

    fn successor_checkpoint_v0(
        predecessor: ExternalNodeCheckpointV0,
        marker: u8,
    ) -> ExternalNodeCheckpointV0 {
        assert_ne!(marker, 0, "successor marker must keep checksums nonzero");
        ExternalNodeCheckpointV0::new(ExternalNodeCheckpointFieldsV0 {
            generation: predecessor
                .generation()
                .checked_add(1)
                .expect("test generation capacity"),
            predecessor_checksum: predecessor.checkpoint_checksum(),
            safety_revision: predecessor
                .fields()
                .safety_revision
                .checked_add(1)
                .expect("test Safety revision capacity"),
            safety_state_record_checksum: [marker; 32],
            safety_record_chain_checksum: [marker.wrapping_add(1); 32],
            application_committed_head_row_checksum: [marker.wrapping_add(2); 32],
            application_recovery_closure_checksum: [marker.wrapping_add(3); 32],
            application_block_id: BlockId::new([marker.wrapping_add(4); 32]),
            application_height: predecessor
                .fields()
                .application_height
                .checked_add(1)
                .expect("test application height capacity"),
            application_state_root: StateRoot::new([marker.wrapping_add(5); 32]),
            application_view: predecessor
                .fields()
                .application_view
                .checked_add(1)
                .expect("test application view capacity"),
            application_timestamp_ms: predecessor
                .fields()
                .application_timestamp_ms
                .checked_add(1)
                .expect("test application timestamp capacity"),
            ..*predecessor.fields()
        })
        .expect("canonical successor checkpoint")
    }

    #[cfg(feature = "legacy-consensus-app")]
    struct ProjectedJoinFixtureV0 {
        _root: TempDir,
        start: PocoNodeStartConfigV0,
        safety: SafetyState,
        safety_journal_id: [u8; 32],
        safety_verifier_profile_ref: [u8; 32],
        safety_core_config_ref: [u8; 32],
        safety_state_record_checksum: [u8; 32],
        safety_chain_checksum: [u8; 32],
        application: ApplicationNodeCheckpointProjectionV0,
        signer: SignerNodeCheckpointProjectionV0,
        observed: ExternalNodeCheckpointV0,
    }

    #[cfg(feature = "legacy-consensus-app")]
    fn projected_safety_v0<'a>(
        fixture: &'a ProjectedJoinFixtureV0,
    ) -> SafetyNodeCheckpointProjectionV0<'a> {
        SafetyNodeCheckpointProjectionV0 {
            state: &fixture.safety,
            application_applied_state_root: Some(fixture.application.state_root),
            journal_id: fixture.safety_journal_id,
            verifier_profile_ref: fixture.safety_verifier_profile_ref,
            core_config_ref: fixture.safety_core_config_ref,
            revision: fixture.safety.revision(),
            state_record_checksum: fixture.safety_state_record_checksum,
            chain_checksum: fixture.safety_chain_checksum,
        }
    }

    #[cfg(feature = "legacy-consensus-app")]
    fn projected_join_fixture_v0() -> ProjectedJoinFixtureV0 {
        let root = TempDir::new().expect("temporary join namespace");
        let safety_parent = root.path().join("safety");
        let signer_parent = root.path().join("signer");
        std::fs::create_dir_all(&safety_parent).expect("create Safety parent");
        std::fs::create_dir_all(&signer_parent).expect("create signer parent");

        let consensus_parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = (1_u8..=4)
            .map(|index| {
                Validator::new(
                    ValidatorId::new([index; 32]),
                    ConsensusPublicKey::new([index.saturating_add(100); 32]),
                    VotingPower::new(1).expect("positive power"),
                )
                .expect("valid validator")
            })
            .collect();
        let validator_set = ValidatorSet::new(
            GenesisHash::new([0xa5; 32]),
            ChainId::from_static("trnm-node-checkpoint-join-test"),
            ProtocolVersion::V0,
            Epoch::new(0),
            consensus_parameters.hash(),
            validators,
        )
        .expect("valid validator set");
        let core_config = CoreConfig::new(
            ValidatorId::new([1; 32]),
            validator_set,
            consensus_parameters,
            17,
            64,
            64,
        )
        .expect("valid Core config");
        let limits = SafetyStateRecordLimitsV0::new(64 * 1024 * 1024, 16 * 1024 * 1024)
            .expect("bounded record limits");
        let start = PocoNodeStartConfigV0::new(
            safety_parent.join("safety.sqlite3"),
            signer_parent.join("signer.sqlite3"),
            core_config,
            limits,
            192 * 1024 * 1024,
            32,
            16 * 1024,
            32 * 1024 * 1024,
        )
        .expect("valid node start config");
        let genesis_qc = GenesisQcV0::new(
            start.core_config().validator_set().genesis_hash(),
            start.core_config().validator_set().chain_id(),
            start.core_config().validator_set(),
        )
        .expect("valid genesis QC");
        let core = Core::new(
            start.core_config().clone(),
            genesis_qc,
            &StrictEd25519Verifier,
        )
        .expect("genesis Core");
        let safety = core.safety_state().clone();
        let safety_journal_id = [2; 32];
        let safety_verifier_profile_ref = start.safety_verifier_profile_ref_v0();
        let safety_core_config_ref = safety_state_record_config_ref_v0(
            &SafetyStateRecordContextV0::new(
                start.core_config(),
                safety_verifier_profile_ref,
                start.record_limits(),
            )
            .expect("record context"),
        )
        .expect("record config reference");
        let safety_state_record_checksum = [4; 32];
        let safety_chain_checksum = [5; 32];
        let applied = safety.application_applied();
        let application = ApplicationNodeCheckpointProjectionV0 {
            host_config_ref: [6; 32],
            projection_profile_ref: [7; 32],
            safety_journal_id,
            safety_verifier_profile_ref,
            safety_revision: safety.revision(),
            safety_state_record_checksum,
            safety_chain_checksum,
            safety_binding_manifest_checksum: [8; 32],
            committed_head_row_checksum: [9; 32],
            recovery_closure_checksum: [10; 32],
            block_id: applied.block_id(),
            height: applied.height().get(),
            state_root: StateRoot::new([12; 32]),
            view: applied.view().get(),
            timestamp_ms: applied.timestamp_ms(),
        };
        let signer_profile = &start.signer_journal_profile;
        let signer_journal_id = [19; 32];
        let signer_watermark = SignerWatermarkV0::from_persisted_parts(
            signer_profile.external_watermark_scope(),
            signer_journal_id,
            0,
            [20; 32],
        )
        .expect("exact signer watermark");
        let signer = SignerNodeCheckpointProjectionV0 {
            journal_id: signer_journal_id,
            profile_checksum: signer_profile.profile_checksum(),
            chain_id: signer_profile.chain_id(),
            protocol_version: signer_profile.protocol_version(),
            epoch: signer_profile.epoch(),
            validator_set_id: signer_profile.validator_set_id(),
            author: signer_profile.author(),
            signer_profile_ref: signer_profile.signer_profile_ref(),
            external_watermark_scope: signer_profile.external_watermark_scope(),
            exact_watermark: signer_watermark,
            capacity: SignerLifecycleCapacityProjectionV0 {
                maximum_safety_revision: None,
                maximum_vote_view: None,
                maximum_timeout_view: None,
            },
            tail: None,
            pending_intent: None,
        };
        let observed = ExternalNodeCheckpointV0::new(ExternalNodeCheckpointFieldsV0 {
            scope: signer.external_watermark_scope,
            generation: 7,
            predecessor_checksum: [21; 32],
            safety_journal_id,
            safety_verifier_profile_ref,
            safety_revision: safety.revision(),
            safety_state_record_checksum,
            safety_record_chain_checksum: safety_chain_checksum,
            application_host_config_ref: application.host_config_ref,
            application_projection_profile_ref: application.projection_profile_ref,
            application_safety_binding_manifest_checksum: application
                .safety_binding_manifest_checksum,
            application_committed_head_row_checksum: application.committed_head_row_checksum,
            application_recovery_closure_checksum: application.recovery_closure_checksum,
            application_block_id: application.block_id,
            application_height: application.height,
            application_state_root: application.state_root,
            application_view: application.view,
            application_timestamp_ms: application.timestamp_ms,
            signer_journal_id,
            signer_profile_checksum: signer.profile_checksum,
            signer_exact_watermark: signer.exact_watermark,
        })
        .expect("canonical observed external checkpoint");
        ProjectedJoinFixtureV0 {
            _root: root,
            start,
            safety,
            safety_journal_id,
            safety_verifier_profile_ref,
            safety_core_config_ref,
            safety_state_record_checksum,
            safety_chain_checksum,
            application,
            signer,
            observed,
        }
    }

    #[cfg(feature = "legacy-consensus-app")]
    fn confirm_projected_join_fixture_v0(
        fixture: &ProjectedJoinFixtureV0,
        observed: ExternalNodeCheckpointV0,
        application: ApplicationNodeCheckpointProjectionV0,
        signer: SignerNodeCheckpointProjectionV0,
    ) -> Result<ConfirmedNodeCheckpointCandidateV0, ExistingNodeCheckpointJoinErrorV0> {
        confirm_existing_node_checkpoint_projected_v0(
            observed,
            fixture.start.core_config(),
            fixture.start.record_limits(),
            fixture.start.safety_verifier_profile_ref_v0(),
            &fixture.start.signer_journal_profile,
            projected_safety_v0(fixture),
            application,
            signer,
        )
    }

    #[cfg(feature = "legacy-consensus-app")]
    #[test]
    fn existing_candidate_is_minted_only_from_exact_joined_observation_v0() {
        let fixture = projected_join_fixture_v0();
        let candidate = confirm_projected_join_fixture_v0(
            &fixture,
            fixture.observed,
            fixture.application,
            fixture.signer,
        )
        .expect("exact projected facts mint one existing-only candidate");
        assert_eq!(candidate.checkpoint(), &fixture.observed);
        assert_eq!(
            candidate.origin,
            ConfirmedNodeCheckpointOriginV0::ExistingNamespace
        );
        assert_eq!(candidate.checkpoint().generation(), 7);
        assert_eq!(candidate.checkpoint().predecessor_checksum(), [21; 32]);

        let mut rootless_safety = projected_safety_v0(&fixture);
        rootless_safety.application_applied_state_root = None;
        assert_eq!(
            confirm_existing_node_checkpoint_projected_v0(
                fixture.observed,
                fixture.start.core_config(),
                fixture.start.record_limits(),
                fixture.start.safety_verifier_profile_ref_v0(),
                &fixture.start.signer_journal_profile,
                rootless_safety,
                fixture.application,
                fixture.signer,
            )
            .expect_err("a detached applied tip without retained proof cannot mint a candidate"),
            ExistingNodeCheckpointJoinErrorV0::ApplicationAppliedRootUnavailable
        );

        let mut external_fields = *fixture.observed.fields();
        external_fields.safety_state_record_checksum = [98; 32];
        let foreign_observation = ExternalNodeCheckpointV0::new(external_fields)
            .expect("canonical but not capability-derived external value");
        assert_eq!(
            confirm_projected_join_fixture_v0(
                &fixture,
                foreign_observation,
                fixture.application,
                fixture.signer,
            )
            .expect_err("a canonical external value cannot replace capability-derived fields"),
            ExistingNodeCheckpointJoinErrorV0::ObservedExternalMismatch
        );

        let mut app = fixture.application;
        app.safety_chain_checksum = [99; 32];
        assert_eq!(
            confirm_projected_join_fixture_v0(&fixture, fixture.observed, app, fixture.signer)
                .expect_err("all five Safety provenance fields are exact"),
            ExistingNodeCheckpointJoinErrorV0::ApplicationSafetyProvenanceMismatch
        );

        let mut app = fixture.application;
        app.timestamp_ms = app.timestamp_ms.saturating_add(1);
        assert_eq!(
            confirm_projected_join_fixture_v0(&fixture, fixture.observed, app, fixture.signer)
                .expect_err("application coordinates join Safety application_applied"),
            ExistingNodeCheckpointJoinErrorV0::ApplicationAppliedMismatch
        );

        let mut app = fixture.application;
        app.state_root = StateRoot::new([97; 32]);
        assert_eq!(
            confirm_projected_join_fixture_v0(&fixture, fixture.observed, app, fixture.signer)
                .expect_err("application state root joins the authenticated applied header"),
            ExistingNodeCheckpointJoinErrorV0::ApplicationAppliedMismatch
        );
    }

    #[cfg(feature = "legacy-consensus-app")]
    #[test]
    fn existing_candidate_rejects_foreign_signer_and_lifecycle_v0() {
        let fixture = projected_join_fixture_v0();
        let mut signer = fixture.signer;
        signer.author = ValidatorId::new([2; 32]);
        assert_eq!(
            confirm_projected_join_fixture_v0(
                &fixture,
                fixture.observed,
                fixture.application,
                signer,
            )
            .expect_err("foreign local author is rejected"),
            ExistingNodeCheckpointJoinErrorV0::SignerIdentityMismatch
        );

        let mut signer = fixture.signer;
        signer.profile_checksum = [88; 32];
        assert_eq!(
            confirm_projected_join_fixture_v0(
                &fixture,
                fixture.observed,
                fixture.application,
                signer,
            )
            .expect_err("foreign signer profile is rejected"),
            ExistingNodeCheckpointJoinErrorV0::SignerProfileMismatch
        );

        let mut signer = fixture.signer;
        signer.capacity.maximum_safety_revision = Some(fixture.safety.revision() + 1);
        assert_eq!(
            confirm_projected_join_fixture_v0(
                &fixture,
                fixture.observed,
                fixture.application,
                signer,
            )
            .expect_err("signer cannot be ahead of Safety"),
            ExistingNodeCheckpointJoinErrorV0::SignerAheadOfSafety
        );

        let mut signer = fixture.signer;
        signer.capacity.maximum_vote_view = Some(1);
        assert_eq!(
            confirm_projected_join_fixture_v0(
                &fixture,
                fixture.observed,
                fixture.application,
                signer,
            )
            .expect_err("signer and Safety vote views must be exact"),
            ExistingNodeCheckpointJoinErrorV0::SignerVoteViewMismatch
        );
    }

    #[cfg(feature = "legacy-consensus-app")]
    #[test]
    fn existing_candidate_rejects_foreign_safety_configuration_v0() {
        let fixture = projected_join_fixture_v0();
        let error = confirm_existing_node_checkpoint_projected_v0(
            fixture.observed,
            fixture.start.core_config(),
            fixture.start.record_limits(),
            fixture.start.safety_verifier_profile_ref_v0(),
            &fixture.start.signer_journal_profile,
            SafetyNodeCheckpointProjectionV0 {
                state: &fixture.safety,
                application_applied_state_root: Some(fixture.application.state_root),
                journal_id: fixture.safety_journal_id,
                verifier_profile_ref: fixture.safety_verifier_profile_ref,
                core_config_ref: [77; 32],
                revision: fixture.safety.revision(),
                state_record_checksum: fixture.safety_state_record_checksum,
                chain_checksum: fixture.safety_chain_checksum,
            },
            fixture.application,
            fixture.signer,
        )
        .expect_err("record-context mismatch is rejected before candidate construction");
        assert_eq!(
            error,
            ExistingNodeCheckpointJoinErrorV0::SafetyConfigurationMismatch
        );

        let foreign_verifier_profile_ref = [91; 32];
        let foreign_core_config_ref = safety_state_record_config_ref_v0(
            &SafetyStateRecordContextV0::new(
                fixture.start.core_config(),
                foreign_verifier_profile_ref,
                fixture.start.record_limits(),
            )
            .expect("self-consistent foreign record context"),
        )
        .expect("self-consistent foreign record config reference");
        let mut foreign_safety = projected_safety_v0(&fixture);
        foreign_safety.verifier_profile_ref = foreign_verifier_profile_ref;
        foreign_safety.core_config_ref = foreign_core_config_ref;
        let error = confirm_existing_node_checkpoint_projected_v0(
            fixture.observed,
            fixture.start.core_config(),
            fixture.start.record_limits(),
            fixture.start.safety_verifier_profile_ref_v0(),
            &fixture.start.signer_journal_profile,
            foreign_safety,
            fixture.application,
            fixture.signer,
        )
        .expect_err("self-consistent foreign Safety verifier profile is rejected");
        assert_eq!(
            error,
            ExistingNodeCheckpointJoinErrorV0::SafetyVerifierProfileMismatch
        );
    }

    #[cfg(feature = "legacy-consensus-app")]
    #[test]
    fn production_join_wrapper_requires_all_three_linear_capabilities_v0() {
        struct UnusedWatermarkV0;
        impl ExternalMonotonicWatermarkV0 for UnusedWatermarkV0 {
            fn load(
                &mut self,
                _scope: [u8; 32],
            ) -> Result<
                Option<SignerWatermarkV0>,
                trnm_consensus_signer_journal::ExternalWatermarkErrorV0,
            > {
                unreachable!("signature-only test never opens a signer owner")
            }

            fn compare_and_advance(
                &mut self,
                _expected: Option<SignerWatermarkV0>,
                _target: SignerWatermarkV0,
            ) -> Result<(), trnm_consensus_signer_journal::ExternalWatermarkErrorV0> {
                unreachable!("signature-only test never advances a watermark")
            }
        }

        let wrapper = confirm_existing_node_checkpoint_candidate_v0::<UnusedWatermarkV0>;
        let _ = wrapper;
    }

    fn candidate_v0(
        checkpoint: ExternalNodeCheckpointV0,
        origin: ConfirmedNodeCheckpointOriginV0,
    ) -> ConfirmedNodeCheckpointCandidateV0 {
        let watermark = checkpoint.signer_exact_watermark();
        confirm_test_node_checkpoint_candidate_v0(checkpoint, watermark, watermark, origin)
            .expect("exact signer facts")
    }

    #[test]
    fn external_node_checkpoint_codec_is_canonical_and_exact_v0() {
        let checkpoint = checkpoint_v0(0, [0; 32], 0, 0, 13, 5);
        let encoded = checkpoint.encode_canonical();
        assert_eq!(encoded.len(), EXTERNAL_NODE_CHECKPOINT_RECORD_BYTES_V0);
        assert_eq!(&encoded[..8], b"TRNMNCP0");
        assert_eq!(&encoded[8..16], &0u64.to_be_bytes());
        assert_eq!(&encoded[16..48], &[1; 32]);
        assert_eq!(&encoded[48..56], &0u64.to_be_bytes());
        assert_eq!(&encoded[56..88], &[0; 32]);
        assert_eq!(&encoded[88..120], &[2; 32]);
        assert_eq!(&encoded[120..152], &[3; 32]);
        assert_eq!(&encoded[152..160], &0u64.to_be_bytes());
        assert_eq!(&encoded[160..192], &[4; 32]);
        assert_eq!(&encoded[192..224], &[5; 32]);
        assert_eq!(&encoded[224..256], &[6; 32]);
        assert_eq!(&encoded[256..288], &[7; 32]);
        assert_eq!(&encoded[288..320], &[8; 32]);
        assert_eq!(&encoded[320..352], &[9; 32]);
        assert_eq!(&encoded[352..384], &[10; 32]);
        assert_eq!(&encoded[384..416], &[11; 32]);
        assert_eq!(&encoded[416..424], &0u64.to_be_bytes());
        assert_eq!(&encoded[424..456], &[12; 32]);
        assert_eq!(&encoded[456..464], &13u64.to_be_bytes());
        assert_eq!(&encoded[464..472], &14u64.to_be_bytes());
        assert_eq!(&encoded[472..504], &[19; 32]);
        assert_eq!(&encoded[504..536], &[18; 32]);
        assert_eq!(&encoded[536..568], &[1; 32]);
        assert_eq!(&encoded[568..600], &[19; 32]);
        assert_eq!(&encoded[600..608], &5u64.to_be_bytes());
        assert_eq!(&encoded[608..640], &[20; 32]);
        assert_eq!(&encoded[640..], &checkpoint.checkpoint_checksum());
        assert_eq!(
            checkpoint.checkpoint_checksum(),
            [
                0x9f, 0x9d, 0xf4, 0xcd, 0xd8, 0x99, 0x73, 0xfb, 0x3d, 0x30, 0xca, 0x0c, 0x18, 0x80,
                0x29, 0x86, 0x79, 0x2c, 0xd8, 0xf0, 0x3d, 0x46, 0x12, 0x76, 0x9b, 0x54, 0x17, 0xce,
                0x16, 0x55, 0x6a, 0x00,
            ]
        );
        assert_eq!(
            ExternalNodeCheckpointV0::decode_canonical_exact(&encoded),
            Ok(checkpoint)
        );

        let mut tampered = encoded;
        tampered[352] ^= 1;
        assert_eq!(
            ExternalNodeCheckpointV0::decode_canonical_exact(&tampered),
            Err(ExternalNodeCheckpointDecodeErrorV0::ChecksumMismatch)
        );
        assert_eq!(
            ExternalNodeCheckpointV0::decode_canonical_exact(&encoded[..671]),
            Err(ExternalNodeCheckpointDecodeErrorV0::WrongLength)
        );

        let mut signer_scope_mismatch = encoded;
        signer_scope_mismatch[16] ^= 1;
        assert_eq!(
            ExternalNodeCheckpointV0::decode_canonical_exact(&signer_scope_mismatch),
            Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
                "signer watermark scope"
            ))
        );
        let mut signer_journal_mismatch = encoded;
        signer_journal_mismatch[472] ^= 1;
        assert_eq!(
            ExternalNodeCheckpointV0::decode_canonical_exact(&signer_journal_mismatch),
            Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
                "signer watermark journal id"
            ))
        );
    }

    #[test]
    fn generation_and_predecessor_shapes_are_exact_v0() {
        let genesis = checkpoint_v0(0, [0; 32], 0, 0, 0, 0);
        let mut fields = *genesis.fields();
        fields.predecessor_checksum = [21; 32];
        assert_eq!(
            ExternalNodeCheckpointV0::new(fields),
            Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
                "generation-zero predecessor"
            ))
        );

        fields = *genesis.fields();
        fields.generation = 1;
        assert_eq!(
            ExternalNodeCheckpointV0::new(fields),
            Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
                "successor predecessor"
            ))
        );

        fields.predecessor_checksum = genesis.checkpoint_checksum();
        let successor = ExternalNodeCheckpointV0::new(fields).expect("exact successor shape");
        assert_eq!(successor.validate_successor_of(&genesis), Ok(()));

        fields.generation = 2;
        let skipped = ExternalNodeCheckpointV0::new(fields).expect("self-canonical skipped value");
        assert_eq!(
            skipped.validate_successor_of(&genesis),
            Err(ExternalNodeCheckpointDecodeErrorV0::InvalidField(
                "successor generation"
            ))
        );
    }

    #[test]
    fn sqlite_checkpoint_store_commissions_virgin_and_advances_exact_successor_v0() {
        let root = secure_checkpoint_temp_dir_v0("temporary checkpoint database namespace");
        let path = root.path().join("whole-node-checkpoint.sqlite3");
        let mut store = SqliteExternalNodeCheckpointStoreV0::initialize_new(&path)
            .expect("initialize independent SQLite checkpoint store");
        assert_eq!(store.database_path(), path.as_path());
        assert_eq!(store.load([1; 32]), Ok(None));

        let invalid_first = checkpoint_v0(1, [0x71; 32], 1, 1, 1, 1);
        assert_eq!(
            store.compare_and_advance(None, invalid_first),
            Err(ExternalNodeCheckpointStoreErrorV0::CompareFailed)
        );
        assert_eq!(store.load([1; 32]), Ok(None));

        let genesis = checkpoint_v0(0, [0; 32], 0, 0, 0, 0);
        store
            .compare_and_advance(None, genesis)
            .expect("commission exact generation zero");
        assert_eq!(store.load([1; 32]), Ok(Some(genesis)));

        let successor = successor_checkpoint_v0(genesis, 0x31);
        store
            .compare_and_advance(Some(genesis), successor)
            .expect("advance exact checksum-linked successor");
        assert_eq!(store.load([1; 32]), Ok(Some(successor)));

        let skipped = successor_checkpoint_v0(successor, 0x41);
        assert_eq!(
            store.compare_and_advance(Some(genesis), skipped),
            Err(ExternalNodeCheckpointStoreErrorV0::CompareFailed),
            "a target two generations beyond expected is rejected before SQLite mutation",
        );
        assert_eq!(store.load([1; 32]), Ok(Some(successor)));
    }

    #[test]
    fn sqlite_checkpoint_store_rejects_stale_expected_and_isolates_scopes_v0() {
        let root = secure_checkpoint_temp_dir_v0("temporary checkpoint database namespace");
        let path = root.path().join("whole-node-checkpoint.sqlite3");
        let mut store = SqliteExternalNodeCheckpointStoreV0::initialize_new(&path)
            .expect("initialize independent SQLite checkpoint store");

        let first_scope_genesis = checkpoint_for_scope_v0([1; 32], 0, [0; 32], 0, 0, 0, 0);
        let first_successor = successor_checkpoint_v0(first_scope_genesis, 0x31);
        let stale_alternative = successor_checkpoint_v0(first_scope_genesis, 0x41);
        store
            .compare_and_advance(None, first_scope_genesis)
            .expect("commission first scope");
        store
            .compare_and_advance(Some(first_scope_genesis), first_successor)
            .expect("advance first scope");
        assert_eq!(
            store.compare_and_advance(Some(first_scope_genesis), stale_alternative),
            Err(ExternalNodeCheckpointStoreErrorV0::CompareFailed)
        );

        let second_scope_genesis = checkpoint_for_scope_v0([0x61; 32], 0, [0; 32], 0, 0, 0, 0);
        assert_eq!(
            store.compare_and_advance(Some(first_successor), second_scope_genesis),
            Err(ExternalNodeCheckpointStoreErrorV0::CompareFailed),
            "an expected value from another scope cannot authorize a write",
        );
        assert_eq!(store.load([0x61; 32]), Ok(None));
        store
            .compare_and_advance(None, second_scope_genesis)
            .expect("commission independent second scope");
        assert_eq!(store.load([1; 32]), Ok(Some(first_successor)));
        assert_eq!(store.load([0x61; 32]), Ok(Some(second_scope_genesis)));
    }

    #[test]
    fn sqlite_checkpoint_store_reopens_durable_successor_v0() {
        let root = secure_checkpoint_temp_dir_v0("temporary checkpoint database namespace");
        let path = root.path().join("whole-node-checkpoint.sqlite3");
        let genesis = checkpoint_v0(0, [0; 32], 0, 0, 0, 0);
        let successor = successor_checkpoint_v0(genesis, 0x31);
        {
            let mut store = SqliteExternalNodeCheckpointStoreV0::initialize_new(&path)
                .expect("initialize independent SQLite checkpoint store");
            store
                .compare_and_advance(None, genesis)
                .expect("commission generation zero");
            store
                .compare_and_advance(Some(genesis), successor)
                .expect("persist successor");
        }

        let mut reopened = SqliteExternalNodeCheckpointStoreV0::open_existing(&path)
            .expect("reopen exact independent checkpoint database");
        assert_eq!(reopened.load([1; 32]), Ok(Some(successor)));
    }

    #[test]
    fn sqlite_checkpoint_store_requires_fresh_load_after_uncertain_commit_v0() {
        let root = secure_checkpoint_temp_dir_v0("temporary checkpoint database namespace");
        let path = root.path().join("whole-node-checkpoint.sqlite3");
        let mut store = SqliteExternalNodeCheckpointStoreV0::initialize_new(&path)
            .expect("initialize independent SQLite checkpoint store");
        let genesis = checkpoint_v0(0, [0; 32], 0, 0, 0, 0);
        let successor = successor_checkpoint_v0(genesis, 0x31);
        let next = successor_checkpoint_v0(successor, 0x41);
        store
            .compare_and_advance(None, genesis)
            .expect("commission generation zero");

        store.report_unavailable_after_next_commit_v0();
        assert_eq!(
            store.compare_and_advance(Some(genesis), successor),
            Err(ExternalNodeCheckpointStoreErrorV0::Unavailable),
            "an applied commit with a lost acknowledgement is reported only as unavailable",
        );
        assert!(store.connection.is_none());
        assert_eq!(
            store.load([0x61; 32]),
            Err(ExternalNodeCheckpointStoreErrorV0::Unavailable)
        );
        assert_eq!(
            store.compare_and_advance(Some(successor), next),
            Err(ExternalNodeCheckpointStoreErrorV0::Unavailable),
            "loading another scope cannot clear the uncertain scope's CAS fence",
        );
        assert_eq!(store.load([1; 32]), Ok(Some(successor)));
        assert!(store.connection.is_some());
        assert!(store.uncertain_commit.is_none());
        store
            .compare_and_advance(Some(successor), next)
            .expect("fresh exact load re-enables CAS");
        assert_eq!(store.load([1; 32]), Ok(Some(next)));
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_checkpoint_store_rejects_replaced_path_without_clearing_uncertainty_v0() {
        let root = secure_checkpoint_temp_dir_v0("temporary checkpoint database namespace");
        let path = root.path().join("whole-node-checkpoint.sqlite3");
        let displaced_path = root.path().join("displaced-checkpoint.sqlite3");
        let mut store = SqliteExternalNodeCheckpointStoreV0::initialize_new(&path)
            .expect("initialize independent SQLite checkpoint store");
        let genesis = checkpoint_v0(0, [0; 32], 0, 0, 0, 0);
        let successor = successor_checkpoint_v0(genesis, 0x31);
        store
            .compare_and_advance(None, genesis)
            .expect("commission generation zero");
        store.report_unavailable_after_next_commit_v0();
        assert_eq!(
            store.compare_and_advance(Some(genesis), successor),
            Err(ExternalNodeCheckpointStoreErrorV0::Unavailable)
        );
        assert!(store.connection.is_none());

        fs::rename(&path, &displaced_path).expect("displace the pinned database inode");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true).mode(0o600);
        options
            .open(&path)
            .expect("install a different regular inode at the pinned path");

        assert_eq!(
            store.load([1; 32]),
            Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState),
            "a replacement inode cannot resolve an uncertain commit",
        );
        assert!(store.connection.is_none());
        assert!(store.uncertain_commit.is_some());
        assert_eq!(
            store.compare_and_advance(Some(genesis), successor),
            Err(ExternalNodeCheckpointStoreErrorV0::Unavailable),
            "the uncertainty fence remains closed after path replacement",
        );
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_checkpoint_store_rejects_hard_link_alias_v0() {
        let root = secure_checkpoint_temp_dir_v0("temporary checkpoint database namespace");
        let path = root.path().join("whole-node-checkpoint.sqlite3");
        let alias = root.path().join("checkpoint-hard-link.sqlite3");
        let store = SqliteExternalNodeCheckpointStoreV0::initialize_new(&path)
            .expect("initialize independent SQLite checkpoint store");
        drop(store);
        fs::hard_link(&path, &alias).expect("create hard-link alias");

        assert!(matches!(
            SqliteExternalNodeCheckpointStoreV0::open_existing(&path),
            Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState)
        ));
        assert!(matches!(
            SqliteExternalNodeCheckpointStoreV0::open_existing(&alias),
            Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_checkpoint_store_rejects_mode_drift_v0() {
        let root = secure_checkpoint_temp_dir_v0("temporary checkpoint database namespace");
        let path = root.path().join("whole-node-checkpoint.sqlite3");
        let mut store = SqliteExternalNodeCheckpointStoreV0::initialize_new(&path)
            .expect("initialize independent SQLite checkpoint store");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
            .expect("drift checkpoint permissions");

        assert_eq!(
            store.load([1; 32]),
            Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState)
        );
        assert!(store.connection.is_none());
        assert!(matches!(
            SqliteExternalNodeCheckpointStoreV0::open_existing(&path),
            Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState)
        ));
    }

    #[test]
    fn sqlite_checkpoint_store_rejects_corrupt_and_mismatched_rows_v0() {
        let root = secure_checkpoint_temp_dir_v0("temporary checkpoint database namespace");

        let mismatch_path = root.path().join("mismatched-checkpoint.sqlite3");
        let genesis = checkpoint_v0(0, [0; 32], 0, 0, 0, 0);
        {
            let mut store = SqliteExternalNodeCheckpointStoreV0::initialize_new(&mismatch_path)
                .expect("initialize mismatch fixture");
            store
                .compare_and_advance(None, genesis)
                .expect("commission mismatch fixture");
        }
        let raw = Connection::open(&mismatch_path).expect("open raw mismatch fixture");
        raw.execute(
            "UPDATE trnm_external_node_checkpoint_v0 SET generation = ?1 WHERE scope = ?2",
            params![&1_u64.to_be_bytes()[..], &[1_u8; 32][..]],
        )
        .expect("mutate mirrored generation");
        drop(raw);
        let mut mismatched = SqliteExternalNodeCheckpointStoreV0::open_existing(&mismatch_path)
            .expect("schema remains exact after row mismatch");
        assert_eq!(
            mismatched.load([1; 32]),
            Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState)
        );

        let corrupt_path = root.path().join("corrupt-checkpoint.sqlite3");
        {
            let mut store = SqliteExternalNodeCheckpointStoreV0::initialize_new(&corrupt_path)
                .expect("initialize corruption fixture");
            store
                .compare_and_advance(None, genesis)
                .expect("commission corruption fixture");
        }
        let mut corrupt_record = genesis.encode_canonical();
        corrupt_record[352] ^= 1;
        let raw = Connection::open(&corrupt_path).expect("open raw corruption fixture");
        raw.execute(
            "UPDATE trnm_external_node_checkpoint_v0 SET record = ?1 WHERE scope = ?2",
            params![&corrupt_record[..], &[1_u8; 32][..]],
        )
        .expect("corrupt canonical record bytes");
        drop(raw);
        let mut corrupt = SqliteExternalNodeCheckpointStoreV0::open_existing(&corrupt_path)
            .expect("schema remains exact after record corruption");
        assert_eq!(
            corrupt.load([1; 32]),
            Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState)
        );
    }

    #[test]
    fn sqlite_checkpoint_store_rejects_foreign_sqlite_namespace_v0() {
        let root = secure_checkpoint_temp_dir_v0("temporary foreign database namespace");
        let path = root.path().join("foreign.sqlite3");
        let foreign = Connection::open(&path).expect("create foreign SQLite database");
        foreign
            .execute("CREATE TABLE foreign_state (value BLOB NOT NULL)", [])
            .expect("create foreign table");
        drop(foreign);
        assert!(matches!(
            SqliteExternalNodeCheckpointStoreV0::open_existing(&path),
            Err(ExternalNodeCheckpointStoreErrorV0::InvalidPersistedState)
        ));
    }

    #[test]
    fn sqlite_checkpoint_store_concurrent_cas_has_one_winner_v0() {
        use std::sync::{Arc, Barrier};

        let root = secure_checkpoint_temp_dir_v0("temporary checkpoint database namespace");
        let path = root.path().join("whole-node-checkpoint.sqlite3");
        let genesis = checkpoint_v0(0, [0; 32], 0, 0, 0, 0);
        let left_target = successor_checkpoint_v0(genesis, 0x31);
        let right_target = successor_checkpoint_v0(genesis, 0x41);
        {
            let mut store = SqliteExternalNodeCheckpointStoreV0::initialize_new(&path)
                .expect("initialize independent SQLite checkpoint store");
            store
                .compare_and_advance(None, genesis)
                .expect("commission generation zero");
        }

        let barrier = Arc::new(Barrier::new(2));
        let mut left_store = SqliteExternalNodeCheckpointStoreV0::open_existing(&path)
            .expect("open left CAS connection");
        let mut right_store = SqliteExternalNodeCheckpointStoreV0::open_existing(&path)
            .expect("open right CAS connection");
        let left_barrier = Arc::clone(&barrier);
        let left = std::thread::spawn(move || {
            left_barrier.wait();
            left_store.compare_and_advance(Some(genesis), left_target)
        });
        let right_barrier = Arc::clone(&barrier);
        let right = std::thread::spawn(move || {
            right_barrier.wait();
            right_store.compare_and_advance(Some(genesis), right_target)
        });
        let outcomes = [
            left.join().expect("left CAS thread"),
            right.join().expect("right CAS thread"),
        ];
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| {
                    **outcome == Err(ExternalNodeCheckpointStoreErrorV0::CompareFailed)
                })
                .count(),
            1,
        );

        let mut reopened = SqliteExternalNodeCheckpointStoreV0::open_existing(&path)
            .expect("reopen after concurrent CAS");
        let winner = reopened
            .load([1; 32])
            .expect("load winning row")
            .expect("winning row exists");
        assert!(winner == left_target || winner == right_target);
    }

    #[test]
    fn real_native_k_uncertain_whole_node_cas_releases_only_inert_request_signature_v0() {
        let root = secure_checkpoint_temp_dir_v0("temporary native K checkpoint namespace");
        let safety_path = root.path().join("safety.sqlite3");
        let application_path = root.path().join("application.sqlite3");
        let signer_path = root.path().join("signer.sqlite3");

        let fixture = RealNativeKFixtureV0::new();
        let genesis_qc = GenesisQcV0::new(
            fixture.validator_set.genesis_hash(),
            fixture.validator_set.chain_id(),
            &fixture.validator_set,
        )
        .expect("valid genesis QC");
        let mut core = Core::new(fixture.config.clone(), genesis_qc, &StrictEd25519Verifier)
            .expect("fresh strict Core");
        let genesis_state = core.safety_state().clone();
        let safety_profile = SafetyStateStoreProfileV0::new(
            fixture.config.clone(),
            [0xD3; 32],
            SafetyStateRecordLimitsV0::new(64 * 1024 * 1024, 16 * 1024 * 1024)
                .expect("valid Safety record limits"),
            192 * 1024 * 1024,
        )
        .expect("valid Safety profile");
        let mut safety = SqliteSafetyStateStoreV0::initialize_new(
            &safety_path,
            safety_profile,
            StrictEd25519Verifier,
            &genesis_state,
        )
        .expect("initialize real Safety journal");
        safety
            .bind_core_v0(core.safety_state_persistence_binding_v0())
            .expect("bind exact live Core");
        let genesis_safety_head = safety.head().expect("authenticated genesis Safety head");
        let genesis_safety_revision = genesis_safety_head.revision();
        let genesis_safety_record_checksum = genesis_safety_head.state_record_checksum();
        let genesis_safety_chain_checksum = genesis_safety_head.chain_checksum();

        let signer_scope = [0xD4; 32];
        let signer_profile = SignerJournalProfileV0::new(
            fixture.validator_set.clone(),
            fixture.keys[0].0,
            [0xD5; 32],
            signer_scope,
            64,
            4096,
            32 * 1024 * 1024,
        )
        .expect("valid signer profile");
        let signer_watermark = MemorySignerWatermarkV0::default();
        let mut signer = SqliteSignerJournalV0::initialize_new(
            &signer_path,
            signer_profile,
            signer_watermark.clone(),
        )
        .expect("initialize operational signer journal");
        let exact_signer_watermark = signer_watermark
            .current_v0()
            .expect("initial signer watermark");
        let signer_compare_calls_before = signer_watermark.compare_calls_v0();
        assert_eq!(exact_signer_watermark.sequence(), 0);

        let seal = core
            .issue_application_seal_authority_v0()
            .expect("issue one application seal");
        let (proposal, payload, receipts) = fixture.proposal_v0();
        let effects = core
            .step(Input::Proposal(Box::new(proposal)), &StrictEd25519Verifier)
            .expect("proposal creates one durable validation obligation");
        let [Effect::PersistSafetyState(obligation)] = effects.as_slice() else {
            panic!("expected one proposal persistence effect: {effects:?}");
        };
        assert_eq!(
            safety
                .persist_exact_v0(obligation, &SafetyTransitionContextV0::Ordinary)
                .expect("persist proposal obligation"),
            SafetyPersistDispositionV0::Inserted
        );
        let released = core
            .step(
                Input::StorageAck {
                    barrier: obligation.barrier(),
                },
                &StrictEd25519Verifier,
            )
            .expect("release exact payload validation request");
        let request = released
            .into_iter()
            .find_map(|effect| match effect {
                Effect::ValidatePayload(request) => Some(request),
                _ => None,
            })
            .expect("one Proposal validation request");
        let claimed = request.try_claim().expect("claim exact validation request");
        let (route, core_id, block, parent, permit) = claimed.into_parts();
        assert_eq!(route, PayloadValidationRouteV0::Proposal);

        let parent_state_root = StateRootV0::new([0xD6; 32]).expect("parent state root");
        let binding = ProposalValidationBindingV0::new(
            ChainIdV0::new(block.header().chain_id().as_str()).expect("native chain id"),
            GenesisHashV0::new(*block.header().genesis_hash().as_bytes())
                .expect("native genesis hash"),
            ApplicationHeadV0::new(
                HeightV0::GENESIS,
                BlockIdV0::new(*parent.tip().block_id().as_bytes()).expect("parent block"),
                parent_state_root,
                ApplicationCommitIdV0::new([0xD7; 32]).expect("parent commit"),
            ),
            BlockIdV0::new(*block.id().as_bytes()).expect("native block id"),
            HeightV0::new(block.header().height().get()),
            block.header().timestamp_ms(),
            ValidatorSetIdV0::new(*block.header().validator_set_id().as_bytes())
                .expect("native validator set"),
            core_id.view().get(),
            core_id.generation(),
            ProposalRouteV0::Proposal,
            NativeExpectedBlockCommitmentsV0::new(
                Hash32V0::new(*block.header().payload_root().as_bytes()),
                StateRootV0::new(*block.header().state_root().as_bytes()).expect("post-state root"),
                ReceiptsRootV0::new(*block.header().receipts_root().as_bytes())
                    .expect("receipts root"),
                Hash32V0::new(*block.header().evidence_root().as_bytes()),
            )
            .expect("native commitments"),
        )
        .expect("exact proposal binding");
        let executed = exact_native_execution_v0(&binding, &payload, &receipts);
        let application_scope =
            ProposalValidationStoreScopeV0::new([0xD8; 32]).expect("application scope");
        let mut application =
            SqliteProposalValidationStoreV0::open(&application_path, application_scope, 0)
                .expect("open application validation journal");
        let reserved = match application
            .reserve_v0(
                &binding,
                ProposalValidationOwnerIdV0::new([0xD9; 32]).expect("application owner"),
                &executed,
            )
            .expect("reserve exact P")
        {
            ReservationOutcomeV0::Applied(reserved) => reserved,
            ReservationOutcomeV0::NotApplied => panic!("normal P reservation must apply"),
        };
        let body = BlockBodyV0::new(payload, Vec::new()).expect("canonical body");
        let commitments = body
            .validate_ordinary_commitments(
                block.header(),
                &receipts,
                &fixture.parameters,
                &fixture.validator_set,
                &StrictEd25519Verifier,
            )
            .expect("strict ordinary commitments");
        let sealed = seal.seal_after_application_store_commit_v0(
            permit,
            commitments,
            ValidatedPayloadArtifactRefV0::new(
                BlockIdOverlayRefV0::new(block.id(), block.header().parent_id(), [0xDA; 32]),
                [0xDB; 32],
            ),
        );
        let accepted = core
            .step_application_sealed_valid_to_delivery_v0(&sealed, &StrictEd25519Verifier)
            .expect("Core mints opaque D authority");
        let delivered = match application
            .deliver_core_accepted_v0(reserved, &binding, &accepted)
            .expect("persist exact Core D")
        {
            DeliverTransitionOutcomeV0::Applied(delivered) => delivered,
            DeliverTransitionOutcomeV0::NotApplied(_) => {
                panic!("normal D transition must apply")
            }
        };
        let context = application
            .native_valid_transition_context_exact_v0(&binding, &delivered, &accepted)
            .expect("derive exact D-bound Safety context");
        assert_eq!(
            safety
                .persist_exact_v0(accepted.persistence_request_v0(), &context)
                .expect("persist real Safety C"),
            SafetyPersistDispositionV0::Inserted
        );
        let acked = match application
            .acknowledge_confirmed_safety_v0(delivered, &binding, &accepted, &safety, &safety_path)
            .expect("fresh-confirm C and close K")
        {
            AckTransitionOutcomeV0::Applied(acked) => acked,
            AckTransitionOutcomeV0::NotApplied(_) => panic!("normal K transition must apply"),
        };

        let source = ExternalNodeCheckpointV0::new(ExternalNodeCheckpointFieldsV0 {
            scope: signer_scope,
            generation: 0,
            predecessor_checksum: [0; 32],
            safety_journal_id: safety.journal_id_v0(),
            safety_verifier_profile_ref: safety.verifier_profile_ref_v0(),
            safety_revision: genesis_safety_revision,
            safety_state_record_checksum: genesis_safety_record_checksum,
            safety_record_chain_checksum: genesis_safety_chain_checksum,
            application_host_config_ref: [0xDC; 32],
            application_projection_profile_ref: [0xDD; 32],
            application_safety_binding_manifest_checksum: [0xDE; 32],
            application_committed_head_row_checksum: [0xDF; 32],
            application_recovery_closure_checksum: [0xE1; 32],
            application_block_id: BlockId::new(*parent.tip().block_id().as_bytes()),
            application_height: 0,
            application_state_root: StateRoot::new(*parent_state_root.as_bytes()),
            application_view: 0,
            application_timestamp_ms: 0,
            signer_journal_id: exact_signer_watermark.journal_id(),
            signer_profile_checksum: signer.profile().profile_checksum(),
            signer_exact_watermark: exact_signer_watermark,
        })
        .expect("canonical predecessor checkpoint");
        let mut checkpoint_store = MemoryNodeCheckpointStoreV0 {
            value: Some(source),
            error_after_apply_once: Some(ExternalNodeCheckpointStoreErrorV0::Unavailable),
            ..MemoryNodeCheckpointStoreV0::default()
        };
        let confirmed = advance_native_k_whole_node_checkpoint_v0(
            &mut checkpoint_store,
            source,
            &safety,
            &safety_path,
            &mut application,
            &application_path,
            &binding,
            &mut signer,
            &signer_path,
        )
        .expect("fresh target readback resolves applied-but-ack-lost whole-node CAS");
        let target = *confirmed.checkpoint_v0();
        assert_eq!(target.generation(), 1);
        assert_eq!(target.predecessor_checksum(), source.checkpoint_checksum());
        assert_eq!(
            target.fields().safety_revision,
            accepted.completion_revision_v0()
        );
        assert_eq!(target.fields().application_height, 1);
        assert_eq!(target.fields().application_view, 1);
        assert_eq!(target.signer_exact_watermark(), exact_signer_watermark);
        assert_eq!(checkpoint_store.value, Some(target));
        assert_eq!(checkpoint_store.advances, 1);
        assert_eq!(checkpoint_store.loads, 2);
        assert_eq!(
            signer_watermark.compare_calls_v0(),
            signer_compare_calls_before,
            "whole-node checkpoint confirmation never repairs or advances the signer watermark",
        );

        assert_eq!(
            core.safety_state()
                .pending_sign()
                .expect("Core retains the inert Vote")
                .signing_root()
                .as_bytes(),
            acked
                .request_bound_safety_confirmation()
                .vote_intent_digest()
                .as_bytes(),
            "K and Core still retain the same inert Vote before whole-node-authorized StorageAck",
        );
        let effects = core
            .step(
                Input::StorageAck {
                    barrier: accepted.barrier_v0(),
                },
                &StrictEd25519Verifier,
            )
            .expect("whole-node-authorized Core StorageAck");
        let [Effect::RequestSignature { intent }] = effects.as_slice() else {
            panic!("expected only one inert RequestSignature: {effects:?}");
        };
        assert_eq!(
            intent.signing_root().as_bytes(),
            acked
                .request_bound_safety_confirmation()
                .vote_intent_digest()
                .as_bytes()
        );
        assert_eq!(
            signer_watermark.compare_calls_v0(),
            signer_compare_calls_before
        );
        assert_eq!(
            signer
                .confirm_node_checkpoint_head_exact_v0()
                .expect("signer remains exact and unsigned")
                .exact_watermark(),
            exact_signer_watermark
        );
    }

    #[test]
    fn only_explicit_virgin_genesis_can_commission_none_to_current_v0() {
        let checkpoint = checkpoint_v0(0, [0; 32], 0, 0, 0, 0);
        let candidate = candidate_v0(checkpoint, ConfirmedNodeCheckpointOriginV0::VirginGenesis);
        let mut store = MemoryNodeCheckpointStoreV0::default();
        let outcome = reconcile_development_only_external_node_checkpoint_startup_v0(
            &mut store,
            ExternalNodeCheckpointStartupModeV0::ExplicitVirginGenesisCommissioning,
            false,
            Some(candidate),
        )
        .expect("virgin genesis commissions once");
        assert_eq!(
            outcome,
            ExternalNodeCheckpointStartupOutcomeV0::CommissionedVirginGenesis
        );
        assert_eq!(store.value, Some(checkpoint));
        assert_eq!(store.advances, 1);

        let retry = reconcile_development_only_external_node_checkpoint_startup_v0(
            &mut store,
            ExternalNodeCheckpointStartupModeV0::ExplicitVirginGenesisCommissioning,
            false,
            Some(candidate_v0(
                checkpoint,
                ConfirmedNodeCheckpointOriginV0::VirginGenesis,
            )),
        )
        .expect("an exact post-CAS retry resolves without another advance");
        assert_eq!(retry, ExternalNodeCheckpointStartupOutcomeV0::ExactExisting);
        assert_eq!(store.advances, 1);

        let existing_candidate = candidate_v0(
            checkpoint,
            ConfirmedNodeCheckpointOriginV0::ExistingNamespace,
        );
        let error = reconcile_development_only_external_node_checkpoint_startup_v0(
            &mut store,
            ExternalNodeCheckpointStartupModeV0::ExplicitVirginGenesisCommissioning,
            false,
            Some(existing_candidate),
        )
        .expect_err("existing namespace cannot claim commissioning authority");
        assert_eq!(
            error,
            ExternalNodeCheckpointStartupErrorV0::CommissioningRequiresVirginGenesis
        );
        assert_eq!(store.advances, 1);
        assert_eq!(store.loads, 2, "invalid commissioning stops before load");

        let nonvirgin = checkpoint_v0(0, [0; 32], 1, 0, 0, 0);
        let mut empty_store = MemoryNodeCheckpointStoreV0::default();
        let error = reconcile_development_only_external_node_checkpoint_startup_v0(
            &mut empty_store,
            ExternalNodeCheckpointStartupModeV0::ExplicitVirginGenesisCommissioning,
            false,
            Some(candidate_v0(
                nonvirgin,
                ConfirmedNodeCheckpointOriginV0::VirginGenesis,
            )),
        )
        .expect_err("an origin label cannot hide non-virgin durable facts");
        assert_eq!(
            error,
            ExternalNodeCheckpointStartupErrorV0::CommissioningRequiresVirginGenesis
        );
        assert_eq!(empty_store.loads, 0);
        assert_eq!(empty_store.advances, 0);

        let mut uncertain_store = MemoryNodeCheckpointStoreV0 {
            error_after_apply_once: Some(ExternalNodeCheckpointStoreErrorV0::Unavailable),
            ..MemoryNodeCheckpointStoreV0::default()
        };
        let resolved = reconcile_development_only_external_node_checkpoint_startup_v0(
            &mut uncertain_store,
            ExternalNodeCheckpointStartupModeV0::ExplicitVirginGenesisCommissioning,
            false,
            Some(candidate_v0(
                checkpoint,
                ConfirmedNodeCheckpointOriginV0::VirginGenesis,
            )),
        )
        .expect("fresh exact readback resolves an uncertain applied CAS");
        assert_eq!(
            resolved,
            ExternalNodeCheckpointStartupOutcomeV0::ExactExisting
        );
        assert_eq!(uncertain_store.loads, 2);
        assert_eq!(uncertain_store.advances, 1);
    }

    #[test]
    fn existing_namespace_requires_exact_external_checkpoint_v0() {
        let local = checkpoint_v0(7, [21; 32], 9, 4, 13, 5);
        let mut store = MemoryNodeCheckpointStoreV0::default();
        let missing = reconcile_development_only_external_node_checkpoint_startup_v0(
            &mut store,
            ExternalNodeCheckpointStartupModeV0::ExistingNamespaceExactComparison,
            false,
            Some(candidate_v0(
                local,
                ConfirmedNodeCheckpointOriginV0::ExistingNamespace,
            )),
        )
        .expect_err("missing independent checkpoint fails closed");
        assert_eq!(
            missing,
            ExternalNodeCheckpointStartupErrorV0::MissingExternalCheckpoint
        );
        assert_eq!(store.advances, 0);

        store.value = Some(checkpoint_v0(7, [22; 32], 9, 4, 13, 5));
        let mismatch = reconcile_development_only_external_node_checkpoint_startup_v0(
            &mut store,
            ExternalNodeCheckpointStartupModeV0::ExistingNamespaceExactComparison,
            false,
            Some(candidate_v0(
                local,
                ConfirmedNodeCheckpointOriginV0::ExistingNamespace,
            )),
        )
        .expect_err("different external checkpoint fails closed");
        assert_eq!(
            mismatch,
            ExternalNodeCheckpointStartupErrorV0::ExternalCheckpointMismatch
        );
        assert_eq!(store.advances, 0);

        store.value = Some(local);
        let exact = reconcile_development_only_external_node_checkpoint_startup_v0(
            &mut store,
            ExternalNodeCheckpointStartupModeV0::ExistingNamespaceExactComparison,
            false,
            Some(candidate_v0(
                local,
                ConfirmedNodeCheckpointOriginV0::ExistingNamespace,
            )),
        )
        .expect("exact external checkpoint is admitted read-only");
        assert_eq!(exact, ExternalNodeCheckpointStartupOutcomeV0::ExactExisting);
        assert_eq!(store.advances, 0);
    }

    #[test]
    fn h1_replay_fence_neither_loads_nor_advances_external_checkpoint_v0() {
        let mut store = MemoryNodeCheckpointStoreV0::default();
        let outcome = reconcile_development_only_external_node_checkpoint_startup_v0(
            &mut store,
            ExternalNodeCheckpointStartupModeV0::H1ReplayFencedOffline,
            false,
            None,
        )
        .expect("permanent h1 replay fence needs no joint checkpoint");
        assert_eq!(
            outcome,
            ExternalNodeCheckpointStartupOutcomeV0::NotRequiredForH1ReplayFence
        );
        assert_eq!(store.loads, 0);
        assert_eq!(store.advances, 0);
        assert_eq!(store.value, None);
    }

    #[test]
    fn whole_three_store_rollback_after_last_sign_is_not_detected_v0() {
        // T0 and T1 share the exact same signer watermark because no signing
        // happened between them.  Safety/App alone advanced at T1.
        let t0 = checkpoint_v0(7, [21; 32], 9, 4, 13, 5);
        let t1 = ExternalNodeCheckpointV0::new(ExternalNodeCheckpointFieldsV0 {
            generation: 8,
            predecessor_checksum: t0.checkpoint_checksum(),
            safety_revision: 12,
            safety_state_record_checksum: [24; 32],
            safety_record_chain_checksum: [25; 32],
            application_committed_head_row_checksum: [26; 32],
            application_recovery_closure_checksum: [27; 32],
            application_block_id: BlockId::new([28; 32]),
            application_height: 7,
            application_state_root: StateRoot::new([29; 32]),
            application_view: 30,
            application_timestamp_ms: 31,
            ..*t0.fields()
        })
        .expect("T1 checkpoint");

        assert_eq!(
            t0.signer_exact_watermark(),
            t1.signer_exact_watermark(),
            "the legacy external signer watermark cannot distinguish T0/T1"
        );
        assert_ne!(
            t0.checkpoint_checksum(),
            t1.checkpoint_checksum(),
            "the joint checkpoint binds Safety/App-only progress"
        );

        // Restore all three local namespaces to T0 while the independent node
        // checkpoint correctly remains T1.  This is a pure model counterexample,
        // not a claim of a real three-process crash test.
        let mut store = MemoryNodeCheckpointStoreV0 {
            value: Some(t1),
            ..MemoryNodeCheckpointStoreV0::default()
        };
        let error = reconcile_development_only_external_node_checkpoint_startup_v0(
            &mut store,
            ExternalNodeCheckpointStartupModeV0::ExistingNamespaceExactComparison,
            false,
            Some(candidate_v0(
                t0,
                ConfirmedNodeCheckpointOriginV0::ExistingNamespace,
            )),
        )
        .expect_err("joint external checkpoint detects the full local rollback");
        assert_eq!(
            error,
            ExternalNodeCheckpointStartupErrorV0::ExternalCheckpointMismatch
        );
        assert_eq!(store.advances, 0);
    }

    #[test]
    fn production_and_nonexact_signer_join_remain_blocked_v0() {
        let checkpoint = checkpoint_v0(0, [0; 32], 0, 0, 0, 0);
        let foreign = SignerWatermarkV0::from_persisted_parts([1; 32], [19; 32], 0, [99; 32])
            .expect("foreign watermark");
        let join_error = confirm_test_node_checkpoint_candidate_v0(
            checkpoint,
            watermark_v0(0),
            foreign,
            ConfirmedNodeCheckpointOriginV0::VirginGenesis,
        )
        .expect_err("non-exact signer facts cannot mint a candidate");
        assert_eq!(
            join_error,
            NodeCheckpointJoinErrorV0::SignerWatermarkNotExact
        );

        let mut store = MemoryNodeCheckpointStoreV0::default();
        let error = reconcile_development_only_external_node_checkpoint_startup_v0(
            &mut store,
            ExternalNodeCheckpointStartupModeV0::ExplicitVirginGenesisCommissioning,
            true,
            Some(candidate_v0(
                checkpoint,
                ConfirmedNodeCheckpointOriginV0::VirginGenesis,
            )),
        )
        .expect_err("production activation remains blocked before any store access");
        assert_eq!(
            error,
            ExternalNodeCheckpointStartupErrorV0::ProductionActivationBlocked
        );
        assert_eq!(store.loads, 0);
        assert_eq!(store.advances, 0);
    }
}
