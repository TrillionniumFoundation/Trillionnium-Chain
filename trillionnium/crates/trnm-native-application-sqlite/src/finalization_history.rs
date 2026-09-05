use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[cfg(unix)]
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use trnm_native_application::{
    ApplicationCommitIdV0, ApplicationHeadV0, BlockIdV0, Hash32V0, HeightV0,
    NativeFinalizationApplyReadbackV0, NativeFinalizationIntentV0, StateRootV0,
};

use crate::error::{error, ValidationStoreErrorCodeV0, ValidationStoreResultV0};

const SCHEMA_VERSION_V0: i64 = 1;
const HEAD_BYTES_V0: usize = 8 + 32 + 32 + 32;
const RECORD_BYTES_V0: usize =
    2 + HEAD_BYTES_V0 + HEAD_BYTES_V0 + (4 * 32) + HEAD_BYTES_V0 + 32 + 32 + 8;
const RECORD_VERSION_V0: u16 = 1;
const RECORD_DIGEST_DOMAIN_V0: &[u8] = b"TRNM_NATIVE_FINALIZATION_HISTORY_RECORD_V0";
const CHAIN_DIGEST_DOMAIN_V0: &[u8] = b"TRNM_NATIVE_FINALIZATION_HISTORY_CHAIN_V0";
const GENESIS_DIGEST_DOMAIN_V0: &[u8] = b"TRNM_NATIVE_FINALIZATION_HISTORY_GENESIS_V0";

pub const MAX_FINALIZATION_HISTORY_ENTRIES_V0: u64 = 1_000_000;

const METADATA_SCHEMA_V0: &str = "CREATE TABLE finalization_history_metadata_v0 (singleton INTEGER PRIMARY KEY CHECK (singleton = 1),schema_version INTEGER NOT NULL CHECK (schema_version = 1),scope BLOB NOT NULL CHECK (length(scope) = 32),initial_head BLOB NOT NULL CHECK (length(initial_head) = 104),sequence BLOB NOT NULL CHECK (length(sequence) = 8),chain_digest BLOB NOT NULL CHECK (length(chain_digest) = 32)) STRICT";
const RECORD_SCHEMA_V0: &str = "CREATE TABLE finalization_history_records_v0 (sequence BLOB PRIMARY KEY NOT NULL CHECK (length(sequence) = 8),target_block_id BLOB NOT NULL UNIQUE CHECK (length(target_block_id) = 32),proof_id BLOB NOT NULL UNIQUE CHECK (length(proof_id) = 32),record BLOB NOT NULL CHECK (length(record) = 514),record_digest BLOB NOT NULL UNIQUE CHECK (length(record_digest) = 32),previous_chain_digest BLOB NOT NULL CHECK (length(previous_chain_digest) = 32),chain_digest BLOB NOT NULL UNIQUE CHECK (length(chain_digest) = 32)) STRICT";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizationHistoryScopeV0([u8; 32]);

impl FinalizationHistoryScopeV0 {
    pub fn new(bytes: [u8; 32]) -> ValidationStoreResultV0<Self> {
        if bytes == [0; 32] {
            return Err(error(
                ValidationStoreErrorCodeV0::ZeroValue,
                "finalization_history.scope",
            ));
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedFinalizationHistoryRecordV0 {
    readback: NativeFinalizationApplyReadbackV0,
    record_digest: Hash32V0,
    previous_chain_digest: Hash32V0,
    chain_digest: Hash32V0,
}

impl ConfirmedFinalizationHistoryRecordV0 {
    pub const fn readback(&self) -> &NativeFinalizationApplyReadbackV0 {
        &self.readback
    }

    pub const fn record_digest(&self) -> Hash32V0 {
        self.record_digest
    }

    pub const fn previous_chain_digest(&self) -> Hash32V0 {
        self.previous_chain_digest
    }

    pub const fn chain_digest(&self) -> Hash32V0 {
        self.chain_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalizationHistoryAppendOutcomeV0 {
    NewlyAppended(ConfirmedFinalizationHistoryRecordV0),
    ExactReplay(ConfirmedFinalizationHistoryRecordV0),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedFinalizationHistoryAuditV0 {
    entry_count: u64,
    committed_head: ApplicationHeadV0,
    chain_digest: Hash32V0,
}

impl ConfirmedFinalizationHistoryAuditV0 {
    pub const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    pub const fn committed_head(&self) -> &ApplicationHeadV0 {
        &self.committed_head
    }

    pub const fn chain_digest(&self) -> Hash32V0 {
        self.chain_digest
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentityV0 {
    device: u64,
    inode: u64,
}

/// Lifetime pin for the authoritative parent directory and database inode.
///
/// SQLite still accepts a pathname, so every trusted operation compares that
/// pathname to these retained descriptors before opening, while the connection
/// is live, and again after the connection is closed. `SQLITE_OPEN_NOFOLLOW`
/// protects the final path component; the retained directory/database handles
/// detect rename, hard-link, symlink, and same-schema database substitution.
#[derive(Debug)]
struct PinnedSqliteNamespaceV0 {
    parent_path: PathBuf,
    database_path: PathBuf,
    #[cfg(unix)]
    parent_file: File,
    #[cfg(unix)]
    database_file: File,
    #[cfg(unix)]
    parent_identity: FileIdentityV0,
    #[cfg(unix)]
    database_identity: FileIdentityV0,
}

#[cfg(unix)]
#[derive(Debug)]
struct PinnedAuxiliaryFileV0 {
    path: PathBuf,
    file: File,
    identity: FileIdentityV0,
}

#[derive(Debug)]
struct PinnedSqliteAuxiliaryNamespaceV0 {
    #[cfg(unix)]
    wal: PinnedAuxiliaryFileV0,
    #[cfg(unix)]
    shm: PinnedAuxiliaryFileV0,
}

impl PinnedSqliteNamespaceV0 {
    fn pin(path: &Path) -> ValidationStoreResultV0<Self> {
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(error(
                ValidationStoreErrorCodeV0::UnsupportedPlatform,
                "finalization_history.namespace_platform",
            ));
        }

        #[cfg(unix)]
        {
            let parent_path = path.parent().ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::InvalidBinding,
                    "finalization_history.parent",
                )
            })?;
            fs::create_dir_all(parent_path).map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::Storage,
                    "finalization_history.parent_create",
                )
            })?;
            let canonical_parent = fs::canonicalize(parent_path).map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::Storage,
                    "finalization_history.parent_canonical",
                )
            })?;
            if canonical_parent != parent_path {
                return Err(error(
                    ValidationStoreErrorCodeV0::ReplacedStore,
                    "finalization_history.parent_not_canonical",
                ));
            }

            let parent_file = open_directory_nofollow_v0(parent_path)?;
            let parent_identity = directory_handle_identity_v0(&parent_file)?;
            let database_file = open_or_create_database_nofollow_v0(path)?;
            let database_identity = file_handle_identity_v0(&database_file)?;
            let namespace = Self {
                parent_path: parent_path.to_path_buf(),
                database_path: path.to_path_buf(),
                parent_file,
                database_file,
                parent_identity,
                database_identity,
            };
            namespace.verify()?;
            Ok(namespace)
        }
    }

    fn verify(&self) -> ValidationStoreResultV0<()> {
        #[cfg(not(unix))]
        {
            return Err(error(
                ValidationStoreErrorCodeV0::UnsupportedPlatform,
                "finalization_history.namespace_platform",
            ));
        }

        #[cfg(unix)]
        {
            verify_directory_identity_v0(
                &self.parent_path,
                &self.parent_file,
                self.parent_identity,
            )?;
            verify_regular_file_identity_v0(
                &self.database_path,
                &self.database_file,
                self.database_identity,
            )?;
            validate_auxiliary_namespace_paths_v0(&self.database_path)
        }
    }

    fn verify_connection(&self, connection: &Connection) -> ValidationStoreResultV0<()> {
        self.verify()?;
        let mut statement = connection.prepare("PRAGMA database_list").map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.database_list_prepare",
            )
        })?;
        let mut rows = statement.query([]).map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.database_list_query",
            )
        })?;
        let mut main_path = None;
        while let Some(row) = rows.next().map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.database_list_row",
            )
        })? {
            let name = row.get::<_, String>(1).map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::Storage,
                    "finalization_history.database_list_name",
                )
            })?;
            if name == "main" {
                main_path = Some(row.get::<_, String>(2).map_err(|_| {
                    error(
                        ValidationStoreErrorCodeV0::Storage,
                        "finalization_history.database_list_path",
                    )
                })?);
            }
        }
        let main_path = main_path.ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::ReplacedStore,
                "finalization_history.database_list_main",
            )
        })?;
        if main_path.is_empty() {
            return Err(error(
                ValidationStoreErrorCodeV0::ReplacedStore,
                "finalization_history.database_list_memory",
            ));
        }
        let canonical = fs::canonicalize(main_path).map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::ReplacedStore,
                "finalization_history.database_list_canonical",
            )
        })?;
        if canonical != self.database_path {
            return Err(error(
                ValidationStoreErrorCodeV0::ReplacedStore,
                "finalization_history.database_list_binding",
            ));
        }
        #[cfg(unix)]
        {
            let metadata = fs::symlink_metadata(&canonical).map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::ReplacedStore,
                    "finalization_history.database_list_metadata",
                )
            })?;
            validate_regular_file_metadata_v0(
                &metadata,
                "finalization_history.database_list_type",
            )?;
            if identity_from_metadata_v0(&metadata) != self.database_identity {
                return Err(error(
                    ValidationStoreErrorCodeV0::ReplacedStore,
                    "finalization_history.database_list_identity",
                ));
            }
        }
        Ok(())
    }
}

impl PinnedSqliteAuxiliaryNamespaceV0 {
    fn capture(database_path: &Path) -> ValidationStoreResultV0<Self> {
        #[cfg(not(unix))]
        {
            let _ = database_path;
            return Err(error(
                ValidationStoreErrorCodeV0::UnsupportedPlatform,
                "finalization_history.auxiliary_platform",
            ));
        }

        #[cfg(unix)]
        {
            reject_rollback_journal_v0(database_path)?;
            Ok(Self {
                wal: pin_required_auxiliary_file_v0(database_path, "-wal")?,
                shm: pin_required_auxiliary_file_v0(database_path, "-shm")?,
            })
        }
    }

    fn verify_live(&self, database_path: &Path) -> ValidationStoreResultV0<()> {
        #[cfg(not(unix))]
        {
            let _ = database_path;
            return Err(error(
                ValidationStoreErrorCodeV0::UnsupportedPlatform,
                "finalization_history.auxiliary_platform",
            ));
        }

        #[cfg(unix)]
        {
            reject_rollback_journal_v0(database_path)?;
            verify_auxiliary_file_identity_v0(&self.wal, false)?;
            verify_auxiliary_file_identity_v0(&self.shm, false)
        }
    }

    fn verify_after_close(&self, database_path: &Path) -> ValidationStoreResultV0<()> {
        #[cfg(not(unix))]
        {
            let _ = database_path;
            return Err(error(
                ValidationStoreErrorCodeV0::UnsupportedPlatform,
                "finalization_history.auxiliary_platform",
            ));
        }

        #[cfg(unix)]
        {
            reject_rollback_journal_v0(database_path)?;
            verify_auxiliary_file_identity_v0(&self.wal, true)?;
            verify_auxiliary_file_identity_v0(&self.shm, true)
        }
    }
}

#[derive(Debug, Clone)]
pub struct SqliteNativeFinalizationHistoryV0 {
    path: PathBuf,
    scope: FinalizationHistoryScopeV0,
    initial_head: ApplicationHeadV0,
    namespace: Arc<PinnedSqliteNamespaceV0>,
}

impl SqliteNativeFinalizationHistoryV0 {
    pub fn open(
        path: impl AsRef<Path>,
        scope: FinalizationHistoryScopeV0,
        initial_head: ApplicationHeadV0,
    ) -> ValidationStoreResultV0<Self> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() || !path.is_absolute() {
            return Err(error(
                ValidationStoreErrorCodeV0::InvalidBinding,
                "finalization_history.path",
            ));
        }
        let namespace = Arc::new(PinnedSqliteNamespaceV0::pin(path)?);
        let store = Self {
            path: path.to_path_buf(),
            scope,
            initial_head,
            namespace,
        };
        store.with_verified_connection_v0(true, |connection| {
            let _ = audit_connection_v0(connection, store.scope, &store.initial_head)?;
            Ok(())
        })?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn scope(&self) -> FinalizationHistoryScopeV0 {
        self.scope
    }

    pub const fn initial_head(&self) -> &ApplicationHeadV0 {
        &self.initial_head
    }

    pub fn audit(&self) -> ValidationStoreResultV0<ConfirmedFinalizationHistoryAuditV0> {
        self.with_verified_connection_v0(false, |connection| {
            audit_connection_v0(connection, self.scope, &self.initial_head)
        })
    }

    pub fn read_sequence(
        &self,
        sequence: u64,
    ) -> ValidationStoreResultV0<Option<ConfirmedFinalizationHistoryRecordV0>> {
        if sequence == 0 {
            return Err(error(
                ValidationStoreErrorCodeV0::ZeroValue,
                "finalization_history.read_sequence",
            ));
        }
        self.with_verified_connection_v0(false, |connection| {
            let audit = audit_connection_v0(connection, self.scope, &self.initial_head)?;
            if sequence > audit.entry_count {
                return Ok(None);
            }
            let row = load_row_by_sequence_v0(connection, sequence)?.ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "finalization_history.missing_sequence",
                )
            })?;
            Ok(Some(confirm_row_v0(self.scope, &row)?))
        })
    }

    pub fn append(
        &self,
        readback: NativeFinalizationApplyReadbackV0,
    ) -> ValidationStoreResultV0<FinalizationHistoryAppendOutcomeV0> {
        let sequence = readback.durable_sequence();
        let record = encode_readback_v0(&readback);
        let record_digest = digest_v0(
            RECORD_DIGEST_DOMAIN_V0,
            &[self.scope.as_bytes().as_slice(), record.as_slice()],
        );

        let write_phase = self.with_verified_connection_v0(false, |connection| {
            let before = audit_connection_v0(connection, self.scope, &self.initial_head)?;
            if sequence <= before.entry_count {
                let existing = load_row_by_sequence_v0(connection, sequence)?.ok_or_else(|| {
                    error(
                        ValidationStoreErrorCodeV0::CorruptStore,
                        "finalization_history.replay_missing",
                    )
                })?;
                if existing.record == record && existing.record_digest == record_digest {
                    return Ok(FinalizationHistoryWritePhaseV0::ExactReplay(Box::new(
                        confirm_row_v0(self.scope, &existing)?,
                    )));
                }
                return Err(error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "finalization_history.replay_conflict",
                ));
            }

            let expected_sequence = before.entry_count.checked_add(1).ok_or_else(|| {
                error(
                    ValidationStoreErrorCodeV0::Overflow,
                    "finalization_history.sequence",
                )
            })?;
            if sequence != expected_sequence || sequence > MAX_FINALIZATION_HISTORY_ENTRIES_V0 {
                return Err(error(
                    ValidationStoreErrorCodeV0::InvalidTransition,
                    "finalization_history.sequence",
                ));
            }
            if readback.intent().parent() != before.committed_head() {
                return Err(error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "finalization_history.parent",
                ));
            }

            let target_block_id_value = readback.intent().target().block_id();
            let target_block_id = target_block_id_value.as_bytes();
            let proof_id_value = readback.intent().proof_id();
            let proof_id = proof_id_value.as_bytes();
            let collision = connection
                .query_row(
                    "SELECT record_digest FROM finalization_history_records_v0 WHERE target_block_id = ?1 OR proof_id = ?2 LIMIT 1",
                    params![target_block_id.as_slice(), proof_id.as_slice()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
                .map_err(|_| {
                    error(
                        ValidationStoreErrorCodeV0::Storage,
                        "finalization_history.collision_read",
                    )
                })?;
            if collision.is_some() {
                return Err(error(
                    ValidationStoreErrorCodeV0::BindingMismatch,
                    "finalization_history.identity_collision",
                ));
            }

            let previous_chain_digest = before.chain_digest().into_bytes();
            let sequence_bytes = sequence.to_be_bytes();
            let chain_digest = digest_v0(
                CHAIN_DIGEST_DOMAIN_V0,
                &[
                    self.scope.as_bytes().as_slice(),
                    previous_chain_digest.as_slice(),
                    record_digest.as_slice(),
                    sequence_bytes.as_slice(),
                ],
            );
            let expected_previous_sequence = before.entry_count.to_be_bytes();
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| {
                    error(
                        ValidationStoreErrorCodeV0::Storage,
                        "finalization_history.transaction",
                    )
                })?;
            transaction
                .execute(
                    "INSERT INTO finalization_history_records_v0 (sequence,target_block_id,proof_id,record,record_digest,previous_chain_digest,chain_digest) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        sequence_bytes.as_slice(),
                        target_block_id.as_slice(),
                        proof_id.as_slice(),
                        record.as_slice(),
                        record_digest.as_slice(),
                        previous_chain_digest.as_slice(),
                        chain_digest.as_slice(),
                    ],
                )
                .map_err(|_| {
                    error(
                        ValidationStoreErrorCodeV0::CommitUncertain,
                        "finalization_history.insert",
                    )
                })?;
            let updated = transaction
                .execute(
                    "UPDATE finalization_history_metadata_v0 SET sequence = ?1, chain_digest = ?2 WHERE singleton = 1 AND sequence = ?3 AND chain_digest = ?4",
                    params![
                        sequence_bytes.as_slice(),
                        chain_digest.as_slice(),
                        expected_previous_sequence.as_slice(),
                        previous_chain_digest.as_slice(),
                    ],
                )
                .map_err(|_| {
                    error(
                        ValidationStoreErrorCodeV0::CommitUncertain,
                        "finalization_history.metadata_update",
                    )
                })?;
            if updated != 1 {
                return Err(error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "finalization_history.metadata_cas",
                ));
            }
            transaction.commit().map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::CommitUncertain,
                    "finalization_history.commit",
                )
            })?;
            Ok(FinalizationHistoryWritePhaseV0::NewlyCommitted {
                previous_chain_digest,
                chain_digest,
            })
        })?;

        match write_phase {
            FinalizationHistoryWritePhaseV0::ExactReplay(confirmed) => {
                Ok(FinalizationHistoryAppendOutcomeV0::ExactReplay(*confirmed))
            }
            FinalizationHistoryWritePhaseV0::NewlyCommitted {
                previous_chain_digest,
                chain_digest,
            } => {
                let confirmed = self.with_verified_connection_v0(false, |fresh| {
                    let after = audit_connection_v0(fresh, self.scope, &self.initial_head)?;
                    if after.entry_count() != sequence
                        || after.committed_head() != readback.committed_head()
                    {
                        return Err(error(
                            ValidationStoreErrorCodeV0::CommitUncertain,
                            "finalization_history.fresh_readback",
                        ));
                    }
                    let stored = load_row_by_sequence_v0(fresh, sequence)?.ok_or_else(|| {
                        error(
                            ValidationStoreErrorCodeV0::CommitUncertain,
                            "finalization_history.fresh_record",
                        )
                    })?;
                    if stored.record != record
                        || stored.record_digest != record_digest
                        || stored.previous_chain_digest != previous_chain_digest
                        || stored.chain_digest != chain_digest
                    {
                        return Err(error(
                            ValidationStoreErrorCodeV0::CommitUncertain,
                            "finalization_history.fresh_identity",
                        ));
                    }
                    confirm_row_v0(self.scope, &stored)
                })?;
                Ok(FinalizationHistoryAppendOutcomeV0::NewlyAppended(confirmed))
            }
        }
    }

    fn with_verified_connection_v0<T>(
        &self,
        initialize: bool,
        operation: impl FnOnce(&mut Connection) -> ValidationStoreResultV0<T>,
    ) -> ValidationStoreResultV0<T> {
        self.namespace.verify()?;
        let mut connection = open_connection_v0(&self.path)?;
        let mut auxiliary = None;
        let operation_result = (|| {
            if initialize {
                initialize_or_validate_schema_v0(&connection, self.scope, &self.initial_head)?;
            } else {
                validate_closed_world_schema_v0(&connection)?;
            }
            materialize_auxiliary_namespace_v0(&connection)?;
            let witness = PinnedSqliteAuxiliaryNamespaceV0::capture(&self.path)?;
            witness.verify_live(&self.path)?;
            self.namespace.verify_connection(&connection)?;
            auxiliary = Some(witness);
            operation(&mut connection)
        })();

        // Never expose a value from the operation until the live namespace and
        // schema are rechecked, SQLite is explicitly closed, and the retained
        // directory/database/sidecar descriptors are compared again.
        let live_result = self
            .namespace
            .verify_connection(&connection)
            .and_then(|_| validate_closed_world_schema_v0(&connection))
            .and_then(|_| match auxiliary.as_ref() {
                Some(witness) => witness.verify_live(&self.path),
                None => validate_auxiliary_namespace_paths_v0(&self.path),
            });
        let close_result = close_connection_v0(connection);
        let post_close_result = self
            .namespace
            .verify()
            .and_then(|_| match auxiliary.as_ref() {
                Some(witness) => witness.verify_after_close(&self.path),
                None => validate_auxiliary_namespace_paths_v0(&self.path),
            });

        live_result?;
        close_result?;
        post_close_result?;
        operation_result
    }
}

#[derive(Debug, Clone)]
enum FinalizationHistoryWritePhaseV0 {
    ExactReplay(Box<ConfirmedFinalizationHistoryRecordV0>),
    NewlyCommitted {
        previous_chain_digest: [u8; 32],
        chain_digest: [u8; 32],
    },
}

#[derive(Debug, Clone)]
struct StoredFinalizationRowV0 {
    sequence: u64,
    target_block_id: [u8; 32],
    proof_id: [u8; 32],
    record: Vec<u8>,
    record_digest: [u8; 32],
    previous_chain_digest: [u8; 32],
    chain_digest: [u8; 32],
}

#[cfg(unix)]
fn open_directory_nofollow_v0(path: &Path) -> ValidationStoreResultV0<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::ReplacedStore,
            "finalization_history.parent_open",
        )
    })
}

#[cfg(unix)]
fn open_or_create_database_nofollow_v0(path: &Path) -> ValidationStoreResultV0<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_regular_file_metadata_v0(&metadata, "finalization_history.path_type")?;
            options.open(path).map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::ReplacedStore,
                    "finalization_history.path_open",
                )
            })
        }
        Err(value) if value.kind() == std::io::ErrorKind::NotFound => options
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::Storage,
                    "finalization_history.path_create",
                )
            }),
        Err(_) => Err(error(
            ValidationStoreErrorCodeV0::Storage,
            "finalization_history.path_metadata",
        )),
    }
}

#[cfg(unix)]
fn open_existing_file_nofollow_v0(
    path: &Path,
    context: &'static str,
) -> ValidationStoreResultV0<File> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| error(ValidationStoreErrorCodeV0::ReplacedStore, context))?;
    validate_regular_file_metadata_v0(&metadata, context)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .map_err(|_| error(ValidationStoreErrorCodeV0::ReplacedStore, context))
}

#[cfg(unix)]
fn validate_regular_file_metadata_v0(
    metadata: &fs::Metadata,
    context: &'static str,
) -> ValidationStoreResultV0<()> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() || metadata.nlink() != 1
    {
        return Err(error(ValidationStoreErrorCodeV0::ReplacedStore, context));
    }
    Ok(())
}

#[cfg(unix)]
fn identity_from_metadata_v0(metadata: &fs::Metadata) -> FileIdentityV0 {
    FileIdentityV0 {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(unix)]
fn file_handle_identity_v0(file: &File) -> ValidationStoreResultV0<FileIdentityV0> {
    let metadata = file.metadata().map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::Storage,
            "finalization_history.file_handle_metadata",
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(error(
            ValidationStoreErrorCodeV0::ReplacedStore,
            "finalization_history.file_handle_type",
        ));
    }
    Ok(identity_from_metadata_v0(&metadata))
}

#[cfg(unix)]
fn directory_handle_identity_v0(file: &File) -> ValidationStoreResultV0<FileIdentityV0> {
    let metadata = file.metadata().map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::Storage,
            "finalization_history.parent_handle_metadata",
        )
    })?;
    if !metadata.file_type().is_dir() {
        return Err(error(
            ValidationStoreErrorCodeV0::ReplacedStore,
            "finalization_history.parent_handle_type",
        ));
    }
    Ok(identity_from_metadata_v0(&metadata))
}

#[cfg(unix)]
fn verify_directory_identity_v0(
    path: &Path,
    file: &File,
    expected: FileIdentityV0,
) -> ValidationStoreResultV0<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::ReplacedStore,
            "finalization_history.parent_missing",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(error(
            ValidationStoreErrorCodeV0::ReplacedStore,
            "finalization_history.parent_type",
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::ReplacedStore,
            "finalization_history.parent_canonical",
        )
    })?;
    if canonical != path
        || identity_from_metadata_v0(&metadata) != expected
        || directory_handle_identity_v0(file)? != expected
    {
        return Err(error(
            ValidationStoreErrorCodeV0::ReplacedStore,
            "finalization_history.parent_identity",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_regular_file_identity_v0(
    path: &Path,
    file: &File,
    expected: FileIdentityV0,
) -> ValidationStoreResultV0<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::ReplacedStore,
            "finalization_history.path_missing",
        )
    })?;
    validate_regular_file_metadata_v0(&metadata, "finalization_history.path_type")?;
    let canonical = fs::canonicalize(path).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::ReplacedStore,
            "finalization_history.path_canonical",
        )
    })?;
    if canonical != path
        || identity_from_metadata_v0(&metadata) != expected
        || file_handle_identity_v0(file)? != expected
    {
        return Err(error(
            ValidationStoreErrorCodeV0::ReplacedStore,
            "finalization_history.path_identity",
        ));
    }
    Ok(())
}

fn sqlite_auxiliary_path_v0(database_path: &Path, suffix: &str) -> PathBuf {
    let mut value = database_path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn reject_rollback_journal_v0(database_path: &Path) -> ValidationStoreResultV0<()> {
    let rollback = sqlite_auxiliary_path_v0(database_path, "-journal");
    match fs::symlink_metadata(rollback) {
        Ok(_) => Err(error(
            ValidationStoreErrorCodeV0::ReplacedStore,
            "finalization_history.rollback_journal",
        )),
        Err(value) if value.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(error(
            ValidationStoreErrorCodeV0::Storage,
            "finalization_history.rollback_metadata",
        )),
    }
}

fn validate_auxiliary_namespace_paths_v0(database_path: &Path) -> ValidationStoreResultV0<()> {
    reject_rollback_journal_v0(database_path)?;
    #[cfg(not(unix))]
    {
        return Err(error(
            ValidationStoreErrorCodeV0::UnsupportedPlatform,
            "finalization_history.auxiliary_platform",
        ));
    }
    #[cfg(unix)]
    {
        for suffix in ["-wal", "-shm"] {
            let path = sqlite_auxiliary_path_v0(database_path, suffix);
            match fs::symlink_metadata(path) {
                Ok(metadata) => validate_regular_file_metadata_v0(
                    &metadata,
                    "finalization_history.auxiliary_type",
                )?,
                Err(value) if value.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {
                    return Err(error(
                        ValidationStoreErrorCodeV0::Storage,
                        "finalization_history.auxiliary_metadata",
                    ))
                }
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn pin_required_auxiliary_file_v0(
    database_path: &Path,
    suffix: &str,
) -> ValidationStoreResultV0<PinnedAuxiliaryFileV0> {
    let path = sqlite_auxiliary_path_v0(database_path, suffix);
    let file = open_existing_file_nofollow_v0(&path, "finalization_history.auxiliary_open")?;
    let identity = file_handle_identity_v0(&file)?;
    let pinned = PinnedAuxiliaryFileV0 {
        path,
        file,
        identity,
    };
    verify_auxiliary_file_identity_v0(&pinned, false)?;
    Ok(pinned)
}

#[cfg(unix)]
fn verify_auxiliary_file_identity_v0(
    pinned: &PinnedAuxiliaryFileV0,
    allow_absent_path: bool,
) -> ValidationStoreResultV0<()> {
    let handle_identity = file_handle_identity_v0(&pinned.file)?;
    if handle_identity != pinned.identity {
        return Err(error(
            ValidationStoreErrorCodeV0::ReplacedStore,
            "finalization_history.auxiliary_handle_identity",
        ));
    }
    let metadata = match fs::symlink_metadata(&pinned.path) {
        Ok(metadata) => metadata,
        Err(value) if allow_absent_path && value.kind() == std::io::ErrorKind::NotFound => {
            return Ok(())
        }
        Err(_) => {
            return Err(error(
                ValidationStoreErrorCodeV0::ReplacedStore,
                "finalization_history.auxiliary_missing",
            ))
        }
    };
    validate_regular_file_metadata_v0(&metadata, "finalization_history.auxiliary_type")?;
    if identity_from_metadata_v0(&metadata) != pinned.identity {
        return Err(error(
            ValidationStoreErrorCodeV0::ReplacedStore,
            "finalization_history.auxiliary_identity",
        ));
    }
    Ok(())
}

fn materialize_auxiliary_namespace_v0(connection: &Connection) -> ValidationStoreResultV0<()> {
    connection
        .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.materialize_auxiliary",
            )
        })
}

fn open_connection_v0(path: &Path) -> ValidationStoreResultV0<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::Storage,
            "finalization_history.open",
        )
    })?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.busy_timeout",
            )
        })?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF; PRAGMA synchronous = FULL; PRAGMA temp_store = MEMORY; PRAGMA wal_autocheckpoint = 0; PRAGMA recursive_triggers = OFF; PRAGMA writable_schema = OFF; PRAGMA query_only = OFF;",
        )
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.pragmas",
            )
        })?;
    let journal_mode = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.journal_mode",
            )
        })?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.journal_mode",
        ));
    }
    validate_connection_pragmas_v0(&connection)?;
    Ok(connection)
}

fn validate_connection_pragmas_v0(connection: &Connection) -> ValidationStoreResultV0<()> {
    let required = [
        ("PRAGMA foreign_keys", 1i64),
        ("PRAGMA trusted_schema", 0i64),
        ("PRAGMA synchronous", 2i64),
        ("PRAGMA temp_store", 2i64),
        ("PRAGMA wal_autocheckpoint", 0i64),
        ("PRAGMA recursive_triggers", 0i64),
        ("PRAGMA writable_schema", 0i64),
        ("PRAGMA query_only", 0i64),
    ];
    for (query, expected) in required {
        let observed = connection
            .query_row(query, [], |row| row.get::<_, i64>(0))
            .map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::Storage,
                    "finalization_history.pragma_read",
                )
            })?;
        if observed != expected {
            return Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "finalization_history.pragma_mismatch",
            ));
        }
    }
    Ok(())
}

fn close_connection_v0(connection: Connection) -> ValidationStoreResultV0<()> {
    connection.close().map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::Storage,
            "finalization_history.close",
        )
    })
}

fn initialize_or_validate_schema_v0(
    connection: &Connection,
    scope: FinalizationHistoryScopeV0,
    initial_head: &ApplicationHeadV0,
) -> ValidationStoreResultV0<()> {
    let schema_objects = read_schema_objects_v0(connection)?;
    if schema_objects.is_empty() {
        connection.execute_batch(METADATA_SCHEMA_V0).map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.create_metadata",
            )
        })?;
        connection.execute_batch(RECORD_SCHEMA_V0).map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.create_records",
            )
        })?;
        let initial_head_bytes = encode_head_v0(initial_head);
        let sequence = 0u64.to_be_bytes();
        let chain_digest = digest_v0(
            GENESIS_DIGEST_DOMAIN_V0,
            &[scope.as_bytes().as_slice(), initial_head_bytes.as_slice()],
        );
        connection
            .execute(
                "INSERT INTO finalization_history_metadata_v0 (singleton,schema_version,scope,initial_head,sequence,chain_digest) VALUES (1,?1,?2,?3,?4,?5)",
                params![
                    SCHEMA_VERSION_V0,
                    scope.as_bytes().as_slice(),
                    initial_head_bytes.as_slice(),
                    sequence.as_slice(),
                    chain_digest.as_slice(),
                ],
            )
            .map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::Storage,
                    "finalization_history.initialize",
                )
            })?;
    }
    validate_closed_world_schema_v0(connection)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SchemaObjectV0 {
    object_type: String,
    name: String,
    table_name: String,
    sql: Option<String>,
}

fn read_schema_objects_v0(connection: &Connection) -> ValidationStoreResultV0<Vec<SchemaObjectV0>> {
    let mut statement = connection
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.schema_prepare",
            )
        })?;
    let rows = statement
        .query_map([], |row| {
            Ok(SchemaObjectV0 {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row.get(3)?,
            })
        })
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.schema_query",
            )
        })?;
    let mut objects = Vec::new();
    for row in rows {
        objects.push(row.map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.schema_row",
            )
        })?);
    }
    Ok(objects)
}

fn validate_closed_world_schema_v0(connection: &Connection) -> ValidationStoreResultV0<()> {
    validate_connection_pragmas_v0(connection)?;
    let observed = read_schema_objects_v0(connection)?;
    let expected = [
        SchemaObjectV0 {
            object_type: "index".to_string(),
            name: "sqlite_autoindex_finalization_history_records_v0_1".to_string(),
            table_name: "finalization_history_records_v0".to_string(),
            sql: None,
        },
        SchemaObjectV0 {
            object_type: "index".to_string(),
            name: "sqlite_autoindex_finalization_history_records_v0_2".to_string(),
            table_name: "finalization_history_records_v0".to_string(),
            sql: None,
        },
        SchemaObjectV0 {
            object_type: "index".to_string(),
            name: "sqlite_autoindex_finalization_history_records_v0_3".to_string(),
            table_name: "finalization_history_records_v0".to_string(),
            sql: None,
        },
        SchemaObjectV0 {
            object_type: "index".to_string(),
            name: "sqlite_autoindex_finalization_history_records_v0_4".to_string(),
            table_name: "finalization_history_records_v0".to_string(),
            sql: None,
        },
        SchemaObjectV0 {
            object_type: "index".to_string(),
            name: "sqlite_autoindex_finalization_history_records_v0_5".to_string(),
            table_name: "finalization_history_records_v0".to_string(),
            sql: None,
        },
        SchemaObjectV0 {
            object_type: "table".to_string(),
            name: "finalization_history_metadata_v0".to_string(),
            table_name: "finalization_history_metadata_v0".to_string(),
            sql: Some(METADATA_SCHEMA_V0.to_string()),
        },
        SchemaObjectV0 {
            object_type: "table".to_string(),
            name: "finalization_history_records_v0".to_string(),
            table_name: "finalization_history_records_v0".to_string(),
            sql: Some(RECORD_SCHEMA_V0.to_string()),
        },
    ];
    if observed.len() != expected.len()
        || observed.iter().zip(expected.iter()).any(|(left, right)| {
            left.object_type != right.object_type
                || left.name != right.name
                || left.table_name != right.table_name
                || match (&left.sql, &right.sql) {
                    (Some(left), Some(right)) => normalize_sql_v0(left) != normalize_sql_v0(right),
                    (None, None) => false,
                    _ => true,
                }
        })
    {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.closed_world_schema",
        ));
    }
    Ok(())
}

fn normalize_sql_v0(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn audit_connection_v0(
    connection: &Connection,
    scope: FinalizationHistoryScopeV0,
    initial_head: &ApplicationHeadV0,
) -> ValidationStoreResultV0<ConfirmedFinalizationHistoryAuditV0> {
    let integrity = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.integrity_check",
            )
        })?;
    if integrity != "ok" {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.integrity_check",
        ));
    }

    let metadata = connection
        .query_row(
            "SELECT schema_version,scope,initial_head,sequence,chain_digest FROM finalization_history_metadata_v0 WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "finalization_history.metadata",
            )
        })?;
    if metadata.0 != SCHEMA_VERSION_V0
        || metadata.1.as_slice() != scope.as_bytes()
        || metadata.2 != encode_head_v0(initial_head)
    {
        return Err(error(
            ValidationStoreErrorCodeV0::ForeignToken,
            "finalization_history.metadata_binding",
        ));
    }
    let metadata_sequence =
        decode_u64_blob_v0(&metadata.3, "finalization_history.metadata_sequence")?;
    let metadata_chain = decode_array_v0::<32>(&metadata.4, "finalization_history.metadata_chain")?;
    if metadata_sequence > MAX_FINALIZATION_HISTORY_ENTRIES_V0 {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.metadata_sequence",
        ));
    }

    let count = connection
        .query_row(
            "SELECT COUNT(*) FROM finalization_history_records_v0",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.count",
            )
        })?;
    let count = u64::try_from(count).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.count",
        )
    })?;
    if count > MAX_FINALIZATION_HISTORY_ENTRIES_V0 {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.count",
        ));
    }

    let mut statement = connection
        .prepare(
            "SELECT sequence,target_block_id,proof_id,record,record_digest,previous_chain_digest,chain_digest FROM finalization_history_records_v0 ORDER BY sequence",
        )
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.records_prepare",
            )
        })?;
    let mapped = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
            ))
        })
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.records_query",
            )
        })?;

    let initial_head_bytes = encode_head_v0(initial_head);
    let mut previous_chain = digest_v0(
        GENESIS_DIGEST_DOMAIN_V0,
        &[scope.as_bytes().as_slice(), initial_head_bytes.as_slice()],
    );
    let mut committed_head = initial_head.clone();
    let mut observed = 0u64;
    for item in mapped {
        let raw = item.map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "finalization_history.record_row",
            )
        })?;
        let row = StoredFinalizationRowV0 {
            sequence: decode_u64_blob_v0(&raw.0, "finalization_history.row_sequence")?,
            target_block_id: decode_array_v0::<32>(&raw.1, "finalization_history.row_target")?,
            proof_id: decode_array_v0::<32>(&raw.2, "finalization_history.row_proof")?,
            record: raw.3,
            record_digest: decode_array_v0::<32>(&raw.4, "finalization_history.row_digest")?,
            previous_chain_digest: decode_array_v0::<32>(
                &raw.5,
                "finalization_history.row_previous_chain",
            )?,
            chain_digest: decode_array_v0::<32>(&raw.6, "finalization_history.row_chain")?,
        };
        observed = observed.checked_add(1).ok_or_else(|| {
            error(
                ValidationStoreErrorCodeV0::Overflow,
                "finalization_history.audit_sequence",
            )
        })?;
        if row.sequence != observed || row.previous_chain_digest != previous_chain {
            return Err(error(
                ValidationStoreErrorCodeV0::RollbackDetected,
                "finalization_history.chain_order",
            ));
        }
        let readback = decode_readback_v0(&row.record)?;
        if readback.durable_sequence() != row.sequence
            || readback.intent().parent() != &committed_head
            || readback.intent().target().block_id().as_bytes() != &row.target_block_id
            || readback.intent().proof_id().as_bytes() != &row.proof_id
        {
            return Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "finalization_history.record_binding",
            ));
        }
        let expected_record_digest = digest_v0(
            RECORD_DIGEST_DOMAIN_V0,
            &[scope.as_bytes().as_slice(), row.record.as_slice()],
        );
        let sequence_bytes = row.sequence.to_be_bytes();
        let expected_chain = digest_v0(
            CHAIN_DIGEST_DOMAIN_V0,
            &[
                scope.as_bytes().as_slice(),
                previous_chain.as_slice(),
                expected_record_digest.as_slice(),
                sequence_bytes.as_slice(),
            ],
        );
        if row.record_digest != expected_record_digest || row.chain_digest != expected_chain {
            return Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "finalization_history.record_digest",
            ));
        }
        committed_head = readback.committed_head().clone();
        previous_chain = row.chain_digest;
    }
    if observed != count || metadata_sequence != observed || metadata_chain != previous_chain {
        return Err(error(
            ValidationStoreErrorCodeV0::RollbackDetected,
            "finalization_history.metadata_head",
        ));
    }
    Ok(ConfirmedFinalizationHistoryAuditV0 {
        entry_count: observed,
        committed_head,
        chain_digest: Hash32V0::new(previous_chain),
    })
}

fn load_row_by_sequence_v0(
    connection: &Connection,
    sequence: u64,
) -> ValidationStoreResultV0<Option<StoredFinalizationRowV0>> {
    let sequence_bytes = sequence.to_be_bytes();
    let raw = connection
        .query_row(
            "SELECT target_block_id,proof_id,record,record_digest,previous_chain_digest,chain_digest FROM finalization_history_records_v0 WHERE sequence = ?1",
            params![sequence_bytes.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::Storage,
                "finalization_history.record_read",
            )
        })?;
    raw.map(|value| {
        Ok(StoredFinalizationRowV0 {
            sequence,
            target_block_id: decode_array_v0::<32>(&value.0, "finalization_history.read_target")?,
            proof_id: decode_array_v0::<32>(&value.1, "finalization_history.read_proof")?,
            record: value.2,
            record_digest: decode_array_v0::<32>(&value.3, "finalization_history.read_digest")?,
            previous_chain_digest: decode_array_v0::<32>(
                &value.4,
                "finalization_history.read_previous_chain",
            )?,
            chain_digest: decode_array_v0::<32>(&value.5, "finalization_history.read_chain")?,
        })
    })
    .transpose()
}

fn confirm_row_v0(
    scope: FinalizationHistoryScopeV0,
    row: &StoredFinalizationRowV0,
) -> ValidationStoreResultV0<ConfirmedFinalizationHistoryRecordV0> {
    let readback = decode_readback_v0(&row.record)?;
    let expected_record_digest = digest_v0(
        RECORD_DIGEST_DOMAIN_V0,
        &[scope.as_bytes().as_slice(), row.record.as_slice()],
    );
    if expected_record_digest != row.record_digest
        || readback.durable_sequence() != row.sequence
        || readback.intent().target().block_id().as_bytes() != &row.target_block_id
        || readback.intent().proof_id().as_bytes() != &row.proof_id
    {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.confirm",
        ));
    }
    Ok(ConfirmedFinalizationHistoryRecordV0 {
        readback,
        record_digest: Hash32V0::new(row.record_digest),
        previous_chain_digest: Hash32V0::new(row.previous_chain_digest),
        chain_digest: Hash32V0::new(row.chain_digest),
    })
}

fn encode_readback_v0(readback: &NativeFinalizationApplyReadbackV0) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(RECORD_BYTES_V0);
    encoded.extend_from_slice(&RECORD_VERSION_V0.to_be_bytes());
    encode_head_into_v0(&mut encoded, readback.intent().parent());
    encode_head_into_v0(&mut encoded, readback.intent().target());
    encoded.extend_from_slice(readback.intent().proof_id().as_bytes());
    encoded.extend_from_slice(readback.intent().overlay_checksum().as_bytes());
    encoded.extend_from_slice(readback.intent().body_digest().as_bytes());
    encoded.extend_from_slice(readback.intent().jmt_plan_digest().as_bytes());
    encode_head_into_v0(&mut encoded, readback.committed_head());
    encoded.extend_from_slice(readback.jmt_root().as_bytes());
    encoded.extend_from_slice(readback.application_receipt_digest().as_bytes());
    encoded.extend_from_slice(&readback.durable_sequence().to_be_bytes());
    debug_assert_eq!(encoded.len(), RECORD_BYTES_V0);
    encoded
}

fn decode_readback_v0(raw: &[u8]) -> ValidationStoreResultV0<NativeFinalizationApplyReadbackV0> {
    if raw.len() != RECORD_BYTES_V0 {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.record_length",
        ));
    }
    let mut offset = 0usize;
    let version = u16::from_be_bytes(take_v0::<2>(raw, &mut offset)?);
    if version != RECORD_VERSION_V0 {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.record_version",
        ));
    }
    let parent = decode_head_v0(raw, &mut offset)?;
    let target = decode_head_v0(raw, &mut offset)?;
    let proof_id = Hash32V0::new(take_v0::<32>(raw, &mut offset)?);
    let overlay_checksum = Hash32V0::new(take_v0::<32>(raw, &mut offset)?);
    let body_digest = Hash32V0::new(take_v0::<32>(raw, &mut offset)?);
    let jmt_plan_digest = Hash32V0::new(take_v0::<32>(raw, &mut offset)?);
    let committed_head = decode_head_v0(raw, &mut offset)?;
    let jmt_root = StateRootV0::new(take_v0::<32>(raw, &mut offset)?).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.jmt_root",
        )
    })?;
    let receipt_digest = Hash32V0::new(take_v0::<32>(raw, &mut offset)?);
    let durable_sequence = u64::from_be_bytes(take_v0::<8>(raw, &mut offset)?);
    if offset != raw.len() {
        return Err(error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.record_trailing",
        ));
    }
    let intent = NativeFinalizationIntentV0::new(
        parent,
        target,
        proof_id,
        overlay_checksum,
        body_digest,
        jmt_plan_digest,
    )
    .map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.intent_decode",
        )
    })?;
    NativeFinalizationApplyReadbackV0::new(
        intent,
        committed_head,
        jmt_root,
        receipt_digest,
        durable_sequence,
    )
    .map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.readback_decode",
        )
    })
}

fn encode_head_v0(head: &ApplicationHeadV0) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(HEAD_BYTES_V0);
    encode_head_into_v0(&mut encoded, head);
    encoded
}

fn encode_head_into_v0(encoded: &mut Vec<u8>, head: &ApplicationHeadV0) {
    encoded.extend_from_slice(&head.height().get().to_be_bytes());
    encoded.extend_from_slice(head.block_id().as_bytes());
    encoded.extend_from_slice(head.state_root().as_bytes());
    encoded.extend_from_slice(head.commit_id().as_bytes());
}

fn decode_head_v0(raw: &[u8], offset: &mut usize) -> ValidationStoreResultV0<ApplicationHeadV0> {
    let height = HeightV0::new(u64::from_be_bytes(take_v0::<8>(raw, offset)?));
    let block_id = BlockIdV0::new(take_v0::<32>(raw, offset)?).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.block_id",
        )
    })?;
    let state_root = StateRootV0::new(take_v0::<32>(raw, offset)?).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.state_root",
        )
    })?;
    let commit_id = ApplicationCommitIdV0::new(take_v0::<32>(raw, offset)?).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.commit_id",
        )
    })?;
    Ok(ApplicationHeadV0::new(
        height, block_id, state_root, commit_id,
    ))
}

fn take_v0<const N: usize>(raw: &[u8], offset: &mut usize) -> ValidationStoreResultV0<[u8; N]> {
    let end = offset.checked_add(N).ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::Overflow,
            "finalization_history.decode_offset",
        )
    })?;
    let value = raw.get(*offset..end).ok_or_else(|| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.decode_truncated",
        )
    })?;
    *offset = end;
    <[u8; N]>::try_from(value).map_err(|_| {
        error(
            ValidationStoreErrorCodeV0::CorruptStore,
            "finalization_history.decode_width",
        )
    })
}

fn decode_array_v0<const N: usize>(
    raw: &[u8],
    context: &'static str,
) -> ValidationStoreResultV0<[u8; N]> {
    <[u8; N]>::try_from(raw).map_err(|_| error(ValidationStoreErrorCodeV0::CorruptStore, context))
}

fn decode_u64_blob_v0(raw: &[u8], context: &'static str) -> ValidationStoreResultV0<u64> {
    Ok(u64::from_be_bytes(decode_array_v0::<8>(raw, context)?))
}

fn digest_v0(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_PATH_V0: AtomicU64 = AtomicU64::new(1);

    struct TestPathV0 {
        root: PathBuf,
        database: PathBuf,
    }

    impl TestPathV0 {
        fn new() -> Self {
            let nonce = NEXT_PATH_V0.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "trnm-finalization-history-{}-{}",
                std::process::id(),
                nonce
            ));
            fs::create_dir_all(&root).unwrap();
            let database = root.join("history.sqlite");
            Self { root, database }
        }
    }

    impl Drop for TestPathV0 {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn hash(seed: u8) -> Hash32V0 {
        Hash32V0::new([seed; 32])
    }

    fn head(height: u64, seed: u8) -> ApplicationHeadV0 {
        ApplicationHeadV0::new(
            HeightV0::new(height),
            BlockIdV0::new([seed; 32]).unwrap(),
            StateRootV0::new([seed.wrapping_add(1); 32]).unwrap(),
            ApplicationCommitIdV0::new([seed.wrapping_add(2); 32]).unwrap(),
        )
    }

    fn intent(
        parent: ApplicationHeadV0,
        target: ApplicationHeadV0,
        seed: u8,
    ) -> NativeFinalizationIntentV0 {
        NativeFinalizationIntentV0::new(
            parent,
            target,
            hash(seed),
            hash(seed.wrapping_add(1)),
            hash(seed.wrapping_add(2)),
            hash(seed.wrapping_add(3)),
        )
        .unwrap()
    }

    fn readback(
        intent: NativeFinalizationIntentV0,
        sequence: u64,
        seed: u8,
    ) -> NativeFinalizationApplyReadbackV0 {
        NativeFinalizationApplyReadbackV0::new(
            intent.clone(),
            intent.target().clone(),
            intent.target().state_root(),
            hash(seed),
            sequence,
        )
        .unwrap()
    }

    fn scope(seed: u8) -> FinalizationHistoryScopeV0 {
        FinalizationHistoryScopeV0::new([seed; 32]).unwrap()
    }

    #[test]
    fn append_reopen_exact_replay_and_chain_audit() {
        let path = TestPathV0::new();
        let h0 = head(0, 11);
        let h1 = head(1, 21);
        let h2 = head(2, 31);
        let first = readback(intent(h0.clone(), h1.clone(), 41), 1, 51);
        let second = readback(intent(h1.clone(), h2.clone(), 61), 2, 71);
        let store =
            SqliteNativeFinalizationHistoryV0::open(&path.database, scope(1), h0.clone()).unwrap();
        let first_confirmed = match store.append(first.clone()).unwrap() {
            FinalizationHistoryAppendOutcomeV0::NewlyAppended(value) => value,
            FinalizationHistoryAppendOutcomeV0::ExactReplay(_) => panic!("first append replayed"),
        };
        assert_eq!(first_confirmed.readback(), &first);
        drop(store);

        let reopened =
            SqliteNativeFinalizationHistoryV0::open(&path.database, scope(1), h0).unwrap();
        assert!(matches!(
            reopened.append(first.clone()).unwrap(),
            FinalizationHistoryAppendOutcomeV0::ExactReplay(_)
        ));
        assert!(matches!(
            reopened.append(second.clone()).unwrap(),
            FinalizationHistoryAppendOutcomeV0::NewlyAppended(_)
        ));
        let audit = reopened.audit().unwrap();
        assert_eq!(audit.entry_count(), 2);
        assert_eq!(audit.committed_head(), &h2);
        assert!(!audit.chain_digest().is_zero());
        assert_eq!(
            reopened.read_sequence(1).unwrap().unwrap().readback(),
            &first
        );
        assert_eq!(
            reopened.read_sequence(2).unwrap().unwrap().readback(),
            &second
        );
        assert!(reopened.read_sequence(3).unwrap().is_none());
    }

    #[test]
    fn rejects_gap_conflict_and_parent_drift_without_mutation() {
        let path = TestPathV0::new();
        let h0 = head(0, 81);
        let h1 = head(1, 91);
        let h2 = head(2, 101);
        let store =
            SqliteNativeFinalizationHistoryV0::open(&path.database, scope(2), h0.clone()).unwrap();
        let first_intent = intent(h0.clone(), h1.clone(), 111);
        store
            .append(readback(first_intent.clone(), 1, 121))
            .unwrap();

        let gap = readback(intent(h1.clone(), h2.clone(), 131), 3, 141);
        assert_eq!(
            store.append(gap).unwrap_err().code(),
            ValidationStoreErrorCodeV0::InvalidTransition
        );
        let conflicting_replay = readback(first_intent, 1, 151);
        assert_eq!(
            store.append(conflicting_replay).unwrap_err().code(),
            ValidationStoreErrorCodeV0::BindingMismatch
        );
        let foreign_parent = readback(intent(head(1, 161), h2, 171), 2, 181);
        assert_eq!(
            store.append(foreign_parent).unwrap_err().code(),
            ValidationStoreErrorCodeV0::BindingMismatch
        );
        let audit = store.audit().unwrap();
        assert_eq!(audit.entry_count(), 1);
        assert_eq!(audit.committed_head(), &h1);
    }

    #[test]
    fn tampered_record_and_metadata_fail_closed_after_reopen() {
        let path = TestPathV0::new();
        let h0 = head(0, 191);
        let h1 = head(1, 201);
        let store =
            SqliteNativeFinalizationHistoryV0::open(&path.database, scope(3), h0.clone()).unwrap();
        store
            .append(readback(intent(h0.clone(), h1, 211), 1, 221))
            .unwrap();
        let connection = Connection::open(&path.database).unwrap();
        connection
            .execute(
                "UPDATE finalization_history_records_v0 SET record = zeroblob(514) WHERE sequence = ?1",
                params![1u64.to_be_bytes().as_slice()],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            store.audit().unwrap_err().code(),
            ValidationStoreErrorCodeV0::CorruptStore
        );

        let other = TestPathV0::new();
        let store =
            SqliteNativeFinalizationHistoryV0::open(&other.database, scope(4), h0.clone()).unwrap();
        store
            .append(readback(intent(h0, head(1, 231), 232), 1, 233))
            .unwrap();
        let connection = Connection::open(&other.database).unwrap();
        connection
            .execute(
                "UPDATE finalization_history_metadata_v0 SET sequence = ?1 WHERE singleton = 1",
                params![0u64.to_be_bytes().as_slice()],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            store.audit().unwrap_err().code(),
            ValidationStoreErrorCodeV0::RollbackDetected
        );
    }

    #[test]
    fn scope_and_initial_head_are_persistent_store_identity() {
        let path = TestPathV0::new();
        let h0 = head(0, 9);
        SqliteNativeFinalizationHistoryV0::open(&path.database, scope(5), h0.clone()).unwrap();
        assert_eq!(
            SqliteNativeFinalizationHistoryV0::open(&path.database, scope(6), h0.clone())
                .unwrap_err()
                .code(),
            ValidationStoreErrorCodeV0::ForeignToken
        );
        assert_eq!(
            SqliteNativeFinalizationHistoryV0::open(&path.database, scope(5), head(0, 10))
                .unwrap_err()
                .code(),
            ValidationStoreErrorCodeV0::ForeignToken
        );
    }

    #[test]
    fn path_must_be_absolute_and_must_not_be_a_symlink() {
        let h0 = head(0, 19);
        assert_eq!(
            SqliteNativeFinalizationHistoryV0::open("relative.sqlite", scope(7), h0.clone())
                .unwrap_err()
                .code(),
            ValidationStoreErrorCodeV0::InvalidBinding
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let path = TestPathV0::new();
            let target = path.root.join("target.sqlite");
            SqliteNativeFinalizationHistoryV0::open(&target, scope(7), h0.clone()).unwrap();
            let link = path.root.join("link.sqlite");
            symlink(&target, &link).unwrap();
            assert_eq!(
                SqliteNativeFinalizationHistoryV0::open(&link, scope(7), h0)
                    .unwrap_err()
                    .code(),
                ValidationStoreErrorCodeV0::ReplacedStore
            );
        }
    }

    fn assert_closed_world_mutation_rejected(sql: &str, seed: u8) {
        let path = TestPathV0::new();
        let h0 = head(0, seed);
        let h1 = head(1, seed.wrapping_add(1));
        let first = readback(
            intent(h0.clone(), h1, seed.wrapping_add(2)),
            1,
            seed.wrapping_add(3),
        );
        let store = SqliteNativeFinalizationHistoryV0::open(
            &path.database,
            scope(seed.wrapping_add(4)),
            h0,
        )
        .unwrap();
        store.append(first.clone()).unwrap();
        let connection = Connection::open(&path.database).unwrap();
        connection.execute_batch(sql).unwrap();
        drop(connection);

        assert_eq!(
            store.audit().unwrap_err().code(),
            ValidationStoreErrorCodeV0::CorruptStore
        );
        assert_eq!(
            store.read_sequence(1).unwrap_err().code(),
            ValidationStoreErrorCodeV0::CorruptStore
        );
        assert_eq!(
            store.append(first).unwrap_err().code(),
            ValidationStoreErrorCodeV0::CorruptStore
        );
    }

    #[test]
    fn closed_world_schema_rejects_extra_table_index_view_and_trigger() {
        assert_closed_world_mutation_rejected("CREATE TABLE injected_table_v0 (id INTEGER)", 31);
        assert_closed_world_mutation_rejected(
            "CREATE INDEX injected_index_v0 ON finalization_history_records_v0(record)",
            41,
        );
        assert_closed_world_mutation_rejected(
            "CREATE VIEW injected_view_v0 AS SELECT sequence FROM finalization_history_records_v0",
            51,
        );
        assert_closed_world_mutation_rejected(
            "CREATE TRIGGER injected_trigger_v0 AFTER INSERT ON finalization_history_records_v0 BEGIN UPDATE finalization_history_metadata_v0 SET sequence = sequence WHERE singleton = 1; END",
            61,
        );
    }

    #[cfg(unix)]
    #[test]
    fn post_open_same_scope_database_substitution_rejects_positive_paths() {
        let original = TestPathV0::new();
        let replacement = TestPathV0::new();
        let h0 = head(0, 71);
        let h1 = head(1, 81);
        let first = readback(intent(h0.clone(), h1, 91), 1, 101);
        let history_scope = scope(11);
        let store =
            SqliteNativeFinalizationHistoryV0::open(&original.database, history_scope, h0.clone())
                .unwrap();
        store.append(first.clone()).unwrap();
        assert!(store.read_sequence(1).unwrap().is_some());

        let replacement_store =
            SqliteNativeFinalizationHistoryV0::open(&replacement.database, history_scope, h0)
                .unwrap();
        replacement_store.append(first.clone()).unwrap();
        drop(replacement_store);

        let displaced = original.root.join("displaced.sqlite");
        fs::rename(&original.database, &displaced).unwrap();
        fs::rename(&replacement.database, &original.database).unwrap();

        assert_eq!(
            store.audit().unwrap_err().code(),
            ValidationStoreErrorCodeV0::ReplacedStore
        );
        assert_eq!(
            store.read_sequence(1).unwrap_err().code(),
            ValidationStoreErrorCodeV0::ReplacedStore
        );
        assert_eq!(
            store.append(first).unwrap_err().code(),
            ValidationStoreErrorCodeV0::ReplacedStore
        );
    }

    #[cfg(unix)]
    #[test]
    fn hardlink_and_sidecar_aliases_fail_closed() {
        use std::os::unix::fs::symlink;

        let hardlink_path = TestPathV0::new();
        let h0 = head(0, 111);
        let store =
            SqliteNativeFinalizationHistoryV0::open(&hardlink_path.database, scope(12), h0.clone())
                .unwrap();
        fs::hard_link(
            &hardlink_path.database,
            hardlink_path.root.join("database-hardlink.sqlite"),
        )
        .unwrap();
        assert_eq!(
            store.audit().unwrap_err().code(),
            ValidationStoreErrorCodeV0::ReplacedStore
        );

        let sidecar_path = TestPathV0::new();
        let store =
            SqliteNativeFinalizationHistoryV0::open(&sidecar_path.database, scope(13), h0).unwrap();
        let wal = sqlite_auxiliary_path_v0(&sidecar_path.database, "-wal");
        let _ = fs::remove_file(&wal);
        let target = sidecar_path.root.join("sidecar-target");
        fs::write(&target, b"not-a-wal").unwrap();
        symlink(&target, &wal).unwrap();
        assert_eq!(
            store.audit().unwrap_err().code(),
            ValidationStoreErrorCodeV0::ReplacedStore
        );
    }

    #[cfg(unix)]
    #[test]
    fn parent_directory_replacement_is_detected_before_trusted_read() {
        let path = TestPathV0::new();
        let h0 = head(0, 121);
        let h1 = head(1, 131);
        let first = readback(intent(h0.clone(), h1, 141), 1, 151);
        let store = SqliteNativeFinalizationHistoryV0::open(&path.database, scope(14), h0).unwrap();
        store.append(first).unwrap();

        let displaced_root = path.root.with_extension("displaced");
        let _ = fs::remove_dir_all(&displaced_root);
        fs::rename(&path.root, &displaced_root).unwrap();
        fs::create_dir_all(&path.root).unwrap();
        fs::copy(displaced_root.join("history.sqlite"), &path.database).unwrap();
        assert_eq!(
            store.read_sequence(1).unwrap_err().code(),
            ValidationStoreErrorCodeV0::ReplacedStore
        );
        let _ = fs::remove_dir_all(displaced_root);
    }
}
