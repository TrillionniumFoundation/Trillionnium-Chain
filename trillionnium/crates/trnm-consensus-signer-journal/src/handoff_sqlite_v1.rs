use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    time::Duration,
};

use fs2::FileExt;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_canonical_handoff_sign_intent_v1_exact, decode_canonical_sign_intent_v0_exact,
    decode_consensus_parameters_v0_exact, decode_handoff_descriptor_v0_exact,
    decode_validator_set_v0_exact, CanonicalHandoffSignIntentV1, CanonicalSignIntentV0,
    HandoffSignerRoleV1, MessageKind, SignatureBytes, SignatureVerifier,
};

use crate::{
    handoff_schema_v1::{
        validate_canonical_schema_v1, JOURNAL_SCHEMA_SQL_V1, JOURNAL_SCHEMA_VERSION_V1,
        MAXIMUM_SQL_INTENT_BYTES_V1,
    },
    hash::hash_domain,
    schema::validate_canonical_schema,
    ExternalMonotonicWatermarkV0, HandoffSignatureProducerV1, HandoffSignatureRequestV1,
    HandoffSignerJournalConflictV1, HandoffSignerJournalErrorV1, HandoffSignerJournalProfileV1,
    SignatureProducerV0, SignatureRequestV0, SignerWatermarkV0, StrictOldSetHandoffAdmissionV1,
};

const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const METADATA_DOMAIN_V1: &str = "trnm.consensus-signer-journal.handoff-metadata.v1";
const INITIAL_HEAD_DOMAIN_V1: &str = "trnm.consensus-signer-journal.handoff-initial-head.v1";
const INTENT_DOMAIN_V1: &str = "trnm.consensus-signer-journal.unified-intent.v1";
const EVENT_DOMAIN_V1: &str = "trnm.consensus-signer-journal.unified-event.v1";
const CHAIN_DOMAIN_V1: &str = "trnm.consensus-signer-journal.unified-chain.v1";
const HEAD_DOMAIN_V1: &str = "trnm.consensus-signer-journal.unified-head.v1";
const FENCE_DOMAIN_V1: &str = "trnm.consensus-signer-journal.terminal-fence.v1";
const UNSUPPORTED_SEMANTIC_WATERMARK_V1: &str =
    "schema1 handoff journal requires an opaque external watermark; semantic lifecycle is unsupported";

const CLASS_CONSENSUS: u8 = 0;
const CLASS_HANDOFF: u8 = 1;
const EVENT_PREPARED: u8 = 0;
const EVENT_SIGNED: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JournalHeadV1 {
    sequence: u64,
    chain_checksum: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentityV1 {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PreparedFieldsV1 {
    Consensus {
        epoch: u64,
        view: u64,
        kind: u8,
        safety_revision: u64,
    },
    Handoff {
        genesis_hash: [u8; 32],
        old_epoch: u64,
        new_epoch: u64,
        role: u8,
        validator_id: Vec<u8>,
        descriptor_digest: [u8; 32],
        descriptor_cev0: Vec<u8>,
        admission_digest: [u8; 32],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedIntentV1 {
    fingerprint: [u8; 32],
    class: u8,
    signing_root: [u8; 32],
    canonical_intent: Vec<u8>,
    intent_checksum: [u8; 32],
    fields: PreparedFieldsV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredEventV1 {
    sequence: u64,
    kind: u8,
    fingerprint: [u8; 32],
    signature: Option<[u8; 64]>,
    predecessor_sequence: u64,
    predecessor_chain_checksum: [u8; 32],
    event_checksum: [u8; 32],
    chain_checksum: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AccountingV1 {
    intent_count: u64,
    event_count: u64,
    intent_bytes: u64,
    maximum_safety_revision: Option<u64>,
    maximum_vote_view: Option<u64>,
    maximum_timeout_view: Option<u64>,
}

/// Exact schema family observed without mutating the SQLite namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerJournalSchemaKindV1 {
    /// Frozen schema0 can be identified/audited only; it is never upgraded or
    /// reinterpreted as a handoff-capable database.
    LegacyV0ReadOnly,
    /// Exact create-new schema1.
    HandoffCapableV1,
}

/// Read-only exact schema classifier. It performs no migration or PRAGMA that
/// writes the database/WAL namespace.
pub fn inspect_signer_journal_schema_read_only_v1(
    database_path: impl AsRef<Path>,
) -> Result<SignerJournalSchemaKindV1, HandoffSignerJournalErrorV1> {
    ensure_supported_platform_v1()?;
    let database_path = database_path.as_ref();
    if !database_path.exists() {
        return Err(HandoffSignerJournalErrorV1::Missing);
    }
    let database_file = open_existing_read_only_private_file_v1(
        database_path,
        "pin read-only schema classifier database",
    )?;
    let database_identity = file_handle_identity_v1(&database_file)?;
    FileExt::try_lock_shared(&database_file).map_err(map_classifier_lock_error_v1)?;
    require_path_identity(database_path, database_identity)?;
    let immutable_uri = format!(
        "file:/proc/self/fd/{}?mode=ro&immutable=1",
        database_file.as_raw_fd()
    );
    let connection = Connection::open_with_flags(
        Path::new(&immutable_uri),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|error| {
        HandoffSignerJournalErrorV1::sqlite("open read-only schema classifier", error)
    })?;
    connection
        .execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;")
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("configure read-only schema classifier", error)
        })?;
    let legacy: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='signer_journal_metadata_v0'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("identify schema0", error))?;
    let current: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='handoff_signer_metadata_v1'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("identify schema1", error))?;
    match (legacy, current) {
        (1, 0) => {
            let auxiliary_pins = pin_checkpointed_legacy_namespace_v1(database_path)?;
            require_persisted_sqlite_journal_mode_v1(&database_file, 2, "schema0 WAL mode")?;
            validate_canonical_schema(&connection)
                .map_err(|_| HandoffSignerJournalErrorV1::SchemaMismatch)?;
            auxiliary_pins.require_unchanged()?;
            require_path_identity(database_path, database_identity)?;
            Ok(SignerJournalSchemaKindV1::LegacyV0ReadOnly)
        }
        (0, 1) => {
            require_schema1_auxiliary_namespace_absent_v1(database_path)?;
            require_persisted_sqlite_journal_mode_v1(&database_file, 1, "schema1 DELETE mode")?;
            validate_canonical_schema_v1(&connection)?;
            require_schema1_auxiliary_namespace_absent_v1(database_path)?;
            require_path_identity(database_path, database_identity)?;
            Ok(SignerJournalSchemaKindV1::HandoffCapableV1)
        }
        _ => Err(HandoffSignerJournalErrorV1::SchemaMismatch),
    }
}

struct LegacyNamespacePinsV1 {
    rollback_path: PathBuf,
    lock_path: PathBuf,
    _lock_file: File,
    lock_identity: FileIdentityV1,
    wal_path: PathBuf,
    wal_file: File,
    wal_identity: FileIdentityV1,
    shm_path: PathBuf,
    _shm_file: File,
    shm_identity: FileIdentityV1,
}

impl LegacyNamespacePinsV1 {
    fn require_unchanged(&self) -> Result<(), HandoffSignerJournalErrorV1> {
        match fs::symlink_metadata(&self.rollback_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(
                    HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                        "rollback journal exists beside schema0 WAL database",
                    ),
                );
            }
            Err(error) => {
                return Err(HandoffSignerJournalErrorV1::io(
                    "reinspect schema0 rollback journal",
                    error,
                ));
            }
        }
        require_path_identity(&self.lock_path, self.lock_identity)?;
        require_path_identity(&self.wal_path, self.wal_identity)?;
        require_path_identity(&self.shm_path, self.shm_identity)?;
        if self
            .wal_file
            .metadata()
            .map_err(|error| {
                HandoffSignerJournalErrorV1::io("restat checkpointed schema0 WAL", error)
            })?
            .len()
            != 0
        {
            return Err(
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                    "schema0 WAL contains live or unclassified frames",
                ),
            );
        }
        Ok(())
    }
}

fn pin_checkpointed_legacy_namespace_v1(
    database_path: &Path,
) -> Result<LegacyNamespacePinsV1, HandoffSignerJournalErrorV1> {
    let rollback_path = sqlite_auxiliary_path_v1(database_path, "-journal");
    match fs::symlink_metadata(&rollback_path) {
        Ok(_) => {
            return Err(
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                    "rollback journal exists beside schema0 WAL database",
                ),
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(HandoffSignerJournalErrorV1::io(
                "inspect schema0 rollback journal",
                error,
            ));
        }
    }
    let lock_path = legacy_lock_path_v1(database_path)?;
    let wal_path = sqlite_auxiliary_path_v1(database_path, "-wal");
    let shm_path = sqlite_auxiliary_path_v1(database_path, "-shm");
    let lock_file =
        open_existing_read_only_private_file_v1(&lock_path, "pin schema0 lock sidecar")?;
    let wal_file = open_existing_read_only_private_file_v1(&wal_path, "pin schema0 WAL")?;
    let shm_file = open_existing_read_only_private_file_v1(&shm_path, "pin schema0 SHM")?;
    FileExt::try_lock_shared(&lock_file).map_err(map_classifier_lock_error_v1)?;
    FileExt::try_lock_shared(&wal_file).map_err(map_classifier_lock_error_v1)?;
    FileExt::try_lock_shared(&shm_file).map_err(map_classifier_lock_error_v1)?;
    let pins = LegacyNamespacePinsV1 {
        rollback_path,
        lock_identity: file_handle_identity_v1(&lock_file)?,
        wal_identity: file_handle_identity_v1(&wal_file)?,
        shm_identity: file_handle_identity_v1(&shm_file)?,
        lock_path,
        _lock_file: lock_file,
        wal_path,
        wal_file,
        shm_path,
        _shm_file: shm_file,
    };
    pins.require_unchanged()?;
    Ok(pins)
}

fn require_schema1_auxiliary_namespace_absent_v1(
    database_path: &Path,
) -> Result<(), HandoffSignerJournalErrorV1> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let path = sqlite_auxiliary_path_v1(database_path, suffix);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(
                    HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                        "schema1 DELETE-mode database has a SQLite sidecar",
                    ),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(HandoffSignerJournalErrorV1::io(
                    "inspect schema1 SQLite sidecar",
                    error,
                ));
            }
        }
    }
    Ok(())
}

fn require_persisted_sqlite_journal_mode_v1(
    database_file: &File,
    expected_format: u8,
    description: &'static str,
) -> Result<(), HandoffSignerJournalErrorV1> {
    let mut header = [0u8; 20];
    std::os::unix::fs::FileExt::read_exact_at(database_file, &mut header, 0).map_err(|error| {
        HandoffSignerJournalErrorV1::io("read pinned SQLite database header", error)
    })?;
    if &header[..16] != b"SQLite format 3\0"
        || header[18] != expected_format
        || header[19] != expected_format
    {
        return Err(HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(description));
    }
    Ok(())
}

fn legacy_lock_path_v1(database_path: &Path) -> Result<PathBuf, HandoffSignerJournalErrorV1> {
    let file_name = database_path.file_name().ok_or(
        HandoffSignerJournalErrorV1::PersistedRepresentationMalformed("schema0 database file name"),
    )?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".signer.lock");
    Ok(database_path.with_file_name(lock_name))
}

fn sqlite_auxiliary_path_v1(database_path: &Path, suffix: &str) -> PathBuf {
    let mut name = database_path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn map_classifier_lock_error_v1(error: std::io::Error) -> HandoffSignerJournalErrorV1 {
    if matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::PermissionDenied
    ) {
        HandoffSignerJournalErrorV1::Locked
    } else {
        HandoffSignerJournalErrorV1::io("acquire read-only schema classifier lock", error)
    }
}

/// Independent create-new schema1 journal.
///
/// One event chain owns old-epoch Vote/Timeout and admitted handoff intents.
/// Runtime remains on schema0; constructing this primitive activates nothing.
/// It performs no SafetyRules evaluation and grants no safe-vote authority:
/// canonical revision/shape are only persistence, conflict-key, accounting,
/// and watermark inputs. A future runtime must consume an unforgeable,
/// durably persisted SafetyRules admission in the same trust domain first.
/// A new-set normal-signing API deliberately does not exist. Handoff signing
/// additionally requires a non-Clone strict pre-certificate admission, so a
/// bare canonical handoff intent cannot persist, advance a watermark, or
/// reach a producer.
pub struct SqliteHandoffSignerJournalV1<W: ExternalMonotonicWatermarkV0> {
    connection: Connection,
    database_file: File,
    directory_file: File,
    database_path: PathBuf,
    database_identity: FileIdentityV1,
    directory_identity: FileIdentityV1,
    profile: HandoffSignerJournalProfileV1,
    external_watermark: W,
    journal_id: [u8; 32],
    observed_head: JournalHeadV1,
    owned_pending: Option<[u8; 32]>,
    owner_pid: u32,
}

impl<W: ExternalMonotonicWatermarkV0> SqliteHandoffSignerJournalV1<W> {
    pub fn create_new(
        database_path: impl AsRef<Path>,
        profile: HandoffSignerJournalProfileV1,
        external_watermark: W,
    ) -> Result<Self, HandoffSignerJournalErrorV1> {
        ensure_supported_platform_v1()?;
        reject_semantic_watermark_v1(&external_watermark)?;
        let database_path = absolute_database_path(database_path.as_ref())?;
        match fs::symlink_metadata(&database_path) {
            Ok(_) => return Err(HandoffSignerJournalErrorV1::AlreadyExists),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(HandoffSignerJournalErrorV1::io(
                    "inspect new schema1 database path",
                    error,
                ));
            }
        }
        let (directory_file, directory_identity) = open_parent_directory(&database_path)?;
        let database_file = create_new_private_file_v1(&database_path)?;
        acquire_lifetime_lock_v1(&database_file)?;
        sync_file(&directory_file, "sync schema1 parent after create")?;
        let database_identity = file_handle_identity_v1(&database_file)?;
        require_path_identity(&database_path, database_identity)?;
        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("open new schema1 database", error))?;
        configure_connection_v1(&connection, true, profile.maximum_database_bytes())?;
        let journal_id = new_journal_id_v1()?;
        let observed_head = initialize_schema_v1(&connection, &profile, journal_id)?;
        sync_file(&database_file, "sync initialized schema1 database")?;
        sync_file(&directory_file, "sync initialized schema1 directory")?;
        let mut store = Self {
            connection,
            database_file,
            directory_file,
            database_path,
            database_identity,
            directory_identity,
            profile,
            external_watermark,
            journal_id,
            observed_head,
            owned_pending: None,
            owner_pid: std::process::id(),
        };
        store.audit_local(None)?;
        let initial = store.watermark_for(store.observed_head)?;
        store
            .external_watermark
            .compare_and_advance(None, initial)
            .map_err(|error| {
                HandoffSignerJournalErrorV1::external("claim schema1 watermark scope", error)
            })?;
        store.require_external_exact()?;
        Ok(store)
    }

    pub fn open_existing(
        database_path: impl AsRef<Path>,
        profile: HandoffSignerJournalProfileV1,
        external_watermark: W,
    ) -> Result<Self, HandoffSignerJournalErrorV1> {
        ensure_supported_platform_v1()?;
        reject_semantic_watermark_v1(&external_watermark)?;
        let database_path = absolute_database_path(database_path.as_ref())?;
        match inspect_signer_journal_schema_read_only_v1(&database_path)? {
            SignerJournalSchemaKindV1::LegacyV0ReadOnly => {
                return Err(HandoffSignerJournalErrorV1::LegacySchemaReadOnly);
            }
            SignerJournalSchemaKindV1::HandoffCapableV1 => {}
        }
        let (directory_file, directory_identity) = open_parent_directory(&database_path)?;
        let database_file = open_existing_private_file_v1(&database_path)?;
        acquire_lifetime_lock_v1(&database_file)?;
        let database_identity = file_handle_identity_v1(&database_file)?;
        require_path_identity(&database_path, database_identity)?;
        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("open existing schema1 database", error)
        })?;
        configure_connection_v1(&connection, false, profile.maximum_database_bytes())?;
        validate_canonical_schema_v1(&connection)?;
        let journal_id = read_journal_id_v1(&connection)?;
        let observed_head = read_head_v1(&connection, journal_id)?;
        let mut store = Self {
            connection,
            database_file,
            directory_file,
            database_path,
            database_identity,
            directory_identity,
            profile,
            external_watermark,
            journal_id,
            observed_head,
            owned_pending: None,
            owner_pid: std::process::id(),
        };
        store.audit_local(None)?;
        store.require_external_exact()?;
        Ok(store)
    }

    pub const fn profile(&self) -> &HandoffSignerJournalProfileV1 {
        &self.profile
    }

    pub fn path(&self) -> &Path {
        &self.database_path
    }

    /// Full old-epoch Vote/Timeout producer path. There is no new-set normal
    /// counterpart. Completed exact replay is returned from durable bytes even
    /// after the terminal fence; every new prepare is rejected after fencing.
    ///
    /// A future caller cannot silently route a new-epoch normal intent through
    /// a parallel method because no such API exists:
    ///
    /// ```compile_fail
    /// # use trnm_consensus_signer_journal::{ExternalMonotonicWatermarkV0, SignatureProducerV0, SqliteHandoffSignerJournalV1};
    /// # use trnm_consensus_types::CanonicalSignIntentV0;
    /// # fn cannot_sign_new_epoch<W: ExternalMonotonicWatermarkV0, P: SignatureProducerV0>(
    /// #     journal: &mut SqliteHandoffSignerJournalV1<W>,
    /// #     intent: &CanonicalSignIntentV0,
    /// #     producer: &mut P,
    /// # ) {
    /// journal.sign_new_epoch_exact_v1(intent, producer);
    /// # }
    /// ```
    pub fn sign_old_epoch_exact_v1<P: SignatureProducerV0>(
        &mut self,
        intent: &CanonicalSignIntentV0,
        producer: &mut P,
    ) -> Result<SignatureBytes, HandoffSignerJournalErrorV1> {
        let prepared = prepare_consensus_intent_v1(&self.profile, intent)?;
        self.ensure_operational()?;
        if let Some(stored) = read_intent_v1(&self.connection, prepared.fingerprint)? {
            require_exact_intent_v1(&stored, &prepared)?;
            if let Some(signature) =
                read_persisted_signature_v1(&self.connection, prepared.fingerprint, &self.profile)?
            {
                return Ok(signature);
            }
            self.require_owned_pending(prepared.fingerprint)?;
            return self.complete_consensus_signature(intent, &prepared, producer);
        }
        if terminal_fence_exists_v1(&self.connection)? {
            return Err(HandoffSignerJournalErrorV1::Conflict(
                HandoffSignerJournalConflictV1::TerminalOldEpochFence {
                    old_epoch: self.profile.old_validator_set().epoch().get(),
                },
            ));
        }
        self.require_no_pending()?;
        self.require_consensus_admissible(&prepared)?;
        self.append_prepared(&prepared)?;
        self.owned_pending = Some(prepared.fingerprint);
        self.advance_external_to_observed()?;
        self.complete_consensus_signature(intent, &prepared, producer)
    }

    /// Old-set handoff path. Both the exact canonical intent and the opaque
    /// strict pre-certificate admission are mandatory before any local or
    /// external mutation. A new-set intent is rejected before operational
    /// state or the producer is touched.
    ///
    /// ```compile_fail
    /// # use trnm_consensus_signer_journal::{ExternalMonotonicWatermarkV0, HandoffSignatureProducerV1, SqliteHandoffSignerJournalV1};
    /// # use trnm_consensus_types::CanonicalHandoffSignIntentV1;
    /// # fn bare_intent_is_not_admission<W: ExternalMonotonicWatermarkV0, P: HandoffSignatureProducerV1>(
    /// #     journal: &mut SqliteHandoffSignerJournalV1<W>,
    /// #     intent: &CanonicalHandoffSignIntentV1,
    /// #     producer: &mut P,
    /// # ) {
    /// journal.sign_old_set_handoff_exact_v1(intent, producer);
    /// # }
    /// ```
    pub fn sign_old_set_handoff_exact_v1<P: HandoffSignatureProducerV1>(
        &mut self,
        intent: &CanonicalHandoffSignIntentV1,
        admission: &StrictOldSetHandoffAdmissionV1,
        producer: &mut P,
    ) -> Result<SignatureBytes, HandoffSignerJournalErrorV1> {
        if intent.signer_role() != HandoffSignerRoleV1::OldSet {
            return Err(HandoffSignerJournalErrorV1::NewSetAdmissionUnavailable);
        }
        admission.require_exact(intent, &self.profile)?;
        let prepared = prepare_handoff_intent_v1(&self.profile, intent, admission)?;
        self.ensure_operational()?;
        if let Some(stored) = read_intent_v1(&self.connection, prepared.fingerprint)? {
            require_exact_intent_v1(&stored, &prepared)?;
            if let Some(signature) =
                read_persisted_signature_v1(&self.connection, prepared.fingerprint, &self.profile)?
            {
                return Ok(signature);
            }
            self.require_owned_pending(prepared.fingerprint)?;
            return self.complete_handoff_signature(intent, &prepared, producer);
        }
        self.require_no_pending()?;
        self.require_handoff_admissible(&prepared)?;
        self.append_prepared(&prepared)?;
        self.owned_pending = Some(prepared.fingerprint);
        self.advance_external_to_observed()?;
        self.complete_handoff_signature(intent, &prepared, producer)
    }

    fn complete_consensus_signature<P: SignatureProducerV0>(
        &mut self,
        intent: &CanonicalSignIntentV0,
        prepared: &PreparedIntentV1,
        producer: &mut P,
    ) -> Result<SignatureBytes, HandoffSignerJournalErrorV1> {
        self.ensure_operational()?;
        self.require_owned_pending(prepared.fingerprint)?;
        let signature = producer
            .sign(SignatureRequestV0::new(
                intent,
                self.profile.signer_profile_ref(),
            ))
            .map_err(HandoffSignerJournalErrorV1::SignatureProducer)?;
        let validator = self
            .profile
            .old_validator_set()
            .validator(self.profile.author())
            .ok_or(HandoffSignerJournalErrorV1::MetadataMismatch)?;
        if !StrictEd25519Verifier.verify(validator, &intent.signing_root(), &signature) {
            return Err(HandoffSignerJournalErrorV1::InvalidProducedSignature);
        }
        self.append_signature(prepared, signature, false)?;
        self.owned_pending = None;
        self.advance_external_to_observed()?;
        read_persisted_signature_v1(&self.connection, prepared.fingerprint, &self.profile)?.ok_or(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "completed consensus signature disappeared",
            ),
        )
    }

    fn complete_handoff_signature<P: HandoffSignatureProducerV1>(
        &mut self,
        intent: &CanonicalHandoffSignIntentV1,
        prepared: &PreparedIntentV1,
        producer: &mut P,
    ) -> Result<SignatureBytes, HandoffSignerJournalErrorV1> {
        self.ensure_operational()?;
        self.require_owned_pending(prepared.fingerprint)?;
        let signature = producer
            .sign_handoff(HandoffSignatureRequestV1::new(
                intent,
                self.profile.signer_profile_ref(),
            ))
            .map_err(HandoffSignerJournalErrorV1::SignatureProducer)?;
        let validator = self
            .profile
            .old_validator_set()
            .validator(self.profile.author())
            .ok_or(HandoffSignerJournalErrorV1::MetadataMismatch)?;
        if !StrictEd25519Verifier.verify(validator, &intent.signing_root(), &signature) {
            return Err(HandoffSignerJournalErrorV1::InvalidProducedSignature);
        }
        self.append_signature(prepared, signature, true)?;
        self.owned_pending = None;
        self.advance_external_to_observed()?;
        read_persisted_signature_v1(&self.connection, prepared.fingerprint, &self.profile)?.ok_or(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "completed handoff signature disappeared",
            ),
        )
    }

    fn ensure_operational(&mut self) -> Result<(), HandoffSignerJournalErrorV1> {
        self.ensure_file_identity()?;
        self.audit_local(self.owned_pending)?;
        let head = read_head_v1(&self.connection, self.journal_id)?;
        if head != self.observed_head {
            return Err(HandoffSignerJournalErrorV1::Conflict(
                HandoffSignerJournalConflictV1::CommitReadbackConflict,
            ));
        }
        self.require_external_exact()
    }

    fn ensure_file_identity(&self) -> Result<(), HandoffSignerJournalErrorV1> {
        if std::process::id() != self.owner_pid {
            return Err(HandoffSignerJournalErrorV1::Conflict(
                HandoffSignerJournalConflictV1::ProcessChanged,
            ));
        }
        let handle = file_handle_identity_v1(&self.database_file)?;
        let path = path_identity_v1(&self.database_path)?;
        let directory_handle = directory_handle_identity_v1(&self.directory_file)?;
        let directory_path = directory_path_identity_v1(self.database_path.parent().ok_or(
            HandoffSignerJournalErrorV1::InvalidProfile("database parent"),
        )?)?;
        if handle != self.database_identity
            || path != self.database_identity
            || directory_handle != self.directory_identity
            || directory_path != self.directory_identity
        {
            return Err(HandoffSignerJournalErrorV1::Conflict(
                HandoffSignerJournalConflictV1::FileIdentityChanged,
            ));
        }
        let length = self
            .database_file
            .metadata()
            .map_err(|error| HandoffSignerJournalErrorV1::io("stat schema1 database", error))?
            .len();
        if length > self.profile.maximum_database_bytes() as u64 {
            return Err(HandoffSignerJournalErrorV1::CapacityExhausted);
        }
        Ok(())
    }

    fn require_external_exact(&mut self) -> Result<(), HandoffSignerJournalErrorV1> {
        let expected = self.watermark_for(self.observed_head)?;
        let actual = self
            .external_watermark
            .load(self.profile.external_watermark_scope())
            .map_err(|error| {
                HandoffSignerJournalErrorV1::external("load schema1 watermark", error)
            })?
            .ok_or(HandoffSignerJournalErrorV1::Conflict(
                HandoffSignerJournalConflictV1::ExternalWatermarkMissing,
            ))?;
        if actual != expected {
            return Err(HandoffSignerJournalErrorV1::Conflict(
                HandoffSignerJournalConflictV1::ExternalWatermarkMismatch,
            ));
        }
        Ok(())
    }

    fn advance_external_to_observed(&mut self) -> Result<(), HandoffSignerJournalErrorV1> {
        let target = self.watermark_for(self.observed_head)?;
        let predecessor_sequence = self.observed_head.sequence.checked_sub(1).ok_or(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "cannot advance external watermark to initial head",
            ),
        )?;
        let predecessor = if predecessor_sequence == 0 {
            JournalHeadV1 {
                sequence: 0,
                chain_checksum: initial_chain_checksum_v1(
                    self.journal_id,
                    self.profile.profile_checksum(),
                ),
            }
        } else {
            read_event_v1(&self.connection, predecessor_sequence)?.map_or_else(
                || {
                    Err(
                        HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                            "missing predecessor event for external advance",
                        ),
                    )
                },
                |event| {
                    Ok(JournalHeadV1 {
                        sequence: event.sequence,
                        chain_checksum: event.chain_checksum,
                    })
                },
            )?
        };
        let expected = self.watermark_for(predecessor)?;
        self.external_watermark
            .compare_and_advance(Some(expected), target)
            .map_err(|error| {
                HandoffSignerJournalErrorV1::external("advance schema1 watermark", error)
            })?;
        self.require_external_exact()
    }

    fn watermark_for(
        &self,
        head: JournalHeadV1,
    ) -> Result<SignerWatermarkV0, HandoffSignerJournalErrorV1> {
        SignerWatermarkV0::from_persisted_parts(
            self.profile.external_watermark_scope(),
            self.journal_id,
            head.sequence,
            head.chain_checksum,
        )
        .map_err(|_| {
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed("watermark parts")
        })
    }

    fn require_owned_pending(
        &self,
        fingerprint: [u8; 32],
    ) -> Result<(), HandoffSignerJournalErrorV1> {
        if self.owned_pending != Some(fingerprint) {
            return Err(HandoffSignerJournalErrorV1::Conflict(
                HandoffSignerJournalConflictV1::PreparedIntentPending,
            ));
        }
        Ok(())
    }

    fn require_no_pending(&self) -> Result<(), HandoffSignerJournalErrorV1> {
        if pending_fingerprint_v1(&self.connection)?.is_some() {
            return Err(HandoffSignerJournalErrorV1::Conflict(
                HandoffSignerJournalConflictV1::PreparedIntentPending,
            ));
        }
        Ok(())
    }

    fn require_consensus_admissible(
        &self,
        prepared: &PreparedIntentV1,
    ) -> Result<(), HandoffSignerJournalErrorV1> {
        let PreparedFieldsV1::Consensus {
            epoch,
            view,
            kind,
            safety_revision,
        } = &prepared.fields
        else {
            return Err(
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                    "consensus admission received handoff fields",
                ),
            );
        };
        let conflicting: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT fingerprint FROM signer_intents_v1
                 WHERE intent_class=0 AND epoch_be=?1 AND view_be=?2 AND intent_kind=?3",
                params![
                    epoch.to_be_bytes().as_slice(),
                    view.to_be_bytes().as_slice(),
                    i64::from(*kind)
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| {
                HandoffSignerJournalErrorV1::sqlite("check schema1 round conflict", error)
            })?;
        if conflicting.is_some() {
            return Err(HandoffSignerJournalErrorV1::Conflict(
                HandoffSignerJournalConflictV1::SameRoundDifferentIntent {
                    epoch: *epoch,
                    view: *view,
                    kind: *kind,
                },
            ));
        }
        let accounting = read_accounting_v1(&self.connection)?;
        if let Some(maximum) = accounting.maximum_safety_revision {
            if *safety_revision <= maximum {
                return Err(HandoffSignerJournalErrorV1::Conflict(
                    HandoffSignerJournalConflictV1::SafetyRevisionRegression {
                        maximum,
                        incoming: *safety_revision,
                    },
                ));
            }
        }
        let maximum_view = match *kind {
            1 => accounting.maximum_vote_view,
            2 => accounting.maximum_timeout_view,
            _ => None,
        };
        if let Some(maximum) = maximum_view {
            if *view <= maximum {
                return Err(HandoffSignerJournalErrorV1::Conflict(
                    HandoffSignerJournalConflictV1::ViewRegression {
                        kind: *kind,
                        maximum,
                        incoming: *view,
                    },
                ));
            }
        }
        require_capacity_for_v1(&accounting, &self.profile, prepared.canonical_intent.len())
    }

    fn require_handoff_admissible(
        &self,
        prepared: &PreparedIntentV1,
    ) -> Result<(), HandoffSignerJournalErrorV1> {
        let PreparedFieldsV1::Handoff {
            old_epoch,
            new_epoch,
            role,
            ref genesis_hash,
            ref validator_id,
            ..
        } = &prepared.fields
        else {
            return Err(
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                    "handoff admission received consensus fields",
                ),
            );
        };
        let conflicting: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT fingerprint FROM signer_intents_v1
                 WHERE intent_class=1 AND genesis_hash=?1 AND old_epoch_be=?2
                   AND new_epoch_be=?3 AND handoff_role=?4 AND validator_id=?5",
                params![
                    genesis_hash.as_slice(),
                    old_epoch.to_be_bytes().as_slice(),
                    new_epoch.to_be_bytes().as_slice(),
                    i64::from(*role),
                    validator_id,
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| {
                HandoffSignerJournalErrorV1::sqlite("check schema1 handoff conflict", error)
            })?;
        if conflicting.is_some() {
            return Err(HandoffSignerJournalErrorV1::Conflict(
                HandoffSignerJournalConflictV1::HandoffTransitionDifferentIntent {
                    old_epoch: *old_epoch,
                    new_epoch: *new_epoch,
                    role: *role,
                },
            ));
        }
        let accounting = read_accounting_v1(&self.connection)?;
        require_capacity_for_v1(&accounting, &self.profile, prepared.canonical_intent.len())
    }

    fn append_prepared(
        &mut self,
        prepared: &PreparedIntentV1,
    ) -> Result<(), HandoffSignerJournalErrorV1> {
        let predecessor = read_head_v1(&self.connection, self.journal_id)?;
        if predecessor != self.observed_head {
            return Err(HandoffSignerJournalErrorV1::Conflict(
                HandoffSignerJournalConflictV1::CommitReadbackConflict,
            ));
        }
        let event = make_event_v1(predecessor, EVENT_PREPARED, prepared, None)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| HandoffSignerJournalErrorV1::sqlite("begin schema1 prepare", error))?;
        insert_intent_v1(&transaction, prepared)?;
        insert_event_v1(&transaction, &event)?;
        update_accounting_prepared_v1(&transaction, prepared)?;
        update_head_v1(&transaction, self.journal_id, &event)?;
        transaction.commit().map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("commit schema1 prepare", error)
        })?;
        sync_file(&self.database_file, "sync schema1 prepared event")?;
        self.observed_head = JournalHeadV1 {
            sequence: event.sequence,
            chain_checksum: event.chain_checksum,
        };
        require_head_readback_v1(&self.connection, self.journal_id, self.observed_head)
    }

    fn append_signature(
        &mut self,
        prepared: &PreparedIntentV1,
        signature: SignatureBytes,
        install_terminal_fence: bool,
    ) -> Result<(), HandoffSignerJournalErrorV1> {
        let predecessor = read_head_v1(&self.connection, self.journal_id)?;
        if predecessor != self.observed_head {
            return Err(HandoffSignerJournalErrorV1::Conflict(
                HandoffSignerJournalConflictV1::CommitReadbackConflict,
            ));
        }
        let event = make_event_v1(
            predecessor,
            EVENT_SIGNED,
            prepared,
            Some(*signature.as_bytes()),
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                HandoffSignerJournalErrorV1::sqlite("begin schema1 signature", error)
            })?;
        insert_event_v1(&transaction, &event)?;
        update_accounting_signed_v1(&transaction)?;
        if install_terminal_fence {
            insert_terminal_fence_v1(&transaction, &self.profile, prepared, event.sequence)?;
        }
        update_head_v1(&transaction, self.journal_id, &event)?;
        transaction.commit().map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("commit schema1 signature", error)
        })?;
        sync_file(&self.database_file, "sync schema1 signed event")?;
        self.observed_head = JournalHeadV1 {
            sequence: event.sequence,
            chain_checksum: event.chain_checksum,
        };
        require_head_readback_v1(&self.connection, self.journal_id, self.observed_head)
    }

    fn audit_local(
        &self,
        allowed_pending: Option<[u8; 32]>,
    ) -> Result<(), HandoffSignerJournalErrorV1> {
        validate_database_v1(
            &self.connection,
            &self.database_file,
            &self.profile,
            self.journal_id,
            allowed_pending,
        )?;
        let head = read_head_v1(&self.connection, self.journal_id)?;
        if head != self.observed_head {
            return Err(HandoffSignerJournalErrorV1::Conflict(
                HandoffSignerJournalConflictV1::CommitReadbackConflict,
            ));
        }
        Ok(())
    }
}

/// Schema1 currently uses the legacy opaque watermark calls for its unified
/// consensus/handoff event chain.  Refusing semantic authorities at the
/// constructor boundary prevents a semantic adapter from creating a local
/// database and only failing later when the first opaque CAS is attempted.
/// A future schema1 semantic implementation must define and attest its own
/// handoff lifecycle before this guard is relaxed.
fn reject_semantic_watermark_v1(
    external: &dyn ExternalMonotonicWatermarkV0,
) -> Result<(), HandoffSignerJournalErrorV1> {
    if external.semantic_mode_v0()
        || external.semantic_per_reservation_v0()
        || external.semantic_signer_journal_pair_v0()
    {
        return Err(HandoffSignerJournalErrorV1::InvalidProfile(
            UNSUPPORTED_SEMANTIC_WATERMARK_V1,
        ));
    }
    Ok(())
}

fn prepare_consensus_intent_v1(
    profile: &HandoffSignerJournalProfileV1,
    intent: &CanonicalSignIntentV0,
) -> Result<PreparedIntentV1, HandoffSignerJournalErrorV1> {
    intent
        .validate(profile.old_validator_set())
        .map_err(|_| HandoffSignerJournalErrorV1::Intent("old-set validation"))?;
    if intent.author() != profile.author()
        || intent.epoch() != profile.old_validator_set().epoch()
        || intent.validator_set_id() != profile.old_validator_set().id()
    {
        return Err(HandoffSignerJournalErrorV1::Intent(
            "old-epoch profile binding",
        ));
    }
    let context = intent.preimage().context();
    let kind = match context.message_kind() {
        MessageKind::Vote => 1,
        MessageKind::Timeout => 2,
        _ => {
            return Err(HandoffSignerJournalErrorV1::Intent(
                "normal path accepts only Vote or Timeout",
            ));
        }
    };
    let canonical_intent = intent
        .canonical_bytes()
        .map_err(|_| HandoffSignerJournalErrorV1::Intent("canonical encoding"))?;
    require_intent_size_v1(profile, canonical_intent.len())?;
    let decoded =
        decode_canonical_sign_intent_v0_exact(&canonical_intent, profile.old_validator_set())
            .map_err(|_| HandoffSignerJournalErrorV1::Intent("exact canonical decode"))?;
    if decoded != *intent {
        return Err(HandoffSignerJournalErrorV1::Intent(
            "canonical decode differs",
        ));
    }
    let fields = PreparedFieldsV1::Consensus {
        epoch: intent.epoch().get(),
        view: context.view().get(),
        kind,
        safety_revision: intent.authorizing_safety_revision(),
    };
    let mut prepared = PreparedIntentV1 {
        fingerprint: *intent.fingerprint().as_bytes(),
        class: CLASS_CONSENSUS,
        signing_root: *intent.signing_root().as_bytes(),
        canonical_intent,
        intent_checksum: [0; 32],
        fields,
    };
    prepared.intent_checksum = compute_intent_checksum_v1(&prepared);
    Ok(prepared)
}

fn prepare_handoff_intent_v1(
    profile: &HandoffSignerJournalProfileV1,
    intent: &CanonicalHandoffSignIntentV1,
    admission: &StrictOldSetHandoffAdmissionV1,
) -> Result<PreparedIntentV1, HandoffSignerJournalErrorV1> {
    intent
        .validate(
            profile.old_validator_set(),
            profile.new_validator_set(),
            profile.old_consensus_parameters(),
            profile.new_consensus_parameters(),
        )
        .map_err(|_| HandoffSignerJournalErrorV1::Intent("handoff transition profile"))?;
    if intent.signer_role() != HandoffSignerRoleV1::OldSet
        || intent.validator_id() != profile.author()
    {
        return Err(HandoffSignerJournalErrorV1::Intent(
            "only admitted old-set handoff is enabled",
        ));
    }
    admission.require_exact(intent, profile)?;
    let canonical_intent = intent
        .canonical_bytes()
        .map_err(|_| HandoffSignerJournalErrorV1::Intent("handoff canonical encoding"))?;
    require_intent_size_v1(profile, canonical_intent.len())?;
    let decoded = decode_canonical_handoff_sign_intent_v1_exact(
        &canonical_intent,
        profile.old_validator_set(),
        profile.new_validator_set(),
        profile.old_consensus_parameters(),
        profile.new_consensus_parameters(),
    )
    .map_err(|_| HandoffSignerJournalErrorV1::Intent("exact handoff canonical decode"))?;
    if decoded != *intent {
        return Err(HandoffSignerJournalErrorV1::Intent(
            "handoff canonical decode differs",
        ));
    }
    let preimage = intent.preimage();
    let fields = PreparedFieldsV1::Handoff {
        genesis_hash: *preimage.genesis_hash().as_bytes(),
        old_epoch: preimage.old_epoch().get(),
        new_epoch: preimage.new_epoch().get(),
        role: intent.signer_role() as u8,
        validator_id: intent.validator_id().as_bytes().to_vec(),
        descriptor_digest: *preimage.descriptor_digest().as_bytes(),
        descriptor_cev0: preimage.descriptor_bytes().to_vec(),
        admission_digest: admission.admission_digest(),
    };
    let mut prepared = PreparedIntentV1 {
        fingerprint: *intent.fingerprint().as_bytes(),
        class: CLASS_HANDOFF,
        signing_root: *intent.signing_root().as_bytes(),
        canonical_intent,
        intent_checksum: [0; 32],
        fields,
    };
    prepared.intent_checksum = compute_intent_checksum_v1(&prepared);
    Ok(prepared)
}

fn require_intent_size_v1(
    profile: &HandoffSignerJournalProfileV1,
    actual: usize,
) -> Result<(), HandoffSignerJournalErrorV1> {
    let maximum = profile
        .maximum_intent_bytes()
        .min(MAXIMUM_SQL_INTENT_BYTES_V1);
    if actual == 0 || actual > maximum {
        return Err(HandoffSignerJournalErrorV1::IntentTooLarge { actual, maximum });
    }
    Ok(())
}

fn compute_intent_checksum_v1(intent: &PreparedIntentV1) -> [u8; 32] {
    let class = [intent.class];
    match &intent.fields {
        PreparedFieldsV1::Consensus {
            epoch,
            view,
            kind,
            safety_revision,
        } => {
            let epoch = epoch.to_be_bytes();
            let view = view.to_be_bytes();
            let kind = [*kind];
            let safety_revision = safety_revision.to_be_bytes();
            hash_domain(
                INTENT_DOMAIN_V1,
                &[
                    &class,
                    &intent.fingerprint,
                    &intent.signing_root,
                    &intent.canonical_intent,
                    &epoch,
                    &view,
                    &kind,
                    &safety_revision,
                ],
            )
        }
        PreparedFieldsV1::Handoff {
            genesis_hash,
            old_epoch,
            new_epoch,
            role,
            validator_id,
            descriptor_digest,
            descriptor_cev0,
            admission_digest,
        } => {
            let old_epoch = old_epoch.to_be_bytes();
            let new_epoch = new_epoch.to_be_bytes();
            let role = [*role];
            hash_domain(
                INTENT_DOMAIN_V1,
                &[
                    &class,
                    &intent.fingerprint,
                    &intent.signing_root,
                    &intent.canonical_intent,
                    genesis_hash,
                    &old_epoch,
                    &new_epoch,
                    &role,
                    validator_id,
                    descriptor_digest,
                    descriptor_cev0,
                    admission_digest,
                ],
            )
        }
    }
}

fn make_event_v1(
    predecessor: JournalHeadV1,
    kind: u8,
    intent: &PreparedIntentV1,
    signature: Option<[u8; 64]>,
) -> Result<StoredEventV1, HandoffSignerJournalErrorV1> {
    let sequence = predecessor
        .sequence
        .checked_add(1)
        .ok_or(HandoffSignerJournalErrorV1::CapacityExhausted)?;
    let sequence_be = sequence.to_be_bytes();
    let predecessor_sequence_be = predecessor.sequence.to_be_bytes();
    let kind_bytes = [kind];
    let signature_tag = [u8::from(signature.is_some())];
    let signature_bytes = signature.as_ref().map_or(&[][..], |value| value.as_slice());
    let event_checksum = hash_domain(
        EVENT_DOMAIN_V1,
        &[
            &sequence_be,
            &kind_bytes,
            &intent.fingerprint,
            &signature_tag,
            signature_bytes,
            &predecessor_sequence_be,
            &predecessor.chain_checksum,
            &intent.intent_checksum,
        ],
    );
    let chain_checksum = hash_domain(
        CHAIN_DOMAIN_V1,
        &[
            &predecessor_sequence_be,
            &predecessor.chain_checksum,
            &event_checksum,
        ],
    );
    Ok(StoredEventV1 {
        sequence,
        kind,
        fingerprint: intent.fingerprint,
        signature,
        predecessor_sequence: predecessor.sequence,
        predecessor_chain_checksum: predecessor.chain_checksum,
        event_checksum,
        chain_checksum,
    })
}

fn configure_connection_v1(
    connection: &Connection,
    initialize: bool,
    maximum_database_bytes: usize,
) -> Result<(), HandoffSignerJournalErrorV1> {
    connection
        .busy_timeout(DEFAULT_BUSY_TIMEOUT)
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("configure schema1 busy timeout", error)
        })?;
    if initialize {
        connection
            .execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=DELETE;")
            .map_err(|error| {
                HandoffSignerJournalErrorV1::sqlite("initialize schema1 journal mode", error)
            })?;
    }
    connection
        .execute_batch(
            "PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;
             PRAGMA recursive_triggers=OFF;",
        )
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("configure schema1 safety", error))?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("read schema1 journal mode", error))?;
    if !journal_mode.eq_ignore_ascii_case("delete") {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "schema1 requires SQLite DELETE journal mode",
            ),
        );
    }
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("read schema1 page size", error))?;
    if page_size <= 0 {
        return Err(HandoffSignerJournalErrorV1::InvalidProfile(
            "SQLite page size",
        ));
    }
    let maximum_pages = (maximum_database_bytes as u64) / (page_size as u64);
    if maximum_pages == 0 || maximum_pages > i64::MAX as u64 {
        return Err(HandoffSignerJournalErrorV1::InvalidProfile(
            "SQLite page count bound",
        ));
    }
    connection
        .pragma_update(None, "max_page_count", maximum_pages as i64)
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("set schema1 page bound", error))?;
    connection
        .pragma_update(None, "journal_size_limit", maximum_database_bytes as i64)
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("set schema1 journal bound", error))?;
    Ok(())
}

fn metadata_checksum_v1(
    profile: &HandoffSignerJournalProfileV1,
    journal_id: [u8; 32],
) -> Result<[u8; 32], HandoffSignerJournalErrorV1> {
    let old_set = profile
        .old_validator_set()
        .try_cev0_bytes()
        .map_err(|_| HandoffSignerJournalErrorV1::MetadataMismatch)?;
    let new_set = profile
        .new_validator_set()
        .try_cev0_bytes()
        .map_err(|_| HandoffSignerJournalErrorV1::MetadataMismatch)?;
    let old_parameters = profile.old_consensus_parameters().canonical_bytes();
    let new_parameters = profile.new_consensus_parameters().canonical_bytes();
    let old_epoch = profile.old_validator_set().epoch().get().to_be_bytes();
    let new_epoch = profile.new_validator_set().epoch().get().to_be_bytes();
    let old_protocol = profile
        .old_validator_set()
        .protocol_version()
        .get()
        .to_be_bytes();
    let new_protocol = profile
        .new_validator_set()
        .protocol_version()
        .get()
        .to_be_bytes();
    let maximum_intents = profile.maximum_intents().to_be_bytes();
    let maximum_intent_bytes = (profile.maximum_intent_bytes() as u64).to_be_bytes();
    let maximum_database_bytes = (profile.maximum_database_bytes() as u64).to_be_bytes();
    Ok(hash_domain(
        METADATA_DOMAIN_V1,
        &[
            &JOURNAL_SCHEMA_VERSION_V1.to_be_bytes(),
            &journal_id,
            profile.old_validator_set().genesis_hash().as_bytes(),
            profile.old_validator_set().chain_id().as_bytes(),
            &old_epoch,
            &new_epoch,
            &old_protocol,
            &new_protocol,
            profile.old_validator_set().id().as_bytes(),
            profile.new_validator_set().id().as_bytes(),
            &old_set,
            &new_set,
            profile.old_consensus_parameters().hash().as_bytes(),
            profile.new_consensus_parameters().hash().as_bytes(),
            &old_parameters,
            &new_parameters,
            profile.author().as_bytes(),
            &profile.signer_profile_ref(),
            &profile.external_watermark_scope(),
            &maximum_intents,
            &maximum_intent_bytes,
            &maximum_database_bytes,
            &profile.profile_checksum(),
        ],
    ))
}

fn initial_chain_checksum_v1(journal_id: [u8; 32], profile_checksum: [u8; 32]) -> [u8; 32] {
    hash_domain(INITIAL_HEAD_DOMAIN_V1, &[&journal_id, &profile_checksum])
}

fn initial_head_v1(profile: &HandoffSignerJournalProfileV1, journal_id: [u8; 32]) -> JournalHeadV1 {
    JournalHeadV1 {
        sequence: 0,
        chain_checksum: initial_chain_checksum_v1(journal_id, profile.profile_checksum()),
    }
}

fn head_checksum_v1(journal_id: [u8; 32], head: JournalHeadV1) -> [u8; 32] {
    hash_domain(
        HEAD_DOMAIN_V1,
        &[
            &journal_id,
            &head.sequence.to_be_bytes(),
            &head.chain_checksum,
        ],
    )
}

fn initialize_schema_v1(
    connection: &Connection,
    profile: &HandoffSignerJournalProfileV1,
    journal_id: [u8; 32],
) -> Result<JournalHeadV1, HandoffSignerJournalErrorV1> {
    connection
        .execute_batch("BEGIN IMMEDIATE;")
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("begin schema1 initialization", error)
        })?;
    let result = (|| {
        connection
            .execute_batch(JOURNAL_SCHEMA_SQL_V1)
            .map_err(|error| HandoffSignerJournalErrorV1::sqlite("create exact schema1", error))?;
        let old_set_bytes = profile
            .old_validator_set()
            .try_cev0_bytes()
            .map_err(|_| HandoffSignerJournalErrorV1::MetadataMismatch)?;
        let new_set_bytes = profile
            .new_validator_set()
            .try_cev0_bytes()
            .map_err(|_| HandoffSignerJournalErrorV1::MetadataMismatch)?;
        let old_parameters = profile.old_consensus_parameters().canonical_bytes();
        let new_parameters = profile.new_consensus_parameters().canonical_bytes();
        let old_author = profile
            .old_validator_set()
            .validator(profile.author())
            .ok_or(HandoffSignerJournalErrorV1::MetadataMismatch)?;
        let metadata_checksum = metadata_checksum_v1(profile, journal_id)?;
        let changed = connection
            .execute(
                "INSERT INTO handoff_signer_metadata_v1(
                    singleton, journal_schema, journal_id, genesis_hash, chain_id,
                    old_epoch_be, new_epoch_be, old_protocol_version_be,
                    new_protocol_version_be, old_validator_set_id, new_validator_set_id,
                    old_validator_set_cev0, new_validator_set_cev0,
                    old_parameters_hash, new_parameters_hash,
                    old_parameters_cev0, new_parameters_cev0, author,
                    old_author_public_key, signer_profile_ref, external_watermark_scope,
                    maximum_intents_be, maximum_intent_bytes_be,
                    maximum_database_bytes_be, profile_checksum, metadata_checksum
                 ) VALUES (1, 1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                           ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                           ?21, ?22, ?23, ?24)",
                params![
                    journal_id.as_slice(),
                    profile
                        .old_validator_set()
                        .genesis_hash()
                        .as_bytes()
                        .as_slice(),
                    profile.old_validator_set().chain_id().as_bytes(),
                    profile
                        .old_validator_set()
                        .epoch()
                        .get()
                        .to_be_bytes()
                        .as_slice(),
                    profile
                        .new_validator_set()
                        .epoch()
                        .get()
                        .to_be_bytes()
                        .as_slice(),
                    profile
                        .old_validator_set()
                        .protocol_version()
                        .get()
                        .to_be_bytes()
                        .as_slice(),
                    profile
                        .new_validator_set()
                        .protocol_version()
                        .get()
                        .to_be_bytes()
                        .as_slice(),
                    profile.old_validator_set().id().as_bytes().as_slice(),
                    profile.new_validator_set().id().as_bytes().as_slice(),
                    old_set_bytes,
                    new_set_bytes,
                    profile
                        .old_consensus_parameters()
                        .hash()
                        .as_bytes()
                        .as_slice(),
                    profile
                        .new_consensus_parameters()
                        .hash()
                        .as_bytes()
                        .as_slice(),
                    old_parameters,
                    new_parameters,
                    profile.author().as_bytes(),
                    old_author.consensus_key().as_bytes().as_slice(),
                    profile.signer_profile_ref().as_slice(),
                    profile.external_watermark_scope().as_slice(),
                    profile.maximum_intents().to_be_bytes().as_slice(),
                    (profile.maximum_intent_bytes() as u64)
                        .to_be_bytes()
                        .as_slice(),
                    (profile.maximum_database_bytes() as u64)
                        .to_be_bytes()
                        .as_slice(),
                    profile.profile_checksum().as_slice(),
                    metadata_checksum.as_slice(),
                ],
            )
            .map_err(|error| {
                HandoffSignerJournalErrorV1::sqlite("insert schema1 metadata", error)
            })?;
        if changed != 1 {
            return Err(HandoffSignerJournalErrorV1::MetadataMismatch);
        }
        let head = initial_head_v1(profile, journal_id);
        connection
            .execute(
                "INSERT INTO signer_head_v1(
                    singleton, active_sequence_be, active_chain_checksum, head_checksum
                 ) VALUES (1, ?1, ?2, ?3)",
                params![
                    head.sequence.to_be_bytes().as_slice(),
                    head.chain_checksum.as_slice(),
                    head_checksum_v1(journal_id, head).as_slice(),
                ],
            )
            .map_err(|error| HandoffSignerJournalErrorV1::sqlite("insert schema1 head", error))?;
        connection
            .execute(
                "INSERT INTO signer_accounting_v1(
                    singleton, intent_count, event_count, intent_bytes,
                    maximum_safety_revision_be, maximum_vote_view_be,
                    maximum_timeout_view_be
                 ) VALUES (1, 0, 0, 0, NULL, NULL, NULL)",
                [],
            )
            .map_err(|error| {
                HandoffSignerJournalErrorV1::sqlite("insert schema1 accounting", error)
            })?;
        connection.execute_batch("COMMIT;").map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("commit schema1 initialization", error)
        })?;
        Ok(head)
    })();
    if result.is_err() {
        let _ = connection.execute_batch("ROLLBACK;");
    }
    result
}

#[derive(Debug)]
struct StoredMetadataV1 {
    journal_schema: i64,
    journal_id: Vec<u8>,
    genesis_hash: Vec<u8>,
    chain_id: Vec<u8>,
    old_epoch_be: Vec<u8>,
    new_epoch_be: Vec<u8>,
    old_protocol_be: Vec<u8>,
    new_protocol_be: Vec<u8>,
    old_set_id: Vec<u8>,
    new_set_id: Vec<u8>,
    old_set_cev0: Vec<u8>,
    new_set_cev0: Vec<u8>,
    old_parameters_hash: Vec<u8>,
    new_parameters_hash: Vec<u8>,
    old_parameters_cev0: Vec<u8>,
    new_parameters_cev0: Vec<u8>,
    author: Vec<u8>,
    old_author_public_key: Vec<u8>,
    signer_profile_ref: Vec<u8>,
    external_scope: Vec<u8>,
    maximum_intents_be: Vec<u8>,
    maximum_intent_bytes_be: Vec<u8>,
    maximum_database_bytes_be: Vec<u8>,
    profile_checksum: Vec<u8>,
    metadata_checksum: Vec<u8>,
}

fn read_and_validate_metadata_v1(
    connection: &Connection,
    profile: &HandoffSignerJournalProfileV1,
) -> Result<[u8; 32], HandoffSignerJournalErrorV1> {
    let row = connection
        .query_row(
            "SELECT journal_schema, journal_id, genesis_hash, chain_id,
                    old_epoch_be, new_epoch_be, old_protocol_version_be,
                    new_protocol_version_be, old_validator_set_id,
                    new_validator_set_id, old_validator_set_cev0,
                    new_validator_set_cev0, old_parameters_hash,
                    new_parameters_hash, old_parameters_cev0,
                    new_parameters_cev0, author, old_author_public_key,
                    signer_profile_ref, external_watermark_scope,
                    maximum_intents_be, maximum_intent_bytes_be,
                    maximum_database_bytes_be, profile_checksum, metadata_checksum
             FROM handoff_signer_metadata_v1 WHERE singleton=1",
            [],
            |row| {
                Ok(StoredMetadataV1 {
                    journal_schema: row.get(0)?,
                    journal_id: row.get(1)?,
                    genesis_hash: row.get(2)?,
                    chain_id: row.get(3)?,
                    old_epoch_be: row.get(4)?,
                    new_epoch_be: row.get(5)?,
                    old_protocol_be: row.get(6)?,
                    new_protocol_be: row.get(7)?,
                    old_set_id: row.get(8)?,
                    new_set_id: row.get(9)?,
                    old_set_cev0: row.get(10)?,
                    new_set_cev0: row.get(11)?,
                    old_parameters_hash: row.get(12)?,
                    new_parameters_hash: row.get(13)?,
                    old_parameters_cev0: row.get(14)?,
                    new_parameters_cev0: row.get(15)?,
                    author: row.get(16)?,
                    old_author_public_key: row.get(17)?,
                    signer_profile_ref: row.get(18)?,
                    external_scope: row.get(19)?,
                    maximum_intents_be: row.get(20)?,
                    maximum_intent_bytes_be: row.get(21)?,
                    maximum_database_bytes_be: row.get(22)?,
                    profile_checksum: row.get(23)?,
                    metadata_checksum: row.get(24)?,
                })
            },
        )
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("read schema1 metadata", error))?;
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM handoff_signer_metadata_v1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("count schema1 metadata", error))?;
    let journal_id = fixed_array_v1::<32>(&row.journal_id, "journal ID")?;
    let old_set = profile
        .old_validator_set()
        .try_cev0_bytes()
        .map_err(|_| HandoffSignerJournalErrorV1::MetadataMismatch)?;
    let new_set = profile
        .new_validator_set()
        .try_cev0_bytes()
        .map_err(|_| HandoffSignerJournalErrorV1::MetadataMismatch)?;
    let old_author = profile
        .old_validator_set()
        .validator(profile.author())
        .ok_or(HandoffSignerJournalErrorV1::MetadataMismatch)?;
    let decoded_old_set = decode_validator_set_v0_exact(&row.old_set_cev0)
        .map_err(|_| HandoffSignerJournalErrorV1::MetadataMismatch)?;
    let decoded_new_set = decode_validator_set_v0_exact(&row.new_set_cev0)
        .map_err(|_| HandoffSignerJournalErrorV1::MetadataMismatch)?;
    let decoded_old_parameters = decode_consensus_parameters_v0_exact(&row.old_parameters_cev0)
        .map_err(|_| HandoffSignerJournalErrorV1::MetadataMismatch)?;
    let decoded_new_parameters = decode_consensus_parameters_v0_exact(&row.new_parameters_cev0)
        .map_err(|_| HandoffSignerJournalErrorV1::MetadataMismatch)?;
    if count != 1
        || row.journal_schema != i64::from(JOURNAL_SCHEMA_VERSION_V1)
        || row.genesis_hash != profile.old_validator_set().genesis_hash().as_bytes()
        || row.chain_id != profile.old_validator_set().chain_id().as_bytes()
        || row.old_epoch_be != profile.old_validator_set().epoch().get().to_be_bytes()
        || row.new_epoch_be != profile.new_validator_set().epoch().get().to_be_bytes()
        || row.old_protocol_be
            != profile
                .old_validator_set()
                .protocol_version()
                .get()
                .to_be_bytes()
        || row.new_protocol_be
            != profile
                .new_validator_set()
                .protocol_version()
                .get()
                .to_be_bytes()
        || row.old_set_id != profile.old_validator_set().id().as_bytes()
        || row.new_set_id != profile.new_validator_set().id().as_bytes()
        || row.old_set_cev0 != old_set
        || row.new_set_cev0 != new_set
        || decoded_old_set != *profile.old_validator_set()
        || decoded_new_set != *profile.new_validator_set()
        || row.old_parameters_hash != profile.old_consensus_parameters().hash().as_bytes()
        || row.new_parameters_hash != profile.new_consensus_parameters().hash().as_bytes()
        || row.old_parameters_cev0 != profile.old_consensus_parameters().canonical_bytes()
        || row.new_parameters_cev0 != profile.new_consensus_parameters().canonical_bytes()
        || decoded_old_parameters != *profile.old_consensus_parameters()
        || decoded_new_parameters != *profile.new_consensus_parameters()
        || row.author != profile.author().as_bytes()
        || row.old_author_public_key != old_author.consensus_key().as_bytes()
        || row.signer_profile_ref != profile.signer_profile_ref()
        || row.external_scope != profile.external_watermark_scope()
        || row.maximum_intents_be != profile.maximum_intents().to_be_bytes()
        || row.maximum_intent_bytes_be != (profile.maximum_intent_bytes() as u64).to_be_bytes()
        || row.maximum_database_bytes_be != (profile.maximum_database_bytes() as u64).to_be_bytes()
        || row.profile_checksum != profile.profile_checksum()
        || row.metadata_checksum != metadata_checksum_v1(profile, journal_id)?
    {
        return Err(HandoffSignerJournalErrorV1::MetadataMismatch);
    }
    Ok(journal_id)
}

fn read_journal_id_v1(connection: &Connection) -> Result<[u8; 32], HandoffSignerJournalErrorV1> {
    let bytes: Vec<u8> = connection
        .query_row(
            "SELECT journal_id FROM handoff_signer_metadata_v1 WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("read schema1 journal ID", error))?;
    fixed_array_v1(&bytes, "journal ID")
}

fn read_head_v1(
    connection: &Connection,
    journal_id: [u8; 32],
) -> Result<JournalHeadV1, HandoffSignerJournalErrorV1> {
    let row: (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT active_sequence_be, active_chain_checksum, head_checksum
             FROM signer_head_v1 WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("read schema1 head", error))?;
    let count: i64 = connection
        .query_row("SELECT count(*) FROM signer_head_v1", [], |row| row.get(0))
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("count schema1 head", error))?;
    let head = JournalHeadV1 {
        sequence: decode_u64_v1(&row.0, "head sequence")?,
        chain_checksum: fixed_array_v1(&row.1, "head chain checksum")?,
    };
    if count != 1
        || fixed_array_v1::<32>(&row.2, "head checksum")? != head_checksum_v1(journal_id, head)
    {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed("schema1 head checksum"),
        );
    }
    Ok(head)
}

#[allow(clippy::type_complexity)]
fn read_accounting_v1(
    connection: &Connection,
) -> Result<AccountingV1, HandoffSignerJournalErrorV1> {
    let row: (
        i64,
        i64,
        i64,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    ) = connection
        .query_row(
            "SELECT intent_count, event_count, intent_bytes,
                    maximum_safety_revision_be, maximum_vote_view_be,
                    maximum_timeout_view_be
             FROM signer_accounting_v1 WHERE singleton=1",
            [],
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
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("read schema1 accounting", error))?;
    if row.0 < 0 || row.1 < 0 || row.2 < 0 {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "negative schema1 accounting",
            ),
        );
    }
    Ok(AccountingV1 {
        intent_count: row.0 as u64,
        event_count: row.1 as u64,
        intent_bytes: row.2 as u64,
        maximum_safety_revision: decode_optional_u64_v1(row.3, "maximum safety revision")?,
        maximum_vote_view: decode_optional_u64_v1(row.4, "maximum vote view")?,
        maximum_timeout_view: decode_optional_u64_v1(row.5, "maximum timeout view")?,
    })
}

fn require_capacity_for_v1(
    accounting: &AccountingV1,
    profile: &HandoffSignerJournalProfileV1,
    incoming_bytes: usize,
) -> Result<(), HandoffSignerJournalErrorV1> {
    if accounting.intent_count >= profile.maximum_intents()
        || accounting
            .intent_bytes
            .checked_add(incoming_bytes as u64)
            .is_none()
    {
        return Err(HandoffSignerJournalErrorV1::CapacityExhausted);
    }
    Ok(())
}

#[allow(clippy::type_complexity)]
fn insert_intent_v1(
    transaction: &Transaction<'_>,
    intent: &PreparedIntentV1,
) -> Result<(), HandoffSignerJournalErrorV1> {
    let (
        epoch,
        view,
        kind,
        revision,
        genesis,
        old_epoch,
        new_epoch,
        role,
        validator,
        descriptor_digest,
        descriptor_cev0,
        admission_digest,
    ): (
        Option<[u8; 8]>,
        Option<[u8; 8]>,
        Option<i64>,
        Option<[u8; 8]>,
        Option<&[u8]>,
        Option<[u8; 8]>,
        Option<[u8; 8]>,
        Option<i64>,
        Option<&[u8]>,
        Option<&[u8]>,
        Option<&[u8]>,
        Option<&[u8]>,
    ) = match &intent.fields {
        PreparedFieldsV1::Consensus {
            epoch,
            view,
            kind,
            safety_revision,
        } => (
            Some(epoch.to_be_bytes()),
            Some(view.to_be_bytes()),
            Some(i64::from(*kind)),
            Some(safety_revision.to_be_bytes()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        PreparedFieldsV1::Handoff {
            genesis_hash,
            old_epoch,
            new_epoch,
            role,
            validator_id,
            descriptor_digest,
            descriptor_cev0,
            admission_digest,
        } => (
            None,
            None,
            None,
            None,
            Some(genesis_hash),
            Some(old_epoch.to_be_bytes()),
            Some(new_epoch.to_be_bytes()),
            Some(i64::from(*role)),
            Some(validator_id),
            Some(descriptor_digest),
            Some(descriptor_cev0),
            Some(admission_digest),
        ),
    };
    let changed = transaction
        .execute(
            "INSERT INTO signer_intents_v1(
                fingerprint, intent_class, signing_root, canonical_intent,
                intent_checksum, epoch_be, view_be, intent_kind,
                safety_revision_be, genesis_hash, old_epoch_be, new_epoch_be,
                handoff_role, validator_id, descriptor_digest, descriptor_cev0,
                admission_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                       ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                intent.fingerprint.as_slice(),
                i64::from(intent.class),
                intent.signing_root.as_slice(),
                intent.canonical_intent,
                intent.intent_checksum.as_slice(),
                epoch.as_ref().map(|value| value.as_slice()),
                view.as_ref().map(|value| value.as_slice()),
                kind,
                revision.as_ref().map(|value| value.as_slice()),
                genesis,
                old_epoch.as_ref().map(|value| value.as_slice()),
                new_epoch.as_ref().map(|value| value.as_slice()),
                role,
                validator,
                descriptor_digest,
                descriptor_cev0,
                admission_digest,
            ],
        )
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("insert schema1 intent", error))?;
    if changed != 1 {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "schema1 intent insert count",
            ),
        );
    }
    Ok(())
}

#[derive(Debug)]
struct RawIntentRowV1 {
    fingerprint: Vec<u8>,
    class: i64,
    signing_root: Vec<u8>,
    canonical_intent: Vec<u8>,
    intent_checksum: Vec<u8>,
    epoch: Option<Vec<u8>>,
    view: Option<Vec<u8>>,
    kind: Option<i64>,
    revision: Option<Vec<u8>>,
    genesis: Option<Vec<u8>>,
    old_epoch: Option<Vec<u8>>,
    new_epoch: Option<Vec<u8>>,
    role: Option<i64>,
    validator: Option<Vec<u8>>,
    descriptor_digest: Option<Vec<u8>>,
    descriptor_cev0: Option<Vec<u8>>,
    admission_digest: Option<Vec<u8>>,
}

fn raw_intent_from_row_v1(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawIntentRowV1> {
    Ok(RawIntentRowV1 {
        fingerprint: row.get(0)?,
        class: row.get(1)?,
        signing_root: row.get(2)?,
        canonical_intent: row.get(3)?,
        intent_checksum: row.get(4)?,
        epoch: row.get(5)?,
        view: row.get(6)?,
        kind: row.get(7)?,
        revision: row.get(8)?,
        genesis: row.get(9)?,
        old_epoch: row.get(10)?,
        new_epoch: row.get(11)?,
        role: row.get(12)?,
        validator: row.get(13)?,
        descriptor_digest: row.get(14)?,
        descriptor_cev0: row.get(15)?,
        admission_digest: row.get(16)?,
    })
}

const SELECT_INTENT_V1: &str = "SELECT fingerprint, intent_class, signing_root, canonical_intent,
            intent_checksum, epoch_be, view_be, intent_kind,
            safety_revision_be, genesis_hash, old_epoch_be, new_epoch_be,
            handoff_role, validator_id, descriptor_digest, descriptor_cev0,
            admission_digest
     FROM signer_intents_v1";

fn admit_raw_intent_v1(
    raw: RawIntentRowV1,
) -> Result<PreparedIntentV1, HandoffSignerJournalErrorV1> {
    let class = u8::try_from(raw.class).map_err(|_| {
        HandoffSignerJournalErrorV1::PersistedRepresentationMalformed("intent class")
    })?;
    let fields = match class {
        CLASS_CONSENSUS => PreparedFieldsV1::Consensus {
            epoch: decode_required_u64_v1(raw.epoch, "intent epoch")?,
            view: decode_required_u64_v1(raw.view, "intent view")?,
            kind: u8::try_from(raw.kind.ok_or(
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed("intent kind"),
            )?)
            .map_err(|_| {
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed("intent kind")
            })?,
            safety_revision: decode_required_u64_v1(raw.revision, "safety revision")?,
        },
        CLASS_HANDOFF => PreparedFieldsV1::Handoff {
            genesis_hash: fixed_required_array_v1(raw.genesis, "handoff genesis")?,
            old_epoch: decode_required_u64_v1(raw.old_epoch, "handoff old epoch")?,
            new_epoch: decode_required_u64_v1(raw.new_epoch, "handoff new epoch")?,
            role: u8::try_from(raw.role.ok_or(
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed("handoff role"),
            )?)
            .map_err(|_| {
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed("handoff role")
            })?,
            validator_id: raw.validator.ok_or(
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed("handoff validator"),
            )?,
            descriptor_digest: fixed_required_array_v1(
                raw.descriptor_digest,
                "handoff descriptor digest",
            )?,
            descriptor_cev0: raw.descriptor_cev0.ok_or(
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                    "handoff descriptor bytes",
                ),
            )?,
            admission_digest: fixed_required_array_v1(
                raw.admission_digest,
                "handoff admission digest",
            )?,
        },
        _ => {
            return Err(
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                    "unknown intent class",
                ),
            );
        }
    };
    let intent = PreparedIntentV1 {
        fingerprint: fixed_array_v1(&raw.fingerprint, "intent fingerprint")?,
        class,
        signing_root: fixed_array_v1(&raw.signing_root, "intent signing root")?,
        canonical_intent: raw.canonical_intent,
        intent_checksum: fixed_array_v1(&raw.intent_checksum, "intent checksum")?,
        fields,
    };
    if intent.intent_checksum != compute_intent_checksum_v1(&intent) {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed("intent checksum"),
        );
    }
    Ok(intent)
}

fn read_intent_v1(
    connection: &Connection,
    fingerprint: [u8; 32],
) -> Result<Option<PreparedIntentV1>, HandoffSignerJournalErrorV1> {
    let sql = format!("{SELECT_INTENT_V1} WHERE fingerprint=?1");
    let raw = connection
        .query_row(
            &sql,
            params![fingerprint.as_slice()],
            raw_intent_from_row_v1,
        )
        .optional()
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("read schema1 intent", error))?;
    raw.map(admit_raw_intent_v1).transpose()
}

fn read_all_intents_v1(
    connection: &Connection,
) -> Result<BTreeMap<[u8; 32], PreparedIntentV1>, HandoffSignerJournalErrorV1> {
    let mut statement = connection
        .prepare(&format!("{SELECT_INTENT_V1} ORDER BY fingerprint"))
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("prepare schema1 intents", error))?;
    let rows = statement
        .query_map([], raw_intent_from_row_v1)
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("query schema1 intents", error))?;
    let mut intents = BTreeMap::new();
    for row in rows {
        let intent = admit_raw_intent_v1(row.map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("read schema1 intent row", error)
        })?)?;
        if intents.insert(intent.fingerprint, intent).is_some() {
            return Err(
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                    "duplicate schema1 intent fingerprint",
                ),
            );
        }
    }
    Ok(intents)
}

fn require_exact_intent_v1(
    stored: &PreparedIntentV1,
    requested: &PreparedIntentV1,
) -> Result<(), HandoffSignerJournalErrorV1> {
    if stored != requested {
        return Err(HandoffSignerJournalErrorV1::Conflict(
            match &requested.fields {
                PreparedFieldsV1::Consensus {
                    epoch, view, kind, ..
                } => HandoffSignerJournalConflictV1::SameRoundDifferentIntent {
                    epoch: *epoch,
                    view: *view,
                    kind: *kind,
                },
                PreparedFieldsV1::Handoff {
                    old_epoch,
                    new_epoch,
                    role,
                    ..
                } => HandoffSignerJournalConflictV1::HandoffTransitionDifferentIntent {
                    old_epoch: *old_epoch,
                    new_epoch: *new_epoch,
                    role: *role,
                },
            },
        ));
    }
    Ok(())
}

fn insert_event_v1(
    transaction: &Transaction<'_>,
    event: &StoredEventV1,
) -> Result<(), HandoffSignerJournalErrorV1> {
    let changed = transaction
        .execute(
            "INSERT INTO signer_events_v1(
                sequence_be, event_kind, fingerprint, signature,
                predecessor_sequence_be, predecessor_chain_checksum,
                event_checksum, chain_checksum
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                event.sequence.to_be_bytes().as_slice(),
                i64::from(event.kind),
                event.fingerprint.as_slice(),
                event.signature.as_ref().map(|value| value.as_slice()),
                event.predecessor_sequence.to_be_bytes().as_slice(),
                event.predecessor_chain_checksum.as_slice(),
                event.event_checksum.as_slice(),
                event.chain_checksum.as_slice(),
            ],
        )
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("insert schema1 event", error))?;
    if changed != 1 {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "schema1 event insert count",
            ),
        );
    }
    Ok(())
}

fn update_head_v1(
    transaction: &Transaction<'_>,
    journal_id: [u8; 32],
    event: &StoredEventV1,
) -> Result<(), HandoffSignerJournalErrorV1> {
    let target = JournalHeadV1 {
        sequence: event.sequence,
        chain_checksum: event.chain_checksum,
    };
    let changed = transaction
        .execute(
            "UPDATE signer_head_v1
             SET active_sequence_be=?1, active_chain_checksum=?2, head_checksum=?3
             WHERE singleton=1 AND active_sequence_be=?4 AND active_chain_checksum=?5",
            params![
                target.sequence.to_be_bytes().as_slice(),
                target.chain_checksum.as_slice(),
                head_checksum_v1(journal_id, target).as_slice(),
                event.predecessor_sequence.to_be_bytes().as_slice(),
                event.predecessor_chain_checksum.as_slice(),
            ],
        )
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("advance schema1 head", error))?;
    if changed != 1 {
        return Err(HandoffSignerJournalErrorV1::Conflict(
            HandoffSignerJournalConflictV1::CommitReadbackConflict,
        ));
    }
    Ok(())
}

fn update_accounting_prepared_v1(
    transaction: &Transaction<'_>,
    intent: &PreparedIntentV1,
) -> Result<(), HandoffSignerJournalErrorV1> {
    let current = read_accounting_v1(transaction)?;
    let intent_count = current
        .intent_count
        .checked_add(1)
        .ok_or(HandoffSignerJournalErrorV1::CapacityExhausted)?;
    let event_count = current
        .event_count
        .checked_add(1)
        .ok_or(HandoffSignerJournalErrorV1::CapacityExhausted)?;
    let intent_bytes = current
        .intent_bytes
        .checked_add(intent.canonical_intent.len() as u64)
        .ok_or(HandoffSignerJournalErrorV1::CapacityExhausted)?;
    let (maximum_safety_revision, maximum_vote_view, maximum_timeout_view) = match &intent.fields {
        PreparedFieldsV1::Consensus {
            view,
            kind,
            safety_revision,
            ..
        } => (
            Some(
                current
                    .maximum_safety_revision
                    .map_or(*safety_revision, |value| value.max(*safety_revision)),
            ),
            if *kind == 1 {
                Some(
                    current
                        .maximum_vote_view
                        .map_or(*view, |value| value.max(*view)),
                )
            } else {
                current.maximum_vote_view
            },
            if *kind == 2 {
                Some(
                    current
                        .maximum_timeout_view
                        .map_or(*view, |value| value.max(*view)),
                )
            } else {
                current.maximum_timeout_view
            },
        ),
        PreparedFieldsV1::Handoff { .. } => (
            current.maximum_safety_revision,
            current.maximum_vote_view,
            current.maximum_timeout_view,
        ),
    };
    let changed = transaction
        .execute(
            "UPDATE signer_accounting_v1 SET
                intent_count=?1, event_count=?2, intent_bytes=?3,
                maximum_safety_revision_be=?4, maximum_vote_view_be=?5,
                maximum_timeout_view_be=?6 WHERE singleton=1",
            params![
                i64::try_from(intent_count)
                    .map_err(|_| HandoffSignerJournalErrorV1::CapacityExhausted)?,
                i64::try_from(event_count)
                    .map_err(|_| HandoffSignerJournalErrorV1::CapacityExhausted)?,
                i64::try_from(intent_bytes)
                    .map_err(|_| HandoffSignerJournalErrorV1::CapacityExhausted)?,
                maximum_safety_revision.map(|value| value.to_be_bytes()),
                maximum_vote_view.map(|value| value.to_be_bytes()),
                maximum_timeout_view.map(|value| value.to_be_bytes()),
            ],
        )
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("update schema1 prepared accounting", error)
        })?;
    if changed != 1 {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "schema1 accounting update count",
            ),
        );
    }
    Ok(())
}

fn update_accounting_signed_v1(
    transaction: &Transaction<'_>,
) -> Result<(), HandoffSignerJournalErrorV1> {
    let current = read_accounting_v1(transaction)?;
    let event_count = current
        .event_count
        .checked_add(1)
        .ok_or(HandoffSignerJournalErrorV1::CapacityExhausted)?;
    let changed = transaction
        .execute(
            "UPDATE signer_accounting_v1 SET event_count=?1 WHERE singleton=1",
            params![i64::try_from(event_count)
                .map_err(|_| HandoffSignerJournalErrorV1::CapacityExhausted)?],
        )
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("update schema1 signed accounting", error)
        })?;
    if changed != 1 {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "schema1 signed accounting update count",
            ),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn fence_checksum_v1(
    profile: &HandoffSignerJournalProfileV1,
    genesis_hash: [u8; 32],
    old_epoch: u64,
    new_epoch: u64,
    validator_id: &[u8],
    descriptor_digest: [u8; 32],
    fingerprint: [u8; 32],
    signature_sequence: u64,
) -> [u8; 32] {
    hash_domain(
        FENCE_DOMAIN_V1,
        &[
            &profile.profile_checksum(),
            &genesis_hash,
            &old_epoch.to_be_bytes(),
            &new_epoch.to_be_bytes(),
            validator_id,
            &descriptor_digest,
            &fingerprint,
            &signature_sequence.to_be_bytes(),
        ],
    )
}

fn insert_terminal_fence_v1(
    transaction: &Transaction<'_>,
    profile: &HandoffSignerJournalProfileV1,
    intent: &PreparedIntentV1,
    signature_sequence: u64,
) -> Result<(), HandoffSignerJournalErrorV1> {
    let PreparedFieldsV1::Handoff {
        genesis_hash,
        old_epoch,
        new_epoch,
        role,
        validator_id,
        descriptor_digest,
        ..
    } = &intent.fields
    else {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "terminal fence requires handoff intent",
            ),
        );
    };
    if *role != HandoffSignerRoleV1::OldSet as u8 {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "terminal fence requires old-set role",
            ),
        );
    }
    let checksum = fence_checksum_v1(
        profile,
        *genesis_hash,
        *old_epoch,
        *new_epoch,
        validator_id,
        *descriptor_digest,
        intent.fingerprint,
        signature_sequence,
    );
    let changed = transaction
        .execute(
            "INSERT INTO terminal_old_epoch_fence_v1(
                singleton, genesis_hash, old_epoch_be, new_epoch_be,
                validator_id, descriptor_digest, fingerprint,
                signature_sequence_be, fence_checksum
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                genesis_hash.as_slice(),
                old_epoch.to_be_bytes().as_slice(),
                new_epoch.to_be_bytes().as_slice(),
                validator_id,
                descriptor_digest.as_slice(),
                intent.fingerprint.as_slice(),
                signature_sequence.to_be_bytes().as_slice(),
                checksum.as_slice(),
            ],
        )
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("insert terminal old-epoch fence", error)
        })?;
    if changed != 1 {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "terminal fence insert count",
            ),
        );
    }
    Ok(())
}

fn terminal_fence_exists_v1(connection: &Connection) -> Result<bool, HandoffSignerJournalErrorV1> {
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM terminal_old_epoch_fence_v1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("count terminal fence", error))?;
    match count {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "multiple terminal fences",
            ),
        ),
    }
}

#[allow(clippy::type_complexity)]
fn raw_event_from_row_v1(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(
    Vec<u8>,
    i64,
    Vec<u8>,
    Option<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
)> {
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
}

#[allow(clippy::type_complexity)]
fn admit_raw_event_v1(
    raw: (
        Vec<u8>,
        i64,
        Vec<u8>,
        Option<Vec<u8>>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ),
) -> Result<StoredEventV1, HandoffSignerJournalErrorV1> {
    let kind = u8::try_from(raw.1)
        .map_err(|_| HandoffSignerJournalErrorV1::PersistedRepresentationMalformed("event kind"))?;
    let signature = raw
        .3
        .map(|bytes| fixed_array_v1::<64>(&bytes, "event signature"))
        .transpose()?;
    if (kind == EVENT_PREPARED && signature.is_some())
        || (kind == EVENT_SIGNED && signature.is_none())
        || kind > EVENT_SIGNED
    {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "event lifecycle/signature relation",
            ),
        );
    }
    Ok(StoredEventV1 {
        sequence: decode_u64_v1(&raw.0, "event sequence")?,
        kind,
        fingerprint: fixed_array_v1(&raw.2, "event fingerprint")?,
        signature,
        predecessor_sequence: decode_u64_v1(&raw.4, "event predecessor sequence")?,
        predecessor_chain_checksum: fixed_array_v1(&raw.5, "event predecessor checksum")?,
        event_checksum: fixed_array_v1(&raw.6, "event checksum")?,
        chain_checksum: fixed_array_v1(&raw.7, "event chain checksum")?,
    })
}

fn read_event_v1(
    connection: &Connection,
    sequence: u64,
) -> Result<Option<StoredEventV1>, HandoffSignerJournalErrorV1> {
    let raw = connection
        .query_row(
            "SELECT sequence_be, event_kind, fingerprint, signature,
                    predecessor_sequence_be, predecessor_chain_checksum,
                    event_checksum, chain_checksum
             FROM signer_events_v1 WHERE sequence_be=?1",
            params![sequence.to_be_bytes().as_slice()],
            raw_event_from_row_v1,
        )
        .optional()
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("read schema1 event", error))?;
    raw.map(admit_raw_event_v1).transpose()
}

fn read_all_events_v1(
    connection: &Connection,
) -> Result<Vec<StoredEventV1>, HandoffSignerJournalErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT sequence_be, event_kind, fingerprint, signature,
                    predecessor_sequence_be, predecessor_chain_checksum,
                    event_checksum, chain_checksum
             FROM signer_events_v1 ORDER BY sequence_be",
        )
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("prepare schema1 events", error))?;
    let rows = statement
        .query_map([], raw_event_from_row_v1)
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("query schema1 events", error))?;
    let mut events = Vec::new();
    for row in rows {
        events.push(admit_raw_event_v1(row.map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("read schema1 event row", error)
        })?)?);
    }
    Ok(events)
}

fn pending_fingerprint_v1(
    connection: &Connection,
) -> Result<Option<[u8; 32]>, HandoffSignerJournalErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT prepared.fingerprint
             FROM signer_events_v1 AS prepared
             LEFT JOIN signer_events_v1 AS signed
               ON signed.fingerprint=prepared.fingerprint AND signed.event_kind=1
             WHERE prepared.event_kind=0 AND signed.fingerprint IS NULL
             ORDER BY prepared.sequence_be",
        )
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("prepare pending schema1 intent", error)
        })?;
    let rows = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("query pending schema1 intent", error)
        })?;
    let mut pending = None;
    for row in rows {
        let fingerprint = fixed_array_v1::<32>(
            &row.map_err(|error| {
                HandoffSignerJournalErrorV1::sqlite("read pending schema1 intent", error)
            })?,
            "pending fingerprint",
        )?;
        if pending.replace(fingerprint).is_some() {
            return Err(
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                    "multiple pending schema1 intents",
                ),
            );
        }
    }
    Ok(pending)
}

fn verify_signature_for_intent_v1(
    profile: &HandoffSignerJournalProfileV1,
    intent: &PreparedIntentV1,
    signature: [u8; 64],
) -> Result<SignatureBytes, HandoffSignerJournalErrorV1> {
    let signature = SignatureBytes::from_array(signature);
    let validator = match &intent.fields {
        PreparedFieldsV1::Consensus { .. } => {
            profile.old_validator_set().validator(profile.author())
        }
        PreparedFieldsV1::Handoff { role, .. } if *role == HandoffSignerRoleV1::OldSet as u8 => {
            profile.old_validator_set().validator(profile.author())
        }
        PreparedFieldsV1::Handoff { .. } => {
            return Err(HandoffSignerJournalErrorV1::NewSetAdmissionUnavailable);
        }
    }
    .ok_or(HandoffSignerJournalErrorV1::MetadataMismatch)?;
    if !StrictEd25519Verifier.verify(
        validator,
        &trnm_consensus_types::SigningRoot::new(intent.signing_root),
        &signature,
    ) {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "persisted signature does not verify",
            ),
        );
    }
    Ok(signature)
}

fn read_persisted_signature_v1(
    connection: &Connection,
    fingerprint: [u8; 32],
    profile: &HandoffSignerJournalProfileV1,
) -> Result<Option<SignatureBytes>, HandoffSignerJournalErrorV1> {
    let bytes: Option<Vec<u8>> = connection
        .query_row(
            "SELECT signature FROM signer_events_v1
             WHERE fingerprint=?1 AND event_kind=1",
            params![fingerprint.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("read persisted schema1 signature", error)
        })?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let signature = fixed_array_v1::<64>(&bytes, "persisted signature")?;
    let intent = read_intent_v1(connection, fingerprint)?.ok_or(
        HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
            "signature references missing intent",
        ),
    )?;
    Ok(Some(verify_signature_for_intent_v1(
        profile, &intent, signature,
    )?))
}

fn require_head_readback_v1(
    connection: &Connection,
    journal_id: [u8; 32],
    expected: JournalHeadV1,
) -> Result<(), HandoffSignerJournalErrorV1> {
    if read_head_v1(connection, journal_id)? != expected {
        return Err(HandoffSignerJournalErrorV1::Conflict(
            HandoffSignerJournalConflictV1::CommitReadbackConflict,
        ));
    }
    Ok(())
}

fn validate_intent_semantics_v1(
    intent: &PreparedIntentV1,
    profile: &HandoffSignerJournalProfileV1,
) -> Result<(), HandoffSignerJournalErrorV1> {
    match &intent.fields {
        PreparedFieldsV1::Consensus {
            epoch,
            view,
            kind,
            safety_revision,
        } => {
            let decoded = decode_canonical_sign_intent_v0_exact(
                &intent.canonical_intent,
                profile.old_validator_set(),
            )
            .map_err(|_| {
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                    "exact consensus intent decode",
                )
            })?;
            decoded.validate(profile.old_validator_set()).map_err(|_| {
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                    "persisted consensus intent validation",
                )
            })?;
            let context = decoded.preimage().context();
            let decoded_kind = match context.message_kind() {
                MessageKind::Vote => 1,
                MessageKind::Timeout => 2,
                _ => {
                    return Err(
                        HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                            "persisted normal intent kind",
                        ),
                    );
                }
            };
            if intent.class != CLASS_CONSENSUS
                || decoded.author() != profile.author()
                || decoded.epoch() != profile.old_validator_set().epoch()
                || decoded.validator_set_id() != profile.old_validator_set().id()
                || *epoch != decoded.epoch().get()
                || *view != context.view().get()
                || *kind != decoded_kind
                || *safety_revision != decoded.authorizing_safety_revision()
                || intent.fingerprint != *decoded.fingerprint().as_bytes()
                || intent.signing_root != *decoded.signing_root().as_bytes()
                || decoded.canonical_bytes().map_err(|_| {
                    HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                        "re-encode persisted consensus intent",
                    )
                })? != intent.canonical_intent
            {
                return Err(
                    HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                        "persisted consensus intent fields",
                    ),
                );
            }
        }
        PreparedFieldsV1::Handoff {
            genesis_hash,
            old_epoch,
            new_epoch,
            role,
            validator_id,
            descriptor_digest,
            descriptor_cev0,
            admission_digest,
        } => {
            let decoded = decode_canonical_handoff_sign_intent_v1_exact(
                &intent.canonical_intent,
                profile.old_validator_set(),
                profile.new_validator_set(),
                profile.old_consensus_parameters(),
                profile.new_consensus_parameters(),
            )
            .map_err(|_| {
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                    "exact handoff intent decode",
                )
            })?;
            decoded
                .validate(
                    profile.old_validator_set(),
                    profile.new_validator_set(),
                    profile.old_consensus_parameters(),
                    profile.new_consensus_parameters(),
                )
                .map_err(|_| {
                    HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                        "persisted handoff intent validation",
                    )
                })?;
            let descriptor = decode_handoff_descriptor_v0_exact(descriptor_cev0).map_err(|_| {
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                    "exact persisted handoff descriptor decode",
                )
            })?;
            if intent.class != CLASS_HANDOFF
                || decoded.signer_role() != HandoffSignerRoleV1::OldSet
                || *role != HandoffSignerRoleV1::OldSet as u8
                || decoded.validator_id() != profile.author()
                || validator_id != profile.author().as_bytes()
                || *genesis_hash != *decoded.preimage().genesis_hash().as_bytes()
                || *old_epoch != decoded.preimage().old_epoch().get()
                || *new_epoch != decoded.preimage().new_epoch().get()
                || *descriptor_digest != *decoded.preimage().descriptor_digest().as_bytes()
                || descriptor != *decoded.preimage().descriptor()
                || descriptor.try_cev0_bytes().map_err(|_| {
                    HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                        "re-encode persisted handoff descriptor",
                    )
                })? != *descriptor_cev0
                || *admission_digest == [0; 32]
                || intent.fingerprint != *decoded.fingerprint().as_bytes()
                || intent.signing_root != *decoded.signing_root().as_bytes()
                || decoded.canonical_bytes().map_err(|_| {
                    HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                        "re-encode persisted handoff intent",
                    )
                })? != intent.canonical_intent
            {
                return Err(
                    HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                        "persisted handoff intent fields",
                    ),
                );
            }
        }
    }
    if intent.intent_checksum != compute_intent_checksum_v1(intent) {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "persisted intent checksum",
            ),
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TerminalFenceV1 {
    genesis_hash: [u8; 32],
    old_epoch: u64,
    new_epoch: u64,
    validator_id: Vec<u8>,
    descriptor_digest: [u8; 32],
    fingerprint: [u8; 32],
    signature_sequence: u64,
    fence_checksum: [u8; 32],
}

#[allow(clippy::type_complexity)]
fn read_terminal_fence_v1(
    connection: &Connection,
) -> Result<Option<TerminalFenceV1>, HandoffSignerJournalErrorV1> {
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM terminal_old_epoch_fence_v1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("count terminal old-epoch fence", error)
        })?;
    if count == 0 {
        return Ok(None);
    }
    if count != 1 {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "terminal fence row count",
            ),
        );
    }
    let raw: (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) = connection
        .query_row(
            "SELECT genesis_hash, old_epoch_be, new_epoch_be, validator_id,
                    descriptor_digest, fingerprint, signature_sequence_be,
                    fence_checksum
             FROM terminal_old_epoch_fence_v1 WHERE singleton=1",
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
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("read terminal fence", error))?;
    Ok(Some(TerminalFenceV1 {
        genesis_hash: fixed_array_v1(&raw.0, "fence genesis")?,
        old_epoch: decode_u64_v1(&raw.1, "fence old epoch")?,
        new_epoch: decode_u64_v1(&raw.2, "fence new epoch")?,
        validator_id: raw.3,
        descriptor_digest: fixed_array_v1(&raw.4, "fence descriptor digest")?,
        fingerprint: fixed_array_v1(&raw.5, "fence fingerprint")?,
        signature_sequence: decode_u64_v1(&raw.6, "fence signature sequence")?,
        fence_checksum: fixed_array_v1(&raw.7, "fence checksum")?,
    }))
}

fn validate_database_v1(
    connection: &Connection,
    database_file: &File,
    profile: &HandoffSignerJournalProfileV1,
    journal_id: [u8; 32],
    allowed_pending: Option<[u8; 32]>,
) -> Result<(), HandoffSignerJournalErrorV1> {
    validate_transaction_environment_v1(connection, profile.maximum_database_bytes())?;
    validate_canonical_schema_v1(connection)?;
    if read_and_validate_metadata_v1(connection, profile)? != journal_id {
        return Err(HandoffSignerJournalErrorV1::MetadataMismatch);
    }
    validate_integrity_v1(connection)?;

    let intents = read_all_intents_v1(connection)?;
    for intent in intents.values() {
        validate_intent_semantics_v1(intent, profile)?;
    }
    let events = read_all_events_v1(connection)?;
    let mut lifecycle = BTreeMap::<[u8; 32], u8>::new();
    let mut expected_head = initial_head_v1(profile, journal_id);
    let mut maximum_safety_revision = None;
    let mut maximum_vote_view = None;
    let mut maximum_timeout_view = None;
    let mut pending = None;
    let mut signed_old_handoff = None;

    for event in &events {
        let intent = intents.get(&event.fingerprint).ok_or(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "event references absent intent",
            ),
        )?;
        let recomputed = make_event_v1(expected_head, event.kind, intent, event.signature)?;
        if recomputed != *event {
            return Err(
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                    "event chain or checksum",
                ),
            );
        }
        match event.kind {
            EVENT_PREPARED => {
                if pending.is_some() {
                    return Err(
                        HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                            "multiple globally pending prepared intents",
                        ),
                    );
                }
                if lifecycle
                    .insert(event.fingerprint, EVENT_PREPARED)
                    .is_some()
                {
                    return Err(
                        HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                            "duplicate prepared lifecycle event",
                        ),
                    );
                }
                if let PreparedFieldsV1::Consensus {
                    view,
                    kind,
                    safety_revision,
                    ..
                } = &intent.fields
                {
                    if maximum_safety_revision.is_some_and(|maximum| *safety_revision <= maximum) {
                        return Err(
                            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                                "non-monotonic persisted safety revision",
                            ),
                        );
                    }
                    maximum_safety_revision = Some(*safety_revision);
                    let maximum_view = if *kind == 1 {
                        &mut maximum_vote_view
                    } else {
                        &mut maximum_timeout_view
                    };
                    if maximum_view.is_some_and(|maximum| *view <= maximum) {
                        return Err(
                            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                                "non-monotonic persisted message view",
                            ),
                        );
                    }
                    *maximum_view = Some(*view);
                }
                pending = Some(event.fingerprint);
            }
            EVENT_SIGNED => {
                if lifecycle.get(&event.fingerprint) != Some(&EVENT_PREPARED) {
                    return Err(
                        HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                            "signed event lacks exact prepared predecessor",
                        ),
                    );
                }
                lifecycle.insert(event.fingerprint, EVENT_SIGNED);
                if pending != Some(event.fingerprint) {
                    return Err(
                        HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                            "signed event is not the global pending intent",
                        ),
                    );
                }
                pending = None;
                verify_signature_for_intent_v1(
                    profile,
                    intent,
                    event.signature.ok_or(
                        HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                            "signed event signature",
                        ),
                    )?,
                )?;
                if matches!(
                    &intent.fields,
                    PreparedFieldsV1::Handoff {
                        role,
                        ..
                    } if *role == HandoffSignerRoleV1::OldSet as u8
                ) && signed_old_handoff
                    .replace((event.fingerprint, event.sequence))
                    .is_some()
                {
                    return Err(
                        HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                            "multiple signed old-set handoffs",
                        ),
                    );
                }
            }
            _ => {
                return Err(
                    HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                        "unknown event kind",
                    ),
                );
            }
        }
        expected_head = JournalHeadV1 {
            sequence: event.sequence,
            chain_checksum: event.chain_checksum,
        };
    }

    if lifecycle.len() != intents.len()
        || intents
            .keys()
            .any(|fingerprint| !lifecycle.contains_key(fingerprint))
    {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "intent/event lifecycle coverage",
            ),
        );
    }
    match (pending, allowed_pending) {
        (None, None) => {}
        (Some(actual), Some(allowed)) if actual == allowed => {
            if events.last().map(|event| (event.kind, event.fingerprint))
                != Some((EVENT_PREPARED, actual))
            {
                return Err(
                    HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                        "pending intent is not the exact tail",
                    ),
                );
            }
        }
        _ => {
            return Err(HandoffSignerJournalErrorV1::Conflict(
                HandoffSignerJournalConflictV1::PreparedIntentPending,
            ));
        }
    }

    let intent_bytes = intents.values().try_fold(0u64, |total, intent| {
        total
            .checked_add(intent.canonical_intent.len() as u64)
            .ok_or(HandoffSignerJournalErrorV1::CapacityExhausted)
    })?;
    let recomputed_accounting = AccountingV1 {
        intent_count: intents.len() as u64,
        event_count: events.len() as u64,
        intent_bytes,
        maximum_safety_revision,
        maximum_vote_view,
        maximum_timeout_view,
    };
    let stored_accounting = read_accounting_v1(connection)?;
    let accounting_rows: i64 = connection
        .query_row("SELECT count(*) FROM signer_accounting_v1", [], |row| {
            row.get(0)
        })
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("count schema1 accounting rows", error)
        })?;
    if accounting_rows != 1 || stored_accounting != recomputed_accounting {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "schema1 recomputed accounting",
            ),
        );
    }
    if recomputed_accounting.intent_count > profile.maximum_intents()
        || intents
            .values()
            .any(|intent| intent.canonical_intent.len() > profile.maximum_intent_bytes())
    {
        return Err(HandoffSignerJournalErrorV1::CapacityExhausted);
    }
    if read_head_v1(connection, journal_id)? != expected_head {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "schema1 recomputed head",
            ),
        );
    }

    let fence = read_terminal_fence_v1(connection)?;
    match (signed_old_handoff, fence) {
        (None, None) => {}
        (Some((fingerprint, signature_sequence)), Some(fence)) => {
            let intent = intents.get(&fingerprint).ok_or(
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                    "terminal fence intent",
                ),
            )?;
            let PreparedFieldsV1::Handoff {
                genesis_hash,
                old_epoch,
                new_epoch,
                role,
                validator_id,
                descriptor_digest,
                ..
            } = &intent.fields
            else {
                return Err(
                    HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                        "terminal fence class",
                    ),
                );
            };
            let expected_checksum = fence_checksum_v1(
                profile,
                *genesis_hash,
                *old_epoch,
                *new_epoch,
                validator_id,
                *descriptor_digest,
                fingerprint,
                signature_sequence,
            );
            if *role != HandoffSignerRoleV1::OldSet as u8
                || fence.genesis_hash != *genesis_hash
                || fence.old_epoch != *old_epoch
                || fence.new_epoch != *new_epoch
                || fence.validator_id != *validator_id
                || fence.descriptor_digest != *descriptor_digest
                || fence.fingerprint != fingerprint
                || fence.signature_sequence != signature_sequence
                || fence.fence_checksum != expected_checksum
                || signature_sequence != expected_head.sequence
            {
                return Err(
                    HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                        "terminal old-epoch fence binding",
                    ),
                );
            }
        }
        _ => {
            return Err(
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                    "terminal fence/signature relation",
                ),
            );
        }
    }

    let length = database_file
        .metadata()
        .map_err(|error| HandoffSignerJournalErrorV1::io("stat audited schema1 database", error))?
        .len();
    if length > profile.maximum_database_bytes() as u64 {
        return Err(HandoffSignerJournalErrorV1::CapacityExhausted);
    }
    Ok(())
}

fn validate_transaction_environment_v1(
    connection: &Connection,
    maximum_database_bytes: usize,
) -> Result<(), HandoffSignerJournalErrorV1> {
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("audit schema1 journal mode", error)
        })?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("audit schema1 synchronous", error))?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("audit schema1 foreign keys", error)
        })?;
    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("audit schema1 trusted schema", error)
        })?;
    let recursive_triggers: i64 = connection
        .query_row("PRAGMA recursive_triggers", [], |row| row.get(0))
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("audit schema1 recursive triggers", error)
        })?;
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("audit schema1 page size", error))?;
    let page_count: i64 = connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("audit schema1 page count", error))?;
    if !journal_mode.eq_ignore_ascii_case("delete")
        || synchronous != 2
        || foreign_keys != 1
        || trusted_schema != 0
        || recursive_triggers != 0
        || page_size <= 0
        || page_count < 0
        || (page_size as u64)
            .checked_mul(page_count as u64)
            .is_none_or(|bytes| bytes > maximum_database_bytes as u64)
    {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "schema1 transaction environment",
            ),
        );
    }
    Ok(())
}

fn validate_integrity_v1(connection: &Connection) -> Result<(), HandoffSignerJournalErrorV1> {
    let mut integrity = connection
        .prepare("PRAGMA integrity_check")
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("prepare schema1 integrity check", error)
        })?;
    let rows = integrity
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("run schema1 integrity check", error)
        })?;
    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("read schema1 integrity result", error)
        })?);
    }
    if results.as_slice() != ["ok"] {
        return Err(HandoffSignerJournalErrorV1::IntegrityFailure);
    }
    let mut foreign_keys = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("prepare schema1 foreign-key check", error)
        })?;
    if foreign_keys.exists([]).map_err(|error| {
        HandoffSignerJournalErrorV1::sqlite("run schema1 foreign-key check", error)
    })? {
        return Err(HandoffSignerJournalErrorV1::IntegrityFailure);
    }
    Ok(())
}

fn absolute_database_path(path: &Path) -> Result<PathBuf, HandoffSignerJournalErrorV1> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| HandoffSignerJournalErrorV1::io("resolve current directory", error))?
            .join(path)
    };
    let file_name = absolute
        .file_name()
        .ok_or(HandoffSignerJournalErrorV1::InvalidProfile(
            "database file name",
        ))?;
    let lower_name = file_name.to_string_lossy().to_ascii_lowercase();
    if ["-wal", "-shm", "-journal", ".signer.lock"]
        .iter()
        .any(|suffix| lower_name.ends_with(suffix))
    {
        return Err(HandoffSignerJournalErrorV1::InvalidProfile(
            "database name collides with SQLite or signer auxiliary namespace",
        ));
    }
    let parent = absolute
        .parent()
        .ok_or(HandoffSignerJournalErrorV1::InvalidProfile(
            "database parent",
        ))?;
    let parent = fs::canonicalize(parent).map_err(|error| {
        HandoffSignerJournalErrorV1::io("canonicalize schema1 parent directory", error)
    })?;
    validate_private_directory_v1(&parent)?;
    Ok(parent.join(file_name))
}

fn validate_private_directory_v1(path: &Path) -> Result<(), HandoffSignerJournalErrorV1> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path)
        .map_err(|error| HandoffSignerJournalErrorV1::io("stat schema1 directory", error))?;
    // SAFETY: `geteuid` accepts no pointer and touches no caller memory.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != effective_uid || metadata.mode() & 0o022 != 0 {
        return Err(HandoffSignerJournalErrorV1::InvalidProfile(
            "schema1 parent must be owner-controlled and non-writable by peers",
        ));
    }
    let mut ancestor = path.parent();
    while let Some(directory) = ancestor {
        let metadata = fs::metadata(directory).map_err(|error| {
            HandoffSignerJournalErrorV1::io("stat schema1 directory ancestor", error)
        })?;
        let peer_writable = metadata.mode() & 0o022 != 0;
        let trusted_sticky_root = metadata.mode() & 0o1000 != 0 && metadata.uid() == 0;
        if !metadata.is_dir() || (peer_writable && !trusted_sticky_root) {
            return Err(HandoffSignerJournalErrorV1::InvalidProfile(
                "schema1 ancestor namespace is peer-writable",
            ));
        }
        ancestor = directory.parent();
    }
    Ok(())
}

fn open_parent_directory(
    database_path: &Path,
) -> Result<(File, FileIdentityV1), HandoffSignerJournalErrorV1> {
    let parent = database_path
        .parent()
        .ok_or(HandoffSignerJournalErrorV1::InvalidProfile(
            "database parent",
        ))?;
    let mut options = OpenOptions::new();
    options.read(true);
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(parent)
        .map_err(|error| HandoffSignerJournalErrorV1::io("pin schema1 parent directory", error))?;
    let identity = directory_handle_identity_v1(&file)?;
    if identity != directory_path_identity_v1(parent)? {
        return Err(HandoffSignerJournalErrorV1::Conflict(
            HandoffSignerJournalConflictV1::FileIdentityChanged,
        ));
    }
    Ok((file, identity))
}

fn create_new_private_file_v1(path: &Path) -> Result<File, HandoffSignerJournalErrorV1> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    use std::os::unix::fs::OpenOptionsExt;
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .map_err(|error| HandoffSignerJournalErrorV1::io("create schema1 database", error))
}

fn open_existing_private_file_v1(path: &Path) -> Result<File, HandoffSignerJournalErrorV1> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .map_err(|error| HandoffSignerJournalErrorV1::io("open schema1 database handle", error))
}

fn open_existing_read_only_private_file_v1(
    path: &Path,
    stage: &'static str,
) -> Result<File, HandoffSignerJournalErrorV1> {
    let mut options = OpenOptions::new();
    options.read(true);
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .map_err(|error| HandoffSignerJournalErrorV1::io(stage, error))
}

fn acquire_lifetime_lock_v1(file: &File) -> Result<(), HandoffSignerJournalErrorV1> {
    match file.try_lock_exclusive() {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            Err(HandoffSignerJournalErrorV1::Locked)
        }
        Err(error) => Err(HandoffSignerJournalErrorV1::io(
            "acquire schema1 lifetime lock",
            error,
        )),
    }
}

fn validate_private_file_metadata_v1(
    metadata: &fs::Metadata,
) -> Result<(), HandoffSignerJournalErrorV1> {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: `geteuid` accepts no pointer and touches no caller memory.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "schema1 database identity or permissions",
            ),
        );
    }
    Ok(())
}

fn identity_from_metadata_v1(metadata: &fs::Metadata) -> FileIdentityV1 {
    use std::os::unix::fs::MetadataExt;

    FileIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn file_handle_identity_v1(file: &File) -> Result<FileIdentityV1, HandoffSignerJournalErrorV1> {
    let metadata = file
        .metadata()
        .map_err(|error| HandoffSignerJournalErrorV1::io("stat pinned schema1 database", error))?;
    validate_private_file_metadata_v1(&metadata)?;
    Ok(identity_from_metadata_v1(&metadata))
}

fn path_identity_v1(path: &Path) -> Result<FileIdentityV1, HandoffSignerJournalErrorV1> {
    let metadata = fs::metadata(path)
        .map_err(|error| HandoffSignerJournalErrorV1::io("stat schema1 database path", error))?;
    validate_private_file_metadata_v1(&metadata)?;
    Ok(identity_from_metadata_v1(&metadata))
}

fn directory_handle_identity_v1(
    file: &File,
) -> Result<FileIdentityV1, HandoffSignerJournalErrorV1> {
    let metadata = file
        .metadata()
        .map_err(|error| HandoffSignerJournalErrorV1::io("stat pinned schema1 directory", error))?;
    if !metadata.is_dir() {
        return Err(
            HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                "pinned schema1 parent is not a directory",
            ),
        );
    }
    Ok(identity_from_metadata_v1(&metadata))
}

fn directory_path_identity_v1(path: &Path) -> Result<FileIdentityV1, HandoffSignerJournalErrorV1> {
    validate_private_directory_v1(path)?;
    let metadata = fs::metadata(path)
        .map_err(|error| HandoffSignerJournalErrorV1::io("stat schema1 directory path", error))?;
    Ok(identity_from_metadata_v1(&metadata))
}

fn require_path_identity(
    path: &Path,
    expected: FileIdentityV1,
) -> Result<(), HandoffSignerJournalErrorV1> {
    if path_identity_v1(path)? != expected {
        return Err(HandoffSignerJournalErrorV1::Conflict(
            HandoffSignerJournalConflictV1::FileIdentityChanged,
        ));
    }
    Ok(())
}

fn sync_file(file: &File, stage: &'static str) -> Result<(), HandoffSignerJournalErrorV1> {
    file.sync_all()
        .map_err(|error| HandoffSignerJournalErrorV1::io(stage, error))
}

fn new_journal_id_v1() -> Result<[u8; 32], HandoffSignerJournalErrorV1> {
    for _ in 0..8 {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|error| {
            HandoffSignerJournalErrorV1::io(
                "generate schema1 journal identity",
                std::io::Error::other(error.to_string()),
            )
        })?;
        if bytes != [0; 32] {
            return Ok(bytes);
        }
    }
    Err(HandoffSignerJournalErrorV1::InvalidProfile(
        "random schema1 journal identity remained zero",
    ))
}

fn ensure_supported_platform_v1() -> Result<(), HandoffSignerJournalErrorV1> {
    #[cfg(target_os = "linux")]
    {
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(HandoffSignerJournalErrorV1::UnsupportedPlatform)
    }
}

fn fixed_array_v1<const N: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; N], HandoffSignerJournalErrorV1> {
    bytes
        .try_into()
        .map_err(|_| HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(field))
}

fn fixed_required_array_v1<const N: usize>(
    bytes: Option<Vec<u8>>,
    field: &'static str,
) -> Result<[u8; N], HandoffSignerJournalErrorV1> {
    fixed_array_v1(
        bytes
            .as_deref()
            .ok_or(HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(field))?,
        field,
    )
}

fn decode_u64_v1(bytes: &[u8], field: &'static str) -> Result<u64, HandoffSignerJournalErrorV1> {
    Ok(u64::from_be_bytes(fixed_array_v1(bytes, field)?))
}

fn decode_required_u64_v1(
    bytes: Option<Vec<u8>>,
    field: &'static str,
) -> Result<u64, HandoffSignerJournalErrorV1> {
    decode_u64_v1(
        bytes
            .as_deref()
            .ok_or(HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(field))?,
        field,
    )
}

fn decode_optional_u64_v1(
    bytes: Option<Vec<u8>>,
    field: &'static str,
) -> Result<Option<u64>, HandoffSignerJournalErrorV1> {
    bytes
        .as_deref()
        .map(|value| decode_u64_v1(value, field))
        .transpose()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };

    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use trnm_consensus_types::{
        BlockId, ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, Height,
        ProtocolVersion, Validator, ValidatorId, ValidatorSet, View, VotingPower,
    };

    use super::*;
    use crate::ExternalWatermarkErrorV0;

    fn audit_profile_v1() -> HandoffSignerJournalProfileV1 {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let validators = (0u8..4)
            .map(|index| {
                let key = SigningKey::from_bytes(&[index + 1; 32]);
                Validator::new(
                    ValidatorId::from_bytes(&[b'a' + index]).expect("validator ID"),
                    ConsensusPublicKey::new(key.verifying_key().to_bytes()),
                    VotingPower::new(1).expect("positive voting power"),
                )
                .expect("validator")
            })
            .collect::<Vec<_>>();
        let genesis = GenesisHash::new([0x31; 32]);
        let chain = ChainId::new("trnm-schema1-audit-mutant").expect("chain ID");
        let old_set = ValidatorSet::new(
            genesis,
            chain,
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators.clone(),
        )
        .expect("old set");
        let new_set = ValidatorSet::new(
            genesis,
            chain,
            ProtocolVersion::V0,
            Epoch::new(1),
            parameters.hash(),
            validators,
        )
        .expect("new set");
        HandoffSignerJournalProfileV1::new(
            old_set,
            new_set,
            parameters,
            parameters,
            ValidatorId::from_bytes(b"a").expect("author"),
            [0x51; 32],
            [0x72; 32],
            64,
            4096,
            32 * 1024 * 1024,
        )
        .expect("audit profile")
    }

    #[derive(Debug, Default)]
    struct SemanticWatermarkForTest;

    impl ExternalMonotonicWatermarkV0 for SemanticWatermarkForTest {
        fn load(
            &mut self,
            _scope: [u8; 32],
        ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
            Err(ExternalWatermarkErrorV0::InvalidPersistedState)
        }

        fn compare_and_advance(
            &mut self,
            _expected: Option<SignerWatermarkV0>,
            _target: SignerWatermarkV0,
        ) -> Result<(), ExternalWatermarkErrorV0> {
            Err(ExternalWatermarkErrorV0::InvalidPersistedState)
        }

        fn semantic_mode_v0(&self) -> bool {
            true
        }
    }

    #[test]
    fn semantic_watermark_is_rejected_before_schema1_file_creation() {
        let temporary = TempDir::new().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let path = temporary.path().join("semantic-rejected.sqlite3");
        let result = SqliteHandoffSignerJournalV1::create_new(
            &path,
            audit_profile_v1(),
            SemanticWatermarkForTest,
        );
        assert!(matches!(
            result,
            Err(HandoffSignerJournalErrorV1::InvalidProfile(
                UNSUPPORTED_SEMANTIC_WATERMARK_V1
            ))
        ));
        assert!(!path.exists());
    }

    #[test]
    fn exact_recomputed_database_rejects_two_consecutive_prepared_events() {
        let temporary = TempDir::new().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let path = temporary.path().join("double-pending.sqlite3");
        let database_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("private database file");
        let mut connection = Connection::open(&path).expect("SQLite connection");
        let profile = audit_profile_v1();
        configure_connection_v1(&connection, true, profile.maximum_database_bytes())
            .expect("configure database");
        let journal_id = [0x91; 32];
        let mut head =
            initialize_schema_v1(&connection, &profile, journal_id).expect("initialize schema1");

        let first = prepare_consensus_intent_v1(
            &profile,
            &CanonicalSignIntentV0::vote(
                profile.old_validator_set(),
                profile.author(),
                1,
                View::new(1),
                Height::new(2),
                BlockId::new([0x41; 32]),
            )
            .expect("first intent"),
        )
        .expect("prepare first intent");
        let first_event = make_event_v1(head, EVENT_PREPARED, &first, None).expect("first event");
        {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("first transaction");
            insert_intent_v1(&transaction, &first).expect("first intent row");
            insert_event_v1(&transaction, &first_event).expect("first event row");
            update_accounting_prepared_v1(&transaction, &first).expect("first accounting");
            update_head_v1(&transaction, journal_id, &first_event).expect("first head");
            transaction.commit().expect("commit first prepared");
        }
        head = JournalHeadV1 {
            sequence: first_event.sequence,
            chain_checksum: first_event.chain_checksum,
        };

        let second = prepare_consensus_intent_v1(
            &profile,
            &CanonicalSignIntentV0::vote(
                profile.old_validator_set(),
                profile.author(),
                2,
                View::new(2),
                Height::new(3),
                BlockId::new([0x42; 32]),
            )
            .expect("second intent"),
        )
        .expect("prepare second intent");
        let second_event =
            make_event_v1(head, EVENT_PREPARED, &second, None).expect("second event");
        let trigger_sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type='trigger' AND name='signer_events_single_pending_v1'",
                [],
                |row| row.get(0),
            )
            .expect("canonical single-pending trigger");
        connection
            .execute_batch("DROP TRIGGER signer_events_single_pending_v1;")
            .expect("open offline mutant path");
        {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("second transaction");
            insert_intent_v1(&transaction, &second).expect("second intent row");
            insert_event_v1(&transaction, &second_event).expect("second event row");
            update_accounting_prepared_v1(&transaction, &second).expect("second accounting");
            update_head_v1(&transaction, journal_id, &second_event).expect("second head");
            transaction.commit().expect("commit second prepared mutant");
        }
        connection
            .execute_batch(&trigger_sql)
            .expect("restore exact single-pending trigger");

        assert!(matches!(
            validate_database_v1(
                &connection,
                &database_file,
                &profile,
                journal_id,
                Some(second.fingerprint),
            ),
            Err(
                HandoffSignerJournalErrorV1::PersistedRepresentationMalformed(
                    "multiple globally pending prepared intents"
                )
            )
        ));
    }
}
