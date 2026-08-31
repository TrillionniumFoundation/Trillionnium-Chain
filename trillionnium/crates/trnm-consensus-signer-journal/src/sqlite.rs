use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use fs2::FileExt;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use subtle::ConstantTimeEq;
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    decode_canonical_sign_intent_v0_exact, CanonicalSignIntentV0, CanonicalSignPreimageV0, ChainId,
    Epoch, ProtocolVersion, SignatureBytes, SignatureVerifier, SigningRoot, ValidatorId,
    ValidatorSetId,
};

use crate::{
    error::{ExternalWatermarkErrorV0, SignerJournalConflictV0, SignerJournalErrorV0},
    hash::hash_domain,
    model::{
        signer_journal_lifecycle_nonce_v0, ExternalMonotonicWatermarkInjectionV0,
        ExternalMonotonicWatermarkV0, ExternalWatermarkSemanticFactsV0, SignatureProducerV0,
        SignatureRequestV0, SignerJournalProfileV0, SignerWatermarkV0,
    },
    schema::{
        validate_canonical_schema, JOURNAL_SCHEMA_SQL_V0, JOURNAL_SCHEMA_VERSION_V0,
        MAXIMUM_SQL_INTENT_BYTES_V0,
    },
};

const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const METADATA_DOMAIN_V0: &str = "trnm.consensus-signer-journal.metadata.v0";
const INITIAL_HEAD_DOMAIN_V0: &str = "trnm.consensus-signer-journal.initial-head.v0";
const INTENT_DOMAIN_V0: &str = "trnm.consensus-signer-journal.intent.v0";
const EVENT_DOMAIN_V0: &str = "trnm.consensus-signer-journal.event.v0";
const CHAIN_DOMAIN_V0: &str = "trnm.consensus-signer-journal.chain.v0";
const HEAD_DOMAIN_V0: &str = "trnm.consensus-signer-journal.head.v0";
const LIFETIME_INVENTORY_DOMAIN_V1: &str = "trnm.consensus-signer-journal.lifetime-inventory.v1";
const MAXIMUM_SHM_BYTES_V0: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JournalHeadV0 {
    sequence: u64,
    chain_checksum: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentityV0 {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedIntentV0 {
    fingerprint: [u8; 32],
    epoch: u64,
    view: u64,
    kind: u8,
    safety_revision: u64,
    signing_root: [u8; 32],
    canonical_intent: Vec<u8>,
    intent_checksum: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredEventV0 {
    sequence: u64,
    kind: u8,
    fingerprint: [u8; 32],
    signature: Option<[u8; 64]>,
    predecessor_sequence: u64,
    predecessor_chain_checksum: [u8; 32],
    event_checksum: [u8; 32],
    chain_checksum: [u8; 32],
}

type RawCapacityRowV0 = (
    i64,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

/// Current bounded append-only usage. Counts never decrease in journal v0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalCapacityV0 {
    intent_count: u64,
    event_count: u64,
    intent_bytes: u64,
    maximum_safety_revision: Option<u64>,
    maximum_vote_view: Option<u64>,
    maximum_timeout_view: Option<u64>,
}

/// Authority-free projection of every durable Vote and TimeoutVote intent in
/// one fully audited journal head.
///
/// Durable counts include the unique prepared-but-not-signed tail, when one
/// exists. Signed counts include only intents whose signed event and Ed25519
/// signature were verified by the same full audit. The digest binds these
/// counts to the exact profile, journal, watermark, capacity, per-kind maxima,
/// and pending-tail description. This type has no public constructor or serde
/// representation; callers can compare or report it but cannot select counts.
///
/// ```compile_fail
/// use trnm_consensus_signer_journal::SignerJournalLifetimeInventoryV1;
/// fn forge() -> SignerJournalLifetimeInventoryV1 {
///     SignerJournalLifetimeInventoryV1 {
///         durable_vote_intent_count: 1,
///         durable_timeout_intent_count: 0,
///         signed_vote_intent_count: 1,
///         signed_timeout_intent_count: 0,
///         inventory_digest: [1; 32],
///     }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerJournalLifetimeInventoryV1 {
    durable_vote_intent_count: u64,
    durable_timeout_intent_count: u64,
    signed_vote_intent_count: u64,
    signed_timeout_intent_count: u64,
    inventory_digest: [u8; 32],
}

impl SignerJournalLifetimeInventoryV1 {
    pub const fn durable_vote_intent_count(&self) -> u64 {
        self.durable_vote_intent_count
    }

    pub const fn durable_timeout_intent_count(&self) -> u64 {
        self.durable_timeout_intent_count
    }

    pub const fn signed_vote_intent_count(&self) -> u64 {
        self.signed_vote_intent_count
    }

    pub const fn signed_timeout_intent_count(&self) -> u64 {
        self.signed_timeout_intent_count
    }

    pub const fn inventory_digest(&self) -> [u8; 32] {
        self.inventory_digest
    }
}

/// Relationship observed between the authenticated local journal head and the
/// independently administered external watermark during a pinned startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerExternalWatermarkRelationV0 {
    /// The external watermark exactly matches the local event-chain head.
    Exact,
    /// The local journal is exactly one authenticated event ahead. Activation
    /// may repair this single local-first crash window with one external CAS.
    LocalOneAhead,
}

/// Copied, inert description of the unique prepared-but-not-signed tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerPreparedIntentFactsV0 {
    fingerprint: [u8; 32],
    epoch: u64,
    view: u64,
    kind: u8,
    safety_revision: u64,
    signing_root: [u8; 32],
    intent_checksum: [u8; 32],
}

/// Lifecycle state of the authenticated final journal event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerJournalTailStateV0 {
    Prepared,
    Signed,
}

/// Copied, inert description of the intent referenced by the final event.
/// Signature bytes, when present, are public verification material and do not
/// grant producer or journal authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerJournalTailFactsV0 {
    state: SignerJournalTailStateV0,
    fingerprint: [u8; 32],
    epoch: u64,
    view: u64,
    kind: u8,
    safety_revision: u64,
    signing_root: [u8; 32],
    intent_checksum: [u8; 32],
    signature: Option<[u8; 64]>,
}

impl SignerJournalTailFactsV0 {
    pub const fn state(&self) -> SignerJournalTailStateV0 {
        self.state
    }

    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn view(&self) -> u64 {
        self.view
    }

    pub const fn kind(&self) -> u8 {
        self.kind
    }

    pub const fn safety_revision(&self) -> u64 {
        self.safety_revision
    }

    pub const fn signing_root(&self) -> [u8; 32] {
        self.signing_root
    }

    pub const fn intent_checksum(&self) -> [u8; 32] {
        self.intent_checksum
    }

    pub const fn signature(&self) -> Option<[u8; 64]> {
        self.signature
    }
}

impl SignerPreparedIntentFactsV0 {
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn view(&self) -> u64 {
        self.view
    }

    pub const fn kind(&self) -> u8 {
        self.kind
    }

    pub const fn safety_revision(&self) -> u64 {
        self.safety_revision
    }

    pub const fn signing_root(&self) -> [u8; 32] {
        self.signing_root
    }

    pub const fn intent_checksum(&self) -> [u8; 32] {
        self.intent_checksum
    }
}

/// Authenticated, copied startup facts. This value carries no database,
/// external-watermark, or signing authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerJournalReconciliationFactsV0 {
    journal_id: [u8; 32],
    profile_checksum: [u8; 32],
    local_watermark: SignerWatermarkV0,
    observed_external_watermark: SignerWatermarkV0,
    external_relation: SignerExternalWatermarkRelationV0,
    capacity: JournalCapacityV0,
    lifetime_inventory: SignerJournalLifetimeInventoryV1,
    tail: Option<SignerJournalTailFactsV0>,
    pending_intent: Option<SignerPreparedIntentFactsV0>,
}

impl SignerJournalReconciliationFactsV0 {
    pub const fn journal_id(&self) -> [u8; 32] {
        self.journal_id
    }

    pub const fn profile_checksum(&self) -> [u8; 32] {
        self.profile_checksum
    }

    pub const fn local_watermark(&self) -> SignerWatermarkV0 {
        self.local_watermark
    }

    pub const fn observed_external_watermark(&self) -> SignerWatermarkV0 {
        self.observed_external_watermark
    }

    pub const fn external_relation(&self) -> SignerExternalWatermarkRelationV0 {
        self.external_relation
    }

    pub const fn capacity(&self) -> JournalCapacityV0 {
        self.capacity
    }

    pub const fn lifetime_inventory(&self) -> SignerJournalLifetimeInventoryV1 {
        self.lifetime_inventory
    }

    pub const fn tail(&self) -> Option<SignerJournalTailFactsV0> {
        self.tail
    }

    pub const fn pending_intent(&self) -> Option<SignerPreparedIntentFactsV0> {
        self.pending_intent
    }
}

/// Immutable signer identity authenticated by one pinned journal profile.
///
/// This value is comparison material only. It contains no private key,
/// external-watermark owner, or journal handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerNodeCheckpointIdentityV0 {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_id: ValidatorSetId,
    author: ValidatorId,
    signer_profile_ref: [u8; 32],
    external_watermark_scope: [u8; 32],
}

impl SignerNodeCheckpointIdentityV0 {
    fn from_profile(profile: &SignerJournalProfileV0) -> Self {
        Self {
            chain_id: profile.chain_id(),
            protocol_version: profile.protocol_version(),
            epoch: profile.epoch(),
            validator_set_id: profile.validator_set_id(),
            author: profile.author(),
            signer_profile_ref: profile.signer_profile_ref(),
            external_watermark_scope: profile.external_watermark_scope(),
        }
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub const fn author(&self) -> ValidatorId {
        self.author
    }

    pub const fn signer_profile_ref(&self) -> [u8; 32] {
        self.signer_profile_ref
    }

    pub const fn external_watermark_scope(&self) -> [u8; 32] {
        self.external_watermark_scope
    }
}

/// One-shot, authority-free facts for an exactly externally checkpointed
/// signer-journal head.
///
/// The capability intentionally implements neither `Clone` nor `Copy`, has
/// private fields, no public constructor, and no serde representation. It can
/// be created only after the pinned SQLite namespace is deeply revalidated, a
/// fresh independently administered watermark is observed equal to the local
/// event-chain head, and the local namespace is revalidated once more. The
/// operation never advances the external watermark.
///
/// ```compile_fail
/// use trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<ConfirmedSignerNodeCheckpointFactsV0>();
/// ```
///
/// ```compile_fail
/// use trnm_consensus_signer_journal::ConfirmedSignerNodeCheckpointFactsV0;
/// fn forge() -> ConfirmedSignerNodeCheckpointFactsV0 {
///     ConfirmedSignerNodeCheckpointFactsV0 {
///         journal_id: [1; 32],
///     }
/// }
/// ```
#[derive(Debug)]
#[must_use = "confirmed signer facts must be consumed by the trusted node-checkpoint join"]
pub struct ConfirmedSignerNodeCheckpointFactsV0 {
    journal_id: [u8; 32],
    profile_checksum: [u8; 32],
    identity: SignerNodeCheckpointIdentityV0,
    exact_watermark: SignerWatermarkV0,
    capacity: JournalCapacityV0,
    lifetime_inventory: SignerJournalLifetimeInventoryV1,
    tail: Option<SignerJournalTailFactsV0>,
    pending_intent: Option<SignerPreparedIntentFactsV0>,
    owner_affinity: Arc<()>,
}

impl ConfirmedSignerNodeCheckpointFactsV0 {
    pub const fn journal_id(&self) -> [u8; 32] {
        self.journal_id
    }

    pub const fn profile_checksum(&self) -> [u8; 32] {
        self.profile_checksum
    }

    pub const fn identity(&self) -> SignerNodeCheckpointIdentityV0 {
        self.identity
    }

    pub const fn exact_watermark(&self) -> SignerWatermarkV0 {
        self.exact_watermark
    }

    pub const fn capacity(&self) -> JournalCapacityV0 {
        self.capacity
    }

    pub const fn lifetime_inventory(&self) -> SignerJournalLifetimeInventoryV1 {
        self.lifetime_inventory
    }

    pub const fn tail(&self) -> Option<SignerJournalTailFactsV0> {
        self.tail
    }

    pub const fn pending_intent(&self) -> Option<SignerPreparedIntentFactsV0> {
        self.pending_intent
    }

    /// Confirms that these detached facts came from this exact still-pinned
    /// owner and that its canonical namespace remains at `expected_path`.
    pub fn belongs_to_pinned_journal_at_path_v0<W: ExternalMonotonicWatermarkV0>(
        &self,
        pinned: &PinnedSqliteSignerJournalV0<W>,
        expected_path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &pinned.owner_affinity)
            && pinned.path() == expected_path
            && pinned.ensure_file_identity().is_ok()
    }

    /// Confirms that these facts came from this exact operational owner and
    /// its still-pinned canonical namespace. Freshness is established by the
    /// operational confirmation method which minted this capability.
    pub fn belongs_to_operational_journal_at_path_v0<W: ExternalMonotonicWatermarkV0>(
        &self,
        journal: &SqliteSignerJournalV0<W>,
        expected_path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner_affinity, &journal.owner_affinity)
            && journal.path() == expected_path
            && journal.ensure_file_identity().is_ok()
    }
}

impl JournalCapacityV0 {
    pub const fn intent_count(&self) -> u64 {
        self.intent_count
    }

    pub const fn event_count(&self) -> u64 {
        self.event_count
    }

    pub const fn intent_bytes(&self) -> u64 {
        self.intent_bytes
    }

    pub const fn maximum_safety_revision(&self) -> Option<u64> {
        self.maximum_safety_revision
    }

    pub const fn maximum_vote_view(&self) -> Option<u64> {
        self.maximum_vote_view
    }

    pub const fn maximum_timeout_view(&self) -> Option<u64> {
        self.maximum_timeout_view
    }
}

/// Non-cloneable authoritative handle for one validator's local sign journal.
pub struct SqliteSignerJournalV0<W> {
    connection: Connection,
    database_file: File,
    lock_file: File,
    wal_file: File,
    shm_file: File,
    directory_file: File,
    database_path: PathBuf,
    lock_path: PathBuf,
    directory_path: PathBuf,
    database_identity: FileIdentityV0,
    lock_identity: FileIdentityV0,
    wal_identity: FileIdentityV0,
    shm_identity: FileIdentityV0,
    directory_identity: FileIdentityV0,
    profile: SignerJournalProfileV0,
    external_watermark: W,
    journal_id: [u8; 32],
    observed_head: JournalHeadV0,
    owner_pid: u32,
    owner_affinity: Arc<()>,
}

/// Non-cloneable, existing-only startup owner. It pins and authenticates the
/// complete local namespace and observes the external watermark without
/// changing either. Call [`Self::activate_v0`] only after the host has
/// reconciled these copied facts with its Core, SafetyStore, and AppStore.
pub struct PinnedSqliteSignerJournalV0<W> {
    connection: Connection,
    database_file: File,
    lock_file: File,
    wal_file: File,
    shm_file: File,
    directory_file: File,
    database_path: PathBuf,
    lock_path: PathBuf,
    directory_path: PathBuf,
    database_identity: FileIdentityV0,
    lock_identity: FileIdentityV0,
    wal_identity: FileIdentityV0,
    shm_identity: FileIdentityV0,
    directory_identity: FileIdentityV0,
    profile: SignerJournalProfileV0,
    external_watermark: W,
    journal_id: [u8; 32],
    observed_head: JournalHeadV0,
    facts: SignerJournalReconciliationFactsV0,
    owner_pid: u32,
    owner_affinity: Arc<()>,
}

/// Owner-preserving activation failure. The caller may inspect the failure,
/// recover the still-pinned startup session, or discard it and reopen.
pub struct SignerJournalActivationFailureV0<W> {
    error: SignerJournalErrorV0,
    pinned: Box<PinnedSqliteSignerJournalV0<W>>,
}

impl<W> SignerJournalActivationFailureV0<W> {
    fn new(pinned: PinnedSqliteSignerJournalV0<W>, error: SignerJournalErrorV0) -> Self {
        Self {
            error,
            pinned: Box::new(pinned),
        }
    }

    pub const fn error(&self) -> &SignerJournalErrorV0 {
        &self.error
    }

    pub fn into_pinned(self) -> PinnedSqliteSignerJournalV0<W> {
        *self.pinned
    }

    pub fn into_error(self) -> SignerJournalErrorV0 {
        self.error
    }
}

impl<W: ExternalMonotonicWatermarkV0> SqliteSignerJournalV0<W> {
    pub fn initialize_new(
        database_path: impl AsRef<Path>,
        profile: SignerJournalProfileV0,
        mut external_watermark: W,
    ) -> Result<Self, SignerJournalErrorV0> {
        ensure_supported_platform()?;
        if !external_watermark.semantic_mode_v0()
            && external_watermark
                .load(profile.external_watermark_scope())
                .map_err(|error| SignerJournalErrorV0::external("preflight new scope", error))?
                .is_some()
        {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::ExternalWatermarkAhead,
            ));
        }

        let database_path = canonical_new_path(database_path.as_ref())?;
        let directory_path = database_path
            .parent()
            .ok_or(SignerJournalErrorV0::InvalidProfile("database parent"))?
            .to_path_buf();
        let directory_file = File::open(&directory_path)
            .map_err(|error| SignerJournalErrorV0::io("pin signer directory", error))?;
        let directory_identity = directory_handle_identity(&directory_file)?;
        ensure_auxiliary_files_absent(&database_path)?;
        let lock_path = lock_path_for(&database_path)?;
        if fs::symlink_metadata(&database_path).is_ok() {
            return Err(SignerJournalErrorV0::AlreadyExists("database"));
        }
        if fs::symlink_metadata(&lock_path).is_ok() {
            return Err(SignerJournalErrorV0::AlreadyExists("lock sidecar"));
        }

        let lock_file = create_new_private_file(&lock_path, "create lock sidecar")?;
        acquire_lifetime_lock(&lock_file)?;
        sync_directory_handle(&directory_file)?;
        let database_file = create_new_private_file(&database_path, "create database")?;
        acquire_lifetime_lock(&database_file)?;
        let database_identity = file_handle_identity(&database_file)?;
        let lock_identity = file_handle_identity(&lock_file)?;

        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| SignerJournalErrorV0::sqlite("open new database", error))?;
        configure_connection(&connection, true, profile.maximum_database_bytes())?;
        let journal_id = new_journal_id()?;
        let observed_head = initialize_schema(&connection, &profile, journal_id)?;
        checkpoint_and_sync_initialization(&connection, &database_file, &directory_file)?;
        materialize_auxiliary_files(&connection)?;
        let (wal_file, wal_identity, shm_file, shm_identity) =
            pin_auxiliary_files(&database_path, profile.maximum_database_bytes())?;
        sync_directory_handle(&directory_file)?;

        let mut store = Self {
            connection,
            database_file,
            lock_file,
            wal_file,
            shm_file,
            directory_file,
            database_path,
            lock_path,
            directory_path,
            database_identity,
            lock_identity,
            wal_identity,
            shm_identity,
            directory_identity,
            profile,
            external_watermark,
            journal_id,
            observed_head,
            owner_pid: std::process::id(),
            owner_affinity: Arc::new(()),
        };
        store.validate_database()?;
        let initial = store.watermark_for(store.observed_head)?;
        if load_external_head_v0(
            &mut store.external_watermark,
            store.profile.external_watermark_scope(),
            store.journal_id,
        )
        .map_err(|error| SignerJournalErrorV0::external("preflight new semantic scope", error))?
        .is_some()
        {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::ExternalWatermarkAhead,
            ));
        }
        compare_and_advance_external_head_v0(
            &mut store.external_watermark,
            &store.connection,
            store.journal_id,
            None,
            initial,
        )
        .map_err(|error| {
            SignerJournalErrorV0::external("claim new external watermark scope", error)
        })?;
        store.require_external_exact(initial, "confirm new external watermark")?;
        store.ensure_file_identity()?;
        Ok(store)
    }

    pub fn open_existing(
        database_path: impl AsRef<Path>,
        profile: SignerJournalProfileV0,
        external_watermark: W,
    ) -> Result<Self, SignerJournalErrorV0> {
        Self::pin_existing_v0(database_path, profile, external_watermark)?
            .activate_v0()
            .map_err(SignerJournalActivationFailureV0::into_error)
    }

    /// Pins and authenticates an existing journal without advancing the
    /// external watermark or changing the SQLite namespace.
    pub fn pin_existing_v0(
        database_path: impl AsRef<Path>,
        profile: SignerJournalProfileV0,
        external_watermark: W,
    ) -> Result<PinnedSqliteSignerJournalV0<W>, SignerJournalErrorV0> {
        PinnedSqliteSignerJournalV0::open_existing_v0(database_path, profile, external_watermark)
    }

    pub fn path(&self) -> &Path {
        &self.database_path
    }

    pub const fn profile(&self) -> &SignerJournalProfileV0 {
        &self.profile
    }

    /// Returns the authenticated durable identity of this signer journal.
    ///
    /// The identity is generated when the SQLite namespace is initialized and
    /// is authenticated again by `open_existing`.  Callers may bind other
    /// recovery fences to this value without exposing any mutable journal
    /// capability.
    pub const fn journal_id(&self) -> [u8; 32] {
        self.journal_id
    }

    /// Consumes an operational owner into the read-only startup form without
    /// changing the journal or external watermark.
    ///
    /// This is used by a whole-node commissioning join which must keep signing
    /// disabled until the first cross-store checkpoint has been durably
    /// installed.  The returned pinned owner must still pass its normal fresh
    /// revalidation before it can be activated again.
    pub fn into_pinned_v0(
        mut self,
    ) -> Result<PinnedSqliteSignerJournalV0<W>, SignerJournalErrorV0> {
        let operational_inventory = self.validate_database()?;
        let operational_head = read_head(&self.connection, self.journal_id)?;
        if operational_head != self.observed_head {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::CommitReadbackConflict,
            ));
        }
        let local_watermark =
            watermark_for_parts(&self.profile, self.journal_id, operational_head)?;
        let capacity = read_capacity(&self.connection)?;
        validate_capacity(&capacity, &self.profile)?;
        let tail = read_tail_facts(&self.connection, operational_head)?;
        let pending_intent = read_pending_intent_facts(&self.connection)?;
        let observed_external_watermark = load_external_head_v0(
            &mut self.external_watermark,
            self.profile.external_watermark_scope(),
            self.journal_id,
        )
        .map_err(|error| {
            SignerJournalErrorV0::external("pin operational external watermark", error)
        })?
        .ok_or(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkMissing,
        ))?;
        if observed_external_watermark != local_watermark {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::ExternalWatermarkRepairRequired,
            ));
        }

        let facts = SignerJournalReconciliationFactsV0 {
            journal_id: self.journal_id,
            profile_checksum: self.profile.profile_checksum(),
            local_watermark,
            observed_external_watermark,
            external_relation: SignerExternalWatermarkRelationV0::Exact,
            capacity,
            lifetime_inventory: operational_inventory,
            tail,
            pending_intent,
        };
        let pinned_connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| SignerJournalErrorV0::sqlite("open pinned operational database", error))?;
        configure_pinned_read_only_connection(&pinned_connection)?;
        let pinned_inventory = validate_pinned_database_connection(
            &pinned_connection,
            &self.database_path,
            &self.profile,
            self.journal_id,
        )?;
        let pinned_head = read_head(&pinned_connection, self.journal_id)?;
        let pinned_capacity = read_capacity(&pinned_connection)?;
        validate_capacity(&pinned_capacity, &self.profile)?;
        let pinned_tail = read_tail_facts(&pinned_connection, pinned_head)?;
        let pinned_pending_intent = read_pending_intent_facts(&pinned_connection)?;
        if pinned_head != operational_head
            || pinned_capacity != facts.capacity
            || pinned_inventory != facts.lifetime_inventory
            || pinned_tail != facts.tail
            || pinned_pending_intent != facts.pending_intent
            || watermark_for_parts(&self.profile, self.journal_id, pinned_head)?
                != facts.local_watermark
        {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::CommitReadbackConflict,
            ));
        }
        self.ensure_file_identity()?;

        let Self {
            connection,
            database_file,
            lock_file,
            wal_file,
            shm_file,
            directory_file,
            database_path,
            lock_path,
            directory_path,
            database_identity,
            lock_identity,
            wal_identity,
            shm_identity,
            directory_identity,
            profile,
            external_watermark,
            journal_id,
            observed_head,
            owner_pid,
            owner_affinity,
        } = self;
        drop(connection);
        let pinned = PinnedSqliteSignerJournalV0 {
            connection: pinned_connection,
            database_file,
            lock_file,
            wal_file,
            shm_file,
            directory_file,
            database_path,
            lock_path,
            directory_path,
            database_identity,
            lock_identity,
            wal_identity,
            shm_identity,
            directory_identity,
            profile,
            external_watermark,
            journal_id,
            observed_head,
            facts,
            owner_pid,
            owner_affinity,
        };
        pinned.revalidate_pinned()?;
        Ok(pinned)
    }

    /// Freshly confirms the exact operational journal/external-watermark head
    /// without preparing an intent, advancing either namespace, or invoking a
    /// signature producer.
    ///
    /// This is the runtime counterpart of the pinned-startup checkpoint
    /// projection.  It accepts only an already-exact external watermark; the
    /// normal one-event repair path is deliberately not entered here because
    /// a whole-node checkpoint must describe an observed cut, not create one.
    pub fn confirm_node_checkpoint_head_exact_v0(
        &mut self,
    ) -> Result<ConfirmedSignerNodeCheckpointFactsV0, SignerJournalErrorV0> {
        self.ensure_operational()?;
        let before_head = read_head(&self.connection, self.journal_id)?;
        let before_inventory = self.validate_database()?;
        if before_head != self.observed_head {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::CommitReadbackConflict,
            ));
        }
        let local = self.watermark_for(before_head)?;
        let external = load_external_head_v0(
            &mut self.external_watermark,
            self.profile.external_watermark_scope(),
            self.journal_id,
        )
        .map_err(|error| {
            SignerJournalErrorV0::external(
                "confirm operational node-checkpoint external watermark",
                error,
            )
        })?
        .ok_or(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkMissing,
        ))?;
        if external != local {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::ExternalWatermarkRepairRequired,
            ));
        }
        let capacity = read_capacity(&self.connection)?;
        validate_capacity(&capacity, &self.profile)?;
        let tail = read_tail_facts(&self.connection, before_head)?;
        let pending_intent = read_pending_intent_facts(&self.connection)?;
        let after_inventory = self.validate_database()?;
        let after_head = read_head(&self.connection, self.journal_id)?;
        if before_head != after_head
            || before_inventory != after_inventory
            || after_head != self.observed_head
            || self.watermark_for(after_head)? != external
        {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::CommitReadbackConflict,
            ));
        }
        Ok(ConfirmedSignerNodeCheckpointFactsV0 {
            journal_id: self.journal_id,
            profile_checksum: self.profile.profile_checksum(),
            identity: SignerNodeCheckpointIdentityV0::from_profile(&self.profile),
            exact_watermark: external,
            capacity,
            lifetime_inventory: after_inventory,
            tail,
            pending_intent,
            owner_affinity: Arc::clone(&self.owner_affinity),
        })
    }

    pub fn capacity(&self) -> Result<JournalCapacityV0, SignerJournalErrorV0> {
        self.ensure_file_identity()?;
        let capacity = read_capacity(&self.connection)?;
        validate_capacity(&capacity, &self.profile)?;
        Ok(capacity)
    }

    pub fn external_head(&mut self) -> Result<SignerWatermarkV0, SignerJournalErrorV0> {
        self.ensure_operational()?;
        self.synchronize_external_head()?;
        self.watermark_for(self.observed_head)
    }

    /// Installs an independently administered watermark behind an already
    /// operational local journal.
    ///
    /// The existing local watermark must first be an exact, checkpoint-ready
    /// head.  A delegate may claim a sequence-zero genesis head; for any
    /// non-genesis head it must already expose the exact value.  Subsequent
    /// intent and signature events use the injected CAS boundary through `W`;
    /// there is no window in which the caller can observe a partially
    /// installed authority.
    pub fn install_external_monotonic_watermark_v0(
        &mut self,
        external: Box<dyn ExternalMonotonicWatermarkV0 + Send>,
    ) -> Result<(), SignerJournalErrorV0>
    where
        W: ExternalMonotonicWatermarkInjectionV0,
    {
        let existing = self.confirm_node_checkpoint_head_exact_v0()?;
        self.external_watermark
            .install_external_monotonic_watermark_v0(external)
            .map_err(|error| {
                SignerJournalErrorV0::external("install external watermark authority", error)
            })?;
        self.require_external_exact(
            existing.exact_watermark(),
            "confirm installed external watermark authority",
        )
    }

    /// Validates, journals, signs, verifies, persists, and only then returns.
    pub fn sign_exact_v0<P: SignatureProducerV0>(
        &mut self,
        intent: &CanonicalSignIntentV0,
        producer: &mut P,
    ) -> Result<SignatureBytes, SignerJournalErrorV0> {
        self.ensure_operational()?;
        self.synchronize_external_head()?;
        let prepared = prepare_intent(&self.profile, self.journal_id, intent)?;

        if let Some(stored) = read_intent(&self.connection, prepared.fingerprint)? {
            require_exact_intent(&stored, &prepared)?;
            if let Some(signature) =
                read_persisted_signature(&self.connection, prepared.fingerprint, &self.profile)?
            {
                return Ok(signature);
            }
            self.require_only_pending(prepared.fingerprint)?;
            return self.complete_signature(intent, &prepared, producer);
        }

        self.require_no_pending_intent()?;
        self.require_new_intent_admissible(&prepared)?;
        self.append_intent_event(&prepared)?;
        self.synchronize_external_head()?;
        self.complete_signature(intent, &prepared, producer)
    }

    fn complete_signature<P: SignatureProducerV0>(
        &mut self,
        intent: &CanonicalSignIntentV0,
        prepared: &PreparedIntentV0,
        producer: &mut P,
    ) -> Result<SignatureBytes, SignerJournalErrorV0> {
        self.synchronize_external_head()?;
        let request = SignatureRequestV0::new(intent, self.profile.signer_profile_ref());
        let signature = producer
            .sign(request)
            .map_err(SignerJournalErrorV0::SignatureProducer)?;
        let validator = self
            .profile
            .validator_set()
            .validator(self.profile.author())
            .ok_or(SignerJournalErrorV0::MetadataMismatch)?;
        if !StrictEd25519Verifier.verify(validator, &intent.signing_root(), &signature) {
            return Err(SignerJournalErrorV0::InvalidProducedSignature);
        }
        self.append_signature_event(prepared, signature)?;
        self.synchronize_external_head()?;
        read_persisted_signature(&self.connection, prepared.fingerprint, &self.profile)?.ok_or(
            SignerJournalErrorV0::PersistedRepresentationMalformed(
                "signature event disappeared before return",
            ),
        )
    }

    fn require_new_intent_admissible(
        &self,
        prepared: &PreparedIntentV0,
    ) -> Result<(), SignerJournalErrorV0> {
        let conflicting: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT fingerprint FROM sign_intents_v0
                 WHERE epoch_be=?1 AND view_be=?2 AND intent_kind=?3",
                params![
                    prepared.epoch.to_be_bytes().as_slice(),
                    prepared.view.to_be_bytes().as_slice(),
                    i64::from(prepared.kind),
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| SignerJournalErrorV0::sqlite("check round conflict", error))?;
        if conflicting.is_some() {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::SameRoundDifferentIntent {
                    epoch: prepared.epoch,
                    view: prepared.view,
                    kind: prepared.kind,
                },
            ));
        }

        let capacity = read_capacity(&self.connection)?;
        validate_capacity(&capacity, &self.profile)?;
        if let Some(maximum) = capacity.maximum_safety_revision {
            if prepared.safety_revision <= maximum {
                return Err(SignerJournalErrorV0::Conflict(
                    SignerJournalConflictV0::SafetyRevisionRegression {
                        maximum,
                        incoming: prepared.safety_revision,
                    },
                ));
            }
        }
        let maximum_view = match prepared.kind {
            0 => capacity.maximum_vote_view,
            1 => capacity.maximum_timeout_view,
            _ => {
                return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
                    "unsupported intent kind",
                ));
            }
        };
        if let Some(maximum) = maximum_view {
            if prepared.view <= maximum {
                return Err(SignerJournalErrorV0::Conflict(
                    SignerJournalConflictV0::ViewRegression {
                        kind: prepared.kind,
                        maximum,
                        incoming: prepared.view,
                    },
                ));
            }
        }
        let new_bytes = capacity
            .intent_bytes
            .checked_add(prepared.canonical_intent.len() as u64)
            .ok_or(SignerJournalErrorV0::CapacityExhausted)?;
        if capacity.intent_count >= self.profile.maximum_intents()
            || new_bytes
                > self
                    .profile
                    .maximum_intents()
                    .saturating_mul(self.profile.maximum_intent_bytes() as u64)
        {
            return Err(SignerJournalErrorV0::CapacityExhausted);
        }
        Ok(())
    }

    fn require_no_pending_intent(&self) -> Result<(), SignerJournalErrorV0> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM signer_journal_events_v0 prepared
                 WHERE prepared.event_kind=0 AND NOT EXISTS (
                     SELECT 1 FROM signer_journal_events_v0 signed
                     WHERE signed.fingerprint=prepared.fingerprint AND signed.event_kind=1
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(|error| SignerJournalErrorV0::sqlite("count pending intent", error))?;
        if count != 0 {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::PreparedIntentPending,
            ));
        }
        Ok(())
    }

    fn require_only_pending(&self, fingerprint: [u8; 32]) -> Result<(), SignerJournalErrorV0> {
        let rows: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM signer_journal_events_v0 prepared
                 WHERE prepared.event_kind=0 AND NOT EXISTS (
                     SELECT 1 FROM signer_journal_events_v0 signed
                     WHERE signed.fingerprint=prepared.fingerprint AND signed.event_kind=1
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(|error| SignerJournalErrorV0::sqlite("count exact pending intent", error))?;
        let exact: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM signer_journal_events_v0
                 WHERE fingerprint=?1 AND event_kind=0",
                params![fingerprint.as_slice()],
                |row| row.get(0),
            )
            .map_err(|error| SignerJournalErrorV0::sqlite("read exact pending intent", error))?;
        if rows != 1 || exact != 1 {
            return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
                "prepared intent is not the unique pending journal event",
            ));
        }
        Ok(())
    }

    fn append_intent_event(
        &mut self,
        prepared: &PreparedIntentV0,
    ) -> Result<(), SignerJournalErrorV0> {
        let source = self.observed_head;
        let sequence = source
            .sequence
            .checked_add(1)
            .ok_or(SignerJournalErrorV0::CapacityExhausted)?;
        let event_checksum = event_checksum(
            self.journal_id,
            sequence,
            0,
            prepared.fingerprint,
            None,
            source,
            prepared.intent_checksum,
        );
        let target = JournalHeadV0 {
            sequence,
            chain_checksum: chain_checksum(source, event_checksum),
        };
        let head_checksum = head_checksum(self.journal_id, target);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| SignerJournalErrorV0::sqlite("begin intent append", error))?;
        transaction
            .execute(
                "INSERT INTO sign_intents_v0(
                    fingerprint, epoch_be, view_be, intent_kind, safety_revision_be,
                    signing_root, canonical_intent, intent_checksum
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    prepared.fingerprint.as_slice(),
                    prepared.epoch.to_be_bytes().as_slice(),
                    prepared.view.to_be_bytes().as_slice(),
                    i64::from(prepared.kind),
                    prepared.safety_revision.to_be_bytes().as_slice(),
                    prepared.signing_root.as_slice(),
                    prepared.canonical_intent.as_slice(),
                    prepared.intent_checksum.as_slice(),
                ],
            )
            .map_err(|error| SignerJournalErrorV0::sqlite("insert canonical intent", error))?;
        insert_event(
            &transaction,
            sequence,
            0,
            prepared.fingerprint,
            None,
            source,
            event_checksum,
            target.chain_checksum,
        )?;
        update_head(&transaction, source, target, head_checksum)?;
        let view_column = match prepared.kind {
            0 => "maximum_vote_view_be",
            1 => "maximum_timeout_view_be",
            _ => {
                return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
                    "unsupported intent kind",
                ));
            }
        };
        let accounting_sql = format!(
            "UPDATE signer_journal_accounting_v0 SET
                intent_count=intent_count+1,
                event_count=event_count+1,
                intent_bytes=intent_bytes+?1,
                maximum_safety_revision_be=?2,
                {view_column}=?3
             WHERE singleton=1"
        );
        let changed = transaction
            .execute(
                &accounting_sql,
                params![
                    i64::try_from(prepared.canonical_intent.len())
                        .map_err(|_| SignerJournalErrorV0::CapacityExhausted)?,
                    prepared.safety_revision.to_be_bytes().as_slice(),
                    prepared.view.to_be_bytes().as_slice(),
                ],
            )
            .map_err(|error| SignerJournalErrorV0::sqlite("update intent accounting", error))?;
        if changed != 1 {
            return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
                "intent accounting singleton",
            ));
        }
        let commit = transaction.commit();
        self.confirm_commit_result(commit, source, target, Some(prepared))?;
        validate_storage_resource_bounds(&self.database_path, &self.profile)?;
        self.ensure_file_identity()
    }

    fn append_signature_event(
        &mut self,
        prepared: &PreparedIntentV0,
        signature: SignatureBytes,
    ) -> Result<(), SignerJournalErrorV0> {
        let source = self.observed_head;
        let sequence = source
            .sequence
            .checked_add(1)
            .ok_or(SignerJournalErrorV0::CapacityExhausted)?;
        let signature_bytes = *signature.as_bytes();
        let event_checksum = event_checksum(
            self.journal_id,
            sequence,
            1,
            prepared.fingerprint,
            Some(&signature_bytes),
            source,
            prepared.intent_checksum,
        );
        let target = JournalHeadV0 {
            sequence,
            chain_checksum: chain_checksum(source, event_checksum),
        };
        let head_checksum = head_checksum(self.journal_id, target);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| SignerJournalErrorV0::sqlite("begin signature append", error))?;
        insert_event(
            &transaction,
            sequence,
            1,
            prepared.fingerprint,
            Some(&signature_bytes),
            source,
            event_checksum,
            target.chain_checksum,
        )?;
        update_head(&transaction, source, target, head_checksum)?;
        let changed = transaction
            .execute(
                "UPDATE signer_journal_accounting_v0
                 SET event_count=event_count+1 WHERE singleton=1",
                [],
            )
            .map_err(|error| SignerJournalErrorV0::sqlite("update signature accounting", error))?;
        if changed != 1 {
            return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
                "signature accounting singleton",
            ));
        }
        let commit = transaction.commit();
        self.confirm_commit_result(commit, source, target, None)?;
        validate_storage_resource_bounds(&self.database_path, &self.profile)?;
        self.ensure_file_identity()
    }

    fn confirm_commit_result(
        &mut self,
        commit_result: rusqlite::Result<()>,
        source: JournalHeadV0,
        target: JournalHeadV0,
        inserted_intent: Option<&PreparedIntentV0>,
    ) -> Result<(), SignerJournalErrorV0> {
        match commit_result {
            Ok(()) => {
                self.observed_head = target;
                Ok(())
            }
            Err(commit) => {
                let observed = read_head(&self.connection, self.journal_id);
                match observed {
                    Ok(head) if head == target => {
                        if let Some(expected) = inserted_intent {
                            let stored = read_intent(&self.connection, expected.fingerprint)?
                                .ok_or(SignerJournalErrorV0::CommitUncertain {
                                    commit,
                                    reason: "target head exists without inserted intent",
                                })?;
                            require_exact_intent(&stored, expected)?;
                        }
                        self.observed_head = target;
                        Ok(())
                    }
                    Ok(head) if head == source => {
                        Err(SignerJournalErrorV0::CommitNotApplied { commit })
                    }
                    Ok(_) => Err(SignerJournalErrorV0::CommitUncertain {
                        commit,
                        reason: "head is neither exact source nor exact target",
                    }),
                    Err(_) => Err(SignerJournalErrorV0::CommitUncertain {
                        commit,
                        reason: "head cannot be confirmed",
                    }),
                }
            }
        }
    }

    fn synchronize_external_head(&mut self) -> Result<(), SignerJournalErrorV0> {
        let external = load_external_head_v0(
            &mut self.external_watermark,
            self.profile.external_watermark_scope(),
            self.journal_id,
        )
        .map_err(|error| SignerJournalErrorV0::external("read external watermark", error))?
        .ok_or(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkMissing,
        ))?;
        let local = self.watermark_for(self.observed_head)?;
        if validate_external_relation(&self.connection, external, local)?
            == SignerExternalWatermarkRelationV0::Exact
        {
            return Ok(());
        }
        compare_and_advance_external_head_v0(
            &mut self.external_watermark,
            &self.connection,
            self.journal_id,
            Some(external),
            local,
        )
        .map_err(|error| SignerJournalErrorV0::external("advance external watermark", error))?;
        self.require_external_exact(local, "confirm external watermark advance")
    }

    fn require_external_exact(
        &mut self,
        expected: SignerWatermarkV0,
        stage: &'static str,
    ) -> Result<(), SignerJournalErrorV0> {
        let observed = load_external_head_v0(
            &mut self.external_watermark,
            self.profile.external_watermark_scope(),
            self.journal_id,
        )
        .map_err(|error| SignerJournalErrorV0::external(stage, error))?;
        if observed != Some(expected) {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::ExternalWatermarkFork,
            ));
        }
        Ok(())
    }

    fn watermark_for(
        &self,
        head: JournalHeadV0,
    ) -> Result<SignerWatermarkV0, SignerJournalErrorV0> {
        watermark_for_parts(&self.profile, self.journal_id, head)
    }

    fn ensure_operational(&mut self) -> Result<(), SignerJournalErrorV0> {
        self.ensure_file_identity()?;
        validate_transaction_environment(&self.connection, &self.profile)?;
        validate_storage_resource_bounds(&self.database_path, &self.profile)?;
        let head = read_head(&self.connection, self.journal_id)?;
        if head != self.observed_head {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::CommitReadbackConflict,
            ));
        }
        validate_capacity(&read_capacity(&self.connection)?, &self.profile)
    }

    fn ensure_file_identity(&self) -> Result<(), SignerJournalErrorV0> {
        if std::process::id() != self.owner_pid {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::ProcessChanged,
            ));
        }
        let wal_path = sqlite_auxiliary_path(&self.database_path, "-wal");
        let shm_path = sqlite_auxiliary_path(&self.database_path, "-shm");
        if file_identity(&self.database_path)? != self.database_identity
            || file_identity(&self.lock_path)? != self.lock_identity
            || file_identity(&wal_path)? != self.wal_identity
            || file_identity(&shm_path)? != self.shm_identity
            || directory_identity(&self.directory_path)? != self.directory_identity
            || file_handle_identity(&self.database_file)? != self.database_identity
            || file_handle_identity(&self.lock_file)? != self.lock_identity
            || file_handle_identity(&self.wal_file)? != self.wal_identity
            || file_handle_identity(&self.shm_file)? != self.shm_identity
            || directory_handle_identity(&self.directory_file)? != self.directory_identity
        {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::FileIdentityChanged,
            ));
        }
        Ok(())
    }

    fn validate_database(&self) -> Result<SignerJournalLifetimeInventoryV1, SignerJournalErrorV0> {
        self.ensure_file_identity()?;
        validate_transaction_environment(&self.connection, &self.profile)?;
        validate_canonical_schema(&self.connection)?;
        let journal_id = read_and_validate_metadata(&self.connection, &self.profile)?;
        if journal_id != self.journal_id {
            return Err(SignerJournalErrorV0::MetadataMismatch);
        }
        validate_integrity(&self.connection)?;
        let lifetime_inventory =
            validate_all_records(&self.connection, &self.profile, self.journal_id)?;
        validate_storage_resource_bounds(&self.database_path, &self.profile)?;
        Ok(lifetime_inventory)
    }
}

impl<W: ExternalMonotonicWatermarkV0> PinnedSqliteSignerJournalV0<W> {
    pub fn open_existing_v0(
        database_path: impl AsRef<Path>,
        profile: SignerJournalProfileV0,
        mut external_watermark: W,
    ) -> Result<Self, SignerJournalErrorV0> {
        ensure_supported_platform()?;
        let database_path = canonical_existing_database_path(database_path.as_ref())?;
        let directory_path = database_path
            .parent()
            .ok_or(SignerJournalErrorV0::InvalidProfile("database parent"))?
            .to_path_buf();
        let directory_file = File::open(&directory_path)
            .map_err(|error| SignerJournalErrorV0::io("pin signer directory", error))?;
        let directory_identity = directory_handle_identity(&directory_file)?;
        require_auxiliary_files(&database_path)?;
        let lock_path = lock_path_for(&database_path)?;
        let lock_file = open_existing_private_file(&lock_path, "open lock sidecar")?;
        acquire_lifetime_lock(&lock_file)?;
        let database_file = open_existing_private_file(&database_path, "pin database")?;
        acquire_lifetime_lock(&database_file)?;
        let database_identity = file_handle_identity(&database_file)?;
        let lock_identity = file_handle_identity(&lock_file)?;
        let (wal_file, wal_identity, shm_file, shm_identity) =
            pin_auxiliary_files(&database_path, profile.maximum_database_bytes())?;

        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| SignerJournalErrorV0::sqlite("open pinned existing database", error))?;
        configure_pinned_read_only_connection(&connection)?;
        let journal_id = read_and_validate_metadata(&connection, &profile)?;
        let observed_head = read_head(&connection, journal_id)?;
        let lifetime_inventory =
            validate_pinned_database_connection(&connection, &database_path, &profile, journal_id)?;
        let local_watermark = watermark_for_parts(&profile, journal_id, observed_head)?;
        let observed_external_watermark = load_external_head_v0(
            &mut external_watermark,
            profile.external_watermark_scope(),
            journal_id,
        )
        .map_err(|error| {
            SignerJournalErrorV0::external("observe pinned external watermark", error)
        })?
        .ok_or(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkMissing,
        ))?;
        let external_relation =
            validate_external_relation(&connection, observed_external_watermark, local_watermark)?;
        let capacity = read_capacity(&connection)?;
        validate_capacity(&capacity, &profile)?;
        let tail = read_tail_facts(&connection, observed_head)?;
        let pending_intent = read_pending_intent_facts(&connection)?;
        let facts = SignerJournalReconciliationFactsV0 {
            journal_id,
            profile_checksum: profile.profile_checksum(),
            local_watermark,
            observed_external_watermark,
            external_relation,
            capacity,
            lifetime_inventory,
            tail,
            pending_intent,
        };
        let pinned = Self {
            connection,
            database_file,
            lock_file,
            wal_file,
            shm_file,
            directory_file,
            database_path,
            lock_path,
            directory_path,
            database_identity,
            lock_identity,
            wal_identity,
            shm_identity,
            directory_identity,
            profile,
            external_watermark,
            journal_id,
            observed_head,
            facts,
            owner_pid: std::process::id(),
            owner_affinity: Arc::new(()),
        };
        pinned.revalidate_pinned()?;
        Ok(pinned)
    }

    pub fn path(&self) -> &Path {
        &self.database_path
    }

    pub const fn profile(&self) -> &SignerJournalProfileV0 {
        &self.profile
    }

    pub const fn reconciliation_facts(&self) -> SignerJournalReconciliationFactsV0 {
        self.facts
    }

    /// Confirms the exact local/external signer head for a future whole-node
    /// checkpoint join without advancing either durable namespace.
    pub fn confirm_node_checkpoint_head_exact_v0(
        &mut self,
    ) -> Result<ConfirmedSignerNodeCheckpointFactsV0, SignerJournalErrorV0> {
        let before_inventory = self.revalidate_pinned()?;
        let external = load_external_head_v0(
            &mut self.external_watermark,
            self.profile.external_watermark_scope(),
            self.journal_id,
        )
        .map_err(|error| {
            SignerJournalErrorV0::external("confirm node-checkpoint external watermark", error)
        })?
        .ok_or(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkMissing,
        ))?;
        let relation =
            validate_external_relation(&self.connection, external, self.facts.local_watermark)?;
        if relation != SignerExternalWatermarkRelationV0::Exact {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::ExternalWatermarkRepairRequired,
            ));
        }
        let after_inventory = self.revalidate_pinned()?;
        if before_inventory != after_inventory {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::CommitReadbackConflict,
            ));
        }
        Ok(ConfirmedSignerNodeCheckpointFactsV0 {
            journal_id: self.journal_id,
            profile_checksum: self.profile.profile_checksum(),
            identity: SignerNodeCheckpointIdentityV0::from_profile(&self.profile),
            exact_watermark: external,
            capacity: self.facts.capacity,
            lifetime_inventory: after_inventory,
            tail: self.facts.tail,
            pending_intent: self.facts.pending_intent,
            owner_affinity: Arc::clone(&self.owner_affinity),
        })
    }

    /// Consumes the pinned startup owner, rechecks its exact local and external
    /// observations, repairs at most the authenticated one-event local-first
    /// window, and yields the normal operational journal owner.
    pub fn activate_v0(
        mut self,
    ) -> Result<SqliteSignerJournalV0<W>, SignerJournalActivationFailureV0<W>> {
        if let Err(error) = self.revalidate_pinned() {
            return Err(SignerJournalActivationFailureV0::new(self, error));
        }

        let external = match load_external_head_v0(
            &mut self.external_watermark,
            self.profile.external_watermark_scope(),
            self.journal_id,
        ) {
            Ok(Some(value)) => value,
            Ok(None) => {
                return Err(SignerJournalActivationFailureV0::new(
                    self,
                    SignerJournalErrorV0::Conflict(
                        SignerJournalConflictV0::ExternalWatermarkMissing,
                    ),
                ));
            }
            Err(error) => {
                return Err(SignerJournalActivationFailureV0::new(
                    self,
                    SignerJournalErrorV0::external(
                        "recheck pinned external watermark before activation",
                        error,
                    ),
                ));
            }
        };
        if external != self.facts.observed_external_watermark {
            return Err(SignerJournalActivationFailureV0::new(
                self,
                SignerJournalErrorV0::Conflict(SignerJournalConflictV0::ExternalWatermarkFork),
            ));
        }
        let relation = match validate_external_relation(
            &self.connection,
            external,
            self.facts.local_watermark,
        ) {
            Ok(value) => value,
            Err(error) => return Err(SignerJournalActivationFailureV0::new(self, error)),
        };
        if relation != self.facts.external_relation {
            return Err(SignerJournalActivationFailureV0::new(
                self,
                SignerJournalErrorV0::Conflict(SignerJournalConflictV0::ExternalWatermarkFork),
            ));
        }

        if relation == SignerExternalWatermarkRelationV0::LocalOneAhead {
            if let Err(error) = compare_and_advance_external_head_v0(
                &mut self.external_watermark,
                &self.connection,
                self.journal_id,
                Some(external),
                self.facts.local_watermark,
            ) {
                return Err(SignerJournalActivationFailureV0::new(
                    self,
                    SignerJournalErrorV0::external("activate pinned external watermark", error),
                ));
            }
            self.facts.observed_external_watermark = self.facts.local_watermark;
            self.facts.external_relation = SignerExternalWatermarkRelationV0::Exact;
        }
        let confirmed = match load_external_head_v0(
            &mut self.external_watermark,
            self.profile.external_watermark_scope(),
            self.journal_id,
        ) {
            Ok(value) => value,
            Err(error) => {
                return Err(SignerJournalActivationFailureV0::new(
                    self,
                    SignerJournalErrorV0::external("confirm activated external watermark", error),
                ));
            }
        };
        if confirmed != Some(self.facts.local_watermark) {
            return Err(SignerJournalActivationFailureV0::new(
                self,
                SignerJournalErrorV0::Conflict(SignerJournalConflictV0::ExternalWatermarkFork),
            ));
        }

        let operational_connection = match Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ) {
            Ok(value) => value,
            Err(error) => {
                return Err(SignerJournalActivationFailureV0::new(
                    self,
                    SignerJournalErrorV0::sqlite("open activated existing database", error),
                ));
            }
        };
        let activated_inventory = match configure_connection(
            &operational_connection,
            false,
            self.profile.maximum_database_bytes(),
        )
        .and_then(|()| materialize_auxiliary_files(&operational_connection))
        .and_then(|()| {
            validate_operational_database_connection(
                &operational_connection,
                &self.database_path,
                &self.profile,
                self.journal_id,
            )
        }) {
            Ok(inventory) => inventory,
            Err(error) => return Err(SignerJournalActivationFailureV0::new(self, error)),
        };
        let activated_head = match read_head(&operational_connection, self.journal_id) {
            Ok(value) => value,
            Err(error) => return Err(SignerJournalActivationFailureV0::new(self, error)),
        };
        if activated_head != self.observed_head
            || activated_inventory != self.facts.lifetime_inventory
        {
            return Err(SignerJournalActivationFailureV0::new(
                self,
                SignerJournalErrorV0::Conflict(SignerJournalConflictV0::CommitReadbackConflict),
            ));
        }
        if let Err(error) = self.ensure_file_identity() {
            return Err(SignerJournalActivationFailureV0::new(self, error));
        }

        let Self {
            connection,
            database_file,
            lock_file,
            wal_file,
            shm_file,
            directory_file,
            database_path,
            lock_path,
            directory_path,
            database_identity,
            lock_identity,
            wal_identity,
            shm_identity,
            directory_identity,
            profile,
            external_watermark,
            journal_id,
            observed_head,
            facts: _,
            owner_pid,
            owner_affinity,
        } = self;
        drop(connection);
        Ok(SqliteSignerJournalV0 {
            connection: operational_connection,
            database_file,
            lock_file,
            wal_file,
            shm_file,
            directory_file,
            database_path,
            lock_path,
            directory_path,
            database_identity,
            lock_identity,
            wal_identity,
            shm_identity,
            directory_identity,
            profile,
            external_watermark,
            journal_id,
            observed_head,
            owner_pid,
            owner_affinity,
        })
    }

    fn revalidate_pinned(&self) -> Result<SignerJournalLifetimeInventoryV1, SignerJournalErrorV0> {
        self.ensure_file_identity()?;
        let before_head = read_head(&self.connection, self.journal_id)?;
        let before_inventory = validate_pinned_database_connection(
            &self.connection,
            &self.database_path,
            &self.profile,
            self.journal_id,
        )?;
        let capacity = read_capacity(&self.connection)?;
        validate_capacity(&capacity, &self.profile)?;
        let tail = read_tail_facts(&self.connection, before_head)?;
        let pending_intent = read_pending_intent_facts(&self.connection)?;
        let after_inventory = validate_pinned_database_connection(
            &self.connection,
            &self.database_path,
            &self.profile,
            self.journal_id,
        )?;
        let after_head = read_head(&self.connection, self.journal_id)?;
        if before_head != after_head
            || before_inventory != after_inventory
            || after_head != self.observed_head
            || capacity != self.facts.capacity
            || after_inventory != self.facts.lifetime_inventory
            || tail != self.facts.tail
            || pending_intent != self.facts.pending_intent
            || watermark_for_parts(&self.profile, self.journal_id, after_head)?
                != self.facts.local_watermark
        {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::CommitReadbackConflict,
            ));
        }
        Ok(after_inventory)
    }

    fn ensure_file_identity(&self) -> Result<(), SignerJournalErrorV0> {
        if std::process::id() != self.owner_pid {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::ProcessChanged,
            ));
        }
        let wal_path = sqlite_auxiliary_path(&self.database_path, "-wal");
        let shm_path = sqlite_auxiliary_path(&self.database_path, "-shm");
        if file_identity(&self.database_path)? != self.database_identity
            || file_identity(&self.lock_path)? != self.lock_identity
            || file_identity(&wal_path)? != self.wal_identity
            || file_identity(&shm_path)? != self.shm_identity
            || directory_identity(&self.directory_path)? != self.directory_identity
            || file_handle_identity(&self.database_file)? != self.database_identity
            || file_handle_identity(&self.lock_file)? != self.lock_identity
            || file_handle_identity(&self.wal_file)? != self.wal_identity
            || file_handle_identity(&self.shm_file)? != self.shm_identity
            || directory_handle_identity(&self.directory_file)? != self.directory_identity
        {
            return Err(SignerJournalErrorV0::Conflict(
                SignerJournalConflictV0::FileIdentityChanged,
            ));
        }
        Ok(())
    }
}

fn watermark_for_parts(
    profile: &SignerJournalProfileV0,
    journal_id: [u8; 32],
    head: JournalHeadV0,
) -> Result<SignerWatermarkV0, SignerJournalErrorV0> {
    SignerWatermarkV0::from_persisted_parts(
        profile.external_watermark_scope(),
        journal_id,
        head.sequence,
        head.chain_checksum,
    )
    .map_err(|error| SignerJournalErrorV0::external("construct local watermark", error))
}

/// Reads one external head through either the legacy opaque protocol or the
/// explicitly opted-in semantic protocol.  The capability never crosses the
/// signer-journal boundary: semantic implementations authenticate their own
/// immutable `(scope, journal, capability)` namespace.
fn load_external_head_v0<W: ExternalMonotonicWatermarkV0>(
    external: &mut W,
    scope: [u8; 32],
    journal_id: [u8; 32],
) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
    if external.semantic_mode_v0() {
        external
            .load_semantic_v0(scope, journal_id)
            .map(|value| value.map(|(watermark, _facts)| watermark))
    } else {
        external.load(scope)
    }
}

/// Advances one external head through the semantic protocol when explicitly
/// enabled.  For non-genesis records, facts are read from the exact local
/// intent event at the target sequence; a semantic authority therefore sees
/// the same epoch/view/revision/fingerprint/root that the local journal has
/// durably committed.  Sequence-zero claims use the adapter-owned genesis
/// binding and never invent signer-intent facts in this crate.
fn compare_and_advance_external_head_v0<W: ExternalMonotonicWatermarkV0>(
    external: &mut W,
    connection: &Connection,
    journal_id: [u8; 32],
    expected: Option<SignerWatermarkV0>,
    target: SignerWatermarkV0,
) -> Result<(), ExternalWatermarkErrorV0> {
    if !external.semantic_mode_v0() {
        return external.compare_and_advance(expected, target);
    }
    if target.journal_id() != journal_id {
        return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
    }
    if target.sequence() == 0 {
        return external.compare_and_advance_semantic_genesis_v0(expected, target);
    }
    let event = read_event(connection, target.sequence())
        .map_err(|_| ExternalWatermarkErrorV0::InvalidPersistedState)?
        .ok_or(ExternalWatermarkErrorV0::InvalidPersistedState)?;
    let intent = read_intent(connection, event.fingerprint)
        .map_err(|_| ExternalWatermarkErrorV0::InvalidPersistedState)?
        .ok_or(ExternalWatermarkErrorV0::InvalidPersistedState)?;
    let facts = ExternalWatermarkSemanticFactsV0::from_journal_intent(
        intent.epoch,
        intent.view,
        intent.safety_revision,
        signer_journal_lifecycle_nonce_v0(
            intent.epoch,
            intent.view,
            intent.safety_revision,
            intent.fingerprint,
            intent.signing_root,
            target.sequence(),
        ),
        intent.fingerprint,
        intent.signing_root,
    )
    .ok_or(ExternalWatermarkErrorV0::InvalidPersistedState)?;
    external.compare_and_advance_semantic_v0(expected, target, facts)
}

fn validate_external_relation(
    connection: &Connection,
    external: SignerWatermarkV0,
    local: SignerWatermarkV0,
) -> Result<SignerExternalWatermarkRelationV0, SignerJournalErrorV0> {
    validate_external_identity(&external, &local)?;
    if external == local {
        return Ok(SignerExternalWatermarkRelationV0::Exact);
    }
    if external.sequence() > local.sequence() {
        return Err(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkAhead,
        ));
    }
    if external.sequence() == local.sequence() {
        return Err(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkFork,
        ));
    }
    if external.sequence().checked_add(1) != Some(local.sequence()) {
        return Err(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkRollback,
        ));
    }
    let head_event = read_event(connection, local.sequence())?.ok_or(
        SignerJournalErrorV0::PersistedRepresentationMalformed("local head event is absent"),
    )?;
    if head_event.predecessor_sequence != external.sequence()
        || head_event.predecessor_chain_checksum != external.chain_checksum()
    {
        return Err(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkFork,
        ));
    }
    Ok(SignerExternalWatermarkRelationV0::LocalOneAhead)
}

fn read_pending_intent_facts(
    connection: &Connection,
) -> Result<Option<SignerPreparedIntentFactsV0>, SignerJournalErrorV0> {
    let fingerprint: Option<Vec<u8>> = connection
        .query_row(
            "SELECT prepared.fingerprint
             FROM signer_journal_events_v0 prepared
             WHERE prepared.event_kind=0 AND NOT EXISTS (
                 SELECT 1 FROM signer_journal_events_v0 signed
                 WHERE signed.fingerprint=prepared.fingerprint AND signed.event_kind=1
             )",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| SignerJournalErrorV0::sqlite("read pending signer intent", error))?;
    let Some(fingerprint) = fingerprint else {
        return Ok(None);
    };
    let fingerprint = decode_array32(&fingerprint, "pending intent fingerprint")?;
    let pending = read_intent(connection, fingerprint)?.ok_or(
        SignerJournalErrorV0::PersistedRepresentationMalformed(
            "pending event references absent intent",
        ),
    )?;
    Ok(Some(prepared_intent_facts_v0(&pending)))
}

fn prepared_intent_facts_v0(pending: &PreparedIntentV0) -> SignerPreparedIntentFactsV0 {
    SignerPreparedIntentFactsV0 {
        fingerprint: pending.fingerprint,
        epoch: pending.epoch,
        view: pending.view,
        kind: pending.kind,
        safety_revision: pending.safety_revision,
        signing_root: pending.signing_root,
        intent_checksum: pending.intent_checksum,
    }
}

fn read_tail_facts(
    connection: &Connection,
    head: JournalHeadV0,
) -> Result<Option<SignerJournalTailFactsV0>, SignerJournalErrorV0> {
    if head.sequence == 0 {
        return Ok(None);
    }
    let event = read_event(connection, head.sequence)?.ok_or(
        SignerJournalErrorV0::PersistedRepresentationMalformed("local head event is absent"),
    )?;
    let intent = read_intent(connection, event.fingerprint)?.ok_or(
        SignerJournalErrorV0::PersistedRepresentationMalformed(
            "tail event references absent intent",
        ),
    )?;
    let (state, signature) = match (event.kind, event.signature) {
        (0, None) => (SignerJournalTailStateV0::Prepared, None),
        (1, Some(signature)) => (SignerJournalTailStateV0::Signed, Some(signature)),
        _ => {
            return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
                "tail event lifecycle",
            ));
        }
    };
    Ok(Some(SignerJournalTailFactsV0 {
        state,
        fingerprint: intent.fingerprint,
        epoch: intent.epoch,
        view: intent.view,
        kind: intent.kind,
        safety_revision: intent.safety_revision,
        signing_root: intent.signing_root,
        intent_checksum: intent.intent_checksum,
        signature,
    }))
}

fn validate_pinned_database_connection(
    connection: &Connection,
    database_path: &Path,
    profile: &SignerJournalProfileV0,
    journal_id: [u8; 32],
) -> Result<SignerJournalLifetimeInventoryV1, SignerJournalErrorV0> {
    validate_pinned_read_only_environment(connection)?;
    validate_canonical_schema(connection)?;
    if read_and_validate_metadata(connection, profile)? != journal_id {
        return Err(SignerJournalErrorV0::MetadataMismatch);
    }
    validate_integrity(connection)?;
    let lifetime_inventory = validate_all_records(connection, profile, journal_id)?;
    validate_storage_resource_bounds(database_path, profile)?;
    Ok(lifetime_inventory)
}

fn validate_operational_database_connection(
    connection: &Connection,
    database_path: &Path,
    profile: &SignerJournalProfileV0,
    journal_id: [u8; 32],
) -> Result<SignerJournalLifetimeInventoryV1, SignerJournalErrorV0> {
    validate_transaction_environment(connection, profile)?;
    validate_canonical_schema(connection)?;
    if read_and_validate_metadata(connection, profile)? != journal_id {
        return Err(SignerJournalErrorV0::MetadataMismatch);
    }
    validate_integrity(connection)?;
    let lifetime_inventory = validate_all_records(connection, profile, journal_id)?;
    validate_storage_resource_bounds(database_path, profile)?;
    Ok(lifetime_inventory)
}

fn prepare_intent(
    profile: &SignerJournalProfileV0,
    journal_id: [u8; 32],
    intent: &CanonicalSignIntentV0,
) -> Result<PreparedIntentV0, SignerJournalErrorV0> {
    if intent.chain_id() != profile.chain_id() {
        return Err(SignerJournalErrorV0::IntentProfileDrift("chain ID"));
    }
    if intent.protocol_version() != profile.protocol_version() {
        return Err(SignerJournalErrorV0::IntentProfileDrift("protocol version"));
    }
    if intent.epoch() != profile.epoch() {
        return Err(SignerJournalErrorV0::IntentProfileDrift("epoch"));
    }
    if intent.validator_set_id() != profile.validator_set_id() {
        return Err(SignerJournalErrorV0::IntentProfileDrift("validator-set ID"));
    }
    if intent.author() != profile.author() {
        return Err(SignerJournalErrorV0::IntentProfileDrift("author"));
    }
    intent
        .validate(profile.validator_set())
        .map_err(|error| SignerJournalErrorV0::intent("validate complete envelope", error))?;
    let preimage = intent
        .preimage()
        .canonical_bytes()
        .map_err(|error| SignerJournalErrorV0::intent("encode canonical preimage", error))?;
    if preimage.is_empty() {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "canonical sign preimage is empty",
        ));
    }
    let canonical_intent = intent
        .canonical_bytes()
        .map_err(|error| SignerJournalErrorV0::intent("encode canonical intent", error))?;
    if canonical_intent.len() > profile.maximum_intent_bytes() {
        return Err(SignerJournalErrorV0::IntentTooLarge {
            actual: canonical_intent.len(),
            maximum: profile.maximum_intent_bytes(),
        });
    }
    let (view, kind) = match intent.preimage() {
        CanonicalSignPreimageV0::Vote(value) => (value.view().get(), 0),
        CanonicalSignPreimageV0::TimeoutVote(value) => (value.view().get(), 1),
    };
    let fingerprint = intent.fingerprint().into_bytes();
    let signing_root = intent.signing_root().into_bytes();
    let epoch = intent.epoch().get();
    let safety_revision = intent.authorizing_safety_revision();
    let checksum = intent_checksum(
        journal_id,
        fingerprint,
        epoch,
        view,
        kind,
        safety_revision,
        signing_root,
        &canonical_intent,
    );
    Ok(PreparedIntentV0 {
        fingerprint,
        epoch,
        view,
        kind,
        safety_revision,
        signing_root,
        canonical_intent,
        intent_checksum: checksum,
    })
}

fn require_exact_intent(
    stored: &PreparedIntentV0,
    incoming: &PreparedIntentV0,
) -> Result<(), SignerJournalErrorV0> {
    let fixed_equal = stored.fingerprint.ct_eq(&incoming.fingerprint).unwrap_u8() == 1
        && stored
            .signing_root
            .ct_eq(&incoming.signing_root)
            .unwrap_u8()
            == 1
        && stored
            .intent_checksum
            .ct_eq(&incoming.intent_checksum)
            .unwrap_u8()
            == 1;
    if !fixed_equal
        || stored.epoch != incoming.epoch
        || stored.view != incoming.view
        || stored.kind != incoming.kind
        || stored.safety_revision != incoming.safety_revision
        || stored.canonical_intent != incoming.canonical_intent
    {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "stored fingerprint does not identify the exact supplied intent",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn intent_checksum(
    journal_id: [u8; 32],
    fingerprint: [u8; 32],
    epoch: u64,
    view: u64,
    kind: u8,
    safety_revision: u64,
    signing_root: [u8; 32],
    canonical_intent: &[u8],
) -> [u8; 32] {
    hash_domain(
        INTENT_DOMAIN_V0,
        &[
            &journal_id,
            &fingerprint,
            &epoch.to_be_bytes(),
            &view.to_be_bytes(),
            &[kind],
            &safety_revision.to_be_bytes(),
            &signing_root,
            canonical_intent,
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn event_checksum(
    journal_id: [u8; 32],
    sequence: u64,
    kind: u8,
    fingerprint: [u8; 32],
    signature: Option<&[u8; 64]>,
    predecessor: JournalHeadV0,
    intent_checksum: [u8; 32],
) -> [u8; 32] {
    let signature_presence = [u8::from(signature.is_some())];
    let signature_bytes = signature.map_or(&[][..], |value| value.as_slice());
    hash_domain(
        EVENT_DOMAIN_V0,
        &[
            &journal_id,
            &sequence.to_be_bytes(),
            &[kind],
            &fingerprint,
            &signature_presence,
            signature_bytes,
            &predecessor.sequence.to_be_bytes(),
            &predecessor.chain_checksum,
            &intent_checksum,
        ],
    )
}

fn chain_checksum(predecessor: JournalHeadV0, event_checksum: [u8; 32]) -> [u8; 32] {
    hash_domain(
        CHAIN_DOMAIN_V0,
        &[
            &predecessor.sequence.to_be_bytes(),
            &predecessor.chain_checksum,
            &event_checksum,
        ],
    )
}

fn head_checksum(journal_id: [u8; 32], head: JournalHeadV0) -> [u8; 32] {
    hash_domain(
        HEAD_DOMAIN_V0,
        &[
            &journal_id,
            &head.sequence.to_be_bytes(),
            &head.chain_checksum,
        ],
    )
}

fn metadata_checksum(profile: &SignerJournalProfileV0, journal_id: [u8; 32]) -> [u8; 32] {
    let author_public_key = profile
        .validator_set()
        .validator(profile.author())
        .map(|validator| validator.consensus_key())
        .unwrap_or_default();
    hash_domain(
        METADATA_DOMAIN_V0,
        &[
            &JOURNAL_SCHEMA_VERSION_V0.to_be_bytes(),
            &journal_id,
            &profile.profile_checksum(),
            profile.chain_id().as_bytes(),
            &profile.protocol_version().get().to_be_bytes(),
            &profile.epoch().get().to_be_bytes(),
            profile.validator_set_id().as_bytes(),
            profile.validator_set().genesis_hash().as_bytes(),
            profile.author().as_bytes(),
            author_public_key.as_bytes(),
            &profile.signer_profile_ref(),
            &profile.external_watermark_scope(),
            &profile.maximum_intents().to_be_bytes(),
            &(profile.maximum_intent_bytes() as u64).to_be_bytes(),
            &(profile.maximum_database_bytes() as u64).to_be_bytes(),
        ],
    )
}

fn initial_head(profile: &SignerJournalProfileV0, journal_id: [u8; 32]) -> JournalHeadV0 {
    JournalHeadV0 {
        sequence: 0,
        chain_checksum: hash_domain(
            INITIAL_HEAD_DOMAIN_V0,
            &[
                &journal_id,
                &metadata_checksum(profile, journal_id),
                &profile.external_watermark_scope(),
            ],
        ),
    }
}

fn initialize_schema(
    connection: &Connection,
    profile: &SignerJournalProfileV0,
    journal_id: [u8; 32],
) -> Result<JournalHeadV0, SignerJournalErrorV0> {
    connection
        .execute_batch("BEGIN IMMEDIATE;")
        .map_err(|error| SignerJournalErrorV0::sqlite("begin schema initialization", error))?;
    let result = (|| {
        connection
            .execute_batch(JOURNAL_SCHEMA_SQL_V0)
            .map_err(|error| SignerJournalErrorV0::sqlite("create signer schema", error))?;
        let validator = profile
            .validator_set()
            .validator(profile.author())
            .ok_or(SignerJournalErrorV0::MetadataMismatch)?;
        let metadata_checksum = metadata_checksum(profile, journal_id);
        connection
            .execute(
                "INSERT INTO signer_journal_metadata_v0(
                    singleton, journal_schema, journal_id, chain_id, protocol_version_be,
                    epoch_be, validator_set_id, genesis_hash, author, author_public_key,
                    signer_profile_ref, external_watermark_scope, maximum_intents_be,
                    maximum_intent_bytes_be, maximum_database_bytes_be, profile_checksum,
                    metadata_checksum
                 ) VALUES (1, 0, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                           ?12, ?13, ?14, ?15)",
                params![
                    journal_id.as_slice(),
                    profile.chain_id().as_bytes(),
                    profile.protocol_version().get().to_be_bytes().as_slice(),
                    profile.epoch().get().to_be_bytes().as_slice(),
                    profile.validator_set_id().as_bytes().as_slice(),
                    profile.validator_set().genesis_hash().as_bytes().as_slice(),
                    profile.author().as_bytes(),
                    validator.consensus_key().as_bytes().as_slice(),
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
            .map_err(|error| SignerJournalErrorV0::sqlite("insert signer metadata", error))?;
        let head = initial_head(profile, journal_id);
        connection
            .execute(
                "INSERT INTO signer_journal_head_v0(
                    singleton, active_sequence_be, active_chain_checksum, head_checksum
                 ) VALUES (1, ?1, ?2, ?3)",
                params![
                    head.sequence.to_be_bytes().as_slice(),
                    head.chain_checksum.as_slice(),
                    head_checksum(journal_id, head).as_slice(),
                ],
            )
            .map_err(|error| SignerJournalErrorV0::sqlite("insert signer head", error))?;
        connection
            .execute(
                "INSERT INTO signer_journal_accounting_v0(
                    singleton, intent_count, event_count, intent_bytes,
                    maximum_safety_revision_be, maximum_vote_view_be,
                    maximum_timeout_view_be
                 ) VALUES (1, 0, 0, 0, NULL, NULL, NULL)",
                [],
            )
            .map_err(|error| SignerJournalErrorV0::sqlite("insert signer accounting", error))?;
        connection
            .execute_batch("COMMIT;")
            .map_err(|error| SignerJournalErrorV0::sqlite("commit schema initialization", error))?;
        Ok(head)
    })();
    if result.is_err() {
        let _ = connection.execute_batch("ROLLBACK;");
    }
    result
}

#[allow(clippy::type_complexity)]
fn read_and_validate_metadata(
    connection: &Connection,
    profile: &SignerJournalProfileV0,
) -> Result<[u8; 32], SignerJournalErrorV0> {
    let row: (
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
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
            "SELECT journal_schema, journal_id, chain_id, protocol_version_be, epoch_be,
                    validator_set_id, genesis_hash, author, author_public_key,
                    signer_profile_ref, external_watermark_scope, maximum_intents_be,
                    maximum_intent_bytes_be, maximum_database_bytes_be, profile_checksum,
                    metadata_checksum
             FROM signer_journal_metadata_v0 WHERE singleton=1",
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
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                ))
            },
        )
        .map_err(|error| SignerJournalErrorV0::sqlite("read signer metadata", error))?;
    let journal_id = decode_array32(&row.1, "journal ID")?;
    let validator = profile
        .validator_set()
        .validator(profile.author())
        .ok_or(SignerJournalErrorV0::MetadataMismatch)?;
    let expected = metadata_checksum(profile, journal_id);
    if row.0 != i64::from(JOURNAL_SCHEMA_VERSION_V0)
        || row.2 != profile.chain_id().as_bytes()
        || row.3 != profile.protocol_version().get().to_be_bytes()
        || row.4 != profile.epoch().get().to_be_bytes()
        || row.5 != profile.validator_set_id().as_bytes()
        || row.6 != profile.validator_set().genesis_hash().as_bytes()
        || row.7 != profile.author().as_bytes()
        || row.8 != validator.consensus_key().as_bytes()
        || row.9 != profile.signer_profile_ref()
        || row.10 != profile.external_watermark_scope()
        || row.11 != profile.maximum_intents().to_be_bytes()
        || row.12 != (profile.maximum_intent_bytes() as u64).to_be_bytes()
        || row.13 != (profile.maximum_database_bytes() as u64).to_be_bytes()
        || row.14 != profile.profile_checksum()
        || row.15 != expected
    {
        return Err(SignerJournalErrorV0::MetadataMismatch);
    }
    Ok(journal_id)
}

fn read_head(
    connection: &Connection,
    journal_id: [u8; 32],
) -> Result<JournalHeadV0, SignerJournalErrorV0> {
    let (sequence, chain, stored_checksum): (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT active_sequence_be, active_chain_checksum, head_checksum
             FROM signer_journal_head_v0 WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| SignerJournalErrorV0::sqlite("read signer head", error))?;
    let head = JournalHeadV0 {
        sequence: decode_u64_blob(&sequence, "head sequence")?,
        chain_checksum: decode_array32(&chain, "head chain checksum")?,
    };
    if stored_checksum.as_slice() != head_checksum(journal_id, head) {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "head checksum",
        ));
    }
    Ok(head)
}

fn read_capacity(connection: &Connection) -> Result<JournalCapacityV0, SignerJournalErrorV0> {
    let (intents, events, bytes, maximum, vote_view, timeout_view): RawCapacityRowV0 = connection
        .query_row(
            "SELECT intent_count, event_count, intent_bytes, maximum_safety_revision_be,
                    maximum_vote_view_be, maximum_timeout_view_be
             FROM signer_journal_accounting_v0 WHERE singleton=1",
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
        .map_err(|error| SignerJournalErrorV0::sqlite("read signer accounting", error))?;
    Ok(JournalCapacityV0 {
        intent_count: u64::try_from(intents).map_err(|_| {
            SignerJournalErrorV0::PersistedRepresentationMalformed("negative intent count")
        })?,
        event_count: u64::try_from(events).map_err(|_| {
            SignerJournalErrorV0::PersistedRepresentationMalformed("negative event count")
        })?,
        intent_bytes: u64::try_from(bytes).map_err(|_| {
            SignerJournalErrorV0::PersistedRepresentationMalformed("negative intent bytes")
        })?,
        maximum_safety_revision: maximum
            .as_deref()
            .map(|value| decode_u64_blob(value, "maximum safety revision"))
            .transpose()?,
        maximum_vote_view: vote_view
            .as_deref()
            .map(|value| decode_u64_blob(value, "maximum vote view"))
            .transpose()?,
        maximum_timeout_view: timeout_view
            .as_deref()
            .map(|value| decode_u64_blob(value, "maximum timeout view"))
            .transpose()?,
    })
}

fn validate_capacity(
    capacity: &JournalCapacityV0,
    profile: &SignerJournalProfileV0,
) -> Result<(), SignerJournalErrorV0> {
    if capacity.intent_count > profile.maximum_intents()
        || capacity.event_count < capacity.intent_count
        || capacity.event_count > capacity.intent_count.saturating_mul(2)
        || capacity.intent_bytes
            > profile
                .maximum_intents()
                .saturating_mul(profile.maximum_intent_bytes() as u64)
        || (capacity.intent_count == 0) != capacity.maximum_safety_revision.is_none()
        || (capacity.intent_count == 0
            && (capacity.maximum_vote_view.is_some() || capacity.maximum_timeout_view.is_some()))
    {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "journal accounting bounds",
        ));
    }
    Ok(())
}

fn read_intent(
    connection: &Connection,
    fingerprint: [u8; 32],
) -> Result<Option<PreparedIntentV0>, SignerJournalErrorV0> {
    connection
        .query_row(
            "SELECT fingerprint, epoch_be, view_be, intent_kind, safety_revision_be,
                    signing_root, canonical_intent, intent_checksum
             FROM sign_intents_v0 WHERE fingerprint=?1",
            params![fingerprint.as_slice()],
            decode_intent_row,
        )
        .optional()
        .map_err(|error| SignerJournalErrorV0::sqlite("read canonical intent", error))
}

fn decode_intent_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PreparedIntentV0> {
    let fingerprint: Vec<u8> = row.get(0)?;
    let epoch: Vec<u8> = row.get(1)?;
    let view: Vec<u8> = row.get(2)?;
    let kind: i64 = row.get(3)?;
    let safety_revision: Vec<u8> = row.get(4)?;
    let signing_root: Vec<u8> = row.get(5)?;
    let canonical_intent: Vec<u8> = row.get(6)?;
    let intent_checksum: Vec<u8> = row.get(7)?;
    Ok(PreparedIntentV0 {
        fingerprint: array_sql::<32>(&fingerprint, 0, "32-byte fingerprint")?,
        epoch: u64_sql(&epoch, 1)?,
        view: u64_sql(&view, 2)?,
        kind: u8::try_from(kind).map_err(|_| sql_shape_error(3, "u8 intent kind"))?,
        safety_revision: u64_sql(&safety_revision, 4)?,
        signing_root: array_sql::<32>(&signing_root, 5, "32-byte signing root")?,
        canonical_intent,
        intent_checksum: array_sql::<32>(&intent_checksum, 7, "32-byte intent checksum")?,
    })
}

fn read_event(
    connection: &Connection,
    sequence: u64,
) -> Result<Option<StoredEventV0>, SignerJournalErrorV0> {
    connection
        .query_row(
            "SELECT sequence_be, event_kind, fingerprint, signature,
                    predecessor_sequence_be, predecessor_chain_checksum,
                    event_checksum, chain_checksum
             FROM signer_journal_events_v0 WHERE sequence_be=?1",
            params![sequence.to_be_bytes().as_slice()],
            decode_event_row,
        )
        .optional()
        .map_err(|error| SignerJournalErrorV0::sqlite("read journal event", error))
}

fn decode_event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEventV0> {
    let sequence: Vec<u8> = row.get(0)?;
    let kind: i64 = row.get(1)?;
    let fingerprint: Vec<u8> = row.get(2)?;
    let signature: Option<Vec<u8>> = row.get(3)?;
    let predecessor_sequence: Vec<u8> = row.get(4)?;
    let predecessor_chain_checksum: Vec<u8> = row.get(5)?;
    let event_checksum: Vec<u8> = row.get(6)?;
    let chain_checksum: Vec<u8> = row.get(7)?;
    Ok(StoredEventV0 {
        sequence: u64_sql(&sequence, 0)?,
        kind: u8::try_from(kind).map_err(|_| sql_shape_error(1, "u8 event kind"))?,
        fingerprint: array_sql::<32>(&fingerprint, 2, "32-byte fingerprint")?,
        signature: signature
            .map(|bytes| array_sql::<64>(&bytes, 3, "64-byte signature"))
            .transpose()?,
        predecessor_sequence: u64_sql(&predecessor_sequence, 4)?,
        predecessor_chain_checksum: array_sql::<32>(
            &predecessor_chain_checksum,
            5,
            "32-byte predecessor checksum",
        )?,
        event_checksum: array_sql::<32>(&event_checksum, 6, "32-byte event checksum")?,
        chain_checksum: array_sql::<32>(&chain_checksum, 7, "32-byte chain checksum")?,
    })
}

fn read_persisted_signature(
    connection: &Connection,
    fingerprint: [u8; 32],
    profile: &SignerJournalProfileV0,
) -> Result<Option<SignatureBytes>, SignerJournalErrorV0> {
    let stored: Option<Vec<u8>> = connection
        .query_row(
            "SELECT signature FROM signer_journal_events_v0
             WHERE fingerprint=?1 AND event_kind=1",
            params![fingerprint.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| SignerJournalErrorV0::sqlite("read persisted signature", error))?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let signature = SignatureBytes::from_slice(&stored)
        .map_err(|error| SignerJournalErrorV0::intent("decode persisted signature", error))?;
    let intent = read_intent(connection, fingerprint)?.ok_or(
        SignerJournalErrorV0::PersistedRepresentationMalformed(
            "signature references absent intent",
        ),
    )?;
    let validator = profile
        .validator_set()
        .validator(profile.author())
        .ok_or(SignerJournalErrorV0::MetadataMismatch)?;
    if !StrictEd25519Verifier.verify(
        validator,
        &SigningRoot::new(intent.signing_root),
        &signature,
    ) {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "persisted signature does not verify",
        ));
    }
    Ok(Some(signature))
}

fn validate_all_records(
    connection: &Connection,
    profile: &SignerJournalProfileV0,
    journal_id: [u8; 32],
) -> Result<SignerJournalLifetimeInventoryV1, SignerJournalErrorV0> {
    let mut intent_statement = connection
        .prepare(
            "SELECT fingerprint, epoch_be, view_be, intent_kind, safety_revision_be,
                    signing_root, canonical_intent, intent_checksum
             FROM sign_intents_v0 ORDER BY safety_revision_be",
        )
        .map_err(|error| SignerJournalErrorV0::sqlite("prepare intent audit", error))?;
    let rows = intent_statement
        .query_map([], decode_intent_row)
        .map_err(|error| SignerJournalErrorV0::sqlite("query intent audit", error))?;
    let mut intents = BTreeMap::new();
    let mut round_keys = BTreeSet::new();
    let mut revisions = BTreeSet::new();
    let mut maximum_views = [None, None];
    let mut durable_intent_counts = [0_u64, 0_u64];
    let mut intent_bytes = 0u64;
    for row in rows {
        let intent =
            row.map_err(|error| SignerJournalErrorV0::sqlite("read intent audit", error))?;
        if intent.epoch != profile.epoch().get()
            || intent.kind > 1
            || intent.safety_revision == 0
            || intent.canonical_intent.is_empty()
            || intent.canonical_intent.len() > profile.maximum_intent_bytes()
            || intent.canonical_intent.len() > MAXIMUM_SQL_INTENT_BYTES_V0
            || intent.intent_checksum
                != intent_checksum(
                    journal_id,
                    intent.fingerprint,
                    intent.epoch,
                    intent.view,
                    intent.kind,
                    intent.safety_revision,
                    intent.signing_root,
                    &intent.canonical_intent,
                )
            || !round_keys.insert((intent.epoch, intent.view, intent.kind))
            || !revisions.insert(intent.safety_revision)
        {
            return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
                "canonical intent row",
            ));
        }
        let decoded = decode_canonical_sign_intent_v0_exact(
            &intent.canonical_intent,
            profile.validator_set(),
        )
        .map_err(|_| {
            SignerJournalErrorV0::PersistedRepresentationMalformed(
                "canonical intent row does not exact-decode",
            )
        })?;
        let decoded = prepare_intent(profile, journal_id, &decoded).map_err(|_| {
            SignerJournalErrorV0::PersistedRepresentationMalformed(
                "canonical intent row fails signer-profile admission",
            )
        })?;
        require_exact_intent(&intent, &decoded)?;
        let kind_index = usize::from(intent.kind);
        if let Some(maximum) = maximum_views[kind_index] {
            if intent.view <= maximum {
                return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
                    "per-kind view watermark regression",
                ));
            }
        }
        maximum_views[kind_index] = Some(intent.view);
        durable_intent_counts[kind_index] = durable_intent_counts[kind_index]
            .checked_add(1)
            .ok_or(SignerJournalErrorV0::CapacityExhausted)?;
        intent_bytes = intent_bytes
            .checked_add(intent.canonical_intent.len() as u64)
            .ok_or(SignerJournalErrorV0::CapacityExhausted)?;
        let fingerprint = intent.fingerprint;
        if intents.insert(fingerprint, intent).is_some() {
            return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
                "duplicate intent fingerprint",
            ));
        }
    }
    drop(intent_statement);

    let initial = initial_head(profile, journal_id);
    let mut predecessor = initial;
    let mut prepared = BTreeSet::new();
    let mut signed = BTreeSet::new();
    let mut signed_intent_counts = [0_u64, 0_u64];
    let mut event_statement = connection
        .prepare(
            "SELECT sequence_be, event_kind, fingerprint, signature,
                    predecessor_sequence_be, predecessor_chain_checksum,
                    event_checksum, chain_checksum
             FROM signer_journal_events_v0 ORDER BY sequence_be",
        )
        .map_err(|error| SignerJournalErrorV0::sqlite("prepare event audit", error))?;
    let rows = event_statement
        .query_map([], decode_event_row)
        .map_err(|error| SignerJournalErrorV0::sqlite("query event audit", error))?;
    let validator = profile
        .validator_set()
        .validator(profile.author())
        .ok_or(SignerJournalErrorV0::MetadataMismatch)?;
    let mut event_count = 0u64;
    let mut last_event = None;
    for row in rows {
        let event = row.map_err(|error| SignerJournalErrorV0::sqlite("read event audit", error))?;
        let intent = intents.get(&event.fingerprint).ok_or(
            SignerJournalErrorV0::PersistedRepresentationMalformed(
                "event references absent intent",
            ),
        )?;
        let expected_sequence = predecessor
            .sequence
            .checked_add(1)
            .ok_or(SignerJournalErrorV0::CapacityExhausted)?;
        let expected_event = event_checksum(
            journal_id,
            expected_sequence,
            event.kind,
            event.fingerprint,
            event.signature.as_ref(),
            predecessor,
            intent.intent_checksum,
        );
        let expected_chain = chain_checksum(predecessor, expected_event);
        if event.sequence != expected_sequence
            || event.predecessor_sequence != predecessor.sequence
            || event.predecessor_chain_checksum != predecessor.chain_checksum
            || event.event_checksum != expected_event
            || event.chain_checksum != expected_chain
        {
            return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
                "event chain",
            ));
        }
        match (event.kind, event.signature) {
            (0, None) if prepared.insert(event.fingerprint) => {}
            (1, Some(bytes))
                if prepared.contains(&event.fingerprint) && signed.insert(event.fingerprint) =>
            {
                let signature = SignatureBytes::from_array(bytes);
                if !StrictEd25519Verifier.verify(
                    validator,
                    &SigningRoot::new(intent.signing_root),
                    &signature,
                ) {
                    return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
                        "persisted signature verification",
                    ));
                }
                let kind_index = usize::from(intent.kind);
                signed_intent_counts[kind_index] = signed_intent_counts[kind_index]
                    .checked_add(1)
                    .ok_or(SignerJournalErrorV0::CapacityExhausted)?;
            }
            _ => {
                return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
                    "event lifecycle",
                ));
            }
        }
        predecessor = JournalHeadV0 {
            sequence: event.sequence,
            chain_checksum: event.chain_checksum,
        };
        last_event = Some((event.kind, event.fingerprint));
        event_count = event_count
            .checked_add(1)
            .ok_or(SignerJournalErrorV0::CapacityExhausted)?;
    }
    drop(event_statement);
    if prepared.len() != intents.len() || prepared.len().saturating_sub(signed.len()) > 1 {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "intent lifecycle aggregate",
        ));
    }
    let pending_fingerprint = prepared.difference(&signed).next().copied();
    if pending_fingerprint.is_some()
        && last_event != pending_fingerprint.map(|fingerprint| (0, fingerprint))
    {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "pending intent is not journal tail",
        ));
    }

    let head = read_head(connection, journal_id)?;
    if head != predecessor {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "head does not match event chain",
        ));
    }
    let capacity = read_capacity(connection)?;
    validate_capacity(&capacity, profile)?;
    let maximum_revision = revisions.last().copied();
    if capacity.intent_count != intents.len() as u64
        || capacity.event_count != event_count
        || capacity.intent_bytes != intent_bytes
        || capacity.maximum_safety_revision != maximum_revision
        || capacity.maximum_vote_view != maximum_views[0]
        || capacity.maximum_timeout_view != maximum_views[1]
    {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "accounting differs from append-only rows",
        ));
    }
    let pending_intent = match pending_fingerprint {
        Some(fingerprint) => Some(prepared_intent_facts_v0(intents.get(&fingerprint).ok_or(
            SignerJournalErrorV0::PersistedRepresentationMalformed(
                "pending intent is absent from audited inventory",
            ),
        )?)),
        None => None,
    };
    build_lifetime_inventory_v1(
        profile,
        journal_id,
        head,
        capacity,
        durable_intent_counts,
        signed_intent_counts,
        pending_intent,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_lifetime_inventory_v1(
    profile: &SignerJournalProfileV0,
    journal_id: [u8; 32],
    head: JournalHeadV0,
    capacity: JournalCapacityV0,
    durable_intent_counts: [u64; 2],
    signed_intent_counts: [u64; 2],
    pending_intent: Option<SignerPreparedIntentFactsV0>,
) -> Result<SignerJournalLifetimeInventoryV1, SignerJournalErrorV0> {
    let durable_total = durable_intent_counts[0]
        .checked_add(durable_intent_counts[1])
        .ok_or(SignerJournalErrorV0::CapacityExhausted)?;
    let signed_total = signed_intent_counts[0]
        .checked_add(signed_intent_counts[1])
        .ok_or(SignerJournalErrorV0::CapacityExhausted)?;
    let expected_event_count = durable_total
        .checked_add(signed_total)
        .ok_or(SignerJournalErrorV0::CapacityExhausted)?;
    let unsigned_vote = durable_intent_counts[0]
        .checked_sub(signed_intent_counts[0])
        .ok_or(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "signed Vote inventory exceeds durable Vote inventory",
        ))?;
    let unsigned_timeout = durable_intent_counts[1]
        .checked_sub(signed_intent_counts[1])
        .ok_or(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "signed TimeoutVote inventory exceeds durable TimeoutVote inventory",
        ))?;
    let expected_unsigned = match pending_intent {
        None => [0, 0],
        Some(pending) if pending.kind == 0 => [1, 0],
        Some(pending) if pending.kind == 1 => [0, 1],
        Some(_) => {
            return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
                "pending signer intent kind",
            ));
        }
    };
    if durable_total != capacity.intent_count
        || expected_event_count != capacity.event_count
        || [unsigned_vote, unsigned_timeout] != expected_unsigned
    {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "lifetime inventory differs from audited lifecycle",
        ));
    }

    let watermark = watermark_for_parts(profile, journal_id, head)?;
    let inventory_digest = lifetime_inventory_digest_v1(
        profile.profile_checksum(),
        journal_id,
        watermark,
        capacity,
        durable_intent_counts,
        signed_intent_counts,
        pending_intent,
    );
    Ok(SignerJournalLifetimeInventoryV1 {
        durable_vote_intent_count: durable_intent_counts[0],
        durable_timeout_intent_count: durable_intent_counts[1],
        signed_vote_intent_count: signed_intent_counts[0],
        signed_timeout_intent_count: signed_intent_counts[1],
        inventory_digest,
    })
}

#[allow(clippy::too_many_arguments)]
fn lifetime_inventory_digest_v1(
    profile_checksum: [u8; 32],
    journal_id: [u8; 32],
    watermark: SignerWatermarkV0,
    capacity: JournalCapacityV0,
    durable_intent_counts: [u64; 2],
    signed_intent_counts: [u64; 2],
    pending_intent: Option<SignerPreparedIntentFactsV0>,
) -> [u8; 32] {
    let maximum_safety_revision = encode_optional_u64_v1(capacity.maximum_safety_revision);
    let maximum_vote_view = encode_optional_u64_v1(capacity.maximum_vote_view);
    let maximum_timeout_view = encode_optional_u64_v1(capacity.maximum_timeout_view);
    let pending_tag = [u8::from(pending_intent.is_some())];
    let pending_fingerprint = pending_intent.map_or([0; 32], |pending| pending.fingerprint);
    let pending_epoch = pending_intent
        .map_or(0, |pending| pending.epoch)
        .to_be_bytes();
    let pending_view = pending_intent
        .map_or(0, |pending| pending.view)
        .to_be_bytes();
    let pending_kind = [pending_intent.map_or(0, |pending| pending.kind)];
    let pending_safety_revision = pending_intent
        .map_or(0, |pending| pending.safety_revision)
        .to_be_bytes();
    let pending_signing_root = pending_intent.map_or([0; 32], |pending| pending.signing_root);
    let pending_intent_checksum = pending_intent.map_or([0; 32], |pending| pending.intent_checksum);
    hash_domain(
        LIFETIME_INVENTORY_DOMAIN_V1,
        &[
            &profile_checksum,
            &journal_id,
            &watermark.scope(),
            &watermark.journal_id(),
            &watermark.sequence().to_be_bytes(),
            &watermark.chain_checksum(),
            &capacity.intent_count.to_be_bytes(),
            &capacity.event_count.to_be_bytes(),
            &capacity.intent_bytes.to_be_bytes(),
            &maximum_safety_revision,
            &maximum_vote_view,
            &maximum_timeout_view,
            &durable_intent_counts[0].to_be_bytes(),
            &durable_intent_counts[1].to_be_bytes(),
            &signed_intent_counts[0].to_be_bytes(),
            &signed_intent_counts[1].to_be_bytes(),
            &pending_tag,
            &pending_fingerprint,
            &pending_epoch,
            &pending_view,
            &pending_kind,
            &pending_safety_revision,
            &pending_signing_root,
            &pending_intent_checksum,
        ],
    )
}

fn encode_optional_u64_v1(value: Option<u64>) -> [u8; 9] {
    let mut encoded = [0_u8; 9];
    if let Some(value) = value {
        encoded[0] = 1;
        encoded[1..].copy_from_slice(&value.to_be_bytes());
    }
    encoded
}

#[allow(clippy::too_many_arguments)]
fn insert_event(
    transaction: &Transaction<'_>,
    sequence: u64,
    kind: u8,
    fingerprint: [u8; 32],
    signature: Option<&[u8; 64]>,
    predecessor: JournalHeadV0,
    event_checksum: [u8; 32],
    chain_checksum: [u8; 32],
) -> Result<(), SignerJournalErrorV0> {
    let changed = transaction
        .execute(
            "INSERT INTO signer_journal_events_v0(
                sequence_be, event_kind, fingerprint, signature,
                predecessor_sequence_be, predecessor_chain_checksum,
                event_checksum, chain_checksum
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                sequence.to_be_bytes().as_slice(),
                i64::from(kind),
                fingerprint.as_slice(),
                signature.map(|value| value.as_slice()),
                predecessor.sequence.to_be_bytes().as_slice(),
                predecessor.chain_checksum.as_slice(),
                event_checksum.as_slice(),
                chain_checksum.as_slice(),
            ],
        )
        .map_err(|error| SignerJournalErrorV0::sqlite("insert journal event", error))?;
    if changed != 1 {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "journal event insert count",
        ));
    }
    Ok(())
}

fn update_head(
    transaction: &Transaction<'_>,
    source: JournalHeadV0,
    target: JournalHeadV0,
    target_checksum: [u8; 32],
) -> Result<(), SignerJournalErrorV0> {
    let changed = transaction
        .execute(
            "UPDATE signer_journal_head_v0
             SET active_sequence_be=?1, active_chain_checksum=?2, head_checksum=?3
             WHERE singleton=1 AND active_sequence_be=?4 AND active_chain_checksum=?5",
            params![
                target.sequence.to_be_bytes().as_slice(),
                target.chain_checksum.as_slice(),
                target_checksum.as_slice(),
                source.sequence.to_be_bytes().as_slice(),
                source.chain_checksum.as_slice(),
            ],
        )
        .map_err(|error| SignerJournalErrorV0::sqlite("advance signer head", error))?;
    if changed != 1 {
        return Err(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::CommitReadbackConflict,
        ));
    }
    Ok(())
}

fn validate_external_identity(
    external: &SignerWatermarkV0,
    local: &SignerWatermarkV0,
) -> Result<(), SignerJournalErrorV0> {
    if external.scope() != local.scope() || external.journal_id() != local.journal_id() {
        return Err(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::ExternalWatermarkFork,
        ));
    }
    Ok(())
}

fn validate_integrity(connection: &Connection) -> Result<(), SignerJournalErrorV0> {
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|error| SignerJournalErrorV0::sqlite("run integrity check", error))?;
    if integrity != "ok" {
        return Err(SignerJournalErrorV0::IntegrityFailure);
    }
    let foreign_key_failure: Option<i64> = connection
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()
        .map_err(|error| SignerJournalErrorV0::sqlite("run foreign-key check", error))?;
    if foreign_key_failure.is_some() {
        return Err(SignerJournalErrorV0::ForeignKeyFailure);
    }
    Ok(())
}

fn configure_connection(
    connection: &Connection,
    initialize: bool,
    maximum_database_bytes: usize,
) -> Result<(), SignerJournalErrorV0> {
    connection
        .busy_timeout(DEFAULT_BUSY_TIMEOUT)
        .map_err(|error| SignerJournalErrorV0::sqlite("configure busy timeout", error))?;
    if initialize {
        connection
            .execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=WAL;")
            .map_err(|error| SignerJournalErrorV0::sqlite("enable SQLite WAL", error))?;
    }
    connection
        .execute_batch(
            "PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;
             PRAGMA recursive_triggers=OFF;",
        )
        .map_err(|error| SignerJournalErrorV0::sqlite("configure SQLite safety", error))?;
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|error| SignerJournalErrorV0::sqlite("read SQLite page size", error))?;
    if page_size <= 0 {
        return Err(SignerJournalErrorV0::InvalidProfile("SQLite page size"));
    }
    let maximum_pages = (maximum_database_bytes as u64) / (page_size as u64);
    if maximum_pages == 0 || maximum_pages > i64::MAX as u64 {
        return Err(SignerJournalErrorV0::InvalidProfile(
            "SQLite page count bound",
        ));
    }
    connection
        .pragma_update(None, "max_page_count", maximum_pages as i64)
        .map_err(|error| SignerJournalErrorV0::sqlite("set SQLite page bound", error))?;
    connection
        .pragma_update(None, "journal_size_limit", maximum_database_bytes as i64)
        .map_err(|error| SignerJournalErrorV0::sqlite("set WAL bound", error))?;
    enable_persistent_wal(connection)?;
    validate_transaction_environment_raw(connection, maximum_database_bytes)
}

fn configure_pinned_read_only_connection(
    connection: &Connection,
) -> Result<(), SignerJournalErrorV0> {
    connection
        .busy_timeout(DEFAULT_BUSY_TIMEOUT)
        .map_err(|error| SignerJournalErrorV0::sqlite("configure pinned busy timeout", error))?;
    // These are connection-local controls. In particular, this path does not
    // set max_page_count, journal_size_limit, persistent-WAL file controls, or
    // execute a writer transaction.
    connection
        .execute_batch(
            "PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;
             PRAGMA query_only=ON;",
        )
        .map_err(|error| {
            SignerJournalErrorV0::sqlite("configure pinned read-only SQLite", error)
        })?;
    validate_pinned_read_only_environment(connection)
}

fn validate_pinned_read_only_environment(
    connection: &Connection,
) -> Result<(), SignerJournalErrorV0> {
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|error| SignerJournalErrorV0::sqlite("read pinned journal mode", error))?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|error| SignerJournalErrorV0::sqlite("read pinned synchronous mode", error))?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|error| SignerJournalErrorV0::sqlite("read pinned foreign-key mode", error))?;
    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(|error| SignerJournalErrorV0::sqlite("read pinned trusted-schema mode", error))?;
    let query_only: i64 = connection
        .query_row("PRAGMA query_only", [], |row| row.get(0))
        .map_err(|error| SignerJournalErrorV0::sqlite("read pinned query-only mode", error))?;
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|error| SignerJournalErrorV0::sqlite("read pinned page size", error))?;
    if !journal_mode.eq_ignore_ascii_case("wal")
        || synchronous < 2
        || foreign_keys != 1
        || trusted_schema != 0
        || query_only != 1
        || page_size != 4096
    {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "pinned SQLite read-only environment",
        ));
    }
    Ok(())
}

fn validate_transaction_environment(
    connection: &Connection,
    profile: &SignerJournalProfileV0,
) -> Result<(), SignerJournalErrorV0> {
    validate_transaction_environment_raw(connection, profile.maximum_database_bytes())
}

fn validate_transaction_environment_raw(
    connection: &Connection,
    maximum_database_bytes: usize,
) -> Result<(), SignerJournalErrorV0> {
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|error| SignerJournalErrorV0::sqlite("read journal mode", error))?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|error| SignerJournalErrorV0::sqlite("read synchronous mode", error))?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|error| SignerJournalErrorV0::sqlite("read foreign-key mode", error))?;
    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(|error| SignerJournalErrorV0::sqlite("read trusted-schema mode", error))?;
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|error| SignerJournalErrorV0::sqlite("read SQLite page size", error))?;
    let max_pages: i64 = connection
        .query_row("PRAGMA max_page_count", [], |row| row.get(0))
        .map_err(|error| SignerJournalErrorV0::sqlite("read SQLite page bound", error))?;
    let journal_limit: i64 = connection
        .query_row("PRAGMA journal_size_limit", [], |row| row.get(0))
        .map_err(|error| SignerJournalErrorV0::sqlite("read WAL bound", error))?;
    let expected_pages = (maximum_database_bytes as u64) / (page_size.max(1) as u64);
    if !journal_mode.eq_ignore_ascii_case("wal")
        || synchronous < 2
        || foreign_keys != 1
        || trusted_schema != 0
        || page_size != 4096
        || max_pages <= 0
        || max_pages as u64 > expected_pages
        || journal_limit < 0
        || journal_limit as u64 > maximum_database_bytes as u64
    {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "SQLite durability or resource PRAGMAs",
        ));
    }
    Ok(())
}

fn enable_persistent_wal(connection: &Connection) -> Result<(), SignerJournalErrorV0> {
    let mut enabled = 1i32;
    // SAFETY: the live SQLite connection owns the handle for this call,
    // `main` is a static C string, and this opcode requires an `int *`.
    let result = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
            (&mut enabled as *mut i32).cast(),
        )
    };
    if result != rusqlite::ffi::SQLITE_OK || enabled != 1 {
        return Err(SignerJournalErrorV0::sqlite(
            "enable persistent SQLite WAL",
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(result),
                Some("SQLITE_FCNTL_PERSIST_WAL was not accepted".to_owned()),
            ),
        ));
    }
    Ok(())
}

fn checkpoint_and_sync_initialization(
    connection: &Connection,
    database_file: &File,
    directory_file: &File,
) -> Result<(), SignerJournalErrorV0> {
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|error| SignerJournalErrorV0::sqlite("checkpoint initialized journal", error))?;
    database_file
        .sync_all()
        .map_err(|error| SignerJournalErrorV0::io("sync initialized database", error))?;
    sync_directory_handle(directory_file)
}

fn validate_storage_resource_bounds(
    database_path: &Path,
    profile: &SignerJournalProfileV0,
) -> Result<(), SignerJournalErrorV0> {
    let database_bytes = fs::metadata(database_path)
        .map_err(|error| SignerJournalErrorV0::io("stat database size", error))?
        .len();
    let wal_bytes = fs::metadata(sqlite_auxiliary_path(database_path, "-wal"))
        .map_err(|error| SignerJournalErrorV0::io("stat WAL size", error))?
        .len();
    let shm_bytes = fs::metadata(sqlite_auxiliary_path(database_path, "-shm"))
        .map_err(|error| SignerJournalErrorV0::io("stat SHM size", error))?
        .len();
    if database_bytes > profile.maximum_database_bytes() as u64
        || wal_bytes > profile.maximum_database_bytes() as u64
        || shm_bytes > MAXIMUM_SHM_BYTES_V0
    {
        return Err(SignerJournalErrorV0::CapacityExhausted);
    }
    Ok(())
}

fn canonical_new_path(path: &Path) -> Result<PathBuf, SignerJournalErrorV0> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| SignerJournalErrorV0::io("resolve current directory", error))?
            .join(path)
    };
    let file_name = absolute
        .file_name()
        .ok_or(SignerJournalErrorV0::InvalidProfile("database file name"))?;
    validate_database_file_name(file_name)?;
    let parent = absolute
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = match fs::canonicalize(parent) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(SignerJournalErrorV0::Missing(
                "pre-existing private parent directory",
            ));
        }
        Err(error) => {
            return Err(SignerJournalErrorV0::io(
                "canonicalize signer directory",
                error,
            ));
        }
    };
    validate_private_directory(&parent)?;
    Ok(parent.join(file_name))
}

fn canonical_existing_database_path(path: &Path) -> Result<PathBuf, SignerJournalErrorV0> {
    match fs::canonicalize(path) {
        Ok(value) => {
            let file_name = value
                .file_name()
                .ok_or(SignerJournalErrorV0::InvalidProfile("database file name"))?;
            validate_database_file_name(file_name)?;
            let parent = value
                .parent()
                .ok_or(SignerJournalErrorV0::InvalidProfile("database parent"))?;
            validate_private_directory(parent)?;
            file_identity(&value)?;
            Ok(value)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(SignerJournalErrorV0::Missing("database"))
        }
        Err(error) => Err(SignerJournalErrorV0::io(
            "canonicalize existing database",
            error,
        )),
    }
}

fn validate_database_file_name(file_name: &std::ffi::OsStr) -> Result<(), SignerJournalErrorV0> {
    let name = file_name.to_string_lossy().to_ascii_lowercase();
    if ["-wal", "-shm", "-journal", ".signer.lock"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
    {
        return Err(SignerJournalErrorV0::InvalidProfile(
            "database name collides with protected auxiliary namespace",
        ));
    }
    Ok(())
}

fn validate_private_directory(path: &Path) -> Result<(), SignerJournalErrorV0> {
    let metadata = fs::metadata(path)
        .map_err(|error| SignerJournalErrorV0::io("stat signer directory", error))?;
    if !metadata.is_dir() {
        return Err(SignerJournalErrorV0::InvalidProfile(
            "signer parent is not a directory",
        ));
    }
    use std::os::unix::fs::MetadataExt;
    // SAFETY: `geteuid` has no pointer arguments or caller-owned memory.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid || metadata.mode() & 0o022 != 0 {
        return Err(SignerJournalErrorV0::InvalidProfile(
            "signer parent must be owner-controlled and non-writable by peers",
        ));
    }
    let mut ancestor = path.parent();
    while let Some(directory) = ancestor {
        let metadata = fs::metadata(directory)
            .map_err(|error| SignerJournalErrorV0::io("stat signer ancestor", error))?;
        if !metadata.is_dir() {
            return Err(SignerJournalErrorV0::InvalidProfile(
                "signer ancestor is not a directory",
            ));
        }
        let peer_writable = metadata.mode() & 0o022 != 0;
        let trusted_sticky_root = metadata.mode() & 0o1000 != 0 && metadata.uid() == 0;
        if peer_writable && !trusted_sticky_root {
            return Err(SignerJournalErrorV0::InvalidProfile(
                "signer ancestor namespace is peer-writable",
            ));
        }
        ancestor = directory.parent();
    }
    Ok(())
}

fn lock_path_for(database_path: &Path) -> Result<PathBuf, SignerJournalErrorV0> {
    let file_name = database_path
        .file_name()
        .ok_or(SignerJournalErrorV0::InvalidProfile("database file name"))?;
    let mut lock_name = OsString::from(file_name);
    lock_name.push(".signer.lock");
    Ok(database_path.with_file_name(lock_name))
}

fn sqlite_auxiliary_path(database_path: &Path, suffix: &str) -> PathBuf {
    let mut name = database_path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn ensure_auxiliary_files_absent(database_path: &Path) -> Result<(), SignerJournalErrorV0> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let path = sqlite_auxiliary_path(database_path, suffix);
        match fs::symlink_metadata(&path) {
            Ok(_) => return Err(SignerJournalErrorV0::AlreadyExists("SQLite auxiliary file")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(SignerJournalErrorV0::io(
                    "inspect SQLite auxiliary path",
                    error,
                ));
            }
        }
    }
    Ok(())
}

fn require_auxiliary_files(database_path: &Path) -> Result<(), SignerJournalErrorV0> {
    let rollback = sqlite_auxiliary_path(database_path, "-journal");
    if fs::symlink_metadata(&rollback).is_ok() {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "rollback journal exists beside WAL database",
        ));
    }
    for (suffix, target) in [("-wal", "persistent WAL"), ("-shm", "persistent SHM")] {
        let path = sqlite_auxiliary_path(database_path, suffix);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => {
                return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
                    "SQLite auxiliary path is not a regular file",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(SignerJournalErrorV0::Missing(target));
            }
            Err(error) => {
                return Err(SignerJournalErrorV0::io(
                    "inspect persistent SQLite auxiliary",
                    error,
                ));
            }
        }
    }
    Ok(())
}

fn materialize_auxiliary_files(connection: &Connection) -> Result<(), SignerJournalErrorV0> {
    connection
        .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
        .map_err(|error| SignerJournalErrorV0::sqlite("materialize WAL namespace", error))
}

fn pin_auxiliary_files(
    database_path: &Path,
    maximum_database_bytes: usize,
) -> Result<(File, FileIdentityV0, File, FileIdentityV0), SignerJournalErrorV0> {
    validate_auxiliary_files(database_path, maximum_database_bytes)?;
    let wal_path = sqlite_auxiliary_path(database_path, "-wal");
    let shm_path = sqlite_auxiliary_path(database_path, "-shm");
    let wal_file = open_existing_private_file(&wal_path, "pin SQLite WAL")?;
    acquire_lifetime_lock(&wal_file)?;
    let shm_file = open_existing_private_file(&shm_path, "pin SQLite SHM")?;
    acquire_lifetime_lock(&shm_file)?;
    let wal_identity = file_handle_identity(&wal_file)?;
    let shm_identity = file_handle_identity(&shm_file)?;
    if file_identity(&wal_path)? != wal_identity || file_identity(&shm_path)? != shm_identity {
        return Err(SignerJournalErrorV0::Conflict(
            SignerJournalConflictV0::FileIdentityChanged,
        ));
    }
    Ok((wal_file, wal_identity, shm_file, shm_identity))
}

fn validate_auxiliary_files(
    database_path: &Path,
    maximum_database_bytes: usize,
) -> Result<(), SignerJournalErrorV0> {
    let rollback = sqlite_auxiliary_path(database_path, "-journal");
    match fs::symlink_metadata(&rollback) {
        Ok(_) => {
            return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
                "rollback journal exists beside WAL database",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(SignerJournalErrorV0::io("inspect rollback journal", error));
        }
    }
    for suffix in ["-wal", "-shm"] {
        let path = sqlite_auxiliary_path(database_path, suffix);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(SignerJournalErrorV0::io("inspect SQLite auxiliary", error));
            }
        };
        if !metadata.file_type().is_file() || metadata.len() > maximum_database_bytes as u64 {
            return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
                "SQLite auxiliary file shape or size",
            ));
        }
        validate_private_file_metadata(&metadata)?;
    }
    Ok(())
}

fn create_new_private_file(path: &Path, stage: &'static str) -> Result<File, SignerJournalErrorV0> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    use std::os::unix::fs::OpenOptionsExt;
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .map_err(|error| SignerJournalErrorV0::io(stage, error))
}

fn open_existing_private_file(
    path: &Path,
    stage: &'static str,
) -> Result<File, SignerJournalErrorV0> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .map_err(|error| SignerJournalErrorV0::io(stage, error))
}

fn acquire_lifetime_lock(file: &File) -> Result<(), SignerJournalErrorV0> {
    match file.try_lock_exclusive() {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            Err(SignerJournalErrorV0::Locked)
        }
        Err(error) => Err(SignerJournalErrorV0::io(
            "acquire lifetime owner lock",
            error,
        )),
    }
}

fn sync_directory_handle(directory: &File) -> Result<(), SignerJournalErrorV0> {
    directory
        .sync_all()
        .map_err(|error| SignerJournalErrorV0::io("sync signer parent directory", error))
}

fn file_identity(path: &Path) -> Result<FileIdentityV0, SignerJournalErrorV0> {
    let metadata =
        fs::metadata(path).map_err(|error| SignerJournalErrorV0::io("stat signer file", error))?;
    validate_private_file_metadata(&metadata)?;
    identity_from_metadata(&metadata)
}

fn file_handle_identity(file: &File) -> Result<FileIdentityV0, SignerJournalErrorV0> {
    let metadata = file
        .metadata()
        .map_err(|error| SignerJournalErrorV0::io("stat pinned signer file", error))?;
    validate_private_file_metadata(&metadata)?;
    identity_from_metadata(&metadata)
}

fn validate_private_file_metadata(metadata: &fs::Metadata) -> Result<(), SignerJournalErrorV0> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: `geteuid` has no pointer arguments or caller-owned memory.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "signer file identity or permissions",
        ));
    }
    Ok(())
}

fn directory_identity(path: &Path) -> Result<FileIdentityV0, SignerJournalErrorV0> {
    let metadata = fs::metadata(path)
        .map_err(|error| SignerJournalErrorV0::io("stat signer directory path", error))?;
    if !metadata.is_dir() {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "signer directory path is not a directory",
        ));
    }
    identity_from_metadata(&metadata)
}

fn directory_handle_identity(file: &File) -> Result<FileIdentityV0, SignerJournalErrorV0> {
    let metadata = file
        .metadata()
        .map_err(|error| SignerJournalErrorV0::io("stat pinned signer directory", error))?;
    if !metadata.is_dir() {
        return Err(SignerJournalErrorV0::PersistedRepresentationMalformed(
            "pinned signer directory is not a directory",
        ));
    }
    identity_from_metadata(&metadata)
}

fn identity_from_metadata(metadata: &fs::Metadata) -> Result<FileIdentityV0, SignerJournalErrorV0> {
    use std::os::unix::fs::MetadataExt;
    Ok(FileIdentityV0 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn new_journal_id() -> Result<[u8; 32], SignerJournalErrorV0> {
    for _ in 0..8 {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|error| {
            SignerJournalErrorV0::io(
                "generate journal identity",
                std::io::Error::other(error.to_string()),
            )
        })?;
        if bytes != [0; 32] {
            return Ok(bytes);
        }
    }
    Err(SignerJournalErrorV0::InvalidProfile(
        "random journal identity remained zero",
    ))
}

fn ensure_supported_platform() -> Result<(), SignerJournalErrorV0> {
    #[cfg(target_os = "linux")]
    {
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(SignerJournalErrorV0::UnsupportedPlatform)
    }
}

fn decode_u64_blob(bytes: &[u8], field: &'static str) -> Result<u64, SignerJournalErrorV0> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| SignerJournalErrorV0::PersistedRepresentationMalformed(field))?;
    Ok(u64::from_be_bytes(bytes))
}

fn decode_array32(bytes: &[u8], field: &'static str) -> Result<[u8; 32], SignerJournalErrorV0> {
    bytes
        .try_into()
        .map_err(|_| SignerJournalErrorV0::PersistedRepresentationMalformed(field))
}

fn u64_sql(bytes: &[u8], column: usize) -> rusqlite::Result<u64> {
    let value: [u8; 8] = bytes
        .try_into()
        .map_err(|_| sql_shape_error(column, "8-byte big-endian integer"))?;
    Ok(u64::from_be_bytes(value))
}

fn array_sql<const N: usize>(
    bytes: &[u8],
    column: usize,
    shape: &'static str,
) -> rusqlite::Result<[u8; N]> {
    bytes.try_into().map_err(|_| sql_shape_error(column, shape))
}

fn sql_shape_error(column: usize, shape: &'static str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        rusqlite::types::Type::Blob,
        std::io::Error::new(std::io::ErrorKind::InvalidData, shape).into(),
    )
}

#[cfg(test)]
mod lifetime_inventory_tests {
    use super::*;

    #[test]
    fn same_total_swapped_kind_distribution_changes_inventory_digest() {
        let journal_id = [0x22; 32];
        let watermark =
            SignerWatermarkV0::from_persisted_parts([0x11; 32], journal_id, 6, [0x33; 32])
                .expect("fixture watermark");
        let capacity = JournalCapacityV0 {
            intent_count: 3,
            event_count: 6,
            intent_bytes: 384,
            maximum_safety_revision: Some(3),
            maximum_vote_view: Some(9),
            maximum_timeout_view: Some(8),
        };
        let two_vote_one_timeout = lifetime_inventory_digest_v1(
            [0x44; 32],
            journal_id,
            watermark,
            capacity,
            [2, 1],
            [2, 1],
            None,
        );
        let one_vote_two_timeout = lifetime_inventory_digest_v1(
            [0x44; 32],
            journal_id,
            watermark,
            capacity,
            [1, 2],
            [1, 2],
            None,
        );
        assert_ne!(two_vote_one_timeout, one_vote_two_timeout);
    }
}
