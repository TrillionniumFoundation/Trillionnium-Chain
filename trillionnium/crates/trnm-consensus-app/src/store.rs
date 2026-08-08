use std::{
    collections::BTreeMap,
    fmt, fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, TryLockError,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, ensure, Context, Result};
use jmt::{
    storage::{HasPreimage, LeafNode, NibblePath, Node, NodeKey, TreeReader},
    JellyfishMerkleIterator, KeyHash, RootHash, Version,
};
use rusqlite::{
    backup::Backup, ffi::ErrorCode, params, Connection, DatabaseName, OpenFlags, OptionalExtension,
    Transaction, TransactionBehavior,
};
use serde::Serialize;
use trnm_consensus_core::{PayloadValidationParentV0, PayloadValidationRouteV0, ValidationId};

use super::{
    auth_tree::{
        authenticated_key_hash, plan_put_value_set, poco_snapshot_key_components,
        prove_with_reader, stored_object_key, stored_object_key_preimage, validator_state_key,
        verify_ics23_membership, verify_ics23_non_membership, AuthProof, AuthWrite,
        AuthenticatedObjectRecord, InMemoryAuthTree, PlannedAuthUpdate, PruneStats,
    },
    persist_state_bytes,
    poco_transition::{
        take_and_validate_production_poco_projection_v0, ProductionPocoProjectionV0,
    },
    validate_in_memory_authenticated_domain_projection, AppState, PendingBlock, StoredObject,
    ValidatorLifecycleStateV1, APP_VERSION, VALIDATOR_LIFECYCLE_SCHEMA_V1,
};

const STORE_SCHEMA_VERSION: &str = "5";
const PREVIOUS_STORE_SCHEMA_VERSION: &str = "4";
const LEGACY_STORE_SCHEMA_VERSION: &str = "3";
const STATUS_SCHEMA_V2: &str = "trnm_cometbft_app_status_v2";
const AUTH_QUERY_FLOOR_KEY: &str = "auth_query_floor";
const AUTH_PRUNE_TARGET_KEY: &str = "auth_prune_target";
const AUTH_PRUNE_BATCH_MAX_DURATION: Duration = Duration::from_millis(10);
const MAX_SNAPSHOT_AUTH_NODE_BYTES: u64 = 64 * 1024;
const MAX_SNAPSHOT_AUTH_VALUE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SNAPSHOT_KEY_PREIMAGE_BYTES: u64 = 1024 * 1024;
const MAX_SNAPSHOT_OBJECT_VALUE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SNAPSHOT_LIFECYCLE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SNAPSHOT_IDENTIFIER_BYTES: u64 = 4096;
const MAX_NATIVE_VALIDATION_RESERVATIONS: u64 = 65_536;
const STORE_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS objects (
        object_key_hex TEXT PRIMARY KEY NOT NULL,
        object_type TEXT NOT NULL,
        version TEXT NOT NULL,
        value_hash_hex TEXT NOT NULL,
        value_bytes BLOB NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS command_ids (
        command_id TEXT PRIMARY KEY NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS signer_nonces (
        signer_id TEXT NOT NULL,
        nonce BLOB NOT NULL CHECK(length(nonce)=8),
        PRIMARY KEY (signer_id, nonce)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS validator_lifecycle (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        state_json BLOB NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS auth_nodes (
        node_key BLOB PRIMARY KEY NOT NULL,
        node BLOB NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS auth_values (
        key_hash BLOB NOT NULL CHECK(length(key_hash)=32),
        version_be BLOB NOT NULL CHECK(length(version_be)=8),
        value BLOB,
        is_deleted INTEGER NOT NULL CHECK(is_deleted IN (0,1)),
        PRIMARY KEY (key_hash, version_be)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS auth_preimages (
        key_hash BLOB PRIMARY KEY NOT NULL CHECK(length(key_hash)=32),
        key_preimage BLOB NOT NULL CHECK(length(key_preimage)>0)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS auth_stale_nodes (
        stale_since_version_be BLOB NOT NULL CHECK(length(stale_since_version_be)=8),
        node_key BLOB NOT NULL,
        PRIMARY KEY (stale_since_version_be, node_key)
    ) STRICT;
    CREATE UNIQUE INDEX IF NOT EXISTS auth_stale_nodes_by_node_key
        ON auth_stale_nodes(node_key);
    CREATE TABLE IF NOT EXISTS auth_stale_values (
        stale_since_version_be BLOB NOT NULL CHECK(length(stale_since_version_be)=8),
        key_hash BLOB NOT NULL CHECK(length(key_hash)=32),
        version_be BLOB NOT NULL CHECK(length(version_be)=8),
        PRIMARY KEY (stale_since_version_be, key_hash, version_be),
        UNIQUE (key_hash, version_be)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS auth_roots (
        version_be BLOB PRIMARY KEY NOT NULL CHECK(length(version_be)=8),
        root_hash BLOB NOT NULL CHECK(length(root_hash)=32)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS native_validation_reservations (
        route INTEGER NOT NULL CHECK(route IN (0,1)),
        block_id BLOB NOT NULL CHECK(length(block_id)=32),
        view_be BLOB NOT NULL CHECK(length(view_be)=8),
        generation_be BLOB NOT NULL CHECK(length(generation_be)=8),
        target_height_be BLOB NOT NULL CHECK(length(target_height_be)=8),
        parent_block_id BLOB NOT NULL CHECK(length(parent_block_id)=32),
        request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint)=32),
        PRIMARY KEY(route, block_id, view_be, generation_be),
        UNIQUE(block_id, view_be, generation_be)
    ) STRICT;
";

/// The exact authenticated-read boundary which observed a storage failure.
///
/// This is deliberately a closed, data-free stage marker. Consensus callers
/// may use it for diagnostics, but must classify retryability from
/// [`AuthenticatedRuntimeReadFailureV0`] rather than from error strings.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthenticatedRuntimeReadStageV0 {
    OpenDatabase,
    ConfigureDatabase,
    ValidateBindings,
    BeginSnapshot,
    ReadHead,
    ReadQueryFloor,
    ReadRoot,
    ReadObject,
    DeriveObjectKey,
    BuildProof,
    VerifyObject,
    VerifyPocoProjection,
    PlanPostState,
    EndSnapshot,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TypedSqliteReadCodeV0 {
    pub(super) code: ErrorCode,
    pub(super) extended_code: i32,
}

/// Typed source taxonomy for authenticated runtime object reads.
///
/// SQLite failures are classified only from `ErrorCode` and the numeric
/// extended code. Persisted-content and proof failures are fail-stop facts;
/// they never become retryable merely because their diagnostic text happens
/// to resemble an I/O error.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AuthenticatedRuntimeReadFailureV0 {
    DatabaseUnavailable {
        stage: AuthenticatedRuntimeReadStageV0,
        sqlite: TypedSqliteReadCodeV0,
    },
    StorageUnavailable {
        stage: AuthenticatedRuntimeReadStageV0,
        sqlite: TypedSqliteReadCodeV0,
    },
    HostResourceUnavailable {
        stage: AuthenticatedRuntimeReadStageV0,
        sqlite: Option<TypedSqliteReadCodeV0>,
        reason: &'static str,
    },
    Pruned {
        requested: Version,
        floor: Version,
    },
    /// The Core-authenticated parent is not the committed source represented
    /// by this store. This remains retryable source unavailability rather than
    /// a negative fact about the signed target block.
    SourceMismatch {
        stage: AuthenticatedRuntimeReadStageV0,
        reason: &'static str,
    },
    AuthenticatedStateInvariant {
        stage: AuthenticatedRuntimeReadStageV0,
        sqlite: Option<TypedSqliteReadCodeV0>,
        reason: &'static str,
    },
    HostInvariant {
        stage: AuthenticatedRuntimeReadStageV0,
        sqlite: Option<TypedSqliteReadCodeV0>,
        reason: &'static str,
    },
}

impl fmt::Display for AuthenticatedRuntimeReadFailureV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatabaseUnavailable { stage, sqlite } => write!(
                formatter,
                "authenticated runtime read database unavailable at {stage:?} ({:?}/{})",
                sqlite.code, sqlite.extended_code
            ),
            Self::StorageUnavailable { stage, sqlite } => write!(
                formatter,
                "authenticated runtime read storage unavailable at {stage:?} ({:?}/{})",
                sqlite.code, sqlite.extended_code
            ),
            Self::HostResourceUnavailable {
                stage,
                sqlite,
                reason,
            } => write!(
                formatter,
                "authenticated runtime read host resource unavailable at {stage:?} ({sqlite:?}): {reason}"
            ),
            Self::Pruned { requested, floor } => write!(
                formatter,
                "authenticated runtime read version {requested} is below durable query floor {floor}"
            ),
            Self::SourceMismatch { stage, reason } => write!(
                formatter,
                "authenticated runtime source mismatch at {stage:?}: {reason}"
            ),
            Self::AuthenticatedStateInvariant {
                stage,
                sqlite,
                reason,
            } => write!(
                formatter,
                "authenticated runtime state invariant at {stage:?} ({sqlite:?}): {reason}"
            ),
            Self::HostInvariant {
                stage,
                sqlite,
                reason,
            } => write!(
                formatter,
                "authenticated runtime read host invariant at {stage:?} ({sqlite:?}): {reason}"
            ),
        }
    }
}

impl std::error::Error for AuthenticatedRuntimeReadFailureV0 {}

/// Process-local inputs for one durable native payload-validation reservation.
///
/// The constructor is crate-private and the value is deliberately neither
/// cloneable nor serializable. The fingerprint is only a congruence seal over
/// the retained Core request; it is not payload-validity or terminal-result
/// authority.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct NativeValidationReservationFactsV0 {
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
    target_height: u64,
    parent_block_id: [u8; 32],
    request_fingerprint: [u8; 32],
}

#[cfg_attr(not(test), allow(dead_code))]
impl NativeValidationReservationFactsV0 {
    pub(super) const fn new(
        route: PayloadValidationRouteV0,
        validation_id: ValidationId,
        target_height: u64,
        parent_block_id: [u8; 32],
        request_fingerprint: [u8; 32],
    ) -> Self {
        Self {
            route,
            validation_id,
            target_height,
            parent_block_id,
            request_fingerprint,
        }
    }
}

/// Opaque proof that the exact route/full-ValidationId request family has a
/// congruent durable reservation in the authoritative application database.
/// This token does not authorize evaluation, persistence, a Core callback, or
/// ABCI output.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a durable native validation reservation is not terminal authority"]
pub(super) struct NativeValidationReservationTokenV0 {
    facts: NativeValidationReservationFactsV0,
}

#[cfg_attr(not(test), allow(dead_code))]
impl NativeValidationReservationTokenV0 {
    pub(super) const fn route(&self) -> PayloadValidationRouteV0 {
        self.facts.route
    }

    pub(super) const fn validation_id(&self) -> ValidationId {
        self.facts.validation_id
    }
}

/// Opaque suppression fact for an already-identical durable reservation.
/// Unlike [`NativeValidationReservationTokenV0`], this type can never enter
/// evaluation and exposes no conversion into the reserved-owner token.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a coalesced durable reservation must suppress duplicate evaluation"]
pub(super) struct NativeValidationReservationCoalescedV0 {
    route: PayloadValidationRouteV0,
    validation_id: ValidationId,
}

#[cfg_attr(not(test), allow(dead_code))]
impl NativeValidationReservationCoalescedV0 {
    pub(super) const fn route(&self) -> PayloadValidationRouteV0 {
        self.route
    }

    pub(super) const fn validation_id(&self) -> ValidationId {
        self.validation_id
    }
}

/// Whether this call created the durable row or joined the already-identical
/// reservation. Only `Reserved` retains the evaluation-admission token;
/// `Coalesced` is a distinct suppression-only type. Neither is a result or
/// callback authority.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a reservation decision must remain attached to its opaque token"]
pub(super) enum NativeValidationReservationDecisionV0 {
    Reserved(NativeValidationReservationTokenV0),
    Coalesced(NativeValidationReservationCoalescedV0),
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NativeValidationReservationStageV0 {
    LockWriter,
    OpenDatabase,
    ConfigureDatabase,
    BeginTransaction,
    ValidateBindings,
    ReadExisting,
    ReadCapacity,
    Insert,
    Commit,
    ConfirmCommit,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NativeValidationReservationInvariantV0 {
    RouteMismatch,
    TargetHeightMismatch,
    ParentBlockIdMismatch,
    RequestFingerprintMismatch,
    PersistedRepresentationMalformed,
    CommitReadbackConflict,
}

/// Typed durable-reservation failure taxonomy. Callers must retain their
/// claimed Core owner alongside this cause; no bare cause can be retried or
/// promoted on its own.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum NativeValidationReservationFailureCauseV0 {
    DatabaseUnavailable {
        stage: NativeValidationReservationStageV0,
        sqlite: TypedSqliteReadCodeV0,
    },
    StorageUnavailable {
        stage: NativeValidationReservationStageV0,
        sqlite: TypedSqliteReadCodeV0,
    },
    HostResourceUnavailable {
        stage: NativeValidationReservationStageV0,
        sqlite: Option<TypedSqliteReadCodeV0>,
    },
    Capacity {
        maximum: u64,
    },
    Invariant {
        stage: NativeValidationReservationStageV0,
        kind: NativeValidationReservationInvariantV0,
        sqlite: Option<TypedSqliteReadCodeV0>,
    },
    HostInvariant {
        stage: NativeValidationReservationStageV0,
        sqlite: Option<TypedSqliteReadCodeV0>,
    },
}

/// Owning failure returned only after the reservation transaction has ended.
/// It retains the exact facts so a future explicit retry path cannot splice a
/// different route, generation, source, parent, or fingerprint into the same
/// claimed Core owner.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "a failed durable reservation retains exact facts for an explicit retry"]
pub(super) struct FailedNativeValidationReservationV0 {
    facts: NativeValidationReservationFactsV0,
    cause: NativeValidationReservationFailureCauseV0,
}

#[cfg_attr(not(test), allow(dead_code))]
impl FailedNativeValidationReservationV0 {
    pub(super) const fn route(&self) -> PayloadValidationRouteV0 {
        self.facts.route
    }

    pub(super) const fn validation_id(&self) -> ValidationId {
        self.facts.validation_id
    }

    pub(super) const fn cause(&self) -> &NativeValidationReservationFailureCauseV0 {
        &self.cause
    }
}

struct NativeValidationReservationExistingV0 {
    route: i64,
    target_height_be: Vec<u8>,
    parent_block_id: Vec<u8>,
    request_fingerprint: Vec<u8>,
}

enum NativeValidationReservationInnerDecisionV0 {
    Reserved,
    Coalesced,
    CommitUncertainCoalesced,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StoreFailpoint {
    BeforeSqlCommit,
    AfterSqlCommitBeforeStatus,
}

#[derive(Debug, Clone)]
pub(super) struct ApplicationStore {
    status_path: PathBuf,
    database_path: PathBuf,
    chain_id: String,
    signer_policy_hash_hex: String,
    writer_gate: Arc<Mutex<()>>,
    writer_waiters: Arc<AtomicUsize>,
    maintenance_gate: Arc<Mutex<()>>,
    active_snapshot_pins: Arc<AtomicUsize>,
}

pub(super) struct PinnedSnapshot {
    source: Option<Connection>,
    active_snapshot_pins: Arc<AtomicUsize>,
}

/// Opaque, transaction-owned authenticated runtime read snapshot.
///
/// The connection owns the SQLite read transaction directly; no self-
/// referential `Transaction<'_>` is stored. Production can open this snapshot
/// only by consuming the Core-retained exact-parent capability and matching
/// the committed head height/root; the snapshot is still not terminal outcome
/// or persistence authority.
#[cfg_attr(not(test), allow(dead_code))]
#[must_use = "an authenticated runtime snapshot must be explicitly finished before promoting an execution result"]
pub(super) struct AuthenticatedRuntimeReadSnapshotV0 {
    source: Option<Connection>,
    height: Version,
    root_hash: RootHash,
    active_snapshot_pins: Arc<AtomicUsize>,
    #[cfg(test)]
    fail_finish_for_test_v0: bool,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthenticatedRuntimeExpectedParentV0 {
    height: Version,
    root_hash: RootHash,
}

impl PinnedSnapshot {
    fn source(&self) -> Result<&Connection> {
        self.source
            .as_ref()
            .context("pinned snapshot source was already released")
    }

    fn release(&mut self) -> Result<()> {
        let Some(source) = self.source.take() else {
            return Ok(());
        };
        let rollback = source.execute_batch("ROLLBACK");
        drop(source);
        self.active_snapshot_pins.fetch_sub(1, Ordering::AcqRel);
        rollback?;
        Ok(())
    }
}

impl Drop for PinnedSnapshot {
    fn drop(&mut self) {
        if let Some(source) = self.source.take() {
            let _ = source.execute_batch("ROLLBACK");
            drop(source);
            self.active_snapshot_pins.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl AuthenticatedRuntimeReadSnapshotV0 {
    pub(super) fn load(
        &self,
        object_key_hex: &str,
    ) -> std::result::Result<Option<StoredObject>, AuthenticatedRuntimeReadFailureV0> {
        let source =
            self.source
                .as_ref()
                .ok_or(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadObject,
                    sqlite: None,
                    reason: "authenticated runtime snapshot was already finished",
                })?;
        load_authenticated_runtime_object_at_v0(source, self.height, self.root_hash, object_key_hex)
    }

    /// Reads the validator lifecycle from this snapshot's already-fixed
    /// parent root and proves that the physical singleton is the same value
    /// committed by the authenticated tree.
    ///
    /// The snapshot itself can now be opened from a Core-issued exact-parent
    /// capability. This method deliberately does not open a second connection
    /// or read a later committed head.
    pub(super) fn load_authenticated_validator_lifecycle_v0(
        &self,
    ) -> std::result::Result<ValidatorLifecycleStateV1, AuthenticatedRuntimeReadFailureV0> {
        let source =
            self.source
                .as_ref()
                .ok_or(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadObject,
                    sqlite: None,
                    reason: "authenticated runtime snapshot was already finished",
                })?;
        load_authenticated_validator_lifecycle_at_v0(source, self.height, self.root_hash)
    }

    /// Loads the complete namespace-8 production projection from this same
    /// already-open transaction and proves every physical leaf against the
    /// snapshot's fixed root. No cache, second connection, version argument,
    /// or independently-read root participates.
    pub(super) fn load_authenticated_production_poco_projection_v0(
        &self,
    ) -> std::result::Result<ProductionPocoProjectionV0, AuthenticatedRuntimeReadFailureV0> {
        let stage = AuthenticatedRuntimeReadStageV0::VerifyPocoProjection;
        let source =
            self.source
                .as_ref()
                .ok_or(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage,
                    sqlite: None,
                    reason: "authenticated runtime snapshot was already finished",
                })?;
        load_production_poco_projection_from_connection_v0(source, self.height, self.root_hash)
            .map_err(|error| {
                classify_authenticated_read_anyhow_v0(
                    stage,
                    &error,
                    "authenticated parent PoCO projection failed exact verification",
                )
            })?
            .ok_or(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage,
                    sqlite: None,
                    reason: "authenticated parent lacks the active PoCO configuration namespace",
                },
            )
    }

    /// Plans the exact next authenticated state on this snapshot's existing
    /// SQLite connection and read transaction.
    ///
    /// The snapshot itself already owns the Core-authenticated exact-parent
    /// authority used to open this connection. No target version or expected
    /// root is caller supplied here. The only legal target is the fixed parent
    /// version plus one, and the complete persisted state is revalidated before
    /// the JMT planner reads from this same transaction. The returned plan is
    /// inert and is never applied or persisted by this method.
    pub(super) fn plan_exact_next_auth_update_v0(
        &self,
        writes: impl IntoIterator<Item = AuthWrite>,
    ) -> std::result::Result<PlannedAuthUpdate, AuthenticatedRuntimeReadFailureV0> {
        let stage = AuthenticatedRuntimeReadStageV0::PlanPostState;
        let source =
            self.source
                .as_ref()
                .ok_or(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage,
                    sqlite: None,
                    reason: "authenticated runtime snapshot was already finished",
                })?;
        let target_version =
            self.height
                .checked_add(1)
                .ok_or(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage,
                    sqlite: None,
                    reason: "authenticated parent height cannot advance",
                })?;
        let state = load_sqlite_state(source).map_err(|error| {
            classify_authenticated_read_anyhow_v0(
                stage,
                &error,
                "complete authenticated parent state failed post-state planning validation",
            )
        })?;
        if state.height != self.height || RootHash(state.app_hash) != self.root_hash {
            return Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage,
                    sqlite: None,
                    reason: "post-state planner parent differs from the fixed runtime snapshot",
                },
            );
        }
        let reader = SqliteAuthReader { connection: source };
        // `plan_put_value_set` takes `(expected_next_version, version)`. Both
        // are the unique target derived above; the retained parent version is
        // represented by the reader's fixed SQLite snapshot, not either
        // numeric argument.
        let plan = plan_put_value_set(&reader, target_version, target_version, writes).map_err(
            |error| {
                classify_authenticated_read_anyhow_v0(
                    stage,
                    &error,
                    "authenticated post-state JMT planning failed",
                )
            },
        )?;
        if plan.version != target_version {
            return Err(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                stage,
                sqlite: None,
                reason: "authenticated post-state planner returned a foreign target version",
            });
        }
        Ok(plan)
    }

    pub(super) fn finish(mut self) -> std::result::Result<(), AuthenticatedRuntimeReadFailureV0> {
        let source =
            self.source
                .take()
                .ok_or(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    sqlite: None,
                    reason: "authenticated runtime snapshot was already finished",
                })?;
        let rollback = source.execute_batch("ROLLBACK").map_err(|error| {
            classify_sqlite_authenticated_read_failure_v0(
                AuthenticatedRuntimeReadStageV0::EndSnapshot,
                &error,
            )
        });
        drop(source);
        self.active_snapshot_pins.fetch_sub(1, Ordering::AcqRel);
        #[cfg(test)]
        if self.fail_finish_for_test_v0 && rollback.is_ok() {
            return Err(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                stage: AuthenticatedRuntimeReadStageV0::EndSnapshot,
                sqlite: None,
                reason: "injected authenticated runtime snapshot finish failure",
            });
        }
        rollback
    }

    /// Test-only failure injection after the real rollback has released the
    /// SQLite snapshot and pin. This proves callers cannot promote an inert
    /// traversal when the explicit finish boundary reports failure.
    #[cfg(test)]
    pub(super) fn inject_finish_failure_for_test_v0(&mut self) {
        self.fail_finish_for_test_v0 = true;
    }
}

impl Drop for AuthenticatedRuntimeReadSnapshotV0 {
    fn drop(&mut self) {
        if let Some(source) = self.source.take() {
            let _ = source.execute_batch("ROLLBACK");
            drop(source);
            self.active_snapshot_pins.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PruneBatchOutcome {
    pub(super) stats: PruneStats,
    pub(super) query_floor: Version,
    pub(super) target: Version,
    pub(super) complete: bool,
    pub(super) rows_examined: usize,
    pub(super) logical_bytes_examined: u64,
    pub(super) elapsed: Duration,
}

#[cfg(any(test, feature = "scale-gate"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AuthPruneStatus {
    pub(super) query_floor: Version,
    pub(super) target: Option<Version>,
}

#[derive(Serialize)]
struct PersistedStatusV2 {
    schema: &'static str,
    app_version: u64,
    height: u64,
    app_hash_hex: String,
}

struct SqliteAuthReader<'a> {
    connection: &'a Connection,
}

impl TreeReader for SqliteAuthReader<'_> {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let encoded_key = borsh::to_vec(node_key).context("encode JMT node key")?;
        let encoded: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT node FROM auth_nodes WHERE node_key=?1",
                params![encoded_key],
                |row| row.get(0),
            )
            .optional()?;
        encoded
            .map(|bytes| borsh::from_slice(&bytes).context("decode persisted JMT node"))
            .transpose()
    }

    fn get_value_option(&self, max_version: Version, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        let row: Option<(Option<Vec<u8>>, i64)> = self
            .connection
            .query_row(
                "SELECT value, is_deleted
                 FROM auth_values
                 WHERE key_hash=?1 AND version_be<=?2
                 ORDER BY version_be DESC
                 LIMIT 1",
                params![key_hash.0.as_slice(), max_version.to_be_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match row {
            None | Some((None, 1)) => Ok(None),
            Some((Some(value), 0)) => Ok(Some(value)),
            Some(_) => Err(anyhow!("persisted JMT value tombstone mismatch")),
        }
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let mut statement = self
            .connection
            .prepare("SELECT node_key, node FROM auth_nodes")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut rightmost: Option<(NodeKey, LeafNode)> = None;
        for row in rows {
            let (node_key, node) = row?;
            let node_key: NodeKey =
                borsh::from_slice(&node_key).context("decode persisted JMT node key")?;
            let node: Node = borsh::from_slice(&node).context("decode persisted JMT node")?;
            let Node::Leaf(leaf) = node else {
                continue;
            };
            if rightmost.as_ref().is_none_or(|(best_key, best_leaf)| {
                (leaf.key_hash(), node_key.version()) > (best_leaf.key_hash(), best_key.version())
            }) {
                rightmost = Some((node_key, leaf));
            }
        }
        Ok(rightmost)
    }
}

impl HasPreimage for SqliteAuthReader<'_> {
    fn preimage(&self, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        Ok(self
            .connection
            .query_row(
                "SELECT key_preimage FROM auth_preimages WHERE key_hash=?1",
                params![key_hash.0.as_slice()],
                |row| row.get(0),
            )
            .optional()?)
    }
}

impl ApplicationStore {
    fn lock_writer(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        self.writer_waiters.fetch_add(1, Ordering::AcqRel);
        let locked = self.writer_gate.lock();
        self.writer_waiters.fetch_sub(1, Ordering::AcqRel);
        locked.map_err(|_| anyhow!("application store writer gate poisoned"))
    }

    /// Durably reserves one Core-issued native payload-validation identity.
    ///
    /// The complete identity is globally unique in this SQLite store even
    /// though route is also part of the primary key. An exactly congruent row
    /// coalesces before the capacity check; any reuse of the full identity with
    /// different route, parent, target height, or fingerprint is fail-stop.
    /// This method does not evaluate the block or create terminal/callback
    /// authority.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn reserve_native_validation_v0(
        &self,
        facts: NativeValidationReservationFactsV0,
    ) -> std::result::Result<
        NativeValidationReservationDecisionV0,
        Box<FailedNativeValidationReservationV0>,
    > {
        match self.reserve_native_validation_inner_v0(&facts) {
            Ok(NativeValidationReservationInnerDecisionV0::Reserved) => {
                Ok(NativeValidationReservationDecisionV0::Reserved(
                    NativeValidationReservationTokenV0 { facts },
                ))
            }
            Ok(
                NativeValidationReservationInnerDecisionV0::Coalesced
                | NativeValidationReservationInnerDecisionV0::CommitUncertainCoalesced,
            ) => Ok(NativeValidationReservationDecisionV0::Coalesced(
                NativeValidationReservationCoalescedV0 {
                    route: facts.route,
                    validation_id: facts.validation_id,
                },
            )),
            Err(cause) => Err(Box::new(FailedNativeValidationReservationV0 {
                facts,
                cause,
            })),
        }
    }

    fn reserve_native_validation_inner_v0(
        &self,
        facts: &NativeValidationReservationFactsV0,
    ) -> std::result::Result<
        NativeValidationReservationInnerDecisionV0,
        NativeValidationReservationFailureCauseV0,
    > {
        let stage = NativeValidationReservationStageV0::LockWriter;
        self.writer_waiters.fetch_add(1, Ordering::AcqRel);
        let writer = self.writer_gate.lock();
        self.writer_waiters.fetch_sub(1, Ordering::AcqRel);
        let _writer =
            writer.map_err(
                |_| NativeValidationReservationFailureCauseV0::HostInvariant {
                    stage,
                    sqlite: None,
                },
            )?;

        let mut connection = self.connect_native_validation_reservation_v0()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                classify_native_validation_reservation_sqlite_failure_v0(
                    NativeValidationReservationStageV0::BeginTransaction,
                    &error,
                )
            })?;
        validate_native_validation_reservation_bindings_v0(&transaction, self)?;
        let already_exists = match load_native_validation_reservation_v0(&transaction, facts)? {
            Some(existing) => {
                validate_native_validation_reservation_congruence_v0(facts, &existing)?;
                true
            }
            None => {
                let count = transaction
                    .query_row(
                        "SELECT COUNT(*) FROM native_validation_reservations",
                        [],
                        |row| row.get::<_, u64>(0),
                    )
                    .map_err(|error| {
                        classify_native_validation_reservation_sqlite_failure_v0(
                            NativeValidationReservationStageV0::ReadCapacity,
                            &error,
                        )
                    })?;
                if count >= MAX_NATIVE_VALIDATION_RESERVATIONS {
                    return Err(NativeValidationReservationFailureCauseV0::Capacity {
                        maximum: MAX_NATIVE_VALIDATION_RESERVATIONS,
                    });
                }
                insert_native_validation_reservation_v0(&transaction, facts)?;
                false
            }
        };

        if let Err(commit_error) = transaction.commit() {
            // A failed SQLite commit can leave the caller uncertain about
            // whether the WAL record became durable. Reopen read-only and
            // accept an exact row only as suppression: another process may
            // have inserted it after this transaction released its lock, so
            // readback alone can never mint the unique evaluation token.
            return match self.confirm_native_validation_reservation_v0(facts) {
                Ok(()) => Ok(NativeValidationReservationInnerDecisionV0::CommitUncertainCoalesced),
                Err(invariant @ NativeValidationReservationFailureCauseV0::Invariant { .. }) => {
                    Err(invariant)
                }
                Err(_) => Err(classify_native_validation_reservation_sqlite_failure_v0(
                    NativeValidationReservationStageV0::Commit,
                    &commit_error,
                )),
            };
        }

        Ok(if already_exists {
            NativeValidationReservationInnerDecisionV0::Coalesced
        } else {
            NativeValidationReservationInnerDecisionV0::Reserved
        })
    }

    fn connect_native_validation_reservation_v0(
        &self,
    ) -> std::result::Result<Connection, NativeValidationReservationFailureCauseV0> {
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| {
            classify_native_validation_reservation_sqlite_failure_v0(
                NativeValidationReservationStageV0::OpenDatabase,
                &error,
            )
        })?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| {
                classify_native_validation_reservation_sqlite_failure_v0(
                    NativeValidationReservationStageV0::ConfigureDatabase,
                    &error,
                )
            })?;
        connection
            .execute_batch(
                "
                PRAGMA synchronous=FULL;
                PRAGMA foreign_keys=ON;
                ",
            )
            .map_err(|error| {
                classify_native_validation_reservation_sqlite_failure_v0(
                    NativeValidationReservationStageV0::ConfigureDatabase,
                    &error,
                )
            })?;
        let schema_version = connection
            .query_row(
                "SELECT value FROM metadata WHERE key='schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| {
                classify_native_validation_reservation_sqlite_failure_v0(
                    NativeValidationReservationStageV0::ConfigureDatabase,
                    &error,
                )
            })?;
        if schema_version != STORE_SCHEMA_VERSION {
            return Err(NativeValidationReservationFailureCauseV0::HostInvariant {
                stage: NativeValidationReservationStageV0::ConfigureDatabase,
                sqlite: None,
            });
        }
        Ok(connection)
    }

    fn confirm_native_validation_reservation_v0(
        &self,
        facts: &NativeValidationReservationFactsV0,
    ) -> std::result::Result<(), NativeValidationReservationFailureCauseV0> {
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| {
            classify_native_validation_reservation_sqlite_failure_v0(
                NativeValidationReservationStageV0::ConfirmCommit,
                &error,
            )
        })?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| {
                classify_native_validation_reservation_sqlite_failure_v0(
                    NativeValidationReservationStageV0::ConfirmCommit,
                    &error,
                )
            })?;
        validate_native_validation_reservation_bindings_v0(&connection, self)?;
        let existing = load_native_validation_reservation_v0(&connection, facts)?.ok_or(
            NativeValidationReservationFailureCauseV0::HostInvariant {
                stage: NativeValidationReservationStageV0::ConfirmCommit,
                sqlite: None,
            },
        )?;
        validate_native_validation_reservation_congruence_v0(facts, &existing).map_err(
            |failure| match failure {
                NativeValidationReservationFailureCauseV0::Invariant { kind, sqlite, .. } => {
                    NativeValidationReservationFailureCauseV0::Invariant {
                        stage: NativeValidationReservationStageV0::ConfirmCommit,
                        kind: if kind
                            == NativeValidationReservationInvariantV0::PersistedRepresentationMalformed
                        {
                            kind
                        } else {
                            NativeValidationReservationInvariantV0::CommitReadbackConflict
                        },
                        sqlite,
                    }
                }
                other => other,
            },
        )
    }

    pub(super) fn open(
        status_path: &Path,
        chain_id: &str,
        signer_policy_hash_hex: &str,
    ) -> Result<Self> {
        let extension = status_path
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| format!("{value}.sqlite3"))
            .unwrap_or_else(|| "sqlite3".to_string());
        let store = Self {
            status_path: status_path.to_path_buf(),
            database_path: status_path.with_extension(extension),
            chain_id: chain_id.to_string(),
            signer_policy_hash_hex: signer_policy_hash_hex.to_string(),
            writer_gate: Arc::new(Mutex::new(())),
            writer_waiters: Arc::new(AtomicUsize::new(0)),
            maintenance_gate: Arc::new(Mutex::new(())),
            active_snapshot_pins: Arc::new(AtomicUsize::new(0)),
        };
        Ok(store)
    }

    pub(super) fn load_or_migrate(&self) -> Result<AppState> {
        if !self.database_path.exists() && self.status_path.exists() {
            return Err(anyhow!(
                "existing pre-v4 state requires the explicit export/new-genesis migration tool"
            ));
        }
        if self.database_path.exists() {
            self.probe_existing_database()?;
        }
        let connection = self.connect()?;
        if self.has_committed_state(&connection)? {
            let state = load_sqlite_state(&connection)?;
            self.refresh_status_best_effort(&state);
            return Ok(state);
        }
        drop(connection);

        if !self.status_path.exists() {
            return Ok(AppState::default());
        }
        Err(anyhow!(
            "existing pre-v4 state requires the explicit export/new-genesis migration tool"
        ))
    }

    pub(super) fn load_object(&self, object_key_hex: &str) -> Result<Option<StoredObject>> {
        let connection = self.connect_read()?;
        load_object(&connection, object_key_hex)
    }

    /// Loads one object from the committed head while independently proving
    /// that the physical object row agrees with the authenticated JMT.
    ///
    /// This is a legacy self-head read, not host parent authority. It validates
    /// bindings, head metadata, app hash, query floor, root, row, and proof in
    /// one temporary read transaction, while leaving the existing `anyhow`
    /// wrapper in place for old callers. New execution adapters must instead
    /// begin from a separately authenticated expected-parent capability.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn load_authenticated_runtime_object_v0(
        &self,
        object_key_hex: &str,
    ) -> std::result::Result<Option<StoredObject>, AuthenticatedRuntimeReadFailureV0> {
        let snapshot = self.begin_authenticated_runtime_read_snapshot_v0(None)?;
        let result = snapshot.load(object_key_hex);
        let rollback = snapshot.finish();
        merge_authenticated_runtime_read_and_rollback_v0(result, rollback)
    }

    #[cfg(test)]
    pub(super) fn begin_authenticated_runtime_read_snapshot_for_test_v0(
        &self,
        expected_height: Version,
        expected_root: [u8; 32],
    ) -> std::result::Result<AuthenticatedRuntimeReadSnapshotV0, AuthenticatedRuntimeReadFailureV0>
    {
        self.begin_authenticated_runtime_read_snapshot_v0(Some(
            AuthenticatedRuntimeExpectedParentV0 {
                height: expected_height,
                root_hash: RootHash(expected_root),
            },
        ))
    }

    /// Opens the committed head only when it is exactly the positive-height
    /// parent frozen inside a Core-issued payload-validation capability.
    /// Synthetic genesis deliberately has no native header/state root and is
    /// therefore reported as source-unavailable rather than guessed.
    pub(super) fn begin_authenticated_runtime_read_snapshot_for_core_parent_v0(
        &self,
        parent: &PayloadValidationParentV0,
    ) -> std::result::Result<AuthenticatedRuntimeReadSnapshotV0, AuthenticatedRuntimeReadFailureV0>
    {
        let header =
            parent
                .exact_header()
                .ok_or(AuthenticatedRuntimeReadFailureV0::SourceMismatch {
                    stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    reason: "trusted genesis parent has no canonical native state-root header",
                })?;
        self.begin_authenticated_runtime_read_snapshot_v0(Some(
            AuthenticatedRuntimeExpectedParentV0 {
                height: header.height().get(),
                root_hash: RootHash(*header.state_root().as_bytes()),
            },
        ))
    }

    #[cfg(test)]
    pub(super) fn active_runtime_snapshot_pins_for_test_v0(&self) -> usize {
        self.active_snapshot_pins.load(Ordering::Acquire)
    }

    pub(super) fn configured_signer_policy_commitment_v0(
        &self,
    ) -> std::result::Result<[u8; 32], AuthenticatedRuntimeReadFailureV0> {
        trnm_finality_types::decode_hash32(
            "authenticated runtime configured signer policy",
            &self.signer_policy_hash_hex,
        )
        .map_err(|_| AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
            sqlite: None,
            reason: "configured signer-policy commitment is not canonical hash32",
        })
    }

    pub(super) fn configured_chain_id_v0(&self) -> &str {
        &self.chain_id
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn begin_authenticated_runtime_read_snapshot_v0(
        &self,
        expected_parent: Option<AuthenticatedRuntimeExpectedParentV0>,
    ) -> std::result::Result<AuthenticatedRuntimeReadSnapshotV0, AuthenticatedRuntimeReadFailureV0>
    {
        let _maintenance = match self.maintenance_gate.try_lock() {
            Ok(maintenance) => maintenance,
            Err(TryLockError::WouldBlock) => {
                return Err(AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable {
                    stage: AuthenticatedRuntimeReadStageV0::BeginSnapshot,
                    sqlite: None,
                    reason: "application store maintenance is busy",
                });
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(AuthenticatedRuntimeReadFailureV0::HostInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::BeginSnapshot,
                    sqlite: None,
                    reason: "application store maintenance gate is poisoned",
                });
            }
        };
        let connection = self.connect_authenticated_runtime_read_v0()?;
        connection
            .execute_batch("BEGIN DEFERRED")
            .map_err(|error| {
                classify_sqlite_authenticated_read_failure_v0(
                    AuthenticatedRuntimeReadStageV0::BeginSnapshot,
                    &error,
                )
            })?;

        let validated = (|| {
            let (height, root_hash) =
                self.validate_authenticated_runtime_snapshot_head_v0(&connection)?;
            if let Some(expected_parent) = expected_parent {
                if (height, root_hash) != (expected_parent.height, expected_parent.root_hash) {
                    return Err(AuthenticatedRuntimeReadFailureV0::SourceMismatch {
                        stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                        reason: "authenticated runtime snapshot differs from expected parent",
                    });
                }
            }
            Ok((height, root_hash))
        })();
        match validated {
            Ok((height, root_hash)) => {
                self.active_snapshot_pins.fetch_add(1, Ordering::AcqRel);
                Ok(AuthenticatedRuntimeReadSnapshotV0 {
                    source: Some(connection),
                    height,
                    root_hash,
                    active_snapshot_pins: Arc::clone(&self.active_snapshot_pins),
                    #[cfg(test)]
                    fail_finish_for_test_v0: false,
                })
            }
            Err(error) => {
                let rollback = connection.execute_batch("ROLLBACK").map_err(|rollback| {
                    classify_sqlite_authenticated_read_failure_v0(
                        AuthenticatedRuntimeReadStageV0::EndSnapshot,
                        &rollback,
                    )
                });
                merge_authenticated_runtime_read_and_rollback_v0(Err(error), rollback)
            }
        }
    }

    #[cfg(test)]
    pub(super) fn contains_command_id(&self, command_id: &str) -> Result<bool> {
        let connection = self.connect_read()?;
        Ok(connection
            .query_row(
                "SELECT 1 FROM command_ids WHERE command_id=?1",
                params![command_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    #[cfg(test)]
    pub(super) fn contains_signer_nonce(&self, signer_id: &str, nonce: u64) -> Result<bool> {
        let connection = self.connect_read()?;
        Ok(connection
            .query_row(
                "SELECT 1 FROM signer_nonces WHERE signer_id=?1 AND nonce=?2",
                params![signer_id, nonce.to_be_bytes().as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub(super) fn plan_auth_update(
        &self,
        version: Version,
        writes: impl IntoIterator<Item = AuthWrite>,
    ) -> Result<PlannedAuthUpdate> {
        let connection = self.connect_read()?;
        connection.execute_batch("BEGIN DEFERRED")?;
        let expected_next_version = latest_auth_version(&connection)?.map_or(0, |value| value + 1);
        let reader = SqliteAuthReader {
            connection: &connection,
        };
        let update = plan_put_value_set(&reader, expected_next_version, version, writes)?;
        connection.execute_batch("ROLLBACK")?;
        Ok(update)
    }

    pub(super) fn prove(&self, version: Version, key: Vec<u8>) -> Result<AuthProof> {
        let connection = self.connect_read()?;
        connection.execute_batch("BEGIN DEFERRED")?;
        let query_floor = optional_metadata_version(&connection, AUTH_QUERY_FLOOR_KEY)?
            .or(oldest_auth_version(&connection)?)
            .unwrap_or(0);
        ensure!(
            version >= query_floor,
            "authenticated version {version} was pruned; retained query floor is {query_floor}"
        );
        let root_hash = auth_root(&connection, version)?
            .with_context(|| format!("missing authenticated root at version {version}"))?;
        let reader = SqliteAuthReader {
            connection: &connection,
        };
        let proof = prove_with_reader(&reader, version, root_hash, key)?;
        let valid = match proof.value.as_deref() {
            Some(value) => verify_ics23_membership(&proof, value),
            None => verify_ics23_non_membership(&proof),
        };
        ensure!(valid, "persisted authenticated proof failed verification");
        connection.execute_batch("ROLLBACK")?;
        Ok(proof)
    }

    pub(super) fn production_poco_projection(
        &self,
        version: Version,
    ) -> Result<(RootHash, Option<ProductionPocoProjectionV0>)> {
        let connection = self.connect_read()?;
        connection.execute_batch("BEGIN DEFERRED")?;
        let query_floor = optional_metadata_version(&connection, AUTH_QUERY_FLOOR_KEY)?
            .or(oldest_auth_version(&connection)?)
            .unwrap_or(0);
        ensure!(
            version >= query_floor,
            "authenticated version {version} was pruned; retained query floor is {query_floor}"
        );
        let root_hash = auth_root(&connection, version)?
            .with_context(|| format!("missing authenticated root at version {version}"))?;
        let projection =
            load_production_poco_projection_from_connection_v0(&connection, version, root_hash)?;
        connection.execute_batch("ROLLBACK")?;
        Ok((root_hash, projection))
    }

    pub(super) fn authenticated_root_at(&self, version: Version) -> Result<RootHash> {
        let connection = self.connect_read()?;
        let query_floor = optional_metadata_version(&connection, AUTH_QUERY_FLOOR_KEY)?
            .or(oldest_auth_version(&connection)?)
            .unwrap_or(0);
        ensure!(
            version >= query_floor,
            "authenticated version {version} was pruned; retained query floor is {query_floor}"
        );
        auth_root(&connection, version)?
            .with_context(|| format!("missing authenticated root at version {version}"))
    }

    /// Removes authenticated roots, stale nodes, and superseded values below
    /// the durable query floor using one writer-budgeted transaction.
    ///
    /// A `None` result means the consensus writer currently owns the shared
    /// gate. Callers must yield and retry; they must never wait in front of a
    /// Commit. Preimages remain one-per-distinct-key in the live database;
    /// latest-only snapshot compaction removes dead-key preimages.
    pub(super) fn try_prune_auth_batch(
        &self,
        max_rows: usize,
        max_logical_bytes: u64,
    ) -> Result<Option<PruneBatchOutcome>> {
        ensure!(max_rows > 0, "authenticated prune batch must allow a row");
        ensure!(
            max_logical_bytes > 0,
            "authenticated prune batch must allow logical bytes"
        );
        let _maintenance = match self.maintenance_gate.try_lock() {
            Ok(maintenance) => maintenance,
            Err(TryLockError::WouldBlock) => return Ok(None),
            Err(TryLockError::Poisoned(_)) => {
                return Err(anyhow!("application store maintenance gate poisoned"));
            }
        };
        if self.active_snapshot_pins.load(Ordering::Acquire) > 0 {
            return Ok(None);
        }
        if self.writer_waiters.load(Ordering::Acquire) > 0 {
            return Ok(None);
        }
        let _writer = match self.writer_gate.try_lock() {
            Ok(writer) => writer,
            Err(TryLockError::WouldBlock) => return Ok(None),
            Err(TryLockError::Poisoned(_)) => {
                return Err(anyhow!("application store writer gate poisoned"));
            }
        };
        let started = Instant::now();
        let mut connection = self.connect_maintenance()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let query_floor = optional_metadata_version(&transaction, AUTH_QUERY_FLOOR_KEY)?
            .context("application store is missing authenticated query floor")?;
        let Some(target) = optional_metadata_version(&transaction, AUTH_PRUNE_TARGET_KEY)? else {
            transaction.rollback()?;
            return Ok(Some(PruneBatchOutcome {
                stats: PruneStats::default(),
                query_floor,
                target: query_floor,
                complete: true,
                rows_examined: 0,
                logical_bytes_examined: 0,
                elapsed: started.elapsed(),
            }));
        };
        let height = metadata(&transaction, "height")?
            .parse::<u64>()
            .context("parse application store height during authenticated pruning")?;
        let app_hash = trnm_finality_types::decode_hash32(
            "application store app_hash",
            &metadata(&transaction, "app_hash_hex")?,
        )?;
        ensure!(
            target <= query_floor && query_floor <= height,
            "authenticated prune control exceeds the committed head"
        );
        ensure!(
            auth_root(&transaction, target)?.is_some(),
            "authenticated prune boundary root is absent"
        );

        let target_be = target.to_be_bytes();
        let mut stats = PruneStats::default();
        let mut rows_examined = 0_usize;
        let mut logical_bytes_examined = 0_u64;
        let mut budget_expired = false;

        let root_versions = {
            let mut statement = transaction.prepare(
                "SELECT version_be
                 FROM auth_roots
                 WHERE version_be<?1
                 ORDER BY version_be
                 LIMIT ?2",
            )?;
            let rows = statement.query_map(
                params![target_be.as_slice(), i64::try_from(max_rows)?],
                |row| row.get::<_, Vec<u8>>(0),
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for encoded_version in root_versions {
            let version = decode_version_be(&encoded_version)?;
            let root_path: NibblePath = std::iter::empty().collect();
            let encoded_key = borsh::to_vec(&NodeKey::new(version, root_path))
                .context("encode authenticated root node key during pruning")?;
            let node_bytes = transaction
                .query_row(
                    "SELECT length(node) FROM auth_nodes WHERE node_key=?1",
                    params![encoded_key.as_slice()],
                    |row| row.get::<_, u64>(0),
                )
                .optional()?
                .unwrap_or(0)
                .saturating_add(u64::try_from(encoded_key.len())?);
            if rows_examined > 0
                && (logical_bytes_examined.saturating_add(node_bytes) > max_logical_bytes
                    || started.elapsed() >= AUTH_PRUNE_BATCH_MAX_DURATION)
            {
                budget_expired = true;
                break;
            }
            rows_examined = rows_examined.saturating_add(1);
            logical_bytes_examined = logical_bytes_examined.saturating_add(node_bytes);
            stats.nodes_removed = stats.nodes_removed.saturating_add(transaction.execute(
                "DELETE FROM auth_nodes WHERE node_key=?1",
                params![encoded_key.as_slice()],
            )?);
            stats.roots_removed = stats.roots_removed.saturating_add(transaction.execute(
                "DELETE FROM auth_roots WHERE version_be=?1",
                params![encoded_version],
            )?);
        }

        let old_roots_remain = transaction
            .query_row(
                "SELECT 1 FROM auth_roots WHERE version_be<?1 LIMIT 1",
                params![target_be.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !old_roots_remain && !budget_expired && rows_examined < max_rows {
            let remaining = max_rows.saturating_sub(rows_examined);
            let stale_rows = {
                let mut statement = transaction.prepare(
                    "SELECT stale.stale_since_version_be,
                            stale.node_key,
                            COALESCE(length(nodes.node), 0)
                     FROM auth_stale_nodes AS stale
                     LEFT JOIN auth_nodes AS nodes ON nodes.node_key=stale.node_key
                     WHERE stale.stale_since_version_be<=?1
                     ORDER BY stale.stale_since_version_be, stale.node_key
                     LIMIT ?2",
                )?;
                let rows = statement.query_map(
                    params![target_be.as_slice(), i64::try_from(remaining)?],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, u64>(2)?,
                        ))
                    },
                )?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            for (stale_since, node_key, node_length) in stale_rows {
                let logical_bytes = node_length.saturating_add(u64::try_from(node_key.len())?);
                if rows_examined > 0
                    && (logical_bytes_examined.saturating_add(logical_bytes) > max_logical_bytes
                        || started.elapsed() >= AUTH_PRUNE_BATCH_MAX_DURATION)
                {
                    break;
                }
                rows_examined = rows_examined.saturating_add(1);
                logical_bytes_examined = logical_bytes_examined.saturating_add(logical_bytes);
                stats.nodes_removed = stats.nodes_removed.saturating_add(transaction.execute(
                    "DELETE FROM auth_nodes WHERE node_key=?1",
                    params![node_key.as_slice()],
                )?);
                stats.stale_indices_removed =
                    stats
                        .stale_indices_removed
                        .saturating_add(transaction.execute(
                            "DELETE FROM auth_stale_nodes
                             WHERE stale_since_version_be=?1 AND node_key=?2",
                            params![stale_since, node_key],
                        )?);
            }
        }

        let stale_nodes_remain = transaction
            .query_row(
                "SELECT 1
                 FROM auth_stale_nodes
                 WHERE stale_since_version_be<=?1
                 LIMIT 1",
                params![target_be.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !old_roots_remain
            && !stale_nodes_remain
            && rows_examined < max_rows
            && started.elapsed() < AUTH_PRUNE_BATCH_MAX_DURATION
        {
            let remaining = max_rows.saturating_sub(rows_examined);
            let stale_values = {
                let mut statement = transaction.prepare(
                    "SELECT stale.stale_since_version_be,
                            stale.key_hash,
                            stale.version_be,
                            history.key_hash IS NOT NULL,
                            COALESCE(length(history.value), 0)
                     FROM auth_stale_values AS stale
                     LEFT JOIN auth_values AS history
                       ON history.key_hash=stale.key_hash
                      AND history.version_be=stale.version_be
                     WHERE stale.stale_since_version_be<=?1
                     ORDER BY stale.stale_since_version_be,
                              stale.key_hash,
                              stale.version_be
                     LIMIT ?2",
                )?;
                let rows = statement.query_map(
                    params![target_be.as_slice(), i64::try_from(remaining)?],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, bool>(3)?,
                            row.get::<_, u64>(4)?,
                        ))
                    },
                )?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            for (stale_since, key_hash, version_be, value_exists, value_length) in stale_values {
                ensure!(
                    value_exists,
                    "authenticated stale-value index points to an absent value"
                );
                let logical_bytes = value_length
                    .saturating_add(u64::try_from(key_hash.len())?)
                    .saturating_add(u64::try_from(version_be.len())?);
                if rows_examined > 0
                    && (logical_bytes_examined.saturating_add(logical_bytes) > max_logical_bytes
                        || started.elapsed() >= AUTH_PRUNE_BATCH_MAX_DURATION)
                {
                    break;
                }
                rows_examined = rows_examined.saturating_add(1);
                logical_bytes_examined = logical_bytes_examined.saturating_add(logical_bytes);
                let removed = transaction.execute(
                    "DELETE FROM auth_values
                     WHERE key_hash=?1 AND version_be=?2",
                    params![key_hash.as_slice(), version_be.as_slice()],
                )?;
                ensure!(
                    removed == 1,
                    "authenticated stale value disappeared during pruning"
                );
                stats.value_versions_removed = stats.value_versions_removed.saturating_add(removed);
                let index_removed = transaction.execute(
                    "DELETE FROM auth_stale_values
                     WHERE stale_since_version_be=?1
                       AND key_hash=?2
                       AND version_be=?3",
                    params![
                        stale_since.as_slice(),
                        key_hash.as_slice(),
                        version_be.as_slice(),
                    ],
                )?;
                ensure!(
                    index_removed == 1,
                    "authenticated stale-value index disappeared during pruning"
                );
                stats.stale_indices_removed =
                    stats.stale_indices_removed.saturating_add(index_removed);
            }
        }

        let old_roots_remain = transaction
            .query_row(
                "SELECT 1 FROM auth_roots WHERE version_be<?1 LIMIT 1",
                params![target_be.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let stale_nodes_remain = transaction
            .query_row(
                "SELECT 1
                 FROM auth_stale_nodes
                 WHERE stale_since_version_be<=?1
                 LIMIT 1",
                params![target_be.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let stale_values_remain = transaction
            .query_row(
                "SELECT 1
                 FROM auth_stale_values
                 WHERE stale_since_version_be<=?1
                 LIMIT 1",
                params![target_be.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let complete = !old_roots_remain && !stale_nodes_remain && !stale_values_remain;
        if complete {
            verify_retained_lifecycle_proofs(&transaction, height, app_hash, target)?;
            transaction.execute(
                "DELETE FROM metadata WHERE key=?1",
                params![AUTH_PRUNE_TARGET_KEY],
            )?;
        }
        transaction.commit()?;
        Ok(Some(PruneBatchOutcome {
            stats,
            query_floor,
            target,
            complete,
            rows_examined,
            logical_bytes_examined,
            elapsed: started.elapsed(),
        }))
    }

    #[cfg(any(test, feature = "scale-gate"))]
    pub(super) fn request_auth_prune(
        &self,
        retain_from_version: Version,
    ) -> Result<AuthPruneStatus> {
        let _writer = self.lock_writer()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let height = metadata(&transaction, "height")?
            .parse::<u64>()
            .context("parse application store height during prune request")?;
        ensure!(
            retain_from_version <= height,
            "cannot request a future authenticated query floor"
        );
        ensure!(
            auth_root(&transaction, retain_from_version)?.is_some(),
            "requested authenticated query floor has no root"
        );
        advance_auth_query_floor(&transaction, retain_from_version)?;
        let status = AuthPruneStatus {
            query_floor: optional_metadata_version(&transaction, AUTH_QUERY_FLOOR_KEY)?
                .context("application store is missing authenticated query floor")?,
            target: optional_metadata_version(&transaction, AUTH_PRUNE_TARGET_KEY)?,
        };
        transaction.commit()?;
        Ok(status)
    }

    #[cfg(any(test, feature = "scale-gate"))]
    pub(super) fn auth_prune_status(&self) -> Result<AuthPruneStatus> {
        let connection = self.connect_read()?;
        connection.execute_batch("BEGIN DEFERRED")?;
        let status = AuthPruneStatus {
            query_floor: optional_metadata_version(&connection, AUTH_QUERY_FLOOR_KEY)?
                .context("application store is missing authenticated query floor")?,
            target: optional_metadata_version(&connection, AUTH_PRUNE_TARGET_KEY)?,
        };
        connection.execute_batch("ROLLBACK")?;
        Ok(status)
    }

    pub(super) fn has_pending_auth_prune(&self) -> Result<bool> {
        let connection = self.connect_read()?;
        connection.execute_batch("BEGIN DEFERRED")?;
        let pending = optional_metadata_version(&connection, AUTH_PRUNE_TARGET_KEY)?.is_some();
        connection.execute_batch("ROLLBACK")?;
        Ok(pending)
    }

    pub(super) fn prune_auth_versions_before(
        &self,
        state: &AppState,
        retain_from_version: Version,
    ) -> Result<PruneStats> {
        ensure!(
            state.pending.is_none(),
            "cannot prune authenticated history while a block is pending"
        );
        ensure!(
            retain_from_version <= state.height,
            "cannot retain a future authenticated version"
        );
        let _maintenance = self
            .maintenance_gate
            .lock()
            .map_err(|_| anyhow!("application store maintenance gate poisoned"))?;
        ensure!(
            self.active_snapshot_pins.load(Ordering::Acquire) == 0,
            "cannot run full authenticated pruning while a snapshot is pinned"
        );
        let _writer = self.lock_writer()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_database_head(&transaction, state)?;
        ensure!(
            latest_auth_version(&transaction)? == Some(state.height),
            "authenticated tree head differs from application height"
        );
        let current_query_floor = optional_metadata_version(&transaction, AUTH_QUERY_FLOOR_KEY)?
            .context("application store is missing authenticated query floor")?;
        ensure!(
            retain_from_version >= current_query_floor,
            "authenticated query floor cannot move backwards"
        );

        transaction.execute_batch(
            "
            CREATE TEMP TABLE trnm_prune_nodes (
                node_key BLOB PRIMARY KEY NOT NULL
            ) WITHOUT ROWID;
            CREATE TEMP TABLE trnm_live_preimages (
                key_hash BLOB PRIMARY KEY NOT NULL CHECK(length(key_hash)=32)
            ) WITHOUT ROWID;
            ",
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO trnm_prune_nodes(node_key)
             SELECT node_key
             FROM auth_stale_nodes
             WHERE stale_since_version_be<=?1",
            params![retain_from_version.to_be_bytes().as_slice()],
        )?;

        {
            let mut statement = transaction.prepare(
                "SELECT version_be
                 FROM auth_roots
                 WHERE version_be<?1
                 ORDER BY version_be",
            )?;
            let rows = statement.query_map(
                params![retain_from_version.to_be_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )?;
            for row in rows {
                let version = decode_version_be(&row?)?;
                let root_path: NibblePath = std::iter::empty().collect();
                let encoded_key = borsh::to_vec(&NodeKey::new(version, root_path))
                    .context("encode historical JMT root node key during pruning")?;
                transaction.execute(
                    "INSERT OR IGNORE INTO trnm_prune_nodes(node_key) VALUES (?1)",
                    params![encoded_key],
                )?;
            }
        }

        let nodes_removed = transaction.execute(
            "DELETE FROM auth_nodes
             WHERE node_key IN (SELECT node_key FROM trnm_prune_nodes)",
            [],
        )?;
        let stale_node_indices_removed = transaction.execute(
            "DELETE FROM auth_stale_nodes WHERE stale_since_version_be<=?1",
            params![retain_from_version.to_be_bytes().as_slice()],
        )?;
        let roots_removed = transaction.execute(
            "DELETE FROM auth_roots WHERE version_be<?1",
            params![retain_from_version.to_be_bytes().as_slice()],
        )?;
        {
            let mut statement = transaction.prepare("SELECT node FROM auth_nodes")?;
            let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
            for row in rows {
                let node: Node =
                    borsh::from_slice(&row?).context("decode retained JMT node during pruning")?;
                if let Node::Leaf(leaf) = node {
                    transaction.execute(
                        "INSERT OR IGNORE INTO trnm_live_preimages(key_hash) VALUES (?1)",
                        params![leaf.key_hash().0.as_slice()],
                    )?;
                }
            }
        }
        let value_versions_removed = transaction.execute(
            "DELETE FROM auth_values AS candidate
             WHERE EXISTS (
                 SELECT 1
                 FROM auth_stale_values AS stale
                 WHERE stale.stale_since_version_be<=?1
                   AND stale.key_hash=candidate.key_hash
                   AND stale.version_be=candidate.version_be
             )",
            params![retain_from_version.to_be_bytes().as_slice()],
        )?;
        let stale_value_indices_removed = transaction.execute(
            "DELETE FROM auth_stale_values WHERE stale_since_version_be<=?1",
            params![retain_from_version.to_be_bytes().as_slice()],
        )?;
        ensure!(
            value_versions_removed == stale_value_indices_removed,
            "authenticated stale-value index differs from value history"
        );
        let dead_value_versions_removed = if retain_from_version == state.height {
            transaction.execute(
                "DELETE FROM auth_values
                 WHERE key_hash NOT IN (SELECT key_hash FROM trnm_live_preimages)",
                [],
            )?
        } else {
            0
        };
        let preimages_removed = transaction.execute(
            "DELETE FROM auth_preimages
             WHERE key_hash NOT IN (SELECT key_hash FROM trnm_live_preimages)",
            [],
        )?;
        write_metadata_version(&transaction, AUTH_QUERY_FLOOR_KEY, retain_from_version)?;
        transaction.execute(
            "DELETE FROM metadata WHERE key=?1",
            params![AUTH_PRUNE_TARGET_KEY],
        )?;

        let retained_root = auth_root(&transaction, state.height)?
            .context("pruning removed the committed authenticated root")?;
        ensure!(
            <[u8; 32]>::from(retained_root) == state.app_hash,
            "authenticated pruning changed the committed AppHash"
        );
        let lifecycle_bytes: Vec<u8> = transaction.query_row(
            "SELECT state_json FROM validator_lifecycle WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let reader = SqliteAuthReader {
            connection: &transaction,
        };
        let latest_proof =
            prove_with_reader(&reader, state.height, retained_root, validator_state_key()?)?;
        let latest_value = latest_proof
            .value
            .as_deref()
            .context("latest validator lifecycle proof is absent")?;
        let lifecycle_record = AuthenticatedObjectRecord::decode(latest_value)?;
        ensure!(
            lifecycle_record.object_type == VALIDATOR_LIFECYCLE_SCHEMA_V1
                && lifecycle_record.object_version <= state.height
                && lifecycle_record.value == lifecycle_bytes
                && verify_ics23_membership(&latest_proof, latest_value),
            "authenticated pruning damaged the latest validator lifecycle proof"
        );
        if retain_from_version < state.height {
            let boundary_root = auth_root(&transaction, retain_from_version)?
                .context("pruning removed the retention-boundary root")?;
            let boundary_proof = prove_with_reader(
                &reader,
                retain_from_version,
                boundary_root,
                validator_state_key()?,
            )?;
            let boundary_value = boundary_proof
                .value
                .as_deref()
                .context("retention-boundary lifecycle proof is absent")?;
            ensure!(
                verify_ics23_membership(&boundary_proof, boundary_value),
                "authenticated pruning damaged the retention-boundary proof"
            );
        }
        transaction.commit()?;
        Ok(PruneStats {
            nodes_removed,
            value_versions_removed: value_versions_removed
                .saturating_add(dead_value_versions_removed),
            preimages_removed,
            stale_indices_removed: stale_node_indices_removed
                .saturating_add(stale_value_indices_removed),
            roots_removed,
        })
    }

    pub(super) fn build_snapshot_database(
        &self,
        state: &AppState,
        destination: &Path,
        mut pinned: PinnedSnapshot,
    ) -> Result<AppState> {
        ensure!(
            state.height > 0 && state.pending.is_none(),
            "snapshot database requires committed non-genesis state"
        );
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create snapshot directory {}", parent.display()))?;
        }
        let temporary = destination.with_extension("snapshot.tmp");
        remove_file_if_exists(&temporary)?;
        remove_sqlite_sidecars(&temporary)?;

        let mut target = Connection::open(&temporary)
            .with_context(|| format!("create SQLite snapshot {}", temporary.display()))?;
        {
            let backup = Backup::new(pinned.source()?, &mut target)?;
            backup.run_to_completion(256, Duration::from_millis(2), None)?;
        }
        drop(target);
        pinned.release()?;

        // Validation reservations are node-local, monotonic work journal
        // rows, not consensus state. Scrub only the temporary copy before
        // pruning/VACUUM; the authoritative source database remains intact.
        {
            let mut connection = Connection::open(&temporary)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute("DELETE FROM native_validation_reservations", [])?;
            transaction.commit()?;
        }

        let snapshot_store = self.with_database_path(temporary.clone());
        snapshot_store.prune_auth_versions_before(state, state.height)?;
        {
            let connection = Connection::open(&temporary)?;
            connection.execute_batch(
                "
                PRAGMA wal_checkpoint(TRUNCATE);
                PRAGMA journal_mode=DELETE;
                VACUUM;
                ",
            )?;
        }
        remove_sqlite_sidecars(&temporary)?;
        let validated =
            snapshot_store.validate_snapshot_database(&temporary, state.height, state.app_hash)?;
        fs::File::open(&temporary)?.sync_all()?;
        fs::rename(&temporary, destination).with_context(|| {
            format!(
                "install completed snapshot {} from {}",
                destination.display(),
                temporary.display()
            )
        })?;
        sync_parent(destination)?;
        Ok(validated)
    }

    pub(super) fn pin_snapshot(&self, state: &AppState) -> Result<PinnedSnapshot> {
        ensure!(
            state.height > 0 && state.pending.is_none(),
            "snapshot pin requires committed non-genesis state"
        );
        let _maintenance = match self.maintenance_gate.try_lock() {
            Ok(maintenance) => maintenance,
            Err(TryLockError::WouldBlock) => {
                return Err(anyhow!(
                    "application store maintenance is busy; defer optional snapshot pin"
                ));
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(anyhow!("application store maintenance gate poisoned"));
            }
        };
        let source = self.connect_read()?;
        source.execute_batch("BEGIN DEFERRED")?;
        let pinned_height = metadata(&source, "height")?
            .parse::<u64>()
            .context("parse pinned snapshot height")?;
        let pinned_hash = trnm_finality_types::decode_hash32(
            "pinned snapshot app_hash",
            &metadata(&source, "app_hash_hex")?,
        )?;
        ensure!(
            (pinned_height, pinned_hash) == (state.height, state.app_hash),
            "application store head differs from requested snapshot"
        );
        self.active_snapshot_pins.fetch_add(1, Ordering::AcqRel);
        Ok(PinnedSnapshot {
            source: Some(source),
            active_snapshot_pins: Arc::clone(&self.active_snapshot_pins),
        })
    }

    pub(super) fn install_snapshot_database(
        &self,
        expected: &AppState,
        source_path: &Path,
        expected_height: u64,
        expected_app_hash: [u8; 32],
    ) -> Result<AppState> {
        ensure!(
            expected.height == 0 && expected.pending.is_none(),
            "snapshot install requires empty application state"
        );
        let restored =
            self.validate_snapshot_database(source_path, expected_height, expected_app_hash)?;

        let _maintenance = self
            .maintenance_gate
            .lock()
            .map_err(|_| anyhow!("application store maintenance gate poisoned"))?;
        ensure!(
            self.active_snapshot_pins.load(Ordering::Acquire) == 0,
            "cannot install a snapshot while a live snapshot read is pinned"
        );
        let _writer = self.lock_writer()?;
        let mut destination = self.connect()?;
        {
            let transaction =
                destination.transaction_with_behavior(TransactionBehavior::Immediate)?;
            verify_database_head(&transaction, expected)?;
            transaction.rollback()?;
        }
        destination.restore(
            DatabaseName::Main,
            source_path,
            None::<fn(rusqlite::backup::Progress)>,
        )?;
        let post_install = (|| -> Result<AppState> {
            let mut installed_schema = metadata(&destination, "schema_version")?;
            if installed_schema == LEGACY_STORE_SCHEMA_VERSION {
                migrate_store_schema_v3_to_v4(&mut destination)?;
                installed_schema = metadata(&destination, "schema_version")?;
            }
            if installed_schema == PREVIOUS_STORE_SCHEMA_VERSION {
                migrate_store_schema_v4_to_v5(&mut destination)?;
                installed_schema = metadata(&destination, "schema_version")?;
            }
            ensure!(
                installed_schema == STORE_SCHEMA_VERSION,
                "installed snapshot store schema is unsupported"
            );
            validate_auth_prune_metadata(&destination)?;
            let checkpoint =
                destination.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                })?;
            ensure!(
                checkpoint.0 == 0,
                "installed snapshot WAL checkpoint was blocked by an active reader"
            );
            drop(destination);
            fs::File::open(&self.database_path)?.sync_all()?;
            let wal = sqlite_sidecar(&self.database_path, "-wal");
            if wal.exists() {
                fs::File::open(&wal)?.sync_all()?;
            }
            sync_parent(&self.database_path)?;

            let installed = self.validate_snapshot_database(
                &self.database_path,
                expected_height,
                expected_app_hash,
            )?;
            ensure!(
                (installed.height, installed.app_hash) == (restored.height, restored.app_hash),
                "installed snapshot differs from its prevalidated source"
            );
            Ok(installed)
        })();
        match post_install {
            Ok(installed) => {
                self.refresh_status_best_effort(&installed);
                Ok(installed)
            }
            Err(error) => fail_stop_after_snapshot_install(error),
        }
    }

    pub(super) fn validate_snapshot_database(
        &self,
        path: &Path,
        expected_height: u64,
        expected_app_hash: [u8; 32],
    ) -> Result<AppState> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("open untrusted SQLite snapshot {}", path.display()))?;
        connection.execute_batch(
            "
            PRAGMA trusted_schema=OFF;
            PRAGMA query_only=ON;
            ",
        )?;
        let integrity: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        ensure!(integrity == "ok", "SQLite snapshot quick_check failed");
        validate_snapshot_schema(&connection)?;
        validate_storage_resource_bounds(&connection)?;
        let store_schema = self.verify_compatible_database_bindings(&connection)?;
        ensure!(
            metadata(&connection, "height")? == expected_height.to_string()
                && metadata(&connection, "app_hash_hex")? == hex::encode(expected_app_hash),
            "SQLite snapshot trusted head mismatch"
        );
        let root_count = connection.query_row("SELECT COUNT(*) FROM auth_roots", [], |row| {
            row.get::<_, u64>(0)
        })?;
        let stale_count =
            connection.query_row("SELECT COUNT(*) FROM auth_stale_nodes", [], |row| {
                row.get::<_, u64>(0)
            })?;
        let stale_value_count = if store_schema != LEGACY_STORE_SCHEMA_VERSION {
            connection.query_row("SELECT COUNT(*) FROM auth_stale_values", [], |row| {
                row.get::<_, u64>(0)
            })?
        } else {
            0
        };
        ensure!(
            root_count == 1 && stale_count == 0 && stale_value_count == 0,
            "SQLite snapshot must contain latest-only authenticated history"
        );
        if store_schema != LEGACY_STORE_SCHEMA_VERSION {
            ensure!(
                optional_metadata_version(&connection, AUTH_QUERY_FLOOR_KEY)?
                    == Some(expected_height),
                "SQLite snapshot authenticated query floor is not latest-only"
            );
            ensure!(
                optional_metadata_version(&connection, AUTH_PRUNE_TARGET_KEY)?.is_none(),
                "SQLite snapshot contains unfinished authenticated maintenance"
            );
        }
        if store_schema == STORE_SCHEMA_VERSION {
            let reservations = connection.query_row(
                "SELECT COUNT(*) FROM native_validation_reservations",
                [],
                |row| row.get::<_, u64>(0),
            )?;
            ensure!(
                reservations == 0,
                "SQLite snapshot contains node-local native validation reservations"
            );
        }
        Self::validate_latest_only_auth_storage(&connection, expected_height)?;
        let restored = load_sqlite_state(&connection)?;
        ensure!(
            (restored.height, restored.app_hash) == (expected_height, expected_app_hash),
            "validated SQLite snapshot state differs from trusted head"
        );
        Ok(restored)
    }

    pub(super) fn load_snapshot_object(
        &self,
        path: &Path,
        object_key_hex: &str,
    ) -> Result<Option<StoredObject>> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("open validated SQLite snapshot {}", path.display()))?;
        connection.execute_batch(
            "
            PRAGMA trusted_schema=OFF;
            PRAGMA query_only=ON;
            ",
        )?;
        load_object(&connection, object_key_hex)
    }

    fn validate_latest_only_auth_storage(connection: &Connection, height: u64) -> Result<()> {
        let reader = SqliteAuthReader { connection };
        let root_path: NibblePath = std::iter::empty().collect();
        let mut stack = vec![NodeKey::new(height, root_path)];
        let mut reachable_nodes = 0_u64;
        let mut reachable_leaves = 0_u64;
        while let Some(node_key) = stack.pop() {
            ensure!(
                node_key.version() <= height,
                "SQLite snapshot contains a future-version reachable node"
            );
            let node = reader
                .get_node_option(&node_key)?
                .context("SQLite snapshot is missing a reachable JMT node")?;
            reachable_nodes = reachable_nodes
                .checked_add(1)
                .context("reachable JMT node count overflow")?;
            match node {
                Node::Null => {}
                Node::Leaf(leaf) => {
                    reachable_leaves = reachable_leaves
                        .checked_add(1)
                        .context("reachable JMT leaf count overflow")?;
                    let preimage = reader
                        .preimage(leaf.key_hash())?
                        .context("reachable JMT leaf is missing its preimage")?;
                    ensure!(
                        authenticated_key_hash(&preimage)? == leaf.key_hash(),
                        "reachable JMT leaf preimage hash mismatch"
                    );
                }
                Node::Internal(internal) => {
                    for (nibble, child) in internal.children_sorted() {
                        ensure!(
                            child.version <= height,
                            "SQLite snapshot contains a future-version JMT child"
                        );
                        let path = node_key
                            .nibble_path()
                            .nibbles()
                            .chain(std::iter::once(nibble))
                            .collect();
                        stack.push(NodeKey::new(child.version, path));
                    }
                }
            }
        }
        let stored_nodes = connection.query_row("SELECT COUNT(*) FROM auth_nodes", [], |row| {
            row.get::<_, u64>(0)
        })?;
        let stored_preimages =
            connection.query_row("SELECT COUNT(*) FROM auth_preimages", [], |row| {
                row.get::<_, u64>(0)
            })?;
        let stored_values =
            connection.query_row("SELECT COUNT(*) FROM auth_values", [], |row| {
                row.get::<_, u64>(0)
            })?;
        ensure!(
            stored_nodes == reachable_nodes
                && stored_preimages == reachable_leaves
                && stored_values == reachable_leaves,
            "SQLite snapshot contains unreachable authenticated rows"
        );

        let mut statement = connection
            .prepare("SELECT key_hash, version_be, value, is_deleted FROM auth_values")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        for row in rows {
            let (key_hash, version, value, is_deleted) = row?;
            ensure!(
                key_hash.len() == 32
                    && decode_version_be(&version)? <= height
                    && value.is_some()
                    && is_deleted == 0,
                "SQLite snapshot contains a non-canonical latest value"
            );
            let preimage_exists = connection
                .query_row(
                    "SELECT 1 FROM auth_preimages WHERE key_hash=?1",
                    params![key_hash],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            ensure!(
                preimage_exists,
                "SQLite snapshot value has no reachable preimage"
            );
        }
        Ok(())
    }

    fn with_database_path(&self, database_path: PathBuf) -> Self {
        Self {
            status_path: database_path.with_extension("status-cache-unused"),
            database_path,
            chain_id: self.chain_id.clone(),
            signer_policy_hash_hex: self.signer_policy_hash_hex.clone(),
            writer_gate: Arc::new(Mutex::new(())),
            writer_waiters: Arc::new(AtomicUsize::new(0)),
            maintenance_gate: Arc::new(Mutex::new(())),
            active_snapshot_pins: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(super) fn persist_transition(
        &self,
        current: &AppState,
        pending: &PendingBlock,
        query_floor: Version,
    ) -> Result<()> {
        self.persist_transition_inner(current, pending, query_floor, None)
    }

    #[cfg(test)]
    pub(super) fn persist_transition_with_failpoint(
        &self,
        current: &AppState,
        pending: &PendingBlock,
        failpoint: StoreFailpoint,
    ) -> Result<()> {
        self.persist_transition_inner(current, pending, 0, Some(failpoint))
    }

    fn persist_transition_inner(
        &self,
        current: &AppState,
        pending: &PendingBlock,
        query_floor: Version,
        #[cfg_attr(not(test), allow(unused_variables))] failpoint: Option<StoreFailpoint>,
    ) -> Result<()> {
        ensure!(
            pending.height == current.height.saturating_add(1),
            "application store height transition is not contiguous"
        );
        ensure!(
            pending.auth_update.version == pending.height,
            "authenticated update version differs from pending height"
        );
        ensure!(
            query_floor <= pending.height,
            "authenticated query floor exceeds pending height"
        );

        let _writer = self.lock_writer()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_database_head(&transaction, current)?;
        ensure!(
            latest_auth_version(&transaction)? == Some(current.height)
                && auth_root(&transaction, current.height)?.map(Into::<[u8; 32]>::into)
                    == Some(current.app_hash),
            "authenticated tree head differs from committed application head"
        );
        validate_planned_production_poco_projection(
            &transaction,
            Some(current.height),
            &pending.auth_update,
        )?;
        for object in pending.delta.objects.values() {
            upsert_object(&transaction, object)?;
        }
        for command_id in &pending.delta.command_ids {
            ensure!(
                !current.command_ids.contains(command_id),
                "pending command ID already exists in committed state"
            );
            transaction.execute(
                "INSERT INTO command_ids(command_id) VALUES (?1)",
                params![command_id],
            )?;
        }
        for (signer_id, nonce) in &pending.delta.signer_nonces {
            ensure!(
                !current.signer_nonces.contains(&(signer_id.clone(), *nonce)),
                "pending signer nonce already exists in committed state"
            );
            transaction.execute(
                "INSERT INTO signer_nonces(signer_id, nonce) VALUES (?1, ?2)",
                params![signer_id, nonce.to_be_bytes().as_slice()],
            )?;
        }
        let lifecycle = pending
            .delta
            .validator_lifecycle
            .as_ref()
            .or(current.validator_lifecycle.as_ref())
            .context("cannot persist state before validator lifecycle initialization")?;
        write_validator_lifecycle(&transaction, lifecycle)?;
        ensure!(
            <[u8; 32]>::from(pending.auth_update.root_hash) == pending.app_hash,
            "pending AppHash differs from authenticated tree root"
        );
        persist_auth_update(&transaction, &pending.auth_update)?;
        write_head_values(&transaction, pending.height, pending.app_hash)?;
        advance_auth_query_floor(&transaction, query_floor)?;
        #[cfg(test)]
        if failpoint == Some(StoreFailpoint::BeforeSqlCommit) {
            return Err(anyhow!("injected failure before SQLite COMMIT"));
        }
        transaction.commit()?;
        #[cfg(test)]
        if failpoint == Some(StoreFailpoint::AfterSqlCommitBeforeStatus) {
            return Err(anyhow!(
                "injected failure after SQLite COMMIT before status refresh"
            ));
        }
        self.refresh_status_values_best_effort(pending.height, pending.app_hash);
        Ok(())
    }

    pub(super) fn replace_empty_state(
        &self,
        expected: &AppState,
        state: &AppState,
        auth_update: &PlannedAuthUpdate,
    ) -> Result<()> {
        ensure!(
            expected.height == 0 && expected.pending.is_none(),
            "replacement expected state must be empty"
        );
        ensure!(state.pending.is_none(), "cannot persist pending state");
        ensure!(
            auth_update.version == state.height
                && <[u8; 32]>::from(auth_update.root_hash) == state.app_hash,
            "replacement authenticated update does not match app head"
        );
        let _writer = self.lock_writer()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_database_head(&transaction, expected)?;
        validate_planned_production_poco_projection(
            &transaction,
            latest_auth_version(&transaction)?,
            auth_update,
        )?;
        replace_domain_state(&transaction, state)?;
        clear_auth_tree(&transaction)?;
        persist_auth_update(&transaction, auth_update)?;
        write_head_values(&transaction, state.height, state.app_hash)?;
        transaction.commit()?;
        self.refresh_status_best_effort(state);
        Ok(())
    }

    pub(super) fn replace_empty_state_from_tree(
        &self,
        expected: &AppState,
        state: &AppState,
        auth_tree: &InMemoryAuthTree,
    ) -> Result<()> {
        ensure!(
            expected.height == 0 && expected.pending.is_none(),
            "snapshot replacement expected state must be empty"
        );
        ensure!(state.pending.is_none(), "cannot persist pending state");
        ensure!(
            auth_tree.latest_version() == Some(state.height)
                && auth_tree
                    .root_hash(state.height)
                    .map(Into::<[u8; 32]>::into)
                    == Some(state.app_hash),
            "replacement authenticated state does not match app head"
        );
        validate_in_memory_authenticated_domain_projection(state, auth_tree)?;
        let _writer = self.lock_writer()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_database_head(&transaction, expected)?;
        replace_domain_state(&transaction, state)?;
        clear_auth_tree(&transaction)?;
        persist_full_auth_tree(&transaction, auth_tree)?;
        write_head_values(&transaction, state.height, state.app_hash)?;
        transaction.commit()?;
        self.refresh_status_best_effort(state);
        Ok(())
    }

    fn connect(&self) -> Result<Connection> {
        if let Some(parent) = self.database_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("create application store directory {}", parent.display())
            })?;
        }
        let initialize = !self.database_path.exists();
        let mut connection = Connection::open(&self.database_path)
            .with_context(|| format!("open application store {}", self.database_path.display()))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        if initialize {
            connection.execute_batch("PRAGMA journal_mode=WAL;")?;
        }
        connection.execute_batch(
            "
            PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON;
            ",
        )?;
        if initialize {
            connection.execute_batch(STORE_SCHEMA_SQL)?;
        }
        let schema: Option<String> = connection
            .query_row(
                "SELECT value FROM metadata WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match schema.as_deref() {
            Some(schema) => ensure!(
                schema == STORE_SCHEMA_VERSION
                    || schema == PREVIOUS_STORE_SCHEMA_VERSION
                    || schema == LEGACY_STORE_SCHEMA_VERSION,
                "unsupported application store schema version"
            ),
            None => {
                ensure!(
                    initialize,
                    "existing application store is missing schema_version"
                );
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES ('schema_version', ?1)",
                    params![STORE_SCHEMA_VERSION],
                )?;
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES (?1, '0')",
                    params![AUTH_QUERY_FLOOR_KEY],
                )?;
            }
        }
        if schema.as_deref() == Some(LEGACY_STORE_SCHEMA_VERSION) {
            migrate_store_schema_v3_to_v4(&mut connection)?;
        }
        if metadata(&connection, "schema_version")? == PREVIOUS_STORE_SCHEMA_VERSION {
            migrate_store_schema_v4_to_v5(&mut connection)?;
        }
        if initialize {
            ensure_metadata_binding(&connection, "chain_id", &self.chain_id)?;
            ensure_metadata_binding(&connection, "app_version", &APP_VERSION.to_string())?;
            ensure_metadata_binding(
                &connection,
                "authorized_signers_hash_hex",
                &self.signer_policy_hash_hex,
            )?;
            ensure_metadata_binding(&connection, "auth_tree", "jmt-sha256-v0.12.0")?;
            ensure_metadata_binding(&connection, "auth_codec", "borsh-v1")?;
        } else {
            self.verify_database_bindings(&connection)?;
        }
        validate_auth_prune_metadata(&connection)?;
        Ok(connection)
    }

    fn connect_read(&self) -> Result<Connection> {
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| {
            format!(
                "open application store read-only {}",
                self.database_path.display()
            )
        })?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "
            PRAGMA trusted_schema=OFF;
            PRAGMA query_only=ON;
            ",
        )?;
        self.verify_database_bindings(&connection)?;
        Ok(connection)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn connect_authenticated_runtime_read_v0(
        &self,
    ) -> std::result::Result<Connection, AuthenticatedRuntimeReadFailureV0> {
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| {
            classify_sqlite_authenticated_read_failure_v0(
                AuthenticatedRuntimeReadStageV0::OpenDatabase,
                &error,
            )
        })?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| {
                classify_sqlite_authenticated_read_failure_v0(
                    AuthenticatedRuntimeReadStageV0::ConfigureDatabase,
                    &error,
                )
            })?;
        connection
            .execute_batch(
                "
                PRAGMA trusted_schema=OFF;
                PRAGMA query_only=ON;
                ",
            )
            .map_err(|error| {
                classify_sqlite_authenticated_read_failure_v0(
                    AuthenticatedRuntimeReadStageV0::ConfigureDatabase,
                    &error,
                )
            })?;
        Ok(connection)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn validate_authenticated_runtime_snapshot_head_v0(
        &self,
        connection: &Connection,
    ) -> std::result::Result<(Version, RootHash), AuthenticatedRuntimeReadFailureV0> {
        self.verify_authenticated_runtime_database_bindings_v0(connection)?;
        let height = authenticated_runtime_head_v0(connection)?;
        let latest_version = latest_auth_version(connection).map_err(|error| {
            classify_authenticated_read_anyhow_v0(
                AuthenticatedRuntimeReadStageV0::ReadRoot,
                &error,
                "persisted authenticated root version is invalid",
            )
        })?;
        if latest_version != Some(height) {
            return Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadRoot,
                    sqlite: None,
                    reason: "latest authenticated root version differs from committed height",
                },
            );
        }
        let app_hash_hex = authenticated_runtime_required_metadata_v0(
            connection,
            "app_hash_hex",
            AuthenticatedRuntimeReadStageV0::ReadHead,
            "application store is missing committed app hash",
        )?;
        let app_hash = trnm_finality_types::decode_hash32(
            "authenticated runtime snapshot app_hash",
            &app_hash_hex,
        )
        .map_err(
            |_| AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage: AuthenticatedRuntimeReadStageV0::ReadHead,
                sqlite: None,
                reason: "application store committed app hash is not canonical lowercase hash32",
            },
        )?;
        require_authenticated_query_floor_v0(connection, height, height)?;
        let root_hash = authenticated_runtime_root_v0(connection, height)?.ok_or(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage: AuthenticatedRuntimeReadStageV0::ReadRoot,
                sqlite: None,
                reason: "committed head is missing its authenticated root",
            },
        )?;
        if root_hash != RootHash(app_hash) {
            return Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadRoot,
                    sqlite: None,
                    reason: "committed app hash differs from authenticated head root",
                },
            );
        }
        Ok((height, root_hash))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn verify_authenticated_runtime_database_bindings_v0(
        &self,
        connection: &Connection,
    ) -> std::result::Result<(), AuthenticatedRuntimeReadFailureV0> {
        let stage = AuthenticatedRuntimeReadStageV0::ValidateBindings;
        let schema_version = authenticated_runtime_required_metadata_v0(
            connection,
            "schema_version",
            stage,
            "application store is missing schema_version",
        )?;
        if schema_version != STORE_SCHEMA_VERSION {
            return Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage,
                    sqlite: None,
                    reason: "application store schema is not the active runtime schema",
                },
            );
        }
        let app_version = APP_VERSION.to_string();
        let bindings = [
            ("chain_id", self.chain_id.as_str()),
            ("app_version", app_version.as_str()),
            (
                "authorized_signers_hash_hex",
                self.signer_policy_hash_hex.as_str(),
            ),
            ("auth_tree", "jmt-sha256-v0.12.0"),
            ("auth_codec", "borsh-v1"),
        ];
        for (key, expected) in bindings {
            let actual = authenticated_runtime_required_metadata_v0(
                connection,
                key,
                stage,
                "application store is missing a required runtime binding",
            )?;
            if actual != expected {
                return Err(
                    AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                        stage,
                        sqlite: None,
                        reason: "application store runtime binding differs from configuration",
                    },
                );
            }
        }
        Ok(())
    }

    fn connect_maintenance(&self) -> Result<Connection> {
        let connection = Connection::open(&self.database_path).with_context(|| {
            format!(
                "open application store maintenance connection {}",
                self.database_path.display()
            )
        })?;
        connection.busy_timeout(Duration::ZERO)?;
        connection.execute_batch(
            "
            PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON;
            ",
        )?;
        self.verify_database_bindings(&connection)?;
        validate_auth_prune_metadata(&connection)?;
        Ok(connection)
    }

    fn probe_existing_database(&self) -> Result<()> {
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| {
            format!(
                "open existing application store read-only {}",
                self.database_path.display()
            )
        })?;
        validate_snapshot_schema(&connection)?;
        validate_storage_resource_bounds(&connection)?;
        self.verify_compatible_database_bindings(&connection)?;
        Ok(())
    }

    fn verify_database_bindings(&self, connection: &Connection) -> Result<()> {
        ensure!(
            self.verify_compatible_database_bindings(connection)? == STORE_SCHEMA_VERSION,
            "existing application store requires schema migration"
        );
        Ok(())
    }

    fn verify_compatible_database_bindings(&self, connection: &Connection) -> Result<String> {
        let schema_version: String = connection
            .query_row(
                "SELECT value FROM metadata WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .context("existing application store is missing or cannot read schema_version")?;
        ensure!(
            schema_version == STORE_SCHEMA_VERSION
                || schema_version == PREVIOUS_STORE_SCHEMA_VERSION
                || schema_version == LEGACY_STORE_SCHEMA_VERSION,
            "existing application store schema version is unsupported"
        );
        let app_version = APP_VERSION.to_string();
        let bindings = [
            ("chain_id", self.chain_id.as_str()),
            ("app_version", app_version.as_str()),
            (
                "authorized_signers_hash_hex",
                self.signer_policy_hash_hex.as_str(),
            ),
            ("auth_tree", "jmt-sha256-v0.12.0"),
            ("auth_codec", "borsh-v1"),
        ];
        for (key, expected) in bindings {
            let actual: String = connection
                .query_row(
                    "SELECT value FROM metadata WHERE key=?1",
                    params![key],
                    |row| row.get(0),
                )
                .with_context(|| {
                    format!("existing application store is missing or cannot read {key}")
                })?;
            ensure!(
                actual == expected,
                "existing application store {key} differs from configured value"
            );
        }
        Ok(schema_version)
    }

    fn has_committed_state(&self, connection: &Connection) -> Result<bool> {
        Ok(connection
            .query_row("SELECT value FROM metadata WHERE key='height'", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
            .is_some())
    }

    fn refresh_status_best_effort(&self, state: &AppState) {
        self.refresh_status_values_best_effort(state.height, state.app_hash);
    }

    fn refresh_status_values_best_effort(&self, height: u64, app_hash: [u8; 32]) {
        if let Err(error) = self.write_status_values(height, app_hash) {
            eprintln!(
                "[trnm-cometbft-app] SQLite commit is authoritative; failed to refresh status cache: {error:#}"
            );
        }
    }

    fn write_status_values(&self, height: u64, app_hash: [u8; 32]) -> Result<()> {
        let status = PersistedStatusV2 {
            schema: STATUS_SCHEMA_V2,
            app_version: APP_VERSION,
            height,
            app_hash_hex: hex::encode(app_hash),
        };
        persist_state_bytes(&self.status_path, &serde_json::to_vec(&status)?)
    }
}

fn verify_database_head(transaction: &Transaction<'_>, current: &AppState) -> Result<()> {
    let stored_height: Option<String> = transaction
        .query_row("SELECT value FROM metadata WHERE key='height'", [], |row| {
            row.get(0)
        })
        .optional()?;
    if current.height == 0 && stored_height.is_none() {
        return Ok(());
    }
    let stored_height = stored_height
        .ok_or_else(|| anyhow!("application store is missing committed height"))?
        .parse::<u64>()
        .context("parse application store height")?;
    let stored_hash: String = transaction
        .query_row(
            "SELECT value FROM metadata WHERE key='app_hash_hex'",
            [],
            |row| row.get(0),
        )
        .context("application store is missing committed app hash")?;
    ensure!(
        stored_height == current.height && stored_hash == hex::encode(current.app_hash),
        "application store head differs from in-memory committed state"
    );
    Ok(())
}

fn validate_planned_production_poco_projection(
    transaction: &Transaction<'_>,
    source_version: Option<Version>,
    update: &PlannedAuthUpdate,
) -> Result<()> {
    let expected_version = source_version.map_or(0, |version| version.saturating_add(1));
    ensure!(
        update.version == expected_version,
        "planned PoCO validation version is not exact-next"
    );
    let mut touches_poco = false;
    for preimage in update.preimages().values() {
        if poco_snapshot_key_components(preimage)?.is_some() {
            touches_poco = true;
        }
    }
    if !touches_poco {
        return Ok(());
    }

    let reader = SqliteAuthReader {
        connection: transaction,
    };
    let mut live = BTreeMap::new();
    if let Some(version) = source_version {
        let root_hash = auth_root(transaction, version)?
            .with_context(|| format!("missing source root for PoCO plan at version {version}"))?;
        // The iterator requires Arc even though this transaction-bound reader
        // never escapes the current thread.
        #[allow(clippy::arc_with_non_send_sync)]
        let iterator_reader = Arc::new(SqliteAuthReader {
            connection: transaction,
        });
        let iterator =
            JellyfishMerkleIterator::new(Arc::clone(&iterator_reader), version, KeyHash([0; 32]))
                .with_context(|| format!("open source PoCO iterator at version {version}"))?;
        for item in iterator {
            let (hash, value) =
                item.with_context(|| format!("iterate source PoCO state at version {version}"))?;
            let preimage = iterator_reader
                .preimage(hash)?
                .with_context(|| format!("missing PoCO source key preimage {hash:?}"))?;
            if poco_snapshot_key_components(&preimage)?.is_none() {
                continue;
            }
            let proof = prove_with_reader(
                iterator_reader.as_ref(),
                version,
                root_hash,
                preimage.clone(),
            )?;
            ensure!(
                proof.value.as_deref() == Some(value.as_slice())
                    && verify_ics23_membership(&proof, &value),
                "source PoCO leaf failed authenticated verification"
            );
            ensure!(
                live.insert(preimage, value).is_none(),
                "source PoCO namespace contains a duplicate physical key"
            );
        }
    }

    for ((version, hash), value) in update.tree_update_batch.node_batch.values() {
        ensure!(
            *version == update.version,
            "planned update contains a value at the wrong version"
        );
        let preimage = match update.preimages().get(hash) {
            Some(preimage) => preimage.clone(),
            None => reader
                .preimage(*hash)?
                .with_context(|| format!("missing planned authenticated key preimage {hash:?}"))?,
        };
        if poco_snapshot_key_components(&preimage)?.is_none() {
            continue;
        }
        match value {
            Some(value) => {
                live.insert(preimage, value.clone());
            }
            None => {
                live.remove(&preimage);
            }
        }
    }
    take_and_validate_production_poco_projection_v0(update.version, &mut live)?;
    ensure!(
        live.is_empty(),
        "planned PoCO projection left unclassified leaves"
    );
    Ok(())
}

/// Verifies the complete physical PoCO namespace at one already-authenticated
/// version/root using the caller's existing SQLite transaction.
///
/// Keeping this connection-bound primitive separate prevents native payload
/// validation from accidentally reopening the latest head or consulting the
/// projection cache after its exact parent snapshot has been fixed.
fn load_production_poco_projection_from_connection_v0(
    connection: &Connection,
    version: Version,
    root_hash: RootHash,
) -> Result<Option<ProductionPocoProjectionV0>> {
    #[allow(clippy::arc_with_non_send_sync)]
    let reader = Arc::new(SqliteAuthReader { connection });
    let iterator = JellyfishMerkleIterator::new(Arc::clone(&reader), version, KeyHash([0; 32]))
        .with_context(|| format!("open PoCO projection iterator at version {version}"))?;
    let mut live = BTreeMap::new();
    for item in iterator {
        let (hash, value) =
            item.with_context(|| format!("iterate PoCO projection at version {version}"))?;
        let preimage = reader
            .preimage(hash)?
            .with_context(|| format!("missing PoCO key preimage {hash:?}"))?;
        if poco_snapshot_key_components(&preimage)?.is_none() {
            continue;
        }
        let proof = prove_with_reader(reader.as_ref(), version, root_hash, preimage.clone())?;
        ensure!(
            proof.value.as_deref() == Some(value.as_slice())
                && verify_ics23_membership(&proof, &value),
            "PoCO projection leaf failed authenticated verification"
        );
        ensure!(
            live.insert(preimage, value).is_none(),
            "duplicate PoCO physical key"
        );
    }
    let projection = take_and_validate_production_poco_projection_v0(version, &mut live)?;
    ensure!(live.is_empty(), "unclassified PoCO physical leaves");
    Ok(projection)
}

fn write_head_values(transaction: &Transaction<'_>, height: u64, app_hash: [u8; 32]) -> Result<()> {
    for (key, value) in [
        ("height", height.to_string()),
        ("app_hash_hex", hex::encode(app_hash)),
    ] {
        transaction.execute(
            "INSERT INTO metadata(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
    }
    Ok(())
}

fn advance_auth_query_floor(transaction: &Transaction<'_>, requested: Version) -> Result<()> {
    let current = optional_metadata_version(transaction, AUTH_QUERY_FLOOR_KEY)?
        .context("application store is missing authenticated query floor")?;
    if requested <= current {
        return Ok(());
    }
    write_metadata_version(transaction, AUTH_QUERY_FLOOR_KEY, requested)?;
    write_metadata_version(transaction, AUTH_PRUNE_TARGET_KEY, requested)
}

fn clear_auth_tree(transaction: &Transaction<'_>) -> Result<()> {
    transaction.execute("DELETE FROM auth_nodes", [])?;
    transaction.execute("DELETE FROM auth_values", [])?;
    transaction.execute("DELETE FROM auth_preimages", [])?;
    transaction.execute("DELETE FROM auth_stale_nodes", [])?;
    transaction.execute("DELETE FROM auth_stale_values", [])?;
    transaction.execute("DELETE FROM auth_roots", [])?;
    write_metadata_version(transaction, AUTH_QUERY_FLOOR_KEY, 0)?;
    transaction.execute(
        "DELETE FROM metadata WHERE key=?1",
        params![AUTH_PRUNE_TARGET_KEY],
    )?;
    Ok(())
}

fn replace_domain_state(transaction: &Transaction<'_>, state: &AppState) -> Result<()> {
    transaction.execute("DELETE FROM objects", [])?;
    transaction.execute("DELETE FROM command_ids", [])?;
    transaction.execute("DELETE FROM signer_nonces", [])?;
    transaction.execute("DELETE FROM validator_lifecycle", [])?;
    for object in state.objects.values() {
        upsert_object(transaction, object)?;
    }
    for command_id in &state.command_ids {
        transaction.execute(
            "INSERT INTO command_ids(command_id) VALUES (?1)",
            params![command_id],
        )?;
    }
    for (signer_id, nonce) in &state.signer_nonces {
        transaction.execute(
            "INSERT INTO signer_nonces(signer_id, nonce) VALUES (?1, ?2)",
            params![signer_id, nonce.to_be_bytes().as_slice()],
        )?;
    }
    if let Some(lifecycle) = &state.validator_lifecycle {
        write_validator_lifecycle(transaction, lifecycle)?;
    }
    Ok(())
}

fn persist_full_auth_tree(
    transaction: &Transaction<'_>,
    auth_tree: &InMemoryAuthTree,
) -> Result<()> {
    for (node_key, node) in auth_tree.nodes() {
        transaction.execute(
            "INSERT INTO auth_nodes(node_key, node) VALUES (?1, ?2)",
            params![
                borsh::to_vec(node_key).context("encode JMT node key")?,
                borsh::to_vec(node).context("encode JMT node")?,
            ],
        )?;
    }
    for ((key_hash, version), value) in auth_tree.values() {
        transaction.execute(
            "INSERT INTO auth_values(key_hash, version_be, value, is_deleted)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                key_hash.0.as_slice(),
                version.to_be_bytes().as_slice(),
                value.as_deref(),
                i64::from(value.is_none()),
            ],
        )?;
    }
    rebuild_auth_stale_values(transaction)?;
    for (key_hash, preimage) in auth_tree.preimages() {
        transaction.execute(
            "INSERT INTO auth_preimages(key_hash, key_preimage) VALUES (?1, ?2)",
            params![key_hash.0.as_slice(), preimage],
        )?;
    }
    for stale in auth_tree.stale_nodes() {
        transaction.execute(
            "INSERT INTO auth_stale_nodes(stale_since_version_be, node_key)
             VALUES (?1, ?2)",
            params![
                stale.stale_since_version.to_be_bytes().as_slice(),
                borsh::to_vec(&stale.node_key).context("encode stale JMT node key")?,
            ],
        )?;
    }
    for (version, root) in auth_tree.roots() {
        transaction.execute(
            "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
            params![version.to_be_bytes().as_slice(), root.0.as_slice(),],
        )?;
    }
    Ok(())
}

fn persist_auth_update(transaction: &Transaction<'_>, update: &PlannedAuthUpdate) -> Result<()> {
    for (node_key, node) in update.tree_update_batch.node_batch.nodes() {
        transaction.execute(
            "INSERT INTO auth_nodes(node_key, node) VALUES (?1, ?2)",
            params![
                borsh::to_vec(node_key).context("encode JMT node key")?,
                borsh::to_vec(node).context("encode JMT node")?,
            ],
        )?;
    }
    for ((version, key_hash), value) in update.tree_update_batch.node_batch.values() {
        let previous_version: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT version_be
                 FROM auth_values
                 WHERE key_hash=?1 AND version_be<?2
                 ORDER BY version_be DESC
                 LIMIT 1",
                params![key_hash.0.as_slice(), version.to_be_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(previous_version) = previous_version {
            transaction.execute(
                "INSERT INTO auth_stale_values(
                    stale_since_version_be,
                    key_hash,
                    version_be
                 ) VALUES (?1, ?2, ?3)",
                params![
                    version.to_be_bytes().as_slice(),
                    key_hash.0.as_slice(),
                    previous_version,
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO auth_values(key_hash, version_be, value, is_deleted)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                key_hash.0.as_slice(),
                version.to_be_bytes().as_slice(),
                value.as_deref(),
                i64::from(value.is_none()),
            ],
        )?;
    }
    for (key_hash, preimage) in update.preimages() {
        transaction.execute(
            "INSERT INTO auth_preimages(key_hash, key_preimage) VALUES (?1, ?2)
             ON CONFLICT(key_hash) DO NOTHING",
            params![key_hash.0.as_slice(), preimage],
        )?;
        let stored: Vec<u8> = transaction.query_row(
            "SELECT key_preimage FROM auth_preimages WHERE key_hash=?1",
            params![key_hash.0.as_slice()],
            |row| row.get(0),
        )?;
        ensure!(
            stored == *preimage,
            "authenticated key hash collision in persistent preimage store"
        );
    }
    for stale in &update.tree_update_batch.stale_node_index_batch {
        transaction.execute(
            "INSERT INTO auth_stale_nodes(stale_since_version_be, node_key)
             VALUES (?1, ?2)",
            params![
                stale.stale_since_version.to_be_bytes().as_slice(),
                borsh::to_vec(&stale.node_key).context("encode stale JMT node key")?,
            ],
        )?;
    }
    transaction.execute(
        "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
        params![
            update.version.to_be_bytes().as_slice(),
            update.root_hash.0.as_slice(),
        ],
    )?;
    Ok(())
}

fn decode_version_be(bytes: &[u8]) -> Result<Version> {
    Ok(u64::from_be_bytes(<[u8; 8]>::try_from(bytes).map_err(
        |_| anyhow!("persisted JMT version is not 8 bytes"),
    )?))
}

fn rebuild_auth_stale_values(connection: &Connection) -> Result<()> {
    connection.execute("DELETE FROM auth_stale_values", [])?;
    connection.execute(
        "INSERT INTO auth_stale_values(
            stale_since_version_be,
            key_hash,
            version_be
         )
         SELECT next_version_be, key_hash, version_be
         FROM (
             SELECT key_hash,
                    version_be,
                    LEAD(version_be) OVER (
                        PARTITION BY key_hash
                        ORDER BY version_be
                    ) AS next_version_be
             FROM auth_values
         )
         WHERE next_version_be IS NOT NULL",
        [],
    )?;
    Ok(())
}

fn upsert_object(transaction: &Transaction<'_>, object: &StoredObject) -> Result<()> {
    transaction.execute(
        "INSERT INTO objects(
            object_key_hex, object_type, version, value_hash_hex, value_bytes
         ) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(object_key_hex) DO UPDATE SET
            object_type=excluded.object_type,
            version=excluded.version,
            value_hash_hex=excluded.value_hash_hex,
            value_bytes=excluded.value_bytes",
        params![
            object.object_key_hex,
            object.object_type,
            object.version.to_string(),
            object.value_hash_hex,
            object.value_bytes,
        ],
    )?;
    Ok(())
}

fn write_validator_lifecycle(
    transaction: &Transaction<'_>,
    lifecycle: &ValidatorLifecycleStateV1,
) -> Result<()> {
    lifecycle.validate()?;
    transaction.execute(
        "INSERT INTO validator_lifecycle(singleton, state_json) VALUES (1, ?1)
         ON CONFLICT(singleton) DO UPDATE SET state_json=excluded.state_json",
        params![serde_json::to_vec(lifecycle)?],
    )?;
    Ok(())
}

fn verify_retained_lifecycle_proofs(
    connection: &Connection,
    height: Version,
    app_hash: [u8; 32],
    boundary: Version,
) -> Result<()> {
    ensure!(
        boundary <= height,
        "authenticated proof boundary exceeds the committed head"
    );
    let retained_root = auth_root(connection, height)?
        .context("authenticated maintenance removed the committed root")?;
    ensure!(
        <[u8; 32]>::from(retained_root) == app_hash,
        "authenticated maintenance changed the committed AppHash"
    );
    let lifecycle_bytes: Vec<u8> = connection.query_row(
        "SELECT state_json FROM validator_lifecycle WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let reader = SqliteAuthReader { connection };
    let latest_proof = prove_with_reader(&reader, height, retained_root, validator_state_key()?)?;
    let latest_value = latest_proof
        .value
        .as_deref()
        .context("latest validator lifecycle proof is absent")?;
    let lifecycle_record = AuthenticatedObjectRecord::decode(latest_value)?;
    ensure!(
        lifecycle_record.object_type == VALIDATOR_LIFECYCLE_SCHEMA_V1
            && lifecycle_record.object_version <= height
            && lifecycle_record.value == lifecycle_bytes
            && verify_ics23_membership(&latest_proof, latest_value),
        "authenticated maintenance damaged the latest validator lifecycle proof"
    );
    if boundary < height {
        let boundary_root = auth_root(connection, boundary)?
            .context("authenticated maintenance removed the retention-boundary root")?;
        let boundary_proof =
            prove_with_reader(&reader, boundary, boundary_root, validator_state_key()?)?;
        let boundary_value = boundary_proof
            .value
            .as_deref()
            .context("retention-boundary lifecycle proof is absent")?;
        ensure!(
            verify_ics23_membership(&boundary_proof, boundary_value),
            "authenticated maintenance damaged the retention-boundary proof"
        );
    }
    Ok(())
}

fn load_sqlite_state(connection: &Connection) -> Result<AppState> {
    let height = metadata(connection, "height")?
        .parse::<u64>()
        .context("parse application store height")?;
    let app_hash = trnm_finality_types::decode_hash32(
        "application store app_hash",
        &metadata(connection, "app_hash_hex")?,
    )?;
    if let Some(query_floor) = optional_metadata_version(connection, AUTH_QUERY_FLOOR_KEY)? {
        ensure!(
            query_floor <= height && auth_root(connection, query_floor)?.is_some(),
            "application store authenticated query floor is invalid"
        );
        if let Some(target) = optional_metadata_version(connection, AUTH_PRUNE_TARGET_KEY)? {
            ensure!(
                target == query_floor,
                "application store authenticated prune target differs from its query floor"
            );
        }
    }
    validate_no_future_auth_rows(connection, height)?;
    if metadata(connection, "schema_version")? != LEGACY_STORE_SCHEMA_VERSION {
        validate_auth_stale_value_index(connection)?;
    }

    let lifecycle_bytes: Vec<u8> = connection
        .query_row(
            "SELECT state_json FROM validator_lifecycle WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .context("application store is missing committed validator lifecycle")?;
    let validator_lifecycle: ValidatorLifecycleStateV1 =
        serde_json::from_slice(&lifecycle_bytes)
            .context("decode application store validator lifecycle")?;
    validator_lifecycle.validate()?;

    ensure!(
        latest_auth_version(connection)? == Some(height),
        "authenticated tree version differs from application height"
    );
    let root_hash = auth_root(connection, height)?
        .context("application store is missing authenticated root")?;
    ensure!(
        <[u8; 32]>::from(root_hash) == app_hash,
        "application store content does not match committed app hash"
    );

    let object_count = connection.query_row("SELECT COUNT(*) FROM objects", [], |row| {
        row.get::<_, u64>(0)
    })?;
    // JellyfishMerkleIterator's public API requires Arc even though this
    // connection-bound reader never leaves the current thread.
    #[allow(clippy::arc_with_non_send_sync)]
    let reader = Arc::new(SqliteAuthReader { connection });
    let iterator = JellyfishMerkleIterator::new(Arc::clone(&reader), height, KeyHash([0; 32]))
        .with_context(|| format!("open authenticated tree iterator at version {height}"))?;
    let lifecycle_key = validator_state_key()?;
    let mut object_leaves = 0_u64;
    let mut lifecycle_seen = false;
    let mut poco_leaves = BTreeMap::new();
    for entry in iterator {
        let (hash, value) =
            entry.with_context(|| format!("iterate authenticated tree at version {height}"))?;
        let preimage = reader
            .preimage(hash)?
            .with_context(|| format!("missing authenticated key preimage {hash:?}"))?;
        ensure!(
            authenticated_key_hash(&preimage)? == hash,
            "authenticated key preimage hash mismatch"
        );
        let proof = prove_with_reader(reader.as_ref(), height, root_hash, preimage.clone())?;
        ensure!(
            proof.value.as_deref() == Some(value.as_slice())
                && verify_ics23_membership(&proof, &value),
            "authenticated tree leaf failed root verification"
        );
        if preimage == lifecycle_key {
            ensure!(
                !lifecycle_seen,
                "authenticated state contains duplicate validator lifecycle"
            );
            let lifecycle_record = AuthenticatedObjectRecord::decode(&value)?;
            ensure!(
                lifecycle_record.object_type == VALIDATOR_LIFECYCLE_SCHEMA_V1
                    && lifecycle_record.object_version <= height
                    && lifecycle_record.value == lifecycle_bytes,
                "application store validator lifecycle differs from authenticated state"
            );
            lifecycle_seen = true;
            continue;
        }

        if poco_snapshot_key_components(&preimage)?.is_some() {
            ensure!(
                poco_leaves.insert(preimage, value).is_none(),
                "authenticated state contains duplicate PoCO physical key"
            );
            continue;
        }

        let object_key_hex = stored_object_key_preimage(&preimage)?;
        let object = load_object(connection, &object_key_hex)?.with_context(|| {
            format!("authenticated object {object_key_hex} is absent from the application store")
        })?;
        validate_object(&object)?;
        let expected =
            AuthenticatedObjectRecord::new(object.object_type, object.version, object.value_bytes)?
                .encode()?;
        ensure!(
            value == expected,
            "application store object {object_key_hex} differs from authenticated state"
        );
        object_leaves = object_leaves.saturating_add(1);
    }
    ensure!(
        lifecycle_seen,
        "authenticated state is missing validator lifecycle"
    );
    ensure!(
        object_leaves == object_count,
        "application store contains objects absent from authenticated state"
    );
    take_and_validate_production_poco_projection_v0(height, &mut poco_leaves)?;
    ensure!(
        poco_leaves.is_empty(),
        "application store contains unclassified PoCO leaves"
    );

    Ok(AppState {
        height,
        app_hash,
        objects: std::collections::BTreeMap::new(),
        command_ids: std::collections::BTreeSet::new(),
        signer_nonces: std::collections::BTreeSet::new(),
        validator_lifecycle: Some(validator_lifecycle),
        pending: None,
    })
}

fn validate_no_future_auth_rows(connection: &Connection, height: u64) -> Result<()> {
    {
        let mut statement = connection.prepare("SELECT node_key FROM auth_nodes")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            let node_key: NodeKey =
                borsh::from_slice(&row?).context("decode persisted JMT node key")?;
            ensure!(
                node_key.version() <= height,
                "application store contains a future-version JMT node"
            );
        }
    }
    let mut version_columns = vec![
        ("auth_values", "version_be"),
        ("auth_roots", "version_be"),
        ("auth_stale_nodes", "stale_since_version_be"),
    ];
    if metadata(connection, "schema_version")? != LEGACY_STORE_SCHEMA_VERSION {
        version_columns.extend([
            ("auth_stale_values", "stale_since_version_be"),
            ("auth_stale_values", "version_be"),
        ]);
    }
    for (table, column) in version_columns {
        let query = format!("SELECT {column} FROM {table}");
        let mut statement = connection.prepare(&query)?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            ensure!(
                decode_version_be(&row?)? <= height,
                "application store contains a future-version row in {table}"
            );
        }
    }
    Ok(())
}

fn validate_auth_stale_value_index(connection: &Connection) -> Result<()> {
    let missing_or_wrong = connection
        .query_row(
            "WITH ordered AS (
                 SELECT key_hash,
                        version_be,
                        LEAD(version_be) OVER (
                            PARTITION BY key_hash
                            ORDER BY version_be
                        ) AS next_version_be
                 FROM auth_values
             )
             SELECT 1
             FROM ordered
             LEFT JOIN auth_stale_values AS stale
               ON stale.key_hash=ordered.key_hash
              AND stale.version_be=ordered.version_be
             WHERE ordered.next_version_be IS NOT NULL
               AND (
                   stale.stale_since_version_be IS NULL
                   OR stale.stale_since_version_be<>ordered.next_version_be
               )
             LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    ensure!(
        !missing_or_wrong,
        "application store authenticated stale-value index is incomplete"
    );
    let unexpected = connection
        .query_row(
            "WITH ordered AS (
                 SELECT key_hash,
                        version_be,
                        LEAD(version_be) OVER (
                            PARTITION BY key_hash
                            ORDER BY version_be
                        ) AS next_version_be
                 FROM auth_values
             )
             SELECT 1
             FROM auth_stale_values AS stale
             LEFT JOIN ordered
               ON ordered.key_hash=stale.key_hash
              AND ordered.version_be=stale.version_be
             WHERE ordered.next_version_be IS NULL
                OR ordered.next_version_be<>stale.stale_since_version_be
             LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    ensure!(
        !unexpected,
        "application store authenticated stale-value index contains an invalid row"
    );
    Ok(())
}

fn native_validation_route_code_v0(route: PayloadValidationRouteV0) -> i64 {
    match route {
        PayloadValidationRouteV0::Proposal => 0,
        PayloadValidationRouteV0::Synced => 1,
    }
}

fn validate_native_validation_reservation_bindings_v0(
    connection: &Connection,
    store: &ApplicationStore,
) -> std::result::Result<(), NativeValidationReservationFailureCauseV0> {
    let stage = NativeValidationReservationStageV0::ValidateBindings;
    let app_version = APP_VERSION.to_string();
    let bindings = [
        ("schema_version", STORE_SCHEMA_VERSION),
        ("chain_id", store.chain_id.as_str()),
        ("app_version", app_version.as_str()),
        (
            "authorized_signers_hash_hex",
            store.signer_policy_hash_hex.as_str(),
        ),
        ("auth_tree", "jmt-sha256-v0.12.0"),
        ("auth_codec", "borsh-v1"),
    ];
    for (key, expected) in bindings {
        let actual = connection
            .query_row(
                "SELECT value FROM metadata WHERE key=?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| {
                classify_native_validation_reservation_sqlite_failure_v0(stage, &error)
            })?;
        if actual != expected {
            return Err(NativeValidationReservationFailureCauseV0::HostInvariant {
                stage,
                sqlite: None,
            });
        }
    }
    Ok(())
}

fn load_native_validation_reservation_v0(
    connection: &Connection,
    facts: &NativeValidationReservationFactsV0,
) -> std::result::Result<
    Option<NativeValidationReservationExistingV0>,
    NativeValidationReservationFailureCauseV0,
> {
    let validation_id = facts.validation_id;
    connection
        .query_row(
            "SELECT route, target_height_be, parent_block_id, request_fingerprint
             FROM native_validation_reservations
             WHERE block_id=?1 AND view_be=?2 AND generation_be=?3",
            params![
                validation_id.block_id().as_bytes().as_slice(),
                validation_id.view().get().to_be_bytes().as_slice(),
                validation_id.generation().to_be_bytes().as_slice(),
            ],
            |row| {
                Ok(NativeValidationReservationExistingV0 {
                    route: row.get(0)?,
                    target_height_be: row.get(1)?,
                    parent_block_id: row.get(2)?,
                    request_fingerprint: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(|error| {
            classify_native_validation_reservation_sqlite_failure_v0(
                NativeValidationReservationStageV0::ReadExisting,
                &error,
            )
        })
}

fn validate_native_validation_reservation_congruence_v0(
    facts: &NativeValidationReservationFactsV0,
    existing: &NativeValidationReservationExistingV0,
) -> std::result::Result<(), NativeValidationReservationFailureCauseV0> {
    let stage = NativeValidationReservationStageV0::ReadExisting;
    if !matches!(existing.route, 0 | 1)
        || existing.target_height_be.len() != 8
        || existing.parent_block_id.len() != 32
        || existing.request_fingerprint.len() != 32
    {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
            sqlite: None,
        });
    }
    if existing.route != native_validation_route_code_v0(facts.route) {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::RouteMismatch,
            sqlite: None,
        });
    }
    let mut target_height_be = [0_u8; 8];
    target_height_be.copy_from_slice(&existing.target_height_be);
    if u64::from_be_bytes(target_height_be) != facts.target_height {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::TargetHeightMismatch,
            sqlite: None,
        });
    }
    if existing.parent_block_id.as_slice() != facts.parent_block_id.as_slice() {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::ParentBlockIdMismatch,
            sqlite: None,
        });
    }
    if existing.request_fingerprint.as_slice() != facts.request_fingerprint.as_slice() {
        return Err(NativeValidationReservationFailureCauseV0::Invariant {
            stage,
            kind: NativeValidationReservationInvariantV0::RequestFingerprintMismatch,
            sqlite: None,
        });
    }
    Ok(())
}

fn insert_native_validation_reservation_v0(
    connection: &Connection,
    facts: &NativeValidationReservationFactsV0,
) -> std::result::Result<(), NativeValidationReservationFailureCauseV0> {
    let validation_id = facts.validation_id;
    connection
        .execute(
            "INSERT INTO native_validation_reservations(
                 route, block_id, view_be, generation_be, target_height_be,
                 parent_block_id, request_fingerprint
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                native_validation_route_code_v0(facts.route),
                validation_id.block_id().as_bytes().as_slice(),
                validation_id.view().get().to_be_bytes().as_slice(),
                validation_id.generation().to_be_bytes().as_slice(),
                facts.target_height.to_be_bytes().as_slice(),
                facts.parent_block_id.as_slice(),
                facts.request_fingerprint.as_slice(),
            ],
        )
        .map_err(|error| {
            classify_native_validation_reservation_sqlite_failure_v0(
                NativeValidationReservationStageV0::Insert,
                &error,
            )
        })?;
    Ok(())
}

fn classify_native_validation_reservation_sqlite_failure_v0(
    stage: NativeValidationReservationStageV0,
    error: &rusqlite::Error,
) -> NativeValidationReservationFailureCauseV0 {
    match classify_sqlite_authenticated_read_failure_v0(
        AuthenticatedRuntimeReadStageV0::ValidateBindings,
        error,
    ) {
        AuthenticatedRuntimeReadFailureV0::DatabaseUnavailable { sqlite, .. } => {
            NativeValidationReservationFailureCauseV0::DatabaseUnavailable { stage, sqlite }
        }
        AuthenticatedRuntimeReadFailureV0::StorageUnavailable { sqlite, .. } => {
            NativeValidationReservationFailureCauseV0::StorageUnavailable { stage, sqlite }
        }
        AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable { sqlite, .. } => {
            NativeValidationReservationFailureCauseV0::HostResourceUnavailable { stage, sqlite }
        }
        AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant { sqlite, .. } => {
            NativeValidationReservationFailureCauseV0::Invariant {
                stage,
                kind: NativeValidationReservationInvariantV0::PersistedRepresentationMalformed,
                sqlite,
            }
        }
        AuthenticatedRuntimeReadFailureV0::HostInvariant { sqlite, .. } => {
            NativeValidationReservationFailureCauseV0::HostInvariant { stage, sqlite }
        }
        AuthenticatedRuntimeReadFailureV0::SourceMismatch { .. }
        | AuthenticatedRuntimeReadFailureV0::Pruned { .. } => {
            NativeValidationReservationFailureCauseV0::HostInvariant {
                stage,
                sqlite: None,
            }
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn classify_sqlite_authenticated_read_failure_v0(
    stage: AuthenticatedRuntimeReadStageV0,
    error: &rusqlite::Error,
) -> AuthenticatedRuntimeReadFailureV0 {
    let rusqlite::Error::SqliteFailure(error, _) = error else {
        return match error {
            rusqlite::Error::FromSqlConversionFailure(_, _, _)
            | rusqlite::Error::IntegralValueOutOfRange(_, _)
            | rusqlite::Error::Utf8Error(_)
            | rusqlite::Error::InvalidColumnType(_, _, _)
            | rusqlite::Error::QueryReturnedNoRows => {
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage,
                    sqlite: None,
                    reason: "persisted SQLite value does not match the authenticated schema",
                }
            }
            _ => AuthenticatedRuntimeReadFailureV0::HostInvariant {
                stage,
                sqlite: None,
                reason: "non-SQLite host API failure at an authenticated read boundary",
            },
        };
    };
    let sqlite = TypedSqliteReadCodeV0 {
        code: error.code,
        extended_code: error.extended_code,
    };
    match error.code {
        ErrorCode::DatabaseBusy
        | ErrorCode::DatabaseLocked
        | ErrorCode::OperationInterrupted
        | ErrorCode::FileLockingProtocolFailed => {
            AuthenticatedRuntimeReadFailureV0::DatabaseUnavailable { stage, sqlite }
        }
        ErrorCode::PermissionDenied
        | ErrorCode::ReadOnly
        | ErrorCode::DiskFull
        | ErrorCode::CannotOpen
        | ErrorCode::NoLargeFileSupport => {
            AuthenticatedRuntimeReadFailureV0::StorageUnavailable { stage, sqlite }
        }
        ErrorCode::SystemIoFailure => classify_sqlite_system_io_failure_v0(stage, sqlite),
        ErrorCode::OutOfMemory => AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable {
            stage,
            sqlite: Some(sqlite),
            reason: "SQLite host resource limit prevented an authenticated read",
        },
        ErrorCode::DatabaseCorrupt
        | ErrorCode::NotADatabase
        | ErrorCode::TooBig
        | ErrorCode::TypeMismatch => {
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: Some(sqlite),
                reason: "SQLite authenticated-state representation is corrupt",
            }
        }
        ErrorCode::InternalMalfunction
        | ErrorCode::OperationAborted
        | ErrorCode::NotFound
        | ErrorCode::SchemaChanged
        | ErrorCode::ConstraintViolation
        | ErrorCode::ApiMisuse
        | ErrorCode::AuthorizationForStatementDenied
        | ErrorCode::ParameterOutOfRange
        | ErrorCode::Unknown => AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage,
            sqlite: Some(sqlite),
            reason: "SQLite returned a fail-stop host or unknown error code",
        },
        // `ErrorCode` is non-exhaustive. Future codes remain fail-stop until
        // they receive an explicit protocol-safe classification here.
        _ => AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage,
            sqlite: Some(sqlite),
            reason: "unclassified future SQLite error code",
        },
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn classify_sqlite_system_io_failure_v0(
    stage: AuthenticatedRuntimeReadStageV0,
    sqlite: TypedSqliteReadCodeV0,
) -> AuthenticatedRuntimeReadFailureV0 {
    match sqlite.extended_code {
        // Only these named VFS operation failures are retryable storage
        // dependencies. The primary SQLITE_IOERR code and future extended
        // codes are intentionally absent from this allowlist.
        rusqlite::ffi::SQLITE_IOERR_READ
        | rusqlite::ffi::SQLITE_IOERR_SHORT_READ
        | rusqlite::ffi::SQLITE_IOERR_WRITE
        | rusqlite::ffi::SQLITE_IOERR_FSYNC
        | rusqlite::ffi::SQLITE_IOERR_DIR_FSYNC
        | rusqlite::ffi::SQLITE_IOERR_TRUNCATE
        | rusqlite::ffi::SQLITE_IOERR_FSTAT
        | rusqlite::ffi::SQLITE_IOERR_UNLOCK
        | rusqlite::ffi::SQLITE_IOERR_RDLOCK
        | rusqlite::ffi::SQLITE_IOERR_DELETE
        | rusqlite::ffi::SQLITE_IOERR_BLOCKED
        | rusqlite::ffi::SQLITE_IOERR_ACCESS
        | rusqlite::ffi::SQLITE_IOERR_CHECKRESERVEDLOCK
        | rusqlite::ffi::SQLITE_IOERR_LOCK
        | rusqlite::ffi::SQLITE_IOERR_CLOSE
        | rusqlite::ffi::SQLITE_IOERR_DIR_CLOSE
        | rusqlite::ffi::SQLITE_IOERR_SHMOPEN
        | rusqlite::ffi::SQLITE_IOERR_SHMSIZE
        | rusqlite::ffi::SQLITE_IOERR_SHMLOCK
        | rusqlite::ffi::SQLITE_IOERR_SHMMAP
        | rusqlite::ffi::SQLITE_IOERR_SEEK
        | rusqlite::ffi::SQLITE_IOERR_DELETE_NOENT
        | rusqlite::ffi::SQLITE_IOERR_MMAP
        | rusqlite::ffi::SQLITE_IOERR_GETTEMPPATH
        | rusqlite::ffi::SQLITE_IOERR_BEGIN_ATOMIC
        | rusqlite::ffi::SQLITE_IOERR_COMMIT_ATOMIC
        | rusqlite::ffi::SQLITE_IOERR_ROLLBACK_ATOMIC => {
            AuthenticatedRuntimeReadFailureV0::StorageUnavailable { stage, sqlite }
        }
        rusqlite::ffi::SQLITE_IOERR_NOMEM => {
            AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable {
                stage,
                sqlite: Some(sqlite),
                reason: "SQLite VFS memory exhaustion prevented an authenticated read",
            }
        }
        // DATA and IN_PAGE mean the persisted database page cannot be trusted,
        // so they are authenticated-state corruption rather than retryable I/O.
        rusqlite::ffi::SQLITE_IOERR_DATA | rusqlite::ffi::SQLITE_IOERR_IN_PAGE => {
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: Some(sqlite),
                reason: "SQLite reported untrustworthy authenticated database page data",
            }
        }
        // CORRUPTFS and VFS/path authorization failures describe the host
        // storage environment, not authenticated application state.
        rusqlite::ffi::SQLITE_IOERR_CORRUPTFS
        | rusqlite::ffi::SQLITE_IOERR_CONVPATH
        | rusqlite::ffi::SQLITE_IOERR_VNODE
        | rusqlite::ffi::SQLITE_IOERR_AUTH => AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage,
            sqlite: Some(sqlite),
            reason: "SQLite reported a fail-stop VFS or filesystem invariant",
        },
        _ => AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage,
            sqlite: Some(sqlite),
            reason: "unclassified SQLite system I/O extended code",
        },
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn authenticated_runtime_read_failure_is_fail_stop_v0(
    failure: &AuthenticatedRuntimeReadFailureV0,
) -> bool {
    matches!(
        failure,
        AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant { .. }
            | AuthenticatedRuntimeReadFailureV0::HostInvariant { .. }
    )
}

#[cfg_attr(not(test), allow(dead_code))]
fn merge_authenticated_runtime_read_and_rollback_v0<T>(
    result: std::result::Result<T, AuthenticatedRuntimeReadFailureV0>,
    rollback: std::result::Result<(), AuthenticatedRuntimeReadFailureV0>,
) -> std::result::Result<T, AuthenticatedRuntimeReadFailureV0> {
    match (result, rollback) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(rollback_error)) => Err(rollback_error),
        (Err(read_error), Ok(())) => Err(read_error),
        (Err(read_error), Err(rollback_error)) => {
            if authenticated_runtime_read_failure_is_fail_stop_v0(&rollback_error)
                && !authenticated_runtime_read_failure_is_fail_stop_v0(&read_error)
            {
                Err(rollback_error)
            } else {
                Err(read_error)
            }
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn classify_authenticated_read_anyhow_v0(
    stage: AuthenticatedRuntimeReadStageV0,
    error: &anyhow::Error,
    invariant_reason: &'static str,
) -> AuthenticatedRuntimeReadFailureV0 {
    if let Some(sqlite) = error
        .chain()
        .find_map(|source| source.downcast_ref::<rusqlite::Error>())
    {
        return classify_sqlite_authenticated_read_failure_v0(stage, sqlite);
    }
    AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
        stage,
        sqlite: None,
        reason: invariant_reason,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn authenticated_runtime_required_metadata_v0(
    connection: &Connection,
    key: &str,
    stage: AuthenticatedRuntimeReadStageV0,
    missing_reason: &'static str,
) -> std::result::Result<String, AuthenticatedRuntimeReadFailureV0> {
    match connection.query_row(
        "SELECT value FROM metadata WHERE key=?1",
        params![key],
        |row| row.get(0),
    ) {
        Ok(value) => Ok(value),
        Err(rusqlite::Error::QueryReturnedNoRows) => Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: None,
                reason: missing_reason,
            },
        ),
        Err(error) => Err(classify_sqlite_authenticated_read_failure_v0(stage, &error)),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn authenticated_runtime_optional_metadata_v0(
    connection: &Connection,
    key: &str,
    stage: AuthenticatedRuntimeReadStageV0,
) -> std::result::Result<Option<String>, AuthenticatedRuntimeReadFailureV0> {
    connection
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| classify_sqlite_authenticated_read_failure_v0(stage, &error))
}

#[cfg_attr(not(test), allow(dead_code))]
fn parse_canonical_decimal_version_v0(
    value: &str,
    stage: AuthenticatedRuntimeReadStageV0,
    reason: &'static str,
) -> std::result::Result<Version, AuthenticatedRuntimeReadFailureV0> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: None,
                reason,
            },
        );
    }
    value.parse::<Version>().map_err(|_| {
        AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
            stage,
            sqlite: None,
            reason,
        }
    })
}

#[cfg_attr(not(test), allow(dead_code))]
fn authenticated_runtime_head_v0(
    connection: &Connection,
) -> std::result::Result<Version, AuthenticatedRuntimeReadFailureV0> {
    let stage = AuthenticatedRuntimeReadStageV0::ReadHead;
    let value = authenticated_runtime_required_metadata_v0(
        connection,
        "height",
        stage,
        "application store is missing committed height",
    )?;
    parse_canonical_decimal_version_v0(
        &value,
        stage,
        "application store committed height is not canonical u64",
    )
}

#[cfg_attr(not(test), allow(dead_code))]
fn require_authenticated_query_floor_v0(
    connection: &Connection,
    requested: Version,
    committed_height: Version,
) -> std::result::Result<Version, AuthenticatedRuntimeReadFailureV0> {
    let stage = AuthenticatedRuntimeReadStageV0::ReadQueryFloor;
    let floor_value = authenticated_runtime_required_metadata_v0(
        connection,
        AUTH_QUERY_FLOOR_KEY,
        stage,
        "application store is missing durable authenticated query floor",
    )?;
    let floor = parse_canonical_decimal_version_v0(
        &floor_value,
        stage,
        "durable authenticated query floor is not canonical u64",
    )?;
    let target =
        authenticated_runtime_optional_metadata_v0(connection, AUTH_PRUNE_TARGET_KEY, stage)?
            .map(|value| {
                parse_canonical_decimal_version_v0(
                    &value,
                    stage,
                    "authenticated prune target is not canonical u64",
                )
            })
            .transpose()?;
    if floor > committed_height {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: None,
                reason: "durable authenticated query floor exceeds committed height",
            },
        );
    }
    if target.is_some_and(|target| target != floor) {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: None,
                reason: "authenticated prune target differs from durable query floor",
            },
        );
    }
    if authenticated_runtime_root_v0(connection, floor)?.is_none() {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: None,
                reason: "durable authenticated query floor has no retained root",
            },
        );
    }
    if requested < floor {
        return Err(AuthenticatedRuntimeReadFailureV0::Pruned { requested, floor });
    }
    if requested > committed_height {
        return Err(AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable {
            stage,
            sqlite: None,
            reason: "requested authenticated version is not committed locally",
        });
    }
    Ok(floor)
}

#[cfg_attr(not(test), allow(dead_code))]
fn authenticated_runtime_root_v0(
    connection: &Connection,
    version: Version,
) -> std::result::Result<Option<RootHash>, AuthenticatedRuntimeReadFailureV0> {
    let stage = AuthenticatedRuntimeReadStageV0::ReadRoot;
    let encoded: Option<Vec<u8>> = connection
        .query_row(
            "SELECT root_hash FROM auth_roots WHERE version_be=?1",
            params![version.to_be_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| classify_sqlite_authenticated_read_failure_v0(stage, &error))?;
    encoded
        .map(|bytes| {
            <[u8; 32]>::try_from(bytes.as_slice())
                .map(RootHash)
                .map_err(
                    |_| AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                        stage,
                        sqlite: None,
                        reason: "persisted authenticated root is not 32 bytes",
                    },
                )
        })
        .transpose()
}

#[cfg_attr(not(test), allow(dead_code))]
fn load_authenticated_runtime_object_at_v0(
    connection: &Connection,
    height: Version,
    root_hash: RootHash,
    object_key_hex: &str,
) -> std::result::Result<Option<StoredObject>, AuthenticatedRuntimeReadFailureV0> {
    let key = stored_object_key(object_key_hex).map_err(|_| {
        AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage: AuthenticatedRuntimeReadStageV0::DeriveObjectKey,
            sqlite: None,
            reason: "runtime object key is not canonical",
        }
    })?;
    let object = load_authenticated_runtime_object_row_v0(connection, object_key_hex)?;
    let reader = SqliteAuthReader { connection };
    let proof = prove_with_reader(&reader, height, root_hash, key).map_err(|error| {
        classify_authenticated_read_anyhow_v0(
            AuthenticatedRuntimeReadStageV0::BuildProof,
            &error,
            "persisted authenticated proof reconstruction failed",
        )
    })?;
    match &object {
        Some(object) => {
            let expected = AuthenticatedObjectRecord::new(
                object.object_type.clone(),
                object.version,
                object.value_bytes.clone(),
            )
            .and_then(|record| record.encode())
            .map_err(|error| {
                classify_authenticated_read_anyhow_v0(
                    AuthenticatedRuntimeReadStageV0::VerifyObject,
                    &error,
                    "persisted object cannot form its authenticated record",
                )
            })?;
            if proof.value.as_deref() != Some(expected.as_slice())
                || !verify_ics23_membership(&proof, &expected)
            {
                return Err(
                    AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                        stage: AuthenticatedRuntimeReadStageV0::VerifyObject,
                        sqlite: None,
                        reason: "physical object differs from authenticated state",
                    },
                );
            }
        }
        None => {
            if proof.value.is_some() || !verify_ics23_non_membership(&proof) {
                return Err(
                    AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                        stage: AuthenticatedRuntimeReadStageV0::VerifyObject,
                        sqlite: None,
                        reason: "physical object absence differs from authenticated state",
                    },
                );
            }
        }
    }
    Ok(object)
}

fn load_authenticated_validator_lifecycle_at_v0(
    connection: &Connection,
    height: Version,
    root_hash: RootHash,
) -> std::result::Result<ValidatorLifecycleStateV1, AuthenticatedRuntimeReadFailureV0> {
    let lifecycle_key =
        validator_state_key().map_err(|_| AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage: AuthenticatedRuntimeReadStageV0::DeriveObjectKey,
            sqlite: None,
            reason: "validator lifecycle authenticated key cannot be derived",
        })?;
    let reader = SqliteAuthReader { connection };
    let proof = prove_with_reader(&reader, height, root_hash, lifecycle_key).map_err(|error| {
        classify_authenticated_read_anyhow_v0(
            AuthenticatedRuntimeReadStageV0::BuildProof,
            &error,
            "validator lifecycle authenticated proof reconstruction failed",
        )
    })?;
    let authenticated_value = proof.value.as_deref().ok_or(
        AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
            stage: AuthenticatedRuntimeReadStageV0::VerifyObject,
            sqlite: None,
            reason: "authenticated parent state lacks validator lifecycle",
        },
    )?;
    if !verify_ics23_membership(&proof, authenticated_value) {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage: AuthenticatedRuntimeReadStageV0::VerifyObject,
                sqlite: None,
                reason: "validator lifecycle membership does not verify against parent root",
            },
        );
    }
    let record = AuthenticatedObjectRecord::decode(authenticated_value).map_err(|error| {
        classify_authenticated_read_anyhow_v0(
            AuthenticatedRuntimeReadStageV0::VerifyObject,
            &error,
            "authenticated validator lifecycle record is malformed",
        )
    })?;
    if record.object_type != VALIDATOR_LIFECYCLE_SCHEMA_V1 || record.object_version > height {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage: AuthenticatedRuntimeReadStageV0::VerifyObject,
                sqlite: None,
                reason: "authenticated validator lifecycle record metadata is invalid",
            },
        );
    }
    let physical_value: Vec<u8> = connection
        .query_row(
            "SELECT state_json FROM validator_lifecycle WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| {
            classify_sqlite_authenticated_read_failure_v0(
                AuthenticatedRuntimeReadStageV0::ReadObject,
                &error,
            )
        })?;
    if physical_value != record.value {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage: AuthenticatedRuntimeReadStageV0::VerifyObject,
                sqlite: None,
                reason: "physical validator lifecycle differs from authenticated parent state",
            },
        );
    }
    let lifecycle: ValidatorLifecycleStateV1 =
        serde_json::from_slice(&record.value).map_err(|_| {
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage: AuthenticatedRuntimeReadStageV0::VerifyObject,
                sqlite: None,
                reason: "authenticated validator lifecycle JSON is malformed",
            }
        })?;
    lifecycle.validate().map_err(|_| {
        AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
            stage: AuthenticatedRuntimeReadStageV0::VerifyObject,
            sqlite: None,
            reason: "authenticated validator lifecycle is not canonical",
        }
    })?;
    let expected_chain_id = authenticated_runtime_required_metadata_v0(
        connection,
        "chain_id",
        AuthenticatedRuntimeReadStageV0::ValidateBindings,
        "application store is missing chain binding",
    )?;
    let expected_signer_policy = authenticated_runtime_required_metadata_v0(
        connection,
        "authorized_signers_hash_hex",
        AuthenticatedRuntimeReadStageV0::ValidateBindings,
        "application store is missing signer-policy binding",
    )?;
    if lifecycle.chain_id != expected_chain_id
        || lifecycle.app_version != APP_VERSION
        || lifecycle.authorized_signers_hash_hex != expected_signer_policy
    {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                sqlite: None,
                reason: "authenticated validator lifecycle differs from store bindings",
            },
        );
    }
    Ok(lifecycle)
}

#[cfg_attr(not(test), allow(dead_code))]
fn load_authenticated_runtime_object_row_v0(
    connection: &Connection,
    object_key_hex: &str,
) -> std::result::Result<Option<StoredObject>, AuthenticatedRuntimeReadFailureV0> {
    let stage = AuthenticatedRuntimeReadStageV0::ReadObject;
    let raw_object = connection
        .query_row(
            "SELECT object_key_hex, object_type, version, value_hash_hex, value_bytes
             FROM objects
             WHERE object_key_hex=?1",
            params![object_key_hex],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|error| classify_sqlite_authenticated_read_failure_v0(stage, &error))?;
    let Some((object_key_hex_value, object_type, version, value_hash_hex, value_bytes)) =
        raw_object
    else {
        return Ok(None);
    };
    let object = StoredObject {
        object_key_hex: object_key_hex_value,
        object_type,
        version: parse_canonical_decimal_version_v0(
            &version,
            stage,
            "persisted runtime object version is not canonical u64",
        )?,
        value_hash_hex,
        value_bytes,
    };
    if object.object_key_hex != object_key_hex {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: None,
                reason: "persisted object key differs from its physical lookup key",
            },
        );
    }
    if object.value_hash_hex
        != hex::encode(trnm_finality_types::hash_domain(
            "trnm.state.object.value.v1",
            &[&object.value_bytes],
        ))
    {
        return Err(
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                stage,
                sqlite: None,
                reason: "persisted object value hash does not match its bytes",
            },
        );
    }
    Ok(Some(object))
}

fn load_object(connection: &Connection, object_key_hex: &str) -> Result<Option<StoredObject>> {
    let object = connection
        .query_row(
            "SELECT object_key_hex, object_type, version, value_hash_hex, value_bytes
             FROM objects
             WHERE object_key_hex=?1",
            params![object_key_hex],
            |row| {
                Ok(StoredObject {
                    object_key_hex: row.get(0)?,
                    object_type: row.get(1)?,
                    version: row.get::<_, String>(2)?.parse::<u64>().map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                    value_hash_hex: row.get(3)?,
                    value_bytes: row.get(4)?,
                })
            },
        )
        .optional()?;
    object
        .map(|object| validate_object(&object).map(|()| object))
        .transpose()
}

fn validate_object(object: &StoredObject) -> Result<()> {
    ensure!(
        object.value_hash_hex
            == hex::encode(trnm_finality_types::hash_domain(
                "trnm.state.object.value.v1",
                &[&object.value_bytes],
            )),
        "application store object value hash mismatch"
    );
    Ok(())
}

fn latest_auth_version(connection: &Connection) -> Result<Option<Version>> {
    let encoded: Option<Vec<u8>> = connection
        .query_row(
            "SELECT version_be FROM auth_roots ORDER BY version_be DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    encoded.map(|bytes| decode_version_be(&bytes)).transpose()
}

fn oldest_auth_version(connection: &Connection) -> Result<Option<Version>> {
    let encoded: Option<Vec<u8>> = connection
        .query_row(
            "SELECT version_be FROM auth_roots ORDER BY version_be ASC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    encoded.map(|bytes| decode_version_be(&bytes)).transpose()
}

fn auth_root(connection: &Connection, version: Version) -> Result<Option<RootHash>> {
    let encoded: Option<Vec<u8>> = connection
        .query_row(
            "SELECT root_hash FROM auth_roots WHERE version_be=?1",
            params![version.to_be_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    encoded
        .map(|bytes| {
            Ok(RootHash(<[u8; 32]>::try_from(bytes.as_slice()).map_err(
                |_| anyhow!("persisted JMT root hash is not 32 bytes"),
            )?))
        })
        .transpose()
}

fn physical_prune_candidates_remain(connection: &Connection, target: Version) -> Result<bool> {
    let target_be = target.to_be_bytes();
    Ok(connection.query_row(
        "SELECT
             EXISTS(
                 SELECT 1 FROM auth_roots
                 WHERE version_be<?1
             )
             OR EXISTS(
                 SELECT 1 FROM auth_stale_nodes
                 WHERE stale_since_version_be<=?1
             )
             OR EXISTS(
                 SELECT 1 FROM auth_stale_values
                 WHERE stale_since_version_be<=?1
             )",
        params![target_be.as_slice()],
        |row| row.get::<_, bool>(0),
    )?)
}

fn metadata(connection: &Connection, key: &str) -> Result<String> {
    connection
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            params![key],
            |row| row.get(0),
        )
        .with_context(|| format!("application store is missing {key}"))
}

fn optional_metadata_version(connection: &Connection, key: &str) -> Result<Option<Version>> {
    connection
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|value| {
            value
                .parse::<Version>()
                .with_context(|| format!("parse application store {key}"))
        })
        .transpose()
}

fn write_metadata_version(transaction: &Transaction<'_>, key: &str, value: Version) -> Result<()> {
    transaction.execute(
        "INSERT INTO metadata(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value.to_string()],
    )?;
    Ok(())
}

fn validate_auth_prune_metadata(connection: &Connection) -> Result<()> {
    let floor = optional_metadata_version(connection, AUTH_QUERY_FLOOR_KEY)?
        .context("application store is missing authenticated query floor")?;
    let target = optional_metadata_version(connection, AUTH_PRUNE_TARGET_KEY)?;
    if let Some(target) = target {
        ensure!(
            target == floor,
            "authenticated prune target differs from the query floor"
        );
    }
    let height = connection
        .query_row("SELECT value FROM metadata WHERE key='height'", [], |row| {
            row.get::<_, String>(0)
        })
        .optional()?
        .map(|value| {
            value
                .parse::<Version>()
                .context("parse application store height during prune metadata validation")
        })
        .transpose()?;
    match height {
        Some(height) => {
            ensure!(
                floor <= height && auth_root(connection, floor)?.is_some(),
                "application store authenticated query floor is invalid"
            );
            if target.is_none() {
                ensure!(
                    oldest_auth_version(connection)? == Some(floor),
                    "completed authenticated maintenance differs from its query floor"
                );
                ensure!(
                    !physical_prune_candidates_remain(connection, floor)?,
                    "completed authenticated maintenance still has prune candidates"
                );
            }
        }
        None => ensure!(
            floor == 0 && target.is_none(),
            "empty application store contains authenticated maintenance state"
        ),
    }
    Ok(())
}

fn migrate_store_schema_v3_to_v4(connection: &mut Connection) -> Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure!(
        metadata(&transaction, "schema_version")? == LEGACY_STORE_SCHEMA_VERSION,
        "application store schema changed before v3 to v4 migration"
    );
    transaction.execute_batch(
        "
        CREATE UNIQUE INDEX IF NOT EXISTS auth_stale_nodes_by_node_key
            ON auth_stale_nodes(node_key);
        CREATE TABLE IF NOT EXISTS auth_stale_values (
            stale_since_version_be BLOB NOT NULL CHECK(length(stale_since_version_be)=8),
            key_hash BLOB NOT NULL CHECK(length(key_hash)=32),
            version_be BLOB NOT NULL CHECK(length(version_be)=8),
            PRIMARY KEY (stale_since_version_be, key_hash, version_be),
            UNIQUE (key_hash, version_be)
        ) STRICT;
        ",
    )?;
    let encoded: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT version_be FROM auth_roots ORDER BY version_be ASC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let inferred_floor = encoded
        .map(|bytes| decode_version_be(&bytes))
        .transpose()?
        .unwrap_or(0);
    rebuild_auth_stale_values(&transaction)?;
    write_metadata_version(&transaction, AUTH_QUERY_FLOOR_KEY, inferred_floor)?;
    transaction.execute(
        "DELETE FROM metadata WHERE key=?1",
        params![AUTH_PRUNE_TARGET_KEY],
    )?;
    transaction.execute(
        "UPDATE metadata SET value=?1 WHERE key='schema_version'",
        params![PREVIOUS_STORE_SCHEMA_VERSION],
    )?;
    transaction.commit()?;
    Ok(())
}

fn migrate_store_schema_v4_to_v5(connection: &mut Connection) -> Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure!(
        metadata(&transaction, "schema_version")? == PREVIOUS_STORE_SCHEMA_VERSION,
        "application store schema changed before v4 to v5 migration"
    );
    transaction.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS native_validation_reservations (
            route INTEGER NOT NULL CHECK(route IN (0,1)),
            block_id BLOB NOT NULL CHECK(length(block_id)=32),
            view_be BLOB NOT NULL CHECK(length(view_be)=8),
            generation_be BLOB NOT NULL CHECK(length(generation_be)=8),
            target_height_be BLOB NOT NULL CHECK(length(target_height_be)=8),
            parent_block_id BLOB NOT NULL CHECK(length(parent_block_id)=32),
            request_fingerprint BLOB NOT NULL CHECK(length(request_fingerprint)=32),
            PRIMARY KEY(route, block_id, view_be, generation_be),
            UNIQUE(block_id, view_be, generation_be)
        ) STRICT;
        ",
    )?;
    transaction.execute(
        "UPDATE metadata SET value=?1 WHERE key='schema_version'",
        params![STORE_SCHEMA_VERSION],
    )?;
    transaction.commit()?;
    Ok(())
}

fn ensure_metadata_binding(connection: &Connection, key: &str, expected: &str) -> Result<()> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    match actual {
        Some(actual) => ensure!(
            actual == expected,
            "application store {key} differs from configured value"
        ),
        None => {
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES (?1, ?2)",
                params![key, expected],
            )?;
        }
    }
    Ok(())
}

fn validate_snapshot_schema(connection: &Connection) -> Result<()> {
    let schema_version = metadata(connection, "schema_version")?;
    ensure!(
        schema_version == STORE_SCHEMA_VERSION
            || schema_version == PREVIOUS_STORE_SCHEMA_VERSION
            || schema_version == LEGACY_STORE_SCHEMA_VERSION,
        "SQLite snapshot store schema is unsupported"
    );
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch(STORE_SCHEMA_SQL)?;
    if schema_version != STORE_SCHEMA_VERSION {
        canonical.execute_batch("DROP TABLE native_validation_reservations;")?;
    }
    if schema_version == LEGACY_STORE_SCHEMA_VERSION {
        canonical.execute_batch(
            "
            DROP INDEX auth_stale_nodes_by_node_key;
            DROP TABLE auth_stale_values;
            ",
        )?;
    }
    let expected = schema_objects(&canonical)?;
    let actual = schema_objects(connection)?;
    ensure!(
        actual == expected,
        "SQLite snapshot schema differs from the canonical store schema"
    );
    Ok(())
}

fn validate_storage_resource_bounds(connection: &Connection) -> Result<()> {
    for (table, column, maximum) in [
        ("metadata", "key", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        ("metadata", "value", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        ("objects", "object_key_hex", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        ("objects", "object_type", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        ("objects", "version", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        ("objects", "value_hash_hex", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        ("objects", "value_bytes", MAX_SNAPSHOT_OBJECT_VALUE_BYTES),
        ("command_ids", "command_id", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        ("signer_nonces", "signer_id", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        (
            "validator_lifecycle",
            "state_json",
            MAX_SNAPSHOT_LIFECYCLE_BYTES,
        ),
        ("auth_nodes", "node_key", MAX_SNAPSHOT_IDENTIFIER_BYTES),
        ("auth_nodes", "node", MAX_SNAPSHOT_AUTH_NODE_BYTES),
        ("auth_values", "value", MAX_SNAPSHOT_AUTH_VALUE_BYTES),
        (
            "auth_preimages",
            "key_preimage",
            MAX_SNAPSHOT_KEY_PREIMAGE_BYTES,
        ),
        (
            "auth_stale_nodes",
            "node_key",
            MAX_SNAPSHOT_IDENTIFIER_BYTES,
        ),
    ] {
        let query = format!("SELECT COALESCE(MAX(length(CAST({column} AS BLOB))), 0) FROM {table}");
        let observed = connection.query_row(&query, [], |row| row.get::<_, u64>(0))?;
        ensure!(
            observed <= maximum,
            "SQLite store {table}.{column} exceeds the {maximum}-byte resource limit"
        );
    }
    if metadata(connection, "schema_version")? == STORE_SCHEMA_VERSION {
        let reservations = connection.query_row(
            "SELECT COUNT(*) FROM native_validation_reservations",
            [],
            |row| row.get::<_, u64>(0),
        )?;
        ensure!(
            reservations <= MAX_NATIVE_VALIDATION_RESERVATIONS,
            "SQLite store native validation reservations exceed the {MAX_NATIVE_VALIDATION_RESERVATIONS}-row resource limit"
        );
    }
    Ok(())
}

fn schema_objects(
    connection: &Connection,
) -> Result<std::collections::BTreeMap<(String, String), String>> {
    let mut objects = std::collections::BTreeMap::new();
    let mut statement = connection.prepare(
        "SELECT type, name, sql
         FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'
         ORDER BY type, name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    for row in rows {
        let (kind, name, sql) = row?;
        let sql = sql
            .context("SQLite snapshot table is missing CREATE statement")?
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        ensure!(
            objects.insert((kind, name), sql).is_none(),
            "SQLite snapshot contains duplicate schema object"
        );
    }
    Ok(objects)
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("remove stale temporary file {}", path.display()))
        }
    }
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn remove_sqlite_sidecars(path: &Path) -> Result<()> {
    remove_file_if_exists(&sqlite_sidecar(path, "-wal"))?;
    remove_file_if_exists(&sqlite_sidecar(path, "-shm"))
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cold]
fn fail_stop_after_snapshot_install(error: anyhow::Error) -> ! {
    eprintln!(
        "[trnm-cometbft-app] fatal error after authoritative snapshot installation; \
         restart is required before serving ABCI: {error:#}"
    );
    #[cfg(not(test))]
    std::process::abort();
    #[cfg(test)]
    panic!("fatal post-install snapshot error: {error:#}");
}

#[cfg(test)]
mod authenticated_runtime_read_taxonomy_tests {
    use super::*;

    fn sqlite_failure(code: i32) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None)
    }

    #[test]
    fn sqlite_error_codes_have_closed_retry_or_fail_stop_classes() {
        let stage = AuthenticatedRuntimeReadStageV0::ReadObject;
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_BUSY_RECOVERY),
            ),
            AuthenticatedRuntimeReadFailureV0::DatabaseUnavailable {
                sqlite: TypedSqliteReadCodeV0 {
                    code: ErrorCode::DatabaseBusy,
                    extended_code: rusqlite::ffi::SQLITE_BUSY_RECOVERY,
                },
                ..
            }
        ));
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_IOERR_READ),
            ),
            AuthenticatedRuntimeReadFailureV0::StorageUnavailable {
                sqlite: TypedSqliteReadCodeV0 {
                    code: ErrorCode::SystemIoFailure,
                    extended_code: rusqlite::ffi::SQLITE_IOERR_READ,
                },
                ..
            }
        ));
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_IOERR_NOMEM),
            ),
            AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable { .. }
        ));
        for code in [
            rusqlite::ffi::SQLITE_IOERR_DATA,
            rusqlite::ffi::SQLITE_IOERR_IN_PAGE,
        ] {
            assert!(matches!(
                classify_sqlite_authenticated_read_failure_v0(stage, &sqlite_failure(code)),
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    sqlite: Some(TypedSqliteReadCodeV0 {
                        code: ErrorCode::SystemIoFailure,
                        extended_code,
                    }),
                    ..
                } if extended_code == code
            ));
        }
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_IOERR_CORRUPTFS),
            ),
            AuthenticatedRuntimeReadFailureV0::HostInvariant {
                sqlite: Some(TypedSqliteReadCodeV0 {
                    code: ErrorCode::SystemIoFailure,
                    extended_code: rusqlite::ffi::SQLITE_IOERR_CORRUPTFS,
                }),
                ..
            }
        ));
        let unknown_ioerr = rusqlite::ffi::SQLITE_IOERR | (63 << 8);
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(unknown_ioerr),
            ),
            AuthenticatedRuntimeReadFailureV0::HostInvariant {
                sqlite: Some(TypedSqliteReadCodeV0 {
                    code: ErrorCode::SystemIoFailure,
                    extended_code,
                }),
                ..
            } if extended_code == unknown_ioerr
        ));
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_NOMEM),
            ),
            AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable { .. }
        ));
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_CORRUPT),
            ),
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant { .. }
        ));
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_TOOBIG),
            ),
            AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant { .. }
        ));
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_SCHEMA),
            ),
            AuthenticatedRuntimeReadFailureV0::HostInvariant { .. }
        ));
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(
                stage,
                &sqlite_failure(rusqlite::ffi::SQLITE_CONSTRAINT),
            ),
            AuthenticatedRuntimeReadFailureV0::HostInvariant { .. }
        ));
        assert!(matches!(
            classify_sqlite_authenticated_read_failure_v0(stage, &sqlite_failure(0x7f)),
            AuthenticatedRuntimeReadFailureV0::HostInvariant {
                sqlite: Some(TypedSqliteReadCodeV0 {
                    code: ErrorCode::Unknown,
                    extended_code: 0x7f,
                }),
                ..
            }
        ));
    }

    #[test]
    fn fail_stop_rollback_error_outranks_retryable_or_pruned_read_failure() {
        let rollback_fail_stop = AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
            stage: AuthenticatedRuntimeReadStageV0::EndSnapshot,
            sqlite: None,
            reason: "rollback exposed an authenticated-state invariant",
        };
        assert_eq!(
            merge_authenticated_runtime_read_and_rollback_v0::<()>(
                Err(AuthenticatedRuntimeReadFailureV0::Pruned {
                    requested: 4,
                    floor: 5,
                }),
                Err(rollback_fail_stop.clone()),
            ),
            Err(rollback_fail_stop.clone())
        );
        assert_eq!(
            merge_authenticated_runtime_read_and_rollback_v0::<()>(
                Err(AuthenticatedRuntimeReadFailureV0::StorageUnavailable {
                    stage: AuthenticatedRuntimeReadStageV0::ReadObject,
                    sqlite: TypedSqliteReadCodeV0 {
                        code: ErrorCode::SystemIoFailure,
                        extended_code: rusqlite::ffi::SQLITE_IOERR_READ,
                    },
                }),
                Err(rollback_fail_stop.clone()),
            ),
            Err(rollback_fail_stop)
        );

        let rollback_fail_stop = AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage: AuthenticatedRuntimeReadStageV0::EndSnapshot,
            sqlite: None,
            reason: "rollback exposed a host invariant",
        };
        assert_eq!(
            merge_authenticated_runtime_read_and_rollback_v0::<()>(
                Err(AuthenticatedRuntimeReadFailureV0::SourceMismatch {
                    stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    reason: "requested parent is not the committed source",
                }),
                Err(rollback_fail_stop.clone()),
            ),
            Err(rollback_fail_stop)
        );

        let read_fail_stop = AuthenticatedRuntimeReadFailureV0::HostInvariant {
            stage: AuthenticatedRuntimeReadStageV0::BuildProof,
            sqlite: None,
            reason: "primary read exposed a host invariant",
        };
        assert_eq!(
            merge_authenticated_runtime_read_and_rollback_v0::<()>(
                Err(read_fail_stop.clone()),
                Err(AuthenticatedRuntimeReadFailureV0::StorageUnavailable {
                    stage: AuthenticatedRuntimeReadStageV0::EndSnapshot,
                    sqlite: TypedSqliteReadCodeV0 {
                        code: ErrorCode::SystemIoFailure,
                        extended_code: rusqlite::ffi::SQLITE_IOERR_FSYNC,
                    },
                }),
            ),
            Err(read_fail_stop)
        );
    }

    #[test]
    fn typed_runtime_object_api_preserves_cannot_open_as_storage_unavailable() {
        let path = std::env::temp_dir().join(format!(
            "trnm-authenticated-runtime-read-missing-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_nanos()
        ));
        let store = ApplicationStore::open(&path, "typed-read-test", &"00".repeat(32))
            .expect("construct store path");
        assert!(matches!(
            store.load_authenticated_runtime_object_v0("00"),
            Err(AuthenticatedRuntimeReadFailureV0::StorageUnavailable {
                stage: AuthenticatedRuntimeReadStageV0::OpenDatabase,
                sqlite: TypedSqliteReadCodeV0 {
                    code: ErrorCode::CannotOpen,
                    ..
                },
            })
        ));
    }

    fn floor_test_connection() -> Connection {
        let connection = Connection::open_in_memory().expect("open in-memory SQLite");
        connection
            .execute_batch(
                "
                CREATE TABLE metadata (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                ) STRICT;
                CREATE TABLE auth_roots (
                    version_be BLOB PRIMARY KEY NOT NULL CHECK(length(version_be)=8),
                    root_hash BLOB NOT NULL
                ) STRICT;
                ",
            )
            .expect("create floor-test schema");
        connection
    }

    fn authenticated_runtime_snapshot_store() -> (
        PathBuf,
        PathBuf,
        ApplicationStore,
        [u8; 32],
        BTreeMap<String, StoredObject>,
    ) {
        let root = std::env::temp_dir().join(format!(
            "trnm-authenticated-runtime-snapshot-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("create snapshot test directory");
        let status_path = root.join("state.json");
        let signer_policy_hash_hex = "11".repeat(32);
        let store = ApplicationStore::open(
            &status_path,
            "authenticated-runtime-snapshot-test",
            &signer_policy_hash_hex,
        )
        .expect("construct snapshot test store");
        let expected = store
            .load_or_migrate()
            .expect("initialize snapshot test store");
        let objects = [
            ("snapshot-object-a", "alpha", b"alpha-value".as_slice()),
            ("snapshot-object-b", "beta", b"beta-value".as_slice()),
        ]
        .into_iter()
        .map(|(object_key_hex, object_type, value_bytes)| {
            let value_bytes = value_bytes.to_vec();
            let object = StoredObject {
                object_key_hex: object_key_hex.to_string(),
                object_type: object_type.to_string(),
                version: 1,
                value_hash_hex: hex::encode(trnm_finality_types::hash_domain(
                    "trnm.state.object.value.v1",
                    &[&value_bytes],
                )),
                value_bytes,
            };
            (object.object_key_hex.clone(), object)
        })
        .collect::<BTreeMap<_, _>>();
        let writes = objects
            .values()
            .map(|object| {
                let record = AuthenticatedObjectRecord::new(
                    object.object_type.clone(),
                    object.version,
                    object.value_bytes.clone(),
                )
                .and_then(|record| record.encode())
                .expect("encode snapshot test object record");
                AuthWrite::put(
                    stored_object_key(&object.object_key_hex)
                        .expect("derive snapshot test object key"),
                    record,
                )
                .expect("construct snapshot test authenticated write")
            })
            .collect::<Vec<_>>();
        let update = store
            .plan_auth_update(0, writes)
            .expect("plan snapshot test authenticated update");
        let app_hash = <[u8; 32]>::from(update.root_hash);
        let state = AppState {
            objects: objects.clone(),
            app_hash,
            ..AppState::default()
        };
        store
            .replace_empty_state(&expected, &state, &update)
            .expect("persist snapshot test state");
        (root, status_path, store, app_hash, objects)
    }

    #[test]
    fn authenticated_runtime_snapshot_binds_expected_parent_and_same_transaction_bindings() {
        let (root, status_path, store, app_hash, _) = authenticated_runtime_snapshot_store();

        for (height, expected_root) in [(1, app_hash), (0, [9_u8; 32])] {
            assert!(matches!(
                store.begin_authenticated_runtime_read_snapshot_for_test_v0(height, expected_root,),
                Err(AuthenticatedRuntimeReadFailureV0::SourceMismatch {
                    stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    ..
                })
            ));
        }

        let wrong_chain = ApplicationStore::open(
            &status_path,
            "wrong-authenticated-runtime-snapshot-chain",
            &"11".repeat(32),
        )
        .expect("construct wrong-chain snapshot store handle");
        assert!(matches!(
            wrong_chain.begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ValidateBindings,
                    ..
                }
            )
        ));

        {
            let _maintenance = store
                .maintenance_gate
                .lock()
                .expect("lock snapshot test maintenance gate");
            assert!(matches!(
                store.begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash),
                Err(AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable {
                    stage: AuthenticatedRuntimeReadStageV0::BeginSnapshot,
                    ..
                })
            ));
        }

        let connection = store.connect().expect("open future-root writer");
        connection
            .execute(
                "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
                params![1_u64.to_be_bytes().as_slice(), [7_u8; 32].as_slice()],
            )
            .expect("insert orphan future authenticated root");
        drop(connection);
        assert!(matches!(
            store.begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadRoot,
                    ..
                }
            )
        ));
        let connection = store.connect().expect("open future-root cleanup writer");
        connection
            .execute(
                "DELETE FROM auth_roots WHERE version_be=?1",
                params![1_u64.to_be_bytes().as_slice()],
            )
            .expect("remove orphan future authenticated root");
        drop(connection);

        let connection = store.connect().expect("open snapshot test writer");
        connection
            .execute(
                "UPDATE metadata SET value=?1 WHERE key='app_hash_hex'",
                params![hex::encode([8_u8; 32])],
            )
            .expect("corrupt committed app hash");
        drop(connection);
        assert!(matches!(
            store.begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadRoot,
                    ..
                }
            )
        ));

        let connection = store.connect().expect("open noncanonical app-hash writer");
        connection
            .execute(
                "UPDATE metadata SET value=?1 WHERE key='app_hash_hex'",
                params![hex::encode(app_hash).to_uppercase()],
            )
            .expect("write noncanonical committed app hash");
        drop(connection);
        assert!(matches!(
            store.begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadHead,
                    ..
                }
            )
        ));

        let connection = store.connect().expect("open snapshot test repair writer");
        connection
            .execute(
                "UPDATE metadata SET value=?1 WHERE key='app_hash_hex'",
                params![hex::encode(app_hash)],
            )
            .expect("repair committed app hash");
        drop(connection);
        let snapshot = store
            .begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash)
            .expect("begin correctly bound authenticated runtime snapshot");
        snapshot.finish().expect("finish bound snapshot");

        drop(wrong_chain);
        drop(store);
        fs::remove_dir_all(root).expect("remove snapshot test directory");
    }

    #[test]
    fn authenticated_runtime_snapshot_reuses_one_pin_and_preserves_typed_failures() {
        let (root, _, store, app_hash, objects) = authenticated_runtime_snapshot_store();
        let snapshot = store
            .begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash)
            .expect("begin authenticated runtime snapshot");
        assert_eq!(store.active_snapshot_pins.load(Ordering::Acquire), 1);
        for (key, expected) in &objects {
            assert_eq!(
                snapshot
                    .load(key)
                    .expect("load authenticated snapshot object"),
                Some(expected.clone())
            );
        }
        assert_eq!(
            snapshot
                .load("snapshot-object-missing")
                .expect("verify authenticated non-membership"),
            None
        );
        snapshot
            .finish()
            .expect("finish authenticated runtime snapshot");
        assert_eq!(store.active_snapshot_pins.load(Ordering::Acquire), 0);
        let dropped_snapshot = store
            .begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash)
            .expect("begin snapshot for best-effort drop");
        assert_eq!(store.active_snapshot_pins.load(Ordering::Acquire), 1);
        drop(dropped_snapshot);
        assert_eq!(store.active_snapshot_pins.load(Ordering::Acquire), 0);

        let connection = store.connect().expect("open snapshot corruption writer");
        connection
            .execute(
                "UPDATE objects SET value_hash_hex=?1 WHERE object_key_hex='snapshot-object-a'",
                params!["00".repeat(32)],
            )
            .expect("corrupt physical object hash");
        drop(connection);
        let snapshot = store
            .begin_authenticated_runtime_read_snapshot_for_test_v0(0, app_hash)
            .expect("begin snapshot over checksum-consistent head metadata");
        assert!(matches!(
            snapshot.load("snapshot-object-a"),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadObject,
                    ..
                }
            )
        ));
        snapshot.finish().expect("finish corrupted-object snapshot");
        assert_eq!(store.active_snapshot_pins.load(Ordering::Acquire), 0);

        drop(store);
        fs::remove_dir_all(root).expect("remove snapshot test directory");
    }

    #[test]
    fn required_query_floor_never_falls_back_and_pruned_is_typed() {
        let connection = floor_test_connection();
        assert!(matches!(
            require_authenticated_query_floor_v0(&connection, 7, 7),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadQueryFloor,
                    ..
                }
            )
        ));

        connection
            .execute(
                "INSERT INTO metadata(key, value) VALUES (?1, 'seven')",
                rusqlite::params![AUTH_QUERY_FLOOR_KEY],
            )
            .expect("insert malformed floor");
        assert!(matches!(
            require_authenticated_query_floor_v0(&connection, 7, 7),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadQueryFloor,
                    ..
                }
            )
        ));

        connection
            .execute(
                "UPDATE metadata SET value='5' WHERE key=?1",
                rusqlite::params![AUTH_QUERY_FLOOR_KEY],
            )
            .expect("repair floor");
        connection
            .execute(
                "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
                rusqlite::params![5_u64.to_be_bytes().as_slice(), [9_u8; 32].as_slice()],
            )
            .expect("insert floor root");
        assert_eq!(
            require_authenticated_query_floor_v0(&connection, 4, 7),
            Err(AuthenticatedRuntimeReadFailureV0::Pruned {
                requested: 4,
                floor: 5,
            })
        );
        assert!(matches!(
            require_authenticated_query_floor_v0(&connection, 8, 7),
            Err(AuthenticatedRuntimeReadFailureV0::HostResourceUnavailable {
                stage: AuthenticatedRuntimeReadStageV0::ReadQueryFloor,
                ..
            })
        ));
    }

    #[test]
    fn typed_runtime_versions_require_canonical_decimal_u64() {
        let stage = AuthenticatedRuntimeReadStageV0::ReadHead;
        assert_eq!(
            parse_canonical_decimal_version_v0("0", stage, "invalid"),
            Ok(0)
        );
        assert_eq!(
            parse_canonical_decimal_version_v0(&u64::MAX.to_string(), stage, "invalid",),
            Ok(u64::MAX)
        );
        for value in [
            "",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "00",
            "18446744073709551616",
        ] {
            assert!(matches!(
                parse_canonical_decimal_version_v0(value, stage, "invalid"),
                Err(
                    AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                        stage: AuthenticatedRuntimeReadStageV0::ReadHead,
                        ..
                    }
                )
            ));
        }

        let connection = floor_test_connection();
        connection
            .execute(
                "INSERT INTO metadata(key, value) VALUES ('height', '01')",
                [],
            )
            .expect("insert noncanonical head");
        assert!(matches!(
            authenticated_runtime_head_v0(&connection),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadHead,
                    ..
                }
            )
        ));
        connection
            .execute("UPDATE metadata SET value='1' WHERE key='height'", [])
            .expect("repair head");
        connection
            .execute(
                "INSERT INTO metadata(key, value) VALUES (?1, '01')",
                rusqlite::params![AUTH_QUERY_FLOOR_KEY],
            )
            .expect("insert noncanonical floor");
        assert!(matches!(
            require_authenticated_query_floor_v0(&connection, 1, 1),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadQueryFloor,
                    ..
                }
            )
        ));
        connection
            .execute(
                "UPDATE metadata SET value='1' WHERE key=?1",
                rusqlite::params![AUTH_QUERY_FLOOR_KEY],
            )
            .expect("repair floor");
        connection
            .execute(
                "INSERT INTO metadata(key, value) VALUES (?1, '+1')",
                rusqlite::params![AUTH_PRUNE_TARGET_KEY],
            )
            .expect("insert noncanonical prune target");
        connection
            .execute(
                "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
                rusqlite::params![1_u64.to_be_bytes().as_slice(), [7_u8; 32].as_slice()],
            )
            .expect("insert floor root");
        assert!(matches!(
            require_authenticated_query_floor_v0(&connection, 1, 1),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadQueryFloor,
                    ..
                }
            )
        ));

        connection
            .execute_batch(
                "
                CREATE TABLE objects (
                    object_key_hex TEXT PRIMARY KEY NOT NULL,
                    object_type TEXT NOT NULL,
                    version TEXT NOT NULL,
                    value_hash_hex TEXT NOT NULL,
                    value_bytes BLOB NOT NULL
                ) STRICT;
                ",
            )
            .expect("create object table");
        let value_bytes = [1_u8, 2];
        let value_hash_hex = hex::encode(trnm_finality_types::hash_domain(
            "trnm.state.object.value.v1",
            &[&value_bytes],
        ));
        connection
            .execute(
                "INSERT INTO objects(
                    object_key_hex, object_type, version, value_hash_hex, value_bytes
                 ) VALUES ('aa', 'test-v0', '01', ?1, ?2)",
                rusqlite::params![value_hash_hex, value_bytes.as_slice()],
            )
            .expect("insert noncanonical object version");
        assert!(matches!(
            load_authenticated_runtime_object_row_v0(&connection, "aa"),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadObject,
                    ..
                }
            )
        ));
    }

    #[test]
    fn checksum_consistent_root_and_object_corruption_remain_fail_stop() {
        let connection = floor_test_connection();
        connection
            .execute_batch(
                "
                CREATE TABLE objects (
                    object_key_hex TEXT PRIMARY KEY NOT NULL,
                    object_type TEXT NOT NULL,
                    version TEXT NOT NULL,
                    value_hash_hex TEXT NOT NULL,
                    value_bytes BLOB NOT NULL
                ) STRICT;
                ",
            )
            .expect("create object table");
        connection
            .execute(
                "INSERT INTO auth_roots(version_be, root_hash) VALUES (?1, ?2)",
                rusqlite::params![3_u64.to_be_bytes().as_slice(), [1_u8; 31].as_slice()],
            )
            .expect("insert malformed root");
        assert!(matches!(
            authenticated_runtime_root_v0(&connection, 3),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadRoot,
                    ..
                }
            )
        ));

        connection
            .execute(
                "INSERT INTO objects(
                    object_key_hex, object_type, version, value_hash_hex, value_bytes
                 ) VALUES ('aa', 'test-v0', '1', ?1, X'0102')",
                rusqlite::params!["00".repeat(32)],
            )
            .expect("insert inconsistent object");
        assert!(matches!(
            load_authenticated_runtime_object_row_v0(&connection, "aa"),
            Err(
                AuthenticatedRuntimeReadFailureV0::AuthenticatedStateInvariant {
                    stage: AuthenticatedRuntimeReadStageV0::ReadObject,
                    ..
                }
            )
        ));
    }
}

#[cfg(test)]
mod native_validation_reservation_tests {
    use std::{
        fs,
        path::PathBuf,
        sync::{Arc, Barrier},
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    use trnm_consensus_core::{PayloadValidationRouteV0, ValidationId};
    use trnm_consensus_types::{BlockId, View};

    use super::{
        metadata, migrate_store_schema_v4_to_v5, validate_snapshot_schema, ApplicationStore,
        NativeValidationReservationDecisionV0, NativeValidationReservationFactsV0,
        NativeValidationReservationFailureCauseV0, NativeValidationReservationInvariantV0,
        PREVIOUS_STORE_SCHEMA_VERSION, STORE_SCHEMA_VERSION,
    };

    fn test_store(label: &str) -> (PathBuf, ApplicationStore) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "trnm-native-validation-reservation-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create reservation test directory");
        let store = ApplicationStore::open(
            &root.join("app.status"),
            "reservation-test-chain",
            &"11".repeat(32),
        )
        .expect("construct reservation test store");
        store
            .load_or_migrate()
            .expect("initialize reservation test store");
        (root, store)
    }

    fn facts(
        route: PayloadValidationRouteV0,
        generation: u64,
        parent: u8,
        fingerprint: u8,
    ) -> NativeValidationReservationFactsV0 {
        NativeValidationReservationFactsV0::new(
            route,
            ValidationId::new(BlockId::new([7; 32]), View::new(9), generation),
            12,
            [parent; 32],
            [fingerprint; 32],
        )
    }

    #[test]
    fn durable_reservation_is_unique_and_exact_duplicate_only_coalesces() {
        let (root, store) = test_store("coalesce");
        let expected_id = ValidationId::new(BlockId::new([7; 32]), View::new(9), 3);
        let first = match store.reserve_native_validation_v0(facts(
            PayloadValidationRouteV0::Proposal,
            3,
            8,
            9,
        )) {
            Ok(decision) => decision,
            Err(_) => panic!("reserve exact validation identity"),
        };
        let NativeValidationReservationDecisionV0::Reserved(token) = first else {
            panic!("first reservation must own evaluation admission");
        };
        assert_eq!(token.route(), PayloadValidationRouteV0::Proposal);
        assert_eq!(token.validation_id(), expected_id);

        let duplicate = match store.reserve_native_validation_v0(facts(
            PayloadValidationRouteV0::Proposal,
            3,
            8,
            9,
        )) {
            Ok(decision) => decision,
            Err(_) => panic!("coalesce exact duplicate"),
        };
        let NativeValidationReservationDecisionV0::Coalesced(coalesced) = duplicate else {
            panic!("exact duplicate must not regain evaluation admission");
        };
        assert_eq!(coalesced.route(), PayloadValidationRouteV0::Proposal);
        assert_eq!(coalesced.validation_id(), expected_id);

        let connection = store.connect().expect("open reservation test database");
        let count = connection
            .query_row(
                "SELECT COUNT(*) FROM native_validation_reservations",
                [],
                |row| row.get::<_, u64>(0),
            )
            .expect("count durable reservations");
        assert_eq!(count, 1);
        drop(connection);
        fs::remove_dir_all(root).expect("remove reservation test directory");
    }

    #[test]
    fn durable_reservation_is_unique_across_independent_stores_and_reopen() {
        const WORKER_COUNT: usize = 8;

        let (root, initialized_store) = test_store("independent-stores");
        let status_path = root.join("app.status");
        drop(initialized_store);

        let stores = (0..WORKER_COUNT)
            .map(|_| {
                let store = ApplicationStore::open(
                    &status_path,
                    "reservation-test-chain",
                    &"11".repeat(32),
                )
                .expect("open independent reservation test store");
                store
                    .load_or_migrate()
                    .expect("load independent reservation test store");
                store
            })
            .collect::<Vec<_>>();
        let barrier = Arc::new(Barrier::new(WORKER_COUNT));
        let workers = stores
            .into_iter()
            .map(|store| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    let reserved = match store.reserve_native_validation_v0(facts(
                        PayloadValidationRouteV0::Proposal,
                        5,
                        8,
                        9,
                    )) {
                        Ok(NativeValidationReservationDecisionV0::Reserved(_)) => true,
                        Ok(NativeValidationReservationDecisionV0::Coalesced(_)) => false,
                        Err(_) => panic!("reserve from independent application store"),
                    };
                    drop(store);
                    reserved
                })
            })
            .collect::<Vec<_>>();

        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().expect("join reservation worker"))
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes.iter().filter(|reserved| **reserved).count(),
            1,
            "exactly one independent ApplicationStore must own evaluation admission"
        );
        assert_eq!(
            outcomes.iter().filter(|reserved| !**reserved).count(),
            WORKER_COUNT - 1,
            "all other independent ApplicationStore instances must coalesce"
        );

        let reopened =
            ApplicationStore::open(&status_path, "reservation-test-chain", &"11".repeat(32))
                .expect("reopen reservation test store");
        reopened
            .load_or_migrate()
            .expect("load reopened reservation test store");
        let repeated = match reopened.reserve_native_validation_v0(facts(
            PayloadValidationRouteV0::Proposal,
            5,
            8,
            9,
        )) {
            Ok(decision) => decision,
            Err(_) => panic!("coalesce reservation after store reopen"),
        };
        let NativeValidationReservationDecisionV0::Coalesced(coalesced) = repeated else {
            panic!("reopening the store must not regain evaluation admission");
        };
        assert_eq!(coalesced.route(), PayloadValidationRouteV0::Proposal);
        assert_eq!(
            coalesced.validation_id(),
            ValidationId::new(BlockId::new([7; 32]), View::new(9), 5)
        );

        let connection = reopened
            .connect()
            .expect("open reopened reservation test database");
        let count = connection
            .query_row(
                "SELECT COUNT(*) FROM native_validation_reservations",
                [],
                |row| row.get::<_, u64>(0),
            )
            .expect("count durable reservations after reopen");
        assert_eq!(count, 1);
        drop(connection);
        drop(reopened);
        fs::remove_dir_all(root).expect("remove independent reservation test directory");
    }

    #[test]
    fn durable_reservation_exact_duplicate_coalesces_at_capacity() {
        let (root, store) = test_store("capacity-coalesce");
        let mut connection = store.connect().expect("open capacity test database");
        let transaction = connection.transaction().expect("begin capacity fixture");
        {
            let mut insert = transaction
                .prepare(
                    "INSERT INTO native_validation_reservations(
                         route, block_id, view_be, generation_be, target_height_be,
                         parent_block_id, request_fingerprint
                     ) VALUES (0, ?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .expect("prepare capacity fixture insert");
            for generation in 0..super::MAX_NATIVE_VALIDATION_RESERVATIONS {
                insert
                    .execute(rusqlite::params![
                        [7_u8; 32].as_slice(),
                        9_u64.to_be_bytes().as_slice(),
                        generation.to_be_bytes().as_slice(),
                        12_u64.to_be_bytes().as_slice(),
                        [8_u8; 32].as_slice(),
                        [9_u8; 32].as_slice(),
                    ])
                    .expect("insert capacity fixture row");
            }
        }
        transaction.commit().expect("commit capacity fixture");
        drop(connection);

        let duplicate = match store.reserve_native_validation_v0(facts(
            PayloadValidationRouteV0::Proposal,
            3,
            8,
            9,
        )) {
            Ok(decision) => decision,
            Err(_) => panic!("exact duplicate at capacity must coalesce"),
        };
        assert!(matches!(
            duplicate,
            NativeValidationReservationDecisionV0::Coalesced(_)
        ));

        let failure = match store.reserve_native_validation_v0(facts(
            PayloadValidationRouteV0::Proposal,
            super::MAX_NATIVE_VALIDATION_RESERVATIONS,
            8,
            9,
        )) {
            Ok(_) => panic!("new reservation above capacity unexpectedly succeeded"),
            Err(failure) => failure,
        };
        assert!(matches!(
            failure.cause(),
            NativeValidationReservationFailureCauseV0::Capacity { maximum }
                if *maximum == super::MAX_NATIVE_VALIDATION_RESERVATIONS
        ));

        drop(store);
        fs::remove_dir_all(root).expect("remove capacity test directory");
    }

    #[test]
    fn durable_reservation_rejects_route_parent_and_fingerprint_splices() {
        let (root, store) = test_store("splices");
        match store.reserve_native_validation_v0(facts(PayloadValidationRouteV0::Proposal, 4, 8, 9))
        {
            Ok(NativeValidationReservationDecisionV0::Reserved(_)) => {}
            Ok(NativeValidationReservationDecisionV0::Coalesced(_)) | Err(_) => {
                panic!("reserve baseline validation identity")
            }
        }

        for (candidate, expected) in [
            (
                facts(PayloadValidationRouteV0::Synced, 4, 8, 9),
                NativeValidationReservationInvariantV0::RouteMismatch,
            ),
            (
                facts(PayloadValidationRouteV0::Proposal, 4, 10, 9),
                NativeValidationReservationInvariantV0::ParentBlockIdMismatch,
            ),
            (
                facts(PayloadValidationRouteV0::Proposal, 4, 8, 11),
                NativeValidationReservationInvariantV0::RequestFingerprintMismatch,
            ),
        ] {
            let failure = match store.reserve_native_validation_v0(candidate) {
                Ok(_) => panic!("spliced reservation unexpectedly succeeded"),
                Err(failure) => failure,
            };
            assert!(matches!(
                failure.cause(),
                NativeValidationReservationFailureCauseV0::Invariant { kind, .. }
                    if *kind == expected
            ));
        }
        fs::remove_dir_all(root).expect("remove reservation splice test directory");
    }

    #[test]
    fn durable_reservation_binding_failure_is_zero_write() {
        let (root, store) = test_store("binding-zero-write");
        let connection = store.connect().expect("open binding test database");
        connection
            .execute(
                "UPDATE metadata SET value='foreign-chain' WHERE key='chain_id'",
                [],
            )
            .expect("corrupt reservation binding fixture");
        drop(connection);

        let failure = match store.reserve_native_validation_v0(facts(
            PayloadValidationRouteV0::Proposal,
            6,
            8,
            9,
        )) {
            Ok(_) => panic!("binding-mismatched reservation unexpectedly succeeded"),
            Err(failure) => failure,
        };
        assert!(matches!(
            failure.cause(),
            NativeValidationReservationFailureCauseV0::HostInvariant {
                stage: super::NativeValidationReservationStageV0::ValidateBindings,
                ..
            }
        ));
        let connection = rusqlite::Connection::open(&store.database_path)
            .expect("reopen binding test database without revalidating the corrupted fixture");
        let count = connection
            .query_row(
                "SELECT COUNT(*) FROM native_validation_reservations",
                [],
                |row| row.get::<_, u64>(0),
            )
            .expect("count reservations after binding failure");
        assert_eq!(count, 0);
        drop(connection);
        drop(store);
        fs::remove_dir_all(root).expect("remove binding test directory");
    }

    #[test]
    fn schema_v4_migrates_to_empty_schema_v5_reservation_table() {
        let (root, store) = test_store("migration");
        let mut connection = store.connect().expect("open migration test database");
        connection
            .execute_batch("DROP TABLE native_validation_reservations;")
            .expect("remove schema v5 reservation table");
        connection
            .execute(
                "UPDATE metadata SET value=?1 WHERE key='schema_version'",
                rusqlite::params![PREVIOUS_STORE_SCHEMA_VERSION],
            )
            .expect("downgrade migration fixture to schema v4");
        validate_snapshot_schema(&connection).expect("validate canonical schema v4 fixture");
        migrate_store_schema_v4_to_v5(&mut connection).expect("migrate schema v4 to v5");
        assert_eq!(
            metadata(&connection, "schema_version").expect("read migrated schema version"),
            STORE_SCHEMA_VERSION
        );
        let count = connection
            .query_row(
                "SELECT COUNT(*) FROM native_validation_reservations",
                [],
                |row| row.get::<_, u64>(0),
            )
            .expect("count migrated reservation rows");
        assert_eq!(count, 0);
        drop(connection);
        fs::remove_dir_all(root).expect("remove reservation migration test directory");
    }
}
