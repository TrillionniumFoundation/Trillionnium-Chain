//! Candidate-only Node admission for one verified PoCO v1 cross-plane cut.
//!
//! The flow is deliberately private and inert:
//! 1. verify raw Order proof bytes against an independently pinned trust digest;
//! 2. consume one already-confirmed G2F projection;
//! 3. reopen/rejoin all five stores and require byte-exact projection equality;
//! 4. advance a distinct checkpoint namespace by exactly one successor;
//! 5. perform a mandatory fresh read and mint a non-Clone carrier only for the
//!    exact target.
//!
//! The Order verifier now exposes the exact draft-v1 256-level sparse-tree
//! membership kernel. The admission path consumes that proof before any CAS,
//! but still fails closed because this generic projection path does not invoke
//! the dedicated tag-50 value/ancestry verifier and has no terminal owner or
//! authoritative Order-state writer. A bare projection digest or a proof for
//! another typed object is never accepted as a substitute. The Order proof and
//! stable local projection remain non-authoritative parallel observations, so
//! this tranche closes no global G2 authority or proof-to-state substitution
//! boundary.
//!
//! It mutates only the independent checkpoint database. It does not lock or
//! atomically commit the five source stores, does not provide anti-whole-store
//! rollback authority, and cannot acknowledge Core, settle, sign, or broadcast.

use std::{
    error::Error,
    ffi::OsString,
    fmt,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::{
    fs::{File, Metadata},
    io::Read,
};

use borsh::{to_vec, BorshDeserialize};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use trnm_poco_cross_plane_readback_v1::{
    fresh_join_cross_plane_v1, ConfirmedCrossPlaneReadbackV1, CrossPlaneJoinRequestV1,
    CrossPlaneReadbackProjectionV1, CrossPlaneStoresV1,
};
use trnm_poco_order_finality_verifier_v1::{
    verify_bounded_application_state_membership_v1, verify_pinned_fresh_genesis_order_finality_v1,
    BoundedApplicationStateMembershipV1, OrderFinalityVerifyErrorV1,
    VerifiedApplicationStateMembershipV1, VerifiedOrderFinalityV1,
};

const CHECKPOINT_SCHEMA_V1: u16 = 1;
const CHECKPOINT_MAGIC_V1: [u8; 8] = *b"TRNMCPV1";
const CHECKPOINT_DOMAIN_V1: &[u8] = b"trnm.poco-ai.node-cross-plane-checkpoint.candidate.v1";
const SQLITE_APPLICATION_ID_V1: i64 = 0x5452_4350;
const SQLITE_SCHEMA_VERSION_V1: i64 = 1;
const MAX_CHECKPOINT_RECORD_BYTES_V1: usize = 16 * 1024;
const MAX_CHECKPOINT_DATABASE_BYTES_V1: u64 = 64 * 1024 * 1024;
const SQLITE_CREATE_V1: &str = concat!(
    "CREATE TABLE trnm_poco_cross_plane_checkpoint_v1 (",
    "scope BLOB NOT NULL PRIMARY KEY CHECK(typeof(scope)='blob' AND length(scope)=32),",
    "generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=8),",
    "checkpoint_checksum BLOB NOT NULL CHECK(typeof(checkpoint_checksum)='blob' AND length(checkpoint_checksum)=32),",
    "record BLOB NOT NULL CHECK(typeof(record)='blob' AND length(record)>0 AND length(record)<=16384)",
    ") STRICT, WITHOUT ROWID"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrossPlaneCheckpointErrorCodeV1 {
    OrderProofRejected,
    CrossPlaneReadbackRejected,
    ContextMismatch,
    OrderMismatch,
    StateMembershipRejected,
    ProjectionStateObjectUndefined,
    ProjectionChanged,
    InvalidCheckpoint,
    ExpectedCheckpointMismatch,
    CompareNotApplied,
    ThirdCheckpointState,
    CheckpointUnavailable,
}

#[derive(Debug)]
pub(crate) struct CrossPlaneCheckpointErrorV1 {
    code: CrossPlaneCheckpointErrorCodeV1,
    detail: &'static str,
}

impl CrossPlaneCheckpointErrorV1 {
    pub(crate) const fn code_v1(&self) -> CrossPlaneCheckpointErrorCodeV1 {
        self.code
    }
}

impl fmt::Display for CrossPlaneCheckpointErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "cross-plane checkpoint rejected: {}",
            self.detail
        )
    }
}

impl Error for CrossPlaneCheckpointErrorV1 {}

type ResultV1<T> = Result<T, CrossPlaneCheckpointErrorV1>;

fn reject<T>(code: CrossPlaneCheckpointErrorCodeV1, detail: &'static str) -> ResultV1<T> {
    Err(CrossPlaneCheckpointErrorV1 { code, detail })
}

fn require(
    condition: bool,
    code: CrossPlaneCheckpointErrorCodeV1,
    detail: &'static str,
) -> ResultV1<()> {
    if condition {
        Ok(())
    } else {
        reject(code, detail)
    }
}

/// Canonical value in the separate v1 checkpoint CAS namespace.
///
/// It is data only. Decoding this value cannot recreate either the verified
/// Order-proof capability or [`VerifiedCrossPlaneCheckpointV1`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CrossPlaneCheckpointValueV1 {
    scope: [u8; 32],
    generation: u64,
    predecessor_checksum: [u8; 32],
    pinned_trust_sha256: [u8; 32],
    order_proof_id: [u8; 32],
    // Parallel finalized-Order fact only. No membership proof binds the local
    // five-store projection beneath this root in the candidate tranche.
    finalized_post_state_root: [u8; 32],
    projection: CrossPlaneReadbackProjectionV1,
    checksum: [u8; 32],
}

impl CrossPlaneCheckpointValueV1 {
    fn successor(
        predecessor: &Self,
        order: &VerifiedOrderFinalityV1,
        projection: CrossPlaneReadbackProjectionV1,
    ) -> ResultV1<Self> {
        require(
            predecessor.pinned_trust_sha256 == order.pinned_trust_sha256(),
            CrossPlaneCheckpointErrorCodeV1::ExpectedCheckpointMismatch,
            "Order trust pin differs from the checkpoint lineage",
        )?;
        require(
            projection.order_height > predecessor.projection.order_height,
            CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
            "Order height must strictly advance",
        )?;
        validate_stable_store_successors(&predecessor.projection, &projection)?;
        let generation =
            predecessor
                .generation
                .checked_add(1)
                .ok_or(CrossPlaneCheckpointErrorV1 {
                    code: CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
                    detail: "checkpoint generation overflows",
                })?;
        let mut value = Self {
            scope: predecessor.scope,
            generation,
            predecessor_checksum: predecessor.checksum,
            pinned_trust_sha256: order.pinned_trust_sha256(),
            order_proof_id: order.proof_id(),
            finalized_post_state_root: order.finalized_post_state_root(),
            projection,
            checksum: [0; 32],
        };
        value.checksum = checkpoint_checksum(&value.encode_prefix()?);
        Ok(value)
    }

    #[cfg(test)]
    fn test_anchor(
        scope: [u8; 32],
        order: &VerifiedOrderFinalityV1,
        projection: CrossPlaneReadbackProjectionV1,
    ) -> ResultV1<Self> {
        let mut value = Self {
            scope,
            generation: 0,
            predecessor_checksum: [0; 32],
            pinned_trust_sha256: order.pinned_trust_sha256(),
            order_proof_id: projection.order_proof_digest.0,
            finalized_post_state_root: [2; 32],
            projection,
            checksum: [0; 32],
        };
        value.checksum = checkpoint_checksum(&value.encode_prefix()?);
        Ok(value)
    }

    fn encode_prefix(&self) -> ResultV1<Vec<u8>> {
        let projection = to_vec(&self.projection).map_err(|_| CrossPlaneCheckpointErrorV1 {
            code: CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
            detail: "cross-plane projection cannot be canonically encoded",
        })?;
        let mut out = Vec::with_capacity(220 + projection.len());
        out.extend_from_slice(&CHECKPOINT_MAGIC_V1);
        out.extend_from_slice(&CHECKPOINT_SCHEMA_V1.to_le_bytes());
        out.extend_from_slice(&self.scope);
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&self.predecessor_checksum);
        out.extend_from_slice(&self.pinned_trust_sha256);
        out.extend_from_slice(&self.order_proof_id);
        out.extend_from_slice(&self.finalized_post_state_root);
        out.extend_from_slice(
            &u32::try_from(projection.len())
                .map_err(|_| CrossPlaneCheckpointErrorV1 {
                    code: CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
                    detail: "cross-plane projection exceeds u32",
                })?
                .to_le_bytes(),
        );
        out.extend_from_slice(&projection);
        require(
            out.len() + 32 <= MAX_CHECKPOINT_RECORD_BYTES_V1,
            CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
            "checkpoint record exceeds bounded size",
        )?;
        Ok(out)
    }

    fn encode(&self) -> ResultV1<Vec<u8>> {
        let mut value = self.encode_prefix()?;
        value.extend_from_slice(&self.checksum);
        Ok(value)
    }

    fn decode_exact(raw: &[u8]) -> ResultV1<Self> {
        require(
            raw.len() <= MAX_CHECKPOINT_RECORD_BYTES_V1 && raw.len() >= 214,
            CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
            "checkpoint record length differs",
        )?;
        let mut cursor = RecordCursorV1::new(raw);
        require(
            cursor.array::<8>()? == CHECKPOINT_MAGIC_V1,
            CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
            "checkpoint magic differs",
        )?;
        require(
            cursor.u16()? == CHECKPOINT_SCHEMA_V1,
            CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
            "checkpoint schema differs",
        )?;
        let scope = cursor.array()?;
        let generation = cursor.u64()?;
        let predecessor_checksum = cursor.array()?;
        let pinned_trust_sha256 = cursor.array()?;
        let order_proof_id = cursor.array()?;
        let finalized_post_state_root = cursor.array()?;
        let projection_length =
            usize::try_from(cursor.u32()?).map_err(|_| CrossPlaneCheckpointErrorV1 {
                code: CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
                detail: "projection length cannot fit usize",
            })?;
        let projection_raw = cursor.take(projection_length)?;
        let projection =
            CrossPlaneReadbackProjectionV1::try_from_slice(projection_raw).map_err(|_| {
                CrossPlaneCheckpointErrorV1 {
                    code: CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
                    detail: "checkpoint projection does not strictly decode",
                }
            })?;
        require(
            to_vec(&projection).ok().as_deref() == Some(projection_raw),
            CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
            "checkpoint projection is not canonical",
        )?;
        let checksum = cursor.array()?;
        require(
            cursor.remaining() == 0,
            CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
            "checkpoint has trailing bytes",
        )?;
        let value = Self {
            scope,
            generation,
            predecessor_checksum,
            pinned_trust_sha256,
            order_proof_id,
            finalized_post_state_root,
            projection,
            checksum,
        };
        require(
            checkpoint_checksum(&value.encode_prefix()?) == checksum,
            CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
            "checkpoint checksum differs",
        )?;
        require(
            value.scope != [0; 32]
                && value.pinned_trust_sha256 != [0; 32]
                && value.order_proof_id != [0; 32]
                && value.projection.projection_digest.0 != [0; 32],
            CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
            "checkpoint contains a zero authority/reference field",
        )?;
        Ok(value)
    }

    const fn scope(&self) -> [u8; 32] {
        self.scope
    }

    const fn generation(&self) -> u64 {
        self.generation
    }

    const fn checksum(&self) -> [u8; 32] {
        self.checksum
    }
}

/// Exact target readback after successor CAS.
///
/// This capability remains crate-private, has no constructor or decoder, and
/// intentionally implements neither `Clone` nor `Copy`.
#[derive(Debug)]
pub(crate) struct VerifiedCrossPlaneCheckpointV1 {
    checkpoint: CrossPlaneCheckpointValueV1,
}

impl VerifiedCrossPlaneCheckpointV1 {
    pub(crate) const fn checkpoint_v1(&self) -> &CrossPlaneCheckpointValueV1 {
        &self.checkpoint
    }
}

pub(crate) trait CrossPlaneCheckpointStoreV1 {
    fn fresh_load_v1(&mut self, scope: [u8; 32]) -> ResultV1<Option<CrossPlaneCheckpointValueV1>>;

    fn compare_and_advance_v1(
        &mut self,
        expected: &CrossPlaneCheckpointValueV1,
        target: &CrossPlaneCheckpointValueV1,
    ) -> ResultV1<()>;
}

/// Dedicated SQLite namespace used only by this candidate checkpoint.
///
/// No public or crate-visible constructor is supplied. The module is private
/// and the Node runtime does not instantiate this backend in this tranche.
struct SqliteCrossPlaneCheckpointStoreV1 {
    path: PathBuf,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckpointFileStatV1 {
    device: u64,
    inode: u64,
    owner: u32,
    links: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckpointFileIdentityV1 {
    stat: CheckpointFileStatV1,
    content_sha256: [u8; 32],
}

impl SqliteCrossPlaneCheckpointStoreV1 {
    #[allow(dead_code)]
    fn initialize_new(path: impl AsRef<Path>) -> ResultV1<Self> {
        let path = validate_checkpoint_path(path.as_ref(), false)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| unavailable("cannot create checkpoint database"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|_| unavailable("cannot set checkpoint permissions"))?;
        }
        drop(file);
        let connection = open_rw(&path)?;
        configure_connection(&connection)?;
        connection
            .pragma_update(None, "application_id", SQLITE_APPLICATION_ID_V1)
            .map_err(|_| unavailable("cannot set checkpoint application id"))?;
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION_V1)
            .map_err(|_| unavailable("cannot set checkpoint schema version"))?;
        connection
            .execute(SQLITE_CREATE_V1, [])
            .map_err(|_| unavailable("cannot create checkpoint schema"))?;
        validate_schema(&connection)?;
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|_| unavailable("cannot finalize checkpoint initialization"))?;
        drop(connection);
        reject_sidecars(&path)?;
        Ok(Self { path })
    }

    #[allow(dead_code)]
    fn open_existing(path: impl AsRef<Path>) -> ResultV1<Self> {
        let path = validate_checkpoint_path(path.as_ref(), true)?;
        let (connection, identity) = open_existing_ro_preflight(&path)?;
        drop(connection);
        reject_sidecars(&path)?;
        require_checkpoint_file_identity(&path, identity)?;
        Ok(Self { path })
    }

    #[cfg(test)]
    fn seed_test_anchor(&mut self, anchor: &CrossPlaneCheckpointValueV1) -> ResultV1<()> {
        let connection = open_existing_rw_after_immutable_preflight(&self.path)?;
        connection
            .execute(
                "INSERT INTO trnm_poco_cross_plane_checkpoint_v1 \
                 (scope, generation, checkpoint_checksum, record) VALUES (?1, ?2, ?3, ?4)",
                params![
                    &anchor.scope[..],
                    &anchor.generation.to_be_bytes()[..],
                    &anchor.checksum[..],
                    anchor.encode()?,
                ],
            )
            .map_err(|_| unavailable("cannot seed test checkpoint"))?;
        Ok(())
    }
}

impl CrossPlaneCheckpointStoreV1 for SqliteCrossPlaneCheckpointStoreV1 {
    fn fresh_load_v1(&mut self, scope: [u8; 32]) -> ResultV1<Option<CrossPlaneCheckpointValueV1>> {
        let (connection, identity) = open_existing_ro_preflight(&self.path)?;
        let raw: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT generation, checkpoint_checksum, record \
                 FROM trnm_poco_cross_plane_checkpoint_v1 WHERE scope=?1",
                params![&scope[..]],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| unavailable("cannot fresh-read checkpoint"))?;
        drop(connection);
        reject_sidecars(&self.path)?;
        require_checkpoint_file_identity(&self.path, identity)?;
        raw.map(|(generation, checksum, record)| {
            let value = CrossPlaneCheckpointValueV1::decode_exact(&record)?;
            require(
                generation == value.generation.to_be_bytes() && checksum == value.checksum,
                CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
                "checkpoint row metadata differs from canonical record",
            )?;
            Ok(value)
        })
        .transpose()
    }

    fn compare_and_advance_v1(
        &mut self,
        expected: &CrossPlaneCheckpointValueV1,
        target: &CrossPlaneCheckpointValueV1,
    ) -> ResultV1<()> {
        require(
            target.scope == expected.scope
                && expected.generation.checked_add(1) == Some(target.generation)
                && target.predecessor_checksum == expected.checksum,
            CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
            "checkpoint CAS target is not the exact successor",
        )?;
        let mut connection = open_existing_rw_after_immutable_preflight(&self.path)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable("cannot start checkpoint CAS"))?;
        let changed = transaction
            .execute(
                "UPDATE trnm_poco_cross_plane_checkpoint_v1 \
                 SET generation=?1, checkpoint_checksum=?2, record=?3 \
                 WHERE scope=?4 AND generation=?5 AND checkpoint_checksum=?6 AND record=?7",
                params![
                    &target.generation.to_be_bytes()[..],
                    &target.checksum[..],
                    target.encode()?,
                    &expected.scope[..],
                    &expected.generation.to_be_bytes()[..],
                    &expected.checksum[..],
                    expected.encode()?,
                ],
            )
            .map_err(|_| unavailable("checkpoint CAS update failed"))?;
        require(
            changed == 1,
            CrossPlaneCheckpointErrorCodeV1::ExpectedCheckpointMismatch,
            "checkpoint CAS source differs",
        )?;
        transaction
            .commit()
            .map_err(|_| unavailable("checkpoint CAS commit is uncertain"))?;
        drop(connection);
        reject_sidecars(&self.path)?;
        Ok(())
    }
}

/// Private admission entry point. It is intentionally not called by the Node
/// process runtime in this candidate tranche.
#[allow(dead_code, clippy::too_many_arguments)]
fn admit_verified_cross_plane_checkpoint_v1<S: CrossPlaneCheckpointStoreV1>(
    checkpoint_store: &mut S,
    expected_checkpoint: CrossPlaneCheckpointValueV1,
    scope: [u8; 32],
    pinned_trust_sha256: [u8; 32],
    trust_bundle_cev1: &[u8],
    order_finality_proof_cev1: &[u8],
    state_membership: BoundedApplicationStateMembershipV1<'_>,
    initial_readback: ConfirmedCrossPlaneReadbackV1,
    stores: CrossPlaneStoresV1<'_>,
    request: &CrossPlaneJoinRequestV1,
) -> ResultV1<VerifiedCrossPlaneCheckpointV1> {
    let order = verify_pinned_fresh_genesis_order_finality_v1(
        pinned_trust_sha256,
        trust_bundle_cev1,
        order_finality_proof_cev1,
    )
    .map_err(order_error)?;
    let initial = initial_readback.projection().clone();
    verify_projection_state_membership_v1(&order, &initial, state_membership)?;
    let reconfirmed =
        fresh_join_cross_plane_v1(stores, request).map_err(|_| CrossPlaneCheckpointErrorV1 {
            code: CrossPlaneCheckpointErrorCodeV1::CrossPlaneReadbackRejected,
            detail: "five-store fresh rejoin rejected",
        })?;
    require(
        reconfirmed.projection() == &initial,
        CrossPlaneCheckpointErrorCodeV1::ProjectionChanged,
        "five-store projection changed before checkpoint CAS",
    )?;
    advance_verified_projection_v1(
        checkpoint_store,
        expected_checkpoint,
        scope,
        &order,
        initial,
    )
}

fn verify_projection_state_membership_v1(
    order: &VerifiedOrderFinalityV1,
    projection: &CrossPlaneReadbackProjectionV1,
    state_membership: BoundedApplicationStateMembershipV1<'_>,
) -> ResultV1<()> {
    validate_order_projection(order, projection)?;
    let membership = verify_bounded_application_state_membership_v1(order, state_membership)
        .map_err(state_membership_error)?;
    validate_projection_state_membership_v1(order, projection, &membership)
}

fn validate_projection_state_membership_v1(
    order: &VerifiedOrderFinalityV1,
    projection: &CrossPlaneReadbackProjectionV1,
    membership: &VerifiedApplicationStateMembershipV1,
) -> ResultV1<()> {
    validate_order_projection(order, projection)?;
    require(
        membership.order_proof_id() == order.proof_id()
            && membership.finalized_block_id() == order.finalized_block_id()
            && membership.finalized_height() == order.finalized_height()
            && membership.state_root() == order.finalized_post_state_root(),
        CrossPlaneCheckpointErrorCodeV1::StateMembershipRejected,
        "application membership capability differs from finalized Order authority",
    )?;

    // ObjectKind 50 now commits the candidate composite/final execution roots,
    // but it does not contain this implementation-local five-store
    // projection/store-journal cut. This generic single-membership path cannot
    // substitute for the dedicated execution-binding verifier, its strict
    // ancestor proof, or the still-missing authoritative state writer. Do not
    // smuggle Borsh projection bytes into any object's immutable/mutable value.
    let _ = (
        membership.state_key(),
        membership.object_kind(),
        membership.object_id(),
        membership.object_version(),
        membership.value_bytes(),
        to_vec(projection).map_err(|_| CrossPlaneCheckpointErrorV1 {
            code: CrossPlaneCheckpointErrorCodeV1::StateMembershipRejected,
            detail: "cross-plane projection cannot be canonically encoded",
        })?,
    );
    reject(
        CrossPlaneCheckpointErrorCodeV1::ProjectionStateObjectUndefined,
        "no state-eligible canonical object directly commits the exact five-plane projection",
    )
}

fn advance_verified_projection_v1<S: CrossPlaneCheckpointStoreV1>(
    checkpoint_store: &mut S,
    expected_checkpoint: CrossPlaneCheckpointValueV1,
    scope: [u8; 32],
    order: &VerifiedOrderFinalityV1,
    projection: CrossPlaneReadbackProjectionV1,
) -> ResultV1<VerifiedCrossPlaneCheckpointV1> {
    require(
        scope != [0; 32] && expected_checkpoint.scope == scope,
        CrossPlaneCheckpointErrorCodeV1::ExpectedCheckpointMismatch,
        "checkpoint scope differs",
    )?;
    validate_order_projection(order, &projection)?;
    require(
        checkpoint_store.fresh_load_v1(scope)? == Some(expected_checkpoint.clone()),
        CrossPlaneCheckpointErrorCodeV1::ExpectedCheckpointMismatch,
        "fresh checkpoint source differs",
    )?;
    let target = CrossPlaneCheckpointValueV1::successor(&expected_checkpoint, order, projection)?;
    let compare_result = checkpoint_store.compare_and_advance_v1(&expected_checkpoint, &target);
    // Mandatory fresh read regardless of the reported compare result.
    let observed = checkpoint_store.fresh_load_v1(scope)?;
    match observed {
        Some(value) if value == target => Ok(VerifiedCrossPlaneCheckpointV1 { checkpoint: value }),
        Some(value) if value == expected_checkpoint => {
            let _ = compare_result;
            reject(
                CrossPlaneCheckpointErrorCodeV1::CompareNotApplied,
                "checkpoint CAS was proven not applied",
            )
        }
        _ => reject(
            CrossPlaneCheckpointErrorCodeV1::ThirdCheckpointState,
            "fresh checkpoint state is neither source nor target",
        ),
    }
}

fn validate_order_projection(
    order: &VerifiedOrderFinalityV1,
    projection: &CrossPlaneReadbackProjectionV1,
) -> ResultV1<()> {
    require(
        projection.schema_version == 1
            && projection.chain_id == order.chain_id()
            && projection.genesis_hash.0 == order.genesis_hash()
            && projection.protocol_version == order.protocol_version()
            && projection.stack_profile_hash.0 == order.stack_profile_hash(),
        CrossPlaneCheckpointErrorCodeV1::ContextMismatch,
        "cross-plane context differs from verified Order proof",
    )?;
    require(
        projection.order_height == order.finalized_height()
            && projection.order_block_id.0 == order.finalized_block_id()
            && projection.order_proof_digest.0 == order.proof_id(),
        CrossPlaneCheckpointErrorCodeV1::OrderMismatch,
        "cross-plane Order head/proof differs from verified finality",
    )?;
    require(
        projection.store_heads.len() == 5,
        CrossPlaneCheckpointErrorCodeV1::CrossPlaneReadbackRejected,
        "cross-plane projection does not contain exactly five stores",
    )
}

fn validate_stable_store_successors(
    predecessor: &CrossPlaneReadbackProjectionV1,
    target: &CrossPlaneReadbackProjectionV1,
) -> ResultV1<()> {
    require(
        predecessor.chain_id == target.chain_id
            && predecessor.genesis_hash == target.genesis_hash
            && predecessor.protocol_version == target.protocol_version
            && predecessor.stack_profile_hash == target.stack_profile_hash
            && predecessor.store_heads.len() == 5
            && target.store_heads.len() == 5,
        CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
        "checkpoint protocol context or store count differs",
    )?;
    for (before, after) in predecessor.store_heads.iter().zip(&target.store_heads) {
        require(
            before.plane_tag == after.plane_tag
                && before.store_schema_version == after.store_schema_version
                && before.store_id == after.store_id
                && after.sequence_or_height >= before.sequence_or_height
                && after.order_height >= before.order_height,
            CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
            "store identity/schema regressed or sequence went backwards",
        )?;
    }
    Ok(())
}

fn order_error(_: OrderFinalityVerifyErrorV1) -> CrossPlaneCheckpointErrorV1 {
    CrossPlaneCheckpointErrorV1 {
        code: CrossPlaneCheckpointErrorCodeV1::OrderProofRejected,
        detail: "independent Rust Order verifier rejected proof/trust bytes",
    }
}

fn state_membership_error(_: OrderFinalityVerifyErrorV1) -> CrossPlaneCheckpointErrorV1 {
    CrossPlaneCheckpointErrorV1 {
        code: CrossPlaneCheckpointErrorCodeV1::StateMembershipRejected,
        detail: "finalized application-state membership proof was rejected",
    }
}

fn checkpoint_checksum(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(
        u32::try_from(CHECKPOINT_DOMAIN_V1.len())
            .expect("static checkpoint domain fits u32")
            .to_le_bytes(),
    );
    hasher.update(CHECKPOINT_DOMAIN_V1);
    hasher.update(prefix);
    hasher.finalize().into()
}

fn unavailable(detail: &'static str) -> CrossPlaneCheckpointErrorV1 {
    CrossPlaneCheckpointErrorV1 {
        code: CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable,
        detail,
    }
}

fn validate_checkpoint_path(path: &Path, must_exist: bool) -> ResultV1<PathBuf> {
    require(
        path.is_absolute(),
        CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable,
        "checkpoint database path must be absolute",
    )?;
    let parent = path
        .parent()
        .ok_or_else(|| unavailable("checkpoint path has no parent"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|_| unavailable("checkpoint parent cannot be canonicalized"))?;
    let name = path
        .file_name()
        .ok_or_else(|| unavailable("checkpoint path has no file name"))?;
    let resolved = parent.join(name);
    require(
        must_exist == resolved.exists(),
        CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable,
        "checkpoint path existence differs",
    )?;
    Ok(resolved)
}

fn reject_sidecars(path: &Path) -> ResultV1<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar: OsString = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match fs::symlink_metadata(PathBuf::from(sidecar)) {
            Ok(_) => {
                return reject(
                    CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable,
                    "checkpoint SQLite sidecar exists",
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return reject(
                    CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable,
                    "checkpoint SQLite sidecar metadata is unavailable",
                );
            }
        }
    }
    Ok(())
}

fn open_rw(path: &Path) -> ResultV1<Connection> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|_| unavailable("cannot open checkpoint database read-write"))
}

fn open_ro(path: &Path) -> ResultV1<Connection> {
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_encoded_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'.' | b'_' | b'-' | b'~') {
            uri.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut uri, "%{byte:02X}")
                .map_err(|_| unavailable("cannot encode immutable checkpoint URI"))?;
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|_| unavailable("cannot open checkpoint database immutable read-only"))
}

#[cfg(unix)]
fn checkpoint_file_stat(metadata: &Metadata) -> CheckpointFileStatV1 {
    CheckpointFileStatV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        links: metadata.nlink(),
        size: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[cfg(unix)]
fn require_safe_checkpoint_metadata(metadata: &Metadata) -> ResultV1<()> {
    require(
        metadata.file_type().is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 1
            && metadata.len() >= 100
            && metadata.len() <= MAX_CHECKPOINT_DATABASE_BYTES_V1,
        CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable,
        "checkpoint file type, link count, or size is unsafe",
    )
}

#[cfg(unix)]
fn checkpoint_file_identity(path: &Path) -> ResultV1<CheckpointFileIdentityV1> {
    let path_before = fs::symlink_metadata(path)
        .map_err(|_| unavailable("cannot read checkpoint file identity"))?;
    require_safe_checkpoint_metadata(&path_before)?;

    let mut file = File::open(path).map_err(|_| unavailable("cannot read checkpoint bytes"))?;
    let file_before = file
        .metadata()
        .map_err(|_| unavailable("cannot read opened checkpoint identity"))?;
    require_safe_checkpoint_metadata(&file_before)?;
    require(
        checkpoint_file_stat(&path_before) == checkpoint_file_stat(&file_before),
        CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable,
        "checkpoint path changed while opening immutable identity",
    )?;

    let mut header = [0_u8; 100];
    file.read_exact(&mut header)
        .map_err(|_| unavailable("cannot read checkpoint SQLite header"))?;
    require(
        &header[..16] == b"SQLite format 3\0" && header[18] == 1 && header[19] == 1,
        CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable,
        "checkpoint SQLite header or rollback-journal mode differs",
    )?;
    let mut hasher = Sha256::new();
    hasher.update(header);
    let mut total = u64::try_from(header.len()).expect("fixed header length fits u64");
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| unavailable("cannot hash checkpoint bytes"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).expect("buffer read length fits u64"))
            .ok_or_else(|| unavailable("checkpoint byte count overflows"))?;
        hasher.update(&buffer[..read]);
    }

    let file_after = file
        .metadata()
        .map_err(|_| unavailable("cannot re-read opened checkpoint identity"))?;
    let path_after = fs::symlink_metadata(path)
        .map_err(|_| unavailable("cannot re-read checkpoint path identity"))?;
    require_safe_checkpoint_metadata(&file_after)?;
    require_safe_checkpoint_metadata(&path_after)?;
    let stat = checkpoint_file_stat(&file_before);
    require(
        stat == checkpoint_file_stat(&file_after)
            && stat == checkpoint_file_stat(&path_after)
            && total == stat.size,
        CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable,
        "checkpoint file changed while hashing immutable identity",
    )?;
    Ok(CheckpointFileIdentityV1 {
        stat,
        content_sha256: hasher.finalize().into(),
    })
}

#[cfg(not(unix))]
fn checkpoint_file_identity(_: &Path) -> ResultV1<()> {
    reject(
        CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable,
        "checkpoint file identity preflight requires Unix metadata",
    )
}

#[cfg(unix)]
fn require_checkpoint_file_identity(
    path: &Path,
    expected: CheckpointFileIdentityV1,
) -> ResultV1<()> {
    require(
        checkpoint_file_identity(path)? == expected,
        CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable,
        "checkpoint file dev/ino/uid/nlink/size/time/content identity changed",
    )
}

#[cfg(not(unix))]
fn require_checkpoint_file_identity(_: &Path, _: ()) -> ResultV1<()> {
    reject(
        CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable,
        "checkpoint file identity preflight requires Unix metadata",
    )
}

#[cfg(unix)]
fn open_existing_ro_preflight(path: &Path) -> ResultV1<(Connection, CheckpointFileIdentityV1)> {
    reject_sidecars(path)?;
    let identity = checkpoint_file_identity(path)?;
    let connection = open_ro(path)?;
    // Revalidate the path before any SQLite schema query. The connection is
    // immutable, so schema validation cannot repair or migrate the file.
    require_checkpoint_file_identity(path, identity)?;
    validate_schema(&connection)?;
    require_checkpoint_file_identity(path, identity)?;
    reject_sidecars(path)?;
    Ok((connection, identity))
}

#[cfg(not(unix))]
fn open_existing_ro_preflight(_: &Path) -> ResultV1<(Connection, ())> {
    reject(
        CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable,
        "checkpoint immutable preflight requires Unix metadata",
    )
}

#[cfg(unix)]
fn open_rw_matching_preflight(
    path: &Path,
    expected: CheckpointFileIdentityV1,
) -> ResultV1<Connection> {
    reject_sidecars(path)?;
    require_checkpoint_file_identity(path, expected)?;
    let connection = open_rw(path)?;
    // Immutable preflight has already required a rollback-journal SQLite
    // header, so a plain read-write open cannot enter WAL recovery. Recheck
    // sidecars plus the complete path/content identity before issuing even a
    // read-only PRAGMA on this connection.
    reject_sidecars(path)?;
    require_checkpoint_file_identity(path, expected)?;
    validate_schema(&connection)?;
    reject_sidecars(path)?;
    require_checkpoint_file_identity(path, expected)?;
    configure_connection(&connection)?;
    Ok(connection)
}

#[cfg(not(unix))]
fn open_rw_matching_preflight(_: &Path, _: ()) -> ResultV1<Connection> {
    reject(
        CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable,
        "checkpoint read-write preflight requires Unix metadata",
    )
}

fn open_existing_rw_after_immutable_preflight(path: &Path) -> ResultV1<Connection> {
    let (read_only, identity) = open_existing_ro_preflight(path)?;
    drop(read_only);
    reject_sidecars(path)?;
    require_checkpoint_file_identity(path, identity)?;
    open_rw_matching_preflight(path, identity)
}

fn configure_connection(connection: &Connection) -> ResultV1<()> {
    connection
        .execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; \
             PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;",
        )
        .map_err(|_| unavailable("cannot configure checkpoint database"))
}

fn validate_schema(connection: &Connection) -> ResultV1<()> {
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| unavailable("cannot read checkpoint application id"))?;
    let user_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| unavailable("cannot read checkpoint schema version"))?;
    require(
        application_id == SQLITE_APPLICATION_ID_V1 && user_version == SQLITE_SCHEMA_VERSION_V1,
        CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
        "checkpoint SQLite identity/schema differs",
    )?;
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type IN ('table','trigger','view','index') \
             AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| unavailable("cannot inspect checkpoint schema"))?;
    require(
        count == 1,
        CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
        "checkpoint SQLite schema inventory differs",
    )?;
    let (name, sql): (String, String) = connection
        .query_row(
            "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| unavailable("cannot read checkpoint schema definition"))?;
    require(
        name == "trnm_poco_cross_plane_checkpoint_v1" && sql == SQLITE_CREATE_V1,
        CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
        "checkpoint SQLite schema definition differs",
    )
}

struct RecordCursorV1<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> RecordCursorV1<'a> {
    const fn new(raw: &'a [u8]) -> Self {
        Self { raw, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.raw.len().saturating_sub(self.offset)
    }

    fn take(&mut self, length: usize) -> ResultV1<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CrossPlaneCheckpointErrorV1 {
                code: CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
                detail: "checkpoint cursor overflows",
            })?;
        if end > self.raw.len() {
            return reject(
                CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
                "checkpoint record is truncated",
            );
        }
        let value = &self.raw[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> ResultV1<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| CrossPlaneCheckpointErrorV1 {
                code: CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
                detail: "checkpoint fixed field is truncated",
            })
    }

    fn u16(&mut self) -> ResultV1<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> ResultV1<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> ResultV1<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use serde_json::Value;
    use tempfile::tempdir;
    use trnm_poco_cross_plane_readback_v1::{CrossPlaneStoreHeadV1, Hash32V1};

    use super::*;

    fn corpus() -> Value {
        serde_json::from_str(include_str!(
            "../../../../docs/protocol/poco-ai-native-v1/vectors/cev1-order-finality-light-client-kernel-v1.json"
        ))
        .expect("checked-in light-client corpus")
    }

    fn hex(raw: &str) -> Vec<u8> {
        (0..raw.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&raw[index..index + 2], 16).expect("hex fixture"))
            .collect()
    }

    fn verified_order() -> VerifiedOrderFinalityV1 {
        let corpus = corpus();
        let trust = hex(corpus["trust_bundle_cev1_hex"].as_str().expect("trust"));
        let proof = hex(corpus["order_finality_proof_cev1_hex"]
            .as_str()
            .expect("proof"));
        verify_pinned_fresh_genesis_order_finality_v1(Sha256::digest(&trust).into(), &trust, &proof)
            .expect("fixture verifies")
    }

    fn projection(
        order: &VerifiedOrderFinalityV1,
        order_height: u64,
    ) -> CrossPlaneReadbackProjectionV1 {
        let store_heads = (1u8..=5)
            .map(|plane| CrossPlaneStoreHeadV1 {
                plane_tag: plane,
                store_schema_version: if plane <= 3 { 2 } else { 1 },
                store_id: Hash32V1([20 + plane; 32]),
                sequence_or_height: order_height + u64::from(plane),
                order_height,
                order_block_id: Hash32V1(if order_height == order.finalized_height() {
                    order.finalized_block_id()
                } else {
                    [9; 32]
                }),
                durable_state_or_metadata_root: Hash32V1([40 + plane; 32]),
                durable_journal_tail_root: Hash32V1([50 + plane; 32]),
            })
            .collect();
        CrossPlaneReadbackProjectionV1 {
            schema_version: 1,
            chain_id: order.chain_id().to_owned(),
            genesis_hash: Hash32V1(order.genesis_hash()),
            protocol_version: order.protocol_version(),
            stack_profile_hash: Hash32V1(order.stack_profile_hash()),
            order_height,
            order_block_id: Hash32V1(if order_height == order.finalized_height() {
                order.finalized_block_id()
            } else {
                [9; 32]
            }),
            order_proof_digest: Hash32V1(order.proof_id()),
            store_heads,
            da_scope_id: Hash32V1([60; 32]),
            da_batch_id: Hash32V1([61; 32]),
            da_certificate_id: Hash32V1([62; 32]),
            da_obligation_id: Hash32V1([63; 32]),
            da_obligation_version: 1,
            task_id: Hash32V1([64; 32]),
            lease_id: Hash32V1([65; 32]),
            escrow_id: Hash32V1([66; 32]),
            result_id: Hash32V1([67; 32]),
            agent_operation_id: Hash32V1([68; 32]),
            verify_operation_id: Hash32V1([69; 32]),
            settlement_operation_id: Hash32V1([70; 32]),
            settlement_id: Hash32V1([71; 32]),
            mvcc_receipts_root: Hash32V1([72; 32]),
            mvcc_resource_totals_root: Hash32V1([73; 32]),
            mvcc_fee_deltas_root: Hash32V1([74; 32]),
            mvcc_resolution_root: Hash32V1([75; 32]),
            projection_digest: Hash32V1([76; 32]),
        }
    }

    fn application_object_value(
        object_kind: u16,
        object_id: [u8; 32],
        immutable: &[u8],
        mutable: &[u8],
    ) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&1u16.to_le_bytes());
        value.extend_from_slice(&object_kind.to_le_bytes());
        value.extend_from_slice(&object_id);
        value.extend_from_slice(
            &u32::try_from(immutable.len())
                .expect("bounded immutable bytes")
                .to_le_bytes(),
        );
        value.extend_from_slice(immutable);
        value.extend_from_slice(
            &u32::try_from(mutable.len())
                .expect("bounded mutable bytes")
                .to_le_bytes(),
        );
        value.extend_from_slice(mutable);
        value
    }

    #[derive(Default)]
    struct MockCheckpointStoreV1 {
        states: VecDeque<Option<CrossPlaneCheckpointValueV1>>,
        compare_observed: Option<CrossPlaneCheckpointValueV1>,
        compare_calls: u64,
        fresh_loads: u64,
        compare_returns_uncertain: bool,
    }

    impl CrossPlaneCheckpointStoreV1 for MockCheckpointStoreV1 {
        fn fresh_load_v1(&mut self, _: [u8; 32]) -> ResultV1<Option<CrossPlaneCheckpointValueV1>> {
            self.fresh_loads += 1;
            Ok(self
                .states
                .pop_front()
                .unwrap_or_else(|| self.compare_observed.clone()))
        }

        fn compare_and_advance_v1(
            &mut self,
            expected: &CrossPlaneCheckpointValueV1,
            target: &CrossPlaneCheckpointValueV1,
        ) -> ResultV1<()> {
            self.compare_calls += 1;
            require(
                target.generation == expected.generation + 1
                    && target.predecessor_checksum == expected.checksum,
                CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint,
                "mock observed non-successor target",
            )?;
            self.compare_observed = Some(target.clone());
            if self.compare_returns_uncertain {
                reject(
                    CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable,
                    "mock applied-but-ack-lost",
                )
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn successor_cas_requires_mandatory_exact_fresh_target_readback() {
        let order = verified_order();
        let mut before = projection(&order, 0);
        before.order_proof_digest = Hash32V1([3; 32]);
        let source =
            CrossPlaneCheckpointValueV1::test_anchor([8; 32], &order, before).expect("anchor");
        let target_projection = projection(&order, order.finalized_height());
        let mut store = MockCheckpointStoreV1 {
            states: VecDeque::from([Some(source.clone())]),
            ..Default::default()
        };
        let verified =
            advance_verified_projection_v1(&mut store, source, [8; 32], &order, target_projection)
                .expect("exact successor accepted");
        assert_eq!(verified.checkpoint_v1().generation(), 1);
        assert_eq!(store.compare_calls, 1);
        assert_eq!(store.fresh_loads, 2);

        let mut before = projection(&order, 0);
        before.order_proof_digest = Hash32V1([3; 32]);
        let source =
            CrossPlaneCheckpointValueV1::test_anchor([8; 32], &order, before).expect("anchor");
        let mut uncertain = MockCheckpointStoreV1 {
            states: VecDeque::from([Some(source.clone())]),
            compare_returns_uncertain: true,
            ..Default::default()
        };
        let verified = advance_verified_projection_v1(
            &mut uncertain,
            source,
            [8; 32],
            &order,
            projection(&order, order.finalized_height()),
        )
        .expect("fresh target proves applied despite uncertain acknowledgement");
        assert_eq!(verified.checkpoint_v1().generation(), 1);
    }

    #[test]
    fn order_head_and_checkpoint_lineage_mismatches_fail_closed() {
        let order = verified_order();
        let exact = projection(&order, order.finalized_height());

        let mut wrong_proof = exact.clone();
        wrong_proof.order_proof_digest = Hash32V1([99; 32]);
        assert_eq!(
            validate_order_projection(&order, &wrong_proof)
                .expect_err("proof substitution")
                .code_v1(),
            CrossPlaneCheckpointErrorCodeV1::OrderMismatch
        );

        let mut wrong_store = exact.clone();
        wrong_store.store_heads[2].store_id = Hash32V1([99; 32]);
        let mut before = projection(&order, 0);
        before.order_proof_digest = Hash32V1([3; 32]);
        let source =
            CrossPlaneCheckpointValueV1::test_anchor([8; 32], &order, before).expect("anchor");
        let mut wrong_pin_source = source.clone();
        wrong_pin_source.pinned_trust_sha256 = [99; 32];
        assert_eq!(
            CrossPlaneCheckpointValueV1::successor(&wrong_pin_source, &order, exact.clone(),)
                .expect_err("trust-pin substitution")
                .code_v1(),
            CrossPlaneCheckpointErrorCodeV1::ExpectedCheckpointMismatch
        );
        assert_eq!(
            CrossPlaneCheckpointValueV1::successor(&source, &order, wrong_store)
                .expect_err("store identity substitution")
                .code_v1(),
            CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint
        );

        let target =
            CrossPlaneCheckpointValueV1::successor(&source, &order, exact.clone()).expect("target");
        let mut replay_store = MockCheckpointStoreV1 {
            states: VecDeque::from([Some(target)]),
            ..Default::default()
        };
        assert_eq!(
            advance_verified_projection_v1(&mut replay_store, source, [8; 32], &order, exact,)
                .expect_err("stale predecessor replay")
                .code_v1(),
            CrossPlaneCheckpointErrorCodeV1::ExpectedCheckpointMismatch
        );
        assert_eq!(replay_store.compare_calls, 0);
    }

    #[test]
    fn projection_membership_shape_root_and_bare_value_substitutions_fail_closed() {
        let order = verified_order();
        let exact = projection(&order, order.finalized_height());
        let object_kind = 4;
        let object_id = [0x44; 32];
        let value = application_object_value(
            object_kind,
            object_id,
            b"immutable-task-object",
            b"mutable-task-state",
        );
        let siblings = vec![[0x55; 32]; 256];

        assert_eq!(
            verify_projection_state_membership_v1(
                &order,
                &exact,
                BoundedApplicationStateMembershipV1 {
                    state_tree_version: 0,
                    object_kind,
                    object_id,
                    object_version: 1,
                    value_bytes: &value,
                    siblings: &siblings[..255],
                },
            )
            .expect_err("short membership path must reject")
            .code_v1(),
            CrossPlaneCheckpointErrorCodeV1::StateMembershipRejected
        );

        assert_eq!(
            verify_projection_state_membership_v1(
                &order,
                &exact,
                BoundedApplicationStateMembershipV1 {
                    state_tree_version: 0,
                    object_kind,
                    object_id,
                    object_version: 1,
                    value_bytes: &value,
                    siblings: &siblings,
                },
            )
            .expect_err("unrelated valid-shape state path must reject")
            .code_v1(),
            CrossPlaneCheckpointErrorCodeV1::StateMembershipRejected
        );

        let bare_projection = to_vec(&exact).expect("projection encodes");
        assert_eq!(
            verify_projection_state_membership_v1(
                &order,
                &exact,
                BoundedApplicationStateMembershipV1 {
                    state_tree_version: 0,
                    object_kind,
                    object_id,
                    object_version: 1,
                    value_bytes: &bare_projection,
                    siblings: &siblings,
                },
            )
            .expect_err("bare projection bytes must not masquerade as a state object")
            .code_v1(),
            CrossPlaneCheckpointErrorCodeV1::StateMembershipRejected
        );
    }

    #[test]
    fn source_and_third_state_after_compare_never_mint_verified_carrier() {
        let order = verified_order();
        let mut before = projection(&order, 0);
        before.order_proof_digest = Hash32V1([3; 32]);
        let source =
            CrossPlaneCheckpointValueV1::test_anchor([8; 32], &order, before).expect("anchor");
        let exact = projection(&order, order.finalized_height());

        let mut not_applied = MockCheckpointStoreV1 {
            states: VecDeque::from([Some(source.clone()), Some(source.clone())]),
            ..Default::default()
        };
        assert_eq!(
            advance_verified_projection_v1(
                &mut not_applied,
                source.clone(),
                [8; 32],
                &order,
                exact.clone(),
            )
            .expect_err("source readback")
            .code_v1(),
            CrossPlaneCheckpointErrorCodeV1::CompareNotApplied
        );

        let mut third = source.clone();
        third.checksum = [98; 32];
        let mut third_state = MockCheckpointStoreV1 {
            states: VecDeque::from([Some(source.clone()), Some(third)]),
            ..Default::default()
        };
        assert_eq!(
            advance_verified_projection_v1(&mut third_state, source, [8; 32], &order, exact,)
                .expect_err("third state")
                .code_v1(),
            CrossPlaneCheckpointErrorCodeV1::ThirdCheckpointState
        );
    }

    #[test]
    fn sqlite_successor_reopens_exact_target_and_rejects_row_tamper() {
        let order = verified_order();
        let mut before = projection(&order, 0);
        before.order_proof_digest = Hash32V1([3; 32]);
        let source =
            CrossPlaneCheckpointValueV1::test_anchor([8; 32], &order, before).expect("anchor");
        let exact = projection(&order, order.finalized_height());
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("cross-plane-checkpoint.sqlite");
        let mut store = SqliteCrossPlaneCheckpointStoreV1::initialize_new(&path)
            .expect("initialize checkpoint");
        store.seed_test_anchor(&source).expect("seed predecessor");
        let verified = advance_verified_projection_v1(&mut store, source, [8; 32], &order, exact)
            .expect("SQLite successor");
        let exact_target = verified.checkpoint_v1().clone();
        drop(store);

        let mut reopened =
            SqliteCrossPlaneCheckpointStoreV1::open_existing(&path).expect("strict reopen");
        assert_eq!(
            reopened.fresh_load_v1([8; 32]).expect("fresh read"),
            Some(exact_target)
        );
        drop(reopened);

        let connection = open_rw(&path).expect("test tamper open");
        connection
            .execute(
                "UPDATE trnm_poco_cross_plane_checkpoint_v1 SET checkpoint_checksum=zeroblob(32)",
                [],
            )
            .expect("tamper row metadata");
        drop(connection);
        let mut reopened =
            SqliteCrossPlaneCheckpointStoreV1::open_existing(&path).expect("schema still opens");
        assert_eq!(
            reopened
                .fresh_load_v1([8; 32])
                .expect_err("row tamper must reject")
                .code_v1(),
            CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint
        );
    }

    #[test]
    fn missing_table_and_wrong_schema_reject_without_changing_database_bytes() {
        let order = verified_order();
        let mut before_projection = projection(&order, 0);
        before_projection.order_proof_digest = Hash32V1([3; 32]);
        let source = CrossPlaneCheckpointValueV1::test_anchor([8; 32], &order, before_projection)
            .expect("anchor");
        let directory = tempdir().expect("tempdir");

        let missing_table = directory.path().join("missing-table.sqlite");
        let connection = Connection::open(&missing_table).expect("create malformed database");
        connection
            .pragma_update(None, "application_id", SQLITE_APPLICATION_ID_V1)
            .expect("set application id");
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION_V1)
            .expect("set schema version");
        drop(connection);
        let missing_before = fs::read(&missing_table).expect("read malformed database");
        let mut missing_store = SqliteCrossPlaneCheckpointStoreV1 {
            path: missing_table.clone(),
        };
        assert_eq!(
            missing_store
                .seed_test_anchor(&source)
                .expect_err("missing table must reject before read-write open")
                .code_v1(),
            CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint
        );
        assert_eq!(
            fs::read(&missing_table).expect("re-read malformed database"),
            missing_before
        );

        let wrong_schema = directory.path().join("wrong-schema.sqlite");
        let mut wrong_store = SqliteCrossPlaneCheckpointStoreV1::initialize_new(&wrong_schema)
            .expect("initialize valid database");
        let connection = open_rw(&wrong_schema).expect("open test database");
        connection
            .pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION_V1 + 1)
            .expect("set wrong schema version");
        drop(connection);
        let wrong_before = fs::read(&wrong_schema).expect("read wrong-schema database");
        assert_eq!(
            wrong_store
                .seed_test_anchor(&source)
                .expect_err("wrong schema must reject before read-write effects")
                .code_v1(),
            CrossPlaneCheckpointErrorCodeV1::InvalidCheckpoint
        );
        assert_eq!(
            fs::read(&wrong_schema).expect("re-read wrong-schema database"),
            wrong_before
        );

        let wal_mode = directory.path().join("wal-mode.sqlite");
        let mut wal_store = SqliteCrossPlaneCheckpointStoreV1::initialize_new(&wal_mode)
            .expect("initialize rollback-journal database");
        let connection = open_rw(&wal_mode).expect("open test database");
        let mode: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .expect("set persisted WAL mode");
        assert_eq!(mode, "wal");
        drop(connection);
        reject_sidecars(&wal_mode).expect("closed WAL database has no live sidecars");
        let wal_before = fs::read(&wal_mode).expect("read WAL-mode database");
        assert_eq!(
            wal_store
                .seed_test_anchor(&source)
                .expect_err("WAL-mode header must reject before read-write open")
                .code_v1(),
            CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable
        );
        assert_eq!(
            fs::read(&wal_mode).expect("re-read WAL-mode database"),
            wal_before
        );
        reject_sidecars(&wal_mode).expect("WAL-mode rejection created no sidecars");
    }

    #[cfg(unix)]
    #[test]
    fn path_replacement_after_immutable_preflight_rejects_before_read_write_effects() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("checkpoint.sqlite");
        let replacement = directory.path().join("replacement.sqlite");
        let displaced = directory.path().join("displaced.sqlite");
        let store =
            SqliteCrossPlaneCheckpointStoreV1::initialize_new(&path).expect("initialize source");
        drop(store);
        let replacement_store = SqliteCrossPlaneCheckpointStoreV1::initialize_new(&replacement)
            .expect("initialize replacement");
        drop(replacement_store);

        let (read_only, pinned_identity) =
            open_existing_ro_preflight(&path).expect("immutable preflight");
        drop(read_only);
        fs::rename(&path, &displaced).expect("displace preflighted file");
        fs::rename(&replacement, &path).expect("replace database path");
        let replacement_before = fs::read(&path).expect("read replacement");
        let error = open_rw_matching_preflight(&path, pinned_identity)
            .expect_err("replacement must reject before any PRAGMA");
        assert_eq!(
            error.code_v1(),
            CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable
        );
        assert_eq!(
            fs::read(&path).expect("re-read replacement"),
            replacement_before
        );
    }

    #[test]
    fn sqlite_sidecar_rejects_before_open_without_changing_database_bytes() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("checkpoint.sqlite");
        let store =
            SqliteCrossPlaneCheckpointStoreV1::initialize_new(&path).expect("initialize database");
        drop(store);
        let database_before = fs::read(&path).expect("read database");
        let mut sidecar_name = path.as_os_str().to_os_string();
        sidecar_name.push("-wal");
        fs::write(PathBuf::from(sidecar_name), b"unresolved").expect("create unresolved sidecar");
        let error = SqliteCrossPlaneCheckpointStoreV1::open_existing(&path)
            .err()
            .expect("sidecar must reject before SQLite open");
        assert_eq!(
            error.code_v1(),
            CrossPlaneCheckpointErrorCodeV1::CheckpointUnavailable
        );
        assert_eq!(fs::read(&path).expect("re-read database"), database_before);
    }
}
