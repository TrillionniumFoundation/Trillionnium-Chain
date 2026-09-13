//! Finality-gated, canonical CEV1 Order-state successor application.
//!
//! This module deliberately supports one bounded transition shape: exactly
//! one owner-backed immutable object-kind-50 create.  The inert application
//! preview is not authority.  A normal permit exists only after the exact
//! prepared header/root has independently finalized, the candidate is a
//! certified strict ancestor, the current durable parent is exact, and the
//! retained global terminal owner has consumed the resulting membership
//! binding.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use sha2::{Digest, Sha256};
use trnm_poco_global_execution_v1::WholeNodeFinalizationOwnerV1;
use trnm_poco_order_application_v1::{
    preview_order_block_v1, recover_order_application_parent_v1 as recover_inert_parent_v1,
    revalidate_prepared_order_block_v1, revalidate_sealed_manifest_bound_g2_order_block_v2,
    seal_manifest_bound_g2_order_block_v2, EmptyOrderStateAnchorV1, OrderApplicationOperationV1,
    OrderApplicationParentV1, OrderHeaderTemplateV1, PreparedOrderBlockV1,
    RecoveredOrderApplicationLeafV1, RecoveredOrderApplicationParentV1,
    SealedManifestBoundG2OrderBlockV2, GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1,
};
use trnm_poco_order_finality_verifier_v1::{
    verify_order_state_execution_binding_receipt_v1, GlobalExecutionBindingCreateMaterialV1,
    OrderStateExecutionBindingReceiptProofV1, VerifiedOrderFinalityV1,
    VerifiedOrderStateExecutionBindingV1,
};
use trnm_poco_order_types_v1::{
    decode_block_header_v1, derive_block_id_v1, BlockIdV1, Cev1EncodeV1, G2InertExecutionPlanV2,
    G2ManifestBoundInputV2, ParentBlockRefV1,
};

use crate::{
    error::{error, OrderStateErrorCodeV1},
    verify_order_state_membership_proof_v1, OrderStateMembershipProofV1, OrderStateResultV1,
};

const SCHEMA_VERSION: u16 = 1;
const SQLITE_APPLICATION_ID: i64 = 0x5452_434f;
const SQLITE_USER_VERSION: i64 = 1;
const OBJECT_KIND: u16 = GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1;
const OBJECT_VERSION: u64 = 0;
const STATE_TREE_VERSION: u16 = 0;
const STATE_TREE_DEPTH: usize = 256;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_VALUE_BYTES: usize = 4 * 1024 * 1024;

const STATE_EMPTY_LEAF_DOMAIN: &str = "trnm.poco-ai.state-empty-leaf.v1";
const STATE_LEAF_DOMAIN: &str = "trnm.poco-ai.state-leaf.v1";
const STATE_NODE_DOMAIN: &str = "trnm.poco-ai.state-node.v1";
const VALUE_DIGEST_DOMAIN: &str = "trnm.poco-ai.canonical-order-state-value.v1";
const DELTA_DIGEST_DOMAIN: &str = "trnm.poco-ai.canonical-order-state-delta.v1";
const PERMIT_DIGEST_DOMAIN: &str = "trnm.poco-ai.canonical-finalized-order-apply-permit.v1";
const ANCHOR_CHECKSUM_DOMAIN: &str = "trnm.poco-ai.canonical-order-state-anchor.v1";
const BLOCK_CHECKSUM_DOMAIN: &str = "trnm.poco-ai.canonical-order-state-block.v1";

const METADATA_SQL: &str = "CREATE TABLE canonical_order_state_metadata_v1 (singleton INTEGER PRIMARY KEY CHECK(singleton=1),store_id BLOB NOT NULL CHECK(typeof(store_id)='blob' AND length(store_id)=32),anchor_height BLOB NOT NULL CHECK(typeof(anchor_height)='blob' AND length(anchor_height)=8),anchor_block_id BLOB NOT NULL CHECK(typeof(anchor_block_id)='blob' AND length(anchor_block_id)=32),anchor_root BLOB NOT NULL CHECK(typeof(anchor_root)='blob' AND length(anchor_root)=32),head_height BLOB NOT NULL CHECK(typeof(head_height)='blob' AND length(head_height)=8),head_block_id BLOB NOT NULL CHECK(typeof(head_block_id)='blob' AND length(head_block_id)=32),head_root BLOB NOT NULL CHECK(typeof(head_root)='blob' AND length(head_root)=32),head_checksum BLOB NOT NULL CHECK(typeof(head_checksum)='blob' AND length(head_checksum)=32),fenced INTEGER NOT NULL CHECK(fenced IN(0,1))) STRICT";
const BLOCKS_SQL: &str = "CREATE TABLE canonical_order_state_blocks_v1 (height BLOB PRIMARY KEY CHECK(typeof(height)='blob' AND length(height)=8),parent_height BLOB NOT NULL CHECK(typeof(parent_height)='blob' AND length(parent_height)=8),parent_block_id BLOB NOT NULL CHECK(typeof(parent_block_id)='blob' AND length(parent_block_id)=32),parent_root BLOB NOT NULL CHECK(typeof(parent_root)='blob' AND length(parent_root)=32),block_id BLOB NOT NULL UNIQUE CHECK(typeof(block_id)='blob' AND length(block_id)=32),header_cev1 BLOB NOT NULL CHECK(typeof(header_cev1)='blob' AND length(header_cev1)>0 AND length(header_cev1)<=65536),plan_digest BLOB NOT NULL UNIQUE CHECK(typeof(plan_digest)='blob' AND length(plan_digest)=32),post_state_root BLOB NOT NULL CHECK(typeof(post_state_root)='blob' AND length(post_state_root)=32),pinned_trust_sha256 BLOB NOT NULL CHECK(typeof(pinned_trust_sha256)='blob' AND length(pinned_trust_sha256)=32),order_proof_id BLOB NOT NULL UNIQUE CHECK(typeof(order_proof_id)='blob' AND length(order_proof_id)=32),candidate_height BLOB NOT NULL CHECK(typeof(candidate_height)='blob' AND length(candidate_height)=8),candidate_block_id BLOB NOT NULL UNIQUE CHECK(typeof(candidate_block_id)='blob' AND length(candidate_block_id)=32),final_execution_root BLOB NOT NULL CHECK(typeof(final_execution_root)='blob' AND length(final_execution_root)=32),permit_digest BLOB NOT NULL UNIQUE CHECK(typeof(permit_digest)='blob' AND length(permit_digest)=32),delta_digest BLOB NOT NULL UNIQUE CHECK(typeof(delta_digest)='blob' AND length(delta_digest)=32),predecessor_checksum BLOB NOT NULL CHECK(typeof(predecessor_checksum)='blob' AND length(predecessor_checksum)=32),checksum BLOB NOT NULL UNIQUE CHECK(typeof(checksum)='blob' AND length(checksum)=32)) STRICT, WITHOUT ROWID";
const DELTAS_SQL: &str = "CREATE TABLE canonical_order_state_deltas_v1 (height BLOB NOT NULL CHECK(typeof(height)='blob' AND length(height)=8),ordinal INTEGER NOT NULL CHECK(ordinal=0),state_key BLOB NOT NULL UNIQUE CHECK(typeof(state_key)='blob' AND length(state_key)=32),object_kind INTEGER NOT NULL CHECK(object_kind=50),object_id BLOB NOT NULL UNIQUE CHECK(typeof(object_id)='blob' AND length(object_id)=32),object_version BLOB NOT NULL CHECK(typeof(object_version)='blob' AND length(object_version)=8),value_bytes BLOB NOT NULL CHECK(typeof(value_bytes)='blob' AND length(value_bytes)>0 AND length(value_bytes)<=4194304),value_digest BLOB NOT NULL UNIQUE CHECK(typeof(value_digest)='blob' AND length(value_digest)=32),delta_digest BLOB NOT NULL UNIQUE CHECK(typeof(delta_digest)='blob' AND length(delta_digest)=32),PRIMARY KEY(height,ordinal),FOREIGN KEY(height) REFERENCES canonical_order_state_blocks_v1(height) ON DELETE RESTRICT) STRICT, WITHOUT ROWID";
const LEAVES_SQL: &str = "CREATE TABLE canonical_order_state_leaves_v1 (state_key BLOB PRIMARY KEY CHECK(typeof(state_key)='blob' AND length(state_key)=32),object_kind INTEGER NOT NULL CHECK(object_kind=50),object_id BLOB NOT NULL UNIQUE CHECK(typeof(object_id)='blob' AND length(object_id)=32),object_version BLOB NOT NULL CHECK(typeof(object_version)='blob' AND length(object_version)=8),value_bytes BLOB NOT NULL CHECK(typeof(value_bytes)='blob' AND length(value_bytes)>0 AND length(value_bytes)<=4194304),created_height BLOB NOT NULL UNIQUE CHECK(typeof(created_height)='blob' AND length(created_height)=8),block_checksum BLOB NOT NULL UNIQUE CHECK(typeof(block_checksum)='blob' AND length(block_checksum)=32)) STRICT, WITHOUT ROWID";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalOrderStateHeadPinV1 {
    store_id: [u8; 32],
    height: u64,
    block_id: BlockIdV1,
    state_root: [u8; 32],
    history_checksum: [u8; 32],
}

impl CanonicalOrderStateHeadPinV1 {
    /// Reconstitute an externally authenticated selector for a complete
    /// canonical-store audit. This cloneable value is rollback-detection data
    /// only; it cannot authorize a write or recreate a linear applied owner.
    pub fn from_external_trusted_parts_v1(
        store_id: [u8; 32],
        height: u64,
        block_id: BlockIdV1,
        state_root: [u8; 32],
        history_checksum: [u8; 32],
    ) -> OrderStateResultV1<Self> {
        if store_id == [0; 32]
            || height == 0
            || block_id.to_bytes() == [0; 32]
            || state_root == [0; 32]
            || history_checksum == [0; 32]
        {
            return Err(error(
                OrderStateErrorCodeV1::InvalidContext,
                "external canonical Order-state pin contains a zero fact",
            ));
        }
        Ok(Self {
            store_id,
            height,
            block_id,
            state_root,
            history_checksum,
        })
    }

    pub const fn store_id(&self) -> [u8; 32] {
        self.store_id
    }

    pub const fn height(&self) -> u64 {
        self.height
    }

    pub const fn block_id(&self) -> BlockIdV1 {
        self.block_id
    }

    pub const fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    pub const fn history_checksum(&self) -> [u8; 32] {
        self.history_checksum
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalFinalizedOrderApplyReceiptV1 {
    replay: bool,
    materialized_pin: CanonicalOrderStateHeadPinV1,
    observed_head_pin: CanonicalOrderStateHeadPinV1,
    pinned_trust_sha256: [u8; 32],
    order_proof_id: [u8; 32],
    plan_digest: [u8; 32],
    proof: OrderStateMembershipProofV1,
}

impl CanonicalFinalizedOrderApplyReceiptV1 {
    pub const fn is_replay(&self) -> bool {
        self.replay
    }

    pub const fn pin(&self) -> &CanonicalOrderStateHeadPinV1 {
        &self.materialized_pin
    }

    pub const fn observed_head_pin(&self) -> &CanonicalOrderStateHeadPinV1 {
        &self.observed_head_pin
    }

    pub const fn pinned_trust_sha256(&self) -> [u8; 32] {
        self.pinned_trust_sha256
    }

    pub const fn order_proof_id(&self) -> [u8; 32] {
        self.order_proof_id
    }

    pub const fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    pub const fn proof(&self) -> &OrderStateMembershipProofV1 {
        &self.proof
    }
}

#[must_use = "the finalized Order apply permit is linear and must be consumed exactly once"]
#[derive(Debug)]
pub struct CanonicalFinalizedOrderApplyPermitV1 {
    owner: WholeNodeFinalizationOwnerV1,
    finality: VerifiedOrderFinalityV1,
    prepared: PreparedOrderBlockV1,
    sealed: SealedCanonicalApplyV1,
}

#[must_use = "a failed canonical apply retains the exact permit for recovery"]
#[derive(Debug)]
pub struct CanonicalFinalizedOrderApplyFailureV1 {
    cause: crate::OrderStateErrorV1,
    permit: CanonicalFinalizedOrderApplyPermitV1,
}

impl CanonicalFinalizedOrderApplyFailureV1 {
    pub const fn cause(&self) -> &crate::OrderStateErrorV1 {
        &self.cause
    }

    pub const fn code(&self) -> OrderStateErrorCodeV1 {
        self.cause.code()
    }

    pub fn into_retry_permit(self) -> CanonicalFinalizedOrderApplyPermitV1 {
        self.permit
    }
}

#[must_use = "the applied finalized Order-state owner remains linear terminal authority"]
#[derive(Debug)]
pub struct AppliedFinalizedOrderStateOwnerV1 {
    owner: WholeNodeFinalizationOwnerV1,
    receipt: CanonicalFinalizedOrderApplyReceiptV1,
}

impl AppliedFinalizedOrderStateOwnerV1 {
    pub const fn receipt(&self) -> &CanonicalFinalizedOrderApplyReceiptV1 {
        &self.receipt
    }

    pub const fn finalization_owner(&self) -> &WholeNodeFinalizationOwnerV1 {
        &self.owner
    }

    pub fn into_parts(
        self,
    ) -> (
        WholeNodeFinalizationOwnerV1,
        CanonicalFinalizedOrderApplyReceiptV1,
    ) {
        (self.owner, self.receipt)
    }
}

pub type CanonicalFinalizedOrderApplyAttemptV1 =
    Result<AppliedFinalizedOrderStateOwnerV1, CanonicalFinalizedOrderApplyFailureV1>;

/// Non-forgeable recovery owner for the exact fresh-audited canonical
/// application parent. It is inert planning authority only; the canonical
/// finalized apply permit remains the sole write capability.
#[must_use = "the recovered canonical Order parent must remain joined to its store pin"]
#[derive(Debug)]
pub struct RecoveredCanonicalOrderApplicationParentV1 {
    store_id: [u8; 32],
    pin: CanonicalOrderStateHeadPinV1,
    parent: RecoveredCanonicalOrderApplicationParentInnerV1,
}

impl RecoveredCanonicalOrderApplicationParentV1 {
    pub const fn pin(&self) -> &CanonicalOrderStateHeadPinV1 {
        &self.pin
    }
}

// Keep the recovered parent inline: this private enum is a linear authority
// carrier and avoiding a second allocation is intentional at the one-shot
// recovery boundary.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum RecoveredCanonicalOrderApplicationParentInnerV1 {
    Empty(EmptyOrderStateAnchorV1),
    Durable(RecoveredOrderApplicationParentV1),
}

impl RecoveredCanonicalOrderApplicationParentInnerV1 {
    fn matches_pin(&self, pin: &CanonicalOrderStateHeadPinV1) -> bool {
        match self {
            Self::Empty(anchor) => {
                anchor.height() == pin.height
                    && anchor.block_id() == pin.block_id
                    && anchor.state_root() == pin.state_root
            }
            Self::Durable(parent) => {
                parent.height() == pin.height
                    && parent.block_id() == pin.block_id
                    && parent.state_root() == pin.state_root
            }
        }
    }

    const fn application_parent(&self) -> OrderApplicationParentV1<'_> {
        match self {
            Self::Empty(anchor) => OrderApplicationParentV1::EmptyAnchor(anchor),
            Self::Durable(parent) => OrderApplicationParentV1::Recovered(parent),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalLeafV1 {
    object_kind: u16,
    object_id: [u8; 32],
    object_version: u64,
    value_bytes: Vec<u8>,
    created_height: u64,
    block_checksum: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalDeltaV1 {
    height: u64,
    state_key: [u8; 32],
    object_kind: u16,
    object_id: [u8; 32],
    object_version: u64,
    value_bytes: Vec<u8>,
    value_digest: [u8; 32],
    delta_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalBlockRecordV1 {
    height: u64,
    parent_height: u64,
    parent_block_id: BlockIdV1,
    parent_root: [u8; 32],
    block_id: BlockIdV1,
    header_cev1: Vec<u8>,
    plan_digest: [u8; 32],
    post_state_root: [u8; 32],
    pinned_trust_sha256: [u8; 32],
    order_proof_id: [u8; 32],
    candidate_height: u64,
    candidate_block_id: [u8; 32],
    final_execution_root: [u8; 32],
    permit_digest: [u8; 32],
    delta_digest: [u8; 32],
    predecessor_checksum: [u8; 32],
    checksum: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SealedCanonicalApplyV1 {
    store_id: [u8; 32],
    expected_parent: CanonicalOrderStateHeadPinV1,
    block: CanonicalBlockRecordV1,
    delta: CanonicalDeltaV1,
    target_proof: OrderStateMembershipProofV1,
}

#[derive(Debug)]
struct CanonicalAuditV1 {
    anchor_height: u64,
    anchor_block_id: BlockIdV1,
    anchor_root: [u8; 32],
    head: CanonicalOrderStateHeadPinV1,
    blocks: BTreeMap<u64, CanonicalBlockRecordV1>,
    deltas: BTreeMap<u64, CanonicalDeltaV1>,
    leaves: BTreeMap<[u8; 32], CanonicalLeafV1>,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentityV1 {
    device: u64,
    inode: u64,
    uid: u32,
    links: u64,
    mode: u32,
}

#[cfg(not(unix))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct FileIdentityV1 {
    canonical_path: PathBuf,
}

#[derive(Debug)]
pub struct PocoCanonicalOrderStateStoreV1 {
    path: PathBuf,
    store_id: [u8; 32],
    file_identity: FileIdentityV1,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanonicalOrderApplyFaultV1 {
    BeforeCommit,
    AfterCommitBeforeReturn,
}

impl PocoCanonicalOrderStateStoreV1 {
    pub fn initialize_new(
        path: impl Into<PathBuf>,
        store_id: [u8; 32],
        anchor_height: u64,
        anchor_block_id: BlockIdV1,
    ) -> OrderStateResultV1<Self> {
        require_nonzero(store_id, "canonical Order-state store ID")?;
        require_nonzero(
            anchor_block_id.to_bytes(),
            "canonical Order-state anchor BlockId",
        )?;
        if anchor_height == 0 {
            return Err(error(
                OrderStateErrorCodeV1::InvalidContext,
                "canonical Order-state anchor height must be positive",
            ));
        }
        let path = validate_path(&path.into(), false)?;
        reject_sidecars(&path)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|cause| unavailable(cause.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|cause| unavailable(cause.to_string()))?;
        }
        drop(file);
        let mut connection = open_rw_raw(&path)?;
        configure_rw(&connection)?;
        connection.pragma_update(None, "application_id", SQLITE_APPLICATION_ID)?;
        connection.pragma_update(None, "user_version", SQLITE_USER_VERSION)?;
        let anchor_root = empty_state_root_v1();
        let anchor_checksum =
            anchor_checksum_v1(store_id, anchor_height, anchor_block_id, anchor_root);
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(METADATA_SQL)?;
        transaction.execute_batch(BLOCKS_SQL)?;
        transaction.execute_batch(DELTAS_SQL)?;
        transaction.execute_batch(LEAVES_SQL)?;
        transaction.execute(
            "INSERT INTO canonical_order_state_metadata_v1(singleton,store_id,anchor_height,anchor_block_id,anchor_root,head_height,head_block_id,head_root,head_checksum,fenced) VALUES(1,?1,?2,?3,?4,?2,?3,?4,?5,0)",
            params![
                &store_id[..],
                &anchor_height.to_be_bytes()[..],
                &anchor_block_id.to_bytes()[..],
                &anchor_root[..],
                &anchor_checksum[..],
            ],
        )?;
        transaction.commit()?;
        drop(connection);
        reject_sidecars(&path)?;
        let store = Self {
            file_identity: file_identity(&path)?,
            path,
            store_id,
        };
        let observed = store.audit_fresh()?;
        if observed.anchor_height != anchor_height
            || observed.anchor_block_id != anchor_block_id
            || observed.anchor_root != anchor_root
            || observed.head.height != anchor_height
            || observed.head.block_id != anchor_block_id
            || observed.head.state_root != anchor_root
            || observed.head.history_checksum != anchor_checksum
            || !observed.blocks.is_empty()
            || !observed.deltas.is_empty()
            || !observed.leaves.is_empty()
        {
            return Err(error(
                OrderStateErrorCodeV1::StoreTamper,
                "fresh canonical Order-state anchor readback differs",
            ));
        }
        Ok(store)
    }

    pub fn open_existing_pinned(
        path: impl Into<PathBuf>,
        store_id: [u8; 32],
        trusted_pin: &CanonicalOrderStateHeadPinV1,
    ) -> OrderStateResultV1<Self> {
        require_nonzero(store_id, "canonical Order-state store ID")?;
        let path = validate_path(&path.into(), true)?;
        let store = Self {
            file_identity: file_identity(&path)?,
            path,
            store_id,
        };
        let observed = store.audit_fresh()?;
        if observed.head != *trusted_pin {
            return Err(error(
                OrderStateErrorCodeV1::StoreRollback,
                "canonical Order-state head differs from trusted external pin",
            ));
        }
        Ok(store)
    }

    pub fn fresh_head_pin_v1(&self) -> OrderStateResultV1<CanonicalOrderStateHeadPinV1> {
        Ok(self.audit_fresh()?.head)
    }

    /// Rebuild the exact inert application parent from a complete fresh audit
    /// of canonical headers, BlockIds, roots, deltas, live projection, sequence,
    /// history checksums, and the caller's externally retained head pin.
    pub fn recover_order_application_parent_v1(
        &self,
        expected_head: &CanonicalOrderStateHeadPinV1,
    ) -> OrderStateResultV1<RecoveredCanonicalOrderApplicationParentV1> {
        let audited = self.audit_fresh()?;
        if expected_head.store_id != self.store_id || audited.head != *expected_head {
            return Err(error(
                OrderStateErrorCodeV1::StoreRollback,
                "canonical application-parent recovery differs from the trusted head pin",
            ));
        }
        let parent = application_parent_from_audit_v1(&audited)?;
        let observed = self.audit_fresh()?;
        if observed.head != audited.head || !parent.matches_pin(&audited.head) {
            return Err(error(
                OrderStateErrorCodeV1::StoreRollback,
                "canonical application parent changed during mandatory fresh re-audit",
            ));
        }
        Ok(RecoveredCanonicalOrderApplicationParentV1 {
            store_id: self.store_id,
            pin: audited.head,
            parent,
        })
    }

    /// Preview one exact successor only while the recovered parent remains the
    /// fresh canonical head. The result stays inert and still needs the normal
    /// owner + finality + private canonical apply permit.
    pub fn preview_next_from_recovered_parent_v1(
        &self,
        parent: &RecoveredCanonicalOrderApplicationParentV1,
        template: OrderHeaderTemplateV1,
        operations: &[OrderApplicationOperationV1],
    ) -> OrderStateResultV1<PreparedOrderBlockV1> {
        let before = self.audit_fresh()?;
        if parent.store_id != self.store_id
            || before.head != parent.pin
            || !parent.parent.matches_pin(&parent.pin)
        {
            return Err(error(
                OrderStateErrorCodeV1::StoreRollback,
                "recovered application parent is foreign or no longer canonical",
            ));
        }
        let prepared =
            preview_order_block_v1(parent.parent.application_parent(), template, operations)
                .map_err(|cause| {
                    error(
                        OrderStateErrorCodeV1::PreparedPlanMismatch,
                        format!("recovered canonical parent preview failed: {cause}"),
                    )
                })?;
        let after = self.audit_fresh()?;
        if after.head != before.head
            || prepared.header().height
                != parent.pin.height.checked_add(1).ok_or_else(|| {
                    error(
                        OrderStateErrorCodeV1::ArithmeticOverflow,
                        "recovered canonical parent successor height overflows",
                    )
                })?
            || prepared.header().parent != ParentBlockRefV1::V1Block(parent.pin.block_id)
            || prepared.parent_state_root() != parent.pin.state_root
        {
            return Err(error(
                OrderStateErrorCodeV1::StoreRollback,
                "canonical head changed or recovered preview names another successor",
            ));
        }
        Ok(prepared)
    }

    /// Seal one manifest-bound G2 candidate from the exact recovered
    /// canonical parent without exposing the inner application parent. This
    /// is inert planning only: it grants no write, finality, vote, signing,
    /// checkpoint, process, or activation authority.
    pub fn seal_manifest_bound_g2_from_recovered_parent_v2(
        &self,
        parent: &RecoveredCanonicalOrderApplicationParentV1,
        template: OrderHeaderTemplateV1,
        input: G2ManifestBoundInputV2,
        plan: G2InertExecutionPlanV2,
    ) -> OrderStateResultV1<SealedManifestBoundG2OrderBlockV2> {
        let before = self.audit_fresh()?;
        let target_height = parent.pin.height.checked_add(1).ok_or_else(|| {
            error(
                OrderStateErrorCodeV1::ArithmeticOverflow,
                "recovered canonical G2 successor height overflows",
            )
        })?;
        if parent.store_id != self.store_id
            || parent.pin.store_id != self.store_id
            || before.head != parent.pin
            || !parent.parent.matches_pin(&parent.pin)
            || before.blocks.contains_key(&target_height)
        {
            return Err(error(
                OrderStateErrorCodeV1::StoreRollback,
                "recovered G2 application parent is foreign, stale, or not the unique canonical head",
            ));
        }

        let sealed = seal_manifest_bound_g2_order_block_v2(
            parent.parent.application_parent(),
            template,
            input,
            plan,
        )
        .map_err(|cause| {
            error(
                OrderStateErrorCodeV1::PreparedPlanMismatch,
                format!("recovered canonical G2 seal failed: {cause}"),
            )
        })?;
        revalidate_sealed_manifest_bound_g2_order_block_v2(&sealed).map_err(|cause| {
            error(
                OrderStateErrorCodeV1::PreparedPlanMismatch,
                format!("recovered canonical G2 seal revalidation failed: {cause}"),
            )
        })?;

        let after = self.audit_fresh()?;
        if after.head != before.head
            || after.head != parent.pin
            || !parent.parent.matches_pin(&after.head)
            || after.blocks.contains_key(&target_height)
            || sealed.header().height != target_height
            || sealed.header().parent != ParentBlockRefV1::V1Block(parent.pin.block_id)
        {
            return Err(error(
                OrderStateErrorCodeV1::StoreRollback,
                "canonical head changed or manifest-bound G2 seal is not its unique direct successor",
            ));
        }
        Ok(sealed)
    }

    /// Rebuild the inert prepared plan for one already-committed exact
    /// successor without writing the database. Both pins are treated only as
    /// externally authenticated selectors. A complete fresh target audit is
    /// pruned in memory to its exact predecessor, the normal application
    /// preview is rerun there, and the result must equal the durable target.
    pub fn recover_committed_prepared_order_block_v1(
        &self,
        expected_parent: &CanonicalOrderStateHeadPinV1,
        expected_target: &CanonicalOrderStateHeadPinV1,
        template: OrderHeaderTemplateV1,
        operations: &[OrderApplicationOperationV1],
    ) -> OrderStateResultV1<PreparedOrderBlockV1> {
        let audited = self.audit_fresh()?;
        let (predecessor, durable_block, durable_delta) =
            reconstruct_exact_committed_predecessor_v1(
                audited,
                self.store_id,
                expected_parent,
                expected_target,
            )?;
        let parent = application_parent_from_audit_v1(&predecessor)?;
        let prepared = preview_order_block_v1(parent.application_parent(), template, operations)
            .map_err(|cause| {
                error(
                    OrderStateErrorCodeV1::PreparedPlanMismatch,
                    format!("committed target recovery preview failed: {cause}"),
                )
            })?;
        require_prepared_matches_durable_target_v1(&prepared, &durable_block, &durable_delta)?;

        let reaudited = self.audit_fresh()?;
        let (_, reaudited_block, reaudited_delta) = reconstruct_exact_committed_predecessor_v1(
            reaudited,
            self.store_id,
            expected_parent,
            expected_target,
        )?;
        if reaudited_block != durable_block || reaudited_delta != durable_delta {
            return Err(error(
                OrderStateErrorCodeV1::StoreRollback,
                "committed target changed during prepared-plan recovery",
            ));
        }
        Ok(prepared)
    }

    /// Reissue the linear applied owner for one exact already-committed
    /// target, solely from freshly reauthenticated upstream authorities.
    ///
    /// This path performs no database write. It consumes a freshly recovered
    /// whole-node terminal owner, independently verified target finality, the
    /// exact reconstructed prepared plan, and external parent/target pins. It
    /// reruns the normal private seal/binding path against an in-memory exact
    /// predecessor and returns authority only after a second fresh membership
    /// readback proves that the target is still the canonical head.
    pub fn recover_applied_finalized_order_state_owner_v1(
        &self,
        owner: WholeNodeFinalizationOwnerV1,
        finality: VerifiedOrderFinalityV1,
        prepared: PreparedOrderBlockV1,
        expected_parent: &CanonicalOrderStateHeadPinV1,
        expected_target: &CanonicalOrderStateHeadPinV1,
    ) -> OrderStateResultV1<AppliedFinalizedOrderStateOwnerV1> {
        let audited = self.audit_fresh()?;
        let (predecessor, durable_block, durable_delta) =
            reconstruct_exact_committed_predecessor_v1(
                audited,
                self.store_id,
                expected_parent,
                expected_target,
            )?;
        let (sealed, binding) =
            seal_canonical_apply_v1(self.store_id, &predecessor, &owner, &finality, &prepared)?;
        if sealed.expected_parent != *expected_parent
            || sealed.block != durable_block
            || sealed.delta != durable_delta
        {
            return Err(error(
                OrderStateErrorCodeV1::PermitMismatch,
                "recovered authority regenerates a different durable block or delta",
            ));
        }
        let fresh_target_proof = prove_membership_at_v1(
            &self.audit_fresh()?,
            expected_target.height,
            durable_delta.state_key,
        )?;
        if sealed.target_proof != fresh_target_proof {
            return Err(error(
                OrderStateErrorCodeV1::MembershipInvalid,
                "regenerated target proof differs from fresh durable membership",
            ));
        }
        let owner = owner.bind_verified_order_state_v1(binding).map_err(|_| {
            error(
                OrderStateErrorCodeV1::PermitMismatch,
                "terminal owner rejected recovered finalized Order-state binding",
            )
        })?;
        let receipt =
            self.fresh_receipt_v1(expected_target.height, durable_delta.state_key, true)?;
        if receipt.pin() != expected_target
            || receipt.observed_head_pin() != expected_target
            || receipt.pinned_trust_sha256() != durable_block.pinned_trust_sha256
            || receipt.order_proof_id() != durable_block.order_proof_id
            || receipt.plan_digest() != durable_block.plan_digest
            || receipt.proof() != &sealed.target_proof
        {
            return Err(error(
                OrderStateErrorCodeV1::StoreRollback,
                "fresh recovered applied-owner readback differs from the exact target",
            ));
        }
        Ok(AppliedFinalizedOrderStateOwnerV1 { owner, receipt })
    }

    /// Consume the exact global terminal owner, independently verified target
    /// finality, inert prepared plan, and durable parent pin into one private
    /// finalized-apply permit.
    pub fn issue_finalized_prepared_order_apply_v1(
        &self,
        owner: WholeNodeFinalizationOwnerV1,
        finality: VerifiedOrderFinalityV1,
        prepared: PreparedOrderBlockV1,
        expected_parent: &CanonicalOrderStateHeadPinV1,
    ) -> OrderStateResultV1<CanonicalFinalizedOrderApplyPermitV1> {
        let audited = self.audit_fresh()?;
        if audited.head != *expected_parent || expected_parent.store_id != self.store_id {
            return Err(error(
                OrderStateErrorCodeV1::StaleParent,
                "canonical finalized apply does not name the exact durable parent",
            ));
        }
        let (sealed, binding) =
            seal_canonical_apply_v1(self.store_id, &audited, &owner, &finality, &prepared)?;
        let owner = owner.bind_verified_order_state_v1(binding).map_err(|_| {
            error(
                OrderStateErrorCodeV1::PermitMismatch,
                "terminal owner rejected exact finalized Order-state binding",
            )
        })?;
        Ok(CanonicalFinalizedOrderApplyPermitV1 {
            owner,
            finality,
            prepared,
            sealed,
        })
    }

    // The error intentionally retains the complete non-Clone permit so an
    // uncertain write can be retried without reconstructing authority.
    #[allow(clippy::result_large_err)]
    pub fn apply_finalized_prepared_order_block_v1(
        &self,
        permit: CanonicalFinalizedOrderApplyPermitV1,
    ) -> CanonicalFinalizedOrderApplyAttemptV1 {
        self.apply_with_optional_fault_v1(permit, None)
    }

    #[allow(clippy::result_large_err)]
    fn apply_with_optional_fault_v1(
        &self,
        permit: CanonicalFinalizedOrderApplyPermitV1,
        fault: Option<CanonicalOrderApplyFaultV1>,
    ) -> CanonicalFinalizedOrderApplyAttemptV1 {
        match self.apply_inner_v1(&permit, fault) {
            Ok(receipt) => Ok(AppliedFinalizedOrderStateOwnerV1 {
                owner: permit.owner,
                receipt,
            }),
            Err(cause) => Err(CanonicalFinalizedOrderApplyFailureV1 { cause, permit }),
        }
    }

    fn apply_inner_v1(
        &self,
        permit: &CanonicalFinalizedOrderApplyPermitV1,
        #[cfg_attr(not(test), allow(unused_variables))] fault: Option<CanonicalOrderApplyFaultV1>,
    ) -> OrderStateResultV1<CanonicalFinalizedOrderApplyReceiptV1> {
        revalidate_permit_v1(permit)?;
        self.apply_sealed_inner_v1(&permit.sealed, fault)
    }

    fn apply_sealed_inner_v1(
        &self,
        sealed: &SealedCanonicalApplyV1,
        #[cfg_attr(not(test), allow(unused_variables))] fault: Option<CanonicalOrderApplyFaultV1>,
    ) -> OrderStateResultV1<CanonicalFinalizedOrderApplyReceiptV1> {
        self.validate_file_identity()?;
        reject_sidecars(&self.path)?;
        if sealed.store_id != self.store_id {
            return Err(error(
                OrderStateErrorCodeV1::PermitMismatch,
                "canonical finalized permit belongs to another store",
            ));
        }
        let mut connection = open_rw_raw(&self.path)?;
        configure_rw(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let audited = audit_connection_v1(&transaction, self.store_id)?;
        let target_height = sealed.block.height;

        if let Some(existing) = audited.blocks.get(&target_height) {
            let exact = existing == &sealed.block
                && audited.deltas.get(&target_height) == Some(&sealed.delta);
            drop(transaction);
            drop(connection);
            if !exact {
                return Err(error(
                    OrderStateErrorCodeV1::Fork,
                    "canonical target height is occupied by another finalized block",
                ));
            }
            return self.fresh_receipt_v1(target_height, sealed.delta.state_key, true);
        }

        if audited.head != sealed.expected_parent {
            return Err(error(
                OrderStateErrorCodeV1::StaleParent,
                "canonical finalized permit parent is no longer the exact head",
            ));
        }
        if audited.leaves.contains_key(&sealed.delta.state_key) {
            return Err(error(
                OrderStateErrorCodeV1::DuplicateKey,
                "canonical finalized object key already exists",
            ));
        }
        let (parent_root, _) = sparse_root_and_siblings_v1(&audited.leaves, None)?;
        if parent_root != sealed.block.parent_root {
            return Err(error(
                OrderStateErrorCodeV1::StoreTamper,
                "canonical parent sparse root differs from finalized permit",
            ));
        }

        transaction.execute(
            "INSERT INTO canonical_order_state_blocks_v1(height,parent_height,parent_block_id,parent_root,block_id,header_cev1,plan_digest,post_state_root,pinned_trust_sha256,order_proof_id,candidate_height,candidate_block_id,final_execution_root,permit_digest,delta_digest,predecessor_checksum,checksum) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![
                &sealed.block.height.to_be_bytes()[..],
                &sealed.block.parent_height.to_be_bytes()[..],
                &sealed.block.parent_block_id.to_bytes()[..],
                &sealed.block.parent_root[..],
                &sealed.block.block_id.to_bytes()[..],
                &sealed.block.header_cev1,
                &sealed.block.plan_digest[..],
                &sealed.block.post_state_root[..],
                &sealed.block.pinned_trust_sha256[..],
                &sealed.block.order_proof_id[..],
                &sealed.block.candidate_height.to_be_bytes()[..],
                &sealed.block.candidate_block_id[..],
                &sealed.block.final_execution_root[..],
                &sealed.block.permit_digest[..],
                &sealed.block.delta_digest[..],
                &sealed.block.predecessor_checksum[..],
                &sealed.block.checksum[..],
            ],
        )?;
        transaction.execute(
            "INSERT INTO canonical_order_state_deltas_v1(height,ordinal,state_key,object_kind,object_id,object_version,value_bytes,value_digest,delta_digest) VALUES(?1,0,?2,50,?3,?4,?5,?6,?7)",
            params![
                &sealed.delta.height.to_be_bytes()[..],
                &sealed.delta.state_key[..],
                &sealed.delta.object_id[..],
                &sealed.delta.object_version.to_be_bytes()[..],
                &sealed.delta.value_bytes,
                &sealed.delta.value_digest[..],
                &sealed.delta.delta_digest[..],
            ],
        )?;
        transaction.execute(
            "INSERT INTO canonical_order_state_leaves_v1(state_key,object_kind,object_id,object_version,value_bytes,created_height,block_checksum) VALUES(?1,50,?2,?3,?4,?5,?6)",
            params![
                &sealed.delta.state_key[..],
                &sealed.delta.object_id[..],
                &sealed.delta.object_version.to_be_bytes()[..],
                &sealed.delta.value_bytes,
                &sealed.delta.height.to_be_bytes()[..],
                &sealed.block.checksum[..],
            ],
        )?;
        let changed = transaction.execute(
            "UPDATE canonical_order_state_metadata_v1 SET head_height=?1,head_block_id=?2,head_root=?3,head_checksum=?4 WHERE singleton=1 AND fenced=0 AND head_height=?5 AND head_block_id=?6 AND head_root=?7 AND head_checksum=?8",
            params![
                &sealed.block.height.to_be_bytes()[..],
                &sealed.block.block_id.to_bytes()[..],
                &sealed.block.post_state_root[..],
                &sealed.block.checksum[..],
                &sealed.expected_parent.height.to_be_bytes()[..],
                &sealed.expected_parent.block_id.to_bytes()[..],
                &sealed.expected_parent.state_root[..],
                &sealed.expected_parent.history_checksum[..],
            ],
        )?;
        if changed != 1 {
            return Err(error(
                OrderStateErrorCodeV1::StaleParent,
                "canonical Order-state metadata tuple CAS changed no row",
            ));
        }
        #[cfg(test)]
        if matches!(fault, Some(CanonicalOrderApplyFaultV1::BeforeCommit)) {
            return Err(error(
                OrderStateErrorCodeV1::CommitUncertain,
                "injected canonical Order-state loss before commit",
            ));
        }
        transaction.commit().map_err(|cause| {
            error(
                OrderStateErrorCodeV1::CommitUncertain,
                format!("canonical Order-state commit outcome is uncertain: {cause}"),
            )
        })?;
        drop(connection);
        #[cfg(test)]
        if matches!(
            fault,
            Some(CanonicalOrderApplyFaultV1::AfterCommitBeforeReturn)
        ) {
            return Err(error(
                OrderStateErrorCodeV1::CommitUncertain,
                "canonical Order-state committed before acknowledgement loss",
            ));
        }
        self.fresh_receipt_v1(target_height, sealed.delta.state_key, false)
    }

    fn fresh_receipt_v1(
        &self,
        height: u64,
        state_key: [u8; 32],
        replay: bool,
    ) -> OrderStateResultV1<CanonicalFinalizedOrderApplyReceiptV1> {
        let audited = self.audit_fresh()?;
        let record = audited.blocks.get(&height).ok_or_else(|| {
            error(
                OrderStateErrorCodeV1::StoreTamper,
                "canonical finalized block is absent during fresh readback",
            )
        })?;
        let proof = prove_membership_at_v1(&audited, height, state_key)?;
        if !verify_order_state_membership_proof_v1(&proof)
            || proof.state_root() != record.post_state_root
        {
            return Err(error(
                OrderStateErrorCodeV1::MembershipInvalid,
                "fresh canonical target membership proof differs",
            ));
        }
        Ok(CanonicalFinalizedOrderApplyReceiptV1 {
            replay,
            materialized_pin: CanonicalOrderStateHeadPinV1 {
                store_id: self.store_id,
                height,
                block_id: record.block_id,
                state_root: record.post_state_root,
                history_checksum: record.checksum,
            },
            observed_head_pin: audited.head,
            pinned_trust_sha256: record.pinned_trust_sha256,
            order_proof_id: record.order_proof_id,
            plan_digest: record.plan_digest,
            proof,
        })
    }

    fn audit_fresh(&self) -> OrderStateResultV1<CanonicalAuditV1> {
        self.validate_file_identity()?;
        reject_sidecars(&self.path)?;
        let connection = open_ro(&self.path)?;
        let audited = audit_connection_v1(&connection, self.store_id)?;
        drop(connection);
        self.validate_file_identity()?;
        reject_sidecars(&self.path)?;
        Ok(audited)
    }

    fn validate_file_identity(&self) -> OrderStateResultV1<()> {
        if file_identity(&self.path)? != self.file_identity {
            return Err(error(
                OrderStateErrorCodeV1::StoreUnavailable,
                "canonical Order-state database identity changed",
            ));
        }
        Ok(())
    }
}

fn application_parent_from_audit_v1(
    audited: &CanonicalAuditV1,
) -> OrderStateResultV1<RecoveredCanonicalOrderApplicationParentInnerV1> {
    let mut leaves = Vec::with_capacity(audited.deltas.len());
    for (height, delta) in &audited.deltas {
        let block = audited.blocks.get(height).ok_or_else(|| {
            error(
                OrderStateErrorCodeV1::StoreTamper,
                "canonical recovery delta has no exact block record",
            )
        })?;
        leaves.push(
            RecoveredOrderApplicationLeafV1::new(
                *height,
                delta.object_kind,
                delta.object_id,
                delta.object_version,
                delta.state_key,
                delta.value_bytes.clone(),
                block.candidate_height,
                BlockIdV1::new(block.candidate_block_id),
            )
            .map_err(|cause| {
                error(
                    OrderStateErrorCodeV1::StoreTamper,
                    format!("canonical recovery leaf failed application audit: {cause}"),
                )
            })?,
        );
    }
    if audited.blocks.is_empty() {
        if !leaves.is_empty()
            || audited.head.height != audited.anchor_height
            || audited.head.block_id != audited.anchor_block_id
            || audited.head.state_root != audited.anchor_root
        {
            return Err(error(
                OrderStateErrorCodeV1::StoreTamper,
                "canonical empty anchor retains leaves or differs from its anchor",
            ));
        }
        return Ok(RecoveredCanonicalOrderApplicationParentInnerV1::Empty(
            EmptyOrderStateAnchorV1::new(audited.head.height, audited.head.block_id).map_err(
                |cause| {
                    error(
                        OrderStateErrorCodeV1::StoreTamper,
                        format!("canonical empty anchor reconstruction failed: {cause}"),
                    )
                },
            )?,
        ));
    }
    let head_block = audited.blocks.get(&audited.head.height).ok_or_else(|| {
        error(
            OrderStateErrorCodeV1::StoreTamper,
            "canonical durable parent has no exact head block record",
        )
    })?;
    let header = decode_block_header_v1(&head_block.header_cev1).map_err(|cause| {
        error(
            OrderStateErrorCodeV1::StoreTamper,
            format!("canonical durable parent header failed exact decode: {cause}"),
        )
    })?;
    Ok(RecoveredCanonicalOrderApplicationParentInnerV1::Durable(
        recover_inert_parent_v1(header, audited.head.block_id, leaves).map_err(|cause| {
            error(
                OrderStateErrorCodeV1::StoreTamper,
                format!("canonical application parent reconstruction failed: {cause}"),
            )
        })?,
    ))
}

fn reconstruct_exact_committed_predecessor_v1(
    mut audited: CanonicalAuditV1,
    store_id: [u8; 32],
    expected_parent: &CanonicalOrderStateHeadPinV1,
    expected_target: &CanonicalOrderStateHeadPinV1,
) -> OrderStateResultV1<(CanonicalAuditV1, CanonicalBlockRecordV1, CanonicalDeltaV1)> {
    if expected_parent.store_id != store_id
        || expected_target.store_id != store_id
        || audited.head != *expected_target
    {
        return Err(error(
            OrderStateErrorCodeV1::StoreRollback,
            "committed recovery parent/target store or target head differs",
        ));
    }
    let target_height = expected_parent.height.checked_add(1).ok_or_else(|| {
        error(
            OrderStateErrorCodeV1::ArithmeticOverflow,
            "committed recovery successor height overflows",
        )
    })?;
    if expected_target.height != target_height {
        return Err(error(
            OrderStateErrorCodeV1::StaleParent,
            "committed recovery target is not the exact parent successor",
        ));
    }
    let block = audited.blocks.remove(&target_height).ok_or_else(|| {
        error(
            OrderStateErrorCodeV1::StoreRollback,
            "committed recovery target block is absent",
        )
    })?;
    let delta = audited.deltas.remove(&target_height).ok_or_else(|| {
        error(
            OrderStateErrorCodeV1::StoreTamper,
            "committed recovery target delta is absent",
        )
    })?;
    let leaf = audited.leaves.remove(&delta.state_key).ok_or_else(|| {
        error(
            OrderStateErrorCodeV1::StoreTamper,
            "committed recovery target live leaf is absent",
        )
    })?;
    let expected_leaf = CanonicalLeafV1 {
        object_kind: delta.object_kind,
        object_id: delta.object_id,
        object_version: delta.object_version,
        value_bytes: delta.value_bytes.clone(),
        created_height: delta.height,
        block_checksum: block.checksum,
    };
    if block.height != expected_target.height
        || block.block_id != expected_target.block_id
        || block.post_state_root != expected_target.state_root
        || block.checksum != expected_target.history_checksum
        || block.parent_height != expected_parent.height
        || block.parent_block_id != expected_parent.block_id
        || block.parent_root != expected_parent.state_root
        || block.predecessor_checksum != expected_parent.history_checksum
        || delta.height != expected_target.height
        || block.delta_digest != delta.delta_digest
        || leaf != expected_leaf
    {
        return Err(error(
            OrderStateErrorCodeV1::StoreRollback,
            "committed recovery durable successor differs from exact parent/target pins",
        ));
    }
    let (parent_root, _) = sparse_root_and_siblings_v1(&audited.leaves, None)?;
    if parent_root != expected_parent.state_root {
        return Err(error(
            OrderStateErrorCodeV1::StoreTamper,
            "committed recovery predecessor sparse root differs",
        ));
    }
    match audited.blocks.last_key_value() {
        None => {
            if expected_parent.height != audited.anchor_height
                || expected_parent.block_id != audited.anchor_block_id
                || expected_parent.state_root != audited.anchor_root
                || expected_parent.history_checksum
                    != anchor_checksum_v1(
                        store_id,
                        audited.anchor_height,
                        audited.anchor_block_id,
                        audited.anchor_root,
                    )
                || !audited.deltas.is_empty()
                || !audited.leaves.is_empty()
            {
                return Err(error(
                    OrderStateErrorCodeV1::StoreRollback,
                    "committed recovery predecessor differs from the exact anchor",
                ));
            }
        }
        Some((height, parent_block)) => {
            if *height != expected_parent.height
                || parent_block.block_id != expected_parent.block_id
                || parent_block.post_state_root != expected_parent.state_root
                || parent_block.checksum != expected_parent.history_checksum
                || audited.deltas.len() != audited.blocks.len()
            {
                return Err(error(
                    OrderStateErrorCodeV1::StoreRollback,
                    "committed recovery predecessor differs from the exact history tail",
                ));
            }
        }
    }
    audited.head = expected_parent.clone();
    Ok((audited, block, delta))
}

fn require_prepared_matches_durable_target_v1(
    prepared: &PreparedOrderBlockV1,
    block: &CanonicalBlockRecordV1,
    delta: &CanonicalDeltaV1,
) -> OrderStateResultV1<()> {
    revalidate_prepared_order_block_v1(prepared).map_err(|_| {
        error(
            OrderStateErrorCodeV1::PreparedPlanMismatch,
            "recovered committed prepared plan failed exact revalidation",
        )
    })?;
    let [create] = prepared.system_creates() else {
        return Err(error(
            OrderStateErrorCodeV1::PreparedPlanMismatch,
            "recovered committed plan does not contain exactly one create",
        ));
    };
    let value_digest = digest(VALUE_DIGEST_DOMAIN, create.value_bytes());
    let expected_delta = CanonicalDeltaV1 {
        height: prepared.header().height,
        state_key: create.state_key(),
        object_kind: create.object_kind(),
        object_id: create.object_id(),
        object_version: create.object_version(),
        value_bytes: create.value_bytes().to_vec(),
        value_digest,
        delta_digest: delta_digest_v1(
            prepared.header().height,
            create.state_key(),
            create.object_id(),
            create.value_bytes(),
            value_digest,
        ),
    };
    if prepared.header().to_cev1_bytes() != block.header_cev1
        || prepared.block_id() != block.block_id
        || prepared.plan_digest() != block.plan_digest
        || prepared.post_state_root() != block.post_state_root
        || expected_delta != *delta
    {
        return Err(error(
            OrderStateErrorCodeV1::PreparedPlanMismatch,
            "recovered committed plan differs from durable header, root, plan, or delta",
        ));
    }
    Ok(())
}

fn seal_canonical_apply_v1(
    store_id: [u8; 32],
    audited: &CanonicalAuditV1,
    owner: &WholeNodeFinalizationOwnerV1,
    finality: &VerifiedOrderFinalityV1,
    prepared: &PreparedOrderBlockV1,
) -> OrderStateResultV1<(SealedCanonicalApplyV1, VerifiedOrderStateExecutionBindingV1)> {
    revalidate_prepared_order_block_v1(prepared).map_err(|_| {
        error(
            OrderStateErrorCodeV1::PreparedPlanMismatch,
            "canonical Order application preview failed exact revalidation",
        )
    })?;
    let header = prepared.header();
    let parent_block_id = match header.parent {
        ParentBlockRefV1::V1Block(block_id) => block_id,
        ParentBlockRefV1::Genesis { .. } => {
            return Err(error(
                OrderStateErrorCodeV1::PreparedPlanMismatch,
                "bounded canonical apply requires an exact v1 parent BlockId",
            ))
        }
    };
    let expected_height = audited.head.height.checked_add(1).ok_or_else(|| {
        error(
            OrderStateErrorCodeV1::ArithmeticOverflow,
            "canonical Order-state successor height overflows",
        )
    })?;
    if header.height != expected_height
        || parent_block_id != audited.head.block_id
        || prepared.parent_state_root() != audited.head.state_root
        || prepared.block_id() != derive_block_id_v1(header)
        || prepared.post_state_root() != header.post_state_root
    {
        return Err(error(
            OrderStateErrorCodeV1::PreparedPlanMismatch,
            "prepared Order block differs from the exact canonical parent/header/root",
        ));
    }
    if finality.chain_id() != header.context.chain_id
        || finality.genesis_hash() != header.context.genesis_hash
        || finality.protocol_version() != header.context.protocol_version
        || finality.stack_profile_hash() != header.context.stack_profile_hash
        || finality.epoch() != header.epoch
        || finality.finalized_height() != header.height
        || finality.finalized_block_id() != prepared.block_id().to_bytes()
        || finality.finalized_post_state_root() != prepared.post_state_root()
    {
        return Err(error(
            OrderStateErrorCodeV1::FinalityMismatch,
            "verified Order finality differs from the exact prepared target",
        ));
    }
    let [create] = prepared.system_creates() else {
        return Err(error(
            OrderStateErrorCodeV1::PreparedPlanMismatch,
            "bounded canonical apply requires exactly one tag-50 create",
        ));
    };
    let material = owner
        .derive_order_binding_create_material_v1(header.height)
        .map_err(|_| {
            error(
                OrderStateErrorCodeV1::PermitMismatch,
                "terminal owner cannot derive exact target-height tag-50 material",
            )
        })?;
    require_create_matches_material_v1(create, &material)?;
    if audited.leaves.contains_key(&create.state_key()) {
        return Err(error(
            OrderStateErrorCodeV1::DuplicateKey,
            "owner-backed tag-50 key already exists at canonical parent",
        ));
    }

    let value_digest = digest(VALUE_DIGEST_DOMAIN, create.value_bytes());
    let delta_digest = delta_digest_v1(
        header.height,
        create.state_key(),
        create.object_id(),
        create.value_bytes(),
        value_digest,
    );
    let delta = CanonicalDeltaV1 {
        height: header.height,
        state_key: create.state_key(),
        object_kind: create.object_kind(),
        object_id: create.object_id(),
        object_version: create.object_version(),
        value_bytes: create.value_bytes().to_vec(),
        value_digest,
        delta_digest,
    };
    let mut target_leaves = audited.leaves.clone();
    target_leaves.insert(
        create.state_key(),
        CanonicalLeafV1 {
            object_kind: create.object_kind(),
            object_id: create.object_id(),
            object_version: create.object_version(),
            value_bytes: create.value_bytes().to_vec(),
            created_height: header.height,
            block_checksum: [0; 32],
        },
    );
    let (target_root, siblings) =
        sparse_root_and_siblings_v1(&target_leaves, Some(create.state_key()))?;
    if target_root != prepared.post_state_root() {
        return Err(error(
            OrderStateErrorCodeV1::PreparedPlanMismatch,
            "prepared post-state root differs from canonical durable parent plus delta",
        ));
    }
    let target_proof = OrderStateMembershipProofV1 {
        height: header.height,
        state_root: target_root,
        state_tree_version: STATE_TREE_VERSION,
        object_kind: create.object_kind(),
        object_id: create.object_id(),
        object_version: create.object_version(),
        state_key: create.state_key(),
        value_bytes: create.value_bytes().to_vec(),
        siblings,
    };
    if !verify_order_state_membership_proof_v1(&target_proof) {
        return Err(error(
            OrderStateErrorCodeV1::MembershipInvalid,
            "precommit canonical target membership proof failed",
        ));
    }
    let binding = verify_order_state_execution_binding_receipt_v1(
        finality,
        OrderStateExecutionBindingReceiptProofV1 {
            materialized_height: target_proof.height(),
            materialized_state_root: target_proof.state_root(),
            state_tree_version: target_proof.state_tree_version(),
            object_kind: target_proof.object_kind(),
            object_id: target_proof.object_id(),
            object_version: target_proof.object_version(),
            state_key: target_proof.state_key(),
            value_bytes: target_proof.value_bytes(),
            siblings: target_proof.siblings(),
        },
    )
    .map_err(|_| {
        error(
            OrderStateErrorCodeV1::FinalityMismatch,
            "target finality does not prove the exact owner-backed membership and ancestry",
        )
    })?;

    let header_cev1 = header.to_cev1_bytes();
    if header_cev1.is_empty() || header_cev1.len() > MAX_HEADER_BYTES {
        return Err(error(
            OrderStateErrorCodeV1::PreparedPlanMismatch,
            "canonical Order header exceeds durable input bound",
        ));
    }
    let permit_digest = permit_digest_v1(
        store_id,
        &audited.head,
        prepared.block_id(),
        &header_cev1,
        prepared.plan_digest(),
        prepared.post_state_root(),
        finality.pinned_trust_sha256(),
        finality.proof_id(),
        owner.candidate_height(),
        owner.candidate_block_id().0,
        owner.final_execution_root().0,
        delta_digest,
    );
    let mut block = CanonicalBlockRecordV1 {
        height: header.height,
        parent_height: audited.head.height,
        parent_block_id: audited.head.block_id,
        parent_root: audited.head.state_root,
        block_id: prepared.block_id(),
        header_cev1,
        plan_digest: prepared.plan_digest(),
        post_state_root: prepared.post_state_root(),
        pinned_trust_sha256: finality.pinned_trust_sha256(),
        order_proof_id: finality.proof_id(),
        candidate_height: owner.candidate_height(),
        candidate_block_id: owner.candidate_block_id().0,
        final_execution_root: owner.final_execution_root().0,
        permit_digest,
        delta_digest,
        predecessor_checksum: audited.head.history_checksum,
        checksum: [0; 32],
    };
    block.checksum = block_checksum_v1(store_id, &block);
    let block_checksum = block.checksum;
    let mut proof = target_proof;
    target_leaves
        .get_mut(&delta.state_key)
        .expect("just inserted canonical target leaf")
        .block_checksum = block_checksum;
    // The block checksum is deliberately not part of the sparse leaf hash.
    // Replacing it is nevertheless detected by the complete live projection
    // audit against the block row below.
    proof.state_root = target_root;
    Ok((
        SealedCanonicalApplyV1 {
            store_id,
            expected_parent: audited.head.clone(),
            block,
            delta,
            target_proof: proof,
        },
        binding,
    ))
}

fn revalidate_permit_v1(permit: &CanonicalFinalizedOrderApplyPermitV1) -> OrderStateResultV1<()> {
    revalidate_prepared_order_block_v1(&permit.prepared).map_err(|_| {
        error(
            OrderStateErrorCodeV1::PreparedPlanMismatch,
            "retained canonical prepared plan failed revalidation",
        )
    })?;
    let header = permit.prepared.header();
    let [create] = permit.prepared.system_creates() else {
        return Err(error(
            OrderStateErrorCodeV1::PreparedPlanMismatch,
            "retained canonical plan no longer has exactly one create",
        ));
    };
    let material = permit
        .owner
        .derive_order_binding_create_material_v1(header.height)
        .map_err(|_| {
            error(
                OrderStateErrorCodeV1::PermitMismatch,
                "retained terminal owner no longer derives target material",
            )
        })?;
    require_create_matches_material_v1(create, &material)?;
    let sealed = &permit.sealed;
    let expected_parent_id = match header.parent {
        ParentBlockRefV1::V1Block(block_id) => block_id,
        ParentBlockRefV1::Genesis { .. } => {
            return Err(error(
                OrderStateErrorCodeV1::PreparedPlanMismatch,
                "retained canonical plan has a non-v1 parent",
            ))
        }
    };
    let value_digest = digest(VALUE_DIGEST_DOMAIN, create.value_bytes());
    let expected_delta = CanonicalDeltaV1 {
        height: header.height,
        state_key: create.state_key(),
        object_kind: create.object_kind(),
        object_id: create.object_id(),
        object_version: create.object_version(),
        value_bytes: create.value_bytes().to_vec(),
        value_digest,
        delta_digest: delta_digest_v1(
            header.height,
            create.state_key(),
            create.object_id(),
            create.value_bytes(),
            value_digest,
        ),
    };
    let header_cev1 = header.to_cev1_bytes();
    let expected_permit_digest = permit_digest_v1(
        sealed.store_id,
        &sealed.expected_parent,
        permit.prepared.block_id(),
        &header_cev1,
        permit.prepared.plan_digest(),
        permit.prepared.post_state_root(),
        permit.finality.pinned_trust_sha256(),
        permit.finality.proof_id(),
        permit.owner.candidate_height(),
        permit.owner.candidate_block_id().0,
        permit.owner.final_execution_root().0,
        expected_delta.delta_digest,
    );
    if permit.finality.chain_id() != header.context.chain_id
        || permit.finality.genesis_hash() != header.context.genesis_hash
        || permit.finality.protocol_version() != header.context.protocol_version
        || permit.finality.stack_profile_hash() != header.context.stack_profile_hash
        || permit.finality.epoch() != header.epoch
        || permit.finality.finalized_height() != header.height
        || permit.finality.finalized_block_id() != permit.prepared.block_id().to_bytes()
        || permit.finality.finalized_post_state_root() != permit.prepared.post_state_root()
        || expected_parent_id != sealed.expected_parent.block_id
        || permit.prepared.parent_state_root() != sealed.expected_parent.state_root
        || expected_delta != sealed.delta
        || sealed.block.height != header.height
        || sealed.block.parent_height != sealed.expected_parent.height
        || sealed.block.parent_block_id != sealed.expected_parent.block_id
        || sealed.block.parent_root != sealed.expected_parent.state_root
        || sealed.block.block_id != permit.prepared.block_id()
        || sealed.block.header_cev1 != header_cev1
        || sealed.block.plan_digest != permit.prepared.plan_digest()
        || sealed.block.post_state_root != permit.prepared.post_state_root()
        || sealed.block.pinned_trust_sha256 != permit.finality.pinned_trust_sha256()
        || sealed.block.order_proof_id != permit.finality.proof_id()
        || sealed.block.candidate_height != permit.owner.candidate_height()
        || sealed.block.candidate_block_id != permit.owner.candidate_block_id().0
        || sealed.block.final_execution_root != permit.owner.final_execution_root().0
        || sealed.block.permit_digest != expected_permit_digest
        || sealed.block.delta_digest != expected_delta.delta_digest
        || sealed.block.predecessor_checksum != sealed.expected_parent.history_checksum
        || sealed.block.checksum != block_checksum_v1(sealed.store_id, &sealed.block)
        || sealed.target_proof.height() != sealed.block.height
        || sealed.target_proof.state_root() != sealed.block.post_state_root
        || sealed.target_proof.state_key() != sealed.delta.state_key
        || sealed.target_proof.value_bytes() != sealed.delta.value_bytes
        || !verify_order_state_membership_proof_v1(&sealed.target_proof)
    {
        return Err(error(
            OrderStateErrorCodeV1::PermitMismatch,
            "canonical finalized apply permit failed exact revalidation",
        ));
    }
    Ok(())
}

fn require_create_matches_material_v1(
    create: &trnm_poco_order_application_v1::PreparedSystemObjectCreateV1,
    material: &GlobalExecutionBindingCreateMaterialV1,
) -> OrderStateResultV1<()> {
    if create.object_kind() != OBJECT_KIND
        || create.object_kind() != material.object_kind()
        || create.object_id() != material.object_id()
        || create.object_version() != OBJECT_VERSION
        || create.object_version() != material.object_version()
        || create.state_key() != material.state_key()
        || create.value_bytes() != material.value_bytes()
    {
        return Err(error(
            OrderStateErrorCodeV1::PermitMismatch,
            "prepared tag-50 create differs from exact retained terminal owner material",
        ));
    }
    Ok(())
}

fn audit_connection_v1(
    connection: &Connection,
    expected_store_id: [u8; 32],
) -> OrderStateResultV1<CanonicalAuditV1> {
    verify_schema_v1(connection)?;
    let metadata = connection.query_row(
        "SELECT store_id,anchor_height,anchor_block_id,anchor_root,head_height,head_block_id,head_root,head_checksum,fenced FROM canonical_order_state_metadata_v1 WHERE singleton=1",
        [],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, i64>(8)?,
            ))
        },
    )?;
    let store_id = array32(&metadata.0, "canonical store ID")?;
    let anchor_height = be_u64(&metadata.1, "canonical anchor height")?;
    let anchor_block_id = BlockIdV1::new(array32(&metadata.2, "canonical anchor BlockId")?);
    let anchor_root = array32(&metadata.3, "canonical anchor root")?;
    let head = CanonicalOrderStateHeadPinV1 {
        store_id,
        height: be_u64(&metadata.4, "canonical head height")?,
        block_id: BlockIdV1::new(array32(&metadata.5, "canonical head BlockId")?),
        state_root: array32(&metadata.6, "canonical head root")?,
        history_checksum: array32(&metadata.7, "canonical head checksum")?,
    };
    if store_id != expected_store_id
        || store_id == [0; 32]
        || anchor_height == 0
        || anchor_block_id.to_bytes() == [0; 32]
        || anchor_root != empty_state_root_v1()
        || metadata.8 != 0
    {
        return Err(error(
            OrderStateErrorCodeV1::StoreTamper,
            "canonical Order-state metadata is invalid or fenced",
        ));
    }

    let mut blocks_statement = connection.prepare(
        "SELECT height,parent_height,parent_block_id,parent_root,block_id,header_cev1,plan_digest,post_state_root,pinned_trust_sha256,order_proof_id,candidate_height,candidate_block_id,final_execution_root,permit_digest,delta_digest,predecessor_checksum,checksum FROM canonical_order_state_blocks_v1 ORDER BY height",
    )?;
    let block_rows = blocks_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, Vec<u8>>(10)?,
                row.get::<_, Vec<u8>>(11)?,
                row.get::<_, Vec<u8>>(12)?,
                row.get::<_, Vec<u8>>(13)?,
                row.get::<_, Vec<u8>>(14)?,
                row.get::<_, Vec<u8>>(15)?,
                row.get::<_, Vec<u8>>(16)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut blocks = BTreeMap::new();
    for row in block_rows {
        let record = CanonicalBlockRecordV1 {
            height: be_u64(&row.0, "canonical block height")?,
            parent_height: be_u64(&row.1, "canonical parent height")?,
            parent_block_id: BlockIdV1::new(array32(&row.2, "canonical parent BlockId")?),
            parent_root: array32(&row.3, "canonical parent root")?,
            block_id: BlockIdV1::new(array32(&row.4, "canonical block ID")?),
            header_cev1: row.5,
            plan_digest: array32(&row.6, "canonical plan digest")?,
            post_state_root: array32(&row.7, "canonical post-state root")?,
            pinned_trust_sha256: array32(&row.8, "canonical trust digest")?,
            order_proof_id: array32(&row.9, "canonical Order proof ID")?,
            candidate_height: be_u64(&row.10, "canonical candidate height")?,
            candidate_block_id: array32(&row.11, "canonical candidate BlockId")?,
            final_execution_root: array32(&row.12, "canonical final execution root")?,
            permit_digest: array32(&row.13, "canonical permit digest")?,
            delta_digest: array32(&row.14, "canonical delta digest")?,
            predecessor_checksum: array32(&row.15, "canonical predecessor checksum")?,
            checksum: array32(&row.16, "canonical block checksum")?,
        };
        let height = record.height;
        if blocks.insert(height, record).is_some() {
            return Err(error(
                OrderStateErrorCodeV1::StoreTamper,
                "canonical block history contains a duplicate height",
            ));
        }
    }

    let mut deltas_statement = connection.prepare(
        "SELECT height,ordinal,state_key,object_kind,object_id,object_version,value_bytes,value_digest,delta_digest FROM canonical_order_state_deltas_v1 ORDER BY height,ordinal",
    )?;
    let delta_rows = deltas_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut deltas = BTreeMap::new();
    for row in delta_rows {
        let height = be_u64(&row.0, "canonical delta height")?;
        let delta = CanonicalDeltaV1 {
            height,
            state_key: array32(&row.2, "canonical delta state key")?,
            object_kind: u16::try_from(row.3).map_err(|_| {
                error(
                    OrderStateErrorCodeV1::StoreTamper,
                    "canonical delta object kind exceeds u16",
                )
            })?,
            object_id: array32(&row.4, "canonical delta object ID")?,
            object_version: be_u64(&row.5, "canonical delta object version")?,
            value_bytes: row.6,
            value_digest: array32(&row.7, "canonical value digest")?,
            delta_digest: array32(&row.8, "canonical stored delta digest")?,
        };
        if row.1 != 0 || deltas.insert(height, delta).is_some() {
            return Err(error(
                OrderStateErrorCodeV1::StoreTamper,
                "canonical block does not have exactly one ordinal-zero delta",
            ));
        }
    }

    let mut leaves_statement = connection.prepare(
        "SELECT state_key,object_kind,object_id,object_version,value_bytes,created_height,block_checksum FROM canonical_order_state_leaves_v1 ORDER BY state_key",
    )?;
    let leaf_rows = leaves_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut stored_leaves = BTreeMap::new();
    for row in leaf_rows {
        let state_key = array32(&row.0, "canonical live state key")?;
        let leaf = CanonicalLeafV1 {
            object_kind: u16::try_from(row.1).map_err(|_| {
                error(
                    OrderStateErrorCodeV1::StoreTamper,
                    "canonical live object kind exceeds u16",
                )
            })?,
            object_id: array32(&row.2, "canonical live object ID")?,
            object_version: be_u64(&row.3, "canonical live object version")?,
            value_bytes: row.4,
            created_height: be_u64(&row.5, "canonical live created height")?,
            block_checksum: array32(&row.6, "canonical live block checksum")?,
        };
        if stored_leaves.insert(state_key, leaf).is_some() {
            return Err(error(
                OrderStateErrorCodeV1::StoreTamper,
                "canonical live leaves contain a duplicate key",
            ));
        }
    }

    if blocks.len() != deltas.len() {
        return Err(error(
            OrderStateErrorCodeV1::StoreTamper,
            "canonical block and delta inventories differ",
        ));
    }
    let mut expected_height = anchor_height;
    let mut expected_block_id = anchor_block_id;
    let mut expected_root = anchor_root;
    let mut expected_checksum =
        anchor_checksum_v1(store_id, anchor_height, anchor_block_id, anchor_root);
    let mut reconstructed_leaves = BTreeMap::new();
    for (height, block) in &blocks {
        let target_height = expected_height.checked_add(1).ok_or_else(|| {
            error(
                OrderStateErrorCodeV1::ArithmeticOverflow,
                "canonical history height overflows",
            )
        })?;
        let delta = deltas.get(height).ok_or_else(|| {
            error(
                OrderStateErrorCodeV1::StoreTamper,
                "canonical block is missing its exact delta",
            )
        })?;
        let header = decode_block_header_v1(&block.header_cev1).map_err(|_| {
            error(
                OrderStateErrorCodeV1::StoreTamper,
                "canonical durable header fails exact CEV1 decode/re-encode",
            )
        })?;
        if block.header_cev1.len() > MAX_HEADER_BYTES
            || *height != target_height
            || block.height != target_height
            || block.parent_height != expected_height
            || block.parent_block_id != expected_block_id
            || block.parent_root != expected_root
            || block.predecessor_checksum != expected_checksum
            || header.height != block.height
            || header.parent != ParentBlockRefV1::V1Block(block.parent_block_id)
            || header.post_state_root != block.post_state_root
            || derive_block_id_v1(&header) != block.block_id
            || block.plan_digest == [0; 32]
            || block.pinned_trust_sha256 == [0; 32]
            || block.order_proof_id == [0; 32]
            || block.candidate_height == 0
            || block.candidate_height >= block.height
            || block.candidate_block_id == [0; 32]
            || block.final_execution_root == [0; 32]
            || block.permit_digest == [0; 32]
            || block.delta_digest != delta.delta_digest
            || block.checksum != block_checksum_v1(store_id, block)
            || delta.height != block.height
            || delta.object_kind != OBJECT_KIND
            || delta.object_version != OBJECT_VERSION
            || delta.object_id == [0; 32]
            || delta.value_bytes.is_empty()
            || delta.value_bytes.len() > MAX_VALUE_BYTES
            || delta.value_digest != digest(VALUE_DIGEST_DOMAIN, &delta.value_bytes)
            || delta.delta_digest
                != delta_digest_v1(
                    delta.height,
                    delta.state_key,
                    delta.object_id,
                    &delta.value_bytes,
                    delta.value_digest,
                )
            || reconstructed_leaves.contains_key(&delta.state_key)
        {
            return Err(error(
                OrderStateErrorCodeV1::StoreTamper,
                "canonical block/delta history failed exact successor audit",
            ));
        }
        reconstructed_leaves.insert(
            delta.state_key,
            CanonicalLeafV1 {
                object_kind: delta.object_kind,
                object_id: delta.object_id,
                object_version: delta.object_version,
                value_bytes: delta.value_bytes.clone(),
                created_height: delta.height,
                block_checksum: block.checksum,
            },
        );
        let (root, _) = sparse_root_and_siblings_v1(&reconstructed_leaves, None)?;
        if root != block.post_state_root {
            return Err(error(
                OrderStateErrorCodeV1::StoreTamper,
                "canonical history post-state root differs from reconstructed sparse JMT",
            ));
        }
        expected_height = block.height;
        expected_block_id = block.block_id;
        expected_root = block.post_state_root;
        expected_checksum = block.checksum;
    }
    if reconstructed_leaves != stored_leaves
        || head.height != expected_height
        || head.block_id != expected_block_id
        || head.state_root != expected_root
        || head.history_checksum != expected_checksum
    {
        return Err(error(
            OrderStateErrorCodeV1::StoreTamper,
            "canonical live projection or metadata head differs from complete history",
        ));
    }
    Ok(CanonicalAuditV1 {
        anchor_height,
        anchor_block_id,
        anchor_root,
        head,
        blocks,
        deltas,
        leaves: reconstructed_leaves,
    })
}

fn prove_membership_at_v1(
    audited: &CanonicalAuditV1,
    height: u64,
    state_key: [u8; 32],
) -> OrderStateResultV1<OrderStateMembershipProofV1> {
    if height <= audited.anchor_height || height > audited.head.height {
        return Err(error(
            OrderStateErrorCodeV1::MembershipInvalid,
            "canonical membership height is outside finalized history",
        ));
    }
    let mut leaves = BTreeMap::new();
    for (delta_height, delta) in &audited.deltas {
        if *delta_height > height {
            break;
        }
        leaves.insert(
            delta.state_key,
            CanonicalLeafV1 {
                object_kind: delta.object_kind,
                object_id: delta.object_id,
                object_version: delta.object_version,
                value_bytes: delta.value_bytes.clone(),
                created_height: delta.height,
                block_checksum: audited
                    .blocks
                    .get(delta_height)
                    .expect("audited block/delta inventory")
                    .checksum,
            },
        );
    }
    let leaf = leaves.get(&state_key).ok_or_else(|| {
        error(
            OrderStateErrorCodeV1::MembershipInvalid,
            "canonical finalized state key is absent at requested height",
        )
    })?;
    let (root, siblings) = sparse_root_and_siblings_v1(&leaves, Some(state_key))?;
    let record = audited.blocks.get(&height).ok_or_else(|| {
        error(
            OrderStateErrorCodeV1::StoreTamper,
            "canonical membership block record is absent",
        )
    })?;
    if root != record.post_state_root {
        return Err(error(
            OrderStateErrorCodeV1::StoreTamper,
            "canonical historical root differs during membership reconstruction",
        ));
    }
    Ok(OrderStateMembershipProofV1 {
        height,
        state_root: root,
        state_tree_version: STATE_TREE_VERSION,
        object_kind: leaf.object_kind,
        object_id: leaf.object_id,
        object_version: leaf.object_version,
        state_key,
        value_bytes: leaf.value_bytes.clone(),
        siblings,
    })
}

fn sparse_root_and_siblings_v1(
    leaves: &BTreeMap<[u8; 32], CanonicalLeafV1>,
    target: Option<[u8; 32]>,
) -> OrderStateResultV1<([u8; 32], Vec<[u8; 32]>)> {
    let empties = empty_hashes_v1();
    let mut current = leaves
        .iter()
        .map(|(state_key, leaf)| {
            (
                *state_key,
                state_leaf_hash_v1(
                    *state_key,
                    leaf.object_kind,
                    leaf.object_version,
                    &leaf.value_bytes,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut siblings = Vec::with_capacity(STATE_TREE_DEPTH);
    for (level, empty) in empties.iter().copied().enumerate().take(STATE_TREE_DEPTH) {
        let bit_index = 255 - level;
        if let Some(target_key) = target {
            let node_key = clear_low_bits(target_key, level);
            let mut sibling_key = node_key;
            toggle_bit(&mut sibling_key, bit_index);
            siblings.push(current.get(&sibling_key).copied().unwrap_or(empty));
        }
        let mut parent_keys = BTreeSet::new();
        for key in current.keys() {
            parent_keys.insert(clear_low_bits(*key, level + 1));
        }
        let mut next = BTreeMap::new();
        for parent in parent_keys {
            let mut right_key = parent;
            set_bit(&mut right_key, bit_index);
            let left = current.get(&parent).copied().unwrap_or(empty);
            let right = current.get(&right_key).copied().unwrap_or(empty);
            next.insert(parent, state_node_hash_v1(level, left, right));
        }
        current = next;
    }
    Ok((
        current
            .get(&[0; 32])
            .copied()
            .unwrap_or(empties[STATE_TREE_DEPTH]),
        siblings,
    ))
}

fn empty_state_root_v1() -> [u8; 32] {
    empty_hashes_v1()[STATE_TREE_DEPTH]
}

fn empty_hashes_v1() -> Vec<[u8; 32]> {
    let mut hashes = Vec::with_capacity(STATE_TREE_DEPTH + 1);
    hashes.push(digest(
        STATE_EMPTY_LEAF_DOMAIN,
        &STATE_TREE_VERSION.to_le_bytes(),
    ));
    for level in 0..STATE_TREE_DEPTH {
        hashes.push(state_node_hash_v1(level, hashes[level], hashes[level]));
    }
    hashes
}

fn state_leaf_hash_v1(
    state_key: [u8; 32],
    object_kind: u16,
    object_version: u64,
    value_bytes: &[u8],
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(46 + value_bytes.len());
    encoded.extend_from_slice(&state_key);
    encoded.extend_from_slice(&object_kind.to_le_bytes());
    encoded.extend_from_slice(&object_version.to_le_bytes());
    put_bytes(&mut encoded, value_bytes);
    digest(STATE_LEAF_DOMAIN, &encoded)
}

fn state_node_hash_v1(level: usize, left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(66);
    encoded.extend_from_slice(
        &u16::try_from(level)
            .expect("fixed canonical sparse-tree level fits u16")
            .to_le_bytes(),
    );
    encoded.extend_from_slice(&left);
    encoded.extend_from_slice(&right);
    digest(STATE_NODE_DOMAIN, &encoded)
}

fn clear_low_bits(mut key: [u8; 32], count: usize) -> [u8; 32] {
    for offset in 0..count {
        let bit_index = 255 - offset;
        key[bit_index / 8] &= !(1 << (7 - (bit_index % 8)));
    }
    key
}

fn set_bit(key: &mut [u8; 32], bit_index: usize) {
    key[bit_index / 8] |= 1 << (7 - (bit_index % 8));
}

fn toggle_bit(key: &mut [u8; 32], bit_index: usize) {
    key[bit_index / 8] ^= 1 << (7 - (bit_index % 8));
}

fn anchor_checksum_v1(
    store_id: [u8; 32],
    height: u64,
    block_id: BlockIdV1,
    root: [u8; 32],
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(106);
    encoded.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    encoded.extend_from_slice(&store_id);
    encoded.extend_from_slice(&height.to_le_bytes());
    encoded.extend_from_slice(block_id.as_bytes());
    encoded.extend_from_slice(&root);
    digest(ANCHOR_CHECKSUM_DOMAIN, &encoded)
}

#[allow(clippy::too_many_arguments)]
fn permit_digest_v1(
    store_id: [u8; 32],
    parent: &CanonicalOrderStateHeadPinV1,
    block_id: BlockIdV1,
    header_cev1: &[u8],
    plan_digest: [u8; 32],
    post_state_root: [u8; 32],
    pinned_trust_sha256: [u8; 32],
    order_proof_id: [u8; 32],
    candidate_height: u64,
    candidate_block_id: [u8; 32],
    final_execution_root: [u8; 32],
    delta_digest: [u8; 32],
) -> [u8; 32] {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    encoded.extend_from_slice(&store_id);
    encoded.extend_from_slice(&parent.height.to_le_bytes());
    encoded.extend_from_slice(parent.block_id.as_bytes());
    encoded.extend_from_slice(&parent.state_root);
    encoded.extend_from_slice(&parent.history_checksum);
    encoded.extend_from_slice(block_id.as_bytes());
    put_bytes(&mut encoded, header_cev1);
    encoded.extend_from_slice(&plan_digest);
    encoded.extend_from_slice(&post_state_root);
    encoded.extend_from_slice(&pinned_trust_sha256);
    encoded.extend_from_slice(&order_proof_id);
    encoded.extend_from_slice(&candidate_height.to_le_bytes());
    encoded.extend_from_slice(&candidate_block_id);
    encoded.extend_from_slice(&final_execution_root);
    encoded.extend_from_slice(&delta_digest);
    digest(PERMIT_DIGEST_DOMAIN, &encoded)
}

fn delta_digest_v1(
    height: u64,
    state_key: [u8; 32],
    object_id: [u8; 32],
    value_bytes: &[u8],
    value_digest: [u8; 32],
) -> [u8; 32] {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    encoded.extend_from_slice(&height.to_le_bytes());
    encoded.extend_from_slice(&0_u32.to_le_bytes());
    encoded.extend_from_slice(&state_key);
    encoded.extend_from_slice(&OBJECT_KIND.to_le_bytes());
    encoded.extend_from_slice(&object_id);
    encoded.extend_from_slice(&OBJECT_VERSION.to_le_bytes());
    put_bytes(&mut encoded, value_bytes);
    encoded.extend_from_slice(&value_digest);
    digest(DELTA_DIGEST_DOMAIN, &encoded)
}

fn block_checksum_v1(store_id: [u8; 32], block: &CanonicalBlockRecordV1) -> [u8; 32] {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    encoded.extend_from_slice(&store_id);
    encoded.extend_from_slice(&block.height.to_le_bytes());
    encoded.extend_from_slice(&block.parent_height.to_le_bytes());
    encoded.extend_from_slice(block.parent_block_id.as_bytes());
    encoded.extend_from_slice(&block.parent_root);
    encoded.extend_from_slice(block.block_id.as_bytes());
    put_bytes(&mut encoded, &block.header_cev1);
    encoded.extend_from_slice(&block.plan_digest);
    encoded.extend_from_slice(&block.post_state_root);
    encoded.extend_from_slice(&block.pinned_trust_sha256);
    encoded.extend_from_slice(&block.order_proof_id);
    encoded.extend_from_slice(&block.candidate_height.to_le_bytes());
    encoded.extend_from_slice(&block.candidate_block_id);
    encoded.extend_from_slice(&block.final_execution_root);
    encoded.extend_from_slice(&block.permit_digest);
    encoded.extend_from_slice(&block.delta_digest);
    encoded.extend_from_slice(&block.predecessor_checksum);
    digest(BLOCK_CHECKSUM_DOMAIN, &encoded)
}

fn digest(domain: &str, encoded: &[u8]) -> [u8; 32] {
    let domain = domain.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(
        u32::try_from(domain.len())
            .expect("static canonical domain length fits u32")
            .to_le_bytes(),
    );
    hasher.update(domain);
    hasher.update(encoded);
    hasher.finalize().into()
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .expect("bounded canonical CEV1 bytes fit u32")
            .to_le_bytes(),
    );
    output.extend_from_slice(value);
}

fn verify_schema_v1(connection: &Connection) -> OrderStateResultV1<()> {
    if connection.query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))?
        != SQLITE_APPLICATION_ID
        || connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?
            != SQLITE_USER_VERSION
    {
        return Err(error(
            OrderStateErrorCodeV1::SchemaMismatch,
            "canonical Order-state SQLite identity/schema differs",
        ));
    }
    let mut statement = connection.prepare(
        "SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let actual = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = vec![
        (
            "canonical_order_state_blocks_v1".to_owned(),
            BLOCKS_SQL.to_owned(),
        ),
        (
            "canonical_order_state_deltas_v1".to_owned(),
            DELTAS_SQL.to_owned(),
        ),
        (
            "canonical_order_state_leaves_v1".to_owned(),
            LEAVES_SQL.to_owned(),
        ),
        (
            "canonical_order_state_metadata_v1".to_owned(),
            METADATA_SQL.to_owned(),
        ),
    ];
    if actual != expected {
        return Err(error(
            OrderStateErrorCodeV1::SchemaMismatch,
            "canonical Order-state SQLite schema differs",
        ));
    }
    Ok(())
}

fn configure_rw(connection: &Connection) -> OrderStateResultV1<()> {
    connection.pragma_update(None, "journal_mode", "DELETE")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", true)?;
    Ok(())
}

fn open_rw_raw(path: &Path) -> OrderStateResultV1<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_secs(2))?;
    Ok(connection)
}

fn open_ro(path: &Path) -> OrderStateResultV1<Connection> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut uri = String::from("file:");
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'.' | b'_' | b'-') {
            uri.push(char::from(*byte));
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri.push_str("?mode=ro");
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )?;
    connection.busy_timeout(Duration::from_secs(2))?;
    Ok(connection)
}

fn validate_path(path: &Path, must_exist: bool) -> OrderStateResultV1<PathBuf> {
    if path.as_os_str().is_empty() || path.is_symlink() {
        return Err(unavailable(
            "canonical Order-state path is empty or a symlink".to_owned(),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        unavailable("canonical Order-state path has no parent directory".to_owned())
    })?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|cause| unavailable(format!("canonical store parent unavailable: {cause}")))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(unavailable(
            "canonical Order-state parent is not a direct directory".to_owned(),
        ));
    }
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|cause| unavailable(format!("canonical store parent cannot resolve: {cause}")))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| unavailable("canonical Order-state path has no file name".to_owned()))?;
    let resolved = canonical_parent.join(file_name);
    if must_exist {
        let metadata = fs::symlink_metadata(&resolved)
            .map_err(|cause| unavailable(format!("canonical store unavailable: {cause}")))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(unavailable(
                "canonical Order-state target is not a direct regular file".to_owned(),
            ));
        }
    } else if fs::symlink_metadata(&resolved).is_ok() {
        return Err(unavailable(
            "canonical Order-state target already exists".to_owned(),
        ));
    }
    Ok(resolved)
}

#[cfg(unix)]
fn file_identity(path: &Path) -> OrderStateResultV1<FileIdentityV1> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)
        .map_err(|cause| unavailable(format!("canonical store metadata unavailable: {cause}")))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(unavailable(
            "canonical Order-state file type/link-count/mode is invalid".to_owned(),
        ));
    }
    Ok(FileIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        links: metadata.nlink(),
        mode: metadata.permissions().mode() & 0o777,
    })
}

#[cfg(not(unix))]
fn file_identity(path: &Path) -> OrderStateResultV1<FileIdentityV1> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|cause| unavailable(format!("canonical store metadata unavailable: {cause}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(unavailable(
            "canonical Order-state target is not a direct regular file".to_owned(),
        ));
    }
    Ok(FileIdentityV1 {
        canonical_path: fs::canonicalize(path).map_err(|cause| {
            unavailable(format!("canonical store path cannot resolve: {cause}"))
        })?,
    })
}

fn reject_sidecars(path: &Path) -> OrderStateResultV1<()> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut value = OsString::from(path.as_os_str());
        value.push(suffix);
        if fs::symlink_metadata(PathBuf::from(value)).is_ok() {
            return Err(unavailable(format!(
                "canonical Order-state SQLite sidecar {suffix} is not permitted"
            )));
        }
    }
    Ok(())
}

fn array32(value: &[u8], label: &str) -> OrderStateResultV1<[u8; 32]> {
    value.try_into().map_err(|_| {
        error(
            OrderStateErrorCodeV1::StoreTamper,
            format!("{label} does not contain exactly 32 bytes"),
        )
    })
}

fn be_u64(value: &[u8], label: &str) -> OrderStateResultV1<u64> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| {
        error(
            OrderStateErrorCodeV1::StoreTamper,
            format!("{label} does not contain exactly 8 bytes"),
        )
    })?;
    Ok(u64::from_be_bytes(bytes))
}

fn require_nonzero(value: [u8; 32], label: &str) -> OrderStateResultV1<()> {
    if value == [0; 32] {
        return Err(error(
            OrderStateErrorCodeV1::InvalidContext,
            format!("{label} must be nonzero"),
        ));
    }
    Ok(())
}

fn unavailable(detail: String) -> crate::OrderStateErrorV1 {
    error(OrderStateErrorCodeV1::StoreUnavailable, detail)
}

#[cfg(test)]
mod tests {
    use rusqlite::{params, Connection};
    use tempfile::TempDir;
    use trnm_poco_order_application_v1::GlobalExecutionBindingInputV1;
    use trnm_poco_order_finality_verifier_v1::derive_global_execution_binding_create_material_v1;
    use trnm_poco_order_types_v1::{
        BlockHeaderV1, BlockKindV1, EpochDescriptorIdV1, G2CommandCommitmentV2, G2CommandPlaneV2,
        G2OrderedItemV2, G2OrderedRootKindV2, G2StateCreateV2, ProtocolContextV1,
        QuorumCertificateIdV1,
    };

    use super::*;

    const STORE_ID: [u8; 32] = [0xa7; 32];
    const ANCHOR_BLOCK_ID: BlockIdV1 = BlockIdV1::new([0x16; 32]);

    fn path(temp: &TempDir) -> PathBuf {
        temp.path().join("canonical-order-state.sqlite")
    }

    fn initialize() -> (
        TempDir,
        PocoCanonicalOrderStateStoreV1,
        CanonicalOrderStateHeadPinV1,
    ) {
        let temp = tempfile::tempdir().expect("canonical Order-state tempdir");
        let store = PocoCanonicalOrderStateStoreV1::initialize_new(
            path(&temp),
            STORE_ID,
            6,
            ANCHOR_BLOCK_ID,
        )
        .expect("initialize canonical Order-state store");
        let pin = store.fresh_head_pin_v1().expect("fresh canonical anchor");
        (temp, store, pin)
    }

    #[derive(Clone, Copy, Debug)]
    struct CandidateFactsV1 {
        height: u64,
        block_id: [u8; 32],
        composite_root: [u8; 32],
        final_execution_root: [u8; 32],
    }

    fn application_context() -> ProtocolContextV1 {
        ProtocolContextV1 {
            schema_version: 1,
            genesis_hash: [0x21; 32],
            chain_id: "trnm-canonical-order-state-test".to_owned(),
            protocol_version: 1,
            stack_profile_hash: [0x22; 32],
        }
    }

    fn application_template(parent: BlockIdV1, height: u64) -> OrderHeaderTemplateV1 {
        OrderHeaderTemplateV1 {
            schema_version: 1,
            context: application_context(),
            epoch: 1,
            view: height + 10,
            height,
            block_kind: BlockKindV1::Ordinary,
            parent: ParentBlockRefV1::V1Block(parent),
            proposer_id: b"validator-a".to_vec(),
            epoch_descriptor_id: EpochDescriptorIdV1::new([0x23; 32]),
            justify_qc_id: Some(QuorumCertificateIdV1::new([0x24; 32])),
            timeout_certificate_id: None,
            next_epoch_descriptor_id: None,
            upgrade_plan_id: None,
            epoch_handoff_id: None,
        }
    }

    fn candidate_facts(seed: u8, height: u64) -> CandidateFactsV1 {
        CandidateFactsV1 {
            height,
            block_id: [seed.wrapping_add(5); 32],
            composite_root: [seed.wrapping_add(6); 32],
            final_execution_root: [seed.wrapping_add(7); 32],
        }
    }

    fn application_binding(facts: CandidateFactsV1) -> GlobalExecutionBindingInputV1 {
        GlobalExecutionBindingInputV1::new(
            application_context(),
            facts.height,
            BlockIdV1::new(facts.block_id),
            facts.composite_root,
            facts.final_execution_root,
        )
        .expect("valid synthetic canonical application binding")
    }

    fn manifest_bound_order_material(
        parent: &CanonicalOrderStateHeadPinV1,
        seed: u8,
    ) -> (G2ManifestBoundInputV2, G2InertExecutionPlanV2) {
        let input = G2ManifestBoundInputV2::new(
            application_context(),
            [seed.max(1); 32],
            [seed.wrapping_add(1).max(1); 32],
            [seed.wrapping_add(2).max(1); 32],
            [seed.wrapping_add(3).max(1); 32],
            parent.height,
            parent.block_id,
            parent.state_root,
            parent.height + 1,
            [seed.wrapping_add(4).max(1); 32],
            [seed.wrapping_add(5).max(1); 32],
            [seed.wrapping_add(6).max(1); 32],
            vec![G2CommandCommitmentV2::new(
                G2CommandPlaneV2::MvccFee,
                0,
                3,
                [seed.wrapping_add(7).max(1); 32],
            )
            .expect("valid canonical G2 command")],
        )
        .expect("valid canonical G2 input");
        let plan = G2InertExecutionPlanV2::new(
            &input,
            vec![G2StateCreateV2::new(
                60,
                [seed.wrapping_add(8).max(1); 32],
                0,
                vec![seed.wrapping_add(9).max(1); 16],
            )
            .expect("valid canonical G2 create")],
            vec![G2OrderedItemV2::new(
                G2OrderedRootKindV2::TransactionExecutionReceipts,
                0,
                61,
                [seed.wrapping_add(10).max(1); 32],
                [seed.wrapping_add(11).max(1); 32],
            )
            .expect("valid canonical G2 receipt")],
        )
        .expect("valid canonical G2 plan");
        (input, plan)
    }

    fn sealed_from_prepared(
        store: &PocoCanonicalOrderStateStoreV1,
        parent: &CanonicalOrderStateHeadPinV1,
        prepared: &PreparedOrderBlockV1,
        facts: CandidateFactsV1,
        seed: u8,
    ) -> SealedCanonicalApplyV1 {
        let audited = store.audit_fresh().expect("audit prepared parent");
        assert_eq!(&audited.head, parent);
        let header = prepared.header();
        let [create] = prepared.system_creates() else {
            panic!("synthetic prepared successor has exactly one create")
        };
        let value_bytes = create.value_bytes().to_vec();
        let value_digest = digest(VALUE_DIGEST_DOMAIN, &value_bytes);
        let delta_digest = delta_digest_v1(
            header.height,
            create.state_key(),
            create.object_id(),
            &value_bytes,
            value_digest,
        );
        let delta = CanonicalDeltaV1 {
            height: header.height,
            state_key: create.state_key(),
            object_kind: create.object_kind(),
            object_id: create.object_id(),
            object_version: create.object_version(),
            value_bytes: value_bytes.clone(),
            value_digest,
            delta_digest,
        };
        let mut target_leaves = audited.leaves;
        target_leaves.insert(
            create.state_key(),
            CanonicalLeafV1 {
                object_kind: create.object_kind(),
                object_id: create.object_id(),
                object_version: create.object_version(),
                value_bytes: value_bytes.clone(),
                created_height: header.height,
                block_checksum: [0; 32],
            },
        );
        let (post_state_root, siblings) =
            sparse_root_and_siblings_v1(&target_leaves, Some(create.state_key()))
                .expect("derive exact prepared successor root");
        assert_eq!(post_state_root, prepared.post_state_root());
        let header_cev1 = header.to_cev1_bytes();
        let block_id = prepared.block_id();
        let pinned_trust_sha256 = [seed.wrapping_add(3); 32];
        let order_proof_id = [seed.wrapping_add(4); 32];
        let permit_digest = permit_digest_v1(
            STORE_ID,
            parent,
            block_id,
            &header_cev1,
            prepared.plan_digest(),
            post_state_root,
            pinned_trust_sha256,
            order_proof_id,
            facts.height,
            facts.block_id,
            facts.final_execution_root,
            delta_digest,
        );
        let mut block = CanonicalBlockRecordV1 {
            height: header.height,
            parent_height: parent.height,
            parent_block_id: parent.block_id,
            parent_root: parent.state_root,
            block_id,
            header_cev1,
            plan_digest: prepared.plan_digest(),
            post_state_root,
            pinned_trust_sha256,
            order_proof_id,
            candidate_height: facts.height,
            candidate_block_id: facts.block_id,
            final_execution_root: facts.final_execution_root,
            permit_digest,
            delta_digest,
            predecessor_checksum: parent.history_checksum,
            checksum: [0; 32],
        };
        block.checksum = block_checksum_v1(STORE_ID, &block);
        SealedCanonicalApplyV1 {
            store_id: STORE_ID,
            expected_parent: parent.clone(),
            block,
            delta,
            target_proof: OrderStateMembershipProofV1 {
                height: header.height,
                state_root: post_state_root,
                state_tree_version: STATE_TREE_VERSION,
                object_kind: create.object_kind(),
                object_id: create.object_id(),
                object_version: create.object_version(),
                state_key: create.state_key(),
                value_bytes,
                siblings,
            },
        }
    }

    fn commit_application_successor(
        store: &PocoCanonicalOrderStateStoreV1,
        parent: &CanonicalOrderStateHeadPinV1,
        seed: u8,
    ) -> CanonicalFinalizedOrderApplyReceiptV1 {
        let recovered = store
            .recover_order_application_parent_v1(parent)
            .expect("recover exact canonical application parent");
        let target_height = parent.height + 1;
        let facts = candidate_facts(seed, parent.height);
        let prepared = store
            .preview_next_from_recovered_parent_v1(
                &recovered,
                application_template(parent.block_id, target_height),
                &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                    application_binding(facts),
                )],
            )
            .expect("preview exact canonical application successor");
        let sealed = sealed_from_prepared(store, parent, &prepared, facts, seed);
        store
            .apply_sealed_inner_v1(&sealed, None)
            .expect("commit synthetic canonical application successor")
    }

    fn sealed_successor(
        store: &PocoCanonicalOrderStateStoreV1,
        parent: &CanonicalOrderStateHeadPinV1,
        seed: u8,
    ) -> SealedCanonicalApplyV1 {
        let audited = store.audit_fresh().expect("audit synthetic parent");
        assert_eq!(&audited.head, parent);
        let height = parent.height + 1;
        let chain_id = "trnm-canonical-order-state-test";
        let genesis_hash = [0x21; 32];
        let protocol_version = 1;
        let stack_profile_hash = [0x22; 32];
        let candidate_height = parent.height;
        let candidate_block_id = [seed.wrapping_add(5); 32];
        let candidate_composite_root = [seed.wrapping_add(6); 32];
        let final_execution_root = [seed.wrapping_add(7); 32];
        let material = derive_global_execution_binding_create_material_v1(
            chain_id,
            genesis_hash,
            protocol_version,
            stack_profile_hash,
            candidate_height,
            candidate_block_id,
            candidate_composite_root,
            final_execution_root,
            height,
        )
        .expect("derive valid synthetic tag-50 material");
        let state_key = material.state_key();
        let object_id = material.object_id();
        let value_bytes = material.value_bytes().to_vec();
        let value_digest = digest(VALUE_DIGEST_DOMAIN, &value_bytes);
        let delta_digest =
            delta_digest_v1(height, state_key, object_id, &value_bytes, value_digest);
        let delta = CanonicalDeltaV1 {
            height,
            state_key,
            object_kind: OBJECT_KIND,
            object_id,
            object_version: OBJECT_VERSION,
            value_bytes: value_bytes.clone(),
            value_digest,
            delta_digest,
        };
        let mut target_leaves = audited.leaves;
        target_leaves.insert(
            state_key,
            CanonicalLeafV1 {
                object_kind: OBJECT_KIND,
                object_id,
                object_version: OBJECT_VERSION,
                value_bytes: value_bytes.clone(),
                created_height: height,
                block_checksum: [0; 32],
            },
        );
        let (post_state_root, siblings) =
            sparse_root_and_siblings_v1(&target_leaves, Some(state_key))
                .expect("derive synthetic successor root");
        let header = BlockHeaderV1 {
            schema_version: 1,
            context: ProtocolContextV1 {
                schema_version: 1,
                genesis_hash,
                chain_id: chain_id.to_owned(),
                protocol_version,
                stack_profile_hash,
            },
            epoch: 1,
            view: height + 10,
            height,
            block_kind: BlockKindV1::Ordinary,
            parent: ParentBlockRefV1::V1Block(parent.block_id),
            proposer_id: b"validator-a".to_vec(),
            epoch_descriptor_id: EpochDescriptorIdV1::new([0x23; 32]),
            justify_qc_id: Some(QuorumCertificateIdV1::new([0x24; 32])),
            timeout_certificate_id: None,
            batch_refs_root: [0x25; 32],
            protocol_objects_root: [0x26; 32],
            post_state_root,
            transaction_execution_receipts_root: [0x27; 32],
            evidence_root: [0x28; 32],
            consumption_rollups_root: [0x29; 32],
            settlement_root: [0x2a; 32],
            resource_usage_root: [0x2b; 32],
            next_epoch_descriptor_id: None,
            upgrade_plan_id: None,
            epoch_handoff_id: None,
        };
        let header_cev1 = header.to_cev1_bytes();
        let block_id = derive_block_id_v1(&header);
        let plan_digest = digest("trnm.poco-ai.test-canonical-plan.v1", &[seed]);
        let pinned_trust_sha256 = [seed.wrapping_add(3); 32];
        let order_proof_id = [seed.wrapping_add(4); 32];
        let permit_digest = permit_digest_v1(
            STORE_ID,
            parent,
            block_id,
            &header_cev1,
            plan_digest,
            post_state_root,
            pinned_trust_sha256,
            order_proof_id,
            candidate_height,
            candidate_block_id,
            final_execution_root,
            delta_digest,
        );
        let mut block = CanonicalBlockRecordV1 {
            height,
            parent_height: parent.height,
            parent_block_id: parent.block_id,
            parent_root: parent.state_root,
            block_id,
            header_cev1,
            plan_digest,
            post_state_root,
            pinned_trust_sha256,
            order_proof_id,
            candidate_height,
            candidate_block_id,
            final_execution_root,
            permit_digest,
            delta_digest,
            predecessor_checksum: parent.history_checksum,
            checksum: [0; 32],
        };
        block.checksum = block_checksum_v1(STORE_ID, &block);
        SealedCanonicalApplyV1 {
            store_id: STORE_ID,
            expected_parent: parent.clone(),
            block,
            delta,
            target_proof: OrderStateMembershipProofV1 {
                height,
                state_root: post_state_root,
                state_tree_version: STATE_TREE_VERSION,
                object_kind: OBJECT_KIND,
                object_id,
                object_version: OBJECT_VERSION,
                state_key,
                value_bytes,
                siblings,
            },
        }
    }

    #[test]
    fn canonical_cas_faults_exact_retry_and_fork_fail_closed() {
        let (temp, store, anchor) = initialize();
        let exact = sealed_successor(&store, &anchor, 0x31);
        let fork = sealed_successor(&store, &anchor, 0x41);

        assert_eq!(
            store
                .apply_sealed_inner_v1(&exact, Some(CanonicalOrderApplyFaultV1::BeforeCommit))
                .expect_err("precommit loss rolls back")
                .code(),
            OrderStateErrorCodeV1::CommitUncertain
        );
        assert_eq!(
            store.fresh_head_pin_v1().expect("head after rollback"),
            anchor
        );
        assert_eq!(
            store
                .apply_sealed_inner_v1(
                    &exact,
                    Some(CanonicalOrderApplyFaultV1::AfterCommitBeforeReturn),
                )
                .expect_err("postcommit acknowledgement loss")
                .code(),
            OrderStateErrorCodeV1::CommitUncertain
        );
        let receipt = store
            .apply_sealed_inner_v1(&exact, None)
            .expect("exact retry reopens committed target");
        assert!(receipt.is_replay());
        assert!(verify_order_state_membership_proof_v1(receipt.proof()));
        assert_eq!(
            store
                .apply_sealed_inner_v1(&fork, None)
                .expect_err("different target at occupied height is a fork")
                .code(),
            OrderStateErrorCodeV1::Fork
        );
        PocoCanonicalOrderStateStoreV1::open_existing_pinned(path(&temp), STORE_ID, receipt.pin())
            .expect("exact pinned fresh reopen");
    }

    #[test]
    fn canonical_parent_recovery_supports_consecutive_application_heights() {
        let (temp, store, anchor) = initialize();

        let first = commit_application_successor(&store, &anchor, 0x31);
        assert_eq!(first.pin().height(), anchor.height() + 1);
        let second = commit_application_successor(&store, first.pin(), 0x41);
        assert_eq!(second.pin().height(), anchor.height() + 2);

        let recovered = store
            .recover_order_application_parent_v1(second.pin())
            .expect("recover second durable canonical application parent");
        assert_eq!(recovered.pin(), second.pin());
        let facts = candidate_facts(0x51, second.pin().height());
        let third = store
            .preview_next_from_recovered_parent_v1(
                &recovered,
                application_template(second.pin().block_id(), second.pin().height() + 1),
                &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                    application_binding(facts),
                )],
            )
            .expect("preview third consecutive application height");
        assert_eq!(third.header().height, anchor.height() + 3);
        assert_eq!(
            third.header().parent,
            ParentBlockRefV1::V1Block(second.pin().block_id())
        );
        assert_eq!(third.parent_state_root(), second.pin().state_root());
        PocoCanonicalOrderStateStoreV1::open_existing_pinned(path(&temp), STORE_ID, second.pin())
            .expect("fresh reopen retains exact recovered-parent head");
    }

    #[test]
    fn canonical_manifest_bound_g2_seal_uses_fresh_recovered_durable_parent() {
        let (_temp, store, anchor) = initialize();
        let first = commit_application_successor(&store, &anchor, 0x31);
        let durable_parent_pin = first.pin().clone();
        let recovered = store
            .recover_order_application_parent_v1(&durable_parent_pin)
            .expect("recover real durable canonical parent");
        let (input, plan) = manifest_bound_order_material(&durable_parent_pin, 0x51);
        let head_before = store.fresh_head_pin_v1().expect("head before G2 seal");
        let sealed = store
            .seal_manifest_bound_g2_from_recovered_parent_v2(
                &recovered,
                application_template(durable_parent_pin.block_id, durable_parent_pin.height + 1),
                input,
                plan,
            )
            .expect("fresh recovered durable parent seals exact G2 successor");
        assert_eq!(sealed.header().height, durable_parent_pin.height + 1);
        assert_eq!(
            sealed.header().parent,
            ParentBlockRefV1::V1Block(durable_parent_pin.block_id)
        );
        assert_ne!(
            sealed.header().post_state_root,
            durable_parent_pin.state_root
        );
        assert_eq!(
            store.fresh_head_pin_v1().expect("head after inert G2 seal"),
            head_before,
            "the recovered-parent G2 seam is no-write planning only",
        );

        let stale_parent = store
            .recover_order_application_parent_v1(&durable_parent_pin)
            .expect("recover parent before competing canonical successor");
        let (stale_input, stale_plan) = manifest_bound_order_material(&durable_parent_pin, 0x61);
        let second = commit_application_successor(&store, &durable_parent_pin, 0x41);
        assert_eq!(second.pin().height(), durable_parent_pin.height + 1);
        assert_eq!(
            store
                .seal_manifest_bound_g2_from_recovered_parent_v2(
                    &stale_parent,
                    application_template(
                        durable_parent_pin.block_id,
                        durable_parent_pin.height + 1,
                    ),
                    stale_input,
                    stale_plan,
                )
                .expect_err("stale recovered parent cannot seal after head advancement")
                .code(),
            OrderStateErrorCodeV1::StoreRollback,
        );
    }

    #[test]
    fn committed_prepared_recovery_is_no_write_and_rejects_pin_plan_and_delta_substitution() {
        let (temp, store, anchor) = initialize();
        let seed = 0x91;
        let committed = commit_application_successor(&store, &anchor, seed);
        let target = committed.pin().clone();
        let before = fs::read(path(&temp)).expect("read canonical bytes before no-write recovery");
        let facts = candidate_facts(seed, anchor.height());
        let prepared = store
            .recover_committed_prepared_order_block_v1(
                &anchor,
                &target,
                application_template(anchor.block_id(), target.height()),
                &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                    application_binding(facts),
                )],
            )
            .expect("fresh target reconstructs exact committed prepared plan");
        assert_eq!(prepared.header().height, target.height());
        assert_eq!(prepared.block_id(), target.block_id());
        assert_eq!(prepared.post_state_root(), target.state_root());
        assert_eq!(
            fs::read(path(&temp)).expect("read canonical bytes after no-write recovery"),
            before,
        );
        assert_eq!(
            store
                .fresh_head_pin_v1()
                .expect("head after no-write recovery"),
            target,
        );

        let mut parent_fork = anchor.clone();
        parent_fork.block_id = BlockIdV1::new([0xd1; 32]);
        assert_eq!(
            store
                .recover_committed_prepared_order_block_v1(
                    &parent_fork,
                    &target,
                    application_template(anchor.block_id(), target.height()),
                    &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                        application_binding(facts),
                    )],
                )
                .expect_err("forked parent pin rejects")
                .code(),
            OrderStateErrorCodeV1::StoreRollback,
        );

        let mut target_fork = target.clone();
        target_fork.history_checksum[0] ^= 1;
        assert_eq!(
            store
                .recover_committed_prepared_order_block_v1(
                    &anchor,
                    &target_fork,
                    application_template(anchor.block_id(), target.height()),
                    &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                        application_binding(facts),
                    )],
                )
                .expect_err("forked target pin rejects")
                .code(),
            OrderStateErrorCodeV1::StoreRollback,
        );

        let mut foreign_parent = anchor.clone();
        foreign_parent.store_id[0] ^= 1;
        assert_eq!(
            store
                .recover_committed_prepared_order_block_v1(
                    &foreign_parent,
                    &target,
                    application_template(anchor.block_id(), target.height()),
                    &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                        application_binding(facts),
                    )],
                )
                .expect_err("foreign parent store rejects")
                .code(),
            OrderStateErrorCodeV1::StoreRollback,
        );

        let mut alternate_template = application_template(anchor.block_id(), target.height());
        alternate_template.view += 1;
        assert_eq!(
            store
                .recover_committed_prepared_order_block_v1(
                    &anchor,
                    &target,
                    alternate_template,
                    &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                        application_binding(facts),
                    )],
                )
                .expect_err("header/plan substitution rejects")
                .code(),
            OrderStateErrorCodeV1::PreparedPlanMismatch,
        );

        let alternate_facts = candidate_facts(seed.wrapping_add(1), anchor.height());
        assert_eq!(
            store
                .recover_committed_prepared_order_block_v1(
                    &anchor,
                    &target,
                    application_template(anchor.block_id(), target.height()),
                    &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                        application_binding(alternate_facts),
                    )],
                )
                .expect_err("durable delta substitution rejects")
                .code(),
            OrderStateErrorCodeV1::PreparedPlanMismatch,
        );
    }

    #[test]
    fn committed_prepared_recovery_reconstructs_a_non_anchor_exact_predecessor() {
        let (_temp, store, anchor) = initialize();
        let first = commit_application_successor(&store, &anchor, 0xa1);
        let first_pin = first.pin().clone();
        let second_seed = 0xb1;
        let second = commit_application_successor(&store, &first_pin, second_seed);
        let second_pin = second.pin().clone();
        let second_facts = candidate_facts(second_seed, first_pin.height());
        let prepared = store
            .recover_committed_prepared_order_block_v1(
                &first_pin,
                &second_pin,
                application_template(first_pin.block_id(), second_pin.height()),
                &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                    application_binding(second_facts),
                )],
            )
            .expect("fresh target reconstructs durable non-anchor predecessor");
        assert_eq!(prepared.parent_state_root(), first_pin.state_root());
        assert_eq!(prepared.block_id(), second_pin.block_id());
        assert_eq!(prepared.post_state_root(), second_pin.state_root());
        assert_eq!(
            store
                .fresh_head_pin_v1()
                .expect("head remains second target"),
            second_pin,
        );
    }

    #[test]
    fn canonical_parent_recovery_rejects_fork_foreign_store_tamper_and_rollback() {
        let (temp, store, anchor) = initialize();

        let mut fork_pin = anchor.clone();
        fork_pin.block_id = BlockIdV1::new([0xf1; 32]);
        assert_eq!(
            store
                .recover_order_application_parent_v1(&fork_pin)
                .expect_err("forked external head pin rejects")
                .code(),
            OrderStateErrorCodeV1::StoreRollback,
        );

        let foreign_path = temp.path().join("foreign-canonical-order-state.sqlite");
        let foreign_store_id = [0xb8; 32];
        let foreign = PocoCanonicalOrderStateStoreV1::initialize_new(
            &foreign_path,
            foreign_store_id,
            anchor.height(),
            anchor.block_id(),
        )
        .expect("initialize foreign canonical store");
        let foreign_pin = foreign
            .fresh_head_pin_v1()
            .expect("fresh foreign canonical anchor");
        let foreign_parent = foreign
            .recover_order_application_parent_v1(&foreign_pin)
            .expect("recover foreign application parent");
        assert_eq!(
            store
                .preview_next_from_recovered_parent_v1(
                    &foreign_parent,
                    application_template(anchor.block_id(), anchor.height() + 1),
                    &[OrderApplicationOperationV1::Noop],
                )
                .expect_err("foreign recovered parent owner rejects")
                .code(),
            OrderStateErrorCodeV1::StoreRollback,
        );
        assert_eq!(
            store
                .recover_order_application_parent_v1(&foreign_pin)
                .expect_err("foreign external pin rejects")
                .code(),
            OrderStateErrorCodeV1::StoreRollback,
        );

        let first = commit_application_successor(&store, &anchor, 0x61);
        let trusted_first = first.pin().clone();
        {
            let connection = Connection::open(path(&temp)).expect("open raw header tamper");
            connection
                .execute(
                    "UPDATE canonical_order_state_blocks_v1 SET header_cev1=?1 WHERE height=?2",
                    params![vec![1_u8], &trusted_first.height.to_be_bytes()[..]],
                )
                .expect("replace exact canonical header bytes");
        }
        assert_eq!(
            store
                .recover_order_application_parent_v1(&trusted_first)
                .expect_err("header tamper rejects recovered parent")
                .code(),
            OrderStateErrorCodeV1::StoreTamper,
        );

        let rollback_temp = tempfile::tempdir().expect("rollback canonical tempdir");
        let rollback_store = PocoCanonicalOrderStateStoreV1::initialize_new(
            path(&rollback_temp),
            STORE_ID,
            6,
            ANCHOR_BLOCK_ID,
        )
        .expect("initialize rollback canonical store");
        let rollback_anchor = rollback_store
            .fresh_head_pin_v1()
            .expect("fresh rollback anchor");
        let rollback_first = commit_application_successor(&rollback_store, &rollback_anchor, 0x71);
        let trusted_rollback_first = rollback_first.pin().clone();
        let rollback_second =
            commit_application_successor(&rollback_store, rollback_first.pin(), 0x81);
        let trusted_rollback_second = rollback_second.pin().clone();
        {
            let connection =
                Connection::open(path(&rollback_temp)).expect("open raw coherent rollback");
            connection
                .execute(
                    "DELETE FROM canonical_order_state_leaves_v1 WHERE created_height=?1",
                    params![&trusted_rollback_second.height.to_be_bytes()[..]],
                )
                .expect("delete rolled-back live leaf");
            connection
                .execute(
                    "DELETE FROM canonical_order_state_deltas_v1 WHERE height=?1",
                    params![&trusted_rollback_second.height.to_be_bytes()[..]],
                )
                .expect("delete rolled-back delta");
            connection
                .execute(
                    "DELETE FROM canonical_order_state_blocks_v1 WHERE height=?1",
                    params![&trusted_rollback_second.height.to_be_bytes()[..]],
                )
                .expect("delete rolled-back block");
            connection
                .execute(
                    "UPDATE canonical_order_state_metadata_v1 SET head_height=?1,head_block_id=?2,head_root=?3,head_checksum=?4 WHERE singleton=1",
                    params![
                        &trusted_rollback_first.height.to_be_bytes()[..],
                        &trusted_rollback_first.block_id.to_bytes()[..],
                        &trusted_rollback_first.state_root[..],
                        &trusted_rollback_first.history_checksum[..],
                    ],
                )
                .expect("rewind metadata to coherent prior head");
        }
        assert_eq!(
            rollback_store
                .recover_order_application_parent_v1(&trusted_rollback_second)
                .expect_err("coherent whole-store rollback differs from external head pin")
                .code(),
            OrderStateErrorCodeV1::StoreRollback,
        );
    }

    #[test]
    fn canonical_partial_projection_tamper_fails_fresh_reopen() {
        let (temp, store, anchor) = initialize();
        let exact = sealed_successor(&store, &anchor, 0x51);
        let receipt = store
            .apply_sealed_inner_v1(&exact, None)
            .expect("commit canonical tamper fixture");
        let trusted_pin = receipt.pin().clone();
        drop(store);

        let connection = Connection::open(path(&temp)).expect("open raw tamper connection");
        connection
            .execute(
                "DELETE FROM canonical_order_state_deltas_v1 WHERE height=?1",
                params![&trusted_pin.height.to_be_bytes()[..]],
            )
            .expect("delete one atomic projection row");
        drop(connection);
        assert_eq!(
            PocoCanonicalOrderStateStoreV1::open_existing_pinned(
                path(&temp),
                STORE_ID,
                &trusted_pin,
            )
            .expect_err("partial canonical projection rejects")
            .code(),
            OrderStateErrorCodeV1::StoreTamper
        );
    }
}
