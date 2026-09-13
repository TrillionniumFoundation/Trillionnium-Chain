use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use sha2::{Digest, Sha256};
use trnm_poco_global_execution_v1::{GlobalExecutionErrorV1, WholeNodeFinalizationOwnerV1};
use trnm_poco_order_finality_verifier_v1::{
    verify_order_state_execution_binding_receipt_v1, GlobalExecutionBindingCreateMaterialV1,
    OrderFinalityVerifyErrorV1, OrderStateExecutionBindingReceiptProofV1, VerifiedOrderFinalityV1,
    VerifiedOrderStateExecutionBindingV1,
};

#[cfg(any(test, feature = "test-support"))]
use trnm_poco_order_finality_verifier_v1::derive_global_execution_binding_create_material_v1;

use crate::{
    error::{error, OrderStateErrorCodeV1},
    OrderStateResultV1,
};

const SCHEMA_VERSION: u16 = 1;
const SQLITE_APPLICATION_ID: i64 = 0x5452_4f53;
const SQLITE_USER_VERSION: i64 = 1;
const OBJECT_KIND: u16 = 50;
const OBJECT_VERSION: u64 = 0;
const STATE_TREE_VERSION: u16 = 0;
const STATE_TREE_DEPTH: usize = 256;
const MAX_CHAIN_ID_BYTES: usize = 1024;
const MAX_VALUE_BYTES: usize = 4 * 1024 * 1024;
const BINDING_ID_DOMAIN: &str = "trnm.poco-ai.global-execution-binding.v1";
const STATE_KEY_DOMAIN: &str = "trnm.poco-ai.state-key.v1";
const STATE_EMPTY_LEAF_DOMAIN: &str = "trnm.poco-ai.state-empty-leaf.v1";
const STATE_LEAF_DOMAIN: &str = "trnm.poco-ai.state-leaf.v1";
const STATE_NODE_DOMAIN: &str = "trnm.poco-ai.state-node.v1";
const VALUE_DIGEST_DOMAIN: &str = "trnm.poco-ai.order-state-value.v1";
const PERMIT_DIGEST_DOMAIN: &str = "trnm.poco-ai.order-state-tag50-write-permit.v1";
const GENESIS_CHECKSUM_DOMAIN: &str = "trnm.poco-ai.order-state-genesis.v1";
const HISTORY_CHECKSUM_DOMAIN: &str = "trnm.poco-ai.order-state-history.v1";

const METADATA_SQL: &str = "CREATE TABLE order_state_metadata_v1 (singleton INTEGER PRIMARY KEY CHECK(singleton=1),store_id BLOB NOT NULL CHECK(typeof(store_id)='blob' AND length(store_id)=32),anchor_height BLOB NOT NULL CHECK(typeof(anchor_height)='blob' AND length(anchor_height)=8),anchor_root BLOB NOT NULL CHECK(typeof(anchor_root)='blob' AND length(anchor_root)=32),head_height BLOB NOT NULL CHECK(typeof(head_height)='blob' AND length(head_height)=8),head_root BLOB NOT NULL CHECK(typeof(head_root)='blob' AND length(head_root)=32),head_checksum BLOB NOT NULL CHECK(typeof(head_checksum)='blob' AND length(head_checksum)=32),fenced INTEGER NOT NULL CHECK(fenced IN(0,1))) STRICT";
const HISTORY_SQL: &str = "CREATE TABLE order_state_history_v1 (height BLOB PRIMARY KEY CHECK(typeof(height)='blob' AND length(height)=8),parent_root BLOB NOT NULL CHECK(typeof(parent_root)='blob' AND length(parent_root)=32),state_root BLOB NOT NULL UNIQUE CHECK(typeof(state_root)='blob' AND length(state_root)=32),state_key BLOB NOT NULL UNIQUE CHECK(typeof(state_key)='blob' AND length(state_key)=32),object_kind INTEGER NOT NULL CHECK(object_kind=50),object_id BLOB NOT NULL UNIQUE CHECK(typeof(object_id)='blob' AND length(object_id)=32),object_version BLOB NOT NULL CHECK(typeof(object_version)='blob' AND length(object_version)=8),value_bytes BLOB NOT NULL CHECK(typeof(value_bytes)='blob' AND length(value_bytes)>0 AND length(value_bytes)<=4194304),value_digest BLOB NOT NULL UNIQUE CHECK(typeof(value_digest)='blob' AND length(value_digest)=32),permit_digest BLOB NOT NULL UNIQUE CHECK(typeof(permit_digest)='blob' AND length(permit_digest)=32),predecessor_checksum BLOB NOT NULL CHECK(typeof(predecessor_checksum)='blob' AND length(predecessor_checksum)=32),checksum BLOB NOT NULL UNIQUE CHECK(typeof(checksum)='blob' AND length(checksum)=32)) STRICT, WITHOUT ROWID";
const LEAVES_SQL: &str = "CREATE TABLE order_state_leaves_v1 (state_key BLOB PRIMARY KEY CHECK(typeof(state_key)='blob' AND length(state_key)=32),object_kind INTEGER NOT NULL CHECK(object_kind=50),object_id BLOB NOT NULL UNIQUE CHECK(typeof(object_id)='blob' AND length(object_id)=32),object_version BLOB NOT NULL CHECK(typeof(object_version)='blob' AND length(object_version)=8),value_bytes BLOB NOT NULL CHECK(typeof(value_bytes)='blob' AND length(value_bytes)>0 AND length(value_bytes)<=4194304),created_height BLOB NOT NULL UNIQUE CHECK(typeof(created_height)='blob' AND length(created_height)=8),history_checksum BLOB NOT NULL UNIQUE CHECK(typeof(history_checksum)='blob' AND length(history_checksum)=32)) STRICT, WITHOUT ROWID";

type MetadataRowRawV1 = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderStateHeadPinV1 {
    store_id: [u8; 32],
    height: u64,
    state_root: [u8; 32],
    history_checksum: [u8; 32],
}

impl OrderStateHeadPinV1 {
    pub const fn store_id(&self) -> [u8; 32] {
        self.store_id
    }

    pub const fn height(&self) -> u64 {
        self.height
    }

    pub const fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    pub const fn history_checksum(&self) -> [u8; 32] {
        self.history_checksum
    }
}

#[must_use = "the sole tag-50 write permit must be consumed exactly once"]
#[derive(Debug)]
pub struct OrderStateWritePermitV1 {
    owner: WholeNodeFinalizationOwnerV1,
    prepared: PreparedTag50WriteV1,
}

#[derive(Debug)]
struct PreparedTag50WriteV1 {
    store_id: [u8; 32],
    parent_height: u64,
    parent_root: [u8; 32],
    parent_history_checksum: [u8; 32],
    target_height: u64,
    object_id: [u8; 32],
    state_key: [u8; 32],
    value_bytes: Vec<u8>,
    value_digest: [u8; 32],
    permit_digest: [u8; 32],
}

impl OrderStateWritePermitV1 {
    pub const fn parent_height(&self) -> u64 {
        self.prepared.parent_height
    }

    pub const fn parent_root(&self) -> [u8; 32] {
        self.prepared.parent_root
    }

    pub const fn target_height(&self) -> u64 {
        self.prepared.target_height
    }

    pub const fn object_id(&self) -> [u8; 32] {
        self.prepared.object_id
    }

    pub const fn state_key(&self) -> [u8; 32] {
        self.prepared.state_key
    }
}

#[cfg(any(test, feature = "test-support"))]
#[must_use = "the test-only tag-50 write permit must be consumed exactly once"]
#[derive(Debug)]
pub struct TestOrderStateWritePermitV1 {
    prepared: PreparedTag50WriteV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderStateMembershipProofV1 {
    pub(crate) height: u64,
    pub(crate) state_root: [u8; 32],
    pub(crate) state_tree_version: u16,
    pub(crate) object_kind: u16,
    pub(crate) object_id: [u8; 32],
    pub(crate) object_version: u64,
    pub(crate) state_key: [u8; 32],
    pub(crate) value_bytes: Vec<u8>,
    pub(crate) siblings: Vec<[u8; 32]>,
}

impl OrderStateMembershipProofV1 {
    pub const fn height(&self) -> u64 {
        self.height
    }

    pub const fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    pub const fn state_tree_version(&self) -> u16 {
        self.state_tree_version
    }

    pub const fn object_kind(&self) -> u16 {
        self.object_kind
    }

    pub const fn state_key(&self) -> [u8; 32] {
        self.state_key
    }

    pub const fn object_id(&self) -> [u8; 32] {
        self.object_id
    }

    pub const fn object_version(&self) -> u64 {
        self.object_version
    }

    pub fn value_bytes(&self) -> &[u8] {
        &self.value_bytes
    }

    pub fn siblings(&self) -> &[[u8; 32]] {
        &self.siblings
    }

    #[cfg(test)]
    pub(crate) fn test_flip_sibling_v1(&mut self, level: usize) {
        self.siblings[level][0] ^= 1;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderStateWriteReceiptV1 {
    replay: bool,
    materialized_pin: OrderStateHeadPinV1,
    observed_head_pin: OrderStateHeadPinV1,
    proof: OrderStateMembershipProofV1,
}

#[must_use = "the materialized terminal owner must be retained until Order-state verification"]
#[derive(Debug)]
pub struct MaterializedOrderStateOwnerV1 {
    owner: WholeNodeFinalizationOwnerV1,
    receipt: OrderStateWriteReceiptV1,
}

impl MaterializedOrderStateOwnerV1 {
    pub const fn receipt(&self) -> &OrderStateWriteReceiptV1 {
        &self.receipt
    }

    pub fn bind_verified_order_state_v1(
        self,
        binding: VerifiedOrderStateExecutionBindingV1,
    ) -> Result<VerifiedMaterializedOrderStateOwnerV1, GlobalExecutionErrorV1> {
        Ok(VerifiedMaterializedOrderStateOwnerV1 {
            owner: self.owner.bind_verified_order_state_v1(binding)?,
            receipt: self.receipt,
        })
    }

    /// Verify this exact private writer receipt beneath independently verified
    /// later Order finality while retaining the linear terminal owner.
    ///
    /// The returned carrier is still inert until
    /// [`Self::bind_verified_order_state_v1`] consumes this owner and checks all
    /// candidate/composite/final roots against the terminal commitment.
    pub fn verify_later_order_finality_v1(
        &self,
        order: &VerifiedOrderFinalityV1,
    ) -> Result<VerifiedOrderStateExecutionBindingV1, OrderFinalityVerifyErrorV1> {
        self.receipt.verify_later_order_finality_v1(order)
    }
}

#[must_use = "the verified materialized terminal owner remains linear authority"]
#[derive(Debug)]
pub struct VerifiedMaterializedOrderStateOwnerV1 {
    owner: WholeNodeFinalizationOwnerV1,
    receipt: OrderStateWriteReceiptV1,
}

impl VerifiedMaterializedOrderStateOwnerV1 {
    pub const fn receipt(&self) -> &OrderStateWriteReceiptV1 {
        &self.receipt
    }

    pub const fn finalization_owner(&self) -> &WholeNodeFinalizationOwnerV1 {
        &self.owner
    }

    pub fn into_parts(self) -> (WholeNodeFinalizationOwnerV1, OrderStateWriteReceiptV1) {
        (self.owner, self.receipt)
    }
}

#[must_use = "a failed write retains the exact linear permit for fail-closed retry"]
#[derive(Debug)]
pub struct OrderStateWriteFailureV1 {
    cause: crate::OrderStateErrorV1,
    permit: OrderStateWritePermitV1,
}

impl OrderStateWriteFailureV1 {
    pub const fn cause(&self) -> &crate::OrderStateErrorV1 {
        &self.cause
    }

    pub const fn code(&self) -> OrderStateErrorCodeV1 {
        self.cause.code()
    }

    pub fn into_retry_permit(self) -> OrderStateWritePermitV1 {
        self.permit
    }
}

pub type OrderStateWriteAttemptV1 = Result<MaterializedOrderStateOwnerV1, OrderStateWriteFailureV1>;

impl OrderStateWriteReceiptV1 {
    pub const fn is_replay(&self) -> bool {
        self.replay
    }

    pub const fn pin(&self) -> &OrderStateHeadPinV1 {
        &self.materialized_pin
    }

    pub const fn observed_head_pin(&self) -> &OrderStateHeadPinV1 {
        &self.observed_head_pin
    }

    pub const fn proof(&self) -> &OrderStateMembershipProofV1 {
        &self.proof
    }

    /// Canonically project this freshly read-back writer receipt into the
    /// independent Order-finality verifier.
    ///
    /// A receipt is cloneable evidence, not mutation or finalization
    /// authority. Positive verification additionally requires a
    /// non-forgeable finality carrier for this exact height/root and proves the
    /// complete 256-level membership path.
    pub fn verify_later_order_finality_v1(
        &self,
        order: &VerifiedOrderFinalityV1,
    ) -> Result<VerifiedOrderStateExecutionBindingV1, OrderFinalityVerifyErrorV1> {
        verify_order_state_execution_binding_receipt_v1(
            order,
            OrderStateExecutionBindingReceiptProofV1 {
                materialized_height: self.materialized_pin.height,
                materialized_state_root: self.materialized_pin.state_root,
                state_tree_version: self.proof.state_tree_version,
                object_kind: self.proof.object_kind,
                object_id: self.proof.object_id,
                object_version: self.proof.object_version,
                state_key: self.proof.state_key,
                value_bytes: &self.proof.value_bytes,
                siblings: &self.proof.siblings,
            },
        )
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    links: u64,
    mode: u32,
}

#[cfg(not(unix))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct FileIdentity {
    canonical_path: PathBuf,
}

#[derive(Debug)]
pub struct PocoOrderStateStoreV1 {
    path: PathBuf,
    store_id: [u8; 32],
    file_identity: FileIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredLeaf {
    object_kind: u16,
    object_id: [u8; 32],
    object_version: u64,
    value_bytes: Vec<u8>,
    created_height: u64,
    history_checksum: [u8; 32],
}

#[derive(Debug)]
struct AuditedState {
    anchor_height: u64,
    anchor_root: [u8; 32],
    head: OrderStateHeadPinV1,
    leaves: BTreeMap<[u8; 32], StoredLeaf>,
    history: BTreeMap<u64, HistoryRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HistoryRecord {
    parent_root: [u8; 32],
    state_root: [u8; 32],
    state_key: [u8; 32],
    object_id: [u8; 32],
    object_version: u64,
    value_bytes: Vec<u8>,
    value_digest: [u8; 32],
    permit_digest: [u8; 32],
    checksum: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct ParsedBinding {
    object_id: [u8; 32],
    candidate_height: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug)]
pub(crate) enum OrderStateWriteFaultV1 {
    BeforeCommit,
    AfterCommitBeforeReturn,
}

impl PocoOrderStateStoreV1 {
    pub fn initialize_new(
        path: impl Into<PathBuf>,
        store_id: [u8; 32],
        anchor_height: u64,
    ) -> OrderStateResultV1<Self> {
        require_nonzero(store_id, "Order-state store ID")?;
        if anchor_height == 0 {
            return Err(error(
                OrderStateErrorCodeV1::InvalidContext,
                "Order-state anchor height must be positive",
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
        let anchor_root = empty_order_state_root_v1();
        let checksum = genesis_checksum(store_id, anchor_height, anchor_root);
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(METADATA_SQL)?;
        transaction.execute_batch(HISTORY_SQL)?;
        transaction.execute_batch(LEAVES_SQL)?;
        transaction.execute(
            "INSERT INTO order_state_metadata_v1(singleton,store_id,anchor_height,anchor_root,head_height,head_root,head_checksum,fenced) VALUES(1,?1,?2,?3,?2,?3,?4,0)",
            params![
                &store_id[..],
                &anchor_height.to_be_bytes()[..],
                &anchor_root[..],
                &checksum[..],
            ],
        )?;
        transaction.commit()?;
        drop(connection);
        reject_sidecars(&path)?;
        let identity = file_identity(&path)?;
        let store = Self {
            path,
            store_id,
            file_identity: identity,
        };
        let observed = store.audit_fresh()?;
        if observed.head.height != anchor_height
            || observed.head.state_root != anchor_root
            || observed.head.history_checksum != checksum
            || !observed.leaves.is_empty()
        {
            return Err(error(
                OrderStateErrorCodeV1::StoreTamper,
                "fresh Order-state anchor readback differs",
            ));
        }
        Ok(store)
    }

    pub fn open_existing_pinned(
        path: impl Into<PathBuf>,
        store_id: [u8; 32],
        trusted_pin: &OrderStateHeadPinV1,
    ) -> OrderStateResultV1<Self> {
        require_nonzero(store_id, "Order-state store ID")?;
        let path = validate_path(&path.into(), true)?;
        let identity = file_identity(&path)?;
        let store = Self {
            path,
            store_id,
            file_identity: identity,
        };
        let observed = store.audit_fresh()?;
        if observed.head != *trusted_pin {
            return Err(error(
                OrderStateErrorCodeV1::StoreRollback,
                "Order-state head differs from the trusted external pin",
            ));
        }
        Ok(store)
    }

    pub fn fresh_head_pin_v1(&self) -> OrderStateResultV1<OrderStateHeadPinV1> {
        Ok(self.audit_fresh()?.head)
    }

    // The error intentionally retains the complete non-Clone permit so an
    // uncertain write can be retried without reconstructing authority.
    #[allow(clippy::result_large_err)]
    pub fn materialize_global_execution_binding_v1(
        &self,
        permit: OrderStateWritePermitV1,
    ) -> OrderStateWriteAttemptV1 {
        match self.create_inner(&permit.prepared, None) {
            Ok(receipt) => Ok(MaterializedOrderStateOwnerV1 {
                owner: permit.owner,
                receipt,
            }),
            Err(cause) => Err(OrderStateWriteFailureV1 { cause, permit }),
        }
    }

    pub fn prove_membership_v1(
        &self,
        height: u64,
        state_key: [u8; 32],
    ) -> OrderStateResultV1<OrderStateMembershipProofV1> {
        let audited = self.audit_fresh()?;
        prove_from_audit(&audited, height, state_key)
    }

    #[cfg(test)]
    pub(crate) fn create_with_fault_v1(
        &self,
        permit: TestOrderStateWritePermitV1,
        fault: OrderStateWriteFaultV1,
    ) -> OrderStateResultV1<OrderStateWriteReceiptV1> {
        self.create_inner(&permit.prepared, Some(fault))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn create_test_global_execution_binding_v1(
        &self,
        permit: TestOrderStateWritePermitV1,
    ) -> OrderStateResultV1<OrderStateWriteReceiptV1> {
        self.create_inner(&permit.prepared, None)
    }

    fn create_inner(
        &self,
        permit: &PreparedTag50WriteV1,
        #[cfg_attr(not(test), allow(unused_variables))] fault: Option<OrderStateWriteFaultV1>,
    ) -> OrderStateResultV1<OrderStateWriteReceiptV1> {
        self.validate_file_identity()?;
        reject_sidecars(&self.path)?;
        validate_prepared_write(permit)?;
        if permit.store_id != self.store_id {
            return Err(error(
                OrderStateErrorCodeV1::PermitMismatch,
                "tag-50 write permit belongs to a different Order-state store",
            ));
        }
        let mut connection = open_rw_raw(&self.path)?;
        configure_rw(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let audited = audit_connection(&transaction, self.store_id)?;

        if let Some(existing) = audited.history.get(&permit.target_height) {
            let exact = existing.parent_root == permit.parent_root
                && existing.state_key == permit.state_key
                && existing.object_id == permit.object_id
                && existing.object_version == OBJECT_VERSION
                && existing.value_bytes == permit.value_bytes
                && existing.value_digest == permit.value_digest
                && existing.permit_digest == permit.permit_digest;
            drop(transaction);
            drop(connection);
            if !exact {
                return Err(error(
                    OrderStateErrorCodeV1::Fork,
                    "target Order-state height is already occupied by another write",
                ));
            }
            return self.fresh_receipt(permit.target_height, permit.state_key, true);
        }

        if audited.head.height != permit.parent_height
            || audited.head.state_root != permit.parent_root
            || audited.head.history_checksum != permit.parent_history_checksum
        {
            return Err(error(
                OrderStateErrorCodeV1::StaleParent,
                "tag-50 write permit does not name the exact current parent",
            ));
        }
        if audited.leaves.contains_key(&permit.state_key) {
            return Err(error(
                OrderStateErrorCodeV1::DuplicateKey,
                "tag-50 state key already exists at the exact parent",
            ));
        }
        let (parent_root, _) = sparse_root_and_siblings(&audited.leaves, Some(permit.state_key))?;
        if parent_root != permit.parent_root {
            return Err(error(
                OrderStateErrorCodeV1::StoreTamper,
                "recomputed parent nonmembership root differs from permit",
            ));
        }

        let mut target_leaves = audited.leaves.clone();
        target_leaves.insert(
            permit.state_key,
            StoredLeaf {
                object_kind: OBJECT_KIND,
                object_id: permit.object_id,
                object_version: OBJECT_VERSION,
                value_bytes: permit.value_bytes.clone(),
                created_height: permit.target_height,
                history_checksum: [0; 32],
            },
        );
        let (target_root, _) = sparse_root_and_siblings(&target_leaves, Some(permit.state_key))?;
        let checksum = history_checksum(
            self.store_id,
            permit.target_height,
            permit.parent_root,
            target_root,
            permit.state_key,
            permit.object_id,
            permit.value_digest,
            permit.permit_digest,
            audited.head.history_checksum,
        );

        transaction.execute(
            "INSERT INTO order_state_history_v1(height,parent_root,state_root,state_key,object_kind,object_id,object_version,value_bytes,value_digest,permit_digest,predecessor_checksum,checksum) VALUES(?1,?2,?3,?4,50,?5,?6,?7,?8,?9,?10,?11)",
            params![
                &permit.target_height.to_be_bytes()[..],
                &permit.parent_root[..],
                &target_root[..],
                &permit.state_key[..],
                &permit.object_id[..],
                &OBJECT_VERSION.to_be_bytes()[..],
                &permit.value_bytes,
                &permit.value_digest[..],
                &permit.permit_digest[..],
                &audited.head.history_checksum[..],
                &checksum[..],
            ],
        )?;
        transaction.execute(
            "INSERT INTO order_state_leaves_v1(state_key,object_kind,object_id,object_version,value_bytes,created_height,history_checksum) VALUES(?1,50,?2,?3,?4,?5,?6)",
            params![
                &permit.state_key[..],
                &permit.object_id[..],
                &OBJECT_VERSION.to_be_bytes()[..],
                &permit.value_bytes,
                &permit.target_height.to_be_bytes()[..],
                &checksum[..],
            ],
        )?;
        transaction.execute(
            "UPDATE order_state_metadata_v1 SET head_height=?1,head_root=?2,head_checksum=?3 WHERE singleton=1 AND head_height=?4 AND head_root=?5 AND head_checksum=?6 AND fenced=0",
            params![
                &permit.target_height.to_be_bytes()[..],
                &target_root[..],
                &checksum[..],
                &permit.parent_height.to_be_bytes()[..],
                &permit.parent_root[..],
                &audited.head.history_checksum[..],
            ],
        )?;
        if transaction.changes() != 1 {
            return Err(error(
                OrderStateErrorCodeV1::StaleParent,
                "Order-state successor CAS changed no metadata row",
            ));
        }
        #[cfg(test)]
        if matches!(fault, Some(OrderStateWriteFaultV1::BeforeCommit)) {
            return Err(error(
                OrderStateErrorCodeV1::CommitUncertain,
                "injected loss before Order-state commit",
            ));
        }
        transaction.commit().map_err(|cause| {
            error(
                OrderStateErrorCodeV1::CommitUncertain,
                format!("Order-state commit outcome is uncertain: {cause}"),
            )
        })?;
        drop(connection);
        #[cfg(test)]
        if matches!(fault, Some(OrderStateWriteFaultV1::AfterCommitBeforeReturn)) {
            return Err(error(
                OrderStateErrorCodeV1::CommitUncertain,
                "injected response loss after Order-state commit",
            ));
        }
        self.fresh_receipt(permit.target_height, permit.state_key, false)
    }

    fn fresh_receipt(
        &self,
        height: u64,
        state_key: [u8; 32],
        replay: bool,
    ) -> OrderStateResultV1<OrderStateWriteReceiptV1> {
        let audited = self.audit_fresh()?;
        let proof = prove_from_audit(&audited, height, state_key)?;
        if !verify_order_state_membership_proof_v1(&proof) {
            return Err(error(
                OrderStateErrorCodeV1::MembershipInvalid,
                "fresh Order-state membership proof failed self-verification",
            ));
        }
        let record = audited.history.get(&height).ok_or_else(|| {
            error(
                OrderStateErrorCodeV1::StoreTamper,
                "materialized Order-state history record is absent",
            )
        })?;
        Ok(OrderStateWriteReceiptV1 {
            replay,
            materialized_pin: OrderStateHeadPinV1 {
                store_id: self.store_id,
                height,
                state_root: record.state_root,
                history_checksum: record.checksum,
            },
            observed_head_pin: audited.head,
            proof,
        })
    }

    fn audit_fresh(&self) -> OrderStateResultV1<AuditedState> {
        self.validate_file_identity()?;
        reject_sidecars(&self.path)?;
        let connection = open_ro(&self.path)?;
        let audited = audit_connection(&connection, self.store_id)?;
        drop(connection);
        self.validate_file_identity()?;
        reject_sidecars(&self.path)?;
        Ok(audited)
    }

    fn validate_file_identity(&self) -> OrderStateResultV1<()> {
        if file_identity(&self.path)? != self.file_identity {
            return Err(error(
                OrderStateErrorCodeV1::StoreUnavailable,
                "Order-state database file identity changed",
            ));
        }
        Ok(())
    }
}

pub fn issue_order_state_write_permit_v1(
    owner: WholeNodeFinalizationOwnerV1,
    parent: &OrderStateHeadPinV1,
) -> OrderStateResultV1<OrderStateWritePermitV1> {
    let target_height = parent.height.checked_add(1).ok_or_else(|| {
        error(
            OrderStateErrorCodeV1::ArithmeticOverflow,
            "Order-state target height overflows",
        )
    })?;
    let material = owner
        .derive_order_binding_create_material_v1(target_height)
        .map_err(|_| {
            error(
                OrderStateErrorCodeV1::PermitMismatch,
                "terminal owner cannot derive exact successor tag-50 material",
            )
        })?;
    let prepared = seal_prepared_write(parent, material)?;
    Ok(OrderStateWritePermitV1 { owner, prepared })
}

#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::too_many_arguments)]
pub fn issue_test_order_state_write_permit_v1(
    store_id: [u8; 32],
    parent_height: u64,
    parent_root: [u8; 32],
    parent_history_checksum: [u8; 32],
    chain_id: &str,
    genesis_hash: [u8; 32],
    protocol_version: u32,
    stack_profile_hash: [u8; 32],
    candidate_height: u64,
    candidate_block_id: [u8; 32],
    candidate_composite_root: [u8; 32],
    final_execution_root: [u8; 32],
    materialized_at_height: u64,
) -> OrderStateResultV1<TestOrderStateWritePermitV1> {
    let material = derive_global_execution_binding_create_material_v1(
        chain_id,
        genesis_hash,
        protocol_version,
        stack_profile_hash,
        candidate_height,
        candidate_block_id,
        candidate_composite_root,
        final_execution_root,
        materialized_at_height,
    )
    .map_err(|_| {
        error(
            OrderStateErrorCodeV1::PermitMismatch,
            "test terminal material derivation rejected",
        )
    })?;
    let parent = OrderStateHeadPinV1 {
        store_id,
        height: parent_height,
        state_root: parent_root,
        history_checksum: parent_history_checksum,
    };
    Ok(TestOrderStateWritePermitV1 {
        prepared: seal_prepared_write(&parent, material)?,
    })
}

fn seal_prepared_write(
    parent: &OrderStateHeadPinV1,
    material: GlobalExecutionBindingCreateMaterialV1,
) -> OrderStateResultV1<PreparedTag50WriteV1> {
    require_nonzero(parent.store_id, "Order-state store ID")?;
    require_nonzero(parent.state_root, "Order-state parent root")?;
    require_nonzero(
        parent.history_checksum,
        "Order-state parent history checksum",
    )?;
    let target_height = parent.height.checked_add(1).ok_or_else(|| {
        error(
            OrderStateErrorCodeV1::ArithmeticOverflow,
            "Order-state target height overflows",
        )
    })?;
    if material.materialized_at_height() != target_height
        || material.object_kind() != OBJECT_KIND
        || material.object_version() != OBJECT_VERSION
    {
        return Err(error(
            OrderStateErrorCodeV1::PermitMismatch,
            "tag-50 material does not name the exact successor/version",
        ));
    }
    let object_id = material.object_id();
    let state_key = material.state_key();
    let value_bytes = material.value_bytes().to_vec();
    let parsed = validate_tag50_value(&value_bytes, object_id, state_key)?;
    if parsed.candidate_height >= target_height {
        return Err(error(
            OrderStateErrorCodeV1::PermitMismatch,
            "tag-50 candidate is not a strict materialization ancestor",
        ));
    }
    let value_digest = digest(VALUE_DIGEST_DOMAIN, &value_bytes);
    let permit_digest = permit_digest(
        parent.store_id,
        parent.height,
        parent.state_root,
        parent.history_checksum,
        target_height,
        state_key,
        object_id,
        value_digest,
    );
    Ok(PreparedTag50WriteV1 {
        store_id: parent.store_id,
        parent_height: parent.height,
        parent_root: parent.state_root,
        parent_history_checksum: parent.history_checksum,
        target_height,
        object_id,
        state_key,
        value_bytes,
        value_digest,
        permit_digest,
    })
}

fn validate_prepared_write(permit: &PreparedTag50WriteV1) -> OrderStateResultV1<()> {
    require_nonzero(permit.store_id, "Order-state permit store ID")?;
    require_nonzero(permit.parent_root, "Order-state permit parent root")?;
    require_nonzero(
        permit.parent_history_checksum,
        "Order-state permit parent history checksum",
    )?;
    let expected_target = permit.parent_height.checked_add(1).ok_or_else(|| {
        error(
            OrderStateErrorCodeV1::ArithmeticOverflow,
            "Order-state permit target height overflows",
        )
    })?;
    let parsed = validate_tag50_value(&permit.value_bytes, permit.object_id, permit.state_key)?;
    let value_digest = digest(VALUE_DIGEST_DOMAIN, &permit.value_bytes);
    let expected_permit = permit_digest(
        permit.store_id,
        permit.parent_height,
        permit.parent_root,
        permit.parent_history_checksum,
        permit.target_height,
        permit.state_key,
        permit.object_id,
        value_digest,
    );
    if permit.target_height != expected_target
        || parsed.candidate_height >= permit.target_height
        || value_digest != permit.value_digest
        || expected_permit != permit.permit_digest
    {
        return Err(error(
            OrderStateErrorCodeV1::PermitMismatch,
            "tag-50 write permit failed canonical revalidation",
        ));
    }
    Ok(())
}

pub fn empty_order_state_root_v1() -> [u8; 32] {
    empty_hashes()[STATE_TREE_DEPTH]
}

pub fn verify_order_state_membership_proof_v1(proof: &OrderStateMembershipProofV1) -> bool {
    if proof.state_tree_version != STATE_TREE_VERSION
        || proof.object_kind != OBJECT_KIND
        || proof.object_version != OBJECT_VERSION
        || proof.object_id == [0; 32]
        || proof.state_key != application_state_key(OBJECT_KIND, proof.object_id)
        || proof.siblings.len() != STATE_TREE_DEPTH
        || validate_tag50_value(&proof.value_bytes, proof.object_id, proof.state_key).is_err()
    {
        return false;
    }
    let mut running = state_leaf_hash(
        proof.state_key,
        proof.object_kind,
        proof.object_version,
        &proof.value_bytes,
    );
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let bit_index = 255 - level;
        let bit = bit_at(proof.state_key, bit_index);
        let (left, right) = if bit == 0 {
            (running, *sibling)
        } else {
            (*sibling, running)
        };
        running = state_node_hash(level, left, right);
    }
    running == proof.state_root
}

fn prove_from_audit(
    audited: &AuditedState,
    height: u64,
    state_key: [u8; 32],
) -> OrderStateResultV1<OrderStateMembershipProofV1> {
    if height < audited.anchor_height || height > audited.head.height {
        return Err(error(
            OrderStateErrorCodeV1::MembershipInvalid,
            "requested Order-state proof height is outside retained history",
        ));
    }
    let leaves = audited
        .leaves
        .iter()
        .filter(|(_, leaf)| leaf.created_height <= height)
        .map(|(key, leaf)| (*key, leaf.clone()))
        .collect::<BTreeMap<_, _>>();
    let leaf = leaves.get(&state_key).ok_or_else(|| {
        error(
            OrderStateErrorCodeV1::MembershipInvalid,
            "requested Order-state key is absent at proof height",
        )
    })?;
    let (root, siblings) = sparse_root_and_siblings(&leaves, Some(state_key))?;
    let expected_root = if height == audited.anchor_height {
        audited.anchor_root
    } else {
        audited
            .history
            .get(&height)
            .ok_or_else(|| {
                error(
                    OrderStateErrorCodeV1::StoreTamper,
                    "Order-state history root is absent at proof height",
                )
            })?
            .state_root
    };
    if root != expected_root {
        return Err(error(
            OrderStateErrorCodeV1::StoreTamper,
            "historical sparse root differs from audited history",
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

fn audit_connection(
    connection: &Connection,
    expected_store_id: [u8; 32],
) -> OrderStateResultV1<AuditedState> {
    verify_schema(connection)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(error(
            OrderStateErrorCodeV1::StoreTamper,
            "Order-state SQLite integrity check failed",
        ));
    }
    let metadata: MetadataRowRawV1 = connection
        .query_row(
            "SELECT store_id,anchor_height,anchor_root,head_height,head_root,head_checksum,fenced FROM order_state_metadata_v1 WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
        )?;
    let store_id = array32(&metadata.0, "metadata store ID")?;
    let anchor_height = decode_u64_blob(&metadata.1, "anchor height")?;
    let anchor_root = array32(&metadata.2, "anchor root")?;
    let head_height = decode_u64_blob(&metadata.3, "head height")?;
    let head_root = array32(&metadata.4, "head root")?;
    let head_checksum = array32(&metadata.5, "head checksum")?;
    if store_id != expected_store_id
        || anchor_height == 0
        || anchor_root != empty_order_state_root_v1()
        || !matches!(metadata.6, 0 | 1)
        || metadata.6 != 0
    {
        return Err(error(
            OrderStateErrorCodeV1::StoreTamper,
            "Order-state metadata identity/anchor/fence differs",
        ));
    }
    let mut statement = connection.prepare(
        "SELECT height,parent_root,state_root,state_key,object_kind,object_id,object_version,value_bytes,value_digest,permit_digest,predecessor_checksum,checksum FROM order_state_history_v1 ORDER BY height",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, Vec<u8>>(10)?,
                row.get::<_, Vec<u8>>(11)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    let mut leaves = BTreeMap::new();
    let mut history = BTreeMap::new();
    let mut prior_root = anchor_root;
    let mut prior_checksum = genesis_checksum(store_id, anchor_height, anchor_root);
    let mut prior_height = anchor_height;
    for raw in rows {
        let height = decode_u64_blob(&raw.0, "history height")?;
        let parent_root = array32(&raw.1, "history parent root")?;
        let state_root = array32(&raw.2, "history state root")?;
        let state_key = array32(&raw.3, "history state key")?;
        let object_kind = u16::try_from(raw.4).map_err(|_| {
            error(
                OrderStateErrorCodeV1::StoreTamper,
                "history object kind overflows",
            )
        })?;
        let object_id = array32(&raw.5, "history object ID")?;
        let object_version = decode_u64_blob(&raw.6, "history object version")?;
        let value_bytes = raw.7;
        let value_digest = array32(&raw.8, "history value digest")?;
        let permit_digest_value = array32(&raw.9, "history permit digest")?;
        let predecessor_checksum = array32(&raw.10, "history predecessor checksum")?;
        let checksum = array32(&raw.11, "history checksum")?;
        let expected_height = prior_height.checked_add(1).ok_or_else(|| {
            error(
                OrderStateErrorCodeV1::ArithmeticOverflow,
                "history height overflows",
            )
        })?;
        if height != expected_height
            || parent_root != prior_root
            || predecessor_checksum != prior_checksum
            || object_kind != OBJECT_KIND
            || object_version != OBJECT_VERSION
            || leaves.contains_key(&state_key)
        {
            return Err(error(
                OrderStateErrorCodeV1::StoreTamper,
                "Order-state history is not one contiguous create-only chain",
            ));
        }
        let parsed = validate_tag50_value(&value_bytes, object_id, state_key).map_err(|_| {
            error(
                OrderStateErrorCodeV1::StoreTamper,
                "history tag-50 value is not canonical",
            )
        })?;
        if parsed.object_id != object_id || parsed.candidate_height >= height {
            return Err(error(
                OrderStateErrorCodeV1::StoreTamper,
                "history tag-50 value differs from its height/identity",
            ));
        }
        let expected_value_digest = digest(VALUE_DIGEST_DOMAIN, &value_bytes);
        let expected_permit = permit_digest(
            store_id,
            height - 1,
            parent_root,
            predecessor_checksum,
            height,
            state_key,
            object_id,
            expected_value_digest,
        );
        if value_digest != expected_value_digest || permit_digest_value != expected_permit {
            return Err(error(
                OrderStateErrorCodeV1::StoreTamper,
                "history value/permit digest differs",
            ));
        }
        leaves.insert(
            state_key,
            StoredLeaf {
                object_kind,
                object_id,
                object_version,
                value_bytes: value_bytes.clone(),
                created_height: height,
                history_checksum: checksum,
            },
        );
        let (computed_root, _) = sparse_root_and_siblings(&leaves, Some(state_key))?;
        let expected_checksum = history_checksum(
            store_id,
            height,
            parent_root,
            computed_root,
            state_key,
            object_id,
            value_digest,
            permit_digest_value,
            predecessor_checksum,
        );
        if state_root != computed_root || checksum != expected_checksum {
            return Err(error(
                OrderStateErrorCodeV1::StoreTamper,
                "history state root/checksum differs from full reconstruction",
            ));
        }
        history.insert(
            height,
            HistoryRecord {
                parent_root,
                state_root,
                state_key,
                object_id,
                object_version,
                value_bytes,
                value_digest,
                permit_digest: permit_digest_value,
                checksum,
            },
        );
        prior_height = height;
        prior_root = state_root;
        prior_checksum = checksum;
    }
    if head_height != prior_height || head_root != prior_root || head_checksum != prior_checksum {
        return Err(error(
            OrderStateErrorCodeV1::StoreTamper,
            "Order-state metadata head differs from complete history",
        ));
    }
    verify_leaf_projection(connection, &leaves)?;
    Ok(AuditedState {
        anchor_height,
        anchor_root,
        head: OrderStateHeadPinV1 {
            store_id,
            height: head_height,
            state_root: head_root,
            history_checksum: head_checksum,
        },
        leaves,
        history,
    })
}

fn verify_leaf_projection(
    connection: &Connection,
    expected: &BTreeMap<[u8; 32], StoredLeaf>,
) -> OrderStateResultV1<()> {
    let mut statement = connection.prepare(
        "SELECT state_key,object_kind,object_id,object_version,value_bytes,created_height,history_checksum FROM order_state_leaves_v1 ORDER BY state_key",
    )?;
    let rows = statement
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
    if rows.len() != expected.len() {
        return Err(error(
            OrderStateErrorCodeV1::StoreTamper,
            "live Order-state leaf count differs from history",
        ));
    }
    for raw in rows {
        let key = array32(&raw.0, "leaf state key")?;
        let observed = StoredLeaf {
            object_kind: u16::try_from(raw.1).map_err(|_| {
                error(
                    OrderStateErrorCodeV1::StoreTamper,
                    "leaf object kind overflows",
                )
            })?,
            object_id: array32(&raw.2, "leaf object ID")?,
            object_version: decode_u64_blob(&raw.3, "leaf object version")?,
            value_bytes: raw.4,
            created_height: decode_u64_blob(&raw.5, "leaf created height")?,
            history_checksum: array32(&raw.6, "leaf history checksum")?,
        };
        if expected.get(&key) != Some(&observed) {
            return Err(error(
                OrderStateErrorCodeV1::StoreTamper,
                "live Order-state leaf differs from reconstructed history",
            ));
        }
    }
    Ok(())
}

fn sparse_root_and_siblings(
    leaves: &BTreeMap<[u8; 32], StoredLeaf>,
    target: Option<[u8; 32]>,
) -> OrderStateResultV1<([u8; 32], Vec<[u8; 32]>)> {
    let empties = empty_hashes();
    let mut current = leaves
        .iter()
        .map(|(key, leaf)| {
            (
                *key,
                state_leaf_hash(
                    *key,
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
            next.insert(parent, state_node_hash(level, left, right));
        }
        current = next;
    }
    let root = current
        .get(&[0; 32])
        .copied()
        .unwrap_or(empties[STATE_TREE_DEPTH]);
    Ok((root, siblings))
}

fn empty_hashes() -> Vec<[u8; 32]> {
    let mut hashes = Vec::with_capacity(STATE_TREE_DEPTH + 1);
    hashes.push(digest(
        STATE_EMPTY_LEAF_DOMAIN,
        &STATE_TREE_VERSION.to_le_bytes(),
    ));
    for level in 0..STATE_TREE_DEPTH {
        hashes.push(state_node_hash(level, hashes[level], hashes[level]));
    }
    hashes
}

fn state_leaf_hash(
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

fn state_node_hash(level: usize, left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(66);
    encoded.extend_from_slice(
        &u16::try_from(level)
            .expect("fixed sparse-tree level fits u16")
            .to_le_bytes(),
    );
    encoded.extend_from_slice(&left);
    encoded.extend_from_slice(&right);
    digest(STATE_NODE_DOMAIN, &encoded)
}

fn application_state_key(object_kind: u16, object_id: [u8; 32]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(34);
    encoded.extend_from_slice(&object_kind.to_le_bytes());
    encoded.extend_from_slice(&object_id);
    digest(STATE_KEY_DOMAIN, &encoded)
}

fn clear_low_bits(mut key: [u8; 32], count: usize) -> [u8; 32] {
    for offset in 0..count {
        clear_bit(&mut key, 255 - offset);
    }
    key
}

fn bit_at(key: [u8; 32], bit_index: usize) -> u8 {
    (key[bit_index / 8] >> (7 - (bit_index % 8))) & 1
}

fn clear_bit(key: &mut [u8; 32], bit_index: usize) {
    key[bit_index / 8] &= !(1 << (7 - (bit_index % 8)));
}

fn set_bit(key: &mut [u8; 32], bit_index: usize) {
    key[bit_index / 8] |= 1 << (7 - (bit_index % 8));
}

fn toggle_bit(key: &mut [u8; 32], bit_index: usize) {
    key[bit_index / 8] ^= 1 << (7 - (bit_index % 8));
}

fn validate_tag50_value(
    raw: &[u8],
    expected_object_id: [u8; 32],
    expected_state_key: [u8; 32],
) -> OrderStateResultV1<ParsedBinding> {
    if raw.is_empty() || raw.len() > MAX_VALUE_BYTES {
        return Err(error(
            OrderStateErrorCodeV1::PermitMismatch,
            "tag-50 value length is outside the bound",
        ));
    }
    let mut envelope = Cursor::new(raw);
    let envelope_schema = envelope.u16()?;
    let object_kind = envelope.u16()?;
    let object_id = envelope.hash32()?;
    let immutable = envelope.bytes(MAX_VALUE_BYTES)?;
    let mutable = envelope.bytes(MAX_VALUE_BYTES)?;
    envelope.finish()?;
    if envelope_schema != 1
        || object_kind != OBJECT_KIND
        || object_id != expected_object_id
        || expected_state_key != application_state_key(OBJECT_KIND, object_id)
        || immutable.is_empty()
        || mutable.is_empty()
    {
        return Err(error(
            OrderStateErrorCodeV1::PermitMismatch,
            "tag-50 application envelope identity differs",
        ));
    }

    let mut object = Cursor::new(immutable);
    let body_start = object.offset;
    let body_schema = object.u16()?;
    let context_schema = object.u16()?;
    let genesis_hash = object.hash32()?;
    let chain_id = object.bytes(MAX_CHAIN_ID_BYTES)?;
    let protocol_version = object.u32()?;
    let stack_profile_hash = object.hash32()?;
    let candidate_height = object.u64()?;
    let candidate_block_id = object.hash32()?;
    let candidate_composite_root = object.hash32()?;
    let final_execution_root = object.hash32()?;
    let body_end = object.offset;
    let binding_id = object.hash32()?;
    object.finish()?;
    if body_schema != 1
        || context_schema != 1
        || genesis_hash == [0; 32]
        || chain_id.is_empty()
        || std::str::from_utf8(chain_id).is_err()
        || protocol_version != 1
        || stack_profile_hash == [0; 32]
        || candidate_height == 0
        || candidate_block_id == [0; 32]
        || candidate_composite_root == [0; 32]
        || final_execution_root == [0; 32]
        || binding_id != digest(BINDING_ID_DOMAIN, &immutable[body_start..body_end])
        || binding_id != object_id
    {
        return Err(error(
            OrderStateErrorCodeV1::PermitMismatch,
            "tag-50 immutable object is noncanonical or differs",
        ));
    }
    let mut state = Cursor::new(mutable);
    let state_schema = state.u16()?;
    let state_binding_id = state.hash32()?;
    let state_version = state.u64()?;
    state.finish()?;
    if state_schema != 1 || state_binding_id != binding_id || state_version != OBJECT_VERSION {
        return Err(error(
            OrderStateErrorCodeV1::PermitMismatch,
            "tag-50 mutable state is not exact version zero",
        ));
    }
    Ok(ParsedBinding {
        object_id,
        candidate_height,
    })
}

#[allow(clippy::too_many_arguments)]
fn permit_digest(
    store_id: [u8; 32],
    parent_height: u64,
    parent_root: [u8; 32],
    parent_history_checksum: [u8; 32],
    target_height: u64,
    state_key: [u8; 32],
    object_id: [u8; 32],
    value_digest: [u8; 32],
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(216);
    encoded.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    encoded.extend_from_slice(&store_id);
    encoded.extend_from_slice(&parent_height.to_le_bytes());
    encoded.extend_from_slice(&parent_root);
    encoded.extend_from_slice(&parent_history_checksum);
    encoded.extend_from_slice(&target_height.to_le_bytes());
    encoded.extend_from_slice(&state_key);
    encoded.extend_from_slice(&OBJECT_KIND.to_le_bytes());
    encoded.extend_from_slice(&object_id);
    encoded.extend_from_slice(&OBJECT_VERSION.to_le_bytes());
    encoded.extend_from_slice(&value_digest);
    digest(PERMIT_DIGEST_DOMAIN, &encoded)
}

#[allow(clippy::too_many_arguments)]
fn history_checksum(
    store_id: [u8; 32],
    height: u64,
    parent_root: [u8; 32],
    state_root: [u8; 32],
    state_key: [u8; 32],
    object_id: [u8; 32],
    value_digest: [u8; 32],
    permit_digest: [u8; 32],
    predecessor_checksum: [u8; 32],
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(274);
    encoded.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    encoded.extend_from_slice(&store_id);
    encoded.extend_from_slice(&height.to_le_bytes());
    encoded.extend_from_slice(&parent_root);
    encoded.extend_from_slice(&state_root);
    encoded.extend_from_slice(&state_key);
    encoded.extend_from_slice(&OBJECT_KIND.to_le_bytes());
    encoded.extend_from_slice(&object_id);
    encoded.extend_from_slice(&OBJECT_VERSION.to_le_bytes());
    encoded.extend_from_slice(&value_digest);
    encoded.extend_from_slice(&permit_digest);
    encoded.extend_from_slice(&predecessor_checksum);
    digest(HISTORY_CHECKSUM_DOMAIN, &encoded)
}

fn genesis_checksum(store_id: [u8; 32], height: u64, root: [u8; 32]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(74);
    encoded.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    encoded.extend_from_slice(&store_id);
    encoded.extend_from_slice(&height.to_le_bytes());
    encoded.extend_from_slice(&root);
    digest(GENESIS_CHECKSUM_DOMAIN, &encoded)
}

fn digest(domain: &str, encoded: &[u8]) -> [u8; 32] {
    let domain = domain.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(
        u32::try_from(domain.len())
            .expect("static domain length fits u32")
            .to_le_bytes(),
    );
    hasher.update(domain);
    hasher.update(encoded);
    hasher.finalize().into()
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("bounded CEV1 bytes fit u32")
            .to_le_bytes(),
    );
    output.extend_from_slice(bytes);
}

struct Cursor<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(raw: &'a [u8]) -> Self {
        Self { raw, offset: 0 }
    }

    fn take(&mut self, length: usize) -> OrderStateResultV1<&'a [u8]> {
        let end = self.offset.checked_add(length).ok_or_else(|| {
            error(
                OrderStateErrorCodeV1::PermitMismatch,
                "tag-50 CEV1 offset overflows",
            )
        })?;
        let value = self.raw.get(self.offset..end).ok_or_else(|| {
            error(
                OrderStateErrorCodeV1::PermitMismatch,
                "tag-50 CEV1 value is truncated",
            )
        })?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> OrderStateResultV1<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| {
            error(
                OrderStateErrorCodeV1::PermitMismatch,
                "tag-50 fixed field is truncated",
            )
        })
    }

    fn u16(&mut self) -> OrderStateResultV1<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> OrderStateResultV1<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> OrderStateResultV1<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn hash32(&mut self) -> OrderStateResultV1<[u8; 32]> {
        self.array()
    }

    fn bytes(&mut self, maximum: usize) -> OrderStateResultV1<&'a [u8]> {
        let length = usize::try_from(self.u32()?).map_err(|_| {
            error(
                OrderStateErrorCodeV1::PermitMismatch,
                "tag-50 CEV1 byte length cannot fit usize",
            )
        })?;
        if length > maximum {
            return Err(error(
                OrderStateErrorCodeV1::PermitMismatch,
                "tag-50 CEV1 byte field exceeds bound",
            ));
        }
        self.take(length)
    }

    fn finish(&self) -> OrderStateResultV1<()> {
        if self.offset != self.raw.len() {
            return Err(error(
                OrderStateErrorCodeV1::PermitMismatch,
                "tag-50 CEV1 value has trailing bytes",
            ));
        }
        Ok(())
    }
}

fn verify_schema(connection: &Connection) -> OrderStateResultV1<()> {
    if connection.query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))?
        != SQLITE_APPLICATION_ID
        || connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?
            != SQLITE_USER_VERSION
    {
        return Err(error(
            OrderStateErrorCodeV1::SchemaMismatch,
            "Order-state SQLite identity/schema version differs",
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
        ("order_state_history_v1".to_owned(), HISTORY_SQL.to_owned()),
        ("order_state_leaves_v1".to_owned(), LEAVES_SQL.to_owned()),
        (
            "order_state_metadata_v1".to_owned(),
            METADATA_SQL.to_owned(),
        ),
    ];
    if actual != expected {
        return Err(error(
            OrderStateErrorCodeV1::SchemaMismatch,
            "Order-state SQLite schema differs",
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
    if !path.is_absolute() {
        return Err(unavailable("Order-state path must be absolute"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| unavailable("Order-state path has no parent"))?;
    let parent = fs::canonicalize(parent).map_err(|cause| unavailable(cause.to_string()))?;
    let name = path
        .file_name()
        .ok_or_else(|| unavailable("Order-state path has no file name"))?;
    let resolved = parent.join(name);
    let metadata = match fs::symlink_metadata(&resolved) {
        Ok(metadata) if must_exist => Some(metadata),
        Ok(_) => return Err(unavailable("Order-state path already exists")),
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound && !must_exist => None,
        Err(cause) => return Err(unavailable(cause.to_string())),
    };
    if let Some(metadata) = metadata {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(unavailable(
                "Order-state path is not one regular non-symlink file",
            ));
        }
    }
    Ok(resolved)
}

#[cfg(unix)]
fn file_identity(path: &Path) -> OrderStateResultV1<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path).map_err(|cause| unavailable(cause.to_string()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(unavailable(
            "Order-state database must be one mode-0600 regular single-link non-symlink file",
        ));
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        links: metadata.nlink(),
        mode: metadata.mode(),
    })
}

#[cfg(not(unix))]
fn file_identity(path: &Path) -> OrderStateResultV1<FileIdentity> {
    let metadata = fs::metadata(path).map_err(|cause| unavailable(cause.to_string()))?;
    if !metadata.is_file() {
        return Err(unavailable("Order-state database is not a regular file"));
    }
    Ok(FileIdentity {
        canonical_path: fs::canonicalize(path).map_err(|cause| unavailable(cause.to_string()))?,
    })
}

fn reject_sidecars(path: &Path) -> OrderStateResultV1<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar: OsString = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match fs::symlink_metadata(Path::new(&sidecar)) {
            Ok(_) => return Err(unavailable("Order-state SQLite sidecar is present")),
            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => {}
            Err(cause) => return Err(unavailable(cause.to_string())),
        }
    }
    Ok(())
}

fn array32(raw: &[u8], label: &str) -> OrderStateResultV1<[u8; 32]> {
    raw.try_into().map_err(|_| {
        error(
            OrderStateErrorCodeV1::StoreTamper,
            format!("{label} length differs"),
        )
    })
}

fn decode_u64_blob(raw: &[u8], label: &str) -> OrderStateResultV1<u64> {
    let bytes: [u8; 8] = raw.try_into().map_err(|_| {
        error(
            OrderStateErrorCodeV1::StoreTamper,
            format!("{label} length differs"),
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

fn unavailable(detail: impl Into<String>) -> crate::OrderStateErrorV1 {
    error(OrderStateErrorCodeV1::StoreUnavailable, detail)
}
