//! Inert, exact-parent application-state preview for AI-native v1 Order.
//!
//! The first bounded slice supports only an empty/no-op transition and one or
//! more deterministic system creates of immutable object kind 50. It computes
//! the complete application sparse-JMT root and then seals the exact eight-root
//! [`BlockHeaderV1`]. It owns no database, signer, Safety, Core, finality, or
//! commit permit.
//!
//! A prepared preview is deliberately non-duplicable and has no commit API:
//!
//! ```compile_fail
//! use trnm_poco_order_application_v1::PreparedOrderBlockV1;
//! fn requires_clone<T: Clone>() {}
//! requires_clone::<PreparedOrderBlockV1>();
//! ```
//!
//! ```compile_fail
//! # fn consume(value: trnm_poco_order_application_v1::PreparedOrderBlockV1) {
//! value.commit();
//! # }
//! ```
//!
//! Legacy opaque bytes cannot enter the closed v1 operation API:
//!
//! ```compile_fail
//! use trnm_poco_order_application_v1::OrderApplicationOperationV1;
//! let _operation: OrderApplicationOperationV1 = vec![0_u8; 8];
//! ```
//!
//! A recovered durable parent is also an exact, non-duplicable planning
//! carrier rather than caller-constructible state authority:
//!
//! ```compile_fail
//! use trnm_poco_order_application_v1::RecoveredOrderApplicationParentV1;
//! let _forged = RecoveredOrderApplicationParentV1 {};
//! ```
//!
//! ```compile_fail
//! use trnm_poco_order_application_v1::RecoveredOrderApplicationParentV1;
//! fn duplicate(value: RecoveredOrderApplicationParentV1) { let _copy = value.clone(); }
//! ```
//!
//! The T0-A manifest-bound seal and its later-CAS request are also linear,
//! private-construction carriers.  They remain inert and grant no execution,
//! signing, finality, write, or checkpoint authority:
//!
//! ```compile_fail
//! use trnm_poco_order_application_v1::G2FinalizeBindingRequestV2;
//! fn duplicate(value: G2FinalizeBindingRequestV2) { let _copy = value.clone(); }
//! ```
//!
//! ```compile_fail
//! use trnm_poco_order_application_v1::G2FinalizeBindingRequestV2;
//! let _forged = G2FinalizeBindingRequestV2 {};
//! ```
//!
//! Caller-selected roots are absent from the header template:
//!
//! ```compile_fail
//! use trnm_poco_order_application_v1::OrderHeaderTemplateV1;
//! fn substitute_root(mut template: OrderHeaderTemplateV1) {
//!     template.post_state_root = [9_u8; 32];
//! }
//! ```

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use trnm_poco_order_types_v1::{
    derive_block_id_v1, domain_separated_digest_v1, empty_ordered_root_v1, BlockHeaderV1,
    BlockIdV1, BlockKindV1, Cev1EncodeV1, EpochDescriptorIdV1, EpochHandoffIdV1, ParentBlockRefV1,
    ProtocolContextV1, QuorumCertificateIdV1, TimeoutCertificateIdV1, UpgradePlanIdV1,
};

mod g2_manifest_v2;

pub use g2_manifest_v2::{
    revalidate_sealed_manifest_bound_g2_order_block_v2, seal_manifest_bound_g2_order_block_v2,
    G2FinalizeBindingRequestV2, SealedManifestBoundG2OrderBlockV2,
};

pub const GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1: u16 = 50;
pub const GLOBAL_EXECUTION_BINDING_ID_DOMAIN_V1: &str = "trnm.poco-ai.global-execution-binding.v1";

const SCHEMA_VERSION_V1: u16 = 1;
const OBJECT_VERSION_V1: u64 = 0;
const STATE_TREE_VERSION_V1: u16 = 0;
const STATE_TREE_DEPTH_V1: usize = 256;
const MAX_CHAIN_ID_BYTES_V1: usize = 1024;
const MAX_VALUE_BYTES_V1: usize = 4 * 1024 * 1024;
const MAX_SYSTEM_CREATES_PER_BLOCK_V1: usize = 16;
const MAX_RECOVERED_PARENT_LEAVES_V1: usize = 131_072;
const MAX_RECOVERED_PARENT_VALUE_BYTES_V1: usize = 64 * 1024 * 1024;
const STATE_KEY_DOMAIN_V1: &str = "trnm.poco-ai.state-key.v1";
const STATE_EMPTY_LEAF_DOMAIN_V1: &str = "trnm.poco-ai.state-empty-leaf.v1";
const STATE_LEAF_DOMAIN_V1: &str = "trnm.poco-ai.state-leaf.v1";
const STATE_NODE_DOMAIN_V1: &str = "trnm.poco-ai.state-node.v1";
const PREPARED_PLAN_DOMAIN_V1: &str = "trnm.poco-ai.order-application-prepared-plan.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderApplicationErrorCodeV1 {
    InvalidContext,
    InvalidParent,
    InvalidHeader,
    InvalidOperation,
    InvalidBinding,
    SelfCandidateBinding,
    NonCanonicalOrder,
    DuplicateObject,
    ArithmeticOverflow,
    RootMismatch,
    PlanMismatch,
    RecoveredParentInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderApplicationErrorV1 {
    code: OrderApplicationErrorCodeV1,
    detail: &'static str,
}

impl OrderApplicationErrorV1 {
    pub const fn code(&self) -> OrderApplicationErrorCodeV1 {
        self.code
    }
}

impl fmt::Display for OrderApplicationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Order application preview rejected: {}",
            self.detail
        )
    }
}

impl Error for OrderApplicationErrorV1 {}

pub type OrderApplicationResultV1<T> = Result<T, OrderApplicationErrorV1>;

fn reject<T>(
    code: OrderApplicationErrorCodeV1,
    detail: &'static str,
) -> OrderApplicationResultV1<T> {
    Err(OrderApplicationErrorV1 { code, detail })
}

/// Public, inert facts from a previously finalized G2 candidate.
///
/// A future Node adapter must construct this only by borrowing a retained
/// non-Clone terminal owner. This low-level crate intentionally treats it as
/// public planning material and grants no write/finality authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GlobalExecutionBindingInputV1 {
    context: ProtocolContextV1,
    candidate_height: u64,
    candidate_block_id: BlockIdV1,
    candidate_composite_root: [u8; 32],
    final_execution_root: [u8; 32],
}

impl GlobalExecutionBindingInputV1 {
    pub fn new(
        context: ProtocolContextV1,
        candidate_height: u64,
        candidate_block_id: BlockIdV1,
        candidate_composite_root: [u8; 32],
        final_execution_root: [u8; 32],
    ) -> OrderApplicationResultV1<Self> {
        validate_context(&context)?;
        if candidate_height == 0
            || candidate_block_id.to_bytes() == [0; 32]
            || candidate_composite_root == [0; 32]
            || final_execution_root == [0; 32]
        {
            return reject(
                OrderApplicationErrorCodeV1::InvalidBinding,
                "tag-50 candidate height, block ID, or execution root is zero",
            );
        }
        Ok(Self {
            context,
            candidate_height,
            candidate_block_id,
            candidate_composite_root,
            final_execution_root,
        })
    }

    pub const fn candidate_height(&self) -> u64 {
        self.candidate_height
    }

    pub const fn candidate_block_id(&self) -> BlockIdV1 {
        self.candidate_block_id
    }

    pub fn object_id_v1(&self) -> [u8; 32] {
        derive_binding_material(self).object_id
    }
}

/// Header authority fields excluding all eight execution-derived roots.
///
/// Omitting roots from this input makes root substitution impossible at the
/// producer boundary. The preview computes seven exact empty ordered roots and
/// the complete post-state root itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderHeaderTemplateV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub epoch: u64,
    pub view: u64,
    pub height: u64,
    pub block_kind: BlockKindV1,
    pub parent: ParentBlockRefV1,
    pub proposer_id: Vec<u8>,
    pub epoch_descriptor_id: EpochDescriptorIdV1,
    pub justify_qc_id: Option<QuorumCertificateIdV1>,
    pub timeout_certificate_id: Option<TimeoutCertificateIdV1>,
    pub next_epoch_descriptor_id: Option<EpochDescriptorIdV1>,
    pub upgrade_plan_id: Option<UpgradePlanIdV1>,
    pub epoch_handoff_id: Option<EpochHandoffIdV1>,
}

/// Empty-state, already authenticated parent cut used to start the bounded
/// application preview chain. It is public data, not a finality proof.
#[derive(Debug)]
pub struct EmptyOrderStateAnchorV1 {
    height: u64,
    block_id: BlockIdV1,
    state_root: [u8; 32],
}

impl EmptyOrderStateAnchorV1 {
    pub fn new(height: u64, block_id: BlockIdV1) -> OrderApplicationResultV1<Self> {
        if height == 0 || block_id.to_bytes() == [0; 32] {
            return reject(
                OrderApplicationErrorCodeV1::InvalidParent,
                "empty Order-state anchor height or block ID is zero",
            );
        }
        Ok(Self {
            height,
            block_id,
            state_root: empty_order_state_root_v1(),
        })
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrderApplicationOperationV1 {
    Noop,
    CreateGlobalExecutionBinding(GlobalExecutionBindingInputV1),
}

#[derive(Clone, Copy, Debug)]
pub enum OrderApplicationParentV1<'a> {
    EmptyAnchor(&'a EmptyOrderStateAnchorV1),
    Prepared(&'a PreparedOrderBlockV1),
    Recovered(&'a RecoveredOrderApplicationParentV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StateLeafV1 {
    object_kind: u16,
    object_version: u64,
    value_bytes: Vec<u8>,
}

/// One inert leaf supplied by a durable canonical-store recovery adapter.
///
/// The public constructor grants no write or finality authority. It merely
/// preserves enough exact facts for the application crate to re-parse the
/// registered tag-50 value and recompute the complete sparse-state root.
#[derive(Debug)]
pub struct RecoveredOrderApplicationLeafV1 {
    materialized_height: u64,
    object_kind: u16,
    object_id: [u8; 32],
    object_version: u64,
    state_key: [u8; 32],
    value_bytes: Vec<u8>,
    candidate_height: u64,
    candidate_block_id: BlockIdV1,
}

impl RecoveredOrderApplicationLeafV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        materialized_height: u64,
        object_kind: u16,
        object_id: [u8; 32],
        object_version: u64,
        state_key: [u8; 32],
        value_bytes: Vec<u8>,
        candidate_height: u64,
        candidate_block_id: BlockIdV1,
    ) -> OrderApplicationResultV1<Self> {
        if materialized_height == 0
            || object_kind != GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1
            || object_id == [0; 32]
            || object_version != OBJECT_VERSION_V1
            || state_key != application_state_key_v1(object_kind, object_id)
            || value_bytes.is_empty()
            || value_bytes.len() > MAX_VALUE_BYTES_V1
            || candidate_height == 0
            || candidate_height >= materialized_height
            || candidate_block_id.to_bytes() == [0; 32]
        {
            return reject(
                OrderApplicationErrorCodeV1::RecoveredParentInvalid,
                "recovered Order leaf identity, height, or value bound differs",
            );
        }
        let leaf = Self {
            materialized_height,
            object_kind,
            object_id,
            object_version,
            state_key,
            value_bytes,
            candidate_height,
            candidate_block_id,
        };
        leaf.validate()?;
        Ok(leaf)
    }

    fn validate(&self) -> OrderApplicationResultV1<()> {
        if self.materialized_height == 0
            || self.candidate_height == 0
            || self.candidate_height >= self.materialized_height
        {
            return reject(
                OrderApplicationErrorCodeV1::RecoveredParentInvalid,
                "recovered Order leaf height relation differs",
            );
        }
        validate_binding_value(&PreparedSystemObjectCreateV1 {
            object_kind: self.object_kind,
            object_id: self.object_id,
            object_version: self.object_version,
            state_key: self.state_key,
            value_bytes: self.value_bytes.clone(),
            candidate_height: self.candidate_height,
            candidate_block_id: self.candidate_block_id,
        })
        .map_err(|_| OrderApplicationErrorV1 {
            code: OrderApplicationErrorCodeV1::RecoveredParentInvalid,
            detail: "recovered Order leaf tag-50 value differs",
        })
    }
}

/// Exact inert application parent reconstructed from a durable canonical
/// store's complete fresh-audited live projection.
///
/// This type is intentionally non-Clone and has no public fields. A caller can
/// supply planning facts to the recovery function below, but only the
/// canonical Order-state store can wrap the result in its private durable
/// parent owner and later authorize a write.
#[must_use = "the recovered Order application parent is an exact planning carrier"]
#[derive(Debug)]
pub struct RecoveredOrderApplicationParentV1 {
    header: BlockHeaderV1,
    block_id: BlockIdV1,
    entries: Vec<RecoveredOrderApplicationLeafV1>,
    leaves: BTreeMap<[u8; 32], StateLeafV1>,
}

impl RecoveredOrderApplicationParentV1 {
    pub const fn height(&self) -> u64 {
        self.header.height
    }

    pub const fn block_id(&self) -> BlockIdV1 {
        self.block_id
    }

    pub const fn state_root(&self) -> [u8; 32] {
        self.header.post_state_root
    }

    pub const fn header(&self) -> &BlockHeaderV1 {
        &self.header
    }
}

/// Recompute one inert recovered parent from bounded canonical leaf facts.
///
/// This does not inspect a database and is not write authority. The
/// authoritative Order-state adapter must independently fresh-audit its
/// header/history/pin before and after invoking this function.
pub fn recover_order_application_parent_v1(
    header: BlockHeaderV1,
    block_id: BlockIdV1,
    entries: Vec<RecoveredOrderApplicationLeafV1>,
) -> OrderApplicationResultV1<RecoveredOrderApplicationParentV1> {
    validate_context(&header.context)?;
    if header.schema_version != SCHEMA_VERSION_V1
        || header.height == 0
        || block_id.to_bytes() == [0; 32]
        || derive_block_id_v1(&header) != block_id
        || header.block_kind != BlockKindV1::Ordinary
        || !matches!(header.parent, ParentBlockRefV1::V1Block(_))
        || header.proposer_id.is_empty()
        || header.proposer_id.len() > 128
        || header.epoch_descriptor_id.to_bytes() == [0; 32]
        || header.justify_qc_id.is_none()
        || header.next_epoch_descriptor_id.is_some()
        || header.upgrade_plan_id.is_some()
        || header.epoch_handoff_id.is_some()
        || !has_expected_non_state_roots(&header)
        || entries.len() > MAX_RECOVERED_PARENT_LEAVES_V1
    {
        return reject(
            OrderApplicationErrorCodeV1::RecoveredParentInvalid,
            "recovered Order parent identity or leaf count differs",
        );
    }
    let mut total_value_bytes = 0_usize;
    let mut leaves = BTreeMap::new();
    for entry in &entries {
        entry.validate()?;
        if entry.materialized_height > header.height {
            return reject(
                OrderApplicationErrorCodeV1::RecoveredParentInvalid,
                "recovered Order leaf is newer than its durable parent",
            );
        }
        total_value_bytes = total_value_bytes
            .checked_add(entry.value_bytes.len())
            .ok_or(OrderApplicationErrorV1 {
                code: OrderApplicationErrorCodeV1::ArithmeticOverflow,
                detail: "recovered Order parent value inventory overflows",
            })?;
        if total_value_bytes > MAX_RECOVERED_PARENT_VALUE_BYTES_V1
            || leaves
                .insert(
                    entry.state_key,
                    StateLeafV1 {
                        object_kind: entry.object_kind,
                        object_version: entry.object_version,
                        value_bytes: entry.value_bytes.clone(),
                    },
                )
                .is_some()
        {
            return reject(
                OrderApplicationErrorCodeV1::RecoveredParentInvalid,
                "recovered Order parent bytes or keys are noncanonical",
            );
        }
    }
    if sparse_state_root(&leaves) != header.post_state_root {
        return reject(
            OrderApplicationErrorCodeV1::RootMismatch,
            "recovered Order parent sparse root differs",
        );
    }
    Ok(RecoveredOrderApplicationParentV1 {
        header,
        block_id,
        entries,
        leaves,
    })
}

pub fn revalidate_recovered_order_application_parent_v1(
    parent: &RecoveredOrderApplicationParentV1,
) -> OrderApplicationResultV1<()> {
    if parent.header.schema_version != SCHEMA_VERSION_V1
        || parent.header.height == 0
        || parent.block_id.to_bytes() == [0; 32]
        || validate_context(&parent.header.context).is_err()
        || derive_block_id_v1(&parent.header) != parent.block_id
        || parent.header.block_kind != BlockKindV1::Ordinary
        || !matches!(parent.header.parent, ParentBlockRefV1::V1Block(_))
        || parent.header.proposer_id.is_empty()
        || parent.header.proposer_id.len() > 128
        || parent.header.epoch_descriptor_id.to_bytes() == [0; 32]
        || parent.header.justify_qc_id.is_none()
        || parent.header.next_epoch_descriptor_id.is_some()
        || parent.header.upgrade_plan_id.is_some()
        || parent.header.epoch_handoff_id.is_some()
        || !has_expected_non_state_roots(&parent.header)
        || parent.entries.len() > MAX_RECOVERED_PARENT_LEAVES_V1
    {
        return reject(
            OrderApplicationErrorCodeV1::RecoveredParentInvalid,
            "retained recovered Order parent identity differs",
        );
    }
    let mut total_value_bytes = 0_usize;
    let mut leaves = BTreeMap::new();
    for entry in &parent.entries {
        entry.validate()?;
        if entry.materialized_height > parent.header.height {
            return reject(
                OrderApplicationErrorCodeV1::RecoveredParentInvalid,
                "retained recovered leaf is newer than its parent",
            );
        }
        total_value_bytes = total_value_bytes
            .checked_add(entry.value_bytes.len())
            .ok_or(OrderApplicationErrorV1 {
                code: OrderApplicationErrorCodeV1::ArithmeticOverflow,
                detail: "retained recovered Order parent bytes overflow",
            })?;
        if total_value_bytes > MAX_RECOVERED_PARENT_VALUE_BYTES_V1
            || leaves
                .insert(
                    entry.state_key,
                    StateLeafV1 {
                        object_kind: entry.object_kind,
                        object_version: entry.object_version,
                        value_bytes: entry.value_bytes.clone(),
                    },
                )
                .is_some()
        {
            return reject(
                OrderApplicationErrorCodeV1::RecoveredParentInvalid,
                "retained recovered Order parent keys or bytes differ",
            );
        }
    }
    if leaves != parent.leaves || sparse_state_root(&leaves) != parent.header.post_state_root {
        return reject(
            OrderApplicationErrorCodeV1::RootMismatch,
            "retained recovered Order parent root differs",
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedSystemObjectCreateV1 {
    object_kind: u16,
    object_id: [u8; 32],
    object_version: u64,
    state_key: [u8; 32],
    value_bytes: Vec<u8>,
    candidate_height: u64,
    candidate_block_id: BlockIdV1,
}

impl PreparedSystemObjectCreateV1 {
    pub const fn object_kind(&self) -> u16 {
        self.object_kind
    }

    pub const fn object_id(&self) -> [u8; 32] {
        self.object_id
    }

    pub const fn object_version(&self) -> u64 {
        self.object_version
    }

    pub const fn state_key(&self) -> [u8; 32] {
        self.state_key
    }

    pub fn value_bytes(&self) -> &[u8] {
        &self.value_bytes
    }
}

#[must_use = "the inert prepared block must be retained for an exact later Node-owned transition"]
#[derive(Debug)]
pub struct PreparedOrderBlockV1 {
    parent_height: u64,
    parent_block_id: BlockIdV1,
    parent_state_root: [u8; 32],
    parent_leaves: BTreeMap<[u8; 32], StateLeafV1>,
    header: BlockHeaderV1,
    block_id: BlockIdV1,
    target_leaves: BTreeMap<[u8; 32], StateLeafV1>,
    system_creates: Vec<PreparedSystemObjectCreateV1>,
    plan_digest: [u8; 32],
}

impl PreparedOrderBlockV1 {
    pub const fn header(&self) -> &BlockHeaderV1 {
        &self.header
    }

    pub const fn block_id(&self) -> BlockIdV1 {
        self.block_id
    }

    pub const fn parent_state_root(&self) -> [u8; 32] {
        self.parent_state_root
    }

    pub const fn post_state_root(&self) -> [u8; 32] {
        self.header.post_state_root
    }

    pub fn system_creates(&self) -> &[PreparedSystemObjectCreateV1] {
        &self.system_creates
    }

    pub const fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }
}

pub fn preview_order_block_v1(
    parent: OrderApplicationParentV1<'_>,
    template: OrderHeaderTemplateV1,
    operations: &[OrderApplicationOperationV1],
) -> OrderApplicationResultV1<PreparedOrderBlockV1> {
    let parent_view = parent_view(parent)?;
    validate_template(&template, &parent_view)?;

    let bindings = validate_operation_shape(operations)?;
    let mut creates = Vec::with_capacity(bindings.len());
    let mut previous_key = None;
    for binding in bindings {
        if binding.context != template.context || binding.candidate_height >= template.height {
            return reject(
                OrderApplicationErrorCodeV1::InvalidBinding,
                "tag-50 context differs or candidate is not at a strict earlier height",
            );
        }
        let material = derive_binding_material(binding);
        let key = (material.object_kind, material.object_id);
        if previous_key.is_some_and(|previous| previous >= key) {
            return reject(
                OrderApplicationErrorCodeV1::NonCanonicalOrder,
                "system creates are not strictly ordered and unique by typed object key",
            );
        }
        previous_key = Some(key);
        if parent_view.leaves.contains_key(&material.state_key) {
            return reject(
                OrderApplicationErrorCodeV1::DuplicateObject,
                "system create state key already exists at the exact parent",
            );
        }
        creates.push(material);
    }

    let mut target_leaves = parent_view.leaves.clone();
    for create in &creates {
        if target_leaves
            .insert(
                create.state_key,
                StateLeafV1 {
                    object_kind: create.object_kind,
                    object_version: create.object_version,
                    value_bytes: create.value_bytes.clone(),
                },
            )
            .is_some()
        {
            return reject(
                OrderApplicationErrorCodeV1::DuplicateObject,
                "system creates collide in the target sparse JMT",
            );
        }
    }
    let post_state_root = sparse_state_root(&target_leaves);
    let header = seal_header(template, post_state_root);
    let block_id = derive_block_id_v1(&header);
    if creates
        .iter()
        .any(|create| create.candidate_block_id == block_id)
    {
        return reject(
            OrderApplicationErrorCodeV1::SelfCandidateBinding,
            "tag-50 object binds the block that would contain it",
        );
    }
    let plan_digest = prepared_plan_digest(
        parent_view.height,
        parent_view.block_id,
        parent_view.state_root,
        &header,
        block_id,
        &creates,
    );
    let prepared = PreparedOrderBlockV1 {
        parent_height: parent_view.height,
        parent_block_id: parent_view.block_id,
        parent_state_root: parent_view.state_root,
        parent_leaves: parent_view.leaves,
        header,
        block_id,
        target_leaves,
        system_creates: creates,
        plan_digest,
    };
    revalidate_prepared_order_block_v1(&prepared)?;
    Ok(prepared)
}

/// Recompute every inert plan commitment. This does not promote the plan into
/// a writable or signable capability.
pub fn revalidate_prepared_order_block_v1(
    prepared: &PreparedOrderBlockV1,
) -> OrderApplicationResultV1<()> {
    if sparse_state_root(&prepared.parent_leaves) != prepared.parent_state_root {
        return reject(
            OrderApplicationErrorCodeV1::RootMismatch,
            "prepared parent sparse-JMT root differs",
        );
    }
    let expected_height = prepared
        .parent_height
        .checked_add(1)
        .ok_or(OrderApplicationErrorV1 {
            code: OrderApplicationErrorCodeV1::ArithmeticOverflow,
            detail: "prepared successor height overflows",
        })?;
    if prepared.header.height != expected_height
        || prepared.header.parent != ParentBlockRefV1::V1Block(prepared.parent_block_id)
        || prepared.header.post_state_root != sparse_state_root(&prepared.target_leaves)
        || !has_expected_non_state_roots(&prepared.header)
        || derive_block_id_v1(&prepared.header) != prepared.block_id
    {
        return reject(
            OrderApplicationErrorCodeV1::RootMismatch,
            "prepared header, parent, root, or block ID differs",
        );
    }
    let mut expected = prepared.parent_leaves.clone();
    let mut previous_key = None;
    for create in &prepared.system_creates {
        let key = (create.object_kind, create.object_id);
        if previous_key.is_some_and(|previous| previous >= key)
            || create.object_kind != GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1
            || create.object_version != OBJECT_VERSION_V1
            || create.state_key != application_state_key_v1(create.object_kind, create.object_id)
            || create.candidate_height >= prepared.header.height
            || create.candidate_block_id == prepared.block_id
            || validate_binding_value(create).is_err()
            || expected
                .insert(
                    create.state_key,
                    StateLeafV1 {
                        object_kind: create.object_kind,
                        object_version: create.object_version,
                        value_bytes: create.value_bytes.clone(),
                    },
                )
                .is_some()
        {
            return reject(
                OrderApplicationErrorCodeV1::PlanMismatch,
                "prepared system-create plan failed exact revalidation",
            );
        }
        previous_key = Some(key);
    }
    if expected != prepared.target_leaves {
        return reject(
            OrderApplicationErrorCodeV1::PlanMismatch,
            "prepared target leaves differ from exact system creates",
        );
    }
    let expected_digest = prepared_plan_digest(
        prepared.parent_height,
        prepared.parent_block_id,
        prepared.parent_state_root,
        &prepared.header,
        prepared.block_id,
        &prepared.system_creates,
    );
    if expected_digest != prepared.plan_digest {
        return reject(
            OrderApplicationErrorCodeV1::PlanMismatch,
            "prepared plan digest differs",
        );
    }
    Ok(())
}

pub fn empty_order_state_root_v1() -> [u8; 32] {
    empty_hashes()[STATE_TREE_DEPTH_V1]
}

pub fn application_state_key_v1(object_kind: u16, object_id: [u8; 32]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(34);
    put_u16(&mut encoded, object_kind);
    put_hash(&mut encoded, object_id);
    domain_separated_digest_v1(STATE_KEY_DOMAIN_V1, &encoded)
}

#[derive(Debug)]
struct ParentViewV1 {
    height: u64,
    block_id: BlockIdV1,
    state_root: [u8; 32],
    leaves: BTreeMap<[u8; 32], StateLeafV1>,
    context: Option<ProtocolContextV1>,
    epoch: Option<u64>,
    view: Option<u64>,
    epoch_descriptor_id: Option<EpochDescriptorIdV1>,
}

fn parent_view(parent: OrderApplicationParentV1<'_>) -> OrderApplicationResultV1<ParentViewV1> {
    match parent {
        OrderApplicationParentV1::EmptyAnchor(anchor) => {
            if anchor.state_root != empty_order_state_root_v1() {
                return reject(
                    OrderApplicationErrorCodeV1::RootMismatch,
                    "empty parent anchor root differs",
                );
            }
            Ok(ParentViewV1 {
                height: anchor.height,
                block_id: anchor.block_id,
                state_root: anchor.state_root,
                leaves: BTreeMap::new(),
                context: None,
                epoch: None,
                view: None,
                epoch_descriptor_id: None,
            })
        }
        OrderApplicationParentV1::Prepared(prepared) => {
            revalidate_prepared_order_block_v1(prepared)?;
            Ok(ParentViewV1 {
                height: prepared.header.height,
                block_id: prepared.block_id,
                state_root: prepared.header.post_state_root,
                leaves: prepared.target_leaves.clone(),
                context: Some(prepared.header.context.clone()),
                epoch: Some(prepared.header.epoch),
                view: Some(prepared.header.view),
                epoch_descriptor_id: Some(prepared.header.epoch_descriptor_id),
            })
        }
        OrderApplicationParentV1::Recovered(recovered) => {
            revalidate_recovered_order_application_parent_v1(recovered)?;
            Ok(ParentViewV1 {
                height: recovered.header.height,
                block_id: recovered.block_id,
                state_root: recovered.header.post_state_root,
                leaves: recovered.leaves.clone(),
                context: Some(recovered.header.context.clone()),
                epoch: Some(recovered.header.epoch),
                view: Some(recovered.header.view),
                epoch_descriptor_id: Some(recovered.header.epoch_descriptor_id),
            })
        }
    }
}

fn validate_context(context: &ProtocolContextV1) -> OrderApplicationResultV1<()> {
    if context.schema_version != SCHEMA_VERSION_V1
        || context.protocol_version != 1
        || context.genesis_hash == [0; 32]
        || context.stack_profile_hash == [0; 32]
        || context.chain_id.is_empty()
        || context.chain_id.len() > MAX_CHAIN_ID_BYTES_V1
    {
        return reject(
            OrderApplicationErrorCodeV1::InvalidContext,
            "v1 protocol context is invalid",
        );
    }
    Ok(())
}

fn validate_template(
    template: &OrderHeaderTemplateV1,
    parent: &ParentViewV1,
) -> OrderApplicationResultV1<()> {
    validate_context(&template.context)?;
    let expected_height = parent
        .height
        .checked_add(1)
        .ok_or(OrderApplicationErrorV1 {
            code: OrderApplicationErrorCodeV1::ArithmeticOverflow,
            detail: "Order application successor height overflows",
        })?;
    if template.schema_version != SCHEMA_VERSION_V1
        || template.height != expected_height
        || template.block_kind != BlockKindV1::Ordinary
        || template.parent != ParentBlockRefV1::V1Block(parent.block_id)
        || parent
            .context
            .as_ref()
            .is_some_and(|context| context != &template.context)
        || parent.epoch.is_some_and(|epoch| epoch != template.epoch)
        || parent.view.is_some_and(|view| template.view <= view)
        || parent
            .epoch_descriptor_id
            .is_some_and(|descriptor| descriptor != template.epoch_descriptor_id)
        || template.proposer_id.is_empty()
        || template.proposer_id.len() > 128
        || template.epoch_descriptor_id.to_bytes() == [0; 32]
        || template.justify_qc_id.is_none()
        || template.next_epoch_descriptor_id.is_some()
        || template.upgrade_plan_id.is_some()
        || template.epoch_handoff_id.is_some()
    {
        return reject(
            OrderApplicationErrorCodeV1::InvalidHeader,
            "bounded application preview requires one exact ordinary successor template",
        );
    }
    Ok(())
}

fn validate_operation_shape(
    operations: &[OrderApplicationOperationV1],
) -> OrderApplicationResultV1<Vec<&GlobalExecutionBindingInputV1>> {
    if operations.is_empty() || matches!(operations, [OrderApplicationOperationV1::Noop]) {
        return Ok(Vec::new());
    }
    if operations.len() > MAX_SYSTEM_CREATES_PER_BLOCK_V1 {
        return reject(
            OrderApplicationErrorCodeV1::InvalidOperation,
            "system-create count exceeds the bounded preview limit",
        );
    }
    let mut bindings = Vec::with_capacity(operations.len());
    for operation in operations {
        match operation {
            OrderApplicationOperationV1::Noop => {
                return reject(
                    OrderApplicationErrorCodeV1::InvalidOperation,
                    "Noop cannot be mixed with system creates",
                )
            }
            OrderApplicationOperationV1::CreateGlobalExecutionBinding(binding) => {
                bindings.push(binding)
            }
        }
    }
    Ok(bindings)
}

fn seal_header(template: OrderHeaderTemplateV1, post_state_root: [u8; 32]) -> BlockHeaderV1 {
    BlockHeaderV1 {
        schema_version: template.schema_version,
        context: template.context,
        epoch: template.epoch,
        view: template.view,
        height: template.height,
        block_kind: template.block_kind,
        parent: template.parent,
        proposer_id: template.proposer_id,
        epoch_descriptor_id: template.epoch_descriptor_id,
        justify_qc_id: template.justify_qc_id,
        timeout_certificate_id: template.timeout_certificate_id,
        batch_refs_root: empty_ordered_root_v1(0),
        protocol_objects_root: empty_ordered_root_v1(1),
        post_state_root,
        transaction_execution_receipts_root: empty_ordered_root_v1(2),
        evidence_root: empty_ordered_root_v1(3),
        consumption_rollups_root: empty_ordered_root_v1(4),
        settlement_root: empty_ordered_root_v1(5),
        resource_usage_root: empty_ordered_root_v1(6),
        next_epoch_descriptor_id: template.next_epoch_descriptor_id,
        upgrade_plan_id: template.upgrade_plan_id,
        epoch_handoff_id: template.epoch_handoff_id,
    }
}

fn has_expected_non_state_roots(header: &BlockHeaderV1) -> bool {
    header.batch_refs_root == empty_ordered_root_v1(0)
        && header.protocol_objects_root == empty_ordered_root_v1(1)
        && header.transaction_execution_receipts_root == empty_ordered_root_v1(2)
        && header.evidence_root == empty_ordered_root_v1(3)
        && header.consumption_rollups_root == empty_ordered_root_v1(4)
        && header.settlement_root == empty_ordered_root_v1(5)
        && header.resource_usage_root == empty_ordered_root_v1(6)
}

fn derive_binding_material(input: &GlobalExecutionBindingInputV1) -> PreparedSystemObjectCreateV1 {
    let mut immutable_body = Vec::new();
    put_u16(&mut immutable_body, SCHEMA_VERSION_V1);
    input.context.encode_cev1_into(&mut immutable_body);
    put_u64(&mut immutable_body, input.candidate_height);
    put_hash(&mut immutable_body, input.candidate_block_id.to_bytes());
    put_hash(&mut immutable_body, input.candidate_composite_root);
    put_hash(&mut immutable_body, input.final_execution_root);
    let object_id =
        domain_separated_digest_v1(GLOBAL_EXECUTION_BINDING_ID_DOMAIN_V1, &immutable_body);

    let mut immutable = immutable_body;
    put_hash(&mut immutable, object_id);
    let mut mutable = Vec::with_capacity(42);
    put_u16(&mut mutable, SCHEMA_VERSION_V1);
    put_hash(&mut mutable, object_id);
    put_u64(&mut mutable, OBJECT_VERSION_V1);

    let mut value_bytes = Vec::with_capacity(46 + immutable.len() + mutable.len());
    put_u16(&mut value_bytes, SCHEMA_VERSION_V1);
    put_u16(&mut value_bytes, GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1);
    put_hash(&mut value_bytes, object_id);
    put_bytes(&mut value_bytes, &immutable);
    put_bytes(&mut value_bytes, &mutable);
    PreparedSystemObjectCreateV1 {
        object_kind: GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1,
        object_id,
        object_version: OBJECT_VERSION_V1,
        state_key: application_state_key_v1(GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1, object_id),
        value_bytes,
        candidate_height: input.candidate_height,
        candidate_block_id: input.candidate_block_id,
    }
}

fn validate_binding_value(create: &PreparedSystemObjectCreateV1) -> OrderApplicationResultV1<()> {
    if create.value_bytes.is_empty() || create.value_bytes.len() > MAX_VALUE_BYTES_V1 {
        return reject(
            OrderApplicationErrorCodeV1::InvalidBinding,
            "tag-50 value length is outside the bound",
        );
    }
    let mut cursor = ValueCursorV1::new(&create.value_bytes);
    let envelope_schema = cursor.u16()?;
    let object_kind = cursor.u16()?;
    let object_id = cursor.hash32()?;
    let immutable = cursor.bytes()?;
    let mutable = cursor.bytes()?;
    cursor.finish()?;

    let mut object = ValueCursorV1::new(immutable);
    let body_start = object.offset;
    let body_schema = object.u16()?;
    let context = ProtocolContextV1 {
        schema_version: object.u16()?,
        genesis_hash: object.hash32()?,
        chain_id: String::from_utf8(object.bytes()?.to_vec()).map_err(|_| {
            OrderApplicationErrorV1 {
                code: OrderApplicationErrorCodeV1::InvalidBinding,
                detail: "tag-50 chain ID is not canonical UTF-8",
            }
        })?,
        protocol_version: object.u32()?,
        stack_profile_hash: object.hash32()?,
    };
    let candidate_height = object.u64()?;
    let candidate_block_id = object.hash32()?;
    let candidate_composite_root = object.hash32()?;
    let final_execution_root = object.hash32()?;
    let body_end = object.offset;
    let binding_id = object.hash32()?;
    object.finish()?;

    let mut state = ValueCursorV1::new(mutable);
    let state_schema = state.u16()?;
    let state_binding_id = state.hash32()?;
    let state_version = state.u64()?;
    state.finish()?;
    if envelope_schema != SCHEMA_VERSION_V1
        || object_kind != GLOBAL_EXECUTION_BINDING_OBJECT_KIND_V1
        || object_id != create.object_id
        || body_schema != SCHEMA_VERSION_V1
        || validate_context(&context).is_err()
        || candidate_height != create.candidate_height
        || candidate_block_id != create.candidate_block_id.to_bytes()
        || candidate_composite_root == [0; 32]
        || final_execution_root == [0; 32]
        || binding_id
            != domain_separated_digest_v1(
                GLOBAL_EXECUTION_BINDING_ID_DOMAIN_V1,
                &immutable[body_start..body_end],
            )
        || binding_id != object_id
        || state_schema != SCHEMA_VERSION_V1
        || state_binding_id != binding_id
        || state_version != OBJECT_VERSION_V1
    {
        return reject(
            OrderApplicationErrorCodeV1::InvalidBinding,
            "tag-50 application object grammar or typed identity differs",
        );
    }
    Ok(())
}

fn sparse_state_root(leaves: &BTreeMap<[u8; 32], StateLeafV1>) -> [u8; 32] {
    let empties = empty_hashes();
    let mut current = leaves
        .iter()
        .map(|(state_key, leaf)| {
            (
                *state_key,
                state_leaf_hash(
                    *state_key,
                    leaf.object_kind,
                    leaf.object_version,
                    &leaf.value_bytes,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for (level, empty) in empties
        .iter()
        .copied()
        .take(STATE_TREE_DEPTH_V1)
        .enumerate()
    {
        let bit_index = 255 - level;
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
    current
        .get(&[0; 32])
        .copied()
        .unwrap_or(empties[STATE_TREE_DEPTH_V1])
}

fn empty_hashes() -> Vec<[u8; 32]> {
    let mut hashes = Vec::with_capacity(STATE_TREE_DEPTH_V1 + 1);
    hashes.push(domain_separated_digest_v1(
        STATE_EMPTY_LEAF_DOMAIN_V1,
        &STATE_TREE_VERSION_V1.to_le_bytes(),
    ));
    for level in 0..STATE_TREE_DEPTH_V1 {
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
    put_hash(&mut encoded, state_key);
    put_u16(&mut encoded, object_kind);
    put_u64(&mut encoded, object_version);
    put_bytes(&mut encoded, value_bytes);
    domain_separated_digest_v1(STATE_LEAF_DOMAIN_V1, &encoded)
}

fn state_node_hash(level: usize, left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(66);
    put_u16(
        &mut encoded,
        u16::try_from(level).expect("fixed sparse-JMT level fits u16"),
    );
    put_hash(&mut encoded, left);
    put_hash(&mut encoded, right);
    domain_separated_digest_v1(STATE_NODE_DOMAIN_V1, &encoded)
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

fn prepared_plan_digest(
    parent_height: u64,
    parent_block_id: BlockIdV1,
    parent_state_root: [u8; 32],
    header: &BlockHeaderV1,
    block_id: BlockIdV1,
    creates: &[PreparedSystemObjectCreateV1],
) -> [u8; 32] {
    let mut encoded = Vec::new();
    put_u16(&mut encoded, SCHEMA_VERSION_V1);
    put_u64(&mut encoded, parent_height);
    put_hash(&mut encoded, parent_block_id.to_bytes());
    put_hash(&mut encoded, parent_state_root);
    put_bytes(&mut encoded, &header.to_cev1_bytes());
    put_hash(&mut encoded, block_id.to_bytes());
    put_u32(
        &mut encoded,
        u32::try_from(creates.len()).expect("bounded create count fits u32"),
    );
    for create in creates {
        put_u16(&mut encoded, create.object_kind);
        put_hash(&mut encoded, create.object_id);
        put_u64(&mut encoded, create.object_version);
        put_hash(&mut encoded, create.state_key);
        put_bytes(&mut encoded, &create.value_bytes);
    }
    domain_separated_digest_v1(PREPARED_PLAN_DOMAIN_V1, &encoded)
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_hash(output: &mut Vec<u8>, value: [u8; 32]) {
    output.extend_from_slice(&value);
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) {
    put_u32(
        output,
        u32::try_from(value.len()).expect("bounded application CEV1 bytes fit u32"),
    );
    output.extend_from_slice(value);
}

struct ValueCursorV1<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> ValueCursorV1<'a> {
    const fn new(raw: &'a [u8]) -> Self {
        Self { raw, offset: 0 }
    }

    fn take(&mut self, length: usize) -> OrderApplicationResultV1<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(OrderApplicationErrorV1 {
                code: OrderApplicationErrorCodeV1::ArithmeticOverflow,
                detail: "tag-50 value cursor overflows",
            })?;
        let value = self
            .raw
            .get(self.offset..end)
            .ok_or(OrderApplicationErrorV1 {
                code: OrderApplicationErrorCodeV1::InvalidBinding,
                detail: "tag-50 value is truncated",
            })?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> OrderApplicationResultV1<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| OrderApplicationErrorV1 {
                code: OrderApplicationErrorCodeV1::InvalidBinding,
                detail: "tag-50 fixed-width value is truncated",
            })
    }

    fn u16(&mut self) -> OrderApplicationResultV1<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> OrderApplicationResultV1<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> OrderApplicationResultV1<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn hash32(&mut self) -> OrderApplicationResultV1<[u8; 32]> {
        self.array()
    }

    fn bytes(&mut self) -> OrderApplicationResultV1<&'a [u8]> {
        let length = usize::try_from(self.u32()?).map_err(|_| OrderApplicationErrorV1 {
            code: OrderApplicationErrorCodeV1::InvalidBinding,
            detail: "tag-50 byte length cannot fit usize",
        })?;
        if length > MAX_VALUE_BYTES_V1 {
            return reject(
                OrderApplicationErrorCodeV1::InvalidBinding,
                "tag-50 byte field exceeds bound",
            );
        }
        self.take(length)
    }

    fn finish(&self) -> OrderApplicationResultV1<()> {
        if self.offset != self.raw.len() {
            return reject(
                OrderApplicationErrorCodeV1::InvalidBinding,
                "tag-50 value has trailing bytes",
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHARED_TAG50_VECTOR_V1: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../docs/protocol/poco-ai-native-v1/vectors/cev1-global-execution-binding-kernel-v1.json"
    ));

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0, "fixed vector hex must be even");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    b'A'..=b'F' => byte - b'A' + 10,
                    _ => panic!("fixed vector contains non-hex bytes"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    fn decode_hash(value: &str) -> [u8; 32] {
        decode_hex(value)
            .try_into()
            .expect("fixed vector hash is exactly 32 bytes")
    }

    fn vector_string<'a>(value: &'a serde_json::Value, field: &str) -> &'a str {
        value[field]
            .as_str()
            .unwrap_or_else(|| panic!("fixed vector field {field} is a string"))
    }

    fn vector_u64(value: &serde_json::Value, field: &str) -> u64 {
        value[field]
            .as_u64()
            .unwrap_or_else(|| panic!("fixed vector field {field} is an unsigned integer"))
    }

    fn context() -> ProtocolContextV1 {
        ProtocolContextV1 {
            schema_version: 1,
            genesis_hash: [0x11; 32],
            chain_id: "trnm-ai-application-test".to_owned(),
            protocol_version: 1,
            stack_profile_hash: [0x22; 32],
        }
    }

    fn template(parent: BlockIdV1, height: u64) -> OrderHeaderTemplateV1 {
        OrderHeaderTemplateV1 {
            schema_version: 1,
            context: context(),
            epoch: 1,
            view: height + 10,
            height,
            block_kind: BlockKindV1::Ordinary,
            parent: ParentBlockRefV1::V1Block(parent),
            proposer_id: b"validator-a".to_vec(),
            epoch_descriptor_id: EpochDescriptorIdV1::new([0x44; 32]),
            justify_qc_id: Some(QuorumCertificateIdV1::new([0x55; 32])),
            timeout_certificate_id: None,
            next_epoch_descriptor_id: None,
            upgrade_plan_id: None,
            epoch_handoff_id: None,
        }
    }

    fn binding(seed: u8) -> GlobalExecutionBindingInputV1 {
        GlobalExecutionBindingInputV1::new(
            context(),
            u64::from(seed),
            BlockIdV1::new([seed; 32]),
            [seed.wrapping_add(1); 32],
            [seed.wrapping_add(2); 32],
        )
        .expect("valid inert binding input")
    }

    fn recovered_leaf(
        prepared: &PreparedOrderBlockV1,
        materialized_height: u64,
    ) -> RecoveredOrderApplicationLeafV1 {
        let create = &prepared.system_creates[0];
        RecoveredOrderApplicationLeafV1::new(
            materialized_height,
            create.object_kind,
            create.object_id,
            create.object_version,
            create.state_key,
            create.value_bytes.clone(),
            create.candidate_height,
            create.candidate_block_id,
        )
        .expect("recover exact prepared tag-50 leaf")
    }

    #[test]
    fn shared_tag50_machine_vector_locks_value_leaf_and_sparse_root() {
        let vector: serde_json::Value =
            serde_json::from_str(SHARED_TAG50_VECTOR_V1).expect("shared tag-50 vector is JSON");
        let case = &vector["canonical_case"];
        let inputs = &case["inputs"];
        let expected = &case["expected"];
        let context = ProtocolContextV1 {
            schema_version: 1,
            genesis_hash: decode_hash(vector_string(inputs, "genesis_hash")),
            chain_id: vector_string(inputs, "chain_id").to_owned(),
            protocol_version: u32::try_from(vector_u64(inputs, "protocol_version"))
                .expect("fixed protocol version fits u32"),
            stack_profile_hash: decode_hash(vector_string(inputs, "stack_profile_hash")),
        };
        let binding = GlobalExecutionBindingInputV1::new(
            context,
            vector_u64(inputs, "candidate_height"),
            BlockIdV1::new(decode_hash(vector_string(inputs, "candidate_block_id"))),
            decode_hash(vector_string(inputs, "candidate_composite_root")),
            decode_hash(vector_string(inputs, "final_execution_root")),
        )
        .expect("shared vector binding input is structurally valid");
        let create = derive_binding_material(&binding);

        assert_eq!(
            create.object_id,
            decode_hash(vector_string(expected, "binding_id"))
        );
        assert_eq!(
            create.value_bytes,
            decode_hex(vector_string(expected, "application_object_value_cev1"))
        );
        assert_eq!(
            create.state_key,
            decode_hash(vector_string(expected, "state_key"))
        );
        let leaf = state_leaf_hash(
            create.state_key,
            create.object_kind,
            create.object_version,
            &create.value_bytes,
        );
        assert_eq!(leaf, decode_hash(vector_string(expected, "state_leaf")));

        let sibling_bytes = decode_hex(vector_string(case, "siblings_hex"));
        assert_eq!(sibling_bytes.len(), STATE_TREE_DEPTH_V1 * 32);
        let mut running = leaf;
        for (level, sibling) in sibling_bytes.chunks_exact(32).enumerate() {
            let sibling: [u8; 32] = sibling
                .try_into()
                .expect("fixed sibling chunk is exactly 32 bytes");
            let bit_index = 255 - level;
            let bit = (create.state_key[bit_index / 8] >> (7 - (bit_index % 8))) & 1;
            let (left, right) = if bit == 0 {
                (running, sibling)
            } else {
                (sibling, running)
            };
            running = state_node_hash(level, left, right);
        }
        assert_eq!(
            running,
            decode_hash(vector_string(expected, "finalized_post_state_root"))
        );
    }

    #[test]
    fn noop_and_two_tag50_creates_form_exact_multi_level_previews() {
        let anchor =
            EmptyOrderStateAnchorV1::new(10, BlockIdV1::new([0x10; 32])).expect("empty anchor");
        let noop = preview_order_block_v1(
            OrderApplicationParentV1::EmptyAnchor(&anchor),
            template(anchor.block_id(), 11),
            &[OrderApplicationOperationV1::Noop],
        )
        .expect("noop preview");
        assert_eq!(noop.post_state_root(), anchor.state_root());
        assert_eq!(noop.header().ordered_roots().len(), 8);

        let mut inputs = [binding(1), binding(2)];
        inputs.sort_by_key(GlobalExecutionBindingInputV1::object_id_v1);
        let operations = inputs.map(OrderApplicationOperationV1::CreateGlobalExecutionBinding);
        let prepared = preview_order_block_v1(
            OrderApplicationParentV1::Prepared(&noop),
            template(noop.block_id(), 12),
            &operations,
        )
        .expect("two-object atomic preview");
        assert_eq!(prepared.system_creates().len(), 2);
        assert_ne!(prepared.post_state_root(), noop.post_state_root());
        revalidate_prepared_order_block_v1(&prepared).expect("fresh plan revalidation");
    }

    #[test]
    fn duplicate_unsorted_and_mixed_noop_operations_fail_closed() {
        let anchor =
            EmptyOrderStateAnchorV1::new(10, BlockIdV1::new([0x10; 32])).expect("empty anchor");
        let value = binding(1);
        let duplicate = [
            OrderApplicationOperationV1::CreateGlobalExecutionBinding(value.clone()),
            OrderApplicationOperationV1::CreateGlobalExecutionBinding(value),
        ];
        assert_eq!(
            preview_order_block_v1(
                OrderApplicationParentV1::EmptyAnchor(&anchor),
                template(anchor.block_id(), 11),
                &duplicate,
            )
            .expect_err("duplicate tag-50 create rejects")
            .code(),
            OrderApplicationErrorCodeV1::NonCanonicalOrder,
        );

        let mut inputs = [binding(1), binding(2)];
        inputs.sort_by_key(GlobalExecutionBindingInputV1::object_id_v1);
        inputs.reverse();
        let unsorted = inputs.map(OrderApplicationOperationV1::CreateGlobalExecutionBinding);
        assert_eq!(
            preview_order_block_v1(
                OrderApplicationParentV1::EmptyAnchor(&anchor),
                template(anchor.block_id(), 11),
                &unsorted,
            )
            .expect_err("unsorted tag-50 creates reject")
            .code(),
            OrderApplicationErrorCodeV1::NonCanonicalOrder,
        );

        assert_eq!(
            preview_order_block_v1(
                OrderApplicationParentV1::EmptyAnchor(&anchor),
                template(anchor.block_id(), 11),
                &[
                    OrderApplicationOperationV1::Noop,
                    OrderApplicationOperationV1::CreateGlobalExecutionBinding(binding(1)),
                ],
            )
            .expect_err("mixed noop rejects")
            .code(),
            OrderApplicationErrorCodeV1::InvalidOperation,
        );
    }

    #[test]
    fn existing_key_root_substitution_and_self_binding_fail_revalidation() {
        let anchor =
            EmptyOrderStateAnchorV1::new(10, BlockIdV1::new([0x10; 32])).expect("empty anchor");
        let value = binding(1);
        let first = preview_order_block_v1(
            OrderApplicationParentV1::EmptyAnchor(&anchor),
            template(anchor.block_id(), 11),
            &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                value.clone(),
            )],
        )
        .expect("first tag-50 create");
        assert_eq!(
            preview_order_block_v1(
                OrderApplicationParentV1::Prepared(&first),
                template(first.block_id(), 12),
                &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                    value
                )],
            )
            .expect_err("existing typed key rejects")
            .code(),
            OrderApplicationErrorCodeV1::DuplicateObject,
        );

        let mut wrong_root = first;
        wrong_root.header.post_state_root[0] ^= 1;
        assert_eq!(
            revalidate_prepared_order_block_v1(&wrong_root)
                .expect_err("post-state root substitution rejects")
                .code(),
            OrderApplicationErrorCodeV1::RootMismatch,
        );

        let mut self_binding = preview_order_block_v1(
            OrderApplicationParentV1::EmptyAnchor(&anchor),
            template(anchor.block_id(), 11),
            &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                binding(2),
            )],
        )
        .expect("ordinary earlier binding");
        self_binding.system_creates[0].candidate_block_id = self_binding.block_id;
        assert_eq!(
            revalidate_prepared_order_block_v1(&self_binding)
                .expect_err("self-candidate tag-50 rejects")
                .code(),
            OrderApplicationErrorCodeV1::PlanMismatch,
        );
    }

    #[test]
    fn recovered_parent_rebuilds_next_height_and_rejects_root_or_sequence_substitution() {
        let anchor =
            EmptyOrderStateAnchorV1::new(10, BlockIdV1::new([0x10; 32])).expect("empty anchor");
        let first = preview_order_block_v1(
            OrderApplicationParentV1::EmptyAnchor(&anchor),
            template(anchor.block_id(), 11),
            &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                binding(1),
            )],
        )
        .expect("first prepared tag-50 parent");
        let recovered = recover_order_application_parent_v1(
            first.header.clone(),
            first.block_id,
            vec![recovered_leaf(&first, first.header.height)],
        )
        .expect("recover exact durable parent facts");
        let second = preview_order_block_v1(
            OrderApplicationParentV1::Recovered(&recovered),
            template(first.block_id(), 12),
            &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                binding(2),
            )],
        )
        .expect("preview next height from recovered parent");
        assert_eq!(second.header.height, 12);
        assert_eq!(second.parent_state_root(), first.post_state_root());

        let mut wrong_root_header = first.header.clone();
        wrong_root_header.post_state_root[0] ^= 1;
        let wrong_root_block_id = derive_block_id_v1(&wrong_root_header);
        assert_eq!(
            recover_order_application_parent_v1(
                wrong_root_header,
                wrong_root_block_id,
                vec![recovered_leaf(&first, first.header.height)],
            )
            .expect_err("recovered parent root substitution rejects")
            .code(),
            OrderApplicationErrorCodeV1::RootMismatch,
        );
        assert_eq!(
            recover_order_application_parent_v1(
                first.header.clone(),
                first.block_id,
                vec![recovered_leaf(&first, first.header.height + 1)],
            )
            .expect_err("future recovered leaf sequence rejects")
            .code(),
            OrderApplicationErrorCodeV1::RecoveredParentInvalid,
        );

        let mut foreign_context = template(first.block_id(), 12);
        foreign_context.context.chain_id.push_str("-foreign");
        assert_eq!(
            preview_order_block_v1(
                OrderApplicationParentV1::Recovered(&recovered),
                foreign_context,
                &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                    binding(2),
                )],
            )
            .expect_err("recovered parent context substitution rejects")
            .code(),
            OrderApplicationErrorCodeV1::InvalidHeader,
        );

        let mut stale_view = template(first.block_id(), 12);
        stale_view.view = first.header.view;
        assert_eq!(
            preview_order_block_v1(
                OrderApplicationParentV1::Recovered(&recovered),
                stale_view,
                &[OrderApplicationOperationV1::CreateGlobalExecutionBinding(
                    binding(2),
                )],
            )
            .expect_err("recovered parent non-successor view rejects")
            .code(),
            OrderApplicationErrorCodeV1::InvalidHeader,
        );
    }
}
