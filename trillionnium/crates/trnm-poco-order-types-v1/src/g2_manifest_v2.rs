//! Candidate-only T0 seam for a non-circular, manifest-bound G2 execution.
//!
//! Every type in this module is inert public data.  In particular, a valid
//! input or plan is neither execution evidence nor voting, finality, state
//! write, or checkpoint authority.  The containing Order block ID and all
//! eight containing-header roots are structurally absent from both bodies.

use super::{
    domain_separated_digest_v1, empty_ordered_root_v1, put_bytes, put_hash, put_list, put_u16,
    put_u32, put_u64, put_u8, reject, BlockIdV1, Cev1EncodeV1, OrderTypeCodecErrorCodeV1,
    OrderTypeCodecResultV1, ProtocolContextV1, MAX_CONSENSUS_STRING_BYTES_V1,
    MERKLE_LIST_ROOT_DOMAIN_V1,
};

pub const G2_MANIFEST_BOUND_INPUT_SCHEMA_V2: u16 = 2;
pub const G2_BATCH_REF_ITEM_KIND_V2: u16 = 0x0200;
pub const G2_PROTOCOL_BINDING_ITEM_KIND_V2: u16 = 0x0201;

const G2_MANIFEST_BOUND_INPUT_DOMAIN_V2: &str = "trnm.poco-ai.g2-manifest-bound-input.v2";
const G2_COMMAND_ID_DOMAIN_V2: &str = "trnm.poco-ai.g2-command-id.v2";
const G2_EXECUTION_PLAN_DOMAIN_V2: &str = "trnm.poco-ai.g2-inert-execution-plan.v2";
const G2_BATCH_REF_COMMITMENT_DOMAIN_V2: &str = "trnm.poco-ai.g2-manifest-batch-ref.v2";
const G2_PROTOCOL_BINDING_COMMITMENT_DOMAIN_V2: &str =
    "trnm.poco-ai.g2-manifest-protocol-binding.v2";
const G2_STATE_KEY_DOMAIN_V1: &str = "trnm.poco-ai.state-key.v1";
const MERKLE_LEAF_DOMAIN_V1: &str = "trnm.poco-ai.merkle-leaf.v1";
const MERKLE_NODE_DOMAIN_V1: &str = "trnm.poco-ai.merkle-node.v1";

const MAX_G2_COMMANDS_V2: usize = 131_072;
const MAX_G2_STATE_CREATES_V2: usize = 131_072;
const MAX_G2_ORDERED_ITEMS_V2: usize = 131_072;
const MAX_G2_STATE_VALUE_BYTES_V2: usize = 4 * 1024 * 1024;
const MAX_G2_TOTAL_STATE_VALUE_BYTES_V2: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[repr(transparent)]
pub struct G2ManifestBoundInputIdV2([u8; 32]);

impl G2ManifestBoundInputIdV2 {
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[repr(transparent)]
pub struct G2ExecutionPlanDigestV2([u8; 32]);

impl G2ExecutionPlanDigestV2 {
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum G2CommandPlaneV2 {
    AgentMarket = 1,
    VerifyChallenge = 2,
    MvccFee = 3,
    ConsumptionSettlement = 4,
}

impl Cev1EncodeV1 for G2CommandPlaneV2 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>) {
        put_u8(output, *self as u8);
    }
}

/// One exact typed-command commitment.  The command ID is derived internally
/// from its plane, per-plane index, kind, and content commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct G2CommandCommitmentV2 {
    plane: G2CommandPlaneV2,
    index: u32,
    command_kind: u16,
    command_id: [u8; 32],
    command_commitment: [u8; 32],
}

impl G2CommandCommitmentV2 {
    pub fn new(
        plane: G2CommandPlaneV2,
        index: u32,
        command_kind: u16,
        command_commitment: [u8; 32],
    ) -> OrderTypeCodecResultV1<Self> {
        if command_kind == 0 || command_commitment == [0; 32] {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "G2 command kind or content commitment is zero",
            );
        }
        let mut body = Vec::with_capacity(39);
        plane.encode_cev1_into(&mut body);
        put_u32(&mut body, index);
        put_u16(&mut body, command_kind);
        put_hash(&mut body, command_commitment);
        let command_id = domain_separated_digest_v1(G2_COMMAND_ID_DOMAIN_V2, &body);
        Ok(Self {
            plane,
            index,
            command_kind,
            command_id,
            command_commitment,
        })
    }

    pub const fn plane(&self) -> G2CommandPlaneV2 {
        self.plane
    }

    pub const fn index(&self) -> u32 {
        self.index
    }

    pub const fn command_kind(&self) -> u16 {
        self.command_kind
    }

    pub const fn command_id(&self) -> [u8; 32] {
        self.command_id
    }

    pub const fn command_commitment(&self) -> [u8; 32] {
        self.command_commitment
    }

    fn revalidate(&self) -> OrderTypeCodecResultV1<()> {
        if Self::new(
            self.plane,
            self.index,
            self.command_kind,
            self.command_commitment,
        )? != *self
        {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "G2 command ID differs from its exact command body",
            );
        }
        Ok(())
    }
}

impl Cev1EncodeV1 for G2CommandCommitmentV2 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>) {
        self.plane.encode_cev1_into(output);
        put_u32(output, self.index);
        put_u16(output, self.command_kind);
        put_hash(output, self.command_id);
        put_hash(output, self.command_commitment);
    }
}

/// Candidate-ID-free input selected before any containing Order header exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct G2ManifestBoundInputV2 {
    schema_version: u16,
    context: ProtocolContextV1,
    campaign_id: [u8; 32],
    manifest_digest: [u8; 32],
    workload_corpus_digest: [u8; 32],
    trust_bundle_digest: [u8; 32],
    parent_height: u64,
    parent_block_id: BlockIdV1,
    parent_state_root: [u8; 32],
    candidate_height: u64,
    da_batch_id: [u8; 32],
    da_certificate_id: [u8; 32],
    source_cut_digest: [u8; 32],
    commands: Vec<G2CommandCommitmentV2>,
    input_id: G2ManifestBoundInputIdV2,
}

impl G2ManifestBoundInputV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: ProtocolContextV1,
        campaign_id: [u8; 32],
        manifest_digest: [u8; 32],
        workload_corpus_digest: [u8; 32],
        trust_bundle_digest: [u8; 32],
        parent_height: u64,
        parent_block_id: BlockIdV1,
        parent_state_root: [u8; 32],
        candidate_height: u64,
        da_batch_id: [u8; 32],
        da_certificate_id: [u8; 32],
        source_cut_digest: [u8; 32],
        commands: Vec<G2CommandCommitmentV2>,
    ) -> OrderTypeCodecResultV1<Self> {
        validate_protocol_context(&context)?;
        if [
            campaign_id,
            manifest_digest,
            workload_corpus_digest,
            trust_bundle_digest,
            parent_block_id.to_bytes(),
            parent_state_root,
            da_batch_id,
            da_certificate_id,
            source_cut_digest,
        ]
        .contains(&[0; 32])
        {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "G2 manifest, parent, DA, trust, or source binding is zero",
            );
        }
        let expected_height = parent_height
            .checked_add(1)
            .ok_or(super::OrderTypeCodecErrorV1 {
                code: OrderTypeCodecErrorCodeV1::ParserBound,
                detail: "G2 candidate height overflows",
            })?;
        if parent_height == 0 || candidate_height != expected_height {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "G2 input is not the exact successor of its parent",
            );
        }
        validate_commands(&commands)?;
        let mut value = Self {
            schema_version: G2_MANIFEST_BOUND_INPUT_SCHEMA_V2,
            context,
            campaign_id,
            manifest_digest,
            workload_corpus_digest,
            trust_bundle_digest,
            parent_height,
            parent_block_id,
            parent_state_root,
            candidate_height,
            da_batch_id,
            da_certificate_id,
            source_cut_digest,
            commands,
            input_id: G2ManifestBoundInputIdV2([0; 32]),
        };
        value.input_id = G2ManifestBoundInputIdV2(domain_separated_digest_v1(
            G2_MANIFEST_BOUND_INPUT_DOMAIN_V2,
            &value.body_bytes(),
        ));
        value.revalidate()?;
        Ok(value)
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn context(&self) -> &ProtocolContextV1 {
        &self.context
    }

    pub const fn campaign_id(&self) -> [u8; 32] {
        self.campaign_id
    }

    pub const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    pub const fn workload_corpus_digest(&self) -> [u8; 32] {
        self.workload_corpus_digest
    }

    pub const fn trust_bundle_digest(&self) -> [u8; 32] {
        self.trust_bundle_digest
    }

    pub const fn parent_height(&self) -> u64 {
        self.parent_height
    }

    pub const fn parent_block_id(&self) -> BlockIdV1 {
        self.parent_block_id
    }

    pub const fn parent_state_root(&self) -> [u8; 32] {
        self.parent_state_root
    }

    pub const fn candidate_height(&self) -> u64 {
        self.candidate_height
    }

    pub const fn da_batch_id(&self) -> [u8; 32] {
        self.da_batch_id
    }

    pub const fn da_certificate_id(&self) -> [u8; 32] {
        self.da_certificate_id
    }

    pub const fn source_cut_digest(&self) -> [u8; 32] {
        self.source_cut_digest
    }

    pub fn commands(&self) -> &[G2CommandCommitmentV2] {
        &self.commands
    }

    pub const fn input_id(&self) -> G2ManifestBoundInputIdV2 {
        self.input_id
    }

    pub fn revalidate(&self) -> OrderTypeCodecResultV1<()> {
        validate_protocol_context(&self.context)?;
        if self.schema_version != G2_MANIFEST_BOUND_INPUT_SCHEMA_V2
            || self.parent_height == 0
            || self.parent_height.checked_add(1) != Some(self.candidate_height)
            || [
                self.campaign_id,
                self.manifest_digest,
                self.workload_corpus_digest,
                self.trust_bundle_digest,
                self.parent_block_id.to_bytes(),
                self.parent_state_root,
                self.da_batch_id,
                self.da_certificate_id,
                self.source_cut_digest,
            ]
            .contains(&[0; 32])
        {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "retained G2 manifest-bound input differs from its structural contract",
            );
        }
        validate_commands(&self.commands)?;
        let expected =
            domain_separated_digest_v1(G2_MANIFEST_BOUND_INPUT_DOMAIN_V2, &self.body_bytes());
        if self.input_id.0 != expected {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "G2 manifest-bound input ID differs from its exact body",
            );
        }
        Ok(())
    }

    fn body_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        put_u16(&mut output, self.schema_version);
        self.context.encode_cev1_into(&mut output);
        for hash in [
            self.campaign_id,
            self.manifest_digest,
            self.workload_corpus_digest,
            self.trust_bundle_digest,
        ] {
            put_hash(&mut output, hash);
        }
        put_u64(&mut output, self.parent_height);
        put_hash(&mut output, self.parent_block_id.to_bytes());
        put_hash(&mut output, self.parent_state_root);
        put_u64(&mut output, self.candidate_height);
        put_hash(&mut output, self.da_batch_id);
        put_hash(&mut output, self.da_certificate_id);
        put_hash(&mut output, self.source_cut_digest);
        put_list(&mut output, &self.commands);
        output
    }
}

impl Cev1EncodeV1 for G2ManifestBoundInputV2 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.body_bytes());
        put_hash(output, self.input_id.0);
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum G2OrderedRootKindV2 {
    BatchRefs = 0,
    ProtocolObjects = 1,
    TransactionExecutionReceipts = 2,
    Evidence = 3,
    ConsumptionRollups = 4,
    Settlement = 5,
    ResourceUsage = 6,
}

impl G2OrderedRootKindV2 {
    const ALL: [Self; 7] = [
        Self::BatchRefs,
        Self::ProtocolObjects,
        Self::TransactionExecutionReceipts,
        Self::Evidence,
        Self::ConsumptionRollups,
        Self::Settlement,
        Self::ResourceUsage,
    ];

    pub const fn tag(self) -> u16 {
        self as u16
    }
}

impl Cev1EncodeV1 for G2OrderedRootKindV2 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>) {
        put_u16(output, self.tag());
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct G2OrderedItemV2 {
    root_kind: G2OrderedRootKindV2,
    index: u32,
    item_kind: u16,
    item_id: [u8; 32],
    item_commitment: [u8; 32],
}

impl G2OrderedItemV2 {
    pub fn new(
        root_kind: G2OrderedRootKindV2,
        index: u32,
        item_kind: u16,
        item_id: [u8; 32],
        item_commitment: [u8; 32],
    ) -> OrderTypeCodecResultV1<Self> {
        if item_kind == 0 || item_id == [0; 32] || item_commitment == [0; 32] {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "G2 ordered item kind, ID, or commitment is zero",
            );
        }
        Ok(Self {
            root_kind,
            index,
            item_kind,
            item_id,
            item_commitment,
        })
    }

    pub const fn root_kind(&self) -> G2OrderedRootKindV2 {
        self.root_kind
    }

    pub const fn index(&self) -> u32 {
        self.index
    }

    pub const fn item_kind(&self) -> u16 {
        self.item_kind
    }

    pub const fn item_id(&self) -> [u8; 32] {
        self.item_id
    }

    pub const fn item_commitment(&self) -> [u8; 32] {
        self.item_commitment
    }
}

impl Cev1EncodeV1 for G2OrderedItemV2 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>) {
        self.root_kind.encode_cev1_into(output);
        put_u32(output, self.index);
        put_u16(output, self.item_kind);
        put_hash(output, self.item_id);
        put_hash(output, self.item_commitment);
    }
}

/// One exact create in the candidate post-state.  The state key is derived
/// internally; callers cannot substitute a key or a root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct G2StateCreateV2 {
    object_kind: u16,
    object_id: [u8; 32],
    object_version: u64,
    state_key: [u8; 32],
    value_bytes: Vec<u8>,
}

impl G2StateCreateV2 {
    pub fn new(
        object_kind: u16,
        object_id: [u8; 32],
        object_version: u64,
        value_bytes: Vec<u8>,
    ) -> OrderTypeCodecResultV1<Self> {
        if object_kind == 0
            || object_id == [0; 32]
            || value_bytes.is_empty()
            || value_bytes.len() > MAX_G2_STATE_VALUE_BYTES_V2
        {
            return reject(
                OrderTypeCodecErrorCodeV1::ParserBound,
                "G2 state create identity or value length is invalid",
            );
        }
        let state_key = derive_state_key(object_kind, object_id);
        Ok(Self {
            object_kind,
            object_id,
            object_version,
            state_key,
            value_bytes,
        })
    }

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

    fn revalidate(&self) -> OrderTypeCodecResultV1<()> {
        if Self::new(
            self.object_kind,
            self.object_id,
            self.object_version,
            self.value_bytes.clone(),
        )? != *self
        {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "G2 state key differs from its typed object identity",
            );
        }
        Ok(())
    }
}

impl Cev1EncodeV1 for G2StateCreateV2 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>) {
        put_u16(output, self.object_kind);
        put_hash(output, self.object_id);
        put_u64(output, self.object_version);
        put_hash(output, self.state_key);
        put_bytes(output, &self.value_bytes);
    }
}

/// Exact candidate-ID-free state/list plan.  Its digest commits to the input
/// ID, complete state creates, and every ordered-list leaf, but to no header
/// root or containing block ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct G2InertExecutionPlanV2 {
    schema_version: u16,
    input_id: G2ManifestBoundInputIdV2,
    state_creates: Vec<G2StateCreateV2>,
    ordered_items: Vec<G2OrderedItemV2>,
    plan_digest: G2ExecutionPlanDigestV2,
}

impl G2InertExecutionPlanV2 {
    pub fn new(
        input: &G2ManifestBoundInputV2,
        state_creates: Vec<G2StateCreateV2>,
        execution_items: Vec<G2OrderedItemV2>,
    ) -> OrderTypeCodecResultV1<Self> {
        input.revalidate()?;
        validate_state_creates(&state_creates)?;
        validate_execution_items(&execution_items)?;

        let batch_anchor = G2OrderedItemV2::new(
            G2OrderedRootKindV2::BatchRefs,
            0,
            G2_BATCH_REF_ITEM_KIND_V2,
            input.da_batch_id,
            derive_batch_ref_commitment(input),
        )?;
        let protocol_anchor = G2OrderedItemV2::new(
            G2OrderedRootKindV2::ProtocolObjects,
            0,
            G2_PROTOCOL_BINDING_ITEM_KIND_V2,
            input.input_id.0,
            derive_protocol_binding_commitment(input),
        )?;
        let mut ordered_items = Vec::with_capacity(execution_items.len() + 2);
        for kind in G2OrderedRootKindV2::ALL {
            if kind == G2OrderedRootKindV2::BatchRefs {
                ordered_items.push(batch_anchor.clone());
            } else if kind == G2OrderedRootKindV2::ProtocolObjects {
                ordered_items.push(protocol_anchor.clone());
            }
            ordered_items.extend(
                execution_items
                    .iter()
                    .filter(|item| item.root_kind == kind)
                    .cloned(),
            );
        }
        validate_complete_ordered_items(&ordered_items)?;

        let mut plan = Self {
            schema_version: G2_MANIFEST_BOUND_INPUT_SCHEMA_V2,
            input_id: input.input_id,
            state_creates,
            ordered_items,
            plan_digest: G2ExecutionPlanDigestV2([0; 32]),
        };
        plan.plan_digest = G2ExecutionPlanDigestV2(domain_separated_digest_v1(
            G2_EXECUTION_PLAN_DOMAIN_V2,
            &plan.body_bytes(),
        ));
        plan.revalidate()?;
        Ok(plan)
    }

    pub const fn input_id(&self) -> G2ManifestBoundInputIdV2 {
        self.input_id
    }

    pub fn state_creates(&self) -> &[G2StateCreateV2] {
        &self.state_creates
    }

    pub fn ordered_items(&self) -> &[G2OrderedItemV2] {
        &self.ordered_items
    }

    pub const fn plan_digest(&self) -> G2ExecutionPlanDigestV2 {
        self.plan_digest
    }

    pub fn revalidate(&self) -> OrderTypeCodecResultV1<()> {
        if self.schema_version != G2_MANIFEST_BOUND_INPUT_SCHEMA_V2 {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "G2 inert plan schema version differs",
            );
        }
        validate_state_creates(&self.state_creates)?;
        validate_complete_ordered_items(&self.ordered_items)?;
        let expected = domain_separated_digest_v1(G2_EXECUTION_PLAN_DOMAIN_V2, &self.body_bytes());
        if expected != self.plan_digest.0 {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "G2 inert plan digest differs from its exact body",
            );
        }
        Ok(())
    }

    /// Rejoin this plan to the exact manifest-bound input and its two
    /// constructor-derived header anchors.  This remains a pure data check.
    pub fn revalidate_for_input(
        &self,
        input: &G2ManifestBoundInputV2,
    ) -> OrderTypeCodecResultV1<()> {
        input.revalidate()?;
        self.revalidate()?;
        if self.input_id != input.input_id
            || self.ordered_items.first() != Some(&expected_batch_anchor(input)?)
            || self
                .ordered_items
                .iter()
                .find(|item| item.root_kind == G2OrderedRootKindV2::ProtocolObjects)
                != Some(&expected_protocol_anchor(input)?)
        {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "G2 inert plan differs from its exact input or mandatory anchors",
            );
        }
        Ok(())
    }

    fn body_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        put_u16(&mut output, self.schema_version);
        put_hash(&mut output, self.input_id.0);
        put_list(&mut output, &self.state_creates);
        put_list(&mut output, &self.ordered_items);
        output
    }
}

impl Cev1EncodeV1 for G2InertExecutionPlanV2 {
    fn encode_cev1_into(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.body_bytes());
        put_hash(output, self.plan_digest.0);
    }
}

/// Derive the seven protocol Merkle-list roots in `RootKindV1` order.  The
/// post-state root is intentionally absent and remains the application JMT's
/// responsibility.
pub fn derive_g2_ordered_list_roots_v2(
    plan: &G2InertExecutionPlanV2,
) -> OrderTypeCodecResultV1<[[u8; 32]; 7]> {
    plan.revalidate()?;
    let mut roots = [[0_u8; 32]; 7];
    for kind in G2OrderedRootKindV2::ALL {
        let items: Vec<&G2OrderedItemV2> = plan
            .ordered_items
            .iter()
            .filter(|item| item.root_kind == kind)
            .collect();
        roots[usize::from(kind.tag())] = derive_list_root(kind, &items)?;
    }
    Ok(roots)
}

pub(crate) fn expected_batch_anchor(
    input: &G2ManifestBoundInputV2,
) -> OrderTypeCodecResultV1<G2OrderedItemV2> {
    G2OrderedItemV2::new(
        G2OrderedRootKindV2::BatchRefs,
        0,
        G2_BATCH_REF_ITEM_KIND_V2,
        input.da_batch_id,
        derive_batch_ref_commitment(input),
    )
}

pub(crate) fn expected_protocol_anchor(
    input: &G2ManifestBoundInputV2,
) -> OrderTypeCodecResultV1<G2OrderedItemV2> {
    G2OrderedItemV2::new(
        G2OrderedRootKindV2::ProtocolObjects,
        0,
        G2_PROTOCOL_BINDING_ITEM_KIND_V2,
        input.input_id.0,
        derive_protocol_binding_commitment(input),
    )
}

fn derive_list_root(
    kind: G2OrderedRootKindV2,
    items: &[&G2OrderedItemV2],
) -> OrderTypeCodecResultV1<[u8; 32]> {
    if items.is_empty() {
        return Ok(empty_ordered_root_v1(kind.tag()));
    }
    let mut level: Vec<[u8; 32]> = items
        .iter()
        .map(|item| {
            let mut body = Vec::with_capacity(72);
            put_u16(&mut body, kind.tag());
            put_u32(&mut body, item.index);
            put_u16(&mut body, item.item_kind);
            put_hash(&mut body, item.item_id);
            put_hash(&mut body, item.item_commitment);
            domain_separated_digest_v1(MERKLE_LEAF_DOMAIN_V1, &body)
        })
        .collect();
    let mut tree_level = 0_u32;
    while level.len() > 1 {
        let mut parents = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = *pair.get(1).unwrap_or(&left);
            let mut body = Vec::with_capacity(70);
            put_u16(&mut body, kind.tag());
            put_u32(&mut body, tree_level);
            put_hash(&mut body, left);
            put_hash(&mut body, right);
            parents.push(domain_separated_digest_v1(MERKLE_NODE_DOMAIN_V1, &body));
        }
        level = parents;
        tree_level = tree_level
            .checked_add(1)
            .ok_or(super::OrderTypeCodecErrorV1 {
                code: OrderTypeCodecErrorCodeV1::ParserBound,
                detail: "G2 ordered Merkle-list level overflows",
            })?;
    }
    let count = u32::try_from(items.len()).map_err(|_| super::OrderTypeCodecErrorV1 {
        code: OrderTypeCodecErrorCodeV1::ParserBound,
        detail: "G2 ordered Merkle-list count exceeds u32",
    })?;
    let mut body = Vec::with_capacity(39);
    put_u16(&mut body, kind.tag());
    put_u32(&mut body, count);
    put_u8(&mut body, 1);
    put_hash(&mut body, level[0]);
    Ok(domain_separated_digest_v1(
        MERKLE_LIST_ROOT_DOMAIN_V1,
        &body,
    ))
}

fn validate_protocol_context(context: &ProtocolContextV1) -> OrderTypeCodecResultV1<()> {
    if context.schema_version != 1
        || context.protocol_version != 1
        || context.genesis_hash == [0; 32]
        || context.stack_profile_hash == [0; 32]
        || context.chain_id.is_empty()
        || context.chain_id.len() > MAX_CONSENSUS_STRING_BYTES_V1
    {
        return reject(
            OrderTypeCodecErrorCodeV1::NonCanonical,
            "G2 protocol context is invalid",
        );
    }
    Ok(())
}

fn validate_commands(commands: &[G2CommandCommitmentV2]) -> OrderTypeCodecResultV1<()> {
    if commands.is_empty() || commands.len() > MAX_G2_COMMANDS_V2 {
        return reject(
            OrderTypeCodecErrorCodeV1::ParserBound,
            "G2 command inventory is empty or exceeds its bound",
        );
    }
    let mut previous_plane = None;
    let mut expected_index = 0_u32;
    for command in commands {
        command.revalidate()?;
        if previous_plane != Some(command.plane) {
            if previous_plane.is_some_and(|plane| plane >= command.plane) {
                return reject(
                    OrderTypeCodecErrorCodeV1::NonCanonical,
                    "G2 command planes are not strictly ordered",
                );
            }
            previous_plane = Some(command.plane);
            expected_index = 0;
        }
        if command.index != expected_index {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "G2 command indexes are not contiguous per plane",
            );
        }
        expected_index = expected_index
            .checked_add(1)
            .ok_or(super::OrderTypeCodecErrorV1 {
                code: OrderTypeCodecErrorCodeV1::ParserBound,
                detail: "G2 command index overflows",
            })?;
    }
    Ok(())
}

fn validate_state_creates(creates: &[G2StateCreateV2]) -> OrderTypeCodecResultV1<()> {
    if creates.len() > MAX_G2_STATE_CREATES_V2 {
        return reject(
            OrderTypeCodecErrorCodeV1::ParserBound,
            "G2 state-create inventory exceeds its bound",
        );
    }
    let mut previous = None;
    let mut total_bytes = 0_usize;
    for create in creates {
        create.revalidate()?;
        let key = (create.object_kind, create.object_id);
        if previous.is_some_and(|previous| previous >= key) {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "G2 state creates are not strictly ordered and unique",
            );
        }
        previous = Some(key);
        total_bytes = total_bytes.checked_add(create.value_bytes.len()).ok_or(
            super::OrderTypeCodecErrorV1 {
                code: OrderTypeCodecErrorCodeV1::ParserBound,
                detail: "G2 state-create bytes overflow",
            },
        )?;
        if total_bytes > MAX_G2_TOTAL_STATE_VALUE_BYTES_V2 {
            return reject(
                OrderTypeCodecErrorCodeV1::ParserBound,
                "G2 state-create bytes exceed their aggregate bound",
            );
        }
    }
    Ok(())
}

fn validate_execution_items(items: &[G2OrderedItemV2]) -> OrderTypeCodecResultV1<()> {
    if items.len() > MAX_G2_ORDERED_ITEMS_V2.saturating_sub(2) {
        return reject(
            OrderTypeCodecErrorCodeV1::ParserBound,
            "G2 execution ordered-item inventory exceeds its bound",
        );
    }
    let mut previous_kind = None;
    let mut expected_index = 0_u32;
    for item in items {
        if item.item_kind == 0 || item.item_id == [0; 32] || item.item_commitment == [0; 32] {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "G2 ordered item identity is invalid",
            );
        }
        if previous_kind != Some(item.root_kind) {
            if previous_kind.is_some_and(|kind| kind >= item.root_kind) {
                return reject(
                    OrderTypeCodecErrorCodeV1::NonCanonical,
                    "G2 ordered-item root kinds are not strictly grouped",
                );
            }
            previous_kind = Some(item.root_kind);
            expected_index = if matches!(
                item.root_kind,
                G2OrderedRootKindV2::BatchRefs | G2OrderedRootKindV2::ProtocolObjects
            ) {
                1
            } else {
                0
            };
        }
        if item.index != expected_index {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "G2 ordered-item indexes are not contiguous",
            );
        }
        expected_index = expected_index
            .checked_add(1)
            .ok_or(super::OrderTypeCodecErrorV1 {
                code: OrderTypeCodecErrorCodeV1::ParserBound,
                detail: "G2 ordered-item index overflows",
            })?;
    }
    Ok(())
}

fn validate_complete_ordered_items(items: &[G2OrderedItemV2]) -> OrderTypeCodecResultV1<()> {
    if items.len() < 2 || items.len() > MAX_G2_ORDERED_ITEMS_V2 {
        return reject(
            OrderTypeCodecErrorCodeV1::ParserBound,
            "complete G2 ordered-item inventory is outside its bound",
        );
    }
    let mut previous_kind = None;
    let mut expected_index = 0_u32;
    let mut saw_batch_anchor = false;
    let mut saw_protocol_anchor = false;
    for item in items {
        if item.item_kind == 0 || item.item_id == [0; 32] || item.item_commitment == [0; 32] {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "complete G2 ordered item is invalid",
            );
        }
        if previous_kind != Some(item.root_kind) {
            if previous_kind.is_some_and(|kind| kind >= item.root_kind) {
                return reject(
                    OrderTypeCodecErrorCodeV1::NonCanonical,
                    "complete G2 ordered items are not strictly grouped",
                );
            }
            previous_kind = Some(item.root_kind);
            expected_index = 0;
        }
        if item.index != expected_index {
            return reject(
                OrderTypeCodecErrorCodeV1::NonCanonical,
                "complete G2 ordered-item indexes are not contiguous",
            );
        }
        if item.root_kind == G2OrderedRootKindV2::BatchRefs && item.index == 0 {
            saw_batch_anchor = item.item_kind == G2_BATCH_REF_ITEM_KIND_V2;
        }
        if item.root_kind == G2OrderedRootKindV2::ProtocolObjects && item.index == 0 {
            saw_protocol_anchor = item.item_kind == G2_PROTOCOL_BINDING_ITEM_KIND_V2;
        }
        expected_index = expected_index
            .checked_add(1)
            .ok_or(super::OrderTypeCodecErrorV1 {
                code: OrderTypeCodecErrorCodeV1::ParserBound,
                detail: "complete G2 ordered-item index overflows",
            })?;
    }
    if !saw_batch_anchor || !saw_protocol_anchor {
        return reject(
            OrderTypeCodecErrorCodeV1::NonCanonical,
            "G2 plan omits its mandatory batch or protocol binding anchor",
        );
    }
    Ok(())
}

fn derive_batch_ref_commitment(input: &G2ManifestBoundInputV2) -> [u8; 32] {
    let mut body = Vec::with_capacity(96);
    put_hash(&mut body, input.input_id.0);
    put_hash(&mut body, input.da_certificate_id);
    put_hash(&mut body, input.source_cut_digest);
    domain_separated_digest_v1(G2_BATCH_REF_COMMITMENT_DOMAIN_V2, &body)
}

fn derive_protocol_binding_commitment(input: &G2ManifestBoundInputV2) -> [u8; 32] {
    let mut body = Vec::with_capacity(160);
    put_hash(&mut body, input.input_id.0);
    put_hash(&mut body, input.campaign_id);
    put_hash(&mut body, input.manifest_digest);
    put_hash(&mut body, input.workload_corpus_digest);
    put_hash(&mut body, input.trust_bundle_digest);
    domain_separated_digest_v1(G2_PROTOCOL_BINDING_COMMITMENT_DOMAIN_V2, &body)
}

fn derive_state_key(object_kind: u16, object_id: [u8; 32]) -> [u8; 32] {
    let mut body = Vec::with_capacity(34);
    put_u16(&mut body, object_kind);
    put_hash(&mut body, object_id);
    domain_separated_digest_v1(G2_STATE_KEY_DOMAIN_V1, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ProtocolContextV1 {
        ProtocolContextV1 {
            schema_version: 1,
            genesis_hash: [0x11; 32],
            chain_id: "trnm-g2-t0".to_owned(),
            protocol_version: 1,
            stack_profile_hash: [0x12; 32],
        }
    }

    fn command(plane: G2CommandPlaneV2, index: u32, seed: u8) -> G2CommandCommitmentV2 {
        G2CommandCommitmentV2::new(plane, index, u16::from(seed), [seed; 32])
            .expect("valid command commitment")
    }

    fn input_with(
        campaign_id: [u8; 32],
        commands: Vec<G2CommandCommitmentV2>,
    ) -> OrderTypeCodecResultV1<G2ManifestBoundInputV2> {
        G2ManifestBoundInputV2::new(
            context(),
            campaign_id,
            [0x22; 32],
            [0x23; 32],
            [0x24; 32],
            10,
            BlockIdV1::new([0x25; 32]),
            [0x26; 32],
            11,
            [0x27; 32],
            [0x28; 32],
            [0x29; 32],
            commands,
        )
    }

    fn input() -> G2ManifestBoundInputV2 {
        input_with(
            [0x21; 32],
            vec![
                command(G2CommandPlaneV2::AgentMarket, 0, 1),
                command(G2CommandPlaneV2::MvccFee, 0, 2),
            ],
        )
        .expect("valid manifest-bound input")
    }

    #[test]
    fn manifest_command_and_da_mutations_readdress_without_containing_block_id() {
        let canonical = input();
        let campaign_mutant = input_with(
            [0x31; 32],
            vec![
                command(G2CommandPlaneV2::AgentMarket, 0, 1),
                command(G2CommandPlaneV2::MvccFee, 0, 2),
            ],
        )
        .expect("campaign mutant remains structural data");
        let command_mutant = input_with(
            [0x21; 32],
            vec![
                command(G2CommandPlaneV2::AgentMarket, 0, 9),
                command(G2CommandPlaneV2::MvccFee, 0, 2),
            ],
        )
        .expect("command mutant remains structural data");
        assert_ne!(canonical.input_id(), campaign_mutant.input_id());
        assert_ne!(canonical.input_id(), command_mutant.input_id());

        let mut da_mutant = canonical.clone();
        da_mutant.da_certificate_id[0] ^= 1;
        assert!(da_mutant.revalidate().is_err());
        assert!(!canonical.to_cev1_bytes().is_empty());
    }

    #[test]
    fn every_manifest_trust_da_parent_source_and_command_mutant_fails_retained_address() {
        let canonical = input();
        let mut mutants = Vec::new();

        let mut value = canonical.clone();
        value.manifest_digest[0] ^= 1;
        mutants.push(value);
        let mut value = canonical.clone();
        value.workload_corpus_digest[0] ^= 1;
        mutants.push(value);
        let mut value = canonical.clone();
        value.trust_bundle_digest[0] ^= 1;
        mutants.push(value);
        let mut value = canonical.clone();
        value.parent_block_id = BlockIdV1::new([0x71; 32]);
        mutants.push(value);
        let mut value = canonical.clone();
        value.parent_state_root[0] ^= 1;
        mutants.push(value);
        let mut value = canonical.clone();
        value.da_batch_id[0] ^= 1;
        mutants.push(value);
        let mut value = canonical.clone();
        value.da_certificate_id[0] ^= 1;
        mutants.push(value);
        let mut value = canonical.clone();
        value.source_cut_digest[0] ^= 1;
        mutants.push(value);
        let mut value = canonical;
        value.commands[0].command_commitment[0] ^= 1;
        mutants.push(value);

        assert!(mutants.iter().all(|mutant| mutant.revalidate().is_err()));
    }

    #[test]
    fn command_and_plan_order_or_duplicate_fail_closed() {
        assert!(input_with(
            [0x21; 32],
            vec![
                command(G2CommandPlaneV2::MvccFee, 0, 2),
                command(G2CommandPlaneV2::AgentMarket, 0, 1),
            ],
        )
        .is_err());
        assert!(input_with(
            [0x21; 32],
            vec![
                command(G2CommandPlaneV2::AgentMarket, 0, 1),
                command(G2CommandPlaneV2::AgentMarket, 0, 1),
            ],
        )
        .is_err());

        let input = input();
        let first = G2OrderedItemV2::new(
            G2OrderedRootKindV2::TransactionExecutionReceipts,
            0,
            10,
            [0x41; 32],
            [0x42; 32],
        )
        .expect("first receipt");
        let second = G2OrderedItemV2::new(
            G2OrderedRootKindV2::TransactionExecutionReceipts,
            1,
            10,
            [0x43; 32],
            [0x44; 32],
        )
        .expect("second receipt");
        assert!(G2InertExecutionPlanV2::new(
            &input,
            Vec::new(),
            vec![second.clone(), first.clone()],
        )
        .is_err());
        assert!(
            G2InertExecutionPlanV2::new(&input, Vec::new(), vec![first.clone(), first]).is_err()
        );
    }

    #[test]
    fn plan_derives_all_list_roots_and_rejects_readdressed_retained_body() {
        let input = input();
        let receipt = G2OrderedItemV2::new(
            G2OrderedRootKindV2::TransactionExecutionReceipts,
            0,
            10,
            [0x41; 32],
            [0x42; 32],
        )
        .expect("receipt item");
        let plan =
            G2InertExecutionPlanV2::new(&input, Vec::new(), vec![receipt]).expect("canonical plan");
        let roots = derive_g2_ordered_list_roots_v2(&plan).expect("derive seven list roots");
        assert_ne!(roots[0], empty_ordered_root_v1(0));
        assert_ne!(roots[1], empty_ordered_root_v1(1));
        assert_ne!(roots[2], empty_ordered_root_v1(2));
        assert_eq!(roots[3], empty_ordered_root_v1(3));

        let mut readdressed = plan;
        readdressed.ordered_items[2].item_commitment[0] ^= 1;
        assert!(readdressed.revalidate().is_err());
    }
}
