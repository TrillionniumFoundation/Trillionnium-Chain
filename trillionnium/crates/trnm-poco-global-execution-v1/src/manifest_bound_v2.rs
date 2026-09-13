//! Candidate-ID-free adapter from exact global plane commands to the shared
//! manifest-bound Order seam.
//!
//! T0-A supplies a pure command/input projection. T0-B adds a bounded
//! five-source read-only preview: the caller supplies no containing Order
//! block ID and no execution root. An internal candidate-local coordinate is
//! derived from the manifest input ID, existing plane previews are used only
//! as transition oracles, and their results are normalized under distinct v2
//! domains. The resulting plan still creates no normative application state;
//! its seven ordered lists commit exact candidate-local roots, receipts,
//! source-cut evidence, rollups, settlement facts, and resource usage.
//!
//! Every public carrier here remains inert. None is a store, commit, voting,
//! finality, Node, or production capability, and no legacy candidate-ID-bearing
//! global preview/ready carrier is promoted by this adapter.

use borsh::{BorshDeserialize, BorshSerialize};
use trnm_poco_agent_market_v1::{
    Hash32V1 as AgentHash32V1, KernelCommandV1, KernelTransitionReceiptV1,
};
use trnm_poco_consumption_settlement_v1::{
    ConsumptionSettlementCommandV1, ConsumptionTransitionReceiptV1,
};
use trnm_poco_da_v1::{AvailabilityCertificateIdV1, BatchIdV1};
use trnm_poco_mvcc_fee_v1::{
    DestinationFeeCreditV1, FeeDeltaV1, MvccBlockV1, ResourceUsageV1, TransactionExecutionReceiptV1,
};
use trnm_poco_order_application_v1::G2FinalizeBindingRequestV2;
use trnm_poco_order_types_v1::{
    derive_g2_ordered_list_roots_v2, domain_separated_digest_v1, BlockIdV1, G2CommandCommitmentV2,
    G2CommandPlaneV2, G2ExecutionPlanDigestV2, G2InertExecutionPlanV2, G2ManifestBoundInputIdV2,
    G2ManifestBoundInputV2, G2OrderedItemV2, G2OrderedRootKindV2, ProtocolContextV1,
};
use trnm_poco_verify_challenge_v1::{VerifyCommandV1, VerifyTransitionReceiptV1};

use crate::{
    codec::{canonical_bytes, digest_value, strict_decode},
    error::{error, GlobalExecutionErrorCodeV1, GlobalExecutionResultV1},
    store::{decode_complete_retrieval_v1, sample_source_cut},
    types::SourceCutV1,
    CandidateExecutionContextV1, GlobalExecutionSourcesV1, Hash32V1,
};

const G2_GLOBAL_BATCH_SCHEMA_V2: u16 = 2;
const G2_TYPED_COMMAND_COMMITMENT_DOMAIN_V2: &str = "trnm.poco-ai.g2-global-typed-command.v2";
const G2_CANDIDATE_LOCAL_ID_DOMAIN_V2: &str = "trnm.poco-ai.g2-candidate-local-execution.v2";
const G2_CANDIDATE_LOCAL_RECEIPT_ID_DOMAIN_V2: &str =
    "trnm.poco-ai.g2-candidate-local-receipt-id.v2";
const G2_CANDIDATE_LOCAL_RECEIPT_COMMITMENT_DOMAIN_V2: &str =
    "trnm.poco-ai.g2-candidate-local-receipt.v2";
const G2_CANDIDATE_LOCAL_RECEIPT_ROOT_DOMAIN_V2: &str =
    "trnm.poco-ai.g2-candidate-local-receipt-root.v2";
const G2_ORDERED_ITEM_ID_DOMAIN_V2: &str = "trnm.poco-ai.g2-global-ordered-item-id.v2";
const G2_ORDERED_ITEM_COMMITMENT_DOMAIN_V2: &str = "trnm.poco-ai.g2-global-ordered-item.v2";
const G2_RETRIEVED_BATCH_DOMAIN_V2: &str = "trnm.poco-ai.g2-retrieved-global-batch.v2";
const G2_FIVE_PLANE_PREVIEW_DOMAIN_V2: &str = "trnm.poco-ai.g2-five-plane-preview.v2";
const G2_FINALIZE_JOIN_DOMAIN_V2: &str = "trnm.poco-ai.g2-finalize-candidate-local-join.v2";

const AGENT_MARKET_COMMAND_KIND_V2: u16 = 1;
const VERIFY_CHALLENGE_COMMAND_KIND_V2: u16 = 2;
const MVCC_FEE_BLOCK_KIND_V2: u16 = 3;
const CONSUMPTION_SETTLEMENT_COMMAND_KIND_V2: u16 = 4;

const G2_PLANE_ROOTS_ITEM_KIND_V2: u16 = 0x0210;
const G2_AGENT_RECEIPT_ITEM_KIND_V2: u16 = 0x0220;
const G2_VERIFY_RECEIPT_ITEM_KIND_V2: u16 = 0x0221;
const G2_MVCC_RECEIPT_ITEM_KIND_V2: u16 = 0x0222;
const G2_CONSUMPTION_RECEIPT_ITEM_KIND_V2: u16 = 0x0223;
const G2_SOURCE_STABILITY_ITEM_KIND_V2: u16 = 0x0230;
const G2_CONSUMPTION_ROLLUP_ITEM_KIND_V2: u16 = 0x0240;
const G2_MVCC_SETTLEMENT_ITEM_KIND_V2: u16 = 0x0250;
const G2_CONSUMPTION_SETTLEMENT_ITEM_KIND_V2: u16 = 0x0251;
const G2_RESOURCE_USAGE_ITEM_KIND_V2: u16 = 0x0260;

const MAX_COMMANDS_PER_PLANE_V2: usize = 256;

/// Exact DA item selected before certification and before a containing Order
/// header exists. The only Order block ID is the already-authenticated parent.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ManifestBoundGlobalExecutionBatchV2 {
    schema_version: u16,
    context: CandidateExecutionContextV1,
    campaign_id: Hash32V1,
    manifest_digest: Hash32V1,
    workload_corpus_digest: Hash32V1,
    trust_bundle_digest: Hash32V1,
    parent_height: u64,
    parent_block_id: Hash32V1,
    parent_state_root: Hash32V1,
    candidate_height: u64,
    agent_market_commands: Vec<KernelCommandV1>,
    verify_challenge_commands: Vec<VerifyCommandV1>,
    mvcc_fee_block: MvccBlockV1,
    consumption_settlement_commands: Vec<ConsumptionSettlementCommandV1>,
}

impl ManifestBoundGlobalExecutionBatchV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: CandidateExecutionContextV1,
        campaign_id: Hash32V1,
        manifest_digest: Hash32V1,
        workload_corpus_digest: Hash32V1,
        trust_bundle_digest: Hash32V1,
        parent_height: u64,
        parent_block_id: BlockIdV1,
        parent_state_root: Hash32V1,
        candidate_height: u64,
        agent_market_commands: Vec<KernelCommandV1>,
        verify_challenge_commands: Vec<VerifyCommandV1>,
        mvcc_fee_block: MvccBlockV1,
        consumption_settlement_commands: Vec<ConsumptionSettlementCommandV1>,
    ) -> GlobalExecutionResultV1<Self> {
        let value = Self {
            schema_version: G2_GLOBAL_BATCH_SCHEMA_V2,
            context,
            campaign_id,
            manifest_digest,
            workload_corpus_digest,
            trust_bundle_digest,
            parent_height,
            parent_block_id: Hash32V1(parent_block_id.to_bytes()),
            parent_state_root,
            candidate_height,
            agent_market_commands,
            verify_challenge_commands,
            mvcc_fee_block,
            consumption_settlement_commands,
        };
        value.revalidate()?;
        Ok(value)
    }

    pub const fn context(&self) -> &CandidateExecutionContextV1 {
        &self.context
    }

    pub const fn parent_height(&self) -> u64 {
        self.parent_height
    }

    pub const fn parent_block_id(&self) -> BlockIdV1 {
        BlockIdV1::new(self.parent_block_id.0)
    }

    pub const fn parent_state_root(&self) -> Hash32V1 {
        self.parent_state_root
    }

    pub const fn candidate_height(&self) -> u64 {
        self.candidate_height
    }

    pub fn agent_market_commands(&self) -> &[KernelCommandV1] {
        &self.agent_market_commands
    }

    pub fn verify_challenge_commands(&self) -> &[VerifyCommandV1] {
        &self.verify_challenge_commands
    }

    pub const fn mvcc_fee_block(&self) -> &MvccBlockV1 {
        &self.mvcc_fee_block
    }

    pub fn consumption_settlement_commands(&self) -> &[ConsumptionSettlementCommandV1] {
        &self.consumption_settlement_commands
    }

    pub fn revalidate(&self) -> GlobalExecutionResultV1<()> {
        validate_candidate_context_v2(&self.context)?;
        let total_commands = self
            .agent_market_commands
            .len()
            .checked_add(self.verify_challenge_commands.len())
            .and_then(|value| value.checked_add(self.mvcc_fee_block.transactions.len()))
            .and_then(|value| value.checked_add(self.consumption_settlement_commands.len()))
            .ok_or_else(|| {
                error(
                    GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                    "manifest-bound G2 command count overflows",
                )
            })?;
        if self.schema_version != G2_GLOBAL_BATCH_SCHEMA_V2
            || [
                self.campaign_id,
                self.manifest_digest,
                self.workload_corpus_digest,
                self.trust_bundle_digest,
                self.parent_block_id,
                self.parent_state_root,
            ]
            .contains(&Hash32V1([0; 32]))
            || self.parent_height == 0
            || self.parent_height.checked_add(1) != Some(self.candidate_height)
            || self.agent_market_commands.len() > MAX_COMMANDS_PER_PLANE_V2
            || self.verify_challenge_commands.len() > MAX_COMMANDS_PER_PLANE_V2
            || self.mvcc_fee_block.transactions.len() > MAX_COMMANDS_PER_PLANE_V2
            || self.consumption_settlement_commands.len() > MAX_COMMANDS_PER_PLANE_V2
            || total_commands == 0
            || self.mvcc_fee_block.schema_version != 1
            || self.mvcc_fee_block.block_id.0 == [0; 32]
            || self.mvcc_fee_block.height != self.candidate_height
            || self.mvcc_fee_block.expected_parent_height != self.parent_height
            || self.mvcc_fee_block.context.chain_id != self.context.chain_id.as_bytes()
            || self.mvcc_fee_block.context.genesis_hash.0 != self.context.genesis_hash.0
            || self.mvcc_fee_block.context.protocol_id != b"trnm-poco-ai-native-v1"
            || self.mvcc_fee_block.context.protocol_version != self.context.protocol_version
            || self.mvcc_fee_block.context.profile_hash.0 != self.context.stack_profile_hash.0
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::InvalidBounds,
                "manifest-bound G2 batch context, parent, or command inventory is invalid",
            ));
        }
        Ok(())
    }
}

/// Exact certified global input prior to containing-header construction.
///
/// There is deliberately no candidate/containing block-ID field and no
/// caller-supplied execution or receipt root. The DA item can be produced
/// first, certified, then joined to the exact certificate and fresh source cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestBoundGlobalExecutionInputV2 {
    batch: ManifestBoundGlobalExecutionBatchV2,
    da_batch_id: BatchIdV1,
    da_certificate_id: AvailabilityCertificateIdV1,
    source_cut_digest: Hash32V1,
}

impl ManifestBoundGlobalExecutionInputV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: CandidateExecutionContextV1,
        campaign_id: Hash32V1,
        manifest_digest: Hash32V1,
        workload_corpus_digest: Hash32V1,
        trust_bundle_digest: Hash32V1,
        parent_height: u64,
        parent_block_id: BlockIdV1,
        parent_state_root: Hash32V1,
        candidate_height: u64,
        da_batch_id: BatchIdV1,
        da_certificate_id: AvailabilityCertificateIdV1,
        source_cut_digest: Hash32V1,
        agent_market_commands: Vec<KernelCommandV1>,
        verify_challenge_commands: Vec<VerifyCommandV1>,
        mvcc_fee_block: MvccBlockV1,
        consumption_settlement_commands: Vec<ConsumptionSettlementCommandV1>,
    ) -> GlobalExecutionResultV1<Self> {
        let batch = ManifestBoundGlobalExecutionBatchV2::new(
            context,
            campaign_id,
            manifest_digest,
            workload_corpus_digest,
            trust_bundle_digest,
            parent_height,
            parent_block_id,
            parent_state_root,
            candidate_height,
            agent_market_commands,
            verify_challenge_commands,
            mvcc_fee_block,
            consumption_settlement_commands,
        )?;
        Self::from_certified_batch_v2(batch, da_batch_id, da_certificate_id, source_cut_digest)
    }

    pub fn from_certified_batch_v2(
        batch: ManifestBoundGlobalExecutionBatchV2,
        da_batch_id: BatchIdV1,
        da_certificate_id: AvailabilityCertificateIdV1,
        source_cut_digest: Hash32V1,
    ) -> GlobalExecutionResultV1<Self> {
        batch.revalidate()?;
        if *da_batch_id.as_bytes() == [0; 32]
            || *da_certificate_id.as_bytes() == [0; 32]
            || source_cut_digest == Hash32V1([0; 32])
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::InvalidBounds,
                "manifest-bound G2 DA or source binding is zero",
            ));
        }
        let value = Self {
            batch,
            da_batch_id,
            da_certificate_id,
            source_cut_digest,
        };
        value.project_order_input_v2()?;
        Ok(value)
    }

    /// Bind typed certified-batch coordinates to a freshly sampled source cut.
    ///
    /// This convenience returns only Clone, inert input data. It neither
    /// exposes a source-store owner nor creates a preview, finalize join, vote
    /// carrier, or persistence authority. Complete certificate/retrieval and
    /// unchanged-source checks still occur in `preview_five_plane_inert_v2`.
    pub fn from_certified_batch_and_fresh_sources_v2(
        batch: ManifestBoundGlobalExecutionBatchV2,
        da_batch_id: BatchIdV1,
        da_certificate_id: AvailabilityCertificateIdV1,
        sources: &mut GlobalExecutionSourcesV1<'_>,
    ) -> GlobalExecutionResultV1<Self> {
        batch.revalidate()?;
        let context = batch.context().clone();
        let source_cut_digest = sample_source_cut(sources, &context)?.digest;
        Self::from_certified_batch_v2(batch, da_batch_id, da_certificate_id, source_cut_digest)
    }

    pub const fn batch(&self) -> &ManifestBoundGlobalExecutionBatchV2 {
        &self.batch
    }

    pub const fn da_batch_id(&self) -> BatchIdV1 {
        self.da_batch_id
    }

    pub const fn da_certificate_id(&self) -> AvailabilityCertificateIdV1 {
        self.da_certificate_id
    }

    pub const fn source_cut_digest(&self) -> Hash32V1 {
        self.source_cut_digest
    }

    /// Project exact Borsh command bytes into the common CEV1 commitment
    /// layer. This is data conversion only and grants no preview or vote
    /// authority.
    pub fn project_order_input_v2(&self) -> GlobalExecutionResultV1<G2ManifestBoundInputV2> {
        self.batch.revalidate()?;
        let mut commands = Vec::new();
        for (index, command) in self.batch.agent_market_commands.iter().enumerate() {
            commands.push(command_commitment(
                G2CommandPlaneV2::AgentMarket,
                index,
                AGENT_MARKET_COMMAND_KIND_V2,
                command,
            )?);
        }
        for (index, command) in self.batch.verify_challenge_commands.iter().enumerate() {
            commands.push(command_commitment(
                G2CommandPlaneV2::VerifyChallenge,
                index,
                VERIFY_CHALLENGE_COMMAND_KIND_V2,
                command,
            )?);
        }
        commands.push(command_commitment(
            G2CommandPlaneV2::MvccFee,
            0,
            MVCC_FEE_BLOCK_KIND_V2,
            &self.batch.mvcc_fee_block,
        )?);
        for (index, command) in self
            .batch
            .consumption_settlement_commands
            .iter()
            .enumerate()
        {
            commands.push(command_commitment(
                G2CommandPlaneV2::ConsumptionSettlement,
                index,
                CONSUMPTION_SETTLEMENT_COMMAND_KIND_V2,
                command,
            )?);
        }

        G2ManifestBoundInputV2::new(
            ProtocolContextV1 {
                schema_version: self.batch.context.schema_version,
                genesis_hash: self.batch.context.genesis_hash.0,
                chain_id: self.batch.context.chain_id.clone(),
                protocol_version: self.batch.context.protocol_version,
                stack_profile_hash: self.batch.context.stack_profile_hash.0,
            },
            self.batch.campaign_id.0,
            self.batch.manifest_digest.0,
            self.batch.workload_corpus_digest.0,
            self.batch.trust_bundle_digest.0,
            self.batch.parent_height,
            BlockIdV1::new(self.batch.parent_block_id.0),
            self.batch.parent_state_root.0,
            self.batch.candidate_height,
            *self.da_batch_id.as_bytes(),
            *self.da_certificate_id.as_bytes(),
            self.source_cut_digest.0,
            commands,
        )
        .map_err(|cause| {
            error(
                GlobalExecutionErrorCodeV1::NonCanonicalBatch,
                format!("manifest-bound G2 input projection failed: {cause}"),
            )
        })
    }

    /// Produce the narrow T0-A inert plan. Mandatory batch/protocol anchors
    /// commit the exact input while all execution-result lists remain empty.
    pub fn project_inert_order_plan_v2(
        &self,
    ) -> GlobalExecutionResultV1<(G2ManifestBoundInputV2, G2InertExecutionPlanV2)> {
        let input = self.project_order_input_v2()?;
        let plan =
            G2InertExecutionPlanV2::new(&input, Vec::new(), Vec::new()).map_err(|cause| {
                error(
                    GlobalExecutionErrorCodeV1::NonCanonicalBatch,
                    format!("manifest-bound G2 inert plan projection failed: {cause}"),
                )
            })?;
        Ok((input, plan))
    }

    /// Freshly retrieve the exact certified v2 batch and preview all four
    /// execution stores from the common five-source cut. The caller supplies
    /// no candidate Order block ID; the only temporary coordinate passed to
    /// legacy plane oracles is derived from the manifest input ID.
    pub fn preview_five_plane_inert_v2(
        &self,
        sources: &mut GlobalExecutionSourcesV1<'_>,
    ) -> GlobalExecutionResultV1<ManifestBoundFivePlanePreviewV2> {
        preview_five_plane_inert_v2(self, sources)
    }
}

/// Internal candidate-local coordinate. It is structurally distinct from the
/// containing Order [`BlockIdV1`] and is derived only after DA/source binding.
#[derive(Clone, Copy, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct G2CandidateLocalExecutionIdV2([u8; 32]);

impl G2CandidateLocalExecutionIdV2 {
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum G2CandidateLocalReceiptPlaneV2 {
    AgentMarket = 1,
    VerifyChallenge = 2,
    MvccFee = 3,
    ConsumptionSettlement = 4,
}

/// Exact candidate-local receipt body. The Agent/Verify/Consumption variants
/// deliberately omit the legacy field named `order_block_id`; their local
/// coordinate is committed by the outer receipt instead. The large MVCC
/// receipt intentionally remains inline so the canonical Borsh shape and
/// ownership model do not acquire heap-indirection semantics.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub enum G2CandidateLocalReceiptBodyV2 {
    AgentMarket {
        store_id: [u8; 32],
        sequence: u64,
        operation_id: [u8; 32],
        operation_kind: u16,
        operation_digest: [u8; 32],
        post_state_root: [u8; 32],
    },
    VerifyChallenge {
        store_id: [u8; 32],
        sequence: u64,
        operation_id: [u8; 32],
        operation_kind: u16,
        post_state_root: [u8; 32],
    },
    MvccFee {
        block_id: [u8; 32],
        receipt: TransactionExecutionReceiptV1,
    },
    ConsumptionSettlement {
        store_id: [u8; 32],
        sequence: u64,
        operation_id: [u8; 32],
        operation_kind: u16,
        post_state_root: [u8; 32],
        settlement_id: Option<[u8; 32]>,
    },
}

/// One normalized, content-addressed candidate-local receipt. It is inert
/// public data, not an Order application receipt or finality fact.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct G2CandidateLocalReceiptV2 {
    schema_version: u16,
    candidate_local_id: G2CandidateLocalExecutionIdV2,
    candidate_height: u64,
    plane: G2CandidateLocalReceiptPlaneV2,
    plane_index: u32,
    body: G2CandidateLocalReceiptBodyV2,
    receipt_commitment: Hash32V1,
    receipt_id: Hash32V1,
}

impl G2CandidateLocalReceiptV2 {
    pub const fn candidate_local_id(&self) -> G2CandidateLocalExecutionIdV2 {
        self.candidate_local_id
    }

    pub const fn candidate_height(&self) -> u64 {
        self.candidate_height
    }

    pub const fn plane(&self) -> G2CandidateLocalReceiptPlaneV2 {
        self.plane
    }

    pub const fn plane_index(&self) -> u32 {
        self.plane_index
    }

    pub const fn body(&self) -> &G2CandidateLocalReceiptBodyV2 {
        &self.body
    }

    pub const fn receipt_commitment(&self) -> Hash32V1 {
        self.receipt_commitment
    }

    pub const fn receipt_id(&self) -> Hash32V1 {
        self.receipt_id
    }
}

/// Exact plane-local roots and normalized receipt inventories produced by one
/// source-stable preview. None is the Order application's JMT root.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct G2CandidateLocalPlaneRootsV2 {
    schema_version: u16,
    candidate_local_id: G2CandidateLocalExecutionIdV2,
    candidate_height: u64,
    source_cut_digest: Hash32V1,
    retrieved_batch_digest: Hash32V1,
    agent_market_candidate_root: Hash32V1,
    agent_market_receipts_root: Hash32V1,
    verify_challenge_candidate_root: Hash32V1,
    verify_challenge_receipts_root: Hash32V1,
    mvcc_fee_candidate_root: Hash32V1,
    mvcc_receipts_root: Hash32V1,
    mvcc_native_receipts_root: Hash32V1,
    mvcc_resource_totals_root: Hash32V1,
    mvcc_fee_deltas_root: Hash32V1,
    mvcc_resolution_root: Hash32V1,
    consumption_settlement_candidate_root: Hash32V1,
    consumption_settlement_receipts_root: Hash32V1,
}

impl G2CandidateLocalPlaneRootsV2 {
    pub const fn candidate_local_id(&self) -> G2CandidateLocalExecutionIdV2 {
        self.candidate_local_id
    }

    pub const fn source_cut_digest(&self) -> Hash32V1 {
        self.source_cut_digest
    }

    pub const fn retrieved_batch_digest(&self) -> Hash32V1 {
        self.retrieved_batch_digest
    }

    pub const fn agent_market_candidate_root(&self) -> Hash32V1 {
        self.agent_market_candidate_root
    }

    pub const fn agent_market_receipts_root(&self) -> Hash32V1 {
        self.agent_market_receipts_root
    }

    pub const fn verify_challenge_candidate_root(&self) -> Hash32V1 {
        self.verify_challenge_candidate_root
    }

    pub const fn verify_challenge_receipts_root(&self) -> Hash32V1 {
        self.verify_challenge_receipts_root
    }

    pub const fn mvcc_fee_candidate_root(&self) -> Hash32V1 {
        self.mvcc_fee_candidate_root
    }

    pub const fn mvcc_receipts_root(&self) -> Hash32V1 {
        self.mvcc_receipts_root
    }

    pub const fn mvcc_native_receipts_root(&self) -> Hash32V1 {
        self.mvcc_native_receipts_root
    }

    pub const fn mvcc_resource_totals_root(&self) -> Hash32V1 {
        self.mvcc_resource_totals_root
    }

    pub const fn mvcc_fee_deltas_root(&self) -> Hash32V1 {
        self.mvcc_fee_deltas_root
    }

    pub const fn mvcc_resolution_root(&self) -> Hash32V1 {
        self.mvcc_resolution_root
    }

    pub const fn consumption_settlement_candidate_root(&self) -> Hash32V1 {
        self.consumption_settlement_candidate_root
    }

    pub const fn consumption_settlement_receipts_root(&self) -> Hash32V1 {
        self.consumption_settlement_receipts_root
    }
}

/// Non-Clone result of one exact five-source preview. It can only be split
/// into the shared Order input/plan and an inert later-join binding.
#[must_use = "retain the preview until its exact Order input and plan are sealed"]
#[derive(Debug)]
pub struct ManifestBoundFivePlanePreviewV2 {
    input: G2ManifestBoundInputV2,
    plan: G2InertExecutionPlanV2,
    plane_roots: G2CandidateLocalPlaneRootsV2,
    receipts: Vec<G2CandidateLocalReceiptV2>,
    ordered_roots: [[u8; 32]; 8],
    preview_digest: Hash32V1,
}

impl ManifestBoundFivePlanePreviewV2 {
    pub const fn input(&self) -> &G2ManifestBoundInputV2 {
        &self.input
    }

    pub const fn plan(&self) -> &G2InertExecutionPlanV2 {
        &self.plan
    }

    pub const fn plane_roots(&self) -> &G2CandidateLocalPlaneRootsV2 {
        &self.plane_roots
    }

    pub fn receipts(&self) -> &[G2CandidateLocalReceiptV2] {
        &self.receipts
    }

    pub const fn ordered_roots(&self) -> [[u8; 32]; 8] {
        self.ordered_roots
    }

    pub const fn preview_digest(&self) -> Hash32V1 {
        self.preview_digest
    }

    pub fn into_order_material_v2(
        self,
    ) -> (
        G2ManifestBoundInputV2,
        G2InertExecutionPlanV2,
        G2CandidateLocalPreviewBindingV2,
    ) {
        let input_id = self.input.input_id();
        let candidate_height = self.input.candidate_height();
        let plan_digest = self.plan.plan_digest();
        (
            self.input,
            self.plan,
            G2CandidateLocalPreviewBindingV2 {
                input_id,
                candidate_height,
                plan_digest,
                plane_roots: self.plane_roots,
                receipts: self.receipts,
                ordered_roots: self.ordered_roots,
                preview_digest: self.preview_digest,
            },
        )
    }
}

/// Non-Clone inert binding retained while Order application derives the exact
/// containing header. It cannot write any source or issue vote authority.
#[must_use = "join this binding to the exact Order finalize request"]
#[derive(Debug)]
pub struct G2CandidateLocalPreviewBindingV2 {
    input_id: G2ManifestBoundInputIdV2,
    candidate_height: u64,
    plan_digest: G2ExecutionPlanDigestV2,
    plane_roots: G2CandidateLocalPlaneRootsV2,
    receipts: Vec<G2CandidateLocalReceiptV2>,
    ordered_roots: [[u8; 32]; 8],
    preview_digest: Hash32V1,
}

impl G2CandidateLocalPreviewBindingV2 {
    pub fn join_finalize_request_v2(
        self,
        request: G2FinalizeBindingRequestV2,
    ) -> GlobalExecutionResultV1<G2CandidateLocalFinalizeJoinV2> {
        if request.input_id() != self.input_id
            || derive_candidate_local_id(request.input_id()) != self.plane_roots.candidate_local_id
            || request.candidate_height() != self.candidate_height
            || request.candidate_height() != self.plane_roots.candidate_height
            || request.plan_digest() != self.plan_digest
            || request.ordered_roots() != self.ordered_roots
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::FinalizationOwnerMismatch,
                "G2 finalize request input, plan, height, or eight roots differ from fresh preview",
            ));
        }
        let join_digest = digest_value(
            G2_FINALIZE_JOIN_DOMAIN_V2,
            &(
                request.binding_digest(),
                self.preview_digest,
                request.candidate_block_id().to_bytes(),
                self.ordered_roots,
                self.plan_digest.to_bytes(),
            ),
        )?;
        Ok(G2CandidateLocalFinalizeJoinV2 {
            request,
            plane_roots: self.plane_roots,
            receipts: self.receipts,
            preview_digest: self.preview_digest,
            join_digest,
        })
    }
}

/// Exact, non-Clone, inert join between candidate-local preview facts and the
/// later containing Order header. It grants no global-store or Node authority.
#[must_use = "this inert join is not a commit or vote capability"]
#[derive(Debug)]
pub struct G2CandidateLocalFinalizeJoinV2 {
    request: G2FinalizeBindingRequestV2,
    plane_roots: G2CandidateLocalPlaneRootsV2,
    receipts: Vec<G2CandidateLocalReceiptV2>,
    preview_digest: Hash32V1,
    join_digest: Hash32V1,
}

impl G2CandidateLocalFinalizeJoinV2 {
    /// Exact manifest input selected by the joined Order request. This is
    /// inert comparison data; it is not a constructor, decoder, or store
    /// capability.
    pub const fn input_id(&self) -> G2ManifestBoundInputIdV2 {
        self.request.input_id()
    }

    /// Exact candidate height selected by the joined Order request.
    pub const fn candidate_height(&self) -> u64 {
        self.request.candidate_height()
    }

    pub const fn candidate_block_id(&self) -> BlockIdV1 {
        self.request.candidate_block_id()
    }

    pub const fn ordered_roots(&self) -> [[u8; 32]; 8] {
        self.request.ordered_roots()
    }

    /// Exact inert execution-plan digest selected by the joined Order
    /// request. Exposing this value does not expose the plan or an issuer.
    pub const fn plan_digest(&self) -> G2ExecutionPlanDigestV2 {
        self.request.plan_digest()
    }

    /// Exact request commitment already checked by the candidate-local join.
    pub const fn binding_digest(&self) -> [u8; 32] {
        self.request.binding_digest()
    }

    pub const fn plane_roots(&self) -> &G2CandidateLocalPlaneRootsV2 {
        &self.plane_roots
    }

    pub fn receipts(&self) -> &[G2CandidateLocalReceiptV2] {
        &self.receipts
    }

    pub const fn preview_digest(&self) -> Hash32V1 {
        self.preview_digest
    }

    pub const fn join_digest(&self) -> Hash32V1 {
        self.join_digest
    }
}

#[derive(Clone, Debug, BorshSerialize)]
struct G2CandidateLocalReceiptCommitmentBodyV2 {
    schema_version: u16,
    candidate_local_id: G2CandidateLocalExecutionIdV2,
    candidate_height: u64,
    plane: G2CandidateLocalReceiptPlaneV2,
    plane_index: u32,
    body: G2CandidateLocalReceiptBodyV2,
}

#[derive(Clone, Debug, BorshSerialize)]
struct G2SourceStabilityEvidenceBodyV2 {
    schema_version: u16,
    input_id: [u8; 32],
    candidate_local_id: G2CandidateLocalExecutionIdV2,
    source_cut: SourceCutV1,
    da_batch_id: [u8; 32],
    da_certificate_id: [u8; 32],
    retrieved_batch_digest: Hash32V1,
    agent_unchanged_row_inventory_digest: Hash32V1,
}

#[derive(Clone, Debug, BorshSerialize)]
struct G2ConsumptionProjectionBodyV2 {
    schema_version: u16,
    command_index: u32,
    command_id: [u8; 32],
    command_commitment: [u8; 32],
    receipt_id: Hash32V1,
    receipt_commitment: Hash32V1,
}

#[derive(Clone, Debug, BorshSerialize)]
struct G2MvccSettlementBodyV2 {
    schema_version: u16,
    candidate_local_id: G2CandidateLocalExecutionIdV2,
    block_id: [u8; 32],
    fee_deltas_root: [u8; 32],
    resolution_root: [u8; 32],
    aggregated_fee_deltas: Vec<FeeDeltaV1>,
    destination_credits: Vec<DestinationFeeCreditV1>,
}

#[derive(BorshSerialize)]
struct G2FivePlanePreviewDigestBodyV2<'a> {
    input_id: [u8; 32],
    plan_digest: [u8; 32],
    ordered_roots: [[u8; 32]; 8],
    plane_roots: &'a G2CandidateLocalPlaneRootsV2,
    receipt_commitments: Vec<[u8; 32]>,
}

fn preview_five_plane_inert_v2(
    manifest: &ManifestBoundGlobalExecutionInputV2,
    sources: &mut GlobalExecutionSourcesV1<'_>,
) -> GlobalExecutionResultV1<ManifestBoundFivePlanePreviewV2> {
    let input = manifest.project_order_input_v2()?;
    let candidate_local_id = derive_candidate_local_id(input.input_id());
    let initial_cut = sample_source_cut(sources, manifest.batch.context())?;
    if initial_cut.digest != manifest.source_cut_digest {
        return Err(error(
            GlobalExecutionErrorCodeV1::SourceCutMismatch,
            "manifest-bound G2 input differs from the fresh five-source cut",
        ));
    }
    validate_order_parent_against_source_cut_v2(manifest.batch(), &initial_cut)?;

    let da_before = sources
        .da
        .fresh_certified_batch_readback(manifest.da_batch_id)
        .map_err(|cause| plane_error_v2(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
    if da_before.batch().certificate_id() != manifest.da_certificate_id
        || da_before.batch().obligation_status() != 0
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::DaRejected,
            "manifest-bound G2 DA certificate or obligation differs",
        ));
    }
    let certified = sources
        .da
        .certified_batch(manifest.da_batch_id)
        .map_err(|cause| plane_error_v2(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
    if certified.certificate().certificate_id() != manifest.da_certificate_id {
        return Err(error(
            GlobalExecutionErrorCodeV1::DaRejected,
            "manifest-bound G2 fresh DA certificate identity differs",
        ));
    }
    let total_length = certified.certificate().envelope().uncompressed_bytes();
    let retrieval = sources
        .da
        .retrieve(manifest.da_batch_id, 0, total_length)
        .map_err(|cause| plane_error_v2(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
    let transaction_items = decode_complete_retrieval_v1(
        manifest.da_certificate_id,
        retrieval.certificate().certificate_id(),
        certified.certificate().envelope().item_count(),
        total_length,
        retrieval.offset(),
        retrieval.total_length(),
        retrieval.bytes(),
    )?;
    let observed_batch: ManifestBoundGlobalExecutionBatchV2 = strict_decode(&transaction_items[0])?;
    observed_batch.revalidate()?;
    if &observed_batch != manifest.batch() {
        return Err(error(
            GlobalExecutionErrorCodeV1::NonCanonicalBatch,
            "retrieved manifest-bound G2 batch differs from exact input bytes",
        ));
    }
    let retrieved_batch_digest = digest_value(G2_RETRIEVED_BATCH_DOMAIN_V2, &transaction_items)?;

    let agent_parent = sources
        .agent_market
        .fresh_readback()
        .map_err(|cause| plane_error_v2(GlobalExecutionErrorCodeV1::AgentMarketRejected, cause))?;
    let verify_parent = sources.verify_challenge.fresh_readback().map_err(|cause| {
        plane_error_v2(GlobalExecutionErrorCodeV1::VerifyChallengeRejected, cause)
    })?;
    let mvcc_parent = sources
        .mvcc_fee
        .fresh_readback()
        .map_err(|cause| plane_error_v2(GlobalExecutionErrorCodeV1::MvccFeeRejected, cause))?;
    let settlement_parent = sources
        .consumption_settlement
        .fresh_readback()
        .map_err(|cause| {
            plane_error_v2(
                GlobalExecutionErrorCodeV1::ConsumptionSettlementRejected,
                cause,
            )
        })?;
    let local_oracle_coordinate = AgentHash32V1(candidate_local_id.0);
    let agent = sources
        .agent_market
        .preview_before_vote_v1(
            &agent_parent,
            manifest.batch.candidate_height,
            local_oracle_coordinate,
            &manifest.batch.agent_market_commands,
        )
        .map_err(|cause| plane_error_v2(GlobalExecutionErrorCodeV1::AgentMarketRejected, cause))?;
    let verify = sources
        .verify_challenge
        .preview_before_vote_v1(
            &verify_parent,
            manifest.batch.candidate_height,
            local_oracle_coordinate,
            &manifest.batch.verify_challenge_commands,
        )
        .map_err(|cause| {
            plane_error_v2(GlobalExecutionErrorCodeV1::VerifyChallengeRejected, cause)
        })?;
    let mvcc = sources
        .mvcc_fee
        .preview_before_vote_v1(&mvcc_parent, &manifest.batch.mvcc_fee_block)
        .map_err(|cause| plane_error_v2(GlobalExecutionErrorCodeV1::MvccFeeRejected, cause))?;
    let settlement = sources
        .consumption_settlement
        .preview_before_vote_v1(
            &settlement_parent,
            manifest.batch.candidate_height,
            local_oracle_coordinate,
            &manifest.batch.consumption_settlement_commands,
        )
        .map_err(|cause| {
            plane_error_v2(
                GlobalExecutionErrorCodeV1::ConsumptionSettlementRejected,
                cause,
            )
        })?;

    validate_preview_source_v2(
        &initial_cut,
        1,
        agent.source_sequence(),
        agent.source_state_root().0,
        agent.source_journal_root().0,
    )?;
    validate_preview_source_v2(
        &initial_cut,
        2,
        verify.source_sequence(),
        verify.source_state_root().0,
        verify.source_journal_root().0,
    )?;
    validate_preview_source_v2(
        &initial_cut,
        3,
        mvcc.source_height(),
        mvcc.source_state_root().0,
        mvcc.source_journal_root().0,
    )?;
    validate_preview_source_v2(
        &initial_cut,
        4,
        settlement.source_sequence(),
        settlement.source_state_root().0,
        settlement.source_journal_root().0,
    )?;

    if agent.candidate_receipts().len() != manifest.batch.agent_market_commands.len()
        || verify.candidate_receipts().len() != manifest.batch.verify_challenge_commands.len()
        || mvcc.candidate_receipt().receipts.len()
            != manifest.batch.mvcc_fee_block.transactions.len()
        || settlement.candidate_receipts().len()
            != manifest.batch.consumption_settlement_commands.len()
        || mvcc.candidate_receipt().height != manifest.batch.candidate_height
        || mvcc.candidate_receipt().block_id != manifest.batch.mvcc_fee_block.block_id
        || mvcc.candidate_receipt().parent_state_root
            != manifest.batch.mvcc_fee_block.expected_parent_state_root
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::CandidateCompositeRootMismatch,
            "plane preview receipt inventory differs from exact manifest commands",
        ));
    }

    let receipts = normalize_candidate_local_receipts_v2(
        candidate_local_id,
        manifest.batch.candidate_height,
        agent.candidate_receipts(),
        verify.candidate_receipts(),
        mvcc.candidate_receipt().block_id.0,
        &mvcc.candidate_receipt().receipts,
        settlement.candidate_receipts(),
    )?;
    let plane_roots = G2CandidateLocalPlaneRootsV2 {
        schema_version: G2_GLOBAL_BATCH_SCHEMA_V2,
        candidate_local_id,
        candidate_height: manifest.batch.candidate_height,
        source_cut_digest: initial_cut.digest,
        retrieved_batch_digest,
        agent_market_candidate_root: Hash32V1(agent.candidate_post_state_root().0),
        agent_market_receipts_root: candidate_local_receipt_root_v2(
            G2CandidateLocalReceiptPlaneV2::AgentMarket,
            &receipts,
        )?,
        verify_challenge_candidate_root: Hash32V1(verify.candidate_post_state_root().0),
        verify_challenge_receipts_root: candidate_local_receipt_root_v2(
            G2CandidateLocalReceiptPlaneV2::VerifyChallenge,
            &receipts,
        )?,
        mvcc_fee_candidate_root: Hash32V1(mvcc.candidate_post_state_root().0),
        mvcc_receipts_root: candidate_local_receipt_root_v2(
            G2CandidateLocalReceiptPlaneV2::MvccFee,
            &receipts,
        )?,
        mvcc_native_receipts_root: Hash32V1(mvcc.candidate_receipt().receipts_root.0),
        mvcc_resource_totals_root: Hash32V1(mvcc.candidate_receipt().resource_totals_root.0),
        mvcc_fee_deltas_root: Hash32V1(mvcc.candidate_receipt().fee_deltas_root.0),
        mvcc_resolution_root: Hash32V1(mvcc.candidate_receipt().mvcc_resolution_root.0),
        consumption_settlement_candidate_root: Hash32V1(settlement.candidate_post_state_root().0),
        consumption_settlement_receipts_root: candidate_local_receipt_root_v2(
            G2CandidateLocalReceiptPlaneV2::ConsumptionSettlement,
            &receipts,
        )?,
    };

    let execution_items = build_ordered_execution_items_v2(
        &input,
        &initial_cut,
        manifest,
        &plane_roots,
        &receipts,
        agent.unchanged_row_inventory_digest().0,
        mvcc.candidate_receipt().resource_totals.as_slice(),
        mvcc.candidate_receipt().aggregated_fee_deltas.as_slice(),
        mvcc.candidate_receipt().destination_credits.as_slice(),
    )?;
    let plan =
        G2InertExecutionPlanV2::new(&input, Vec::new(), execution_items).map_err(|cause| {
            error(
                GlobalExecutionErrorCodeV1::NonCanonicalBatch,
                format!("candidate-local G2 plan projection failed: {cause}"),
            )
        })?;
    let ordered_roots = derive_exact_eight_roots_v2(&input, &plan)?;
    let preview_digest = digest_value(
        G2_FIVE_PLANE_PREVIEW_DOMAIN_V2,
        &G2FivePlanePreviewDigestBodyV2 {
            input_id: input.input_id().to_bytes(),
            plan_digest: plan.plan_digest().to_bytes(),
            ordered_roots,
            plane_roots: &plane_roots,
            receipt_commitments: receipts
                .iter()
                .map(|receipt| receipt.receipt_commitment.0)
                .collect(),
        },
    )?;

    let da_after = sources
        .da
        .fresh_certified_batch_readback(manifest.da_batch_id)
        .map_err(|cause| plane_error_v2(GlobalExecutionErrorCodeV1::DaRejected, cause))?;
    if da_after != da_before {
        return Err(error(
            GlobalExecutionErrorCodeV1::DaSourceChanged,
            "manifest-bound G2 DA head changed across retrieval and preview",
        ));
    }
    if sample_source_cut(sources, manifest.batch.context())? != initial_cut {
        return Err(error(
            GlobalExecutionErrorCodeV1::SourceCutMismatch,
            "five-source cut changed across manifest-bound G2 preview",
        ));
    }

    Ok(ManifestBoundFivePlanePreviewV2 {
        input,
        plan,
        plane_roots,
        receipts,
        ordered_roots,
        preview_digest,
    })
}

fn normalize_candidate_local_receipts_v2(
    candidate_local_id: G2CandidateLocalExecutionIdV2,
    candidate_height: u64,
    agent_receipts: &[KernelTransitionReceiptV1],
    verify_receipts: &[VerifyTransitionReceiptV1],
    mvcc_block_id: [u8; 32],
    mvcc_receipts: &[TransactionExecutionReceiptV1],
    settlement_receipts: &[ConsumptionTransitionReceiptV1],
) -> GlobalExecutionResultV1<Vec<G2CandidateLocalReceiptV2>> {
    let mut receipts = Vec::with_capacity(
        agent_receipts
            .len()
            .saturating_add(verify_receipts.len())
            .saturating_add(mvcc_receipts.len())
            .saturating_add(settlement_receipts.len()),
    );
    for (index, receipt) in agent_receipts.iter().enumerate() {
        validate_oracle_receipt_coordinate_v2(
            candidate_local_id,
            candidate_height,
            receipt.order_height,
            receipt.order_block_id.0,
        )?;
        receipts.push(seal_candidate_local_receipt_v2(
            candidate_local_id,
            candidate_height,
            G2CandidateLocalReceiptPlaneV2::AgentMarket,
            index,
            G2CandidateLocalReceiptBodyV2::AgentMarket {
                store_id: receipt.store_id.0,
                sequence: receipt.sequence,
                operation_id: receipt.operation_id.0,
                operation_kind: receipt.operation_kind,
                operation_digest: receipt.operation_digest.0,
                post_state_root: receipt.post_state_root.0,
            },
        )?);
    }
    for (index, receipt) in verify_receipts.iter().enumerate() {
        validate_oracle_receipt_coordinate_v2(
            candidate_local_id,
            candidate_height,
            receipt.order_height,
            receipt.order_block_id.0,
        )?;
        receipts.push(seal_candidate_local_receipt_v2(
            candidate_local_id,
            candidate_height,
            G2CandidateLocalReceiptPlaneV2::VerifyChallenge,
            index,
            G2CandidateLocalReceiptBodyV2::VerifyChallenge {
                store_id: receipt.store_id.0,
                sequence: receipt.sequence,
                operation_id: receipt.operation_id.0,
                operation_kind: receipt.operation_kind,
                post_state_root: receipt.post_state_root.0,
            },
        )?);
    }
    for (index, receipt) in mvcc_receipts.iter().enumerate() {
        receipts.push(seal_candidate_local_receipt_v2(
            candidate_local_id,
            candidate_height,
            G2CandidateLocalReceiptPlaneV2::MvccFee,
            index,
            G2CandidateLocalReceiptBodyV2::MvccFee {
                block_id: mvcc_block_id,
                receipt: receipt.clone(),
            },
        )?);
    }
    for (index, receipt) in settlement_receipts.iter().enumerate() {
        validate_oracle_receipt_coordinate_v2(
            candidate_local_id,
            candidate_height,
            receipt.order_height,
            receipt.order_block_id.0,
        )?;
        receipts.push(seal_candidate_local_receipt_v2(
            candidate_local_id,
            candidate_height,
            G2CandidateLocalReceiptPlaneV2::ConsumptionSettlement,
            index,
            G2CandidateLocalReceiptBodyV2::ConsumptionSettlement {
                store_id: receipt.store_id.0,
                sequence: receipt.sequence,
                operation_id: receipt.operation_id.0,
                operation_kind: receipt.operation_kind,
                post_state_root: receipt.post_state_root.0,
                settlement_id: receipt.settlement_id.map(|value| value.0),
            },
        )?);
    }
    Ok(receipts)
}

fn seal_candidate_local_receipt_v2(
    candidate_local_id: G2CandidateLocalExecutionIdV2,
    candidate_height: u64,
    plane: G2CandidateLocalReceiptPlaneV2,
    plane_index: usize,
    body: G2CandidateLocalReceiptBodyV2,
) -> GlobalExecutionResultV1<G2CandidateLocalReceiptV2> {
    let plane_index = u32::try_from(plane_index).map_err(|_| {
        error(
            GlobalExecutionErrorCodeV1::ArithmeticOverflow,
            "candidate-local receipt index exceeds u32",
        )
    })?;
    let commitment_body = G2CandidateLocalReceiptCommitmentBodyV2 {
        schema_version: G2_GLOBAL_BATCH_SCHEMA_V2,
        candidate_local_id,
        candidate_height,
        plane,
        plane_index,
        body: body.clone(),
    };
    let receipt_commitment = digest_value(
        G2_CANDIDATE_LOCAL_RECEIPT_COMMITMENT_DOMAIN_V2,
        &commitment_body,
    )?;
    let receipt_id = digest_value(
        G2_CANDIDATE_LOCAL_RECEIPT_ID_DOMAIN_V2,
        &(
            candidate_local_id,
            candidate_height,
            plane,
            plane_index,
            receipt_commitment,
        ),
    )?;
    Ok(G2CandidateLocalReceiptV2 {
        schema_version: G2_GLOBAL_BATCH_SCHEMA_V2,
        candidate_local_id,
        candidate_height,
        plane,
        plane_index,
        body,
        receipt_commitment,
        receipt_id,
    })
}

fn candidate_local_receipt_root_v2(
    plane: G2CandidateLocalReceiptPlaneV2,
    receipts: &[G2CandidateLocalReceiptV2],
) -> GlobalExecutionResultV1<Hash32V1> {
    let inventory = receipts
        .iter()
        .filter(|receipt| receipt.plane == plane)
        .map(|receipt| {
            (
                receipt.plane_index,
                receipt.receipt_id,
                receipt.receipt_commitment,
            )
        })
        .collect::<Vec<_>>();
    digest_value(
        G2_CANDIDATE_LOCAL_RECEIPT_ROOT_DOMAIN_V2,
        &(plane, inventory),
    )
}

#[allow(clippy::too_many_arguments)]
fn build_ordered_execution_items_v2(
    input: &G2ManifestBoundInputV2,
    source_cut: &SourceCutV1,
    manifest: &ManifestBoundGlobalExecutionInputV2,
    plane_roots: &G2CandidateLocalPlaneRootsV2,
    receipts: &[G2CandidateLocalReceiptV2],
    agent_inventory_digest: [u8; 32],
    resource_totals: &[ResourceUsageV1],
    aggregated_fee_deltas: &[FeeDeltaV1],
    destination_credits: &[DestinationFeeCreditV1],
) -> GlobalExecutionResultV1<Vec<G2OrderedItemV2>> {
    let mut items = Vec::new();
    items.push(ordered_item_from_value_v2(
        input,
        G2OrderedRootKindV2::ProtocolObjects,
        1,
        G2_PLANE_ROOTS_ITEM_KIND_V2,
        plane_roots,
    )?);

    for (index, receipt) in receipts.iter().enumerate() {
        items.push(ordered_item_from_value_v2(
            input,
            G2OrderedRootKindV2::TransactionExecutionReceipts,
            index,
            receipt_item_kind_v2(receipt.plane),
            receipt,
        )?);
    }

    let evidence = G2SourceStabilityEvidenceBodyV2 {
        schema_version: G2_GLOBAL_BATCH_SCHEMA_V2,
        input_id: input.input_id().to_bytes(),
        candidate_local_id: plane_roots.candidate_local_id,
        source_cut: source_cut.clone(),
        da_batch_id: *manifest.da_batch_id.as_bytes(),
        da_certificate_id: *manifest.da_certificate_id.as_bytes(),
        retrieved_batch_digest: plane_roots.retrieved_batch_digest,
        agent_unchanged_row_inventory_digest: Hash32V1(agent_inventory_digest),
    };
    items.push(ordered_item_from_value_v2(
        input,
        G2OrderedRootKindV2::Evidence,
        0,
        G2_SOURCE_STABILITY_ITEM_KIND_V2,
        &evidence,
    )?);

    let settlement_receipt_bindings = receipts
        .iter()
        .filter(|receipt| receipt.plane == G2CandidateLocalReceiptPlaneV2::ConsumptionSettlement)
        .collect::<Vec<_>>();
    let mut rollup_index = 0_usize;
    let mut consumption_settlement_index = 1_usize;
    for (command_index, command) in manifest
        .batch
        .consumption_settlement_commands
        .iter()
        .enumerate()
    {
        let command_index_u32 = u32::try_from(command_index).map_err(|_| {
            error(
                GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                "consumption command index exceeds u32",
            )
        })?;
        let command_binding = input
            .commands()
            .iter()
            .find(|binding| {
                binding.plane() == G2CommandPlaneV2::ConsumptionSettlement
                    && binding.index() == command_index_u32
            })
            .ok_or_else(|| {
                error(
                    GlobalExecutionErrorCodeV1::NonCanonicalBatch,
                    "consumption command is absent from exact manifest input",
                )
            })?;
        let receipt = settlement_receipt_bindings
            .iter()
            .find(|receipt| receipt.plane_index == command_index_u32)
            .ok_or_else(|| {
                error(
                    GlobalExecutionErrorCodeV1::ConsumptionSettlementRejected,
                    "consumption command lacks its exact candidate-local receipt",
                )
            })?;
        let projection = G2ConsumptionProjectionBodyV2 {
            schema_version: G2_GLOBAL_BATCH_SCHEMA_V2,
            command_index: command_index_u32,
            command_id: command_binding.command_id(),
            command_commitment: command_binding.command_commitment(),
            receipt_id: receipt.receipt_id,
            receipt_commitment: receipt.receipt_commitment,
        };
        match command {
            ConsumptionSettlementCommandV1::AdmitRollup { .. } => {
                items.push(ordered_item_from_value_v2(
                    input,
                    G2OrderedRootKindV2::ConsumptionRollups,
                    rollup_index,
                    G2_CONSUMPTION_ROLLUP_ITEM_KIND_V2,
                    &projection,
                )?);
                rollup_index = rollup_index.checked_add(1).ok_or_else(|| {
                    error(
                        GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                        "consumption rollup index overflows",
                    )
                })?;
            }
            ConsumptionSettlementCommandV1::Settle { .. } => {
                items.push(ordered_item_from_value_v2(
                    input,
                    G2OrderedRootKindV2::Settlement,
                    consumption_settlement_index,
                    G2_CONSUMPTION_SETTLEMENT_ITEM_KIND_V2,
                    &projection,
                )?);
                consumption_settlement_index =
                    consumption_settlement_index.checked_add(1).ok_or_else(|| {
                        error(
                            GlobalExecutionErrorCodeV1::ArithmeticOverflow,
                            "consumption settlement index overflows",
                        )
                    })?;
            }
            ConsumptionSettlementCommandV1::AdmitReceipt { .. } => {}
        }
    }

    let mvcc_settlement = G2MvccSettlementBodyV2 {
        schema_version: G2_GLOBAL_BATCH_SCHEMA_V2,
        candidate_local_id: plane_roots.candidate_local_id,
        block_id: manifest.batch.mvcc_fee_block.block_id.0,
        fee_deltas_root: plane_roots.mvcc_fee_deltas_root.0,
        resolution_root: plane_roots.mvcc_resolution_root.0,
        aggregated_fee_deltas: aggregated_fee_deltas.to_vec(),
        destination_credits: destination_credits.to_vec(),
    };
    items.push(ordered_item_from_value_v2(
        input,
        G2OrderedRootKindV2::Settlement,
        0,
        G2_MVCC_SETTLEMENT_ITEM_KIND_V2,
        &mvcc_settlement,
    )?);

    for (index, usage) in resource_totals.iter().enumerate() {
        items.push(ordered_item_from_value_v2(
            input,
            G2OrderedRootKindV2::ResourceUsage,
            index,
            G2_RESOURCE_USAGE_ITEM_KIND_V2,
            usage,
        )?);
    }
    items.sort_by_key(|item| (item.root_kind(), item.index()));
    Ok(items)
}

fn ordered_item_from_value_v2<T: BorshSerialize>(
    input: &G2ManifestBoundInputV2,
    root_kind: G2OrderedRootKindV2,
    index: usize,
    item_kind: u16,
    value: &T,
) -> GlobalExecutionResultV1<G2OrderedItemV2> {
    let index = u32::try_from(index).map_err(|_| {
        error(
            GlobalExecutionErrorCodeV1::ArithmeticOverflow,
            "manifest-bound G2 ordered-item index exceeds u32",
        )
    })?;
    let item_commitment = digest_value(
        G2_ORDERED_ITEM_COMMITMENT_DOMAIN_V2,
        &(root_kind.tag(), index, item_kind, value),
    )?;
    let item_id = digest_value(
        G2_ORDERED_ITEM_ID_DOMAIN_V2,
        &(
            input.input_id().to_bytes(),
            root_kind.tag(),
            index,
            item_kind,
            item_commitment,
        ),
    )?;
    G2OrderedItemV2::new(root_kind, index, item_kind, item_id.0, item_commitment.0).map_err(
        |cause| {
            error(
                GlobalExecutionErrorCodeV1::NonCanonicalBatch,
                format!("manifest-bound ordered item projection failed: {cause}"),
            )
        },
    )
}

fn derive_exact_eight_roots_v2(
    input: &G2ManifestBoundInputV2,
    plan: &G2InertExecutionPlanV2,
) -> GlobalExecutionResultV1<[[u8; 32]; 8]> {
    if !plan.state_creates().is_empty() {
        return Err(error(
            GlobalExecutionErrorCodeV1::NonCanonicalBatch,
            "T0-B plane adapter cannot claim a normative Order state delta",
        ));
    }
    let lists = derive_g2_ordered_list_roots_v2(plan).map_err(|cause| {
        error(
            GlobalExecutionErrorCodeV1::NonCanonicalBatch,
            format!("manifest-bound G2 ordered-root derivation failed: {cause}"),
        )
    })?;
    Ok([
        lists[0],
        lists[1],
        input.parent_state_root(),
        lists[2],
        lists[3],
        lists[4],
        lists[5],
        lists[6],
    ])
}

fn validate_order_parent_against_source_cut_v2(
    batch: &ManifestBoundGlobalExecutionBatchV2,
    cut: &SourceCutV1,
) -> GlobalExecutionResultV1<()> {
    for plane_tag in [1_u8, 2, 4] {
        let head = source_head_v2(cut, plane_tag)?;
        if head.order_height != batch.parent_height || head.order_block_id != batch.parent_block_id
        {
            return Err(error(
                GlobalExecutionErrorCodeV1::SourceCutMismatch,
                "manifest-bound Order parent differs from an ordered execution plane",
            ));
        }
    }
    let mvcc = source_head_v2(cut, 3)?;
    if mvcc.sequence_or_height != batch.mvcc_fee_block.expected_parent_height
        || mvcc.order_block_id.0 != batch.mvcc_fee_block.expected_parent_block_id.0
        || mvcc.state_or_metadata_root.0 != batch.mvcc_fee_block.expected_parent_state_root.0
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::SourceCutMismatch,
            "manifest-bound MVCC parent differs from the fresh source cut",
        ));
    }
    Ok(())
}

fn validate_preview_source_v2(
    cut: &SourceCutV1,
    plane_tag: u8,
    sequence_or_height: u64,
    state_root: [u8; 32],
    journal_root: [u8; 32],
) -> GlobalExecutionResultV1<()> {
    let head = source_head_v2(cut, plane_tag)?;
    if head.sequence_or_height != sequence_or_height
        || head.state_or_metadata_root.0 != state_root
        || head.journal_root.0 != journal_root
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::SourceCutMismatch,
            "plane preview source facts differ from the exact five-source cut",
        ));
    }
    Ok(())
}

fn source_head_v2(
    cut: &SourceCutV1,
    plane_tag: u8,
) -> GlobalExecutionResultV1<&crate::types::PlaneHeadV1> {
    cut.plane_heads
        .iter()
        .find(|head| head.plane_tag == plane_tag)
        .ok_or_else(|| {
            error(
                GlobalExecutionErrorCodeV1::SourceCutMismatch,
                "five-source cut omits a required execution plane",
            )
        })
}

fn validate_oracle_receipt_coordinate_v2(
    candidate_local_id: G2CandidateLocalExecutionIdV2,
    candidate_height: u64,
    observed_height: u64,
    observed_coordinate: [u8; 32],
) -> GlobalExecutionResultV1<()> {
    if observed_height != candidate_height || observed_coordinate != candidate_local_id.0 {
        return Err(error(
            GlobalExecutionErrorCodeV1::CandidateCompositeRootMismatch,
            "plane oracle receipt differs from its derived candidate-local coordinate",
        ));
    }
    Ok(())
}

fn receipt_item_kind_v2(plane: G2CandidateLocalReceiptPlaneV2) -> u16 {
    match plane {
        G2CandidateLocalReceiptPlaneV2::AgentMarket => G2_AGENT_RECEIPT_ITEM_KIND_V2,
        G2CandidateLocalReceiptPlaneV2::VerifyChallenge => G2_VERIFY_RECEIPT_ITEM_KIND_V2,
        G2CandidateLocalReceiptPlaneV2::MvccFee => G2_MVCC_RECEIPT_ITEM_KIND_V2,
        G2CandidateLocalReceiptPlaneV2::ConsumptionSettlement => {
            G2_CONSUMPTION_RECEIPT_ITEM_KIND_V2
        }
    }
}

fn derive_candidate_local_id(input_id: G2ManifestBoundInputIdV2) -> G2CandidateLocalExecutionIdV2 {
    G2CandidateLocalExecutionIdV2(domain_separated_digest_v1(
        G2_CANDIDATE_LOCAL_ID_DOMAIN_V2,
        input_id.as_bytes(),
    ))
}

fn validate_candidate_context_v2(
    context: &CandidateExecutionContextV1,
) -> GlobalExecutionResultV1<()> {
    if context.schema_version != 1
        || context.protocol_version != 1
        || context.chain_id.is_empty()
        || context.chain_id.len() > 128
        || !context.chain_id.is_ascii()
        || context.genesis_hash == Hash32V1([0; 32])
        || context.stack_profile_hash == Hash32V1([0; 32])
    {
        return Err(error(
            GlobalExecutionErrorCodeV1::InvalidContext,
            "manifest-bound G2 candidate context is invalid",
        ));
    }
    Ok(())
}

fn command_commitment<T: BorshSerialize>(
    plane: G2CommandPlaneV2,
    index: usize,
    command_kind: u16,
    command: &T,
) -> GlobalExecutionResultV1<G2CommandCommitmentV2> {
    let index = u32::try_from(index).map_err(|_| {
        error(
            GlobalExecutionErrorCodeV1::ArithmeticOverflow,
            "manifest-bound G2 command index exceeds u32",
        )
    })?;
    let bytes = canonical_bytes(command)?;
    let commitment = domain_separated_digest_v1(G2_TYPED_COMMAND_COMMITMENT_DOMAIN_V2, &bytes);
    G2CommandCommitmentV2::new(plane, index, command_kind, commitment).map_err(|cause| {
        error(
            GlobalExecutionErrorCodeV1::NonCanonicalBatch,
            format!("manifest-bound typed command commitment failed: {cause}"),
        )
    })
}

fn plane_error_v2(
    code: GlobalExecutionErrorCodeV1,
    cause: impl std::fmt::Display,
) -> crate::GlobalExecutionErrorV1 {
    error(code, cause.to_string())
}

#[cfg(test)]
mod tests {
    use trnm_poco_order_types_v1::{derive_g2_ordered_list_roots_v2, Cev1EncodeV1};

    use super::*;
    use crate::tests::Rig;

    fn projection(rig: &Rig, manifest: u8, source: u8) -> ManifestBoundGlobalExecutionInputV2 {
        ManifestBoundGlobalExecutionInputV2::new(
            rig.context.clone(),
            Hash32V1([0x31; 32]),
            Hash32V1([manifest; 32]),
            Hash32V1([0x33; 32]),
            Hash32V1([0x34; 32]),
            10,
            BlockIdV1::new([0x35; 32]),
            Hash32V1([0x36; 32]),
            11,
            rig.batch_id,
            rig.certificate_id,
            Hash32V1([source; 32]),
            rig.batch.agent_market_commands.clone(),
            rig.batch.verify_challenge_commands.clone(),
            rig.batch.mvcc_fee_block.clone(),
            rig.batch.consumption_settlement_commands.clone(),
        )
        .expect("valid candidate-ID-free global projection")
    }

    #[test]
    fn exact_global_commands_project_without_containing_block_id_or_roots() {
        let rig = Rig::new();
        let (input, plan) = projection(&rig, 0x32, 0x37)
            .project_inert_order_plan_v2()
            .expect("project shared input and narrow inert plan");
        assert_eq!(input.candidate_height(), 11);
        assert_eq!(input.commands().len(), 1);
        assert_ne!(input.input_id().to_bytes(), [0; 32]);
        assert!(!input.to_cev1_bytes().is_empty());
        assert!(plan.state_creates().is_empty());
        assert_eq!(plan.ordered_items().len(), 2);
        let roots = derive_g2_ordered_list_roots_v2(&plan).expect("derive mandatory roots");
        assert_ne!(roots[0], [0; 32]);
        assert_ne!(roots[1], [0; 32]);
    }

    #[test]
    fn manifest_and_source_mutations_readdress_the_global_projection() {
        let rig = Rig::new();
        let canonical = projection(&rig, 0x32, 0x37)
            .project_order_input_v2()
            .expect("canonical projection");
        let manifest_mutant = projection(&rig, 0x52, 0x37)
            .project_order_input_v2()
            .expect("manifest mutant remains inert data");
        let source_mutant = projection(&rig, 0x32, 0x57)
            .project_order_input_v2()
            .expect("source mutant remains inert data");
        assert_ne!(canonical.input_id(), manifest_mutant.input_id());
        assert_ne!(canonical.input_id(), source_mutant.input_id());
    }
}
