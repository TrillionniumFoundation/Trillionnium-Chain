//! Candidate-only Order application seam for manifest-bound G2 execution.

use std::collections::BTreeMap;

use trnm_poco_order_types_v1::{
    derive_block_id_v1, derive_g2_ordered_list_roots_v2, domain_separated_digest_v1, BlockHeaderV1,
    BlockIdV1, G2ExecutionPlanDigestV2, G2InertExecutionPlanV2, G2ManifestBoundInputIdV2,
    G2ManifestBoundInputV2,
};

use super::{
    application_state_key_v1, parent_view, reject, sparse_state_root, validate_template,
    OrderApplicationErrorCodeV1, OrderApplicationParentV1, OrderApplicationResultV1,
    OrderHeaderTemplateV1, ParentViewV1, StateLeafV1,
};

const G2_FINALIZE_BINDING_REQUEST_DOMAIN_V2: &str = "trnm.poco-ai.g2-finalize-binding-request.v2";

/// Exact eight-root Order application result.  The input and plan contain no
/// containing block ID; this carrier exists only after roots and header were
/// derived together.  It is intentionally non-Clone and still is not a write
/// or consensus capability.
#[must_use = "retain the exact sealed G2 block until a later owner performs a fresh CAS join"]
#[derive(Debug)]
pub struct SealedManifestBoundG2OrderBlockV2 {
    parent: ParentViewV1,
    template: OrderHeaderTemplateV1,
    input: G2ManifestBoundInputV2,
    plan: G2InertExecutionPlanV2,
    header: BlockHeaderV1,
    block_id: BlockIdV1,
}

impl SealedManifestBoundG2OrderBlockV2 {
    pub const fn header(&self) -> &BlockHeaderV1 {
        &self.header
    }

    pub const fn block_id(&self) -> BlockIdV1 {
        self.block_id
    }

    pub const fn input_id(&self) -> G2ManifestBoundInputIdV2 {
        self.input.input_id()
    }

    pub const fn plan_digest(&self) -> G2ExecutionPlanDigestV2 {
        self.plan.plan_digest()
    }

    /// Consume the exact seal into a non-Clone request for a future global
    /// execution CAS.  This method performs only deterministic revalidation;
    /// the future store must independently re-preview and fresh-read every
    /// source before treating the request as eligible input.
    pub fn into_finalize_binding_request_v2(
        self,
    ) -> OrderApplicationResultV1<G2FinalizeBindingRequestV2> {
        revalidate_sealed_manifest_bound_g2_order_block_v2(&self)?;
        let ordered_roots = self.header.ordered_roots();
        let binding_digest = finalize_binding_digest(
            self.input.input_id(),
            self.header.height,
            self.block_id,
            ordered_roots,
            self.plan.plan_digest(),
        );
        Ok(G2FinalizeBindingRequestV2 {
            input_id: self.input.input_id(),
            candidate_height: self.header.height,
            candidate_block_id: self.block_id,
            ordered_roots,
            plan_digest: self.plan.plan_digest(),
            binding_digest,
        })
    }
}

/// Inert exact join request.  Public getters expose data for a future store
/// comparison, but private construction and non-Clone semantics prevent it
/// from being confused with that store's eventual owner-affined authority.
#[must_use = "the future global store must re-preview and CAS this exact request"]
#[derive(Debug)]
pub struct G2FinalizeBindingRequestV2 {
    input_id: G2ManifestBoundInputIdV2,
    candidate_height: u64,
    candidate_block_id: BlockIdV1,
    ordered_roots: [[u8; 32]; 8],
    plan_digest: G2ExecutionPlanDigestV2,
    binding_digest: [u8; 32],
}

impl G2FinalizeBindingRequestV2 {
    pub const fn input_id(&self) -> G2ManifestBoundInputIdV2 {
        self.input_id
    }

    pub const fn candidate_height(&self) -> u64 {
        self.candidate_height
    }

    pub const fn candidate_block_id(&self) -> BlockIdV1 {
        self.candidate_block_id
    }

    pub const fn ordered_roots(&self) -> [[u8; 32]; 8] {
        self.ordered_roots
    }

    pub const fn plan_digest(&self) -> G2ExecutionPlanDigestV2 {
        self.plan_digest
    }

    pub const fn binding_digest(&self) -> [u8; 32] {
        self.binding_digest
    }
}

/// Derive the exact sparse-state root and seven typed Merkle-list roots, then
/// seal the containing Order header.  No root and no containing block ID is a
/// caller input.
pub fn seal_manifest_bound_g2_order_block_v2(
    parent: OrderApplicationParentV1<'_>,
    template: OrderHeaderTemplateV1,
    input: G2ManifestBoundInputV2,
    plan: G2InertExecutionPlanV2,
) -> OrderApplicationResultV1<SealedManifestBoundG2OrderBlockV2> {
    let parent = parent_view(parent)?;
    validate_template(&template, &parent)?;
    input.revalidate().map_err(|_| manifest_rejected())?;
    plan.revalidate_for_input(&input)
        .map_err(|_| plan_rejected())?;
    validate_input_join(&input, &template, &parent)?;

    let target_leaves = apply_state_creates(&parent.leaves, &plan)?;
    let post_state_root = sparse_state_root(&target_leaves);
    let list_roots = derive_g2_ordered_list_roots_v2(&plan).map_err(|_| plan_rejected())?;
    let header = seal_header_with_exact_roots(template.clone(), post_state_root, list_roots);
    let block_id = derive_block_id_v1(&header);
    let sealed = SealedManifestBoundG2OrderBlockV2 {
        parent,
        template,
        input,
        plan,
        header,
        block_id,
    };
    revalidate_sealed_manifest_bound_g2_order_block_v2(&sealed)?;
    Ok(sealed)
}

/// Recompute the complete candidate-ID-free plan join, state root, seven list
/// roots, containing header, and final BlockId.
pub fn revalidate_sealed_manifest_bound_g2_order_block_v2(
    sealed: &SealedManifestBoundG2OrderBlockV2,
) -> OrderApplicationResultV1<()> {
    validate_template(&sealed.template, &sealed.parent)?;
    sealed.input.revalidate().map_err(|_| manifest_rejected())?;
    sealed
        .plan
        .revalidate_for_input(&sealed.input)
        .map_err(|_| plan_rejected())?;
    validate_input_join(&sealed.input, &sealed.template, &sealed.parent)?;
    let target_leaves = apply_state_creates(&sealed.parent.leaves, &sealed.plan)?;
    let post_state_root = sparse_state_root(&target_leaves);
    let list_roots = derive_g2_ordered_list_roots_v2(&sealed.plan).map_err(|_| plan_rejected())?;
    let expected_header =
        seal_header_with_exact_roots(sealed.template.clone(), post_state_root, list_roots);
    let expected_block_id = derive_block_id_v1(&expected_header);
    if sealed.header != expected_header || sealed.block_id != expected_block_id {
        return reject(
            OrderApplicationErrorCodeV1::RootMismatch,
            "sealed G2 header roots or containing BlockId differ from exact derivation",
        );
    }
    Ok(())
}

fn validate_input_join(
    input: &G2ManifestBoundInputV2,
    template: &OrderHeaderTemplateV1,
    parent: &ParentViewV1,
) -> OrderApplicationResultV1<()> {
    if input.context() != &template.context
        || input.parent_height() != parent.height
        || input.parent_block_id() != parent.block_id
        || input.parent_state_root() != parent.state_root
        || input.candidate_height() != template.height
    {
        return reject(
            OrderApplicationErrorCodeV1::InvalidBinding,
            "G2 manifest input differs from the exact Order parent or header template",
        );
    }
    Ok(())
}

fn apply_state_creates(
    parent: &BTreeMap<[u8; 32], StateLeafV1>,
    plan: &G2InertExecutionPlanV2,
) -> OrderApplicationResultV1<BTreeMap<[u8; 32], StateLeafV1>> {
    let mut target = parent.clone();
    for create in plan.state_creates() {
        if create.state_key() != application_state_key_v1(create.object_kind(), create.object_id())
        {
            return reject(
                OrderApplicationErrorCodeV1::PlanMismatch,
                "G2 state-create key differs from its typed object identity",
            );
        }
        if target
            .insert(
                create.state_key(),
                StateLeafV1 {
                    object_kind: create.object_kind(),
                    object_version: create.object_version(),
                    value_bytes: create.value_bytes().to_vec(),
                },
            )
            .is_some()
        {
            return reject(
                OrderApplicationErrorCodeV1::DuplicateObject,
                "G2 state create collides with its exact parent or another create",
            );
        }
    }
    Ok(target)
}

fn seal_header_with_exact_roots(
    template: OrderHeaderTemplateV1,
    post_state_root: [u8; 32],
    list_roots: [[u8; 32]; 7],
) -> BlockHeaderV1 {
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
        batch_refs_root: list_roots[0],
        protocol_objects_root: list_roots[1],
        post_state_root,
        transaction_execution_receipts_root: list_roots[2],
        evidence_root: list_roots[3],
        consumption_rollups_root: list_roots[4],
        settlement_root: list_roots[5],
        resource_usage_root: list_roots[6],
        next_epoch_descriptor_id: template.next_epoch_descriptor_id,
        upgrade_plan_id: template.upgrade_plan_id,
        epoch_handoff_id: template.epoch_handoff_id,
    }
}

fn finalize_binding_digest(
    input_id: G2ManifestBoundInputIdV2,
    candidate_height: u64,
    candidate_block_id: BlockIdV1,
    ordered_roots: [[u8; 32]; 8],
    plan_digest: G2ExecutionPlanDigestV2,
) -> [u8; 32] {
    let mut body = Vec::with_capacity(32 * 11 + 8);
    body.extend_from_slice(input_id.as_bytes());
    body.extend_from_slice(&candidate_height.to_le_bytes());
    body.extend_from_slice(candidate_block_id.as_bytes());
    for root in ordered_roots {
        body.extend_from_slice(&root);
    }
    body.extend_from_slice(plan_digest.as_bytes());
    domain_separated_digest_v1(G2_FINALIZE_BINDING_REQUEST_DOMAIN_V2, &body)
}

const fn manifest_rejected() -> super::OrderApplicationErrorV1 {
    super::OrderApplicationErrorV1 {
        code: OrderApplicationErrorCodeV1::InvalidBinding,
        detail: "G2 manifest-bound input failed exact revalidation",
    }
}

const fn plan_rejected() -> super::OrderApplicationErrorV1 {
    super::OrderApplicationErrorV1 {
        code: OrderApplicationErrorCodeV1::PlanMismatch,
        detail: "G2 inert execution plan failed exact revalidation",
    }
}

#[cfg(test)]
mod tests {
    use trnm_poco_order_types_v1::{
        empty_ordered_root_v1, BlockKindV1, EpochDescriptorIdV1, G2CommandCommitmentV2,
        G2CommandPlaneV2, G2OrderedItemV2, G2OrderedRootKindV2, G2StateCreateV2, ParentBlockRefV1,
        ProtocolContextV1, QuorumCertificateIdV1,
    };

    use super::*;
    use crate::{empty_order_state_root_v1, EmptyOrderStateAnchorV1};

    fn context() -> ProtocolContextV1 {
        ProtocolContextV1 {
            schema_version: 1,
            genesis_hash: [0x11; 32],
            chain_id: "trnm-g2-t0-application".to_owned(),
            protocol_version: 1,
            stack_profile_hash: [0x12; 32],
        }
    }

    fn input(anchor: &EmptyOrderStateAnchorV1, manifest: u8) -> G2ManifestBoundInputV2 {
        G2ManifestBoundInputV2::new(
            context(),
            [0x21; 32],
            [manifest; 32],
            [0x23; 32],
            [0x24; 32],
            anchor.height(),
            anchor.block_id(),
            anchor.state_root(),
            anchor.height() + 1,
            [0x25; 32],
            [0x26; 32],
            [0x27; 32],
            vec![
                G2CommandCommitmentV2::new(G2CommandPlaneV2::MvccFee, 0, 3, [0x28; 32])
                    .expect("valid command commitment"),
            ],
        )
        .expect("valid manifest-bound input")
    }

    fn plan(input: &G2ManifestBoundInputV2) -> G2InertExecutionPlanV2 {
        G2InertExecutionPlanV2::new(
            input,
            vec![G2StateCreateV2::new(60, [0x31; 32], 0, vec![0x32; 16])
                .expect("valid state create")],
            vec![G2OrderedItemV2::new(
                G2OrderedRootKindV2::TransactionExecutionReceipts,
                0,
                61,
                [0x33; 32],
                [0x34; 32],
            )
            .expect("valid receipt item")],
        )
        .expect("valid inert execution plan")
    }

    fn template(anchor: &EmptyOrderStateAnchorV1) -> OrderHeaderTemplateV1 {
        OrderHeaderTemplateV1 {
            schema_version: 1,
            context: context(),
            epoch: 1,
            view: 11,
            height: anchor.height() + 1,
            block_kind: BlockKindV1::Ordinary,
            parent: ParentBlockRefV1::V1Block(anchor.block_id()),
            proposer_id: b"validator-a".to_vec(),
            epoch_descriptor_id: EpochDescriptorIdV1::new([0x41; 32]),
            justify_qc_id: Some(QuorumCertificateIdV1::new([0x42; 32])),
            timeout_certificate_id: None,
            next_epoch_descriptor_id: None,
            upgrade_plan_id: None,
            epoch_handoff_id: None,
        }
    }

    #[test]
    fn candidate_id_free_plan_derives_all_eight_roots_then_binding_request() {
        let anchor = EmptyOrderStateAnchorV1::new(10, BlockIdV1::new([0x10; 32]))
            .expect("empty parent anchor");
        assert_eq!(anchor.state_root(), empty_order_state_root_v1());
        let input = input(&anchor, 0x22);
        let plan = plan(&input);
        let sealed = seal_manifest_bound_g2_order_block_v2(
            OrderApplicationParentV1::EmptyAnchor(&anchor),
            template(&anchor),
            input,
            plan,
        )
        .expect("derive and seal exact G2 block");
        assert_ne!(sealed.header().batch_refs_root, empty_ordered_root_v1(0));
        assert_ne!(
            sealed.header().protocol_objects_root,
            empty_ordered_root_v1(1)
        );
        assert_ne!(
            sealed.header().transaction_execution_receipts_root,
            empty_ordered_root_v1(2)
        );
        assert_ne!(sealed.header().post_state_root, anchor.state_root());
        let request = sealed
            .into_finalize_binding_request_v2()
            .expect("exact seal becomes inert later-CAS request");
        assert_eq!(request.candidate_height(), 11);
        assert_ne!(request.candidate_block_id().to_bytes(), [0; 32]);
        assert_ne!(request.binding_digest(), [0; 32]);
    }

    #[test]
    fn manifest_mutation_root_substitution_and_seal_readdress_fail_closed() {
        let anchor = EmptyOrderStateAnchorV1::new(10, BlockIdV1::new([0x10; 32]))
            .expect("empty parent anchor");
        let canonical_input = input(&anchor, 0x22);
        let foreign_input = input(&anchor, 0x52);
        assert!(seal_manifest_bound_g2_order_block_v2(
            OrderApplicationParentV1::EmptyAnchor(&anchor),
            template(&anchor),
            foreign_input,
            plan(&canonical_input),
        )
        .is_err());

        let plan = plan(&canonical_input);
        let mut sealed = seal_manifest_bound_g2_order_block_v2(
            OrderApplicationParentV1::EmptyAnchor(&anchor),
            template(&anchor),
            canonical_input,
            plan,
        )
        .expect("canonical seal");
        sealed.header.transaction_execution_receipts_root[0] ^= 1;
        assert!(revalidate_sealed_manifest_bound_g2_order_block_v2(&sealed).is_err());
        sealed.block_id = derive_block_id_v1(&sealed.header);
        assert!(revalidate_sealed_manifest_bound_g2_order_block_v2(&sealed).is_err());
    }
}
