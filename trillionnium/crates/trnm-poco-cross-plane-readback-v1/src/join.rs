use std::collections::BTreeSet;

use trnm_poco_agent_market_v1::{
    AgentMarketFreshReadbackV1, Hash32V1 as AgentHash32V1, PocoAgentMarketStoreV1,
    ProtocolContextV1 as AgentProtocolContextV1,
};
use trnm_poco_consumption_settlement_v1::{
    ConsumptionSettlementFreshReadbackV1, ConsumptionSettlementStoreV1,
};
use trnm_poco_da_v1::{
    BatchIdV1, CertifiedBatchFactsV1, DaFreshReadbackV1, PocoDaStoreV1,
    ProtocolContextV1 as DaProtocolContextV1,
};
use trnm_poco_mvcc_fee_v1::{
    MvccFeeFreshReadbackV1, MvccFeeStoreV1, ProtocolContextV1 as MvccProtocolContextV1,
};
use trnm_poco_verify_challenge_v1::{VerifyChallengeFreshReadbackV1, VerifyChallengeStoreV1};

use crate::{
    codec::digest_value,
    error::{error, CrossPlaneReadbackErrorCodeV1, CrossPlaneReadbackResultV1},
    types::{
        ConfirmedCrossPlaneReadbackV1, CrossPlaneJoinRequestV1, CrossPlaneReadbackProjectionV1,
        CrossPlaneStoreHeadV1, Hash32V1,
    },
};

const EXPECTED_PROTOCOL_ID_V1: &[u8] = b"trnm-poco-ai-native-v1";

pub struct CrossPlaneStoresV1<'a> {
    pub da: &'a PocoDaStoreV1,
    pub agent_market: &'a PocoAgentMarketStoreV1,
    pub verify_challenge: &'a VerifyChallengeStoreV1,
    pub mvcc_fee: &'a MvccFeeStoreV1,
    pub consumption_settlement: &'a ConsumptionSettlementStoreV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SampleV1 {
    da: DaHeadV1,
    agent: OrderedHeadV1,
    verify: OrderedHeadV1,
    mvcc: OrderedHeadV1,
    settlement: OrderedHeadV1,
    certificate: CertifiedBatchProjectionV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DaHeadV1 {
    context: ContextProjectionV1,
    scope_id: Hash32V1,
    store: CrossPlaneStoreHeadV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OrderedHeadV1 {
    context: ContextProjectionV1,
    store: CrossPlaneStoreHeadV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ContextProjectionV1 {
    chain_id: String,
    genesis_hash: Hash32V1,
    protocol_version: u32,
    stack_profile_hash: Hash32V1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CertifiedBatchProjectionV1 {
    batch_id: Hash32V1,
    certificate_id: Hash32V1,
    obligation_id: Hash32V1,
    obligation_version: u64,
    obligation_status: u8,
}

/// Join five already-durable local candidate stores without mutating any of
/// them.  Every source is sampled twice through its own fresh-reopen API; any
/// intervening change is rejected rather than papered over as atomicity.
pub fn fresh_join_cross_plane_v1(
    stores: CrossPlaneStoresV1<'_>,
    request: &CrossPlaneJoinRequestV1,
) -> CrossPlaneReadbackResultV1<ConfirmedCrossPlaneReadbackV1> {
    let source = StoreSourceV1 { stores };
    join_from_source(&source, request)
}

trait CrossPlaneSourceV1 {
    fn sample(&self, batch_id: BatchIdV1) -> CrossPlaneReadbackResultV1<SampleV1>;
    fn validate_lifecycle(
        &self,
        request: &CrossPlaneJoinRequestV1,
    ) -> CrossPlaneReadbackResultV1<()>;
}

struct StoreSourceV1<'a> {
    stores: CrossPlaneStoresV1<'a>,
}

impl CrossPlaneSourceV1 for StoreSourceV1<'_> {
    fn sample(&self, batch_id: BatchIdV1) -> CrossPlaneReadbackResultV1<SampleV1> {
        sample_stores(&self.stores, batch_id)
    }

    fn validate_lifecycle(
        &self,
        request: &CrossPlaneJoinRequestV1,
    ) -> CrossPlaneReadbackResultV1<()> {
        validate_store_lifecycle(request, &self.stores)
    }
}

fn join_from_source(
    source: &impl CrossPlaneSourceV1,
    request: &CrossPlaneJoinRequestV1,
) -> CrossPlaneReadbackResultV1<ConfirmedCrossPlaneReadbackV1> {
    validate_request(request)?;
    let first = source.sample(request.da_batch_id)?;
    validate_sample(request, &first)?;
    source.validate_lifecycle(request)?;
    let second = source.sample(request.da_batch_id)?;
    if first != second {
        return Err(error(
            CrossPlaneReadbackErrorCodeV1::SourceChanged,
            "at least one local store changed between fresh readback samples",
        ));
    }
    let mut projection = project(request, first)?;
    projection.projection_digest = digest_value(
        "trnm.poco-ai.cross-plane-readback-projection.candidate.v1",
        &projection,
    )?;
    Ok(ConfirmedCrossPlaneReadbackV1 { projection })
}

fn sample_stores(
    stores: &CrossPlaneStoresV1<'_>,
    batch_id: BatchIdV1,
) -> CrossPlaneReadbackResultV1<SampleV1> {
    let da = stores
        .da
        .fresh_certified_batch_readback(batch_id)
        .map_err(|cause| source_error("DA", cause))?;
    let agent = stores
        .agent_market
        .fresh_readback()
        .map_err(|cause| source_error("Agent/Market", cause))?;
    let verify = stores
        .verify_challenge
        .fresh_readback()
        .map_err(|cause| source_error("Verify/Challenge", cause))?;
    let mvcc = stores
        .mvcc_fee
        .fresh_readback()
        .map_err(|cause| source_error("MVCC/Fee", cause))?;
    let settlement = stores
        .consumption_settlement
        .fresh_readback()
        .map_err(|cause| source_error("Consumption/Settlement", cause))?;
    Ok(SampleV1 {
        da: project_da_head(da.head()),
        agent: project_agent_head(&agent),
        verify: project_verify_head(&verify),
        mvcc: project_mvcc_head(&mvcc)?,
        settlement: project_settlement_head(&settlement),
        certificate: project_certificate(da.batch()),
    })
}

fn validate_request(request: &CrossPlaneJoinRequestV1) -> CrossPlaneReadbackResultV1<()> {
    if request.schema_version != 1
        || request.protocol_version != 1
        || request.chain_id.is_empty()
        || request.chain_id.len() > 128
        || !request.chain_id.is_ascii()
        || request.genesis_hash == Hash32V1([0; 32])
        || request.stack_profile_hash == Hash32V1([0; 32])
        || request.order_height == 0
        || request.order_block_id == Hash32V1([0; 32])
        || request.order_proof_digest == Hash32V1([0; 32])
    {
        return Err(error(
            CrossPlaneReadbackErrorCodeV1::InvalidContext,
            "join request has invalid schema/context/order trust input",
        ));
    }
    if request.verify_result_id.0 != request.settlement_result_id.0
        || request.settlement_receipt.operation_kind != 26
        || request.settlement_receipt.settlement_id != Some(request.settlement_id)
    {
        return Err(error(
            CrossPlaneReadbackErrorCodeV1::LifecycleMismatch,
            "result or terminal settlement identity differs",
        ));
    }
    Ok(())
}

fn validate_sample(
    request: &CrossPlaneJoinRequestV1,
    sample: &SampleV1,
) -> CrossPlaneReadbackResultV1<()> {
    let expected_context = ContextProjectionV1 {
        chain_id: request.chain_id.clone(),
        genesis_hash: request.genesis_hash,
        protocol_version: request.protocol_version,
        stack_profile_hash: request.stack_profile_hash,
    };
    if [
        &sample.da.context,
        &sample.agent.context,
        &sample.verify.context,
        &sample.mvcc.context,
        &sample.settlement.context,
    ]
    .into_iter()
    .any(|context| context != &expected_context)
    {
        return Err(error(
            CrossPlaneReadbackErrorCodeV1::InvalidContext,
            "one or more stores differ from the exact protocol context",
        ));
    }
    let expected_order = (request.order_height, request.order_block_id);
    if [
        &sample.agent.store,
        &sample.verify.store,
        &sample.mvcc.store,
        &sample.settlement.store,
    ]
    .into_iter()
    .any(|head| (head.order_height, head.order_block_id) != expected_order)
    {
        return Err(error(
            CrossPlaneReadbackErrorCodeV1::OrderMismatch,
            "one or more ordered stores differ from the exact Order head",
        ));
    }
    let store_ids = [
        sample.da.store.store_id,
        sample.agent.store.store_id,
        sample.verify.store.store_id,
        sample.mvcc.store.store_id,
        sample.settlement.store.store_id,
    ];
    if store_ids.into_iter().collect::<BTreeSet<_>>().len() != store_ids.len() {
        return Err(error(
            CrossPlaneReadbackErrorCodeV1::StoreIdentityConflict,
            "cross-plane stores must have distinct typed identities",
        ));
    }
    if Hash32V1(request.agent_receipt.store_id.0) != sample.agent.store.store_id
        || request.agent_receipt.sequence != sample.agent.store.sequence_or_height
        || request.agent_receipt.order_height != sample.agent.store.order_height
        || Hash32V1(request.agent_receipt.order_block_id.0) != sample.agent.store.order_block_id
        || Hash32V1(request.agent_receipt.post_state_root.0)
            != sample.agent.store.durable_state_or_metadata_root
        || Hash32V1(request.verify_receipt.store_id.0) != sample.verify.store.store_id
        || request.verify_receipt.sequence != sample.verify.store.sequence_or_height
        || request.verify_receipt.order_height != sample.verify.store.order_height
        || Hash32V1(request.verify_receipt.order_block_id.0) != sample.verify.store.order_block_id
        || Hash32V1(request.verify_receipt.post_state_root.0)
            != sample.verify.store.durable_state_or_metadata_root
        || Hash32V1(request.mvcc_receipt.store_id.0) != sample.mvcc.store.store_id
        || request.mvcc_receipt.height != sample.mvcc.store.sequence_or_height
        || request.mvcc_receipt.height != sample.mvcc.store.order_height
        || Hash32V1(request.mvcc_receipt.block_id.0) != sample.mvcc.store.order_block_id
        || Hash32V1(request.mvcc_receipt.final_state_root.0)
            != sample.mvcc.store.durable_state_or_metadata_root
        || Hash32V1(request.settlement_receipt.store_id.0) != sample.settlement.store.store_id
        || request.settlement_receipt.sequence != sample.settlement.store.sequence_or_height
        || request.settlement_receipt.order_height != sample.settlement.store.order_height
        || Hash32V1(request.settlement_receipt.order_block_id.0)
            != sample.settlement.store.order_block_id
        || Hash32V1(request.settlement_receipt.post_state_root.0)
            != sample.settlement.store.durable_state_or_metadata_root
    {
        return Err(error(
            CrossPlaneReadbackErrorCodeV1::LifecycleMismatch,
            "one or more lifecycle receipts differ from the sampled store identity, position, Order head, or state root",
        ));
    }
    if sample.certificate.batch_id != hash_da(request.da_batch_id.as_bytes())
        || sample.certificate.obligation_status != 0
    {
        return Err(error(
            CrossPlaneReadbackErrorCodeV1::DaCertificateMismatch,
            "DA certificate/obligation does not match an active requested batch",
        ));
    }
    Ok(())
}

fn validate_store_lifecycle(
    request: &CrossPlaneJoinRequestV1,
    stores: &CrossPlaneStoresV1<'_>,
) -> CrossPlaneReadbackResultV1<()> {
    stores
        .agent_market
        .confirm_receipt(&request.agent_receipt)
        .map_err(|cause| source_error("Agent receipt", cause))?;
    stores
        .verify_challenge
        .fresh_confirm_receipt(&request.verify_receipt)
        .map_err(|cause| source_error("Verify receipt", cause))?;
    stores
        .mvcc_fee
        .fresh_confirm(&request.mvcc_receipt)
        .map_err(|cause| source_error("MVCC receipt", cause))?;
    stores
        .consumption_settlement
        .confirm_receipt(&request.settlement_receipt)
        .map_err(|cause| source_error("Settlement receipt", cause))?;
    for (height, block_id) in [
        (
            request.agent_receipt.order_height,
            request.agent_receipt.order_block_id.0,
        ),
        (
            request.verify_receipt.order_height,
            request.verify_receipt.order_block_id.0,
        ),
        (request.mvcc_receipt.height, request.mvcc_receipt.block_id.0),
        (
            request.settlement_receipt.order_height,
            request.settlement_receipt.order_block_id.0,
        ),
    ] {
        if height != request.order_height || block_id != request.order_block_id.0 {
            return Err(error(
                CrossPlaneReadbackErrorCodeV1::OrderMismatch,
                "a confirmed lifecycle receipt differs from the exact Order head",
            ));
        }
    }
    let task = stores
        .agent_market
        .task_state(request.task_id)
        .map_err(|cause| source_error("Task", cause))?;
    let lease = stores
        .agent_market
        .lease_state(request.lease_id)
        .map_err(|cause| source_error("Lease", cause))?;
    let escrow = stores
        .agent_market
        .escrow_state(request.escrow_id)
        .map_err(|cause| source_error("Escrow", cause))?;
    let verify = stores
        .verify_challenge
        .state()
        .map_err(|cause| source_error("Verify state", cause))?;
    let settlement = stores
        .consumption_settlement
        .state()
        .map_err(|cause| source_error("Settlement state", cause))?;
    let verify_result = verify.result.ok_or_else(|| {
        error(
            CrossPlaneReadbackErrorCodeV1::LifecycleMismatch,
            "verify result is absent",
        )
    })?;
    let settlement_state = settlement.settlement.ok_or_else(|| {
        error(
            CrossPlaneReadbackErrorCodeV1::LifecycleMismatch,
            "settlement is absent",
        )
    })?;
    if task.task_id != request.task_id
        || task.active_lease_id != Some(request.lease_id)
        || task.escrow_id != request.escrow_id
        || lease.lease_id != request.lease_id
        || escrow.escrow_id != request.escrow_id
        || verify_result.result_id != request.verify_result_id
        || verify_result.status != 2
        || settlement_state.receipt.task_id != request.task_id
        || settlement_state.receipt.lease_id != request.lease_id
        || settlement_state.receipt.escrow_id != request.escrow_id
        || settlement_state.receipt.result_id != request.settlement_result_id
        || settlement_state.receipt.settlement_id != request.settlement_id
        || settlement_state.settlement_id != request.settlement_id
        || settlement.result.result_status != 3
        || settlement.result.settlement_maturity != 2
        || settlement.result.settlement_id != Some(request.settlement_id)
    {
        return Err(error(
            CrossPlaneReadbackErrorCodeV1::LifecycleMismatch,
            "task/lease/escrow/result/settlement typed lifecycle facts differ",
        ));
    }
    Ok(())
}

fn project(
    request: &CrossPlaneJoinRequestV1,
    sample: SampleV1,
) -> CrossPlaneReadbackResultV1<CrossPlaneReadbackProjectionV1> {
    let settlement_id = request.settlement_receipt.settlement_id.ok_or_else(|| {
        error(
            CrossPlaneReadbackErrorCodeV1::LifecycleMismatch,
            "terminal settlement ID absent",
        )
    })?;
    Ok(CrossPlaneReadbackProjectionV1 {
        schema_version: 1,
        chain_id: request.chain_id.clone(),
        genesis_hash: request.genesis_hash,
        protocol_version: request.protocol_version,
        stack_profile_hash: request.stack_profile_hash,
        order_height: request.order_height,
        order_block_id: request.order_block_id,
        order_proof_digest: request.order_proof_digest,
        store_heads: vec![
            sample.da.store,
            sample.agent.store,
            sample.verify.store,
            sample.mvcc.store,
            sample.settlement.store,
        ],
        da_scope_id: sample.da.scope_id,
        da_batch_id: sample.certificate.batch_id,
        da_certificate_id: sample.certificate.certificate_id,
        da_obligation_id: sample.certificate.obligation_id,
        da_obligation_version: sample.certificate.obligation_version,
        task_id: Hash32V1(request.task_id.0),
        lease_id: Hash32V1(request.lease_id.0),
        escrow_id: Hash32V1(request.escrow_id.0),
        result_id: Hash32V1(request.verify_result_id.0),
        agent_operation_id: Hash32V1(request.agent_receipt.operation_id.0),
        verify_operation_id: Hash32V1(request.verify_receipt.operation_id.0),
        settlement_operation_id: Hash32V1(request.settlement_receipt.operation_id.0),
        settlement_id: Hash32V1(settlement_id.0),
        mvcc_receipts_root: Hash32V1(request.mvcc_receipt.receipts_root.0),
        mvcc_resource_totals_root: Hash32V1(request.mvcc_receipt.resource_totals_root.0),
        mvcc_fee_deltas_root: Hash32V1(request.mvcc_receipt.fee_deltas_root.0),
        mvcc_resolution_root: Hash32V1(request.mvcc_receipt.mvcc_resolution_root.0),
        projection_digest: Hash32V1([0; 32]),
    })
}

fn project_da_head(value: &DaFreshReadbackV1) -> DaHeadV1 {
    DaHeadV1 {
        context: project_da_context(value.context()),
        scope_id: hash_da(value.scope_id().as_bytes()),
        store: CrossPlaneStoreHeadV1 {
            plane_tag: 1,
            store_schema_version: value.store_schema_version(),
            store_id: hash_da(value.store_id().as_bytes()),
            sequence_or_height: value.sequence(),
            order_height: 0,
            order_block_id: Hash32V1([0; 32]),
            durable_state_or_metadata_root: hash_da(value.durable_metadata_root().as_bytes()),
            durable_journal_tail_root: hash_da(value.attestation_journal_tail_root().as_bytes()),
        },
    }
}

fn project_agent_head(value: &AgentMarketFreshReadbackV1) -> OrderedHeadV1 {
    project_agent_ordered_head(
        2,
        value.store_schema_version(),
        value.context(),
        value.store_id(),
        value.sequence(),
        value.order_height(),
        value.order_block_id(),
        value.durable_state_root(),
        value.durable_journal_root(),
    )
}

fn project_verify_head(value: &VerifyChallengeFreshReadbackV1) -> OrderedHeadV1 {
    project_agent_ordered_head(
        3,
        value.store_schema_version(),
        value.context(),
        value.store_id(),
        value.sequence(),
        value.order_height(),
        value.order_block_id(),
        value.durable_state_root(),
        value.durable_journal_root(),
    )
}

fn project_settlement_head(value: &ConsumptionSettlementFreshReadbackV1) -> OrderedHeadV1 {
    project_agent_ordered_head(
        5,
        value.store_schema_version(),
        value.context(),
        value.store_id(),
        value.sequence(),
        value.order_height(),
        value.order_block_id(),
        value.durable_state_root(),
        value.durable_journal_root(),
    )
}

#[allow(clippy::too_many_arguments)]
fn project_agent_ordered_head(
    plane_tag: u8,
    store_schema_version: u16,
    context: &AgentProtocolContextV1,
    store_id: AgentHash32V1,
    sequence: u64,
    order_height: u64,
    order_block_id: AgentHash32V1,
    state_root: AgentHash32V1,
    journal_root: AgentHash32V1,
) -> OrderedHeadV1 {
    OrderedHeadV1 {
        context: project_agent_context(context),
        store: CrossPlaneStoreHeadV1 {
            plane_tag,
            store_schema_version,
            store_id: hash_agent(store_id),
            sequence_or_height: sequence,
            order_height,
            order_block_id: hash_agent(order_block_id),
            durable_state_or_metadata_root: hash_agent(state_root),
            durable_journal_tail_root: hash_agent(journal_root),
        },
    }
}

fn project_mvcc_head(value: &MvccFeeFreshReadbackV1) -> CrossPlaneReadbackResultV1<OrderedHeadV1> {
    Ok(OrderedHeadV1 {
        context: project_mvcc_context(value.context())?,
        store: CrossPlaneStoreHeadV1 {
            plane_tag: 4,
            store_schema_version: value.store_schema_version(),
            store_id: Hash32V1(value.store_id().0),
            sequence_or_height: value.height(),
            order_height: value.height(),
            order_block_id: Hash32V1(value.block_id().0),
            durable_state_or_metadata_root: Hash32V1(value.durable_state_root().0),
            durable_journal_tail_root: Hash32V1(value.durable_journal_root().0),
        },
    })
}

fn project_certificate(value: CertifiedBatchFactsV1) -> CertifiedBatchProjectionV1 {
    CertifiedBatchProjectionV1 {
        batch_id: hash_da(value.batch_id().as_bytes()),
        certificate_id: hash_da(value.certificate_id().as_bytes()),
        obligation_id: hash_da(value.obligation_id().as_bytes()),
        obligation_version: value.obligation_version(),
        obligation_status: value.obligation_status(),
    }
}

fn project_agent_context(value: &AgentProtocolContextV1) -> ContextProjectionV1 {
    ContextProjectionV1 {
        chain_id: value.chain_id.clone(),
        genesis_hash: hash_agent(value.genesis_hash),
        protocol_version: value.protocol_version,
        stack_profile_hash: hash_agent(value.stack_profile_hash),
    }
}

fn project_da_context(value: &DaProtocolContextV1) -> ContextProjectionV1 {
    ContextProjectionV1 {
        chain_id: value.chain_id().to_owned(),
        genesis_hash: hash_da(value.genesis_hash().as_bytes()),
        protocol_version: value.protocol_version(),
        stack_profile_hash: hash_da(value.stack_profile_hash().as_bytes()),
    }
}

fn project_mvcc_context(
    value: &MvccProtocolContextV1,
) -> CrossPlaneReadbackResultV1<ContextProjectionV1> {
    if value.protocol_id != EXPECTED_PROTOCOL_ID_V1 {
        return Err(error(
            CrossPlaneReadbackErrorCodeV1::InvalidContext,
            "MVCC protocol ID differs from PoCO AI-native v1",
        ));
    }
    let chain_id = String::from_utf8(value.chain_id.clone()).map_err(|_| {
        error(
            CrossPlaneReadbackErrorCodeV1::InvalidContext,
            "MVCC chain ID is not UTF-8",
        )
    })?;
    Ok(ContextProjectionV1 {
        chain_id,
        genesis_hash: Hash32V1(value.genesis_hash.0),
        protocol_version: value.protocol_version,
        stack_profile_hash: Hash32V1(value.profile_hash.0),
    })
}

fn hash_agent(value: AgentHash32V1) -> Hash32V1 {
    Hash32V1(value.0)
}
fn hash_da(value: &[u8; 32]) -> Hash32V1 {
    Hash32V1(*value)
}

fn source_error(label: &str, cause: impl std::fmt::Display) -> crate::CrossPlaneReadbackErrorV1 {
    error(
        CrossPlaneReadbackErrorCodeV1::SourceRejected,
        format!("{label}: {cause}"),
    )
}

const _: () = assert!(EXPECTED_PROTOCOL_ID_V1.len() == 22);

#[cfg(test)]
mod join_tests {
    use std::{cell::RefCell, collections::VecDeque};

    use borsh::BorshDeserialize;
    use trnm_poco_agent_market_v1::{
        EscrowIdV1, Hash32V1 as AgentHash, KernelOperationIdV1, KernelTransitionReceiptV1,
        LeaseIdV1, SettlementIdV1, TaskIdV1,
    };
    use trnm_poco_consumption_settlement_v1::{
        ConsumptionOperationIdV1, ConsumptionTransitionReceiptV1, ResultIdV1 as SettlementResultId,
    };
    use trnm_poco_mvcc_fee_v1::{Hash32V1 as MvccHash, MvccBlockReceiptV1};
    use trnm_poco_verify_challenge_v1::{
        ResultIdV1 as VerifyResultId, VerifyOperationIdV1, VerifyTransitionReceiptV1,
    };

    use super::*;

    struct MockSourceV1 {
        samples: RefCell<VecDeque<SampleV1>>,
        lifecycle_error: bool,
    }

    impl MockSourceV1 {
        fn stable(sample: SampleV1) -> Self {
            Self {
                samples: RefCell::new(VecDeque::from([sample.clone(), sample])),
                lifecycle_error: false,
            }
        }

        fn changing(first: SampleV1, second: SampleV1) -> Self {
            Self {
                samples: RefCell::new(VecDeque::from([first, second])),
                lifecycle_error: false,
            }
        }
    }

    impl CrossPlaneSourceV1 for MockSourceV1 {
        fn sample(&self, _: BatchIdV1) -> CrossPlaneReadbackResultV1<SampleV1> {
            self.samples.borrow_mut().pop_front().ok_or_else(|| {
                error(
                    CrossPlaneReadbackErrorCodeV1::SourceRejected,
                    "mock sample exhausted",
                )
            })
        }

        fn validate_lifecycle(
            &self,
            _: &CrossPlaneJoinRequestV1,
        ) -> CrossPlaneReadbackResultV1<()> {
            if self.lifecycle_error {
                Err(error(
                    CrossPlaneReadbackErrorCodeV1::LifecycleMismatch,
                    "mock lifecycle differs",
                ))
            } else {
                Ok(())
            }
        }
    }

    fn h(byte: u8) -> Hash32V1 {
        Hash32V1([byte; 32])
    }

    fn agent_h(byte: u8) -> AgentHash {
        AgentHash([byte; 32])
    }

    fn batch(byte: u8) -> BatchIdV1 {
        BatchIdV1::try_from_slice(&[byte; 32]).expect("batch ID")
    }

    fn context() -> ContextProjectionV1 {
        ContextProjectionV1 {
            chain_id: "trnm-test".to_owned(),
            genesis_hash: h(1),
            protocol_version: 1,
            stack_profile_hash: h(2),
        }
    }

    fn head(plane: u8) -> CrossPlaneStoreHeadV1 {
        CrossPlaneStoreHeadV1 {
            plane_tag: plane,
            store_schema_version: if matches!(plane, 1..=3) { 2 } else { 1 },
            store_id: h(20 + plane),
            sequence_or_height: if plane == 4 { 10 } else { 9 },
            order_height: if plane == 1 { 0 } else { 10 },
            order_block_id: if plane == 1 { h(0) } else { h(3) },
            durable_state_or_metadata_root: h(40 + plane),
            durable_journal_tail_root: h(50 + plane),
        }
    }

    fn sample() -> SampleV1 {
        let ordered = |plane| OrderedHeadV1 {
            context: context(),
            store: head(plane),
        };
        SampleV1 {
            da: DaHeadV1 {
                context: context(),
                scope_id: h(60),
                store: head(1),
            },
            agent: ordered(2),
            verify: ordered(3),
            mvcc: ordered(4),
            settlement: ordered(5),
            certificate: CertifiedBatchProjectionV1 {
                batch_id: h(61),
                certificate_id: h(62),
                obligation_id: h(63),
                obligation_version: 4,
                obligation_status: 0,
            },
        }
    }

    fn request() -> CrossPlaneJoinRequestV1 {
        let settlement_id = SettlementIdV1([9; 32]);
        CrossPlaneJoinRequestV1 {
            schema_version: 1,
            chain_id: "trnm-test".to_owned(),
            genesis_hash: h(1),
            protocol_version: 1,
            stack_profile_hash: h(2),
            order_height: 10,
            order_block_id: h(3),
            order_proof_digest: h(4),
            da_batch_id: batch(61),
            task_id: TaskIdV1([5; 32]),
            lease_id: LeaseIdV1([6; 32]),
            escrow_id: EscrowIdV1([7; 32]),
            verify_result_id: VerifyResultId([8; 32]),
            settlement_result_id: SettlementResultId([8; 32]),
            settlement_id,
            agent_receipt: KernelTransitionReceiptV1 {
                schema_version: 1,
                store_id: agent_h(22),
                sequence: 9,
                operation_id: KernelOperationIdV1([70; 32]),
                operation_kind: 9,
                operation_digest: agent_h(71),
                order_height: 10,
                order_block_id: agent_h(3),
                post_state_root: agent_h(42),
            },
            verify_receipt: VerifyTransitionReceiptV1 {
                schema_version: 1,
                store_id: agent_h(23),
                sequence: 9,
                operation_id: VerifyOperationIdV1([72; 32]),
                operation_kind: 22,
                order_height: 10,
                order_block_id: agent_h(3),
                post_state_root: agent_h(43),
            },
            mvcc_receipt: MvccBlockReceiptV1 {
                schema_version: 1,
                store_id: MvccHash([24; 32]),
                block_id: MvccHash([3; 32]),
                height: 10,
                parent_state_root: MvccHash([80; 32]),
                final_state_root: MvccHash([44; 32]),
                receipts_root: MvccHash([81; 32]),
                resource_totals_root: MvccHash([82; 32]),
                fee_deltas_root: MvccHash([83; 32]),
                mvcc_resolution_root: MvccHash([84; 32]),
                transaction_count: 1,
                receipts: vec![],
                resource_totals: vec![],
                aggregated_fee_deltas: vec![],
                destination_credits: vec![],
            },
            settlement_receipt: ConsumptionTransitionReceiptV1 {
                schema_version: 1,
                store_id: agent_h(25),
                sequence: 9,
                operation_id: ConsumptionOperationIdV1([73; 32]),
                operation_kind: 26,
                order_height: 10,
                order_block_id: agent_h(3),
                post_state_root: agent_h(45),
                settlement_id: Some(settlement_id),
            },
        }
    }

    #[test]
    fn stable_double_sample_produces_nonzero_deterministic_digest() {
        let request = request();
        let first = join_from_source(&MockSourceV1::stable(sample()), &request).expect("join");
        let second = join_from_source(&MockSourceV1::stable(sample()), &request).expect("join");
        assert_ne!(first.digest(), h(0));
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.projection().store_heads.len(), 5);
    }

    #[test]
    fn rejects_intervening_sequence_change() {
        let first = sample();
        let mut second = first.clone();
        second.verify.store.sequence_or_height += 1;
        let error = join_from_source(&MockSourceV1::changing(first, second), &request())
            .expect_err("change must reject");
        assert_eq!(error.code(), CrossPlaneReadbackErrorCodeV1::SourceChanged);
    }

    #[test]
    fn rejects_intervening_root_substitution() {
        let first = sample();
        let mut second = first.clone();
        second.settlement.store.durable_journal_tail_root = h(99);
        assert_eq!(
            join_from_source(&MockSourceV1::changing(first, second), &request())
                .expect_err("change")
                .code(),
            CrossPlaneReadbackErrorCodeV1::SourceChanged
        );
    }

    #[test]
    fn rejects_context_substitution() {
        let mut value = sample();
        value.mvcc.context.genesis_hash = h(99);
        assert_eq!(
            join_from_source(&MockSourceV1::stable(value), &request())
                .expect_err("context")
                .code(),
            CrossPlaneReadbackErrorCodeV1::InvalidContext
        );
    }

    #[test]
    fn rejects_order_head_substitution() {
        let mut value = sample();
        value.agent.store.order_block_id = h(99);
        assert_eq!(
            join_from_source(&MockSourceV1::stable(value), &request())
                .expect_err("order")
                .code(),
            CrossPlaneReadbackErrorCodeV1::OrderMismatch
        );
    }

    #[test]
    fn rejects_store_identity_swap() {
        let mut value = sample();
        value.verify.store.store_id = value.agent.store.store_id;
        assert_eq!(
            join_from_source(&MockSourceV1::stable(value), &request())
                .expect_err("identity")
                .code(),
            CrossPlaneReadbackErrorCodeV1::StoreIdentityConflict
        );
    }

    #[test]
    fn rejects_wrong_da_batch() {
        let mut value = sample();
        value.certificate.batch_id = h(99);
        assert_eq!(
            join_from_source(&MockSourceV1::stable(value), &request())
                .expect_err("DA")
                .code(),
            CrossPlaneReadbackErrorCodeV1::DaCertificateMismatch
        );
    }

    #[test]
    fn rejects_inactive_da_obligation() {
        let mut value = sample();
        value.certificate.obligation_status = 1;
        assert_eq!(
            join_from_source(&MockSourceV1::stable(value), &request())
                .expect_err("DA")
                .code(),
            CrossPlaneReadbackErrorCodeV1::DaCertificateMismatch
        );
    }

    #[test]
    fn rejects_cross_plane_result_id_reinterpretation() {
        let mut request = request();
        request.settlement_result_id = SettlementResultId([99; 32]);
        assert_eq!(
            join_from_source(&MockSourceV1::stable(sample()), &request)
                .expect_err("result")
                .code(),
            CrossPlaneReadbackErrorCodeV1::LifecycleMismatch
        );
    }

    #[test]
    fn rejects_receipt_store_identity_or_sequence_mismatch() {
        let mut request = request();
        request.agent_receipt.sequence += 1;
        assert_eq!(
            join_from_source(&MockSourceV1::stable(sample()), &request)
                .expect_err("receipt position")
                .code(),
            CrossPlaneReadbackErrorCodeV1::LifecycleMismatch
        );
    }

    #[test]
    fn rejects_receipt_post_state_root_mismatch() {
        let mut request = request();
        request.verify_receipt.post_state_root = agent_h(99);
        assert_eq!(
            join_from_source(&MockSourceV1::stable(sample()), &request)
                .expect_err("receipt root")
                .code(),
            CrossPlaneReadbackErrorCodeV1::LifecycleMismatch
        );
    }

    #[test]
    fn rejects_mvcc_receipt_head_root_mismatch() {
        let mut request = request();
        request.mvcc_receipt.final_state_root = MvccHash([99; 32]);
        assert_eq!(
            join_from_source(&MockSourceV1::stable(sample()), &request)
                .expect_err("MVCC head root")
                .code(),
            CrossPlaneReadbackErrorCodeV1::LifecycleMismatch
        );
    }

    #[test]
    fn rejects_nonterminal_settlement_receipt() {
        let mut request = request();
        request.settlement_receipt.operation_kind = 25;
        assert_eq!(
            join_from_source(&MockSourceV1::stable(sample()), &request)
                .expect_err("settlement")
                .code(),
            CrossPlaneReadbackErrorCodeV1::LifecycleMismatch
        );
    }

    #[test]
    fn propagates_typed_lifecycle_rejection_before_second_sample() {
        let source = MockSourceV1 {
            samples: RefCell::new(VecDeque::from([sample(), sample()])),
            lifecycle_error: true,
        };
        assert_eq!(
            join_from_source(&source, &request())
                .expect_err("lifecycle")
                .code(),
            CrossPlaneReadbackErrorCodeV1::LifecycleMismatch
        );
        assert_eq!(source.samples.borrow().len(), 1);
    }
}
