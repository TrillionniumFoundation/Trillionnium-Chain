use borsh::{BorshDeserialize, BorshSerialize};
use trnm_poco_agent_market_v1::{EscrowIdV1, KernelTransitionReceiptV1, LeaseIdV1, TaskIdV1};
use trnm_poco_consumption_settlement_v1::{
    ConsumptionTransitionReceiptV1, ResultIdV1 as SettlementResultIdV1,
};
use trnm_poco_da_v1::BatchIdV1;
use trnm_poco_mvcc_fee_v1::MvccBlockReceiptV1;
use trnm_poco_verify_challenge_v1::{ResultIdV1 as VerifyResultIdV1, VerifyTransitionReceiptV1};

#[derive(
    Clone, Copy, Debug, Default, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd,
)]
pub struct Hash32V1(pub [u8; 32]);

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct CrossPlaneJoinRequestV1 {
    pub schema_version: u16,
    pub chain_id: String,
    pub genesis_hash: Hash32V1,
    pub protocol_version: u32,
    pub stack_profile_hash: Hash32V1,
    pub order_height: u64,
    pub order_block_id: Hash32V1,
    pub order_proof_digest: Hash32V1,
    pub da_batch_id: BatchIdV1,
    pub task_id: TaskIdV1,
    pub lease_id: LeaseIdV1,
    pub escrow_id: EscrowIdV1,
    pub verify_result_id: VerifyResultIdV1,
    pub settlement_result_id: SettlementResultIdV1,
    pub settlement_id: trnm_poco_agent_market_v1::SettlementIdV1,
    pub agent_receipt: KernelTransitionReceiptV1,
    pub verify_receipt: VerifyTransitionReceiptV1,
    pub mvcc_receipt: MvccBlockReceiptV1,
    pub settlement_receipt: ConsumptionTransitionReceiptV1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct CrossPlaneStoreHeadV1 {
    pub plane_tag: u8,
    pub store_schema_version: u16,
    pub store_id: Hash32V1,
    pub sequence_or_height: u64,
    pub order_height: u64,
    pub order_block_id: Hash32V1,
    pub durable_state_or_metadata_root: Hash32V1,
    pub durable_journal_tail_root: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct CrossPlaneReadbackProjectionV1 {
    pub schema_version: u16,
    pub chain_id: String,
    pub genesis_hash: Hash32V1,
    pub protocol_version: u32,
    pub stack_profile_hash: Hash32V1,
    pub order_height: u64,
    pub order_block_id: Hash32V1,
    pub order_proof_digest: Hash32V1,
    pub store_heads: Vec<CrossPlaneStoreHeadV1>,
    pub da_scope_id: Hash32V1,
    pub da_batch_id: Hash32V1,
    pub da_certificate_id: Hash32V1,
    pub da_obligation_id: Hash32V1,
    pub da_obligation_version: u64,
    pub task_id: Hash32V1,
    pub lease_id: Hash32V1,
    pub escrow_id: Hash32V1,
    pub result_id: Hash32V1,
    pub agent_operation_id: Hash32V1,
    pub verify_operation_id: Hash32V1,
    pub settlement_operation_id: Hash32V1,
    pub settlement_id: Hash32V1,
    pub mvcc_receipts_root: Hash32V1,
    pub mvcc_resource_totals_root: Hash32V1,
    pub mvcc_fee_deltas_root: Hash32V1,
    pub mvcc_resolution_root: Hash32V1,
    pub projection_digest: Hash32V1,
}

#[derive(Debug)]
pub struct ConfirmedCrossPlaneReadbackV1 {
    pub(crate) projection: CrossPlaneReadbackProjectionV1,
}

impl ConfirmedCrossPlaneReadbackV1 {
    pub const fn projection(&self) -> &CrossPlaneReadbackProjectionV1 {
        &self.projection
    }

    pub const fn digest(&self) -> Hash32V1 {
        self.projection.projection_digest
    }
}
