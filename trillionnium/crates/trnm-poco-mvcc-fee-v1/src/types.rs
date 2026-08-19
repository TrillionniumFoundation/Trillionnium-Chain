use borsh::{BorshDeserialize, BorshSerialize};

pub const SCHEMA_VERSION_V1: u16 = 1;
pub const RESOURCE_ORDERED_BYTES_V1: u16 = 0;
pub const RESOURCE_STATE_READ_BYTES_V1: u16 = 2;
pub const RESOURCE_STATE_WRITE_BYTES_V1: u16 = 3;
pub const RESOURCE_COMPUTE_UNITS_V1: u16 = 7;
pub const UNIT_BYTE_V1: u16 = 1;
pub const UNIT_COMPUTE_V1: u16 = 3;

#[derive(
    Clone, Copy, Debug, Default, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd,
)]
pub struct Hash32V1(pub [u8; 32]);

#[derive(Clone, Copy, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct TypedObjectIdV1 {
    pub object_kind: u16,
    pub object_id: [u8; 32],
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ProtocolContextV1 {
    pub chain_id: Vec<u8>,
    pub genesis_hash: Hash32V1,
    pub protocol_id: Vec<u8>,
    pub protocol_version: u32,
    pub profile_hash: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ObjectStateV1 {
    pub schema_version: u16,
    pub object_id: TypedObjectIdV1,
    pub version: u64,
    pub value: u128,
    pub closed: bool,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ResourcePriceV1 {
    pub resource_class: u16,
    pub resource_id: Vec<u8>,
    pub unit: u16,
    pub price_numerator: u128,
    pub price_denominator: u128,
    pub minimum_charge: u128,
    pub maximum_charge: u128,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct FeeDestinationSplitV1 {
    pub destination: TypedObjectIdV1,
    pub numerator: u128,
    pub denominator: u128,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct MvccFeeGenesisV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub store_id: Hash32V1,
    pub initial_height: u64,
    pub initial_block_id: Hash32V1,
    pub initial_objects: Vec<ObjectStateV1>,
    pub resource_prices: Vec<ResourcePriceV1>,
    pub destination_splits: Vec<FeeDestinationSplitV1>,
    pub remainder_destination: TypedObjectIdV1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub enum ObjectProgramV1 {
    Add {
        target: TypedObjectIdV1,
        amount: u128,
    },
    Transfer {
        source: TypedObjectIdV1,
        destination: TypedObjectIdV1,
        amount: u128,
    },
    Revert {
        error_class: u16,
    },
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct MvccTransactionV1 {
    pub schema_version: u16,
    pub transaction_id: Hash32V1,
    pub transaction_index: u32,
    pub fee_payer: TypedObjectIdV1,
    pub declared_reads: Vec<TypedObjectIdV1>,
    pub declared_writes: Vec<TypedObjectIdV1>,
    pub compute_unit_limit: u128,
    pub max_fee: u128,
    pub program: ObjectProgramV1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct MvccBlockV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub block_id: Hash32V1,
    pub height: u64,
    pub expected_parent_height: u64,
    pub expected_parent_block_id: Hash32V1,
    pub expected_parent_state_root: Hash32V1,
    pub transactions: Vec<MvccTransactionV1>,
}

#[derive(Clone, Copy, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub enum ReceiptStatusV1 {
    Success,
    Reverted,
    OutOfResource,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReadSetEntryV1 {
    pub object_id: TypedObjectIdV1,
    pub observed_version: u64,
    pub observed_value_hash: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct WriteSetEntryV1 {
    pub object_id: TypedObjectIdV1,
    pub prior_version: u64,
    pub successor_version: u64,
    pub successor_value_hash: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResourceUsageV1 {
    pub resource_class: u16,
    pub resource_id: Vec<u8>,
    pub meter_id: Vec<u8>,
    pub meter_version: u32,
    pub amount: u128,
    pub unit: u16,
    pub measurement_commitment: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct FeeDeltaV1 {
    pub source: TypedObjectIdV1,
    pub destination: TypedObjectIdV1,
    pub amount: u128,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct DestinationFeeCreditV1 {
    pub destination: TypedObjectIdV1,
    pub amount: u128,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct TransactionExecutionReceiptV1 {
    pub schema_version: u16,
    pub transaction_id: Hash32V1,
    pub transaction_index: u32,
    pub status: ReceiptStatusV1,
    pub error_class: Option<u16>,
    pub read_set: Vec<ReadSetEntryV1>,
    pub write_set: Vec<WriteSetEntryV1>,
    pub read_set_root: Hash32V1,
    pub write_set_root: Hash32V1,
    pub state_delta_root: Hash32V1,
    pub post_transaction_state_root: Hash32V1,
    pub resource_usage: Vec<ResourceUsageV1>,
    pub fee_charged: u128,
    pub refund_amount: u128,
    pub fee_deltas: Vec<FeeDeltaV1>,
    pub conflict_set: Vec<TypedObjectIdV1>,
    pub retry_count: u32,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct MvccBlockReceiptV1 {
    pub schema_version: u16,
    pub store_id: Hash32V1,
    pub block_id: Hash32V1,
    pub height: u64,
    pub parent_state_root: Hash32V1,
    pub final_state_root: Hash32V1,
    pub receipts_root: Hash32V1,
    pub resource_totals_root: Hash32V1,
    pub fee_deltas_root: Hash32V1,
    pub mvcc_resolution_root: Hash32V1,
    pub transaction_count: u32,
    pub receipts: Vec<TransactionExecutionReceiptV1>,
    pub resource_totals: Vec<ResourceUsageV1>,
    pub aggregated_fee_deltas: Vec<FeeDeltaV1>,
    pub destination_credits: Vec<DestinationFeeCreditV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MvccCommitFaultV1 {
    NotAppliedAckLost,
    AppliedAckLost,
    ThirdState,
}
