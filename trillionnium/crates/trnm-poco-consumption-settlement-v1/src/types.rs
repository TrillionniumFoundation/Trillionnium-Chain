use borsh::{BorshDeserialize, BorshSerialize};

pub use trnm_poco_agent_market_v1::{
    AccountIdV1, AgentIdV1, AgentKeyIdV1, EscrowIdV1, Hash32V1, LeaseIdV1, ProtocolContextV1,
    SettlementIdV1, TaskIdV1,
};

pub const SCHEMA_VERSION_V1: u16 = 1;
pub const KEY_ROLE_BILATERAL_RECEIPT_V1: u8 = 4;
pub const SIGNATURE_SCHEME_ED25519_V1: u16 = 0;
pub const RESULT_STATUS_FINAL_VALID_V1: u8 = 3;
pub const SETTLEMENT_MATURITY_NOT_STARTED_V1: u8 = 0;
pub const SETTLEMENT_MATURITY_FINAL_V1: u8 = 2;

macro_rules! typed_hash {
    ($name:ident) => {
        #[derive(
            Clone,
            Copy,
            Debug,
            Default,
            BorshDeserialize,
            BorshSerialize,
            Eq,
            Ord,
            PartialEq,
            PartialOrd,
        )]
        pub struct $name(pub [u8; 32]);

        impl From<Hash32V1> for $name {
            fn from(value: Hash32V1) -> Self {
                Self(value.0)
            }
        }

        impl From<$name> for Hash32V1 {
            fn from(value: $name) -> Self {
                Self(value.0)
            }
        }
    };
}

typed_hash!(ResultIdV1);
typed_hash!(AvailabilityCertificateIdV1);
typed_hash!(ConsumptionReceiptIdV1);
typed_hash!(ConsumptionRollupIdV1);
typed_hash!(ConsumptionOperationIdV1);

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct RegisteredBilateralKeyV1 {
    pub agent_id: AgentIdV1,
    pub key_id: AgentKeyIdV1,
    pub public_key: [u8; 32],
    pub policy_revision: u64,
    pub key_generation: u64,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConsumptionPriceV1 {
    pub resource_class: u16,
    pub resource_id: Vec<u8>,
    pub meter_id: Vec<u8>,
    pub meter_version: u32,
    pub unit: u16,
    pub unit_price: u128,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct SettlementPolicyV1 {
    pub schema_version: u16,
    pub policy_revision: u32,
    pub minimum_rollup_challenge_blocks: u64,
    pub maximum_rollups: u32,
    pub protocol_fee_numerator: u128,
    pub protocol_fee_denominator: u128,
    pub fee_schedule_hash: Hash32V1,
}

/// Bootstrap verifier input for the bounded candidate, not a consensus object.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ConsumptionSettlementFreshGenesisTrustBundleV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub initial_order_height: u64,
    pub initial_order_block_id: Hash32V1,
    pub provider: RegisteredBilateralKeyV1,
    pub consumer: RegisteredBilateralKeyV1,
    pub task_id: TaskIdV1,
    pub lease_id: LeaseIdV1,
    pub attempt: u32,
    pub result_id: ResultIdV1,
    pub result_revision: u64,
    pub result_status: u8,
    pub escrow_id: EscrowIdV1,
    pub escrow_version: u64,
    pub asset_id: Hash32V1,
    pub escrow_funding: u128,
    pub provider_account_id: AccountIdV1,
    pub consumer_account_id: AccountIdV1,
    pub protocol_account_id: AccountIdV1,
    pub provider_opening_balance: u128,
    pub consumer_opening_balance: u128,
    pub protocol_opening_balance: u128,
    pub prices: Vec<ConsumptionPriceV1>,
    pub accepted_evidence_certificates: Vec<AvailabilityCertificateIdV1>,
    pub related_party_policy_hash: Hash32V1,
    pub settlement_policy: SettlementPolicyV1,
}

/// Per-call finalized-order CAS input; proof authority remains out of scope.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ConsumptionOrderFinalizedExecutionContextV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub expected_order_height: u64,
    pub expected_order_block_id: Hash32V1,
    pub order_height: u64,
    pub order_block_id: Hash32V1,
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
pub struct CumulativeResourceUsageV1 {
    pub resource_class: u16,
    pub resource_id: Vec<u8>,
    pub meter_id: Vec<u8>,
    pub meter_version: u32,
    pub total_amount: u128,
    pub unit: u16,
    pub accumulator_commitment: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ConsumptionReceiptBodyV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub provider_id: AgentIdV1,
    pub consumer_id: AgentIdV1,
    pub task_id: TaskIdV1,
    pub lease_id: LeaseIdV1,
    pub attempt: u32,
    pub result_id: ResultIdV1,
    pub meter_id: Vec<u8>,
    pub meter_version: u32,
    pub sequence: u64,
    pub period_start_height: u64,
    pub period_end_height: u64,
    pub usage: Vec<ResourceUsageV1>,
    pub prior_receipt_id: Option<ConsumptionReceiptIdV1>,
    pub cumulative_usage: Vec<CumulativeResourceUsageV1>,
    pub cumulative_usage_root: Hash32V1,
    pub cumulative_charge: u128,
    pub evidence_certificate_id: AvailabilityCertificateIdV1,
    pub related_party_policy_hash: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct BilateralSignatureEntryV1 {
    pub agent_id: AgentIdV1,
    pub key_id: AgentKeyIdV1,
    pub key_role: u8,
    pub policy_revision: u64,
    pub key_generation: u64,
    pub authority_height: u64,
    pub signature_scheme: u16,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct BilateralSignatureStatementV1 {
    pub schema_version: u16,
    pub body_id: Hash32V1,
    pub agent_id: AgentIdV1,
    pub key_id: AgentKeyIdV1,
    pub key_role: u8,
    pub policy_revision: u64,
    pub key_generation: u64,
    pub authority_height: u64,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ConsumptionReceiptV1 {
    pub body: ConsumptionReceiptBodyV1,
    pub provider_signature: BilateralSignatureEntryV1,
    pub consumer_signature: BilateralSignatureEntryV1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ConsumptionReceiptStateV1 {
    pub receipt: ConsumptionReceiptV1,
    pub receipt_id: ConsumptionReceiptIdV1,
    pub version: u64,
    pub status: u8,
    pub assigned_rollup_id: Option<ConsumptionRollupIdV1>,
    pub accepted_height: u64,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ConsumptionRollupBodyV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub provider_id: AgentIdV1,
    pub consumer_id: AgentIdV1,
    pub task_id: TaskIdV1,
    pub lease_id: LeaseIdV1,
    pub attempt: u32,
    pub result_id: ResultIdV1,
    pub meter_id: Vec<u8>,
    pub meter_version: u32,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub receipt_ids: Vec<ConsumptionReceiptIdV1>,
    pub receipt_count: u32,
    pub receipts_root: Hash32V1,
    pub usage_totals: Vec<ResourceUsageV1>,
    pub total_charge: u128,
    pub evidence_certificate_id: AvailabilityCertificateIdV1,
    pub escrow_id: EscrowIdV1,
    pub settlement_policy_hash: Hash32V1,
    pub related_party_policy_hash: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ConsumptionRollupV1 {
    pub body: ConsumptionRollupBodyV1,
    pub provider_signature: BilateralSignatureEntryV1,
    pub consumer_signature: BilateralSignatureEntryV1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ConsumptionRollupStateV1 {
    pub rollup: ConsumptionRollupV1,
    pub rollup_id: ConsumptionRollupIdV1,
    pub version: u64,
    pub accepted_height: u64,
    pub challenge_close_height: u64,
    pub status: u8,
    pub consumed_by_settlement_id: Option<SettlementIdV1>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct SettlementOperationBodyV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub task_id: TaskIdV1,
    pub lease_id: LeaseIdV1,
    pub attempt: u32,
    pub result_id: ResultIdV1,
    pub expected_result_revision: u64,
    pub expected_escrow_version: u64,
    pub expected_rollup_version: u64,
    pub settlement_policy_hash: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct SettlementInputV1 {
    pub asset_id: Hash32V1,
    pub escrow_id: EscrowIdV1,
    pub escrow_version: u64,
    pub amount: u128,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct ValueDeltaV1 {
    pub asset_id: Hash32V1,
    pub account_id: AccountIdV1,
    pub reason: u16,
    pub amount: u128,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct SettlementIntentV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub task_id: TaskIdV1,
    pub lease_id: LeaseIdV1,
    pub attempt: u32,
    pub result_id: ResultIdV1,
    pub result_revision: u64,
    pub result_status: u8,
    pub settlement_maturity: u8,
    pub escrow_id: EscrowIdV1,
    pub consumption_rollup_ids: Vec<ConsumptionRollupIdV1>,
    pub fee_schedule_hash: Hash32V1,
    pub settlement_policy_hash: Hash32V1,
    pub inputs: Vec<SettlementInputV1>,
    pub input_value_root: Hash32V1,
    pub planned_deltas: Vec<ValueDeltaV1>,
    pub planned_deltas_root: Hash32V1,
    pub conservation_root: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct PostAccountVersionEntryV1 {
    pub account_id: AccountIdV1,
    pub prior_version: u64,
    pub post_version: u64,
    pub post_value_hash: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct SettlementReceiptV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub settlement_id: SettlementIdV1,
    pub task_id: TaskIdV1,
    pub lease_id: LeaseIdV1,
    pub result_id: ResultIdV1,
    pub escrow_id: EscrowIdV1,
    pub applied_deltas: Vec<ValueDeltaV1>,
    pub post_account_versions: Vec<PostAccountVersionEntryV1>,
    pub post_account_versions_root: Hash32V1,
    pub post_escrow_version: u64,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct SettlementStateV1 {
    pub settlement_id: SettlementIdV1,
    pub state_version: u64,
    pub intent: SettlementIntentV1,
    pub status: u8,
    pub receipt: SettlementReceiptV1,
    pub applied_height: u64,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct AccountBalanceStateV1 {
    pub account_id: AccountIdV1,
    pub version: u64,
    pub balance: u128,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct EscrowBalanceStateV1 {
    pub escrow_id: EscrowIdV1,
    pub version: u64,
    pub balance: u128,
    pub closed: bool,
    pub last_settlement_id: Option<SettlementIdV1>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ResultSettlementStateV1 {
    pub result_id: ResultIdV1,
    pub revision: u64,
    pub result_status: u8,
    pub settlement_maturity: u8,
    pub settlement_id: Option<SettlementIdV1>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ConsumptionSettlementKernelStateV1 {
    pub receipts: Vec<ConsumptionReceiptStateV1>,
    pub rollup: Option<ConsumptionRollupStateV1>,
    pub settlement: Option<SettlementStateV1>,
    pub escrow: EscrowBalanceStateV1,
    pub result: ResultSettlementStateV1,
    pub accounts: Vec<AccountBalanceStateV1>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub enum ConsumptionSettlementCommandV1 {
    AdmitReceipt {
        receipt: ConsumptionReceiptV1,
    },
    AdmitRollup {
        rollup: ConsumptionRollupV1,
        receipts: Vec<ConsumptionReceiptV1>,
    },
    Settle {
        operation: SettlementOperationBodyV1,
    },
}

impl ConsumptionSettlementCommandV1 {
    pub const fn operation_kind(&self) -> u16 {
        match self {
            Self::AdmitReceipt { .. } => 24,
            Self::AdmitRollup { .. } => 25,
            Self::Settle { .. } => 26,
        }
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ConsumptionTransitionReceiptV1 {
    pub schema_version: u16,
    pub store_id: Hash32V1,
    pub sequence: u64,
    pub operation_id: ConsumptionOperationIdV1,
    pub operation_kind: u16,
    pub order_height: u64,
    pub order_block_id: Hash32V1,
    pub post_state_root: Hash32V1,
    pub settlement_id: Option<SettlementIdV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumptionCommitFaultV1 {
    NotAppliedAckLost,
    AppliedAckLost,
    ThirdState,
}
