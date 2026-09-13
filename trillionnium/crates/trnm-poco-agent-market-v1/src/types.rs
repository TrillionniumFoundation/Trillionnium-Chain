use borsh::{BorshDeserialize, BorshSerialize};

use crate::{codec::digest_value, AgentMarketResultV1};

pub const PROTOCOL_VERSION_V1: u32 = 1;
pub const SCHEMA_VERSION_V1: u16 = 1;
pub const CONTROLLER_LANE_V1: u16 = 0;
pub const CONTROLLER_SENTINEL_KEY_V1: AgentKeyIdV1 = AgentKeyIdV1([0; 32]);

#[derive(
    Clone, Copy, Debug, Default, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd,
)]
pub struct Hash32V1(pub [u8; 32]);

macro_rules! id_type {
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

id_type!(AgentIdV1);
id_type!(AgentKeyIdV1);
id_type!(CapabilityIdV1);
id_type!(SessionKeyGrantIdV1);
id_type!(NonceLaneIdV1);
id_type!(TaskIdV1);
id_type!(BidIdV1);
id_type!(LeaseIdV1);
id_type!(EscrowIdV1);
id_type!(AccountIdV1);
id_type!(BondIdV1);
id_type!(ArtifactIdV1);
id_type!(SettlementIdV1);
id_type!(CheckpointIdV1);
id_type!(KernelOperationIdV1);

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ProtocolContextV1 {
    pub genesis_hash: Hash32V1,
    pub chain_id: String,
    pub protocol_version: u32,
    pub stack_profile_hash: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct BootstrapAgentV1 {
    pub agent_id: AgentIdV1,
    pub controller_key_id: AgentKeyIdV1,
    pub controller_public_key: [u8; 32],
    pub session_key_id: AgentKeyIdV1,
    pub session_public_key: [u8; 32],
}

/// Verifier/store bootstrap input. This is not a protocol-v1 consensus object.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct AgentMarketFreshGenesisTrustBundleV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub initial_order_height: u64,
    pub initial_order_block_id: Hash32V1,
    pub requester: BootstrapAgentV1,
    pub provider: BootstrapAgentV1,
    pub requester_account_body: AccountBodyV1,
    pub requester_account_id: AccountIdV1,
    pub requester_account_funding: u128,
    pub provider_bond_body: BondBodyV1,
    pub provider_bond_id: BondIdV1,
    pub provider_bond_funding: u128,
    pub provider_bond_hold: u128,
}

/// Per-call order-finalized verifier input. This is not a consensus object.
///
/// The expected fields form an exact compare-and-swap against the durable
/// store tip. A successor may remain in the same finalized block or advance
/// monotonically to a later finalized block; it can never move backwards or
/// silently switch the block identity at one height.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct OrderFinalizedExecutionContextV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub expected_order_height: u64,
    pub expected_order_block_id: Hash32V1,
    pub order_height: u64,
    pub order_block_id: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct VerificationProfileRefV1 {
    pub profile_id: Vec<u8>,
    pub profile_version: u32,
    pub profile_hash: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct OperationScopeV1 {
    pub operation_kind: u16,
    pub task_id: Option<TaskIdV1>,
    pub market_id: Option<Hash32V1>,
    pub model_commitment: Option<Hash32V1>,
    pub tool_commitment: Option<Hash32V1>,
    pub endpoint_commitment: Option<Hash32V1>,
    pub verification_profile: Option<VerificationProfileRefV1>,
    pub privacy_lane: Option<u8>,
    pub maximum_unit_price: Option<u128>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResourceScopeV1 {
    pub resource_kind: u16,
    pub scope_mode: u8,
    pub allowed_ids: Vec<Hash32V1>,
    pub allowlist_commitment: Option<Hash32V1>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct AssetLimitV1 {
    pub asset_id: Hash32V1,
    pub maximum_amount: u128,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct CapabilityGrantBodyV1 {
    pub schema_version: u16,
    pub genesis_hash: Hash32V1,
    pub chain_id: String,
    pub protocol_version: u32,
    pub stack_profile_hash: Hash32V1,
    pub issuer_agent_id: AgentIdV1,
    pub issuer_key_id: AgentKeyIdV1,
    pub delegate_agent_id: AgentIdV1,
    pub delegate_key_id: Option<AgentKeyIdV1>,
    pub parent_capability_id: Option<CapabilityIdV1>,
    pub grant_nonce: Hash32V1,
    pub operation_scopes: Vec<OperationScopeV1>,
    pub resource_scopes: Vec<ResourceScopeV1>,
    pub spend_limits: Vec<AssetLimitV1>,
    pub fee_limit: u128,
    pub gas_limit: u64,
    pub da_byte_limit: u64,
    pub artifact_retention_limit: u64,
    pub allowed_nonce_lanes: Vec<u16>,
    pub valid_from_height: u64,
    pub expires_after_height: u64,
    pub rate_window_blocks: u64,
    pub rate_max_operations: u64,
    pub max_total_operations: u64,
    pub delegation_depth_remaining: u8,
    pub revocation_generation: u64,
    pub conditions_hash: Hash32V1,
}

impl CapabilityGrantBodyV1 {
    pub fn capability_id(&self) -> AgentMarketResultV1<CapabilityIdV1> {
        Ok(digest_value("trnm.poco-ai.capability.v1", self)?.into())
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct AssetBudgetCounterV1 {
    pub asset_id: Hash32V1,
    pub limit: u128,
    pub spent: u128,
    pub reserved: u128,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct CapabilityBudgetStateV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub capability_id: CapabilityIdV1,
    pub budget_version: u64,
    pub revocation_generation: u64,
    pub asset_counters: Vec<AssetBudgetCounterV1>,
    pub fee_limit: u128,
    pub fee_spent: u128,
    pub fee_reserved: u128,
    pub gas_limit: u64,
    pub gas_spent: u64,
    pub gas_reserved: u64,
    pub da_byte_limit: u64,
    pub da_bytes_spent: u64,
    pub da_bytes_reserved: u64,
    pub retention_limit: u64,
    pub retention_spent: u64,
    pub retention_reserved: u64,
    pub operation_limit: u64,
    pub operations_spent: u64,
    pub operations_reserved: u64,
    pub rate_window_start_height: u64,
    pub rate_window_operations: u64,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct CapabilityStateV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub capability_id: CapabilityIdV1,
    pub state_version: u64,
    pub status: u8,
    pub live_revocation_generation: u64,
    pub accepted_height: u64,
    pub status_changed_height: u64,
    pub revoked_at_height: Option<u64>,
    pub budget: CapabilityBudgetStateV1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct SessionKeyGrantBodyV1 {
    pub schema_version: u16,
    pub genesis_hash: Hash32V1,
    pub chain_id: String,
    pub protocol_version: u32,
    pub stack_profile_hash: Hash32V1,
    pub agent_id: AgentIdV1,
    pub session_key_id: AgentKeyIdV1,
    pub capability_id: CapabilityIdV1,
    pub allowed_nonce_lanes: Vec<u16>,
    pub valid_from_height: u64,
    pub expires_after_height: u64,
    pub max_total_operations: u64,
    pub session_generation: u64,
    pub grant_nonce: Hash32V1,
}

impl SessionKeyGrantBodyV1 {
    pub fn session_key_grant_id(&self) -> AgentMarketResultV1<SessionKeyGrantIdV1> {
        Ok(digest_value("trnm.poco-ai.session-key-grant.v1", self)?.into())
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct SessionKeyGrantStateV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub session_key_grant_id: SessionKeyGrantIdV1,
    pub state_version: u64,
    pub status: u8,
    pub session_generation: u64,
    pub bound_capability_generation: u64,
    pub operations_spent: u64,
    pub accepted_height: u64,
    pub status_changed_height: u64,
    pub revoked_at_height: Option<u64>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct NonceLaneKeyBodyV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub agent_id: AgentIdV1,
    pub authorizing_key_id: AgentKeyIdV1,
    pub capability_id: Option<CapabilityIdV1>,
    pub session_generation: u64,
    pub lane: u16,
}

impl NonceLaneKeyBodyV1 {
    pub fn nonce_lane_id(&self) -> AgentMarketResultV1<NonceLaneIdV1> {
        Ok(digest_value("trnm.poco-ai.nonce-lane.v1", self)?.into())
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct NonceLaneStateV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub nonce_lane_id: NonceLaneIdV1,
    pub state_version: u64,
    pub agent_id: AgentIdV1,
    pub authorizing_key_id: AgentKeyIdV1,
    pub capability_id: Option<CapabilityIdV1>,
    pub session_generation: u64,
    pub lane: u16,
    pub next_nonce: u64,
    pub last_operation_digest: Option<Hash32V1>,
    pub status: u8,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct AssetChargeV1 {
    pub asset_id: Hash32V1,
    pub amount: u128,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct KernelResourceChargeV1 {
    pub asset_charges: Vec<AssetChargeV1>,
    pub fee: u128,
    pub gas: u64,
    pub da_bytes: u64,
    pub retention: u64,
    pub operations: u64,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct AccountBodyV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub owner_agent_id: AgentIdV1,
    pub asset_id: Hash32V1,
    pub account_nonce: Hash32V1,
}

impl AccountBodyV1 {
    pub fn account_id(&self) -> AgentMarketResultV1<AccountIdV1> {
        Ok(digest_value("trnm.poco-ai.account.v1", self)?.into())
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct AccountStateV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub account_id: AccountIdV1,
    pub version: u64,
    pub available: u128,
    pub reserved: u128,
    pub spent: u128,
    pub closed: bool,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct BondBodyV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub owner_agent_id: AgentIdV1,
    pub asset_id: Hash32V1,
    pub purpose: u16,
    pub source_object_kind: u16,
    pub source_object_id: Hash32V1,
    pub bond_nonce: Hash32V1,
}

impl BondBodyV1 {
    pub fn bond_id(&self) -> AgentMarketResultV1<BondIdV1> {
        Ok(digest_value("trnm.poco-ai.bond.v1", self)?.into())
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct BondStateV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub bond_id: BondIdV1,
    pub version: u64,
    pub available: u128,
    pub held: u128,
    pub released: u128,
    pub slashed: u128,
    pub closed: bool,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct EscrowTermsV1 {
    pub schema_version: u16,
    pub asset_id: Hash32V1,
    pub funded_amount: u128,
    pub provider_payment_cap: u128,
    pub order_fee_reserve: u128,
    pub transaction_da_fee_reserve: u128,
    pub artifact_da_fee_reserve: u128,
    pub verification_fee_reserve: u128,
    pub challenge_reserve: u128,
    pub refund_beneficiary: AgentIdV1,
    pub settlement_policy_hash: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct TaskOfferBodyV1 {
    pub schema_version: u16,
    pub genesis_hash: Hash32V1,
    pub chain_id: String,
    pub protocol_version: u32,
    pub stack_profile_hash: Hash32V1,
    pub requester_agent_id: AgentIdV1,
    pub requester_key_id: AgentKeyIdV1,
    pub requester_capability_id: Option<CapabilityIdV1>,
    pub requester_session_generation: u64,
    pub request_nonce_lane: u16,
    pub request_nonce: u64,
    pub task_kind: Vec<u8>,
    pub task_spec_commitment: Hash32V1,
    pub input_artifacts: Vec<ArtifactIdV1>,
    pub model_scope_commitment: Hash32V1,
    pub tool_scope_commitment: Hash32V1,
    pub verification_profile_id: Vec<u8>,
    pub verification_profile_version: u32,
    pub verification_profile_hash: Hash32V1,
    pub privacy_lane: u8,
    pub provider_policy_hash: Hash32V1,
    pub resource_limit_hash: Hash32V1,
    pub pricing_policy_hash: Hash32V1,
    pub escrow_terms_hash: Hash32V1,
    pub checkpoint_policy_hash: Hash32V1,
    pub migration_policy_hash: Hash32V1,
    pub challenge_policy_hash: Hash32V1,
    pub offer_expiry_height: u64,
    pub start_deadline_height: u64,
    pub result_deadline_height: u64,
    pub settlement_deadline_height: u64,
    pub requester_metadata_commitment: Hash32V1,
}

impl TaskOfferBodyV1 {
    pub fn task_id(&self) -> AgentMarketResultV1<TaskIdV1> {
        Ok(digest_value("trnm.poco-ai.task.v1", self)?.into())
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct TaskCreationOperationBodyV1 {
    pub task_offer_body: TaskOfferBodyV1,
    pub escrow_terms: EscrowTermsV1,
    pub funding_account_id: AccountIdV1,
    pub expected_funding_account_version: u64,
    pub escrow_nonce: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct TaskStateV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub task_id: TaskIdV1,
    pub revision: u64,
    pub attempt: u32,
    pub status: u8,
    pub active_lease_id: Option<LeaseIdV1>,
    pub latest_checkpoint_id: Option<CheckpointIdV1>,
    pub active_result_id: Option<Hash32V1>,
    pub escrow_id: EscrowIdV1,
    pub active_deadline_kind: u8,
    pub active_deadline_height: u64,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct EscrowBodyV1 {
    pub schema_version: u16,
    pub genesis_hash: Hash32V1,
    pub chain_id: String,
    pub protocol_version: u32,
    pub stack_profile_hash: Hash32V1,
    pub task_id: TaskIdV1,
    pub requester_agent_id: AgentIdV1,
    pub asset_id: Hash32V1,
    pub funded_amount: u128,
    pub provider_payment_cap: u128,
    pub order_fee_reserve: u128,
    pub transaction_da_fee_reserve: u128,
    pub artifact_da_fee_reserve: u128,
    pub verification_fee_reserve: u128,
    pub challenge_reserve: u128,
    pub refund_beneficiary: AgentIdV1,
    pub settlement_policy_hash: Hash32V1,
    pub escrow_nonce: Hash32V1,
}

impl EscrowBodyV1 {
    pub fn escrow_id(&self) -> AgentMarketResultV1<EscrowIdV1> {
        Ok(digest_value("trnm.poco-ai.escrow.v1", self)?.into())
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct EscrowReservationEntryV1 {
    pub reservation_kind: u16,
    pub source_object_kind: u16,
    pub source_object_id: Hash32V1,
    pub asset_id: Hash32V1,
    pub amount: u128,
    pub created_height: u64,
    pub release_condition_hash: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct EscrowStateV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub escrow_id: EscrowIdV1,
    pub version: u64,
    pub available: u128,
    pub reserved: u128,
    pub disbursed: u128,
    pub refunded: u128,
    pub forfeited: u128,
    pub active_reservations: Vec<EscrowReservationEntryV1>,
    pub active_reservation_root: Hash32V1,
    pub last_settlement_id: Option<SettlementIdV1>,
    pub closed: bool,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct BidBodyV1 {
    pub schema_version: u16,
    pub genesis_hash: Hash32V1,
    pub chain_id: String,
    pub protocol_version: u32,
    pub stack_profile_hash: Hash32V1,
    pub task_id: TaskIdV1,
    pub task_revision: u64,
    pub provider_agent_id: AgentIdV1,
    pub provider_key_id: AgentKeyIdV1,
    pub provider_capability_id: Option<CapabilityIdV1>,
    pub provider_session_generation: u64,
    pub provider_nonce_lane: u16,
    pub provider_nonce: u64,
    pub price_asset_id: Hash32V1,
    pub maximum_price: u128,
    pub pricing_terms_hash: Hash32V1,
    pub resource_offer_hash: Hash32V1,
    pub execution_environment_hash: Hash32V1,
    pub provider_bond_id: BondIdV1,
    pub checkpoint_terms_hash: Hash32V1,
    pub availability_terms_hash: Hash32V1,
    pub bid_expiry_height: u64,
    pub provider_metadata_commitment: Hash32V1,
}

impl BidBodyV1 {
    pub fn bid_id(&self) -> AgentMarketResultV1<BidIdV1> {
        Ok(digest_value("trnm.poco-ai.bid.v1", self)?.into())
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct BidStateV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub bid_id: BidIdV1,
    pub state_version: u64,
    pub status: u8,
    pub accepted_lease_id: Option<LeaseIdV1>,
    pub accepted_height: Option<u64>,
    pub terminal_height: Option<u64>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct TaskLeaseBodyV1 {
    pub schema_version: u16,
    pub genesis_hash: Hash32V1,
    pub chain_id: String,
    pub protocol_version: u32,
    pub stack_profile_hash: Hash32V1,
    pub task_id: TaskIdV1,
    pub base_task_revision: u64,
    pub attempt: u32,
    pub accepted_bid_id: BidIdV1,
    pub requester_agent_id: AgentIdV1,
    pub provider_agent_id: AgentIdV1,
    pub escrow_id: EscrowIdV1,
    pub provider_bond_id: BondIdV1,
    pub resume_checkpoint_id: Option<CheckpointIdV1>,
    pub execution_environment_hash: Hash32V1,
    pub verification_profile_id: Vec<u8>,
    pub verification_profile_version: u32,
    pub verification_profile_hash: Hash32V1,
    pub pricing_terms_hash: Hash32V1,
    pub checkpoint_terms_hash: Hash32V1,
    pub availability_terms_hash: Hash32V1,
    pub start_deadline_height: u64,
    pub checkpoint_deadline_height: u64,
    pub result_deadline_height: u64,
    pub lease_nonce: Hash32V1,
}

impl TaskLeaseBodyV1 {
    pub fn lease_id(&self) -> AgentMarketResultV1<LeaseIdV1> {
        Ok(digest_value("trnm.poco-ai.lease.v1", self)?.into())
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct TaskLeaseStateV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub lease_id: LeaseIdV1,
    pub revision: u64,
    pub attempt: u32,
    pub status: u8,
    pub accepted_height: Option<u64>,
    pub started_height: Option<u64>,
    pub terminal_height: Option<u64>,
    pub latest_checkpoint_id: Option<CheckpointIdV1>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct LeaseProviderAcceptanceBodyV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub lease_id: LeaseIdV1,
    pub provider_agent_id: AgentIdV1,
    pub expected_task_revision: u64,
    pub acceptance_nonce: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct KernelAuthorizationStatementV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub operation_kind: u16,
    pub operation_digest: Hash32V1,
    pub sender_agent_id: AgentIdV1,
    pub authorizing_key_id: AgentKeyIdV1,
    pub capability_id: Option<CapabilityIdV1>,
    pub live_capability_generation: u64,
    pub session_key_grant_id: Option<SessionKeyGrantIdV1>,
    pub session_generation: u64,
    pub nonce_lane: u16,
    pub nonce: u64,
    pub expected_lane_version: u64,
    pub valid_after_height: u64,
    pub expires_after_height: u64,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct KernelAuthorizationV1 {
    pub statement: KernelAuthorizationStatementV1,
    pub signer_key_id: AgentKeyIdV1,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum KernelCommandV1 {
    CapabilityGrant {
        body: CapabilityGrantBodyV1,
        authorization: KernelAuthorizationV1,
    },
    SessionGrant {
        body: SessionKeyGrantBodyV1,
        authorization: KernelAuthorizationV1,
    },
    TaskCreate {
        body: TaskCreationOperationBodyV1,
        charge: KernelResourceChargeV1,
        authorization: KernelAuthorizationV1,
    },
    Bid {
        body: BidBodyV1,
        charge: KernelResourceChargeV1,
        authorization: KernelAuthorizationV1,
    },
    LeaseAccept {
        body: TaskLeaseBodyV1,
        expected_bid_version: u64,
        expected_escrow_version: u64,
        expected_bond_version: u64,
        charge: KernelResourceChargeV1,
        authorization: KernelAuthorizationV1,
    },
    ProviderAccept {
        body: LeaseProviderAcceptanceBodyV1,
        expected_lease_revision: u64,
        charge: KernelResourceChargeV1,
        authorization: KernelAuthorizationV1,
    },
}

impl KernelCommandV1 {
    pub const fn operation_kind(&self) -> u16 {
        match self {
            Self::CapabilityGrant { .. } => 2,
            Self::SessionGrant { .. } => 3,
            Self::TaskCreate { .. } => 4,
            Self::Bid { .. } => 5,
            Self::LeaseAccept { .. } => 6,
            Self::ProviderAccept { .. } => 7,
        }
    }

    pub fn operation_digest(&self) -> AgentMarketResultV1<Hash32V1> {
        match self {
            Self::CapabilityGrant { body, .. } => {
                digest_value("trnm.poco-ai.capability-grant-operation.candidate.v1", body)
            }
            Self::SessionGrant { body, .. } => {
                digest_value("trnm.poco-ai.session-grant-operation.candidate.v1", body)
            }
            Self::TaskCreate { body, charge, .. } => digest_value(
                "trnm.poco-ai.task-create-operation.candidate.v1",
                &(body, charge),
            ),
            Self::Bid { body, charge, .. } => {
                digest_value("trnm.poco-ai.bid-operation.candidate.v1", &(body, charge))
            }
            Self::LeaseAccept {
                body,
                expected_bid_version,
                expected_escrow_version,
                expected_bond_version,
                charge,
                ..
            } => digest_value(
                "trnm.poco-ai.lease-accept-operation.candidate.v1",
                &(
                    body,
                    expected_bid_version,
                    expected_escrow_version,
                    expected_bond_version,
                    charge,
                ),
            ),
            Self::ProviderAccept {
                body,
                expected_lease_revision,
                charge,
                ..
            } => digest_value(
                "trnm.poco-ai.provider-accept-operation.candidate.v1",
                &(body, expected_lease_revision, charge),
            ),
        }
    }

    pub const fn authorization(&self) -> &KernelAuthorizationV1 {
        match self {
            Self::CapabilityGrant { authorization, .. }
            | Self::SessionGrant { authorization, .. }
            | Self::TaskCreate { authorization, .. }
            | Self::Bid { authorization, .. }
            | Self::LeaseAccept { authorization, .. }
            | Self::ProviderAccept { authorization, .. } => authorization,
        }
    }

    #[cfg(test)]
    pub(crate) const fn authorization_mut_for_test(&mut self) -> &mut KernelAuthorizationV1 {
        match self {
            Self::CapabilityGrant { authorization, .. }
            | Self::SessionGrant { authorization, .. }
            | Self::TaskCreate { authorization, .. }
            | Self::Bid { authorization, .. }
            | Self::LeaseAccept { authorization, .. }
            | Self::ProviderAccept { authorization, .. } => authorization,
        }
    }

    pub fn operation_id(&self) -> AgentMarketResultV1<KernelOperationIdV1> {
        Ok(digest_value(
            "trnm.poco-ai.agent-market-kernel-operation.candidate.v1",
            &self.authorization().statement,
        )?
        .into())
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct KernelTransitionReceiptV1 {
    pub schema_version: u16,
    pub store_id: Hash32V1,
    pub sequence: u64,
    pub operation_id: KernelOperationIdV1,
    pub operation_kind: u16,
    pub operation_digest: Hash32V1,
    pub order_height: u64,
    pub order_block_id: Hash32V1,
    pub post_state_root: Hash32V1,
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKindV1 {
    Capability = 2,
    SessionGrant = 3,
    Task = 4,
    Bid = 5,
    Lease = 6,
    Escrow = 7,
    NonceLane = 44,
    Account = 45,
    Bond = 47,
}
