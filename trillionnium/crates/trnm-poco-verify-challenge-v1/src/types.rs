use borsh::{BorshDeserialize, BorshSerialize};
use trnm_poco_agent_market_v1::{AgentIdV1, AgentKeyIdV1, BondIdV1, Hash32V1, ProtocolContextV1};

use crate::{codec::digest_value, VerifyChallengeResultV1};

pub const SCHEMA_VERSION_V1: u16 = 1;
pub const PROTOCOL_VERSION_V1: u32 = 1;

macro_rules! typed_hash {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, BorshDeserialize, BorshSerialize, Eq, Ord, PartialEq, PartialOrd,
        )]
        pub struct $name(pub [u8; 32]);
        impl From<Hash32V1> for $name {
            fn from(value: Hash32V1) -> Self {
                Self(value.0)
            }
        }
    };
}

typed_hash!(ExecutionReceiptIdV1);
typed_hash!(ResultIdV1);
typed_hash!(VerificationClaimIdV1);
typed_hash!(VerificationDecisionIdV1);
typed_hash!(ChallengeIdV1);
typed_hash!(VerifyOperationIdV1);

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct RegisteredActorV1 {
    pub agent_id: AgentIdV1,
    pub key_id: AgentKeyIdV1,
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct RegisteredVerifierV1 {
    pub verifier_id: [u8; 32],
    pub key_id: [u8; 32],
    pub public_key: [u8; 32],
    pub weight: u128,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct StakeQuorumProfileV1 {
    pub profile_id: Vec<u8>,
    pub profile_version: u32,
    pub profile_hash: Hash32V1,
    pub verifier_set_hash: Hash32V1,
    pub threshold_weight: u128,
    pub minimum_unique_signers: u32,
    pub minimum_challenge_blocks: u64,
    pub required_da_policy_hash: Hash32V1,
    pub challenge_policy_hash: Hash32V1,
    pub settlement_policy_hash: Hash32V1,
    pub challenge_bond_asset_id: Hash32V1,
    pub challenge_bond_amount: u128,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct VerifyChallengeFreshGenesisTrustBundleV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub initial_order_height: u64,
    pub initial_order_block_id: Hash32V1,
    pub task_id: Hash32V1,
    pub task_revision: u64,
    pub lease_id: Hash32V1,
    pub attempt: u32,
    pub execution_environment_hash: Hash32V1,
    pub provider: RegisteredActorV1,
    pub challenger: RegisteredActorV1,
    pub verifiers: Vec<RegisteredVerifierV1>,
    pub profile: StakeQuorumProfileV1,
    pub challenge_bond_id: BondIdV1,
    pub challenge_bond_funding: u128,
}

/// Node-supplied order-finality fact used as a monotonic compare-and-swap input.
///
/// This is deliberately a verifier trust input in the candidate kernel, not a
/// consensus object or proof that order finality occurred.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct VerifyOrderFinalizedExecutionContextV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub expected_order_height: u64,
    pub expected_order_block_id: Hash32V1,
    pub order_height: u64,
    pub order_block_id: Hash32V1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ExecutionReceiptBodyV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub task_id: Hash32V1,
    pub task_revision: u64,
    pub lease_id: Hash32V1,
    pub attempt: u32,
    pub provider_agent_id: AgentIdV1,
    pub provider_key_id: AgentKeyIdV1,
    pub execution_outcome: u8,
    pub failure_code: Option<u32>,
    pub execution_environment_hash: Hash32V1,
    pub output_commitment: Hash32V1,
    pub meter_root: Hash32V1,
    pub verification_profile_id: Vec<u8>,
    pub verification_profile_version: u32,
    pub verification_profile_hash: Hash32V1,
    pub receipt_sequence: u64,
    pub submitted_height_upper_bound: u64,
}

impl ExecutionReceiptBodyV1 {
    pub fn receipt_id(&self) -> VerifyChallengeResultV1<ExecutionReceiptIdV1> {
        Ok(digest_value("trnm.poco-ai.execution-receipt.v1", self)?.into())
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct SignedExecutionReceiptV1 {
    pub body: ExecutionReceiptBodyV1,
    pub receipt_id: ExecutionReceiptIdV1,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct VerificationClaimBodyV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub result_id: ResultIdV1,
    pub execution_receipt_id: ExecutionReceiptIdV1,
    pub verification_profile_id: Vec<u8>,
    pub verification_profile_version: u32,
    pub verification_profile_hash: Hash32V1,
    pub decision_round: u32,
    pub verifier_id: [u8; 32],
    pub verifier_key_id: [u8; 32],
    pub verdict: u8,
    pub statement_digest: Hash32V1,
    pub evidence_root: Hash32V1,
    pub claim_sequence: u64,
}

impl VerificationClaimBodyV1 {
    pub fn claim_id(&self) -> VerifyChallengeResultV1<VerificationClaimIdV1> {
        Ok(digest_value("trnm.poco-ai.verification-claim.v1", self)?.into())
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct SignedVerificationClaimV1 {
    pub body: VerificationClaimBodyV1,
    pub claim_id: VerificationClaimIdV1,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ChallengeOpenBodyV1 {
    pub schema_version: u16,
    pub context: ProtocolContextV1,
    pub result_id: ResultIdV1,
    pub execution_receipt_id: ExecutionReceiptIdV1,
    pub challenger_agent_id: AgentIdV1,
    pub challenger_key_id: AgentKeyIdV1,
    pub challenged_statement_digest: Hash32V1,
    pub counter_statement_digest: Hash32V1,
    pub challenge_bond_id: BondIdV1,
    pub challenge_bond_asset_id: Hash32V1,
    pub challenge_bond_amount: u128,
    pub evidence_deadline_height: u64,
    pub response_deadline_height: u64,
    pub decision_deadline_height: u64,
    pub challenge_nonce: Hash32V1,
}

impl ChallengeOpenBodyV1 {
    pub fn challenge_id(&self) -> VerifyChallengeResultV1<ChallengeIdV1> {
        Ok(digest_value("trnm.poco-ai.challenge.v1", self)?.into())
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ActorAuthorizationV1 {
    pub actor_agent_id: AgentIdV1,
    pub actor_key_id: AgentKeyIdV1,
    pub action_digest: Hash32V1,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub enum VerifyCommandV1 {
    AdmitReceipt {
        receipt: SignedExecutionReceiptV1,
    },
    Evaluate {
        result_id: ResultIdV1,
        expected_result_revision: u64,
        decision_round: u32,
        accepted_claims: Vec<SignedVerificationClaimV1>,
        decision: u8,
        decision_nonce: Hash32V1,
    },
    OpenChallenge {
        expected_result_revision: u64,
        body: ChallengeOpenBodyV1,
        authorization: ActorAuthorizationV1,
    },
    AddEvidence {
        challenge_id: ChallengeIdV1,
        expected_challenge_revision: u64,
        expected_result_revision: u64,
        evidence_artifact_id: Hash32V1,
        availability_certificate_id: Hash32V1,
        authorization: ActorAuthorizationV1,
    },
    Respond {
        challenge_id: ChallengeIdV1,
        expected_challenge_revision: u64,
        expected_result_revision: u64,
        response_statement_digest: Hash32V1,
        authorization: ActorAuthorizationV1,
    },
    Adjudicate {
        challenge_id: ChallengeIdV1,
        expected_challenge_revision: u64,
        expected_result_revision: u64,
        decision_round: u32,
        accepted_claims: Vec<SignedVerificationClaimV1>,
        decision: u8,
        decision_nonce: Hash32V1,
    },
}

impl VerifyCommandV1 {
    pub const fn operation_kind(&self) -> u16 {
        match self {
            Self::AdmitReceipt { .. } => 10,
            Self::Evaluate { .. } => 22,
            Self::OpenChallenge { .. } => 11,
            Self::AddEvidence { .. } | Self::Respond { .. } | Self::Adjudicate { .. } => 23,
        }
    }

    pub fn operation_id(&self) -> VerifyChallengeResultV1<VerifyOperationIdV1> {
        Ok(digest_value("trnm.poco-ai.verify-challenge-operation.candidate.v1", self)?.into())
    }

    #[cfg(test)]
    pub(crate) fn mutate_actor_authorization_for_test(
        &mut self,
        mutate: impl FnOnce(&mut ActorAuthorizationV1),
    ) {
        match self {
            Self::OpenChallenge { authorization, .. }
            | Self::AddEvidence { authorization, .. }
            | Self::Respond { authorization, .. } => mutate(authorization),
            Self::AdmitReceipt { .. } | Self::Evaluate { .. } | Self::Adjudicate { .. } => {
                panic!("command has no actor authorization")
            }
        }
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ResultStateV1 {
    pub result_id: ResultIdV1,
    pub execution_receipt_id: ExecutionReceiptIdV1,
    pub revision: u64,
    pub status: u8,
    pub accepted_height: u64,
    pub challenge_close_height: Option<u64>,
    pub verification_statement_digest: Option<Hash32V1>,
    pub verification_evidence_root: Option<Hash32V1>,
    pub required_da_policy_hash: Hash32V1,
    pub transition_history: Vec<Hash32V1>,
    pub challenge_id: Option<ChallengeIdV1>,
    pub open_challenge_count: u32,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ChallengeStateV1 {
    pub challenge_id: ChallengeIdV1,
    pub result_id: ResultIdV1,
    pub revision: u64,
    pub status: u8,
    pub opened_height: u64,
    pub evidence_deadline_height: u64,
    pub response_deadline_height: u64,
    pub decision_deadline_height: u64,
    pub evidence_entries: Vec<(Hash32V1, Hash32V1)>,
    pub response_statements: Vec<Hash32V1>,
    pub decision_claim_ids: Vec<VerificationClaimIdV1>,
    pub last_transition_hash: Hash32V1,
    pub terminal_height: Option<u64>,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct ChallengeBondStateV1 {
    pub bond_id: BondIdV1,
    pub funded: u128,
    pub available: u128,
    pub held: u128,
    pub released: u128,
    pub slashed: u128,
    pub version: u64,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct VerifyKernelStateV1 {
    pub receipt: Option<SignedExecutionReceiptV1>,
    pub result: Option<ResultStateV1>,
    pub challenge: Option<ChallengeStateV1>,
    pub bond: ChallengeBondStateV1,
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub struct VerifyTransitionReceiptV1 {
    pub schema_version: u16,
    pub store_id: Hash32V1,
    pub sequence: u64,
    pub operation_id: VerifyOperationIdV1,
    pub operation_kind: u16,
    pub order_height: u64,
    pub order_block_id: Hash32V1,
    pub post_state_root: Hash32V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyCommitFaultV1 {
    NotAppliedAckLost,
    AppliedAckLost,
    ThirdState,
}
