use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use trnm_protocol::{
    account_key, fee_policy_key, monetary_state_key, result_commitment_hex, task_key, AccountV1,
    CanonicalCommandV1, CanonicalTxV1, FeePolicyV1, MonetaryStateV1, TaskStatusV1, TaskV1,
    ACCOUNT_OBJECT_TYPE_V1, FEE_COLLECTOR_ACCOUNT_V1, FEE_POLICY_OBJECT_TYPE_V1,
    MONETARY_STATE_OBJECT_TYPE_V1, TASK_OBJECT_TYPE_V1,
};

mod paper_raid;
mod research;
pub use paper_raid::{
    execute_paper_raid_finality, paper_raid_finality_applied_command_key,
    paper_raid_finality_commitment_key, paper_raid_finality_evaluation_index_key,
    paper_raid_finality_submission_index_key, PAPER_RAID_FINALITY_APPLIED_COMMAND_OBJECT_TYPE_V2,
    PAPER_RAID_FINALITY_COMMITMENT_OBJECT_TYPE_V2,
    PAPER_RAID_FINALITY_EVALUATION_INDEX_OBJECT_TYPE_V2,
    PAPER_RAID_FINALITY_SUBMISSION_INDEX_OBJECT_TYPE_V2,
};
pub use research::{execute_research, research_genesis_mutation};

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("protocol validation failed: {0}")]
    Protocol(String),
    #[error("transaction sender does not match signed envelope")]
    SenderMismatch,
    #[error("research signer role does not match signed command")]
    ResearchRoleMismatch,
    #[error("research command chain does not match execution context")]
    ResearchChainMismatch,
    #[error("research protocol genesis authority set is missing")]
    ResearchAuthoritySetMissing,
    #[error("research protocol state transition failed: {0}")]
    ResearchState(String),
    #[error("research command id was replayed with altered signed bytes")]
    ResearchAlteredReplay,
    #[error("research command was already applied")]
    ResearchCommandReplay,
    #[error("research state mirror {0} is missing or inconsistent")]
    ResearchMirrorMismatch(String),
    #[error("legacy Research V1 accepted-work and claim settlement lanes are locked")]
    LegacyResearchSettlementLocked,
    #[error("Paper Raid finality signer role does not match the signed command")]
    PaperRaidFinalityRoleMismatch,
    #[error("Paper Raid finality command chain does not match execution context")]
    PaperRaidFinalityChainMismatch,
    #[error("Paper Raid finality signer is not a genesis Hepta authority")]
    PaperRaidFinalityUnauthorizedAuthority,
    #[error("Paper Raid settlement eligibility remains locked in finality ingress v2")]
    PaperRaidFinalityEligibilityLocked,
    #[error("Paper Raid finality state transition failed: {0}")]
    PaperRaidFinalityState(String),
    #[error("Paper Raid finality command id was replayed with altered signed bytes")]
    PaperRaidFinalityAlteredReplay,
    #[error("Paper Raid finality command was already applied")]
    PaperRaidFinalityCommandReplay,
    #[error("Paper Raid finality commitment already exists")]
    PaperRaidFinalityCommitmentExists,
    #[error("Paper Raid finality already exists for this Paper submission")]
    PaperRaidFinalitySubmissionExists,
    #[error("Paper Raid finality already exists for this evaluation")]
    PaperRaidFinalityEvaluationExists,
    #[error(
        "Paper Raid finality block time {block_time_unix_s} precedes required finality time {required_unix_s}"
    )]
    PaperRaidFinalityTimeNotReached {
        block_time_unix_s: u64,
        required_unix_s: u64,
    },
    #[error("Paper Raid finality state mirror {0} is missing or inconsistent")]
    PaperRaidFinalityMirrorMismatch(String),
    #[error("operator role required")]
    OperatorRequired,
    #[error("account nonce mismatch: expected {expected}, received {received}")]
    NonceMismatch { expected: u64, received: u64 },
    #[error("account nonce exhausted")]
    NonceExhausted,
    #[error("gas limit exceeded: required {required}, limit {limit}")]
    GasLimitExceeded { required: u64, limit: u64 },
    #[error("fee limit exceeded: required {required}, limit {limit}")]
    FeeLimitExceeded { required: u128, limit: u128 },
    #[error("insufficient balance for {account}: required {required}, available {available}")]
    InsufficientBalance {
        account: String,
        required: u128,
        available: u128,
    },
    #[error("object {0} has an unexpected type")]
    ObjectType(String),
    #[error("decode object {0}: {1}")]
    DecodeObject(String, String),
    #[error("encode object: {0}")]
    EncodeObject(String),
    #[error("task already exists")]
    TaskAlreadyExists,
    #[error("task not found")]
    TaskNotFound,
    #[error("invalid task transition")]
    InvalidTaskTransition,
    #[error("task authority mismatch")]
    TaskAuthorityMismatch,
    #[error("task result deadline exceeded")]
    DeadlineExceeded,
    #[error("task challenge window is still open")]
    ChallengeWindowOpen,
    #[error("task challenge window is closed")]
    ChallengeWindowClosed,
    #[error("task is not eligible for expiry")]
    TaskExpiryUnavailable,
    #[error("worker must accept assignment with its own signed transaction")]
    WorkerAcceptanceRequired,
    #[error("the same account cannot occupy conflicting task roles")]
    ConflictingTaskRole,
    #[error("reserved system account cannot sign transactions")]
    ReservedSystemAccount,
    #[error("object version exhausted")]
    ObjectVersionExhausted,
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
}

impl RuntimeError {
    /// Stable machine-readable identifier for transaction simulation and RPC clients.
    ///
    /// Display strings remain diagnostic and may include transaction-specific values;
    /// callers should branch on this code instead.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Protocol(_) => "protocol_validation_failed",
            Self::SenderMismatch => "sender_mismatch",
            Self::ResearchRoleMismatch => "research_role_mismatch",
            Self::ResearchChainMismatch => "research_chain_mismatch",
            Self::ResearchAuthoritySetMissing => "research_authority_set_missing",
            Self::ResearchState(_) => "research_state_failed",
            Self::ResearchAlteredReplay => "research_altered_replay",
            Self::ResearchCommandReplay => "research_command_replay",
            Self::ResearchMirrorMismatch(_) => "research_mirror_mismatch",
            Self::LegacyResearchSettlementLocked => "legacy_research_settlement_locked",
            Self::PaperRaidFinalityRoleMismatch => "paper_raid_finality_role_mismatch",
            Self::PaperRaidFinalityChainMismatch => "paper_raid_finality_chain_mismatch",
            Self::PaperRaidFinalityUnauthorizedAuthority => {
                "paper_raid_finality_unauthorized_authority"
            }
            Self::PaperRaidFinalityEligibilityLocked => "paper_raid_finality_eligibility_locked",
            Self::PaperRaidFinalityState(_) => "paper_raid_finality_state_failed",
            Self::PaperRaidFinalityAlteredReplay => "paper_raid_finality_altered_replay",
            Self::PaperRaidFinalityCommandReplay => "paper_raid_finality_command_replay",
            Self::PaperRaidFinalityCommitmentExists => "paper_raid_finality_commitment_exists",
            Self::PaperRaidFinalitySubmissionExists => "paper_raid_finality_submission_exists",
            Self::PaperRaidFinalityEvaluationExists => "paper_raid_finality_evaluation_exists",
            Self::PaperRaidFinalityTimeNotReached { .. } => "paper_raid_finality_time_not_reached",
            Self::PaperRaidFinalityMirrorMismatch(_) => "paper_raid_finality_mirror_mismatch",
            Self::OperatorRequired => "operator_required",
            Self::NonceMismatch { .. } => "nonce_mismatch",
            Self::NonceExhausted => "nonce_exhausted",
            Self::GasLimitExceeded { .. } => "gas_limit_exceeded",
            Self::FeeLimitExceeded { .. } => "fee_limit_exceeded",
            Self::InsufficientBalance { .. } => "insufficient_balance",
            Self::ObjectType(_) => "object_type_mismatch",
            Self::DecodeObject(_, _) => "object_decode_failed",
            Self::EncodeObject(_) => "object_encode_failed",
            Self::TaskAlreadyExists => "task_already_exists",
            Self::TaskNotFound => "task_not_found",
            Self::InvalidTaskTransition => "invalid_task_transition",
            Self::TaskAuthorityMismatch => "task_authority_mismatch",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::ChallengeWindowOpen => "challenge_window_open",
            Self::ChallengeWindowClosed => "challenge_window_closed",
            Self::TaskExpiryUnavailable => "task_expiry_unavailable",
            Self::WorkerAcceptanceRequired => "worker_acceptance_required",
            Self::ConflictingTaskRole => "conflicting_task_role",
            Self::ReservedSystemAccount => "reserved_system_account",
            Self::ObjectVersionExhausted => "object_version_exhausted",
            Self::ArithmeticOverflow => "arithmetic_overflow",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateObject {
    pub object_type: String,
    pub version: u64,
    pub value_bytes: Vec<u8>,
}

pub trait StateView {
    fn get(&self, object_key_hex: &str) -> Option<StateObject>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeMutation {
    pub object_key_hex: String,
    pub object_type: String,
    pub expected_version: Option<u64>,
    pub next_version: u64,
    pub value_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub kind: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeReceipt {
    pub gas_used: u64,
    pub fee_charged: u128,
    pub events: Vec<RuntimeEvent>,
    pub mutations: Vec<RuntimeMutation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceEstimate {
    pub gas_used: u64,
    pub fee_estimate: u128,
}

#[derive(Debug, Clone, Copy)]
pub struct ExecutionContext<'a> {
    pub height: u64,
    pub chain_id: &'a str,
    pub signer_id: &'a str,
    pub signer_role: &'a str,
    pub payload_len: usize,
}

struct Loaded<T> {
    version: Option<u64>,
    value: T,
    dirty: bool,
}

struct ChallengeSettlement {
    client: String,
    worker: String,
    consumer: Option<String>,
    challenger: String,
    reward: u128,
    worker_stake: u128,
    consumption_payment: u128,
    challenge_bond: u128,
}

struct RuntimeState<'a> {
    view: &'a dyn StateView,
    accounts: BTreeMap<String, Loaded<AccountV1>>,
    tasks: BTreeMap<String, Loaded<TaskV1>>,
    policy: Option<Loaded<FeePolicyV1>>,
    monetary_state: Option<Loaded<MonetaryStateV1>>,
}

impl<'a> RuntimeState<'a> {
    fn new(view: &'a dyn StateView) -> Self {
        Self {
            view,
            accounts: BTreeMap::new(),
            tasks: BTreeMap::new(),
            policy: None,
            monetary_state: None,
        }
    }

    fn policy(&mut self) -> Result<&mut Loaded<FeePolicyV1>, RuntimeError> {
        if self.policy.is_none() {
            self.policy = Some(load_or_default(
                self.view,
                &fee_policy_key(),
                FEE_POLICY_OBJECT_TYPE_V1,
                FeePolicyV1::default(),
            )?);
        }
        Ok(self.policy.as_mut().expect("policy initialized"))
    }

    fn account(&mut self, account: &str) -> Result<&mut Loaded<AccountV1>, RuntimeError> {
        if !self.accounts.contains_key(account) {
            let loaded = load_or_default(
                self.view,
                &account_key(account),
                ACCOUNT_OBJECT_TYPE_V1,
                AccountV1 {
                    account: account.to_string(),
                    balance: 0,
                    nonce: 0,
                },
            )?;
            self.accounts.insert(account.to_string(), loaded);
        }
        Ok(self.accounts.get_mut(account).expect("account initialized"))
    }

    fn monetary_state(&mut self) -> Result<&mut Loaded<MonetaryStateV1>, RuntimeError> {
        if self.monetary_state.is_none() {
            self.monetary_state = Some(load_or_default(
                self.view,
                &monetary_state_key(),
                MONETARY_STATE_OBJECT_TYPE_V1,
                MonetaryStateV1::default(),
            )?);
        }
        Ok(self
            .monetary_state
            .as_mut()
            .expect("monetary state initialized"))
    }

    fn existing_task(&mut self, task_id: &str) -> Result<&mut Loaded<TaskV1>, RuntimeError> {
        if !self.tasks.contains_key(task_id) {
            let key = task_key(task_id);
            let object = self.view.get(&key).ok_or(RuntimeError::TaskNotFound)?;
            ensure_type(&key, &object, TASK_OBJECT_TYPE_V1)?;
            let value = serde_json::from_slice(&object.value_bytes)
                .map_err(|error| RuntimeError::DecodeObject(key, error.to_string()))?;
            self.tasks.insert(
                task_id.to_string(),
                Loaded {
                    version: Some(object.version),
                    value,
                    dirty: false,
                },
            );
        }
        Ok(self.tasks.get_mut(task_id).expect("task initialized"))
    }

    fn insert_task(&mut self, task: TaskV1) -> Result<(), RuntimeError> {
        let key = task_key(&task.task_id);
        if self.tasks.contains_key(&task.task_id) || self.view.get(&key).is_some() {
            return Err(RuntimeError::TaskAlreadyExists);
        }
        self.tasks.insert(
            task.task_id.clone(),
            Loaded {
                version: None,
                value: task,
                dirty: true,
            },
        );
        Ok(())
    }

    fn debit(&mut self, account: &str, amount: u128) -> Result<(), RuntimeError> {
        let loaded = self.account(account)?;
        if loaded.value.balance < amount {
            return Err(RuntimeError::InsufficientBalance {
                account: account.to_string(),
                required: amount,
                available: loaded.value.balance,
            });
        }
        loaded.value.balance -= amount;
        loaded.dirty = true;
        Ok(())
    }

    fn credit(&mut self, account: &str, amount: u128) -> Result<(), RuntimeError> {
        let loaded = self.account(account)?;
        loaded.value.balance = loaded
            .value
            .balance
            .checked_add(amount)
            .ok_or(RuntimeError::ArithmeticOverflow)?;
        loaded.dirty = true;
        Ok(())
    }

    fn issue(&mut self, amount: u128) -> Result<(), RuntimeError> {
        let loaded = self.monetary_state()?;
        loaded.value.total_issued = loaded
            .value
            .total_issued
            .checked_add(amount)
            .ok_or(RuntimeError::ArithmeticOverflow)?;
        loaded.dirty = true;
        Ok(())
    }

    fn into_mutations(self) -> Result<Vec<RuntimeMutation>, RuntimeError> {
        let mut mutations = Vec::new();
        for (account, loaded) in self.accounts {
            if loaded.dirty {
                mutations.push(encode_mutation(
                    account_key(&account),
                    ACCOUNT_OBJECT_TYPE_V1,
                    loaded,
                )?);
            }
        }
        for (task_id, loaded) in self.tasks {
            if loaded.dirty {
                mutations.push(encode_mutation(
                    task_key(&task_id),
                    TASK_OBJECT_TYPE_V1,
                    loaded,
                )?);
            }
        }
        if let Some(loaded) = self.policy {
            if loaded.dirty {
                mutations.push(encode_mutation(
                    fee_policy_key(),
                    FEE_POLICY_OBJECT_TYPE_V1,
                    loaded,
                )?);
            }
        }
        if let Some(loaded) = self.monetary_state {
            if loaded.dirty {
                mutations.push(encode_mutation(
                    monetary_state_key(),
                    MONETARY_STATE_OBJECT_TYPE_V1,
                    loaded,
                )?);
            }
        }
        mutations.sort_by(|left, right| left.object_key_hex.cmp(&right.object_key_hex));
        Ok(mutations)
    }
}

pub fn execute(
    tx: &CanonicalTxV1,
    context: ExecutionContext<'_>,
    view: &dyn StateView,
) -> Result<RuntimeReceipt, RuntimeError> {
    validate_transaction_context(tx, context)?;
    let mut state = RuntimeState::new(view);
    let estimate = estimate_resources_with_state(tx, context, &mut state)?;
    if estimate.gas_used > tx.max_gas {
        return Err(RuntimeError::GasLimitExceeded {
            required: estimate.gas_used,
            limit: tx.max_gas,
        });
    }
    if estimate.fee_estimate > tx.fee_limit {
        return Err(RuntimeError::FeeLimitExceeded {
            required: estimate.fee_estimate,
            limit: tx.fee_limit,
        });
    }

    let expected_nonce = state
        .account(&tx.sender)?
        .value
        .nonce
        .checked_add(1)
        .ok_or(RuntimeError::NonceExhausted)?;
    if tx.nonce != expected_nonce {
        return Err(RuntimeError::NonceMismatch {
            expected: expected_nonce,
            received: tx.nonce,
        });
    }
    if !is_operator_command(&tx.command) {
        state.debit(&tx.sender, estimate.fee_estimate)?;
        state.credit(FEE_COLLECTOR_ACCOUNT_V1, estimate.fee_estimate)?;
    }
    let sender = state.account(&tx.sender)?;
    sender.value.nonce = tx.nonce;
    sender.dirty = true;

    let mut events = Vec::new();
    apply_command(&mut state, tx, context, &mut events)?;
    Ok(RuntimeReceipt {
        gas_used: estimate.gas_used,
        fee_charged: estimate.fee_estimate,
        events,
        mutations: state.into_mutations()?,
    })
}

/// Computes the exact gas and fee that [`execute`] will charge for the same
/// transaction bytes, execution context, and state view.
///
/// Resource limits, nonce, balance, and command state transitions are not
/// applied here. This lets callers return the required estimate even when a
/// transaction's `max_gas` or `fee_limit` is too low.
pub fn estimate_resources(
    tx: &CanonicalTxV1,
    context: ExecutionContext<'_>,
    view: &dyn StateView,
) -> Result<ResourceEstimate, RuntimeError> {
    validate_transaction_context(tx, context)?;
    estimate_resources_with_state(tx, context, &mut RuntimeState::new(view))
}

fn validate_transaction_context(
    tx: &CanonicalTxV1,
    context: ExecutionContext<'_>,
) -> Result<(), RuntimeError> {
    tx.validate()
        .map_err(|error| RuntimeError::Protocol(error.to_string()))?;
    if tx.sender != context.signer_id {
        return Err(RuntimeError::SenderMismatch);
    }
    if tx.sender == FEE_COLLECTOR_ACCOUNT_V1 {
        return Err(RuntimeError::ReservedSystemAccount);
    }
    if is_operator_command(&tx.command) && context.signer_role != "operator" {
        return Err(RuntimeError::OperatorRequired);
    }
    Ok(())
}

fn estimate_resources_with_state(
    tx: &CanonicalTxV1,
    context: ExecutionContext<'_>,
    state: &mut RuntimeState<'_>,
) -> Result<ResourceEstimate, RuntimeError> {
    let operator_command = is_operator_command(&tx.command);
    // Recovery-capable operator commands use the immutable bootstrap gas schedule.
    // A corrupt or historically unsafe on-chain policy therefore cannot prevent an
    // authorized operator from replacing it.
    let policy = if operator_command {
        FeePolicyV1::default()
    } else {
        state.policy()?.value.clone()
    };
    let payload_gas = u64::try_from(context.payload_len)
        .unwrap_or(u64::MAX)
        .checked_mul(policy.byte_gas)
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    let gas_used = policy
        .base_gas
        .checked_add(payload_gas)
        .and_then(|gas| gas.checked_add(tx.command.operation_gas()))
        .ok_or(RuntimeError::ArithmeticOverflow)?;
    let fee = if operator_command {
        0
    } else {
        u128::from(gas_used)
            .checked_mul(policy.gas_price)
            .ok_or(RuntimeError::ArithmeticOverflow)?
    };
    Ok(ResourceEstimate {
        gas_used,
        fee_estimate: fee,
    })
}

fn is_operator_command(command: &CanonicalCommandV1) -> bool {
    matches!(
        command,
        CanonicalCommandV1::CreditAccount { .. }
            | CanonicalCommandV1::SetFeePolicy { .. }
            | CanonicalCommandV1::DistributeFees { .. }
    )
}

fn apply_command(
    state: &mut RuntimeState<'_>,
    tx: &CanonicalTxV1,
    context: ExecutionContext<'_>,
    events: &mut Vec<RuntimeEvent>,
) -> Result<(), RuntimeError> {
    match &tx.command {
        CanonicalCommandV1::CreditAccount { account, amount } => {
            state.credit(account, *amount)?;
            state.issue(*amount)?;
            events.push(event("account_credited", [("account", account)]));
        }
        CanonicalCommandV1::Transfer { to, amount } => {
            state.debit(&tx.sender, *amount)?;
            state.credit(to, *amount)?;
            events.push(event("transfer", [("from", &tx.sender), ("to", to)]));
        }
        CanonicalCommandV1::CreateTask {
            task_id,
            reward,
            worker_stake,
            result_deadline_height,
            challenge_window_blocks,
        } => {
            if *result_deadline_height <= context.height {
                return Err(RuntimeError::DeadlineExceeded);
            }
            state.debit(&tx.sender, *reward)?;
            state.insert_task(TaskV1 {
                task_id: task_id.clone(),
                client: tx.sender.clone(),
                worker: None,
                reward: *reward,
                worker_stake: *worker_stake,
                result_deadline_height: *result_deadline_height,
                challenge_window_blocks: *challenge_window_blocks,
                status: TaskStatusV1::Open,
                commitment_hex: None,
                result_hash_hex: None,
                reveal_salt_hex: None,
                challenge_deadline_height: None,
                consumer: None,
                consumed_units: 0,
                consumption_payment: 0,
                receipt_hash_hex: None,
                challenger: None,
                challenge_bond: 0,
                evidence_hash_hex: None,
            })?;
            events.push(event("task_created", [("task_id", task_id)]));
        }
        CanonicalCommandV1::AssignTask { task_id, worker } => {
            if worker != &tx.sender {
                return Err(RuntimeError::WorkerAcceptanceRequired);
            }
            let worker_stake = {
                let task = state.existing_task(task_id)?;
                if task.value.status != TaskStatusV1::Open {
                    return Err(RuntimeError::InvalidTaskTransition);
                }
                if context.height >= task.value.result_deadline_height {
                    return Err(RuntimeError::DeadlineExceeded);
                }
                task.value.worker_stake
            };
            state.debit(&tx.sender, worker_stake)?;
            let task = state.existing_task(task_id)?;
            task.value.worker = Some(worker.clone());
            task.value.status = TaskStatusV1::Assigned;
            task.dirty = true;
            events.push(event(
                "task_assigned",
                [("task_id", task_id), ("worker", worker)],
            ));
        }
        CanonicalCommandV1::CommitResult {
            task_id,
            commitment_hex,
        } => {
            let task = state.existing_task(task_id)?;
            require_worker(&task.value, &tx.sender)?;
            if task.value.status != TaskStatusV1::Assigned {
                return Err(RuntimeError::InvalidTaskTransition);
            }
            if context.height >= task.value.result_deadline_height {
                return Err(RuntimeError::DeadlineExceeded);
            }
            task.value.commitment_hex = Some(commitment_hex.clone());
            task.value.status = TaskStatusV1::Committed;
            task.dirty = true;
            events.push(event("result_committed", [("task_id", task_id)]));
        }
        CanonicalCommandV1::RevealResult {
            task_id,
            result_hash_hex,
            reveal_salt_hex,
        } => {
            let task = state.existing_task(task_id)?;
            require_worker(&task.value, &tx.sender)?;
            if task.value.status != TaskStatusV1::Committed {
                return Err(RuntimeError::InvalidTaskTransition);
            }
            if context.height >= task.value.result_deadline_height {
                return Err(RuntimeError::DeadlineExceeded);
            }
            let expected_commitment =
                result_commitment_hex(task_id, &tx.sender, result_hash_hex, reveal_salt_hex)
                    .map_err(|error| RuntimeError::Protocol(error.to_string()))?;
            if task.value.commitment_hex.as_deref() != Some(expected_commitment.as_str()) {
                return Err(RuntimeError::InvalidTaskTransition);
            }
            let challenge_deadline_height = context
                .height
                .checked_add(task.value.challenge_window_blocks)
                .ok_or(RuntimeError::ArithmeticOverflow)?;
            task.value.result_hash_hex = Some(result_hash_hex.clone());
            task.value.reveal_salt_hex = Some(reveal_salt_hex.clone());
            task.value.challenge_deadline_height = Some(challenge_deadline_height);
            task.value.status = TaskStatusV1::Revealed;
            task.dirty = true;
            events.push(event("result_revealed", [("task_id", task_id)]));
        }
        CanonicalCommandV1::RecordConsumption {
            task_id,
            units,
            payment,
            receipt_hash_hex,
        } => {
            let worker = {
                let task = state.existing_task(task_id)?;
                if task.value.status != TaskStatusV1::Revealed {
                    return Err(RuntimeError::InvalidTaskTransition);
                }
                if context.height
                    > task
                        .value
                        .challenge_deadline_height
                        .ok_or(RuntimeError::InvalidTaskTransition)?
                {
                    return Err(RuntimeError::ChallengeWindowClosed);
                }
                task.value
                    .worker
                    .clone()
                    .ok_or(RuntimeError::InvalidTaskTransition)?
            };
            if worker == tx.sender {
                return Err(RuntimeError::ConflictingTaskRole);
            }
            state.debit(&tx.sender, *payment)?;
            let task = state.existing_task(task_id)?;
            task.value.consumer = Some(tx.sender.clone());
            task.value.consumed_units = *units;
            task.value.consumption_payment = *payment;
            task.value.receipt_hash_hex = Some(receipt_hash_hex.clone());
            task.value.status = TaskStatusV1::Consumed;
            task.dirty = true;
            events.push(event("consumption_recorded", [("task_id", task_id)]));
        }
        CanonicalCommandV1::OpenChallenge {
            task_id,
            bond,
            evidence_hash_hex,
        } => {
            let worker = {
                let task = state.existing_task(task_id)?;
                if !matches!(
                    task.value.status,
                    TaskStatusV1::Revealed | TaskStatusV1::Consumed
                ) {
                    return Err(RuntimeError::InvalidTaskTransition);
                }
                if context.height
                    > task
                        .value
                        .challenge_deadline_height
                        .ok_or(RuntimeError::InvalidTaskTransition)?
                {
                    return Err(RuntimeError::ChallengeWindowClosed);
                }
                task.value
                    .worker
                    .clone()
                    .ok_or(RuntimeError::InvalidTaskTransition)?
            };
            if worker == tx.sender {
                return Err(RuntimeError::ConflictingTaskRole);
            }
            state.debit(&tx.sender, *bond)?;
            let task = state.existing_task(task_id)?;
            task.value.challenger = Some(tx.sender.clone());
            task.value.challenge_bond = *bond;
            task.value.evidence_hash_hex = Some(evidence_hash_hex.clone());
            task.value.status = TaskStatusV1::Challenged;
            task.dirty = true;
            events.push(event("challenge_opened", [("task_id", task_id)]));
        }
        CanonicalCommandV1::ResolveChallenge {
            task_id,
            accept_challenge,
        } => {
            if context.signer_role != "operator" {
                return Err(RuntimeError::OperatorRequired);
            }
            let settlement = {
                let task = state.existing_task(task_id)?;
                if task.value.status != TaskStatusV1::Challenged {
                    return Err(RuntimeError::InvalidTaskTransition);
                }
                ChallengeSettlement {
                    client: task.value.client.clone(),
                    worker: task
                        .value
                        .worker
                        .clone()
                        .ok_or(RuntimeError::InvalidTaskTransition)?,
                    consumer: task.value.consumer.clone(),
                    challenger: task
                        .value
                        .challenger
                        .clone()
                        .ok_or(RuntimeError::InvalidTaskTransition)?,
                    reward: task.value.reward,
                    worker_stake: task.value.worker_stake,
                    consumption_payment: task.value.consumption_payment,
                    challenge_bond: task.value.challenge_bond,
                }
            };
            if *accept_challenge {
                state.credit(&settlement.client, settlement.reward)?;
                let challenger_payout = settlement
                    .worker_stake
                    .checked_add(settlement.challenge_bond)
                    .ok_or(RuntimeError::ArithmeticOverflow)?;
                state.credit(&settlement.challenger, challenger_payout)?;
                if settlement.consumption_payment > 0 {
                    let consumer = settlement
                        .consumer
                        .as_deref()
                        .ok_or(RuntimeError::InvalidTaskTransition)?;
                    state.credit(consumer, settlement.consumption_payment)?;
                }
            } else {
                let worker_payout = settlement
                    .reward
                    .checked_add(settlement.worker_stake)
                    .and_then(|value| value.checked_add(settlement.consumption_payment))
                    .and_then(|value| value.checked_add(settlement.challenge_bond))
                    .ok_or(RuntimeError::ArithmeticOverflow)?;
                state.credit(&settlement.worker, worker_payout)?;
            }
            let task = state.existing_task(task_id)?;
            task.value.status = if *accept_challenge {
                TaskStatusV1::ResolvedForChallenger
            } else {
                TaskStatusV1::ResolvedForWorker
            };
            task.dirty = true;
            events.push(event("challenge_resolved", [("task_id", task_id)]));
        }
        CanonicalCommandV1::SettleTask { task_id } => {
            let (client, worker, payout, challenge_deadline_height) = {
                let task = state.existing_task(task_id)?;
                if task.value.status != TaskStatusV1::Consumed {
                    return Err(RuntimeError::InvalidTaskTransition);
                }
                (
                    task.value.client.clone(),
                    task.value
                        .worker
                        .clone()
                        .ok_or(RuntimeError::InvalidTaskTransition)?,
                    task.value
                        .reward
                        .checked_add(task.value.worker_stake)
                        .and_then(|value| value.checked_add(task.value.consumption_payment))
                        .ok_or(RuntimeError::ArithmeticOverflow)?,
                    task.value
                        .challenge_deadline_height
                        .ok_or(RuntimeError::InvalidTaskTransition)?,
                )
            };
            if tx.sender != client && context.signer_role != "operator" {
                return Err(RuntimeError::TaskAuthorityMismatch);
            }
            if context.height <= challenge_deadline_height {
                return Err(RuntimeError::ChallengeWindowOpen);
            }
            state.credit(&worker, payout)?;
            let task = state.existing_task(task_id)?;
            task.value.status = TaskStatusV1::Settled;
            task.dirty = true;
            events.push(event("task_settled", [("task_id", task_id)]));
        }
        CanonicalCommandV1::ExpireTask { task_id } => {
            let (client, worker, reward, worker_stake, outcome) = {
                let task = state.existing_task(task_id)?;
                match task.value.status {
                    TaskStatusV1::Open if context.height >= task.value.result_deadline_height => (
                        task.value.client.clone(),
                        None,
                        task.value.reward,
                        0,
                        "open_refund",
                    ),
                    TaskStatusV1::Assigned | TaskStatusV1::Committed
                        if context.height >= task.value.result_deadline_height =>
                    {
                        (
                            task.value.client.clone(),
                            task.value.worker.clone(),
                            task.value.reward,
                            task.value.worker_stake,
                            "worker_deadline_slash",
                        )
                    }
                    TaskStatusV1::Revealed
                        if context.height
                            > task
                                .value
                                .challenge_deadline_height
                                .ok_or(RuntimeError::InvalidTaskTransition)? =>
                    {
                        (
                            task.value.client.clone(),
                            task.value.worker.clone(),
                            task.value.reward,
                            task.value.worker_stake,
                            "unconsumed_refund",
                        )
                    }
                    _ => return Err(RuntimeError::TaskExpiryUnavailable),
                }
            };
            state.credit(&client, reward)?;
            if worker_stake > 0 {
                let worker = worker.ok_or(RuntimeError::InvalidTaskTransition)?;
                if outcome == "worker_deadline_slash" {
                    state.credit(&client, worker_stake)?;
                } else {
                    state.credit(&worker, worker_stake)?;
                }
            }
            let task = state.existing_task(task_id)?;
            task.value.status = TaskStatusV1::Expired;
            task.dirty = true;
            events.push(event(
                "task_expired",
                [("task_id", task_id), ("outcome", outcome)],
            ));
        }
        CanonicalCommandV1::SetFeePolicy {
            gas_price,
            base_gas,
            byte_gas,
        } => {
            let policy = state.policy()?;
            policy.value = FeePolicyV1 {
                gas_price: *gas_price,
                base_gas: *base_gas,
                byte_gas: *byte_gas,
            };
            policy.dirty = true;
            events.push(event("fee_policy_updated", []));
        }
        CanonicalCommandV1::DistributeFees { to, amount } => {
            state.debit(FEE_COLLECTOR_ACCOUNT_V1, *amount)?;
            state.credit(to, *amount)?;
            events.push(event("fees_distributed", [("to", to)]));
        }
    }
    Ok(())
}

fn require_worker(task: &TaskV1, sender: &str) -> Result<(), RuntimeError> {
    if task.worker.as_deref() != Some(sender) {
        return Err(RuntimeError::TaskAuthorityMismatch);
    }
    Ok(())
}

fn event<'a, const N: usize>(kind: &str, attributes: [(&'a str, &'a str); N]) -> RuntimeEvent {
    RuntimeEvent {
        kind: kind.to_string(),
        attributes: attributes
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
    }
}

fn load_or_default<T>(
    view: &dyn StateView,
    key: &str,
    object_type: &str,
    default: T,
) -> Result<Loaded<T>, RuntimeError>
where
    T: for<'de> Deserialize<'de>,
{
    match view.get(key) {
        Some(object) => {
            ensure_type(key, &object, object_type)?;
            let value = serde_json::from_slice(&object.value_bytes)
                .map_err(|error| RuntimeError::DecodeObject(key.to_string(), error.to_string()))?;
            Ok(Loaded {
                version: Some(object.version),
                value,
                dirty: false,
            })
        }
        None => Ok(Loaded {
            version: None,
            value: default,
            dirty: false,
        }),
    }
}

fn ensure_type(key: &str, object: &StateObject, expected: &str) -> Result<(), RuntimeError> {
    if object.object_type != expected {
        return Err(RuntimeError::ObjectType(key.to_string()));
    }
    Ok(())
}

fn encode_mutation<T: Serialize>(
    object_key_hex: String,
    object_type: &str,
    loaded: Loaded<T>,
) -> Result<RuntimeMutation, RuntimeError> {
    let next_version = loaded
        .version
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(RuntimeError::ObjectVersionExhausted)?;
    Ok(RuntimeMutation {
        object_key_hex,
        object_type: object_type.to_string(),
        expected_version: loaded.version,
        next_version,
        value_bytes: serde_json::to_vec(&loaded.value)
            .map_err(|error| RuntimeError::EncodeObject(error.to_string()))?,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use sha2::{Digest, Sha256};
    use trnm_protocol::{
        monetary_state_key, result_commitment_hex, CanonicalCommandV1, MonetaryStateV1,
        CANONICAL_TX_SCHEMA_V1,
    };

    #[derive(Default)]
    struct MemoryView(BTreeMap<String, StateObject>);

    impl StateView for MemoryView {
        fn get(&self, object_key_hex: &str) -> Option<StateObject> {
            self.0.get(object_key_hex).cloned()
        }
    }

    impl MemoryView {
        fn apply(&mut self, receipt: RuntimeReceipt) {
            for mutation in receipt.mutations {
                assert_eq!(
                    self.0
                        .get(&mutation.object_key_hex)
                        .map(|item| item.version),
                    mutation.expected_version
                );
                self.0.insert(
                    mutation.object_key_hex,
                    StateObject {
                        object_type: mutation.object_type,
                        version: mutation.next_version,
                        value_bytes: mutation.value_bytes,
                    },
                );
            }
        }

        fn account(&self, account: &str) -> AccountV1 {
            serde_json::from_slice(&self.0[&account_key(account)].value_bytes).unwrap()
        }

        fn task(&self, task_id: &str) -> TaskV1 {
            serde_json::from_slice(&self.0[&task_key(task_id)].value_bytes).unwrap()
        }

        fn monetary_state(&self) -> MonetaryStateV1 {
            serde_json::from_slice(&self.0[&monetary_state_key()].value_bytes).unwrap()
        }

        fn economic_total(&self) -> u128 {
            let account_total: u128 = self
                .0
                .values()
                .filter(|object| object.object_type == ACCOUNT_OBJECT_TYPE_V1)
                .map(|object| {
                    serde_json::from_slice::<AccountV1>(&object.value_bytes)
                        .unwrap()
                        .balance
                })
                .sum();
            let escrow_total: u128 = self
                .0
                .values()
                .filter(|object| object.object_type == TASK_OBJECT_TYPE_V1)
                .map(|object| {
                    let task: TaskV1 = serde_json::from_slice(&object.value_bytes).unwrap();
                    match task.status {
                        TaskStatusV1::Open => task.reward,
                        TaskStatusV1::Assigned
                        | TaskStatusV1::Committed
                        | TaskStatusV1::Revealed => {
                            task.reward.checked_add(task.worker_stake).unwrap()
                        }
                        TaskStatusV1::Consumed => task
                            .reward
                            .checked_add(task.worker_stake)
                            .and_then(|value| value.checked_add(task.consumption_payment))
                            .unwrap(),
                        TaskStatusV1::Challenged => task
                            .reward
                            .checked_add(task.worker_stake)
                            .and_then(|value| value.checked_add(task.consumption_payment))
                            .and_then(|value| value.checked_add(task.challenge_bond))
                            .unwrap(),
                        TaskStatusV1::Settled
                        | TaskStatusV1::ResolvedForWorker
                        | TaskStatusV1::ResolvedForChallenger
                        | TaskStatusV1::Expired => 0,
                    }
                })
                .sum();
            account_total.checked_add(escrow_total).unwrap()
        }
    }

    fn tx(sender: &str, nonce: u64, command: CanonicalCommandV1) -> CanonicalTxV1 {
        CanonicalTxV1 {
            schema: CANONICAL_TX_SCHEMA_V1.to_string(),
            sender: sender.to_string(),
            nonce,
            max_gas: 100_000,
            fee_limit: 100_000,
            command,
        }
    }

    fn run(view: &mut MemoryView, tx: CanonicalTxV1, height: u64, role: &str) -> RuntimeReceipt {
        let payload = serde_json::to_vec(&tx).unwrap();
        let receipt = execute(
            &tx,
            ExecutionContext {
                height,
                chain_id: "trnm-devnet-v1",
                signer_id: &tx.sender,
                signer_role: role,
                payload_len: payload.len(),
            },
            view,
        )
        .unwrap();
        view.apply(receipt.clone());
        receipt
    }

    fn issue(
        view: &mut MemoryView,
        operator_nonce: u64,
        account: &str,
        amount: u128,
    ) -> RuntimeReceipt {
        run(
            view,
            tx(
                "operator",
                operator_nonce,
                CanonicalCommandV1::CreditAccount {
                    account: account.to_string(),
                    amount,
                },
            ),
            1,
            "operator",
        )
    }

    fn create_task(task_id: &str, challenge_window_blocks: u64) -> CanonicalCommandV1 {
        CanonicalCommandV1::CreateTask {
            task_id: task_id.to_string(),
            reward: 10_000,
            worker_stake: 5_000,
            result_deadline_height: 20,
            challenge_window_blocks,
        }
    }

    fn setup_paid_task(view: &mut MemoryView, challenge_window_blocks: u64) {
        for (nonce, account, amount) in [
            (1, "operator", 10_000),
            (2, "client", 100_000),
            (3, "worker", 20_000),
            (4, "consumer", 30_000),
            (5, "challenger", 10_000),
        ] {
            issue(view, nonce, account, amount);
        }
        run(
            view,
            tx("client", 1, create_task("task-1", challenge_window_blocks)),
            2,
            "hepta",
        );
        run(
            view,
            tx(
                "worker",
                1,
                CanonicalCommandV1::AssignTask {
                    task_id: "task-1".to_string(),
                    worker: "worker".to_string(),
                },
            ),
            3,
            "nakama",
        );
        let result_hash = "11".repeat(32);
        let reveal_salt = "22".repeat(32);
        let commitment =
            result_commitment_hex("task-1", "worker", &result_hash, &reveal_salt).unwrap();
        run(
            view,
            tx(
                "worker",
                2,
                CanonicalCommandV1::CommitResult {
                    task_id: "task-1".to_string(),
                    commitment_hex: commitment,
                },
            ),
            4,
            "nakama",
        );
        run(
            view,
            tx(
                "worker",
                3,
                CanonicalCommandV1::RevealResult {
                    task_id: "task-1".to_string(),
                    result_hash_hex: result_hash,
                    reveal_salt_hex: reveal_salt,
                },
            ),
            5,
            "nakama",
        );
    }

    #[test]
    fn paid_poco_rejected_challenge_preserves_every_issued_unit() {
        let mut view = MemoryView::default();
        setup_paid_task(&mut view, 10);
        let worker_before_consumption = view.account("worker").balance;
        run(
            &mut view,
            tx(
                "consumer",
                1,
                CanonicalCommandV1::RecordConsumption {
                    task_id: "task-1".to_string(),
                    units: 100,
                    payment: 2_000,
                    receipt_hash_hex: "22".repeat(32),
                },
            ),
            6,
            "hepta",
        );
        assert_eq!(view.account("worker").balance, worker_before_consumption);
        run(
            &mut view,
            tx(
                "challenger",
                1,
                CanonicalCommandV1::OpenChallenge {
                    task_id: "task-1".to_string(),
                    bond: 1_000,
                    evidence_hash_hex: "33".repeat(32),
                },
            ),
            7,
            "hepta",
        );
        run(
            &mut view,
            tx(
                "operator",
                6,
                CanonicalCommandV1::ResolveChallenge {
                    task_id: "task-1".to_string(),
                    accept_challenge: false,
                },
            ),
            8,
            "operator",
        );

        let task = view.task("task-1");
        assert_eq!(task.status, TaskStatusV1::ResolvedForWorker);
        assert!(view.account("worker").balance > 20_000);
        assert!(view.account(FEE_COLLECTOR_ACCOUNT_V1).balance > 0);
        assert_eq!(view.economic_total(), view.monetary_state().total_issued);
    }

    #[test]
    fn successful_challenge_refunds_payers_and_slashes_only_worker_stake() {
        let mut view = MemoryView::default();
        setup_paid_task(&mut view, 10);
        let client_after_create = view.account("client").balance;
        let consumer_before = view.account("consumer").balance;
        let worker_after_reveal = view.account("worker").balance;
        run(
            &mut view,
            tx(
                "consumer",
                1,
                CanonicalCommandV1::RecordConsumption {
                    task_id: "task-1".to_string(),
                    units: 100,
                    payment: 2_000,
                    receipt_hash_hex: "33".repeat(32),
                },
            ),
            6,
            "hepta",
        );
        run(
            &mut view,
            tx(
                "challenger",
                1,
                CanonicalCommandV1::OpenChallenge {
                    task_id: "task-1".to_string(),
                    bond: 1_000,
                    evidence_hash_hex: "44".repeat(32),
                },
            ),
            7,
            "hepta",
        );
        run(
            &mut view,
            tx(
                "operator",
                6,
                CanonicalCommandV1::ResolveChallenge {
                    task_id: "task-1".to_string(),
                    accept_challenge: true,
                },
            ),
            8,
            "operator",
        );
        assert_eq!(
            view.task("task-1").status,
            TaskStatusV1::ResolvedForChallenger
        );
        assert_eq!(view.account("client").balance, client_after_create + 10_000);
        assert!(view.account("consumer").balance < consumer_before);
        assert_eq!(view.account("worker").balance, worker_after_reveal);
        assert!(view.account("challenger").balance > 10_000);
        assert_eq!(view.economic_total(), view.monetary_state().total_issued);
    }

    #[test]
    fn task_assignment_requires_worker_signed_acceptance() {
        let mut view = MemoryView::default();
        issue(&mut view, 1, "client", 100_000);
        issue(&mut view, 2, "worker", 20_000);
        run(
            &mut view,
            tx("client", 1, create_task("task-1", 10)),
            2,
            "hepta",
        );
        let malicious = tx(
            "client",
            2,
            CanonicalCommandV1::AssignTask {
                task_id: "task-1".to_string(),
                worker: "worker".to_string(),
            },
        );
        let payload = serde_json::to_vec(&malicious).unwrap();
        assert!(matches!(
            execute(
                &malicious,
                ExecutionContext {
                    height: 3,
                    chain_id: "trnm-devnet-v1",
                    signer_id: "client",
                    signer_role: "hepta",
                    payload_len: payload.len(),
                },
                &view,
            ),
            Err(RuntimeError::WorkerAcceptanceRequired)
        ));
        assert_eq!(view.task("task-1").status, TaskStatusV1::Open);
        assert_eq!(view.account("worker").balance, 20_000);
        run(
            &mut view,
            tx(
                "worker",
                1,
                CanonicalCommandV1::AssignTask {
                    task_id: "task-1".to_string(),
                    worker: "worker".to_string(),
                },
            ),
            3,
            "nakama",
        );
        assert_eq!(view.task("task-1").status, TaskStatusV1::Assigned);
    }

    #[test]
    fn reveal_is_bound_to_salt_and_challenge_window() {
        let mut view = MemoryView::default();
        setup_paid_task(&mut view, 2);
        let task = view.task("task-1");
        assert_eq!(task.challenge_deadline_height, Some(7));

        let self_consumption = tx(
            "worker",
            4,
            CanonicalCommandV1::RecordConsumption {
                task_id: "task-1".to_string(),
                units: 1,
                payment: 1,
                receipt_hash_hex: "33".repeat(32),
            },
        );
        let payload = serde_json::to_vec(&self_consumption).unwrap();
        assert!(matches!(
            execute(
                &self_consumption,
                ExecutionContext {
                    height: 6,
                    chain_id: "trnm-devnet-v1",
                    signer_id: "worker",
                    signer_role: "nakama",
                    payload_len: payload.len(),
                },
                &view,
            ),
            Err(RuntimeError::ConflictingTaskRole)
        ));

        run(
            &mut view,
            tx(
                "consumer",
                1,
                CanonicalCommandV1::RecordConsumption {
                    task_id: "task-1".to_string(),
                    units: 1,
                    payment: 2_000,
                    receipt_hash_hex: "33".repeat(32),
                },
            ),
            6,
            "hepta",
        );
        let early_settle = tx(
            "client",
            2,
            CanonicalCommandV1::SettleTask {
                task_id: "task-1".to_string(),
            },
        );
        let payload = serde_json::to_vec(&early_settle).unwrap();
        assert!(matches!(
            execute(
                &early_settle,
                ExecutionContext {
                    height: 7,
                    chain_id: "trnm-devnet-v1",
                    signer_id: "client",
                    signer_role: "hepta",
                    payload_len: payload.len(),
                },
                &view,
            ),
            Err(RuntimeError::ChallengeWindowOpen)
        ));
        run(&mut view, early_settle, 8, "hepta");
        assert_eq!(view.task("task-1").status, TaskStatusV1::Settled);
        assert_eq!(view.economic_total(), view.monetary_state().total_issued);
    }

    #[test]
    fn forged_reveal_salt_is_rejected_without_state_mutation() {
        let mut view = MemoryView::default();
        issue(&mut view, 1, "client", 100_000);
        issue(&mut view, 2, "worker", 20_000);
        run(
            &mut view,
            tx("client", 1, create_task("task-1", 10)),
            2,
            "hepta",
        );
        run(
            &mut view,
            tx(
                "worker",
                1,
                CanonicalCommandV1::AssignTask {
                    task_id: "task-1".to_string(),
                    worker: "worker".to_string(),
                },
            ),
            3,
            "nakama",
        );
        let result_hash = "11".repeat(32);
        let salt = "22".repeat(32);
        let commitment = result_commitment_hex("task-1", "worker", &result_hash, &salt).unwrap();
        run(
            &mut view,
            tx(
                "worker",
                2,
                CanonicalCommandV1::CommitResult {
                    task_id: "task-1".to_string(),
                    commitment_hex: commitment,
                },
            ),
            4,
            "nakama",
        );
        let forged = tx(
            "worker",
            3,
            CanonicalCommandV1::RevealResult {
                task_id: "task-1".to_string(),
                result_hash_hex: result_hash,
                reveal_salt_hex: "99".repeat(32),
            },
        );
        let payload = serde_json::to_vec(&forged).unwrap();
        assert!(matches!(
            execute(
                &forged,
                ExecutionContext {
                    height: 5,
                    chain_id: "trnm-devnet-v1",
                    signer_id: "worker",
                    signer_role: "nakama",
                    payload_len: payload.len(),
                },
                &view,
            ),
            Err(RuntimeError::InvalidTaskTransition)
        ));
        assert_eq!(view.task("task-1").status, TaskStatusV1::Committed);
    }

    #[test]
    fn rejects_replay_and_underfunded_gas() {
        let mut view = MemoryView::default();
        issue(&mut view, 1, "alice", 10_000);
        let first = tx(
            "alice",
            1,
            CanonicalCommandV1::Transfer {
                to: "bob".to_string(),
                amount: 1,
            },
        );
        run(&mut view, first.clone(), 2, "hepta");
        let payload = serde_json::to_vec(&first).unwrap();
        assert!(matches!(
            execute(
                &first,
                ExecutionContext {
                    height: 3,
                    chain_id: "trnm-devnet-v1",
                    signer_id: "alice",
                    signer_role: "hepta",
                    payload_len: payload.len()
                },
                &view
            ),
            Err(RuntimeError::NonceMismatch { .. })
        ));

        let mut low_gas = tx(
            "alice",
            2,
            CanonicalCommandV1::Transfer {
                to: "bob".to_string(),
                amount: 1,
            },
        );
        low_gas.max_gas = 1;
        let payload = serde_json::to_vec(&low_gas).unwrap();
        assert!(matches!(
            execute(
                &low_gas,
                ExecutionContext {
                    height: 3,
                    chain_id: "trnm-devnet-v1",
                    signer_id: "alice",
                    signer_role: "hepta",
                    payload_len: payload.len()
                },
                &view
            ),
            Err(RuntimeError::GasLimitExceeded { .. })
        ));
        assert_eq!(view.account("alice").nonce, 1);
    }

    #[test]
    fn task_expiry_releases_every_escrow_path_without_minting() {
        let mut worker_fault = MemoryView::default();
        issue(&mut worker_fault, 1, "client", 100_000);
        issue(&mut worker_fault, 2, "worker", 20_000);
        run(
            &mut worker_fault,
            tx("client", 1, create_task("deadline-task", 10)),
            2,
            "hepta",
        );
        run(
            &mut worker_fault,
            tx(
                "worker",
                1,
                CanonicalCommandV1::AssignTask {
                    task_id: "deadline-task".to_string(),
                    worker: "worker".to_string(),
                },
            ),
            3,
            "nakama",
        );
        let too_early = tx(
            "client",
            2,
            CanonicalCommandV1::ExpireTask {
                task_id: "deadline-task".to_string(),
            },
        );
        let payload = serde_json::to_vec(&too_early).unwrap();
        assert!(matches!(
            execute(
                &too_early,
                ExecutionContext {
                    height: 19,
                    chain_id: "trnm-devnet-v1",
                    signer_id: "client",
                    signer_role: "hepta",
                    payload_len: payload.len(),
                },
                &worker_fault,
            ),
            Err(RuntimeError::TaskExpiryUnavailable)
        ));
        let client_before_expiry = worker_fault.account("client").balance;
        let receipt = run(&mut worker_fault, too_early, 20, "hepta");
        assert_eq!(
            worker_fault.task("deadline-task").status,
            TaskStatusV1::Expired
        );
        assert_eq!(
            worker_fault.account("client").balance,
            client_before_expiry + 10_000 + 5_000 - receipt.fee_charged
        );
        assert_eq!(
            worker_fault.economic_total(),
            worker_fault.monetary_state().total_issued
        );

        let mut unconsumed = MemoryView::default();
        setup_paid_task(&mut unconsumed, 2);
        let client_before_expiry = unconsumed.account("client").balance;
        let worker_before_expiry = unconsumed.account("worker").balance;
        let receipt = run(
            &mut unconsumed,
            tx(
                "client",
                2,
                CanonicalCommandV1::ExpireTask {
                    task_id: "task-1".to_string(),
                },
            ),
            8,
            "hepta",
        );
        assert_eq!(unconsumed.task("task-1").status, TaskStatusV1::Expired);
        assert_eq!(
            unconsumed.account("client").balance,
            client_before_expiry + 10_000 - receipt.fee_charged
        );
        assert_eq!(
            unconsumed.account("worker").balance,
            worker_before_expiry + 5_000
        );
        assert_eq!(
            unconsumed.economic_total(),
            unconsumed.monetary_state().total_issued
        );
    }

    #[test]
    fn result_deadline_is_exclusive_for_worker_acceptance() {
        let mut view = MemoryView::default();
        issue(&mut view, 1, "client", 100_000);
        issue(&mut view, 2, "worker", 20_000);
        run(
            &mut view,
            tx("client", 1, create_task("deadline-task", 10)),
            2,
            "hepta",
        );
        let accept = tx(
            "worker",
            1,
            CanonicalCommandV1::AssignTask {
                task_id: "deadline-task".to_string(),
                worker: "worker".to_string(),
            },
        );
        let payload = serde_json::to_vec(&accept).unwrap();
        assert!(matches!(
            execute(
                &accept,
                ExecutionContext {
                    height: 20,
                    chain_id: "trnm-devnet-v1",
                    signer_id: "worker",
                    signer_role: "nakama",
                    payload_len: payload.len(),
                },
                &view,
            ),
            Err(RuntimeError::DeadlineExceeded)
        ));
        run(
            &mut view,
            tx(
                "client",
                2,
                CanonicalCommandV1::ExpireTask {
                    task_id: "deadline-task".to_string(),
                },
            ),
            20,
            "hepta",
        );
        assert_eq!(view.task("deadline-task").status, TaskStatusV1::Expired);
        assert_eq!(view.account("worker").nonce, 0);
        assert_eq!(view.economic_total(), view.monetary_state().total_issued);
    }

    #[test]
    fn fee_policy_is_bounded_and_operator_recovery_ignores_corrupt_policy() {
        let mut view = MemoryView::default();
        view.0.insert(
            fee_policy_key(),
            StateObject {
                object_type: FEE_POLICY_OBJECT_TYPE_V1.to_string(),
                version: 1,
                value_bytes: serde_json::to_vec(&FeePolicyV1 {
                    gas_price: u128::MAX,
                    base_gas: u64::MAX,
                    byte_gas: u64::MAX,
                })
                .unwrap(),
            },
        );
        let mut recover = tx(
            "operator",
            1,
            CanonicalCommandV1::SetFeePolicy {
                gas_price: 2,
                base_gas: 1_000,
                byte_gas: 3,
            },
        );
        recover.fee_limit = 0;
        let receipt = run(&mut view, recover, 1, "operator");
        assert_eq!(receipt.fee_charged, 0);
        let recovered: FeePolicyV1 =
            serde_json::from_slice(&view.0[&fee_policy_key()].value_bytes).unwrap();
        assert_eq!(
            recovered,
            FeePolicyV1 {
                gas_price: 2,
                base_gas: 1_000,
                byte_gas: 3,
            }
        );

        let extreme = tx(
            "operator",
            2,
            CanonicalCommandV1::SetFeePolicy {
                gas_price: u128::MAX,
                base_gas: 1,
                byte_gas: 1,
            },
        );
        let payload = serde_json::to_vec(&extreme).unwrap();
        assert!(matches!(
            execute(
                &extreme,
                ExecutionContext {
                    height: 2,
                    chain_id: "trnm-devnet-v1",
                    signer_id: "operator",
                    signer_role: "operator",
                    payload_len: payload.len(),
                },
                &view,
            ),
            Err(RuntimeError::Protocol(_))
        ));
    }

    #[test]
    fn collected_fees_are_governance_distributable() {
        let mut view = MemoryView::default();
        issue(&mut view, 1, "alice", 100_000);
        run(
            &mut view,
            tx(
                "alice",
                1,
                CanonicalCommandV1::Transfer {
                    to: "bob".to_string(),
                    amount: 1,
                },
            ),
            2,
            "hepta",
        );
        let collected = view.account(FEE_COLLECTOR_ACCOUNT_V1).balance;
        assert!(collected > 0);
        run(
            &mut view,
            tx(
                "operator",
                2,
                CanonicalCommandV1::DistributeFees {
                    to: "treasury".to_string(),
                    amount: collected,
                },
            ),
            3,
            "operator",
        );
        assert_eq!(view.account(FEE_COLLECTOR_ACCOUNT_V1).balance, 0);
        assert_eq!(view.account("treasury").balance, collected);
        assert_eq!(view.economic_total(), view.monetary_state().total_issued);
    }

    #[test]
    fn nonce_and_object_versions_fail_closed_at_u64_max() {
        let mut nonce_view = MemoryView::default();
        nonce_view.0.insert(
            account_key("alice"),
            StateObject {
                object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
                version: 1,
                value_bytes: serde_json::to_vec(&AccountV1 {
                    account: "alice".to_string(),
                    balance: 10_000,
                    nonce: u64::MAX,
                })
                .unwrap(),
            },
        );
        let exhausted = tx(
            "alice",
            u64::MAX,
            CanonicalCommandV1::Transfer {
                to: "bob".to_string(),
                amount: 1,
            },
        );
        let payload = serde_json::to_vec(&exhausted).unwrap();
        assert!(matches!(
            execute(
                &exhausted,
                ExecutionContext {
                    height: 1,
                    chain_id: "trnm-devnet-v1",
                    signer_id: "alice",
                    signer_role: "hepta",
                    payload_len: payload.len(),
                },
                &nonce_view,
            ),
            Err(RuntimeError::NonceExhausted)
        ));

        let mut version_view = MemoryView::default();
        version_view.0.insert(
            account_key("alice"),
            StateObject {
                object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
                version: 1,
                value_bytes: serde_json::to_vec(&AccountV1 {
                    account: "alice".to_string(),
                    balance: 10_000,
                    nonce: 0,
                })
                .unwrap(),
            },
        );
        version_view.0.insert(
            account_key("bob"),
            StateObject {
                object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
                version: u64::MAX,
                value_bytes: serde_json::to_vec(&AccountV1 {
                    account: "bob".to_string(),
                    balance: 0,
                    nonce: 0,
                })
                .unwrap(),
            },
        );
        let transfer = tx(
            "alice",
            1,
            CanonicalCommandV1::Transfer {
                to: "bob".to_string(),
                amount: 1,
            },
        );
        let payload = serde_json::to_vec(&transfer).unwrap();
        assert!(matches!(
            execute(
                &transfer,
                ExecutionContext {
                    height: 1,
                    chain_id: "trnm-devnet-v1",
                    signer_id: "alice",
                    signer_role: "hepta",
                    payload_len: payload.len(),
                },
                &version_view,
            ),
            Err(RuntimeError::ObjectVersionExhausted)
        ));
    }

    #[test]
    fn legacy_and_canonical_transition_smoke_agrees_on_core_task_statuses() {
        use trnm_pouw::{
            apply_accept_task_at_height, apply_commit_result_at_height, apply_create_task,
            apply_reveal_result_at_height,
        };
        use trnm_state::StateStore;
        use trnm_types::TaskStatus;

        let mut legacy = StateStore::new();
        legacy.set_balance("worker", 20_000);
        let legacy_open = apply_create_task(&mut legacy, 42, "client".to_string(), 10_000).unwrap();
        let legacy_assigned =
            apply_accept_task_at_height(&mut legacy, legacy_open, "worker".to_string(), 3).unwrap();

        let mut canonical = MemoryView::default();
        issue(&mut canonical, 1, "client", 100_000);
        issue(&mut canonical, 2, "worker", 20_000);
        run(
            &mut canonical,
            tx("client", 1, create_task("42", 100)),
            2,
            "hepta",
        );
        run(
            &mut canonical,
            tx(
                "worker",
                1,
                CanonicalCommandV1::AssignTask {
                    task_id: "42".to_string(),
                    worker: "worker".to_string(),
                },
            ),
            3,
            "nakama",
        );
        assert_eq!(legacy.get_task(42).unwrap().status, TaskStatus::Assigned);
        assert_eq!(canonical.task("42").status, TaskStatusV1::Assigned);

        let result_hash = [0x11; 32];
        let reveal_salt = [0x22; 32];
        let legacy_payload = format!(
            "42|{}|{}|worker",
            hex::encode(result_hash),
            hex::encode(reveal_salt)
        );
        let legacy_commitment: [u8; 32] = Sha256::digest(legacy_payload.as_bytes()).into();
        let legacy_committed = apply_commit_result_at_height(
            &mut legacy,
            legacy_assigned,
            "worker".to_string(),
            legacy_commitment,
            4,
        )
        .unwrap();
        let result_hash_hex = hex::encode(result_hash);
        let reveal_salt_hex = hex::encode(reveal_salt);
        let commitment =
            result_commitment_hex("42", "worker", &result_hash_hex, &reveal_salt_hex).unwrap();
        run(
            &mut canonical,
            tx(
                "worker",
                2,
                CanonicalCommandV1::CommitResult {
                    task_id: "42".to_string(),
                    commitment_hex: commitment,
                },
            ),
            4,
            "nakama",
        );
        assert_eq!(legacy.get_task(42).unwrap().status, TaskStatus::Committed);
        assert_eq!(canonical.task("42").status, TaskStatusV1::Committed);

        let legacy_revealed = apply_reveal_result_at_height(
            &mut legacy,
            legacy_committed,
            result_hash,
            reveal_salt,
            None,
            5,
        )
        .unwrap();
        run(
            &mut canonical,
            tx(
                "worker",
                3,
                CanonicalCommandV1::RevealResult {
                    task_id: "42".to_string(),
                    result_hash_hex,
                    reveal_salt_hex,
                },
            ),
            5,
            "nakama",
        );
        let legacy_task = legacy.get_task(legacy_revealed.id).unwrap();
        let canonical_task = canonical.task("42");
        assert_eq!(legacy_task.status, TaskStatus::Revealed);
        assert_eq!(canonical_task.status, TaskStatusV1::Revealed);
        assert_eq!(
            legacy_task.challenge_deadline_height,
            canonical_task.challenge_deadline_height
        );
    }
}
