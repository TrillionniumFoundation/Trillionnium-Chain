use std::{collections::BTreeMap, convert::Infallible, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use trnm_protocol::{
    account_key, fee_policy_key, monetary_state_key, result_commitment_hex, task_key, AccountV1,
    CanonicalCommandV1, CanonicalTxV1, FeePolicyV1, MonetaryStateV1, ProtocolError, TaskStatusV1,
    TaskV1, ACCOUNT_OBJECT_TYPE_V1, FEE_COLLECTOR_ACCOUNT_V1, FEE_POLICY_OBJECT_TYPE_V1,
    MONETARY_STATE_OBJECT_TYPE_V1, TASK_OBJECT_TYPE_V1,
};

/// Stable classification of failures produced by deterministic transaction execution.
///
/// A transaction rejection makes the transaction semantically invalid once its canonical
/// bytes, execution context, and authenticated state view are fixed. An invariant fault is
/// also deterministic for those inputs, but identifies malformed authenticated state or an
/// internal runtime invariant violation and must not be presented as a transaction rejection.
///
/// Retryable host failures such as unavailable state, database errors, or other I/O faults are
/// deliberately outside both this type and [`RuntimeError`]. Neither disposition carries a
/// failed receipt or mutations.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeterministicRuntimeFailureV0 {
    disposition: DeterministicRuntimeFailureDispositionV0,
    code: &'static str,
    reason: &'static str,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeterministicRuntimeFailureDispositionV0 {
    TransactionReject,
    InvariantFault,
}

impl DeterministicRuntimeFailureV0 {
    const fn transaction_reject(code: &'static str, reason: &'static str) -> Self {
        Self {
            disposition: DeterministicRuntimeFailureDispositionV0::TransactionReject,
            code,
            reason,
        }
    }

    const fn invariant_fault(code: &'static str, reason: &'static str) -> Self {
        Self {
            disposition: DeterministicRuntimeFailureDispositionV0::InvariantFault,
            code,
            reason,
        }
    }

    /// Stable consensus disposition. The failure's fields and constructors are
    /// private so callers cannot inject arbitrary codes or flip this value.
    pub const fn disposition(self) -> DeterministicRuntimeFailureDispositionV0 {
        self.disposition
    }

    /// Stable machine-readable leaf code.
    pub const fn code(self) -> &'static str {
        self.code
    }

    /// Stable context-free reason. Use [`RuntimeError`]'s display text for diagnostics only.
    pub const fn reason(self) -> &'static str {
        self.reason
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("protocol validation failed: {0}")]
    Protocol(ProtocolError),
    #[error("validated result commitment construction failed: {0}")]
    CommitmentConstructionInvariant(ProtocolError),
    #[error("transaction sender does not match signed envelope")]
    SenderMismatch,
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
    #[error("authenticated-state arithmetic invariant failed: {0}")]
    ArithmeticInvariant(&'static str),
    #[error("authenticated task state invariant failed: {0}")]
    AuthenticatedTaskStateInvariant(&'static str),
    #[error("authenticated state object invariant failed: {0}")]
    AuthenticatedObjectStateInvariant(&'static str),
}

impl RuntimeError {
    /// Classifies every pure runtime error without consulting diagnostic strings.
    ///
    /// This match intentionally has no catch-all arm: adding a [`RuntimeError`] variant forces
    /// an explicit consensus-policy review of its deterministic disposition, code, and reason.
    pub const fn deterministic_failure_v0(&self) -> DeterministicRuntimeFailureV0 {
        match self {
            Self::Protocol(_) => DeterministicRuntimeFailureV0::transaction_reject(
                "protocol_validation_failed",
                "transaction protocol validation failed",
            ),
            Self::CommitmentConstructionInvariant(_) => {
                DeterministicRuntimeFailureV0::invariant_fault(
                    "commitment_construction_invariant",
                    "validated result commitment construction invariant failed",
                )
            }
            Self::SenderMismatch => DeterministicRuntimeFailureV0::transaction_reject(
                "sender_mismatch",
                "transaction sender does not match signed envelope",
            ),
            Self::OperatorRequired => DeterministicRuntimeFailureV0::transaction_reject(
                "operator_required",
                "operator role required",
            ),
            Self::NonceMismatch { .. } => DeterministicRuntimeFailureV0::transaction_reject(
                "nonce_mismatch",
                "account nonce mismatch",
            ),
            Self::NonceExhausted => DeterministicRuntimeFailureV0::transaction_reject(
                "nonce_exhausted",
                "account nonce exhausted",
            ),
            Self::GasLimitExceeded { .. } => DeterministicRuntimeFailureV0::transaction_reject(
                "gas_limit_exceeded",
                "transaction gas limit exceeded",
            ),
            Self::FeeLimitExceeded { .. } => DeterministicRuntimeFailureV0::transaction_reject(
                "fee_limit_exceeded",
                "transaction fee limit exceeded",
            ),
            Self::InsufficientBalance { .. } => DeterministicRuntimeFailureV0::transaction_reject(
                "insufficient_balance",
                "insufficient account balance",
            ),
            Self::ObjectType(_) => DeterministicRuntimeFailureV0::invariant_fault(
                "object_type_mismatch",
                "authenticated state object type mismatch",
            ),
            Self::DecodeObject(_, _) => DeterministicRuntimeFailureV0::invariant_fault(
                "object_decode_failed",
                "authenticated state object decode failed",
            ),
            Self::EncodeObject(_) => DeterministicRuntimeFailureV0::invariant_fault(
                "object_encode_failed",
                "runtime state object encode invariant failed",
            ),
            Self::TaskAlreadyExists => DeterministicRuntimeFailureV0::transaction_reject(
                "task_already_exists",
                "task already exists",
            ),
            Self::TaskNotFound => DeterministicRuntimeFailureV0::transaction_reject(
                "task_not_found",
                "task not found",
            ),
            Self::InvalidTaskTransition => DeterministicRuntimeFailureV0::transaction_reject(
                "invalid_task_transition",
                "invalid task transition",
            ),
            Self::TaskAuthorityMismatch => DeterministicRuntimeFailureV0::transaction_reject(
                "task_authority_mismatch",
                "task authority mismatch",
            ),
            Self::DeadlineExceeded => DeterministicRuntimeFailureV0::transaction_reject(
                "deadline_exceeded",
                "task result deadline exceeded",
            ),
            Self::ChallengeWindowOpen => DeterministicRuntimeFailureV0::transaction_reject(
                "challenge_window_open",
                "task challenge window is still open",
            ),
            Self::ChallengeWindowClosed => DeterministicRuntimeFailureV0::transaction_reject(
                "challenge_window_closed",
                "task challenge window is closed",
            ),
            Self::TaskExpiryUnavailable => DeterministicRuntimeFailureV0::transaction_reject(
                "task_expiry_unavailable",
                "task is not eligible for expiry",
            ),
            Self::WorkerAcceptanceRequired => DeterministicRuntimeFailureV0::transaction_reject(
                "worker_acceptance_required",
                "worker acceptance transaction required",
            ),
            Self::ConflictingTaskRole => DeterministicRuntimeFailureV0::transaction_reject(
                "conflicting_task_role",
                "account occupies conflicting task roles",
            ),
            Self::ReservedSystemAccount => DeterministicRuntimeFailureV0::transaction_reject(
                "reserved_system_account",
                "reserved system account cannot sign transactions",
            ),
            Self::ObjectVersionExhausted => DeterministicRuntimeFailureV0::transaction_reject(
                "object_version_exhausted",
                "runtime state object version capacity exhausted",
            ),
            Self::ArithmeticOverflow => DeterministicRuntimeFailureV0::transaction_reject(
                "arithmetic_overflow",
                "transaction arithmetic capacity exceeded",
            ),
            Self::ArithmeticInvariant(_) => DeterministicRuntimeFailureV0::invariant_fault(
                "authenticated_state_arithmetic_overflow",
                "authenticated state arithmetic invariant overflowed",
            ),
            Self::AuthenticatedTaskStateInvariant(_) => {
                DeterministicRuntimeFailureV0::invariant_fault(
                    "authenticated_task_state_invariant",
                    "authenticated task state is internally inconsistent",
                )
            }
            Self::AuthenticatedObjectStateInvariant(_) => {
                DeterministicRuntimeFailureV0::invariant_fault(
                    "authenticated_object_state_invariant",
                    "authenticated state object is internally inconsistent",
                )
            }
        }
    }

    /// Stable machine-readable identifier for transaction simulation and RPC clients.
    ///
    /// Display strings remain diagnostic and may include transaction-specific values;
    /// callers should branch on this code instead.
    pub const fn code(&self) -> &'static str {
        self.deterministic_failure_v0().code()
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

/// Authenticated state view whose dependency failures remain distinct from a
/// genuinely absent object.
///
/// Implementations must return `Err` for read failures. Returning `Ok(None)`
/// after a failed read would let execution misclassify dependency loss as a
/// default account or a deterministic `TaskNotFound` rejection.
pub trait TryStateViewV0 {
    type Error;

    fn try_get(&self, object_key_hex: &str) -> Result<Option<StateObject>, Self::Error>;
}

/// Opaque failure produced only by [`try_execute_v0`].
///
/// Its private representation prevents callers from manufacturing a
/// deterministic execution-attempt fact from a standalone [`RuntimeError`].
/// Callers can inspect the stable deterministic classification or borrow the
/// typed state dependency error, but cannot construct either branch.
#[must_use]
#[derive(Debug)]
pub struct RuntimeExecutionAttemptFailureV0<StateError> {
    inner: RuntimeExecutionAttemptFailureKindV0<StateError>,
}

#[derive(Debug)]
enum RuntimeExecutionAttemptFailureKindV0<StateError> {
    Deterministic(RuntimeError),
    StateUnavailable(StateError),
}

impl<StateError> RuntimeExecutionAttemptFailureV0<StateError> {
    /// Returns the exhaustive deterministic leaf classification only when the
    /// real execution attempt reached a pure [`RuntimeError`].
    pub fn deterministic_failure_v0(&self) -> Option<DeterministicRuntimeFailureV0> {
        match &self.inner {
            RuntimeExecutionAttemptFailureKindV0::Deterministic(error) => {
                Some(error.deterministic_failure_v0())
            }
            RuntimeExecutionAttemptFailureKindV0::StateUnavailable(_) => None,
        }
    }

    /// Borrows the exact dependency error only when authenticated state could
    /// not be read. No diagnostic strings participate in this distinction.
    pub fn state_unavailable(&self) -> Option<&StateError> {
        match &self.inner {
            RuntimeExecutionAttemptFailureKindV0::Deterministic(_) => None,
            RuntimeExecutionAttemptFailureKindV0::StateUnavailable(error) => Some(error),
        }
    }

    fn from_internal(error: RuntimeExecutionInternalErrorV0<StateError>) -> Self {
        let inner = match error {
            RuntimeExecutionInternalErrorV0::Deterministic(error) => {
                RuntimeExecutionAttemptFailureKindV0::Deterministic(error)
            }
            RuntimeExecutionInternalErrorV0::StateUnavailable(error) => {
                RuntimeExecutionAttemptFailureKindV0::StateUnavailable(error)
            }
        };
        Self { inner }
    }
}

impl<StateError: fmt::Display> fmt::Display for RuntimeExecutionAttemptFailureV0<StateError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            RuntimeExecutionAttemptFailureKindV0::Deterministic(error) => {
                fmt::Display::fmt(error, formatter)
            }
            RuntimeExecutionAttemptFailureKindV0::StateUnavailable(error) => {
                write!(formatter, "authenticated state unavailable: {error}")
            }
        }
    }
}

/// Opaque failure produced only by [`try_estimate_resources_v0`].
///
/// Resource estimation is deliberately a separate authority boundary from
/// execution: it never returns a receipt or mutations. Its private
/// representation nevertheless preserves the same critical distinction
/// between a deterministic runtime failure and an unavailable authenticated
/// state dependency. Callers cannot manufacture either branch or reclassify a
/// dependency error by inspecting its diagnostic text.
#[must_use]
#[derive(Debug)]
pub struct RuntimeResourceEstimateAttemptFailureV0<StateError> {
    inner: RuntimeResourceEstimateAttemptFailureKindV0<StateError>,
}

#[derive(Debug)]
enum RuntimeResourceEstimateAttemptFailureKindV0<StateError> {
    Deterministic(RuntimeError),
    StateUnavailable(StateError),
}

impl<StateError> RuntimeResourceEstimateAttemptFailureV0<StateError> {
    /// Returns the exhaustive deterministic leaf classification only when the
    /// real estimation attempt reached a pure [`RuntimeError`].
    pub fn deterministic_failure_v0(&self) -> Option<DeterministicRuntimeFailureV0> {
        match &self.inner {
            RuntimeResourceEstimateAttemptFailureKindV0::Deterministic(error) => {
                Some(error.deterministic_failure_v0())
            }
            RuntimeResourceEstimateAttemptFailureKindV0::StateUnavailable(_) => None,
        }
    }

    /// Borrows the exact dependency error when authenticated state could not
    /// be read. No diagnostic strings participate in this distinction.
    pub fn state_unavailable(&self) -> Option<&StateError> {
        match &self.inner {
            RuntimeResourceEstimateAttemptFailureKindV0::Deterministic(_) => None,
            RuntimeResourceEstimateAttemptFailureKindV0::StateUnavailable(error) => Some(error),
        }
    }

    fn from_internal(error: RuntimeExecutionInternalErrorV0<StateError>) -> Self {
        let inner = match error {
            RuntimeExecutionInternalErrorV0::Deterministic(error) => {
                RuntimeResourceEstimateAttemptFailureKindV0::Deterministic(error)
            }
            RuntimeExecutionInternalErrorV0::StateUnavailable(error) => {
                RuntimeResourceEstimateAttemptFailureKindV0::StateUnavailable(error)
            }
        };
        Self { inner }
    }
}

impl<StateError: fmt::Display> fmt::Display
    for RuntimeResourceEstimateAttemptFailureV0<StateError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            RuntimeResourceEstimateAttemptFailureKindV0::Deterministic(error) => {
                fmt::Display::fmt(error, formatter)
            }
            RuntimeResourceEstimateAttemptFailureKindV0::StateUnavailable(error) => {
                write!(formatter, "authenticated state unavailable: {error}")
            }
        }
    }
}

enum RuntimeExecutionInternalErrorV0<StateError> {
    Deterministic(RuntimeError),
    StateUnavailable(StateError),
}

impl<StateError> From<RuntimeError> for RuntimeExecutionInternalErrorV0<StateError> {
    fn from(error: RuntimeError) -> Self {
        Self::Deterministic(error)
    }
}

type RuntimeExecutionInternalResultV0<Value, StateError> =
    Result<Value, RuntimeExecutionInternalErrorV0<StateError>>;

struct InfallibleStateViewAdapter<'a> {
    view: &'a dyn StateView,
}

impl TryStateViewV0 for InfallibleStateViewAdapter<'_> {
    type Error = Infallible;

    fn try_get(&self, object_key_hex: &str) -> Result<Option<StateObject>, Self::Error> {
        Ok(self.view.get(object_key_hex))
    }
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

struct RuntimeState<'a, View>
where
    View: TryStateViewV0 + ?Sized,
{
    view: &'a View,
    height: u64,
    accounts: BTreeMap<String, Loaded<AccountV1>>,
    tasks: BTreeMap<String, Loaded<TaskV1>>,
    policy: Option<Loaded<FeePolicyV1>>,
    monetary_state: Option<Loaded<MonetaryStateV1>>,
}

impl<'a, View> RuntimeState<'a, View>
where
    View: TryStateViewV0 + ?Sized,
{
    fn new(view: &'a View, height: u64) -> Self {
        Self {
            view,
            height,
            accounts: BTreeMap::new(),
            tasks: BTreeMap::new(),
            policy: None,
            monetary_state: None,
        }
    }

    fn policy(
        &mut self,
    ) -> RuntimeExecutionInternalResultV0<&mut Loaded<FeePolicyV1>, View::Error> {
        if self.policy.is_none() {
            let loaded = load_or_default(
                self.view,
                &fee_policy_key(),
                FEE_POLICY_OBJECT_TYPE_V1,
                FeePolicyV1::default(),
            )?;
            validate_authenticated_fee_policy(&loaded.value)?;
            self.policy = Some(loaded);
        }
        Ok(self.policy.as_mut().expect("policy initialized"))
    }

    /// Loads the exact persisted policy shape for an authorized replacement
    /// without treating unsafe legacy bounds as an obstacle to recovery.
    /// Type, encoding, and nonzero-version invariants are still enforced by
    /// `load_or_default`; only the old value's canonical bounds are skipped.
    fn policy_for_replacement(
        &mut self,
    ) -> RuntimeExecutionInternalResultV0<&mut Loaded<FeePolicyV1>, View::Error> {
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

    fn account(
        &mut self,
        account: &str,
    ) -> RuntimeExecutionInternalResultV0<&mut Loaded<AccountV1>, View::Error> {
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
            if loaded.value.account != account {
                return Err(RuntimeError::AuthenticatedObjectStateInvariant(
                    "account object key does not match account id",
                )
                .into());
            }
            self.accounts.insert(account.to_string(), loaded);
        }
        Ok(self.accounts.get_mut(account).expect("account initialized"))
    }

    fn monetary_state(
        &mut self,
    ) -> RuntimeExecutionInternalResultV0<&mut Loaded<MonetaryStateV1>, View::Error> {
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

    fn existing_task(
        &mut self,
        task_id: &str,
    ) -> RuntimeExecutionInternalResultV0<&mut Loaded<TaskV1>, View::Error> {
        if !self.tasks.contains_key(task_id) {
            let key = task_key(task_id);
            let object = self
                .view
                .try_get(&key)
                .map_err(RuntimeExecutionInternalErrorV0::StateUnavailable)?
                .ok_or(RuntimeError::TaskNotFound)?;
            let value = decode_authenticated_task(task_id, &key, &object, self.height)?;
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

    fn insert_task(&mut self, task: TaskV1) -> RuntimeExecutionInternalResultV0<(), View::Error> {
        let key = task_key(&task.task_id);
        if self.tasks.contains_key(&task.task_id) {
            return Err(RuntimeError::TaskAlreadyExists.into());
        }
        if let Some(object) = self
            .view
            .try_get(&key)
            .map_err(RuntimeExecutionInternalErrorV0::StateUnavailable)?
        {
            decode_authenticated_task(&task.task_id, &key, &object, self.height)?;
            return Err(RuntimeError::TaskAlreadyExists.into());
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

    fn debit(
        &mut self,
        account: &str,
        amount: u128,
    ) -> RuntimeExecutionInternalResultV0<(), View::Error> {
        let loaded = self.account(account)?;
        if loaded.value.balance < amount {
            return Err(RuntimeError::InsufficientBalance {
                account: account.to_string(),
                required: amount,
                available: loaded.value.balance,
            }
            .into());
        }
        loaded.value.balance -= amount;
        loaded.dirty = true;
        Ok(())
    }

    fn credit(
        &mut self,
        account: &str,
        amount: u128,
    ) -> RuntimeExecutionInternalResultV0<(), View::Error> {
        let loaded = self.account(account)?;
        loaded.value.balance = loaded
            .value
            .balance
            .checked_add(amount)
            .ok_or(RuntimeError::ArithmeticInvariant("account credit"))?;
        loaded.dirty = true;
        Ok(())
    }

    fn credit_mint_capacity(
        &mut self,
        account: &str,
        amount: u128,
    ) -> RuntimeExecutionInternalResultV0<(), View::Error> {
        let loaded = self.account(account)?;
        loaded.value.balance = loaded
            .value
            .balance
            .checked_add(amount)
            .ok_or(RuntimeError::ArithmeticOverflow)?;
        loaded.dirty = true;
        Ok(())
    }

    fn issue(&mut self, amount: u128) -> RuntimeExecutionInternalResultV0<(), View::Error> {
        let loaded = self.monetary_state()?;
        loaded.value.total_issued = loaded
            .value
            .total_issued
            .checked_add(amount)
            .ok_or(RuntimeError::ArithmeticOverflow)?;
        loaded.dirty = true;
        Ok(())
    }

    fn into_mutations(self) -> RuntimeExecutionInternalResultV0<Vec<RuntimeMutation>, View::Error> {
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
    let view = InfallibleStateViewAdapter { view };
    collapse_infallible_execution_result(execute_with_try_state_view_v0(tx, context, &view))
}

/// Executes against an authenticated state source that can fail independently
/// of deterministic runtime semantics.
///
/// The error wrapper has no public constructor. Its deterministic branch can
/// therefore originate only at this real execution boundary, while a failed
/// state read preserves the view's exact typed error and cannot become
/// `TaskNotFound`, a default object, or a [`RuntimeError`].
pub fn try_execute_v0<View>(
    tx: &CanonicalTxV1,
    context: ExecutionContext<'_>,
    view: &View,
) -> Result<RuntimeReceipt, RuntimeExecutionAttemptFailureV0<View::Error>>
where
    View: TryStateViewV0 + ?Sized,
{
    execute_with_try_state_view_v0(tx, context, view)
        .map_err(RuntimeExecutionAttemptFailureV0::from_internal)
}

fn execute_with_try_state_view_v0<View>(
    tx: &CanonicalTxV1,
    context: ExecutionContext<'_>,
    view: &View,
) -> RuntimeExecutionInternalResultV0<RuntimeReceipt, View::Error>
where
    View: TryStateViewV0 + ?Sized,
{
    validate_transaction_context(tx, context)?;
    let mut state = RuntimeState::new(view, context.height);
    let estimate = estimate_resources_with_state(tx, context, &mut state)?;
    if estimate.gas_used > tx.max_gas {
        return Err(RuntimeError::GasLimitExceeded {
            required: estimate.gas_used,
            limit: tx.max_gas,
        }
        .into());
    }
    if estimate.fee_estimate > tx.fee_limit {
        return Err(RuntimeError::FeeLimitExceeded {
            required: estimate.fee_estimate,
            limit: tx.fee_limit,
        }
        .into());
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
        }
        .into());
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
    let view = InfallibleStateViewAdapter { view };
    collapse_infallible_execution_result(estimate_resources_with_try_state_view_v0(
        tx, context, &view,
    ))
}

/// Computes the exact gas and fee estimate against an authenticated state
/// source whose dependency reads may fail independently of runtime semantics.
///
/// The opaque error distinguishes a deterministic transaction/context failure
/// from the view's exact typed dependency error without examining diagnostic
/// text. Estimation never applies resource limits or state transitions and can
/// return neither a receipt nor mutations.
pub fn try_estimate_resources_v0<View>(
    tx: &CanonicalTxV1,
    context: ExecutionContext<'_>,
    view: &View,
) -> Result<ResourceEstimate, RuntimeResourceEstimateAttemptFailureV0<View::Error>>
where
    View: TryStateViewV0 + ?Sized,
{
    estimate_resources_with_try_state_view_v0(tx, context, view)
        .map_err(RuntimeResourceEstimateAttemptFailureV0::from_internal)
}

fn estimate_resources_with_try_state_view_v0<View>(
    tx: &CanonicalTxV1,
    context: ExecutionContext<'_>,
    view: &View,
) -> RuntimeExecutionInternalResultV0<ResourceEstimate, View::Error>
where
    View: TryStateViewV0 + ?Sized,
{
    validate_transaction_context(tx, context)?;
    estimate_resources_with_state(tx, context, &mut RuntimeState::new(view, context.height))
}

fn collapse_infallible_execution_result<Value>(
    result: RuntimeExecutionInternalResultV0<Value, Infallible>,
) -> Result<Value, RuntimeError> {
    match result {
        Ok(value) => Ok(value),
        Err(RuntimeExecutionInternalErrorV0::Deterministic(error)) => Err(error),
        Err(RuntimeExecutionInternalErrorV0::StateUnavailable(unavailable)) => match unavailable {},
    }
}

fn validate_transaction_context(
    tx: &CanonicalTxV1,
    context: ExecutionContext<'_>,
) -> Result<(), RuntimeError> {
    tx.validate().map_err(RuntimeError::Protocol)?;
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

fn estimate_resources_with_state<View>(
    tx: &CanonicalTxV1,
    context: ExecutionContext<'_>,
    state: &mut RuntimeState<'_, View>,
) -> RuntimeExecutionInternalResultV0<ResourceEstimate, View::Error>
where
    View: TryStateViewV0 + ?Sized,
{
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
        .ok_or(RuntimeError::ArithmeticInvariant("payload gas"))?;
    let gas_used = policy
        .base_gas
        .checked_add(payload_gas)
        .and_then(|gas| gas.checked_add(tx.command.operation_gas()))
        .ok_or(RuntimeError::ArithmeticInvariant("total gas"))?;
    let fee = if operator_command {
        0
    } else {
        u128::from(gas_used)
            .checked_mul(policy.gas_price)
            .ok_or(RuntimeError::ArithmeticInvariant("fee computation"))?
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

fn apply_command<View>(
    state: &mut RuntimeState<'_, View>,
    tx: &CanonicalTxV1,
    context: ExecutionContext<'_>,
    events: &mut Vec<RuntimeEvent>,
) -> RuntimeExecutionInternalResultV0<(), View::Error>
where
    View: TryStateViewV0 + ?Sized,
{
    match &tx.command {
        CanonicalCommandV1::CreditAccount { account, amount } => {
            state.credit_mint_capacity(account, *amount)?;
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
                return Err(RuntimeError::DeadlineExceeded.into());
            }
            result_deadline_height
                .checked_add(*challenge_window_blocks)
                .ok_or(RuntimeError::ArithmeticOverflow)?;
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
                return Err(RuntimeError::WorkerAcceptanceRequired.into());
            }
            let worker_stake = {
                let task = state.existing_task(task_id)?;
                if task.value.status != TaskStatusV1::Open {
                    return Err(RuntimeError::InvalidTaskTransition.into());
                }
                if context.height >= task.value.result_deadline_height {
                    return Err(RuntimeError::DeadlineExceeded.into());
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
                return Err(RuntimeError::InvalidTaskTransition.into());
            }
            if context.height >= task.value.result_deadline_height {
                return Err(RuntimeError::DeadlineExceeded.into());
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
                return Err(RuntimeError::InvalidTaskTransition.into());
            }
            if context.height >= task.value.result_deadline_height {
                return Err(RuntimeError::DeadlineExceeded.into());
            }
            let expected_commitment =
                result_commitment_hex(task_id, &tx.sender, result_hash_hex, reveal_salt_hex)
                    .map_err(RuntimeError::CommitmentConstructionInvariant)?;
            if task.value.commitment_hex.as_deref() != Some(expected_commitment.as_str()) {
                return Err(RuntimeError::InvalidTaskTransition.into());
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
                    return Err(RuntimeError::InvalidTaskTransition.into());
                }
                if context.height
                    > task.value.challenge_deadline_height.ok_or(
                        RuntimeError::AuthenticatedTaskStateInvariant(
                            "revealed task is missing challenge deadline",
                        ),
                    )?
                {
                    return Err(RuntimeError::ChallengeWindowClosed.into());
                }
                task.value
                    .worker
                    .clone()
                    .ok_or(RuntimeError::AuthenticatedTaskStateInvariant(
                        "revealed task is missing worker",
                    ))?
            };
            if worker == tx.sender {
                return Err(RuntimeError::ConflictingTaskRole.into());
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
                    return Err(RuntimeError::InvalidTaskTransition.into());
                }
                if context.height
                    > task.value.challenge_deadline_height.ok_or(
                        RuntimeError::AuthenticatedTaskStateInvariant(
                            "challengeable task is missing challenge deadline",
                        ),
                    )?
                {
                    return Err(RuntimeError::ChallengeWindowClosed.into());
                }
                task.value
                    .worker
                    .clone()
                    .ok_or(RuntimeError::AuthenticatedTaskStateInvariant(
                        "challengeable task is missing worker",
                    ))?
            };
            if worker == tx.sender {
                return Err(RuntimeError::ConflictingTaskRole.into());
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
                return Err(RuntimeError::OperatorRequired.into());
            }
            let settlement = {
                let task = state.existing_task(task_id)?;
                if task.value.status != TaskStatusV1::Challenged {
                    return Err(RuntimeError::InvalidTaskTransition.into());
                }
                ChallengeSettlement {
                    client: task.value.client.clone(),
                    worker: task.value.worker.clone().ok_or(
                        RuntimeError::AuthenticatedTaskStateInvariant(
                            "challenged task is missing worker",
                        ),
                    )?,
                    consumer: task.value.consumer.clone(),
                    challenger: task.value.challenger.clone().ok_or(
                        RuntimeError::AuthenticatedTaskStateInvariant(
                            "challenged task is missing challenger",
                        ),
                    )?,
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
                    .ok_or(RuntimeError::ArithmeticInvariant("challenger payout"))?;
                state.credit(&settlement.challenger, challenger_payout)?;
                if settlement.consumption_payment > 0 {
                    let consumer = settlement.consumer.as_deref().ok_or(
                        RuntimeError::AuthenticatedTaskStateInvariant(
                            "consumption payment is missing consumer",
                        ),
                    )?;
                    state.credit(consumer, settlement.consumption_payment)?;
                }
            } else {
                let worker_payout = settlement
                    .reward
                    .checked_add(settlement.worker_stake)
                    .and_then(|value| value.checked_add(settlement.consumption_payment))
                    .and_then(|value| value.checked_add(settlement.challenge_bond))
                    .ok_or(RuntimeError::ArithmeticInvariant("worker challenge payout"))?;
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
                    return Err(RuntimeError::InvalidTaskTransition.into());
                }
                (
                    task.value.client.clone(),
                    task.value.worker.clone().ok_or(
                        RuntimeError::AuthenticatedTaskStateInvariant(
                            "consumed task is missing worker",
                        ),
                    )?,
                    task.value
                        .reward
                        .checked_add(task.value.worker_stake)
                        .and_then(|value| value.checked_add(task.value.consumption_payment))
                        .ok_or(RuntimeError::ArithmeticInvariant("task settlement payout"))?,
                    task.value.challenge_deadline_height.ok_or(
                        RuntimeError::AuthenticatedTaskStateInvariant(
                            "consumed task is missing challenge deadline",
                        ),
                    )?,
                )
            };
            if tx.sender != client && context.signer_role != "operator" {
                return Err(RuntimeError::TaskAuthorityMismatch.into());
            }
            if context.height <= challenge_deadline_height {
                return Err(RuntimeError::ChallengeWindowOpen.into());
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
                            > task.value.challenge_deadline_height.ok_or(
                                RuntimeError::AuthenticatedTaskStateInvariant(
                                    "revealed task is missing challenge deadline",
                                ),
                            )? =>
                    {
                        (
                            task.value.client.clone(),
                            task.value.worker.clone(),
                            task.value.reward,
                            task.value.worker_stake,
                            "unconsumed_refund",
                        )
                    }
                    _ => return Err(RuntimeError::TaskExpiryUnavailable.into()),
                }
            };
            state.credit(&client, reward)?;
            if worker_stake > 0 {
                let worker = worker.ok_or(RuntimeError::AuthenticatedTaskStateInvariant(
                    "expirable assigned task is missing worker",
                ))?;
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
            let policy = state.policy_for_replacement()?;
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
    let worker = task
        .worker
        .as_deref()
        .ok_or(RuntimeError::AuthenticatedTaskStateInvariant(
            "assigned task is missing worker",
        ))?;
    if worker != sender {
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

fn decode_authenticated_task(
    expected_task_id: &str,
    key: &str,
    object: &StateObject,
    current_height: u64,
) -> Result<TaskV1, RuntimeError> {
    ensure_type(key, object, TASK_OBJECT_TYPE_V1)?;
    if object.version == 0 {
        return Err(RuntimeError::AuthenticatedObjectStateInvariant(
            "persisted task object has zero version",
        ));
    }
    let task: TaskV1 = serde_json::from_slice(&object.value_bytes)
        .map_err(|error| RuntimeError::DecodeObject(key.to_string(), error.to_string()))?;
    validate_authenticated_task(expected_task_id, &task, object.version, current_height)?;
    Ok(task)
}

fn validate_authenticated_task(
    expected_task_id: &str,
    task: &TaskV1,
    object_version: u64,
    current_height: u64,
) -> Result<(), RuntimeError> {
    if task.task_id != expected_task_id {
        return Err(RuntimeError::AuthenticatedTaskStateInvariant(
            "task object key does not match task_id",
        ));
    }
    CanonicalCommandV1::CreateTask {
        task_id: task.task_id.clone(),
        reward: task.reward,
        worker_stake: task.worker_stake,
        result_deadline_height: task.result_deadline_height,
        challenge_window_blocks: task.challenge_window_blocks,
    }
    .validate()
    .map_err(|_| {
        RuntimeError::AuthenticatedTaskStateInvariant("task base fields are non-canonical")
    })?;
    if task
        .result_deadline_height
        .checked_add(task.challenge_window_blocks)
        .is_none()
    {
        return Err(RuntimeError::AuthenticatedTaskStateInvariant(
            "task deadline and challenge window exceed height capacity",
        ));
    }
    CanonicalCommandV1::Transfer {
        to: task.client.clone(),
        amount: 1,
    }
    .validate()
    .map_err(|_| RuntimeError::AuthenticatedTaskStateInvariant("task client is non-canonical"))?;
    if task.client == FEE_COLLECTOR_ACCOUNT_V1 {
        return Err(RuntimeError::AuthenticatedTaskStateInvariant(
            "task client is the reserved fee collector",
        ));
    }
    if let Some(worker) = &task.worker {
        CanonicalCommandV1::AssignTask {
            task_id: task.task_id.clone(),
            worker: worker.clone(),
        }
        .validate()
        .map_err(|_| {
            RuntimeError::AuthenticatedTaskStateInvariant("task worker is non-canonical")
        })?;
        if worker == FEE_COLLECTOR_ACCOUNT_V1 {
            return Err(RuntimeError::AuthenticatedTaskStateInvariant(
                "task worker is the reserved fee collector",
            ));
        }
    }
    if let Some(commitment_hex) = &task.commitment_hex {
        CanonicalCommandV1::CommitResult {
            task_id: task.task_id.clone(),
            commitment_hex: commitment_hex.clone(),
        }
        .validate()
        .map_err(|_| {
            RuntimeError::AuthenticatedTaskStateInvariant("task result commitment is non-canonical")
        })?;
    }

    let reveal_any = task.result_hash_hex.is_some()
        || task.reveal_salt_hex.is_some()
        || task.challenge_deadline_height.is_some();
    let reveal_all = task.result_hash_hex.is_some()
        && task.reveal_salt_hex.is_some()
        && task.challenge_deadline_height.is_some();
    if reveal_any != reveal_all || task.challenge_deadline_height == Some(0) {
        return Err(RuntimeError::AuthenticatedTaskStateInvariant(
            "task reveal fields are partial or invalid",
        ));
    }
    if reveal_all {
        CanonicalCommandV1::RevealResult {
            task_id: task.task_id.clone(),
            result_hash_hex: task.result_hash_hex.clone().expect("reveal group checked"),
            reveal_salt_hex: task.reveal_salt_hex.clone().expect("reveal group checked"),
        }
        .validate()
        .map_err(|_| {
            RuntimeError::AuthenticatedTaskStateInvariant("task reveal fields are non-canonical")
        })?;
        let worker =
            task.worker
                .as_deref()
                .ok_or(RuntimeError::AuthenticatedTaskStateInvariant(
                    "revealed task is missing its authenticated worker",
                ))?;
        let expected_commitment = result_commitment_hex(
            &task.task_id,
            worker,
            task.result_hash_hex
                .as_deref()
                .expect("reveal group checked"),
            task.reveal_salt_hex
                .as_deref()
                .expect("reveal group checked"),
        )
        .map_err(RuntimeError::CommitmentConstructionInvariant)?;
        if task.commitment_hex.as_deref() != Some(expected_commitment.as_str()) {
            return Err(RuntimeError::AuthenticatedTaskStateInvariant(
                "revealed result does not match the authenticated commitment",
            ));
        }
        let challenge_deadline = task
            .challenge_deadline_height
            .expect("reveal group checked");
        let latest_challenge_deadline = task
            .result_deadline_height
            .checked_sub(1)
            .and_then(|height| height.checked_add(task.challenge_window_blocks))
            .ok_or(RuntimeError::AuthenticatedTaskStateInvariant(
                "task reveal horizon is internally inconsistent",
            ))?;
        if challenge_deadline < task.challenge_window_blocks
            || challenge_deadline > latest_challenge_deadline
        {
            return Err(RuntimeError::AuthenticatedTaskStateInvariant(
                "task challenge deadline is outside its reachable horizon",
            ));
        }
        let implied_reveal_height = challenge_deadline
            .checked_sub(task.challenge_window_blocks)
            .ok_or(RuntimeError::AuthenticatedTaskStateInvariant(
                "task reveal height is internally inconsistent",
            ))?;
        if implied_reveal_height > current_height {
            return Err(RuntimeError::AuthenticatedTaskStateInvariant(
                "task reveal fields imply a future reveal height",
            ));
        }
    }

    let consumption_any = task.consumer.is_some()
        || task.consumed_units != 0
        || task.consumption_payment != 0
        || task.receipt_hash_hex.is_some();
    let consumption_all = task.consumer.is_some()
        && task.consumed_units != 0
        && task.consumption_payment != 0
        && task.receipt_hash_hex.is_some();
    if consumption_any != consumption_all {
        return Err(RuntimeError::AuthenticatedTaskStateInvariant(
            "task consumption fields are partial",
        ));
    }
    if consumption_all {
        let consumer = task.consumer.as_deref().expect("consumption group checked");
        CanonicalCommandV1::Transfer {
            to: consumer.to_string(),
            amount: 1,
        }
        .validate()
        .map_err(|_| {
            RuntimeError::AuthenticatedTaskStateInvariant("task consumer is non-canonical")
        })?;
        if consumer == FEE_COLLECTOR_ACCOUNT_V1 || task.worker.as_deref() == Some(consumer) {
            return Err(RuntimeError::AuthenticatedTaskStateInvariant(
                "task consumer has an impossible authenticated role",
            ));
        }
        CanonicalCommandV1::RecordConsumption {
            task_id: task.task_id.clone(),
            units: task.consumed_units,
            payment: task.consumption_payment,
            receipt_hash_hex: task
                .receipt_hash_hex
                .clone()
                .expect("consumption group checked"),
        }
        .validate()
        .map_err(|_| {
            RuntimeError::AuthenticatedTaskStateInvariant(
                "task consumption fields are non-canonical",
            )
        })?;
    }

    let challenge_any =
        task.challenger.is_some() || task.challenge_bond != 0 || task.evidence_hash_hex.is_some();
    let challenge_all =
        task.challenger.is_some() && task.challenge_bond != 0 && task.evidence_hash_hex.is_some();
    if challenge_any != challenge_all {
        return Err(RuntimeError::AuthenticatedTaskStateInvariant(
            "task challenge fields are partial",
        ));
    }
    if challenge_all {
        let challenger = task.challenger.as_deref().expect("challenge group checked");
        CanonicalCommandV1::Transfer {
            to: challenger.to_string(),
            amount: 1,
        }
        .validate()
        .map_err(|_| {
            RuntimeError::AuthenticatedTaskStateInvariant("task challenger is non-canonical")
        })?;
        if challenger == FEE_COLLECTOR_ACCOUNT_V1 || task.worker.as_deref() == Some(challenger) {
            return Err(RuntimeError::AuthenticatedTaskStateInvariant(
                "task challenger has an impossible authenticated role",
            ));
        }
        CanonicalCommandV1::OpenChallenge {
            task_id: task.task_id.clone(),
            bond: task.challenge_bond,
            evidence_hash_hex: task
                .evidence_hash_hex
                .clone()
                .expect("challenge group checked"),
        }
        .validate()
        .map_err(|_| {
            RuntimeError::AuthenticatedTaskStateInvariant("task challenge fields are non-canonical")
        })?;
    }

    let worker = task.worker.is_some();
    let commitment = task.commitment_hex.is_some();
    let fields_match_status = match task.status {
        TaskStatusV1::Open => {
            !worker && !commitment && !reveal_all && !consumption_all && !challenge_all
        }
        TaskStatusV1::Assigned => {
            worker && !commitment && !reveal_all && !consumption_all && !challenge_all
        }
        TaskStatusV1::Committed => {
            worker && commitment && !reveal_all && !consumption_all && !challenge_all
        }
        TaskStatusV1::Revealed => {
            worker && commitment && reveal_all && !consumption_all && !challenge_all
        }
        TaskStatusV1::Consumed | TaskStatusV1::Settled => {
            worker && commitment && reveal_all && consumption_all && !challenge_all
        }
        TaskStatusV1::Challenged
        | TaskStatusV1::ResolvedForWorker
        | TaskStatusV1::ResolvedForChallenger => {
            worker && commitment && reveal_all && challenge_all
        }
        TaskStatusV1::Expired => {
            !consumption_all
                && !challenge_all
                && ((!commitment && !reveal_all) || (worker && commitment))
        }
    };
    if !fields_match_status {
        return Err(RuntimeError::AuthenticatedTaskStateInvariant(
            "task status and staged field groups disagree",
        ));
    }

    let expected_version = match task.status {
        TaskStatusV1::Open => 1,
        TaskStatusV1::Assigned => 2,
        TaskStatusV1::Committed => 3,
        TaskStatusV1::Revealed => 4,
        TaskStatusV1::Consumed => 5,
        TaskStatusV1::Challenged => {
            if consumption_all {
                6
            } else {
                5
            }
        }
        TaskStatusV1::Settled => 6,
        TaskStatusV1::ResolvedForWorker | TaskStatusV1::ResolvedForChallenger => {
            if consumption_all {
                7
            } else {
                6
            }
        }
        TaskStatusV1::Expired => {
            if !worker {
                2
            } else if !commitment {
                3
            } else if !reveal_all {
                4
            } else {
                5
            }
        }
    };
    if object_version != expected_version {
        return Err(RuntimeError::AuthenticatedTaskStateInvariant(
            "task object version does not match its reachable transition path",
        ));
    }

    match task.status {
        TaskStatusV1::Settled => {
            if current_height
                <= task
                    .challenge_deadline_height
                    .expect("settled task has reveal fields")
            {
                return Err(RuntimeError::AuthenticatedTaskStateInvariant(
                    "settled task predates the end of its challenge window",
                ));
            }
        }
        TaskStatusV1::Expired => {
            let expiry_reached = if reveal_all {
                current_height
                    > task
                        .challenge_deadline_height
                        .expect("revealed expired task has challenge deadline")
            } else {
                current_height >= task.result_deadline_height
            };
            if !expiry_reached {
                return Err(RuntimeError::AuthenticatedTaskStateInvariant(
                    "expired task predates its reachable expiry boundary",
                ));
            }
        }
        TaskStatusV1::Open
        | TaskStatusV1::Assigned
        | TaskStatusV1::Committed
        | TaskStatusV1::Revealed
        | TaskStatusV1::Consumed
        | TaskStatusV1::Challenged
        | TaskStatusV1::ResolvedForWorker
        | TaskStatusV1::ResolvedForChallenger => {}
    }

    Ok(())
}

/// Opaque failure from read-only validation of one authenticated task value.
///
/// This type deliberately does not expose the runtime error that identified
/// the malformed state and is independent from execution-attempt failures. It
/// carries no receipt, mutation, authority, or retry disposition.
#[must_use]
pub struct RuntimeTaskStateValidationFailureV0 {
    _private: (),
}

impl fmt::Debug for RuntimeTaskStateValidationFailureV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeTaskStateValidationFailureV0")
    }
}

/// Validates the complete persisted-state shape of a task without executing a
/// transaction or minting an authority token.
///
/// Key-to-`task_id` identity remains the caller's separate authenticated-store
/// responsibility. This function validates every status/field group,
/// transition version, commitment relation, and height boundary enforced when
/// the runtime reads an authenticated task.
pub fn validate_authenticated_task_state_v0(
    task: &TaskV1,
    object_version: u64,
    current_height: u64,
) -> Result<(), RuntimeTaskStateValidationFailureV0> {
    validate_authenticated_task(&task.task_id, task, object_version, current_height)
        .map_err(|_| RuntimeTaskStateValidationFailureV0 { _private: () })
}

fn validate_authenticated_fee_policy(policy: &FeePolicyV1) -> Result<(), RuntimeError> {
    CanonicalCommandV1::SetFeePolicy {
        gas_price: policy.gas_price,
        base_gas: policy.base_gas,
        byte_gas: policy.byte_gas,
    }
    .validate()
    .map_err(|_| {
        RuntimeError::AuthenticatedObjectStateInvariant(
            "persisted fee policy is outside canonical bounds",
        )
    })
}

fn load_or_default<T, View>(
    view: &View,
    key: &str,
    object_type: &str,
    default: T,
) -> RuntimeExecutionInternalResultV0<Loaded<T>, View::Error>
where
    T: for<'de> Deserialize<'de>,
    View: TryStateViewV0 + ?Sized,
{
    match view
        .try_get(key)
        .map_err(RuntimeExecutionInternalErrorV0::StateUnavailable)?
    {
        Some(object) => {
            ensure_type(key, &object, object_type)?;
            if object.version == 0 {
                return Err(RuntimeError::AuthenticatedObjectStateInvariant(
                    "persisted object has zero version",
                )
                .into());
            }
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
    use std::cell::Cell;
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use sha2::{Digest, Sha256};
    use trnm_protocol::{
        monetary_state_key, result_commitment_hex, CanonicalCommandV1, MonetaryStateV1,
        CANONICAL_TX_SCHEMA_V1,
    };

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct MemoryView(BTreeMap<String, StateObject>);

    impl StateView for MemoryView {
        fn get(&self, object_key_hex: &str) -> Option<StateObject> {
            self.0.get(object_key_hex).cloned()
        }
    }

    impl TryStateViewV0 for MemoryView {
        type Error = Infallible;

        fn try_get(&self, object_key_hex: &str) -> Result<Option<StateObject>, Self::Error> {
            Ok(self.get(object_key_hex))
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum InjectedStateReadFailure {
        DependencyUnavailable,
    }

    impl fmt::Display for InjectedStateReadFailure {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("nonce mismatch; authenticated state corrupt")
        }
    }

    struct FailingStateView<'a> {
        base: &'a MemoryView,
        fail_key: String,
    }

    impl TryStateViewV0 for FailingStateView<'_> {
        type Error = InjectedStateReadFailure;

        fn try_get(&self, object_key_hex: &str) -> Result<Option<StateObject>, Self::Error> {
            if object_key_hex == self.fail_key.as_str() {
                Err(InjectedStateReadFailure::DependencyUnavailable)
            } else {
                Ok(self.base.get(object_key_hex))
            }
        }
    }

    #[derive(Default)]
    struct RejectEveryReadCountingView {
        reads: Cell<usize>,
    }

    impl RejectEveryReadCountingView {
        fn read_count(&self) -> usize {
            self.reads.get()
        }
    }

    impl TryStateViewV0 for RejectEveryReadCountingView {
        type Error = InjectedStateReadFailure;

        fn try_get(&self, _object_key_hex: &str) -> Result<Option<StateObject>, Self::Error> {
            self.reads.set(self.reads.get() + 1);
            Err(InjectedStateReadFailure::DependencyUnavailable)
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

    #[test]
    fn runtime_error_taxonomy_is_exhaustive_stable_and_dispositioned() {
        use DeterministicRuntimeFailureDispositionV0::{InvariantFault, TransactionReject};

        let cases = [
            (
                RuntimeError::Protocol(ProtocolError::NonCanonical("diagnostic")),
                TransactionReject,
                "protocol_validation_failed",
                "transaction protocol validation failed",
            ),
            (
                RuntimeError::CommitmentConstructionInvariant(ProtocolError::NonCanonical(
                    "diagnostic",
                )),
                InvariantFault,
                "commitment_construction_invariant",
                "validated result commitment construction invariant failed",
            ),
            (
                RuntimeError::SenderMismatch,
                TransactionReject,
                "sender_mismatch",
                "transaction sender does not match signed envelope",
            ),
            (
                RuntimeError::OperatorRequired,
                TransactionReject,
                "operator_required",
                "operator role required",
            ),
            (
                RuntimeError::NonceMismatch {
                    expected: 2,
                    received: 1,
                },
                TransactionReject,
                "nonce_mismatch",
                "account nonce mismatch",
            ),
            (
                RuntimeError::NonceExhausted,
                TransactionReject,
                "nonce_exhausted",
                "account nonce exhausted",
            ),
            (
                RuntimeError::GasLimitExceeded {
                    required: 2,
                    limit: 1,
                },
                TransactionReject,
                "gas_limit_exceeded",
                "transaction gas limit exceeded",
            ),
            (
                RuntimeError::FeeLimitExceeded {
                    required: 2,
                    limit: 1,
                },
                TransactionReject,
                "fee_limit_exceeded",
                "transaction fee limit exceeded",
            ),
            (
                RuntimeError::InsufficientBalance {
                    account: "alice".to_string(),
                    required: 2,
                    available: 1,
                },
                TransactionReject,
                "insufficient_balance",
                "insufficient account balance",
            ),
            (
                RuntimeError::ObjectType("object-key".to_string()),
                InvariantFault,
                "object_type_mismatch",
                "authenticated state object type mismatch",
            ),
            (
                RuntimeError::DecodeObject(
                    "object-key".to_string(),
                    "diagnostic detail".to_string(),
                ),
                InvariantFault,
                "object_decode_failed",
                "authenticated state object decode failed",
            ),
            (
                RuntimeError::EncodeObject("diagnostic detail".to_string()),
                InvariantFault,
                "object_encode_failed",
                "runtime state object encode invariant failed",
            ),
            (
                RuntimeError::TaskAlreadyExists,
                TransactionReject,
                "task_already_exists",
                "task already exists",
            ),
            (
                RuntimeError::TaskNotFound,
                TransactionReject,
                "task_not_found",
                "task not found",
            ),
            (
                RuntimeError::InvalidTaskTransition,
                TransactionReject,
                "invalid_task_transition",
                "invalid task transition",
            ),
            (
                RuntimeError::TaskAuthorityMismatch,
                TransactionReject,
                "task_authority_mismatch",
                "task authority mismatch",
            ),
            (
                RuntimeError::DeadlineExceeded,
                TransactionReject,
                "deadline_exceeded",
                "task result deadline exceeded",
            ),
            (
                RuntimeError::ChallengeWindowOpen,
                TransactionReject,
                "challenge_window_open",
                "task challenge window is still open",
            ),
            (
                RuntimeError::ChallengeWindowClosed,
                TransactionReject,
                "challenge_window_closed",
                "task challenge window is closed",
            ),
            (
                RuntimeError::TaskExpiryUnavailable,
                TransactionReject,
                "task_expiry_unavailable",
                "task is not eligible for expiry",
            ),
            (
                RuntimeError::WorkerAcceptanceRequired,
                TransactionReject,
                "worker_acceptance_required",
                "worker acceptance transaction required",
            ),
            (
                RuntimeError::ConflictingTaskRole,
                TransactionReject,
                "conflicting_task_role",
                "account occupies conflicting task roles",
            ),
            (
                RuntimeError::ReservedSystemAccount,
                TransactionReject,
                "reserved_system_account",
                "reserved system account cannot sign transactions",
            ),
            (
                RuntimeError::ObjectVersionExhausted,
                TransactionReject,
                "object_version_exhausted",
                "runtime state object version capacity exhausted",
            ),
            (
                RuntimeError::ArithmeticOverflow,
                TransactionReject,
                "arithmetic_overflow",
                "transaction arithmetic capacity exceeded",
            ),
            (
                RuntimeError::ArithmeticInvariant("diagnostic detail"),
                InvariantFault,
                "authenticated_state_arithmetic_overflow",
                "authenticated state arithmetic invariant overflowed",
            ),
            (
                RuntimeError::AuthenticatedTaskStateInvariant("diagnostic detail"),
                InvariantFault,
                "authenticated_task_state_invariant",
                "authenticated task state is internally inconsistent",
            ),
            (
                RuntimeError::AuthenticatedObjectStateInvariant("diagnostic detail"),
                InvariantFault,
                "authenticated_object_state_invariant",
                "authenticated state object is internally inconsistent",
            ),
        ];

        assert_eq!(cases.len(), 28);
        let mut codes = BTreeSet::new();
        let mut transaction_rejects = 0;
        let mut invariant_faults = 0;
        for (error, disposition, code, reason) in cases {
            let actual = error.deterministic_failure_v0();
            assert_eq!(actual.disposition(), disposition);
            assert_eq!(actual.code(), code);
            assert_eq!(actual.reason(), reason);
            assert_eq!(error.code(), code);
            assert!(codes.insert(code));
            match disposition {
                TransactionReject => transaction_rejects += 1,
                InvariantFault => invariant_faults += 1,
            }
        }
        assert_eq!(transaction_rejects, 21);
        assert_eq!(invariant_faults, 7);
    }

    #[test]
    fn fallible_execute_matches_legacy_success_and_wraps_real_deterministic_failure() {
        let mut view = MemoryView::default();
        issue(&mut view, 1, "alice", 100_000);
        let candidate = tx(
            "alice",
            1,
            CanonicalCommandV1::Transfer {
                to: "bob".to_string(),
                amount: 10,
            },
        );
        let payload = serde_json::to_vec(&candidate).unwrap();
        let context = ExecutionContext {
            height: 2,
            signer_id: "alice",
            signer_role: "hepta",
            payload_len: payload.len(),
        };
        let legacy = execute(&candidate, context, &view).expect("legacy execution succeeds");
        let fallible =
            try_execute_v0(&candidate, context, &view).expect("fallible execution succeeds");
        assert_eq!(fallible, legacy);

        let mut low_gas = candidate;
        low_gas.max_gas = 1;
        let payload = serde_json::to_vec(&low_gas).unwrap();
        let context = ExecutionContext {
            height: 2,
            signer_id: "alice",
            signer_role: "hepta",
            payload_len: payload.len(),
        };
        let legacy_error = execute(&low_gas, context, &view).expect_err("low gas must reject");
        let attempt_error =
            try_execute_v0(&low_gas, context, &view).expect_err("low gas must reject");
        assert_eq!(
            attempt_error.deterministic_failure_v0(),
            Some(legacy_error.deterministic_failure_v0())
        );
        assert!(attempt_error.state_unavailable().is_none());
    }

    #[test]
    fn fallible_resource_estimate_matches_legacy_success() {
        let mut view = MemoryView::default();
        issue(&mut view, 1, "alice", 100_000);
        let candidate = tx(
            "alice",
            1,
            CanonicalCommandV1::Transfer {
                to: "bob".to_string(),
                amount: 10,
            },
        );
        let payload = serde_json::to_vec(&candidate).unwrap();
        let context = ExecutionContext {
            height: 2,
            signer_id: "alice",
            signer_role: "hepta",
            payload_len: payload.len(),
        };

        let legacy =
            estimate_resources(&candidate, context, &view).expect("legacy estimate succeeds");
        let fallible = try_estimate_resources_v0(&candidate, context, &view)
            .expect("fallible estimate succeeds");

        assert_eq!(fallible, legacy);
    }

    #[test]
    fn fallible_resource_estimate_preserves_typed_policy_read_failure() {
        let base = MemoryView::default();
        let candidate = tx(
            "alice",
            1,
            CanonicalCommandV1::Transfer {
                to: "bob".to_string(),
                amount: 1,
            },
        );
        let payload = serde_json::to_vec(&candidate).unwrap();
        let view = FailingStateView {
            base: &base,
            fail_key: fee_policy_key(),
        };

        let error = try_estimate_resources_v0(
            &candidate,
            ExecutionContext {
                height: 1,
                signer_id: "alice",
                signer_role: "hepta",
                payload_len: payload.len(),
            },
            &view,
        )
        .expect_err("failed policy read must remain unavailable");

        assert_eq!(
            error.state_unavailable(),
            Some(&InjectedStateReadFailure::DependencyUnavailable)
        );
        assert!(error.deterministic_failure_v0().is_none());
        assert!(error.to_string().contains("nonce mismatch"));
    }

    #[test]
    fn fallible_resource_estimate_classifies_validation_before_state_reads() {
        let mut malformed = tx(
            "alice",
            1,
            CanonicalCommandV1::Transfer {
                to: "bob".to_string(),
                amount: 1,
            },
        );
        malformed.schema = "foreign-schema".to_string();
        let payload = serde_json::to_vec(&malformed).unwrap();
        let view = RejectEveryReadCountingView::default();
        let malformed_error = try_estimate_resources_v0(
            &malformed,
            ExecutionContext {
                height: 1,
                signer_id: "alice",
                signer_role: "hepta",
                payload_len: payload.len(),
            },
            &view,
        )
        .expect_err("malformed transaction must reject before state reads");
        assert_eq!(
            malformed_error
                .deterministic_failure_v0()
                .expect("deterministic protocol rejection")
                .code(),
            "protocol_validation_failed"
        );
        assert!(malformed_error.state_unavailable().is_none());
        assert_eq!(view.read_count(), 0, "validation attempted a state read");

        let valid = tx(
            "alice",
            1,
            CanonicalCommandV1::Transfer {
                to: "bob".to_string(),
                amount: 1,
            },
        );
        let payload = serde_json::to_vec(&valid).unwrap();
        let context_error = try_estimate_resources_v0(
            &valid,
            ExecutionContext {
                height: 1,
                signer_id: "mallory",
                signer_role: "hepta",
                payload_len: payload.len(),
            },
            &view,
        )
        .expect_err("sender mismatch must reject before state reads");
        assert_eq!(
            context_error
                .deterministic_failure_v0()
                .expect("deterministic context rejection")
                .code(),
            "sender_mismatch"
        );
        assert!(context_error.state_unavailable().is_none());
        assert_eq!(view.read_count(), 0, "context validation read state");
    }

    #[test]
    fn operator_recovery_estimate_does_not_read_fee_policy() {
        let base = MemoryView::default();
        let candidate = tx(
            "operator",
            1,
            CanonicalCommandV1::SetFeePolicy {
                gas_price: 2,
                base_gas: 1_000,
                byte_gas: 3,
            },
        );
        let payload = serde_json::to_vec(&candidate).unwrap();
        let view = RejectEveryReadCountingView::default();

        let fallible = try_estimate_resources_v0(
            &candidate,
            ExecutionContext {
                height: 1,
                signer_id: "operator",
                signer_role: "operator",
                payload_len: payload.len(),
            },
            &view,
        )
        .expect("operator recovery estimate must use the bootstrap policy");
        let legacy = estimate_resources(
            &candidate,
            ExecutionContext {
                height: 1,
                signer_id: "operator",
                signer_role: "operator",
                payload_len: payload.len(),
            },
            &base,
        )
        .expect("legacy operator estimate succeeds");

        assert_eq!(fallible, legacy);
        assert_eq!(fallible.fee_estimate, 0);
        assert_eq!(view.read_count(), 0, "operator estimate read state");
    }

    #[test]
    fn failed_task_read_is_unavailable_before_task_not_found_and_discards_staging() {
        let mut base = MemoryView::default();
        issue(&mut base, 1, "alice", 100_000);
        let before = base.clone();
        let candidate = tx(
            "alice",
            1,
            CanonicalCommandV1::ExpireTask {
                task_id: "missing-task".to_string(),
            },
        );
        let payload = serde_json::to_vec(&candidate).unwrap();
        let view = FailingStateView {
            base: &base,
            fail_key: task_key("missing-task"),
        };
        let error = try_execute_v0(
            &candidate,
            ExecutionContext {
                height: 2,
                signer_id: "alice",
                signer_role: "hepta",
                payload_len: payload.len(),
            },
            &view,
        )
        .expect_err("failed task read must be unavailable");

        assert_eq!(
            error.state_unavailable(),
            Some(&InjectedStateReadFailure::DependencyUnavailable)
        );
        assert!(error.deterministic_failure_v0().is_none());
        assert_eq!(
            base, before,
            "failed read exposed staged fee/nonce mutations"
        );
    }

    #[test]
    fn failed_account_read_is_unavailable_before_default_account_semantics() {
        let base = MemoryView::default();
        let before = base.clone();
        let candidate = tx(
            "alice",
            1,
            CanonicalCommandV1::Transfer {
                to: "bob".to_string(),
                amount: 1,
            },
        );
        let payload = serde_json::to_vec(&candidate).unwrap();
        let view = FailingStateView {
            base: &base,
            fail_key: account_key("alice"),
        };
        let error = try_execute_v0(
            &candidate,
            ExecutionContext {
                height: 1,
                signer_id: "alice",
                signer_role: "hepta",
                payload_len: payload.len(),
            },
            &view,
        )
        .expect_err("failed account read must be unavailable");

        assert_eq!(
            error.state_unavailable(),
            Some(&InjectedStateReadFailure::DependencyUnavailable)
        );
        assert!(error.deterministic_failure_v0().is_none());
        assert_eq!(base, before, "failed read mutated the authenticated view");
    }

    #[test]
    fn execute_errors_return_no_receipt_or_mutations() {
        let mut view = MemoryView::default();
        view.0.insert(
            account_key("alice"),
            StateObject {
                object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
                version: 7,
                value_bytes: serde_json::to_vec(&AccountV1 {
                    account: "alice".to_string(),
                    balance: 100_000,
                    nonce: 0,
                })
                .unwrap(),
            },
        );
        view.0.insert(
            account_key("bob"),
            StateObject {
                object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
                version: 9,
                value_bytes: serde_json::to_vec(&AccountV1 {
                    account: "bob".to_string(),
                    balance: u128::MAX,
                    nonce: 0,
                })
                .unwrap(),
            },
        );
        let before = view.clone();

        let attempts = [
            (
                tx(
                    "alice",
                    1,
                    CanonicalCommandV1::Transfer {
                        to: "carol".to_string(),
                        amount: 100_000,
                    },
                ),
                "insufficient_balance",
                false,
            ),
            (
                tx(
                    "alice",
                    1,
                    CanonicalCommandV1::Transfer {
                        to: "bob".to_string(),
                        amount: 1,
                    },
                ),
                "authenticated_state_arithmetic_overflow",
                true,
            ),
        ];

        for (candidate, expected_code, expect_invariant_fault) in attempts {
            let payload = serde_json::to_vec(&candidate).unwrap();
            let error = execute(
                &candidate,
                ExecutionContext {
                    height: 1,
                    signer_id: "alice",
                    signer_role: "hepta",
                    payload_len: payload.len(),
                },
                &view,
            )
            .expect_err("failed execution must not return a receipt");
            let classification = error.deterministic_failure_v0();
            assert_eq!(classification.code(), expected_code);
            assert_eq!(
                classification.disposition()
                    == DeterministicRuntimeFailureDispositionV0::InvariantFault,
                expect_invariant_fault
            );
            assert_eq!(view, before, "failed execution exposed staged mutations");
        }
    }

    #[test]
    fn mint_capacity_exhaustion_is_a_transaction_reject_without_mutations() {
        let mut view = MemoryView::default();
        issue(&mut view, 1, "alice", u128::MAX);
        let before = view.clone();
        let candidate = tx(
            "operator",
            2,
            CanonicalCommandV1::CreditAccount {
                account: "bob".to_string(),
                amount: 1,
            },
        );
        let payload = serde_json::to_vec(&candidate).unwrap();
        let error = execute(
            &candidate,
            ExecutionContext {
                height: 2,
                signer_id: "operator",
                signer_role: "operator",
                payload_len: payload.len(),
            },
            &view,
        )
        .expect_err("mint beyond total supply capacity must reject");
        let classification = error.deterministic_failure_v0();
        assert_eq!(classification.code(), "arithmetic_overflow");
        assert_eq!(
            classification.disposition(),
            DeterministicRuntimeFailureDispositionV0::TransactionReject
        );
        assert_eq!(view, before, "failed mint exposed staged mutations");
    }

    #[test]
    fn inconsistent_authenticated_task_fields_are_invariant_faults() {
        let mut view = MemoryView::default();
        view.0.insert(
            account_key("worker"),
            StateObject {
                object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
                version: 1,
                value_bytes: serde_json::to_vec(&AccountV1 {
                    account: "worker".to_string(),
                    balance: 100_000,
                    nonce: 0,
                })
                .unwrap(),
            },
        );
        view.0.insert(
            task_key("task-1"),
            StateObject {
                object_type: TASK_OBJECT_TYPE_V1.to_string(),
                version: 1,
                value_bytes: serde_json::to_vec(&TaskV1 {
                    task_id: "task-1".to_string(),
                    client: "client".to_string(),
                    worker: Some("worker".to_string()),
                    reward: 10,
                    worker_stake: 5,
                    result_deadline_height: 20,
                    challenge_window_blocks: 5,
                    status: TaskStatusV1::Revealed,
                    commitment_hex: Some("11".repeat(32)),
                    result_hash_hex: Some("22".repeat(32)),
                    reveal_salt_hex: Some("33".repeat(32)),
                    challenge_deadline_height: None,
                    consumer: None,
                    consumed_units: 0,
                    consumption_payment: 0,
                    receipt_hash_hex: None,
                    challenger: None,
                    challenge_bond: 0,
                    evidence_hash_hex: None,
                })
                .unwrap(),
            },
        );
        let candidate = tx(
            "worker",
            1,
            CanonicalCommandV1::RecordConsumption {
                task_id: "task-1".to_string(),
                units: 1,
                payment: 1,
                receipt_hash_hex: "44".repeat(32),
            },
        );
        let payload = serde_json::to_vec(&candidate).unwrap();
        let error = execute(
            &candidate,
            ExecutionContext {
                height: 10,
                signer_id: "worker",
                signer_role: "hepta",
                payload_len: payload.len(),
            },
            &view,
        )
        .expect_err("inconsistent authenticated task must fail stop");
        assert_eq!(
            error.deterministic_failure_v0().disposition(),
            DeterministicRuntimeFailureDispositionV0::InvariantFault
        );
        assert_eq!(error.code(), "authenticated_task_state_invariant");
    }

    #[test]
    fn read_only_task_state_validation_reuses_full_runtime_invariants() {
        let open = TaskV1 {
            task_id: "task-open".to_string(),
            client: "client".to_string(),
            worker: None,
            reward: 10,
            worker_stake: 5,
            result_deadline_height: 20,
            challenge_window_blocks: 10,
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
        };
        assert!(validate_authenticated_task_state_v0(&open, 1, 2).is_ok());

        let mut contradictory = open.clone();
        contradictory.worker = Some("worker".to_string());
        assert!(validate_authenticated_task_state_v0(&contradictory, 1, 2).is_err());
        assert!(validate_authenticated_task_state_v0(&open, 2, 2).is_err());

        let mut view = MemoryView::default();
        setup_paid_task(&mut view, 10);
        let revealed = view.task("task-1");
        assert!(validate_authenticated_task_state_v0(&revealed, 4, 5).is_ok());
        assert!(validate_authenticated_task_state_v0(&revealed, 4, 4).is_err());
    }

    #[test]
    fn authenticated_task_version_and_terminal_height_are_exact() {
        fn expect_task_invariant(view: &MemoryView, candidate: &CanonicalTxV1, height: u64) {
            let before = view.clone();
            let payload = serde_json::to_vec(candidate).unwrap();
            let error = execute(
                candidate,
                ExecutionContext {
                    height,
                    signer_id: &candidate.sender,
                    signer_role: "hepta",
                    payload_len: payload.len(),
                },
                view,
            )
            .expect_err("unreachable authenticated task state must fail stop");
            assert_eq!(error.code(), "authenticated_task_state_invariant");
            assert_eq!(
                error.deterministic_failure_v0().disposition(),
                DeterministicRuntimeFailureDispositionV0::InvariantFault
            );
            assert_eq!(view, &before, "failed validation exposed staged mutations");
        }

        let mut revealed = MemoryView::default();
        setup_paid_task(&mut revealed, 10);
        let task_key = task_key("task-1");

        let mut wrong_version = revealed.clone();
        wrong_version.0.get_mut(&task_key).unwrap().version = 5;
        expect_task_invariant(
            &wrong_version,
            &tx(
                "client",
                2,
                CanonicalCommandV1::ExpireTask {
                    task_id: "task-1".to_string(),
                },
            ),
            16,
        );

        let mut future_reveal = revealed.clone();
        let mut task = future_reveal.task("task-1");
        task.challenge_deadline_height = Some(20);
        future_reveal.0.get_mut(&task_key).unwrap().value_bytes =
            serde_json::to_vec(&task).unwrap();
        expect_task_invariant(
            &future_reveal,
            &tx(
                "client",
                2,
                CanonicalCommandV1::ExpireTask {
                    task_id: "task-1".to_string(),
                },
            ),
            7,
        );

        let mut premature_expired = revealed.clone();
        let mut task = premature_expired.task("task-1");
        task.status = TaskStatusV1::Expired;
        let object = premature_expired.0.get_mut(&task_key).unwrap();
        object.version = 5;
        object.value_bytes = serde_json::to_vec(&task).unwrap();
        expect_task_invariant(
            &premature_expired,
            &tx(
                "client",
                2,
                CanonicalCommandV1::ExpireTask {
                    task_id: "task-1".to_string(),
                },
            ),
            7,
        );

        run(
            &mut revealed,
            tx(
                "consumer",
                1,
                CanonicalCommandV1::RecordConsumption {
                    task_id: "task-1".to_string(),
                    units: 1,
                    payment: 1,
                    receipt_hash_hex: "66".repeat(32),
                },
            ),
            6,
            "hepta",
        );
        let mut premature_settled = revealed;
        let mut task = premature_settled.task("task-1");
        task.status = TaskStatusV1::Settled;
        let object = premature_settled.0.get_mut(&task_key).unwrap();
        object.version = 6;
        object.value_bytes = serde_json::to_vec(&task).unwrap();
        expect_task_invariant(
            &premature_settled,
            &tx(
                "client",
                2,
                CanonicalCommandV1::SettleTask {
                    task_id: "task-1".to_string(),
                },
            ),
            7,
        );
    }

    #[test]
    fn task_horizon_capacity_exhaustion_is_a_transaction_reject_without_mutations() {
        let mut view = MemoryView::default();
        view.0.insert(
            account_key("client"),
            StateObject {
                object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
                version: 1,
                value_bytes: serde_json::to_vec(&AccountV1 {
                    account: "client".to_string(),
                    balance: 100_000,
                    nonce: 0,
                })
                .unwrap(),
            },
        );
        let before = view.clone();
        let candidate = tx(
            "client",
            1,
            CanonicalCommandV1::CreateTask {
                task_id: "task-1".to_string(),
                reward: 10,
                worker_stake: 5,
                result_deadline_height: u64::MAX,
                challenge_window_blocks: 2,
            },
        );
        let payload = serde_json::to_vec(&candidate).unwrap();
        let error = execute(
            &candidate,
            ExecutionContext {
                height: u64::MAX - 1,
                signer_id: "client",
                signer_role: "hepta",
                payload_len: payload.len(),
            },
            &view,
        )
        .expect_err("task horizon beyond height capacity must reject");
        let classification = error.deterministic_failure_v0();
        assert_eq!(classification.code(), "arithmetic_overflow");
        assert_eq!(
            classification.disposition(),
            DeterministicRuntimeFailureDispositionV0::TransactionReject
        );
        assert_eq!(
            view, before,
            "failed task creation exposed staged mutations"
        );
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
    fn revealed_task_can_be_challenged_without_a_consumption_record() {
        let mut view = MemoryView::default();
        setup_paid_task(&mut view, 10);
        run(
            &mut view,
            tx(
                "challenger",
                1,
                CanonicalCommandV1::OpenChallenge {
                    task_id: "task-1".to_string(),
                    bond: 1_000,
                    evidence_hash_hex: "55".repeat(32),
                },
            ),
            6,
            "hepta",
        );
        assert_eq!(view.task("task-1").status, TaskStatusV1::Challenged);
        assert!(view.task("task-1").consumer.is_none());

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
            7,
            "operator",
        );
        assert_eq!(view.task("task-1").status, TaskStatusV1::ResolvedForWorker);
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
    fn fee_policy_recovery_still_rejects_shape_encoding_and_version_corruption() {
        let valid_bytes = serde_json::to_vec(&FeePolicyV1::default()).unwrap();
        let corrupt_objects = [
            StateObject {
                object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
                version: 1,
                value_bytes: valid_bytes.clone(),
            },
            StateObject {
                object_type: FEE_POLICY_OBJECT_TYPE_V1.to_string(),
                version: 0,
                value_bytes: valid_bytes,
            },
            StateObject {
                object_type: FEE_POLICY_OBJECT_TYPE_V1.to_string(),
                version: 1,
                value_bytes: b"not-json".to_vec(),
            },
        ];

        for corrupt in corrupt_objects {
            let mut view = MemoryView::default();
            view.0.insert(fee_policy_key(), corrupt);
            let before = view.clone();
            let candidate = tx(
                "operator",
                1,
                CanonicalCommandV1::SetFeePolicy {
                    gas_price: 2,
                    base_gas: 1_000,
                    byte_gas: 3,
                },
            );
            let payload = serde_json::to_vec(&candidate).unwrap();
            let error = execute(
                &candidate,
                ExecutionContext {
                    height: 1,
                    signer_id: "operator",
                    signer_role: "operator",
                    payload_len: payload.len(),
                },
                &view,
            )
            .expect_err("operator recovery must not overwrite malformed object authority");
            assert_eq!(
                error.deterministic_failure_v0().disposition(),
                DeterministicRuntimeFailureDispositionV0::InvariantFault
            );
            assert_eq!(view, before, "failed recovery exposed staged mutations");
        }
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
