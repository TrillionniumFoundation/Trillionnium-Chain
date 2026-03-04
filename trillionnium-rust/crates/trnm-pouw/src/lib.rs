use sha2::{Digest, Sha256};
use thiserror::Error;
use trnm_state::StateStore;
use trnm_types::{Hash32, ObjectRef, ProofType, TaskMetadata, TaskObject, TaskStatus};

pub mod verification;
use verification::registry::VerifierRegistry;
use verification::VerificationResult;

fn get_default_registry() -> VerifierRegistry {
    VerifierRegistry::with_builtin_verifiers()
}

#[derive(Debug, Error)]
pub enum PouwError {
    #[error("state error: {0}")]
    State(String),
    #[error("invalid transition")]
    InvalidTransition,
    #[error("version conflict")]
    VersionConflict,
    #[error("missing worker")]
    MissingWorker,
    #[error("missing commitment")]
    MissingCommitment,
    #[error("commitment mismatch")]
    CommitmentMismatch,
    #[error("unauthorized")]
    Unauthorized,
    #[error("insufficient stake")]
    InsufficientStake,
    #[error("deadline exceeded")]
    DeadlineExceeded,
}

impl PouwError {
    /// Stable external error code for protocol-facing surfaces.
    pub fn stable_code(&self) -> &'static str {
        match self {
            PouwError::InvalidTransition => "InvalidTransition",
            PouwError::VersionConflict => "VersionConflict",
            PouwError::MissingWorker => "MissingWorker",
            PouwError::MissingCommitment => "MissingCommitment",
            PouwError::CommitmentMismatch => "CommitmentMismatch",
            PouwError::Unauthorized => "Unauthorized",
            PouwError::InsufficientStake => "InsufficientStake",
            PouwError::DeadlineExceeded => "DeadlineExceeded",
            // Internal-only state storage errors are not protocol-stable.
            PouwError::State(_) => "StateInternal",
        }
    }
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() {
        return true;
    }
    if n.len() > h.len() {
        return false;
    }
    h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

fn map_state_err(err: String) -> PouwError {
    if contains_ascii_case_insensitive(&err, "version conflict") {
        PouwError::VersionConflict
    } else {
        PouwError::State(err)
    }
}

const DEFAULT_ASSIGNMENT_WINDOW_BLOCKS: u64 = 20;
const DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 20;
const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 100;
const DEFAULT_CHALLENGE_MIN_BOND: u128 = 10;
const DEFAULT_CHALLENGE_MIN_BOND_BOUNTY_BPS: u128 = 500;
const DEFAULT_CHALLENGE_MIN_BOND_WORKER_STAKE_BPS: u128 = 0;
const DEFAULT_MIN_WORKER_STAKE: u128 = 1;
const DEFAULT_CHALLENGE_SUCCESS_BOUNTY: u128 = 1;
const BPS_DENOMINATOR: u128 = 10_000;
const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";
const WORKER_SLASH_TREASURY_ACCOUNT: &str = "treasury.worker_slashes";
const DEFAULT_RESOLVE_AUTHORITY: &str = "governance.resolve_authority";
const MIN_CHALLENGE_WINDOW_BLOCKS: u64 = 1;

fn worker_stake_lock_account(task_id: u64) -> String {
    format!("worker_stake_lock.{}", task_id)
}

fn ensure_balance_at_least(st: &StateStore, account: &str, amount: u128) -> Result<(), PouwError> {
    let cur = st.balance_of(account);
    if cur < amount {
        return Err(PouwError::State(format!(
            "insufficient balance: address={}, have={}, need={}",
            account, cur, amount
        )));
    }
    Ok(())
}

fn require_deadline_exceeded(deadline: Option<u64>, current_height: u64) -> Result<(), PouwError> {
    let deadline = deadline.ok_or(PouwError::InvalidTransition)?;
    if current_height <= deadline {
        return Err(PouwError::InvalidTransition);
    }
    Ok(())
}

fn reject_if_deadline_exceeded(
    deadline: Option<u64>,
    current_height: u64,
) -> Result<(), PouwError> {
    let deadline = deadline.ok_or(PouwError::InvalidTransition)?;
    if current_height > deadline {
        return Err(PouwError::DeadlineExceeded);
    }
    Ok(())
}

fn reject_if_deadline_exceeded_optional(
    deadline: Option<u64>,
    current_height: u64,
) -> Result<(), PouwError> {
    if let Some(deadline) = deadline {
        if current_height > deadline {
            return Err(PouwError::DeadlineExceeded);
        }
    }
    Ok(())
}

fn ceil_mul_div(value: u128, numerator: u128, denominator: u128) -> u128 {
    if value == 0 || numerator == 0 {
        return 0;
    }
    value
        .saturating_mul(numerator)
        .saturating_add(denominator.saturating_sub(1))
        / denominator
}

fn required_challenge_bond(st: &StateStore, task: &TaskObject) -> u128 {
    let static_floor = st
        .gov_param_u128("challenge_min_bond")
        .unwrap_or(DEFAULT_CHALLENGE_MIN_BOND);

    let bounty_bps = st
        .gov_param_u128("challenge_min_bond_bounty_bps")
        .unwrap_or(DEFAULT_CHALLENGE_MIN_BOND_BOUNTY_BPS);
    let bounty_floor = ceil_mul_div(task.bounty, bounty_bps, BPS_DENOMINATOR);

    let min_worker_stake = st
        .gov_param_u128("min_worker_stake")
        .unwrap_or(DEFAULT_MIN_WORKER_STAKE);
    let worker_stake_bps = st
        .gov_param_u128("challenge_min_bond_worker_stake_bps")
        .unwrap_or(DEFAULT_CHALLENGE_MIN_BOND_WORKER_STAKE_BPS);
    let worker_stake_floor = ceil_mul_div(min_worker_stake, worker_stake_bps, BPS_DENOMINATOR);

    static_floor.max(bounty_floor).max(worker_stake_floor)
}

fn resolve_authority_account(st: &StateStore) -> String {
    st.gov_param_string("resolve_authority")
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_RESOLVE_AUTHORITY.to_string())
}

fn validate_challenge_accounting_invariants(task: &TaskObject) -> Result<(), PouwError> {
    let has_bond = task.challenge_bond.is_some();
    let has_challenger = task.challenger.is_some();

    if matches!(task.challenge_bond, Some(0)) {
        return Err(PouwError::State(
            "challenge metadata contains zero challenge bond".into(),
        ));
    }

    if let Some(challenger) = task.challenger.as_ref() {
        let challenger_trimmed = challenger.trim();
        if challenger_trimmed.is_empty() {
            return Err(PouwError::State(
                "challenge metadata contains blank challenger identity".into(),
            ));
        }
        if challenger_trimmed != challenger {
            return Err(PouwError::State(
                "challenge metadata contains non-canonical challenger identity".into(),
            ));
        }
    }

    if has_bond != has_challenger {
        return Err(PouwError::State(format!(
            "inconsistent challenge fields: status={:?}, challenge_bond_present={}, challenger_present={}",
            task.status, has_bond, has_challenger
        )));
    }

    match task.status {
        TaskStatus::Open | TaskStatus::Assigned | TaskStatus::Committed => {
            if has_bond
                || task.challenge_bond_forfeited.is_some()
                || task.challenged_at_height.is_some()
                || task.challenge_deadline_height.is_some()
                || task.resolve_deadline_height.is_some()
            {
                return Err(PouwError::State(format!(
                    "stale challenge fields for non-challenged status: status={:?}",
                    task.status
                )));
            }
        }
        TaskStatus::Revealed => {
            if has_bond
                || task.challenge_bond_forfeited.is_some()
                || task.challenged_at_height.is_some()
                || task.resolve_deadline_height.is_some()
            {
                return Err(PouwError::State(format!(
                    "stale challenge fields for non-challenged status: status={:?}",
                    task.status
                )));
            }
        }
        TaskStatus::Challenged => {
            if !has_bond {
                return Err(PouwError::State(
                    "challenged status requires challenge bond fields".into(),
                ));
            }
            if task.resolve_deadline_height.is_none()
                || task.challenged_at_height.is_none()
                || task.challenge_deadline_height.is_none()
            {
                return Err(PouwError::State(
                    "challenged status requires challenged_at_height, challenge_deadline_height, and resolve_deadline_height"
                        .into(),
                ));
            }
            let challenged_at = task.challenged_at_height.expect("checked is_some");
            let challenge_deadline = task.challenge_deadline_height.expect("checked is_some");
            let resolve_deadline = task.resolve_deadline_height.expect("checked is_some");
            if challenged_at > challenge_deadline || challenge_deadline > resolve_deadline {
                return Err(PouwError::State(
                    "challenged status has non-monotonic challenge/resolve deadlines".into(),
                ));
            }
            if task.challenge_bond_forfeited.is_some() {
                return Err(PouwError::State(
                    "challenged task cannot have terminal challenge bond outcome".into(),
                ));
            }
        }
        TaskStatus::Completed | TaskStatus::Slashed => {
            if task.challenge_bond_forfeited.is_some() && !has_bond {
                return Err(PouwError::State(
                    "terminal challenge bond outcome requires challenge bond fields".into(),
                ));
            }
            if has_bond && task.challenge_bond_forfeited.is_none() {
                return Err(PouwError::State(
                    "terminal challenged task missing challenge bond outcome".into(),
                ));
            }
            if has_bond
                && (task.challenge_deadline_height.is_none()
                    || task.challenged_at_height.is_none()
                    || task.resolve_deadline_height.is_none())
            {
                return Err(PouwError::State(
                    "terminal challenged task missing challenge timing metadata".into(),
                ));
            }
            if !has_bond
                && (task.challenged_at_height.is_some() || task.resolve_deadline_height.is_some())
            {
                return Err(PouwError::State(
                    "terminal non-challenged task has stale challenge timing fields".into(),
                ));
            }
        }
    }

    Ok(())
}

fn preflight_challenge_transfer(
    st: &StateStore,
    challenger: &str,
    challenge_bond: u128,
) -> Result<(), PouwError> {
    if st.balance_of(challenger) < challenge_bond {
        return Err(PouwError::InsufficientStake);
    }

    let mut sim = st.clone();
    sim.debit_balance(challenger, challenge_bond)
        .map_err(|_| PouwError::InsufficientStake)?;
    sim.credit_balance(CHALLENGE_ESCROW_ACCOUNT, challenge_bond)
        .map_err(PouwError::State)?;
    Ok(())
}

fn preflight_resolve_transfers(
    st: &StateStore,
    task: &TaskObject,
    slash_worker: bool,
) -> Result<(), PouwError> {
    let mut sim = st.clone();

    if let Some(bond) = task.challenge_bond {
        sim.debit_balance(CHALLENGE_ESCROW_ACCOUNT, bond)
            .map_err(PouwError::State)?;
        if slash_worker {
            if let Some(ref challenger) = task.challenger {
                sim.credit_balance(challenger, bond)
                    .map_err(PouwError::State)?;
            }
        } else {
            sim.credit_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, bond)
                .map_err(PouwError::State)?;
        }
    }

    if slash_worker {
        let _ = maybe_pay_challenge_success_bounty(&mut sim, task)?;
    }

    settle_worker_stake_for_terminal_state(&mut sim, task)?;
    Ok(())
}

fn preflight_timeout_transfers(
    st: &StateStore,
    task: &TaskObject,
    forfeit_challenge_bond: bool,
    refund_challenge_bond: bool,
) -> Result<(), PouwError> {
    if forfeit_challenge_bond && refund_challenge_bond {
        return Err(PouwError::State(
            "timeout challenge transfer mode conflict".into(),
        ));
    }
    if (forfeit_challenge_bond || refund_challenge_bond) && task.challenge_bond.is_none() {
        return Err(PouwError::State(
            "timeout challenge transfer requested without posted challenge bond".into(),
        ));
    }
    if refund_challenge_bond && task.challenge_bond.is_some() && task.challenger.is_none() {
        return Err(PouwError::State(
            "timeout challenge refund requested without challenger".into(),
        ));
    }
    if forfeit_challenge_bond && task.challenge_bond.is_some() && task.challenger.is_none() {
        return Err(PouwError::State(
            "timeout challenge forfeit requested without challenger".into(),
        ));
    }

    let mut sim = st.clone();

    if let Some(bond) = task.challenge_bond {
        if forfeit_challenge_bond {
            sim.debit_balance(CHALLENGE_ESCROW_ACCOUNT, bond)
                .map_err(PouwError::State)?;
            sim.credit_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, bond)
                .map_err(PouwError::State)?;
        } else if refund_challenge_bond {
            sim.debit_balance(CHALLENGE_ESCROW_ACCOUNT, bond)
                .map_err(PouwError::State)?;
            if let Some(ref challenger) = task.challenger {
                sim.credit_balance(challenger, bond)
                    .map_err(PouwError::State)?;
            }
        }
    }

    settle_worker_stake_for_terminal_state(&mut sim, task)?;
    Ok(())
}

fn compute_commitment(
    task_id: u64,
    result_hash: &Hash32,
    reveal_salt: &[u8; 32],
    worker: &str,
) -> Hash32 {
    let payload = format!(
        "{}|{}|{}|{}",
        task_id,
        hex::encode(result_hash),
        hex::encode(reveal_salt),
        worker
    );
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hasher.finalize().into()
}

pub fn apply_create_task(
    st: &mut StateStore,
    task_id: u64,
    creator: String,
    bounty: u128,
) -> Result<ObjectRef, PouwError> {
    // Boundary hardening: creator account id must be canonical and non-blank
    // before task object is persisted into state.
    let creator_trimmed = creator.trim();
    if creator_trimmed.is_empty() || creator_trimmed != creator {
        return Err(PouwError::Unauthorized);
    }

    let task = TaskObject {
        task_id,
        creator,
        bounty,
        status: TaskStatus::Open,
        proof_type: Default::default(),
        metadata: None,
        worker: None,
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: None,
        reveal_deadline_height: None,
        challenge_deadline_height: None,
        challenge_window_blocks_snapshot: None,
        challenged_at_height: None,
        resolve_deadline_height: None,
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 1,
    };
    st.put_task_new(task).map_err(map_state_err)
}

pub fn apply_create_task_with_metadata(
    st: &mut StateStore,
    task_id: u64,
    creator: String,
    bounty: u128,
    metadata: Option<TaskMetadata>,
) -> Result<ObjectRef, PouwError> {
    // Boundary hardening: creator account id must be canonical and non-blank
    // before task object is persisted into state.
    let creator_trimmed = creator.trim();
    if creator_trimmed.is_empty() || creator_trimmed != creator {
        return Err(PouwError::Unauthorized);
    }

    let task = TaskObject {
        task_id,
        creator,
        bounty,
        status: TaskStatus::Open,
        proof_type: Default::default(),
        metadata,
        worker: None,
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: None,
        reveal_deadline_height: None,
        challenge_deadline_height: None,
        challenge_window_blocks_snapshot: None,
        challenged_at_height: None,
        resolve_deadline_height: None,
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 1,
    };
    st.put_task_new(task).map_err(map_state_err)
}

pub fn apply_accept_task(
    st: &mut StateStore,
    task_ref: ObjectRef,
    worker: String,
) -> Result<ObjectRef, PouwError> {
    apply_accept_task_at_height(st, task_ref, worker, 0)
}

pub fn apply_accept_task_at_height(
    st: &mut StateStore,
    task_ref: ObjectRef,
    worker: String,
    current_height: u64,
) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    if task.status != TaskStatus::Open {
        return Err(PouwError::InvalidTransition);
    }

    // Gate hardening: enforce canonical worker account ids at assignment so
    // malformed payloads cannot lock stake under blank/whitespace variants.
    let worker_trimmed = worker.trim();
    if worker_trimmed.is_empty() || worker_trimmed != worker {
        return Err(PouwError::Unauthorized);
    }

    let min_worker_stake = st
        .gov_param_u128("min_worker_stake")
        .unwrap_or(DEFAULT_MIN_WORKER_STAKE);
    let worker_balance = st.balance_of(&worker);
    if worker_balance < min_worker_stake {
        return Err(PouwError::InsufficientStake);
    }

    let lock_account = worker_stake_lock_account(task_ref.id);
    let lock_balance = st.balance_of(&lock_account);
    lock_balance.checked_add(min_worker_stake).ok_or_else(|| {
        PouwError::State(format!(
            "balance overflow on credit: address={}, current={}, amount={}",
            lock_account, lock_balance, min_worker_stake
        ))
    })?;

    task.status = TaskStatus::Assigned;
    task.worker = Some(worker.clone());
    task.committed_at_height = Some(current_height);
    task.reveal_deadline_height =
        Some(current_height.saturating_add(DEFAULT_ASSIGNMENT_WINDOW_BLOCKS));
    let next_ref = st.update_task(task_ref, task).map_err(map_state_err)?;

    st.debit_balance(&worker, min_worker_stake)
        .map_err(|_| PouwError::InsufficientStake)?;
    st.credit_balance(&lock_account, min_worker_stake)
        .map_err(PouwError::State)?;

    Ok(next_ref)
}

fn settle_worker_stake_for_terminal_state(
    st: &mut StateStore,
    task: &TaskObject,
) -> Result<(), PouwError> {
    let Some(worker) = task.worker.as_ref() else {
        return Ok(());
    };

    let lock_account = worker_stake_lock_account(task.task_id);
    let locked = st.balance_of(&lock_account);
    if locked == 0 {
        return Ok(());
    }

    st.debit_balance(&lock_account, locked)
        .map_err(PouwError::State)?;
    if task.status == TaskStatus::Slashed {
        st.credit_balance(WORKER_SLASH_TREASURY_ACCOUNT, locked)
            .map_err(PouwError::State)?;
    } else {
        st.credit_balance(worker, locked)
            .map_err(PouwError::State)?;
    }
    Ok(())
}

fn maybe_pay_challenge_success_bounty(
    st: &mut StateStore,
    task: &TaskObject,
) -> Result<u128, PouwError> {
    if task.status != TaskStatus::Slashed {
        return Ok(0);
    }
    let Some(challenger) = task.challenger.as_ref() else {
        return Ok(0);
    };

    let configured_bounty = st
        .gov_param_u128("challenge_success_bounty")
        .unwrap_or(DEFAULT_CHALLENGE_SUCCESS_BOUNTY);
    if configured_bounty == 0 {
        return Ok(0);
    }

    let lock_account = worker_stake_lock_account(task.task_id);
    let lock_available = st.balance_of(&lock_account);
    let from_lock = configured_bounty.min(lock_available);

    if from_lock > 0 {
        st.debit_balance(&lock_account, from_lock)
            .map_err(PouwError::State)?;
        st.credit_balance(challenger, from_lock)
            .map_err(PouwError::State)?;
        return Ok(from_lock);
    }

    let slash_treasury_available = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let from_slash_treasury = configured_bounty.min(slash_treasury_available);
    if from_slash_treasury > 0 {
        st.debit_balance(WORKER_SLASH_TREASURY_ACCOUNT, from_slash_treasury)
            .map_err(PouwError::State)?;
        st.credit_balance(challenger, from_slash_treasury)
            .map_err(PouwError::State)?;
    }

    Ok(from_slash_treasury)
}

pub fn apply_commit_result(
    st: &mut StateStore,
    task_ref: ObjectRef,
    worker: String,
    committed_hash: Hash32,
) -> Result<ObjectRef, PouwError> {
    apply_commit_result_at_height(st, task_ref, worker, committed_hash, 0)
}

pub fn apply_commit_result_at_height(
    st: &mut StateStore,
    task_ref: ObjectRef,
    worker: String,
    committed_hash: Hash32,
    current_height: u64,
) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    if task.status != TaskStatus::Assigned {
        return Err(PouwError::InvalidTransition);
    }

    let assigned_worker = task.worker.clone().ok_or(PouwError::MissingWorker)?;
    if assigned_worker != worker {
        return Err(PouwError::Unauthorized);
    }

    task.status = TaskStatus::Committed;
    task.committed_hash = Some(committed_hash);
    task.committed_at_height = Some(current_height);
    task.reveal_deadline_height = Some(current_height.saturating_add(DEFAULT_REVEAL_WINDOW_BLOCKS));
    st.update_task(task_ref, task).map_err(map_state_err)
}

pub fn apply_reveal_result(
    st: &mut StateStore,
    task_ref: ObjectRef,
    result_hash: Hash32,
    reveal_salt: [u8; 32],
    proof_data: Option<Vec<u8>>,
) -> Result<ObjectRef, PouwError> {
    apply_reveal_result_at_height(st, task_ref, result_hash, reveal_salt, proof_data, 0)
}

pub fn apply_reveal_result_at_height(
    st: &mut StateStore,
    task_ref: ObjectRef,
    result_hash: Hash32,
    reveal_salt: [u8; 32],
    proof_data: Option<Vec<u8>>,
    current_height: u64,
) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;

    if task.status != TaskStatus::Committed {
        return Err(PouwError::InvalidTransition);
    }
    if let Some(deadline) = task.reveal_deadline_height {
        if current_height > deadline {
            return Err(PouwError::DeadlineExceeded);
        }
    }

    let worker = task.worker.clone().ok_or(PouwError::MissingWorker)?;
    let worker_trimmed = worker.trim();
    if worker_trimmed.is_empty() || worker_trimmed != worker {
        // Legacy-state hardening: fail closed on malformed assigned worker ids so
        // commitment/proof envelope worker binding cannot be validated against
        // non-canonical identity strings.
        return Err(PouwError::State("non-canonical worker account".into()));
    }

    let committed = task.committed_hash.ok_or(PouwError::MissingCommitment)?;
    let expected = compute_commitment(task.task_id, &result_hash, &reveal_salt, &worker);
    if expected != committed {
        return Err(PouwError::CommitmentMismatch);
    }

    // Verify proof if TEE/ZK.
    // For Fraud proofs, we rely on the challenge period (no immediate verification).
    if matches!(task.proof_type, ProofType::Tee | ProofType::Zk) {
        let proof_payload = proof_data.as_deref().unwrap_or(&[]);
        if proof_payload.is_empty() {
            return Err(PouwError::State(
                "Proof verification failed: missing proof payload".into(),
            ));
        }

        let registry = get_default_registry();
        let mut verification_task = task.clone();
        verification_task.result_hash = Some(result_hash);
        let verification = registry.verify(&verification_task, proof_payload);
        match verification {
            VerificationResult::Valid => {
                // Immediate finality for verifiable execution.
                task.status = TaskStatus::Completed;
                task.result_hash = Some(result_hash);
                task.reveal_salt = Some(reveal_salt);
                // No challenge window needed.
                task.challenge_deadline_height = None;
                task.resolve_deadline_height = None;

                // Settle payment immediately.
                settle_worker_stake_for_terminal_state(st, &task)?;

                return st.update_task(task_ref, task).map_err(map_state_err);
            }
            VerificationResult::Invalid(reason) => {
                // Return error to reject the transaction, allowing retry with correct proof
                // before deadline. If deadline passes, timeout will slash.
                // Alternatively, we could slash immediately if we consider bad proof as malicious.
                // For now, let's reject to be safe against client errors.
                return Err(PouwError::State(format!(
                    "Proof verification failed: {}",
                    reason
                )));
            }
            VerificationResult::Indeterminate(reason) => {
                return Err(PouwError::State(format!(
                    "Proof verification indeterminate: {}",
                    reason
                )));
            }
        }
    }

    let challenge_window_blocks = sanitize_challenge_window_blocks(
        st.gov_param_u64("challenge_window_blocks")
            .unwrap_or(DEFAULT_CHALLENGE_WINDOW_BLOCKS),
    );

    task.status = TaskStatus::Revealed;
    task.result_hash = Some(result_hash);
    task.reveal_salt = Some(reveal_salt);
    task.challenge_window_blocks_snapshot = Some(challenge_window_blocks);
    task.challenge_deadline_height = Some(current_height.saturating_add(challenge_window_blocks));
    st.update_task(task_ref, task).map_err(map_state_err)
}

pub fn apply_challenge(
    st: &mut StateStore,
    task_ref: ObjectRef,
    challenger: String,
    challenge_bond: u128,
    signer: String,
) -> Result<ObjectRef, PouwError> {
    apply_challenge_at_height(st, task_ref, challenger, challenge_bond, signer, 0)
}

fn sanitize_challenge_window_blocks(raw: u64) -> u64 {
    raw.max(MIN_CHALLENGE_WINDOW_BLOCKS)
}

fn effective_challenge_window_blocks(st: &StateStore, task: &TaskObject) -> u64 {
    sanitize_challenge_window_blocks(task.challenge_window_blocks_snapshot.unwrap_or_else(|| {
        // Legacy compatibility path for pre-snapshot Revealed tasks.
        // Semantics are explicitly pinned to challenge-time governance value when no snapshot
        // exists (instead of trying to infer reveal-time state that is no longer recoverable).
        st.gov_param_u64("challenge_window_blocks")
            .unwrap_or(DEFAULT_CHALLENGE_WINDOW_BLOCKS)
    }))
}

pub fn apply_challenge_at_height(
    st: &mut StateStore,
    task_ref: ObjectRef,
    challenger: String,
    challenge_bond: u128,
    signer: String,
    current_height: u64,
) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    if task.status != TaskStatus::Revealed {
        return Err(PouwError::InvalidTransition);
    }
    validate_challenge_accounting_invariants(&task)?;
    reject_if_deadline_exceeded(task.challenge_deadline_height, current_height)?;

    let min_bond = required_challenge_bond(st, &task);
    // Safety hardening: challenge escrow must always carry non-zero economic weight,
    // even under permissive or malformed governance parameters.
    if challenge_bond == 0 || challenge_bond < min_bond {
        return Err(PouwError::InsufficientStake);
    }

    // Authorization is bound to authenticated signer context.
    // Harden against blank actor/signer values so malformed payloads cannot
    // bind escrow/accounting updates to an empty account id.
    let challenger_trimmed = challenger.trim();
    let signer_trimmed = signer.trim();
    if challenger_trimmed.is_empty()
        || signer_trimmed.is_empty()
        || challenger_trimmed != challenger
        || signer_trimmed != signer
        || signer_trimmed != challenger_trimmed
    {
        return Err(PouwError::Unauthorized);
    }

    if let Some(worker) = task.worker.as_ref() {
        let worker_trimmed = worker.trim();
        if worker_trimmed.is_empty() || worker_trimmed != worker {
            // Legacy-state hardening: reject malformed non-canonical worker ids
            // so self-challenge and accounting gates cannot be bypassed.
            return Err(PouwError::State("non-canonical worker account".into()));
        }
        if worker_trimmed == challenger_trimmed {
            // Consensus safety hardening: disallow self-challenge to prevent
            // worker-controlled challenge/reveal loops from gaming resolve paths.
            return Err(PouwError::Unauthorized);
        }
    }

    let challenge_window_blocks = effective_challenge_window_blocks(st, &task);

    preflight_challenge_transfer(st, &challenger, challenge_bond)?;

    task.status = TaskStatus::Challenged;
    if task.challenge_window_blocks_snapshot != Some(challenge_window_blocks) {
        // Legacy hardening: freeze fallback window at first challenge so
        // post-challenge governance updates cannot create audit ambiguity.
        // Also canonicalize malformed preexisting zero/invalid snapshots.
        task.challenge_window_blocks_snapshot = Some(challenge_window_blocks);
    }
    let resolve_deadline_height = current_height
        .checked_add(challenge_window_blocks)
        .ok_or_else(|| PouwError::State("challenge resolve deadline height overflow".into()))?;
    task.challenged_at_height = Some(current_height);
    task.resolve_deadline_height = Some(resolve_deadline_height);
    task.challenge_bond = Some(challenge_bond);
    task.challenger = Some(challenger.clone());
    task.challenge_bond_forfeited = None;
    let next_ref = st.update_task(task_ref, task).map_err(map_state_err)?;

    // Apply corresponding balance movement only after task object commit succeeds.
    st.debit_balance(&challenger, challenge_bond)
        .map_err(|_| PouwError::InsufficientStake)?;
    st.credit_balance(CHALLENGE_ESCROW_ACCOUNT, challenge_bond)
        .map_err(PouwError::State)?;

    Ok(next_ref)
}

pub fn apply_resolve(
    st: &mut StateStore,
    task_ref: ObjectRef,
    slash_worker: bool,
    resolver: String,
    signer: String,
) -> Result<ObjectRef, PouwError> {
    apply_resolve_at_height(st, task_ref, slash_worker, resolver, signer, 0)
}

pub fn apply_resolve_at_height(
    st: &mut StateStore,
    task_ref: ObjectRef,
    slash_worker: bool,
    resolver: String,
    signer: String,
    current_height: u64,
) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    if task.status != TaskStatus::Challenged {
        return Err(PouwError::InvalidTransition);
    }
    // Emergency circuit-breaker boundary: challenged-task resolution is terminal
    // escrow movement and must remain frozen while governance pause is active.
    if st.is_emergency_paused() {
        return Err(PouwError::InvalidTransition);
    }
    validate_challenge_accounting_invariants(&task)?;
    let resolve_authority = resolve_authority_account(st);
    // Authorization is bound to authenticated signer context; payload resolver
    // is retained only for backward-compatible event fields.
    // Gate hardening: reject malformed or divergent resolver payloads so canonical
    // signer authorization cannot be paired with spoofed event actor metadata.
    let resolver_trimmed = resolver.trim();
    // Gate hardening: signer and configured authority must both be canonical
    // non-blank account identifiers (no surrounding whitespace).
    let signer_trimmed = signer.trim();
    let authority_trimmed = resolve_authority.trim();
    // Decentralization hardening: reserve privileged runtime account ids from
    // governance resolve authority flow; challenge resolution must be executed
    // by explicit governance-designated non-system operators.
    let uses_reserved_system_actor = resolver_trimmed == "system"
        || signer_trimmed == "system"
        || authority_trimmed == "system";
    // Minimal multi-party control: escrow treasury account must never be reused
    // as resolve authority signer/payload, otherwise custody + adjudication roles
    // collapse into a single privileged actor surface.
    let uses_escrow_account_as_authority = resolver_trimmed == CHALLENGE_ESCROW_ACCOUNT
        || signer_trimmed == CHALLENGE_ESCROW_ACCOUNT
        || authority_trimmed == CHALLENGE_ESCROW_ACCOUNT;
    // Decentralization hardening: unresolved default placeholder must never
    // authorize challenge resolution. Governance must explicitly set a concrete
    // non-placeholder resolve authority before terminal escrow movement can occur.
    let uses_unconfigured_placeholder_authority = resolver_trimmed == DEFAULT_RESOLVE_AUTHORITY
        || signer_trimmed == DEFAULT_RESOLVE_AUTHORITY
        || authority_trimmed == DEFAULT_RESOLVE_AUTHORITY;
    // Minimal multi-party control: assigned worker cannot self-authorize terminal
    // challenge resolution for their own disputed task.
    let resolver_is_assigned_worker = task.worker.as_deref() == Some(signer_trimmed);
    if resolver_trimmed.is_empty()
        || resolver_trimmed != resolver
        || signer_trimmed.is_empty()
        || authority_trimmed.is_empty()
        || signer_trimmed != signer
        || authority_trimmed != resolve_authority
        || signer_trimmed != authority_trimmed
        || resolver_trimmed != signer_trimmed
        || uses_reserved_system_actor
        || uses_escrow_account_as_authority
        || uses_unconfigured_placeholder_authority
        || resolver_is_assigned_worker
    {
        return Err(PouwError::Unauthorized);
    }
    reject_if_deadline_exceeded_optional(task.resolve_deadline_height, current_height)?;
    task.status = if slash_worker {
        TaskStatus::Slashed
    } else {
        TaskStatus::Completed
    };
    if let Some(bond) = task.challenge_bond {
        ensure_balance_at_least(st, CHALLENGE_ESCROW_ACCOUNT, bond)?;
        task.challenge_bond_forfeited = Some(!slash_worker);
    }
    preflight_resolve_transfers(st, &task, slash_worker)?;

    let next_ref = st
        .update_task(task_ref, task.clone())
        .map_err(map_state_err)?;

    if let Some(bond) = task.challenge_bond {
        // Funds always flow out of escrow at resolve for auditability.
        st.debit_balance(CHALLENGE_ESCROW_ACCOUNT, bond)
            .map_err(PouwError::State)?;
        if slash_worker {
            // Challenge succeeds: return challenger bond.
            if let Some(ref challenger) = task.challenger {
                st.credit_balance(challenger, bond)
                    .map_err(PouwError::State)?;
            }
        } else {
            // Challenge fails: forfeit bond into treasury pool.
            st.credit_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, bond)
                .map_err(PouwError::State)?;
        }
    }

    if slash_worker {
        // Success incentive: pay a fixed minimal bounty to challenger from slashed worker stake
        // lock first, with fallback to worker-slash treasury if lock is empty.
        let _ = maybe_pay_challenge_success_bounty(st, &task)?;
    }

    settle_worker_stake_for_terminal_state(st, &task)?;

    Ok(next_ref)
}

pub fn apply_timeout(
    st: &mut StateStore,
    task_ref: ObjectRef,
    current_height: u64,
) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;

    validate_challenge_accounting_invariants(&task)?;

    let mut forfeit_challenge_bond = false;
    let mut refund_challenge_bond = false;

    match task.status {
        TaskStatus::Assigned | TaskStatus::Committed => {
            require_deadline_exceeded(task.reveal_deadline_height, current_height)?;
            task.status = TaskStatus::Slashed;
        }
        TaskStatus::Revealed => {
            let challenge_deadline = task.challenge_deadline_height.ok_or_else(|| {
                PouwError::State("revealed task missing challenge_deadline_height".into())
            })?;
            require_deadline_exceeded(Some(challenge_deadline), current_height)?;
            if task.challenged_at_height.is_some() {
                return Err(PouwError::InvalidTransition);
            }
            task.status = TaskStatus::Completed;
        }
        TaskStatus::Challenged => {
            if st.is_emergency_paused() {
                // Safety boundary: governance emergency pause freezes terminal challenge
                // settlement paths that move escrowed challenge bonds.
                return Err(PouwError::InvalidTransition);
            }
            require_deadline_exceeded(task.resolve_deadline_height, current_height)?;
            task.status = TaskStatus::Completed;
            if let Some(bond) = task.challenge_bond {
                ensure_balance_at_least(st, CHALLENGE_ESCROW_ACCOUNT, bond)?;
                task.challenge_bond_forfeited = Some(false);
                refund_challenge_bond = true;
            }
        }
        _ => return Err(PouwError::InvalidTransition),
    }

    if matches!(task.status, TaskStatus::Completed)
        && !matches!(task.challenge_bond_forfeited, Some(false))
    {
        forfeit_challenge_bond = task.challenge_bond.is_some();
    }

    preflight_timeout_transfers(st, &task, forfeit_challenge_bond, refund_challenge_bond)?;

    let next_ref = st
        .update_task(task_ref, task.clone())
        .map_err(map_state_err)?;

    if let Some(bond) = task.challenge_bond {
        if forfeit_challenge_bond {
            st.debit_balance(CHALLENGE_ESCROW_ACCOUNT, bond)
                .map_err(PouwError::State)?;
            st.credit_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, bond)
                .map_err(PouwError::State)?;
        } else if refund_challenge_bond {
            st.debit_balance(CHALLENGE_ESCROW_ACCOUNT, bond)
                .map_err(PouwError::State)?;
            if let Some(ref challenger) = task.challenger {
                st.credit_balance(challenger, bond)
                    .map_err(PouwError::State)?;
            }
        }
    }

    settle_worker_stake_for_terminal_state(st, &task)?;

    Ok(next_ref)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded_state() -> StateStore {
        let mut st = StateStore::new();
        st.set_balance("worker1", 1_000);
        st.set_balance("worker2", 1_000);
        st
    }

    fn set_resolve_authority(st: &mut StateStore, authority: &str) {
        st.set_gov_param_unchecked(9_500, "resolve_authority".into(), authority.into())
            .unwrap();
    }

    #[test]
    fn create_task_defaults_proof_type_to_fraud() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 1001, "alice".into(), 10).unwrap();
        let task = st.get_task(r1.id).unwrap();
        // Since ProofType::Fraud is the default (0/first variant usually or Default impl), verify it.
        // We need to access ProofType via crate root re-export or super import.
        // The `use super::*;` pulls in `trnm_types` if it is used in super.
        // But `trnm_types` is used via `use trnm_types::{...}` in super.
        // I should check if `trnm_types` crate is available as `trnm_types`.
        // It is a dependency, so `trnm_types::ProofType` should work if I add `use trnm_types::ProofType;` or similar.
        // Or simply check equality if I import ProofType.
        assert_eq!(task.proof_type, trnm_types::ProofType::Fraud);
    }

    #[test]
    fn full_happy_path_to_completed() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let r1 = apply_create_task(&mut st, 42, "alice".into(), 100).unwrap();

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(42, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
        set_resolve_authority(&mut st, "challenger");
        let r6 =
            apply_resolve(&mut st, r5, false, "challenger".into(), "challenger".into()).unwrap();

        let task = st.get_task(r6.id).unwrap();
        assert_eq!(task.status, TaskStatus::Completed);
    }

    #[test]
    fn forged_reveal_is_rejected() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 1, "alice".into(), 1).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let bad_reveal =
            apply_reveal_result(&mut st, r3, [3u8; 32], reveal_salt, None).unwrap_err();
        assert!(matches!(bad_reveal, PouwError::CommitmentMismatch));
    }

    #[test]
    fn challenge_requires_revealed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 9, "alice".into(), 10).unwrap();
        let err =
            apply_challenge(&mut st, r1, "challenger".into(), 10, "challenger".into()).unwrap_err();
        assert!(matches!(err, PouwError::InvalidTransition));
    }

    #[test]
    fn commit_requires_assigned() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 11, "alice".into(), 10).unwrap();
        let err = apply_commit_result(&mut st, r1, "worker1".into(), [1u8; 32]).unwrap_err();
        assert!(matches!(err, PouwError::InvalidTransition));
    }

    #[test]
    fn create_task_rejects_noncanonical_creator_identity() {
        let mut st = seeded_state();

        let blank = apply_create_task(&mut st, 209, "   ".into(), 10).unwrap_err();
        assert!(matches!(blank, PouwError::Unauthorized));

        let padded = apply_create_task(&mut st, 210, " alice ".into(), 10).unwrap_err();
        assert!(matches!(padded, PouwError::Unauthorized));
    }

    #[test]
    fn accept_task_rejects_noncanonical_worker_identity() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 211, "alice".into(), 10).unwrap();

        let blank = apply_accept_task(&mut st, r1.clone(), "   ".into()).unwrap_err();
        assert!(matches!(blank, PouwError::Unauthorized));

        let padded = apply_accept_task(&mut st, r1, " worker1 ".into()).unwrap_err();
        assert!(matches!(padded, PouwError::Unauthorized));
    }

    #[test]
    fn commit_worker_must_match_assigned_worker() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 12, "alice".into(), 10).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let err = apply_commit_result(&mut st, r2, "worker2".into(), [1u8; 32]).unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));
    }

    #[test]
    fn invalid_transition_matrix_smoke() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let r1 = apply_create_task(&mut st, 99, "alice".into(), 10).unwrap();

        // OPEN: only accept is valid.
        assert!(matches!(
            apply_reveal_result(&mut st, r1.clone(), [1u8; 32], [2u8; 32], None).unwrap_err(),
            PouwError::InvalidTransition
        ));
        assert!(matches!(
            apply_challenge(
                &mut st,
                r1.clone(),
                "challenger".into(),
                10,
                "challenger".into()
            )
            .unwrap_err(),
            PouwError::InvalidTransition
        ));
        assert!(matches!(
            apply_resolve(
                &mut st,
                r1.clone(),
                false,
                "challenger".into(),
                "challenger".into()
            )
            .unwrap_err(),
            PouwError::InvalidTransition
        ));

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        // ASSIGNED: reveal/challenge/resolve are invalid before commit.
        assert!(matches!(
            apply_reveal_result(&mut st, r2.clone(), [1u8; 32], [2u8; 32], None).unwrap_err(),
            PouwError::InvalidTransition
        ));
        assert!(matches!(
            apply_challenge(
                &mut st,
                r2.clone(),
                "challenger".into(),
                10,
                "challenger".into()
            )
            .unwrap_err(),
            PouwError::InvalidTransition
        ));
        assert!(matches!(
            apply_resolve(
                &mut st,
                r2.clone(),
                false,
                "challenger".into(),
                "challenger".into()
            )
            .unwrap_err(),
            PouwError::InvalidTransition
        ));

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(99, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // COMMITTED: challenge/resolve invalid before reveal.
        assert!(matches!(
            apply_challenge(
                &mut st,
                r3.clone(),
                "challenger".into(),
                10,
                "challenger".into()
            )
            .unwrap_err(),
            PouwError::InvalidTransition
        ));
        assert!(matches!(
            apply_resolve(
                &mut st,
                r3.clone(),
                false,
                "challenger".into(),
                "challenger".into()
            )
            .unwrap_err(),
            PouwError::InvalidTransition
        ));

        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        // REVEALED: resolve invalid before challenge.
        assert!(matches!(
            apply_resolve(
                &mut st,
                r4.clone(),
                false,
                "challenger".into(),
                "challenger".into()
            )
            .unwrap_err(),
            PouwError::InvalidTransition
        ));

        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
        set_resolve_authority(&mut st, "challenger");
        let _r6 = apply_resolve(
            &mut st,
            r5.clone(),
            false,
            "challenger".into(),
            "challenger".into(),
        )
        .unwrap();

        // FINAL: further resolve is invalid.
        assert!(matches!(
            apply_resolve(&mut st, r5, false, "challenger".into(), "challenger".into())
                .unwrap_err(),
            PouwError::InvalidTransition
        ));
    }

    #[test]
    fn stable_error_code_mapping() {
        assert_eq!(
            PouwError::InvalidTransition.stable_code(),
            "InvalidTransition"
        );
        assert_eq!(PouwError::VersionConflict.stable_code(), "VersionConflict");
        assert_eq!(PouwError::MissingWorker.stable_code(), "MissingWorker");
        assert_eq!(
            PouwError::MissingCommitment.stable_code(),
            "MissingCommitment"
        );
        assert_eq!(
            PouwError::CommitmentMismatch.stable_code(),
            "CommitmentMismatch"
        );
        assert_eq!(PouwError::Unauthorized.stable_code(), "Unauthorized");
        assert_eq!(
            PouwError::InsufficientStake.stable_code(),
            "InsufficientStake"
        );
        assert_eq!(
            PouwError::DeadlineExceeded.stable_code(),
            "DeadlineExceeded"
        );
        assert_eq!(PouwError::State("x".into()).stable_code(), "StateInternal");
    }

    #[test]
    fn reveal_missing_worker_is_mapped() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 77, "alice".into(), 10).unwrap();

        // Forge an Assigned+Committed task with worker=None to exercise defensive mapping.
        let bad_task = TaskObject {
            task_id: 77,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: Default::default(),
            metadata: None,
            worker: None,
            committed_hash: Some([1u8; 32]),
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        };
        let r2 = st.update_task(r1, bad_task).unwrap();

        let err = apply_reveal_result(&mut st, r2, [2u8; 32], [3u8; 32], None).unwrap_err();
        assert!(matches!(err, PouwError::MissingWorker));
    }

    #[test]
    fn reveal_rejects_noncanonical_worker_in_legacy_committed_state() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 78, "alice".into(), 10).unwrap();

        // Forge a legacy Committed task with malformed worker identity.
        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let malformed_worker = " worker1 ".to_string();
        let bad_task = TaskObject {
            task_id: 78,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: Default::default(),
            metadata: None,
            worker: Some(malformed_worker.clone()),
            committed_hash: Some(compute_commitment(
                78,
                &result_hash,
                &reveal_salt,
                &malformed_worker,
            )),
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        };
        let r2 = st.update_task(r1, bad_task).unwrap();

        let err = apply_reveal_result(&mut st, r2, result_hash, reveal_salt, None).unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("non-canonical worker account")));
    }

    #[test]
    fn assigned_timeout_transitions_to_slashed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 500, "alice".into(), 10).unwrap();
        let r2 = apply_accept_task_at_height(&mut st, r1, "worker1".into(), 100).unwrap();

        let before = apply_timeout(&mut st, r2.clone(), 120).unwrap_err();
        assert!(matches!(before, PouwError::InvalidTransition));

        let r3 = apply_timeout(&mut st, r2, 121).unwrap();
        let task = st.get_task(r3.id).unwrap();
        assert_eq!(task.status, TaskStatus::Slashed);
    }

    #[test]
    fn committed_timeout_transitions_to_slashed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 501, "alice".into(), 10).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(501, &result_hash, &reveal_salt, "worker1");
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();

        let before = apply_timeout(&mut st, r3.clone(), 120).unwrap_err();
        assert!(matches!(before, PouwError::InvalidTransition));

        let r4 = apply_timeout(&mut st, r3, 121).unwrap();
        let task = st.get_task(r4.id).unwrap();
        assert_eq!(task.status, TaskStatus::Slashed);
    }

    #[test]
    fn challenged_timeout_transitions_to_completed() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let r1 = apply_create_task(&mut st, 777, "alice".into(), 10).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(777, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 10).unwrap();
        let r4 =
            apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 20).unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            30,
        )
        .unwrap();
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);

        let before = apply_timeout(&mut st, r5.clone(), 130).unwrap_err();
        assert!(matches!(before, PouwError::InvalidTransition));

        let r6 = apply_timeout(&mut st, r5, 131).unwrap();
        let task = st.get_task(r6.id).unwrap();
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
        assert_eq!(st.balance_of("challenger"), 100);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn challenge_rejected_after_reveal_deadline_window() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_unchecked(9101, "challenge_window_blocks".into(), "100".into())
            .unwrap();

        let r1 = apply_create_task(&mut st, 901, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(901, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

        let err = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            211,
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::DeadlineExceeded));
    }

    #[test]
    fn challenge_accepted_at_reveal_deadline_boundary() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_unchecked(9102, "challenge_window_blocks".into(), "100".into())
            .unwrap();

        let r1 = apply_create_task(&mut st, 902, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(902, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            210,
        )
        .unwrap();

        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
    }

    #[test]
    fn challenge_rejects_resolve_deadline_height_overflow() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 903, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(903, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

        let mut near_overflow = st.get_task(r4.id).unwrap();
        near_overflow.challenge_deadline_height = Some(u64::MAX);
        near_overflow.challenge_window_blocks_snapshot = Some(1);
        let r4 = st.update_task(r4, near_overflow).unwrap();

        let err = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            u64::MAX,
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::State(_)));
        assert_eq!(st.balance_of("challenger"), 100);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    }

    #[test]
    fn challenge_clamps_malformed_legacy_zero_snapshot_to_minimum_block() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 91020, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(91020, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

        let mut malformed = st.get_task(r4.id).unwrap();
        malformed.challenge_window_blocks_snapshot = Some(0);
        let r4 = st.update_task(r4, malformed).unwrap();

        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            111,
        )
        .unwrap();
        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.challenge_window_blocks_snapshot, Some(1));
        assert_eq!(task.resolve_deadline_height, Some(112));
    }

    #[test]
    fn challenge_legacy_fallback_none_snapshot_uses_default_window_when_gov_missing() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 91021, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(91021, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

        // Simulate pre-snapshot legacy Revealed task persisted before rollout.
        let mut legacy = st.get_task(r4.id).unwrap();
        legacy.challenge_window_blocks_snapshot = None;
        let r4 = st.update_task(r4, legacy).unwrap();

        // Do not seed challenge_window_blocks governance: fallback should use default safely.
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            111,
        )
        .unwrap();
        let task = st.get_task(r5.id).unwrap();
        assert_eq!(
            task.challenge_window_blocks_snapshot,
            Some(DEFAULT_CHALLENGE_WINDOW_BLOCKS)
        );
        assert_eq!(
            task.resolve_deadline_height,
            Some(111 + DEFAULT_CHALLENGE_WINDOW_BLOCKS)
        );
    }

    #[test]
    fn challenge_window_is_snapshotted_at_reveal_even_if_governance_changes_after() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_unchecked(9110, "challenge_window_blocks".into(), "100".into())
            .unwrap();

        let r1 = apply_create_task(&mut st, 19110, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19110, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

        st.set_gov_param_unchecked(9110, "challenge_window_blocks".into(), "300".into())
            .unwrap();

        let err = apply_challenge_at_height(
            &mut st,
            r4.clone(),
            "challenger".into(),
            10,
            "challenger".into(),
            211,
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::DeadlineExceeded));

        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            210,
        )
        .unwrap();
        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.challenge_window_blocks_snapshot, Some(100));
        assert_eq!(task.resolve_deadline_height, Some(310));
    }

    #[test]
    fn legacy_revealed_without_snapshot_gets_snapshotted_on_challenge() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_unchecked(9130, "challenge_window_blocks".into(), "100".into())
            .unwrap();

        let r1 = apply_create_task(&mut st, 19130, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19130, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

        // Simulate pre-snapshot legacy Revealed task persisted before rollout.
        let mut legacy = st.get_task(r4.id).unwrap();
        legacy.challenge_window_blocks_snapshot = None;
        let r4 = st.update_task(r4, legacy).unwrap();

        st.set_gov_param_unchecked(9130, "challenge_window_blocks".into(), "300".into())
            .unwrap();

        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            210,
        )
        .unwrap();
        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.challenge_window_blocks_snapshot, Some(300));
        assert_eq!(task.challenge_deadline_height, Some(210));
        assert_eq!(task.resolve_deadline_height, Some(510));
    }

    #[test]
    fn legacy_revealed_snapshot_freezes_resolve_timing_after_challenge_despite_later_gov_change() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_unchecked(9133, "challenge_window_blocks".into(), "100".into())
            .unwrap();

        let r1 = apply_create_task(&mut st, 19133, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19133, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

        // Simulate pre-snapshot legacy Revealed task persisted before rollout.
        let mut legacy = st.get_task(r4.id).unwrap();
        legacy.challenge_window_blocks_snapshot = None;
        let r4 = st.update_task(r4, legacy).unwrap();

        st.set_gov_param_unchecked(9133, "challenge_window_blocks".into(), "300".into())
            .unwrap();

        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            210,
        )
        .unwrap();
        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.challenge_window_blocks_snapshot, Some(300));
        assert_eq!(task.resolve_deadline_height, Some(510));

        // Later governance updates must not affect already-derived challenged timing.
        st.set_gov_param_unchecked(9133, "challenge_window_blocks".into(), "600".into())
            .unwrap();

        let err = apply_timeout(&mut st, r5.clone(), 510).unwrap_err();
        assert!(matches!(err, PouwError::InvalidTransition));

        let r6 = apply_timeout(&mut st, r5, 511).unwrap();
        let timed_out = st.get_task(r6.id).unwrap();
        assert_eq!(timed_out.status, TaskStatus::Completed);
    }

    #[test]
    fn legacy_revealed_without_snapshot_still_enforces_stored_challenge_deadline_under_gov_change()
    {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_unchecked(9131, "challenge_window_blocks".into(), "100".into())
            .unwrap();

        let r1 = apply_create_task(&mut st, 19131, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19131, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

        // Simulate pre-snapshot legacy Revealed task persisted before rollout.
        let mut legacy = st.get_task(r4.id).unwrap();
        legacy.challenge_window_blocks_snapshot = None;
        let r4 = st.update_task(r4, legacy).unwrap();

        st.set_gov_param_unchecked(9131, "challenge_window_blocks".into(), "300".into())
            .unwrap();

        let err = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            211,
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::DeadlineExceeded));
    }

    #[test]
    fn legacy_fallback_asymmetry_keeps_challenge_deadline_and_signer_auth_intact() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_unchecked(9132, "challenge_window_blocks".into(), "100".into())
            .unwrap();
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 19132, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19132, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

        // Simulate pre-snapshot legacy Revealed task persisted before rollout.
        let mut legacy = st.get_task(r4.id).unwrap();
        legacy.challenge_window_blocks_snapshot = None;
        let r4 = st.update_task(r4, legacy).unwrap();

        // Increase window to governance max just before challenge.
        st.set_gov_param_unchecked(9132, "challenge_window_blocks".into(), "600".into())
            .unwrap();

        // Challenge admission still respects stored reveal-time deadline (<= 210).
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            210,
        )
        .unwrap();
        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.challenge_deadline_height, Some(210));
        assert_eq!(task.resolve_deadline_height, Some(810));

        // Resolve remains signer-bound; payload resolver cannot bypass authority check.
        let err = apply_resolve_at_height(
            &mut st,
            r5,
            true,
            "authority".into(),
            "attacker".into(),
            211,
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(19132).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    }

    #[test]
    fn challenge_boundary_stays_correct_at_and_after_deadline_with_snapshot() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_unchecked(9120, "challenge_window_blocks".into(), "100".into())
            .unwrap();

        let r1 = apply_create_task(&mut st, 19120, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19120, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

        st.set_gov_param_unchecked(9120, "challenge_window_blocks".into(), "300".into())
            .unwrap();

        let r5 = apply_challenge_at_height(
            &mut st,
            r4.clone(),
            "challenger".into(),
            10,
            "challenger".into(),
            210,
        )
        .unwrap();
        let before_resolve_timeout = apply_timeout(&mut st, r5.clone(), 310).unwrap_err();
        assert!(matches!(
            before_resolve_timeout,
            PouwError::InvalidTransition
        ));

        let r6 = apply_timeout(&mut st, r5, 311).unwrap();
        let task = st.get_task(r6.id).unwrap();
        assert_eq!(task.status, TaskStatus::Completed);
    }

    #[test]
    fn revealed_timeout_auto_completes_without_challenge() {
        let mut st = seeded_state();
        st.set_gov_param_unchecked(9103, "challenge_window_blocks".into(), "100".into())
            .unwrap();

        let r1 = apply_create_task(&mut st, 903, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(903, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

        let before = apply_timeout(&mut st, r4.clone(), 210).unwrap_err();
        assert!(matches!(before, PouwError::InvalidTransition));

        let r5 = apply_timeout(&mut st, r4, 211).unwrap();
        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.challenged_at_height, None);
    }

    #[test]
    fn challenge_requires_min_bond_from_worker_stake_floor() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_unchecked(9000, "challenge_min_bond".into(), "1".into())
            .unwrap();
        st.set_gov_param_unchecked(9001, "challenge_min_bond_bounty_bps".into(), "1".into())
            .unwrap();
        st.set_gov_param_unchecked(9002, "min_worker_stake".into(), "80".into())
            .unwrap();
        st.set_gov_param_unchecked(
            9003,
            "challenge_min_bond_worker_stake_bps".into(),
            "2500".into(),
        )
        .unwrap();

        let r1 = apply_create_task(&mut st, 887, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(887, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        // Worker stake floor = ceil(80 * 25%) = 20, which should dominate static/bounty floors.
        let err = apply_challenge(
            &mut st,
            r4.clone(),
            "challenger".into(),
            19,
            "challenger".into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::InsufficientStake));

        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 20, "challenger".into()).unwrap();
        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.challenge_bond, Some(20));
    }

    #[test]
    fn challenge_requires_min_bond_as_max_of_governance_bounty_and_worker_stake_floors() {
        let mut st = seeded_state();
        st.set_balance("challenger", 200);
        st.set_gov_param_unchecked(9004, "challenge_min_bond".into(), "30".into())
            .unwrap();
        st.set_gov_param_unchecked(9005, "challenge_min_bond_bounty_bps".into(), "5000".into())
            .unwrap();
        st.set_gov_param_unchecked(9006, "min_worker_stake".into(), "80".into())
            .unwrap();
        st.set_gov_param_unchecked(
            9007,
            "challenge_min_bond_worker_stake_bps".into(),
            "7500".into(),
        )
        .unwrap();

        let r1 = apply_create_task(&mut st, 886, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(886, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        // Floors are: governance=30, bounty=50, worker-stake=60; effective min bond is max=60.
        let err = apply_challenge(
            &mut st,
            r4.clone(),
            "challenger".into(),
            59,
            "challenger".into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::InsufficientStake));

        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 60, "challenger".into()).unwrap();
        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.challenge_bond, Some(60));
    }

    #[test]
    fn challenge_requires_min_bond_from_governance() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_unchecked(9001, "challenge_min_bond".into(), "50".into())
            .unwrap();

        let r1 = apply_create_task(&mut st, 888, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(888, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        let err = apply_challenge(
            &mut st,
            r4.clone(),
            "challenger".into(),
            49,
            "challenger".into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::InsufficientStake));

        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 50, "challenger".into()).unwrap();
        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.challenge_bond, Some(50));
    }

    #[test]
    fn challenge_requires_min_bond_default_when_governance_absent() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 890, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(890, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        let err = apply_challenge(
            &mut st,
            r4.clone(),
            "challenger".into(),
            9,
            "challenger".into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::InsufficientStake));

        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.challenge_bond, Some(10));
    }

    #[test]
    fn challenge_rejects_zero_bond() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 889, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(889, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        let err =
            apply_challenge(&mut st, r4, "challenger".into(), 0, "challenger".into()).unwrap_err();
        assert!(matches!(err, PouwError::InsufficientStake));
    }

    #[test]
    fn challenge_rejects_spam_like_low_bond_under_dynamic_bounty_floor() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_unchecked(9050, "challenge_min_bond".into(), "10".into())
            .unwrap();
        st.set_gov_param_unchecked(9051, "challenge_min_bond_bounty_bps".into(), "5000".into())
            .unwrap();

        let r1 = apply_create_task(&mut st, 29050, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(29050, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        let err =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap_err();
        assert!(matches!(err, PouwError::InsufficientStake));
    }

    #[test]
    fn challenge_accepts_normal_bond_when_dynamic_floor_met() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_unchecked(9052, "challenge_min_bond".into(), "10".into())
            .unwrap();
        st.set_gov_param_unchecked(9053, "challenge_min_bond_bounty_bps".into(), "5000".into())
            .unwrap();

        let r1 = apply_create_task(&mut st, 29052, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(29052, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 50, "challenger".into()).unwrap();
        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond, Some(50));
    }

    #[test]
    fn challenge_dynamic_floor_boundary_ceil_passes_and_fails() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_unchecked(9054, "challenge_min_bond".into(), "1".into())
            .unwrap();
        st.set_gov_param_unchecked(9055, "challenge_min_bond_bounty_bps".into(), "500".into())
            .unwrap();

        let r1 = apply_create_task(&mut st, 29054, "alice".into(), 101).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(29054, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        let err = apply_challenge(
            &mut st,
            r4.clone(),
            "challenger".into(),
            5,
            "challenger".into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::InsufficientStake));

        let r5 = apply_challenge(&mut st, r4, "challenger".into(), 6, "challenger".into()).unwrap();
        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.challenge_bond, Some(6));
    }

    #[test]
    fn challenge_rejects_self_challenge_by_assigned_worker() {
        let mut st = seeded_state();
        st.set_balance("worker1", 100);

        let r1 = apply_create_task(&mut st, 29058, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(29058, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        let err = apply_challenge(&mut st, r4, "worker1".into(), 10, "worker1".into()).unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));
    }

    #[test]
    fn challenge_rejects_noncanonical_worker_id_in_legacy_revealed_state() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 29059, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(29059, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        let mut bad = st.get_task(r4.id).unwrap();
        bad.worker = Some(" worker1".into());
        let bad_ref = st.update_task(r4, bad).unwrap();

        let err = apply_challenge(
            &mut st,
            bad_ref,
            "challenger".into(),
            10,
            "challenger".into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::State(_)));
    }

    #[test]
    fn challenged_timeout_refunds_bond_and_keeps_forfeit_bucket_unchanged() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_unchecked(9056, "challenge_min_bond".into(), "10".into())
            .unwrap();
        st.set_gov_param_unchecked(9057, "challenge_min_bond_bounty_bps".into(), "5000".into())
            .unwrap();

        let r1 = apply_create_task(&mut st, 29056, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(29056, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            50,
            "challenger".into(),
            120,
        )
        .unwrap();

        let r6 = apply_timeout(&mut st, r5, 221).unwrap();
        let task = st.get_task(r6.id).unwrap();
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
        assert_eq!(st.balance_of("challenger"), 100);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn resolve_rejects_inconsistent_challenged_task_missing_challenger_when_bond_exists() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 29057, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(29057, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        // Simulate an inconsistent legacy/corrupted challenged object.
        let mut bad = st.get_task(r5.id).unwrap();
        bad.challenger = None;
        let bad_ref = st.update_task(r5, bad).unwrap();

        set_resolve_authority(&mut st, "authority");
        let err = apply_resolve(
            &mut st,
            bad_ref,
            true,
            "authority".into(),
            "authority".into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::State(_)));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn timeout_rejects_inconsistent_challenged_task_missing_challenger_when_bond_exists() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 29058, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(29058, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            120,
        )
        .unwrap();

        // Simulate an inconsistent legacy/corrupted challenged object.
        let mut bad = st.get_task(r5.id).unwrap();
        bad.challenger = None;
        let bad_ref = st.update_task(r5, bad).unwrap();

        let err = apply_timeout(&mut st, bad_ref, 221).unwrap_err();
        assert!(matches!(err, PouwError::State(_)));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn timeout_rejects_inconsistent_challenged_task_noncanonical_challenger_when_bond_exists() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 29059, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(29059, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            120,
        )
        .unwrap();

        // Simulate an inconsistent legacy/corrupted challenged object.
        let mut bad = st.get_task(r5.id).unwrap();
        bad.challenger = Some(" challenger ".into());
        let bad_ref = st.update_task(r5, bad).unwrap();

        let err = apply_timeout(&mut st, bad_ref, 221).unwrap_err();
        assert!(matches!(err, PouwError::State(_)));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn timeout_rejects_inconsistent_challenged_task_zero_bond() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 29060, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(29060, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            120,
        )
        .unwrap();

        // Simulate a corrupted legacy state that bypassed min-bond checks.
        let mut bad = st.get_task(r5.id).unwrap();
        bad.challenge_bond = Some(0);
        let bad_ref = st.update_task(r5, bad).unwrap();

        let err = apply_timeout(&mut st, bad_ref, 221).unwrap_err();
        assert!(matches!(err, PouwError::State(_)));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn malformed_challenged_invariant_failure_rejects_early_without_status_or_balance_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 39001, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(39001, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let mut bad = st.get_task(r5.id).unwrap();
        bad.challenger = None;
        let bad_ref = st.update_task(r5, bad).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        set_resolve_authority(&mut st, "authority");
        let err = apply_resolve(
            &mut st,
            bad_ref,
            true,
            "authority".into(),
            "authority".into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::State(_)));

        let task = st.get_task(39001).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
    }

    #[test]
    fn resolve_rejects_non_canonical_challenger_identity_without_balance_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 39002, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(39002, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        // Simulate malformed legacy state carrying non-canonical challenger identity.
        let mut bad = st.get_task(r5.id).unwrap();
        bad.challenger = Some(" challenger".into());
        let bad_ref = st.update_task(r5, bad).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        set_resolve_authority(&mut st, "authority");
        let err = apply_resolve(
            &mut st,
            bad_ref,
            true,
            "authority".into(),
            "authority".into(),
        )
        .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("non-canonical challenger identity"))
        );

        let task = st.get_task(39002).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
    }

    #[test]
    fn timeout_rejects_terminal_non_challenged_task_with_stale_challenge_timing_fields() {
        let mut st = seeded_state();

        let r1 = apply_create_task(&mut st, 39010, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(39010, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();
        let done = apply_timeout(&mut st, r4, 211).unwrap();

        // Simulate legacy/corrupted terminal object carrying stale challenge timing metadata.
        let mut bad = st.get_task(done.id).unwrap();
        assert_eq!(bad.status, TaskStatus::Completed);
        bad.challenged_at_height = Some(120);
        let bad_ref = st.update_task(done, bad).unwrap();

        let err = apply_timeout(&mut st, bad_ref, 212).unwrap_err();
        assert!(matches!(err, PouwError::State(_)));
    }

    #[test]
    fn timeout_rejects_terminal_challenged_task_missing_challenge_timing_fields() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 39016, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(39016, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            120,
        )
        .unwrap();
        let done = apply_timeout(&mut st, r5, 221).unwrap();

        // Simulate corrupted terminal challenged object missing critical timing metadata.
        let mut bad = st.get_task(done.id).unwrap();
        assert_eq!(bad.status, TaskStatus::Completed);
        bad.challenged_at_height = None;
        let bad_ref = st.update_task(done, bad).unwrap();

        let err = apply_timeout(&mut st, bad_ref, 222).unwrap_err();
        assert!(matches!(err, PouwError::State(_)));
    }

    #[test]
    fn timeout_rejects_terminal_challenged_task_missing_challenge_bond_outcome() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 39017, "alice".into(), 100).unwrap();
        let result_hash = [3u8; 32];
        let reveal_salt = [4u8; 32];
        let committed = compute_commitment(39017, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            120,
        )
        .unwrap();
        let done = apply_timeout(&mut st, r5, 221).unwrap();

        // Simulate corrupted terminal challenged object where bond escrow decision is missing.
        let mut bad = st.get_task(done.id).unwrap();
        assert_eq!(bad.status, TaskStatus::Completed);
        bad.challenge_bond_forfeited = None;
        let bad_ref = st.update_task(done, bad).unwrap();

        let err = apply_timeout(&mut st, bad_ref, 222).unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("missing challenge bond outcome"))
        );
    }

    #[test]
    fn timeout_rejects_revealed_state_with_stale_challenge_timing_fields() {
        let mut st = seeded_state();

        let r1 = apply_create_task(&mut st, 39013, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(39013, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

        // Simulate legacy/corrupted non-challenged object carrying stale challenge timing metadata.
        let mut bad = st.get_task(r4.id).unwrap();
        assert_eq!(bad.status, TaskStatus::Revealed);
        bad.challenged_at_height = Some(111);
        let bad_ref = st.update_task(r4, bad).unwrap();

        let err = apply_timeout(&mut st, bad_ref, 211).unwrap_err();
        assert!(matches!(err, PouwError::State(_)));
    }

    #[test]
    fn resolve_rejects_challenged_state_without_bond_fields_even_if_status_is_challenged() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 39011, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(39011, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let mut bad = st.get_task(r5.id).unwrap();
        bad.challenge_bond = None;
        bad.challenger = None;
        let bad_ref = st.update_task(r5, bad).unwrap();

        set_resolve_authority(&mut st, "authority");
        let err = apply_resolve(
            &mut st,
            bad_ref,
            false,
            "authority".into(),
            "authority".into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::State(_)));
        assert_eq!(st.get_task(39011).unwrap().status, TaskStatus::Challenged);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    }

    #[test]
    fn timeout_rejects_challenged_state_missing_resolve_metadata() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 39012, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(39012, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            120,
        )
        .unwrap();

        let mut bad = st.get_task(r5.id).unwrap();
        bad.resolve_deadline_height = None;
        let bad_ref = st.update_task(r5, bad).unwrap();

        let err = apply_timeout(&mut st, bad_ref, 221).unwrap_err();
        assert!(matches!(err, PouwError::State(_)));
        assert_eq!(st.get_task(39012).unwrap().status, TaskStatus::Challenged);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn timeout_rejects_challenged_state_missing_challenge_deadline_metadata() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 39014, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(39014, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            120,
        )
        .unwrap();

        let mut bad = st.get_task(r5.id).unwrap();
        bad.challenge_deadline_height = None;
        let bad_ref = st.update_task(r5, bad).unwrap();

        let err = apply_timeout(&mut st, bad_ref, 221).unwrap_err();
        assert!(matches!(err, PouwError::State(_)));
        assert_eq!(st.get_task(39014).unwrap().status, TaskStatus::Challenged);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn timeout_rejects_challenged_state_with_non_monotonic_deadline_metadata() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 39015, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(39015, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            120,
        )
        .unwrap();

        let mut bad = st.get_task(r5.id).unwrap();
        bad.challenge_deadline_height = Some(300);
        bad.resolve_deadline_height = Some(250);
        let bad_ref = st.update_task(r5, bad).unwrap();

        let err = apply_timeout(&mut st, bad_ref, 301).unwrap_err();
        assert!(matches!(err, PouwError::State(_)));
        assert_eq!(st.get_task(39015).unwrap().status, TaskStatus::Challenged);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn malformed_revealed_stale_challenge_fields_rejected_before_timeout_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 39002, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(39002, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

        let mut bad = st.get_task(r4.id).unwrap();
        bad.challenge_bond = Some(10);
        bad.challenger = Some("challenger".into());
        let bad_ref = st.update_task(r4, bad).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        let err = apply_timeout(&mut st, bad_ref, 211).unwrap_err();
        assert!(matches!(err, PouwError::State(_)));

        let task = st.get_task(39002).unwrap();
        assert_eq!(task.status, TaskStatus::Revealed);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
    }

    #[test]
    fn timeout_rejects_revealed_state_missing_challenge_deadline_metadata() {
        let mut st = seeded_state();

        let r1 = apply_create_task(&mut st, 39013, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(39013, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

        let mut bad = st.get_task(r4.id).unwrap();
        bad.challenge_deadline_height = None;
        let bad_ref = st.update_task(r4, bad).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        let err = apply_timeout(&mut st, bad_ref, 211).unwrap_err();
        assert!(matches!(err, PouwError::State(_)));

        let task = st.get_task(39013).unwrap();
        assert_eq!(task.status, TaskStatus::Revealed);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
    }

    #[test]
    fn default_challenge_window_meets_governance_minimum_floor() {
        assert!(DEFAULT_CHALLENGE_WINDOW_BLOCKS >= 100);
    }

    #[test]
    fn challenge_uses_default_window_when_governance_absent() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 893, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(893, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            120,
        )
        .unwrap();

        let challenged = st.get_task(r5.id).unwrap();
        assert_eq!(
            challenged.resolve_deadline_height,
            Some(120 + DEFAULT_CHALLENGE_WINDOW_BLOCKS)
        );
    }

    #[test]
    fn challenge_uses_governance_window_and_resolve_marks_bond_outcome() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_unchecked(9002, "challenge_window_blocks".into(), "123".into())
            .unwrap();

        let r1 = apply_create_task(&mut st, 889, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(889, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            120,
        )
        .unwrap();

        let challenged = st.get_task(r5.id).unwrap();
        assert_eq!(challenged.resolve_deadline_height, Some(243));
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);

        set_resolve_authority(&mut st, "challenger");
        let r6 =
            apply_resolve(&mut st, r5, false, "challenger".into(), "challenger".into()).unwrap();
        let resolved = st.get_task(r6.id).unwrap();
        assert_eq!(resolved.challenge_bond_forfeited, Some(true));
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 10);
    }

    #[test]
    fn resolve_success_gives_challenger_more_than_bond_refund_baseline() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 891, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(891, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);

        let refund_only_baseline = 100u128;
        set_resolve_authority(&mut st, "challenger");
        let r6 =
            apply_resolve(&mut st, r5, true, "challenger".into(), "challenger".into()).unwrap();

        let resolved = st.get_task(r6.id).unwrap();
        assert_eq!(resolved.status, TaskStatus::Slashed);
        assert_eq!(resolved.challenge_bond_forfeited, Some(false));
        assert!(st.balance_of("challenger") > refund_only_baseline);
        assert_eq!(st.balance_of("challenger"), 101);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn resolve_success_conserves_challenge_related_buckets_with_explicit_bounty_flow() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_unchecked(9810, "min_worker_stake".into(), "40".into())
            .unwrap();
        st.set_balance("worker1", 40);

        let task_id = 29810u64;
        let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let initial_sum = st.balance_of("challenger")
            + st.balance_of(&worker_stake_lock_account(task_id))
            + st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT)
            + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
            + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        set_resolve_authority(&mut st, "challenger");
        let _r6 =
            apply_resolve(&mut st, r5, true, "challenger".into(), "challenger".into()).unwrap();

        let final_sum = st.balance_of("challenger")
            + st.balance_of(&worker_stake_lock_account(task_id))
            + st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT)
            + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
            + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        assert_eq!(initial_sum, final_sum);
        assert_eq!(st.balance_of("challenger"), 101);
        assert_eq!(st.balance_of(&worker_stake_lock_account(task_id)), 0);
        assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), 39);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn resolve_rejects_challenger_when_not_configured_authority() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 894, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(894, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let err =
            apply_resolve(&mut st, r5, true, "challenger".into(), "challenger".into()).unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(894).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn resolve_accepts_configured_authority_resolver() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 895, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(895, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let r6 = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into()).unwrap();
        let task = st.get_task(r6.id).unwrap();
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
        assert_eq!(st.balance_of("challenger"), 101);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn resolve_rejects_worker_as_configured_authority_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "worker1");

        let r1 = apply_create_task(&mut st, 8_959, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_959, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(&mut st, r5, true, "worker1".into(), "worker1".into())
            .expect_err("assigned worker must not self-authorize challenged resolution");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_959).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), before_forfeit);
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_while_emergency_pause_active_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_960, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_960, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let pause = st
            .set_gov_param(9_200, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(matches!(pause, trnm_state::GovParamUpdateOutcome::Applied(_)));
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_960).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err("emergency pause must freeze terminal challenge resolution");
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_960).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(after_task.challenge_bond_forfeited, before_task.challenge_bond_forfeited);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), before_forfeit);
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_rejects_non_slashing_path_while_emergency_pause_active_without_balance_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_961, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, false, "authority".into(), "authority".into())
            .expect_err("emergency pause must freeze non-slashing challenge resolution path too");
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(after_task.challenge_bond_forfeited, before_task.challenge_bond_forfeited);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), before_forfeit);
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn timeout_rejects_challenged_path_while_emergency_pause_active_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 8_962, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_962, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_202, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_962).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_timeout(&mut st, r5, 221)
            .expect_err("emergency pause must freeze challenged timeout settlement path");
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_962).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(after_task.challenge_bond_forfeited, before_task.challenge_bond_forfeited);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), before_forfeit);
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn timeout_revealed_path_remains_available_while_emergency_pause_active() {
        let mut st = seeded_state();

        let r1 = apply_create_task(&mut st, 8_963, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_963, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        st.set_gov_param(9_203, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_worker_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

        let next = apply_timeout(&mut st, r4, 10_000)
            .expect("emergency pause must not block non-challenged timeout completion path");

        let task = st
            .get_task(next.id)
            .expect("revealed timeout completion must persist task object");
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.challenge_bond, None);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), before_forfeit);
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before_worker_slash_treasury
        );
    }

    #[test]
    fn resolve_reopens_after_emergency_pause_clears_with_single_settlement() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_964, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_964, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_204, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let paused_err = apply_resolve(&mut st, r5.clone(), false, "authority".into(), "authority".into())
            .expect_err("resolve must stay frozen while emergency pause is active");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
        assert_eq!(st.balance_of("challenger"), 90);

        st.set_gov_param(9_205, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let r6 = apply_resolve(&mut st, r5, false, "authority".into(), "authority".into())
            .expect("resolve must reopen after emergency pause is cleared");
        let task = st.get_task(r6.id).expect("resolved task must persist");
        assert_eq!(task.challenge_bond_forfeited, Some(true));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 10);
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_missing_governance_authority_stays_fail_closed() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 8_951, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_951, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5.clone(), true, "authority".into(), "authority".into())
            .expect_err("missing governance authority must not silently authorize legacy singleton");
        assert!(matches!(err, PouwError::Unauthorized));

        let err = apply_resolve(
            &mut st,
            r5,
            true,
            DEFAULT_RESOLVE_AUTHORITY.into(),
            DEFAULT_RESOLVE_AUTHORITY.into(),
        )
        .expect_err("missing governance authority must remain fail-closed for placeholder authority");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_951).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn resolve_replay_attempt_after_terminal_resolution_is_rejected_without_double_payout() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_995, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_995, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let r6 = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into()).unwrap();
        let challenger_after_first_resolve = st.balance_of("challenger");
        let escrow_after_first_resolve = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let forfeit_after_first_resolve = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        let err =
            apply_resolve(&mut st, r6, true, "authority".into(), "authority".into()).unwrap_err();
        assert!(matches!(err, PouwError::InvalidTransition));

        assert_eq!(st.balance_of("challenger"), challenger_after_first_resolve);
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            escrow_after_first_resolve
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            forfeit_after_first_resolve
        );
    }

    #[test]
    fn challenge_replay_attempt_after_challenged_state_is_rejected_without_double_escrow_debit() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 8_996, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_996, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let challenger_after_first_challenge = st.balance_of("challenger");
        let escrow_after_first_challenge = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let forfeit_after_first_challenge = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        let err =
            apply_challenge(&mut st, r5, "challenger".into(), 10, "challenger".into()).unwrap_err();
        assert!(matches!(err, PouwError::InvalidTransition));

        assert_eq!(
            st.balance_of("challenger"),
            challenger_after_first_challenge
        );
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            escrow_after_first_challenge
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            forfeit_after_first_challenge
        );
    }

    #[test]
    fn resolve_rejects_when_payload_resolver_matches_but_signer_is_attacker() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 896, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(896, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let err =
            apply_resolve(&mut st, r5, true, "authority".into(), "attacker".into()).unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(896).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn resolve_rejects_payload_resolver_that_diverges_from_authority_signer() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_996, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_996, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(
            &mut st,
            r5,
            true,
            "auditor_alias".into(),
            "authority".into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_996).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn resolve_rejects_noncanonical_payload_resolver_even_if_signer_is_authority() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 897, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(897, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, false, " authority ".into(), "authority".into())
            .unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(897).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn resolve_rejects_blank_signer_without_state_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_998, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_998, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "   ".into()).unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_998).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn resolve_rejects_non_canonical_configured_authority_without_state_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, " authority ");

        let r1 = apply_create_task(&mut st, 8_999, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_999, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(
            &mut st,
            r5,
            true,
            " authority ".into(),
            " authority ".into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_999).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn resolve_rejects_case_drift_in_authority_payload_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "Authority");

        let r1 = apply_create_task(&mut st, 9_000, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_000, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err("case-drifted payload must not authorize resolve actor");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_000).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn resolve_rejects_reserved_system_authority_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "system");

        let r1 = apply_create_task(&mut st, 9_001, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, "system".into(), "system".into()).unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn resolve_rejects_escrow_account_authority_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, CHALLENGE_ESCROW_ACCOUNT);

        let r1 = apply_create_task(&mut st, 9_001_2, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_2, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(
            &mut st,
            r5,
            true,
            CHALLENGE_ESCROW_ACCOUNT.into(),
            CHALLENGE_ESCROW_ACCOUNT.into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_2).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn resolve_rejects_unconfigured_placeholder_authority_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        // Keep default unconfigured governance placeholder authority.

        let r1 = apply_create_task(&mut st, 9_001_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(
            &mut st,
            r5,
            true,
            DEFAULT_RESOLVE_AUTHORITY.into(),
            DEFAULT_RESOLVE_AUTHORITY.into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_1).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn challenge_rejects_when_payload_challenger_matches_but_signer_is_attacker() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 898, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(898, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        let before = st.clone();
        let err =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "attacker".into()).unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        // Unauthorized attempts must not move balances or mutate task state.
        let task = st.get_task(898).unwrap();
        assert_eq!(task.status, TaskStatus::Revealed);
        assert_eq!(task.challenger, None);
        assert_eq!(task.challenge_bond, None);
        assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn challenge_rejects_blank_actor_or_signer_values() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 8_991, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_991, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        let before = st.clone();
        let err = apply_challenge(&mut st, r4, "".into(), 10, "".into()).unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        // Blank identities must not mutate task status or balances.
        let task = st.get_task(8_991).unwrap();
        assert_eq!(task.status, TaskStatus::Revealed);
        assert_eq!(task.challenger, None);
        assert_eq!(task.challenge_bond, None);
        assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn challenge_rejects_whitespace_only_actor_or_signer_without_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 8_992, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_992, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        let before = st.clone();
        let err = apply_challenge(&mut st, r4, "   ".into(), 10, "   ".into()).unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_992).unwrap();
        assert_eq!(task.status, TaskStatus::Revealed);
        assert_eq!(task.challenger, None);
        assert_eq!(task.challenge_bond, None);
        assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn challenge_rejects_actor_or_signer_with_surrounding_whitespace_without_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 8_993, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_993, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        let before = st.clone();
        let err = apply_challenge(
            &mut st,
            r4.clone(),
            " challenger".into(),
            10,
            " challenger".into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let err2 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger ".into())
            .unwrap_err();
        assert!(matches!(err2, PouwError::Unauthorized));

        let task = st.get_task(8_993).unwrap();
        assert_eq!(task.status, TaskStatus::Revealed);
        assert_eq!(task.challenger, None);
        assert_eq!(task.challenge_bond, None);
        assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn challenge_rejects_malformed_worker_id_in_revealed_state_without_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 8_994, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_994, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        // Simulate malformed legacy state carrying non-canonical worker account id.
        let mut malformed = st.get_task(r4.id).unwrap();
        malformed.worker = Some(" worker1".into());
        let r4 = st.update_task(r4, malformed).unwrap();

        let before = st.clone();
        let err =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("non-canonical worker account"))
        );

        let task = st.get_task(8_994).unwrap();
        assert_eq!(task.status, TaskStatus::Revealed);
        assert_eq!(task.challenger, None);
        assert_eq!(task.challenge_bond, None);
        assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn challenge_accepts_when_signer_matches_challenger() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 899, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(899, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenger.as_deref(), Some("challenger"));
        assert_eq!(task.challenge_bond, Some(10));
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    }

    #[test]
    fn challenge_rejects_when_challenger_balance_insufficient() {
        let mut st = seeded_state();
        st.set_balance("challenger", 5);

        let r1 = apply_create_task(&mut st, 892, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(892, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        let err =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap_err();
        assert!(matches!(err, PouwError::InsufficientStake));
        assert_eq!(st.balance_of("challenger"), 5);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn challenge_preflight_overflow_rejects_without_status_or_balance_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_balance(CHALLENGE_ESCROW_ACCOUNT, u128::MAX - 5);

        let r1 = apply_create_task(&mut st, 9951, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9951, &result_hash, &reveal_salt, "worker1");
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        let err =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap_err();
        assert!(matches!(err, PouwError::State(_)));

        let task = st.get_task(9951).unwrap();
        assert_eq!(task.status, TaskStatus::Revealed);
        assert_eq!(st.balance_of("challenger"), 100);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), u128::MAX - 5);
    }

    #[test]
    fn resolve_preflight_overflow_rejects_without_status_or_balance_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, u128::MAX - 5);

        let r1 = apply_create_task(&mut st, 9952, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9952, &result_hash, &reveal_salt, "worker1");
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        set_resolve_authority(&mut st, "challenger");
        let err = apply_resolve(&mut st, r5, false, "challenger".into(), "challenger".into())
            .unwrap_err();
        assert!(matches!(err, PouwError::State(_)));

        let task = st.get_task(9952).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            u128::MAX - 5
        );
    }

    #[test]
    fn timeout_challenged_preflight_overflow_rejects_without_status_or_balance_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 9953, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9953, &result_hash, &reveal_salt, "worker1");
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            120,
        )
        .unwrap();

        st.set_balance("challenger", u128::MAX - 5);

        let err = apply_timeout(&mut st, r5, 221).unwrap_err();
        assert!(matches!(err, PouwError::State(_)));

        let task = st.get_task(9953).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(st.balance_of("challenger"), u128::MAX - 5);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    }

    #[test]
    fn state_error_mapping_version_conflict() {
        let err = map_state_err("version conflict".to_string());
        assert!(matches!(err, PouwError::VersionConflict));

        let err_mixed_case = map_state_err("Version Conflict on task".to_string());
        assert!(matches!(err_mixed_case, PouwError::VersionConflict));

        let err2 = map_state_err("object not found".to_string());
        assert!(matches!(err2, PouwError::State(_)));

        let err3 = map_state_err("version-conflict while syncing".to_string());
        assert!(matches!(err3, PouwError::State(_)));
    }

    #[test]
    fn challenge_version_conflict_does_not_move_funds() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 9901, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9901, &result_hash, &reveal_salt, "worker1");
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        let stale_ref = r4.clone();
        let same_task = st.get_task(r4.id).unwrap();
        let _fresh_ref = st.update_task(r4, same_task).unwrap();

        let err = apply_challenge(
            &mut st,
            stale_ref,
            "challenger".into(),
            10,
            "challenger".into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::VersionConflict));
        assert_eq!(st.balance_of("challenger"), 100);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn resolve_version_conflict_does_not_move_funds() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 9902, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9902, &result_hash, &reveal_salt, "worker1");
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        set_resolve_authority(&mut st, "challenger");
        let stale_ref = r5.clone();
        let same_task = st.get_task(r5.id).unwrap();
        let _fresh_ref = st.update_task(r5, same_task).unwrap();

        let err = apply_resolve(
            &mut st,
            stale_ref,
            false,
            "challenger".into(),
            "challenger".into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::VersionConflict));
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn timeout_version_conflict_does_not_move_funds() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 9903, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9903, &result_hash, &reveal_salt, "worker1");
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            30,
        )
        .unwrap();

        let stale_ref = r5.clone();
        let same_task = st.get_task(r5.id).unwrap();
        let _fresh_ref = st.update_task(r5, same_task).unwrap();

        let err = apply_timeout(&mut st, stale_ref, 131).unwrap_err();
        assert!(matches!(err, PouwError::VersionConflict));
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn accept_preflight_rejects_lock_credit_overflow_without_mutation() {
        let mut st = seeded_state();
        st.set_gov_param_unchecked(9801, "min_worker_stake".into(), "50".into())
            .unwrap();
        st.set_balance("worker1", 50);
        st.set_balance(&worker_stake_lock_account(19801), u128::MAX);

        let r1 = apply_create_task(&mut st, 19801, "alice".into(), 10).unwrap();
        let err = apply_accept_task(&mut st, r1.clone(), "worker1".into()).unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("balance overflow on credit")));

        let task = st.get_task(r1.id).unwrap();
        assert_eq!(task.status, TaskStatus::Open);
        assert_eq!(task.worker, None);
        assert_eq!(st.balance_of("worker1"), 50);
        assert_eq!(st.balance_of(&worker_stake_lock_account(19801)), u128::MAX);
    }

    #[test]
    fn accept_preflight_rejects_insufficient_stake_without_mutation() {
        let mut st = seeded_state();
        st.set_gov_param_unchecked(9802, "min_worker_stake".into(), "50".into())
            .unwrap();
        st.set_balance("worker1", 49);

        let r1 = apply_create_task(&mut st, 19802, "alice".into(), 10).unwrap();
        let err = apply_accept_task(&mut st, r1.clone(), "worker1".into()).unwrap_err();
        assert!(matches!(err, PouwError::InsufficientStake));

        let task = st.get_task(r1.id).unwrap();
        assert_eq!(task.status, TaskStatus::Open);
        assert_eq!(task.worker, None);
        assert_eq!(st.balance_of("worker1"), 49);
        assert_eq!(st.balance_of(&worker_stake_lock_account(19802)), 0);
    }

    #[test]
    fn accept_succeeds_when_worker_stake_at_or_above_minimum() {
        let mut st = seeded_state();
        st.set_gov_param_unchecked(9802, "min_worker_stake".into(), "50".into())
            .unwrap();
        st.set_balance("worker1", 50);

        let r1 = apply_create_task(&mut st, 19802, "alice".into(), 10).unwrap();
        let _r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        assert_eq!(st.balance_of("worker1"), 0);
        assert_eq!(st.balance_of(&worker_stake_lock_account(19802)), 50);
    }

    #[test]
    fn committed_timeout_slashes_worker_economically_and_credits_treasury() {
        let mut st = seeded_state();
        st.set_gov_param_unchecked(9803, "min_worker_stake".into(), "40".into())
            .unwrap();
        st.set_balance("worker1", 40);

        let r1 = apply_create_task(&mut st, 19803, "alice".into(), 10).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(19803, &result_hash, &reveal_salt, "worker1");
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();

        let r4 = apply_timeout(&mut st, r3, 121).unwrap();
        let task = st.get_task(r4.id).unwrap();
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(st.balance_of("worker1"), 0);
        assert_eq!(st.balance_of(&worker_stake_lock_account(19803)), 0);
        assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), 40);
    }

    #[test]
    fn committed_timeout_no_double_slash_on_repeated_attempts() {
        let mut st = seeded_state();
        st.set_gov_param_unchecked(9804, "min_worker_stake".into(), "40".into())
            .unwrap();
        st.set_balance("worker1", 40);

        let r1 = apply_create_task(&mut st, 19804, "alice".into(), 10).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(19804, &result_hash, &reveal_salt, "worker1");
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();

        let r4 = apply_timeout(&mut st, r3, 121).unwrap();
        assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), 40);

        let err = apply_timeout(&mut st, r4, 122).unwrap_err();
        assert!(matches!(err, PouwError::InvalidTransition));
        assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), 40);
    }

    #[test]
    fn timeout_preflight_rejects_conflicting_challenge_transfer_modes() {
        let st = seeded_state();
        let task = TaskObject {
            task_id: 77,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker1".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: Some(1),
            reveal_deadline_height: Some(10),
            challenge_deadline_height: Some(20),
            challenge_window_blocks_snapshot: Some(10),
            challenged_at_height: Some(11),
            resolve_deadline_height: Some(30),
            challenge_bond: Some(10),
            challenge_bond_forfeited: None,
            challenger: Some("challenger".into()),
            version: 0,
        };

        let err = preflight_timeout_transfers(&st, &task, true, true).unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("mode conflict")));
    }

    #[test]
    fn timeout_preflight_rejects_refund_without_challenger() {
        let st = seeded_state();
        let task = TaskObject {
            task_id: 78,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker1".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: Some(1),
            reveal_deadline_height: Some(10),
            challenge_deadline_height: Some(20),
            challenge_window_blocks_snapshot: Some(10),
            challenged_at_height: Some(11),
            resolve_deadline_height: Some(30),
            challenge_bond: Some(10),
            challenge_bond_forfeited: None,
            challenger: None,
            version: 0,
        };

        let err = preflight_timeout_transfers(&st, &task, false, true).unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("without challenger")));
    }

    #[test]
    fn timeout_preflight_rejects_forfeit_without_challenger() {
        let st = seeded_state();
        let task = TaskObject {
            task_id: 78,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Challenged,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker1".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: Some(1),
            reveal_deadline_height: Some(10),
            challenge_deadline_height: Some(20),
            challenge_window_blocks_snapshot: Some(10),
            challenged_at_height: Some(11),
            resolve_deadline_height: Some(30),
            challenge_bond: Some(10),
            challenge_bond_forfeited: None,
            challenger: None,
            version: 0,
        };

        let err = preflight_timeout_transfers(&st, &task, true, false).unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("without challenger")));
    }

    #[test]
    fn timeout_preflight_rejects_transfer_when_bond_not_posted() {
        let st = seeded_state();
        let task = TaskObject {
            task_id: 79,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Completed,
            proof_type: Default::default(),
            metadata: None,
            worker: Some("worker1".into()),
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            committed_at_height: Some(1),
            reveal_deadline_height: Some(10),
            challenge_deadline_height: Some(20),
            challenge_window_blocks_snapshot: Some(10),
            challenged_at_height: Some(11),
            resolve_deadline_height: Some(30),
            challenge_bond: None,
            challenge_bond_forfeited: None,
            challenger: Some("challenger".into()),
            version: 0,
        };

        let err = preflight_timeout_transfers(&st, &task, true, false).unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("without posted challenge bond"))
        );
    }

    #[test]
    fn tee_proof_immediately_completes_task() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7001, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7001, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // TEE proof envelope must bind task_id/worker/proof_type.
        let proof = b"TEE:task_id=7001,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap();

        let final_task = st.get_task(r4.id).unwrap();
        assert_eq!(final_task.status, TaskStatus::Completed);
        assert!(final_task.challenge_deadline_height.is_none());
    }

    #[test]
    fn invalid_tee_proof_rejects_reveal() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7002, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7002, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Invalid proof (doesn't start with TE)
        let proof = b"BAD_PROOF".to_vec();
        let err =
            apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));
    }

    #[test]
    fn tee_reveal_rejects_proof_type_mismatch_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7005, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7005, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Deliberately mismatched proof_type binding should be rejected fail-closed.
        let proof = b"TEE:task_id=7005,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on invalid envelope binding.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn missing_tee_proof_rejects_reveal_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7003, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7003, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let err = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));
    }

    #[test]
    fn zk_proof_immediately_completes_task_and_skips_challenge_window() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7004, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [3u8; 32];
        let reveal_salt = [4u8; 32];
        let committed = compute_commitment(7004, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"ZK:task_id=7004,worker=worker1,proof_type=zk,result_hash=0303030303030303030303030303030303030303030303030303030303030303,receipt=VALID_PROOF".to_vec();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, Some(proof)).unwrap();

        let final_task = st.get_task(r4.id).unwrap();
        assert_eq!(final_task.status, TaskStatus::Completed);
        assert!(final_task.challenge_deadline_height.is_none());
        assert!(final_task.resolve_deadline_height.is_none());
    }
}
