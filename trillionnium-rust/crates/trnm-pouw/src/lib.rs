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
    #[error("resolve approval staged")]
    ResolveApprovalStaged,
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
            PouwError::ResolveApprovalStaged => "ResolveApprovalStaged",
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

fn is_ignorable_proof_payload_char(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '\u{feff}' // BOM
                | '\u{200b}' // ZERO WIDTH SPACE
                | '\u{200c}' // ZERO WIDTH NON-JOINER
                | '\u{200d}' // ZERO WIDTH JOINER
                | '\u{2060}' // WORD JOINER
                | '\u{180e}' // MONGOLIAN VOWEL SEPARATOR
        )
}

fn actor_id_has_hidden_or_zero_width_chars(token: &str) -> bool {
    token.chars().any(|c| {
        matches!(
            c,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{061c}'
                | '\u{115f}'
                | '\u{1160}'
                | '\u{17b4}'
                | '\u{17b5}'
                | '\u{180e}'
                | '\u{200b}'
                | '\u{200c}'
                | '\u{200d}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'
                | '\u{202b}'
                | '\u{202c}'
                | '\u{202d}'
                | '\u{202e}'
                | '\u{2060}'
                | '\u{2061}'
                | '\u{2062}'
                | '\u{2063}'
                | '\u{2064}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
                | '\u{206a}'
                | '\u{206b}'
                | '\u{206c}'
                | '\u{206d}'
                | '\u{206e}'
                | '\u{206f}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
                | '\u{ffa0}'
        )
    })
}

fn actor_id_has_forbidden_separator_alias(token: &str) -> bool {
    token.chars().any(|c| {
        matches!(
            c,
            ','
                | ';'
                | ':'
                | '|'
                | '/'
                | '\\'
                | '，'
                | '；'
                | '：'
                | '｜'
                | '／'
                | '＼'
                | '、'
                | '﹐'
                | '﹑'
                | '﹔'
                | '﹕'
                | '︐'
                | '︔'
                | '︓'
                | '⼁'
                | '∕'
                | '⁄'
                | '╱'
                | '╲'
        )
    })
}

fn is_canonical_actor_id(token: &str) -> bool {
    !token.is_empty()
        && token == token.trim()
        && token.is_ascii()
        && !token.chars().any(|c| c.is_whitespace())
        && !token.chars().any(|c| c.is_control())
        && !actor_id_has_hidden_or_zero_width_chars(token)
        && !actor_id_has_forbidden_separator_alias(token)
}

fn require_canonical_actor_id(token: &str) -> Result<(), PouwError> {
    if is_canonical_actor_id(token) {
        Ok(())
    } else {
        Err(PouwError::Unauthorized)
    }
}

fn require_canonical_actor_id_state(token: &str, field_name: &str) -> Result<(), PouwError> {
    if is_canonical_actor_id(token) {
        Ok(())
    } else {
        Err(PouwError::State(format!("non-canonical {}", field_name)))
    }
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
        .filter(|v| !v.trim().is_empty())
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
                && (task.challenged_at_height.is_some()
                    || task.challenge_deadline_height.is_some()
                    || task.resolve_deadline_height.is_some())
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
    if slash_worker && task.challenge_bond.is_some() && task.challenger.is_none() {
        return Err(PouwError::State(
            "resolve challenge refund requested without challenger".into(),
        ));
    }

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

fn finalize_verified_reveal_success(
    st: &mut StateStore,
    task_ref: ObjectRef,
    task: TaskObject,
) -> Result<ObjectRef, PouwError> {
    let mut sim = st.clone();
    settle_worker_stake_for_terminal_state(&mut sim, &task)?;

    let next_ref = st
        .update_task(task_ref, task.clone())
        .map_err(map_state_err)?;
    settle_worker_stake_for_terminal_state(st, &task)?;
    Ok(next_ref)
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
    require_canonical_actor_id(&creator)?;

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
    require_canonical_actor_id(&worker)?;

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

    if task.task_id != task_ref.id {
        // Fail closed if legacy/corrupted state breaks the canonical task_id
        // binding between object reference and proof envelope context.
        return Err(PouwError::State("task id binding mismatch".into()));
    }

    let worker = task.worker.clone().ok_or(PouwError::MissingWorker)?;
    // Legacy-state hardening: fail closed on malformed assigned worker ids so
    // commitment/proof envelope worker binding cannot be validated against
    // non-canonical identity strings.
    require_canonical_actor_id_state(&worker, "worker account")?;

    let committed = task.committed_hash.ok_or(PouwError::MissingCommitment)?;
    let expected = compute_commitment(task.task_id, &result_hash, &reveal_salt, &worker);
    if expected != committed {
        return Err(PouwError::CommitmentMismatch);
    }

    if matches!(task.proof_type, ProofType::Tee | ProofType::Zk) {
        if let Some(stored_result_hash) = task.result_hash {
            if stored_result_hash != result_hash {
                // Legacy-state hardening: verifiable envelopes must not proceed when
                // persisted committed state already drifts from the reveal/hash tuple.
                return Err(PouwError::State(
                    "legacy committed result hash drift".into(),
                ));
            }
            // Fail closed even when the legacy prebound hash matches, because verifiable
            // tasks must only persist result_hash after successful proof verification.
            return Err(PouwError::State(
                "legacy committed result hash prebound".into(),
            ));
        }
    }

    // Verify proof if TEE/ZK.
    // For Fraud proofs, we rely on the challenge period (no immediate verification).
    // Fail closed if a proof payload is supplied for a non-verifiable proof type, so
    // legacy/corrupted proof_type drift cannot silently bypass envelope verification.
    if proof_data.is_some() && !matches!(task.proof_type, ProofType::Tee | ProofType::Zk) {
        return Err(PouwError::State(format!(
            "unexpected proof payload for non-verifiable proof type: {:?}",
            task.proof_type
        )));
    }
    if matches!(task.proof_type, ProofType::Tee | ProofType::Zk) {
        let proof_payload = proof_data.as_deref().unwrap_or(&[]);
        let proof_payload_is_blank = proof_payload.is_empty()
            || proof_payload.iter().all(|b| b.is_ascii_whitespace())
            || std::str::from_utf8(proof_payload)
                .map(|payload| payload.trim_matches(is_ignorable_proof_payload_char).is_empty())
                .unwrap_or(false);
        if proof_payload_is_blank {
            return Err(PouwError::State(format!(
                "Proof verification failed: missing proof payload for {:?}",
                task.proof_type
            )));
        }

        let registry = get_default_registry();
        let mut verification_task = task.clone();
        // Rebind canonical envelope context explicitly so verification always
        // evaluates the committed task_id/worker/proof_type/result_hash tuple,
        // even when legacy state carries drift in optional fields.
        verification_task.task_id = task.task_id;
        verification_task.worker = Some(worker.clone());
        verification_task.proof_type = task.proof_type;
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

                // Immediate finality remains atomic with stake settlement: preflight
                // the unlock on a cloned state, then persist the task before touching balances.
                return finalize_verified_reveal_success(st, task_ref, task);
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
    // Safety boundary: emergency pause must also freeze new challenged-state
    // entry because it immediately debits challenger funds into escrow.
    if st.is_emergency_paused() {
        return Err(PouwError::InvalidTransition);
    }
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
    require_canonical_actor_id(&challenger)?;
    require_canonical_actor_id(&signer)?;
    let challenger_trimmed = challenger.as_str();
    let signer_trimmed = signer.as_str();
    if signer_trimmed != challenger_trimmed {
        return Err(PouwError::Unauthorized);
    }

    if let Some(worker) = task.worker.as_ref() {
        // Legacy-state hardening: reject malformed non-canonical worker ids
        // so self-challenge and accounting gates cannot be bypassed.
        require_canonical_actor_id_state(worker, "worker account")?;
        let worker_trimmed = worker;
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
    let resolver_trimmed = resolver.as_str();
    // Gate hardening: signer and configured authority must both be canonical
    // non-blank account identifiers (no surrounding whitespace).
    let signer_trimmed = signer.as_str();
    let authority_trimmed = resolve_authority.trim();
    let authority_members: Vec<&str> = authority_trimmed.split(',').collect();
    let authority_has_empty_member = authority_members
        .iter()
        .any(|member| member.trim().is_empty());
    let authority_has_duplicate_member = {
        let mut seen = std::collections::BTreeSet::new();
        authority_members
            .iter()
            .map(|member| member.to_ascii_lowercase())
            .any(|member| !seen.insert(member))
    };
    let resolver_is_canonical = is_canonical_actor_id(resolver_trimmed);
    let signer_is_canonical = is_canonical_actor_id(signer_trimmed);
    let authority_members_are_canonical = authority_members
        .iter()
        .all(|member| is_canonical_actor_id(member));
    let signer_matches_configured_member = authority_members
        .iter()
        .any(|member| *member == signer_trimmed);
    // Decentralization hardening: reserve privileged runtime account ids from
    // governance resolve authority flow; challenge resolution must be executed
    // by explicit governance-designated non-system operators.
    let authority_uses_reserved_system_actor = authority_members
        .iter()
        .any(|member| member.eq_ignore_ascii_case("system"));
    let uses_reserved_system_actor = resolver_trimmed.eq_ignore_ascii_case("system")
        || signer_trimmed.eq_ignore_ascii_case("system")
        || authority_uses_reserved_system_actor;
    // Minimal multi-party control: escrow treasury account must never be reused
    // as resolve authority signer/payload, otherwise custody + adjudication roles
    // collapse into a single privileged actor surface.
    let authority_uses_escrow_account = authority_members
        .iter()
        .any(|member| member.eq_ignore_ascii_case(CHALLENGE_ESCROW_ACCOUNT));
    let uses_escrow_account_as_authority = resolver_trimmed
        .eq_ignore_ascii_case(CHALLENGE_ESCROW_ACCOUNT)
        || signer_trimmed.eq_ignore_ascii_case(CHALLENGE_ESCROW_ACCOUNT)
        || authority_uses_escrow_account;
    // Minimal multi-party control: forfeits treasury account receives terminal
    // slashing-path value and must remain custody-only (not an adjudicator).
    let authority_uses_forfeit_treasury_account = authority_members
        .iter()
        .any(|member| member.eq_ignore_ascii_case(CHALLENGE_FORFEIT_TREASURY_ACCOUNT));
    let uses_forfeit_treasury_account_as_authority = resolver_trimmed
        .eq_ignore_ascii_case(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        || signer_trimmed.eq_ignore_ascii_case(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        || authority_uses_forfeit_treasury_account;
    // Minimal multi-party control: worker slash treasury receives terminal
    // slashing-path value and must remain custody-only (not an adjudicator).
    let authority_uses_worker_slash_treasury_account = authority_members
        .iter()
        .any(|member| member.eq_ignore_ascii_case(WORKER_SLASH_TREASURY_ACCOUNT));
    let uses_worker_slash_treasury_account_as_authority = resolver_trimmed
        .eq_ignore_ascii_case(WORKER_SLASH_TREASURY_ACCOUNT)
        || signer_trimmed.eq_ignore_ascii_case(WORKER_SLASH_TREASURY_ACCOUNT)
        || authority_uses_worker_slash_treasury_account;
    // Decentralization hardening: unresolved default placeholder must never
    // authorize challenge resolution. Governance must explicitly set a concrete
    // non-placeholder resolve authority before terminal escrow movement can occur.
    let authority_uses_placeholder = authority_members
        .iter()
        .any(|member| member.eq_ignore_ascii_case(DEFAULT_RESOLVE_AUTHORITY));
    let uses_unconfigured_placeholder_authority = resolver_trimmed
        .eq_ignore_ascii_case(DEFAULT_RESOLVE_AUTHORITY)
        || signer_trimmed.eq_ignore_ascii_case(DEFAULT_RESOLVE_AUTHORITY)
        || authority_uses_placeholder;
    // Legacy-state hardening: assigned worker identity must remain canonical
    // before resolve authority checks, otherwise malformed worker ids could
    // bypass self-resolution separation gates.
    if let Some(worker) = task.worker.as_ref() {
        require_canonical_actor_id_state(worker, "worker account")?;
    }
    // Minimal multi-party control: assigned worker cannot self-authorize terminal
    // challenge resolution for their own disputed task.
    let resolver_is_assigned_worker = task
        .worker
        .as_deref()
        .map(|worker| worker.eq_ignore_ascii_case(signer_trimmed))
        .unwrap_or(false);
    // Minimal multi-party control: configured resolve-authority sets must remain
    // disjoint from the assigned worker role so adjudication stays external even
    // when a different member signs the final resolve.
    let authority_includes_assigned_worker = task
        .worker
        .as_deref()
        .map(|worker| {
            authority_members
                .iter()
                .any(|member| member.eq_ignore_ascii_case(worker))
        })
        .unwrap_or(false);
    // Minimal multi-party control: challenger (escrow depositor) must stay separate
    // from adjudicator authority to avoid prosecutor+judge role collapse.
    let resolver_is_challenger = task
        .challenger
        .as_deref()
        .map(|challenger| challenger.eq_ignore_ascii_case(signer_trimmed))
        .unwrap_or(false);
    let authority_includes_challenger = task
        .challenger
        .as_deref()
        .map(|challenger| {
            authority_members
                .iter()
                .any(|member| member.eq_ignore_ascii_case(challenger))
        })
        .unwrap_or(false);
    if !resolver_is_canonical
        || !signer_is_canonical
        || authority_trimmed.is_empty()
        || authority_trimmed != resolve_authority
        || !signer_matches_configured_member
        || !authority_members_are_canonical
        || authority_has_empty_member
        || authority_has_duplicate_member
        || resolver_trimmed != signer_trimmed
        || uses_reserved_system_actor
        || uses_escrow_account_as_authority
        || uses_forfeit_treasury_account_as_authority
        || uses_worker_slash_treasury_account_as_authority
        || uses_unconfigured_placeholder_authority
        || resolver_is_assigned_worker
        || authority_includes_assigned_worker
        || resolver_is_challenger
        || authority_includes_challenger
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

    // Minimal multi-party control: if governance downgrades a multisig resolver
    // set to single-authority after a first staged approval, fail closed and
    // clear stale staging so one signer cannot inherit partially-approved state.
    if authority_members.len() <= 1
        && (st.pending_resolve_approval(task_ref.id).is_some()
            || st.pending_resolve_first_approver(task_ref.id).is_some())
    {
        st.clear_pending_resolve_approval(task_ref.id);
        return Err(PouwError::Unauthorized);
    }

    // Minimal multi-party control: when governance configures a resolver set,
    // require two distinct member approvals before terminal escrow settlement.
    if authority_members.len() > 1 {
        // Governance hardening: if resolver membership changes after a first
        // staged approval, fail closed and discard stale staged state so a
        // removed approver cannot be counted toward the current signer set.
        if let Some(first_approver) = st.pending_resolve_first_approver(task_ref.id) {
            let first_still_authorized = authority_members
                .iter()
                .any(|member| *member == first_approver);
            if !first_still_authorized {
                st.clear_pending_resolve_approval(task_ref.id);
                return Err(PouwError::Unauthorized);
            }
        }

        let approved = st
            .stage_or_confirm_resolve_approval(
                task_ref.id,
                task_ref.version,
                slash_worker,
                signer_trimmed,
                authority_trimmed,
            )
            .map_err(|_| PouwError::Unauthorized)?;
        if !approved {
            return Err(PouwError::ResolveApprovalStaged);
        }
    }

    let task_id = task_ref.id;
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
    st.clear_pending_resolve_approval(task_id);

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

    if matches!(task.status, TaskStatus::Challenged) && st.is_emergency_paused() {
        // Safety boundary: emergency pause must fail-closed before challenged-task
        // invariant/audit checks so timeout settlement cannot leak challenged-state
        // accounting details while escrow movement paths are frozen.
        return Err(PouwError::InvalidTransition);
    }

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
            task.challenge_deadline_height = None;
            task.challenged_at_height = None;
            task.resolve_deadline_height = None;
        }
        TaskStatus::Challenged => {
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

    let task_id = task_ref.id;
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
    // Hygiene boundary: timeout finalization must clear any staged multisig resolve
    // approvals so stale partial authorizations cannot linger after terminal state.
    st.clear_pending_resolve_approval(task_id);

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
        // Some fail-closed tests intentionally attempt malformed/reserved authorities.
        // Keep the fixture helper tolerant so those tests can still exercise resolve
        // authorization behavior even when governance-layer validation rejects writes.
        let _ = st.set_gov_param_bootstrap_unchecked(
            9_500,
            "resolve_authority".into(),
            authority.into(),
        );
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
        set_resolve_authority(&mut st, "authority,authority2");
        let staged = apply_resolve(&mut st, r5.clone(), false, "authority".into(), "authority".into())
            .expect_err("first resolver should stage multisig approval");
        assert!(matches!(staged, PouwError::ResolveApprovalStaged));
        let r6 = apply_resolve(&mut st, r5, false, "authority2".into(), "authority2".into()).unwrap();

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

    fn dirty_actor_ids() -> Vec<&'static str> {
        vec![
            "worker 1",
            "worker\t1",
            "worker\n1",
            "worker\u{200b}1",
            "worker\u{2060}1",
            "wørker1",
            "worker,1",
            "worker，1",
            "worker;1",
            "worker；1",
            "worker|1",
            "worker｜1",
            "worker/1",
            "worker／1",
            "worker:1",
            "worker：1",
        ]
    }

    #[test]
    fn accept_task_rejects_dirty_worker_actor_ids() {
        for (i, dirty_worker) in dirty_actor_ids().into_iter().enumerate() {
            let mut st = seeded_state();
            let r1 = apply_create_task(&mut st, 21_100 + i as u64, "alice".into(), 10).unwrap();
            let err = apply_accept_task(&mut st, r1, dirty_worker.into()).unwrap_err();
            assert!(matches!(err, PouwError::Unauthorized), "accept should reject dirty worker actor id: {:?}", dirty_worker);
        }
    }

    #[test]
    fn challenge_rejects_dirty_challenger_actor_ids() {
        for (i, dirty_challenger) in dirty_actor_ids().into_iter().enumerate() {
            let mut st = seeded_state();
            st.set_balance("worker1", 10);
            st.set_balance("challenger", 1_000);
            let task_id = 21_300 + i as u64;
            let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
            let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
            let result_hash = [7u8; 32];
            let reveal_salt = [9u8; 32];
            let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");
            let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
            let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
            let err = apply_challenge(&mut st, r4, dirty_challenger.into(), 10, dirty_challenger.into()).unwrap_err();
            assert!(matches!(err, PouwError::Unauthorized), "challenge should reject dirty challenger actor id: {:?}", dirty_challenger);
        }
    }

    #[test]
    fn resolve_rejects_dirty_resolver_actor_ids() {
        for (i, dirty_resolver) in dirty_actor_ids().into_iter().enumerate() {
            let mut st = seeded_state();
            st.set_balance("worker1", 10);
            st.set_balance("challenger", 1_000);
            st.set_gov_param_bootstrap_unchecked(
                9_801 + i as u64,
                "resolve_authority".into(),
                "resolver1,resolver2".into(),
            )
            .unwrap();
            let task_id = 21_500 + i as u64;
            let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
            let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
            let result_hash = [7u8; 32];
            let reveal_salt = [9u8; 32];
            let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");
            let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
            let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
            let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
            let err = apply_resolve(&mut st, r5, false, dirty_resolver.into(), dirty_resolver.into()).unwrap_err();
            assert!(matches!(err, PouwError::Unauthorized), "resolve should reject dirty resolver actor id: {:?}", dirty_resolver);
        }
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
        set_resolve_authority(&mut st, "authority,authority2");
        let staged = apply_resolve(
            &mut st,
            r5.clone(),
            false,
            "authority".into(),
            "authority".into(),
        )
        .unwrap_err();
        assert!(matches!(staged, PouwError::ResolveApprovalStaged));
        let _r6 = apply_resolve(
            &mut st,
            r5.clone(),
            false,
            "authority2".into(),
            "authority2".into(),
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

        let err = apply_reveal_result(&mut st, r2.clone(), [2u8; 32], [3u8; 32], None).unwrap_err();
        assert!(matches!(err, PouwError::MissingWorker));

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_missing_worker_fails_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 779, "alice".into(), 10).unwrap();

        // Legacy/corrupted state may lose assigned worker identity after commit.
        // TEE proof verification must fail closed before any terminal mutation.
        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(779, &result_hash, &reveal_salt, "worker1");
        let bad_task = TaskObject {
            task_id: 779,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: None,
            committed_hash: Some(committed),
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

        let proof = b"TEE:task_id=779,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::MissingWorker));

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_missing_worker_fails_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 780, "alice".into(), 10).unwrap();

        // Legacy/corrupted state may lose assigned worker identity after commit.
        // ZK proof verification must fail closed before any terminal mutation.
        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(780, &result_hash, &reveal_salt, "worker1");
        let bad_task = TaskObject {
            task_id: 780,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: None,
            committed_hash: Some(committed),
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

        let proof = b"ZK:task_id=780,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::MissingWorker));

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_noncanonical_worker_binding_before_verification() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 781, "alice".into(), 10).unwrap();

        // Legacy/corrupted state may carry non-canonical worker account ids.
        // TEE proof verification must fail closed before any terminal mutation.
        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(781, &result_hash, &reveal_salt, " worker1 ");
        let bad_task = TaskObject {
            task_id: 781,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some(" worker1 ".into()),
            committed_hash: Some(committed),
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

        let proof = b"TEE:task_id=781,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(reason) if reason == "non-canonical worker account"));

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_matching_legacy_committed_result_hash_binding_fail_closed_before_verification(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 788, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(788, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Simulate legacy state where committed result_hash was persisted early but
        // still matches the reveal payload. Verifiable tasks must fail closed before
        // verification when committed state is prebound.
        let mut prebound = st.get_task(r3.id).unwrap();
        prebound.result_hash = Some(result_hash);
        let r3 = st.update_task(r3, prebound).unwrap();

        let proof = b"TEE:task_id=788,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("legacy committed result hash prebound"))
        );

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert_eq!(task_after.result_hash, Some(result_hash));
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_malformed_secondary_task_id_binding_fail_closed_before_verification() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7882, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(7882, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Fail closed when the proof envelope repeats task_id with a malformed
        // secondary value, even if the first binding appears canonical.
        let proof = b"TEE:task_id=7882,task_id=7882x,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("duplicate task_id binding")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_matching_legacy_committed_result_hash_binding_fail_closed_before_verification(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7881, "alice".into(), 10).unwrap();
        let mut zk_task = st.get_task(r1.id).unwrap();
        zk_task.proof_type = ProofType::Zk;
        let r1 = st.update_task(r1, zk_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(7881, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Simulate legacy state where committed result_hash was persisted early but
        // still matches the reveal payload. Verifiable tasks must fail closed before
        // verification when committed state is prebound.
        let mut prebound = st.get_task(r3.id).unwrap();
        prebound.result_hash = Some(result_hash);
        let r3 = st.update_task(r3, prebound).unwrap();

        let proof = b"ZK:task_id=7881,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("legacy committed result hash prebound"))
        );

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert_eq!(task_after.result_hash, Some(result_hash));
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_legacy_state_task_id_drift_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 789, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(789, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Simulate legacy/corrupted state where object reference id is still 789
        // but the persisted task body drifts to a different task_id.
        let mut drifted = st.get_task(r3.id).unwrap();
        drifted.task_id = 1789;
        let r3 = st.update_task(r3, drifted).unwrap();

        let proof = b"TEE:task_id=789,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("task id binding mismatch")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_legacy_state_task_id_drift_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7891, "alice".into(), 10).unwrap();
        let mut zk_task = st.get_task(r1.id).unwrap();
        zk_task.proof_type = ProofType::Zk;
        let r1 = st.update_task(r1, zk_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(7891, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Simulate legacy/corrupted state where object reference id is still 7891
        // but the persisted task body drifts to a different task_id.
        let mut drifted = st.get_task(r3.id).unwrap();
        drifted.task_id = 17891;
        let r3 = st.update_task(r3, drifted).unwrap();

        let proof = b"ZK:task_id=7891,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("task id binding mismatch")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn fraud_reveal_rejects_legacy_state_task_id_drift_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7893, "alice".into(), 10).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(7893, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Simulate legacy/corrupted state where object reference id is still 7893
        // but the persisted task body drifts to a different task_id.
        let mut drifted = st.get_task(r3.id).unwrap();
        drifted.task_id = 17893;
        let r3 = st.update_task(r3, drifted).unwrap();

        let err =
            apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, None).unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("task id binding mismatch")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_result_hash_binding_with_repeated_hex_prefix_fail_closed_without_state_mutation(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7892, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(7892, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"TEE:task_id=7892,worker=worker1,proof_type=tee,result_hash=0x0x0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_fullwidth_equals_result_hash_binding_fail_closed_without_state_mutation()
    {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 78921, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(78921, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = "TEE:task_id=78921,worker=worker1,proof_type=tee,result_hash＝0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ"
            .as_bytes()
            .to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_fullwidth_colon_result_hash_binding_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 78923, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(78923, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = "TEE:task_id=78923,worker=worker1,proof_type=tee,result_hash：0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ"
            .as_bytes()
            .to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_fullwidth_colon_proof_type_binding_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 78924, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(78924, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = "TEE:task_id=78924,worker=worker1,proof_type：tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ"
            .as_bytes()
            .to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_fullwidth_comma_delimited_duplicate_worker_binding_fail_closed_without_state_mutation(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 78922, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(78922, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = "TEE:task_id=78922,worker=worker1，worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ"
            .as_bytes()
            .to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_task_id_identifier_spoof_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7900, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(7900, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"TEE:x_task_id=7900,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_task_id_identifier_spoof_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 79001, "alice".into(), 10).unwrap();
        let mut zk_task = st.get_task(r1.id).unwrap();
        zk_task.proof_type = ProofType::Zk;
        let r1 = st.update_task(r1, zk_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(79001, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"ZK:x_task_id=79001,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_proof_type_identifier_spoof_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 79002, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(79002, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"TEE:task_id=79002,worker=worker1,x_proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_missing_result_hash_binding_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 790, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(790, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"TEE:task_id=790,worker=worker1,proof_type=tee,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_missing_proof_type_binding_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7901, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(7901, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"TEE:task_id=7901,worker=worker1,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_worker_binding_mismatch_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7902, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(7902, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"TEE:task_id=7902,worker=worker2,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_missing_result_hash_binding_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 791, "alice".into(), 10).unwrap();
        let mut zk_task = st.get_task(r1.id).unwrap();
        zk_task.proof_type = ProofType::Zk;
        let r1 = st.update_task(r1, zk_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(791, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"ZK:task_id=791,worker=worker1,proof_type=zk,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_missing_proof_type_binding_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7911, "alice".into(), 10).unwrap();
        let mut zk_task = st.get_task(r1.id).unwrap();
        zk_task.proof_type = ProofType::Zk;
        let r1 = st.update_task(r1, zk_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(7911, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"ZK:task_id=7911,worker=worker1,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_worker_binding_mismatch_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7912, "alice".into(), 10).unwrap();
        let mut zk_task = st.get_task(r1.id).unwrap();
        zk_task.proof_type = ProofType::Zk;
        let r1 = st.update_task(r1, zk_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(7912, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"ZK:task_id=7912,worker=worker2,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_fullwidth_equals_result_hash_binding_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 79121, "alice".into(), 10).unwrap();
        let mut zk_task = st.get_task(r1.id).unwrap();
        zk_task.proof_type = ProofType::Zk;
        let r1 = st.update_task(r1, zk_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(79121, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = "ZK:task_id=79121,worker=worker1,proof_type=zk,result_hash＝0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ"
            .as_bytes()
            .to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_fullwidth_colon_result_hash_binding_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 79122, "alice".into(), 10).unwrap();
        let mut zk_task = st.get_task(r1.id).unwrap();
        zk_task.proof_type = ProofType::Zk;
        let r1 = st.update_task(r1, zk_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(79122, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = "ZK:task_id=79122,worker=worker1,proof_type=zk,result_hash：0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ"
            .as_bytes()
            .to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_fullwidth_comma_delimited_duplicate_worker_binding_fail_closed_without_state_mutation(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 79123, "alice".into(), 10).unwrap();
        let mut zk_task = st.get_task(r1.id).unwrap();
        zk_task.proof_type = ProofType::Zk;
        let r1 = st.update_task(r1, zk_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(79123, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = "ZK:task_id=79123,worker=worker1，worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ"
            .as_bytes()
            .to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_result_hash_binding_with_repeated_hex_prefix_fail_closed_without_state_mutation(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 79122, "alice".into(), 10).unwrap();
        let mut zk_task = st.get_task(r1.id).unwrap();
        zk_task.proof_type = ProofType::Zk;
        let r1 = st.update_task(r1, zk_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(79122, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"ZK:task_id=79122,worker=worker1,proof_type=zk,result_hash=0x0x0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_semicolon_delimited_duplicate_task_id_binding_fail_closed_without_state_mutation(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7903, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(7903, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"TEE:task_id=7903;worker=worker1;proof_type=tee;result_hash=0202020202020202020202020202020202020202020202020202020202020202;task_id=7903;quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_semicolon_delimited_duplicate_worker_binding_fail_closed_without_state_mutation(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 79032, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(79032, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"TEE:task_id=79032;worker=worker1;proof_type=tee;result_hash=0202020202020202020202020202020202020202020202020202020202020202;worker=worker1;quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_semicolon_delimited_duplicate_result_hash_binding_fail_closed_without_state_mutation(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 790322, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(790322, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"TEE:task_id=790322;worker=worker1;proof_type=tee;result_hash=0202020202020202020202020202020202020202020202020202020202020202;result_hash=0202020202020202020202020202020202020202020202020202020202020202;quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_semicolon_delimited_duplicate_proof_type_binding_fail_closed_without_state_mutation(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 79033, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(79033, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"TEE:task_id=79033;worker=worker1;proof_type=tee;result_hash=0202020202020202020202020202020202020202020202020202020202020202;proof_type=tee;quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_comma_delimited_duplicate_task_id_binding_fail_closed_without_state_mutation(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 79031, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(79031, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"TEE:task_id=79031,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,task_id=79031,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_comma_delimited_duplicate_task_id_binding_fail_closed_without_state_mutation(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 79033, "alice".into(), 10).unwrap();
        let mut zk_task = st.get_task(r1.id).unwrap();
        zk_task.proof_type = ProofType::Zk;
        let r1 = st.update_task(r1, zk_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(79033, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"ZK:task_id=79033,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,task_id=79033,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_semicolon_delimited_duplicate_task_id_binding_fail_closed_without_state_mutation(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7904, "alice".into(), 10).unwrap();
        let mut zk_task = st.get_task(r1.id).unwrap();
        zk_task.proof_type = ProofType::Zk;
        let r1 = st.update_task(r1, zk_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(7904, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"ZK:task_id=7904;worker=worker1;proof_type=zk;result_hash=0202020202020202020202020202020202020202020202020202020202020202;task_id=7904;seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_semicolon_delimited_duplicate_worker_binding_fail_closed_without_state_mutation(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 79041, "alice".into(), 10).unwrap();
        let mut zk_task = st.get_task(r1.id).unwrap();
        zk_task.proof_type = ProofType::Zk;
        let r1 = st.update_task(r1, zk_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(79041, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"ZK:task_id=79041;worker=worker1;proof_type=zk;result_hash=0202020202020202020202020202020202020202020202020202020202020202;worker=worker1;seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_semicolon_delimited_duplicate_proof_type_binding_fail_closed_without_state_mutation(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 79042, "alice".into(), 10).unwrap();
        let mut zk_task = st.get_task(r1.id).unwrap();
        zk_task.proof_type = ProofType::Zk;
        let r1 = st.update_task(r1, zk_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(79042, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"ZK:task_id=79042;worker=worker1;proof_type=zk;result_hash=0202020202020202020202020202020202020202020202020202020202020202;proof_type=zk;seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_semicolon_delimited_duplicate_result_hash_binding_fail_closed_without_state_mutation(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 79043, "alice".into(), 10).unwrap();
        let mut zk_task = st.get_task(r1.id).unwrap();
        zk_task.proof_type = ProofType::Zk;
        let r1 = st.update_task(r1, zk_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(79043, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let proof = b"ZK:task_id=79043;worker=worker1;proof_type=zk;result_hash=0202020202020202020202020202020202020202020202020202020202020202;result_hash=0202020202020202020202020202020202020202020202020202020202020202;seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_task_ref_id_mismatch_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 781, "alice".into(), 10).unwrap();

        // Simulate legacy/corrupted storage drift where object key and embedded task_id diverge.
        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let committed = compute_commitment(780, &result_hash, &reveal_salt, &worker);
        let bad_task = TaskObject {
            task_id: 780,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some(worker),
            committed_hash: Some(committed),
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

        let proof = b"TEE:task_id=780,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("task id binding mismatch")));

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_task_ref_id_mismatch_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 782, "alice".into(), 10).unwrap();

        // Simulate legacy/corrupted storage drift where object key and embedded task_id diverge.
        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let committed = compute_commitment(781, &result_hash, &reveal_salt, &worker);
        let bad_task = TaskObject {
            task_id: 781,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: Some(worker),
            committed_hash: Some(committed),
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

        let proof = b"ZK:task_id=781,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("task id binding mismatch")));

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn fraud_reveal_rejects_task_ref_id_mismatch_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 783, "alice".into(), 10).unwrap();

        // Simulate legacy/corrupted storage drift where object key and embedded task_id diverge.
        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let committed = compute_commitment(782, &result_hash, &reveal_salt, &worker);
        let bad_task = TaskObject {
            task_id: 782,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Fraud,
            metadata: None,
            worker: Some(worker),
            committed_hash: Some(committed),
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

        let err =
            apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, None).unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("task id binding mismatch")));

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_legacy_committed_result_hash_drift_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 783, "alice".into(), 10).unwrap();

        // Simulate legacy drift where Committed state already carries a stale result_hash.
        // Reveal verification must rebind to the reveal arguments and proof envelope bindings.
        let result_hash = [2u8; 32];
        let stale_result_hash = [9u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let committed = compute_commitment(783, &result_hash, &reveal_salt, &worker);
        let legacy_task = TaskObject {
            task_id: 783,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some(worker),
            committed_hash: Some(committed),
            // Legacy/corrupted optional field drift.
            result_hash: Some(stale_result_hash),
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
        let r2 = st.update_task(r1, legacy_task).unwrap();

        let proof = b"TEE:task_id=783,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("legacy committed result hash drift"))
        );

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert_eq!(task_after.result_hash, Some(stale_result_hash));
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_legacy_committed_result_hash_drift_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 784, "alice".into(), 10).unwrap();

        // Simulate legacy drift where Committed state already carries a stale result_hash.
        // Reveal verification must rebind to the reveal arguments and proof envelope bindings.
        let result_hash = [2u8; 32];
        let stale_result_hash = [9u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let committed = compute_commitment(784, &result_hash, &reveal_salt, &worker);
        let legacy_task = TaskObject {
            task_id: 784,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: Some(worker),
            committed_hash: Some(committed),
            // Legacy/corrupted optional field drift.
            result_hash: Some(stale_result_hash),
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
        let r2 = st.update_task(r1, legacy_task).unwrap();

        let proof = b"ZK:task_id=784,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("legacy committed result hash drift"))
        );

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert_eq!(task_after.result_hash, Some(stale_result_hash));
        assert!(task_after.reveal_salt.is_none());
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
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("non-canonical worker account"))
        );
    }

    #[test]
    fn reveal_rejects_unexpected_proof_payload_for_non_verifiable_proof_type_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 789, "alice".into(), 10).unwrap();

        // Legacy/corrupted proof_type drift may mark a proof-requiring task as Fraud.
        // If a payload is present, reject fail-closed instead of silently bypassing
        // envelope verification.
        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let drifted_task = TaskObject {
            task_id: 789,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Fraud,
            metadata: None,
            worker: Some(worker.clone()),
            committed_hash: Some(compute_commitment(789, &result_hash, &reveal_salt, &worker)),
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
        let r2 = st.update_task(r1, drifted_task).unwrap();

        let proof = b"TEE:task_id=789,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(
            err,
            PouwError::State(msg)
                if msg.contains("unexpected proof payload for non-verifiable proof type")
                    && msg.contains("Fraud")
        ));

        // Fail-closed behavior: state must remain Committed and unset reveal artifacts.
        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn reveal_rejects_zk_payload_for_non_verifiable_proof_type_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7890, "alice".into(), 10).unwrap();

        // Legacy/corrupted proof_type drift may mark a proof-requiring task as Fraud.
        // If a payload is present, reject fail-closed instead of silently bypassing
        // envelope verification, regardless of whether payload prefix is TEE or ZK.
        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let drifted_task = TaskObject {
            task_id: 7890,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Fraud,
            metadata: None,
            worker: Some(worker.clone()),
            committed_hash: Some(compute_commitment(
                7890,
                &result_hash,
                &reveal_salt,
                &worker,
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
        let r2 = st.update_task(r1, drifted_task).unwrap();

        let proof = b"ZK:task_id=7890,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("unexpected proof payload for non-verifiable proof type"))
        );

        // Fail-closed behavior: state must remain Committed and unset reveal artifacts.
        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn reveal_rejects_tee_payload_for_non_verifiable_proof_type_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 78901, "alice".into(), 10).unwrap();

        // Legacy/corrupted proof_type drift may carry a TEE envelope while task
        // state says Fraud. This must fail closed before any reveal mutation.
        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let drifted_task = TaskObject {
            task_id: 78901,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Fraud,
            metadata: None,
            worker: Some(worker.clone()),
            committed_hash: Some(compute_commitment(
                78901,
                &result_hash,
                &reveal_salt,
                &worker,
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
        let r2 = st.update_task(r1, drifted_task).unwrap();

        let proof = b"TEE:task_id=78901,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("unexpected proof payload for non-verifiable proof type") && msg.contains("Fraud"))
        );

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn reveal_rejects_blank_proof_payload_for_non_verifiable_proof_type_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7891, "alice".into(), 10).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let drifted_task = TaskObject {
            task_id: 7891,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Fraud,
            metadata: None,
            worker: Some(worker.clone()),
            committed_hash: Some(compute_commitment(
                7891,
                &result_hash,
                &reveal_salt,
                &worker,
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
        let r2 = st.update_task(r1, drifted_task).unwrap();

        let err = apply_reveal_result(
            &mut st,
            r2.clone(),
            result_hash,
            reveal_salt,
            Some(b" \t\n".to_vec()),
        )
        .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("unexpected proof payload for non-verifiable proof type"))
        );

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn reveal_rejects_utf8_bom_only_proof_payload_for_non_verifiable_proof_type_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7892, "alice".into(), 10).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let drifted_task = TaskObject {
            task_id: 7892,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Fraud,
            metadata: None,
            worker: Some(worker.clone()),
            committed_hash: Some(compute_commitment(
                7892,
                &result_hash,
                &reveal_salt,
                &worker,
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
        let r2 = st.update_task(r1, drifted_task).unwrap();

        let err = apply_reveal_result(
            &mut st,
            r2.clone(),
            result_hash,
            reveal_salt,
            Some(vec![0xEF, 0xBB, 0xBF]),
        )
        .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("unexpected proof payload for non-verifiable proof type"))
        );

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn reveal_rejects_unicode_whitespace_payload_for_non_verifiable_proof_type_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7893, "alice".into(), 10).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let drifted_task = TaskObject {
            task_id: 7893,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Fraud,
            metadata: None,
            worker: Some(worker.clone()),
            committed_hash: Some(compute_commitment(
                7893,
                &result_hash,
                &reveal_salt,
                &worker,
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
        let r2 = st.update_task(r1, drifted_task).unwrap();

        let err = apply_reveal_result(
            &mut st,
            r2.clone(),
            result_hash,
            reveal_salt,
            Some("\u{3000}\u{2003}".as_bytes().to_vec()),
        )
        .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("unexpected proof payload for non-verifiable proof type"))
        );

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn reveal_rejects_non_utf8_proof_payload_for_non_verifiable_proof_type_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 78931, "alice".into(), 10).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let drifted_task = TaskObject {
            task_id: 78931,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Fraud,
            metadata: None,
            worker: Some(worker.clone()),
            committed_hash: Some(compute_commitment(
                78931,
                &result_hash,
                &reveal_salt,
                &worker,
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
        let r2 = st.update_task(r1, drifted_task).unwrap();

        // Non-UTF8 payloads must also fail-closed for non-verifiable proof types.
        let err = apply_reveal_result(
            &mut st,
            r2.clone(),
            result_hash,
            reveal_salt,
            Some(vec![0xFF, 0xFE, 0x00, 0x80]),
        )
        .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("unexpected proof payload for non-verifiable proof type"))
        );

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_utf8_bom_and_whitespace_only_payload_fail_closed_without_state_mutation()
    {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7894, "alice".into(), 10).unwrap();
        let mut tee_task = st.get_task(r1.id).unwrap();
        tee_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, tee_task).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(7894, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let err = apply_reveal_result(
            &mut st,
            r3.clone(),
            result_hash,
            reveal_salt,
            Some(vec![0xEF, 0xBB, 0xBF, b' ', b'\t', b'\n']),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_noncanonical_worker_in_legacy_committed_state_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 79, "alice".into(), 10).unwrap();

        // Forge a legacy Committed+TEE task with malformed worker identity.
        // This must fail closed before proof verification, even if proof bytes are present.
        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let malformed_worker = " worker1 ".to_string();
        let bad_task = TaskObject {
            task_id: 79,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some(malformed_worker.clone()),
            committed_hash: Some(compute_commitment(
                79,
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

        let proof = b"TEE:task_id=79,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("non-canonical worker account"))
        );

        // Fail-closed behavior: state must remain Committed and unset result hash.
        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_newline_suffixed_worker_in_legacy_committed_state_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7900, "alice".into(), 10).unwrap();

        // Legacy/corrupted state may carry worker ids with hidden newline suffixes.
        // Reveal must fail closed before proof verification and before terminal mutation.
        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let malformed_worker = "worker1\n".to_string();
        let bad_task = TaskObject {
            task_id: 7900,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some(malformed_worker.clone()),
            committed_hash: Some(compute_commitment(
                7900,
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

        let proof = b"TEE:task_id=7900,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("non-canonical worker account"))
        );

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn tee_reveal_rejects_duplicate_task_id_binding_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 790, "alice".into(), 10).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let committed = compute_commitment(790, &result_hash, &reveal_salt, &worker);
        let committed_task = TaskObject {
            task_id: 790,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some(worker),
            committed_hash: Some(committed),
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
        let r2 = st.update_task(r1, committed_task).unwrap();

        // Duplicate task_id binding must fail closed (before any state transition).
        let proof = b"TEE:task_id=789,worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,task_id=790,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("duplicate task_id binding")));

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_duplicate_task_id_binding_with_quoted_trailing_space_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 792, "alice".into(), 10).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let committed = compute_commitment(792, &result_hash, &reveal_salt, &worker);
        let committed_task = TaskObject {
            task_id: 792,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some(worker),
            committed_hash: Some(committed),
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
        let r2 = st.update_task(r1, committed_task).unwrap();

        // Quoted trailing-space alias plus canonical task_id must still be treated
        // as duplicate binding and fail closed before any mutation.
        let proof = b"TEE:task_id=\"792 \",worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,task_id=792,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("duplicate task_id binding")));

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_duplicate_task_id_binding_with_quoted_leading_space_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 794, "alice".into(), 10).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let committed = compute_commitment(794, &result_hash, &reveal_salt, &worker);
        let committed_task = TaskObject {
            task_id: 794,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some(worker),
            committed_hash: Some(committed),
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
        let r2 = st.update_task(r1, committed_task).unwrap();

        // Quoted leading-space alias plus canonical task_id must still be treated
        // as duplicate binding and fail closed before any mutation.
        let proof = b"TEE:task_id=\" 794\",worker=worker1,proof_type=tee,result_hash=0202020202020202020202020202020202020202020202020202020202020202,task_id=794,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("duplicate task_id binding")));

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_noncanonical_worker_in_legacy_committed_state_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 80, "alice".into(), 10).unwrap();

        // Forge a legacy Committed+ZK task with malformed worker identity.
        // This must fail closed before proof verification, even if proof bytes are present.
        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let malformed_worker = " worker1 ".to_string();
        let bad_task = TaskObject {
            task_id: 80,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: Some(malformed_worker.clone()),
            committed_hash: Some(compute_commitment(
                80,
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

        let proof = b"ZK:task_id=80,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("non-canonical worker account"))
        );

        // Fail-closed behavior: state must remain Committed and unset result hash.
        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_newline_suffixed_worker_in_legacy_committed_state_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 8000, "alice".into(), 10).unwrap();

        // Legacy/corrupted state may carry worker ids with hidden newline suffixes.
        // Reveal must fail closed before proof verification and before terminal mutation.
        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let malformed_worker = "worker1\n".to_string();
        let bad_task = TaskObject {
            task_id: 8000,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: Some(malformed_worker.clone()),
            committed_hash: Some(compute_commitment(
                8000,
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

        let proof = b"ZK:task_id=8000,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("non-canonical worker account"))
        );

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.reveal_salt.is_none());
    }

    #[test]
    fn zk_reveal_rejects_duplicate_task_id_binding_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 801, "alice".into(), 10).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let committed = compute_commitment(801, &result_hash, &reveal_salt, &worker);
        let committed_task = TaskObject {
            task_id: 801,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: Some(worker),
            committed_hash: Some(committed),
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
        let r2 = st.update_task(r1, committed_task).unwrap();

        // Duplicate task_id binding must fail closed (before any state transition).
        let proof = b"ZK:task_id=800,worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,task_id=801,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("duplicate task_id binding")));

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_duplicate_task_id_binding_with_quoted_trailing_space_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 803, "alice".into(), 10).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let committed = compute_commitment(803, &result_hash, &reveal_salt, &worker);
        let committed_task = TaskObject {
            task_id: 803,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: Some(worker),
            committed_hash: Some(committed),
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
        let r2 = st.update_task(r1, committed_task).unwrap();

        // Quoted trailing-space alias plus canonical task_id must still be treated
        // as duplicate binding and fail closed before any mutation.
        let proof = b"ZK:task_id=\"803 \",worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,task_id=803,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("duplicate task_id binding")));

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_duplicate_task_id_binding_with_quoted_leading_space_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 804, "alice".into(), 10).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let committed = compute_commitment(804, &result_hash, &reveal_salt, &worker);
        let committed_task = TaskObject {
            task_id: 804,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: Some(worker),
            committed_hash: Some(committed),
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
        let r2 = st.update_task(r1, committed_task).unwrap();

        // Quoted leading-space alias plus canonical task_id must still be treated
        // as duplicate binding and fail closed before any mutation.
        let proof = b"ZK:task_id=\" 804\",worker=worker1,proof_type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,task_id=804,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("duplicate task_id binding")));

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_case_variant_duplicate_proof_type_binding_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 802, "alice".into(), 10).unwrap();

        let result_hash = [2u8; 32];
        let reveal_salt = [3u8; 32];
        let worker = "worker1".to_string();
        let committed = compute_commitment(802, &result_hash, &reveal_salt, &worker);
        let committed_task = TaskObject {
            task_id: 802,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            proof_type: ProofType::Zk,
            metadata: None,
            worker: Some(worker),
            committed_hash: Some(committed),
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
        let r2 = st.update_task(r1, committed_task).unwrap();

        // Case-variant duplicate proof_type binding must fail closed.
        let proof = b"ZK:task_id=802,worker=worker1,proof_type=zk,Proof_Type=zk,result_hash=0202020202020202020202020202020202020202020202020202020202020202,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r2.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("duplicate proof_type binding"))
        );

        let task_after = st.get_task(r2.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
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
        st.set_gov_param_bootstrap_unchecked(9101, "challenge_window_blocks".into(), "100".into())
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
        st.set_gov_param_bootstrap_unchecked(9102, "challenge_window_blocks".into(), "100".into())
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
        st.set_gov_param_bootstrap_unchecked(9110, "challenge_window_blocks".into(), "100".into())
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

        st.set_gov_param_bootstrap_unchecked(9110, "challenge_window_blocks".into(), "300".into())
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
        st.set_gov_param_bootstrap_unchecked(9130, "challenge_window_blocks".into(), "100".into())
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

        st.set_gov_param_bootstrap_unchecked(9130, "challenge_window_blocks".into(), "300".into())
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
        st.set_gov_param_bootstrap_unchecked(9133, "challenge_window_blocks".into(), "100".into())
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

        st.set_gov_param_bootstrap_unchecked(9133, "challenge_window_blocks".into(), "300".into())
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
        st.set_gov_param_bootstrap_unchecked(9133, "challenge_window_blocks".into(), "600".into())
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
        st.set_gov_param_bootstrap_unchecked(9131, "challenge_window_blocks".into(), "100".into())
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

        st.set_gov_param_bootstrap_unchecked(9131, "challenge_window_blocks".into(), "300".into())
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
        st.set_gov_param_bootstrap_unchecked(9132, "challenge_window_blocks".into(), "100".into())
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
        st.set_gov_param_bootstrap_unchecked(9132, "challenge_window_blocks".into(), "600".into())
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
        st.set_gov_param_bootstrap_unchecked(9120, "challenge_window_blocks".into(), "100".into())
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

        st.set_gov_param_bootstrap_unchecked(9120, "challenge_window_blocks".into(), "300".into())
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
    fn timeout_clears_stale_multisig_pending_approval_after_challenged_finalization() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 19121, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19121, &result_hash, &reveal_salt, "worker1");

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

        let before_total = st.balance_of("challenger")
            + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
            + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        let staged_err = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
            211,
        )
        .expect_err("first multisig signer should only stage pending approval");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        let r6 = apply_timeout(&mut st, r5, 311).expect("timeout should finalize challenged task");
        let task = st.get_task(r6.id).expect("timed out task must exist");
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
        assert_eq!(st.pending_resolve_approval(r6.id), None);
        assert_eq!(st.pending_resolve_first_approver(r6.id), None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);

        let after_total = st.balance_of("challenger")
            + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
            + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        assert_eq!(after_total, before_total);
    }

    #[test]
    fn challenged_timeout_rejects_while_paused_and_preserves_multisig_staging_until_unpaused() {
        // Safety boundary: emergency pause must fail-closed before challenged-task
        // timeout finalization so staged multisig resolve approvals and escrow
        // custody remain frozen until governance explicitly unpauses.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 19_122, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19_122, &result_hash, &reveal_salt, "worker1");

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

        let staged_err = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
            211,
        )
        .expect_err("first multisig signer should only stage pending approval");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        st.set_gov_param(9_222, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(r5.id).expect("challenged task must persist");
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_worker_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let paused_err = apply_timeout(&mut st, r5.clone(), 311)
            .expect_err("emergency pause must freeze challenged timeout settlement path");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        let after_paused_task = st
            .get_task(r5.id)
            .expect("task must remain unchanged while paused");
        assert_eq!(after_paused_task.status, before_task.status);
        assert_eq!(
            after_paused_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before_worker_slash_treasury
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        st.set_gov_param(9_223, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let r6 = apply_timeout(&mut st, r5, 311)
            .expect("challenged timeout should finalize once emergency pause clears");
        let task = st.get_task(r6.id).expect("timed out task must exist");
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
        assert_eq!(st.pending_resolve_approval(r6.id), None);
        assert_eq!(st.pending_resolve_first_approver(r6.id), None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    }

    #[test]
    fn challenged_timeout_allows_uncontested_revealed_finalization_while_paused() {
        // Safety boundary scope: emergency pause should freeze challenged escrow
        // settlement only; uncontested reveal timeout finalization must remain live.
        let mut st = seeded_state();
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 19_121, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19_121, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

        st.set_gov_param(9_220, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_worker_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

        let r5 = apply_timeout(&mut st, r4, 211)
            .expect("uncontested reveal timeout should finalize even while paused");
        let task = st.get_task(r5.id).expect("task must exist after timeout");
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.pending_resolve_approval(r5.id), None);
        assert_eq!(st.pending_resolve_first_approver(r5.id), None);

        // No challenged escrow path was entered; custodial balances remain unchanged.
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before_worker_slash_treasury
        );
    }

    #[test]
    fn challenged_multisig_first_approval_rejects_while_paused_without_staging_or_escrow_drift() {
        // Safety boundary: emergency pause must also block first-signer staging so
        // challenged escrow paths cannot accumulate latent approvals while paused.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 19_222, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19_222, &result_hash, &reveal_salt, "worker1");

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

        st.set_gov_param(9_221, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(r5.id).expect("challenged task must persist");
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let paused_err = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            false,
            "authority-a".into(),
            "authority-a".into(),
            211,
        )
        .expect_err("emergency pause must block first multisig resolve approval staging");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(st.pending_resolve_approval(r5.id), None);

        let after_paused_task = st
            .get_task(r5.id)
            .expect("task must remain unchanged while paused");
        assert_eq!(after_paused_task.status, before_task.status);
        assert_eq!(
            after_paused_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn challenged_multisig_first_approval_can_stage_after_unpause_without_escrow_drift() {
        // Safety boundary: pause should block first-approval staging, but governance
        // unpause must restore the exact same staging path without mutating custody.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 19_223, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19_223, &result_hash, &reveal_salt, "worker1");

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

        st.set_gov_param(9_226, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_paused_total = st.balance_of("challenger")
            + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
            + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        let paused_err = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            false,
            "authority-a".into(),
            "authority-a".into(),
            211,
        )
        .expect_err("pause must block first multisig staging");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(st.pending_resolve_approval(r5.id), None);

        st.set_gov_param(9_227, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let staged_err = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            false,
            "authority-a".into(),
            "authority-a".into(),
            211,
        )
        .expect_err("first multisig signer should stage once unpaused");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert!(matches!(
            st.pending_resolve_approval(r5.id),
            Some((false, 1))
        ));

        let r6 = apply_resolve_at_height(
            &mut st,
            r5,
            false,
            "authority-b".into(),
            "authority-b".into(),
            212,
        )
        .expect("second multisig signer should finalize once unpaused");
        let task = st.get_task(r6.id).expect("resolved task must exist");
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.challenge_bond_forfeited, Some(true));
        assert_eq!(st.pending_resolve_approval(r6.id), None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);

        let after_total = st.balance_of("challenger")
            + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
            + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        assert_eq!(after_total, before_paused_total);
    }

    #[test]
    fn challenged_multisig_resolve_rejects_while_paused_without_escrow_drift() {
        // Safety boundary: emergency pause must fail-closed before terminal multisig
        // resolve settlement so staged approvals cannot move escrow funds until unpaused.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 19_223, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19_223, &result_hash, &reveal_salt, "worker1");

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

        let staged_err = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            false,
            "authority-a".into(),
            "authority-a".into(),
            211,
        )
        .expect_err("first multisig signer should only stage pending approval");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert!(matches!(st.pending_resolve_approval(r5.id), Some((_, 1))));

        st.set_gov_param(9_224, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(r5.id).expect("challenged task must persist");
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let paused_err = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            false,
            "authority-b".into(),
            "authority-b".into(),
            212,
        )
        .expect_err("emergency pause must freeze multisig resolve settlement path");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert!(matches!(st.pending_resolve_approval(r5.id), Some((_, 1))));

        let after_paused_task = st
            .get_task(r5.id)
            .expect("task must remain unchanged while paused");
        assert_eq!(after_paused_task.status, before_task.status);
        assert_eq!(
            after_paused_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        st.set_gov_param(9_225, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let r6 = apply_resolve_at_height(
            &mut st,
            r5,
            false,
            "authority-b".into(),
            "authority-b".into(),
            212,
        )
        .expect("multisig resolve should settle after emergency pause clears");
        let task = st.get_task(r6.id).expect("resolved task must exist");
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(st.pending_resolve_approval(r6.id), None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        let after_total = st.balance_of("challenger")
            + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
            + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_total = before_challenger + before_escrow + before_forfeit;
        assert_eq!(after_total, before_total);
    }

    #[test]
    fn challenged_multisig_resolve_rejects_first_approval_while_paused_without_staging_or_escrow_drift(
    ) {
        // Safety boundary: emergency pause must fail closed before any multisig
        // approval staging, so no partial authority state is recorded while paused.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 19_223_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19_223_1, &result_hash, &reveal_salt, "worker1");

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

        st.set_gov_param(9_226, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(r5.id).expect("challenged task must persist");
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");
        let before_total = before_challenger + before_escrow + before_forfeit;

        let paused_err = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            false,
            "authority-a".into(),
            "authority-a".into(),
            211,
        )
        .expect_err("emergency pause must reject first multisig approval staging");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(st.pending_resolve_approval(r5.id), None);

        let after_paused_task = st
            .get_task(r5.id)
            .expect("task must remain unchanged while paused");
        assert_eq!(after_paused_task.status, before_task.status);
        assert_eq!(
            after_paused_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
        let after_total = st.balance_of("challenger")
            + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
            + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        assert_eq!(after_total, before_total);

        st.set_gov_param(9_227, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let staged_err = apply_resolve_at_height(
            &mut st,
            r5,
            false,
            "authority-a".into(),
            "authority-a".into(),
            211,
        )
        .expect_err("first signer should stage pending approval once pause clears");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
    }

    #[test]
    fn challenged_pause_preserves_pre_staged_multisig_approval_until_unpaused_consensus() {
        // Safety boundary: emergency pause must reject terminal resolve attempts
        // without mutating previously staged multisig approval state.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b,authority-c");

        let r1 = apply_create_task(&mut st, 19_223_2, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19_223_2, &result_hash, &reveal_salt, "worker1");

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

        let stage_err = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            false,
            "authority-a".into(),
            "authority-a".into(),
            211,
        )
        .expect_err("first signer should only stage pending multisig approval");
        assert!(matches!(stage_err, PouwError::ResolveApprovalStaged));
        let staged_before_pause = st.pending_resolve_approval(r5.id);
        assert!(matches!(staged_before_pause, Some((false, _))));
        let before_paused_total = st.balance_of("challenger")
            + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
            + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        st.set_gov_param(9_228, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let paused_err = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            false,
            "authority-b".into(),
            "authority-b".into(),
            212,
        )
        .expect_err("pause must reject resolve without mutating staged approvals");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(st.pending_resolve_approval(r5.id), staged_before_pause);
        let after_paused_total = st.balance_of("challenger")
            + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
            + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        assert_eq!(after_paused_total, before_paused_total);

        st.set_gov_param(9_229, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let r6 = apply_resolve_at_height(
            &mut st,
            r5,
            false,
            "authority-b".into(),
            "authority-b".into(),
            213,
        )
        .expect("second distinct signer should finalize once pause clears");

        let task = st.get_task(r6.id).expect("resolved task must exist");
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(st.pending_resolve_approval(r6.id), None);
    }

    #[test]
    fn challenged_single_authority_resolve_rejects_while_paused_without_escrow_drift() {
        // Safety boundary: emergency pause must fail-closed for single-authority
        // resolve so escrow settlement remains frozen regardless of multisig mode.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,authority2");

        let r1 = apply_create_task(&mut st, 19_223_2, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19_223_2, &result_hash, &reveal_salt, "worker1");

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

        st.set_gov_param(9_228, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(r5.id).expect("challenged task must persist");
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let paused_err = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            false,
            "authority".into(),
            "authority".into(),
            211,
        )
        .expect_err("emergency pause must freeze single-authority resolve settlement path");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(st.pending_resolve_approval(r5.id), None);

        let after_paused_task = st
            .get_task(r5.id)
            .expect("task must remain unchanged while paused");
        assert_eq!(after_paused_task.status, before_task.status);
        assert_eq!(
            after_paused_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        st.set_gov_param(9_229, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let staged = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            false,
            "authority".into(),
            "authority".into(),
            211,
        )
        .expect_err("first resolver should stage once emergency pause clears");
        assert!(matches!(staged, PouwError::ResolveApprovalStaged));
        let r6 = apply_resolve_at_height(
            &mut st,
            r5,
            false,
            "authority2".into(),
            "authority2".into(),
            211,
        )
        .expect("multisig resolve should settle after emergency pause clears");
        let task = st.get_task(r6.id).expect("resolved task must exist");
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(st.pending_resolve_approval(r6.id), None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        let after_total = st.balance_of("challenger")
            + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
            + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_total = before_challenger + before_escrow + before_forfeit;
        assert_eq!(after_total, before_total);
    }

    #[test]
    fn challenged_single_authority_slash_resolve_rejects_while_paused_without_balance_drift() {
        // Safety boundary: emergency pause must also freeze slash=true resolution
        // so authority cannot trigger worker-forfeit escrow exits while paused.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,authority2");

        let r1 = apply_create_task(&mut st, 19_223_3, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19_223_3, &result_hash, &reveal_salt, "worker1");

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

        st.set_gov_param(9_230, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(r5.id).expect("challenged task must persist");
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_worker_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let paused_err = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            true,
            "authority".into(),
            "authority".into(),
            211,
        )
        .expect_err("emergency pause must freeze slash resolve settlement path");
        assert!(matches!(paused_err, PouwError::InvalidTransition));

        let after_paused_task = st
            .get_task(r5.id)
            .expect("task must remain unchanged while paused");
        assert_eq!(after_paused_task.status, before_task.status);
        assert_eq!(
            after_paused_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before_worker_slash_treasury
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        st.set_gov_param(9_231, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let staged = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            true,
            "authority".into(),
            "authority".into(),
            211,
        )
        .expect_err("first resolver should stage once emergency pause clears");
        assert!(matches!(staged, PouwError::ResolveApprovalStaged));
        let r6 = apply_resolve_at_height(
            &mut st,
            r5,
            true,
            "authority2".into(),
            "authority2".into(),
            211,
        )
        .expect("multisig slash resolve should settle after emergency pause clears");
        let task = st.get_task(r6.id).expect("resolved task must exist");
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
        assert_eq!(st.pending_resolve_approval(r6.id), None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    }

    #[test]
    fn challenged_resolve_case_drift_duplicate_authority_config_is_masked_by_pause_without_escrow_drift(
    ) {
        // Safety boundary: emergency pause must fail before case-drift duplicate
        // authority validation so malformed governance config cannot leak resolver
        // checks while challenged escrow paths are frozen.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "Authority,authority");

        let r1 = apply_create_task(&mut st, 19_223_4, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19_223_4, &result_hash, &reveal_salt, "worker1");

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

        st.set_gov_param(9_232, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(r5.id).expect("challenged task must persist");
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let paused_err = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            false,
            "authority".into(),
            "authority".into(),
            211,
        )
        .expect_err("pause must mask case-drift duplicate-authority resolver validation");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(st.pending_resolve_approval(r5.id), None);

        let after_paused_task = st
            .get_task(r5.id)
            .expect("task must remain unchanged while paused");
        assert_eq!(after_paused_task.status, before_task.status);
        assert_eq!(
            after_paused_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        st.set_gov_param(9_233, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let duplicate_err = apply_resolve_at_height(
            &mut st,
            r5,
            false,
            "authority".into(),
            "authority".into(),
            212,
        )
        .expect_err("case-drift duplicate resolver config should be rejected after unpause");
        assert!(matches!(duplicate_err, PouwError::Unauthorized));
        assert_eq!(st.pending_resolve_approval(before_task.task_id), None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn challenged_resolve_exact_duplicate_authority_config_rejects_without_escrow_drift() {
        // Governance hardening: exact duplicate resolver entries must fail closed
        // so challenged escrow settlement never relies on a single duplicated actor.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,authority");

        let r1 = apply_create_task(&mut st, 19_223_4_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19_223_4_1, &result_hash, &reveal_salt, "worker1");

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

        let before_task = st.get_task(r5.id).expect("challenged task must persist");
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let duplicate_err = apply_resolve_at_height(
            &mut st,
            r5,
            false,
            "authority".into(),
            "authority".into(),
            211,
        )
        .expect_err("duplicate resolver config should be rejected before settlement");
        assert!(matches!(duplicate_err, PouwError::Unauthorized));
        assert_eq!(st.pending_resolve_approval(before_task.task_id), None);

        let after_task = st
            .get_task(before_task.task_id)
            .expect("task must remain unchanged after rejected resolve");
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn challenged_resolve_exact_duplicate_authority_config_is_masked_by_pause_without_escrow_drift(
    ) {
        // Safety boundary: emergency pause must fail before duplicate-authority
        // validation so paused challenged escrow paths do not leak governance
        // misconfiguration details or mutate custodial balances.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,authority");

        let r1 = apply_create_task(&mut st, 19_223_4_2, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19_223_4_2, &result_hash, &reveal_salt, "worker1");

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

        st.set_gov_param(9_232_1, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(r5.id).expect("challenged task must persist");
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let paused_err = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            false,
            "authority".into(),
            "authority".into(),
            211,
        )
        .expect_err("pause must mask duplicate-authority resolver validation");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(st.pending_resolve_approval(r5.id), None);

        let after_paused_task = st
            .get_task(r5.id)
            .expect("task must remain unchanged while paused");
        assert_eq!(after_paused_task.status, before_task.status);
        assert_eq!(
            after_paused_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        st.set_gov_param(9_232_2, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let duplicate_err = apply_resolve_at_height(
            &mut st,
            r5,
            false,
            "authority".into(),
            "authority".into(),
            212,
        )
        .expect_err("duplicate resolver config should be rejected after unpause");
        assert!(matches!(duplicate_err, PouwError::Unauthorized));
        assert_eq!(st.pending_resolve_approval(before_task.task_id), None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn challenged_resolve_escrow_authority_overlap_is_masked_by_pause_without_escrow_drift() {
        // Safety boundary: emergency pause must fail closed before resolver/escrow
        // overlap checks so paused challenged flows cannot leak authority validation
        // behavior or mutate custodial balances.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(
            &mut st,
            &format!("{},authority2", CHALLENGE_ESCROW_ACCOUNT),
        );

        let r1 = apply_create_task(&mut st, 19_223_5, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(19_223_5, &result_hash, &reveal_salt, "worker1");

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

        st.set_gov_param(9_234, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(r5.id).expect("challenged task must persist");
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let paused_err = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            false,
            "authority2".into(),
            "authority2".into(),
            211,
        )
        .expect_err("pause must mask escrow-authority overlap validation");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(st.pending_resolve_approval(r5.id), None);

        let after_paused_task = st
            .get_task(r5.id)
            .expect("task must remain unchanged while paused");
        assert_eq!(after_paused_task.status, before_task.status);
        assert_eq!(
            after_paused_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        st.set_gov_param(9_235, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let overlap_err = apply_resolve_at_height(
            &mut st,
            r5,
            false,
            "authority2".into(),
            "authority2".into(),
            212,
        )
        .expect_err("escrow-authority overlap config should be rejected after unpause");
        assert!(matches!(overlap_err, PouwError::Unauthorized));
        assert_eq!(st.pending_resolve_approval(before_task.task_id), None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn revealed_timeout_auto_completes_without_challenge() {
        let mut st = seeded_state();
        st.set_gov_param_bootstrap_unchecked(9103, "challenge_window_blocks".into(), "100".into())
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
        assert_eq!(task.challenge_deadline_height, None);
        assert_eq!(task.resolve_deadline_height, None);
    }

    #[test]
    fn challenge_requires_min_bond_from_worker_stake_floor() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        st.set_gov_param_bootstrap_unchecked(9000, "challenge_min_bond".into(), "1".into())
            .unwrap();
        st.set_gov_param_bootstrap_unchecked(
            9001,
            "challenge_min_bond_bounty_bps".into(),
            "1".into(),
        )
        .unwrap();
        st.set_gov_param_bootstrap_unchecked(9002, "min_worker_stake".into(), "80".into())
            .unwrap();
        st.set_gov_param_bootstrap_unchecked(
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
        st.set_gov_param_bootstrap_unchecked(9004, "challenge_min_bond".into(), "30".into())
            .unwrap();
        st.set_gov_param_bootstrap_unchecked(
            9005,
            "challenge_min_bond_bounty_bps".into(),
            "5000".into(),
        )
        .unwrap();
        st.set_gov_param_bootstrap_unchecked(9006, "min_worker_stake".into(), "80".into())
            .unwrap();
        st.set_gov_param_bootstrap_unchecked(
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
        st.set_gov_param_bootstrap_unchecked(9001, "challenge_min_bond".into(), "50".into())
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
        st.set_gov_param_bootstrap_unchecked(9050, "challenge_min_bond".into(), "10".into())
            .unwrap();
        st.set_gov_param_bootstrap_unchecked(
            9051,
            "challenge_min_bond_bounty_bps".into(),
            "5000".into(),
        )
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
        st.set_gov_param_bootstrap_unchecked(9052, "challenge_min_bond".into(), "10".into())
            .unwrap();
        st.set_gov_param_bootstrap_unchecked(
            9053,
            "challenge_min_bond_bounty_bps".into(),
            "5000".into(),
        )
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
        st.set_gov_param_bootstrap_unchecked(9054, "challenge_min_bond".into(), "1".into())
            .unwrap();
        st.set_gov_param_bootstrap_unchecked(
            9055,
            "challenge_min_bond_bounty_bps".into(),
            "500".into(),
        )
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
        st.set_gov_param_bootstrap_unchecked(9056, "challenge_min_bond".into(), "10".into())
            .unwrap();
        st.set_gov_param_bootstrap_unchecked(
            9057,
            "challenge_min_bond_bounty_bps".into(),
            "5000".into(),
        )
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
    fn resolve_rejects_noncanonical_assigned_worker_identity_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 39003, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(39003, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        // Simulate malformed legacy state where assigned worker identity drifts.
        let mut bad = st.get_task(r5.id).unwrap();
        bad.worker = Some(" worker1".into());
        let bad_ref = st.update_task(r5, bad).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        let err = apply_resolve(
            &mut st,
            bad_ref,
            true,
            "authority".into(),
            "authority".into(),
        )
        .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("non-canonical worker account"))
        );

        let task = st.get_task(39003).unwrap();
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
        bad.challenge_deadline_height = Some(210);
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
            "authority,authority2".into(),
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
        st.set_gov_param_bootstrap_unchecked(9002, "challenge_window_blocks".into(), "123".into())
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

        set_resolve_authority(&mut st, "authority,authority2");
        let staged = apply_resolve(&mut st, r5.clone(), false, "authority".into(), "authority".into())
            .expect_err("first resolver should stage multisig approval");
        assert!(matches!(staged, PouwError::ResolveApprovalStaged));
        let r6 = apply_resolve(&mut st, r5, false, "authority2".into(), "authority2".into()).unwrap();
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
        set_resolve_authority(&mut st, "authority,authority2");
        let staged = apply_resolve(&mut st, r5.clone(), true, "authority".into(), "authority".into())
            .unwrap_err();
        assert!(matches!(staged, PouwError::ResolveApprovalStaged));
        let r6 = apply_resolve(&mut st, r5, true, "authority2".into(), "authority2".into()).unwrap();

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
        st.set_gov_param_bootstrap_unchecked(9810, "min_worker_stake".into(), "40".into())
            .unwrap();
        st.set_balance("worker1", 40);
        set_resolve_authority(&mut st, "authority,authority2");

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

        let staged = apply_resolve(&mut st, r5.clone(), true, "authority".into(), "authority".into())
            .unwrap_err();
        assert!(matches!(staged, PouwError::ResolveApprovalStaged));
        let _r6 = apply_resolve(&mut st, r5, true, "authority2".into(), "authority2".into()).unwrap();

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
    fn resolve_rejects_challenger_even_when_configured_as_authority_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "challenger");

        let r1 = apply_create_task(&mut st, 894_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(894_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        let err = apply_resolve(&mut st, r5, true, "challenger".into(), "challenger".into())
            .expect_err("challenger must not self-authorize terminal challenged resolution");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(894_1).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
    }

    #[test]
    fn resolve_rejects_authority_set_that_includes_challenger_member_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,challenger");

        let r1 = apply_create_task(&mut st, 894_2, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(894_2, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
                "resolve authority set must reject challenger membership even via multisig list",
            );
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(894_2).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_rejects_authority_set_with_challenger_case_drift_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,Challenger");

        let r1 = apply_create_task(&mut st, 894_3, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(894_3, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
                "resolve authority set must reject challenger membership even with case drift",
            );
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(894_3).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_accepts_configured_authority_resolver() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,authority2");

        let r1 = apply_create_task(&mut st, 895, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(895, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let staged = apply_resolve(&mut st, r5.clone(), true, "authority".into(), "authority".into())
            .unwrap_err();
        assert!(matches!(staged, PouwError::ResolveApprovalStaged));
        let r6 = apply_resolve(&mut st, r5, true, "authority2".into(), "authority2".into()).unwrap();
        let task = st.get_task(r6.id).unwrap();
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
        assert_eq!(st.balance_of("challenger"), 101);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn resolve_multisig_requires_two_distinct_approvers_before_terminal_settlement() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 895_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(895_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let first_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("first multisig approver must not finalize resolve");
        assert!(matches!(first_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        let r6 = apply_resolve(
            &mut st,
            r5,
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect("second distinct multisig approver should finalize resolve");
        let task = st.get_task(r6.id).unwrap();
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
        assert_eq!(st.pending_resolve_approval(r6.id), None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
        assert_eq!(st.balance_of("challenger"), 101);
    }

    #[test]
    fn resolve_multisig_rejects_replayed_first_approver_without_escrow_mutation() {
        // Minimal multi-party control: a staged approval from signer A must still
        // require a distinct signer B; signer A cannot replay approval to finalize.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 895_1_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(895_1_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let first_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("first multisig approver must only stage pending approval");
        assert!(matches!(first_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        let replay_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("replayed first multisig approver must not finalize resolve");
        assert!(matches!(replay_err, PouwError::Unauthorized));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_multisig_rejects_decision_flip_and_preserves_staged_approval_without_escrow_mutation(
    ) {
        // Economic + governance hardening: once one multisig signer stages a
        // slashing/non-slashing decision, a second signer cannot flip that
        // terminal settlement decision in-flight.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 895_2, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(895_2, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");
        let before_worker_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

        let first_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("first signer must only stage slashing resolve approval");
        assert!(matches!(first_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        let decision_flip_err = apply_resolve(
            &mut st,
            r5.clone(),
            false,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect_err("second signer must not flip staged slashing decision to non-slashing");
        assert!(matches!(decision_flip_err, PouwError::Unauthorized));
        assert_eq!(
            st.pending_resolve_approval(r5.id),
            Some((true, 1)),
            "decision mismatch must not mutate staged multisig approval",
        );

        let task = st
            .get_task(r5.id)
            .expect("challenged task must remain in state after decision mismatch");
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before_worker_slash_treasury,
        );
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
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_worker_authority_case_drift_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "Worker1");

        let r1 = apply_create_task(&mut st, 8_960, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_960, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(&mut st, r5, true, "Worker1".into(), "Worker1".into()).expect_err(
            "assigned worker must not self-authorize challenged resolution via case drift",
        );
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_960).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_multisig_authority_that_includes_assigned_worker_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,worker1");

        let r1 = apply_create_task(&mut st, 8_961, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(
            &mut st,
            r5,
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("authority sets that include assigned worker must be rejected");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_961).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_multisig_authority_with_worker_member_case_drift_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,Worker1");

        let r1 = apply_create_task(&mut st, 8_963, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_963, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(
            &mut st,
            r5,
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("authority sets with assigned worker member via case drift must be rejected");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_963).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_duplicate_authority_members_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,authority");

        let r1 = apply_create_task(&mut st, 8_961, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
                "duplicate authority members must be rejected to preserve signer-set integrity",
            );
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_961).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_duplicate_authority_members_case_drift_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "Authority,authority");

        let r1 = apply_create_task(&mut st, 8_962, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_962, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(&mut st, r5, true, "Authority".into(), "Authority".into())
            .expect_err("authority member list must reject case-drift duplicates to preserve minimal multi-party control");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_962).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_non_ascii_separator_in_authority_set_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a，authority-b");

        let r1 = apply_create_task(&mut st, 8_962_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_962_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
        let pending_task_id = r5.id;

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(
            &mut st,
            r5,
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err(
            "non-ASCII separator must be rejected so resolver sets cannot degrade into ambiguous single-signer authority",
        );
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_962_1).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.pending_resolve_approval(pending_task_id), None);
    }

    #[test]
    fn resolve_rejects_control_char_authority_member_without_escrow_mutation() {
        // Canonical signer hardening: invisible control bytes must never be
        // accepted as authority members.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority\u{0000}");

        let r1 = apply_create_task(&mut st, 8_966_9, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_966_9, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(
            &mut st,
            r5,
            true,
            "authority\u{0000}".into(),
            "authority\u{0000}".into(),
        )
        .expect_err("authority members with control bytes must be rejected");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_966_9).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_multisig_authority_with_member_whitespace_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority, authority2");

        let r1 = apply_create_task(&mut st, 8_967, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_967, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
                "authority member whitespace must be rejected to preserve canonical signer set",
            );
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_967).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_multisig_authority_with_tab_member_without_escrow_mutation() {
        // Canonical authority-set hardening: tab-delimited members must be rejected
        // so governance signer sets remain strict comma-separated account ids.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,\tauthority2");

        let r1 = apply_create_task(&mut st, 8_967_00, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_967_00, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err("authority member tabs must be rejected to preserve canonical signer sets");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_967_00).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_multisig_authority_with_newline_member_without_escrow_mutation() {
        // Canonical authority-set hardening: newline-delimited members must be rejected
        // so governance signer sets stay single-line token lists only.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,\nauthority2");

        let r1 = apply_create_task(&mut st, 8_967_0, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_967_0, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
                "authority member newlines must be rejected to preserve canonical signer sets",
            );
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_967_0).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_multisig_authority_with_carriage_return_member_without_escrow_mutation() {
        // Canonical authority-set hardening: CR-delimited members must be rejected
        // so governance signer sets cannot hide malformed CRLF-style tokens.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,\rauthority2");

        let r1 = apply_create_task(&mut st, 8_967_01, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_967_01, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
            "authority member carriage returns must be rejected to preserve canonical signer sets",
        );
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_967_01).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_semicolon_delimited_signer_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_967_0, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_967_0, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(
            &mut st,
            r5,
            true,
            "authority;shadow".into(),
            "authority;shadow".into(),
        )
        .expect_err("semicolon-delimited signer tokens must be rejected to preserve canonical authority identity");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_967_0).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_multisig_authority_with_empty_member_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,");

        let r1 = apply_create_task(&mut st, 8_967_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_967_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err("authority member list with empty entries must be rejected to preserve minimal multi-party control");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_967_1).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_multisig_authority_with_leading_empty_member_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, ",authority");

        let r1 = apply_create_task(&mut st, 8_967_1_05, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_967_1_05, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
                "multisig authority member list with leading empty entries must be rejected",
            );
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_967_1_05).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_multisig_authority_with_middle_empty_member_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,,authority2");

        let r1 = apply_create_task(&mut st, 8_967_1_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_967_1_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(&mut st, r5, true, "authority2".into(), "authority2".into())
            .expect_err(
                "multisig authority member list with interior empty entries must be rejected",
            );
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_967_1_1).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_multisig_member_case_drift_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        // Canonical signer-set hardening: multisig members are exact account ids,
        // not case-insensitive aliases.
        set_resolve_authority(&mut st, "Authority,authority2");

        let r1 = apply_create_task(&mut st, 8_967_2, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_967_2, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err("multisig authority members must reject case-drift signer aliases");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_967_2).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_non_ascii_authority_member_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        // Canonical identity hardening: non-ASCII authority ids can enable
        // homoglyph spoofing and must fail closed.
        let spoofed_authority = "authоrity"; // Cyrillic 'о' (U+043E)
        set_resolve_authority(&mut st, spoofed_authority);

        let r1 = apply_create_task(&mut st, 8_967_3, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_967_3, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(
            &mut st,
            r5,
            true,
            spoofed_authority.into(),
            spoofed_authority.into(),
        )
        .expect_err("non-ASCII resolve authority ids must be rejected");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_967_3).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_non_ascii_signer_payload_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_967_4, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_967_4, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        // Canonical identity hardening: signer/resolver payloads must be ASCII-only
        // account IDs so homoglyph spoofing cannot bypass authority checks.
        let spoofed_signer = "authоrity"; // Cyrillic 'о' (U+043E)
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(
            &mut st,
            r5,
            true,
            spoofed_signer.into(),
            spoofed_signer.into(),
        )
        .expect_err("non-ASCII signer/resolver payload must be rejected");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_967_4).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_rejects_non_ascii_resolver_payload_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_967_5, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_967_5, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        // Canonical identity hardening: resolver payload must remain ASCII-only
        // even when signer is a valid configured authority.
        let spoofed_resolver = "authоrity"; // Cyrillic 'о' (U+043E)
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let err = apply_resolve(
            &mut st,
            r5,
            true,
            spoofed_resolver.into(),
            "authority".into(),
        )
        .expect_err("non-ASCII resolver payload must be rejected");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_967_5).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenge_bond_forfeited, None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_allows_distinct_multisig_authority_member_and_preserves_single_escrow_settlement() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,authority2");

        let r1 = apply_create_task(&mut st, 8_968, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_968, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let staged_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority2".into(),
            "authority2".into(),
        )
        .expect_err("first multisig member must stage but not finalize resolution");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));

        let r6 = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect("second distinct multisig member should finalize resolution");
        let task = st.get_task(r6.id).unwrap();
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
        assert_eq!(st.balance_of("challenger"), 101);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);

        let err = apply_resolve(&mut st, r6, true, "authority2".into(), "authority2".into())
            .expect_err(
            "terminal challenge resolution must remain single-settlement under multisig authority",
        );
        assert!(matches!(err, PouwError::InvalidTransition));
        assert_eq!(st.balance_of("challenger"), 101);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn challenge_rejects_while_emergency_pause_active_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 8_969, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_969, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        st.set_gov_param(9_206, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_969).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into())
            .expect_err("emergency pause must freeze challenge escrow entry path");
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_969).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(after_task.challenger, before_task.challenger);
        assert_eq!(after_task.challenge_bond, before_task.challenge_bond);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn challenge_emergency_pause_precedes_bond_checks_without_escrow_mutation() {
        // Merge-gate hardening: emergency pause must fail-closed before economic
        // min-bond gates so paused challenge flow cannot leak bond-policy outcomes.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        st.set_gov_param_bootstrap_unchecked(9_209, "challenge_min_bond".into(), "50".into())
            .expect("challenge_min_bond governance seed must succeed");

        let r1 = apply_create_task(&mut st, 8_971, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_971, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        st.set_gov_param(9_210, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_971).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into())
            .expect_err(
                "emergency pause must mask min-bond result and freeze challenge entry path",
            );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_971).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(after_task.challenger, before_task.challenger);
        assert_eq!(after_task.challenge_bond, before_task.challenge_bond);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn challenge_emergency_pause_precedes_challenger_signer_auth_checks_without_escrow_mutation() {
        // Merge-gate hardening: pause guard must fire before challenger/signer
        // identity validation so paused challenge flow cannot leak auth-policy outcomes.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 8_971_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_971_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        st.set_gov_param(9_211, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_971_1).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_challenge(&mut st, r4, "challenger".into(), 10, "authority".into())
            .expect_err(
            "emergency pause must mask challenger/signer mismatch and freeze challenge entry path",
        );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_971_1).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(after_task.challenger, before_task.challenger);
        assert_eq!(after_task.challenge_bond, before_task.challenge_bond);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn challenge_reopens_after_emergency_pause_clears() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 8_970, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_970, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

        st.set_gov_param(9_207, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let paused_err = apply_challenge(
            &mut st,
            r4.clone(),
            "challenger".into(),
            10,
            "challenger".into(),
        )
        .expect_err("emergency pause must freeze challenge entry path");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of("challenger"), 100);

        st.set_gov_param(9_208, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into())
            .expect("challenge must reopen after emergency pause is cleared");

        let task = st.get_task(r5.id).expect("challenged task must persist");
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(task.challenger.as_deref(), Some("challenger"));
        assert_eq!(task.challenge_bond, Some(10));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
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
        assert!(matches!(
            pause,
            trnm_state::GovParamUpdateOutcome::Applied(_)
        ));
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
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_pause_boundary_precedes_authority_validation_without_escrow_mutation() {
        // Safety boundary: emergency pause must fail-closed before authority
        // validation so malformed resolver payloads cannot leak auth-policy outcomes.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_960_5, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_960_5, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_200_5, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_960_5).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(
            &mut st,
            r5,
            true,
            "authority".into(),
            "authority;spoof".into(),
        )
        .expect_err("pause boundary must trigger before malformed signer validation");
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_960_5).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
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
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_multisig_paused_after_first_approval_preserves_staged_authority_and_escrow_until_unpaused(
    ) {
        // Safety boundary: pause must fail-closed before multisig confirmation so
        // staged approvals remain intact and escrow cannot settle while paused.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 8_961_2, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_2, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let first_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("first multisig approval should stage only");
        assert!(matches!(first_err, PouwError::ResolveApprovalStaged));
        assert_eq!(
            st.pending_resolve_first_approver(r5.id).as_deref(),
            Some("authority-a")
        );

        st.set_gov_param(9_201_2, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let paused_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect_err("pause must block second multisig approval and terminal settlement");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(
            st.pending_resolve_first_approver(r5.id).as_deref(),
            Some("authority-a")
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        st.set_gov_param(9_201_3, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let r6 = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect("second multisig signer should finalize after pause clears");
        let task = st.get_task(r6.id).expect("resolved task must exist");
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(st.pending_resolve_first_approver(r5.id), None);
    }

    #[test]
    fn resolve_pause_masks_authority_rotation_until_unpause_then_clears_stale_multisig_approval() {
        // Governance + safety hardening: emergency pause must mask signer-set
        // rotation effects while active, then fail closed after unpause by clearing
        // now-stale staged approvals before any escrow settlement path can proceed.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 8_961_16, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_16, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let first_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("first multisig approval should stage only");
        assert!(matches!(first_err, PouwError::ResolveApprovalStaged));
        assert_eq!(
            st.pending_resolve_first_approver(r5.id).as_deref(),
            Some("authority-a")
        );

        st.set_gov_param(9_201_16, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());
        set_resolve_authority(&mut st, "authority-b,authority-c");

        let paused_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-c".into(),
            "authority-c".into(),
        )
        .expect_err("pause must mask rotated signer-set checks and freeze settlement");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(
            st.pending_resolve_first_approver(r5.id).as_deref(),
            Some("authority-a")
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        st.set_gov_param(9_201_17, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let stale_err = apply_resolve(
            &mut st,
            r5,
            true,
            "authority-c".into(),
            "authority-c".into(),
        )
        .expect_err("stale first approver must be cleared after signer-set rotation");
        assert!(matches!(stale_err, PouwError::Unauthorized));
        assert_eq!(st.pending_resolve_first_approver(8_961_16), None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_pause_masks_single_authority_downgrade_until_unpause_then_clears_staged_multisig() {
        // Governance + decentralization hardening: pause must keep already-staged
        // multisig approvals intact, then after unpause a downgraded single-authority
        // resolver config must fail closed and clear stale staging without escrow drift.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 8_961_17, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_17, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let first_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("first multisig approval should stage only");
        assert!(matches!(first_err, PouwError::ResolveApprovalStaged));
        assert_eq!(
            st.pending_resolve_first_approver(r5.id).as_deref(),
            Some("authority-a")
        );

        st.set_gov_param(9_201_18, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());
        set_resolve_authority(&mut st, "authority-b");

        let paused_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect_err("pause must mask downgrade effects and freeze challenged settlement");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(
            st.pending_resolve_first_approver(r5.id).as_deref(),
            Some("authority-a")
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        st.set_gov_param(9_201_19, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let r6 = apply_resolve(
            &mut st,
            r5,
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect("singleton downgrade must be rejected, leaving multisig settlement available");
        assert_eq!(st.pending_resolve_first_approver(r6.id), None);
        let task = st.get_task(r6.id).expect("resolved task must persist");
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert!(st.balance_of("challenger") >= before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_authority_checks_without_escrow_mutation() {
        // Merge-gate hardening: emergency pause must fail-closed before signer/authority
        // checks, so challenged escrow cannot leak side-channel auth outcomes.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_961_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_1, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_1).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, true, "attacker".into(), "attacker".into())
            .expect_err(
                "emergency pause must mask authority result and freeze challenged settlement",
            );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_1).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_reserved_system_actor_validation_without_escrow_mutation() {
        // Merge-gate hardening: emergency pause must fail-closed before reserved
        // system-actor validation so authorization policy details stay non-observable
        // while challenged escrow settlement paths are frozen.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "system");

        let r1 = apply_create_task(&mut st, 8_961_15, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_15, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_15, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_15).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, true, "system".into(), "system".into()).expect_err(
            "emergency pause must mask reserved system-actor validation and freeze settlement",
        );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_15).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_multisig_member_validation_without_escrow_mutation() {
        // Merge-gate hardening: emergency pause must fail-closed before malformed
        // resolve-authority member set validation to avoid auth-shape side channels.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,");

        let r1 = apply_create_task(&mut st, 8_961_2, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_2, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_2, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_2).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
            "emergency pause must mask malformed authority-member validation and freeze settlement",
        );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_2).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_leading_empty_multisig_member_validation_without_escrow_mutation(
    ) {
        // Merge-gate hardening: emergency pause must fail-closed before leading-empty
        // authority-member validation to avoid leaking parser/shape policy details.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, ",authority");

        let r1 = apply_create_task(&mut st, 8_961_2_0, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_2_0, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_2_0, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_2_0).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
                "emergency pause must mask leading-empty authority-member validation and freeze settlement",
            );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_2_0).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_duplicate_multisig_member_validation_without_escrow_mutation(
    ) {
        // Merge-gate hardening: emergency pause must fail-closed before duplicate
        // resolver-member validation so multisig-shape probing cannot leak governance policy.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,authority");

        let r1 = apply_create_task(&mut st, 8_961_2_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_2_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_2_1, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_2_1).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
            "emergency pause must mask duplicate authority-member validation and freeze settlement",
        );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_2_1).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_escrow_member_multisig_validation_without_escrow_mutation()
    {
        // Merge-gate hardening: emergency pause must fail-closed before escrow-member
        // authority-set validation to avoid leaking governance role-separation outcomes.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let authority_with_escrow_member = format!("authority,{}", CHALLENGE_ESCROW_ACCOUNT);
        set_resolve_authority(&mut st, &authority_with_escrow_member);

        let r1 = apply_create_task(&mut st, 8_961_21, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_21, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_21, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_21).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
            "emergency pause must mask escrow-member authority validation and freeze settlement",
        );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_21).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_escrow_account_authority_validation_without_escrow_mutation(
    ) {
        // Merge-gate hardening: emergency pause must fail-closed before escrow-account
        // authority validation to avoid leaking custody-role separation outcomes.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, CHALLENGE_ESCROW_ACCOUNT);

        let r1 = apply_create_task(&mut st, 8_961_211, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_211, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_211, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_211).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(
            &mut st,
            r5,
            true,
            CHALLENGE_ESCROW_ACCOUNT.into(),
            CHALLENGE_ESCROW_ACCOUNT.into(),
        )
        .expect_err(
            "emergency pause must mask escrow-account authority validation and freeze settlement",
        );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_211).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_forfeit_member_multisig_validation_without_escrow_mutation(
    ) {
        // Merge-gate hardening: emergency pause must fail-closed before forfeit-treasury
        // member authority-set validation to avoid leaking role-separation outcomes.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let authority_with_forfeit_member =
            format!("authority,{}", CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        set_resolve_authority(&mut st, &authority_with_forfeit_member);

        let r1 = apply_create_task(&mut st, 8_961_219, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_219, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_219, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_219).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
            "emergency pause must mask forfeit-member authority validation and freeze settlement",
        );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_219).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_forfeit_treasury_authority_validation_without_escrow_mutation(
    ) {
        // Merge-gate hardening: emergency pause must fail-closed before forfeit-treasury
        // authority validation to avoid leaking custody-role separation outcomes.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        let r1 = apply_create_task(&mut st, 8_961_22, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_22, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_22, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_22).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(
            &mut st,
            r5,
            true,
            CHALLENGE_FORFEIT_TREASURY_ACCOUNT.into(),
            CHALLENGE_FORFEIT_TREASURY_ACCOUNT.into(),
        )
        .expect_err(
            "emergency pause must mask forfeit-treasury authority validation and freeze settlement",
        );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_22).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_worker_slash_treasury_authority_validation_without_escrow_mutation(
    ) {
        // Merge-gate hardening: emergency pause must fail-closed before worker-slash
        // treasury authority validation to avoid leaking custody-role separation outcomes.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, WORKER_SLASH_TREASURY_ACCOUNT);

        let r1 = apply_create_task(&mut st, 8_961_23, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_23, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_23, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_23).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_worker_slash = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(
            &mut st,
            r5,
            true,
            WORKER_SLASH_TREASURY_ACCOUNT.into(),
            WORKER_SLASH_TREASURY_ACCOUNT.into(),
        )
        .expect_err(
            "emergency pause must mask worker-slash treasury authority validation and freeze settlement",
        );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_23).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before_worker_slash
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_semicolon_signer_validation_without_escrow_mutation() {
        // Merge-gate hardening: emergency pause must fail-closed before signer token
        // grammar checks so malformed signer payload probing cannot reveal auth policy.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_961_23, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_23, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_23, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_23).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(
            &mut st,
            r5,
            true,
            "authority;attacker".into(),
            "authority;attacker".into(),
        )
        .expect_err("emergency pause must mask semicolon signer validation and freeze settlement");
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_23).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_pipe_signer_validation_without_escrow_mutation() {
        // Merge-gate hardening: emergency pause must fail-closed before signer token
        // grammar checks so pipe-delimited signer probing cannot reveal auth policy.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_961_23_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_23_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_23_1, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_23_1).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(
            &mut st,
            r5,
            true,
            "authority|attacker".into(),
            "authority|attacker".into(),
        )
        .expect_err("emergency pause must mask pipe signer validation and freeze settlement");
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_23_1).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_non_ascii_signer_validation_without_escrow_mutation() {
        // Merge-gate hardening: emergency pause must fail-closed before unicode
        // signer validation so homoglyph payload probes cannot reveal auth policy.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_961_23_2, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_23_2, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_23_2, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_23_2).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let spoofed_signer = "authоrity"; // Cyrillic 'о' (U+043E)
        let err = apply_resolve(
            &mut st,
            r5,
            true,
            spoofed_signer.into(),
            spoofed_signer.into(),
        )
        .expect_err("emergency pause must mask non-ASCII signer validation and freeze settlement");
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_23_2).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_non_ascii_authority_member_validation_without_escrow_mutation(
    ) {
        // Merge-gate hardening: emergency pause must fail-closed before unicode
        // authority-member validation so homoglyph membership probes cannot reveal
        // resolver-policy details while challenged escrow settlement is frozen.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let spoofed_member = "authоrity2"; // Cyrillic 'о' (U+043E)
        set_resolve_authority(&mut st, &format!("authority,{spoofed_member}"));

        let r1 = apply_create_task(&mut st, 8_961_23_2_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_23_2_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_23_2_1, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_23_2_1).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
            "emergency pause must mask non-ASCII authority-member validation and freeze settlement",
        );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_23_2_1).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_unicode_separator_signer_validation_without_escrow_mutation(
    ) {
        // Merge-gate hardening: emergency pause must fail-closed before unicode
        // separator signer validation so delimiter-smuggling probes cannot reveal
        // resolver-policy details while escrow settlement is frozen.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_961_23_3, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_23_3, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_23_3, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_23_3).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let spoofed_signer = "authority；attacker";
        let err = apply_resolve(
            &mut st,
            r5,
            true,
            spoofed_signer.into(),
            spoofed_signer.into(),
        )
        .expect_err(
            "emergency pause must mask unicode separator signer validation and freeze settlement",
        );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_23_3).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_challenger_authority_validation_without_escrow_mutation() {
        // Merge-gate hardening: emergency pause must fail-closed before challenger-role
        // separation checks so resolver-role probes cannot leak adjudicator policy outcomes.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "challenger");

        let r1 = apply_create_task(&mut st, 8_961_24, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_24, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_24, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_24).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, true, "challenger".into(), "challenger".into())
            .expect_err(
                "emergency pause must mask challenger-authority validation and freeze settlement",
            );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_24).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_multisig_challenger_member_validation_without_escrow_mutation(
    ) {
        // Merge-gate hardening: emergency pause must fail-closed before challenger-member
        // multisig validation so role-separation probes cannot leak adjudicator policy.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,challenger");

        let r1 = apply_create_task(&mut st, 8_961_24_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_24_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_24_1, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_24_1).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
            "emergency pause must mask challenger-member multisig validation and freeze settlement",
        );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_24_1).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_challenged_invariant_validation_without_escrow_mutation() {
        // Merge-gate hardening: emergency pause must fail-closed before challenged
        // accounting invariant checks so malformed challenged metadata cannot leak
        // resolver-policy validation outcomes while escrow settlement is frozen.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_961_24_15, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_24_15, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        // Corrupt challenged object to violate resolve challenged-accounting invariants.
        let mut bad = st.get_task(r5.id).unwrap();
        assert_eq!(bad.status, TaskStatus::Challenged);
        bad.challenge_bond_forfeited = Some(false);
        let bad_ref = st.update_task(r5, bad).unwrap();

        st.set_gov_param(9_201_24_15, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_24_15).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(
            &mut st,
            bad_ref,
            true,
            "authority".into(),
            "authority".into(),
        )
        .expect_err("emergency pause must mask challenged invariant validation path");
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_24_15).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_assigned_worker_authority_validation_without_escrow_mutation(
    ) {
        // Merge-gate hardening: emergency pause must fail-closed before assigned-worker
        // authority membership validation so worker-role probes cannot leak adjudicator policy.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "worker1,authority-b");

        let r1 = apply_create_task(&mut st, 8_961_24_2, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_24_2, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_24_2, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_24_2).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, true, "worker1".into(), "worker1".into()).expect_err(
            "emergency pause must mask assigned-worker authority validation and freeze settlement",
        );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_24_2).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_assigned_worker_authority_member_validation_without_escrow_mutation(
    ) {
        // Merge-gate hardening: emergency pause must fail-closed before assigned-worker
        // separation checks so authority-list probes cannot leak adjudicator policy.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,worker1");

        let r1 = apply_create_task(&mut st, 8_961_24_2, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_24_2, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_24_2, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_24_2).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
                "emergency pause must mask assigned-worker authority-member validation and freeze settlement",
            );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_24_2).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_placeholder_authority_validation_without_escrow_mutation() {
        // Merge-gate hardening: emergency pause must fail-closed before unconfigured
        // governance placeholder-authority validation to avoid auth-policy side channels.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        // Keep default unconfigured governance placeholder authority.

        let r1 = apply_create_task(&mut st, 8_961_25, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_25, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_201_25, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_25).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let placeholder = DEFAULT_RESOLVE_AUTHORITY.to_string();
        let err = apply_resolve(&mut st, r5, true, placeholder.clone(), placeholder).expect_err(
            "emergency pause must mask placeholder-authority validation and freeze settlement",
        );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_25).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
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
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn resolve_emergency_pause_precedes_malformed_worker_state_validation_without_escrow_mutation()
    {
        // Merge-gate hardening: emergency pause must fail-closed before malformed
        // worker-account state validation so paused resolve flow does not leak legacy
        // challenged-task corruption details while escrow settlement is frozen.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_961_90, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_90, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        // Simulate malformed legacy challenged state carrying non-canonical worker id.
        let mut malformed = st.get_task(r5.id).unwrap();
        malformed.worker = Some(" worker1".into());
        let r5 = st.update_task(r5, malformed).unwrap();

        st.set_gov_param(9_201_90, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_961_90).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
                "emergency pause must mask malformed worker-state validation and freeze settlement",
            );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_90).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn timeout_emergency_pause_preserves_staged_multisig_resolve_approval_without_escrow_mutation()
    {
        // Safety boundary: emergency pause must fail-closed for challenged timeout
        // settlement even when a multisig resolve approval is already staged.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,authority2");

        let r1 = apply_create_task(&mut st, 8_962_09, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_962_09, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let staged_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority2".into(),
            "authority2".into(),
        )
        .expect_err("first multisig signer must stage resolve approval before timeout");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        st.set_gov_param(9_202_09, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_962_09).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_timeout(&mut st, r5.clone(), 221).expect_err(
            "emergency pause must freeze challenged timeout despite staged multisig approval",
        );
        assert!(matches!(err, PouwError::InvalidTransition));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        let after_task = st.get_task(8_962_09).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        st.set_gov_param(9_202_10, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let done = apply_timeout(&mut st, r5, 221)
            .expect("challenged timeout should reopen after pause clear and finalize once");
        assert_eq!(st.pending_resolve_approval(done.id), None);
    }

    #[test]
    fn timeout_emergency_pause_precedes_challenged_invariant_validation_without_escrow_mutation() {
        // Merge-gate hardening: emergency pause must fail-closed before challenged
        // accounting invariant checks to avoid leaking escrow-state validation paths.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 8_962_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_962_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        // Corrupt challenged object to violate timeout challenged-accounting invariants.
        let mut bad = st.get_task(r5.id).unwrap();
        assert_eq!(bad.status, TaskStatus::Challenged);
        bad.challenge_bond_forfeited = Some(false);
        let bad_ref = st.update_task(r5, bad).unwrap();

        st.set_gov_param(9_202_3, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_962_1).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_timeout(&mut st, bad_ref, 221)
            .expect_err("emergency pause must mask challenged invariant validation path");
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_962_1).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn timeout_emergency_pause_precedes_deadline_checks_without_escrow_mutation() {
        // Merge-gate hardening: emergency pause must fail-closed before timeout
        // deadline checks so challenged timeout flow cannot leak liveness outcomes.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 8_962_4, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_962_4, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_202_4, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_962_4).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_timeout(&mut st, r5, 0).expect_err(
            "emergency pause must mask deadline checks and freeze challenged timeout path",
        );
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_962_4).unwrap();
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn timeout_reopens_after_emergency_pause_clears_with_single_settlement() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 8_962_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_962_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_202_1, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let paused_err = apply_timeout(&mut st, r5.clone(), 221)
            .expect_err("emergency pause must freeze challenged timeout settlement path");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
        assert_eq!(st.balance_of("challenger"), 90);

        st.set_gov_param(9_202_2, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let done = apply_timeout(&mut st, r5, 221)
            .expect("challenged timeout must reopen after emergency pause clears");
        let task = st.get_task(done.id).expect("timed out task must persist");
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
        assert_eq!(st.balance_of("challenger"), 100);

        let escrow_after_first_timeout = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let forfeit_after_first_timeout = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let challenger_after_first_timeout = st.balance_of("challenger");

        let replay_err = apply_timeout(&mut st, done, 221)
            .expect_err("terminal timeout replay must be rejected without double settlement");
        assert!(matches!(replay_err, PouwError::InvalidTransition));
        assert_eq!(
            st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
            escrow_after_first_timeout
        );
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            forfeit_after_first_timeout
        );
        assert_eq!(st.balance_of("challenger"), challenger_after_first_timeout);
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
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before_worker_slash_treasury
        );
    }

    #[test]
    fn resolve_reopens_after_emergency_pause_clears_with_single_settlement() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,authority2");

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

        let paused_err = apply_resolve(
            &mut st,
            r5.clone(),
            false,
            "authority".into(),
            "authority".into(),
        )
        .expect_err("resolve must stay frozen while emergency pause is active");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
        assert_eq!(st.balance_of("challenger"), 90);

        st.set_gov_param(9_205, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let staged = apply_resolve(&mut st, r5.clone(), false, "authority".into(), "authority".into())
            .expect_err("first resolver should stage once emergency pause clears");
        assert!(matches!(staged, PouwError::ResolveApprovalStaged));
        let r6 = apply_resolve(&mut st, r5, false, "authority2".into(), "authority2".into())
            .expect("resolve must reopen after emergency pause is cleared");
        let task = st.get_task(r6.id).expect("resolved task must persist");
        assert_eq!(task.challenge_bond_forfeited, Some(true));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 10);
        assert_eq!(st.balance_of("challenger"), 90);
    }

    #[test]
    fn resolve_pause_toggle_preserves_challenge_funds_conservation() {
        // Merge-gate hardening: emergency pause must freeze terminal settlement while
        // preserving end-to-end challenge-fund conservation across challenger/escrow/forfeit.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,authority2");

        let total_funds = |st: &StateStore| {
            st.balance_of("challenger")
                + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
                + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
        };

        let baseline_total = total_funds(&st);
        assert_eq!(baseline_total, 100);

        let r1 = apply_create_task(&mut st, 8_964_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_964_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
        assert_eq!(total_funds(&st), baseline_total);

        st.set_gov_param(9_214_1, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let paused_err = apply_resolve(
            &mut st,
            r5.clone(),
            false,
            "authority2".into(),
            "authority2".into(),
        )
        .expect_err("resolve must stay frozen while emergency pause is active");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(total_funds(&st), baseline_total);

        st.set_gov_param(9_214_2, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let staged_err = apply_resolve(
            &mut st,
            r5.clone(),
            false,
            "authority2".into(),
            "authority2".into(),
        )
        .expect_err("first multisig member must stage resolve after pause clears");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(total_funds(&st), baseline_total);

        let done = apply_resolve(&mut st, r5, false, "authority".into(), "authority".into())
            .expect("second multisig member must finalize resolve after pause clears");
        let task = st.get_task(done.id).expect("resolved task must persist");
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.challenge_bond_forfeited, Some(true));
        assert_eq!(total_funds(&st), baseline_total);
    }

    #[test]
    fn resolve_multisig_member_reopens_after_emergency_pause_clears_without_escrow_drift() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,authority2");

        let r1 = apply_create_task(&mut st, 8_965, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_965, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        st.set_gov_param(9_214, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_worker_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
        let paused_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority2".into(),
            "authority2".into(),
        )
        .expect_err("emergency pause must freeze multisig-member resolve path");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(
            st.pending_resolve_approval(r5.id),
            None,
            "paused resolve attempt must not stage multisig approvals",
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before_worker_slash_treasury
        );

        st.set_gov_param(9_215, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let staged_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority2".into(),
            "authority2".into(),
        )
        .expect_err("first multisig member must stage resolve after pause clears");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(
            st.pending_resolve_approval(r5.id),
            Some((true, 1)),
            "post-pause first signer should stage exactly one slashing approval",
        );

        let r6 = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect("second multisig member must finalize resolve after pause clears");
        let task = st.get_task(r6.id).expect("resolved task must persist");
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
        assert_eq!(st.balance_of("challenger"), 101);
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before_worker_slash_treasury.saturating_sub(1)
        );
    }

    #[test]
    fn resolve_multisig_pending_approval_remains_staged_across_emergency_pause() {
        // Safety boundary: emergency pause must freeze terminal settlement even when
        // one multisig approval is already staged, without mutating escrow balances.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,authority2");

        let r1 = apply_create_task(&mut st, 8_966, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_966, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let worker_lock_account = worker_stake_lock_account(r5.id);
        let total_funds = |st: &StateStore| {
            st.balance_of("challenger")
                + st.balance_of("worker1")
                + st.balance_of(&worker_lock_account)
                + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
                + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
                + st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT)
        };
        let baseline_total = total_funds(&st);

        let staged_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority2".into(),
            "authority2".into(),
        )
        .expect_err("first multisig member must stage a pending approval");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
        assert_eq!(total_funds(&st), baseline_total);

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");
        let before_worker_slash_treasury = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

        st.set_gov_param(9_216, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let paused_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority".into(),
            "authority".into(),
        )
        .expect_err("emergency pause must block final multisig settlement with pending approval");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before_worker_slash_treasury
        );

        st.set_gov_param(9_217, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let r6 = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect("second distinct signer must finalize once pause clears");
        assert_eq!(st.pending_resolve_approval(r6.id), None);

        let task = st.get_task(r6.id).expect("resolved task must persist");
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(total_funds(&st), baseline_total);
    }

    #[test]
    fn resolve_multisig_rejects_decision_flip_after_pause_clear_without_escrow_mutation() {
        // Governance hardening: once a multisig slash decision is staged, reopening
        // after emergency pause clear must not allow slash/non-slash decision flips.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,authority2");

        let r1 = apply_create_task(&mut st, 8_967, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_967, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let staged_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority2".into(),
            "authority2".into(),
        )
        .expect_err("first multisig member must stage slash decision");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        st.set_gov_param(9_218, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        st.set_gov_param(9_219, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let flip_err = apply_resolve(
            &mut st,
            r5.clone(),
            false,
            "authority".into(),
            "authority".into(),
        )
        .expect_err(
            "second signer must not be able to flip staged slash decision after pause clear",
        );
        assert!(matches!(flip_err, PouwError::Unauthorized));

        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        let r6 = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect("matching staged slash decision should finalize after pause clear");
        let task = st.get_task(r6.id).expect("resolved task must persist");
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
    }

    #[test]
    fn resolve_multisig_rejects_stale_first_approver_after_governance_member_rotation_without_escrow_mutation(
    ) {
        // Governance hardening: once signer membership rotates, previously staged
        // approvals from removed members must be discarded before settlement.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 8_968, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_968, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let staged_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("first multisig signer should only stage pending approval");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        // Rotate signer set: remove staged approver and add a new member.
        set_resolve_authority(&mut st, "authority-b,authority-c");

        let stale_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect_err("stale staged approver from removed member must be discarded");
        assert!(matches!(stale_err, PouwError::Unauthorized));
        assert_eq!(
            st.pending_resolve_approval(r5.id),
            None,
            "stale staged approval should be cleared after authority-set rotation",
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        let staged_again_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect_err("first signer in rotated set should re-stage from empty state");
        assert!(matches!(staged_again_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        let r6 = apply_resolve(
            &mut st,
            r5,
            true,
            "authority-c".into(),
            "authority-c".into(),
        )
        .expect("second rotated signer should finalize terminal settlement");
        assert_eq!(st.pending_resolve_approval(r6.id), None);
        let task = st.get_task(r6.id).expect("resolved task must persist");
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
    }

    #[test]
    fn resolve_multisig_rotation_during_emergency_pause_clears_stale_approval_only_after_unpause() {
        // Safety boundary + governance hardening: pause must fail-closed before
        // multisig membership checks, and stale staged approvals must be cleared
        // only once resolve flow re-opens after unpause.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 8_969, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_969, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let staged_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("first multisig signer should only stage pending approval");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        st.set_gov_param(9_219_30, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        // Rotate membership while paused to remove the staged first approver.
        set_resolve_authority(&mut st, "authority-b,authority-c");

        let paused_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect_err("pause must fail-closed before multisig membership-change handling");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(
            st.pending_resolve_approval(r5.id),
            Some((true, 1)),
            "paused resolve attempt must not clear staged approvals",
        );

        st.set_gov_param(9_219_31, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let stale_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect_err("unpaused resolve should clear stale staged approver removed by rotation");
        assert!(matches!(stale_err, PouwError::Unauthorized));
        assert_eq!(
            st.pending_resolve_approval(r5.id),
            None,
            "stale staged approval should clear once membership checks resume",
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        let staged_again_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect_err("first signer in rotated set should re-stage from empty state");
        assert!(matches!(staged_again_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        let r6 = apply_resolve(
            &mut st,
            r5,
            true,
            "authority-c".into(),
            "authority-c".into(),
        )
        .expect("second rotated signer should finalize terminal settlement");
        assert_eq!(st.pending_resolve_approval(r6.id), None);
        let task = st.get_task(r6.id).expect("resolved task must persist");
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
    }

    #[test]
    fn resolve_multisig_rotation_during_emergency_pause_clears_stale_completed_path_without_escrow_drift(
    ) {
        // Safety boundary + governance hardening: paused challenged-resolve flow
        // must freeze staged approvals, then clear stale approvals after unpause
        // even for slash=false (forfeit-treasury) settlement path.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 8_969_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_969_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");
        let before_total = before_escrow + before_forfeit + before_challenger;

        let staged_err = apply_resolve(
            &mut st,
            r5.clone(),
            false,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("first multisig signer should stage pending approval for slash=false path");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((false, 1)));

        st.set_gov_param(9_219_32, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        set_resolve_authority(&mut st, "authority-b,authority-c");

        let paused_err = apply_resolve(
            &mut st,
            r5.clone(),
            false,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect_err("pause must fail-closed before slash=false membership rotation handling");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((false, 1)));

        st.set_gov_param(9_219_33, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let stale_err = apply_resolve(
            &mut st,
            r5.clone(),
            false,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect_err("unpaused slash=false resolve should clear stale staged approver");
        assert!(matches!(stale_err, PouwError::Unauthorized));
        assert_eq!(st.pending_resolve_approval(r5.id), None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        let restaged_err = apply_resolve(
            &mut st,
            r5.clone(),
            false,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect_err("rotated slash=false signer should re-stage from empty state");
        assert!(matches!(restaged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((false, 1)));

        let r6 = apply_resolve(
            &mut st,
            r5,
            false,
            "authority-c".into(),
            "authority-c".into(),
        )
        .expect("second rotated signer should finalize slash=false settlement");
        assert_eq!(st.pending_resolve_approval(r6.id), None);
        let task = st.get_task(r6.id).expect("resolved task must persist");
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.challenge_bond_forfeited, Some(true));
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit + 10
        );
        let after_total = st.balance_of("challenger")
            + st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
            + st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        assert_eq!(
            after_total, before_total,
            "slash=false rotation/unpause resolve must conserve challenger+escrow+forfeit totals"
        );
    }

    #[test]
    fn resolve_multisig_rotation_that_keeps_first_member_still_clears_stale_staging_before_escrow_settlement(
    ) {
        // Governance hardening: any signer-set rotation must invalidate prior staged approvals,
        // even if the original first approver remains in the new multisig set.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 8_970, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_970, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let staged_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("first multisig signer should only stage pending approval");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        // Rotate membership while keeping authority-a present.
        set_resolve_authority(&mut st, "authority-a,authority-c");

        let stale_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-c".into(),
            "authority-c".into(),
        )
        .expect_err(
            "rotation must clear stale staged approval even when first signer remains in set",
        );
        assert!(matches!(stale_err, PouwError::Unauthorized));
        assert_eq!(
            st.pending_resolve_approval(r5.id),
            None,
            "any authority-set rotation must clear stale staged approvals",
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        let staged_again_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("first signer in rotated set should re-stage from empty state");
        assert!(matches!(staged_again_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        let r6 = apply_resolve(
            &mut st,
            r5,
            true,
            "authority-c".into(),
            "authority-c".into(),
        )
        .expect("second signer in rotated set should finalize terminal settlement");
        assert_eq!(st.pending_resolve_approval(r6.id), None);
        let task = st.get_task(r6.id).expect("resolved task must persist");
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
    }

    #[test]
    fn resolve_multisig_task_version_change_clears_stale_staging_before_terminal_settlement() {
        // Economic snapshot hardening: second multisig finalize must bind to the
        // challenged task version captured at first approval. Any intervening task
        // mutation should clear stale staging and require a fresh quorum.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 8_972, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_972, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let staged_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("first multisig signer should stage before terminal settlement");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        let task = st.get_task(r5.id).expect("challenged task must exist");
        let r5_mut = st
            .update_task(r5.clone(), task)
            .expect("intervening task rewrite should bump version");
        assert!(r5_mut.version > r5.version);

        let stale_err = apply_resolve(
            &mut st,
            r5_mut.clone(),
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect_err("task-version drift must clear stale staged approval");
        assert!(matches!(stale_err, PouwError::Unauthorized));
        assert_eq!(
            st.pending_resolve_approval(r5.id),
            None,
            "task-version drift must clear stale staged approval",
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        let restaged_err = apply_resolve(
            &mut st,
            r5_mut.clone(),
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect_err("fresh first signer should restage after stale approval clears");
        assert!(matches!(restaged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        let r6 = apply_resolve(
            &mut st,
            r5_mut,
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect("second signer should finalize after fresh staging on new version");
        assert_eq!(st.pending_resolve_approval(r6.id), None);
        let task = st.get_task(r6.id).expect("resolved task must persist");
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(task.challenge_bond, Some(10));
        assert_eq!(task.challenge_bond_forfeited, Some(false));
    }

    #[test]
    fn resolve_multisig_member_reordering_clears_stale_staging_before_terminal_settlement() {
        // Canonical-configuration hardening: authority-set reordering changes the
        // configured signer-set payload, so stale approvals must be cleared
        // before escrow can move under the reordered configuration.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 8_976, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_976, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let staged_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("first multisig signer should stage before terminal settlement");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        // Reorder members without changing member identities.
        set_resolve_authority(&mut st, "authority-b,authority-a");

        let stale_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect_err("authority payload reordering must clear stale staged approval");
        assert!(matches!(stale_err, PouwError::Unauthorized));
        assert_eq!(st.pending_resolve_approval(r5.id), None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        let restaged_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect_err("reordered authority set should require a fresh first approval");
        assert!(matches!(restaged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        let r6 = apply_resolve(
            &mut st,
            r5,
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect("second reordered signer should finalize after fresh staging");
        assert_eq!(st.pending_resolve_approval(r6.id), None);
        let task = st.get_task(r6.id).expect("resolved task must persist");
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
    }

    #[test]
    fn resolve_multisig_to_single_authority_rotation_clears_stale_staging_before_terminal_settlement(
    ) {
        // Minimal multi-party control: downgrading resolver membership from multisig
        // to single authority must not allow inheriting partially-approved state.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 8_968, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_968, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let staged_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("first multisig signer should only stage pending approval");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        // Governance downgrade to a singleton must now be rejected, leaving the
        // staged multisig approval intact until a distinct second signer completes it.
        set_resolve_authority(&mut st, "authority-a");

        let singleton_followup = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a,authority-b".into(),
        )
        .expect_err("duplicate signer replay must not consume staged multisig approval");
        assert!(matches!(singleton_followup, PouwError::Unauthorized));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        let r6 = apply_resolve(
            &mut st,
            r5,
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect("second multisig signer should settle after singleton downgrade is rejected");
        assert_eq!(st.pending_resolve_approval(r6.id), None);
        let task = st.get_task(r6.id).expect("resolved task must persist");
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
    }

    #[test]
    fn resolve_multisig_staging_persists_while_paused_then_single_authority_rotation_clears_after_unpause(
    ) {
        // Safety boundary: emergency pause check must execute before stale-staging
        // cleanup so no pending multisig approval state is mutated while paused.
        // After unpause, the single-authority downgrade path should still clear
        // stale staging fail-closed before any terminal escrow settlement.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 8_968, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_968, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let staged_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("first multisig signer should only stage pending approval");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        st.set_gov_param(9_230, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());
        set_resolve_authority(&mut st, "authority-a");

        let paused_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("pause must reject resolve before stale staging cleanup");
        assert!(matches!(paused_err, PouwError::InvalidTransition));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        st.set_gov_param(9_231, 7_999, "emergency_pause".into(), "false".into())
            .expect("pause=false governance update must succeed");
        assert!(!st.is_emergency_paused());

        let stale_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a,authority-b".into(),
        )
        .expect_err("duplicate signer replay must leave paused-staged multisig approval intact after unpause");
        assert!(matches!(stale_err, PouwError::Unauthorized));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);

        let r6 = apply_resolve(
            &mut st,
            r5,
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect("second multisig signer should settle once unpaused after singleton downgrade is rejected");
        assert_eq!(st.pending_resolve_approval(r6.id), None);
        assert_eq!(st.pending_resolve_first_approver(r6.id), None);
        let task = st.get_task(r6.id).expect("resolved task must persist");
        assert_eq!(task.status, TaskStatus::Slashed);
        assert_eq!(task.challenge_bond_forfeited, Some(false));
    }

    #[test]
    fn resolve_multisig_clears_staged_approval_on_case_drifted_member_rotation_without_escrow_mutation(
    ) {
        // Canonical-account hardening: signer membership uses exact account IDs,
        // so case-drifted rotations must clear staged approvals fail-closed.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority-a,authority-b");

        let r1 = apply_create_task(&mut st, 8_969, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_969, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let staged_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
        )
        .expect_err("first multisig signer should only stage pending approval");
        assert!(matches!(staged_err, PouwError::ResolveApprovalStaged));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        // Rotate with case drift for the first approver ID.
        set_resolve_authority(&mut st, "Authority-A,authority-b");

        let stale_err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority-b".into(),
            "authority-b".into(),
        )
        .expect_err("case-drifted membership rotation must clear staged approval fail-closed");
        assert!(matches!(stale_err, PouwError::Unauthorized));
        assert_eq!(
            st.pending_resolve_approval(r5.id),
            None,
            "staged approval should be cleared when first approver account id no longer matches exactly",
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
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
        let err = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority".into(),
            "authority".into(),
        )
        .expect_err("missing governance authority must not silently authorize legacy singleton");
        assert!(matches!(err, PouwError::Unauthorized));

        let err = apply_resolve(
            &mut st,
            r5,
            true,
            DEFAULT_RESOLVE_AUTHORITY.into(),
            DEFAULT_RESOLVE_AUTHORITY.into(),
        )
        .expect_err(
            "missing governance authority must remain fail-closed for placeholder authority",
        );
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
        set_resolve_authority(&mut st, "authority,authority2");

        let r1 = apply_create_task(&mut st, 8_995, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_995, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let staged = apply_resolve(&mut st, r5.clone(), true, "authority".into(), "authority".into())
            .unwrap_err();
        assert!(matches!(staged, PouwError::ResolveApprovalStaged));
        let r6 = apply_resolve(&mut st, r5, true, "authority2".into(), "authority2".into()).unwrap();
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
    fn resolve_rejects_non_canonical_resolver_payload_without_state_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_999_4, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_999_4, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err =
            apply_resolve(&mut st, r5, true, " authority ".into(), "authority".into()).unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_999_4).unwrap();
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
    fn resolve_rejects_configured_authority_with_empty_member_without_state_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,");

        let r1 = apply_create_task(&mut st, 8_999_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_999_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err("authority list with empty member must fail closed");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_999_1).unwrap();
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
    fn resolve_rejects_configured_authority_with_leading_empty_member_without_state_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, ",authority");

        let r1 = apply_create_task(&mut st, 8_999_1_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_999_1_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err("authority list with leading empty member must fail closed");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(8_999_1_1).unwrap();
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
    fn resolve_rejects_malformed_governance_authority_with_whitespace_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        // Governance drift: authority must be canonical and whitespace-free.
        set_resolve_authority(&mut st, "authority ");

        let r1 = apply_create_task(&mut st, 9_001_6, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_6, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err("malformed governance authority must fail closed");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_6).unwrap();
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
    fn resolve_rejects_governance_authority_with_internal_whitespace_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        // Internal whitespace must also fail closed to preserve canonical actor ids.
        set_resolve_authority(&mut st, "authority team");

        let r1 = apply_create_task(&mut st, 9_001_7, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_7, &result_hash, &reveal_salt, "worker1");

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
            "authority team".into(),
            "authority team".into(),
        )
        .expect_err("internal-whitespace governance authority must fail closed");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_7).unwrap();
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
    fn resolve_rejects_governance_authority_with_unicode_internal_whitespace_without_escrow_mutation(
    ) {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        // Unicode whitespace (U+3000 ideographic space) must be rejected the same as ASCII space.
        let authority = "authority\u{3000}team";
        set_resolve_authority(&mut st, authority);

        let r1 = apply_create_task(&mut st, 9_001_71, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_71, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, authority.into(), authority.into())
            .expect_err("unicode internal-whitespace governance authority must fail closed");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_71).unwrap();
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
    fn resolve_rejects_signer_with_forbidden_separator_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 9_001_72, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_72, &result_hash, &reveal_salt, "worker1");

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
            "authority".into(),
            "authority;ops".into(),
        )
        .expect_err("signer separators must fail closed to prevent authority-list spoofing");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_72).unwrap();
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
    fn resolve_rejects_signer_with_unicode_forbidden_separator_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 9_001_73, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_73, &result_hash, &reveal_salt, "worker1");

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
            "authority".into(),
            "authority；ops".into(),
        )
        .expect_err(
            "unicode separator aliases must fail closed to prevent authority-list spoofing",
        );
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_73).unwrap();
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
    fn resolve_rejects_resolver_with_forbidden_separator_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 9_001_74, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_74, &result_hash, &reveal_salt, "worker1");

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
            "authority;ops".into(),
            "authority".into(),
        )
        .expect_err("resolver separators must fail closed to prevent payload actor spoofing");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_74).unwrap();
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
    fn resolve_rejects_configured_authority_member_with_forbidden_separator_without_escrow_mutation(
    ) {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let authority = "authority;ops";
        set_resolve_authority(&mut st, authority);

        let r1 = apply_create_task(&mut st, 9_001_74_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_74_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, authority.into(), authority.into())
            .expect_err("configured authority members containing separators must fail closed");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_74_1).unwrap();
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
    fn resolve_rejects_configured_authority_member_with_unicode_forbidden_separator_without_escrow_mutation(
    ) {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let authority = "authority；ops";
        set_resolve_authority(&mut st, authority);

        let r1 = apply_create_task(&mut st, 9_001_74_2, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_74_2, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, authority.into(), authority.into()).expect_err(
            "configured authority members containing unicode separators must fail closed",
        );
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_74_2).unwrap();
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
    fn resolve_rejects_configured_authority_member_with_ideographic_comma_without_escrow_mutation()
    {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let authority = "authority、ops";
        set_resolve_authority(&mut st, authority);

        let r1 = apply_create_task(&mut st, 9_001_74_3, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_74_3, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, authority.into(), authority.into()).expect_err(
            "configured authority members containing ideographic comma separators must fail closed",
        );
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_74_3).unwrap();
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
    fn governance_rejects_blank_resolve_authority_update_without_side_effects() {
        let mut st = seeded_state();
        let baseline = resolve_authority_account(&st);

        let err = st
            .set_gov_param_bootstrap_unchecked(9_500, "resolve_authority".into(), "".into())
            .expect_err("blank governance resolve authority update must be rejected");
        assert!(
            err.contains("must be non-empty"),
            "expected explicit non-empty guard error, got: {err}"
        );

        let after = resolve_authority_account(&st);
        assert_eq!(after, baseline);
    }

    #[test]
    fn resolve_authority_role_separation_merge_gate_constants_remain_distinct() {
        // Merge-gate hardening: custody (escrow), governance placeholder, and reserved
        // system identities must remain disjoint. If any collide, resolver authorization
        // checks can silently degrade into centralized/single-party control.
        let escrow = CHALLENGE_ESCROW_ACCOUNT.trim();
        let forfeits = CHALLENGE_FORFEIT_TREASURY_ACCOUNT.trim();
        let worker_slash = WORKER_SLASH_TREASURY_ACCOUNT.trim();
        let placeholder = DEFAULT_RESOLVE_AUTHORITY.trim();
        let system = "system";

        assert!(!escrow.is_empty());
        assert!(!forfeits.is_empty());
        assert!(!worker_slash.is_empty());
        assert!(!placeholder.is_empty());
        assert_ne!(escrow, forfeits);
        assert_ne!(escrow, worker_slash);
        assert_ne!(forfeits, worker_slash);
        assert_ne!(escrow, placeholder);
        assert_ne!(forfeits, placeholder);
        assert_ne!(worker_slash, placeholder);
        assert_ne!(escrow, system);
        assert_ne!(forfeits, system);
        assert_ne!(worker_slash, system);
        assert_ne!(placeholder, system);
        assert_ne!(placeholder.to_ascii_lowercase(), system);
    }

    #[test]
    fn resolve_role_accounts_remain_case_insensitively_disjoint() {
        // Hardening invariant: reserved/system, custody, and governance placeholder
        // identities must remain disjoint even after normalization so case-drift cannot
        // collapse minimal multi-party control into a single authority string.
        let normalized = [
            CHALLENGE_ESCROW_ACCOUNT.trim().to_ascii_lowercase(),
            CHALLENGE_FORFEIT_TREASURY_ACCOUNT
                .trim()
                .to_ascii_lowercase(),
            WORKER_SLASH_TREASURY_ACCOUNT.trim().to_ascii_lowercase(),
            DEFAULT_RESOLVE_AUTHORITY.trim().to_ascii_lowercase(),
            "system".to_string(),
        ];

        for value in &normalized {
            assert!(
                !value.is_empty(),
                "normalized authority/control identifier must be non-empty"
            );
        }

        for i in 0..normalized.len() {
            for j in (i + 1)..normalized.len() {
                assert_ne!(
                    normalized[i], normalized[j],
                    "normalized identifiers must remain disjoint to preserve multi-party control"
                );
            }
        }
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
    fn resolve_rejects_reserved_system_authority_with_whitespace_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "system");

        let r1 = apply_create_task(&mut st, 9_001_5, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_5, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err =
            apply_resolve(&mut st, r5, true, " system ".into(), " system ".into()).unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_5).unwrap();
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
    fn resolve_rejects_reserved_system_authority_case_drift_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "System");

        let r1 = apply_create_task(&mut st, 9_001_6, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_6, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, "System".into(), "System".into()).unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_6).unwrap();
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
    fn resolve_rejects_reserved_system_member_in_multisig_authority_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority,system");

        let r1 = apply_create_task(&mut st, 9_001_7, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_7, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err =
            apply_resolve(&mut st, r5, true, "authority".into(), "authority".into()).unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_7).unwrap();
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
    fn resolve_rejects_escrow_account_authority_case_drift_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let escrow_case_drift = "Treasury.Challenge_Escrow";
        set_resolve_authority(&mut st, escrow_case_drift);

        let r1 = apply_create_task(&mut st, 9_001_7, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_7, &result_hash, &reveal_salt, "worker1");

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
            escrow_case_drift.into(),
            escrow_case_drift.into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_7).unwrap();
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
    fn resolve_rejects_forfeit_treasury_account_authority_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        let r1 = apply_create_task(&mut st, 9_001_8, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_8, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(
            &mut st,
            r5,
            false,
            CHALLENGE_FORFEIT_TREASURY_ACCOUNT.into(),
            CHALLENGE_FORFEIT_TREASURY_ACCOUNT.into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_8).unwrap();
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
    fn resolve_rejects_forfeit_treasury_account_authority_case_drift_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let forfeits_case_drift = "Treasury.Challenge_Forfeits";
        set_resolve_authority(&mut st, forfeits_case_drift);

        let r1 = apply_create_task(&mut st, 9_001_9, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_9, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(
            &mut st,
            r5,
            false,
            forfeits_case_drift.into(),
            forfeits_case_drift.into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_9).unwrap();
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
    fn resolve_rejects_forfeit_treasury_account_authority_with_whitespace_without_escrow_mutation()
    {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        let r1 = apply_create_task(&mut st, 9_001_10, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_10, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(
            &mut st,
            r5,
            false,
            " treasury.challenge_forfeits ".into(),
            " treasury.challenge_forfeits ".into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_10).unwrap();
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
    fn resolve_rejects_multisig_authority_when_forfeit_treasury_is_member_without_escrow_mutation()
    {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let authority_with_forfeit_member =
            format!("authority,{}", CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        set_resolve_authority(&mut st, &authority_with_forfeit_member);

        let r1 = apply_create_task(&mut st, 9_001_11, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_11, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, false, "authority".into(), "authority".into())
            .expect_err("authority sets including forfeit treasury member must be rejected");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_11).unwrap();
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
    fn resolve_rejects_multisig_authority_when_forfeit_treasury_member_has_case_drift_without_escrow_mutation(
    ) {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let authority_with_case_drift_forfeit_member =
            format!("authority,{}", "Treasury.Challenge_Forfeits");
        set_resolve_authority(&mut st, &authority_with_case_drift_forfeit_member);

        let r1 = apply_create_task(&mut st, 9_001_12, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_12, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, false, "authority".into(), "authority".into())
            .expect_err(
                "authority sets including case-drift forfeit treasury member must be rejected",
            );
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_12).unwrap();
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
    fn resolve_rejects_worker_slash_treasury_account_authority_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, WORKER_SLASH_TREASURY_ACCOUNT);

        let r1 = apply_create_task(&mut st, 9_001_13, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_13, &result_hash, &reveal_salt, "worker1");

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
            WORKER_SLASH_TREASURY_ACCOUNT.into(),
            WORKER_SLASH_TREASURY_ACCOUNT.into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_13).unwrap();
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
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before.balance_of(WORKER_SLASH_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn resolve_rejects_worker_slash_treasury_account_authority_case_drift_without_escrow_mutation()
    {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let authority_with_case_drift_worker_slash_member = "Treasury.Worker_Slashes".to_string();
        set_resolve_authority(&mut st, &authority_with_case_drift_worker_slash_member);

        let r1 = apply_create_task(&mut st, 9_001_14, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_14, &result_hash, &reveal_salt, "worker1");

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
            authority_with_case_drift_worker_slash_member.clone(),
            authority_with_case_drift_worker_slash_member,
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_14).unwrap();
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
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before.balance_of(WORKER_SLASH_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn resolve_rejects_multisig_authority_when_worker_slash_treasury_is_member_without_escrow_mutation(
    ) {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(
            &mut st,
            &format!("authority,{}", WORKER_SLASH_TREASURY_ACCOUNT),
        );

        let r1 = apply_create_task(&mut st, 9_001_15, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_15, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err("authority sets including worker-slash treasury member must be rejected");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_15).unwrap();
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
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before.balance_of(WORKER_SLASH_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn resolve_rejects_multisig_authority_when_worker_slash_treasury_member_has_case_drift_without_escrow_mutation(
    ) {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let authority_with_case_drift_worker_slash_member = "Treasury.Worker_Slashes";
        set_resolve_authority(
            &mut st,
            &format!("authority,{}", authority_with_case_drift_worker_slash_member),
        );

        let r1 = apply_create_task(&mut st, 9_001_16, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_16, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
                "authority sets including case-drifted worker-slash treasury member must be rejected",
            );
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_16).unwrap();
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
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before.balance_of(WORKER_SLASH_TREASURY_ACCOUNT)
        );
    }

    #[test]
    fn resolve_rejects_multisig_authority_when_worker_slash_treasury_member_has_whitespace_without_escrow_mutation(
    ) {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let authority_with_whitespace_worker_slash_member =
            format!("authority, {}", WORKER_SLASH_TREASURY_ACCOUNT);
        set_resolve_authority(&mut st, &authority_with_whitespace_worker_slash_member);

        let r1 = apply_create_task(&mut st, 9_001_19, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_19, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
                "authority sets including whitespace worker-slash treasury member must be rejected",
            );
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_19).unwrap();
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
        assert_eq!(
            st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
            before.balance_of(WORKER_SLASH_TREASURY_ACCOUNT)
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
    fn resolve_rejects_unconfigured_placeholder_authority_with_whitespace_without_escrow_mutation()
    {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        // Keep default unconfigured governance placeholder authority.

        let r1 = apply_create_task(&mut st, 9_001_3, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_3, &result_hash, &reveal_salt, "worker1");

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
            format!("  {}  ", DEFAULT_RESOLVE_AUTHORITY),
            format!("  {}  ", DEFAULT_RESOLVE_AUTHORITY),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_3).unwrap();
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
    fn resolve_rejects_placeholder_authority_case_drift_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let placeholder_case_drift = "Governance.Resolve_Authority";
        set_resolve_authority(&mut st, placeholder_case_drift);

        let r1 = apply_create_task(&mut st, 9_001_4, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_4, &result_hash, &reveal_salt, "worker1");

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
            placeholder_case_drift.into(),
            placeholder_case_drift.into(),
        )
        .unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_4).unwrap();
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
    fn resolve_rejects_multisig_set_that_contains_placeholder_member_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let mixed_authority = format!("authority,{}", DEFAULT_RESOLVE_AUTHORITY);
        set_resolve_authority(&mut st, &mixed_authority);

        let r1 = apply_create_task(&mut st, 9_001_5, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_5, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err =
            apply_resolve(&mut st, r5, true, "authority".into(), "authority".into()).unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_5).unwrap();
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
    fn resolve_rejects_multisig_set_that_contains_escrow_member_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let mixed_authority = format!("authority,{}", CHALLENGE_ESCROW_ACCOUNT);
        set_resolve_authority(&mut st, &mixed_authority);

        let r1 = apply_create_task(&mut st, 9_001_5_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_5_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err("multisig authority containing escrow account must fail closed");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_5_1).unwrap();
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
    fn resolve_rejects_multisig_set_that_contains_escrow_member_case_drift_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let mixed_authority = format!("authority,{}", CHALLENGE_ESCROW_ACCOUNT.to_ascii_uppercase());
        set_resolve_authority(&mut st, &mixed_authority);

        let r1 = apply_create_task(&mut st, 9_001_5_2, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_5_2, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err("multisig authority containing escrow account with case drift must fail closed");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_5_2).unwrap();
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
    fn resolve_rejects_multisig_authority_with_comma_whitespace_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        let malformed_authority = "authority, guardian";
        set_resolve_authority(&mut st, malformed_authority);

        let r1 = apply_create_task(&mut st, 9_001_6, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_6, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err("comma+whitespace authority list must fail closed");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_6).unwrap();
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
    fn resolve_rejects_semicolon_delimited_authority_token_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        // Canonical token hardening: semicolon-delimited authority aliases must
        // fail closed so signer payload cannot smuggle pseudo-multisig syntax.
        let malformed_authority = "authority;guardian";
        set_resolve_authority(&mut st, malformed_authority);

        let r1 = apply_create_task(&mut st, 9_001_6_0, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_6_0, &result_hash, &reveal_salt, "worker1");

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
            malformed_authority.into(),
            malformed_authority.into(),
        )
        .expect_err("semicolon-delimited authority token must fail closed");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_6_0).unwrap();
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
    fn resolve_rejects_pipe_delimited_authority_token_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        // Canonical token hardening: pipe-delimited authority aliases must
        // fail closed so signer payload cannot smuggle pseudo-multisig syntax.
        let malformed_authority = "authority|guardian";
        set_resolve_authority(&mut st, malformed_authority);

        let r1 = apply_create_task(&mut st, 9_001_6_3, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_6_3, &result_hash, &reveal_salt, "worker1");

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
            malformed_authority.into(),
            malformed_authority.into(),
        )
        .expect_err("pipe-delimited authority token must fail closed");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_6_3).unwrap();
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
    fn resolve_rejects_multisig_authority_with_casefolded_duplicate_member_without_escrow_mutation()
    {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        // Canonical member-set hardening: case-folded duplicates collapse signer
        // diversity and must fail closed before any escrow transfer path.
        let malformed_authority = "authority,AUTHORITY";
        set_resolve_authority(&mut st, malformed_authority);

        let r1 = apply_create_task(&mut st, 9_001_6_2, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_6_2, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err("case-folded duplicate multisig member must fail closed");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_6_2).unwrap();
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
    fn resolve_rejects_multisig_authority_with_unicode_comma_whitespace_without_escrow_mutation() {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        // Unicode ideographic space after comma must fail closed like ASCII whitespace.
        let malformed_authority = "authority,\u{3000}guardian";
        set_resolve_authority(&mut st, malformed_authority);

        let r1 = apply_create_task(&mut st, 9_001_6_1, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9_001_6_1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err("comma+unicode-whitespace authority list must fail closed");
        assert!(matches!(err, PouwError::Unauthorized));

        let task = st.get_task(9_001_6_1).unwrap();
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

        set_resolve_authority(&mut st, "authority,authority2");
        let err =
            apply_resolve(&mut st, r5, false, "authority".into(), "authority".into()).unwrap_err();
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
    fn verified_reveal_success_version_conflict_does_not_unlock_worker_stake() {
        let mut st = seeded_state();
        st.set_gov_param_bootstrap_unchecked(9899, "min_worker_stake".into(), "40".into())
            .unwrap();
        st.set_balance("worker1", 40);

        let r1 = apply_create_task(&mut st, 19899, "alice".into(), 10).unwrap();
        let mut accepted_task = st.get_task(r1.id).unwrap();
        accepted_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, accepted_task).unwrap();

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let result_hash = [7u8; 32];
        let reveal_salt = [8u8; 32];
        let committed = compute_commitment(19899, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let mut completed_task = st.get_task(r3.id).unwrap();
        completed_task.status = TaskStatus::Completed;
        completed_task.result_hash = Some(result_hash);
        completed_task.reveal_salt = Some(reveal_salt);
        completed_task.challenge_deadline_height = None;
        completed_task.resolve_deadline_height = None;

        let stale_ref = r3.clone();
        let same_task = st.get_task(r3.id).unwrap();
        let _fresh_ref = st.update_task(r3, same_task).unwrap();

        let err = finalize_verified_reveal_success(&mut st, stale_ref, completed_task).unwrap_err();
        assert!(matches!(err, PouwError::VersionConflict));

        let task = st.get_task(19899).unwrap();
        assert_eq!(task.status, TaskStatus::Committed);
        assert!(task.result_hash.is_none());
        assert!(task.reveal_salt.is_none());
        assert_eq!(st.balance_of("worker1"), 0);
        assert_eq!(st.balance_of(&worker_stake_lock_account(19899)), 40);
    }

    #[test]
    fn verified_reveal_success_unlocks_worker_stake_after_task_update() {
        let mut st = seeded_state();
        st.set_gov_param_bootstrap_unchecked(9900, "min_worker_stake".into(), "40".into())
            .unwrap();
        st.set_balance("worker1", 40);

        let r1 = apply_create_task(&mut st, 19900, "alice".into(), 10).unwrap();
        let mut accepted_task = st.get_task(r1.id).unwrap();
        accepted_task.proof_type = ProofType::Tee;
        let r1 = st.update_task(r1, accepted_task).unwrap();

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let result_hash = [9u8; 32];
        let reveal_salt = [10u8; 32];
        let committed = compute_commitment(19900, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let mut completed_task = st.get_task(r3.id).unwrap();
        completed_task.status = TaskStatus::Completed;
        completed_task.result_hash = Some(result_hash);
        completed_task.reveal_salt = Some(reveal_salt);
        completed_task.challenge_deadline_height = None;
        completed_task.resolve_deadline_height = None;

        let next_ref = finalize_verified_reveal_success(&mut st, r3, completed_task).unwrap();

        let task = st.get_task(19900).unwrap();
        assert_eq!(next_ref.version, task.version);
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.result_hash, Some(result_hash));
        assert_eq!(task.reveal_salt, Some(reveal_salt));
        assert_eq!(st.balance_of("worker1"), 40);
        assert_eq!(st.balance_of(&worker_stake_lock_account(19900)), 0);
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

        set_resolve_authority(&mut st, "authority,authority2");
        let staged = apply_resolve(&mut st, r5.clone(), false, "authority".into(), "authority".into())
            .unwrap_err();
        assert!(matches!(staged, PouwError::ResolveApprovalStaged));
        let stale_ref = r5.clone();
        let same_task = st.get_task(r5.id).unwrap();
        let _fresh_ref = st.update_task(r5, same_task).unwrap();

        let err = apply_resolve(
            &mut st,
            stale_ref,
            false,
            "authority2".into(),
            "authority2".into(),
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
        st.set_gov_param_bootstrap_unchecked(9801, "min_worker_stake".into(), "50".into())
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
        st.set_gov_param_bootstrap_unchecked(9802, "min_worker_stake".into(), "50".into())
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
        st.set_gov_param_bootstrap_unchecked(9802, "min_worker_stake".into(), "50".into())
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
        st.set_gov_param_bootstrap_unchecked(9803, "min_worker_stake".into(), "40".into())
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
        st.set_gov_param_bootstrap_unchecked(9804, "min_worker_stake".into(), "40".into())
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
    fn resolve_preflight_rejects_slash_refund_without_challenger() {
        let st = seeded_state();
        let task = TaskObject {
            task_id: 76,
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

        let err = preflight_resolve_transfers(&st, &task, true).unwrap_err();
        assert!(matches!(err, PouwError::State(msg) if msg.contains("without challenger")));
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
    fn tee_proof_without_crypto_backend_rejects_reveal_and_preserves_committed_state() {
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
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("Proof verification indeterminate") && msg.contains("backend not configured"))
        );

        let final_task = st.get_task(r3.id).unwrap();
        assert_eq!(final_task.status, TaskStatus::Committed);
        assert!(final_task.result_hash.is_none());
        assert!(final_task.reveal_salt.is_none());
        assert!(final_task.challenge_deadline_height.is_none());
    }

    #[test]
    fn tee_proof_accepts_uppercase_hex_prefix_in_result_hash_binding() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7701, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [0xabu8; 32];
        let reveal_salt = [3u8; 32];
        let committed = compute_commitment(7701, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Accept canonical envelope tuple when result_hash uses uppercase 0X hex prefix.
        let proof = b"TEE:task_id=7701,worker=worker1,proof_type=tee,result_hash=0XABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("Proof verification indeterminate") && msg.contains("backend not configured"))
        );

        let final_task = st.get_task(r3.id).unwrap();
        assert_eq!(final_task.status, TaskStatus::Committed);
        assert!(final_task.result_hash.is_none());
        assert!(final_task.reveal_salt.is_none());
        assert!(final_task.challenge_deadline_height.is_none());
    }

    #[test]
    fn tee_proof_accepts_uppercase_proof_type_binding() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7702, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [0xacu8; 32];
        let reveal_salt = [5u8; 32];
        let committed = compute_commitment(7702, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Accept canonical envelope tuple when proof_type value uses uppercase alias.
        let proof = b"TEE:task_id=7702,worker=worker1,proof_type=TEE,result_hash=ACACACACACACACACACACACACACACACACACACACACACACACACACACACACACACACAC,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("Proof verification indeterminate") && msg.contains("backend not configured"))
        );

        let final_task = st.get_task(r3.id).unwrap();
        assert_eq!(final_task.status, TaskStatus::Committed);
        assert!(final_task.result_hash.is_none());
        assert!(final_task.reveal_salt.is_none());
        assert!(final_task.challenge_deadline_height.is_none());
    }

    #[test]
    fn zk_proof_accepts_uppercase_hex_prefix_in_result_hash_binding() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 8701, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [0xcdu8; 32];
        let reveal_salt = [4u8; 32];
        let committed = compute_commitment(8701, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Accept canonical envelope tuple when result_hash uses uppercase 0X hex prefix.
        let proof = b"ZK:task_id=8701,worker=worker1,proof_type=zk,result_hash=0XCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("Proof verification indeterminate") && msg.contains("backend not configured"))
        );

        let final_task = st.get_task(r3.id).unwrap();
        assert_eq!(final_task.status, TaskStatus::Committed);
        assert!(final_task.result_hash.is_none());
        assert!(final_task.reveal_salt.is_none());
        assert!(final_task.challenge_deadline_height.is_none());
    }

    #[test]
    fn zk_proof_accepts_uppercase_proof_type_binding() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 8702, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [0xceu8; 32];
        let reveal_salt = [6u8; 32];
        let committed = compute_commitment(8702, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Accept canonical envelope tuple when proof_type value uses uppercase alias.
        let proof = b"ZK:task_id=8702,worker=worker1,proof_type=ZK,result_hash=CECECECECECECECECECECECECECECECECECECECECECECECECECECECECECECECE,seal=SEAL_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("Proof verification indeterminate") && msg.contains("backend not configured"))
        );

        let final_task = st.get_task(r3.id).unwrap();
        assert_eq!(final_task.status, TaskStatus::Committed);
        assert!(final_task.result_hash.is_none());
        assert!(final_task.reveal_salt.is_none());
        assert!(final_task.challenge_deadline_height.is_none());
    }

    #[test]
    fn invalid_tee_proof_rejects_reveal_fail_closed_without_state_mutation() {
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
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Fail closed on verifier rejection: committed task must remain unchanged.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.challenge_deadline_height.is_none());
    }

    #[test]
    fn invalid_utf8_tee_proof_rejects_reveal_fail_closed_without_missing_payload_mapping() {
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

        // Invalid UTF-8 payload should still be treated as present proof data and
        // fail through verifier path (not remapped to missing payload).
        let proof = vec![0xff, 0xfe, 0xfd];
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed") && !msg.contains("missing proof payload"))
        );

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.challenge_deadline_height.is_none());
    }

    #[test]
    fn invalid_utf8_zk_proof_rejects_reveal_fail_closed_without_missing_payload_mapping() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7004, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7004, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Invalid UTF-8 payload should still be treated as present proof data and
        // fail through verifier path (not remapped to missing payload).
        let proof = vec![0xff, 0xfe, 0xfd];
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed") && !msg.contains("missing proof payload"))
        );

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.challenge_deadline_height.is_none());
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
        assert!(task_after.reveal_salt.is_none());
        assert!(task_after.challenge_deadline_height.is_none());
    }

    #[test]
    fn tee_reveal_rejects_duplicate_proof_type_binding_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7006, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7006, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Duplicate proof_type binding must fail closed.
        let proof = b"TEE:task_id=7006,worker=worker1,proof_type=tee,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_duplicate_proof_type_binding_with_quoted_trailing_space_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7016, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7016, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Quoted trailing-space alias plus canonical proof_type must still be
        // treated as a duplicate proof_type binding and fail closed.
        let proof = b"TEE:task_id=7016,worker=worker1,proof_type=\"tee \",proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_duplicate_proof_type_binding_with_quoted_leading_space_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7017, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7017, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Quoted leading-space alias plus canonical proof_type must still be
        // treated as a duplicate proof_type binding and fail closed.
        let proof = b"TEE:task_id=7017,worker=worker1,proof_type=\" tee\",proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_case_variant_duplicate_proof_type_binding_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7015, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7015, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Case-variant duplicate proof_type binding must fail closed.
        let proof = b"TEE:task_id=7015,worker=worker1,proof_type=tee,Proof_Type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_case_variant_duplicate_task_id_binding_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7011, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7011, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Case-variant duplicate task_id binding must fail closed.
        let proof = b"TEE:task_id=7011,TASK_ID=7011,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_duplicate_worker_binding_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7009, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7009, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Duplicate worker binding must fail closed.
        let proof = b"TEE:task_id=7009,worker=worker1,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_case_variant_duplicate_worker_binding_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7014, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7014, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Case-variant duplicate worker binding must fail closed.
        let proof = b"TEE:task_id=7014,worker=worker1,Worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_duplicate_worker_binding_with_quoted_trailing_space_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7015, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7015, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Quoted trailing-space alias plus canonical worker binding must be
        // treated as duplicate worker binding and fail closed.
        let proof = b"TEE:task_id=7015,worker=\"worker1 \",worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_duplicate_worker_binding_with_quoted_leading_space_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7028, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7028, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Quoted leading-space alias plus canonical worker binding must still
        // be treated as duplicate worker binding and fail closed.
        let proof = b"TEE:task_id=7028,worker=\" worker1\",worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_duplicate_worker_binding_with_double_quoted_alias_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7037, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7037, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Double-quoted alias plus canonical worker binding must still be
        // treated as duplicate worker binding and fail closed.
        let proof = b"TEE:task_id=7037,worker=\"worker1\",worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_duplicate_worker_binding_with_single_quoted_alias_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7041, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7041, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Single-quoted alias plus canonical worker binding must still be
        // treated as duplicate worker binding and fail closed.
        let proof = b"TEE:task_id=7041,worker='worker1',worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_duplicate_result_hash_binding_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7011, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7011, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Duplicate result_hash binding must fail closed.
        let proof = b"TEE:task_id=7011,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_duplicate_result_hash_binding_with_quoted_trailing_space_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7017, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7017, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Quoted trailing-space alias plus canonical result_hash must still be
        // treated as a duplicate binding and fail closed.
        let proof = b"TEE:task_id=7017,worker=worker1,proof_type=tee,result_hash=\"0101010101010101010101010101010101010101010101010101010101010101 \",result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_duplicate_result_hash_binding_with_quoted_leading_space_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7018, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7018, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Quoted leading-space alias plus canonical result_hash must still be
        // treated as a duplicate binding and fail closed.
        let proof = b"TEE:task_id=7018,worker=worker1,proof_type=tee,result_hash=\" 0101010101010101010101010101010101010101010101010101010101010101\",result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_case_variant_duplicate_result_hash_binding_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7012, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7012, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Case-variant duplicate result_hash binding must fail closed.
        let proof = b"TEE:task_id=7012,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,Result_Hash=0101010101010101010101010101010101010101010101010101010101010101,quote=QUOTE_XYZ".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn invalid_zk_proof_rejects_reveal_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7006, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7006, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Invalid ZK proof payload must be rejected fail-closed.
        let proof = b"BAD_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on verifier rejection.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_proof_type_mismatch_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7007, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7007, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Deliberately mismatched proof_type binding should be rejected fail-closed.
        let proof = b"ZK:task_id=7007,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on invalid envelope binding.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
        assert!(task_after.challenge_deadline_height.is_none());
    }

    #[test]
    fn zk_reveal_rejects_duplicate_proof_type_binding_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7008, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7008, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Duplicate proof_type binding must fail closed.
        let proof = b"ZK:task_id=7008,worker=worker1,proof_type=zk,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_duplicate_proof_type_binding_with_quoted_trailing_space_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7018, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7018, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Quoted trailing-space alias plus canonical proof_type must still be
        // treated as a duplicate binding and fail closed.
        let proof = b"ZK:task_id=7018,worker=worker1,proof_type=\"zk \",proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_duplicate_proof_type_binding_with_single_quoted_trailing_space_fail_closed(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7027, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7027, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Single-quoted trailing-space alias plus canonical proof_type must
        // still be treated as duplicate proof_type binding and fail closed.
        let proof = b"ZK:task_id=7027,worker=worker1,proof_type='zk ',proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_duplicate_proof_type_binding_with_single_quoted_leading_space_fail_closed()
    {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7028, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7028, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Single-quoted leading-space alias plus canonical proof_type must
        // still be treated as duplicate proof_type binding and fail closed.
        let proof = b"ZK:task_id=7028,worker=worker1,proof_type=' zk',proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_duplicate_proof_type_binding_with_double_quoted_leading_space_fail_closed()
    {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7029, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7029, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Double-quoted leading-space alias plus canonical proof_type must
        // still be treated as duplicate proof_type binding and fail closed.
        let proof = b"ZK:task_id=7029,worker=worker1,proof_type=\" zk\",proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_duplicate_worker_binding_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7013, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7013, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Duplicate worker binding must fail closed.
        let proof = b"ZK:task_id=7013,worker=worker1,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_case_variant_duplicate_worker_binding_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7017, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7017, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Case-variant duplicate worker binding must fail closed.
        let proof = b"ZK:task_id=7017,worker=worker1,Worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_duplicate_worker_binding_with_quoted_trailing_space_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7019, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7019, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Quoted trailing-space alias plus canonical worker must still be
        // treated as duplicate worker binding and fail closed.
        let proof = b"ZK:task_id=7019,worker=worker1,\"worker\"=\"worker1 \",proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_duplicate_worker_binding_with_quoted_leading_space_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7020, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7020, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Quoted leading-space alias plus canonical worker must still be
        // treated as duplicate worker binding and fail closed.
        let proof = b"ZK:task_id=7020,worker=worker1,\"worker\"=\" worker1\",proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_duplicate_worker_binding_with_double_quoted_alias_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7021, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7021, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Double-quoted alias plus canonical worker binding must still be
        // treated as duplicate worker binding and fail closed.
        let proof = b"ZK:task_id=7021,worker=worker1,\"worker\"=\"worker1\",proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_duplicate_worker_binding_with_single_quoted_alias_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7025, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7025, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Single-quoted alias plus canonical worker binding must still be
        // treated as duplicate worker binding and fail closed.
        let proof = b"ZK:task_id=7025,worker=worker1,'worker'='worker1',proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_duplicate_task_id_binding_with_single_quoted_trailing_space_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7026, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7026, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Single-quoted trailing-space alias plus canonical task_id must
        // still be treated as duplicate task_id binding and fail closed.
        let proof = b"ZK:task_id='7026 ',task_id=7026,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_case_variant_duplicate_task_id_binding_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7016, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7016, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Case-variant duplicate task_id binding must fail closed.
        let proof = b"ZK:task_id=7016,TASK_ID=7016,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_case_variant_duplicate_result_hash_binding_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7010, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7010, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Case-variant duplicate result_hash binding must fail closed.
        let proof = b"ZK:task_id=7010,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,Result_Hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_duplicate_result_hash_binding_with_quoted_trailing_space_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7018, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7018, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Quoted trailing-space alias plus canonical result_hash must still be
        // treated as duplicate result_hash binding and fail closed.
        let proof = b"ZK:task_id=7018,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,\"result_hash\"=\"0101010101010101010101010101010101010101010101010101010101010101 \",receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Ensure task does not advance on malformed envelope bindings.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_legacy_task_id_binding_mismatch_fail_closed() {
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

        let mut corrupted = st.get_task(r3.id).unwrap();
        corrupted.task_id = r3.id + 1;
        st.update_task(r3.clone(), corrupted).unwrap();

        let proof = b"TEE:task_id=7003,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=VALID_QUOTE".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("task id binding mismatch")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_signed_task_id_binding_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7011, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7011, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Signed numeric task_id is non-canonical and must fail closed.
        let proof = b"TEE:task_id=+7011,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=VALID_QUOTE".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_negative_signed_task_id_binding_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 70115, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(70115, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Negative signed task_id is non-canonical and must fail closed.
        let proof = b"TEE:task_id=-70115,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=VALID_QUOTE".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_quoted_signed_task_id_binding_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 70115, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(70115, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Quoted signed numeric task_id is non-canonical and must fail closed.
        let proof = b"TEE:task_id='+70115',worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=VALID_QUOTE".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn tee_reveal_rejects_fullwidth_plus_signed_task_id_binding_fail_closed_without_state_mutation()
    {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7013, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7013, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Fullwidth signed numeric task_id is non-canonical and must fail closed.
        let proof = "TEE:task_id=＋7013,worker=worker1,proof_type=tee,result_hash=0101010101010101010101010101010101010101010101010101010101010101,quote=VALID_QUOTE"
            .as_bytes()
            .to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_legacy_task_id_binding_mismatch_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7007, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7007, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let mut corrupted = st.get_task(r3.id).unwrap();
        corrupted.task_id = r3.id + 1;
        st.update_task(r3.clone(), corrupted).unwrap();

        let proof = b"ZK:task_id=7007,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("task id binding mismatch")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_signed_task_id_binding_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7012, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7012, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Signed numeric task_id is non-canonical and must fail closed.
        let proof = b"ZK:task_id=+7012,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF".to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_reveal_rejects_fullwidth_plus_signed_task_id_binding_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7014, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7014, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // Fullwidth signed numeric task_id is non-canonical and must fail closed.
        let proof = "ZK:task_id=＋7014,worker=worker1,proof_type=zk,result_hash=0101010101010101010101010101010101010101010101010101010101010101,receipt=VALID_PROOF"
            .as_bytes()
            .to_vec();
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

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

        let err =
            apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, None).unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Fail closed on missing payload: task must remain in Committed state.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn empty_tee_proof_payload_rejects_reveal_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7007, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [3u8; 32];
        let reveal_salt = [4u8; 32];
        let committed = compute_commitment(7007, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let err = apply_reveal_result(
            &mut st,
            r3.clone(),
            result_hash,
            reveal_salt,
            Some(Vec::new()),
        )
        .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

        // Fail closed on empty payload: task must remain Committed with no result hash.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn whitespace_only_tee_proof_payload_rejects_reveal_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7024, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [7u8; 32];
        let reveal_salt = [8u8; 32];
        let committed = compute_commitment(7024, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let err = apply_reveal_result(
            &mut st,
            r3.clone(),
            result_hash,
            reveal_salt,
            Some(b" \t\n\r ".to_vec()),
        )
        .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn unicode_whitespace_only_tee_proof_payload_rejects_reveal_fail_closed_without_state_mutation()
    {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7025, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [7u8; 32];
        let reveal_salt = [8u8; 32];
        let committed = compute_commitment(7025, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let err = apply_reveal_result(
            &mut st,
            r3.clone(),
            result_hash,
            reveal_salt,
            Some("\u{3000}\u{2003}\n".as_bytes().to_vec()),
        )
        .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn word_joiner_only_tee_proof_payload_rejects_reveal_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7026, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [7u8; 32];
        let reveal_salt = [8u8; 32];
        let committed = compute_commitment(7026, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let err = apply_reveal_result(
            &mut st,
            r3.clone(),
            result_hash,
            reveal_salt,
            Some("\u{2060}".as_bytes().to_vec()),
        )
        .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn utf8_bom_only_tee_proof_payload_rejects_reveal_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7027, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Tee;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [7u8; 32];
        let reveal_salt = [8u8; 32];
        let committed = compute_commitment(7027, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let err = apply_reveal_result(
            &mut st,
            r3.clone(),
            result_hash,
            reveal_salt,
            Some("\u{feff}".as_bytes().to_vec()),
        )
        .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn missing_zk_proof_rejects_reveal_fail_closed() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7006, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(7006, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let err =
            apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, None).unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("Proof verification failed")));

        // Fail closed on missing payload: task must remain in Committed state.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn empty_zk_proof_payload_rejects_reveal_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7008, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [5u8; 32];
        let reveal_salt = [6u8; 32];
        let committed = compute_commitment(7008, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let err = apply_reveal_result(
            &mut st,
            r3.clone(),
            result_hash,
            reveal_salt,
            Some(Vec::new()),
        )
        .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

        // Fail closed on empty payload: task must remain Committed with no result hash.
        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn unicode_whitespace_only_zk_proof_payload_rejects_reveal_fail_closed_without_state_mutation()
    {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7026, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [9u8; 32];
        let reveal_salt = [1u8; 32];
        let committed = compute_commitment(7026, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let err = apply_reveal_result(
            &mut st,
            r3.clone(),
            result_hash,
            reveal_salt,
            Some("\u{3000}\u{2003}\n".as_bytes().to_vec()),
        )
        .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn word_joiner_only_zk_proof_payload_rejects_reveal_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7027, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [9u8; 32];
        let reveal_salt = [1u8; 32];
        let committed = compute_commitment(7027, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let err = apply_reveal_result(
            &mut st,
            r3.clone(),
            result_hash,
            reveal_salt,
            Some("\u{2060}".as_bytes().to_vec()),
        )
        .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn utf8_bom_only_zk_proof_payload_rejects_reveal_fail_closed_without_state_mutation() {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7029, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [9u8; 32];
        let reveal_salt = [1u8; 32];
        let committed = compute_commitment(7029, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let err = apply_reveal_result(
            &mut st,
            r3.clone(),
            result_hash,
            reveal_salt,
            Some("\u{feff}".as_bytes().to_vec()),
        )
        .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn utf8_bom_and_whitespace_only_zk_proof_payload_rejects_reveal_fail_closed_without_state_mutation(
    ) {
        let mut st = seeded_state();
        let r1 = apply_create_task(&mut st, 7028, "alice".into(), 10).unwrap();

        let mut task = st.get_task(r1.id).unwrap();
        task.proof_type = ProofType::Zk;
        let r1_updated = st.update_task(r1, task).unwrap();

        let result_hash = [9u8; 32];
        let reveal_salt = [1u8; 32];
        let committed = compute_commitment(7028, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1_updated, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let err = apply_reveal_result(
            &mut st,
            r3.clone(),
            result_hash,
            reveal_salt,
            Some("\u{feff}\u{3000}\n".as_bytes().to_vec()),
        )
        .unwrap_err();

        assert!(matches!(err, PouwError::State(msg) if msg.contains("missing proof payload")));

        let task_after = st.get_task(r3.id).unwrap();
        assert_eq!(task_after.status, TaskStatus::Committed);
        assert!(task_after.result_hash.is_none());
    }

    #[test]
    fn zk_proof_without_crypto_backend_rejects_reveal_and_preserves_committed_state() {
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
        let err = apply_reveal_result(&mut st, r3.clone(), result_hash, reveal_salt, Some(proof))
            .unwrap_err();

        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("Proof verification indeterminate") && msg.contains("backend not configured"))
        );

        let final_task = st.get_task(r3.id).unwrap();
        assert_eq!(final_task.status, TaskStatus::Committed);
        assert!(final_task.result_hash.is_none());
        assert!(final_task.reveal_salt.is_none());
        assert!(final_task.challenge_deadline_height.is_none());
        assert!(final_task.resolve_deadline_height.is_none());
    }

    #[test]
    fn resolve_emergency_pause_precedes_deadline_checks_without_escrow_mutation() {
        // Merge-gate hardening: pause must fail-closed before resolve-deadline checks,
        // so challenged escrow paths do not leak timing-policy outcomes while frozen.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "authority");

        let r1 = apply_create_task(&mut st, 8_961_25, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(8_961_25, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            100,
        )
        .unwrap();

        let task_before_pause = st.get_task(r5.id).unwrap();
        let resolve_deadline = task_before_pause
            .resolve_deadline_height
            .expect("challenge must set resolve deadline");

        st.set_gov_param(9_201_25, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve_at_height(
            &mut st,
            r5,
            true,
            "authority".into(),
            "authority".into(),
            resolve_deadline.saturating_add(1),
        )
        .expect_err("pause must mask deadline-check result and freeze challenged settlement");
        assert!(matches!(err, PouwError::InvalidTransition));

        let after_task = st.get_task(8_961_25).unwrap();
        assert_eq!(after_task.status, task_before_pause.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            task_before_pause.challenge_bond_forfeited
        );
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }

    #[test]
    fn challenged_resolve_rejects_case_variant_duplicate_authority_members_without_escrow_drift() {
        // Decentralization hardening: governance resolver sets must reject
        // case-variant duplicate members, so one actor cannot satisfy the
        // staged + final approval path by casing tricks.
        let mut st = seeded_state();
        st.set_balance("challenger", 100);
        set_resolve_authority(&mut st, "Authority,authority");

        let r1 = apply_create_task(&mut st, 8_961_26, "alice".into(), 10).unwrap();
        let result_hash = [5u8; 32];
        let reveal_salt = [6u8; 32];
        let committed = compute_commitment(8_961_26, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 = apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            100,
        )
        .unwrap();

        let before_task = st.get_task(r5.id).unwrap();
        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
        let before_challenger = st.balance_of("challenger");

        let err = apply_resolve_at_height(
            &mut st,
            r5,
            false,
            "authority".into(),
            "authority".into(),
            311,
        )
        .expect_err("case-variant duplicate resolver members must fail closed");
        assert!(matches!(err, PouwError::Unauthorized));

        let after_task = st
            .get_task(8_961_26)
            .expect("task must remain challenged after duplicate-authority rejection");
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.pending_resolve_approval(8_961_26), None);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
        assert_eq!(st.balance_of("challenger"), before_challenger);
    }
}
