use thiserror::Error;
use trnm_state::StateStore;

use crate::verification::registry::VerifierRegistry;

pub(crate) fn get_default_registry() -> VerifierRegistry {
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

pub(crate) fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
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

pub(crate) fn map_state_err(err: String) -> PouwError {
    if contains_ascii_case_insensitive(&err, "version conflict") {
        PouwError::VersionConflict
    } else {
        PouwError::State(err)
    }
}

pub(crate) const DEFAULT_ASSIGNMENT_WINDOW_BLOCKS: u64 = 20;
pub(crate) const DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 20;
pub(crate) const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 100;
pub(crate) const DEFAULT_LLM_METER_PROMPT_TOKEN_WEIGHT: u128 = 1;
pub(crate) const DEFAULT_LLM_METER_GENERATED_TOKEN_WEIGHT: u128 = 1;
pub(crate) const DEFAULT_LLM_METER_DECODE_STEP_WEIGHT: u128 = 1;
pub(crate) const DEFAULT_LLM_METER_KV_BYTE_WEIGHT: u128 = 0;
pub(crate) const DEFAULT_LLM_METER_MIN_ACCEPT_WORK_UNITS: u128 = 0;
pub(crate) const DEFAULT_LLM_METER_CHALLENGE_SUCCESS_BOUNTY_PER_WORK_UNIT_NUM: u128 = 0;
pub(crate) const DEFAULT_LLM_METER_CHALLENGE_SUCCESS_BOUNTY_PER_WORK_UNIT_DEN: u128 = 1;
pub(crate) const DEFAULT_LLM_METER_WORKER_COMPLETION_BONUS_PER_WORK_UNIT_NUM: u128 = 0;
pub(crate) const DEFAULT_LLM_METER_WORKER_COMPLETION_BONUS_PER_WORK_UNIT_DEN: u128 = 1;
pub(crate) const DEFAULT_LLM_METER_WORKER_SLASH_REBATE_PER_WORK_UNIT_NUM: u128 = 0;
pub(crate) const DEFAULT_LLM_METER_WORKER_SLASH_REBATE_PER_WORK_UNIT_DEN: u128 = 1;
pub(crate) const CURRENT_LLM_METER_POLICY_SNAPSHOT_VERSION: u8 = 1;
pub(crate) const DEFAULT_CHALLENGE_MIN_BOND: u128 = 10;
pub(crate) const DEFAULT_CHALLENGE_MIN_BOND_BOUNTY_BPS: u128 = 500;
pub(crate) const DEFAULT_CHALLENGE_MIN_BOND_WORKER_STAKE_BPS: u128 = 0;
pub(crate) const DEFAULT_MIN_WORKER_STAKE: u128 = 1;
pub(crate) const DEFAULT_CHALLENGE_SUCCESS_BOUNTY: u128 = 1;
pub(crate) const DEFAULT_UNRESOLVED_CHALLENGE_SLASH_ON_TIMEOUT: bool = false;
pub(crate) const BPS_DENOMINATOR: u128 = 10_000;
pub(crate) const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
pub(crate) const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";
pub(crate) const WORKER_SLASH_TREASURY_ACCOUNT: &str = "treasury.worker_slashes";
pub(crate) const DEFAULT_RESOLVE_AUTHORITY: &str = "governance.resolve_authority";
pub(crate) const MIN_CHALLENGE_WINDOW_BLOCKS: u64 = 1;

pub(crate) fn worker_stake_lock_account(task_id: u64) -> String {
    format!("worker_stake_lock.{}", task_id)
}

pub(crate) fn ensure_balance_at_least(
    st: &StateStore,
    account: &str,
    amount: u128,
) -> Result<(), PouwError> {
    let cur = st.balance_of(account);
    if cur < amount {
        return Err(PouwError::State(format!(
            "insufficient balance: address={}, have={}, need={}",
            account, cur, amount
        )));
    }
    Ok(())
}

pub(crate) fn require_deadline_exceeded(
    deadline: Option<u64>,
    current_height: u64,
) -> Result<(), PouwError> {
    let deadline = deadline.ok_or(PouwError::InvalidTransition)?;
    if current_height <= deadline {
        return Err(PouwError::InvalidTransition);
    }
    Ok(())
}

pub(crate) fn reject_if_deadline_exceeded(
    deadline: Option<u64>,
    current_height: u64,
) -> Result<(), PouwError> {
    let deadline = deadline.ok_or(PouwError::InvalidTransition)?;
    if current_height > deadline {
        return Err(PouwError::DeadlineExceeded);
    }
    Ok(())
}

pub(crate) fn reject_if_deadline_exceeded_optional(
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

pub(crate) fn is_ignorable_proof_payload_char(c: char) -> bool {
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

pub(crate) fn proof_payload_is_blank(proof_payload: &[u8]) -> bool {
    proof_payload.is_empty()
        || proof_payload.iter().all(|b| b.is_ascii_whitespace())
        || std::str::from_utf8(proof_payload)
            .map(|payload| {
                payload
                    .trim_matches(is_ignorable_proof_payload_char)
                    .is_empty()
            })
            .unwrap_or(false)
}

pub(crate) fn normalize_hex_string(raw: &str) -> String {
    raw.trim()
        .strip_prefix("0x")
        .unwrap_or(raw.trim())
        .to_ascii_lowercase()
}
