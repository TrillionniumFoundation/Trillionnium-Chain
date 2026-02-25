use sha2::{Digest, Sha256};
use thiserror::Error;
use trnm_state::StateStore;
use trnm_types::{Hash32, ObjectRef, TaskObject, TaskStatus};

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

fn map_state_err(err: String) -> PouwError {
    if err.contains("version conflict") {
        PouwError::VersionConflict
    } else {
        PouwError::State(err)
    }
}

const DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 20;
const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 20;
const DEFAULT_CHALLENGE_MIN_BOND: u128 = 10;
const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";

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
    let task = TaskObject {
        task_id,
        creator,
        bounty,
        status: TaskStatus::Open,
        worker: None,
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: None,
        reveal_deadline_height: None,
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
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    if task.status != TaskStatus::Open {
        return Err(PouwError::InvalidTransition);
    }
    task.status = TaskStatus::Assigned;
    task.worker = Some(worker);
    st.update_task(task_ref, task).map_err(map_state_err)
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
) -> Result<ObjectRef, PouwError> {
    apply_reveal_result_at_height(st, task_ref, result_hash, reveal_salt, 0)
}

pub fn apply_reveal_result_at_height(
    st: &mut StateStore,
    task_ref: ObjectRef,
    result_hash: Hash32,
    reveal_salt: [u8; 32],
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
    let committed = task.committed_hash.ok_or(PouwError::MissingCommitment)?;
    let expected = compute_commitment(task.task_id, &result_hash, &reveal_salt, &worker);
    if expected != committed {
        return Err(PouwError::CommitmentMismatch);
    }

    task.status = TaskStatus::Revealed;
    task.result_hash = Some(result_hash);
    task.reveal_salt = Some(reveal_salt);
    st.update_task(task_ref, task).map_err(map_state_err)
}

pub fn apply_challenge(
    st: &mut StateStore,
    task_ref: ObjectRef,
    challenger: String,
    challenge_bond: u128,
) -> Result<ObjectRef, PouwError> {
    apply_challenge_at_height(st, task_ref, challenger, challenge_bond, 0)
}

pub fn apply_challenge_at_height(
    st: &mut StateStore,
    task_ref: ObjectRef,
    challenger: String,
    challenge_bond: u128,
    current_height: u64,
) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    if task.status != TaskStatus::Revealed {
        return Err(PouwError::InvalidTransition);
    }

    let min_bond = st
        .gov_param_u128("challenge_min_bond")
        .unwrap_or(DEFAULT_CHALLENGE_MIN_BOND);
    if challenge_bond < min_bond {
        return Err(PouwError::InsufficientStake);
    }

    let challenge_window_blocks = st
        .gov_param_u64("challenge_window_blocks")
        .unwrap_or(DEFAULT_CHALLENGE_WINDOW_BLOCKS);

    if st.balance_of(&challenger) < challenge_bond {
        return Err(PouwError::InsufficientStake);
    }

    task.status = TaskStatus::Challenged;
    task.challenged_at_height = Some(current_height);
    task.resolve_deadline_height = Some(current_height.saturating_add(challenge_window_blocks));
    task.challenge_bond = Some(challenge_bond);
    task.challenger = Some(challenger.clone());
    task.challenge_bond_forfeited = None;
    let next_ref = st.update_task(task_ref, task).map_err(map_state_err)?;

    // Apply corresponding balance movement only after task object commit succeeds.
    st.debit_balance(&challenger, challenge_bond)
        .map_err(|_| PouwError::InsufficientStake)?;
    st.credit_balance(CHALLENGE_ESCROW_ACCOUNT, challenge_bond);

    Ok(next_ref)
}

pub fn apply_resolve(
    st: &mut StateStore,
    task_ref: ObjectRef,
    slash_worker: bool,
) -> Result<ObjectRef, PouwError> {
    apply_resolve_at_height(st, task_ref, slash_worker, 0)
}

pub fn apply_resolve_at_height(
    st: &mut StateStore,
    task_ref: ObjectRef,
    slash_worker: bool,
    current_height: u64,
) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    if task.status != TaskStatus::Challenged {
        return Err(PouwError::InvalidTransition);
    }
    if let Some(deadline) = task.resolve_deadline_height {
        if current_height > deadline {
            return Err(PouwError::DeadlineExceeded);
        }
    }
    task.status = if slash_worker {
        TaskStatus::Slashed
    } else {
        TaskStatus::Completed
    };
    if let Some(bond) = task.challenge_bond {
        ensure_balance_at_least(st, CHALLENGE_ESCROW_ACCOUNT, bond)?;
        task.challenge_bond_forfeited = Some(!slash_worker);
    }
    let next_ref = st.update_task(task_ref, task.clone()).map_err(map_state_err)?;

    if let Some(bond) = task.challenge_bond {
        // Funds always flow out of escrow at resolve for auditability.
        st.debit_balance(CHALLENGE_ESCROW_ACCOUNT, bond)
            .map_err(PouwError::State)?;
        if slash_worker {
            // Challenge succeeds: return challenger bond.
            if let Some(challenger) = task.challenger {
                st.credit_balance(&challenger, bond);
            }
        } else {
            // Challenge fails: forfeit bond into treasury pool.
            st.credit_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, bond);
        }
    }

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

    match task.status {
        TaskStatus::Committed => {
            let deadline = task
                .reveal_deadline_height
                .ok_or(PouwError::InvalidTransition)?;
            if current_height <= deadline {
                return Err(PouwError::InvalidTransition);
            }
            task.status = TaskStatus::Slashed;
        }
        TaskStatus::Challenged => {
            let deadline = task
                .resolve_deadline_height
                .ok_or(PouwError::InvalidTransition)?;
            if current_height <= deadline {
                return Err(PouwError::InvalidTransition);
            }
            task.status = TaskStatus::Completed;
            if let Some(bond) = task.challenge_bond {
                ensure_balance_at_least(st, CHALLENGE_ESCROW_ACCOUNT, bond)?;
                task.challenge_bond_forfeited = Some(true);
            }
        }
        _ => return Err(PouwError::InvalidTransition),
    }

    let next_ref = st.update_task(task_ref, task.clone()).map_err(map_state_err)?;

    if matches!(task.status, TaskStatus::Completed) {
        if let Some(bond) = task.challenge_bond {
            st.debit_balance(CHALLENGE_ESCROW_ACCOUNT, bond)
                .map_err(PouwError::State)?;
            st.credit_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, bond);
        }
    }

    Ok(next_ref)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_happy_path_to_completed() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 100);
        let r1 = apply_create_task(&mut st, 42, "alice".into(), 100).unwrap();

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(42, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt).unwrap();
        let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10).unwrap();
        let r6 = apply_resolve(&mut st, r5, false).unwrap();

        let task = st.get_task(r6.id).unwrap();
        assert_eq!(task.status, TaskStatus::Completed);
    }

    #[test]
    fn forged_reveal_is_rejected() {
        let mut st = StateStore::new();
        let r1 = apply_create_task(&mut st, 1, "alice".into(), 1).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        let bad_reveal = apply_reveal_result(&mut st, r3, [3u8; 32], reveal_salt).unwrap_err();
        assert!(matches!(bad_reveal, PouwError::CommitmentMismatch));
    }

    #[test]
    fn challenge_requires_revealed() {
        let mut st = StateStore::new();
        let r1 = apply_create_task(&mut st, 9, "alice".into(), 10).unwrap();
        let err = apply_challenge(&mut st, r1, "challenger".into(), 10).unwrap_err();
        assert!(matches!(err, PouwError::InvalidTransition));
    }

    #[test]
    fn commit_requires_assigned() {
        let mut st = StateStore::new();
        let r1 = apply_create_task(&mut st, 11, "alice".into(), 10).unwrap();
        let err = apply_commit_result(&mut st, r1, "worker1".into(), [1u8; 32]).unwrap_err();
        assert!(matches!(err, PouwError::InvalidTransition));
    }

    #[test]
    fn commit_worker_must_match_assigned_worker() {
        let mut st = StateStore::new();
        let r1 = apply_create_task(&mut st, 12, "alice".into(), 10).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let err = apply_commit_result(&mut st, r2, "worker2".into(), [1u8; 32]).unwrap_err();
        assert!(matches!(err, PouwError::Unauthorized));
    }

    #[test]
    fn invalid_transition_matrix_smoke() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 100);
        let r1 = apply_create_task(&mut st, 99, "alice".into(), 10).unwrap();

        // OPEN: only accept is valid.
        assert!(matches!(
            apply_reveal_result(&mut st, r1.clone(), [1u8; 32], [2u8; 32]).unwrap_err(),
            PouwError::InvalidTransition
        ));
        assert!(matches!(
            apply_challenge(&mut st, r1.clone(), "challenger".into(), 10).unwrap_err(),
            PouwError::InvalidTransition
        ));
        assert!(matches!(
            apply_resolve(&mut st, r1.clone(), false).unwrap_err(),
            PouwError::InvalidTransition
        ));

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

        // ASSIGNED: reveal/challenge/resolve are invalid before commit.
        assert!(matches!(
            apply_reveal_result(&mut st, r2.clone(), [1u8; 32], [2u8; 32]).unwrap_err(),
            PouwError::InvalidTransition
        ));
        assert!(matches!(
            apply_challenge(&mut st, r2.clone(), "challenger".into(), 10).unwrap_err(),
            PouwError::InvalidTransition
        ));
        assert!(matches!(
            apply_resolve(&mut st, r2.clone(), false).unwrap_err(),
            PouwError::InvalidTransition
        ));

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(99, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();

        // COMMITTED: challenge/resolve invalid before reveal.
        assert!(matches!(
            apply_challenge(&mut st, r3.clone(), "challenger".into(), 10).unwrap_err(),
            PouwError::InvalidTransition
        ));
        assert!(matches!(
            apply_resolve(&mut st, r3.clone(), false).unwrap_err(),
            PouwError::InvalidTransition
        ));

        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt).unwrap();

        // REVEALED: resolve invalid before challenge.
        assert!(matches!(
            apply_resolve(&mut st, r4.clone(), false).unwrap_err(),
            PouwError::InvalidTransition
        ));

        let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10).unwrap();
        let _r6 = apply_resolve(&mut st, r5.clone(), false).unwrap();

        // FINAL: further resolve is invalid.
        assert!(matches!(
            apply_resolve(&mut st, r5, false).unwrap_err(),
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
        let mut st = StateStore::new();
        let r1 = apply_create_task(&mut st, 77, "alice".into(), 10).unwrap();

        // Forge an Assigned+Committed task with worker=None to exercise defensive mapping.
        let bad_task = TaskObject {
            task_id: 77,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Committed,
            worker: None,
            committed_hash: Some([1u8; 32]),
            result_hash: None,
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        };
        let r2 = st.update_task(r1, bad_task).unwrap();

        let err = apply_reveal_result(&mut st, r2, [2u8; 32], [3u8; 32]).unwrap_err();
        assert!(matches!(err, PouwError::MissingWorker));
    }

    #[test]
    fn committed_timeout_transitions_to_slashed() {
        let mut st = StateStore::new();
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
        let mut st = StateStore::new();
        st.set_balance("challenger", 100);
        let r1 = apply_create_task(&mut st, 777, "alice".into(), 10).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(777, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 10).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, 20).unwrap();
        let r5 = apply_challenge_at_height(&mut st, r4, "challenger".into(), 10, 30).unwrap();
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);

        let before = apply_timeout(&mut st, r5.clone(), 50).unwrap_err();
        assert!(matches!(before, PouwError::InvalidTransition));

        let r6 = apply_timeout(&mut st, r5, 51).unwrap();
        let task = st.get_task(r6.id).unwrap();
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 10);
    }

    #[test]
    fn challenge_requires_min_bond_from_governance() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 100);
        st.set_gov_param(9001, "challenge_min_bond".into(), "50".into())
            .unwrap();

        let r1 = apply_create_task(&mut st, 888, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(888, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt).unwrap();

        let err = apply_challenge(&mut st, r4.clone(), "challenger".into(), 49).unwrap_err();
        assert!(matches!(err, PouwError::InsufficientStake));

        let r5 = apply_challenge(&mut st, r4, "challenger".into(), 50).unwrap();
        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.challenge_bond, Some(50));
    }

    #[test]
    fn challenge_requires_min_bond_default_when_governance_absent() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 890, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(890, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt).unwrap();

        let err = apply_challenge(&mut st, r4.clone(), "challenger".into(), 9).unwrap_err();
        assert!(matches!(err, PouwError::InsufficientStake));

        let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10).unwrap();
        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.challenge_bond, Some(10));
    }

    #[test]
    fn challenge_uses_governance_window_and_resolve_marks_bond_outcome() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 100);
        st.set_gov_param(9002, "challenge_window_blocks".into(), "123".into())
            .unwrap();

        let r1 = apply_create_task(&mut st, 889, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(889, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 =
            apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
        let r4 = apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, 110).unwrap();
        let r5 = apply_challenge_at_height(&mut st, r4, "challenger".into(), 10, 120).unwrap();

        let challenged = st.get_task(r5.id).unwrap();
        assert_eq!(challenged.resolve_deadline_height, Some(243));
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);

        let r6 = apply_resolve(&mut st, r5, false).unwrap();
        let resolved = st.get_task(r6.id).unwrap();
        assert_eq!(resolved.challenge_bond_forfeited, Some(true));
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 10);
    }

    #[test]
    fn resolve_refunds_challenge_bond_when_worker_slashed() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 891, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(891, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt).unwrap();
        let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10).unwrap();
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        let r6 = apply_resolve(&mut st, r5, true).unwrap();

        let resolved = st.get_task(r6.id).unwrap();
        assert_eq!(resolved.status, TaskStatus::Slashed);
        assert_eq!(resolved.challenge_bond_forfeited, Some(false));
        assert_eq!(st.balance_of("challenger"), 100);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn challenge_rejects_when_challenger_balance_insufficient() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 5);

        let r1 = apply_create_task(&mut st, 892, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(892, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt).unwrap();

        let err = apply_challenge(&mut st, r4, "challenger".into(), 10).unwrap_err();
        assert!(matches!(err, PouwError::InsufficientStake));
        assert_eq!(st.balance_of("challenger"), 5);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn state_error_mapping_version_conflict() {
        let err = map_state_err("version conflict".to_string());
        assert!(matches!(err, PouwError::VersionConflict));

        let err2 = map_state_err("object not found".to_string());
        assert!(matches!(err2, PouwError::State(_)));
    }

    #[test]
    fn challenge_version_conflict_does_not_move_funds() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 9901, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9901, &result_hash, &reveal_salt, "worker1");
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt).unwrap();

        let stale_ref = r4.clone();
        let same_task = st.get_task(r4.id).unwrap();
        let _fresh_ref = st.update_task(r4, same_task).unwrap();

        let err = apply_challenge(&mut st, stale_ref, "challenger".into(), 10).unwrap_err();
        assert!(matches!(err, PouwError::VersionConflict));
        assert_eq!(st.balance_of("challenger"), 100);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn resolve_version_conflict_does_not_move_funds() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 9902, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9902, &result_hash, &reveal_salt, "worker1");
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt).unwrap();
        let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10).unwrap();

        let stale_ref = r5.clone();
        let same_task = st.get_task(r5.id).unwrap();
        let _fresh_ref = st.update_task(r5, same_task).unwrap();

        let err = apply_resolve(&mut st, stale_ref, false).unwrap_err();
        assert!(matches!(err, PouwError::VersionConflict));
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }

    #[test]
    fn timeout_version_conflict_does_not_move_funds() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 100);

        let r1 = apply_create_task(&mut st, 9903, "alice".into(), 10).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(9903, &result_hash, &reveal_salt, "worker1");
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt).unwrap();
        let r5 = apply_challenge_at_height(&mut st, r4, "challenger".into(), 10, 30).unwrap();

        let stale_ref = r5.clone();
        let same_task = st.get_task(r5.id).unwrap();
        let _fresh_ref = st.update_task(r5, same_task).unwrap();

        let err = apply_timeout(&mut st, stale_ref, 51).unwrap_err();
        assert!(matches!(err, PouwError::VersionConflict));
        assert_eq!(st.balance_of("challenger"), 90);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
        assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
    }
}
