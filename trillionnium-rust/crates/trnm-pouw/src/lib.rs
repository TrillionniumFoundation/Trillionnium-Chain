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
}

fn map_state_err(err: String) -> PouwError {
    if err.contains("version conflict") {
        PouwError::VersionConflict
    } else {
        PouwError::State(err)
    }
}

fn compute_commitment(task_id: u64, result_hash: &Hash32, reveal_salt: &[u8; 32], worker: &str) -> Hash32 {
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
        version: 1,
    };
    st.put_task_new(task).map_err(map_state_err)
}

pub fn apply_commit_result(
    st: &mut StateStore,
    task_ref: ObjectRef,
    worker: String,
    committed_hash: Hash32,
) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    if task.status != TaskStatus::Open && task.status != TaskStatus::Assigned {
        return Err(PouwError::InvalidTransition);
    }
    task.status = TaskStatus::Committed;
    task.worker = Some(worker);
    task.committed_hash = Some(committed_hash);
    st.update_task(task_ref, task).map_err(map_state_err)
}

pub fn apply_reveal_result(
    st: &mut StateStore,
    task_ref: ObjectRef,
    result_hash: Hash32,
    reveal_salt: [u8; 32],
) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;

    if task.status != TaskStatus::Committed {
        return Err(PouwError::InvalidTransition);
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

pub fn apply_challenge(st: &mut StateStore, task_ref: ObjectRef) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    if task.status != TaskStatus::Revealed {
        return Err(PouwError::InvalidTransition);
    }
    task.status = TaskStatus::Challenged;
    st.update_task(task_ref, task).map_err(map_state_err)
}

pub fn apply_resolve(st: &mut StateStore, task_ref: ObjectRef, slash_worker: bool) -> Result<ObjectRef, PouwError> {
    let mut task = st
        .get_task(task_ref.id)
        .ok_or_else(|| PouwError::State("task not found".into()))?;
    if task.status != TaskStatus::Challenged {
        return Err(PouwError::InvalidTransition);
    }
    task.status = if slash_worker {
        TaskStatus::Slashed
    } else {
        TaskStatus::Completed
    };
    st.update_task(task_ref, task).map_err(map_state_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_happy_path_to_completed() {
        let mut st = StateStore::new();
        let r1 = apply_create_task(&mut st, 42, "alice".into(), 100).unwrap();

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(42, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_commit_result(&mut st, r1, "worker1".into(), committed).unwrap();
        let r3 = apply_reveal_result(&mut st, r2, result_hash, reveal_salt).unwrap();
        let r4 = apply_challenge(&mut st, r3).unwrap();
        let r5 = apply_resolve(&mut st, r4, false).unwrap();

        let task = st.get_task(r5.id).unwrap();
        assert_eq!(task.status, TaskStatus::Completed);
    }

    #[test]
    fn forged_reveal_is_rejected() {
        let mut st = StateStore::new();
        let r1 = apply_create_task(&mut st, 1, "alice".into(), 1).unwrap();

        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(1, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_commit_result(&mut st, r1, "worker1".into(), committed).unwrap();

        let bad_reveal = apply_reveal_result(&mut st, r2, [3u8; 32], reveal_salt).unwrap_err();
        assert!(matches!(bad_reveal, PouwError::CommitmentMismatch));
    }

    #[test]
    fn challenge_requires_revealed() {
        let mut st = StateStore::new();
        let r1 = apply_create_task(&mut st, 9, "alice".into(), 10).unwrap();
        let err = apply_challenge(&mut st, r1).unwrap_err();
        assert!(matches!(err, PouwError::InvalidTransition));
    }

    #[test]
    fn state_error_mapping_version_conflict() {
        let err = map_state_err("version conflict".to_string());
        assert!(matches!(err, PouwError::VersionConflict));

        let err2 = map_state_err("object not found".to_string());
        assert!(matches!(err2, PouwError::State(_)));
    }
}
