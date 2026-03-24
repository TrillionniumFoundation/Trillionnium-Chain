use super::*;

pub fn apply_create_task(
    st: &mut StateStore,
    task_id: u64,
    creator: String,
    bounty: u128,
) -> Result<ObjectRef, PouwError> {
    // Boundary hardening: creator account id must use the same canonical
    // actor-id gate as the metadata-bearing create path so malformed account
    // aliases cannot enter PoUW state through the legacy task creation entry.
    require_canonical_actor_id(&creator)?;

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
