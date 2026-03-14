use anyhow::{Context, Result};
use trnm_pouw::{
    apply_accept_task_at_height, apply_challenge_at_height, apply_commit_result_at_height,
    apply_create_task, apply_resolve_at_height, apply_reveal_result_at_height,
};
use trnm_state::StateStore;
use trnm_types::ObjectRef;

use crate::txmeta::actor_of;
use crate::types::MockTx;

fn task_ref(st: &StateStore, task_id: u64) -> Result<ObjectRef> {
    st.get_ref(task_id)
        .with_context(|| format!("task_ref missing for task_id={}", task_id))
}

pub(crate) fn verified_signer_of(st: &StateStore, tx: &MockTx) -> String {
    match tx {
        MockTx::Resolve { resolver, .. } => resolver.clone(),
        MockTx::Reveal { task_id, .. } => st
            .get_task(*task_id)
            .and_then(|t| t.worker)
            .unwrap_or_else(|| "unknown_worker".to_string()),
        _ => actor_of(st, tx),
    }
}

pub(crate) fn apply_one(st: &mut StateStore, tx: MockTx, current_height: u64) -> Result<()> {
    let signer = verified_signer_of(st, &tx);
    match tx {
        MockTx::CreateTask {
            task_id,
            creator,
            bounty,
        } => {
            let _ = apply_create_task(st, task_id, creator, bounty)?;
        }
        MockTx::AcceptTask { task_id, worker } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_accept_task_at_height(st, r, worker, current_height)?;
        }
        MockTx::Commit {
            task_id,
            worker,
            committed_hash,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_commit_result_at_height(st, r, worker, committed_hash, current_height)?;
        }
        MockTx::Reveal {
            task_id,
            result_hash,
            reveal_salt,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_reveal_result_at_height(
                st,
                r,
                result_hash,
                reveal_salt,
                None,
                current_height,
            )?;
        }
        MockTx::Challenge {
            task_id,
            challenger,
            bond,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_challenge_at_height(st, r, challenger, bond, signer, current_height)?;
        }
        MockTx::Resolve {
            task_id,
            slash_worker,
            resolver,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_resolve_at_height(st, r, slash_worker, resolver, signer, current_height)?;
        }
    }
    Ok(())
}
