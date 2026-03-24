use super::*;

pub(crate) fn read_write_decl(st: &StateStore, tx: &MockTx, tx_id: u64) -> Tx {
    let task_id = match tx {
        MockTx::CreateTask { task_id, .. }
        | MockTx::AcceptTask { task_id, .. }
        | MockTx::Commit { task_id, .. }
        | MockTx::Reveal { task_id, .. }
        | MockTx::Challenge { task_id, .. }
        | MockTx::Resolve { task_id, .. } => *task_id,
    };

    let task_obj = ObjectRef {
        id: task_id,
        version: 1,
    };
    let mut read_set = vec![task_obj.clone()];
    let mut write_set = vec![task_obj.clone()];

    match tx {
        MockTx::AcceptTask { worker, .. } => {
            let worker_obj = ObjectRef {
                id: pseudo_object_id_for_account(worker),
                version: 1,
            };
            let lock_obj = ObjectRef {
                id: pseudo_object_id_for_account(&format!("worker_stake_lock.{}", task_id)),
                version: 1,
            };
            read_set.push(worker_obj.clone());
            write_set.push(worker_obj);
            read_set.push(lock_obj.clone());
            write_set.push(lock_obj);
        }
        MockTx::Challenge { challenger, .. } => {
            let challenger_obj = ObjectRef {
                id: pseudo_object_id_for_account(challenger),
                version: 1,
            };
            let escrow_obj = ObjectRef {
                id: pseudo_object_id_for_account(CHALLENGE_ESCROW_ACCOUNT),
                version: 1,
            };
            read_set.push(challenger_obj.clone());
            write_set.push(challenger_obj);
            read_set.push(escrow_obj.clone());
            write_set.push(escrow_obj);
        }
        MockTx::Resolve { .. } => {
            let escrow_obj = ObjectRef {
                id: pseudo_object_id_for_account(CHALLENGE_ESCROW_ACCOUNT),
                version: 1,
            };
            let forfeit_obj = ObjectRef {
                id: pseudo_object_id_for_account(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
                version: 1,
            };
            let slash_obj = ObjectRef {
                id: pseudo_object_id_for_account(WORKER_SLASH_TREASURY_ACCOUNT),
                version: 1,
            };
            let lock_obj = ObjectRef {
                id: pseudo_object_id_for_account(&format!("worker_stake_lock.{}", task_id)),
                version: 1,
            };
            read_set.push(escrow_obj.clone());
            write_set.push(escrow_obj);
            read_set.push(forfeit_obj.clone());
            write_set.push(forfeit_obj);
            read_set.push(slash_obj.clone());
            write_set.push(slash_obj);
            read_set.push(lock_obj.clone());
            write_set.push(lock_obj);

            if let Some(challenger) = st.get_task(task_id).and_then(|t| t.challenger) {
                let challenger_obj = ObjectRef {
                    id: pseudo_object_id_for_account(&challenger),
                    version: 1,
                };
                read_set.push(challenger_obj.clone());
                write_set.push(challenger_obj);
            }
        }
        _ => {}
    }

    Tx {
        id: tx_id,
        read_set,
        write_set,
        payload: vec![],
    }
}
