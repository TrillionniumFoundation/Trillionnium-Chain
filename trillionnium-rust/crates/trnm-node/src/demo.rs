use std::collections::VecDeque;

use crate::types::MockTx;
use sha2::{Digest, Sha256};
use trnm_state::StateStore;
use trnm_types::Hash32;

pub(crate) fn compute_commitment(
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

pub(crate) fn demo_worker_name(task_id: u64) -> String {
    format!("worker{}", task_id)
}

pub(crate) fn build_demo_mempool(demo_tasks: u64, _demo_keys: u64) -> VecDeque<MockTx> {
    let mut q = VecDeque::new();

    for i in 0..demo_tasks.max(1) {
        let task_id = 1001u64 + i;
        let worker = demo_worker_name(task_id);
        let result_hash = [7u8; 32];
        let reveal_salt = [task_id as u8; 32];
        let committed_hash = compute_commitment(task_id, &result_hash, &reveal_salt, &worker);

        q.push_back(MockTx::CreateTask {
            task_id,
            creator: "alice".to_string(),
            bounty: 100,
        });
        q.push_back(MockTx::AcceptTask {
            task_id,
            worker: worker.clone(),
        });
        q.push_back(MockTx::Commit {
            task_id,
            worker,
            committed_hash,
        });
        q.push_back(MockTx::Reveal {
            task_id,
            result_hash,
            reveal_salt,
        });
        q.push_back(MockTx::Challenge {
            task_id,
            challenger: "challenger".into(),
            bond: 10,
        });
        q.push_back(MockTx::Resolve {
            task_id,
            slash_worker: false,
            resolver: "governance.resolve_authority".into(),
        });
    }

    q
}

pub(crate) fn init_demo_state_and_mempool(
    demo_tasks: u64,
    demo_keys: u64,
) -> (StateStore, VecDeque<MockTx>) {
    let mut state = StateStore::new();
    state.set_balance("challenger", 1_000_000);

    let mempool = build_demo_mempool(demo_tasks, demo_keys);
    for i in 0..demo_tasks.max(1) {
        let worker = demo_worker_name(1001u64 + i);
        state.set_balance(&worker, 1_000_000);
    }

    (state, mempool)
}
