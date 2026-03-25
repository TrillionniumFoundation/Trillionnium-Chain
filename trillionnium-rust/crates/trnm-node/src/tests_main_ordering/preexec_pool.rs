use super::*;

#[test]
fn preexec_pool_reuses_workers_across_multiple_groups() {
    let state = Arc::new(StateStore::new());
    let picked = Arc::new(vec![
        MockTx::CreateTask {
            task_id: 4201,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::CreateTask {
            task_id: 4202,
            creator: "bob".into(),
            bounty: 20,
        },
        MockTx::CreateTask {
            task_id: 4203,
            creator: "carol".into(),
            bounty: 30,
        },
        MockTx::CreateTask {
            task_id: 4204,
            creator: "dave".into(),
            bounty: 40,
        },
    ]);

    let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 2, 1);
    let first = pre_execute_group_parallel(&pool, vec![1, 2]);
    let second = pre_execute_group_parallel(&pool, vec![3, 4]);

    assert_eq!(first.0, vec![1, 2]);
    assert_eq!(first.1, 0);
    assert_eq!(second.0, vec![3, 4]);
    assert_eq!(second.1, 0);
}

#[test]
fn preexec_pool_treats_empty_group_as_noop_without_affecting_followup_groups() {
    let state = Arc::new(StateStore::new());
    let picked = Arc::new(vec![
        MockTx::CreateTask {
            task_id: 4211,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::CreateTask {
            task_id: 4212,
            creator: "bob".into(),
            bounty: 20,
        },
    ]);

    let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 2, 1);
    let empty = pre_execute_group_parallel(&pool, vec![]);
    let followup = pre_execute_group_parallel(&pool, vec![2, 1]);

    assert_eq!(empty, (vec![], 0));
    assert_eq!(followup.0, vec![2, 1]);
    assert_eq!(followup.1, 0);
}

#[test]
fn preexec_pool_rejects_invalid_job_ids_without_losing_workers() {
    let state = Arc::new(StateStore::new());
    let picked = Arc::new(vec![MockTx::CreateTask {
        task_id: 4301,
        creator: "alice".into(),
        bounty: 10,
    }]);

    let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 2, 1);
    let malformed = pre_execute_group_parallel(&pool, vec![1, 2]);
    let followup = pre_execute_group_parallel(&pool, vec![1]);

    assert_eq!(malformed.0, vec![1]);
    assert_eq!(malformed.1, 1);
    assert_eq!(followup.0, vec![1]);
    assert_eq!(followup.1, 0);
}

#[test]
fn preexec_pool_preserves_first_seen_group_order_while_deduping_duplicates() {
    let state = Arc::new(StateStore::new());
    let picked = Arc::new(vec![
        MockTx::CreateTask {
            task_id: 4401,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::CreateTask {
            task_id: 4402,
            creator: "bob".into(),
            bounty: 20,
        },
    ]);

    let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 2, 1);
    let (ordered_ids, rejected) = pre_execute_group_parallel(&pool, vec![2, 1, 2, 1]);

    assert_eq!(ordered_ids, vec![2, 1]);
    assert_eq!(rejected, 0);
}

#[test]
fn preexec_pool_dedups_repeated_invalid_ids_before_counting_rejections() {
    let state = Arc::new(StateStore::new());
    let picked = Arc::new(vec![MockTx::CreateTask {
        task_id: 4501,
        creator: "alice".into(),
        bounty: 10,
    }]);

    let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 2, 1);
    let (ordered_ids, rejected) = pre_execute_group_parallel(&pool, vec![2, 2, 2, 1, 1]);

    assert_eq!(ordered_ids, vec![1]);
    assert_eq!(rejected, 1);
}

#[test]
fn preexec_pool_rejects_zero_tx_id_without_worker_panic_or_loss() {
    let state = Arc::new(StateStore::new());
    let picked = Arc::new(vec![MockTx::CreateTask {
        task_id: 4601,
        creator: "alice".into(),
        bounty: 10,
    }]);

    let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 2, 1);
    let malformed = pre_execute_group_parallel(&pool, vec![0, 1, 0]);
    let followup = pre_execute_group_parallel(&pool, vec![1]);

    assert_eq!(malformed.0, vec![1]);
    assert_eq!(malformed.1, 1);
    assert_eq!(followup.0, vec![1]);
    assert_eq!(followup.1, 0);
}

#[test]
fn preexec_pool_clamps_zero_workers_to_a_single_safe_worker() {
    let state = Arc::new(StateStore::new());
    let picked = Arc::new(vec![
        MockTx::CreateTask {
            task_id: 4701,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::CreateTask {
            task_id: 4702,
            creator: "bob".into(),
            bounty: 20,
        },
    ]);

    let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 0, 1);
    let first = pre_execute_group_parallel(&pool, vec![1, 2]);
    let second = pre_execute_group_parallel(&pool, vec![2, 1, 2]);

    assert_eq!(pool.width, 1);
    assert_eq!(first.0, vec![1, 2]);
    assert_eq!(first.1, 0);
    assert_eq!(second.0, vec![2, 1]);
    assert_eq!(second.1, 0);
}
