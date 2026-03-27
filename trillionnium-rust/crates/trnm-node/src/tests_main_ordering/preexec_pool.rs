use super::*;

#[test]
fn preexec_error_strings_include_candidate_height_context() {
    assert_eq!(
        invalid_preexec_tx_id(9, 42),
        "preexec invalid tx id 9 at candidate_height=42 (tx ids are 1-based)"
    );
    assert_eq!(
        preexec_worker_panic(7, 99),
        "preexec worker panic while evaluating tx_id=7 at candidate_height=99"
    );
}

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
fn preexec_pool_dedups_replayed_invalid_and_valid_ids_while_preserving_first_seen_order() {
    let state = Arc::new(StateStore::new());
    let picked = Arc::new(vec![
        MockTx::CreateTask {
            task_id: 4651,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::CreateTask {
            task_id: 4652,
            creator: "bob".into(),
            bounty: 20,
        },
    ]);

    let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 2, 1);
    let replayed = pre_execute_group_parallel(&pool, vec![2, 9, 2, 1, 9, 1, 2]);
    let followup = pre_execute_group_parallel(&pool, vec![2, 1]);

    assert_eq!(replayed.0, vec![2, 1]);
    assert_eq!(replayed.1, 1);
    assert_eq!(followup.0, vec![2, 1]);
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

#[test]
fn preexec_pool_keeps_deduped_first_seen_order_across_multi_worker_fanout() {
    let state = Arc::new(StateStore::new());
    let picked = Arc::new(vec![
        MockTx::CreateTask {
            task_id: 4801,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::CreateTask {
            task_id: 4802,
            creator: "bob".into(),
            bounty: 20,
        },
        MockTx::CreateTask {
            task_id: 4803,
            creator: "carol".into(),
            bounty: 30,
        },
        MockTx::CreateTask {
            task_id: 4804,
            creator: "dave".into(),
            bounty: 40,
        },
    ]);

    let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 3, 1);
    let (ordered_ids, rejected) = pre_execute_group_parallel(&pool, vec![4, 2, 4, 1, 3, 2, 1]);

    assert_eq!(ordered_ids, vec![4, 2, 1, 3]);
    assert_eq!(rejected, 0);
}

#[test]
fn preexec_group_normalization_preserves_first_seen_order_across_hashset_fallback() {
    let (normalized, replayed) =
        normalize_group_ids_for_preexec(&[11, 7, 11, 5, 7, 3, 11, 2, 5, 13, 3, 17]);

    assert_eq!(normalized, vec![11, 7, 5, 3, 2, 13, 17]);
    assert_eq!(replayed, 5);
}

#[test]
fn preexec_pool_dedups_long_replayed_invalid_batches_before_counting_rejection() {
    let state = Arc::new(StateStore::new());
    let picked = Arc::new(vec![MockTx::CreateTask {
        task_id: 4901,
        creator: "alice".into(),
        bounty: 10,
    }]);

    let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 3, 77);
    let (ordered_ids, rejected) =
        pre_execute_group_parallel(&pool, vec![9, 1, 9, 9, 1, 9, 1, 9, 9, 1, 9]);
    let followup = pre_execute_group_parallel(&pool, vec![1]);

    assert_eq!(ordered_ids, vec![1]);
    assert_eq!(rejected, 1);
    assert_eq!(followup.0, vec![1]);
    assert_eq!(followup.1, 0);
}
