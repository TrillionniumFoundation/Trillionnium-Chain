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
