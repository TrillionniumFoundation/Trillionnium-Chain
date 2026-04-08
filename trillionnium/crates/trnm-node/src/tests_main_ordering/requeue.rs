use super::*;

#[test]
fn requeue_uncommitted_txs_preserves_order_at_tail() {
    let mut mempool = VecDeque::from(vec![
        MockTx::CreateTask {
            task_id: 2001,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::CreateTask {
            task_id: 2002,
            creator: "bob".into(),
            bounty: 20,
        },
    ]);
    let picked = vec![
        MockTx::AcceptTask {
            task_id: 1001,
            worker: "worker1001".into(),
        },
        MockTx::Commit {
            task_id: 1001,
            worker: "worker1001".into(),
            committed_hash: [9u8; 32],
        },
    ];

    requeue_uncommitted_txs(&mut mempool, picked);

    let task_ids: Vec<u64> = mempool.iter().map(task_id_of).collect();
    assert_eq!(task_ids, vec![2001, 2002, 1001, 1001]);
}

#[test]
fn requeue_uncommitted_txs_noop_on_empty_pick() {
    let mut mempool = VecDeque::from(vec![MockTx::CreateTask {
        task_id: 3001,
        creator: "alice".into(),
        bounty: 10,
    }]);

    requeue_uncommitted_txs(&mut mempool, vec![]);

    let task_ids: Vec<u64> = mempool.iter().map(task_id_of).collect();
    assert_eq!(task_ids, vec![3001]);
}
