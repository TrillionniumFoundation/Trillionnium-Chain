use super::*;

#[test]
fn critical_txs_are_selected_even_when_normal_queue_is_long() {
    let mut mempool = VecDeque::from(vec![
        MockTx::CreateTask {
            task_id: 1,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::AcceptTask {
            task_id: 1,
            worker: "w1".into(),
        },
        MockTx::Commit {
            task_id: 1,
            worker: "w1".into(),
            committed_hash: [3u8; 32],
        },
        MockTx::CreateTask {
            task_id: 2,
            creator: "bob".into(),
            bounty: 20,
        },
        MockTx::Challenge {
            task_id: 1,
            challenger: "c1".into(),
            bond: 10,
        },
        MockTx::Resolve {
            task_id: 1,
            slash_worker: false,
            resolver: "gov".into(),
        },
    ]);

    let picked = pick_txs_with_critical_guard(&mut mempool, 2);
    assert_eq!(picked.len(), 2);
    assert!(matches!(picked[0], MockTx::Challenge { .. }));
    assert!(matches!(picked[1], MockTx::CreateTask { task_id: 1, .. }));
    assert_eq!(mempool.len(), 4);
    assert!(mempool
        .iter()
        .any(|tx| matches!(tx, MockTx::Resolve { .. })));
}

#[test]
fn critical_guard_fast_path_drains_fifo_when_capacity_covers_queue() {
    let mut mempool = VecDeque::from(vec![
        MockTx::CreateTask {
            task_id: 1,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::Challenge {
            task_id: 1,
            challenger: "c1".into(),
            bond: 10,
        },
        MockTx::AcceptTask {
            task_id: 1,
            worker: "w1".into(),
        },
    ]);

    let picked = pick_txs_with_critical_guard(&mut mempool, 3);
    assert_eq!(picked.len(), 3);
    assert!(mempool.is_empty());
    assert!(matches!(picked[0], MockTx::CreateTask { .. }));
    assert!(matches!(picked[1], MockTx::Challenge { .. }));
    assert!(matches!(picked[2], MockTx::AcceptTask { .. }));
}

#[test]
fn critical_guard_zero_block_budget_is_noop_and_preserves_queue_order() {
    let mut mempool = VecDeque::from(vec![
        MockTx::CreateTask {
            task_id: 1,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::Challenge {
            task_id: 1,
            challenger: "c1".into(),
            bond: 10,
        },
        MockTx::AcceptTask {
            task_id: 1,
            worker: "w1".into(),
        },
    ]);

    let picked = pick_txs_with_critical_guard(&mut mempool, 0);
    assert!(picked.is_empty());

    let remaining_task_ids: Vec<u64> = mempool.iter().map(task_id_of).collect();
    assert_eq!(remaining_task_ids, vec![1, 1, 1]);
    assert!(matches!(mempool[0], MockTx::CreateTask { .. }));
    assert!(matches!(mempool[1], MockTx::Challenge { .. }));
    assert!(matches!(mempool[2], MockTx::AcceptTask { .. }));
}

#[test]
fn critical_guard_normal_only_backlog_drains_fifo_prefix_without_reordering() {
    let mut mempool = VecDeque::from(vec![
        MockTx::CreateTask {
            task_id: 31,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::AcceptTask {
            task_id: 31,
            worker: "w31".into(),
        },
        MockTx::Commit {
            task_id: 31,
            worker: "w31".into(),
            committed_hash: [1u8; 32],
        },
        MockTx::CreateTask {
            task_id: 32,
            creator: "bob".into(),
            bounty: 20,
        },
    ]);

    let picked = pick_txs_with_critical_guard(&mut mempool, 2);
    assert_eq!(picked.len(), 2);
    assert!(matches!(picked[0], MockTx::CreateTask { task_id: 31, .. }));
    assert!(matches!(picked[1], MockTx::AcceptTask { task_id: 31, .. }));

    assert_eq!(mempool.len(), 2);
    assert!(matches!(mempool[0], MockTx::Commit { task_id: 31, .. }));
    assert!(matches!(mempool[1], MockTx::CreateTask { task_id: 32, .. }));
}

#[test]
fn critical_guard_critical_only_backlog_preserves_fifo_prefix_within_domain() {
    let mut mempool = VecDeque::from(vec![
        MockTx::Challenge {
            task_id: 41,
            challenger: "c1".into(),
            bond: 10,
        },
        MockTx::Resolve {
            task_id: 41,
            slash_worker: false,
            resolver: "gov".into(),
        },
        MockTx::Challenge {
            task_id: 42,
            challenger: "c2".into(),
            bond: 20,
        },
        MockTx::Resolve {
            task_id: 42,
            slash_worker: true,
            resolver: "gov".into(),
        },
    ]);

    let picked = pick_txs_with_critical_guard(&mut mempool, 2);
    assert_eq!(picked.len(), 2);
    assert!(matches!(picked[0], MockTx::Challenge { task_id: 41, .. }));
    assert!(matches!(picked[1], MockTx::Resolve { task_id: 41, .. }));

    assert_eq!(mempool.len(), 2);
    assert!(matches!(mempool[0], MockTx::Challenge { task_id: 42, .. }));
    assert!(matches!(mempool[1], MockTx::Resolve { task_id: 42, .. }));
}

#[test]
fn critical_guard_selection_respects_lane_fairness_pop_order() {
    let mut mempool = VecDeque::from(vec![
        MockTx::CreateTask {
            task_id: 11,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::Challenge {
            task_id: 11,
            challenger: "c1".into(),
            bond: 10,
        },
        MockTx::Resolve {
            task_id: 11,
            slash_worker: false,
            resolver: "gov".into(),
        },
        MockTx::AcceptTask {
            task_id: 11,
            worker: "w1".into(),
        },
    ]);

    let picked = pick_txs_with_critical_guard(&mut mempool, 3);
    assert_eq!(picked.len(), 3);
    assert!(matches!(picked[0], MockTx::Challenge { .. }));
    assert!(matches!(picked[1], MockTx::CreateTask { .. }));
    assert!(matches!(picked[2], MockTx::Resolve { .. }));
}

#[test]
fn critical_guard_only_reorders_scanned_prefix_and_leaves_suffix_fifo() {
    let mut mempool = VecDeque::from(vec![
        MockTx::CreateTask {
            task_id: 21,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::AcceptTask {
            task_id: 21,
            worker: "w1".into(),
        },
        MockTx::Challenge {
            task_id: 21,
            challenger: "c1".into(),
            bond: 10,
        },
        MockTx::Resolve {
            task_id: 21,
            slash_worker: false,
            resolver: "gov".into(),
        },
        MockTx::CreateTask {
            task_id: 22,
            creator: "bob".into(),
            bounty: 20,
        },
    ]);

    let picked = pick_txs_with_critical_guard(&mut mempool, 3);
    assert_eq!(picked.len(), 3);
    assert!(matches!(picked[0], MockTx::Challenge { .. }));
    assert!(matches!(picked[1], MockTx::CreateTask { task_id: 21, .. }));
    assert!(matches!(picked[2], MockTx::AcceptTask { .. }));

    assert_eq!(mempool.len(), 2);
    assert!(matches!(mempool[0], MockTx::Resolve { .. }));
    assert!(matches!(mempool[1], MockTx::CreateTask { task_id: 22, .. }));
}

#[test]
fn critical_guard_budget_cutoff_keeps_later_critical_spillover_behind_selected_normal_prefix() {
    let mut mempool = VecDeque::from(vec![
        MockTx::CreateTask {
            task_id: 51,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::Challenge {
            task_id: 51,
            challenger: "c1".into(),
            bond: 10,
        },
        MockTx::AcceptTask {
            task_id: 51,
            worker: "w1".into(),
        },
        MockTx::Resolve {
            task_id: 52,
            slash_worker: false,
            resolver: "gov".into(),
        },
        MockTx::CreateTask {
            task_id: 52,
            creator: "bob".into(),
            bounty: 20,
        },
    ]);

    let picked = pick_txs_with_critical_guard(&mut mempool, 2);
    assert_eq!(picked.len(), 2);

    // Once the earliest critical tx is surfaced, the next slot should still honor
    // the warmed lane-fairness contract by admitting the pending normal prefix
    // before a later critical spillover jumps ahead within the same block budget.
    assert!(matches!(picked[0], MockTx::Challenge { task_id: 51, .. }));
    assert!(matches!(picked[1], MockTx::CreateTask { task_id: 51, .. }));

    assert_eq!(mempool.len(), 3);
    assert!(matches!(mempool[0], MockTx::AcceptTask { task_id: 51, .. }));
    assert!(matches!(mempool[1], MockTx::Resolve { task_id: 52, .. }));
    assert!(matches!(mempool[2], MockTx::CreateTask { task_id: 52, .. }));
}

#[test]
fn critical_guard_single_slot_still_surfaces_tail_critical_domain_work() {
    let mut mempool = VecDeque::from(vec![
        MockTx::CreateTask {
            task_id: 31,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::AcceptTask {
            task_id: 31,
            worker: "w1".into(),
        },
        MockTx::CreateTask {
            task_id: 32,
            creator: "bob".into(),
            bounty: 20,
        },
        MockTx::Challenge {
            task_id: 31,
            challenger: "c1".into(),
            bond: 10,
        },
    ]);

    let picked = pick_txs_with_critical_guard(&mut mempool, 1);
    assert_eq!(picked.len(), 1);
    assert!(matches!(picked[0], MockTx::Challenge { task_id: 31, .. }));

    assert_eq!(mempool.len(), 3);
    assert!(matches!(mempool[0], MockTx::CreateTask { task_id: 31, .. }));
    assert!(matches!(mempool[1], MockTx::AcceptTask { task_id: 31, .. }));
    assert!(matches!(mempool[2], MockTx::CreateTask { task_id: 32, .. }));
}

#[test]
fn critical_guard_spillover_preserves_critical_domain_fifo_across_selection() {
    let mut mempool = VecDeque::from(vec![
        MockTx::CreateTask {
            task_id: 41,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::AcceptTask {
            task_id: 41,
            worker: "w1".into(),
        },
        MockTx::Challenge {
            task_id: 41,
            challenger: "c1".into(),
            bond: 10,
        },
        MockTx::Commit {
            task_id: 41,
            worker: "w1".into(),
            committed_hash: [4u8; 32],
        },
        MockTx::Resolve {
            task_id: 42,
            slash_worker: false,
            resolver: "gov".into(),
        },
        MockTx::CreateTask {
            task_id: 42,
            creator: "bob".into(),
            bounty: 20,
        },
    ]);

    let picked = pick_txs_with_critical_guard(&mut mempool, 4);
    assert_eq!(picked.len(), 4);

    // The earliest critical tx should still lead selection, and a later
    // spillovered critical tx must keep its FIFO position within the critical
    // domain instead of leaping ahead of earlier normal work once the guard cools.
    assert!(matches!(picked[0], MockTx::Challenge { task_id: 41, .. }));
    assert!(matches!(picked[1], MockTx::CreateTask { task_id: 41, .. }));
    assert!(matches!(picked[2], MockTx::AcceptTask { task_id: 41, .. }));
    assert!(matches!(picked[3], MockTx::Resolve { task_id: 42, .. }));

    assert_eq!(mempool.len(), 2);
    assert!(matches!(mempool[0], MockTx::Commit { task_id: 41, .. }));
    assert!(matches!(mempool[1], MockTx::CreateTask { task_id: 42, .. }));
}

#[test]
fn critical_guard_long_normal_prefix_still_surfaces_tail_critical_then_rewarms_normal_fifo() {
    let mut mempool = VecDeque::from(vec![
        MockTx::CreateTask {
            task_id: 61,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::AcceptTask {
            task_id: 61,
            worker: "w1".into(),
        },
        MockTx::Commit {
            task_id: 61,
            worker: "w1".into(),
            committed_hash: [6u8; 32],
        },
        MockTx::CreateTask {
            task_id: 62,
            creator: "bob".into(),
            bounty: 20,
        },
        MockTx::Challenge {
            task_id: 61,
            challenger: "c1".into(),
            bond: 10,
        },
        MockTx::Resolve {
            task_id: 62,
            slash_worker: false,
            resolver: "gov".into(),
        },
    ]);

    let picked = pick_txs_with_critical_guard(&mut mempool, 3);
    assert_eq!(picked.len(), 3);

    // A long normal prefix must not hide later critical work, but after surfacing
    // the earliest critical tx the selector should still re-warm the pending
    // normal FIFO instead of immediately jumping to the next later critical.
    assert!(matches!(picked[0], MockTx::Challenge { task_id: 61, .. }));
    assert!(matches!(picked[1], MockTx::CreateTask { task_id: 61, .. }));
    assert!(matches!(picked[2], MockTx::AcceptTask { task_id: 61, .. }));

    assert_eq!(mempool.len(), 3);
    assert!(matches!(mempool[0], MockTx::Commit { task_id: 61, .. }));
    assert!(matches!(mempool[1], MockTx::CreateTask { task_id: 62, .. }));
    assert!(matches!(mempool[2], MockTx::Resolve { task_id: 62, .. }));
}
