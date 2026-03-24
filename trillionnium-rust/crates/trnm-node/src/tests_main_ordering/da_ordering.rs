use super::*;

#[test]
fn da_ordering_decouple_switch_off_and_on_keep_same_commit_order_on_happy_path() {
    let state = StateStore::new();
    let picked = vec![
        MockTx::CreateTask {
            task_id: 4001,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::CreateTask {
            task_id: 4002,
            creator: "bob".into(),
            bounty: 20,
        },
    ];

    let legacy = decide_order_for_commit(&state, &picked, 2, false, 1);
    let decoupled = decide_order_for_commit(&state, &picked, 2, true, 1);

    assert_eq!(legacy.ordered_ids, vec![1, 2]);
    assert_eq!(decoupled.ordered_ids, legacy.ordered_ids);
    assert_eq!(legacy.rejected, 0);
    assert_eq!(decoupled.rejected, 0);
}
