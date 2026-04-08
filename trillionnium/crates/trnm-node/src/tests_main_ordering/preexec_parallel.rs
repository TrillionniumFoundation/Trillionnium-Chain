use super::*;

#[test]
fn preexec_parallel_workers_match_single_worker_results() {
    let state = StateStore::new();
    let picked = vec![
        MockTx::CreateTask {
            task_id: 4051,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::CreateTask {
            task_id: 4052,
            creator: "bob".into(),
            bounty: 20,
        },
        MockTx::AcceptTask {
            task_id: 999_999,
            worker: "worker4053".into(),
        },
    ];

    let pool_single = PreExecPool::new(Arc::new(state.clone()), Arc::new(picked.clone()), 1, 1);
    let single = pre_execute_group_parallel(&pool_single, vec![1, 2, 3]);

    let pool_parallel = PreExecPool::new(Arc::new(state), Arc::new(picked), 3, 1);
    let parallel = pre_execute_group_parallel(&pool_parallel, vec![1, 2, 3]);

    assert_eq!(single, (vec![1, 2], 1));
    assert_eq!(parallel, single);
}

#[test]
fn preexec_replay_sample_uses_duplicate_encounter_order() {
    assert_eq!(
        format_replayed_group_id_sample(&[4, 2, 4, 3, 2, 4], 4),
        "[4, 2, 4]"
    );
}

#[test]
fn preexec_replay_sample_bounds_output_when_duplicates_are_noisy() {
    assert_eq!(
        format_replayed_group_id_sample(&[7, 3, 7, 5, 3, 9, 7, 11, 5, 13, 9, 15], 2),
        "[7, 3]+3more"
    );
}

#[test]
fn preexec_replay_sample_omitted_suffix_counts_duplicate_events_not_unique_ids() {
    assert_eq!(
        format_replayed_group_id_sample(&[7, 3, 7, 7, 7], 1),
        "[7]+2more"
    );
}

#[test]
fn preexec_group_normalization_preserves_first_seen_order_and_counts_replays() {
    let (normalized, replayed) = normalize_group_ids_for_preexec(&[4, 2, 4, 3, 2, 4]);

    assert_eq!(normalized, vec![4, 2, 3]);
    assert_eq!(replayed, 3);
}

#[test]
fn preexec_group_normalization_preserves_first_seen_order_for_long_replay_lists() {
    let (normalized, replayed) =
        normalize_group_ids_for_preexec(&[7, 3, 7, 5, 3, 9, 7, 11, 5, 13, 9, 15]);

    assert_eq!(normalized, vec![7, 3, 5, 9, 11, 13, 15]);
    assert_eq!(replayed, 5);
}

#[test]
fn preexec_parallel_dedupes_replayed_group_ids_before_worker_fanout() {
    let state = StateStore::new();
    let picked = vec![
        MockTx::CreateTask {
            task_id: 4151,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::AcceptTask {
            task_id: 999_999,
            worker: "worker4152".into(),
        },
    ];

    let pool = PreExecPool::new(Arc::new(state), Arc::new(picked), 4, 1);
    let replayed = pre_execute_group_parallel(&pool, vec![1, 2, 1, 2, 1]);

    assert_eq!(replayed, (vec![1], 1));
}

#[test]
fn preexec_uses_candidate_height_for_deadline_sensitive_reveal() {
    let mut state = StateStore::new();
    state.set_balance("worker4100", 1_000);

    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let r1 = apply_create_task(&mut state, 4100, "alice".into(), 100).unwrap();
    let r2 = apply_accept_task_at_height(&mut state, r1, "worker4100".into(), 100).unwrap();
    let committed = compute_commitment(4100, &result_hash, &reveal_salt, "worker4100");
    let _r3 =
        apply_commit_result_at_height(&mut state, r2, "worker4100".into(), committed, 100).unwrap();

    let reveal_deadline = state
        .get_task(4100)
        .and_then(|t| t.reveal_deadline_height)
        .expect("reveal deadline must exist after commit");
    let reveal_tx = MockTx::Reveal {
        task_id: 4100,
        result_hash,
        reveal_salt,
    };

    let accepted_at_deadline = decide_order_for_commit(
        &state,
        std::slice::from_ref(&reveal_tx),
        1,
        false,
        reveal_deadline,
    );
    assert_eq!(accepted_at_deadline.ordered_ids, vec![1]);
    assert_eq!(accepted_at_deadline.rejected, 0);

    let rejected_after_deadline = decide_order_for_commit(
        &state,
        std::slice::from_ref(&reveal_tx),
        1,
        false,
        reveal_deadline.saturating_add(1),
    );
    assert!(rejected_after_deadline.ordered_ids.is_empty());
    assert_eq!(rejected_after_deadline.rejected, 1);

    let rejected_after_deadline_decoupled = decide_order_for_commit(
        &state,
        std::slice::from_ref(&reveal_tx),
        1,
        true,
        reveal_deadline.saturating_add(1),
    );
    assert!(rejected_after_deadline_decoupled.ordered_ids.is_empty());
    assert_eq!(rejected_after_deadline_decoupled.rejected, 1);

    let err = apply_one(
        &mut state.clone(),
        reveal_tx,
        reveal_deadline.saturating_add(1),
    )
    .unwrap_err();
    assert_eq!(classify_apply_error(&err), "deadline_exceeded");
}

#[test]
fn zero_worker_ordering_falls_back_to_single_worker_for_legacy_and_decoupled_paths() {
    let state = StateStore::new();
    let picked = vec![
        MockTx::CreateTask {
            task_id: 4_180,
            creator: "alice".into(),
            bounty: 10,
        },
        MockTx::CreateTask {
            task_id: 4_181,
            creator: "bob".into(),
            bounty: 20,
        },
        MockTx::AcceptTask {
            task_id: 999_999,
            worker: "worker4182".into(),
        },
    ];

    let legacy_single = decide_order_for_commit(&state, &picked, 1, false, 77);
    let legacy_zero = decide_order_for_commit(&state, &picked, 0, false, 77);
    let decoupled_single = decide_order_for_commit(&state, &picked, 1, true, 77);
    let decoupled_zero = decide_order_for_commit(&state, &picked, 0, true, 77);

    assert_eq!(legacy_single.ordered_ids, vec![1, 2]);
    assert_eq!(legacy_single.rejected, 1);
    assert_eq!(legacy_zero.ordered_ids, legacy_single.ordered_ids);
    assert_eq!(legacy_zero.rejected, legacy_single.rejected);

    assert_eq!(decoupled_single.ordered_ids, vec![1, 2]);
    assert_eq!(decoupled_single.rejected, 1);
    assert_eq!(decoupled_zero.ordered_ids, decoupled_single.ordered_ids);
    assert_eq!(decoupled_zero.rejected, decoupled_single.rejected);
}
