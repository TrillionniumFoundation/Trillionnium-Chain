use super::*;

#[test]
fn timeout_rejects_committed_state_with_stale_challenge_window_snapshot() {
    let mut st = seeded_state();

    let r1 = apply_create_task(&mut st, 39019, "alice".into(), 100).unwrap();
    let result_hash = [7u8; 32];
    let reveal_salt = [8u8; 32];
    let committed = compute_commitment(39019, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();

    let mut bad = st.get_task(r3.id).unwrap();
    assert_eq!(bad.status, TaskStatus::Committed);
    bad.challenge_window_blocks_snapshot = Some(MIN_CHALLENGE_WINDOW_BLOCKS);
    let bad_ref = st.update_task(r3, bad).unwrap();

    let err = apply_timeout(&mut st, bad_ref, 211).unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("stale challenge fields")));
}

#[test]
fn timeout_rejects_terminal_non_challenged_task_with_stale_challenge_timing_fields() {
    let mut st = seeded_state();

    let r1 = apply_create_task(&mut st, 39010, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(39010, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();
    let done = apply_timeout(&mut st, r4, 211).unwrap();

    let mut bad = st.get_task(done.id).unwrap();
    assert_eq!(bad.status, TaskStatus::Completed);
    bad.challenge_deadline_height = Some(210);
    let bad_ref = st.update_task(done, bad).unwrap();

    let err = apply_timeout(&mut st, bad_ref, 212).unwrap_err();
    assert!(matches!(err, PouwError::State(_)));
}

#[test]
fn timeout_rejects_terminal_challenged_task_missing_challenge_timing_fields() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 39016, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(39016, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        120,
    )
    .unwrap();
    let done = apply_timeout(&mut st, r5, 221).unwrap();

    let mut bad = st.get_task(done.id).unwrap();
    assert_eq!(bad.status, TaskStatus::Completed);
    bad.challenged_at_height = None;
    let bad_ref = st.update_task(done, bad).unwrap();

    let err = apply_timeout(&mut st, bad_ref, 222).unwrap_err();
    assert!(matches!(err, PouwError::State(_)));
}

#[test]
fn timeout_rejects_terminal_challenged_task_missing_challenge_bond_outcome() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 39017, "alice".into(), 100).unwrap();
    let result_hash = [3u8; 32];
    let reveal_salt = [4u8; 32];
    let committed = compute_commitment(39017, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        120,
    )
    .unwrap();
    let done = apply_timeout(&mut st, r5, 221).unwrap();

    let mut bad = st.get_task(done.id).unwrap();
    assert_eq!(bad.status, TaskStatus::Completed);
    bad.challenge_bond_forfeited = None;
    let bad_ref = st.update_task(done, bad).unwrap();

    let err = apply_timeout(&mut st, bad_ref, 222).unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("missing challenge bond outcome")));
}

#[test]
fn timeout_rejects_terminal_challenged_task_with_non_monotonic_challenge_timing_fields() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 39018, "alice".into(), 100).unwrap();
    let result_hash = [5u8; 32];
    let reveal_salt = [6u8; 32];
    let committed = compute_commitment(39018, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        120,
    )
    .unwrap();
    let done = apply_timeout(&mut st, r5, 221).unwrap();

    let mut bad = st.get_task(done.id).unwrap();
    assert_eq!(bad.status, TaskStatus::Completed);
    bad.challenged_at_height = Some(141);
    bad.challenge_deadline_height = Some(140);
    bad.resolve_deadline_height = Some(145);
    let bad_ref = st.update_task(done, bad).unwrap();

    let err = apply_timeout(&mut st, bad_ref, 222).unwrap_err();
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("non-monotonic challenge/resolve deadlines"))
    );
}

#[test]
fn timeout_rejects_revealed_state_with_stale_challenge_timing_fields() {
    let mut st = seeded_state();

    let r1 = apply_create_task(&mut st, 39013, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(39013, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

    let mut bad = st.get_task(r4.id).unwrap();
    assert_eq!(bad.status, TaskStatus::Revealed);
    bad.challenged_at_height = Some(111);
    let bad_ref = st.update_task(r4, bad).unwrap();

    let err = apply_timeout(&mut st, bad_ref, 211).unwrap_err();
    assert!(matches!(err, PouwError::State(_)));
}

#[test]
fn timeout_rejects_challenged_state_missing_resolve_metadata() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 39012, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(39012, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        120,
    )
    .unwrap();

    let mut bad = st.get_task(r5.id).unwrap();
    bad.resolve_deadline_height = None;
    let bad_ref = st.update_task(r5, bad).unwrap();

    let err = apply_timeout(&mut st, bad_ref, 221).unwrap_err();
    assert!(matches!(err, PouwError::State(_)));
    assert_eq!(st.get_task(39012).unwrap().status, TaskStatus::Challenged);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}

#[test]
fn timeout_rejects_challenged_state_missing_challenge_deadline_metadata() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 39014, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(39014, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        120,
    )
    .unwrap();

    let mut bad = st.get_task(r5.id).unwrap();
    bad.challenge_deadline_height = None;
    let bad_ref = st.update_task(r5, bad).unwrap();

    let err = apply_timeout(&mut st, bad_ref, 221).unwrap_err();
    assert!(matches!(err, PouwError::State(_)));
    assert_eq!(st.get_task(39014).unwrap().status, TaskStatus::Challenged);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}

#[test]
fn timeout_rejects_challenged_state_with_non_monotonic_deadline_metadata() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 39015, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(39015, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();
    let r5 = apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        120,
    )
    .unwrap();

    let mut bad = st.get_task(r5.id).unwrap();
    bad.challenge_deadline_height = Some(300);
    bad.resolve_deadline_height = Some(250);
    let bad_ref = st.update_task(r5, bad).unwrap();

    let err = apply_timeout(&mut st, bad_ref, 301).unwrap_err();
    assert!(matches!(err, PouwError::State(_)));
    assert_eq!(st.get_task(39015).unwrap().status, TaskStatus::Challenged);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}

#[test]
fn timeout_rejects_revealed_state_missing_challenge_deadline_metadata() {
    let mut st = seeded_state();

    let r1 = apply_create_task(&mut st, 39013, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(39013, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result_at_height(&mut st, r2, "worker1".into(), committed, 100).unwrap();
    let r4 =
        apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110).unwrap();

    let mut bad = st.get_task(r4.id).unwrap();
    bad.challenge_deadline_height = None;
    let bad_ref = st.update_task(r4, bad).unwrap();

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = apply_timeout(&mut st, bad_ref, 211).unwrap_err();
    assert!(matches!(err, PouwError::State(_)));

    let task = st.get_task(39013).unwrap();
    assert_eq!(task.status, TaskStatus::Revealed);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
}
