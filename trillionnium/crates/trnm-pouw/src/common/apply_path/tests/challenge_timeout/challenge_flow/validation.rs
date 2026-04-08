use super::*;

#[test]
fn challenge_requires_revealed() {
    let mut st = seeded_state();
    let r1 = apply_create_task(&mut st, 9, "alice".into(), 10).unwrap();
    let err =
        apply_challenge(&mut st, r1, "challenger".into(), 10, "challenger".into()).unwrap_err();
    assert!(matches!(err, PouwError::InvalidTransition));
}

#[test]
fn challenge_rejects_dirty_challenger_actor_ids() {
    for (i, dirty_challenger) in dirty_actor_ids().into_iter().enumerate() {
        let mut st = seeded_state();
        st.set_balance("worker1", 10);
        st.set_balance("challenger", 1_000);
        let task_id = 21_300 + i as u64;
        let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let err = apply_challenge(
            &mut st,
            r4,
            dirty_challenger.into(),
            10,
            dirty_challenger.into(),
        )
        .unwrap_err();
        assert!(
            matches!(err, PouwError::Unauthorized),
            "challenge should reject dirty challenger actor id: {:?}",
            dirty_challenger
        );
    }
}

#[test]
fn challenge_rejects_self_challenge_by_assigned_worker() {
    let mut st = seeded_state();
    st.set_balance("worker1", 100);

    let r1 = apply_create_task(&mut st, 29058, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(29058, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    let err = apply_challenge(&mut st, r4, "worker1".into(), 10, "worker1".into()).unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));
}

#[test]
fn challenge_rejects_noncanonical_worker_id_in_legacy_revealed_state() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 29059, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(29059, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    let mut bad = st.get_task(r4.id).unwrap();
    bad.worker = Some(" worker1".into());
    let bad_ref = st.update_task(r4, bad).unwrap();

    let err = apply_challenge(
        &mut st,
        bad_ref,
        "challenger".into(),
        10,
        "challenger".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::State(_)));
}

#[test]
fn challenge_rejects_when_payload_challenger_matches_but_signer_is_attacker() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 898, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(898, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    let before = st.clone();
    let err = apply_challenge(&mut st, r4, "challenger".into(), 10, "attacker".into()).unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));

    // Unauthorized attempts must not move balances or mutate task state.
    let task = st.get_task(898).unwrap();
    assert_eq!(task.status, TaskStatus::Revealed);
    assert_eq!(task.challenger, None);
    assert_eq!(task.challenge_bond, None);
    assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
    );
}

#[test]
fn challenge_rejects_blank_actor_or_signer_values() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 8_991, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_991, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    let before = st.clone();
    let err = apply_challenge(&mut st, r4, "".into(), 10, "".into()).unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));

    // Blank identities must not mutate task status or balances.
    let task = st.get_task(8_991).unwrap();
    assert_eq!(task.status, TaskStatus::Revealed);
    assert_eq!(task.challenger, None);
    assert_eq!(task.challenge_bond, None);
    assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
    );
}

#[test]
fn challenge_rejects_whitespace_only_actor_or_signer_without_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 8_992, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_992, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    let before = st.clone();
    let err = apply_challenge(&mut st, r4, "   ".into(), 10, "   ".into()).unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(8_992).unwrap();
    assert_eq!(task.status, TaskStatus::Revealed);
    assert_eq!(task.challenger, None);
    assert_eq!(task.challenge_bond, None);
    assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
    );
}

#[test]
fn challenge_rejects_actor_or_signer_with_surrounding_whitespace_without_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 8_993, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_993, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    let before = st.clone();
    let err = apply_challenge(
        &mut st,
        r4.clone(),
        " challenger".into(),
        10,
        " challenger".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));

    let err2 =
        apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger ".into()).unwrap_err();
    assert!(matches!(err2, PouwError::Unauthorized));

    let task = st.get_task(8_993).unwrap();
    assert_eq!(task.status, TaskStatus::Revealed);
    assert_eq!(task.challenger, None);
    assert_eq!(task.challenge_bond, None);
    assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
    );
}

#[test]
fn challenge_rejects_malformed_worker_id_in_revealed_state_without_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 8_994, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_994, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    // Simulate malformed legacy state carrying non-canonical worker account id.
    let mut malformed = st.get_task(r4.id).unwrap();
    malformed.worker = Some(" worker1".into());
    let r4 = st.update_task(r4, malformed).unwrap();

    let before = st.clone();
    let err =
        apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("non-canonical worker account")));

    let task = st.get_task(8_994).unwrap();
    assert_eq!(task.status, TaskStatus::Revealed);
    assert_eq!(task.challenger, None);
    assert_eq!(task.challenge_bond, None);
    assert_eq!(st.balance_of("challenger"), before.balance_of("challenger"));
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        before.balance_of(CHALLENGE_ESCROW_ACCOUNT)
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT)
    );
}
