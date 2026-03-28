use super::*;

#[test]
fn resolve_rejects_dirty_resolver_actor_ids() {
    for (i, dirty_resolver) in dirty_actor_ids().into_iter().enumerate() {
        let mut st = seeded_state();
        st.set_balance("worker1", 10);
        st.set_balance("challenger", 1_000);
        st.set_gov_param_bootstrap_unchecked(
            9_801 + i as u64,
            "resolve_authority".into(),
            "resolver1,resolver2".into(),
        )
        .unwrap();
        let task_id = 21_500 + i as u64;
        let r1 = apply_create_task(&mut st, task_id, "alice".into(), 10).unwrap();
        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
        let err = apply_resolve(
            &mut st,
            r5,
            false,
            dirty_resolver.into(),
            dirty_resolver.into(),
        )
        .unwrap_err();
        assert!(
            matches!(err, PouwError::Unauthorized),
            "resolve should reject dirty resolver actor id: {:?}",
            dirty_resolver
        );
    }
}
#[test]
fn resolve_rejects_inconsistent_challenged_task_missing_challenger_when_bond_exists() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 29057, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(29057, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    // Simulate an inconsistent legacy/corrupted challenged object.
    let mut bad = st.get_task(r5.id).unwrap();
    bad.challenger = None;
    let bad_ref = st.update_task(r5, bad).unwrap();

    set_resolve_authority(&mut st, "authority");
    let err = apply_resolve(
        &mut st,
        bad_ref,
        true,
        "authority".into(),
        "authority".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::State(_)));
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}
#[test]
fn resolve_rejects_blank_challenger_identity_without_balance_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 39001, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(39001, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    // Simulate malformed legacy state carrying a blank challenger identity.
    let mut bad = st.get_task(r5.id).unwrap();
    bad.challenger = Some("   ".into());
    let bad_ref = st.update_task(r5, bad).unwrap();

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    set_resolve_authority(&mut st, "authority");
    let err = apply_resolve(
        &mut st,
        bad_ref,
        true,
        "authority".into(),
        "authority".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("blank challenger identity")));

    let task = st.get_task(39001).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
}

#[test]
fn resolve_rejects_non_canonical_challenger_identity_without_balance_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 39002, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(39002, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    // Simulate malformed legacy state carrying non-canonical challenger identity.
    let mut bad = st.get_task(r5.id).unwrap();
    bad.challenger = Some(" challenger".into());
    let bad_ref = st.update_task(r5, bad).unwrap();

    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    set_resolve_authority(&mut st, "authority");
    let err = apply_resolve(
        &mut st,
        bad_ref,
        true,
        "authority".into(),
        "authority".into(),
    )
    .unwrap_err();
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("non-canonical challenger identity"))
    );

    let task = st.get_task(39002).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
}
#[test]
fn resolve_rejects_hidden_char_challenger_identity_without_balance_mutation() {
    for (i, dirty_challenger) in ["challenger\u{200b}", "challenger\u{2060}"]
        .into_iter()
        .enumerate()
    {
        let mut st = seeded_state();
        st.set_balance("challenger", 100);

        let task_id = 39_003 + i as u64;
        let r1 = apply_create_task(&mut st, task_id, "alice".into(), 100).unwrap();
        let result_hash = [1u8; 32];
        let reveal_salt = [2u8; 32];
        let committed = compute_commitment(task_id, &result_hash, &reveal_salt, "worker1");

        let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let mut bad = st.get_task(r5.id).unwrap();
        bad.challenger = Some(dirty_challenger.into());
        let bad_ref = st.update_task(r5, bad).unwrap();

        let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
        let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

        set_resolve_authority(&mut st, "authority");
        let err = apply_resolve(
            &mut st,
            bad_ref,
            true,
            "authority".into(),
            "authority".into(),
        )
        .unwrap_err();
        assert!(
            matches!(err, PouwError::State(msg) if msg.contains("non-canonical challenger identity"))
        );

        let task = st.get_task(task_id).unwrap();
        assert_eq!(task.status, TaskStatus::Challenged);
        assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
        assert_eq!(
            st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
            before_forfeit
        );
    }
}
#[test]
fn resolve_rejects_challenged_state_without_bond_fields_even_if_status_is_challenged() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 39011, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(39011, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let mut bad = st.get_task(r5.id).unwrap();
    bad.challenge_bond = None;
    bad.challenger = None;
    let bad_ref = st.update_task(r5, bad).unwrap();

    set_resolve_authority(&mut st, "authority");
    let err = apply_resolve(
        &mut st,
        bad_ref,
        false,
        "authority".into(),
        "authority,authority2".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::State(_)));
    assert_eq!(st.get_task(39011).unwrap().status, TaskStatus::Challenged);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
}
#[test]
fn resolve_replay_attempt_after_terminal_resolution_is_rejected_without_double_payout() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority,authority2");

    let r1 = apply_create_task(&mut st, 8_995, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_995, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let staged = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority".into(),
        "authority".into(),
    )
    .unwrap_err();
    assert!(matches!(staged, PouwError::ResolveApprovalStaged));
    let r6 = apply_resolve(&mut st, r5, true, "authority2".into(), "authority2".into()).unwrap();
    let challenger_after_first_resolve = st.balance_of("challenger");
    let escrow_after_first_resolve = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeit_after_first_resolve = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = apply_resolve(&mut st, r6, true, "authority".into(), "authority".into()).unwrap_err();
    assert!(matches!(err, PouwError::InvalidTransition));

    assert_eq!(st.balance_of("challenger"), challenger_after_first_resolve);
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        escrow_after_first_resolve
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeit_after_first_resolve
    );
}
#[test]
fn resolve_preflight_overflow_rejects_without_status_or_balance_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, u128::MAX - 5);

    let r1 = apply_create_task(&mut st, 9952, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9952, &result_hash, &reveal_salt, "worker1");
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    set_resolve_authority(&mut st, "authority,authority2");
    let err =
        apply_resolve(&mut st, r5, false, "authority".into(), "authority".into()).unwrap_err();
    assert!(matches!(err, PouwError::State(_)));

    let task = st.get_task(9952).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(st.balance_of("challenger"), 90);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        u128::MAX - 5
    );
}
#[test]
fn resolve_version_conflict_does_not_move_funds() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 9902, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9902, &result_hash, &reveal_salt, "worker1");
    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    set_resolve_authority(&mut st, "authority,authority2");
    let staged = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority".into(),
        "authority".into(),
    )
    .unwrap_err();
    assert!(matches!(staged, PouwError::ResolveApprovalStaged));
    let stale_ref = r5.clone();
    let same_task = st.get_task(r5.id).unwrap();
    let _fresh_ref = st.update_task(r5, same_task).unwrap();

    let err = apply_resolve(
        &mut st,
        stale_ref,
        false,
        "authority2".into(),
        "authority2".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::VersionConflict));
    assert_eq!(st.balance_of("challenger"), 90);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}
#[test]
fn resolve_preflight_rejects_slash_refund_without_challenger() {
    let st = seeded_state();
    let task = TaskObject {
        task_id: 76,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Challenged,
        proof_type: Default::default(),
        metadata: None,
        worker: Some("worker1".into()),
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: Some(1),
        reveal_deadline_height: Some(10),
        challenge_deadline_height: Some(20),
        challenge_window_blocks_snapshot: Some(10),
        challenged_at_height: Some(11),
        resolve_deadline_height: Some(30),
        challenge_bond: Some(10),
        challenge_bond_forfeited: None,
        challenger: None,
        version: 0,
    };

    let err = preflight_resolve_transfers(&st, &task, true).unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("without challenger")));
}
