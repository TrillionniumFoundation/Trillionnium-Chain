use super::*;

#[test]
fn timeout_scan_auto_migrates_committed_revealed_and_challenged() {
    let mut st = StateStore::new();
    st.set_balance("challenger", 1_000_000);
    st.set_balance("worker7001", 1_000);
    st.set_balance("worker7002", 1_000);
    st.set_balance("worker7003", 1_000);

    let r1 = apply_create_task(&mut st, 7001, "alice".into(), 100).unwrap();
    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(7001, &result_hash, &reveal_salt, "worker7001");
    let r2 = apply_accept_task(&mut st, r1, "worker7001".into()).unwrap();
    let _r3 =
        trnm_pouw::apply_commit_result_at_height(&mut st, r2, "worker7001".into(), committed, 100)
            .unwrap();

    let r4 = apply_create_task(&mut st, 7002, "alice".into(), 100).unwrap();
    let committed2 = compute_commitment(7002, &result_hash, &reveal_salt, "worker7002");
    let r5 = apply_accept_task(&mut st, r4, "worker7002".into()).unwrap();
    let r6 =
        trnm_pouw::apply_commit_result_at_height(&mut st, r5, "worker7002".into(), committed2, 100)
            .unwrap();
    let r7 =
        trnm_pouw::apply_reveal_result_at_height(&mut st, r6, result_hash, reveal_salt, None, 110)
            .unwrap();
    let _r8 = trnm_pouw::apply_challenge_at_height(
        &mut st,
        r7,
        "challenger".into(),
        10,
        "challenger".into(),
        120,
    )
    .unwrap();

    let r9 = apply_create_task(&mut st, 7003, "alice".into(), 100).unwrap();
    let committed3 = compute_commitment(7003, &result_hash, &reveal_salt, "worker7003");
    let r10 = apply_accept_task(&mut st, r9, "worker7003".into()).unwrap();
    let r11 = trnm_pouw::apply_commit_result_at_height(
        &mut st,
        r10,
        "worker7003".into(),
        committed3,
        100,
    )
    .unwrap();
    let _r12 =
        trnm_pouw::apply_reveal_result_at_height(&mut st, r11, result_hash, reveal_salt, None, 110)
            .unwrap();

    let known: HashSet<u64> = [7001u64, 7002u64, 7003u64].into_iter().collect();
    let migrated = scan_and_apply_timeouts(&mut st, &known, 10_000, 9_000_000);

    assert_eq!(migrated, 3);
    assert_eq!(st.get_task(7001).unwrap().status, TaskStatus::Slashed);
    assert_eq!(st.get_task(7002).unwrap().status, TaskStatus::Completed);
    assert_eq!(st.get_task(7003).unwrap().status, TaskStatus::Completed);
}

#[test]
fn timeout_scan_revealed_boundary_at_deadline_and_after() {
    let mut st = StateStore::new();
    st.set_balance("worker7004", 1_000);

    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let r1 = apply_create_task(&mut st, 7004, "alice".into(), 100).unwrap();
    let committed = compute_commitment(7004, &result_hash, &reveal_salt, "worker7004");
    let r2 = apply_accept_task(&mut st, r1, "worker7004".into()).unwrap();
    let r3 =
        trnm_pouw::apply_commit_result_at_height(&mut st, r2, "worker7004".into(), committed, 100)
            .unwrap();
    let _r4 =
        trnm_pouw::apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

    let challenge_deadline = st
        .get_task(7004)
        .and_then(|t| t.challenge_deadline_height)
        .expect("challenge deadline must be present after reveal");

    let known: HashSet<u64> = [7004u64].into_iter().collect();

    let migrated_at_deadline =
        scan_and_apply_timeouts(&mut st, &known, challenge_deadline, 9_100_000);
    assert_eq!(migrated_at_deadline, 0);
    assert_eq!(st.get_task(7004).unwrap().status, TaskStatus::Revealed);

    let migrated_after_deadline = scan_and_apply_timeouts(
        &mut st,
        &known,
        challenge_deadline.saturating_add(1),
        9_100_100,
    );
    assert_eq!(migrated_after_deadline, 1);
    assert_eq!(st.get_task(7004).unwrap().status, TaskStatus::Completed);
}

#[test]
fn timeout_scan_revealed_task_still_finalizes_while_emergency_paused() {
    // Safety boundary scope: emergency pause should block challenged escrow
    // settlement paths only, not uncontested revealed timeout completion.
    let mut st = StateStore::new();
    st.set_balance("worker7005", 1_000);

    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let r1 = apply_create_task(&mut st, 7005, "alice".into(), 100).unwrap();
    let committed = compute_commitment(7005, &result_hash, &reveal_salt, "worker7005");
    let r2 = apply_accept_task(&mut st, r1, "worker7005".into()).unwrap();
    let r3 =
        trnm_pouw::apply_commit_result_at_height(&mut st, r2, "worker7005".into(), committed, 100)
            .unwrap();
    let _r4 =
        trnm_pouw::apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();

    st.set_gov_param(9_230, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let challenge_deadline = st
        .get_task(7005)
        .and_then(|t| t.challenge_deadline_height)
        .expect("challenge deadline must be present after reveal");

    let known: HashSet<u64> = [7005u64].into_iter().collect();
    let migrated = scan_and_apply_timeouts(
        &mut st,
        &known,
        challenge_deadline.saturating_add(1),
        9_100_200,
    );

    assert_eq!(migrated, 1);
    let task = st
        .get_task(7005)
        .expect("task must exist after timeout scan");
    assert_eq!(task.status, TaskStatus::Completed);
    assert_eq!(task.challenge_bond_forfeited, None);
}

#[test]
fn timeout_scan_skips_challenged_task_while_paused_without_mutating_staged_resolve_state() {
    // Governance boundary hardening: the node-level timeout scanner must not touch
    // challenged settlement while paused, preserving staged resolve quorum and escrow.
    let mut st = StateStore::new();
    st.set_balance("worker7006", 1_000);
    st.set_balance("challenger7006", 100);
    st.set_gov_param_bootstrap_unchecked(
        9_500,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .expect("bootstrap resolve authority should succeed");

    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let r1 = apply_create_task(&mut st, 7006, "alice".into(), 100).unwrap();
    let committed = compute_commitment(7006, &result_hash, &reveal_salt, "worker7006");
    let r2 = apply_accept_task(&mut st, r1, "worker7006".into()).unwrap();
    let r3 =
        trnm_pouw::apply_commit_result_at_height(&mut st, r2, "worker7006".into(), committed, 100)
            .unwrap();
    let r4 =
        trnm_pouw::apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();
    let r5 = trnm_pouw::apply_challenge_at_height(
        &mut st,
        r4,
        "challenger7006".into(),
        10,
        "challenger7006".into(),
        210,
    )
    .unwrap();

    let staged = apply_resolve_at_height(
        &mut st,
        r5.clone(),
        true,
        "authority-a".into(),
        "authority-a".into(),
        211,
    )
    .expect_err("first resolve approval should only stage quorum");
    assert!(matches!(
        staged,
        trnm_pouw::PouwError::ResolveApprovalStaged
    ));
    assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(r5.id).as_deref(),
        Some("authority-a")
    );

    st.set_gov_param(9_231, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let resolve_deadline = st
        .get_task(7006)
        .and_then(|t| t.resolve_deadline_height)
        .expect("resolve deadline must be present after challenge");
    let before_task = st.get_task(7006).expect("challenged task must exist");
    let before_root = st.state_root();
    let before_escrow = st.balance_of("treasury.challenge_escrow");
    let before_forfeit = st.balance_of("treasury.challenge_forfeits");
    let before_worker_slash = st.balance_of("treasury.worker_slashes");
    let before_challenger = st.balance_of("challenger7006");

    let known: HashSet<u64> = [7006u64].into_iter().collect();
    let migrated = scan_and_apply_timeouts(
        &mut st,
        &known,
        resolve_deadline.saturating_add(1),
        9_100_201,
    );

    assert_eq!(migrated, 0);
    let after_task = st
        .get_task(7006)
        .expect("challenged task must remain after paused scan");
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.pending_resolve_approval(7006), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(7006).as_deref(),
        Some("authority-a")
    );
    assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
    assert_eq!(st.balance_of("treasury.challenge_forfeits"), before_forfeit);
    assert_eq!(
        st.balance_of("treasury.worker_slashes"),
        before_worker_slash
    );
    assert_eq!(st.balance_of("challenger7006"), before_challenger);
    assert_eq!(
        st.state_root(),
        before_root,
        "paused timeout skip must preserve the deterministic state_root exactly"
    );
    assert_eq!(
        st.state_root(),
        before_root,
        "repeated reads after paused timeout skip should deterministically reuse the unchanged root"
    );
}
