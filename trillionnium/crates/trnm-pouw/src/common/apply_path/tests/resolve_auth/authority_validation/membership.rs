use super::*;

#[test]
fn resolve_rejects_creator_as_authority_member_or_signer() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let r1 = apply_create_task(&mut st, 420, "alice".into(), 100).unwrap();

    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(420, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    set_resolve_authority(&mut st, "alice,authority2");
    let err = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority2".into(),
        "authority2".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));

    set_resolve_authority(&mut st, "authority,Alice");
    let err = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority".into(),
        "authority".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));

    set_resolve_authority(&mut st, "authority,authority2");
    let err = apply_resolve(&mut st, r5.clone(), false, "alice".into(), "alice".into())
        .unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));

    let err = apply_resolve(&mut st, r5, false, "Alice".into(), "Alice".into()).unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));
}

#[test]
fn resolve_rejects_challenger_when_not_configured_authority() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 894, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(894, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let err =
        apply_resolve(&mut st, r5, true, "challenger".into(), "challenger".into()).unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(894).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(st.balance_of("challenger"), 90);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}

#[test]
fn resolve_accepts_configured_authority_resolver() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority,authority2");

    let r1 = apply_create_task(&mut st, 895, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(895, &result_hash, &reveal_salt, "worker1");

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
    let task = st.get_task(r6.id).unwrap();
    assert_eq!(task.status, TaskStatus::Slashed);
    assert_eq!(task.challenge_bond_forfeited, Some(false));
    assert_eq!(st.balance_of("challenger"), 101);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}
