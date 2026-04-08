use super::*;

#[test]
fn resolve_rejects_when_payload_resolver_matches_but_signer_is_attacker() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 896, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(896, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let err = apply_resolve(&mut st, r5, true, "authority".into(), "attacker".into()).unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(896).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(st.balance_of("challenger"), 90);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}

#[test]
fn resolve_rejects_payload_resolver_that_diverges_from_authority_signer() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 8_996, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_996, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(
        &mut st,
        r5,
        true,
        "auditor_alias".into(),
        "authority".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(8_996).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
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
fn resolve_rejects_noncanonical_payload_resolver_even_if_signer_is_authority() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 897, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(897, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err =
        apply_resolve(&mut st, r5, false, " authority ".into(), "authority".into()).unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(897).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
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
fn resolve_rejects_blank_signer_without_state_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 8_998, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_998, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, true, "authority".into(), "   ".into()).unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(8_998).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond_forfeited, None);
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
