use super::*;

#[test]
fn resolve_rejects_malformed_governance_authority_with_whitespace_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    // Governance drift: authority must be canonical and whitespace-free.
    set_resolve_authority(&mut st, "authority ");

    let r1 = apply_create_task(&mut st, 9_001_6, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_6, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
        .expect_err("malformed governance authority must fail closed");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_6).unwrap();
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

fn resolve_rejects_governance_authority_with_internal_whitespace_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    // Internal whitespace must also fail closed to preserve canonical actor ids.
    set_resolve_authority(&mut st, "authority team");

    let r1 = apply_create_task(&mut st, 9_001_7, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_7, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(
        &mut st,
        r5,
        true,
        "authority team".into(),
        "authority team".into(),
    )
    .expect_err("internal-whitespace governance authority must fail closed");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_7).unwrap();
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

fn resolve_rejects_governance_authority_with_unicode_internal_whitespace_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    // Unicode whitespace (U+3000 ideographic space) must be rejected the same as ASCII space.
    let authority = "authority\u{3000}team";
    set_resolve_authority(&mut st, authority);

    let r1 = apply_create_task(&mut st, 9_001_71, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_71, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, true, authority.into(), authority.into())
        .expect_err("unicode internal-whitespace governance authority must fail closed");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_71).unwrap();
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
