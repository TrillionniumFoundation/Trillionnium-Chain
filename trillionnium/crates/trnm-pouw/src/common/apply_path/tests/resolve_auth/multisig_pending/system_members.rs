use super::*;

#[test]
fn resolve_rejects_reserved_system_member_in_multisig_authority_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority,system");

    let r1 = apply_create_task(&mut st, 9_001_7, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_7, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into()).unwrap_err();
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
fn resolve_rejects_multisig_authority_when_forfeit_treasury_is_member_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let authority_with_forfeit_member = format!("authority,{}", CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    set_resolve_authority(&mut st, &authority_with_forfeit_member);

    let r1 = apply_create_task(&mut st, 9_001_11, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_11, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, false, "authority".into(), "authority".into())
        .expect_err("authority sets including forfeit treasury member must be rejected");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_11).unwrap();
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
fn resolve_rejects_multisig_authority_when_forfeit_treasury_member_has_case_drift_without_escrow_mutation(
) {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let authority_with_case_drift_forfeit_member =
        format!("authority,{}", "Treasury.Challenge_Forfeits");
    set_resolve_authority(&mut st, &authority_with_case_drift_forfeit_member);

    let r1 = apply_create_task(&mut st, 9_001_12, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_12, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, false, "authority".into(), "authority".into())
        .expect_err("authority sets including case-drift forfeit treasury member must be rejected");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_12).unwrap();
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
fn resolve_rejects_multisig_authority_when_forfeit_treasury_member_has_whitespace_without_escrow_mutation(
) {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let authority_with_whitespace_forfeit_member =
        format!("authority, {}", CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    set_resolve_authority(&mut st, &authority_with_whitespace_forfeit_member);

    let r1 = apply_create_task(&mut st, 9_001_17, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_17, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, false, "authority".into(), "authority".into())
        .expect_err("authority sets including whitespace forfeit treasury member must be rejected");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_17).unwrap();
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
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before.balance_of(WORKER_SLASH_TREASURY_ACCOUNT)
    );
}
#[test]
fn resolve_rejects_multisig_authority_when_worker_slash_treasury_is_member_without_escrow_mutation()
{
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(
        &mut st,
        &format!("authority,{}", WORKER_SLASH_TREASURY_ACCOUNT),
    );

    let r1 = apply_create_task(&mut st, 9_001_15, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_15, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
        .expect_err("authority sets including worker-slash treasury member must be rejected");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_15).unwrap();
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
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before.balance_of(WORKER_SLASH_TREASURY_ACCOUNT)
    );
}
#[test]
fn resolve_rejects_multisig_authority_when_worker_slash_treasury_member_has_case_drift_without_escrow_mutation(
) {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let authority_with_case_drift_worker_slash_member = "Treasury.Worker_Slashes";
    set_resolve_authority(
        &mut st,
        &format!(
            "authority,{}",
            authority_with_case_drift_worker_slash_member
        ),
    );

    let r1 = apply_create_task(&mut st, 9_001_16, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_16, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into()).expect_err(
        "authority sets including case-drifted worker-slash treasury member must be rejected",
    );
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_16).unwrap();
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
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before.balance_of(WORKER_SLASH_TREASURY_ACCOUNT)
    );
}
#[test]
fn resolve_rejects_multisig_authority_when_worker_slash_treasury_member_has_whitespace_without_escrow_mutation(
) {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let authority_with_whitespace_worker_slash_member =
        format!("authority, {}", WORKER_SLASH_TREASURY_ACCOUNT);
    set_resolve_authority(&mut st, &authority_with_whitespace_worker_slash_member);

    let r1 = apply_create_task(&mut st, 9_001_19, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_19, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into()).expect_err(
        "authority sets including whitespace worker-slash treasury member must be rejected",
    );
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_19).unwrap();
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
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before.balance_of(WORKER_SLASH_TREASURY_ACCOUNT)
    );
}
#[test]
fn resolve_rejects_multisig_set_that_contains_placeholder_member_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let mixed_authority = format!("authority,{}", DEFAULT_RESOLVE_AUTHORITY);
    set_resolve_authority(&mut st, &mixed_authority);

    let r1 = apply_create_task(&mut st, 9_001_5, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_5, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into()).unwrap_err();
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_5).unwrap();
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
fn resolve_rejects_multisig_set_that_contains_escrow_member_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let mixed_authority = format!("authority,{}", CHALLENGE_ESCROW_ACCOUNT);
    set_resolve_authority(&mut st, &mixed_authority);

    let r1 = apply_create_task(&mut st, 9_001_5_1, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_5_1, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
        .expect_err("multisig authority containing escrow account must fail closed");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_5_1).unwrap();
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
fn resolve_rejects_multisig_set_that_contains_escrow_member_case_drift_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let mixed_authority = format!(
        "authority,{}",
        CHALLENGE_ESCROW_ACCOUNT.to_ascii_uppercase()
    );
    set_resolve_authority(&mut st, &mixed_authority);

    let r1 = apply_create_task(&mut st, 9_001_5_2, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_5_2, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into()).expect_err(
        "multisig authority containing escrow account with case drift must fail closed",
    );
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_5_2).unwrap();
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
fn resolve_rejects_multisig_authority_with_comma_whitespace_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let malformed_authority = "authority, guardian";
    set_resolve_authority(&mut st, malformed_authority);

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
        .expect_err("comma+whitespace authority list must fail closed");
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
fn resolve_rejects_multisig_authority_with_casefolded_duplicate_member_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    // Canonical member-set hardening: case-folded duplicates collapse signer
    // diversity and must fail closed before any escrow transfer path.
    let malformed_authority = "authority,AUTHORITY";
    set_resolve_authority(&mut st, malformed_authority);

    let r1 = apply_create_task(&mut st, 9_001_6_2, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_6_2, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
        .expect_err("case-folded duplicate multisig member must fail closed");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_6_2).unwrap();
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
fn resolve_rejects_multisig_authority_with_unicode_comma_whitespace_without_escrow_mutation() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    // Unicode ideographic space after comma must fail closed like ASCII whitespace.
    let malformed_authority = "authority,\u{3000}guardian";
    set_resolve_authority(&mut st, malformed_authority);

    let r1 = apply_create_task(&mut st, 9_001_6_1, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(9_001_6_1, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
        .expect_err("comma+unicode-whitespace authority list must fail closed");
    assert!(matches!(err, PouwError::Unauthorized));

    let task = st.get_task(9_001_6_1).unwrap();
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
