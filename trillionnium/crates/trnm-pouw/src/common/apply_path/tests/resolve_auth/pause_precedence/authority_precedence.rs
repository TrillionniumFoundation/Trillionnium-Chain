use super::*;

#[test]
fn resolve_emergency_pause_precedes_authority_checks_without_escrow_mutation() {
    // Merge-gate hardening: emergency pause must fail-closed before signer/authority
    // checks, so challenged escrow cannot leak side-channel auth outcomes.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 8_961_1, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_1, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_201_1, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_1).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(&mut st, r5, true, "attacker".into(), "attacker".into())
        .expect_err("emergency pause must mask authority result and freeze challenged settlement");
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_1).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
#[test]
fn resolve_emergency_pause_precedes_reserved_system_actor_validation_without_escrow_mutation() {
    // Merge-gate hardening: emergency pause must fail-closed before reserved
    // system-actor validation so authorization policy details stay non-observable
    // while challenged escrow settlement paths are frozen.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "system");

    let r1 = apply_create_task(&mut st, 8_961_15, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_15, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_201_15, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_15).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(&mut st, r5, true, "system".into(), "system".into()).expect_err(
        "emergency pause must mask reserved system-actor validation and freeze settlement",
    );
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_15).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
#[test]
fn resolve_emergency_pause_precedes_multisig_member_validation_without_escrow_mutation() {
    // Merge-gate hardening: emergency pause must fail-closed before malformed
    // resolve-authority member set validation to avoid auth-shape side channels.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority,");

    let r1 = apply_create_task(&mut st, 8_961_2, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_2, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_201_2, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_2).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into()).expect_err(
        "emergency pause must mask malformed authority-member validation and freeze settlement",
    );
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_2).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
#[test]
fn resolve_emergency_pause_precedes_leading_empty_multisig_member_validation_without_escrow_mutation(
) {
    // Merge-gate hardening: emergency pause must fail-closed before leading-empty
    // authority-member validation to avoid leaking parser/shape policy details.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, ",authority");

    let r1 = apply_create_task(&mut st, 8_961_2_0, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_2_0, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_201_2_0, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_2_0).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into()).expect_err(
        "emergency pause must mask leading-empty authority-member validation and freeze settlement",
    );
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_2_0).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
#[test]
fn resolve_emergency_pause_precedes_duplicate_multisig_member_validation_without_escrow_mutation() {
    // Merge-gate hardening: emergency pause must fail-closed before duplicate
    // resolver-member validation so multisig-shape probing cannot leak governance policy.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority,authority");

    let r1 = apply_create_task(&mut st, 8_961_2_1, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_2_1, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_201_2_1, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_2_1).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into()).expect_err(
        "emergency pause must mask duplicate authority-member validation and freeze settlement",
    );
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_2_1).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
#[test]
fn resolve_emergency_pause_precedes_escrow_member_multisig_validation_without_escrow_mutation() {
    // Merge-gate hardening: emergency pause must fail-closed before escrow-member
    // authority-set validation to avoid leaking governance role-separation outcomes.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let authority_with_escrow_member = format!("authority,{}", CHALLENGE_ESCROW_ACCOUNT);
    set_resolve_authority(&mut st, &authority_with_escrow_member);

    let r1 = apply_create_task(&mut st, 8_961_21, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_21, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_201_21, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_21).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into()).expect_err(
        "emergency pause must mask escrow-member authority validation and freeze settlement",
    );
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_21).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
#[test]
fn resolve_emergency_pause_precedes_escrow_account_authority_validation_without_escrow_mutation() {
    // Merge-gate hardening: emergency pause must fail-closed before escrow-account
    // authority validation to avoid leaking custody-role separation outcomes.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, CHALLENGE_ESCROW_ACCOUNT);

    let r1 = apply_create_task(&mut st, 8_961_211, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_211, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_201_211, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_211).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(
        &mut st,
        r5,
        true,
        CHALLENGE_ESCROW_ACCOUNT.into(),
        CHALLENGE_ESCROW_ACCOUNT.into(),
    )
    .expect_err(
        "emergency pause must mask escrow-account authority validation and freeze settlement",
    );
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_211).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
#[test]
fn resolve_emergency_pause_precedes_forfeit_member_multisig_validation_without_escrow_mutation() {
    // Merge-gate hardening: emergency pause must fail-closed before forfeit-treasury
    // member authority-set validation to avoid leaking role-separation outcomes.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    let authority_with_forfeit_member = format!("authority,{}", CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    set_resolve_authority(&mut st, &authority_with_forfeit_member);

    let r1 = apply_create_task(&mut st, 8_961_219, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_219, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_201_219, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_219).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into()).expect_err(
        "emergency pause must mask forfeit-member authority validation and freeze settlement",
    );
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_219).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
#[test]
fn resolve_emergency_pause_precedes_forfeit_treasury_authority_validation_without_escrow_mutation()
{
    // Merge-gate hardening: emergency pause must fail-closed before forfeit-treasury
    // authority validation to avoid leaking custody-role separation outcomes.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let r1 = apply_create_task(&mut st, 8_961_22, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_22, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_201_22, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_22).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(
        &mut st,
        r5,
        true,
        CHALLENGE_FORFEIT_TREASURY_ACCOUNT.into(),
        CHALLENGE_FORFEIT_TREASURY_ACCOUNT.into(),
    )
    .expect_err(
        "emergency pause must mask forfeit-treasury authority validation and freeze settlement",
    );
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_22).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
#[test]
fn resolve_emergency_pause_precedes_worker_slash_treasury_authority_validation_without_escrow_mutation(
) {
    // Merge-gate hardening: emergency pause must fail-closed before worker-slash
    // treasury authority validation to avoid leaking custody-role separation outcomes.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, WORKER_SLASH_TREASURY_ACCOUNT);

    let r1 = apply_create_task(&mut st, 8_961_23, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_23, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_201_23, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_23).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_worker_slash = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(
            &mut st,
            r5,
            true,
            WORKER_SLASH_TREASURY_ACCOUNT.into(),
            WORKER_SLASH_TREASURY_ACCOUNT.into(),
        )
        .expect_err(
            "emergency pause must mask worker-slash treasury authority validation and freeze settlement",
        );
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_23).unwrap();
    assert_eq!(after_task.status, before_task.status);
    assert_eq!(
        after_task.challenge_bond_forfeited,
        before_task.challenge_bond_forfeited
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), before_escrow);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        before_forfeit
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        before_worker_slash
    );
    assert_eq!(st.balance_of("challenger"), before_challenger);
}
