use super::*;

#[test]
fn resolve_emergency_pause_precedes_challenger_authority_validation_without_escrow_mutation() {
    // Merge-gate hardening: emergency pause must fail-closed before challenger-role
    // separation checks so resolver-role probes cannot leak adjudicator policy outcomes.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "challenger");

    let r1 = apply_create_task(&mut st, 8_961_24, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_24, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_201_24, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_24).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(&mut st, r5, true, "challenger".into(), "challenger".into())
        .expect_err(
            "emergency pause must mask challenger-authority validation and freeze settlement",
        );
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_24).unwrap();
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
fn resolve_emergency_pause_precedes_multisig_challenger_member_validation_without_escrow_mutation()
{
    // Merge-gate hardening: emergency pause must fail-closed before challenger-member
    // multisig validation so role-separation probes cannot leak adjudicator policy.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority,challenger");

    let r1 = apply_create_task(&mut st, 8_961_24_1, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_24_1, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_201_24_1, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_24_1).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into()).expect_err(
        "emergency pause must mask challenger-member multisig validation and freeze settlement",
    );
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_24_1).unwrap();
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
fn resolve_emergency_pause_precedes_challenged_invariant_validation_without_escrow_mutation() {
    // Merge-gate hardening: emergency pause must fail-closed before challenged
    // accounting invariant checks so malformed challenged metadata cannot leak
    // resolver-policy validation outcomes while escrow settlement is frozen.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 8_961_24_15, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_24_15, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    // Corrupt challenged object to violate resolve challenged-accounting invariants.
    let mut bad = st.get_task(r5.id).unwrap();
    assert_eq!(bad.status, TaskStatus::Challenged);
    bad.challenge_bond_forfeited = Some(false);
    let bad_ref = st.update_task(r5, bad).unwrap();

    st.set_gov_param(9_201_24_15, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_24_15).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(
        &mut st,
        bad_ref,
        true,
        "authority".into(),
        "authority".into(),
    )
    .expect_err("emergency pause must mask challenged invariant validation path");
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_24_15).unwrap();
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
fn resolve_emergency_pause_precedes_assigned_worker_authority_validation_without_escrow_mutation() {
    // Merge-gate hardening: emergency pause must fail-closed before assigned-worker
    // authority membership validation so worker-role probes cannot leak adjudicator policy.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "worker1,authority-b");

    let r1 = apply_create_task(&mut st, 8_961_24_2, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_24_2, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_201_24_2, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_24_2).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(&mut st, r5, true, "worker1".into(), "worker1".into()).expect_err(
        "emergency pause must mask assigned-worker authority validation and freeze settlement",
    );
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_24_2).unwrap();
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
fn resolve_emergency_pause_precedes_assigned_worker_authority_member_validation_without_escrow_mutation(
) {
    // Merge-gate hardening: emergency pause must fail-closed before assigned-worker
    // separation checks so authority-list probes cannot leak adjudicator policy.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority,worker1");

    let r1 = apply_create_task(&mut st, 8_961_24_2, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_24_2, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_201_24_2, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_24_2).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into())
            .expect_err(
                "emergency pause must mask assigned-worker authority-member validation and freeze settlement",
            );
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_24_2).unwrap();
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
fn resolve_emergency_pause_precedes_placeholder_authority_validation_without_escrow_mutation() {
    // Merge-gate hardening: emergency pause must fail-closed before unconfigured
    // governance placeholder-authority validation to avoid auth-policy side channels.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    // Keep default unconfigured governance placeholder authority.

    let r1 = apply_create_task(&mut st, 8_961_25, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_25, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    st.set_gov_param(9_201_25, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_25).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let placeholder = DEFAULT_RESOLVE_AUTHORITY.to_string();
    let err = apply_resolve(&mut st, r5, true, placeholder.clone(), placeholder).expect_err(
        "emergency pause must mask placeholder-authority validation and freeze settlement",
    );
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_25).unwrap();
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
fn resolve_emergency_pause_precedes_malformed_worker_state_validation_without_escrow_mutation() {
    // Merge-gate hardening: emergency pause must fail-closed before malformed
    // worker-account state validation so paused resolve flow does not leak legacy
    // challenged-task corruption details while escrow settlement is frozen.
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    set_resolve_authority(&mut st, "authority");

    let r1 = apply_create_task(&mut st, 8_961_90, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(8_961_90, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    // Simulate malformed legacy challenged state carrying non-canonical worker id.
    let mut malformed = st.get_task(r5.id).unwrap();
    malformed.worker = Some(" worker1".into());
    let r5 = st.update_task(r5, malformed).unwrap();

    st.set_gov_param(9_201_90, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause=true governance update must succeed");
    assert!(st.is_emergency_paused());

    let before_task = st.get_task(8_961_90).unwrap();
    let before_escrow = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let before_forfeit = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let before_challenger = st.balance_of("challenger");

    let err = apply_resolve(&mut st, r5, true, "authority".into(), "authority".into()).expect_err(
        "emergency pause must mask malformed worker-state validation and freeze settlement",
    );
    assert!(matches!(err, PouwError::InvalidTransition));

    let after_task = st.get_task(8_961_90).unwrap();
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
