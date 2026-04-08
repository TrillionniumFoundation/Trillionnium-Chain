use super::*;

#[test]
fn challenge_requires_min_bond_from_worker_stake_floor() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9000, "challenge_min_bond".into(), "1".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(9001, "challenge_min_bond_bounty_bps".into(), "1".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(9002, "min_worker_stake".into(), "80".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9003,
        "challenge_min_bond_worker_stake_bps".into(),
        "2500".into(),
    )
    .unwrap();

    let r1 = apply_create_task(&mut st, 887, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(887, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    // Worker stake floor = ceil(80 * 25%) = 20, which should dominate static/bounty floors.
    let err = apply_challenge(
        &mut st,
        r4.clone(),
        "challenger".into(),
        19,
        "challenger".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::InsufficientStake));

    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 20, "challenger".into()).unwrap();
    let task = st.get_task(r5.id).unwrap();
    assert_eq!(task.challenge_bond, Some(20));
}

#[test]
fn challenge_requires_min_bond_as_max_of_governance_bounty_and_worker_stake_floors() {
    let mut st = seeded_state();
    st.set_balance("challenger", 200);
    st.set_gov_param_bootstrap_unchecked(9004, "challenge_min_bond".into(), "30".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9005,
        "challenge_min_bond_bounty_bps".into(),
        "5000".into(),
    )
    .unwrap();
    st.set_gov_param_bootstrap_unchecked(9006, "min_worker_stake".into(), "80".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9007,
        "challenge_min_bond_worker_stake_bps".into(),
        "7500".into(),
    )
    .unwrap();

    let r1 = apply_create_task(&mut st, 886, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(886, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    // Floors are: governance=30, bounty=50, worker-stake=60; effective min bond is max=60.
    let err = apply_challenge(
        &mut st,
        r4.clone(),
        "challenger".into(),
        59,
        "challenger".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::InsufficientStake));

    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 60, "challenger".into()).unwrap();
    let task = st.get_task(r5.id).unwrap();
    assert_eq!(task.challenge_bond, Some(60));
}

#[test]
fn challenge_requires_min_bond_from_governance() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9001, "challenge_min_bond".into(), "50".into())
        .unwrap();

    let r1 = apply_create_task(&mut st, 888, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(888, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    let err = apply_challenge(
        &mut st,
        r4.clone(),
        "challenger".into(),
        49,
        "challenger".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::InsufficientStake));

    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 50, "challenger".into()).unwrap();
    let task = st.get_task(r5.id).unwrap();
    assert_eq!(task.challenge_bond, Some(50));
}

#[test]
fn challenge_requires_min_bond_default_when_governance_absent() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 890, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(890, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    let err = apply_challenge(
        &mut st,
        r4.clone(),
        "challenger".into(),
        9,
        "challenger".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::InsufficientStake));

    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
    let task = st.get_task(r5.id).unwrap();
    assert_eq!(task.challenge_bond, Some(10));
}

#[test]
fn challenge_rejects_zero_bond() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 889, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(889, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    let err =
        apply_challenge(&mut st, r4, "challenger".into(), 0, "challenger".into()).unwrap_err();
    assert!(matches!(err, PouwError::InsufficientStake));
}

#[test]
fn challenge_rejects_spam_like_low_bond_under_dynamic_bounty_floor() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9050, "challenge_min_bond".into(), "10".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9051,
        "challenge_min_bond_bounty_bps".into(),
        "5000".into(),
    )
    .unwrap();

    let r1 = apply_create_task(&mut st, 29050, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(29050, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    let err =
        apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap_err();
    assert!(matches!(err, PouwError::InsufficientStake));
}

#[test]
fn challenge_accepts_normal_bond_when_dynamic_floor_met() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9052, "challenge_min_bond".into(), "10".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9053,
        "challenge_min_bond_bounty_bps".into(),
        "5000".into(),
    )
    .unwrap();

    let r1 = apply_create_task(&mut st, 29052, "alice".into(), 100).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(29052, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 50, "challenger".into()).unwrap();
    let task = st.get_task(r5.id).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenge_bond, Some(50));
}

#[test]
fn challenge_dynamic_floor_boundary_ceil_passes_and_fails() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);
    st.set_gov_param_bootstrap_unchecked(9054, "challenge_min_bond".into(), "1".into())
        .unwrap();
    st.set_gov_param_bootstrap_unchecked(
        9055,
        "challenge_min_bond_bounty_bps".into(),
        "500".into(),
    )
    .unwrap();

    let r1 = apply_create_task(&mut st, 29054, "alice".into(), 101).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(29054, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    let err = apply_challenge(
        &mut st,
        r4.clone(),
        "challenger".into(),
        5,
        "challenger".into(),
    )
    .unwrap_err();
    assert!(matches!(err, PouwError::InsufficientStake));

    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 6, "challenger".into()).unwrap();
    let task = st.get_task(r5.id).unwrap();
    assert_eq!(task.challenge_bond, Some(6));
}

#[test]
fn challenge_accepts_when_signer_matches_challenger() {
    let mut st = seeded_state();
    st.set_balance("challenger", 100);

    let r1 = apply_create_task(&mut st, 899, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(899, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();
    let task = st.get_task(r5.id).unwrap();
    assert_eq!(task.status, TaskStatus::Challenged);
    assert_eq!(task.challenger.as_deref(), Some("challenger"));
    assert_eq!(task.challenge_bond, Some(10));
    assert_eq!(st.balance_of("challenger"), 90);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 10);
}

#[test]
fn challenge_rejects_when_challenger_balance_insufficient() {
    let mut st = seeded_state();
    st.set_balance("challenger", 5);

    let r1 = apply_create_task(&mut st, 892, "alice".into(), 10).unwrap();
    let result_hash = [1u8; 32];
    let reveal_salt = [2u8; 32];
    let committed = compute_commitment(892, &result_hash, &reveal_salt, "worker1");

    let r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker1".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();

    let err =
        apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap_err();
    assert!(matches!(err, PouwError::InsufficientStake));
    assert_eq!(st.balance_of("challenger"), 5);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), 0);
    assert_eq!(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT), 0);
}
