use super::*;

#[test]
fn paused_resolve_authority_same_value_replace_preserves_pending_timelock_and_staged_quorum() {
    // L03 paused-boundary idempotence: replaying the exact same pre-activation
    // resolve_authority replacement while emergency_pause is active must not extend the
    // timelock or scrub quorum already staged against the pending authority set.
    let mut st = StateStore::new();

    st.set_gov_param(
        98_300,
        7_310,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .expect("bootstrap resolve_authority write should succeed");
    st.set_gov_param(
        98_320,
        7_310,
        "resolve_authority".into(),
        "authority-a,authority-b".into(),
    )
    .expect("bootstrap resolve_authority should apply after timelock");

    let activate_at_height = match st
        .set_gov_param_with_action(
            98_340,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("replacement resolve_authority update should schedule while unpaused")
    {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        other => panic!("expected scheduled outcome, got {:?}", other),
    };

    st.set_gov_param(98_341, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_984, 1, true, "authority-c", "authority-c,authority-d")
        .expect("pending replacement authority should stage approval while paused");

    let pending_before = st
        .pending_resolve_approval_snapshot(9_984)
        .expect("staged resolve approval should exist before paused idempotent replay");
    let root_with_pending = st.state_root();

    let replay = st
        .set_gov_param_with_action(
            98_342,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("replaying identical paused replacement must be idempotent");

    match replay {
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: replay_height,
        } => {
            assert_eq!(
                replay_height, activate_at_height,
                "paused idempotent replay must not extend resolve_authority timelock"
            );
        }
        other => panic!("expected scheduled outcome, got {:?}", other),
    }

    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("pending resolve_authority timelock should remain staged while paused");
    assert_eq!(pending.value, "authority-c,authority-d");
    assert_eq!(pending.activate_at_height, activate_at_height);
    assert_eq!(
        st.pending_resolve_approval_snapshot(9_984),
        Some(pending_before)
    );
    assert!(st.is_emergency_paused());
    assert_eq!(
        st.state_root(),
        root_with_pending,
        "paused idempotent replay must not invalidate cached state root when no boundary changes"
    );
}

#[test]
fn paused_state_identical_resolve_authority_replace_replay_preserves_staged_quorum_and_escrow() {
    // M1 micro-hardening: while paused, replaying an identical pre-maturity replace against the
    // same pending resolve_authority boundary must stay idempotent. It must preserve staged
    // quorum, keep escrow balances unchanged, and avoid moving the timelock boundary.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_333);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 903);

    let bootstrap = st
        .set_gov_param(
            98_160,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));

    let applied = st
        .set_gov_param(
            98_180,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let scheduled = st
        .set_gov_param_with_action(
            98_181,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("replacement resolve_authority update should be timelocked");
    let activate_at_height = match scheduled {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        other => panic!("expected Scheduled outcome, got {other:?}"),
    };

    st.set_gov_param(98_182, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let staged = st
        .stage_or_confirm_resolve_approval(
            9_819_0,
            4,
            true,
            "authority-c",
            "authority-c,authority-d",
        )
        .expect("approval matching pending paused resolve authority should stage");
    assert!(!staged, "single approver should only stage pending quorum");
    let pending_before = st
        .pending_resolve_approval_snapshot(9_819_0)
        .expect("paused staged quorum should exist before identical replace replay");
    let root_with_pending = st.state_root();
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let replayed = st
        .set_gov_param_with_action(
            98_190,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
            GovPendingUpdateAction::Replace,
        )
        .expect("paused identical replace replay should remain idempotent");
    assert_eq!(
        replayed,
        GovParamUpdateOutcome::Scheduled { activate_at_height }
    );

    let pending_after = st
        .pending_gov_update("resolve_authority")
        .expect("pending resolve_authority update should remain staged after replay");
    assert_eq!(pending_after.value, "authority-c,authority-d");
    assert_eq!(pending_after.activate_at_height, activate_at_height);
    assert_eq!(
        st.pending_resolve_approval_snapshot(9_819_0),
        Some(pending_before),
        "paused identical replace replay must preserve staged quorum"
    );
    assert_eq!(
        st.state_root(),
        root_with_pending,
        "paused identical replace replay must not perturb staged quorum state root"
    );
    assert!(
        st.is_emergency_paused(),
        "paused identical replace replay must not unpause state"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "paused identical replace replay must not apply pending authority set early"
    );
}
