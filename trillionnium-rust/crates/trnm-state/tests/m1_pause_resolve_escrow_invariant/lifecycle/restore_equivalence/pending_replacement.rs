use super::*;

#[test]
fn paused_state_pending_replacement_resolve_approval_accepts_case_and_order_equivalent_authority_set(
) {
    // L03 boundary hardening: while paused, live resolve approvals must accept authority sets
    // that semantically match a pending resolve_authority replacement even if callers replay
    // the same members with different case or order. Benign representation drift must not
    // force governance to restart quorum staging or perturb custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_026);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_008);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 508);

    let bootstrap = st
        .set_gov_param(
            98_240,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_260,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_261,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    st.set_gov_param(98_262, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let first = st
        .stage_or_confirm_resolve_approval(
            9_932,
            4,
            false,
            "Authority-D",
            "Authority-D,Authority-C",
        )
        .expect("case/order-equivalent pending replacement authority should stage while paused");
    assert!(!first, "single approver should only stage paused quorum");
    assert_eq!(st.pending_resolve_approval(9_932), Some((false, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_932).as_deref(),
        Some("Authority-D"),
        "live staging should preserve original approver spelling for auditability"
    );
    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("replacement resolve_authority timelock should remain staged");
    assert_eq!(pending.value, "authority-c,authority-d");
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}

#[test]
fn paused_state_pending_replacement_resolve_approval_finalizes_with_case_and_order_equivalent_authority_set(
) {
    // L03 boundary hardening: once one paused approval is already staged against a pending
    // resolve_authority replacement, the second distinct approval must still finalize when the
    // caller replays the same pending authority members with case/order-only drift.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_027);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_009);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 509);

    let bootstrap = st
        .set_gov_param(
            98_240,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority write should succeed");
    assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
    let applied = st
        .set_gov_param(
            98_260,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve_authority should apply after timelock");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

    let replacement = st
        .set_gov_param(
            98_261,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    st.set_gov_param(98_262, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let first = st
        .stage_or_confirm_resolve_approval(
            9_933,
            4,
            false,
            "Authority-D",
            "Authority-D,Authority-C",
        )
        .expect("first approval should stage against pending replacement authority");
    assert!(
        !first,
        "first distinct approver should only stage paused quorum"
    );
    let root_after_first = st.state_root();

    let second = st
        .stage_or_confirm_resolve_approval(
            9_933,
            4,
            false,
            "authority-c",
            "authority-c,authority-d",
        )
        .expect("second approval should finalize against equivalent pending replacement authority");
    assert!(
        second,
        "second distinct approver should finalize paused quorum"
    );
    assert_eq!(st.pending_resolve_approval(9_933), Some((false, 2)));
    assert_eq!(
        st.pending_resolve_first_approver(9_933).as_deref(),
        Some("Authority-D"),
        "finalization must preserve the original first approver spelling for auditability"
    );
    assert_ne!(
        st.state_root(),
        root_after_first,
        "second distinct paused approval should advance the staged quorum state root"
    );

    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("replacement resolve_authority timelock should remain staged");
    assert_eq!(pending.value, "authority-c,authority-d");
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(
        st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT),
        worker_slash_before
    );
}
