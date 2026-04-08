use super::*;

#[test]
fn paused_resolve_approval_rejects_control_or_whitespace_approver_without_mutating_staged_quorum() {
    // M1 micro-hardening: once a quorum stage exists, malformed approver spellings must fail
    // closed without clearing the staged resolve approval or perturbing custody while paused.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 77_700);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 888);

    st.set_gov_param(98_153, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.stage_or_confirm_resolve_approval(9_919, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_919), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_919).as_deref(),
        Some("authority-a")
    );

    for bad_approver in ["authority-b ", "authority-\tb", "authority-b\u{0007}"] {
        let err = st
            .stage_or_confirm_resolve_approval(
                9_919,
                1,
                true,
                bad_approver,
                "authority-a,authority-b",
            )
            .expect_err("malformed approver spelling must be rejected while paused");
        assert!(
            err.contains("whitespace") || err.contains("control characters"),
            "unexpected error for {:?}: {}",
            bad_approver,
            err
        );
        assert_eq!(
            st.pending_resolve_approval(9_919),
            Some((true, 1)),
            "rejected malformed approver must preserve staged quorum"
        );
        assert_eq!(
            st.pending_resolve_first_approver(9_919).as_deref(),
            Some("authority-a"),
            "rejected malformed approver must preserve first approver audit trail"
        );
    }

    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert!(st.is_emergency_paused());
}

#[test]
fn paused_resolve_approval_rejects_delimiter_or_non_ascii_approver_without_mutating_staged_quorum()
{
    // M1 micro-hardening: live resolve approval parsing must reject the same malformed approver
    // spellings that rollback/restore scrubs, so paused mode cannot stage quorum with delimiter
    // smuggling or non-ASCII actor ids.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 66_600);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 333);

    st.set_gov_param(98_154, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.stage_or_confirm_resolve_approval(9_923, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_923), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(9_923).as_deref(),
        Some("authority-a")
    );

    for bad_approver in ["authority|b", "authority；b", "authority，b", "authorité-b"] {
        let err = st
            .stage_or_confirm_resolve_approval(
                9_923,
                1,
                true,
                bad_approver,
                "authority-a,authority-b",
            )
            .expect_err("delimiter/non-ASCII approver must be rejected while paused");
        assert!(
            err.contains("single canonical actor id"),
            "unexpected error for {:?}: {}",
            bad_approver,
            err
        );
        assert_eq!(
            st.pending_resolve_approval(9_923),
            Some((true, 1)),
            "rejected malformed approver must preserve staged quorum"
        );
        assert_eq!(
            st.pending_resolve_first_approver(9_923).as_deref(),
            Some("authority-a"),
            "rejected malformed approver must preserve first approver audit trail"
        );
    }

    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert!(st.is_emergency_paused());
}

#[test]
fn paused_state_rejects_oversized_resolve_approver_without_side_effects() {
    // M1 micro-hardening: paused live resolve approval must enforce a canonical approver-id
    // length boundary so oversized actor ids cannot stage quorum or perturb custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_041);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_008);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 508);

    st.set_gov_param(98_221, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let oversized_approver = "a".repeat(129);
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(
            9_932,
            1,
            true,
            &oversized_approver,
            "authority-a,authority-b",
        )
        .expect_err("oversized paused resolve approver must be rejected");
    assert!(
        err.contains("max length") || err.contains("approver"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_932), None);
    assert_eq!(st.pending_resolve_first_approver(9_932), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
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
