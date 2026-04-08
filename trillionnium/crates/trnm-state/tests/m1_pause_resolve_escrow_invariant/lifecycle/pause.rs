use super::*;

#[test]
fn paused_state_preserves_escrow_and_keeps_resolve_authority_timelocked() {
    // M1 merge-gate invariant: emergency_pause is a safety brake only.
    // It must not mutate custody balances, and must not bypass resolve_authority timelock.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_000);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 250);

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.set_gov_param(98_100, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let resolve_before = st.gov_param_string("resolve_authority");

    let outcome = st
        .set_gov_param(
            98_101,
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("resolve_authority update should be accepted under pause");

    assert!(
        matches!(outcome, GovParamUpdateOutcome::Scheduled { .. }),
        "resolve_authority must remain timelocked while paused"
    );

    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("resolve_authority update should be staged");
    assert_eq!(pending.key_id, 7_310);
    assert_eq!(pending.value, "authority-a,authority-b");

    assert_eq!(
        st.gov_param_string("resolve_authority"),
        resolve_before,
        "timelocked resolve_authority must not apply immediately under pause"
    );

    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_cancels_pending_resolve_authority_scrubs_staged_approval_without_touching_custody()
{
    // M1 boundary hardening: emergency_pause must not let a pending resolve_authority cancel
    // preserve stale staged quorum, and must not perturb escrow/treasury custody while the
    // governance boundary is being rolled back.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 31_103);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 781);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 21);

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

    st.set_gov_param(98_181, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let slashes_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let replacement = st
        .set_gov_param(
            98_182,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be staged while paused");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    let staged = st
        .stage_or_confirm_resolve_approval(8_183, 3, true, "authority-c", "authority-c,authority-d")
        .expect("pending replacement authority should stage paused resolve approval");
    assert!(!staged);
    assert_eq!(st.pending_resolve_approval(8_183), Some((true, 1)));
    let root_with_pending = st.state_root();

    let cancelled = st
        .set_gov_param_with_action(
            98_183,
            7_310,
            "resolve_authority".into(),
            String::new(),
            GovPendingUpdateAction::Cancel,
        )
        .expect("paused pending resolve_authority update should cancel cleanly");
    assert!(matches!(cancelled, GovParamUpdateOutcome::Cancelled));

    assert!(st.is_emergency_paused());
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(
        st.gov_param_string("resolve_authority").as_deref(),
        Some("authority-a,authority-b")
    );
    assert_eq!(st.pending_resolve_approval(8_183), None);
    assert_eq!(st.pending_resolve_first_approver(8_183), None);
    assert_eq!(st.pending_resolve_approval_snapshot(8_183), None);
    assert_ne!(
        root_with_pending,
        st.state_root(),
        "paused resolve_authority cancel must invalidate cached state root when scrubbing staged quorum"
    );
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), slashes_before);
}

#[test]
fn paused_state_rejects_resolve_approval_against_stale_configured_authority_when_pending_timelock_exists(
) {
    // M1 boundary hardening: once a replacement resolve_authority set is already pending,
    // paused resolve approvals must fail closed against the stale configured quorum instead of
    // letting callers keep staging approvals against the soon-to-be-replaced authority set.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 31_103);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 781);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 21);

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

    let replacement = st
        .set_gov_param(
            98_181,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be scheduled");
    assert!(matches!(
        replacement,
        GovParamUpdateOutcome::Scheduled { .. }
    ));

    st.set_gov_param(98_182, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let slashes_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(8_183, 3, true, "authority-a", "authority-a,authority-b")
        .expect_err(
            "stale configured resolve authority must be rejected once a pending replacement exists",
        );
    assert!(err.contains("must match pending governance authority"));

    assert_eq!(st.pending_resolve_approval(8_183), None);
    assert_eq!(st.pending_resolve_first_approver(8_183), None);
    assert!(st.is_emergency_paused());
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-a,authority-b".into()),
        "rejecting stale approval must not mutate the active configured authority set"
    );
    assert_eq!(
        st.balance_of(CHALLENGE_ESCROW_ACCOUNT),
        escrow_before,
        "rejecting stale approval must not perturb challenge escrow"
    );
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), slashes_before);
}

#[test]
fn paused_state_matured_resolve_authority_apply_rejects_stale_old_quorum_without_residue() {
    // M1 micro-hardening: once a paused resolve_authority timelock is applied, callers must
    // not be able to keep staging approvals against the stale pre-rotation authority set.
    // The new boundary must fail closed without leaving pending quorum residue or mutating
    // pause / custody state.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 42_444);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 904);

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
        .set_gov_param(
            98_181,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("replacement resolve_authority update should be timelocked");
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 98_201
        }
    ));

    st.set_gov_param(98_182, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let applied_pending = st
        .set_gov_param(
            98_201,
            7_310,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("mature paused resolve_authority timelock should apply");
    assert!(matches!(applied_pending, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority-c,authority-d".into())
    );

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let root_before = st.state_root();

    let err = st
        .stage_or_confirm_resolve_approval(
            9_820_0,
            5,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .expect_err("stale pre-rotation authority set must be rejected after paused apply");
    assert!(err.contains("must match configured governance authority"));

    assert_eq!(st.pending_resolve_approval(9_820_0), None);
    assert_eq!(st.pending_resolve_first_approver(9_820_0), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_820_0), None);
    assert_eq!(st.state_root(), root_before);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}
