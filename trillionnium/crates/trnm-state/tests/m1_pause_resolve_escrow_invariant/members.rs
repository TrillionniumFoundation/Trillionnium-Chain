use super::*;

#[test]
fn paused_state_rejects_forfeit_treasury_member_authority_set_without_escrow_side_effects() {
    // M1 merge-gate invariant: emergency pause must not allow custody accounts to enter
    // resolve authority quorum. A forfeit-treasury member in the authority set must fail
    // closed and preserve escrow + treasury balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 6_060);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 909);

    st.set_gov_param(98_190, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let authority_with_forfeits = format!("authority-a,{}", CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let err = st
        .stage_or_confirm_resolve_approval(9_910, 1, true, "authority-a", &authority_with_forfeits)
        .expect_err("forfeit treasury account in authority set must be rejected while paused");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(
        st.pending_resolve_approval(9_910),
        None,
        "rejected authority set must not stage approvals"
    );
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_worker_slash_treasury_member_authority_set_without_escrow_side_effects() {
    // M1 merge-gate invariant: emergency pause must not allow slash treasury custody
    // accounts to join resolve authority quorum. Rejection must remain fail-closed and
    // preserve escrow + custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 6_160);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_010);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 777);

    st.set_gov_param(98_192, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let authority_with_worker_slash = format!("authority-a,{}", WORKER_SLASH_TREASURY_ACCOUNT);
    let err = st
        .stage_or_confirm_resolve_approval(
            9_911,
            1,
            true,
            "authority-a",
            &authority_with_worker_slash,
        )
        .expect_err("worker slash treasury account in authority set must be rejected while paused");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(
        st.pending_resolve_approval(9_911),
        None,
        "rejected authority set must not stage approvals"
    );
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
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
fn paused_state_rejects_challenge_escrow_member_authority_set_without_side_effects() {
    // M1 merge-gate invariant: custody escrow account must never join resolve
    // authority quorum, even while emergency pause is active.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 7_170);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 717);

    st.set_gov_param(98_193, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let authority_with_escrow = format!("authority-a,{}", CHALLENGE_ESCROW_ACCOUNT);
    let err = st
        .stage_or_confirm_resolve_approval(9_912, 1, true, "authority-a", &authority_with_escrow)
        .expect_err("escrow account in authority set must be rejected while paused");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_912), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_reserved_system_member_authority_set_without_side_effects() {
    // M1 merge-gate invariant: emergency pause must not allow reserved control-plane
    // identities (e.g., system actor) to enter resolve quorum. Rejection must remain
    // fail-closed and preserve custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 7_270);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 727);

    st.set_gov_param(98_194, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_913, 1, true, "authority-a", "authority-a,system")
        .expect_err("reserved system member in authority set must be rejected while paused");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_913), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_challenge_escrow_as_singleton_authority_without_side_effects() {
    // M1 merge-gate invariant: emergency pause must not allow the custody escrow account
    // to become the sole resolver authority (single-party + self-custody collapse).
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 8_180);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 818);

    st.set_gov_param(98_194, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(
            9_913,
            1,
            true,
            CHALLENGE_ESCROW_ACCOUNT,
            CHALLENGE_ESCROW_ACCOUNT,
        )
        .expect_err("escrow singleton authority must be rejected while paused");
    assert!(
        err.contains("reserved")
            || err.contains("authority set")
            || err.contains("resolve authority")
            || err.contains("invalid governance value")
            || err.contains("explicit non-system authority"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_913), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_reserved_system_singleton_authority_without_side_effects() {
    // M1 merge-gate invariant: emergency pause must not allow reserved control-plane
    // identities to become the sole resolve authority.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 8_280);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 828);

    st.set_gov_param(98_195, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_914, 1, true, "system", "system")
        .expect_err("reserved system singleton authority must be rejected while paused");
    assert!(
        err.contains("reserved")
            || err.contains("authority set")
            || err.contains("resolve authority")
            || err.contains("explicit non-system authority")
            || err.contains("invalid governance value"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_914), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_placeholder_singleton_authority_without_side_effects() {
    // M1 merge-gate invariant: pause must not permit the default placeholder
    // authority identity to stage resolve approvals or touch custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 8_380);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 838);

    st.set_gov_param(98_196, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(
            9_915,
            1,
            true,
            DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER,
            DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER,
        )
        .expect_err("placeholder singleton authority must be rejected while paused");
    assert!(
        err.contains("placeholder")
            || err.contains("authority set")
            || err.contains("resolve authority")
            || err.contains("explicit non-system authority")
            || err.contains("invalid governance value"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_915), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_duplicate_multisig_member_authority_set_without_side_effects() {
    // M1 merge-gate invariant: emergency pause must not allow a single signer to
    // masquerade as multi-party resolve authority via duplicate members.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 8_480);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 848);

    st.set_gov_param(98_197, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_916, 1, true, "authority-a", "authority-a,authority-a")
        .expect_err("duplicate multisig members must be rejected while paused");
    assert!(
        err.contains("duplicate")
            || err.contains("authority set")
            || err.contains("resolve authority")
            || err.contains("invalid governance value"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_916), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_case_variant_duplicate_multisig_member_authority_set_without_side_effects()
{
    // M1 merge-gate invariant: emergency pause must not permit case-variant duplicates
    // (same signer with different casing) to bypass multi-party resolve quorum.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 8_481);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 849);

    st.set_gov_param(98_197, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_917, 1, true, "authority-a", "authority-a,Authority-A")
        .expect_err("case-variant duplicate members must be rejected while paused");
    assert!(
        err.contains("duplicate")
            || err.contains("authority set")
            || err.contains("resolve authority")
            || err.contains("invalid governance value"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_917), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_case_variant_challenge_escrow_member_without_side_effects() {
    // M1 micro-hardening: custody-account reservation must be case-insensitive so
    // mixed-case aliases cannot bypass resolver-set quarantine under emergency pause.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_910);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 991);

    st.set_gov_param(98_210, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let mixed_case_escrow = CHALLENGE_ESCROW_ACCOUNT.to_ascii_uppercase();
    let authority_with_case_variant_escrow = format!("authority-a,{mixed_case_escrow}");
    let err = st
        .stage_or_confirm_resolve_approval(
            9_915,
            1,
            true,
            "authority-a",
            &authority_with_case_variant_escrow,
        )
        .expect_err("case-variant escrow member must be rejected while paused");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_915), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_case_variant_worker_slash_treasury_member_without_side_effects() {
    // M1 micro-hardening: worker slash treasury reservation must stay
    // case-insensitive so mixed-case aliases cannot enter resolve quorum.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_920);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 992);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 551);

    st.set_gov_param(98_211, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let mixed_case_worker_slash = WORKER_SLASH_TREASURY_ACCOUNT.to_ascii_uppercase();
    let authority_with_case_variant_worker_slash = format!("authority-a,{mixed_case_worker_slash}");
    let err = st
        .stage_or_confirm_resolve_approval(
            9_916,
            1,
            true,
            "authority-a",
            &authority_with_case_variant_worker_slash,
        )
        .expect_err("case-variant worker slash treasury member must be rejected while paused");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_916), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
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
fn paused_state_rejects_case_variant_forfeit_treasury_member_without_side_effects() {
    // M1 micro-hardening: forfeits treasury reservation must stay case-insensitive
    // so mixed-case aliases cannot enter resolve quorum under emergency pause.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_930);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 993);

    st.set_gov_param(98_212, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let mixed_case_forfeits = CHALLENGE_FORFEIT_TREASURY_ACCOUNT.to_ascii_uppercase();
    let authority_with_case_variant_forfeits = format!("authority-a,{mixed_case_forfeits}");
    let err = st
        .stage_or_confirm_resolve_approval(
            9_917,
            1,
            true,
            "authority-a",
            &authority_with_case_variant_forfeits,
        )
        .expect_err("case-variant forfeits treasury member must be rejected while paused");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_917), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_case_drift_approver_membership_without_side_effects() {
    // M1 micro-hardening: under emergency pause, approver identity matching must stay
    // strict/canonical; case-drift approvers cannot consume quorum state or touch custody.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_940);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 994);

    st.set_gov_param(98_213, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_918, 1, true, "authority-a", "Authority-A,authority-b")
        .expect_err("case-drift approver membership must be rejected while paused");
    assert!(err.contains("configured authority member") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_918), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}
