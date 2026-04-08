use super::*;

#[test]
fn paused_state_rejects_case_variant_resolve_authority_placeholder_without_side_effects() {
    // M1 micro-hardening: placeholder resolve authority aliases must stay fail-closed
    // under case drift so emergency pause cannot smuggle a deferred placeholder into quorum.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 14_400);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 511);

    st.set_gov_param(98_151, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let placeholder_case_variant = DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER.to_ascii_uppercase();
    let authority_set = format!("authority-a,{placeholder_case_variant}");
    let err = st
        .stage_or_confirm_resolve_approval(9_915, 1, true, "authority-a", &authority_set)
        .expect_err("case-variant placeholder authority must be rejected while paused");
    assert!(err.contains("forbidden member") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_915), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_case_variant_duplicate_authority_members_without_side_effects() {
    // M1 micro-hardening: duplicate resolve members must stay fail-closed under case drift
    // so emergency pause cannot collapse a nominal 2-of-N approval set into one actor.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 15_050);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 519);

    st.set_gov_param(98_151, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_918, 1, true, "authority-a", "authority-a,Authority-A")
        .expect_err("case-variant duplicate authority members must be rejected while paused");
    assert!(err.contains("duplicate") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_918), None);
    assert_eq!(st.pending_resolve_first_approver(9_918), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_case_variant_system_member_without_side_effects() {
    // M1 micro-hardening: reserved system authorities remain forbidden under case drift,
    // preventing mixed-case aliases from collapsing multisig resolve control.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 15_500);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 522);

    st.set_gov_param(98_152, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(
            9_917,
            1,
            true,
            "authority-a",
            "authority-a,SYSTEM,authority-b",
        )
        .expect_err("reserved system member in middle of authority set must be rejected");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_917), None);
    assert_eq!(st.pending_resolve_first_approver(9_917), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
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
fn paused_state_rejects_case_variant_challenge_escrow_treasury_member_without_side_effects() {
    // M1 micro-hardening: the primary challenge escrow account must stay reserved under
    // case drift so paused resolve flow cannot treat custody as a quorum authority member.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_930);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 993);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 553);

    st.set_gov_param(98_212, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeited_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let slashed_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let mixed_case_challenge_escrow = CHALLENGE_ESCROW_ACCOUNT.to_ascii_uppercase();
    let err = st
        .stage_or_confirm_resolve_approval(
            9_924,
            1,
            true,
            "authority-a",
            &format!("authority-a,{mixed_case_challenge_escrow}"),
        )
        .expect_err("case-variant challenge escrow treasury member must be rejected while paused");
    assert!(
        err.contains("forbidden member") || err.contains("explicit non-system authority"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_924), None);
    assert_eq!(st.pending_resolve_first_approver(9_924), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeited_before
    );
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), slashed_before);
}

#[test]
fn paused_state_rejects_case_variant_challenge_forfeit_treasury_member_without_side_effects() {
    // M1 micro-hardening: all reserved treasury aliases must stay case-insensitively blocked
    // so paused mode cannot route multi-party resolve approval through custody/system accounts.
    let mut st = StateStore::new();
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeited_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let slashed_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    st.set_gov_param(98_214, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let mixed_case_forfeit_treasury = CHALLENGE_FORFEIT_TREASURY_ACCOUNT.to_ascii_uppercase();
    let err = st
        .stage_or_confirm_resolve_approval(
            9_922,
            1,
            true,
            "authority-a",
            &format!("authority-a,{mixed_case_forfeit_treasury}"),
        )
        .expect_err("case-variant challenge forfeit treasury member must be rejected while paused");
    assert!(
        err.contains("forbidden member") || err.contains("explicit non-system authority"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_922), None);
    assert_eq!(st.pending_resolve_first_approver(9_922), None);
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeited_before
    );
    assert_eq!(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT), slashed_before);
}

#[test]
fn paused_state_rejects_exact_emergency_pause_placeholder_member_without_side_effects() {
    // L03 boundary hardening: the exact canonical emergency_pause placeholder must be rejected
    // when it appears inside the live paused authority set too, not only case-drifted aliases.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_929);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 992);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 552);

    st.set_gov_param(98_211, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(
            9_920,
            1,
            true,
            "authority-a",
            "authority-a,governance.emergency_pause",
        )
        .expect_err("exact emergency_pause placeholder member must be rejected while paused");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_920), None);
    assert_eq!(st.pending_resolve_first_approver(9_920), None);
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

#[test]
fn paused_state_rejects_bare_emergency_pause_alias_member_without_side_effects() {
    // L03 boundary hardening: the bare emergency_pause control-plane alias must stay reserved
    // when it appears inside the live paused authority set, not only the governance-prefixed placeholder.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_933);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 996);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 556);

    st.set_gov_param(98_215, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(
            9_923,
            1,
            true,
            "authority-a",
            "authority-a,Emergency_Pause",
        )
        .expect_err("bare emergency_pause alias member must be rejected while paused");
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_923), None);
    assert_eq!(st.pending_resolve_first_approver(9_923), None);
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

#[test]
fn paused_state_rejects_case_variant_emergency_pause_placeholder_member_without_side_effects() {
    // M1 micro-hardening: resolve quorum parsing must keep the emergency pause placeholder
    // reserved under case drift, so paused mode cannot smuggle control-plane aliases into
    // multi-party resolve approval.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 9_930);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 993);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 553);

    st.set_gov_param(98_212, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let mixed_case_pause_placeholder = "Governance.Emergency_Pause";
    let authority_with_case_variant_pause_placeholder =
        format!("authority-a,{mixed_case_pause_placeholder}");
    let err = st
        .stage_or_confirm_resolve_approval(
            9_920,
            1,
            true,
            "authority-a",
            &authority_with_case_variant_pause_placeholder,
        )
        .expect_err(
            "case-variant emergency_pause placeholder member must be rejected while paused",
        );
    assert!(err.contains("reserved") || err.contains("authority set"));

    assert_eq!(st.pending_resolve_approval(9_920), None);
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
fn paused_state_rejects_oversized_resolve_authority_member_without_side_effects() {
    // M1 micro-hardening: paused live resolve approval must reject oversized authority-set
    // members just like oversized approvers, so malformed quorum members cannot stage pending
    // resolve state or perturb custody balances.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 10_042);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 1_009);
    st.set_balance(WORKER_SLASH_TREASURY_ACCOUNT, 509);

    st.set_gov_param(98_222, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    let oversized_member = "a".repeat(129);
    let authority_set = format!("authority-a,{}", oversized_member);
    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);
    let worker_slash_before = st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_933, 1, true, "authority-a", &authority_set)
        .expect_err("oversized paused resolve authority member must be rejected");
    assert!(
        err.contains("authority set") || err.contains("forbidden member"),
        "unexpected error: {err}"
    );

    assert_eq!(st.pending_resolve_approval(9_933), None);
    assert_eq!(st.pending_resolve_first_approver(9_933), None);
    assert_eq!(st.pending_resolve_approval_snapshot(9_933), None);
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
