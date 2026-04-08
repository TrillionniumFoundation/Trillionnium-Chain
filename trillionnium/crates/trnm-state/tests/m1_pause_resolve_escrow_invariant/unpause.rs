use super::*;

#[test]
fn paused_unpause_rejects_noncanonical_key_id_without_mutating_custody_or_quorum_state() {
    // M1 merge-gate invariant: emergency pause exit path must keep canonical key-id guard.
    // A wrong-key unpause attempt must fail closed: pause state, escrow custody, and
    // staged multi-party resolve approvals remain unchanged.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 12_345);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 678);

    st.set_gov_param(98_150, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_906, 1, false, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_906), Some((false, 1)));

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param(98_151, 7_998, "emergency_pause".into(), "false".into())
        .expect_err("unpause must reject non-canonical emergency_pause key id");
    assert!(err.contains("governance key id mismatch"));

    assert!(
        st.is_emergency_paused(),
        "wrong-key unpause must not clear paused state"
    );
    assert_eq!(st.pending_resolve_approval(9_906), Some((false, 1)));
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_state_rejects_authority_set_flip_mid_quorum_without_escrow_side_effects() {
    // M1 merge-gate invariant: under emergency pause, resolve quorum remains multi-party
    // and bound to a stable authority set. Mid-flight authority-set flips must fail closed
    // and keep custody balances untouched.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 55_500);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 444);

    st.set_gov_param(98_160, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_907, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_907), Some((true, 1)));

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .stage_or_confirm_resolve_approval(9_907, 1, true, "authority-c", "authority-a,authority-c")
        .expect_err("authority-set flip must fail closed and reset stale quorum entry");
    assert!(err.contains("authority set changed"));

    assert_eq!(
        st.pending_resolve_approval(9_907),
        None,
        "authority-set flip rejection must clear stale pending approval"
    );
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_unpause_rejects_noncanonical_bool_literal_without_mutating_custody_or_quorum_state() {
    // M1 merge-gate invariant: emergency pause exit must enforce strict bool parsing.
    // A malformed unpause value must fail closed: paused state, escrow custody, and
    // staged multi-party resolve approvals remain unchanged.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 4_242);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 242);

    st.set_gov_param(98_170, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_908, 1, false, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_908), Some((false, 1)));

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param(98_171, 7_999, "emergency_pause".into(), "False".into())
        .expect_err("unpause must reject non-canonical bool literals");
    assert!(err.contains("expected strict bool 'true' or 'false'"));

    assert!(
        st.is_emergency_paused(),
        "malformed unpause value must not clear paused state"
    );
    assert_eq!(st.pending_resolve_approval(9_908), Some((false, 1)));
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_unpause_wrong_key_id_precedes_bool_validation_and_preserves_quorum_and_escrow() {
    // M1 merge-gate invariant: emergency pause key-id boundary must fail closed before
    // value-schema checks, so malformed wrong-key unpause attempts cannot clear pause,
    // mutate staged multi-party quorum, or move escrow custody.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 5_050);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 505);

    st.set_gov_param(98_180, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_909, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_909), Some((true, 1)));

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param(98_181, 8_000, "emergency_pause".into(), "False".into())
        .expect_err("wrong-key unpause attempt must reject before bool validation");
    assert!(
        err.contains("key id") && err.contains("7999"),
        "wrong-key path must reject on canonical key boundary first: {err}"
    );

    assert!(
        st.is_emergency_paused(),
        "wrong-key malformed unpause must keep pause state unchanged"
    );
    assert_eq!(st.pending_resolve_approval(9_909), Some((true, 1)));
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_unpause_rejects_whitespace_bool_literal_without_mutating_custody_or_quorum_state() {
    // M1 merge-gate invariant: pause exit must use canonical strict bool values.
    // Whitespace-smuggled bool payloads must fail closed and preserve escrow + quorum.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 6_060);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 606);

    st.set_gov_param(98_190, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_910, 1, false, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_910), Some((false, 1)));

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param(98_191, 7_999, "emergency_pause".into(), "false ".into())
        .expect_err("whitespace bool literal must be rejected on unpause path");
    assert!(err.contains("expected strict bool 'true' or 'false'"));

    assert!(
        st.is_emergency_paused(),
        "whitespace bool unpause must not clear paused state"
    );
    assert_eq!(st.pending_resolve_approval(9_910), Some((false, 1)));
    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_resolve_authority_update_rejects_noncanonical_member_order_and_case_and_preserves_quorum() {
    // REF03 explicit-validator guard: live governance scheduling must reuse the same canonical
    // resolve-authority validator as restore/quorum paths. Mixed-case or unsorted authority sets
    // must fail closed instead of staging a value that later canonicalizes differently.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 6_060);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 606);

    st.set_gov_param(98_190, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_910, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_910), Some((true, 1)));

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    let err = st
        .set_gov_param(
            98_191,
            7_310,
            "resolve_authority".into(),
            "Authority-B,authority-a".into(),
        )
        .expect_err("non-canonical resolve_authority ordering/case must fail closed");
    assert!(err.contains("canonical lowercase sorted ordering"), "{err}");

    assert_eq!(st.pending_gov_update("resolve_authority"), None);
    assert_eq!(st.pending_resolve_approval(9_910), Some((true, 1)));
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}

#[test]
fn paused_restore_pending_resolve_authority_rejects_noncanonical_snapshot_and_scrubs_quorum() {
    // REF03 explicit-validator guard: restore paths for resolve_authority must reuse the same
    // canonical membership validator as live governance scheduling. A malformed snapshot must
    // fail closed by clearing the pending key and any staged quorum bound to it.
    let mut st = StateStore::new();
    st.set_balance(CHALLENGE_ESCROW_ACCOUNT, 7_070);
    st.set_balance(CHALLENGE_FORFEIT_TREASURY_ACCOUNT, 707);

    st.set_gov_param(98_200, 7_999, "emergency_pause".into(), "true".into())
        .expect("pause toggle must apply immediately");
    assert!(st.is_emergency_paused());

    st.stage_or_confirm_resolve_approval(9_911, 1, true, "authority-a", "authority-a,authority-b")
        .expect("first approval stage should succeed while paused");
    assert_eq!(st.pending_resolve_approval(9_911), Some((true, 1)));

    let escrow_before = st.balance_of(CHALLENGE_ESCROW_ACCOUNT);
    let forfeits_before = st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT);

    st.restore_pending_gov_update(
        "resolve_authority",
        Some(PendingGovParamUpdate {
            key_id: 7_310,
            key: "resolve_authority".into(),
            value: "authority-a".into(),
            activate_at_height: 98_220,
        }),
    );

    assert_eq!(
        st.pending_gov_update("resolve_authority"),
        None,
        "restore path must reject malformed resolve_authority snapshots instead of staging a non-canonical single-member authority set"
    );
    assert_eq!(
        st.pending_resolve_approval(9_911),
        None,
        "rejecting a malformed resolve_authority snapshot must scrub stale staged quorum"
    );
    assert!(st.is_emergency_paused());
    assert_eq!(st.balance_of(CHALLENGE_ESCROW_ACCOUNT), escrow_before);
    assert_eq!(
        st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
        forfeits_before
    );
}
