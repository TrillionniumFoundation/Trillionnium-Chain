use super::*;

#[test]
fn governance_resolve_authority_rejected_before_timelock_expiry() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7310,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let scheduled = st
        .set_gov_param(
            10_000,
            7310,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap();
    let activate_at_height = match scheduled {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
        GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
    };
    assert_eq!(activate_at_height, 10_020);

    let err = st
        .set_gov_param(
            10_019,
            7310,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap_err();
    assert!(err.contains("timelock active"));
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
}
#[test]
fn governance_resolve_authority_applied_after_timelock() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7311,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let _ = st
        .set_gov_param(
            11_000,
            7311,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap();

    let applied = st
        .set_gov_param(
            11_020,
            7311,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v3,resolver-v4".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}
#[test]
fn governance_resolve_authority_rejects_non_canonical_value_without_mutation() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7312,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let err = st
        .set_gov_param(
            12_000,
            7312,
            "resolve_authority".into(),
            " resolver-v2 ".into(),
        )
        .unwrap_err();
    assert!(err.contains("whitespace") || err.contains("canonical"));

    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}
#[test]
fn governance_resolve_authority_rejects_forbidden_separator_without_mutation() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7313,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let err = st
        .set_gov_param(
            12_000,
            7313,
            "resolve_authority".into(),
            "resolver-a，resolver-b".into(),
        )
        .unwrap_err();
    assert!(err.contains("separator") || err.contains("ASCII ','"));

    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}
#[test]
fn governance_resolve_authority_rejects_non_ascii_without_mutation() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7314,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let err = st
        .set_gov_param(
            12_000,
            7314,
            "resolve_authority".into(),
            "resolver-a,resolvér-b".into(),
        )
        .unwrap_err();
    assert!(err.contains("ASCII-only") || err.contains("whitespace") || err.contains("separator"));

    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}
#[test]
fn governance_resolve_authority_rejects_single_member_update_without_mutation() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7315,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let err = st
        .set_gov_param(
            12_500,
            7315,
            "resolve_authority".into(),
            "resolver-v3".into(),
        )
        .expect_err("singleton resolve_authority update must be rejected");
    assert!(err.contains("at least two members"), "{err}");

    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
    assert!(st.pending_gov_update("resolve_authority").is_none());
}
#[test]
fn governance_resolve_authority_pending_mismatch_behaves_like_sensitive_keys() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7312,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .unwrap();

    let scheduled = st
        .set_gov_param(
            12_000,
            7312,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap();
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 12_020
        }
    ));

    let err_value = st
        .set_gov_param(
            12_005,
            7312,
            "resolve_authority".into(),
            "resolver-v5,resolver-v6".into(),
        )
        .unwrap_err();
    assert!(err_value.contains("pending governance update exists"));

    let err_id = st
        .set_gov_param(
            12_005,
            9999,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .unwrap_err();
    assert!(err_id.contains("governance key id mismatch for resolve_authority"));

    let pending = st.pending_gov_update("resolve_authority").unwrap();
    assert_eq!(pending.key_id, 7312);
    assert_eq!(pending.value, "resolver-v3,resolver-v4");
    assert_eq!(pending.activate_at_height, 12_020);
}
#[test]
fn governance_resolve_authority_unchecked_path_rejects_key_id_shadowing() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7313,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .expect("initial unchecked resolve_authority write should succeed");

    let err = st
        .set_gov_param_unchecked(
            9001,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .expect_err("unchecked key-id shadowing for resolve_authority must be rejected");
    assert!(
        err.contains("governance key id mismatch for resolve_authority"),
        "{err}"
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
}
#[test]
fn governance_resolve_authority_unchecked_path_rejects_reserved_emergency_pause_key_id_alias() {
    let mut st = StateStore::new();

    let err = st
        .set_gov_param_unchecked(
            7_999,
            "resolve_authority".into(),
            "resolver-v1,resolver-v2".into(),
        )
        .expect_err("reserved emergency_pause key id must stay pinned on unchecked path");

    assert!(
        err.contains("governance key id mismatch for id 7999: expected_key=emergency_pause, attempted_key=resolve_authority"),
        "{err}"
    );
    assert_eq!(st.gov_param_string("resolve_authority"), None);
    assert!(!st.is_emergency_paused());
}
#[test]
fn governance_resolve_authority_checked_path_rejects_key_id_shadowing_without_state_mutation() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7314,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .expect("initial resolve_authority write should succeed");

    let err = st
        .set_gov_param(
            14_000,
            9001,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .expect_err("checked key-id shadowing for resolve_authority must be rejected");
    assert!(
        err.contains("governance key id mismatch for resolve_authority"),
        "{err}"
    );
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
    assert!(
        st.pending_gov_update("resolve_authority").is_none(),
        "rejected key-id shadowing must not enqueue pending updates"
    );
}
#[test]
fn governance_resolve_authority_cancel_wrong_key_id_preserves_pending_update() {
    // Merge-gate guard: cancel for a sensitive resolve_authority timelock must reject
    // key-id drift before any pending queue mutation.
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7314,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .expect("initial resolve_authority write should succeed");

    let scheduled = st
        .set_gov_param(
            14_500,
            7314,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .expect("resolve_authority update should schedule");
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 14_520
        }
    ));

    let err = st
        .set_gov_param_with_action(
            14_505,
            9001,
            "resolve_authority".into(),
            "ignored-on-cancel".into(),
            GovPendingUpdateAction::Cancel,
        )
        .expect_err("cancel with wrong key id must be rejected");
    assert!(
        err.contains("governance key id mismatch for resolve_authority"),
        "{err}"
    );

    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("wrong-key cancel must not clear pending resolve_authority update");
    assert_eq!(pending.key_id, 7314);
    assert_eq!(pending.value, "resolver-v3,resolver-v4");
    assert_eq!(pending.activate_at_height, 14_520);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into())
    );
}
#[test]
fn governance_resolve_authority_scheduling_scrubs_stale_pending_resolve_approvals() {
    // Merge-gate guard: once resolve_authority enters timelock rotation, any staged
    // approvals under the old quorum must be scrubbed immediately.
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        7_314,
        "resolve_authority".into(),
        "resolver-v1,resolver-v2".into(),
    )
    .expect("initial resolve_authority write should succeed");

    st.stage_or_confirm_resolve_approval(14_600, 7, true, "resolver-v1", "resolver-v1,resolver-v2")
        .expect("staging resolve approval under the live authority set should succeed");
    assert!(
        st.pending_resolve_approval_snapshot(14_600).is_some(),
        "sanity: staged resolve approval should exist before scheduling a quorum rotation"
    );

    let scheduled = st
        .set_gov_param(
            14_601,
            7_314,
            "resolve_authority".into(),
            "resolver-v3,resolver-v4".into(),
        )
        .expect("resolve_authority rotation should schedule successfully");
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 14_621
        }
    ));
    assert!(
        st.pending_resolve_approval_snapshot(14_600).is_none(),
        "scheduling a resolve_authority rotation must scrub staged approvals that were computed under the old quorum"
    );

    let pending = st
        .pending_gov_update("resolve_authority")
        .expect("resolve_authority rotation should remain queued after scrubbing stale approvals");
    assert_eq!(pending.key_id, 7_314);
    assert_eq!(pending.value, "resolver-v3,resolver-v4");
    assert_eq!(pending.activate_at_height, 14_621);
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("resolver-v1,resolver-v2".into()),
        "timelock scheduling must preserve the live authority set until activation"
    );
}

#[test]
fn governance_resolve_authority_rejects_reserved_or_placeholder_values() {
    let mut st = StateStore::new();

    for (i, bad_value) in [
        DEFAULT_RESOLVE_AUTHORITY_PLACEHOLDER,
        "Governance.Resolve_Authority",
        RESERVED_SYSTEM_AUTHORITY,
        "System",
        "authority,system",
        CHALLENGE_ESCROW_ACCOUNT,
        "Treasury.Challenge_Escrow",
        CHALLENGE_FORFEIT_TREASURY_ACCOUNT,
        "TREASURY.CHALLENGE_FORFEITS",
        WORKER_SLASH_TREASURY_ACCOUNT,
        "Treasury.Worker_Slashes",
        "emergency_pause",
        "Governance.Emergency_Pause",
        "authority,emergency_pause",
        "authority,Governance.Emergency_Pause",
        "authority,treasury.challenge_escrow",
        "authority,Treasury.Challenge_Forfeits",
        "authority,treasury.worker_slashes",
        "authority ",
        "authority team",
        "authority\u{3000}team",
        "authority,",
        ",authority",
        "authority,,authority2",
        "authority,authority",
        "authority,Authority",
        "authority, authority2",
        "authority;authority2",
        "authority|authority2",
        "authority,authority2|authority3",
        "authority,authority2;authority3",
        "authority；authority2",
        "authority，authority2",
        "authority、authority2",
        "authority\u{0000}x",
        "authority,\u{0007}authority2",
    ]
    .iter()
    .enumerate()
    {
        let err = st
            .set_gov_param_unchecked(
                97_100 + i as u64,
                "resolve_authority".into(),
                (*bad_value).into(),
            )
            .expect_err("reserved/malformed resolve_authority must be rejected");
        assert!(
            err.contains("invalid governance value for resolve_authority"),
            "unexpected error for value {:?}: {}",
            bad_value,
            err
        );
    }
}
#[test]
fn governance_accepts_comma_separated_resolve_authority_members() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(
        97_500,
        "resolve_authority".into(),
        "authority,authority2".into(),
    )
    .expect("comma-separated resolve authority members should be accepted");
    assert_eq!(
        st.gov_param_string("resolve_authority"),
        Some("authority,authority2".to_string())
    );
}
