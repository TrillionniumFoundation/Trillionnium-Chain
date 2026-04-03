use super::*;

#[test]
fn parse_governed_bool_param_accepts_explicit_true_and_false_aliases() {
    for raw in ["1", "true", "yes", "on", "0", "false", "no", "off"] {
        parse_governed_bool_param(raw, "default_slash_on_unresolved_challenge")
            .expect("supported boolean alias must parse");
    }
}
#[test]
fn parse_governed_bool_param_accepts_mixed_case_aliases_without_whitespace() {
    for raw in ["TRUE", "Yes", "On", "FALSE", "No", "oFf"] {
        parse_governed_bool_param(raw, "default_slash_on_unresolved_challenge").expect(
            "case-insensitive boolean alias must parse when canonicalized without whitespace",
        );
    }
}
#[test]
fn parse_governed_bool_param_rejects_malformed_boolean_aliases_fail_closed() {
    let err = parse_governed_bool_param("maybe", "default_slash_on_unresolved_challenge")
        .expect_err("malformed boolean alias must be rejected");
    assert!(
        matches!(err, PouwError::State(msg) if msg.contains("invalid boolean governance value for default_slash_on_unresolved_challenge: maybe"))
    );
}
#[test]
fn parse_governed_bool_param_rejects_non_canonical_whitespace_wrapped_aliases() {
    for raw in [" true", "true ", "\ttrue", "false\n"] {
        let err = parse_governed_bool_param(raw, "default_slash_on_unresolved_challenge")
            .expect_err("whitespace-wrapped boolean alias must be rejected");
        assert!(matches!(err, PouwError::State(msg) if msg.contains(raw)));
    }
}
#[test]
fn parse_governed_bool_param_rejects_hidden_zero_width_aliases_fail_closed() {
    for raw in ["tr\u{200b}ue", "fa\u{200d}lse", "o\u{2060}n", "of\u{feff}f"] {
        let err = parse_governed_bool_param(raw, "default_slash_on_unresolved_challenge")
            .expect_err("zero-width boolean alias must be rejected");
        assert!(matches!(err, PouwError::State(msg) if msg.contains(raw)));
    }
}
#[test]
fn parse_governed_bool_param_rejects_ascii_internal_whitespace_aliases_fail_closed() {
    for raw in ["tr ue", "fa\tlse", "o\nn", "of\rf"] {
        let err = parse_governed_bool_param(raw, "default_slash_on_unresolved_challenge")
            .expect_err("internal-whitespace boolean alias must be rejected");
        assert!(matches!(err, PouwError::State(msg) if msg.contains(raw)));
    }
}
#[test]
fn parse_governed_bool_param_rejects_unicode_homoglyph_aliases_fail_closed() {
    for raw in ["truｅ", "fаlse", "οn", "оff"] {
        let err = parse_governed_bool_param(raw, "default_slash_on_unresolved_challenge")
            .expect_err("unicode homoglyph boolean alias must be rejected");
        assert!(matches!(err, PouwError::State(msg) if msg.contains(raw)));
    }
}
#[test]
fn parse_governed_bool_param_rejects_blank_governance_value_fail_closed() {
    let err = parse_governed_bool_param("", "default_slash_on_unresolved_challenge")
        .expect_err("blank timeout-slash governance value must be rejected");
    assert!(matches!(err, PouwError::State(msg) if msg.contains(
        "invalid boolean governance value for default_slash_on_unresolved_challenge"
    )));
}
#[test]
fn parse_governed_bool_param_rejects_numeric_and_punctuation_lookalikes_fail_closed() {
    for raw in ["2", "-1", "true.", "false,", "yes/", "off:"] {
        let err = parse_governed_bool_param(raw, "default_slash_on_unresolved_challenge")
            .expect_err("numeric or punctuation boolean lookalikes must be rejected");
        assert!(matches!(err, PouwError::State(msg) if msg.contains(raw)));
    }
}
#[test]
fn parse_governed_bool_param_rejects_fullwidth_digit_aliases_fail_closed() {
    for raw in ["１", "０", "１true", "false０"] {
        let err = parse_governed_bool_param(raw, "default_slash_on_unresolved_challenge")
            .expect_err("fullwidth digit aliases must be rejected");
        assert!(matches!(err, PouwError::State(msg) if msg.contains(raw)));
    }
}
#[test]
fn parse_governed_bool_param_rejects_unicode_whitespace_lookalikes_fail_closed() {
    for raw in [
        "true\u{00a0}",
        "\u{2003}false",
        "o\u{00a0}n",
        "of\u{2009}f",
        "\u{feff}true",
        "o\u{3000}n",
    ] {
        let err = parse_governed_bool_param(raw, "default_slash_on_unresolved_challenge")
            .expect_err("unicode whitespace boolean lookalikes must be rejected");
        assert!(matches!(err, PouwError::State(msg) if msg.contains(raw)));
    }
}
#[test]
fn state_error_mapping_version_conflict() {
    let err = map_state_err("version conflict".to_string());
    assert!(matches!(err, PouwError::VersionConflict));

    let err_mixed_case = map_state_err("Version Conflict on task".to_string());
    assert!(matches!(err_mixed_case, PouwError::VersionConflict));

    let err2 = map_state_err("object not found".to_string());
    assert!(matches!(err2, PouwError::State(_)));

    let err3 = map_state_err("version-conflict while syncing".to_string());
    assert!(matches!(err3, PouwError::State(_)));
}
#[test]
fn accept_preflight_rejects_lock_credit_overflow_without_mutation() {
    let mut st = seeded_state();
    st.set_gov_param_bootstrap_unchecked(9801, "min_worker_stake".into(), "50".into())
        .unwrap();
    st.set_balance("worker1", 50);
    st.set_balance(&worker_stake_lock_account(19801), u128::MAX);

    let r1 = apply_create_task(&mut st, 19801, "alice".into(), 10).unwrap();
    let err = apply_accept_task(&mut st, r1.clone(), "worker1".into()).unwrap_err();
    assert!(matches!(err, PouwError::State(msg) if msg.contains("balance overflow on credit")));

    let task = st.get_task(r1.id).unwrap();
    assert_eq!(task.status, TaskStatus::Open);
    assert_eq!(task.worker, None);
    assert_eq!(st.balance_of("worker1"), 50);
    assert_eq!(st.balance_of(&worker_stake_lock_account(19801)), u128::MAX);
}
#[test]
fn accept_preflight_rejects_insufficient_stake_without_mutation() {
    let mut st = seeded_state();
    st.set_gov_param_bootstrap_unchecked(9802, "min_worker_stake".into(), "50".into())
        .unwrap();
    st.set_balance("worker1", 49);

    let r1 = apply_create_task(&mut st, 19802, "alice".into(), 10).unwrap();
    let err = apply_accept_task(&mut st, r1.clone(), "worker1".into()).unwrap_err();
    assert!(matches!(err, PouwError::InsufficientStake));

    let task = st.get_task(r1.id).unwrap();
    assert_eq!(task.status, TaskStatus::Open);
    assert_eq!(task.worker, None);
    assert_eq!(st.balance_of("worker1"), 49);
    assert_eq!(st.balance_of(&worker_stake_lock_account(19802)), 0);
}
#[test]
fn accept_succeeds_when_worker_stake_at_or_above_minimum() {
    let mut st = seeded_state();
    st.set_gov_param_bootstrap_unchecked(9802, "min_worker_stake".into(), "50".into())
        .unwrap();
    st.set_balance("worker1", 50);

    let r1 = apply_create_task(&mut st, 19802, "alice".into(), 10).unwrap();
    let _r2 = apply_accept_task(&mut st, r1, "worker1".into()).unwrap();

    assert_eq!(st.balance_of("worker1"), 0);
    assert_eq!(st.balance_of(&worker_stake_lock_account(19802)), 50);
}
