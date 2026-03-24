use super::*;

#[test]
fn governance_non_sensitive_failed_apply_does_not_scrub_pending_queue() {
    // Merge-gate guard: failed writes must be side-effect free for unrelated
    // pending governance state (except explicit Cancel unsupported path).
    let mut st = StateStore::new();

    st.pending_gov_updates.insert(
        "max_block_ms".into(),
        PendingGovParamUpdate {
            key_id: 7_400,
            key: "max_block_ms".into(),
            value: "15".into(),
            activate_at_height: 77_700,
        },
    );

    let task = TaskObject {
        task_id: 7_400,
        creator: "alice".into(),
        bounty: 10,
        status: TaskStatus::Open,
        proof_type: Default::default(),
        metadata: None,
        worker: None,
        committed_hash: None,
        result_hash: None,
        reveal_salt: None,
        committed_at_height: None,
        reveal_deadline_height: None,
        challenge_deadline_height: None,
        challenge_window_blocks_snapshot: None,
        challenged_at_height: None,
        resolve_deadline_height: None,
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 1,
    };
    st.put_task_new(task).unwrap();

    let err_unchecked = st
        .set_gov_param_unchecked(7_400, "max_block_ms".into(), "15".into())
        .unwrap_err();
    assert!(err_unchecked.contains("not GovParam"));
    assert!(
        st.pending_gov_update("max_block_ms").is_some(),
        "failed unchecked apply must not scrub pending queue"
    );

    let err_checked = st
        .set_gov_param(77_701, 7_400, "max_block_ms".into(), "15".into())
        .unwrap_err();
    assert!(err_checked.contains("not GovParam"));

    let pending = st
        .pending_gov_update("max_block_ms")
        .expect("failed checked apply must not scrub pending queue");
    assert_eq!(pending.key_id, 7_400);
    assert_eq!(pending.activate_at_height, 77_700);
}
#[test]
fn governance_same_key_different_id_shadow_attempt_rejected() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7401, "max_block_ms".into(), "15".into())
        .unwrap();

    let err = st
        .set_gov_param_unchecked(7402, "max_block_ms".into(), "20".into())
        .unwrap_err();
    assert!(err.contains("key id mismatch"));
}
#[test]
fn governance_readers_use_deterministic_current_value() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7403, "max_block_ms".into(), "15".into())
        .unwrap();
    st.set_gov_param_unchecked(7403, "max_block_ms".into(), "20".into())
        .unwrap();

    assert_eq!(st.gov_param_u64("max_block_ms"), Some(20));
    assert_eq!(st.gov_param_u128("max_block_ms"), Some(20));
    assert_eq!(st.gov_param_string("max_block_ms"), Some("20".into()));
}
#[test]
fn governance_sensitive_update_rejected_before_timelock_expiry() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7300, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(1_000, 7300, "challenge_min_bond".into(), "120".into())
        .unwrap();
    let activate_at_height = match scheduled {
        GovParamUpdateOutcome::Scheduled { activate_at_height } => activate_at_height,
        GovParamUpdateOutcome::Applied(_) => panic!("expected schedule"),
        GovParamUpdateOutcome::Cancelled => panic!("expected schedule"),
    };
    assert_eq!(activate_at_height, 1_020);

    let err = st
        .set_gov_param(1_019, 7300, "challenge_min_bond".into(), "120".into())
        .unwrap_err();
    assert!(err.contains("timelock active"));
}
#[test]
fn governance_sensitive_update_accepted_after_timelock() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7301, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let _ = st
        .set_gov_param(2_000, 7301, "challenge_min_bond".into(), "120".into())
        .unwrap();

    let applied = st
        .set_gov_param(2_020, 7301, "challenge_min_bond".into(), "120".into())
        .unwrap();
    match applied {
        GovParamUpdateOutcome::Applied(r) => assert!(r.version >= 2),
        GovParamUpdateOutcome::Scheduled { .. } => panic!("expected applied"),
        GovParamUpdateOutcome::Cancelled => panic!("expected applied"),
    }

    assert_eq!(st.gov_param_u64("challenge_min_bond"), Some(120));
    assert!(st.pending_gov_update("challenge_min_bond").is_none());
}
#[test]
fn governance_sensitive_noop_update_is_immediate_without_timelock() {
    let mut st = StateStore::new();
    let seeded = st
        .set_gov_param_unchecked(7306, "challenge_min_bond".into(), "100".into())
        .unwrap();

    let applied = st
        .set_gov_param(2_500, 7306, "challenge_min_bond".into(), "100".into())
        .unwrap();

    match applied {
        GovParamUpdateOutcome::Applied(r) => {
            assert_eq!(r.id, seeded.id);
            assert_eq!(r.version, seeded.version);
        }
        GovParamUpdateOutcome::Scheduled { .. } => panic!("expected immediate no-op apply"),
        GovParamUpdateOutcome::Cancelled => panic!("expected immediate no-op apply"),
    }

    assert!(st.pending_gov_update("challenge_min_bond").is_none());
    assert_eq!(st.gov_param_u64("challenge_min_bond"), Some(100));
}
#[test]
fn governance_sensitive_pending_replace_before_activation_resets_timelock() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7320, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let first = st
        .set_gov_param(20_000, 7320, "challenge_window_blocks".into(), "110".into())
        .unwrap();
    assert!(matches!(
        first,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 20_020
        }
    ));

    let replaced = st
        .set_gov_param_with_action(
            20_005,
            7320,
            "challenge_window_blocks".into(),
            "120".into(),
            GovPendingUpdateAction::Replace,
        )
        .unwrap();
    assert!(matches!(
        replaced,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 20_025
        }
    ));

    let pending = st.pending_gov_update("challenge_window_blocks").unwrap();
    assert_eq!(pending.value, "120");
    assert_eq!(pending.activate_at_height, 20_025);

    let err = st
        .set_gov_param(20_020, 7320, "challenge_window_blocks".into(), "120".into())
        .unwrap_err();
    assert!(err.contains("timelock active"));

    let applied = st
        .set_gov_param(20_025, 7320, "challenge_window_blocks".into(), "120".into())
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(st.gov_param_u64("challenge_window_blocks"), Some(120));
}
