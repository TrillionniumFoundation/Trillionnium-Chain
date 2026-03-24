use super::*;

#[test]
fn governance_sensitive_update_excessive_step_change_rejected() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7302, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let err = st
        .set_gov_param(3_000, 7302, "challenge_window_blocks".into(), "130".into())
        .unwrap_err();
    assert!(err.contains("rate-limit exceeded"));
}
#[test]
fn governance_sensitive_update_bounded_step_change_accepted() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7303, "challenge_window_blocks".into(), "100".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(4_000, 7303, "challenge_window_blocks".into(), "120".into())
        .unwrap();
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 4_020
        }
    ));

    let applied = st
        .set_gov_param(4_020, 7303, "challenge_window_blocks".into(), "120".into())
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(st.gov_param_u64("challenge_window_blocks"), Some(120));
}
#[test]
fn governance_challenge_success_bounty_is_sensitive_and_timelocked() {
    let mut st = StateStore::new();
    st.set_gov_param_unchecked(7350, "challenge_success_bounty".into(), "1".into())
        .unwrap();

    let scheduled = st
        .set_gov_param(30_000, 7350, "challenge_success_bounty".into(), "2".into())
        .unwrap();
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 30_020
        }
    ));

    let err = st
        .set_gov_param(30_010, 7350, "challenge_success_bounty".into(), "2".into())
        .unwrap_err();
    assert!(err.contains("timelock active"));

    let applied = st
        .set_gov_param(30_020, 7350, "challenge_success_bounty".into(), "2".into())
        .unwrap();
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(st.gov_param_u64("challenge_success_bounty"), Some(2));
}
#[test]
fn governance_non_sensitive_param_unaffected_by_timelock() {
    let mut st = StateStore::new();
    let r1 = st
        .set_gov_param(5_000, 7304, "max_block_ms".into(), "15".into())
        .unwrap();
    assert!(matches!(r1, GovParamUpdateOutcome::Applied(_)));

    let r2 = st
        .set_gov_param(5_001, 7304, "max_block_ms".into(), "20".into())
        .unwrap();
    assert!(matches!(r2, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(st.gov_param_u64("max_block_ms"), Some(20));
    assert!(st.pending_gov_update("max_block_ms").is_none());
}
#[test]
fn non_sensitive_governance_noop_rejects_mismatched_key_id() {
    // Merge-gate guard: noop/idempotent path must not hide key-id drift for immediate keys.
    let mut st = StateStore::new();

    let first = st
        .set_gov_param(9_300, 6_001, "max_block_ms".into(), "500".into())
        .expect("seed max_block_ms must succeed");
    let first_ref = match first {
        GovParamUpdateOutcome::Applied(r) => r,
        _ => panic!("max_block_ms must remain immediate"),
    };

    let err = st
        .set_gov_param(9_301, 6_002, "max_block_ms".into(), "500".into())
        .expect_err("mismatched key-id noop must be rejected");
    assert!(err.contains("governance key id mismatch"), "{err}");

    let preserved = st
        .get_param(first_ref.id)
        .expect("canonical max_block_ms entry must remain readable");
    assert_eq!(preserved.key_id, 6_001);
    assert_eq!(preserved.value, "500");
    assert!(st.pending_gov_update("max_block_ms").is_none());
}
#[test]
fn governance_allowed_keys_schema_merge_gate_is_explicit() {
    // Exhaustive merge-gate guard for whitelist+schema safety. Any added/changed key
    // must update the static schema entry with an invalid sample that is expected to fail.
    let allowed_keys: Vec<&str> = gov_allowed_keys().collect();
    assert_eq!(
        allowed_keys.len(),
        GOV_PARAM_SCHEMA.len(),
        "governance allowed-key view changed; update schema merge gate"
    );

    let mut st = StateStore::new();
    for (
        i,
        GovParamSchemaEntry {
            key,
            invalid_merge_gate_sample,
            ..
        },
    ) in GOV_PARAM_SCHEMA.iter().copied().enumerate()
    {
        assert!(
            allowed_keys.contains(&key),
            "schema merge gate contains non-whitelisted key: {}",
            key
        );
        let key_id = if key == "emergency_pause" {
            7_999
        } else {
            96_000 + i as u64
        };
        let err = st
            .set_gov_param_unchecked(key_id, key.into(), invalid_merge_gate_sample.into())
            .unwrap_err();
        assert!(
            err.contains("invalid governance value"),
            "expected schema rejection for key={}, got: {}",
            key,
            err
        );
    }
}
#[test]
fn governance_keysets_merge_gate_are_unique_and_subset_safe() {
    // Merge-gate: duplicate keys in derived views can silently weaken policy checks.
    let allowed_keys: Vec<&str> = gov_allowed_keys().collect();
    let allowed_unique: std::collections::BTreeSet<&str> = allowed_keys.iter().copied().collect();
    assert_eq!(
        allowed_unique.len(),
        allowed_keys.len(),
        "derived allowed-key view contains duplicate entries"
    );

    let sensitive_keys: Vec<&str> = gov_sensitive_keys().collect();
    let sensitive_unique: std::collections::BTreeSet<&str> =
        sensitive_keys.iter().copied().collect();
    assert_eq!(
        sensitive_unique.len(),
        sensitive_keys.len(),
        "derived sensitive-key view contains duplicate entries"
    );

    let schema_allowed: std::collections::BTreeSet<&str> =
        GOV_PARAM_SCHEMA.iter().map(|entry| entry.key).collect();
    assert_eq!(
        allowed_unique, schema_allowed,
        "derived allowed-key view drifted from GOV_PARAM_SCHEMA"
    );

    let schema_sensitive: std::collections::BTreeSet<&str> = GOV_PARAM_SCHEMA
        .iter()
        .filter(|entry| entry.is_sensitive())
        .map(|entry| entry.key)
        .collect();
    assert_eq!(
        sensitive_unique, schema_sensitive,
        "derived sensitive-key view drifted from GOV_PARAM_SCHEMA"
    );

    for key in &sensitive_unique {
        assert!(
            allowed_unique.contains(key),
            "sensitive key must also be whitelisted: {}",
            key
        );
    }

    assert!(
        !sensitive_unique.contains("emergency_pause"),
        "emergency_pause must remain immediate and never timelocked"
    );
}
