use super::*;
use crate::governance_ops::{
    canonicalize_resolve_authority_set, gov_invalid_merge_gate_samples, gov_param_registry_entry,
    gov_pinned_key_ids, GovParamKind, GovParamUpdateOutcome, GovParamValueValidator,
    EMERGENCY_PAUSE_KEY_ID,
};

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
fn governance_max_block_ms_registry_entry_stays_canonical_and_typed() {
    // Merge-gate guard: immediate numeric governance rows should remain canonical too, not only
    // the reserved/timelocked examples. Keep max_block_ms wired to one lowercase key spelling,
    // immediate application, and the shared u64 bounds from the typed registry.
    let entry = gov_param_registry_entry("max_block_ms")
        .expect("max_block_ms must stay present in the canonical governance schema");
    assert_eq!(entry.key, "max_block_ms");
    assert_eq!(entry.kind, GovParamKind::Immediate);
    assert_eq!(
        entry.validator,
        GovParamValueValidator::U64Range {
            min: 10,
            max: 120_000,
        }
    );
    assert_eq!(entry.pinned_key_id, None);
    assert!(gov_param_registry_entry("Max_Block_Ms").is_none());

    let mut st = StateStore::new();
    let applied = st
        .set_gov_param(9_400, 6_001, entry.key.into(), "500".into())
        .expect("canonical immediate numeric governance binding must remain writable");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert_eq!(st.gov_param_u64(entry.key), Some(500));
    assert!(st.pending_gov_update(entry.key).is_none());
}

#[test]
fn governance_emergency_pause_registry_entry_stays_canonical_and_typed() {
    // Merge-gate guard: the Algorand-style governance registry must keep the reserved
    // emergency_pause entry bound to one canonical key spelling, reserved key id, and strict
    // bool value rule. Drift in any of the three should fail loudly here.
    let entry = gov_param_registry_entry("emergency_pause")
        .expect("emergency_pause must stay present in the canonical governance schema");
    assert_eq!(entry.key, "emergency_pause");
    assert_eq!(entry.kind, GovParamKind::Immediate);
    assert_eq!(entry.validator, GovParamValueValidator::StrictBool);
    assert_eq!(entry.pinned_key_id, Some(EMERGENCY_PAUSE_KEY_ID));
    assert_eq!(EMERGENCY_PAUSE_KEY_ID, 7_999);
    assert!(gov_param_registry_entry("Emergency_Pause").is_none());

    let mut st = StateStore::new();
    let applied = st
        .set_gov_param(12_345, EMERGENCY_PAUSE_KEY_ID, entry.key.into(), "true".into())
        .expect("canonical emergency_pause binding must remain writable");
    assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));
    assert!(st.is_emergency_paused());
    assert!(st.pending_gov_update(entry.key).is_none());
}

#[test]
fn governance_resolve_authority_registry_entry_stays_canonical_and_typed() {
    // Merge-gate guard: resolve_authority must remain an explicitly-typed canonical registry
    // entry. The key spelling, timelock classification, and authority-set validator must stay
    // aligned so both schema lookup and runtime behavior share one source of truth.
    let entry = gov_param_registry_entry("resolve_authority")
        .expect("resolve_authority must stay present in the canonical governance schema");
    assert_eq!(entry.key, "resolve_authority");
    assert_eq!(entry.kind, GovParamKind::Timelocked);
    assert_eq!(entry.validator, GovParamValueValidator::ResolveAuthoritySet);
    assert_eq!(entry.pinned_key_id, None);
    assert!(gov_param_registry_entry("Resolve_Authority").is_none());

    let mut st = StateStore::new();
    let scheduled = st
        .set_gov_param(
            22_000,
            7_312,
            entry.key.into(),
            "authority-b,authority-a".into(),
        )
        .expect("canonical resolve_authority binding must remain writable through the typed registry");
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 22_020
        }
    ));

    let pending = st
        .pending_gov_update(entry.key)
        .expect("timelocked resolve_authority update must be staged");
    assert_eq!(pending.key_id, 7_312);
    assert_eq!(pending.value, "authority-a,authority-b");
    assert_eq!(pending.activate_at_height, 22_020);
}

#[test]
fn governance_resolve_authority_registry_entry_uses_single_canonical_value_policy() {
    // Merge-gate guard: the typed registry row for resolve_authority and the runtime
    // canonicalizer must keep sharing one value policy. Canonical spellings should round-trip,
    // reordered members should normalize to one canonical value, and malformed placeholders must
    // fail closed.
    let entry = gov_param_registry_entry("resolve_authority")
        .expect("resolve_authority must stay present in the canonical governance schema");
    assert_eq!(entry.validator, GovParamValueValidator::ResolveAuthoritySet);

    entry
        .validator
        .validate(entry.key, "authority-a,authority-b")
        .expect("canonical resolve_authority value must satisfy the typed registry validator");
    assert_eq!(
        canonicalize_resolve_authority_set("authority-b,authority-a")
            .expect("runtime canonicalizer must accept reorder-equivalent authority sets"),
        "authority-a,authority-b"
    );

    let err = entry
        .validator
        .validate(entry.key, "authority-a,Governance.Resolve_Authority")
        .expect_err("placeholder aliases must remain invalid under the typed registry validator");
    assert!(err.contains("invalid governance value for resolve_authority"), "{err}");

    assert!(
        canonicalize_resolve_authority_set("authority-a,Governance.Resolve_Authority").is_err(),
        "runtime canonicalizer must reject the same placeholder alias that the typed registry rejects"
    );
}

#[test]
fn governance_resolve_authority_invalid_merge_gate_sample_stays_fail_closed() {
    // Merge-gate guard: keep the typed registry's explicit invalid sample aligned with the same
    // runtime fail-closed value policy. If the canonical validator ever loosens whitespace-only
    // authority sets, this lane should fail loudly.
    let entry = gov_param_registry_entry("resolve_authority")
        .expect("resolve_authority must stay present in the canonical governance schema");
    assert_eq!(entry.invalid_merge_gate_sample, "   ");

    let err = entry
        .validator
        .validate(entry.key, entry.invalid_merge_gate_sample)
        .expect_err("whitespace-only resolve_authority sample must stay invalid in the typed registry");
    assert!(err.contains("invalid governance value for resolve_authority"), "{err}");

    assert!(
        canonicalize_resolve_authority_set(entry.invalid_merge_gate_sample).is_err(),
        "runtime canonicalizer must reject the same whitespace-only invalid sample"
    );
}

#[test]
fn governance_challenge_min_bond_bounty_bps_registry_entry_stays_canonical_and_typed() {
    // Merge-gate guard: this Algorand-style registry row is a plain numeric timelocked policy.
    // Keep its canonical spelling, sensitivity class, and numeric bounds derived from the shared
    // typed schema instead of ad-hoc call sites.
    let entry = gov_param_registry_entry("challenge_min_bond_bounty_bps")
        .expect("challenge_min_bond_bounty_bps must stay present in the canonical governance schema");
    assert_eq!(entry.key, "challenge_min_bond_bounty_bps");
    assert_eq!(entry.kind, GovParamKind::Timelocked);
    assert_eq!(
        entry.validator,
        GovParamValueValidator::U64Range {
            min: 0,
            max: 100_000,
        }
    );
    assert_eq!(entry.pinned_key_id, None);
    assert!(gov_param_registry_entry("Challenge_Min_Bond_Bounty_Bps").is_none());

    let mut st = StateStore::new();
    let scheduled = st
        .set_gov_param(24_000, 7_330, entry.key.into(), "2500".into())
        .expect("canonical numeric governance binding must remain writable through the typed registry");
    assert!(matches!(
        scheduled,
        GovParamUpdateOutcome::Scheduled {
            activate_at_height: 24_020
        }
    ));

    let pending = st
        .pending_gov_update(entry.key)
        .expect("timelocked numeric governance update must be staged");
    assert_eq!(pending.key_id, 7_330);
    assert_eq!(pending.value, "2500");
    assert_eq!(pending.activate_at_height, 24_020);
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
    for (i, (key, invalid_merge_gate_sample)) in gov_invalid_merge_gate_samples().enumerate() {
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

#[test]
fn governance_pinned_key_registry_merge_gate_is_unique_and_canonical() {
    // Merge-gate: reserved Algorand-style key bindings must stay one-to-one in the typed
    // registry so canonical key and reserved key-id cannot silently drift apart.
    let pinned_pairs: Vec<(&str, u64)> = gov_pinned_key_ids().collect();
    let pinned_keys: std::collections::BTreeSet<&str> =
        pinned_pairs.iter().map(|(key, _)| *key).collect();
    let pinned_ids: std::collections::BTreeSet<u64> =
        pinned_pairs.iter().map(|(_, key_id)| *key_id).collect();

    assert_eq!(
        pinned_keys.len(),
        pinned_pairs.len(),
        "typed pinned-key registry contains duplicate keys"
    );
    assert_eq!(
        pinned_ids.len(),
        pinned_pairs.len(),
        "typed pinned-key registry contains duplicate reserved key_ids"
    );

    let schema_pinned: std::collections::BTreeMap<&str, u64> = GOV_PARAM_SCHEMA
        .iter()
        .filter_map(|entry| entry.pinned_key_id.map(|key_id| (entry.key, key_id)))
        .collect();
    let derived_pinned: std::collections::BTreeMap<&str, u64> =
        pinned_pairs.iter().copied().collect();
    assert_eq!(
        derived_pinned, schema_pinned,
        "derived pinned-key view drifted from GOV_PARAM_SCHEMA"
    );
    assert_eq!(derived_pinned.get("emergency_pause"), Some(&EMERGENCY_PAUSE_KEY_ID));
    assert_eq!(derived_pinned.len(), 1, "unexpected extra reserved governance key binding");
}

#[test]
fn governance_pinned_key_registry_exposes_only_canonical_allowlisted_bindings() {
    // Merge-gate: the typed pinned-key registry must only expose canonical lowercase allowlisted
    // keys. Foreign Algorand-style aliases or case variants must not acquire the reserved id.
    let pinned_pairs: std::collections::BTreeMap<&str, u64> = gov_pinned_key_ids().collect();
    assert_eq!(pinned_pairs.get("emergency_pause"), Some(&EMERGENCY_PAUSE_KEY_ID));
    assert!(!pinned_pairs.contains_key("Emergency_Pause"));
    assert!(!pinned_pairs.contains_key("algorand_governance_key_id"));

    let emergency_pause_entry = gov_param_registry_entry("emergency_pause")
        .expect("canonical emergency_pause entry must stay present in the typed governance schema");
    assert_eq!(emergency_pause_entry.pinned_key_id, Some(EMERGENCY_PAUSE_KEY_ID));
    assert!(gov_param_registry_entry("Emergency_Pause").is_none());
    assert!(gov_param_registry_entry("algorand_governance_key_id").is_none());
}
