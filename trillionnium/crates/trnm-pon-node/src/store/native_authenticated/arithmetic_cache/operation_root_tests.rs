use super::large_input_tests::large_settings;
use super::*;
use crate::{Error, ErrorCode, Node};
use rusqlite::{params, Connection};
use serde_json::json;

fn assert_original_result(actual: Result<StateCommitment>, original: Result<StateCommitment>) {
    match (actual, original) {
        (Ok(actual), Ok(original)) => assert_eq!(actual, original),
        (Err(actual), Err(original)) => {
            assert_eq!(actual.to_string(), original.to_string());
            assert_eq!(actual.kind(), original.kind());
            assert_eq!(actual.requires_owner_stop(), original.requires_owner_stop());
        }
        (actual, original) => panic!("different complete results: {actual:?} / {original:?}"),
    }
}

fn counter(cache: &ArithmeticCache, name: &str) -> u64 {
    cache.observation()["complete_root_arithmetic"]["counters"][name]
        .as_u64()
        .unwrap()
}

#[test]
fn one_use_calculation_keeps_complete_results_and_actual_hash_counts() {
    let settings = large_settings();
    let state = &settings.initial;
    let cache = ArithmeticCache::default();
    let original = complete(&settings, state).unwrap();
    let mut calculation = None;
    let root = cache
        .state_root_with_calculation(&settings, state, &mut calculation)
        .unwrap();
    assert_eq!(root, original.state_root);
    assert!(calculation.is_some());
    let hashes = counter(&cache, "partition_inputs_hashed");
    let calculations = counter(&cache, "calculations");
    assert_eq!(hashes, state.len() as u64);
    assert_eq!(
        cache
            .complete_with_calculation(&settings, state, calculation.take())
            .unwrap(),
        original
    );
    assert!(calculation.is_none());
    assert_eq!(counter(&cache, "operation_full_root_reuses"), 1);
    assert_eq!(counter(&cache, "partition_inputs_hashed"), hashes);
    assert_eq!(counter(&cache, "calculations"), calculations + 1);
    assert_eq!(counter(&cache, "partition_projection_uses"), 1);
    assert_eq!(
        json!(counter(&cache, "partition_projection_compared_keys")),
        json!(original.non_account_count)
    );
    assert!(cache.complete.borrow().is_empty());
    assert!(cache.root.borrow().is_none());
    assert_eq!(cache.complete(&settings, state).unwrap(), original);
    assert_eq!(counter(&cache, "operation_full_root_reuses"), 1);
    assert_eq!(
        counter(&cache, "partition_inputs_hashed"),
        hashes + state.len() as u64
    );
}

#[test]
fn calculation_refuses_other_state_objects_and_all_settings_bindings() {
    let settings = large_settings();
    let cache = ArithmeticCache::default();
    let identical = settings.initial.clone();
    let mut changed = identical.clone();
    changed.insert("fixture-large-parent:1000".into(), json!("y".repeat(4080)));
    let mut changed_keys = identical.clone();
    changed_keys.remove("fixture-large-parent:1000");
    changed_keys.insert("fixture-new-key".into(), json!("x".repeat(4080)));
    let mut noncanonical = identical.clone();
    noncanonical.insert("a".repeat(161), json!(0));
    noncanonical.insert("zz-original-late-error".into(), json!(-0.0));
    for actual in [&identical, &changed, &changed_keys, &noncanonical] {
        let mut calculation = None;
        cache
            .state_root_with_calculation(&settings, &settings.initial, &mut calculation)
            .unwrap();
        assert!(calculation.is_some());
        let before = counter(&cache, "operation_full_root_reuses");
        assert_original_result(
            cache.complete_with_calculation(&settings, actual, calculation),
            complete(&settings, actual),
        );
        assert_eq!(counter(&cache, "operation_full_root_reuses"), before);
    }
    for component in 0..5 {
        let mut other = settings.clone();
        match component {
            0 => {}
            1 => other.app.network[0] ^= 1,
            2 => other.app.parameters[0] ^= 1,
            3 => other.genesis[0] ^= 1,
            _ => other.app.fees[0] ^= 1,
        }
        let mut calculation = None;
        cache
            .state_root_with_calculation(&settings, &settings.initial, &mut calculation)
            .unwrap();
        assert!(calculation.is_some());
        let before = counter(&cache, "operation_full_root_reuses");
        assert_original_result(
            cache.complete_with_calculation(&other, &settings.initial, calculation),
            complete(&other, &settings.initial),
        );
        assert_eq!(counter(&cache, "operation_full_root_reuses"), before);
    }
}

#[test]
fn failed_input_and_original_early_hits_clear_the_out_calculation() {
    let settings = large_settings();
    let small = Settings::development(Some(1)).unwrap();
    let mut invalid = settings.initial.clone();
    invalid.insert("a".repeat(161), json!(0));
    invalid.insert("zz-original-late-error".into(), json!("non-ascii-\u{e9}"));
    let cache = ArithmeticCache::default();
    let mut calculation = None;
    cache
        .state_root_with_calculation(&settings, &settings.initial, &mut calculation)
        .unwrap();
    assert!(calculation.is_some());
    let actual = cache
        .state_root_with_calculation(&settings, &invalid, &mut calculation)
        .unwrap_err();
    assert!(calculation.is_none());
    let original = cache.state_root(&settings, &invalid).unwrap_err();
    assert_eq!(actual.to_string(), original.to_string());
    assert_eq!(actual.kind(), original.kind());
    cache.complete(&small, &small.initial).unwrap();
    cache
        .state_root_with_calculation(&settings, &settings.initial, &mut calculation)
        .unwrap();
    assert!(calculation.is_some());
    let value = cache
        .state_root_with_calculation(&small, &small.initial, &mut calculation)
        .unwrap();
    assert!(calculation.is_none());
    assert_eq!(value, small.state_root(&small.initial).unwrap());
}

#[test]
fn original_account_and_conservation_errors_keep_the_full_root_callback_order() {
    let settings = large_settings();
    let mut malformed_account = settings.initial.clone();
    malformed_account.insert("account:malformed".into(), json!({"balance":0}));
    let mut conservation = settings.initial.clone();
    let original = complete(&settings, &settings.initial).unwrap();
    conservation.insert("meta:issued".into(), json!(original.issued + 1));
    for (state, expected_root_uses) in [(&malformed_account, 0), (&conservation, 1)] {
        let cache = ArithmeticCache::default();
        let mut calculation = None;
        cache
            .state_root_with_calculation(&settings, state, &mut calculation)
            .unwrap();
        assert!(calculation.is_some());
        let expected = complete(&settings, state);
        assert!(expected.is_err());
        assert_original_result(
            cache.complete_with_calculation(&settings, state, calculation),
            expected,
        );
        assert_eq!(
            counter(&cache, "operation_full_root_reuses"),
            expected_root_uses
        );
        assert_eq!(counter(&cache, "partition_projection_uses"), 0);
    }
}

#[test]
fn persisted_root_and_missing_record_refusals_still_precede_later_callbacks() {
    let directory = tempfile::tempdir().unwrap();
    let settings = large_settings();
    let node = Node::open_with_authenticated_state(directory.path(), settings, 1).unwrap();
    let (tip, _, state) = node.read_active().unwrap();
    let mut calls = 0usize;
    let before = counter(&node.authenticated_arithmetic, "operation_full_root_reuses");
    node.check_persisted_state_with_readback(
        tip,
        &state,
        &mut || {
            calls += 1;
            Ok(())
        },
        None,
    )
    .unwrap();
    assert!(calls > 0);
    assert_eq!(
        counter(&node.authenticated_arithmetic, "operation_full_root_reuses"),
        before + 1
    );
    let mut changed = state.clone();
    changed.insert("fixture-large-parent:1000".into(), json!("y".repeat(4080)));
    calls = 0;
    let before = counter(&node.authenticated_arithmetic, "operation_full_root_reuses");
    let error = node
        .check_persisted_state_with_readback(
            tip,
            &changed,
            &mut || {
                calls += 1;
                Ok(())
            },
            None,
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "ROOT");
    assert!(error.requires_owner_stop());
    assert_eq!(calls, 0);
    assert_eq!(
        counter(&node.authenticated_arithmetic, "operation_full_root_reuses"),
        before
    );
    let missing = [0x93; 32];
    assert_ne!(missing, tip);
    let expected = node
        .record(missing)
        .map_err(Error::local_integrity)
        .err()
        .expect("missing record must fail");
    let hashes = counter(&node.authenticated_arithmetic, "partition_inputs_hashed");
    let error = node
        .check_persisted_state_with_readback(
            missing,
            &state,
            &mut || {
                calls += 1;
                Ok(())
            },
            None,
        )
        .unwrap_err();
    assert_eq!(error.to_string(), expected.to_string());
    assert_eq!(error.kind(), expected.kind());
    assert_eq!(calls, 0);
    assert_eq!(
        counter(&node.authenticated_arithmetic, "partition_inputs_hashed"),
        hashes
    );
}

#[test]
fn later_sql_record_reads_and_cancellation_remain_mandatory_with_a_calculation() {
    let directory = tempfile::tempdir().unwrap();
    let settings = large_settings();
    let node = Node::open_with_authenticated_state(directory.path(), settings, 1).unwrap();
    let (tip, _, state) = node.read_active().unwrap();
    let foreign = Connection::open(directory.path().join("native.sqlite")).unwrap();
    let original: Vec<u8> = foreign
        .query_row(
            "SELECT data FROM native_state_commitments WHERE block=?",
            [tip.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let before = counter(&node.authenticated_arithmetic, "operation_full_root_reuses");
    let mut calls = 0usize;
    let error = node
        .check_persisted_state_with_readback(
            tip,
            &state,
            &mut || {
                calls += 1;
                if calls == 1 {
                    foreign
                        .execute(
                            "UPDATE native_state_commitments SET data=? WHERE block=?",
                            params![b"{".as_slice(), tip.as_slice()],
                        )
                        .unwrap();
                }
                Ok(())
            },
            None,
        )
        .unwrap_err();
    let expected = super::super::verify_state_with_cache(
        &node.db,
        &node.settings,
        tip,
        &state,
        &mut || Ok(()),
        None,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), expected.to_string());
    assert_eq!(error.kind(), expected.kind());
    assert!(error.requires_owner_stop());
    assert_eq!(calls, 1);
    assert_eq!(
        counter(&node.authenticated_arithmetic, "operation_full_root_reuses"),
        before
    );
    foreign
        .execute(
            "UPDATE native_state_commitments SET data=? WHERE block=?",
            params![original, tip.as_slice()],
        )
        .unwrap();
    calls = 0;
    let before = counter(&node.authenticated_arithmetic, "operation_full_root_reuses");
    let error = node
        .check_persisted_state_with_readback(
            tip,
            &state,
            &mut || {
                calls += 1;
                Err(Error::new(ErrorCode::FrameDeadline))
            },
            None,
        )
        .unwrap_err();
    assert!(error.is(ErrorCode::FrameDeadline));
    assert_eq!(calls, 1);
    assert_eq!(
        counter(&node.authenticated_arithmetic, "operation_full_root_reuses"),
        before
    );
    node.check_persisted_state_with_readback(tip, &state, &mut || Ok(()), None)
        .unwrap();
    assert_eq!(
        counter(&node.authenticated_arithmetic, "operation_full_root_reuses"),
        before + 1
    );
}
