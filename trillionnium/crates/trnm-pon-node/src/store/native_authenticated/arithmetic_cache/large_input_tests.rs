use super::*;
use crate::{Error, ErrorCode, Node};
use rusqlite::{params, Connection};
use serde_json::json;
use std::cell::Cell;
use trnm_protocol::pon_wire::hash;

#[test]
fn borrowed_complete_partition_preserves_original_commitments_and_error_order() {
    use crate::account_archive_execution::state_witness::{
        commitment_from_complete_state, commitment_from_complete_state_with_borrowed_roots,
    };
    let settings = Settings::development(Some(1)).unwrap();
    let original = settings.initial.clone();
    let mut cases = vec![original.clone(), State::new()];
    for change in [
        "nonce",
        "zero",
        "unknown",
        "issued",
        "issued-absent",
        "issued-nonnumeric",
        "reward",
        "liabilities",
        "escrow-overflow",
        "grammar",
        "account-first",
    ] {
        let mut state = original.clone();
        match change {
            "nonce" => {
                state
                    .values_mut()
                    .find(|value| value.get("nonce").is_some())
                    .unwrap()["nonce"] = json!(9)
            }
            "zero" => {
                state.insert(
                    format!("account:{}", "91".repeat(32)),
                    json!({"balance":0,"nonce":99}),
                );
            }
            "unknown" => {
                state.insert(
                    "future-obligation:opaque".into(),
                    json!({"value":[1,"retained"]}),
                );
            }
            "issued" => {
                state.insert("meta:issued".into(), json!(u64::MAX));
            }
            "issued-absent" => {
                state.remove("meta:issued");
            }
            "issued-nonnumeric" => {
                state.insert("meta:issued".into(), json!("bad"));
            }
            "reward" => {
                state.insert("reward:bad".into(), json!({"amount":"bad"}));
            }
            "liabilities" => {
                state.insert("task:one".into(), json!({"remaining":1}));
                state.insert("quota:two".into(), json!({"remaining":2}));
                state.insert("release:three".into(), json!({"remaining":3}));
                state.insert("reward:four".into(), json!({"amount":4}));
                state.insert(
                    "meta:issued".into(),
                    json!(state["meta:issued"].as_u64().unwrap() + 10),
                );
            }
            "escrow-overflow" => {
                state.insert("task:one".into(), json!({"remaining":u64::MAX}));
                state.insert("quota:two".into(), json!({"remaining":1}));
            }
            "grammar" => {
                state.insert("a".repeat(161), json!(0));
                state.insert("zz-invalid".into(), json!(0.5));
            }
            "account-first" => {
                state.insert("account:malformed".into(), json!({"balance":0}));
                state.insert("zz-invalid".into(), json!(0.5));
            }
            _ => unreachable!(),
        }
        cases.push(state);
    }
    for state in cases {
        let expected = commitment_from_complete_state(&settings, &state);
        let actual = commitment_from_complete_state_with_borrowed_roots(
            &settings,
            &state,
            None,
            || trnm_mvcc_fee::pon_executor::root(&state),
            |partition| {
                assert_eq!(
                    partition.len(),
                    state
                        .keys()
                        .filter(|key| !key.starts_with("account:"))
                        .count()
                );
                for (key, value) in partition.iter() {
                    let (source_key, source_value) = state.get_key_value(key).unwrap();
                    assert!(std::ptr::eq(key, source_key));
                    assert!(std::ptr::eq(value, source_value));
                }
                partition.root()
            },
        );
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
    }
}

fn large_settings() -> Settings {
    let mut settings = Settings::development(Some(1)).unwrap();
    for index in 0..2100 {
        settings.initial.insert(
            format!("fixture-large-parent:{index:04}"),
            json!("x".repeat(4080)),
        );
    }
    let root = settings.state_root(&settings.initial).unwrap();
    settings.genesis = hash(
        b"genesis",
        &[
            &settings.network(),
            &settings.parameters(),
            &root,
            &settings.genesis_time().to_le_bytes(),
        ],
    );
    settings
}

#[test]
fn large_complete_inputs_keep_actual_accounts_conservation_and_context_checks() {
    let settings = large_settings();
    let cache = ArithmeticCache::default();
    let initial = cache.complete(&settings, &settings.initial).unwrap();
    assert_eq!(initial, complete(&settings, &settings.initial).unwrap());
    assert!(bounded_bytes(&settings.initial).is_none());
    assert!(cache.complete.borrow().is_empty());
    assert!(cache.root.borrow().is_none());
    let root_material = cache.observation()["complete_root_arithmetic"].clone();
    assert_eq!(root_material["entry_limit"], 1);
    assert_eq!(root_material["payload_limit_bytes"], 2 * 1024 * 1024);
    assert_eq!(
        root_material["retained_software_charge_limit_bytes"],
        16 * 1024 * 1024
    );
    assert_eq!(
        root_material["schema"],
        "pon-native-complete-root-arithmetic-v3"
    );
    let payload = root_material["retained_material"]["payload_bytes"]
        .as_u64()
        .unwrap();
    let strings = root_material["retained_material"]["exact_string_charge_bytes"]
        .as_u64()
        .unwrap();
    assert!(payload <= 2 * 1024 * 1024);
    assert!(strings > 0 && strings <= payload);
    // The original tree remains compact. Every key/leaf entry is independent;
    // one immutable value allocation fits all repeated strings in the SAME
    // pool, including descriptors and the shared allocation's software charge.
    assert!(payload - strings < 300_000);
    let string_entries = root_material["retained_material"]["exact_string_entries"]
        .as_u64()
        .unwrap();
    // Count the actual complete non-account view using the independent serde
    // encoder. The pre-existing model:current String also belongs to this set.
    let expected_strings: Vec<_> = settings
        .initial
        .iter()
        .filter(|(key, _)| !key.starts_with("account:"))
        .filter_map(|(key, value)| {
            let raw = value.as_str()?;
            let encoded = serde_json::to_vec(value).unwrap();
            (raw.is_ascii()
                && encoded.len() == raw.len() + 2
                && &encoded[1..encoded.len() - 1] == raw.as_bytes())
            .then_some(key.as_str())
        })
        .collect();
    assert!(expected_strings.contains(&"model:current"));
    assert_eq!(
        expected_strings
            .iter()
            .filter(|key| key.starts_with("fixture-large-parent:"))
            .count(),
        2100
    );
    assert_eq!(string_entries, expected_strings.len() as u64);
    assert!(payload < 512 * 1024);
    let counters = &root_material["counters"];
    let observed = counters["partition_inputs_observed"].as_u64().unwrap();
    let hashed = counters["partition_inputs_hashed"].as_u64().unwrap();
    let exact = counters["partition_exact_string_hits"].as_u64().unwrap();
    let encodings = counters["partition_string_encodings_reused"]
        .as_u64()
        .unwrap();
    assert_eq!(observed, hashed + exact);
    assert!(hashed > 0 && exact > 0);
    assert_eq!(encodings, exact);
    assert!(
        root_material["counters"]["partition_roots_reused"]
            .as_u64()
            .unwrap()
            > 1000
    );

    let mut changed = settings.initial.clone();
    changed.insert("fixture-large-parent:1000".into(), json!("y".repeat(4080)));
    let actual = cache.complete(&settings, &changed).unwrap();
    assert_eq!(actual, complete(&settings, &changed).unwrap());
    assert_ne!(actual.state_root, initial.state_root);
    assert_ne!(actual.non_account_root, initial.non_account_root);
    changed.remove("fixture-large-parent:1000");
    assert_eq!(
        cache.complete(&settings, &changed).unwrap(),
        complete(&settings, &changed).unwrap()
    );
    changed.insert("fixture-large-parent:1000".into(), json!("x".repeat(4080)));
    assert_eq!(cache.complete(&settings, &changed).unwrap(), initial);
    changed.insert(
        format!("account:{}", "91".repeat(32)),
        json!({"balance":0,"nonce":9}),
    );
    let account_changed = cache.complete(&settings, &changed).unwrap();
    assert_eq!(account_changed, complete(&settings, &changed).unwrap());
    assert_ne!(account_changed.account_root, initial.account_root);
    assert_eq!(account_changed.non_account_root, initial.non_account_root);

    changed.insert("meta:issued".into(), json!(initial.issued + 1));
    let warm = cache.complete(&settings, &changed).unwrap_err();
    let original = complete(&settings, &changed).unwrap_err();
    assert_eq!(warm.to_string(), original.to_string());
    assert_eq!(warm.kind(), original.kind());
    changed.insert("account:malformed".into(), json!({"balance":0}));
    changed.insert("zz-invalid-number".into(), json!(-0.0));
    let before =
        cache.observation()["complete_root_arithmetic"]["counters"]["calculations"].clone();
    assert_eq!(
        cache.complete(&settings, &changed).unwrap_err().to_string(),
        complete(&settings, &changed).unwrap_err().to_string()
    );
    assert_eq!(
        cache.observation()["complete_root_arithmetic"]["counters"]["calculations"],
        before
    );

    for component in 0..3 {
        let mut foreign = settings.clone();
        match component {
            0 => foreign.app.network[0] ^= 1,
            1 => foreign.app.parameters[0] ^= 1,
            _ => foreign.genesis[0] ^= 1,
        }
        let result = cache.complete(&foreign, &settings.initial).unwrap();
        assert_eq!(result, complete(&foreign, &settings.initial).unwrap());
        assert_ne!(result.id, initial.id);
    }
    assert!(cache.complete.borrow().is_empty());
}

#[test]
fn warmed_large_arithmetic_keeps_actual_sql_rows_cancellation_and_cold_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let settings = large_settings();
    let mut node =
        Node::open_with_authenticated_state(directory.path(), settings.clone(), 1).unwrap();
    let expected = node.read_active().unwrap();
    assert_eq!(node.read_active().unwrap(), expected);
    assert!(
        node.native_history_arithmetic_observation()["complete_root_arithmetic"]["counters"]
            ["partition_roots_reused"]
            .as_u64()
            .unwrap()
            > 1000
    );
    let foreign = Connection::open(directory.path().join("native.sqlite")).unwrap();
    let key = "fixture-large-parent:1000";
    let slot: u64 = foreign
        .query_row(
            "SELECT state_slot FROM active WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let original: Vec<u8> = foreign
        .query_row(
            "SELECT value FROM kv WHERE slot=? AND key=?",
            params![slot, key],
            |row| row.get(0),
        )
        .unwrap();
    for damaged in [
        serde_json::to_vec(&json!("y".repeat(4080))).unwrap(),
        b"-0.0".to_vec(),
    ] {
        node.read_active().unwrap();
        foreign
            .execute(
                "UPDATE kv SET value=? WHERE slot=? AND key=?",
                params![damaged, slot, key],
            )
            .unwrap();
        let warm = node.read_active().unwrap_err();
        node.authenticated_arithmetic = ArithmeticCache::default();
        let cold = node.read_active().unwrap_err();
        assert_eq!(warm.to_string(), cold.to_string());
        assert_eq!(warm.kind(), cold.kind());
        assert!(warm.requires_owner_stop());
        foreign
            .execute(
                "UPDATE kv SET value=? WHERE slot=? AND key=?",
                params![original, slot, key],
            )
            .unwrap();
        assert_eq!(node.read_active().unwrap(), expected);
    }
    foreign
        .execute("DELETE FROM kv WHERE slot=? AND key=?", params![slot, key])
        .unwrap();
    let warm = node.read_active().unwrap_err();
    node.authenticated_arithmetic = ArithmeticCache::default();
    let cold = node.read_active().unwrap_err();
    assert_eq!(warm.to_string(), cold.to_string());
    assert_eq!(warm.kind(), cold.kind());
    assert!(warm.requires_owner_stop());
    foreign
        .execute(
            "INSERT INTO kv(slot,key,value) VALUES(?,?,?)",
            params![slot, key, original],
        )
        .unwrap();
    assert_eq!(node.read_active().unwrap(), expected);

    let calls = Cell::new(0usize);
    node.read_active_with_progress(&mut || {
        calls.set(calls.get() + 1);
        Ok(())
    })
    .unwrap();
    let boundaries = calls.get();
    assert!(boundaries > 4);
    for cut in [1, boundaries / 2, boundaries] {
        calls.set(0);
        let error = node
            .read_active_with_progress(&mut || {
                calls.set(calls.get() + 1);
                if calls.get() == cut {
                    Err(Error::new(ErrorCode::FrameDeadline))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(error.is(ErrorCode::FrameDeadline));
        assert_eq!(calls.get(), cut);
        assert_eq!(node.read_active().unwrap(), expected);
    }
    drop(foreign);
    drop(node);
    let reopened = Node::open_with_authenticated_state(directory.path(), settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), expected);
}
