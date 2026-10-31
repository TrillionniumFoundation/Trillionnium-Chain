use super::*;
use crate::{Error, ErrorCode, Node};
use rusqlite::{params, Connection};
use serde_json::json;
use std::cell::Cell;
use trnm_protocol::pon_wire::hash;

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
    assert!(
        root_material["retained_material"]["payload_bytes"]
            .as_u64()
            .unwrap()
            < 300_000
    );
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
