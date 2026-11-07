//! Same-scan JSON decoding only: the literal original SQL decoder remains
//! the oracle. Malformed-schema probes do not qualify a service schema.
use super::*;
use rusqlite::types::Value as SqlValue;
use serde_json::json;

fn fixture() -> (tempfile::TempDir, Node) {
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open(directory.path(), Settings::development(Some(1)).unwrap(), 1).unwrap();
    (directory, node)
}

fn replace_rows(node: &Node, values: &[SqlValue]) {
    let slot = node.slot().unwrap();
    node.db
        .execute("DELETE FROM kv WHERE slot=?", [slot])
        .unwrap();
    let mut insert = node
        .db
        .prepare("INSERT INTO kv(slot,key,value) VALUES(?,?,?)")
        .unwrap();
    for (index, value) in values.iter().enumerate() {
        insert
            .execute(params![slot, format!("cell:{index:06}"), value])
            .unwrap();
    }
}

type Outcome = std::result::Result<Vec<u8>, (String, bool)>;

fn observed(node: &Node, reference: bool, stop: Option<usize>) -> (Outcome, usize) {
    let mut calls = 0;
    let mut progress = || {
        calls += 1;
        ensure(stop != Some(calls), "CANONICAL_ROW_ORIGINAL_CANCEL")
    };
    let state = if reference {
        original_slot_state(node, node.slot().unwrap(), &mut progress)
    } else {
        node.slot_state_with_progress(node.slot().unwrap(), &mut progress)
    };
    let result = state
        .map(|state| serde_json::to_vec(&state).unwrap())
        .map_err(|error| (error.to_string(), error.requires_owner_stop()));
    (result, calls)
}

fn parity(node: &Node) -> usize {
    let reference = observed(node, true, None);
    assert_eq!(observed(node, false, None), reference);
    reference.1
}

#[test]
fn same_scan_values_match_original_and_never_outlive_actual_rows() {
    let (_directory, node) = fixture();
    let forms: Vec<Value> = vec![
        Value::Null,
        json!(true),
        json!(false),
        json!(0),
        json!(-1),
        json!(u64::MAX),
        serde_json::from_str("-0.0").unwrap(),
        json!(""),
        json!("quote \" slash \\ control \n \u{0} \u{7f} 汉字"),
        json!([]),
        json!([1, "x", null]),
        json!({"a": [true, null], "b": "same"}),
        json!("x".repeat(4080)),
    ];
    for a in &forms {
        let b = json!({"different": true});
        let bytes_a = serde_json::to_vec(a).unwrap();
        let bytes_b = serde_json::to_vec(&b).unwrap();
        replace_rows(
            &node,
            &[
                SqlValue::Blob(bytes_a.clone()),
                SqlValue::Blob(bytes_a.clone()),
                SqlValue::Blob(bytes_b.clone()),
                SqlValue::Blob(bytes_b),
                SqlValue::Blob(bytes_a),
            ],
        );
        parity(&node);
        // A later call always reads and decodes its actual first row again.
        node.db
            .execute(
                "UPDATE kv SET value=? WHERE key='cell:000000'",
                [b"null".as_slice()],
            )
            .unwrap();
        parity(&node);
        node.db
            .execute(
                "UPDATE kv SET value=? WHERE key='cell:000000'",
                [b"".as_slice()],
            )
            .unwrap();
        assert!(observed(&node, false, None).0.is_err());
        parity(&node);
    }
}

#[test]
fn same_bytes_keep_current_sql_types_grammar_limits_and_error_priority() {
    let (_directory, node) = fixture();
    let good = b"\"AA\"".to_vec();
    replace_rows(
        &node,
        &[SqlValue::Blob(good.clone()), SqlValue::Blob(good.clone())],
    );
    for wrong in [
        SqlValue::Text("\"AA\"".into()),
        SqlValue::Null,
        SqlValue::Integer(0),
        SqlValue::Real(0.0),
        SqlValue::Blob(Vec::new()),
        SqlValue::Blob(b" \"AA\"".to_vec()),
        SqlValue::Blob(b"\"AA\" ".to_vec()),
        SqlValue::Blob(b"\"\\u0041A\"".to_vec()),
        SqlValue::Blob(b"{\"a\":1,\"a\":1}".to_vec()),
        SqlValue::Blob(vec![b'x'; 4097]),
    ] {
        node.db
            .execute("UPDATE kv SET value=? WHERE key='cell:000001'", [wrong])
            .unwrap();
        parity(&node);
        assert!(observed(&node, false, None).0.is_err());
    }
    // Independent original-decoder oracle over every byte replacement of two
    // different canonical forms, including replacements that remain valid.
    for seed in [b"\"AA\"".as_slice(), b"{\"a\":1}".as_slice()] {
        for offset in 0..seed.len() {
            for replacement in 0_u8..=255 {
                let mut changed = seed.to_vec();
                changed[offset] = replacement;
                node.db
                    .execute("UPDATE kv SET value=? WHERE key='cell:000001'", [changed])
                    .unwrap();
                parity(&node);
            }
        }
    }
    node.db
        .execute(
            "UPDATE kv SET value=?,key=? WHERE key='cell:000001'",
            params![good, "z".repeat(161)],
        )
        .unwrap();
    parity(&node);
    assert_eq!(observed(&node, false, None).0.unwrap_err().0, "STATE_BYTES");
}

#[test]
fn same_scan_repeated_keys_and_sql_order_keep_original_overwrite_semantics() {
    let (_directory, node) = fixture();
    let slot = node.slot().unwrap();
    // Deliberately malformed schema: decoder equivalence only. No admission,
    // root, migration or closed-schema acceptance is inferred from this case.
    node.db
        .execute_batch(
            "DROP TABLE kv; CREATE TABLE kv(slot INTEGER,key TEXT COLLATE NOCASE,value BLOB)",
        )
        .unwrap();
    for (key, value) in [
        ("a", "1"),
        ("A", "1"),
        ("b", "2"),
        ("B", "2"),
        ("a", "3"),
        ("z", "3"),
    ] {
        node.db
            .execute(
                "INSERT INTO kv(slot,key,value) VALUES(?,?,?)",
                params![slot, key, value.as_bytes()],
            )
            .unwrap();
    }
    parity(&node);
    node.db
        .execute(
            "INSERT INTO kv(slot,key,value) VALUES(?,?,?)",
            params![slot, Vec::<u8>::from(b"raw-key"), b"3".as_slice()],
        )
        .unwrap();
    parity(&node);
    assert!(observed(&node, false, None).0.is_err());
}

#[test]
fn every_original_scan_cancellation_and_late_corruption_still_refuses() {
    let (_directory, node) = fixture();
    let values = vec![SqlValue::Blob(b"{\"a\":1}".to_vec()); 513];
    replace_rows(&node, &values);
    let calls = parity(&node);
    assert_eq!(calls, 5); // entry, rows 0/256/512, original final callback.
    let original = observed(&node, true, None);
    for stop in 1..=calls {
        let reference = observed(&node, true, Some(stop));
        assert_eq!(observed(&node, false, Some(stop)), reference);
        assert_eq!(reference.0.unwrap_err().0, "CANONICAL_ROW_ORIGINAL_CANCEL");
        assert_eq!(observed(&node, false, None), original);
    }
    node.db
        .execute(
            "UPDATE kv SET value=? WHERE key='cell:000512'",
            [b"bad".as_slice()],
        )
        .unwrap();
    parity(&node);
    assert!(observed(&node, false, None).0.is_err());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "explicit complete SQL scan ABBA observation; not state activation, original Host, confirmation TPS or a timing assertion"]
fn complete_slot_scan_abba_records_adjacent_and_all_miss_inputs() {
    let (_directory, node) = fixture();
    let clock = || {
        let t = rustix::time::clock_gettime(rustix::time::ClockId::ThreadCPUTime);
        u64::try_from(t.tv_sec).unwrap() * 1_000_000_000 + u64::try_from(t.tv_nsec).unwrap()
    };
    for (case, count, width, adjacent) in [
        ("small_adjacent", 128, 64, true),
        ("small_all_miss", 128, 64, false),
        ("large_adjacent", 2100, 4080, true),
        ("large_all_miss", 2100, 4080, false),
    ] {
        let values: Vec<_> = (0..count)
            .map(|i| {
                let text = if adjacent {
                    "x".repeat(width)
                } else {
                    format!("{i:08}{}", "x".repeat(width - 8))
                };
                SqlValue::Blob(serde_json::to_vec(&text).unwrap())
            })
            .collect();
        replace_rows(&node, &values);
        let expected = original_slot_state(&node, node.slot().unwrap(), &mut || Ok(())).unwrap();
        for round in 0..8 {
            for (position, reference) in [true, false, false, true].into_iter().enumerate() {
                let wall = std::time::Instant::now();
                let cpu = clock();
                let actual = if reference {
                    original_slot_state(&node, node.slot().unwrap(), &mut || Ok(())).unwrap()
                } else {
                    node.slot_state_with_progress(node.slot().unwrap(), &mut || Ok(()))
                        .unwrap()
                };
                std::hint::black_box(&actual);
                let cpu_ns = clock() - cpu;
                let wall_ns = wall.elapsed().as_nanos();
                assert_eq!(actual, expected);
                println!(
                    "{}",
                    json!({
                        "schema":"same-scan-canonical-row-abba-v1","case":case,"rows":count,
                        "value_string_bytes":width,"round":round,"position":position,
                        "path":if reference {"literal_original"} else {"same_scan_decoding"},
                        "wall_ns":wall_ns.to_string(),"thread_cpu_ns":cpu_ns,
                        "scope":"complete actual SQL scan and State materialization; equivalence check and drop outside timed interval; each invocation starts with no decoding fact; not disk-cold, State activation or original-resource business qualification"
                    })
                );
            }
        }
    }
}

// Literal pre-change SQL decoder from d26/619; never calls the candidate.
fn original_slot_state(
    node: &Node,
    slot: u64,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<State> {
    progress()?;
    // Validate stored dimensions before copying a cell into Rust. SQL types
    // are retained: TEXT is not a value BLOB, and a BLOB is not a key TEXT.
    // Cache only the compiled statement in the connection's existing
    // bounded cache. Every call still opens a new query, reads all actual
    // rows, and repeats the original dimensions/canonical/root checks.
    // No State, row, snapshot or validation verdict survives this call.
    let mut stmt = node.db.prepare_cached(
            "SELECT CASE WHEN typeof(key)='text' THEN CAST(substr(CAST(key AS BLOB),1,161) AS TEXT) ELSE key END,
             CASE WHEN typeof(value)='blob' THEN substr(value,1,4097) ELSE value END,
             length(CAST(key AS BLOB)),length(CAST(value AS BLOB))
             FROM kv WHERE slot=? ORDER BY kv.key",
        ).map_err(|error| Error::from(error).local_integrity())?;
    let mut rows = stmt
        .query([slot])
        .map_err(|error| Error::from(error).local_integrity())?;
    let mut state = State::new();
    let mut canonical_bytes = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| Error::from(error).local_integrity())?
    {
        if state.len().is_multiple_of(256) {
            progress()?;
        }
        let key: String = (|| -> Result<_> {
            let key_len: i64 = row.get(2)?;
            let value_len: i64 = row.get(3)?;
            ensure(
                state.len()
                    < if growth_profile_v2::enabled(&node.settings.app) {
                        growth_profile_v2::MAX_TOTAL_KEYS
                    } else {
                        65_536
                    }
                    && (0..=160).contains(&key_len)
                    && (0..=4096).contains(&value_len),
                "STATE_BYTES",
            )?;
            Ok(row.get(0)?)
        })()
        .map_err(Error::local_integrity)?;
        // The bounded SQL BLOB remains borrowed until this row advances.
        // Decoded State owns its data; no SQLite borrow escapes this scope.
        let cell = row
            .get_ref(1)
            .map_err(|error| Error::from(error).local_integrity())?;
        let bytes = cell.as_blob().map_err(|_| {
            Error::from(rusqlite::Error::InvalidColumnType(
                1,
                "value".into(),
                cell.data_type(),
            ))
            .local_integrity()
        })?;
        let value: Value =
            serde_json::from_slice(bytes).map_err(|error| Error::from(error).local_integrity())?;
        canonical_bytes.clear();
        serde_json::to_writer(&mut canonical_bytes, &value)
            .map_err(|error| Error::from(error).local_integrity())?;
        ensure(canonical_bytes == bytes, "STATE_BYTES").map_err(Error::local_integrity)?;
        state.insert(key, value);
    }
    progress()?;
    Ok(state)
}
