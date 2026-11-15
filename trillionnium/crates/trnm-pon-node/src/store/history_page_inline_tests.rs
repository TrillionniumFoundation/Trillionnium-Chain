use super::*;
use rusqlite::{types::Value as SqlValue, Connection};

fn original_record(row: &rusqlite::Row<'_>, first: usize) -> Result<Record> {
    decode_record(raw_record(row, first)?)
}

fn equal_records(original: Result<Record>, actual: Result<Record>) {
    match (original, actual) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a.parent, b.parent);
            assert_eq!(a.height, b.height);
            assert_eq!(a.work.bytes(), b.work.bytes());
            assert_eq!(a.root, b.root);
        }
        (Err(a), Err(b)) => {
            assert_eq!(a.to_string(), b.to_string());
            assert_eq!(a.kind(), b.kind());
            assert_eq!(a.code(), b.code());
            assert_eq!(a.requires_owner_stop(), b.requires_owner_stop());
        }
        _ => panic!("inline record conversion differs from original"),
    }
}

fn compare_columns(db: &Connection, values: &[SqlValue; 4]) {
    for first in [0, 4] {
        let sql = if first == 0 {
            "SELECT ?1,?2,?3,?4"
        } else {
            "SELECT NULL,NULL,NULL,NULL,?1,?2,?3,?4"
        };
        let mut statement = db.prepare(sql).unwrap();
        let mut rows = statement.query(rusqlite::params_from_iter(values)).unwrap();
        let row = rows.next().unwrap().unwrap();
        equal_records(original_record(row, first), inline_record(row, first));
    }
}

#[test]
fn history_inline_record_types_widths_and_error_precedence_match_original() {
    let db = Connection::open_in_memory().unwrap();
    let valid = [
        SqlValue::Blob(vec![7; 32]),
        SqlValue::Integer(1),
        SqlValue::Blob(vec![9; 64]),
        SqlValue::Blob(vec![11; 32]),
    ];
    let mut variants = vec![
        SqlValue::Null,
        SqlValue::Integer(-1),
        SqlValue::Integer(0),
        SqlValue::Integer(i64::MAX),
        SqlValue::Real(1.5),
        SqlValue::Text("not a blob".into()),
    ];
    variants.extend(
        [0, 1, 31, 32, 33, 63, 64, 65, 4 * 1024 * 1024]
            .into_iter()
            .map(|length| SqlValue::Blob(vec![13; length])),
    );
    compare_columns(&db, &valid);
    for column in 0..4 {
        for value in &variants {
            let mut values = valid.clone();
            values[column] = value.clone();
            compare_columns(&db, &values);
        }
    }
    // SQL conversion faults still precede earlier width defects. Once all SQL
    // types convert, parent width precedes work width, which precedes root width.
    for values in [
        [
            SqlValue::Blob(vec![7; 33]),
            SqlValue::Integer(1),
            SqlValue::Text("bad work type".into()),
            SqlValue::Blob(vec![11; 33]),
        ],
        [
            SqlValue::Blob(vec![7; 33]),
            SqlValue::Integer(1),
            SqlValue::Blob(vec![9; 65]),
            SqlValue::Blob(vec![11; 33]),
        ],
        [
            SqlValue::Null,
            SqlValue::Integer(1),
            SqlValue::Blob(vec![9; 65]),
            SqlValue::Text("bad root type".into()),
        ],
    ] {
        compare_columns(&db, &values);
    }
}

fn narrow_chain(directory: &Path, blocks: u64) -> (Node, Vec<Hash>) {
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = Node::open(directory, settings.clone(), 1).unwrap();
    let mut ids = vec![settings.genesis()];
    for _ in 0..blocks {
        let parent = *ids.last().unwrap();
        ids.push(extend(&mut node, parent, false, 2, true));
    }
    (node, ids)
}

#[test]
fn history_inline_record_complete_pages_and_foreign_corruption_match_original() {
    let directory = tempfile::tempdir().unwrap();
    let (node, ids) = narrow_chain(directory.path(), 65);
    let state = node.read_active().unwrap();
    let writes = node.db.total_changes();
    for (height, cursor, limit) in [
        (1, 0, 1),
        (64, 0, 16),
        (65, 0, 16),
        (65, 64, 1),
        (65, 65, 16),
    ] {
        let mut expected = None;
        for decoder in [
            original_record as fn(&rusqlite::Row<'_>, usize) -> Result<Record>,
            inline_record,
        ] {
            let before = node.history_page_read_counters();
            let mut progress = Vec::new();
            let page = node
                .history_with_decoders(
                    ids[height],
                    ids[cursor],
                    limit,
                    &mut |n| {
                        progress.push(n);
                        Ok(())
                    },
                    |packet| packet.checked_wire_length_for_settings(node.settings()),
                    decoder,
                )
                .unwrap();
            let after = node.history_page_read_counters();
            assert_eq!(
                after.ancestor_links - before.ancestor_links,
                (height - cursor) as u64
            );
            assert_eq!(
                after.ancestor_selects - before.ancestor_selects,
                ((height - cursor) as u64).div_ceil(64)
            );
            assert!(after.retained_ids_high_water <= 16);
            let result = (encoded(&page), progress);
            if let Some(expected) = &expected {
                assert_eq!(&result, expected);
            } else {
                expected = Some(result);
            }
        }
    }
    // Warm reads grant no authority to a later request. A foreign SQLite writer
    // corrupts an ancestor outside the returned first page; both codecs reject.
    let foreign = Connection::open(directory.path().join("native.sqlite")).unwrap();
    let original = node.record(ids[32]).unwrap();
    foreign
        .execute(
            "UPDATE blocks SET chainwork=X'01' WHERE id=?",
            [ids[32].as_slice()],
        )
        .unwrap();
    for decoder in [
        original_record as fn(&rusqlite::Row<'_>, usize) -> Result<Record>,
        inline_record,
    ] {
        let error = node
            .history_with_decoders(
                ids[65],
                ids[0],
                1,
                &mut |_| Ok(()),
                |packet| packet.checked_wire_length_for_settings(node.settings()),
                decoder,
            )
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "STORAGE_WORK");
        assert!(error.requires_owner_stop());
    }
    foreign
        .execute(
            "UPDATE blocks SET chainwork=? WHERE id=?",
            params![original.work.bytes().as_slice(), ids[32].as_slice()],
        )
        .unwrap();
    compare(&node, ids[65], ids[0], 16, 65);
    assert_eq!(node.db.total_changes(), writes);
    assert_eq!(node.read_active().unwrap(), state);
}

/// Identical CTE, SQL reads, full ancestry checks, native packet work and callback
/// path in both arms. This measures only the decoder substitution's effect on
/// the complete call; no wall-time ratio is a correctness requirement.
#[test]
#[ignore = "paired complete native history call cost; run explicitly in release mode"]
fn history_inline_record_complete_call_cost() {
    let directory = tempfile::tempdir().unwrap();
    let (node, ids) = narrow_chain(directory.path(), 257);
    let state = node.read_active().unwrap();
    let writes = node.db.total_changes();
    let mut observations = Vec::new();
    for height in [1_usize, 16, 64, 257] {
        let mut expected = None;
        for pair in 0..8 {
            for reference in if pair % 2 == 0 {
                [true, false]
            } else {
                [false, true]
            } {
                let decoder = if reference {
                    original_record as fn(&rusqlite::Row<'_>, usize) -> Result<Record>
                } else {
                    inline_record
                };
                let before = node.history_page_read_counters();
                let mut progress = Vec::new();
                let started = Instant::now();
                let packets = node
                    .history_with_decoders(
                        ids[height],
                        ids[0],
                        16,
                        &mut |n| {
                            progress.push(n);
                            Ok(())
                        },
                        |packet| packet.checked_wire_length_for_settings(node.settings()),
                        decoder,
                    )
                    .unwrap();
                let actual = encoded(&packets);
                drop(packets);
                let elapsed_ns = started.elapsed().as_nanos();
                let after = node.history_page_read_counters();
                let result = (actual, progress);
                if let Some(expected) = &expected {
                    assert_eq!(&result, expected);
                } else {
                    expected = Some(result);
                }
                assert_eq!(after.ancestor_links - before.ancestor_links, height as u64);
                assert_eq!(
                    after.ancestor_selects - before.ancestor_selects,
                    (height as u64).div_ceil(64)
                );
                observations.push(json!({
                    "height":height,"pair":pair,"reference_first":pair % 2 == 0,
                    "codec":if reference { "vec" } else { "inline" },
                    "elapsed_ns":elapsed_ns,
                    "ancestor_links":after.ancestor_links - before.ancestor_links,
                    "ancestor_selects":after.ancestor_selects - before.ancestor_selects,
                    "fixed_record_nonempty_vec_values":if reference { 6 * height - 1 } else { 0 },
                    "value_count_scope":"child/parent parent, work and root columns only; excludes locator IDs, SQLite, packets and allocator traffic"
                }));
            }
        }
    }
    assert_eq!(node.db.total_changes(), writes);
    assert_eq!(node.read_active().unwrap(), state);
    println!(
        "{}",
        json!({
            "schema":"native-history-inline-record-cost-v1",
            "source_files":compiled_source::FILES.iter().map(|(path, bytes)| json!({"path":path,"sha256":hex::encode(Sha256::digest(bytes))})).collect::<Vec<_>>(),
            "build_profile":if cfg!(debug_assertions) { "debug" } else { "release" },
            "scope":"same binary, owner and CTE; complete call, returned packet encoding and Packet release; equality checks outside clocks",
            "observations":observations,"all_bytes_progress_and_checks_equal":true,
            "history_page_asymptotic":"O(H)","full_pagination_asymptotic":"O(H^2/p)",
            "confirmed_tps":null,"wan_tps":null,"production_activation":false
        })
    );
}
