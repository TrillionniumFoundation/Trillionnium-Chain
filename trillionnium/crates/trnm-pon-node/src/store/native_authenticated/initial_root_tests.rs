use super::*;
use crate::{ErrorCode, Node};
use rusqlite::types::Value as SqlValue;
use serde_json::json;

mod reference;

fn receipt<T>(result: Result<T>) -> std::result::Result<T, (String, String, bool)> {
    result.map_err(|error| {
        (
            error.to_string(),
            format!("{:?}", error.kind()),
            error.requires_owner_stop(),
        )
    })
}

fn counter(cache: &ArithmeticCache, name: &str) -> u64 {
    cache.observation()["complete_root_arithmetic"]["counters"][name]
        .as_u64()
        .unwrap()
}

fn stage_calls(cache: &ArithmeticCache) -> BTreeMap<String, u64> {
    cache.observation()["stages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["stage"].as_str().unwrap().to_owned(),
                row["totals"]["calls"].as_u64().unwrap(),
            )
        })
        .collect()
}

fn fixture(settings: Settings) -> (tempfile::TempDir, Node) {
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open_with_authenticated_state(directory.path(), settings, 1).unwrap();
    (directory, node)
}

fn history(
    original: bool,
    node: &Node,
    progress: &mut dyn FnMut() -> Result<()>,
    cache: Option<&ArithmeticCache>,
) -> Result<()> {
    if original {
        reference::verify_history_with_readback(
            &node.db,
            &node.settings,
            node.settings.genesis(),
            progress,
            cache,
            None,
        )
    } else {
        verify_history_with_readback(
            &node.db,
            &node.settings,
            node.settings.genesis(),
            progress,
            cache,
            None,
        )
    }
}

fn capture<'a>(node: &'a Node, cache: &ArithmeticCache) -> Result<InitialRootCalculation<'a>> {
    let record = load_observed(
        &node.db,
        node.settings.genesis(),
        Some((&node.settings, cache)),
    )?;
    let value = verify_record_with_initial_root(
        &node.db,
        &node.settings,
        &record,
        &mut || Ok(()),
        Some(cache),
        None,
    )?
    .ok_or("TEST_INITIAL_ROOT_CALCULATION_ABSENT")?;
    Ok(InitialRootCalculation {
        settings: &node.settings,
        value,
    })
}

fn second_record_checkpoint(node: &Node) -> usize {
    let record = load_observed(&node.db, node.settings.genesis(), None).unwrap();
    let mut calls = 0usize;
    reference::checked_record(
        &node.db,
        &node.settings,
        &record,
        &mut || {
            calls += 1;
            Ok(())
        },
        None,
    )
    .unwrap();
    // The original history-loop checkpoint precedes the first record; the
    // original verify_state entry checkpoint follows the snapshot read.
    2 + calls
}

type BlockIdentity = (Option<Hash>, u64, Hash, Option<Hash>);

fn block_identity(block: NativeBlock) -> BlockIdentity {
    (block.parent, block.height, block.root, block.packet_digest)
}

// The existing legitimate large-input fixture, copied without changing its
// row count, value size, root calculation, genesis binding or settings.
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
fn history_initial_root_reuse_keeps_results_progress_and_actual_hash_counts() {
    let (_directory, node) = fixture(large_settings());
    let original_cache = ArithmeticCache::default();
    let actual_cache = ArithmeticCache::default();
    let mut original_calls = 0usize;
    let mut actual_calls = 0usize;
    let original = history(
        true,
        &node,
        &mut || {
            original_calls += 1;
            Ok(())
        },
        Some(&original_cache),
    );
    let actual = history(
        false,
        &node,
        &mut || {
            actual_calls += 1;
            Ok(())
        },
        Some(&actual_cache),
    );
    assert!(original.is_ok());
    assert_eq!(receipt(actual), receipt(original));
    assert_eq!(actual_calls, original_calls);
    assert_eq!(stage_calls(&actual_cache), stage_calls(&original_cache));
    let rows = node.settings.initial.len() as u64;
    assert_eq!(counter(&actual_cache, "operation_initial_root_reuses"), 1);
    assert_eq!(counter(&original_cache, "operation_initial_root_reuses"), 0);
    assert_eq!(
        counter(&actual_cache, "partition_inputs_hashed") + rows,
        counter(&original_cache, "partition_inputs_hashed")
    );
    assert_eq!(
        counter(&actual_cache, "calculations") + 1,
        counter(&original_cache, "calculations")
    );
    assert_eq!(
        counter(&actual_cache, "partition_projection_uses"),
        counter(&original_cache, "partition_projection_uses")
    );
    let before = counter(&actual_cache, "partition_inputs_hashed");
    let calculations = counter(&actual_cache, "calculations");
    history(false, &node, &mut || Ok(()), Some(&actual_cache)).unwrap();
    assert_eq!(counter(&actual_cache, "operation_initial_root_reuses"), 2);
    // A later history walk calculates its actual initial input again, and the
    // distinct snapshot still performs its complete actual-input root work.
    assert_eq!(
        counter(&actual_cache, "partition_inputs_hashed") - before,
        2 * rows
    );
    assert_eq!(counter(&actual_cache, "calculations") - calculations, 3);
}

#[test]
fn initial_root_requires_same_settings_and_never_reissues_a_consumed_value() {
    let (_directory, node) = fixture(Settings::development(Some(1)).unwrap());
    let id = node.settings.genesis();
    let cache = ArithmeticCache::default();
    let calculation = capture(&node, &cache).unwrap();
    let (actual, replacement) = native_block_with_initial_root(
        &node.db,
        &node.settings,
        id,
        Some(&cache),
        Some(calculation),
    )
    .unwrap();
    assert!(replacement.is_none());
    assert_eq!(
        block_identity(actual),
        block_identity(
            reference::checked_block(&node.db, &node.settings, id, Some(&cache)).unwrap()
        )
    );
    assert_eq!(counter(&cache, "operation_initial_root_reuses"), 1);

    for component in 0..7 {
        let mut other = node.settings.clone();
        match component {
            0 => {}
            1 => other.app.network[0] ^= 1,
            2 => other.app.parameters[0] ^= 1,
            3 => other.genesis[0] ^= 1,
            4 => other.app.fees[0] ^= 1,
            5 => {
                other.initial.insert("different-initial".into(), json!(1));
            }
            _ => {
                other.initial.insert("invalid-initial".into(), json!(-0.0));
            }
        }
        let cache = ArithmeticCache::default();
        let calculation = capture(&node, &cache).unwrap();
        let actual =
            native_block_with_initial_root(&node.db, &other, id, Some(&cache), Some(calculation))
                .map(|(block, replacement)| {
                    assert!(replacement.is_none());
                    block_identity(block)
                });
        let original =
            reference::checked_block(&node.db, &other, id, Some(&ArithmeticCache::default()))
                .map(block_identity);
        assert_eq!(receipt(actual), receipt(original), "component {component}");
        assert_eq!(counter(&cache, "operation_initial_root_reuses"), 0);
    }

    let cache = ArithmeticCache::default();
    let calculation = capture(&node, &cache).unwrap();
    let (actual, replacement) =
        native_block_with_initial_root(&node.db, &node.settings, id, None, Some(calculation))
            .unwrap();
    assert!(replacement.is_none());
    assert_eq!(
        block_identity(actual),
        block_identity(reference::checked_block(&node.db, &node.settings, id, None).unwrap())
    );
    assert_eq!(counter(&cache, "operation_initial_root_reuses"), 0);
}

#[test]
fn first_record_failures_preserve_root_and_progress_error_order_without_a_result() {
    let (_directory, node) = fixture(Settings::development(Some(1)).unwrap());
    let id = node.settings.genesis();
    let mut record = load_observed(&node.db, id, None).unwrap();
    record.delta_root[0] ^= 1;
    for cancel in [false, true] {
        let actual_cache = ArithmeticCache::default();
        let original_cache = ArithmeticCache::default();
        let mut actual_calls = 0usize;
        let mut original_calls = 0usize;
        let actual = verify_record_with_initial_root(
            &node.db,
            &node.settings,
            &record,
            &mut || {
                actual_calls += 1;
                if cancel {
                    Err(Error::new(ErrorCode::FrameDeadline))
                } else {
                    Ok(())
                }
            },
            Some(&actual_cache),
            None,
        )
        .map(|value| {
            assert!(
                value.is_none(),
                "an invalid first record cannot publish arithmetic"
            );
        });
        let original = reference::checked_record(
            &node.db,
            &node.settings,
            &record,
            &mut || {
                original_calls += 1;
                if cancel {
                    Err(Error::new(ErrorCode::FrameDeadline))
                } else {
                    Ok(())
                }
            },
            Some(&original_cache),
        );
        assert!(actual.is_err());
        if cancel {
            assert!(actual.as_ref().err().unwrap().is(ErrorCode::FrameDeadline));
            assert_eq!(actual_calls, 1);
        } else {
            assert_eq!(
                actual.as_ref().err().unwrap().to_string(),
                "NATIVE_STATE_BINDING"
            );
        }
        assert_eq!(receipt(actual), receipt(original));
        assert_eq!(actual_calls, original_calls);
        assert_eq!(counter(&actual_cache, "operation_initial_root_reuses"), 0);
    }

    let mut invalid = node.settings.clone();
    invalid
        .initial
        .insert("late-invalid-initial".into(), json!(-0.0));
    let record = load_observed(&node.db, id, None).unwrap();
    for height in [0, 1] {
        node.db
            .execute(
                "UPDATE blocks SET height=? WHERE id=?",
                params![height, id.as_slice()],
            )
            .unwrap();
        let cache = ArithmeticCache::default();
        let mut actual_calls = 0usize;
        let mut original_calls = 0usize;
        let actual = verify_record_with_initial_root(
            &node.db,
            &invalid,
            &record,
            &mut || {
                actual_calls += 1;
                Ok(())
            },
            Some(&cache),
            None,
        )
        .map(|_| ());
        let original = reference::checked_record(
            &node.db,
            &invalid,
            &record,
            &mut || {
                original_calls += 1;
                Ok(())
            },
            Some(&ArithmeticCache::default()),
        );
        assert!(actual.is_err());
        if height == 1 {
            assert_eq!(
                actual.as_ref().err().unwrap().to_string(),
                "NATIVE_STATE_GENESIS"
            );
            assert_eq!(counter(&cache, "calculations"), 0);
        }
        assert_eq!(receipt(actual), receipt(original));
        assert_eq!(actual_calls, 0);
        assert_eq!(actual_calls, original_calls);
        assert_eq!(counter(&cache, "operation_initial_root_reuses"), 0);
    }
    node.db
        .execute("UPDATE blocks SET height=0 WHERE id=?", [id.as_slice()])
        .unwrap();
}

#[test]
fn history_rereads_callback_changed_sql_fields_types_records_and_snapshot_bytes() {
    let (directory, node) = fixture(Settings::development(Some(1)).unwrap());
    let foreign = Connection::open(directory.path().join("native.sqlite")).unwrap();
    let id = node.settings.genesis();
    let checkpoint = second_record_checkpoint(&node);
    let mut wrong_root: Vec<u8> = foreign
        .query_row(
            "SELECT state_root FROM blocks WHERE id=?",
            [id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    wrong_root[0] ^= 1;
    let mut noncanonical: Vec<u8> = foreign
        .query_row(
            "SELECT state FROM snapshots WHERE block=?",
            [id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    noncanonical.push(b' ');
    let mut changed = node.settings.initial.clone();
    changed.insert("different-snapshot".into(), json!(true));
    let cases = [
        (
            "SELECT data FROM native_state_commitments WHERE block=?",
            "UPDATE native_state_commitments SET data=? WHERE block=?",
            SqlValue::Blob(b"{".to_vec()),
            checkpoint,
            0,
        ),
        (
            "SELECT state_root FROM blocks WHERE id=?",
            "UPDATE blocks SET state_root=? WHERE id=?",
            SqlValue::Blob(wrong_root),
            checkpoint,
            1,
        ),
        (
            "SELECT state_root FROM blocks WHERE id=?",
            "UPDATE blocks SET state_root=? WHERE id=?",
            SqlValue::Text("wrong-type".into()),
            checkpoint,
            0,
        ),
        (
            "SELECT height FROM blocks WHERE id=?",
            "UPDATE blocks SET height=? WHERE id=?",
            SqlValue::Integer(1),
            checkpoint,
            0,
        ),
        (
            "SELECT packet FROM blocks WHERE id=?",
            "UPDATE blocks SET packet=? WHERE id=?",
            SqlValue::Blob(vec![0]),
            checkpoint,
            0,
        ),
        (
            "SELECT chainwork FROM blocks WHERE id=?",
            "UPDATE blocks SET chainwork=? WHERE id=?",
            SqlValue::Blob(vec![1; 64]),
            checkpoint,
            0,
        ),
        (
            "SELECT state FROM snapshots WHERE block=?",
            "UPDATE snapshots SET state=? WHERE block=?",
            SqlValue::Blob(noncanonical),
            checkpoint - 1,
            0,
        ),
        (
            "SELECT state FROM snapshots WHERE block=?",
            "UPDATE snapshots SET state=? WHERE block=?",
            SqlValue::Text("{}".into()),
            checkpoint - 1,
            0,
        ),
        (
            "SELECT state FROM snapshots WHERE block=?",
            "UPDATE snapshots SET state=? WHERE block=?",
            SqlValue::Blob(canonical(&changed).unwrap()),
            checkpoint - 1,
            0,
        ),
    ];
    for (select, update, replacement, at, reused) in cases {
        let original: SqlValue = foreign
            .query_row(select, [id.as_slice()], |row| row.get(0))
            .unwrap();
        let mut expected = None;
        for reference in [true, false] {
            let cache = ArithmeticCache::default();
            let mut calls = 0usize;
            let result = history(
                reference,
                &node,
                &mut || {
                    calls += 1;
                    if calls == at {
                        foreign
                            .execute(update, params![&replacement, id.as_slice()])
                            .unwrap();
                    }
                    Ok(())
                },
                Some(&cache),
            );
            assert!(result.is_err(), "{update}");
            assert_eq!(calls, at, "{update}");
            assert_eq!(
                counter(&cache, "operation_initial_root_reuses"),
                if reference { 0 } else { reused },
                "{update}"
            );
            let observed = (receipt(result), calls);
            if reference {
                expected = Some(observed);
            } else {
                assert_eq!(&observed, expected.as_ref().unwrap(), "{update}");
            }
            foreign
                .execute(update, params![&original, id.as_slice()])
                .unwrap();
            history(reference, &node, &mut || Ok(()), Some(&cache)).unwrap();
        }
    }
}

#[test]
fn initial_root_does_not_replace_actual_snapshot_root_account_or_conservation_checks() {
    let (_directory, node) = fixture(Settings::development(Some(1)).unwrap());
    let mut changed = node.settings.initial.clone();
    changed.insert("different-snapshot".into(), json!(true));
    let mut malformed_account = node.settings.initial.clone();
    malformed_account.insert("account:malformed".into(), json!({"balance":0}));
    let mut conservation = node.settings.initial.clone();
    let issued = complete(&node.settings, &node.settings.initial)
        .unwrap()
        .issued;
    conservation.insert("meta:issued".into(), json!(issued + 1));
    let mut grammar = node.settings.initial.clone();
    grammar.insert("a".repeat(161), json!(0));
    grammar.insert("zz-late-invalid".into(), json!(-0.0));
    for actual_state in [&changed, &malformed_account, &conservation, &grammar] {
        let cache = ArithmeticCache::default();
        let calculation = capture(&node, &cache).unwrap();
        let mut calls = 0usize;
        let mut original_calls = 0usize;
        let actual = verify_state_with_readback_and_calculations(
            &node.db,
            &node.settings,
            node.settings.genesis(),
            actual_state,
            &mut || {
                calls += 1;
                Ok(())
            },
            Some(&cache),
            None,
            None,
            Some(calculation),
        );
        let original = reference::verify_state_with_readback_and_calculation(
            &node.db,
            &node.settings,
            node.settings.genesis(),
            actual_state,
            &mut || {
                original_calls += 1;
                Ok(())
            },
            Some(&ArithmeticCache::default()),
            None,
            None,
        );
        assert!(actual.is_err());
        assert_eq!(receipt(actual), receipt(original));
        assert_eq!(calls, original_calls);
        assert_eq!(counter(&cache, "operation_initial_root_reuses"), 1);
        assert_eq!(counter(&cache, "operation_full_root_reuses"), 0);
    }
}

#[test]
fn history_still_checks_complete_commitment_and_actual_account_nodes() {
    let (directory, node) = fixture(Settings::development(Some(1)).unwrap());
    let foreign = Connection::open(directory.path().join("native.sqlite")).unwrap();
    let id = node.settings.genesis();
    let original_record: Vec<u8> = foreign
        .query_row(
            "SELECT data FROM native_state_commitments WHERE block=?",
            [id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let mut record = load_observed(&node.db, id, None).unwrap();
    record.state.issued += 1;
    save(&node.db, &mut record).unwrap();
    let mut expected = None;
    for reference in [true, false] {
        let cache = ArithmeticCache::default();
        let mut calls = 0usize;
        let result = history(
            reference,
            &node,
            &mut || {
                calls += 1;
                Ok(())
            },
            Some(&cache),
        );
        assert_eq!(
            result.as_ref().err().unwrap().to_string(),
            "NATIVE_STATE_ROOT"
        );
        assert_eq!(
            counter(&cache, "operation_initial_root_reuses"),
            u64::from(!reference)
        );
        let observed = (receipt(result), calls);
        if reference {
            expected = Some(observed);
        } else {
            assert_eq!(&observed, expected.as_ref().unwrap());
        }
    }
    foreign
        .execute(
            "UPDATE native_state_commitments SET data=? WHERE block=?",
            params![original_record, id.as_slice()],
        )
        .unwrap();

    let key = load_observed(&node.db, id, None)
        .unwrap()
        .accounts
        .node
        .expect("development genesis has an actual account root");
    let original_node: Vec<u8> = foreign
        .query_row(
            "SELECT data FROM archive_nodes WHERE id=?",
            [key.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    foreign
        .execute(
            "UPDATE archive_nodes SET data=? WHERE id=?",
            params![b"{".as_slice(), key.as_slice()],
        )
        .unwrap();
    let mut expected = None;
    for reference in [true, false] {
        let cache = ArithmeticCache::default();
        let mut calls = 0usize;
        let result = history(
            reference,
            &node,
            &mut || {
                calls += 1;
                Ok(())
            },
            Some(&cache),
        );
        assert!(result.is_err());
        assert_eq!(
            counter(&cache, "operation_initial_root_reuses"),
            u64::from(!reference)
        );
        assert_eq!(stage_calls(&cache)["account_graph"], 1);
        let observed = (receipt(result), calls);
        if reference {
            expected = Some(observed);
        } else {
            assert_eq!(&observed, expected.as_ref().unwrap());
        }
    }
    foreign
        .execute(
            "UPDATE archive_nodes SET data=? WHERE id=?",
            params![original_node, key.as_slice()],
        )
        .unwrap();
    history(
        false,
        &node,
        &mut || Ok(()),
        Some(&ArithmeticCache::default()),
    )
    .unwrap();
}

#[test]
fn history_cancellation_keeps_every_original_checkpoint_and_discards_unused_roots() {
    let (directory, node) = fixture(Settings::development(Some(1)).unwrap());
    let mut total = 0usize;
    history(
        true,
        &node,
        &mut || {
            total += 1;
            Ok(())
        },
        Some(&ArithmeticCache::default()),
    )
    .unwrap();
    let entry = second_record_checkpoint(&node);
    assert!(total > entry);
    for cut in 1..=total {
        let mut expected = None;
        for reference in [true, false] {
            let cache = ArithmeticCache::default();
            let mut calls = 0usize;
            let result = history(
                reference,
                &node,
                &mut || {
                    calls += 1;
                    if calls == cut {
                        Err(Error::new(ErrorCode::FrameDeadline))
                    } else {
                        Ok(())
                    }
                },
                Some(&cache),
            );
            assert!(result.as_ref().err().unwrap().is(ErrorCode::FrameDeadline));
            assert_eq!(calls, cut);
            let uses = if !reference && cut > entry { 1 } else { 0 };
            assert_eq!(counter(&cache, "operation_initial_root_reuses"), uses);
            let observed = (receipt(result), calls);
            if reference {
                expected = Some(observed);
            } else {
                assert_eq!(&observed, expected.as_ref().unwrap());
                history(false, &node, &mut || Ok(()), Some(&cache)).unwrap();
                assert_eq!(counter(&cache, "operation_initial_root_reuses"), uses + 1);
            }
        }
    }

    let foreign = Connection::open(directory.path().join("native.sqlite")).unwrap();
    let id = node.settings.genesis();
    let mut expected = None;
    for reference in [true, false] {
        let cache = ArithmeticCache::default();
        let mut calls = 0usize;
        let result = history(
            reference,
            &node,
            &mut || {
                calls += 1;
                if calls == entry {
                    foreign
                        .execute("UPDATE blocks SET height=1 WHERE id=?", [id.as_slice()])
                        .unwrap();
                    Err(Error::new(ErrorCode::FrameDeadline))
                } else {
                    Ok(())
                }
            },
            Some(&cache),
        );
        assert!(result.as_ref().err().unwrap().is(ErrorCode::FrameDeadline));
        assert_eq!(calls, entry);
        assert_eq!(counter(&cache, "operation_initial_root_reuses"), 0);
        let observed = (receipt(result), calls);
        if reference {
            expected = Some(observed);
        } else {
            assert_eq!(&observed, expected.as_ref().unwrap());
        }
        foreign
            .execute("UPDATE blocks SET height=0 WHERE id=?", [id.as_slice()])
            .unwrap();
    }
}
