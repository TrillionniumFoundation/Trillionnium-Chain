//! Actual SQLite codec/reference controls, not held-FD campaign qualification.
//! The normal AuthV1 fixture retains its original full-JSON snapshots. These
//! tests exercise new shared records against real admitted native COW nodes;
//! the unchanged native-IO campaign must separately qualify the factory route.
use super::*;
use crate::store::Node;
use crate::{development_public, Packet};
use serde_json::json;

struct Fixture {
    node: Node,
    directory: tempfile::TempDir,
    block: Hash,
    state: State,
}
fn packet(node: &Node, parent: Hash, miner: u64, time: u64) -> Packet {
    node.make_consensus_maintenance(
        parent,
        vec![],
        development_public(miner).unwrap(),
        time,
        4096,
    )
    .unwrap()
}
fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let mut node = Node::open_with_authenticated_state(directory.path(), settings, 1).unwrap();
    let packet = packet(&node, node.settings.genesis(), 0, 11);
    let block = node.admit(&packet, 100_000).unwrap();
    let state = node.state_at(block).unwrap();
    node.db.execute_batch(DDL).unwrap();
    save(
        &node.db,
        &node.settings,
        block,
        &state,
        &mut || Ok(()),
        &node.authenticated_arithmetic,
    )
    .unwrap();
    Fixture {
        node,
        directory,
        block,
        state,
    }
}
fn read(f: &Fixture) -> Result<Option<State>> {
    in_read_snapshot(&f.node.db, || {
        load(
            &f.node.db,
            &f.node.settings,
            f.block,
            &mut || Ok(()),
            &f.node.authenticated_arithmetic,
        )
    })
}

#[test]
fn shared_records_materialize_complete_state_and_never_store_account_values_twice() {
    let f = fixture();
    assert_eq!(read(&f).unwrap(), Some(f.state.clone()));
    let bytes: Vec<u8> = f
        .node
        .db
        .query_row(
            "SELECT data FROM native_io_shared_snapshots WHERE block=?",
            [f.block.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let stored: Snapshot = serde_json::from_slice(&bytes).unwrap();
    assert!(stored
        .working
        .keys()
        .all(|key| !key.starts_with("account:")));
    assert!(f.state.keys().any(|key| key.starts_with("account:")));
    f.node
        .db
        .execute("DELETE FROM native_io_shared_snapshots", [])
        .unwrap();
    assert_eq!(read(&f).unwrap(), None);
    assert_eq!(f.node.state_at(f.block).unwrap(), f.state);
}

#[test]
fn shared_records_reject_resealed_wrong_context_partition_and_raw_codec_damage() {
    let f = fixture();
    let bytes: Vec<u8> = f
        .node
        .db
        .query_row(
            "SELECT data FROM native_io_shared_snapshots WHERE block=?",
            [f.block.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    for which in 0..8 {
        f.node.db.execute_batch("SAVEPOINT corrupt_shared").unwrap();
        let mut value: Snapshot = serde_json::from_slice(&bytes).unwrap();
        match which {
            0 => value.block = [7; 32],
            1 => value.native_commitment = [8; 32],
            2 => {
                value
                    .working
                    .insert("unexpected-working-key".into(), json!(1));
            }
            3 => {
                value.working.insert(
                    format!("account:{}", hex::encode([1; 32])),
                    json!({"balance":0,"nonce":0}),
                );
            }
            4 => value.schema = "foreign-format".into(),
            5..=7 => {}
            _ => unreachable!(),
        }
        value.id = value.digest(&f.node.settings).unwrap();
        let bad = match which {
            5 => [bytes.clone(), b" ".to_vec()].concat(),
            6 => bytes[..bytes.len() - 1].to_vec(),
            7 => {
                let mut value = serde_json::to_value(&value).unwrap();
                value["foreign-field"] = json!(1);
                canonical(&value).unwrap()
            }
            _ => canonical(&value).unwrap(),
        };
        f.node
            .db
            .execute("UPDATE native_io_shared_snapshots SET data=?", [bad])
            .unwrap();
        assert!(read(&f).unwrap_err().requires_owner_stop(), "case {which}");
        f.node
            .db
            .execute_batch("ROLLBACK TO corrupt_shared; RELEASE corrupt_shared")
            .unwrap();
        assert_eq!(read(&f).unwrap(), Some(f.state.clone()));
    }
    f.node
        .db
        .execute_batch(
            "SAVEPOINT wrong_type; UPDATE native_io_shared_snapshots SET data=CAST(data AS TEXT)",
        )
        .unwrap();
    assert!(read(&f).unwrap_err().requires_owner_stop());
    f.node
        .db
        .execute_batch("ROLLBACK TO wrong_type; RELEASE wrong_type")
        .unwrap();
    let record = native_authenticated::load(&f.node.db, f.block).unwrap();
    f.node.db.execute_batch("SAVEPOINT missing_node").unwrap();
    f.node
        .db
        .execute(
            "DELETE FROM archive_nodes WHERE id=?",
            [record.accounts.node.unwrap().as_slice()],
        )
        .unwrap();
    assert!(read(&f).unwrap_err().requires_owner_stop());
    f.node
        .db
        .execute_batch("ROLLBACK TO missing_node; RELEASE missing_node")
        .unwrap();
    assert_eq!(read(&f).unwrap(), Some(f.state.clone()));
}

#[test]
fn shared_insert_and_late_storage_faults_roll_back_the_same_transaction() {
    for trigger in [
        "CREATE TEMP TRIGGER shared_fault BEFORE INSERT ON native_io_shared_snapshots BEGIN SELECT RAISE(IGNORE); END;",
        "CREATE TEMP TRIGGER shared_fault AFTER INSERT ON native_io_shared_snapshots BEGIN UPDATE native_io_shared_snapshots SET data=X'7b7d' WHERE block=NEW.block; END;",
        "CREATE TEMP TRIGGER shared_fault AFTER INSERT ON native_io_shared_snapshots BEGIN DELETE FROM archive_nodes; END;",
        "CREATE TEMP TRIGGER shared_fault AFTER INSERT ON native_io_shared_snapshots BEGIN DELETE FROM snapshots; END;",
    ] {
        let f = fixture();
        f.node
            .db
            .execute("DELETE FROM native_io_shared_snapshots", [])
            .unwrap();
        let before_nodes: u64 = f
            .node
            .db
            .query_row("SELECT COUNT(*) FROM archive_nodes", [], |r| r.get(0))
            .unwrap();
        f.node.db.execute_batch(trigger).unwrap();
        let write = f.node.db.unchecked_transaction().unwrap();
        assert!(
            save(
                &write,
                &f.node.settings,
                f.block,
                &f.state,
                &mut || Ok(()),
                &f.node.authenticated_arithmetic
            )
            .is_err()
        );
        write.rollback().unwrap();
        assert_eq!(
            f.node
                .db
                .query_row::<u64, _, _>("SELECT COUNT(*) FROM archive_nodes", [], |r| r.get(0))
                .unwrap(),
            before_nodes
        );
        assert_eq!(
            f.node
                .db
                .query_row::<u64, _, _>(
                    "SELECT COUNT(*) FROM native_io_shared_snapshots",
                    [],
                    |r| r.get(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(f.node.state_at(f.block).unwrap(), f.state);
    }
}

#[test]
fn shared_fork_records_reconstruct_after_all_codec_connections_close() {
    let mut f = fixture();
    let fork = packet(&f.node, f.node.settings.genesis(), 1, 12);
    let fork_id = f.node.admit(&fork, 100_000).unwrap();
    let fork_state = f.node.state_at(fork_id).unwrap();
    save(
        &f.node.db,
        &f.node.settings,
        fork_id,
        &fork_state,
        &mut || Ok(()),
        &f.node.authenticated_arithmetic,
    )
    .unwrap();
    assert_eq!(read(&f).unwrap(), Some(f.state.clone()));
    let settings = f.node.settings.clone();
    let original = f.block;
    let original_state = f.state.clone();
    drop(f.node);
    let db = Connection::open(f.directory.path().join("native.sqlite")).unwrap();
    let cache = native_authenticated::ArithmeticCache::default();
    for (id, expected) in [(original, original_state), (fork_id, fork_state)] {
        assert_eq!(
            in_read_snapshot(&db, || load(&db, &settings, id, &mut || Ok(()), &cache)).unwrap(),
            Some(expected)
        );
    }
}

#[test]
fn shared_final_record_mutation_is_not_a_successful_state_read() {
    let f = fixture();
    let mut calls = 0usize;
    load(
        &f.node.db,
        &f.node.settings,
        f.block,
        &mut || {
            calls += 1;
            Ok(())
        },
        &f.node.authenticated_arithmetic,
    )
    .unwrap();
    let mut index = 0usize;
    let error = load(
        &f.node.db,
        &f.node.settings,
        f.block,
        &mut || {
            index += 1;
            if index == calls {
                f.node
                    .db
                    .execute("UPDATE native_io_shared_snapshots SET data=X'7b7d'", [])?;
            }
            Ok(())
        },
        &f.node.authenticated_arithmetic,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_SHARED_SNAPSHOT_CHANGED");
    assert!(error.requires_owner_stop());
}

#[test]
fn shared_pruning_suppression_keeps_the_original_64_index_limit_atomic() {
    let mut f = fixture();
    let mut parent = f.block;
    f.node.activate(parent).unwrap();
    for height in 2..=64 {
        let packet = packet(&f.node, parent, 0, 1 + height * 10);
        parent = f.node.admit(&packet, 100_000).unwrap();
        f.node.activate(parent).unwrap();
        let state = f.node.state_at(parent).unwrap();
        save(
            &f.node.db,
            &f.node.settings,
            parent,
            &state,
            &mut || Ok(()),
            &f.node.authenticated_arithmetic,
        )
        .unwrap();
    }
    let packet = packet(&f.node, parent, 0, 651);
    let id = f.node.admit(&packet, 100_000).unwrap();
    let state = f.node.state_at(id).unwrap();
    f.node.db.execute_batch("CREATE TEMP TRIGGER refuse_shared_prune BEFORE DELETE ON native_io_shared_snapshots BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    let write = f.node.db.unchecked_transaction().unwrap();
    let error = save(
        &write,
        &f.node.settings,
        id,
        &state,
        &mut || Ok(()),
        &f.node.authenticated_arithmetic,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "SNAPSHOT_LIMIT");
    assert!(error.requires_owner_stop());
    write.rollback().unwrap();
    assert_eq!(
        f.node
            .db
            .query_row::<u64, _, _>("SELECT COUNT(*) FROM native_io_shared_snapshots", [], |r| r
                .get(0))
            .unwrap(),
        64
    );
    f.node
        .db
        .execute_batch("DROP TRIGGER refuse_shared_prune")
        .unwrap();
    save(
        &f.node.db,
        &f.node.settings,
        id,
        &state,
        &mut || Ok(()),
        &f.node.authenticated_arithmetic,
    )
    .unwrap();
    assert_eq!(
        f.node
            .db
            .query_row::<u64, _, _>("SELECT COUNT(*) FROM native_io_shared_snapshots", [], |r| r
                .get(0))
            .unwrap(),
        64
    );
}

#[test]
fn shared_owner_layout_rejects_mixed_legacy_rows_and_missing_genesis() {
    let f = fixture();
    // This codec fixture deliberately includes the ordinary owner's child JSON
    // row. A real shared-format owner must reject that mixed physical layout.
    let error = check_layout(&f.node.db, &f.node.settings).unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_SHARED_MIXED_LAYOUT");
    assert!(error.requires_owner_stop());
    f.node
        .db
        .execute(
            "DELETE FROM snapshots WHERE block!=?",
            [f.node.settings.genesis().as_slice()],
        )
        .unwrap();
    check_layout(&f.node.db, &f.node.settings).unwrap();
    f.node.db.execute("DELETE FROM snapshots", []).unwrap();
    assert!(check_layout(&f.node.db, &f.node.settings)
        .unwrap_err()
        .requires_owner_stop());
}

#[test]
fn shared_final_graph_mutation_in_same_transaction_never_returns_old_materialization() {
    for corrupt in [false, true] {
        let f = fixture();
        let native = native_authenticated::load(&f.node.db, f.block).unwrap();
        let root = native.accounts.node.unwrap();
        let before = encoded(&f.node.db, f.block).unwrap();
        let write = f.node.db.unchecked_transaction().unwrap();
        let mut calls = 0usize;
        load(
            &write,
            &f.node.settings,
            f.block,
            &mut || {
                calls += 1;
                Ok(())
            },
            &f.node.authenticated_arithmetic,
        )
        .unwrap();
        let mut index = 0usize;
        let error = load(
            &write,
            &f.node.settings,
            f.block,
            &mut || {
                index += 1;
                if index == calls {
                    if corrupt {
                        f.node.db.execute(
                            "UPDATE archive_nodes SET data=X'7b7d' WHERE id=?",
                            [root.as_slice()],
                        )?;
                    } else {
                        f.node
                            .db
                            .execute("DELETE FROM archive_nodes WHERE id=?", [root.as_slice()])?;
                    }
                }
                Ok(())
            },
            &f.node.authenticated_arithmetic,
        )
        .unwrap_err();
        assert!(error.requires_owner_stop());
        assert_eq!(encoded(&f.node.db, f.block).unwrap(), before);
        assert_eq!(
            native_authenticated::load(&f.node.db, f.block).unwrap(),
            native
        );
        write.rollback().unwrap();
        assert_eq!(read(&f).unwrap(), Some(f.state.clone()));
    }
}

/// Explicit native-ABI supplement. Ignore/Unsupported is NEVER qualification:
/// the qualified owner must actually execute this exact test under original
/// resource limits; the original campaign/fixture remains a separate gate.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires actual qualified native-IO owner; NOT_RUN/Unsupported is not PASS"]
fn actual_shared_factory_active_row_graph_callbacks_and_same_lease_cold_read() {
    let directory = tempfile::tempdir().unwrap();
    let owner = trnm_sqlite_io_boundary::NativeIoOwner::create(std::array::from_fn(|i| {
        directory.path().join(format!("root-{i}"))
    }))
    .unwrap();
    let lease = owner.lease(0).unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let mut node =
        Node::open_with_authenticated_state_and_native_io(lease.clone(), settings.clone(), 1)
            .unwrap();
    assert_eq!(node.storage_layout, Layout::SharedAccountsV1);
    assert_eq!(
        node.db
            .query_row::<i64, _, _>("PRAGMA page_size", [], |r| r.get(0))
            .unwrap(),
        4096
    );
    assert_eq!(
        node.db
            .query_row::<String, _, _>("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap(),
        "wal"
    );
    let work = packet(&node, settings.genesis(), 0, 11);
    let id = node.admit(&work, 100_000).unwrap();
    node.activate(id).unwrap();
    let expected = node.read_active().unwrap();
    node.db
        .execute_batch("SAVEPOINT actual_bad_active")
        .unwrap();
    node.db
        .execute(
            "UPDATE native_io_shared_snapshots SET data=X'7b7d' WHERE block=?",
            [id.as_slice()],
        )
        .unwrap();
    assert!(node.read_active().unwrap_err().requires_owner_stop());
    assert!(node.state_at(id).unwrap_err().requires_owner_stop());
    node.db
        .execute_batch("ROLLBACK TO actual_bad_active; RELEASE actual_bad_active")
        .unwrap();
    assert_eq!(node.read_active().unwrap(), expected);
    let native = native_authenticated::load(&node.db, id).unwrap();
    for corrupt in [false, true] {
        let write = node.db.unchecked_transaction().unwrap();
        let mut calls = 0usize;
        node.read_active_with_progress(&mut || {
            calls += 1;
            Ok(())
        })
        .unwrap();
        let mut index = 0usize;
        let error = node
            .read_active_with_progress(&mut || {
                index += 1;
                if index == calls {
                    let root = native.accounts.node.unwrap();
                    if corrupt {
                        node.db.execute(
                            "UPDATE archive_nodes SET data=X'7b7d' WHERE id=?",
                            [root.as_slice()],
                        )?;
                    } else {
                        node.db
                            .execute("DELETE FROM archive_nodes WHERE id=?", [root.as_slice()])?;
                    }
                }
                Ok(())
            })
            .unwrap_err();
        assert!(error.requires_owner_stop());
        write.rollback().unwrap();
        assert_eq!(node.read_active().unwrap(), expected);
    }
    let second = packet(&node, id, 0, 21);
    let historical = node.admit(&second, 100_000).unwrap();
    let historical_state = node.state_at(historical).unwrap();
    node.db
        .execute_batch("SAVEPOINT actual_bad_historical")
        .unwrap();
    node.db
        .execute(
            "UPDATE native_io_shared_snapshots SET data=X'7b7d' WHERE block=?",
            [historical.as_slice()],
        )
        .unwrap();
    assert!(node.state_at(historical).unwrap_err().requires_owner_stop());
    node.db
        .execute_batch("ROLLBACK TO actual_bad_historical; RELEASE actual_bad_historical")
        .unwrap();
    assert_eq!(node.state_at(historical).unwrap(), historical_state);
    let historical_record = native_authenticated::load(&node.db, historical).unwrap();
    let write = node.db.unchecked_transaction().unwrap();
    let mut calls = 0usize;
    node.state_at_with_progress(historical, &mut || {
        calls += 1;
        Ok(())
    })
    .unwrap();
    let mut index = 0usize;
    let error = node
        .state_at_with_progress(historical, &mut || {
            index += 1;
            if index == calls {
                node.db.execute(
                    "DELETE FROM archive_nodes WHERE id=?",
                    [historical_record.accounts.node.unwrap().as_slice()],
                )?;
            }
            Ok(())
        })
        .unwrap_err();
    assert!(error.requires_owner_stop());
    write.rollback().unwrap();
    assert_eq!(node.state_at(historical).unwrap(), historical_state);
    node.activate(historical).unwrap();
    let expected = node.read_active().unwrap();
    node.db
        .execute(
            "DELETE FROM native_io_shared_snapshots WHERE block=?",
            [historical.as_slice()],
        )
        .unwrap();
    assert_eq!(node.read_active().unwrap(), expected);
    assert_eq!(node.state_at(historical).unwrap(), expected.2);
    drop(node);
    let reopened =
        Node::open_with_authenticated_state_and_native_io(lease.clone(), settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), expected);
    drop(reopened);
    let terminal = lease.receipt().unwrap();
    assert!(!terminal.failed && terminal.lifecycle_complete);
    assert!(terminal
        .objects
        .iter()
        .all(|r| r.handles == 0 && r.pending_opens == 0 && r.shm_references == 0));
}

#[test]
fn shared_same_byte_text_key_is_damage_not_optional_absence() {
    let f = fixture();
    let write = f.node.db.unchecked_transaction().unwrap();
    assert_eq!(
        write.execute(
            "UPDATE main.native_io_shared_snapshots SET block=CAST(block AS TEXT) WHERE block=?",
            [f.block.as_slice()],
        ).unwrap(),
        1
    );
    let unchanged: Vec<u8> = write
        .query_row(
            "SELECT CAST(block AS BLOB) FROM main.native_io_shared_snapshots",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(unchanged.as_slice(), f.block.as_slice());
    let error = read(&f).unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_SHARED_TYPED_RECORD");
    assert!(error.requires_owner_stop());
    write.rollback().unwrap();
    assert_eq!(read(&f).unwrap(), Some(f.state));
}

/// R3 negative controls use the actual production factory and public reads.
/// This opt-in supplement has no successful Unsupported/NOT_RUN path and never
/// replaces the original native caller, resource limits or independent reader.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires actual qualified native-IO owner; NOT_RUN/Unsupported is not PASS"]
fn actual_shared_factory_wrong_key_and_authority_shadow_are_owner_fatal() {
    let directory = tempfile::tempdir().unwrap();
    let owner = trnm_sqlite_io_boundary::NativeIoOwner::create(std::array::from_fn(|i| {
        directory.path().join(format!("root-{i}"))
    }))
    .unwrap();
    let lease = owner.lease(0).unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let mut node =
        Node::open_with_authenticated_state_and_native_io(lease.clone(), settings.clone(), 1)
            .unwrap();
    let first = packet(&node, settings.genesis(), 0, 11);
    let active = node.admit(&first, 100_000).unwrap();
    node.activate(active).unwrap();
    let second = packet(&node, active, 0, 21);
    let historical = node.admit(&second, 100_000).unwrap();
    let expected = node.read_active().unwrap();
    let historical_state = node.state_at(historical).unwrap();
    for block in [active, historical] {
        let write = node.db.unchecked_transaction().unwrap();
        assert_eq!(write.execute(
            "UPDATE main.native_io_shared_snapshots SET block=CAST(block AS TEXT) WHERE block=?",
            [block.as_slice()],
        ).unwrap(), 1);
        let unchanged: Vec<u8> = write.query_row(
            "SELECT CAST(block AS BLOB) FROM main.native_io_shared_snapshots WHERE typeof(block)='text'",
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(unchanged.as_slice(), block.as_slice());
        assert!(node.read_active().unwrap_err().requires_owner_stop());
        assert!(node.state_at(block).unwrap_err().requires_owner_stop());
        write.rollback().unwrap();
        assert_eq!(node.read_active().unwrap(), expected);
        assert_eq!(node.state_at(historical).unwrap(), historical_state);
    }
    for block in [active, historical] {
        let write = node.db.unchecked_transaction().unwrap();
        let mut calls = 0usize;
        node.state_at_with_progress(block, &mut || {
            calls += 1;
            Ok(())
        })
        .unwrap();
        let mut index = 0usize;
        let error = node.state_at_with_progress(block, &mut || {
            index += 1;
            if index == calls {
                node.db.execute(
                    "UPDATE main.native_io_shared_snapshots SET block=CAST(block AS TEXT) WHERE block=?",
                    [block.as_slice()],
                )?;
            }
            Ok(())
        }).unwrap_err();
        assert!(error.requires_owner_stop());
        write.rollback().unwrap();
        assert_eq!(node.read_active().unwrap(), expected);
    }
    // Keep unrelated TEMP workspace available. The explicit memory setting is
    // only this supplemental control's setup, never a campaign/profile change.
    node.db.execute_batch("PRAGMA temp_store=MEMORY; CREATE TEMP TABLE unrelated_workspace(value INTEGER); INSERT INTO unrelated_workspace VALUES(1);").unwrap();
    assert_eq!(node.read_active().unwrap(), expected);
    assert_eq!(node.state_at(historical).unwrap(), historical_state);
    for table in [
        "native_io_shared_snapshots",
        "archive_nodes",
        "native_state_commitments",
    ] {
        for historical_read in [false, true] {
            let block = if historical_read { historical } else { active };
            let record = native_authenticated::load(&node.db, block).unwrap();
            let write = node.db.unchecked_transaction().unwrap();
            let mut calls = 0usize;
            if historical_read {
                node.state_at_with_progress(block, &mut || {
                    calls += 1;
                    Ok(())
                })
                .unwrap();
            } else {
                node.read_active_with_progress(&mut || {
                    calls += 1;
                    Ok(())
                })
                .unwrap();
            }
            let mut index = 0usize;
            let mut progress = || -> Result<()> {
                index += 1;
                if index == calls {
                    node.db.execute_batch(&format!(
                        "CREATE TEMP TABLE {} AS SELECT * FROM main.{table}",
                        table.to_ascii_uppercase(),
                    ))?;
                    match table {
                        "archive_nodes" => {
                            node.db.execute(
                                "DELETE FROM main.archive_nodes WHERE id=?",
                                [record.accounts.node.unwrap().as_slice()],
                            )?;
                        }
                        "native_state_commitments" => {
                            node.db.execute(
                                "UPDATE main.native_state_commitments SET data=X'7b7d' WHERE block=?",
                                [block.as_slice()],
                            )?;
                        }
                        _ => {
                            node.db.execute(
                                "UPDATE main.native_io_shared_snapshots SET data=X'7b7d' WHERE block=?",
                                [block.as_slice()],
                            )?;
                        }
                    }
                }
                Ok(())
            };
            let error = if historical_read {
                node.state_at_with_progress(block, &mut progress)
                    .unwrap_err()
            } else {
                node.read_active_with_progress(&mut progress).unwrap_err()
            };
            assert_eq!(error.to_string(), "NATIVE_SHARED_AUTHORITY_SHADOW");
            assert!(error.requires_owner_stop());
            write.rollback().unwrap();
            assert_eq!(node.read_active().unwrap(), expected);
            assert_eq!(node.state_at(historical).unwrap(), historical_state);
        }
    }
    // The original native factory authorizer rejects ATTACH/DETACH before any
    // attached-schema guard. Do not disable it to exercise that separate guard.
    for sql in [
        "ATTACH ':memory:' AS unrelated_attached",
        "DETACH unrelated_attached",
    ] {
        let denied = node.db.execute_batch(sql).unwrap_err();
        assert_eq!(
            denied.sqlite_error_code(),
            Some(rusqlite::ErrorCode::AuthorizationForStatementDenied)
        );
        assert_eq!(node.read_active().unwrap(), expected);
        assert_eq!(node.state_at(historical).unwrap(), historical_state);
    }
    node.db
        .execute_batch("DROP TABLE temp.unrelated_workspace")
        .unwrap();
    assert_eq!(node.read_active().unwrap(), expected);
    assert_eq!(node.state_at(historical).unwrap(), historical_state);
    drop(node);
    let terminal = lease.receipt().unwrap();
    assert!(!terminal.failed && terminal.lifecycle_complete);
    assert!(terminal
        .objects
        .iter()
        .all(|r| r.handles == 0 && r.pending_opens == 0 && r.shm_references == 0));
}

#[test]
fn shared_unknown_and_genesis_keys_are_damage_not_optional_absence() {
    let f = fixture();
    let unknown = hash(b"native-shared-unknown-key-negative-control-v1", &[]);
    assert_ne!(unknown, f.node.settings.genesis());
    assert_eq!(
        f.node
            .db
            .query_row::<u64, _, _>(
                "SELECT COUNT(*) FROM main.blocks WHERE id=?",
                [unknown.as_slice()],
                |r| r.get(0),
            )
            .unwrap(),
        0
    );
    let before: Vec<u8> = f
        .node
        .db
        .query_row(
            "SELECT data FROM main.native_io_shared_snapshots WHERE block=?",
            [f.block.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    for bad_key in [unknown, f.node.settings.genesis()] {
        let write = f.node.db.unchecked_transaction().unwrap();
        assert_eq!(
            write
                .execute(
                    "UPDATE main.native_io_shared_snapshots SET block=? WHERE block=?",
                    params![bad_key.as_slice(), f.block.as_slice()],
                )
                .unwrap(),
            1
        );
        assert_eq!(
            write
                .query_row::<Vec<u8>, _, _>(
                    "SELECT data FROM main.native_io_shared_snapshots WHERE block=?",
                    [bad_key.as_slice()],
                    |r| r.get(0),
                )
                .unwrap(),
            before
        );
        let error = read(&f).unwrap_err();
        assert_eq!(error.to_string(), "NATIVE_SHARED_KEY_DOMAIN");
        assert!(error.requires_owner_stop());
        write.rollback().unwrap();
        assert_eq!(read(&f).unwrap(), Some(f.state.clone()));
    }
}

#[test]
fn shared_attached_schema_guard_is_separate_from_native_authorizer() {
    // This ordinary connection intentionally has no NativeIoLease authorizer.
    // The actual-factory control above verifies that original authorizer rejects
    // ATTACH before this namespace guard can be reached.
    let db = Connection::open_in_memory().unwrap();
    check_authoritative_namespace(&db).unwrap();
    db.execute_batch("ATTACH ':memory:' AS unrelated_attached")
        .unwrap();
    let error = check_authoritative_namespace(&db).unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_SHARED_ATTACHED_SCHEMA");
    assert!(error.requires_owner_stop());
    db.execute_batch("DETACH unrelated_attached").unwrap();
    check_authoritative_namespace(&db).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires actual qualified native-IO owner; NOT_RUN/Unsupported is not PASS"]
fn actual_shared_factory_unknown_and_genesis_keys_fail_hot_and_final_public_reads() {
    let directory = tempfile::tempdir().unwrap();
    let owner = trnm_sqlite_io_boundary::NativeIoOwner::create(std::array::from_fn(|i| {
        directory.path().join(format!("root-{i}"))
    }))
    .unwrap();
    let lease = owner.lease(0).unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let mut node =
        Node::open_with_authenticated_state_and_native_io(lease.clone(), settings.clone(), 1)
            .unwrap();
    let first = packet(&node, settings.genesis(), 0, 11);
    let active = node.admit(&first, 100_000).unwrap();
    node.activate(active).unwrap();
    let second = packet(&node, active, 0, 21);
    let historical = node.admit(&second, 100_000).unwrap();
    let expected = node.read_active().unwrap();
    let historical_state = node.state_at(historical).unwrap();
    let unknown = hash(b"native-shared-unknown-key-negative-control-v1", &[]);
    assert_ne!(unknown, settings.genesis());
    assert_eq!(
        node.db
            .query_row::<u64, _, _>(
                "SELECT COUNT(*) FROM main.blocks WHERE id=?",
                [unknown.as_slice()],
                |r| r.get(0),
            )
            .unwrap(),
        0
    );
    for block in [active, historical] {
        for bad_key in [unknown, settings.genesis()] {
            let before: Vec<u8> = node
                .db
                .query_row(
                    "SELECT data FROM main.native_io_shared_snapshots WHERE block=?",
                    [block.as_slice()],
                    |r| r.get(0),
                )
                .unwrap();
            let write = node.db.unchecked_transaction().unwrap();
            assert_eq!(
                write
                    .execute(
                        "UPDATE main.native_io_shared_snapshots SET block=? WHERE block=?",
                        params![bad_key.as_slice(), block.as_slice()],
                    )
                    .unwrap(),
                1
            );
            assert_eq!(
                write
                    .query_row::<Vec<u8>, _, _>(
                        "SELECT data FROM main.native_io_shared_snapshots WHERE block=?",
                        [bad_key.as_slice()],
                        |r| r.get(0),
                    )
                    .unwrap(),
                before
            );
            assert!(node.read_active().unwrap_err().requires_owner_stop());
            assert!(node.state_at(block).unwrap_err().requires_owner_stop());
            write.rollback().unwrap();
            assert_eq!(node.read_active().unwrap(), expected);
            assert_eq!(node.state_at(historical).unwrap(), historical_state);
            let write = node.db.unchecked_transaction().unwrap();
            let mut calls = 0usize;
            if block == active {
                node.read_active_with_progress(&mut || {
                    calls += 1;
                    Ok(())
                })
                .unwrap();
            } else {
                node.state_at_with_progress(block, &mut || {
                    calls += 1;
                    Ok(())
                })
                .unwrap();
            }
            let mut index = 0usize;
            let mut progress = || -> Result<()> {
                index += 1;
                if index == calls {
                    node.db.execute(
                        "UPDATE main.native_io_shared_snapshots SET block=? WHERE block=?",
                        params![bad_key.as_slice(), block.as_slice()],
                    )?;
                }
                Ok(())
            };
            let error = if block == active {
                node.read_active_with_progress(&mut progress).unwrap_err()
            } else {
                node.state_at_with_progress(block, &mut progress)
                    .unwrap_err()
            };
            assert_eq!(error.to_string(), "NATIVE_SHARED_KEY_DOMAIN");
            assert!(error.requires_owner_stop());
            write.rollback().unwrap();
            assert_eq!(node.read_active().unwrap(), expected);
            assert_eq!(node.state_at(historical).unwrap(), historical_state);
        }
    }
    known_pruned_key_public_checks(&mut node, active, historical, &expected, &historical_state);
    drop(node);
    let terminal = lease.receipt().unwrap();
    assert!(!terminal.failed && terminal.lifecycle_complete);
    assert!(terminal
        .objects
        .iter()
        .all(|r| r.handles == 0 && r.pending_opens == 0 && r.shm_references == 0));
}

fn add_then_prune_codec_fork(f: &mut Fixture) -> (Hash, State) {
    let fork = packet(&f.node, f.node.settings.genesis(), 1, 12);
    let id = f.node.admit(&fork, 100_000).unwrap();
    let state = f.node.state_at(id).unwrap();
    save(
        &f.node.db,
        &f.node.settings,
        id,
        &state,
        &mut || Ok(()),
        &f.node.authenticated_arithmetic,
    )
    .unwrap();
    assert_eq!(
        f.node
            .db
            .execute(
                "DELETE FROM main.native_io_shared_snapshots WHERE block=?",
                [id.as_slice()],
            )
            .unwrap(),
        1
    );
    assert_eq!(
        load(
            &f.node.db,
            &f.node.settings,
            id,
            &mut || Ok(()),
            &f.node.authenticated_arithmetic,
        )
        .unwrap(),
        None
    );
    assert_eq!(f.node.state_at(id).unwrap(), state);
    (id, state)
}

#[test]
fn shared_known_pruned_key_relocation_never_becomes_optional_absence() {
    let mut f = fixture();
    let (pruned, _) = add_then_prune_codec_fork(&mut f);
    let before = encoded(&f.node.db, f.block).unwrap().unwrap();
    let write = f.node.db.unchecked_transaction().unwrap();
    assert_eq!(
        write
            .execute(
                "UPDATE main.native_io_shared_snapshots SET block=? WHERE block=?",
                params![pruned.as_slice(), f.block.as_slice()],
            )
            .unwrap(),
        1
    );
    assert_eq!(
        write
            .query_row::<Vec<u8>, _, _>(
                "SELECT data FROM main.native_io_shared_snapshots WHERE block=?",
                [pruned.as_slice()],
                |r| r.get(0),
            )
            .unwrap(),
        before
    );
    let error = read(&f).unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_SHARED_SNAPSHOT_RECORD");
    assert!(error.requires_owner_stop());
    write.rollback().unwrap();
    assert_eq!(read(&f).unwrap(), Some(f.state.clone()));
    let write = f.node.db.unchecked_transaction().unwrap();
    let mut calls = 0usize;
    load(
        &f.node.db,
        &f.node.settings,
        f.block,
        &mut || {
            calls += 1;
            Ok(())
        },
        &f.node.authenticated_arithmetic,
    )
    .unwrap();
    let mut index = 0usize;
    let error = load(
        &f.node.db,
        &f.node.settings,
        f.block,
        &mut || {
            index += 1;
            if index == calls {
                f.node.db.execute(
                    "UPDATE main.native_io_shared_snapshots SET block=? WHERE block=?",
                    params![pruned.as_slice(), f.block.as_slice()],
                )?;
            }
            Ok(())
        },
        &f.node.authenticated_arithmetic,
    )
    .unwrap_err();
    assert!(error.requires_owner_stop());
    write.rollback().unwrap();
    assert_eq!(read(&f).unwrap(), Some(f.state));
}

#[test]
fn shared_optional_none_checks_every_present_codec_and_working_binding() {
    let mut f = fixture();
    let (pruned, _) = add_then_prune_codec_fork(&mut f);
    let before = encoded(&f.node.db, f.block).unwrap().unwrap();
    for which in 0..6 {
        let write = f.node.db.unchecked_transaction().unwrap();
        let mut value: Snapshot = serde_json::from_slice(&before).unwrap();
        match which {
            0 => value.schema = "foreign-format".into(),
            1 => value.native_commitment = [7; 32],
            2 => {
                value
                    .working
                    .insert("unexpected-working-key".into(), json!(1));
            }
            3 => {
                let key = value.working.keys().next().unwrap().clone();
                let old = value.working.remove(&key).unwrap();
                assert!(value
                    .working
                    .insert("unexpected-working-key".into(), old)
                    .is_none());
            }
            4 | 5 => {}
            _ => unreachable!(),
        }
        value.id = if which == 4 {
            value
                .digest(&Settings::development(Some(2)).unwrap())
                .unwrap()
        } else {
            value.digest(&f.node.settings).unwrap()
        };
        let mut bytes = canonical(&value).unwrap();
        if which == 5 {
            bytes.push(b' ');
        }
        write
            .execute(
                "UPDATE main.native_io_shared_snapshots SET data=? WHERE block=?",
                params![bytes, f.block.as_slice()],
            )
            .unwrap();
        let error = load(
            &f.node.db,
            &f.node.settings,
            pruned,
            &mut || Ok(()),
            &f.node.authenticated_arithmetic,
        )
        .unwrap_err();
        assert!(
            error.requires_owner_stop(),
            "unselected present record case {which}"
        );
        write.rollback().unwrap();
        assert_eq!(
            load(
                &f.node.db,
                &f.node.settings,
                pruned,
                &mut || Ok(()),
                &f.node.authenticated_arithmetic,
            )
            .unwrap(),
            None
        );
        assert_eq!(read(&f).unwrap(), Some(f.state.clone()));
    }
}

/// Extend the existing actual-factory native control instead of adding any new
/// ignored/default-skip test. A legal optional-index deletion is first read back
/// through the original complete public State path, with actual COW/history.
#[cfg(target_os = "linux")]
fn known_pruned_key_public_checks(
    node: &mut Node,
    active: Hash,
    historical: Hash,
    expected: &(Hash, u64, State),
    historical_state: &State,
) {
    let fork = packet(node, node.settings.genesis(), 1, 12);
    let pruned = node.admit(&fork, 100_000).unwrap();
    let pruned_state = node.state_at(pruned).unwrap();
    assert_eq!(
        node.db
            .execute(
                "DELETE FROM main.native_io_shared_snapshots WHERE block=?",
                [pruned.as_slice()],
            )
            .unwrap(),
        1
    );
    assert_eq!(node.state_at(pruned).unwrap(), pruned_state);
    assert_eq!(node.read_active().unwrap(), *expected);
    for block in [active, historical] {
        let before: Vec<u8> = node
            .db
            .query_row(
                "SELECT data FROM main.native_io_shared_snapshots WHERE block=?",
                [block.as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        let write = node.db.unchecked_transaction().unwrap();
        assert_eq!(
            write
                .execute(
                    "UPDATE main.native_io_shared_snapshots SET block=? WHERE block=?",
                    params![pruned.as_slice(), block.as_slice()],
                )
                .unwrap(),
            1
        );
        assert_eq!(
            write
                .query_row::<Vec<u8>, _, _>(
                    "SELECT data FROM main.native_io_shared_snapshots WHERE block=?",
                    [pruned.as_slice()],
                    |r| r.get(0),
                )
                .unwrap(),
            before
        );
        assert!(node.read_active().unwrap_err().requires_owner_stop());
        assert!(node.state_at(block).unwrap_err().requires_owner_stop());
        assert!(node.state_at(pruned).unwrap_err().requires_owner_stop());
        write.rollback().unwrap();
        assert_eq!(node.read_active().unwrap(), *expected);
        assert_eq!(node.state_at(historical).unwrap(), *historical_state);
        let write = node.db.unchecked_transaction().unwrap();
        let mut calls = 0usize;
        if block == active {
            node.read_active_with_progress(&mut || {
                calls += 1;
                Ok(())
            })
            .unwrap();
        } else {
            node.state_at_with_progress(block, &mut || {
                calls += 1;
                Ok(())
            })
            .unwrap();
        }
        let mut index = 0usize;
        let mut progress = || -> Result<()> {
            index += 1;
            if index == calls {
                node.db.execute(
                    "UPDATE main.native_io_shared_snapshots SET block=? WHERE block=?",
                    params![pruned.as_slice(), block.as_slice()],
                )?;
            }
            Ok(())
        };
        let error = if block == active {
            node.read_active_with_progress(&mut progress).unwrap_err()
        } else {
            node.state_at_with_progress(block, &mut progress)
                .unwrap_err()
        };
        assert!(error.requires_owner_stop());
        write.rollback().unwrap();
        assert_eq!(node.read_active().unwrap(), *expected);
        assert_eq!(node.state_at(historical).unwrap(), *historical_state);
        assert_eq!(node.state_at(pruned).unwrap(), pruned_state);
    }
}
