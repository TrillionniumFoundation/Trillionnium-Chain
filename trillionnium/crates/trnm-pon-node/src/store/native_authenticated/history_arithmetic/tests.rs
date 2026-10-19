use super::super::{
    canonical, delta_root, load, load_observed, native_block, native_block_with_cache,
    stored_delta_root, stored_delta_root_observed, verify_history, verify_history_with_cache,
    ArithmeticCache, DeltaRootBuilder, MAX_RECORD_BYTES,
};
use super::*;
use crate::{development_public, Error, ErrorCode, Node, Result};
use rusqlite::{params, Connection};

fn settings() -> Settings {
    Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap()
}
fn chain(path: &std::path::Path, blocks: usize) -> (Node, Vec<Hash>) {
    let mut node = Node::open_with_authenticated_state(path, settings(), 1).unwrap();
    let mut ids = vec![node.settings.genesis()];
    for height in 1..=blocks {
        let packet = node
            .make_consensus_maintenance(
                *ids.last().unwrap(),
                vec![],
                development_public(7).unwrap(),
                1 + height as u64 * 10,
                4096,
            )
            .unwrap();
        let id = node.admit(&packet, 100_000).unwrap();
        node.activate(id).unwrap();
        ids.push(id);
    }
    (node, ids)
}
fn history(
    node: &Node,
    id: Hash,
    warm: bool,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    if warm {
        verify_history_with_cache(
            &node.db,
            &node.settings,
            id,
            progress,
            Some(&node.authenticated_arithmetic),
        )
    } else {
        verify_history(&node.db, &node.settings, id, progress)
    }
}
fn same_error<T>(warm: Result<T>, cold: Result<T>) {
    let warm = warm.err().expect("warm path must reject");
    let cold = cold.err().expect("original path must reject");
    assert_eq!(warm.to_string(), cold.to_string());
    assert_eq!(warm.kind(), cold.kind());
    assert_eq!(warm.requires_owner_stop(), cold.requires_owner_stop());
}

#[test]
fn current_record_bytes_namespace_and_long_scans_never_replace_prior_observations() {
    let directory = tempfile::tempdir().unwrap();
    let (node, ids) = chain(directory.path(), 0);
    let cache = &node.authenticated_arithmetic;
    cache.history.clear();
    let template = load(&node.db, ids[0]).unwrap();
    // Real canonical record rows, independently validated by the original load.
    // This is a codec/cache test, not a claim that these rows are admitted blocks.
    for n in 0..=MAX_ENTRIES {
        let mut record = template.clone();
        record.block = [n as u8; 32];
        record.id = record.digest().unwrap();
        node.db
            .execute(
                "INSERT INTO native_state_commitments VALUES(?,?)",
                params![record.block.as_slice(), canonical(&record).unwrap()],
            )
            .unwrap();
        assert_eq!(
            load_observed(&node.db, record.block, Some((&node.settings, cache))).unwrap(),
            load(&node.db, record.block).unwrap()
        );
    }
    assert_eq!(cache.history.records.entries.borrow().len(), MAX_ENTRIES);
    for reverse in [true, false, true] {
        let before = cache.history.counters.get();
        for n in 0..=MAX_ENTRIES {
            let n = if reverse { MAX_ENTRIES - n } else { n };
            load_observed(&node.db, [n as u8; 32], Some((&node.settings, cache))).unwrap();
        }
        let after = cache.history.counters.get();
        assert_eq!(after.record_hits - before.record_hits, MAX_ENTRIES as u64);
        assert_eq!(after.record_computations - before.record_computations, 1);
        assert!(after.record_bytes_observed > before.record_bytes_observed);
    }
    let id = [2; 32];
    let bytes: Vec<u8> = node
        .db
        .query_row(
            "SELECT data FROM native_state_commitments WHERE block=?",
            [id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let foreign = Connection::open(directory.path().join("native.sqlite")).unwrap();
    let mut noncanonical = bytes.clone();
    noncanonical.push(b' ');
    foreign
        .execute(
            "UPDATE native_state_commitments SET data=? WHERE block=?",
            params![noncanonical, id.as_slice()],
        )
        .unwrap();
    same_error(
        load_observed(&node.db, id, Some((&node.settings, cache))),
        load(&node.db, id),
    );
    foreign
        .execute(
            "UPDATE native_state_commitments SET data=? WHERE block=?",
            params![bytes, id.as_slice()],
        )
        .unwrap();
    let other = Settings::development_with_profiles(
        Some(2),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap();
    let before = cache.history.counters.get();
    load_observed(&node.db, id, Some((&other, cache))).unwrap();
    assert_eq!(cache.history.counters.get().record_hits, before.record_hits);
    assert_eq!(
        cache.history.counters.get().record_computations,
        before.record_computations + 1
    );
    for mutation in [
        "DELETE FROM native_state_commitments WHERE block=?",
        "UPDATE native_state_commitments SET data=CAST(data AS TEXT) WHERE block=?",
    ] {
        node.db.execute_batch("SAVEPOINT record_fault").unwrap();
        node.db.execute(mutation, [id.as_slice()]).unwrap();
        same_error(
            load_observed(&node.db, id, Some((&node.settings, cache))),
            load(&node.db, id),
        );
        node.db
            .execute_batch("ROLLBACK TO record_fault; RELEASE record_fault")
            .unwrap();
    }
    node.db.execute_batch("SAVEPOINT record_limit").unwrap();
    node.db
        .execute(
            "UPDATE native_state_commitments SET data=zeroblob(?) WHERE block=?",
            params![MAX_RECORD_BYTES + 1, id.as_slice()],
        )
        .unwrap();
    same_error(
        load_observed(&node.db, id, Some((&node.settings, cache))),
        load(&node.db, id),
    );
    node.db
        .execute_batch("ROLLBACK TO record_limit; RELEASE record_limit")
        .unwrap();
}

#[test]
fn actual_packet_columns_and_parent_work_are_rechecked_after_warm_history() {
    let directory = tempfile::tempdir().unwrap();
    let (node, ids) = chain(directory.path(), 3);
    let tip = ids[3];
    history(&node, tip, true, &mut || Ok(())).unwrap();
    let before = node.authenticated_arithmetic.history.counters.get();
    history(&node, tip, true, &mut || Ok(())).unwrap();
    assert!(
        node.authenticated_arithmetic
            .history
            .counters
            .get()
            .packet_hits
            > before.packet_hits
    );
    for (sql, id) in [
        (
            "UPDATE blocks SET chainwork=zeroblob(64) WHERE id=?",
            ids[2],
        ),
        ("UPDATE blocks SET height=height+1 WHERE id=?", ids[2]),
        ("UPDATE blocks SET parent=zeroblob(32) WHERE id=?", tip),
        ("UPDATE blocks SET state_root=zeroblob(32) WHERE id=?", tip),
        (
            "UPDATE blocks SET packet=CAST(packet AS TEXT) WHERE id=?",
            tip,
        ),
        ("UPDATE blocks SET packet=zeroblob(1048577) WHERE id=?", tip),
        (
            "UPDATE blocks SET chainwork=zeroblob(65) WHERE id=?",
            ids[2],
        ),
    ] {
        node.db.execute_batch("SAVEPOINT packet_fault").unwrap();
        node.db.execute(sql, [id.as_slice()]).unwrap();
        same_error(
            history(&node, tip, true, &mut || Ok(())),
            history(&node, tip, false, &mut || Ok(())),
        );
        node.db
            .execute_batch("ROLLBACK TO packet_fault; RELEASE packet_fault")
            .unwrap();
    }
    let raw: Vec<u8> = node
        .db
        .query_row(
            "SELECT packet FROM blocks WHERE id=?",
            [tip.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let mut different = raw.clone();
    *different.last_mut().unwrap() ^= 1;
    let external = Connection::open(directory.path().join("native.sqlite")).unwrap();
    external
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![different, tip.as_slice()],
        )
        .unwrap();
    same_error(
        native_block_with_cache(
            &node.db,
            &node.settings,
            tip,
            Some(&node.authenticated_arithmetic),
        ),
        native_block(&node.db, &node.settings, tip),
    );
    external
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![raw, tip.as_slice()],
        )
        .unwrap();
    history(&node, tip, true, &mut || Ok(())).unwrap();
}

#[test]
fn old_delta_and_parent_record_faults_keep_original_error_order() {
    let directory = tempfile::tempdir().unwrap();
    let (node, ids) = chain(directory.path(), 3);
    let tip = ids[3];
    history(&node, tip, true, &mut || Ok(())).unwrap();
    assert!(
        node.authenticated_arithmetic
            .history
            .counters
            .get()
            .delta_leaf_hits
            > 0
    );
    for sql in [
        "DELETE FROM deltas WHERE block=?",
        "UPDATE deltas SET after=X'' WHERE block=?",
        "UPDATE deltas SET after=CAST(after AS TEXT) WHERE block=?",
        "UPDATE deltas SET before=after WHERE block=?",
        "UPDATE deltas SET after=zeroblob(4097) WHERE block=?",
        "UPDATE native_state_commitments SET data=X'' WHERE block=?",
        "DELETE FROM native_state_commitments WHERE block=?",
    ] {
        node.db.execute_batch("SAVEPOINT old_fault").unwrap();
        node.db.execute(sql, [ids[1].as_slice()]).unwrap();
        same_error(
            history(&node, tip, true, &mut || Ok(())),
            history(&node, tip, false, &mut || Ok(())),
        );
        // The nearer parent's malformed record is reached in its original
        // position; a prefix hash scan must not move an older delta error first.
        node.db
            .execute(
                "UPDATE native_state_commitments SET data=X'' WHERE block=?",
                [ids[2].as_slice()],
            )
            .unwrap();
        same_error(
            history(&node, tip, true, &mut || Ok(())),
            history(&node, tip, false, &mut || Ok(())),
        );
        node.db
            .execute_batch("ROLLBACK TO old_fault; RELEASE old_fault")
            .unwrap();
        history(&node, tip, true, &mut || Ok(())).unwrap();
    }
    node.db.execute_batch("SAVEPOINT genesis_fault").unwrap();
    node.db
        .execute(
            "UPDATE snapshots SET state=X'' WHERE block=?",
            [ids[0].as_slice()],
        )
        .unwrap();
    same_error(
        history(&node, tip, true, &mut || Ok(())),
        history(&node, tip, false, &mut || Ok(())),
    );
    node.db
        .execute_batch("ROLLBACK TO genesis_fault; RELEASE genesis_fault")
        .unwrap();
}

#[test]
fn every_history_progress_boundary_keeps_cancellation_identity_and_retry() {
    let directory = tempfile::tempdir().unwrap();
    let (node, ids) = chain(directory.path(), 2);
    let tip = ids[2];
    let mut counts = Vec::new();
    for warm in [false, true] {
        let mut calls = 0;
        history(&node, tip, warm, &mut || {
            calls += 1;
            Ok(())
        })
        .unwrap();
        counts.push(calls);
    }
    assert_eq!(counts[0], counts[1]);
    assert!(counts[0] > 10);
    for code in [
        ErrorCode::PublicRequestCancelled,
        ErrorCode::PublicMutationCpuBudget,
        ErrorCode::UnknownParent,
    ] {
        for stop in 1..=counts[0] {
            for warm in [true, false] {
                let mut calls = 0;
                let error = history(&node, tip, warm, &mut || {
                    calls += 1;
                    if calls == stop {
                        Err(Error::new(code))
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
                assert!(error.is(code));
                assert_eq!(error.kind(), Error::new(code).kind());
                assert!(!error.requires_owner_stop());
                assert_eq!(calls, stop);
            }
        }
    }
    history(&node, tip, true, &mut || Ok(())).unwrap();
}

fn delta_database(rows: &[Delta]) -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE deltas(block BLOB NOT NULL,key TEXT NOT NULL,before BLOB,after BLOB,PRIMARY KEY(block,key));").unwrap();
    for (key, before, after) in rows {
        db.execute(
            "INSERT INTO deltas VALUES(?,?,?,?)",
            params![[7u8; 32].as_slice(), key, before, after],
        )
        .unwrap();
    }
    db
}
#[test]
fn indexed_leaf_reuse_keeps_padding_current_rows_and_typed_null_errors() {
    let settings = settings();
    for count in [0, 1, 3, 6, 11, 255, 256, 257, 513, 1025] {
        let rows: Vec<Delta> = (0..count)
            .map(|index| {
                (
                    format!("key-{index:06}"),
                    None,
                    Some(canonical(&format!("value-{index}")).unwrap()),
                )
            })
            .collect();
        let expected = crate::sequence_root(
            "native-authenticated-deltas-v1",
            &rows
                .iter()
                .map(canonical)
                .collect::<Result<Vec<_>>>()
                .unwrap(),
        );
        let db = delta_database(&rows);
        let cache = ArithmeticCache::default();
        for _ in 0..2 {
            assert_eq!(
                stored_delta_root_observed(&db, [7; 32], &mut || Ok(()), Some((&settings, &cache)))
                    .unwrap(),
                (count, expected)
            );
        }
        assert_eq!(
            cache.history.counters.get().delta_rows_observed,
            2 * count as u64
        );
        assert_eq!(cache.history.counters.get().delta_leaf_hits, count as u64);
        assert_eq!(
            cache.history.counters.get().delta_leaf_computations,
            count as u64
        );
        if count > 0 {
            db.execute_batch("SAVEPOINT delta_change").unwrap();
            db.execute(
                "INSERT INTO deltas VALUES(?,?,NULL,?)",
                params![[7u8; 32].as_slice(), "a-new-first-key", b"null".as_slice()],
            )
            .unwrap();
            assert_eq!(
                stored_delta_root_observed(&db, [7; 32], &mut || Ok(()), Some((&settings, &cache)))
                    .unwrap(),
                stored_delta_root(&db, [7; 32], &mut || Ok(())).unwrap()
            );
            db.execute_batch("ROLLBACK TO delta_change; RELEASE delta_change")
                .unwrap();
            for sql in [
                "UPDATE deltas SET after=X''",
                "UPDATE deltas SET after=CAST(after AS TEXT)",
                "UPDATE deltas SET after=before",
                "UPDATE deltas SET key=CAST(key AS BLOB)",
            ] {
                db.execute_batch("SAVEPOINT delta_fault").unwrap();
                db.execute_batch(sql).unwrap();
                same_error(
                    stored_delta_root_observed(
                        &db,
                        [7; 32],
                        &mut || Ok(()),
                        Some((&settings, &cache)),
                    ),
                    stored_delta_root(&db, [7; 32], &mut || Ok(())),
                );
                db.execute_batch("ROLLBACK TO delta_fault; RELEASE delta_fault")
                    .unwrap();
            }
        }
    }
}

#[test]
fn retained_charge_and_operation_capture_bounds_only_discard_acceleration() {
    let settings = settings();
    let pool = Pool::<u8>::default();
    pool.retain(Key::new(&settings, [0; 32]), 0, usize::MAX);
    pool.retain(Key::new(&settings, [0; 32]), 0, MAX_POOL_CHARGE);
    assert!(pool.entries.borrow().is_empty());
    for n in 0..=MAX_ENTRIES {
        pool.retain(
            Key::new(&settings, [n as u8; 32]),
            n as u8,
            MAX_POOL_CHARGE / 3,
        );
    }
    assert_eq!(pool.entries.borrow().len(), 2);
    assert!(pool.charge.get() <= MAX_POOL_CHARGE);
    assert_eq!(pool.get(Key::new(&settings, [0; 32])).unwrap().value, 0);
    let cache = HistoryArithmetic::default();
    let mut pass = cache.delta_pass(&settings, [8; 32]);
    let mut tree = DeltaRootBuilder::default();
    for n in 0..600 {
        let row = (
            format!("key-{n:06}"),
            Some(vec![b'a'; 4096]),
            Some(vec![b'b'; 4096]),
        );
        let leaf = tree.leaf(&row).unwrap();
        tree.push_leaf(leaf);
        pass.retain(row, leaf);
    }
    assert!(pass.capture.is_none());
    pass.finish();
    assert!(cache.deltas.entries.borrow().is_empty());
    let rows = vec![("small".to_string(), None, Some(b"null".to_vec()))];
    let db = delta_database(&rows);
    let cache = ArithmeticCache::default();
    assert_eq!(
        stored_delta_root_observed(&db, [7; 32], &mut || Ok(()), Some((&settings, &cache)))
            .unwrap()
            .1,
        delta_root(&rows).unwrap()
    );
    let status = cache.history.observation();
    assert_eq!(status["has_consensus_authority"], false);
    assert_eq!(
        status["retained_software_charge_limit_bytes"],
        3 * MAX_POOL_CHARGE
    );
}

#[test]
fn old_history_trigger_rolls_back_new_block_and_cached_codec_cannot_create_it() {
    let directory = tempfile::tempdir().unwrap();
    let (mut node, ids) = chain(directory.path(), 2);
    history(&node, ids[2], true, &mut || Ok(())).unwrap();
    let packet = node
        .make_consensus_maintenance(ids[2], vec![], development_public(7).unwrap(), 31, 4096)
        .unwrap();
    let id = packet.id().unwrap();
    let previous = node.read_active().unwrap();
    node.db.execute_batch(&format!("CREATE TEMP TRIGGER damage_history AFTER INSERT ON native_state_commitments BEGIN DELETE FROM deltas WHERE block=X'{}'; END;",hex::encode(ids[1]))).unwrap();
    assert!(node.admit(&packet, 100_000).is_err());
    assert_eq!(
        node.db
            .query_row(
                "SELECT COUNT(*) FROM blocks WHERE id=?",
                [id.as_slice()],
                |row| row.get::<_, usize>(0)
            )
            .unwrap(),
        0
    );
    same_error(
        load_observed(
            &node.db,
            id,
            Some((&node.settings, &node.authenticated_arithmetic)),
        ),
        load(&node.db, id),
    );
    assert_eq!(node.read_active().unwrap(), previous);
    node.db
        .execute_batch("DROP TRIGGER damage_history")
        .unwrap();
    assert_eq!(node.admit(&packet, 100_000).unwrap(), id);
    history(&node, id, true, &mut || Ok(())).unwrap();
    drop(node);
    let reopened = Node::open_with_authenticated_state(directory.path(), settings(), 1).unwrap();
    history(&reopened, id, true, &mut || Ok(())).unwrap();
}

#[test]
fn nested_observations_do_not_hold_a_guard_across_cancellation_or_change_errors() {
    let cache = HistoryArithmetic::default();
    let result: Result<()> = {
        let _outer = cache.observe(HistoryStage::Admission);
        let _inner = cache.observe(HistoryStage::VerifyHistory);
        Err(Error::new(ErrorCode::PublicMutationCpuBudget))
    };
    assert!(result.unwrap_err().is(ErrorCode::PublicMutationCpuBudget));
    let status = cache.observation();
    assert_eq!(status["stage_observation_failed"], false);
    for index in [
        HistoryStage::Admission as usize,
        HistoryStage::VerifyHistory as usize,
    ] {
        let totals = &status["stages"][index]["totals"];
        assert_eq!(totals["calls"], 1);
        assert_eq!(
            totals["cpu_known_calls"].as_u64().unwrap()
                + totals["cpu_unknown_calls"].as_u64().unwrap(),
            1
        );
    }
}
