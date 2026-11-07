//! Cached SQL bytecode must still observe actual transactional and schema changes.
use super::*;
use serde_json::json;

fn open(path: &Path, settings: Settings, authenticated: bool) -> Node {
    if authenticated {
        Node::open_with_authenticated_state(path, settings, 1).unwrap()
    } else {
        Node::open(path, settings, 1).unwrap()
    }
}

#[test]
fn warmed_queries_recheck_actual_writes_rollback_schema_and_cold_state() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(directory.path(), settings.clone(), authenticated);
        let packet = node
            .make(
                settings.genesis(),
                vec![],
                development_public(0).unwrap(),
                11,
                4096,
            )
            .unwrap();
        let left = node.admit(&packet, 1000).unwrap();
        node.activate(left).unwrap();
        // A direct append has its own fast path and need not leave a reorg
        // row. Use a real longer sibling branch to exercise the original
        // detach/attach journal before warming its readback statements.
        let right = node
            .make(
                settings.genesis(),
                vec![],
                development_public(1).unwrap(),
                12,
                4096,
            )
            .unwrap();
        let right = node.admit(&right, 1000).unwrap();
        let target_packet = node
            .make(right, vec![], development_public(1).unwrap(), 22, 4096)
            .unwrap();
        let tip = node.admit(&target_packet, 1000).unwrap();
        node.activate(tip).unwrap();
        let original = node.read_active().unwrap();
        let original_slot = node.slot().unwrap();
        let key = original.2.keys().next().unwrap().clone();
        let (old, target, generation, cursor, done): (Vec<u8>, Vec<u8>, u64, u64, u64) = node
            .db
            .query_row(
                "SELECT old_tip,new_tip,generation,cursor,done FROM reorg WHERE singleton=1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        let old = bytes32(old).unwrap();
        let target = bytes32(target).unwrap();
        // Zero and eviction-sized caches retain the same correctness contract;
        // sixteen is the existing connection default, not an increased budget.
        for capacity in [0, 1, 16] {
            node.db.set_prepared_statement_cache_capacity(capacity);
            for _ in 0..2 {
                node.check_active_before_commit().unwrap();
                node.check_reorg_row(old, target, generation, cursor, done)
                    .unwrap();
                assert_eq!(node.read_active().unwrap(), original);
            }

            node.db.execute_batch("SAVEPOINT actual_write").unwrap();
            node.db
                .execute(
                    "UPDATE active SET generation=?,state_slot=? WHERE singleton=1",
                    params![original.1 + 1, original_slot + 1],
                )
                .unwrap();
            assert_eq!(node.active().unwrap(), (tip, original.1 + 1));
            assert_eq!(node.slot().unwrap(), original_slot + 1);
            node.db
                .execute_batch("ROLLBACK TO actual_write; RELEASE actual_write")
                .unwrap();
            assert_eq!(node.read_active().unwrap(), original);

            node.db.execute_batch("SAVEPOINT actual_state").unwrap();
            node.db
                .execute(
                    "UPDATE kv SET value=? WHERE slot=? AND key=?",
                    params![b"{}".as_slice(), original_slot, key],
                )
                .unwrap();
            assert_eq!(node.slot_state(original_slot).unwrap()[&key], json!({}));
            assert!(node
                .check_active_before_commit()
                .unwrap_err()
                .requires_owner_stop());
            node.db
                .execute_batch("ROLLBACK TO actual_state; RELEASE actual_state")
                .unwrap();
            assert_eq!(node.read_active().unwrap(), original);

            node.db.execute_batch("SAVEPOINT actual_context").unwrap();
            node.db
                .execute(
                    "UPDATE metadata SET value=zeroblob(32) WHERE key='parameters'",
                    [],
                )
                .unwrap();
            assert!(node.storage_context().unwrap_err().requires_owner_stop());
            node.db
                .execute_batch("ROLLBACK TO actual_context; RELEASE actual_context")
                .unwrap();
            node.storage_context().unwrap();

            node.db.execute_batch("SAVEPOINT actual_cursor").unwrap();
            node.db
                .execute("UPDATE reorg SET cursor=cursor+1", [])
                .unwrap();
            assert!(node
                .check_reorg_row(old, target, generation, cursor, done)
                .unwrap_err()
                .requires_owner_stop());
            node.db
                .execute_batch("ROLLBACK TO actual_cursor; RELEASE actual_cursor")
                .unwrap();
            node.check_reorg_row(old, target, generation, cursor, done)
                .unwrap();

            node.db
                .execute_batch("SAVEPOINT missing_active; DELETE FROM active")
                .unwrap();
            assert!(node.active().is_err());
            assert!(node
                .check_active_before_commit()
                .unwrap_err()
                .requires_owner_stop());
            node.db
                .execute_batch("ROLLBACK TO missing_active; RELEASE missing_active")
                .unwrap();

            // Invalidate the warmed SQLite programs with actual DDL. Reusing
            // bytecode must not return an old row when its table is absent.
            for table in ["metadata", "active", "kv", "reorg"] {
                node.db
                    .execute_batch(&format!("SAVEPOINT actual_schema; DROP TABLE {table}"))
                    .unwrap();
                let refused = match table {
                    "metadata" => node.storage_context().is_err(),
                    "active" => node.active().is_err() && node.slot().is_err(),
                    "kv" => node.slot_state(original_slot).is_err(),
                    "reorg" => node
                        .check_reorg_row(old, target, generation, cursor, done)
                        .is_err(),
                    _ => unreachable!(),
                };
                assert!(refused, "{table}");
                node.db
                    .execute_batch("ROLLBACK TO actual_schema; RELEASE actual_schema")
                    .unwrap();
                node.check_active_before_commit().unwrap();
                node.check_reorg_row(old, target, generation, cursor, done)
                    .unwrap();
                assert_eq!(node.read_active().unwrap(), original);
            }
        }
        drop(node);
        let reopened = open(directory.path(), settings, authenticated);
        assert_eq!(reopened.read_active().unwrap(), original);
        assert_eq!(reopened.slot().unwrap(), original_slot);
        reopened.check_active_before_commit().unwrap();
        reopened
            .check_reorg_row(old, target, generation, cursor, done)
            .unwrap();
    }
}
