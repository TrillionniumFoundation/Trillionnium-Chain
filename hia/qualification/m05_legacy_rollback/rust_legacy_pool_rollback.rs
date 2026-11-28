#[test]
fn legacy_owner_enable_pool_insert_cancels_before_commit_and_cold_read_matches() {
    use rusqlite::hooks::Action;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    fn pool_counts(db: &Connection) -> [u64; 4] {
        db.query_row(
            "SELECT (SELECT count(*) FROM local_pool_metadata),
                    (SELECT count(*) FROM local_pool_groups),
                    (SELECT count(*) FROM local_pool_rows),
                    (SELECT count(*) FROM local_pool_removals)",
            [],
            |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?]),
        )
        .unwrap()
    }

    for cancel in [false, true] {
        let dir = fixtures::directory();
        let journal = fixtures::directory();
        let settings = Settings::development_with_profiles(
            Some(1),
            "native-public-evaluation-dev-v1",
            trnm_protocol::qualified_work_task::lifecycle_v3::PROFILE,
        )
        .unwrap();
        let mut node = Node::open(dir.path(), settings.clone(), 1).unwrap();
        let active = node.active().unwrap();
        let state = node.state_at(active.0).unwrap();
        assert_eq!(pool_counts(&node.db), [0; 4]);

        let limits = PoolLimits {
            max_records: 16,
            max_bytes: 32768,
            max_group_members: 16,
            critical_reserve: 0,
            max_removals: 16,
            preview_miner: crate::development_public(3).unwrap(),
        };
        let raw = serde_json::to_vec(&limits).unwrap();
        let context = hash(
            b"native-local-queued-pnx1-v2",
            &[
                &settings.network(),
                &settings.parameters(),
                &settings.genesis(),
                &raw,
            ],
        );
        let grant = pool_owner_fixture(&node);
        let mut enable =
            policy::pool::tests::body(&grant, "enable-pool", std::slice::from_ref(&raw), 1);
        enable.pool_context = hex::encode(context);
        enable.expected_generation = active.1;
        enable.operation_id = policy::pool::pool_operation_id(&enable).unwrap();
        // Same authenticated test authority and real journal used by the legacy
        // owner tests. This is not the protected deployment opener.
        attach_pool_owner(&mut node, journal.path(), grant, vec![enable]);
        let owner = node.owner_policy.as_ref().unwrap();
        let epoch = Arc::clone(&owner.epoch);
        let expected_epoch = epoch.load(Ordering::Acquire);
        let next_epoch = expected_epoch.checked_add(1).unwrap();
        let inserts = Arc::new(AtomicUsize::new(0));
        let commits = Arc::new(AtomicUsize::new(0));
        let rollbacks = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&inserts);
        node.db
            .update_hook(Some(move |action, database: &str, table: &str, rowid| {
                if action == Action::SQLITE_INSERT
                    && database == "main"
                    && table == "local_pool_metadata"
                    && rowid == 1
                {
                    observed.fetch_add(1, Ordering::Release);
                    if cancel {
                        // Existing legacy permit invalidation signal, deterministically
                        // after SQLite changes the row; no SQL or mocked result in hook.
                        epoch.store(next_epoch, Ordering::Release);
                    }
                }
            }))
            .unwrap();
        let observed = Arc::clone(&inserts);
        let commit_count = Arc::clone(&commits);
        node.db
            .commit_hook(Some(move || {
                if observed.load(Ordering::Acquire) > 0 {
                    commit_count.fetch_add(1, Ordering::Relaxed);
                }
                false
            }))
            .unwrap();
        let observed = Arc::clone(&inserts);
        let rollback_count = Arc::clone(&rollbacks);
        node.db
            .rollback_hook(Some(move || {
                if observed.load(Ordering::Acquire) > 0 {
                    rollback_count.fetch_add(1, Ordering::Relaxed);
                }
            }))
            .unwrap();

        let result = node.enable_local_mempool(limits);
        let inserted = inserts.load(Ordering::Acquire);
        let committed = commits.load(Ordering::Acquire);
        let rolled_back = rollbacks.load(Ordering::Acquire);
        assert_eq!(inserted, 1);
        let claims = node
            .owner_policy
            .as_ref()
            .unwrap()
            .journal
            .borrow()
            .pool_claim_count_for_tests();
        assert_eq!(claims, 1, "rollback must not refund a reserved owner claim");
        let expected_counts = if cancel {
            assert_eq!(result.unwrap_err().to_string(), "OWNER_TASK_VIEW_CHANGED");
            assert_eq!(committed, 0);
            assert_eq!(rolled_back, 1);
            [0; 4]
        } else {
            assert_eq!(result.unwrap(), context);
            assert!(committed >= 1);
            assert_eq!(rolled_back, 0);
            [1, 0, 0, 0]
        };
        assert_eq!(pool_counts(&node.db), expected_counts);
        assert_eq!(node.active().unwrap(), active);
        assert_eq!(node.state_at(active.0).unwrap(), state);
        drop(node);

        let closed = Connection::open_with_flags(
            dir.path().join("native.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        assert_eq!(pool_counts(&closed), expected_counts);
        let stored: Option<(Vec<u8>, Vec<u8>)> = closed
            .query_row(
                "SELECT context,limits FROM local_pool_metadata WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .unwrap();
        assert_eq!(stored, (!cancel).then(|| (context.to_vec(), raw)));
        drop(closed);
        let cold = Node::open(dir.path(), settings, 1).unwrap();
        assert_eq!(cold.active().unwrap(), active);
        assert_eq!(cold.state_at(active.0).unwrap(), state);
        if cancel {
            assert_eq!(
                cold.pool_status_snapshot().unwrap_err().to_string(),
                "POOL_NOT_ENABLED"
            );
        } else {
            assert_eq!(cold.pool_status_snapshot().unwrap().retained_records, 0);
        }
        println!(
            "legacy-pool-enable cancel={cancel} insert={inserted} commit_callbacks={committed} \
             rollback_callbacks={rolled_back} claims={claims} cold_tables={expected_counts:?} \
             active_parent={} active_generation={}",
            hex::encode(active.0),
            active.1
        );
    }
}
