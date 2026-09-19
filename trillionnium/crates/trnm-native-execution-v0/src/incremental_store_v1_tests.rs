use super::*;
use crate::{
    store::{plan_complete_state_update_v0, CompleteStateWriteV0},
    AuthorizedSignerV0, InMemoryNativeExecutionStoreV0, NativeStateWriteV0,
};
use rusqlite::Connection;
use trnm_consensus_types::ConsensusParametersV0;

fn namespace() -> IncrementalNamespaceV1 {
    IncrementalNamespaceV1 {
        chain: "incremental-test".into(),
        genesis: [1; 32],
        namespace: [2; 32],
        owner_generation: 1,
    }
}
fn seed() -> InMemoryNativeExecutionStoreV0 {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let mut store = InMemoryNativeExecutionStoreV0::new(
        "incremental-test",
        vec![AuthorizedSignerV0::new(
            "signer",
            "operator",
            hex::encode(key.verifying_key().to_bytes()),
        )
        .unwrap()],
        ConsensusParametersV0::reference_shadow_v0(),
    )
    .unwrap();
    store
        .apply_seed_v0(
            0,
            vec![
                NativeStateWriteV0::raw(b"a".to_vec(), b"original".to_vec()).unwrap(),
                NativeStateWriteV0::raw(b"b".to_vec(), b"retained".to_vec()).unwrap(),
            ],
        )
        .unwrap();
    store
}
fn initialize(connection: &mut Connection) -> (IncrementalHeadV1, InMemoryNativeExecutionStoreV0) {
    connection
        .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")
        .unwrap();
    let transaction = connection.transaction().unwrap();
    install_incremental_schema_v1(&transaction).unwrap();
    check_incremental_schema_v1(&transaction).unwrap();
    let store = seed();
    let head = IncrementalHeadV1 {
        height: 0,
        block: [3; 32],
        root: store.roots[&0].0,
        commit_sequence: 0,
        intent: [4; 32],
        checksum: [0; 32],
    };
    let head = import_incremental_snapshot_v1(&transaction, &namespace(), head, 0, &store).unwrap();
    transaction.commit().unwrap();
    (head, store)
}
fn plan(
    reader: &IncrementalJmtReaderV1<'_>,
    writes: &[(&[u8], Option<&[u8]>)],
) -> CompleteStatePlanV0 {
    plan_complete_state_update_v0(
        reader,
        reader.version(),
        reader.version() + 1,
        writes
            .iter()
            .map(|(key, value)| {
                CompleteStateWriteV0::new(key.to_vec(), value.map(<[u8]>::to_vec)).unwrap()
            })
            .collect(),
    )
    .unwrap()
}
fn stage(
    connection: &mut Connection,
    parent: IncrementalParentV1,
    block: u8,
    writes: &[(&[u8], Option<&[u8]>)],
) -> PreparedIncrementalDeltaV1 {
    let transaction = connection.transaction().unwrap();
    let reader = open_incremental_reader_v1(&transaction, &namespace(), parent).unwrap();
    let plan = plan(&reader, writes);
    let prepared =
        stage_incremental_plan_v1(&transaction, &namespace(), parent, [block; 32], &plan).unwrap();
    transaction.commit().unwrap();
    prepared
}
fn apply(
    connection: &mut Connection,
    head: &IncrementalHeadV1,
    prepared: &PreparedIncrementalDeltaV1,
    op: u8,
) -> IncrementalHeadV1 {
    let transaction = connection.transaction().unwrap();
    let head = apply_incremental_delta_v1(&transaction, &namespace(), head, prepared, [op; 32], 0)
        .unwrap();
    transaction.commit().unwrap();
    head
}

#[test]
fn incremental_roots_match_reference_and_writes_do_not_scale_with_retained_history() {
    let mut connection = Connection::open_in_memory().unwrap();
    let (mut head, mut reference) = initialize(&mut connection);
    let mut delta_sizes = Vec::new();
    for version in 1u64..=96 {
        let value = version.to_be_bytes();
        let transaction = connection.transaction().unwrap();
        let parent = IncrementalParentV1::Committed(head.block);
        let reader = open_incremental_reader_v1(&transaction, &namespace(), parent).unwrap();
        let plan = plan(&reader, &[(b"a", Some(&value))]);
        let reference_plan = plan_complete_state_update_v0(
            &reference,
            version - 1,
            version,
            vec![CompleteStateWriteV0::new(b"a".to_vec(), Some(value.to_vec())).unwrap()],
        )
        .unwrap();
        assert_eq!(plan.state_root(), reference_plan.state_root());
        reference
            .apply_complete_state_plan_v0(reference_plan)
            .unwrap();
        let prepared = stage_incremental_plan_v1(
            &transaction,
            &namespace(),
            parent,
            [version as u8 + 8; 32],
            &plan,
        )
        .unwrap();
        delta_sizes.push(
            transaction
                .query_row(
                    "SELECT length(delta) FROM ni_prepared WHERE artifact=?1",
                    [prepared.artifact.as_slice()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
        );
        head = apply_incremental_delta_v1(
            &transaction,
            &namespace(),
            &head,
            &prepared,
            [version as u8 + 128; 32],
            0,
        )
        .unwrap();
        let reader = open_incremental_reader_v1(
            &transaction,
            &namespace(),
            IncrementalParentV1::Committed(head.block),
        )
        .unwrap();
        assert_eq!(reader.prove(b"a").unwrap(), Some(value.to_vec()));
        assert_eq!(reader.prove(b"b").unwrap(), Some(b"retained".to_vec()));
        transaction.commit().unwrap();
    }
    assert_eq!(delta_sizes.iter().min(), delta_sizes.iter().max());
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM ni_roots", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        97
    );
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM ni_values", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        98
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM ni_prepared WHERE phase=0",
                [],
                |row| row.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn sibling_deltas_and_speculative_descendants_remain_isolated_after_rebase() {
    let mut connection = Connection::open_in_memory().unwrap();
    let (genesis, _) = initialize(&mut connection);
    let parent = IncrementalParentV1::Committed(genesis.block);
    let a = stage(&mut connection, parent, 10, &[(b"a", Some(b"left"))]);
    let b = stage(&mut connection, parent, 11, &[(b"a", Some(b"right"))]);
    let a2 = stage(
        &mut connection,
        IncrementalParentV1::Prepared(a.artifact),
        12,
        &[(b"b", None)],
    );
    {
        let transaction = connection.transaction().unwrap();
        let committed = open_incremental_reader_v1(&transaction, &namespace(), parent).unwrap();
        assert_eq!(committed.prove(b"a").unwrap(), Some(b"original".to_vec()));
        let right = open_incremental_reader_v1(
            &transaction,
            &namespace(),
            IncrementalParentV1::Prepared(b.artifact),
        )
        .unwrap();
        assert_eq!(right.prove(b"a").unwrap(), Some(b"right".to_vec()));
        let left = open_incremental_reader_v1(
            &transaction,
            &namespace(),
            IncrementalParentV1::Prepared(a2.artifact),
        )
        .unwrap();
        assert_eq!(left.prove(b"a").unwrap(), Some(b"left".to_vec()));
        assert_eq!(left.prove(b"b").unwrap(), None);
    }
    let h1 = apply(&mut connection, &genesis, &a, 20);
    // New child now resolves through a committed ancestor while a2 still has
    // its original genesis pin. This must not change a2's storage artifact.
    let a3 = stage(
        &mut connection,
        IncrementalParentV1::Prepared(a2.artifact),
        13,
        &[(b"c", Some(b"new"))],
    );
    let h2 = apply(&mut connection, &h1, &a2, 21);
    let h3 = apply(&mut connection, &h2, &a3, 22);
    let transaction = connection.transaction().unwrap();
    assert!(
        apply_incremental_delta_v1(&transaction, &namespace(), &genesis, &b, [23; 32], 0).is_err()
    );
    assert_eq!(
        read_incremental_head_v1(&transaction, &namespace()).unwrap(),
        h3
    );
    let reader = open_incremental_reader_v1(
        &transaction,
        &namespace(),
        IncrementalParentV1::Committed(h3.block),
    )
    .unwrap();
    assert_eq!(reader.prove(b"b").unwrap(), None);
    assert_eq!(reader.prove(b"c").unwrap(), Some(b"new".to_vec()));
    assert_eq!(
        apply_incremental_delta_v1(&transaction, &namespace(), &genesis, &a, [20; 32], 0).unwrap(),
        h1
    );
    assert!(
        apply_incremental_delta_v1(&transaction, &namespace(), &genesis, &a, [20; 32], 1).is_err()
    );
}

#[test]
fn transaction_abort_and_file_reopen_keep_exact_prepared_or_committed_state() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("incremental.sqlite");
    let mut connection = Connection::open(&path).unwrap();
    let (genesis, _) = initialize(&mut connection);
    let prepared = stage(
        &mut connection,
        IncrementalParentV1::Committed(genesis.block),
        10,
        &[(b"a", Some(b"after"))],
    );
    {
        let transaction = connection.transaction().unwrap();
        apply_incremental_delta_v1(&transaction, &namespace(), &genesis, &prepared, [20; 32], 0)
            .unwrap();
        // Drop before owner commit: even rows already changed by apply revert.
    }
    drop(connection);
    let mut connection = Connection::open(&path).unwrap();
    {
        let transaction = connection.transaction().unwrap();
        assert_eq!(
            read_incremental_head_v1(&transaction, &namespace()).unwrap(),
            genesis
        );
        assert!(
            !load_prepared(&transaction, &namespace(), prepared.artifact)
                .unwrap()
                .committed
        );
        assert_eq!(
            transaction
                .query_row("SELECT count(*) FROM ni_roots", [], |row| row
                    .get::<_, u64>(0))
                .unwrap(),
            1
        );
    }
    let target = apply(&mut connection, &genesis, &prepared, 20);
    drop(connection);
    let mut connection = Connection::open(&path).unwrap();
    let transaction = connection.transaction().unwrap();
    assert_eq!(
        read_incremental_head_v1(&transaction, &namespace()).unwrap(),
        target
    );
    assert_eq!(
        apply_incremental_delta_v1(&transaction, &namespace(), &genesis, &prepared, [20; 32], 0)
            .unwrap(),
        target
    );
    assert!(apply_incremental_delta_v1(
        &transaction,
        &namespace(),
        &genesis,
        &prepared,
        [21; 32],
        0
    )
    .is_err());
}

#[test]
fn exact_stage_retry_is_idempotent_and_conflicting_same_block_rejects() {
    let mut connection = Connection::open_in_memory().unwrap();
    let (head, _) = initialize(&mut connection);
    let parent = IncrementalParentV1::Committed(head.block);
    let first = stage(&mut connection, parent, 10, &[(b"a", Some(b"same"))]);
    assert_eq!(
        stage(&mut connection, parent, 10, &[(b"a", Some(b"same"))]),
        first
    );
    let transaction = connection.transaction().unwrap();
    let reader = open_incremental_reader_v1(&transaction, &namespace(), parent).unwrap();
    let wrong = plan(&reader, &[(b"a", Some(b"other"))]);
    assert!(
        stage_incremental_plan_v1(&transaction, &namespace(), parent, [10; 32], &wrong).is_err()
    );
    assert_eq!(
        transaction
            .query_row("SELECT count(*) FROM ni_prepared", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        1
    );
    let mut foreign = namespace();
    foreign.owner_generation += 1;
    assert!(open_incremental_reader_v1(&transaction, &foreign, parent).is_err());
}

#[test]
fn retained_proof_detects_value_corruption_and_head_rejects_partial_commit() {
    let mut connection = Connection::open_in_memory().unwrap();
    let (head, _) = initialize(&mut connection);
    let key = authenticated_key_hash_v0(b"a").unwrap();
    let transaction = connection.transaction().unwrap();
    transaction
        .execute(
            "UPDATE ni_values SET value=x'00' WHERE key_hash=?1",
            [key.0.as_slice()],
        )
        .unwrap();
    let reader = open_incremental_reader_v1(
        &transaction,
        &namespace(),
        IncrementalParentV1::Committed(head.block),
    )
    .unwrap();
    assert!(reader.prove(b"a").is_err());
    transaction
        .execute(
            "UPDATE ni_roots SET commit_sequence=?1",
            [1u64.to_be_bytes().as_slice()],
        )
        .unwrap();
    assert!(read_incremental_head_v1(&transaction, &namespace()).is_err());
}

#[test]
fn prepared_codec_rejects_all_truncations_order_and_record_substitution() {
    let mut connection = Connection::open_in_memory().unwrap();
    let (head, _) = initialize(&mut connection);
    let prepared = stage(
        &mut connection,
        IncrementalParentV1::Committed(head.block),
        10,
        &[(b"a", Some(b"new")), (b"b", None)],
    );
    let transaction = connection.transaction().unwrap();
    let row = load_prepared(&transaction, &namespace(), prepared.artifact).unwrap();
    for end in 0..row.bytes.len() {
        assert!(Delta::decode(&row.bytes[..end], 1).is_err(), "prefix {end}");
    }
    let mut trailing = row.bytes.clone();
    trailing.push(0);
    assert!(Delta::decode(&trailing, 1).is_err());
    assert!(Delta::decode(&row.bytes, 2).is_err());
    transaction
        .execute(
            "UPDATE ni_prepared SET block_id=?1 WHERE artifact=?2",
            params![[99u8; 32].as_slice(), prepared.artifact.as_slice()],
        )
        .unwrap();
    assert!(load_prepared(&transaction, &namespace(), prepared.artifact).is_err());
}

#[test]
fn prepared_depth_bound_does_not_consume_an_extra_record() {
    let mut connection = Connection::open_in_memory().unwrap();
    let (head, _) = initialize(&mut connection);
    let mut parent = IncrementalParentV1::Committed(head.block);
    for height in 1..=MAX_DEPTH {
        let prepared = stage(
            &mut connection,
            parent,
            height as u8 + 10,
            &[(b"a", Some(&[height as u8]))],
        );
        parent = IncrementalParentV1::Prepared(prepared.artifact);
    }
    let transaction = connection.transaction().unwrap();
    let reader = open_incremental_reader_v1(&transaction, &namespace(), parent).unwrap();
    let plan = plan(&reader, &[(b"a", Some(b"overflow"))]);
    assert!(
        stage_incremental_plan_v1(&transaction, &namespace(), parent, [90; 32], &plan).is_err()
    );
    assert_eq!(
        transaction
            .query_row("SELECT count(*) FROM ni_prepared", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        MAX_DEPTH as u64
    );
}

#[test]
fn no_op_and_delete_last_leaf_retain_real_roots() {
    let mut connection = Connection::open_in_memory().unwrap();
    let (head, _) = initialize(&mut connection);
    let no_op = stage(
        &mut connection,
        IncrementalParentV1::Committed(head.block),
        10,
        &[],
    );
    assert_eq!(no_op.root, head.root);
    let h1 = apply(&mut connection, &head, &no_op, 20);
    let deleted = stage(
        &mut connection,
        IncrementalParentV1::Committed(h1.block),
        11,
        &[(b"a", None), (b"b", None)],
    );
    let h2 = apply(&mut connection, &h1, &deleted, 21);
    assert_eq!(h2.root, node_hash(&Node::Null));
    let transaction = connection.transaction().unwrap();
    let reader = open_incremental_reader_v1(
        &transaction,
        &namespace(),
        IncrementalParentV1::Committed(h2.block),
    )
    .unwrap();
    assert_eq!(reader.prove(b"a").unwrap(), None);
    assert_eq!(reader.prove(b"b").unwrap(), None);
    assert!(reader.get_rightmost_leaf().is_err());
}

#[test]
fn closed_schema_rejects_unlisted_triggers_and_indexes() {
    let mut connection = Connection::open_in_memory().unwrap();
    initialize(&mut connection);
    {
        let transaction = connection.transaction().unwrap();
        transaction
            .execute_batch(
                "CREATE TRIGGER unexpected AFTER INSERT ON ni_nodes BEGIN SELECT 1; END;",
            )
            .unwrap();
        assert!(check_incremental_schema_v1(&transaction).is_err());
    }
    {
        let transaction = connection.transaction().unwrap();
        transaction
            .execute_batch("CREATE INDEX unexpected ON ni_nodes(node_hash);")
            .unwrap();
        assert!(check_incremental_schema_v1(&transaction).is_err());
    }
    let transaction = connection.transaction().unwrap();
    check_incremental_schema_v1(&transaction).unwrap();
}

#[test]
fn ordinary_history_migration_preserves_all_roots_and_continues_with_delta() {
    let mut reference = seed();
    let mut roots = vec![(
        IncrementalHeadV1 {
            height: 0,
            block: [3; 32],
            root: reference.roots[&0].0,
            commit_sequence: 0,
            intent: [4; 32],
            checksum: [0; 32],
        },
        0,
    )];
    for height in 1u64..=12 {
        let plan = plan_complete_state_update_v0(
            &reference,
            height - 1,
            height,
            vec![
                CompleteStateWriteV0::new(b"a".to_vec(), Some(height.to_be_bytes().to_vec()))
                    .unwrap(),
            ],
        )
        .unwrap();
        reference.apply_complete_state_plan_v0(plan).unwrap();
        roots.push((
            IncrementalHeadV1 {
                height,
                block: [height as u8 + 8; 32],
                root: reference.roots[&height].0,
                commit_sequence: height,
                intent: [height as u8 + 128; 32],
                checksum: [0; 32],
            },
            0,
        ));
    }
    let mut connection = Connection::open_in_memory().unwrap();
    let tx = connection.transaction().unwrap();
    install_incremental_schema_v1(&tx).unwrap();
    let head =
        import_incremental_history_v1(&tx, &namespace(), &roots, &reference, [91; 32]).unwrap();
    for (root, _) in &roots {
        let reader = open_incremental_reader_v1(
            &tx,
            &namespace(),
            IncrementalParentV1::Committed(root.block),
        )
        .unwrap();
        assert_eq!(reader.root().0, root.root);
        assert_eq!(
            reader.verified_live_values_v1().unwrap(),
            reference.verified_live_values_v0(root.height).unwrap()
        );
        let expected = if root.height == 0 {
            b"original".to_vec()
        } else {
            root.height.to_be_bytes().to_vec()
        };
        assert_eq!(reader.prove(b"a").unwrap(), Some(expected));
    }
    tx.commit().unwrap();
    let delta = stage(
        &mut connection,
        IncrementalParentV1::Committed(head.block),
        77,
        &[(b"a", Some(b"after migration"))],
    );
    assert_eq!(delta.height, 13);
    assert_eq!(delta.persist_sequence, 13);
    let head = apply(&mut connection, &head, &delta, 78);
    assert_eq!(head.commit_sequence, 13);
    let tx = connection.transaction().unwrap();
    assert_eq!(read_incremental_head_v1(&tx, &namespace()).unwrap(), head);
    check_incremental_schema_v1(&tx).unwrap();
    tx.execute(
        "UPDATE ni_imported_root SET source_anchor=? WHERE version=?",
        params![[0u8; 32].as_slice(), 7u64.to_be_bytes().as_slice()],
    )
    .unwrap();
    assert!(open_incremental_reader_v1(
        &tx,
        &namespace(),
        IncrementalParentV1::Committed(roots[7].0.block)
    )
    .is_err());
}

#[test]
fn retiring_prepared_fork_releases_exact_pins_and_never_reuses_sequence() {
    let mut connection = Connection::open_in_memory().unwrap();
    let (head, _) = initialize(&mut connection);
    let first = stage(
        &mut connection,
        IncrementalParentV1::Committed(head.block),
        51,
        &[(b"a", Some(b"fork"))],
    );
    let child = stage(
        &mut connection,
        IncrementalParentV1::Prepared(first.artifact),
        52,
        &[(b"b", None)],
    );
    {
        let tx = connection.transaction().unwrap();
        assert!(retire_incremental_prepared_v1(&tx, &namespace(), &[first.artifact]).is_err());
    }
    let before: u64 = connection
        .query_row("SELECT count(*) FROM ni_pin", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, 3);
    let tx = connection.transaction().unwrap();
    retire_incremental_prepared_v1(&tx, &namespace(), &[first.artifact, child.artifact]).unwrap();
    tx.commit().unwrap();
    let after: u64 = connection
        .query_row("SELECT count(*) FROM ni_pin", [], |r| r.get(0))
        .unwrap();
    assert_eq!(after, 1);
    let replacement = stage(
        &mut connection,
        IncrementalParentV1::Committed(head.block),
        53,
        &[(b"a", Some(b"selected"))],
    );
    assert!(replacement.persist_sequence > child.persist_sequence);
    let _ = apply(&mut connection, &head, &replacement, 54);
    let tx = connection.transaction().unwrap();
    assert!(retire_incremental_prepared_v1(&tx, &namespace(), &[replacement.artifact]).is_err());
}

#[test]
fn over_budget_sql_blob_is_an_error_not_missing_state() {
    let mut connection = Connection::open_in_memory().unwrap();
    let (head, _) = initialize(&mut connection);
    let tx = connection.transaction().unwrap();
    tx.execute(
        "UPDATE ni_values SET value=zeroblob(16777217) WHERE key_hash=?",
        [authenticated_key_hash_v0(b"a").unwrap().0.as_slice()],
    )
    .unwrap();
    let reader = open_incremental_reader_v1(
        &tx,
        &namespace(),
        IncrementalParentV1::Committed(head.block),
    )
    .unwrap();
    assert!(reader.prove(b"a").is_err());
    tx.execute(
        "UPDATE ni_preimages SET preimage=zeroblob(65537) WHERE key_hash=?",
        [authenticated_key_hash_v0(b"b").unwrap().0.as_slice()],
    )
    .unwrap();
    assert!(reader.prove(b"b").is_err());
    tx.execute(
        "UPDATE ni_nodes SET node_bytes=zeroblob(4097) WHERE node_key=?",
        [borsh::to_vec(&root_key(0)).unwrap()],
    )
    .unwrap();
    assert!(open_incremental_reader_v1(
        &tx,
        &namespace(),
        IncrementalParentV1::Committed(head.block)
    )
    .is_err());
}

#[test]
fn stage_rejects_suffix_that_its_reader_cannot_reopen() {
    let mut connection = Connection::open_in_memory().unwrap();
    let (head, _) = initialize(&mut connection);
    let value = vec![3u8; MAX_VALUE_BYTES];
    let mut parent = IncrementalParentV1::Committed(head.block);
    for block in 60..63 {
        let delta = stage(&mut connection, parent, block, &[(b"a", Some(&value))]);
        parent = IncrementalParentV1::Prepared(delta.artifact);
    }
    let tx = connection.transaction().unwrap();
    let reader = open_incremental_reader_v1(&tx, &namespace(), parent).unwrap();
    let plan = plan(&reader, &[(b"a", Some(&value))]);
    assert!(stage_incremental_plan_v1(&tx, &namespace(), parent, [63; 32], &plan).is_err());
    let count: u64 = tx
        .query_row("SELECT count(*) FROM ni_prepared", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 3);
    assert_eq!(reader.prove(b"a").unwrap(), Some(value));
}

#[test]
fn bounded_gc_deletes_only_an_unreferenced_node_and_keeps_retention_rows() {
    let mut connection = Connection::open_in_memory().unwrap();
    let (head, store) = initialize(&mut connection);
    let (source_key, source_node) = store
        .nodes
        .iter()
        .find(|(_, node)| matches!(node, Node::Leaf(_)))
        .map(|(key, node)| (key.clone(), node.clone()))
        .expect("seed contains a leaf");
    let orphan_key = NodeKey::new(777, source_key.nibble_path().nibbles().collect());
    let orphan_bytes = borsh::to_vec(&orphan_key).unwrap();
    let orphan_node_bytes = borsh::to_vec(&source_node).unwrap();
    let orphan_hash = node_hash(&source_node);
    let tx = connection.transaction().unwrap();
    tx.execute(
        "INSERT INTO ni_nodes VALUES(?1,?2,?3,?4,?5)",
        params![
            orphan_bytes.as_slice(),
            777u64.to_be_bytes().as_slice(),
            orphan_node_bytes.as_slice(),
            orphan_hash.as_slice(),
            0u64.to_be_bytes().as_slice()
        ],
    )
    .unwrap();
    let report = collect_incremental_nodes_v1(&tx, &namespace(), 1).unwrap();
    assert_eq!(report.deleted_nodes, 1);
    assert!(report.queue_depth <= 1);
    tx.commit().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM ni_nodes WHERE node_key=?1",
                [orphan_bytes.as_slice()],
                |row| row.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM ni_roots", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM ni_values", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM ni_preimages", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        read_incremental_head_v1(&connection.transaction().unwrap(), &namespace()).unwrap(),
        head
    );
}

#[test]
fn zero_sized_gc_pass_is_a_read_only_audit_and_does_not_fill_queue() {
    let mut connection = Connection::open_in_memory().unwrap();
    let (_, store) = initialize(&mut connection);
    let (source_key, source_node) = store
        .nodes
        .iter()
        .find(|(_, node)| matches!(node, Node::Leaf(_)))
        .map(|(key, node)| (key.clone(), node.clone()))
        .expect("seed contains a leaf");
    let orphan_key = NodeKey::new(779, source_key.nibble_path().nibbles().collect());
    let orphan_bytes = borsh::to_vec(&orphan_key).unwrap();
    let tx = connection.transaction().unwrap();
    tx.execute(
        "INSERT INTO ni_nodes VALUES(?1,?2,?3,?4,?5)",
        params![
            orphan_bytes.as_slice(),
            779u64.to_be_bytes().as_slice(),
            borsh::to_vec(&source_node).unwrap().as_slice(),
            node_hash(&source_node).as_slice(),
            0u64.to_be_bytes().as_slice()
        ],
    )
    .unwrap();
    let report = collect_incremental_nodes_v1(&tx, &namespace(), 0).unwrap();
    assert_eq!(report.deleted_nodes, 0);
    assert_eq!(report.enqueued_nodes, 0);
    assert_eq!(report.queue_depth, 0);
    tx.commit().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM ni_nodes WHERE node_key=?1",
                [orphan_bytes.as_slice()],
                |row| row.get::<_, u64>(0)
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM ni_gc_queue", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn gc_fences_reference_count_corruption_and_transaction_drop_rolls_back_queue() {
    let mut connection = Connection::open_in_memory().unwrap();
    let (_, store) = initialize(&mut connection);
    let (source_key, source_node) = store
        .nodes
        .iter()
        .find(|(_, node)| matches!(node, Node::Leaf(_)))
        .map(|(key, node)| (key.clone(), node.clone()))
        .expect("seed contains a leaf");
    let orphan_key = NodeKey::new(778, source_key.nibble_path().nibbles().collect());
    let orphan_bytes = borsh::to_vec(&orphan_key).unwrap();
    let tx = connection.transaction().unwrap();
    tx.execute(
        "INSERT INTO ni_nodes VALUES(?1,?2,?3,?4,?5)",
        params![
            orphan_bytes.as_slice(),
            778u64.to_be_bytes().as_slice(),
            borsh::to_vec(&source_node).unwrap().as_slice(),
            node_hash(&source_node).as_slice(),
            0u64.to_be_bytes().as_slice()
        ],
    )
    .unwrap();
    tx.commit().unwrap();
    let tx = connection.transaction().unwrap();
    tx.execute(
        "UPDATE ni_nodes SET refs=?1 WHERE node_key=?2",
        params![
            0u64.to_be_bytes().as_slice(),
            borsh::to_vec(&root_key(0)).unwrap()
        ],
    )
    .unwrap();
    assert!(collect_incremental_nodes_v1(&tx, &namespace(), 4).is_err());
    drop(tx);
    assert_eq!(
        connection
            .query_row(
                "SELECT refs FROM ni_nodes WHERE node_key=?1",
                [borsh::to_vec(&root_key(0)).unwrap()],
                |row| row.get::<_, Vec<u8>>(0)
            )
            .map(|raw| u64_blob(raw).unwrap())
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM ni_gc_queue", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM ni_nodes WHERE node_key=?1",
                [orphan_bytes.as_slice()],
                |row| row.get::<_, u64>(0)
            )
            .unwrap(),
        1
    );
}
