//! Current SQL, graph and cancellation boundaries for pure node decode reuse.
use super::*;
fn decode_cache_fixture(db: &Connection) -> (State, Root) {
    db.execute_batch(crate::store::native_authenticated::DDL)
        .unwrap();
    let state = (0u64..8)
        .map(|index| {
            let owner = hash(b"native-node-decode-negative", &[&index.to_le_bytes()]);
            (
                format!("account:{}", hex::encode(owner)),
                json!({"balance": index * 7, "nonce": index}),
            )
        })
        .collect();
    let root = native_store::seed(db, &state, &mut || Ok(())).unwrap();
    (state, root)
}

fn observed_decode_cache(
    db: &Connection,
    root: &Root,
    state: &State,
    cache: Option<&native_store::LiftCache>,
    stop: usize,
) -> (Verdict, usize) {
    let mut visits = 0;
    let result = native_store::verify_with_lifts(
        db,
        root,
        state,
        &mut || {
            visits += 1;
            if visits == stop {
                Err(Error::new(ErrorCode::PublicRequestCancelled))
            } else {
                Ok(())
            }
        },
        cache,
    );
    (verdict(result), visits)
}

#[test]
fn native_hot_decode_cache_observes_foreign_sql_types_bytes_deletion_and_rollback() {
    use rusqlite::types::Value as SqlValue;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("native.sqlite");
    let db = Connection::open(&path).unwrap();
    let (state, root) = decode_cache_fixture(&db);
    let cache = native_store::LiftCache::default();
    assert_eq!(
        observed_decode_cache(&db, &root, &state, Some(&cache), usize::MAX),
        (Ok(()), 15)
    );
    let owner = *accounts(&state).unwrap().first_key_value().unwrap().0;
    let value = accounts(&state).unwrap()[&owner];
    let leaf = Node::account(owner, value);
    let bytes = leaf.encode();
    let mut changed = bytes.clone();
    changed[40] ^= 0x80;
    let replacement = Node::account(
        owner,
        Account {
            nonce: value.nonce + 1,
            ..value
        },
    )
    .encode();
    let foreign = Connection::open(&path).unwrap();
    let compare = || {
        let cold = Connection::open(&path).unwrap();
        let current = observed_decode_cache(&db, &root, &state, Some(&cache), usize::MAX);
        let independent = observed_decode_cache(&cold, &root, &state, None, usize::MAX);
        assert_eq!(current, independent);
        assert_eq!(current.0.as_ref().unwrap_err().0, ErrorKind::LocalStructure);
    };
    for corrupt in [
        SqlValue::Blob(changed),
        SqlValue::Blob(bytes[..bytes.len() - 1].to_vec()),
        SqlValue::Blob(vec![0; 164]),
        SqlValue::Blob(replacement),
        SqlValue::Text("foreign-row".into()),
        SqlValue::Integer(7),
    ] {
        foreign
            .execute(
                "UPDATE archive_nodes SET data=? WHERE id=?",
                params![corrupt, leaf.id.as_slice()],
            )
            .unwrap();
        compare();
        foreign
            .execute(
                "UPDATE archive_nodes SET data=? WHERE id=?",
                params![&bytes, leaf.id.as_slice()],
            )
            .unwrap();
        assert_eq!(
            observed_decode_cache(&db, &root, &state, Some(&cache), usize::MAX),
            (Ok(()), 15)
        );
    }
    foreign
        .execute("DELETE FROM archive_nodes WHERE id=?", [leaf.id.as_slice()])
        .unwrap();
    compare();
    foreign
        .execute(
            "INSERT INTO archive_nodes(id,data) VALUES(?,?)",
            params![leaf.id.as_slice(), &bytes],
        )
        .unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    db.execute(
        "UPDATE archive_nodes SET data=X'00' WHERE id=?",
        [leaf.id.as_slice()],
    )
    .unwrap();
    let hot = observed_decode_cache(&db, &root, &state, Some(&cache), usize::MAX);
    assert_eq!(
        hot,
        observed_decode_cache(&db, &root, &state, None, usize::MAX)
    );
    assert!(hot.0.is_err());
    db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        observed_decode_cache(&db, &root, &state, Some(&cache), usize::MAX),
        (Ok(()), 15)
    );
}

#[test]
fn native_hot_decode_cache_keeps_graph_state_trigger_and_cancellation_fences() {
    let db = Connection::open_in_memory().unwrap();
    let (state, root) = decode_cache_fixture(&db);
    let cache = native_store::LiftCache::default();
    assert_eq!(
        observed_decode_cache(&db, &root, &state, Some(&cache), usize::MAX),
        (Ok(()), 15)
    );
    for stop in [1, 2, 7, 15, 16] {
        let hot = observed_decode_cache(&db, &root, &state, Some(&cache), stop);
        assert_eq!(hot, observed_decode_cache(&db, &root, &state, None, stop));
        if stop <= 15 {
            let error = hot.0.unwrap_err();
            assert_eq!(error.1, Some(ErrorCode::PublicRequestCancelled));
            assert_ne!(error.0, ErrorKind::LocalStructure);
        }
    }
    let mut wrong_state = state.clone();
    wrong_state.values_mut().next().unwrap()["nonce"] = json!(99);
    let mut wrong_roots = Vec::new();
    let mut wrong = root.clone();
    wrong.count = 65_537;
    wrong_roots.push(wrong);
    let mut wrong = root.clone();
    wrong.balance += 1;
    wrong_roots.push(wrong);
    let mut wrong = root.clone();
    wrong.digest[0] ^= 1;
    wrong_roots.push(wrong);
    for (root, state) in wrong_roots
        .iter()
        .map(|root| (root, &state))
        .chain([(&root, &wrong_state)])
    {
        let hot = observed_decode_cache(&db, root, state, Some(&cache), usize::MAX);
        assert_eq!(
            hot,
            observed_decode_cache(&db, root, state, None, usize::MAX)
        );
        assert_eq!(hot.0.unwrap_err().0, ErrorKind::LocalStructure);
    }
    let parent = load_node(&db, root.node.unwrap()).unwrap();
    let Kind::Fork {
        left,
        right,
        left_hash,
        right_hash,
    } = parent.kind
    else {
        panic!("fork required")
    };
    // The fork itself has canonical bytes and a correct content ID. Its actual
    // child relation is wrong; retaining decode math must never validate it.
    let mut bad = parent;
    bad.kind = Kind::Fork {
        left: right,
        right: left,
        left_hash,
        right_hash,
    };
    bad.id = hash(b"account-archive-node-record-v1", &[&bad.encode()]);
    save_node(&db, &bad).unwrap();
    let mut wrong = root.clone();
    wrong.node = Some(bad.id);
    for _ in 0..2 {
        let hot = observed_decode_cache(&db, &wrong, &state, Some(&cache), usize::MAX);
        assert_eq!(
            hot,
            observed_decode_cache(&db, &wrong, &state, None, usize::MAX)
        );
        assert_eq!(hot.0.unwrap_err().0, ErrorKind::LocalStructure);
    }
    db.execute_batch(&format!(
        "CREATE TEMP TABLE decode_probe(value INTEGER); CREATE TEMP TRIGGER decode_probe_change AFTER INSERT ON decode_probe BEGIN UPDATE archive_nodes SET data=X'00' WHERE id=X'{}'; END;",
        hex::encode(right),
    )).unwrap();
    let mut observations = Vec::new();
    for lifts in [None, Some(&cache)] {
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut visits = 0;
        let result = native_store::verify_with_lifts(
            &db,
            &root,
            &state,
            &mut || {
                visits += 1;
                if visits == 1 {
                    db.execute("INSERT INTO decode_probe VALUES(1)", [])?;
                }
                Ok(())
            },
            lifts,
        );
        observations.push((verdict(result), visits));
        db.execute_batch("ROLLBACK").unwrap();
    }
    assert_eq!(observations[0], observations[1]);
    assert_eq!(
        observations[0].0.as_ref().unwrap_err().0,
        ErrorKind::LocalStructure
    );
    assert_eq!(observations[0].1, 1);
    assert_eq!(
        observed_decode_cache(&db, &root, &state, Some(&cache), usize::MAX),
        (Ok(()), 15)
    );
}
