//! Actual signed ordinary Node graphs, not injected account State or a Growth
//! namespace. The unchanged no-scope verifier is the differential reference.
use super::*;
use trnm_protocol::pon_wire::{hash, Envelope};

struct TwoRoots {
    fixture: Fixture,
    parent: Hash,
    child: Hash,
    before: State,
    after: State,
}

fn transfer(settings: &Settings, nonce: u64, recipient: Hash) -> Vec<u8> {
    let mut payload = recipient.to_vec();
    payload.extend(1u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: crate::development_public(0).unwrap(),
        nonce,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&0u64.to_le_bytes()],
    )))
    .unwrap();
    tx.signature = hex::decode(trnm_crypto_primitives::sign_hex(
        &key,
        &tx.signing_digest().unwrap(),
    ))
    .unwrap()
    .try_into()
    .unwrap();
    tx.encode().unwrap()
}

fn two_roots() -> TwoRoots {
    let mut f = fixture();
    let transactions = (1..=64u64)
        .map(|nonce| {
            transfer(
                &f.node.settings,
                nonce,
                hash(b"frontier-real-funded-account", &[&nonce.to_le_bytes()]),
            )
        })
        .collect();
    let packet = f
        .node
        .make_consensus_maintenance(
            f.node.settings.genesis(),
            transactions,
            crate::development_public(0).unwrap(),
            11,
            4096,
        )
        .unwrap();
    let parent = f.node.admit(&packet, 100_000).unwrap();
    let packet = f
        .node
        .make_consensus_maintenance(
            parent,
            vec![transfer(
                &f.node.settings,
                65,
                crate::development_public(1).unwrap(),
            )],
            crate::development_public(0).unwrap(),
            21,
            4096,
        )
        .unwrap();
    let child = f.node.admit(&packet, 100_000).unwrap();
    let before = f.node.state_at(parent).unwrap();
    let after = f.node.state_at(child).unwrap();
    let first = load_observed(&f.node.db, parent, None).unwrap();
    let second = load_observed(&f.node.db, child, None).unwrap();
    assert_ne!(first.accounts, second.accounts);
    assert_eq!(first.accounts.count, second.accounts.count);
    assert_eq!(first.accounts.count, 68);
    TwoRoots {
        fixture: f,
        parent,
        child,
        before,
        after,
    }
}

fn source_scope(f: &TwoRoots) -> PostWriteReadback<'_> {
    let node = &f.fixture.node;
    let mut scope = capture(node, f.child);
    verify(node, f.child, &f.after, &mut scope, &mut || Ok(())).unwrap();
    let frontier = scope.frontier.as_ref().unwrap();
    assert!((2..=16).contains(&frontier.occupied_slots()));
    assert!(std::mem::size_of_val(frontier) <= 4096);
    assert_eq!(
        frontier.source_record(),
        load_observed(&node.db, f.child, None).unwrap().id
    );
    assert!(!scope.consumed);
    scope
}

fn reference(
    node: &Node,
    block: Hash,
    state: &State,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    super::super::super::verify_state_with_cache(
        &node.db,
        &node.settings,
        block,
        state,
        progress,
        Some(&node.authenticated_arithmetic),
    )
}

#[test]
fn real_different_roots_use_bounded_subtrees_without_promoting_partial_results() {
    let mut f = two_roots();
    let node = &mut f.fixture.node;
    let packet = node
        .make_consensus_maintenance(
            f.child,
            vec![transfer(
                &node.settings,
                66,
                crate::development_public(2).unwrap(),
            )],
            crate::development_public(0).unwrap(),
            31,
            4096,
        )
        .unwrap();
    let fifth = node.admit(&packet, 100_000).unwrap();
    let fifth_state = node.state_at(fifth).unwrap();
    node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(node, f.child);
    verify(node, fifth, &fifth_state, &mut scope, &mut || Ok(())).unwrap();
    assert!(scope.frontier.is_none());
    assert!(scope.graphs.iter().all(Option::is_none));
    drop(scope);
    let mut scope = source_scope(&f);
    let node = &f.fixture.node;
    let current = load_observed(&node.db, f.parent, None).unwrap();
    assert!(scope
        .graphs
        .iter()
        .flatten()
        .all(|graph| graph.record.accounts != current.accounts));
    let ids = scope.ids;
    let source = scope.frontier.as_ref().unwrap().source_record();
    let mut original = 0u64;
    reference(node, f.parent, &f.before, &mut || {
        original += 1;
        Ok(())
    })
    .unwrap();
    let mut partial = 0u64;
    verify(node, f.parent, &f.before, &mut scope, &mut || {
        partial += 1;
        Ok(())
    })
    .unwrap();
    assert!(
        partial > 5 && partial < original,
        "original={original} partial={partial}"
    );
    assert_eq!(scope.hits, 0); // No whole-Root match accounts for the observation.
    assert_eq!(scope.partial_uses, 1);
    assert!(scope.subtree_hits >= 2);
    assert!(scope.consumed);
    assert_eq!(scope.ids, ids);
    assert_eq!(scope.graphs[2].as_ref().unwrap().source, Some(source));
    assert_eq!(scope.frontier.as_ref().unwrap().source_record(), source);
    verify(node, f.parent, &f.before, &mut scope, &mut || Ok(())).unwrap();
    assert_eq!(scope.partial_uses, 1); // The original frontier was used only once.
    assert_eq!(scope.hits, 1); // The same four-slot completed result was borrowed.
    assert_eq!(scope.graphs[2].as_ref().unwrap().source, Some(source));

    let before = (graphs(node), scope.partial_uses, scope.subtree_hits);
    for _ in 0..2 {
        let mut actual = 0u64;
        verify(node, fifth, &fifth_state, &mut scope, &mut || {
            actual += 1;
            Ok(())
        })
        .unwrap();
        let mut expected = 0u64;
        reference(node, fifth, &fifth_state, &mut || {
            expected += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(actual, expected); // Fifth ID cannot borrow even a subtree.
    }
    assert_eq!(graphs(node) - before.0, 4);
    assert_eq!(
        (scope.partial_uses, scope.subtree_hits),
        (before.1, before.2)
    );

    let owner = format!(
        "account:{}",
        hex::encode(crate::development_public(0).unwrap())
    );
    for change in ["nonce", "zero-account", "field", "liability"] {
        let mut changed = f.before.clone();
        match change {
            "nonce" => changed.get_mut(&owner).unwrap()["nonce"] = serde_json::json!(63),
            "zero-account" => {
                changed.insert(
                    format!("account:{}", "ab".repeat(32)),
                    serde_json::json!({"balance":0,"nonce":9}),
                );
            }
            "field" => changed.get_mut(&owner).unwrap()["extra"] = serde_json::json!(0),
            "liability" => {
                let key = changed
                    .keys()
                    .find(|key| key.starts_with("reward:"))
                    .unwrap()
                    .clone();
                let amount = changed[&key]["amount"].as_u64().unwrap();
                changed.get_mut(&key).unwrap()["amount"] = serde_json::json!(amount + 1);
            }
            _ => unreachable!(),
        }
        let expected = reference(node, f.parent, &changed, &mut || Ok(())).unwrap_err();
        let error = verify(node, f.parent, &changed, &mut scope, &mut || Ok(())).unwrap_err();
        assert_eq!(error.to_string(), expected.to_string(), "{change}");
        assert_eq!(scope.partial_uses, 1);
    }
    node.db.execute_batch("ROLLBACK").unwrap();
}

fn raw(db: &Connection, id: Hash) -> Vec<u8> {
    db.query_row(
        "SELECT data FROM archive_nodes WHERE id=?",
        [id.as_slice()],
        |row| row.get(0),
    )
    .unwrap()
}

fn child_id(bytes: &[u8], offset: usize) -> Hash {
    bytes[offset..offset + 32].try_into().unwrap()
}

fn contains(db: &Connection, root: Hash, wanted: Hash) -> bool {
    if root == wanted {
        return true;
    }
    let bytes = raw(db, root);
    bytes[0] == 1
        && (contains(db, child_id(&bytes, 35), wanted)
            || contains(db, child_id(&bytes, 67), wanted))
}

fn shared_frontier_fork(f: &TwoRoots) -> Hash {
    let db = &f.fixture.node.db;
    let source = load_observed(db, f.child, None)
        .unwrap()
        .accounts
        .node
        .unwrap();
    let target = load_observed(db, f.parent, None)
        .unwrap()
        .accounts
        .node
        .unwrap();
    let mut stack = vec![source];
    while let Some(id) = stack.pop() {
        let bytes = raw(db, id);
        if bytes[0] == 0 {
            continue;
        }
        assert_eq!(bytes.len(), 163);
        let depth = u16::from_le_bytes(bytes[1..3].try_into().unwrap());
        if depth >= 4 {
            if contains(db, target, id) {
                return id;
            }
            continue;
        }
        stack.push(child_id(&bytes, 67));
        stack.push(child_id(&bytes, 35));
    }
    panic!("real signed two-account change has no shared frontier fork");
}

fn insert_raw(db: &Connection, bytes: &[u8]) -> Hash {
    let id = hash(b"account-archive-node-record-v1", &[bytes]);
    db.execute(
        "INSERT OR IGNORE INTO archive_nodes VALUES(?,?)",
        rusqlite::params![id.as_slice(), bytes],
    )
    .unwrap();
    id
}

// Copy only actual ancestor IDs. Path/depth and BOTH child hashes remain byte
// identical, so all account digests stay unchanged while availability changes.
fn replace_id(db: &Connection, current: Hash, old: Hash, new: Hash) -> Option<Hash> {
    if current == old {
        return Some(new);
    }
    let mut bytes = raw(db, current);
    if bytes[0] == 0 {
        return None;
    }
    for offset in [35, 67] {
        if let Some(replacement) = replace_id(db, child_id(&bytes, offset), old, new) {
            bytes[offset..offset + 32].copy_from_slice(&replacement);
            return Some(insert_raw(db, &bytes));
        }
    }
    None
}

fn write_record(db: &Connection, record: &mut Record) {
    record.id = record.digest().unwrap();
    db.execute(
        "UPDATE native_state_commitments SET data=? WHERE block=?",
        rusqlite::params![
            super::super::super::canonical(record).unwrap(),
            record.block.as_slice()
        ],
    )
    .unwrap();
}

#[test]
fn reencoded_frontier_child_ids_cannot_hide_missing_nodes_or_wrong_side_edges() {
    let f = two_roots();
    let node = &f.fixture.node;
    let original_parent = load_observed(&node.db, f.parent, None).unwrap();
    let original_child = load_observed(&node.db, f.child, None).unwrap();
    let fork = shared_frontier_fork(&f);
    let original = raw(&node.db, fork);
    for change in ["missing", "wrong-side"] {
        let mut damaged = original.clone();
        let pointer = if change == "missing" {
            let missing = hash(b"frontier-absent-child", &[&fork]);
            assert_eq!(
                node.db
                    .query_row(
                        "SELECT COUNT(*) FROM archive_nodes WHERE id=?",
                        [missing.as_slice()],
                        |row| row.get::<_, u64>(0)
                    )
                    .unwrap(),
                0
            );
            missing
        } else {
            child_id(&original, 67)
        };
        damaged[35..67].copy_from_slice(&pointer);
        let bad_fork = insert_raw(&node.db, &damaged);
        assert_ne!(bad_fork, fork);
        assert_eq!(&damaged[1..35], &original[1..35]);
        assert_eq!(&damaged[99..], &original[99..]);
        let mut parent = original_parent.clone();
        parent.accounts.node = replace_id(&node.db, parent.accounts.node.unwrap(), fork, bad_fork);
        assert!(parent.accounts.node.is_some());
        assert_eq!(parent.accounts.digest, original_parent.accounts.digest);
        assert_eq!(parent.accounts.count, original_parent.accounts.count);
        assert_eq!(parent.accounts.balance, original_parent.accounts.balance);
        write_record(&node.db, &mut parent);
        // Keep every CURRENT Record/parent-commitment binding valid. The source
        // child's account graph still names the original, available subtree.
        let mut child = original_child.clone();
        child.parent_commitment = Some(parent.id);
        write_record(&node.db, &mut child);
        node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut scope = source_scope(&f);
        let expected = reference(node, f.parent, &f.before, &mut || Ok(())).unwrap_err();
        let error = verify(node, f.parent, &f.before, &mut scope, &mut || Ok(())).unwrap_err();
        assert!(expected.to_string().starts_with("NATIVE_ACCOUNT_STORE"));
        assert_eq!(error.to_string(), expected.to_string(), "{change}");
        assert_eq!(scope.partial_uses, 0);
        assert!(!scope.consumed);
        drop(scope);
        node.db.execute_batch("ROLLBACK").unwrap();
        write_record(&node.db, &mut original_parent.clone());
        write_record(&node.db, &mut original_child.clone());
    }
}

#[test]
fn partial_cancellation_and_no_row_writes_keep_original_boundaries_and_sticky_fences() {
    let f = two_roots();
    let node = &f.fixture.node;
    node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = source_scope(&f);
    let mut callbacks = 0usize;
    verify(node, f.parent, &f.before, &mut scope, &mut || {
        callbacks += 1;
        Ok(())
    })
    .unwrap();
    assert!(scope.subtree_hits >= 2);
    drop(scope);
    node.db.execute_batch("ROLLBACK").unwrap();

    for cancel_at in [1, callbacks - 1, callbacks] {
        node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut scope = source_scope(&f);
        let mut current = 0;
        let error = verify(node, f.parent, &f.before, &mut scope, &mut || {
            current += 1;
            if current == cancel_at {
                Err("FRONTIER_CANCELLED".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "FRONTIER_CANCELLED");
        assert_eq!(scope.partial_uses, 0);
        assert!(!scope.consumed);
        drop(scope);
        node.db.execute_batch("ROLLBACK").unwrap();
    }

    for write_at in [1, callbacks - 1, callbacks] {
        node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut scope = source_scope(&f);
        let before = (graphs(node), node.db.total_changes());
        let mut current = 0;
        verify(node, f.parent, &f.before, &mut scope, &mut || {
            current += 1;
            if current == write_at {
                node.db
                    .execute("UPDATE archive_nodes SET data=data WHERE 0", [])?;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(node.db.total_changes(), before.1);
        assert_eq!(graphs(node) - before.0, if write_at == 1 { 1 } else { 2 });
        assert!(!scope.enabled);
        assert!(scope.frontier.is_none());
        assert_eq!(scope.partial_uses, 0);
        assert!(!scope.consumed);
        let before = graphs(node);
        verify(node, f.parent, &f.before, &mut scope, &mut || Ok(())).unwrap();
        assert_eq!(graphs(node) - before, 1);
        assert!(scope.frontier.is_none());
        drop(scope);
        node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn final_callback_deletion_and_later_outer_write_cannot_use_partial_availability() {
    let f = two_roots();
    let node = &f.fixture.node;
    let descendant = child_id(&raw(&node.db, shared_frontier_fork(&f)), 35);
    node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = source_scope(&f);
    let mut callbacks = 0;
    verify(node, f.parent, &f.before, &mut scope, &mut || {
        callbacks += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(scope.partial_uses, 1);
    node.db
        .execute("UPDATE archive_nodes SET data=data WHERE 0", [])
        .unwrap();
    let error = scope.validate_consumed(&node.db).unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_POST_WRITE_CHANGED");
    assert!(scope.frontier.is_none());
    drop(scope);
    node.db.execute_batch("ROLLBACK").unwrap();

    node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = source_scope(&f);
    let before = graphs(node);
    let mut current = 0;
    let error = verify(node, f.parent, &f.before, &mut scope, &mut || {
        current += 1;
        if current == callbacks {
            assert_eq!(
                node.db.execute(
                    "DELETE FROM archive_nodes WHERE id=?",
                    [descendant.as_slice()]
                )?,
                1
            );
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.to_string().starts_with("NATIVE_ACCOUNT_STORE"));
    assert_eq!(graphs(node) - before, 2); // Partial then the real original fallback.
    assert_eq!(scope.partial_uses, 0);
    assert!(!scope.consumed);
    assert!(scope.frontier.is_none());
    drop(scope);
    node.db.execute_batch("ROLLBACK").unwrap();
}

struct MetadataFrontierFixture {
    roots: TwoRoots,
    child: Hash,
    state: State,
}

fn metadata_frontier_fixture() -> MetadataFrontierFixture {
    let mut roots = two_roots();
    roots.fixture.node.activate(roots.parent).unwrap();
    let node = &mut roots.fixture.node;
    let packet = node
        .make_consensus_maintenance(
            roots.child,
            vec![],
            crate::development_public(0).unwrap(),
            31,
            4096,
        )
        .unwrap();
    let child = node.admit(&packet, 100_000).unwrap();
    let state = node.state_at(child).unwrap();
    let source = load_observed(&node.db, roots.child, None).unwrap();
    let current = load_observed(&node.db, child, None).unwrap();
    let active = load_observed(&node.db, roots.parent, None).unwrap();
    assert_eq!(current.accounts, source.accounts);
    assert_ne!(current.accounts, active.accounts);
    assert_eq!(node.active().unwrap().0, roots.parent);
    MetadataFrontierFixture {
        roots,
        child,
        state,
    }
}

fn prepare_frontier_metadata<'db>(f: &'db MetadataFrontierFixture) -> PreparedMetadataInsert<'db> {
    let prepared = prepare_frontier_metadata_with_progress(f, &mut || Ok(()));
    let frontier = prepared.graph.frontier.as_ref().unwrap();
    assert!((2..=16).contains(&frontier.occupied_slots()));
    assert!(frontier.is_for(
        prepared.record.parent_commitment.unwrap(),
        &prepared.record.accounts,
    ));
    assert!(!prepared.graph.consumed);
    prepared
}

fn prepare_frontier_metadata_with_progress<'db>(
    f: &'db MetadataFrontierFixture,
    progress: &mut dyn FnMut() -> Result<()>,
) -> PreparedMetadataInsert<'db> {
    let node = &f.roots.fixture.node;
    let record = load_observed(&node.db, f.child, None).unwrap();
    assert_eq!(record.parent, Some(f.roots.child));
    node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let owner = TransactionScope::capture(&node.db).unwrap();
    assert_eq!(
        node.db
            .execute(
                "DELETE FROM native_state_commitments WHERE block=?",
                [f.child.as_slice()],
            )
            .unwrap(),
        1
    );
    let rows =
        super::super::super::deltas_with_progress(&node.db, f.child, &mut || Ok(())).unwrap();
    assert!(rows.iter().all(|row| !row.0.starts_with("account:")));
    let mut graph = PostWriteReadback::new(
        &node.db,
        &node.settings,
        f.roots.child,
        &owner,
        node.post_write_schema.as_ref().unwrap(),
    )
    .unwrap()
    .unwrap();
    verify(node, f.roots.child, &f.roots.after, &mut graph, progress).unwrap();
    PreparedMetadataInsert {
        owner,
        graph,
        record,
        rows,
    }
}

#[test]
fn metadata_frontier_preserves_actual_active_reader_without_another_graph_walk() {
    let f = metadata_frontier_fixture();
    let node = &f.roots.fixture.node;
    let prepared = prepare_frontier_metadata(&f);
    let source = prepared.graph.frontier.as_ref().unwrap().source_record();
    let mut scope = prepared.save(node).unwrap();
    assert!(scope.metadata_insert_seeded);
    verify(node, f.child, &f.state, &mut scope, &mut || Ok(())).unwrap();

    // Both calls use the ORIGINAL Node active reader, current SQL KV and the
    // same real signed blocks. The reference omits only optional graph facts.
    let mut original = 0u64;
    node.check_active_before_commit_with_readback(
        &mut || {
            original += 1;
            Ok(())
        },
        None,
    )
    .unwrap();
    let mut scoped = 0u64;
    node.check_active_before_commit_with_readback(
        &mut || {
            scoped += 1;
            Ok(())
        },
        Some(&mut scope),
    )
    .unwrap();
    eprintln!("metadata_frontier_actual_active original={original} scoped={scoped}");
    assert!(scoped < original);
    assert!(scope.partial_uses > 0);
    assert!(scope.subtree_hits > 0);
    assert_eq!(scope.frontier.as_ref().unwrap().source_record(), source);
    assert_eq!(
        scope.ids,
        [
            Some(f.child),
            Some(node.settings.genesis()),
            Some(f.roots.child),
            Some(f.roots.parent),
        ]
    );
    scope.require_unchanged_after_last_write(&node.db).unwrap();
    drop(scope);
    node.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(node.state_at(f.child).unwrap(), f.state);
    assert_eq!(node.read_active().unwrap().0, f.roots.parent);
}

fn another_metadata_child(f: &mut MetadataFrontierFixture) -> (Hash, State) {
    let node = &mut f.roots.fixture.node;
    let packet = node
        .make_consensus_maintenance(
            f.roots.child,
            vec![],
            crate::development_public(0).unwrap(),
            41,
            4096,
        )
        .unwrap();
    let child = node.admit(&packet, 100_000).unwrap();
    let state = node.state_at(child).unwrap();
    assert_ne!(child, f.child);
    assert_eq!(
        load_observed(&node.db, child, None).unwrap().accounts,
        load_observed(&node.db, f.child, None).unwrap().accounts
    );
    (child, state)
}

fn actual_active_calls(
    node: &Node,
    scope: Option<&mut PostWriteReadback<'_>>,
) -> (Result<()>, u64) {
    let mut calls = 0;
    let result = node.check_active_before_commit_with_readback(
        &mut || {
            calls += 1;
            Ok(())
        },
        scope,
    );
    (result, calls)
}

#[test]
fn metadata_frontier_rejects_another_real_source_even_when_its_root_matches() {
    for same_root in [false, true] {
        let mut f = metadata_frontier_fixture();
        let (foreign_id, foreign_state) = if same_root {
            another_metadata_child(&mut f)
        } else {
            (f.roots.parent, f.roots.before.clone())
        };
        let node = &f.roots.fixture.node;
        let mut prepared = prepare_frontier_metadata(&f);
        let mut other = capture(node, foreign_id);
        verify(node, foreign_id, &foreign_state, &mut other, &mut || Ok(())).unwrap();
        let foreign = other.frontier.take().unwrap();
        let original = &prepared.graph.graphs[0].as_ref().unwrap().record;
        assert_ne!(foreign.source_record(), original.id);
        assert_eq!(
            load_observed(&node.db, foreign_id, None).unwrap().accounts == original.accounts,
            same_root
        );
        assert!(!foreign.is_for(original.id, &original.accounts));
        // The substituted fact was really minted by another complete native
        // reader. Neither a caller-provided fake proof nor a forged Root is used.
        prepared.graph.frontier = Some(foreign);
        drop(other);
        let mut scope = prepared.save(node).unwrap();
        assert!(scope.metadata_insert_seeded);
        assert!(scope.frontier.is_none());
        verify(node, f.child, &f.state, &mut scope, &mut || Ok(())).unwrap();
        let (expected, full) = actual_active_calls(node, None);
        let (actual, observed) = actual_active_calls(node, Some(&mut scope));
        expected.unwrap();
        actual.unwrap();
        assert_eq!(observed, full);
        assert_eq!(scope.partial_uses, 0);
        scope.require_unchanged_after_last_write(&node.db).unwrap();
        drop(scope);
        node.db.execute_batch("ROLLBACK").unwrap();
        assert_eq!(node.read_active().unwrap().0, f.roots.parent);
    }
}

#[test]
fn metadata_frontier_does_not_nominate_a_fifth_same_root_record() {
    let mut f = metadata_frontier_fixture();
    let (fifth, fifth_state) = another_metadata_child(&mut f);
    let node = &f.roots.fixture.node;
    let prepared = prepare_frontier_metadata(&f);
    let source = prepared.graph.frontier.as_ref().unwrap().source_record();
    let mut scope = prepared.save(node).unwrap();
    actual_active_calls(node, Some(&mut scope)).0.unwrap();
    assert!(scope.partial_uses > 0);
    assert_eq!(
        scope.ids,
        [
            Some(f.child),
            Some(node.settings.genesis()),
            Some(f.roots.child),
            Some(f.roots.parent),
        ]
    );
    assert!(!scope.ids.contains(&Some(fifth)));
    let before = (scope.hits, scope.partial_uses, scope.subtree_hits);
    let mut full = 0;
    reference(node, fifth, &fifth_state, &mut || {
        full += 1;
        Ok(())
    })
    .unwrap();
    let mut observed = 0;
    verify(node, fifth, &fifth_state, &mut scope, &mut || {
        observed += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(observed, full);
    assert_eq!(before, (scope.hits, scope.partial_uses, scope.subtree_hits));
    assert_eq!(scope.frontier.as_ref().unwrap().source_record(), source);
    scope.require_unchanged_after_last_write(&node.db).unwrap();
    drop(scope);
    node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn metadata_frontier_extra_sql_and_graph_damage_keep_the_original_fallback() {
    for stage in [
        MetadataInsertStage::BeforeSave,
        MetadataInsertStage::AfterSave,
        MetadataInsertStage::AfterCapture,
        MetadataInsertStage::AfterSeed,
    ] {
        for effect in ["no-row", "same-row", "ddl-aba", "missing-subtree"] {
            let f = metadata_frontier_fixture();
            let node = &f.roots.fixture.node;
            let descendant = child_id(&raw(&node.db, shared_frontier_fork(&f.roots)), 35);
            let prepared = prepare_frontier_metadata(&f);
            let source = prepared.graph.frontier.as_ref().unwrap().source_record();
            let _hook = MetadataHookGuard::install(move |db, observed| {
                if observed == stage {
                    match effect {
                        "no-row" => {
                            db.execute("UPDATE archive_nodes SET data=data WHERE 0", [])?;
                        }
                        "same-row" => {
                            db.execute("UPDATE archive_nodes SET data=data", [])?;
                        }
                        "ddl-aba" => {
                            db.execute_batch(
                                "CREATE TABLE metadata_frontier_probe(x); DROP TABLE metadata_frontier_probe",
                            )?;
                        }
                        "missing-subtree" => {
                            assert_eq!(
                                db.execute(
                                    "DELETE FROM archive_nodes WHERE id=?",
                                    [descendant.as_slice()],
                                )?,
                                1
                            );
                        }
                        _ => unreachable!(),
                    }
                }
                Ok(())
            });
            let mut scope = prepared.save(node).unwrap();
            scope.current(&node.db).unwrap();
            assert!(scope.frontier.is_none(), "{stage:?} {effect}");
            if stage != MetadataInsertStage::AfterSeed {
                assert!(!scope.metadata_insert_seeded, "{stage:?} {effect}");
            }
            let (expected, full) = actual_active_calls(node, None);
            let before = graphs(node);
            let (actual, observed) = actual_active_calls(node, Some(&mut scope));
            assert_eq!(
                actual.as_ref().err().map(ToString::to_string),
                expected.as_ref().err().map(ToString::to_string),
                "{stage:?} {effect}"
            );
            assert_eq!(actual.is_ok(), effect != "missing-subtree");
            assert_eq!(observed, full, "{stage:?} {effect}");
            assert!(graphs(node) > before);
            assert_eq!(scope.partial_uses, 0);
            assert_eq!(scope.subtree_hits, 0);
            assert!(
                scope
                    .frontier
                    .as_ref()
                    .is_none_or(|frontier| { frontier.source_record() != source }),
                "{stage:?} {effect}"
            );
            drop(scope);
            node.db.execute_batch("ROLLBACK").unwrap();
            assert_eq!(node.read_active().unwrap().0, f.roots.parent);
        }
    }
}

#[test]
fn metadata_frontier_final_parent_callback_cannot_certify_a_missing_subtree() {
    let f = metadata_frontier_fixture();
    let node = &f.roots.fixture.node;
    let descendant = child_id(&raw(&node.db, shared_frontier_fork(&f.roots)), 35);
    let mut callbacks = 0;
    let prepared = prepare_frontier_metadata_with_progress(&f, &mut || {
        callbacks += 1;
        Ok(())
    });
    assert!(callbacks > 100);
    assert!(prepared.graph.frontier.is_some());
    drop(prepared);
    node.db.execute_batch("ROLLBACK").unwrap();

    let mut current = 0;
    let prepared = prepare_frontier_metadata_with_progress(&f, &mut || {
        current += 1;
        if current == callbacks {
            assert_eq!(
                node.db.execute(
                    "DELETE FROM archive_nodes WHERE id=?",
                    [descendant.as_slice()],
                )?,
                1
            );
        }
        Ok(())
    });
    assert_eq!(current, callbacks);
    assert!(prepared.graph.frontier.is_none());
    assert!(prepared.graph.graphs.iter().all(Option::is_none));
    let mut scope = prepared.save(node).unwrap();
    assert!(!scope.metadata_insert_seeded);
    assert!(scope.frontier.is_none());
    assert!(actual_active_calls(node, Some(&mut scope)).0.is_err());
    assert_eq!(scope.partial_uses, 0);
    drop(scope);
    node.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(node.state_at(f.child).unwrap(), f.state);
}

#[test]
fn metadata_frontier_keeps_partial_cancellation_and_final_callback_readback() {
    let f = metadata_frontier_fixture();
    let node = &f.roots.fixture.node;
    let descendant = child_id(&raw(&node.db, shared_frontier_fork(&f.roots)), 35);
    let prepared = prepare_frontier_metadata(&f);
    let mut scope = prepared.save(node).unwrap();
    scope
        .nominate_active(&node.db, node.active().unwrap().0)
        .unwrap();
    let mut callbacks = 0;
    verify(
        node,
        f.roots.parent,
        &f.roots.before,
        &mut scope,
        &mut || {
            callbacks += 1;
            Ok(())
        },
    )
    .unwrap();
    assert!(scope.partial_uses > 0);
    assert!(scope.subtree_hits > 0);
    assert!(scope.graphs[3].as_ref().unwrap().source.is_some());
    drop(scope);
    node.db.execute_batch("ROLLBACK").unwrap();

    for cancel_at in [1, callbacks - 1, callbacks] {
        let prepared = prepare_frontier_metadata(&f);
        let mut scope = prepared.save(node).unwrap();
        scope
            .nominate_active(&node.db, node.active().unwrap().0)
            .unwrap();
        let source = scope.frontier.as_ref().unwrap().source_record();
        let mut current = 0;
        let error = verify(
            node,
            f.roots.parent,
            &f.roots.before,
            &mut scope,
            &mut || {
                current += 1;
                if current == cancel_at {
                    Err("METADATA_FRONTIER_CANCELLED".into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "METADATA_FRONTIER_CANCELLED");
        assert_eq!(scope.partial_uses, 0);
        assert!(!scope.consumed);
        assert!(scope.graphs[3].is_none());
        assert_eq!(scope.frontier.as_ref().unwrap().source_record(), source);
        drop(scope);
        node.db.execute_batch("ROLLBACK").unwrap();
    }

    let prepared = prepare_frontier_metadata(&f);
    let mut scope = prepared.save(node).unwrap();
    scope
        .nominate_active(&node.db, node.active().unwrap().0)
        .unwrap();
    let before = graphs(node);
    let mut current = 0;
    let error = verify(
        node,
        f.roots.parent,
        &f.roots.before,
        &mut scope,
        &mut || {
            current += 1;
            if current == callbacks {
                assert_eq!(
                    node.db.execute(
                        "DELETE FROM archive_nodes WHERE id=?",
                        [descendant.as_slice()],
                    )?,
                    1
                );
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.to_string().starts_with("NATIVE_ACCOUNT_STORE"));
    assert_eq!(graphs(node) - before, 2);
    assert_eq!(scope.partial_uses, 0);
    assert!(!scope.consumed);
    assert!(scope.frontier.is_none());
    drop(scope);
    node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn metadata_frontier_original_active_reader_keeps_the_consumed_outer_write_fence() {
    let f = metadata_frontier_fixture();
    let node = &f.roots.fixture.node;
    let prepared = prepare_frontier_metadata(&f);
    let mut scope = prepared.save(node).unwrap();
    actual_active_calls(node, Some(&mut scope)).0.unwrap();
    assert!(scope.partial_uses > 0);
    assert!(scope.consumed);
    node.db
        .execute("UPDATE archive_nodes SET data=data WHERE 0", [])
        .unwrap();
    let error = scope
        .require_unchanged_after_last_write(&node.db)
        .unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_POST_WRITE_CHANGED");
    assert!(scope.frontier.is_none());
    assert_eq!(
        scope.validate_consumed(&node.db).unwrap_err().to_string(),
        "NATIVE_POST_WRITE_CHANGED"
    );
    drop(scope);
    node.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(node.read_active().unwrap().0, f.roots.parent);
}

#[test]
fn metadata_frontier_extra_index_programs_cannot_cross_the_native_insert() {
    for definition in [
        "CREATE INDEX metadata_extra ON native_state_commitments(block)",
        "CREATE INDEX metadata_extra ON native_state_commitments(length(data))",
        "CREATE INDEX metadata_extra ON native_state_commitments(data) WHERE length(data)>0",
        "CREATE INDEX metadata_extra ON native_state_commitments(data COLLATE NOCASE)",
        "CREATE INDEX unrelated_archive_expression ON archive_nodes(length(data))",
    ] {
        let mut f = metadata_frontier_fixture();
        let node = &mut f.roots.fixture.node;
        node.db.execute_batch(definition).unwrap();
        // A deliberately matching expected catalog is not authority to admit
        // an index program on the table actually written by the native helper.
        node.post_write_schema = Some(crate::store::schema(&node.db).unwrap());
        let node = &f.roots.fixture.node;
        let prepared = prepare_frontier_metadata(&f);
        let source = prepared.graph.frontier.as_ref().unwrap().source_record();
        let mut scope = prepared.save(node).unwrap();
        let passive = definition.contains("unrelated_archive");
        assert_eq!(scope.metadata_insert_seeded, passive, "{definition}");
        assert_eq!(scope.frontier.is_some(), passive, "{definition}");
        if passive {
            assert_eq!(scope.frontier.as_ref().unwrap().source_record(), source);
        }
        let (expected, full) = actual_active_calls(node, None);
        let (actual, observed) = actual_active_calls(node, Some(&mut scope));
        expected.unwrap();
        actual.unwrap();
        if passive {
            assert!(observed < full);
            assert!(scope.partial_uses > 0);
        } else {
            assert_eq!(observed, full);
            assert_eq!(scope.partial_uses, 0);
        }
        scope.require_unchanged_after_last_write(&node.db).unwrap();
        drop(scope);
        node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn completed_different_root_reuses_original_scope_without_new_frontier() {
    let f = two_roots();
    let node = &f.fixture.node;
    node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = source_scope(&f);
    let original_ids = scope.ids;
    let frontier = scope.frontier.as_ref().unwrap();
    let source = frontier.source_record();
    let slots = frontier.occupied_slots();
    let before_graphs = graphs(node);
    let mut full = 0;
    reference(node, f.parent, &f.before, &mut || {
        full += 1;
        Ok(())
    })
    .unwrap();
    let mut first = 0;
    verify(node, f.parent, &f.before, &mut scope, &mut || {
        first += 1;
        Ok(())
    })
    .unwrap();
    let mut repeated = 0;
    verify(node, f.parent, &f.before, &mut scope, &mut || {
        repeated += 1;
        Ok(())
    })
    .unwrap();
    eprintln!(
        "completed_graph_actual_callbacks full={full} first={first} repeated={repeated} actual_graphs={}",
        graphs(node) - before_graphs
    );
    assert!(first > 5 && first < full);
    assert!(repeated > 0 && repeated < first);
    assert_eq!(scope.ids, original_ids);
    assert_eq!(scope.frontier.as_ref().unwrap().source_record(), source);
    assert_eq!(scope.frontier.as_ref().unwrap().occupied_slots(), slots);
    assert_eq!(scope.graphs.len(), 4);
    scope.require_unchanged_after_last_write(&node.db).unwrap();
    drop(scope);
    node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn completed_graph_keeps_current_state_record_delta_and_schema_fences() {
    let f = two_roots();
    let node = &f.fixture.node;
    for effect in [
        "same-row",
        "no-row",
        "record-aba",
        "delta-no-row",
        "schema-aba",
        "transaction-aba",
    ] {
        node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut scope = source_scope(&f);
        verify(node, f.parent, &f.before, &mut scope, &mut || Ok(())).unwrap();
        assert!(scope.graphs[2].as_ref().unwrap().source.is_some());
        let source = scope.frontier.as_ref().unwrap().source_record();
        let actual = load_observed(&node.db, f.parent, None).unwrap();
        let before = graphs(node);
        match effect {
            "same-row" => {
                node.db
                    .execute("UPDATE archive_nodes SET data=data", [])
                    .unwrap();
            }
            "no-row" => {
                node.db
                    .execute("UPDATE archive_nodes SET data=data WHERE 0", [])
                    .unwrap();
            }
            "record-aba" => {
                let bytes: Vec<u8> = node
                    .db
                    .query_row(
                        "SELECT data FROM native_state_commitments WHERE block=?",
                        [f.parent.as_slice()],
                        |row| row.get(0),
                    )
                    .unwrap();
                node.db
                    .execute(
                        "UPDATE native_state_commitments SET data=? WHERE block=?",
                        rusqlite::params![b"changed".as_slice(), f.parent.as_slice()],
                    )
                    .unwrap();
                node.db
                    .execute(
                        "UPDATE native_state_commitments SET data=? WHERE block=?",
                        rusqlite::params![bytes, f.parent.as_slice()],
                    )
                    .unwrap();
            }
            "delta-no-row" => {
                node.db.execute("DELETE FROM deltas WHERE 0", []).unwrap();
            }
            "schema-aba" => {
                node.db.execute_batch(
                    "CREATE TEMP VIEW completed_transient AS SELECT 1; DROP VIEW completed_transient"
                ).unwrap();
            }
            "transaction-aba" => {
                node.db.execute_batch("COMMIT; BEGIN IMMEDIATE").unwrap();
            }
            _ => unreachable!(),
        }
        let error = verify(node, f.parent, &f.before, &mut scope, &mut || Ok(())).unwrap_err();
        eprintln!("completed_graph_actual_fence effect={effect} error={error}");
        assert!(
            error.to_string().starts_with("NATIVE_POST_WRITE_"),
            "{effect}: {error}"
        );
        assert_eq!(graphs(node), before, "{effect}");
        // The same visible record/root after ABA never restores the old scope.
        assert_eq!(load_observed(&node.db, f.parent, None).unwrap(), actual);
        assert!(scope
            .frontier
            .as_ref()
            .is_none_or(|frontier| { frontier.source_record() == source }));
        drop(scope);
        node.db.execute_batch("ROLLBACK").unwrap();
    }
}

#[test]
fn completed_graph_hit_keeps_original_entry_final_and_outer_callback_refusals() {
    let f = two_roots();
    let node = &f.fixture.node;
    node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = source_scope(&f);
    verify(node, f.parent, &f.before, &mut scope, &mut || Ok(())).unwrap();
    let mut callbacks = 0;
    verify(node, f.parent, &f.before, &mut scope, &mut || {
        callbacks += 1;
        Ok(())
    })
    .unwrap();
    assert!(callbacks >= 2);
    drop(scope);
    node.db.execute_batch("ROLLBACK").unwrap();

    for refusal in ["cancel", "deadline", "no-row-write", "remove-current-root"] {
        for at in [1, callbacks] {
            node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
            let mut scope = source_scope(&f);
            verify(node, f.parent, &f.before, &mut scope, &mut || Ok(())).unwrap();
            let root = load_observed(&node.db, f.parent, None)
                .unwrap()
                .accounts
                .node
                .unwrap();
            let before_hits = scope.hits;
            let mut current = 0;
            let error = verify(node, f.parent, &f.before, &mut scope, &mut || {
                current += 1;
                if current == at {
                    match refusal {
                        "cancel" => return Err("COMPLETED_GRAPH_CANCELLED".into()),
                        "deadline" => return Err("PUBLIC_REQUEST_DEADLINE".into()),
                        "no-row-write" => {
                            node.db
                                .execute("UPDATE archive_nodes SET data=data WHERE 0", [])?;
                        }
                        "remove-current-root" => {
                            assert_eq!(
                                node.db.execute(
                                    "DELETE FROM archive_nodes WHERE id=?",
                                    [root.as_slice()],
                                )?,
                                1
                            );
                        }
                        _ => unreachable!(),
                    }
                }
                Ok(())
            })
            .unwrap_err();
            assert_eq!(scope.hits, before_hits, "{refusal} at {at}");
            let expected = match refusal {
                "cancel" => "COMPLETED_GRAPH_CANCELLED",
                "deadline" => "PUBLIC_REQUEST_DEADLINE",
                _ => "NATIVE_POST_WRITE_CHANGED",
            };
            assert_eq!(error.to_string(), expected, "{refusal} at {at}");
            drop(scope);
            node.db.execute_batch("ROLLBACK").unwrap();
        }
    }
}

#[test]
fn completed_graph_target_and_original_source_are_not_replaceable() {
    let f = two_roots();
    let node = &f.fixture.node;
    node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = source_scope(&f);
    let record = load_observed(&node.db, f.parent, None).unwrap();
    let ids = scope.ids;
    let source = scope.frontier.as_ref().unwrap().source_record();
    let access = scope
        .graph_access(
            &node.db,
            &node.settings,
            CurrentAccountGraph {
                record: &record,
                state: &f.before,
            },
        )
        .unwrap()
        .unwrap();
    let completed = crate::account_archive_prototype::native_store::scoped_readback::verify(
        access,
        &mut || Ok(()),
        Some(&node.authenticated_arithmetic.lifts),
        None,
    )
    .unwrap();
    let mut wrong = record.clone();
    wrong.id[0] ^= 1;
    let error = scope
        .remember_completed(&node.db, &node.settings, wrong, completed)
        .unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_ACCOUNT_FRONTIER");
    assert!(scope.graphs[2].is_none());
    assert_eq!(scope.ids, ids);
    assert_eq!(scope.frontier.as_ref().unwrap().source_record(), source);

    verify(node, f.parent, &f.before, &mut scope, &mut || Ok(())).unwrap();
    assert!(scope.matches(&node.db, &node.settings, &record).unwrap());
    let original = scope.frontier.take().unwrap();
    // There is no production setter for this test-only corruption. Even an
    // exact same target Root cannot borrow a missing source certificate.
    assert!(!scope.matches(&node.db, &node.settings, &record).unwrap());
    scope.frontier = Some(original);
    assert!(scope.matches(&node.db, &node.settings, &record).unwrap());
    assert_eq!(scope.ids, ids);
    drop(scope);
    node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn completed_graph_never_survives_the_original_transaction() {
    let f = two_roots();
    let node = &f.fixture.node;
    let mut observed = Vec::new();
    for _ in 0..2 {
        node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut scope = source_scope(&f);
        let mut first = 0;
        verify(node, f.parent, &f.before, &mut scope, &mut || {
            first += 1;
            Ok(())
        })
        .unwrap();
        let mut repeated = 0;
        verify(node, f.parent, &f.before, &mut scope, &mut || {
            repeated += 1;
            Ok(())
        })
        .unwrap();
        assert!(repeated < first);
        observed.push((first, repeated));
        drop(scope);
        node.db.execute_batch("COMMIT").unwrap();
    }
    assert_eq!(observed[0], observed[1]);
    // An ordinary independent fresh reader has no loan from either scope.
    let mut full = 0;
    reference(node, f.parent, &f.before, &mut || {
        full += 1;
        Ok(())
    })
    .unwrap();
    assert!(full > observed[0].0);
}

fn completed_graph_rejects_another_original_owner(transaction_aba: bool) {
    let f = two_roots();
    let node = &f.fixture.node;
    node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut original = source_scope(&f);
    let record = load_observed(&node.db, f.parent, None).unwrap();
    let original_source = original.frontier.as_ref().unwrap().source_record();
    let original_ids = original.ids;
    let access = original
        .graph_access(
            &node.db,
            &node.settings,
            CurrentAccountGraph {
                record: &record,
                state: &f.before,
            },
        )
        .unwrap()
        .unwrap();
    let completed = crate::account_archive_prototype::native_store::scoped_readback::verify(
        access,
        &mut || Ok(()),
        Some(&node.authenticated_arithmetic.lifts),
        None,
    )
    .unwrap();
    assert_eq!(completed.source_used(), Some(original_source));
    // The actual fully traversed result outlives this owner. Its retained opaque
    // identity must not be replaced by a new equal SQL/Record/Root/source tuple.
    drop(original);
    if transaction_aba {
        node.db.execute_batch("COMMIT; BEGIN IMMEDIATE").unwrap();
    }
    let mut next = source_scope(&f);
    assert_eq!(next.ids, original_ids);
    assert_eq!(
        next.frontier.as_ref().unwrap().source_record(),
        original_source
    );
    assert_eq!(load_observed(&node.db, f.parent, None).unwrap(), record);
    assert!(next.graphs[2].is_none());
    let error = next
        .remember_completed(&node.db, &node.settings, record.clone(), completed)
        .unwrap_err();
    eprintln!(
        "completed_graph_actual_owner_replay transaction_aba={transaction_aba} error={error}"
    );
    assert_eq!(error.to_string(), "NATIVE_ACCOUNT_FRONTIER");
    assert!(next.graphs[2].is_none());
    assert_eq!(next.ids, original_ids);
    assert_eq!(
        next.frontier.as_ref().unwrap().source_record(),
        original_source
    );
    // A fresh traversal issued by this exact new owner can still complete;
    // rejection of the old result did not create or consume a graph proof.
    let mut first = 0;
    verify(node, f.parent, &f.before, &mut next, &mut || {
        first += 1;
        Ok(())
    })
    .unwrap();
    let mut repeated = 0;
    verify(node, f.parent, &f.before, &mut next, &mut || {
        repeated += 1;
        Ok(())
    })
    .unwrap();
    assert!(first > repeated && repeated > 0);
    next.require_unchanged_after_last_write(&node.db).unwrap();
    drop(next);
    node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn completed_graph_cannot_reinstall_into_another_scope_in_the_same_transaction() {
    completed_graph_rejects_another_original_owner(false);
}

#[test]
fn completed_graph_cannot_reinstall_after_commit_into_a_new_transaction() {
    completed_graph_rejects_another_original_owner(true);
}
