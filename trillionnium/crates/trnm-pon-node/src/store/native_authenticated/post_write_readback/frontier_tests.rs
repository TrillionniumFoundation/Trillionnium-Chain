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
        .all(|record| record.accounts != current.accounts));
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
    assert!(scope.graphs[2].is_none());
    assert_eq!(scope.frontier.as_ref().unwrap().source_record(), source);
    verify(node, f.parent, &f.before, &mut scope, &mut || Ok(())).unwrap();
    assert_eq!(scope.partial_uses, 2); // Partial is not a new whole-Root receipt.
    assert_eq!(scope.hits, 0);
    assert!(scope.graphs[2].is_none());

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
        assert_eq!(scope.partial_uses, 2);
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
