//! Actual Node/SQLite adaptation controls for the existing c165 readback owner.
//! Local graph counts are not a service, hardware or WAN qualification.
use super::super::{load_observed, verify_state_with_readback};
use super::*;
use crate::Node;
use trnm_mvcc_fee::pon_executor::State;

#[path = "fence_tests.rs"]
mod fences;

#[path = "frontier_tests.rs"]
mod frontier;

struct Fixture {
    node: Node,
    directory: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap();
    let node = Node::open_with_authenticated_state(directory.path(), settings, 1).unwrap();
    Fixture { node, directory }
}

fn capture(node: &Node, child: Hash) -> PostWriteReadback<'_> {
    let owner = TransactionScope::capture(&node.db).unwrap();
    PostWriteReadback::new(
        &node.db,
        &node.settings,
        child,
        &owner,
        node.post_write_schema.as_ref().unwrap(),
    )
    .unwrap()
    .unwrap()
}

fn verify(
    node: &Node,
    block: Hash,
    state: &State,
    scope: &mut PostWriteReadback<'_>,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    verify_state_with_readback(
        &node.db,
        &node.settings,
        block,
        state,
        progress,
        Some(&node.authenticated_arithmetic),
        Some(scope),
    )
}

fn graphs(node: &Node) -> u64 {
    node.native_history_arithmetic_observation()["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["stage"] == "account_graph")
        .unwrap()["totals"]["calls"]
        .as_u64()
        .unwrap()
}

fn mint_genesis(node: &Node) -> PostWriteReadback<'_> {
    node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(node, node.settings.genesis());
    verify(
        node,
        node.settings.genesis(),
        &node.settings.initial,
        &mut scope,
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(scope.hits, 0);
    scope
}

fn working_only_child() -> (Fixture, Hash, State) {
    let mut f = fixture();
    let genesis = f.node.settings.genesis();
    let packet = f
        .node
        .make_consensus_maintenance(
            genesis,
            vec![],
            crate::development_public(7).unwrap(),
            11,
            4096,
        )
        .unwrap();
    let child = f.node.admit(&packet, 100_000).unwrap();
    let state = f.node.state_at(child).unwrap();
    let parent_record = load_observed(&f.node.db, genesis, None).unwrap();
    let child_record = load_observed(&f.node.db, child, None).unwrap();
    assert_ne!(child_record.state, parent_record.state);
    assert_eq!(child_record.accounts, parent_record.accounts);
    assert_ne!(state, f.node.settings.initial);
    (f, child, state)
}

#[test]
fn different_current_records_share_only_the_exact_account_graph_in_one_writer() {
    let (f, child, state) = working_only_child();
    let genesis = f.node.settings.genesis();
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(&f.node, child);
    verify(&f.node, child, &state, &mut scope, &mut || Ok(())).unwrap();
    assert_eq!(scope.ids, [Some(child), Some(genesis), Some(genesis), None]);
    assert!(scope.graphs[1].is_none());
    assert!(scope.graphs[2].is_none());
    let parent_record = load_observed(&f.node.db, genesis, None).unwrap();
    assert_ne!(scope.graphs[0].as_ref(), Some(&parent_record));
    assert_eq!(
        crate::account_archive_prototype::accounts(&state).unwrap(),
        crate::account_archive_prototype::accounts(&f.node.settings.initial).unwrap()
    );

    // The reference is the original real SQL/graph verifier in THIS writer,
    // with the same arithmetic material and progress callback. Only its
    // optional transaction-local graph result is absent.
    let before = graphs(&f.node);
    let mut original_progress = 0u64;
    super::super::verify_state_with_cache(
        &f.node.db,
        &f.node.settings,
        genesis,
        &f.node.settings.initial,
        &mut || {
            original_progress += 1;
            Ok(())
        },
        Some(&f.node.authenticated_arithmetic),
    )
    .unwrap();
    assert_eq!(graphs(&f.node) - before, 1);
    let before = graphs(&f.node);
    let mut reused_progress = 0u64;
    verify(
        &f.node,
        genesis,
        &f.node.settings.initial,
        &mut scope,
        &mut || {
            reused_progress += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(graphs(&f.node), before);
    assert_eq!(scope.hits, 1);
    assert!(scope.consumed);
    // Entry, all three original delta boundaries and the final boundary remain.
    assert_eq!(reused_progress, 5);
    assert_eq!(
        original_progress - reused_progress,
        2 * parent_record.accounts.count - 1
    );

    for field in ["node", "digest", "count", "balance"] {
        let mut changed = parent_record.clone();
        match field {
            "node" => changed.accounts.node = None,
            "digest" => changed.accounts.digest[0] ^= 1,
            "count" => changed.accounts.count += 1,
            "balance" => changed.accounts.balance += 1,
            _ => unreachable!(),
        }
        assert!(
            !scope
                .matches(&f.node.db, &f.node.settings, &changed)
                .unwrap(),
            "{field}"
        );
    }
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn cross_record_reuse_keeps_current_nonce_existence_grammar_and_working_state_checks() {
    let (f, child, state) = working_only_child();
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(&f.node, child);
    verify(
        &f.node,
        f.node.settings.genesis(),
        &f.node.settings.initial,
        &mut scope,
        &mut || Ok(()),
    )
    .unwrap();
    let child_record = load_observed(&f.node.db, child, None).unwrap();
    assert!(scope
        .matches(&f.node.db, &f.node.settings, &child_record)
        .unwrap());
    let owner = format!(
        "account:{}",
        hex::encode(crate::development_public(0).unwrap())
    );
    let reward = state.keys().find(|key| key.starts_with("reward:")).unwrap();
    for change in [
        "nonce",
        "balance",
        "zero-account",
        "missing-account",
        "alias",
        "field",
        "float",
        "working",
        "liability",
    ] {
        let mut changed = state.clone();
        match change {
            "nonce" => changed.get_mut(&owner).unwrap()["nonce"] = serde_json::json!(1),
            "balance" => {
                let balance = changed[&owner]["balance"].as_u64().unwrap();
                changed.get_mut(&owner).unwrap()["balance"] = serde_json::json!(balance - 1);
            }
            "zero-account" => {
                assert!(changed
                    .insert(
                        format!("account:{}", "93".repeat(32)),
                        serde_json::json!({"balance": 0, "nonce": 7})
                    )
                    .is_none());
            }
            "missing-account" => {
                changed.remove(&owner);
            }
            "alias" => {
                changed.insert(
                    format!("account:{}", "AB".repeat(32)),
                    serde_json::json!({"balance": 0, "nonce": 0}),
                );
            }
            "field" => changed.get_mut(&owner).unwrap()["extra"] = serde_json::json!(0),
            "float" => changed.get_mut(&owner).unwrap()["nonce"] = serde_json::json!(0.0),
            "working" => {
                changed.insert("meta:readback-negative".into(), serde_json::json!(1));
            }
            "liability" => {
                let amount = changed[reward]["amount"].as_u64().unwrap();
                changed.get_mut(reward).unwrap()["amount"] = serde_json::json!(amount + 1);
            }
            _ => unreachable!(),
        }
        // Compare the actual original error, including parser/conservation
        // precedence, before any graph hit can be consumed.
        let original = super::super::verify_state_with_cache(
            &f.node.db,
            &f.node.settings,
            child,
            &changed,
            &mut || Ok(()),
            None,
        )
        .unwrap_err();
        let before = graphs(&f.node);
        let error = verify(&f.node, child, &changed, &mut scope, &mut || Ok(())).unwrap_err();
        assert_eq!(error.to_string(), original.to_string(), "{change}");
        assert_eq!(graphs(&f.node), before, "{change}");
        assert_eq!(scope.hits, 0, "{change}");
        assert!(!scope.consumed, "{change}");
    }
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn a_current_child_record_with_another_node_cannot_borrow_the_parent_graph() {
    let (f, child, state) = working_only_child();
    let mut record = load_observed(&f.node.db, child, None).unwrap();
    record.accounts.node = None;
    record.id = record.digest().unwrap();
    f.node
        .db
        .execute(
            "UPDATE native_state_commitments SET data=? WHERE block=?",
            rusqlite::params![super::super::canonical(&record).unwrap(), child.as_slice()],
        )
        .unwrap();
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(&f.node, child);
    verify(
        &f.node,
        f.node.settings.genesis(),
        &f.node.settings.initial,
        &mut scope,
        &mut || Ok(()),
    )
    .unwrap();
    // This current row still passes Record/complete-State bindings, so an
    // account-digest-only lookup would incorrectly suppress the real failure.
    let before = graphs(&f.node);
    let error = verify(&f.node, child, &state, &mut scope, &mut || Ok(())).unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_ACCOUNT_ROOT");
    assert_eq!(graphs(&f.node) - before, 1);
    assert_eq!(scope.hits, 0);
    assert!(!scope.consumed);
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn actual_admission_reuses_graphs_and_keeps_original_state_packet_and_reopen() {
    let mut accelerated = fixture();
    let mut reference = fixture();
    reference.node.post_write_schema = None;
    let mut parent = accelerated.node.settings.genesis();
    for height in 1..=3 {
        let packet = accelerated
            .node
            .make_consensus_maintenance(
                parent,
                vec![],
                crate::development_public(height).unwrap(),
                10 + height,
                4096,
            )
            .unwrap();
        let before = (graphs(&accelerated.node), graphs(&reference.node));
        parent = accelerated.node.admit(&packet, 100_000).unwrap();
        assert_eq!(reference.node.admit(&packet, 100_000).unwrap(), parent);
        let traversals = (
            graphs(&accelerated.node) - before.0,
            graphs(&reference.node) - before.1,
        );
        assert!(
            traversals.0 < traversals.1,
            "real graphs with/without scoped reuse: {traversals:?}"
        );
        assert_eq!(
            accelerated.node.packet(parent).unwrap().encode().unwrap(),
            reference.node.packet(parent).unwrap().encode().unwrap()
        );
        assert_eq!(
            accelerated.node.state_at(parent).unwrap(),
            reference.node.state_at(parent).unwrap()
        );
        assert_eq!(
            accelerated.node.read_active().unwrap(),
            reference.node.read_active().unwrap()
        );
    }
    accelerated.node.activate_observed(parent, 100_000).unwrap();
    reference.node.activate_observed(parent, 100_000).unwrap();
    let expected = reference.node.read_active().unwrap();
    assert_eq!(accelerated.node.read_active().unwrap(), expected);
    let settings = accelerated.node.settings.clone();
    drop(accelerated.node);
    let reopened =
        Node::open_with_authenticated_state(accelerated.directory.path(), settings, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), expected);
}

#[test]
fn current_complete_state_remains_mandatory_on_a_graph_hit() {
    let f = fixture();
    let genesis = f.node.settings.genesis();
    let mut scope = mint_genesis(&f.node);
    let before = graphs(&f.node);
    verify(
        &f.node,
        genesis,
        &f.node.settings.initial,
        &mut scope,
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(graphs(&f.node), before);
    assert_eq!(scope.hits, 1);
    let mut changed = f.node.settings.initial.clone();
    changed.insert("meta:readback-negative".into(), serde_json::json!(1));
    let error = verify(&f.node, genesis, &changed, &mut scope, &mut || Ok(())).unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_STATE_ROOT");
    assert_eq!(scope.hits, 1);
    f.node.db.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn another_actual_connection_cannot_use_the_original_write_scope() {
    let f = fixture();
    let other = fixture();
    let mut scope = mint_genesis(&f.node);
    other.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let error = verify(
        &other.node,
        other.node.settings.genesis(),
        &other.node.settings.initial,
        &mut scope,
        &mut || Ok(()),
    )
    .unwrap_err();
    assert!(error.to_string().starts_with("NATIVE_POST_WRITE_SCOPE"));
    assert_eq!(scope.hits, 0);
}

#[test]
fn no_row_writes_and_reversed_ddl_disable_reuse_without_resetting_the_scope() {
    for sql in [
        "UPDATE archive_nodes SET data=data WHERE 0",
        "CREATE TABLE readback_probe(x); DROP TABLE readback_probe",
    ] {
        let f = fixture();
        let mut scope = mint_genesis(&f.node);
        let changes = f.node.db.total_changes();
        f.node.db.execute_batch(sql).unwrap();
        assert_eq!(f.node.db.total_changes(), changes);
        let before = graphs(&f.node);
        for _ in 0..2 {
            verify(
                &f.node,
                f.node.settings.genesis(),
                &f.node.settings.initial,
                &mut scope,
                &mut || Ok(()),
            )
            .unwrap();
        }
        assert_eq!(graphs(&f.node) - before, 2);
        assert_eq!(scope.hits, 0);
        assert!(!scope.enabled);
    }
}

#[test]
fn actual_stored_graph_damage_is_reread_after_a_receipt() {
    let f = fixture();
    let mut scope = mint_genesis(&f.node);
    let root = load_observed(&f.node.db, f.node.settings.genesis(), None)
        .unwrap()
        .accounts
        .node
        .unwrap();
    f.node
        .db
        .execute(
            "UPDATE archive_nodes SET data=x'00' WHERE id=?",
            [root.as_slice()],
        )
        .unwrap();
    let error = verify(
        &f.node,
        f.node.settings.genesis(),
        &f.node.settings.initial,
        &mut scope,
        &mut || Ok(()),
    )
    .unwrap_err();
    assert!(error.to_string().starts_with("NATIVE_ACCOUNT_STORE"));
    assert_eq!(scope.hits, 0);
}

#[test]
fn first_graph_callback_write_cannot_mint_a_result_or_reenable_it() {
    let f = fixture();
    let genesis = f.node.settings.genesis();
    f.node.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut scope = capture(&f.node, genesis);
    let mut wrote = false;
    verify(
        &f.node,
        genesis,
        &f.node.settings.initial,
        &mut scope,
        &mut || {
            if !wrote {
                f.node
                    .db
                    .execute("UPDATE archive_nodes SET data=data WHERE 0", [])?;
                wrote = true;
            }
            Ok(())
        },
    )
    .unwrap();
    assert!(wrote);
    assert!(scope.graphs.iter().all(Option::is_none));
    let before = graphs(&f.node);
    verify(
        &f.node,
        genesis,
        &f.node.settings.initial,
        &mut scope,
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(graphs(&f.node) - before, 1);
}

#[test]
fn original_transaction_owner_refuses_commit_begin_and_savepoint_aba() {
    for sql in [
        "COMMIT; BEGIN IMMEDIATE",
        "SAVEPOINT probe; RELEASE probe",
        "SAVEPOINT probe; ROLLBACK TO probe; RELEASE probe",
    ] {
        let f = fixture();
        let mut scope = mint_genesis(&f.node);
        let original = TransactionScope::capture(&f.node.db).unwrap();
        f.node.db.execute_batch(sql).unwrap();
        let error = verify(
            &f.node,
            f.node.settings.genesis(),
            &f.node.settings.initial,
            &mut scope,
            &mut || Ok(()),
        )
        .unwrap_err();
        assert!(error.to_string().starts_with("NATIVE_POST_WRITE_SCOPE"));
        assert!(PostWriteReadback::new(
            &f.node.db,
            &f.node.settings,
            f.node.settings.genesis(),
            &original,
            f.node.post_write_schema.as_ref().unwrap()
        )
        .is_err());
    }
}

#[test]
fn changed_schema_or_namespace_never_creates_a_new_scope() {
    for sql in [
        "PRAGMA writable_schema=ON",
        "CREATE TEMP TABLE probe(x)",
        "ATTACH ':memory:' AS foreign_db",
    ] {
        let f = fixture();
        let mut scope = mint_genesis(&f.node);
        f.node.db.execute_batch(sql).unwrap();
        let before = graphs(&f.node);
        verify(
            &f.node,
            f.node.settings.genesis(),
            &f.node.settings.initial,
            &mut scope,
            &mut || Ok(()),
        )
        .unwrap();
        assert_eq!(graphs(&f.node) - before, 1);
        let original = TransactionScope::capture(&f.node.db).unwrap();
        assert!(PostWriteReadback::new(
            &f.node.db,
            &f.node.settings,
            f.node.settings.genesis(),
            &original,
            f.node.post_write_schema.as_ref().unwrap()
        )
        .unwrap()
        .is_none());
    }
}

#[test]
fn consumed_active_reader_refuses_a_last_callback_write() {
    let f = fixture();
    let mut scope = mint_genesis(&f.node);
    let mut callbacks = 0;
    f.node
        .read_active_with_readback(
            &mut || {
                callbacks += 1;
                Ok(())
            },
            Some(&mut scope),
        )
        .unwrap();
    assert!(scope.consumed);
    let mut current = 0;
    let error = f
        .node
        .read_active_with_readback(
            &mut || {
                current += 1;
                if current == callbacks {
                    f.node
                        .db
                        .execute("UPDATE archive_nodes SET data=data WHERE 0", [])?;
                }
                Ok(())
            },
            Some(&mut scope),
        )
        .unwrap_err();
    assert_eq!(current, callbacks);
    assert_eq!(error.to_string(), "NATIVE_POST_WRITE_CHANGED");
}

#[test]
fn original_cancellation_before_and_after_a_match_is_preserved() {
    let f = fixture();
    let mut scope = mint_genesis(&f.node);
    let mut callbacks = 0;
    verify(
        &f.node,
        f.node.settings.genesis(),
        &f.node.settings.initial,
        &mut scope,
        &mut || {
            callbacks += 1;
            Ok(())
        },
    )
    .unwrap();
    for cancel_at in [1, callbacks] {
        let hits = scope.hits;
        let mut current = 0;
        let error = verify(
            &f.node,
            f.node.settings.genesis(),
            &f.node.settings.initial,
            &mut scope,
            &mut || {
                current += 1;
                if current == cancel_at {
                    Err("READBACK_TEST_CANCELLED".into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "READBACK_TEST_CANCELLED");
        assert_eq!(scope.hits, hits);
    }
}

#[test]
fn actual_original_writer_excludes_an_independent_database_writer() {
    let f = fixture();
    let mut scope = mint_genesis(&f.node);
    let outside = Connection::open(f.directory.path().join("native.sqlite")).unwrap();
    outside.busy_timeout(std::time::Duration::ZERO).unwrap();
    assert!(outside
        .execute("UPDATE archive_nodes SET data=data", [])
        .is_err());
    verify(
        &f.node,
        f.node.settings.genesis(),
        &f.node.settings.initial,
        &mut scope,
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(scope.hits, 1);
}

#[test]
fn prepare_only_schema_reset_preserves_the_normalized_writer() {
    let f = fixture();
    let mut scope = mint_genesis(&f.node);
    let before = readback_schema(&f.node.db).unwrap();
    drop(f.node.db.prepare("PRAGMA writable_schema=RESET").unwrap());
    assert_eq!(readback_schema(&f.node.db).unwrap(), before);
    verify(
        &f.node,
        f.node.settings.genesis(),
        &f.node.settings.initial,
        &mut scope,
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(scope.hits, 1);
}

#[test]
fn cached_catalog_statement_reads_current_ddl_and_unversioned_catalog_rows() {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE original(key INTEGER PRIMARY KEY, value BLOB)")
        .unwrap();
    let first = readback_schema(&db).unwrap().unwrap();
    assert_eq!(readback_schema(&db).unwrap().unwrap(), first);
    db.execute_batch("ALTER TABLE original ADD COLUMN extra TEXT")
        .unwrap();
    let altered = readback_schema(&db).unwrap().unwrap();
    assert_ne!(altered, first);
    assert!(altered[0].5.as_ref().unwrap().contains("extra"));
    let rootpage = altered[0].4;
    // Catalog writes deliberately do not bump schema_version. A cached SQL
    // program must still expose the changed row, never retain its old result.
    db.execute_batch("PRAGMA writable_schema=ON").unwrap();
    assert!(readback_schema(&db).unwrap().is_none());
    db.execute(
        "UPDATE sqlite_master SET rootpage=? WHERE name='original'",
        [rootpage + 1],
    )
    .unwrap();
    db.execute_batch("PRAGMA writable_schema=OFF").unwrap();
    let changed = readback_schema(&db).unwrap().unwrap();
    assert_eq!(changed[0].4, rootpage + 1);
    db.execute_batch("PRAGMA writable_schema=ON").unwrap();
    db.execute(
        "UPDATE sqlite_master SET rootpage=? WHERE name='original'",
        [rootpage],
    )
    .unwrap();
    db.execute_batch("PRAGMA writable_schema=RESET").unwrap();
    assert_eq!(readback_schema(&db).unwrap().unwrap(), altered);
    db.execute_batch("DROP TABLE original; CREATE TABLE replacement(value TEXT)")
        .unwrap();
    let replaced = readback_schema(&db).unwrap().unwrap();
    assert_eq!(replaced.len(), 1);
    assert_eq!(replaced[0].2, "replacement");
}

#[test]
fn warm_catalog_statement_never_hides_temp_objects_or_database_attachments() {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE original(value TEXT)")
        .unwrap();
    let first = readback_schema(&db).unwrap().unwrap();
    db.execute_batch("CREATE TEMP TABLE temporary(value TEXT)")
        .unwrap();
    assert!(readback_schema(&db).unwrap().is_none());
    db.execute_batch("DROP TABLE temp.temporary").unwrap();
    assert_eq!(readback_schema(&db).unwrap().unwrap(), first);
    db.execute_batch("ATTACH DATABASE ':memory:' AS extra")
        .unwrap();
    assert!(readback_schema(&db).unwrap().is_none());
    db.execute_batch("DETACH DATABASE extra").unwrap();
    assert_eq!(readback_schema(&db).unwrap().unwrap(), first);
}
