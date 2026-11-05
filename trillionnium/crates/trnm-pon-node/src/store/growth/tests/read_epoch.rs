//! A read snapshot hides foreign WAL commits until its transaction ends.
//! Mathematical account facts cannot renew the original audited owner epoch.
use super::*;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
use std::sync::Arc;

fn data_version(node: &Node) -> u64 {
    node.db
        .query_row("PRAGMA data_version", [], |row| row.get(0))
        .unwrap()
}

fn commit_and_restore_generation(path: &Path) {
    let foreign = Connection::open(path).unwrap();
    assert!(foreign.is_autocommit());
    for statement in [
        "UPDATE active SET generation=generation+1 WHERE singleton=1",
        "UPDATE active SET generation=generation-1 WHERE singleton=1",
    ] {
        assert_eq!(foreign.execute(statement, []).unwrap(), 1);
        assert!(foreign.is_autocommit());
    }
    assert_eq!(foreign.total_changes(), 2);
}

#[test]
fn native_growth_v2_read_snapshot_hides_foreign_epoch_until_release() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let node = Node::open_with_permanent_account_growth_v2(directory.path(), settings).unwrap();
    let before = rows(&node.db);
    let changes = node.db.total_changes();
    let version = data_version(&node);
    let tx = node.db.unchecked_transaction().unwrap();
    // A real read fixes the SQLite WAL snapshot before the foreign commits.
    let active = node.active().unwrap();
    commit_and_restore_generation(&directory.path().join("native.sqlite"));
    assert_eq!(data_version(&node), version);
    assert_eq!(node.active().unwrap(), active);
    node.growth_guard().unwrap();
    tx.rollback().unwrap();
    assert_ne!(data_version(&node), version);
    let error = node.growth_guard().unwrap_err();
    assert_eq!(error.to_string(), "GROWTH_STORAGE_EPOCH_CHANGED");
    assert!(error.requires_owner_stop());
    assert_eq!(node.db.total_changes(), changes);
    assert_eq!(rows(&node.db), before);
}

fn query(node: &Node, kind: u8) -> Result<serde_json::Value> {
    let genesis = node.settings().genesis();
    match kind {
        0 => serde_json::to_value(node.growth_account(genesis, public(0))?).map_err(Into::into),
        1 => serde_json::to_value(node.next_nonces(&[public(7), public(0), public(777)])?)
            .map_err(Into::into),
        2 => serde_json::to_value(
            node.growth_account_multiproof(genesis, &[public(7), public(0), public(777)])?,
        )
        .map_err(Into::into),
        _ => unreachable!(),
    }
}

#[test]
fn native_growth_v2_account_queries_refuse_foreign_commit_inside_read_snapshot() {
    for kind in 0..3 {
        let directory = tempfile::tempdir().unwrap();
        let settings = settings();
        let node = Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone())
            .unwrap();
        let expected = query(&node, kind).unwrap();
        let before = rows(&node.db);
        let changes = node.db.total_changes();
        let version = data_version(&node);
        let path = directory.path().join("native.sqlite");
        let changed = Arc::new(AtomicBool::new(false));
        let foreign_commit = changed.clone();
        let events = Arc::new(Mutex::new(Vec::new()));
        let trace = events.clone();
        let in_read = AtomicBool::new(false);
        let read_block = AtomicBool::new(false);
        node.db
            .authorizer(Some(move |context: AuthContext<'_>| {
                match context.action {
                    AuthAction::Transaction {
                        operation: TransactionOperation::Begin,
                    } => {
                        in_read.store(true, Ordering::Relaxed);
                    }
                    AuthAction::Read {
                        table_name: "blocks",
                        ..
                    } if in_read.load(Ordering::Relaxed) => {
                        read_block.store(true, Ordering::Relaxed);
                    }
                    AuthAction::Read {
                        table_name: "archive_nodes",
                        ..
                    } if !foreign_commit.swap(true, Ordering::Relaxed) => {
                        assert!(in_read.load(Ordering::Relaxed));
                        assert!(read_block.load(Ordering::Relaxed));
                        // The parent header/working state were already selected
                        // in this snapshot. Two genuine commits preserve every
                        // final row but invalidate the audited storage epoch.
                        commit_and_restore_generation(&path);
                        trace.lock().unwrap().push("foreign-committed");
                    }
                    AuthAction::Pragma {
                        pragma_name: "data_version",
                        ..
                    } if foreign_commit.load(Ordering::Relaxed) => {
                        trace
                            .lock()
                            .unwrap()
                            .push(if in_read.load(Ordering::Relaxed) {
                                "snapshot-version-check"
                            } else {
                                "fresh-version-check"
                            });
                    }
                    AuthAction::Transaction {
                        operation: TransactionOperation::Rollback,
                    } => {
                        in_read.store(false, Ordering::Relaxed);
                        trace.lock().unwrap().push("snapshot-released");
                    }
                    _ => (),
                }
                Authorization::Allow
            }))
            .unwrap();
        let result = query(&node, kind);
        node.db
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
            .unwrap();
        assert!(changed.load(Ordering::Relaxed));
        let error = result.expect_err("query accepted a snapshot from an invalidated owner epoch");
        assert_eq!(error.to_string(), "GROWTH_STORAGE_EPOCH_CHANGED");
        assert!(error.requires_owner_stop());
        let events = events.lock().unwrap();
        assert_eq!(
            events.as_slice(),
            [
                "foreign-committed",
                "snapshot-version-check",
                "snapshot-released",
                "fresh-version-check"
            ],
            "query kind={kind} must check the new epoch only after releasing the old snapshot"
        );
        assert!(node.db.is_autocommit());
        assert_ne!(data_version(&node), version);
        assert_eq!(node.db.total_changes(), changes);
        assert_eq!(rows(&node.db), before);
        // The old owner cannot erase its refusal by retrying identical data.
        assert_eq!(
            query(&node, kind).unwrap_err().to_string(),
            "GROWTH_STORAGE_EPOCH_CHANGED"
        );
        drop(node);
        // Only the existing cold open/audit creates a fresh owner epoch. The
        // foreign transactions restored all semantic data, so all values match.
        let reopened =
            Node::open_with_permanent_account_growth_v2(directory.path(), settings).unwrap();
        assert_eq!(query(&reopened, kind).unwrap(), expected);
        assert_eq!(rows(&reopened.db), before);
    }
}
