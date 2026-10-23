//! Current SQL and cursor-lifetime controls, independent of timing acceptance.
use super::*;
use crate::account_archive_prototype::native_store::{self, Root};
use crate::account_archive_prototype::{self as archive, Account, Kind};
use crate::{Error, ErrorCode, ErrorKind};
use rusqlite::params;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use trnm_mvcc_fee::pon_executor::State;
use trnm_protocol::pon_wire::hash;

type Verdict = std::result::Result<(), (ErrorKind, Option<ErrorCode>, String)>;

fn verdict(result: crate::Result<()>) -> Verdict {
    result.map_err(|error| (error.kind(), error.code(), error.to_string()))
}

fn fields(node: Node) -> (Hash, Hash, usize, Hash, Vec<u8>) {
    (node.id, node.path, node.depth, node.digest, node.encode())
}

fn fixture(db: &Connection, count: u64) -> (State, Root) {
    db.execute_batch(crate::store::native_authenticated::DDL)
        .unwrap();
    let state = (0..count)
        .map(|index| {
            let owner = hash(b"native-node-reader-fixture", &[&index.to_le_bytes()]);
            (
                format!("account:{}", hex::encode(owner)),
                json!({"balance":index * 7,"nonce":index}),
            )
        })
        .collect();
    let root = native_store::seed(db, &state, &mut || Ok(())).unwrap();
    (state, root)
}

// Frozen pre-change traversal. In particular, this reference still obtains
// Vec<u8> through the original per-node cached SELECT, even with a warm decode
// cache. It never calls NodeReader or the changed production child helper.
fn reference_verify(
    db: &Connection,
    root: &Root,
    state: &State,
    progress: &mut dyn FnMut() -> crate::Result<()>,
    lifts: Option<&LiftCache>,
) -> crate::Result<()> {
    let empty = native_store::empty_hashes();
    let actual = archive::accounts(state).map_err(native_store::storage)?;
    let load = |id| {
        archive::load_node_decoded(db, id, |id, bytes| {
            lifts.map_or_else(
                || Node::decode(id, bytes),
                |cache| cache.1.decode(id, bytes),
            )
        })
    };
    let node = root
        .node
        .map(load)
        .transpose()
        .map_err(native_store::storage)?;
    crate::ensure(
        root.count <= 65_536
            && root.node.is_none() == (root.count == 0)
            && node.as_ref().map_or(empty[0], |node| {
                lifts.map_or_else(|| node.lift(0, &empty), |cache| cache.lift(node, 0))
            }) == root.digest,
        "NATIVE_ACCOUNT_ROOT",
    )
    .map_err(Error::local_integrity)?;
    let child = |parent: &Node, side| -> archive::Result<Node> {
        let Kind::Fork {
            left,
            right,
            left_hash,
            right_hash,
        } = parent.kind
        else {
            return Err(ArchiveError::CorruptRecord);
        };
        let out = load(if side { right } else { left })?;
        if out.depth <= parent.depth
            || archive::common(&out.path, &parent.path) < parent.depth
            || archive::bit(&out.path, parent.depth) != side
            || lifts.map_or_else(
                || out.lift(parent.depth + 1, &empty),
                |cache| cache.lift(&out, parent.depth + 1),
            ) != if side { right_hash } else { left_hash }
        {
            return Err(ArchiveError::CorruptRecord);
        }
        Ok(out)
    };
    let mut stack = node.into_iter().collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    let mut retained = BTreeMap::new();
    let mut balance = 0u64;
    while let Some(node) = stack.pop() {
        progress()?;
        crate::ensure(
            seen.insert(node.id) && seen.len() <= 131_071,
            "NATIVE_ACCOUNT_GRAPH",
        )
        .map_err(Error::local_integrity)?;
        match node.kind {
            Kind::Leaf(owner, value) => {
                crate::ensure(
                    retained.insert(owner, value).is_none(),
                    "NATIVE_ACCOUNT_DUPLICATE",
                )
                .map_err(Error::local_integrity)?;
                balance = balance
                    .checked_add(value.balance)
                    .ok_or("NATIVE_ACCOUNT_BALANCE")?;
            }
            Kind::Fork { .. } => {
                stack.push(child(&node, true).map_err(native_store::storage)?);
                stack.push(child(&node, false).map_err(native_store::storage)?);
            }
        }
    }
    crate::ensure(
        retained == actual && retained.len() as u64 == root.count && balance == root.balance,
        "NATIVE_ACCOUNT_STATE",
    )
    .map_err(Error::local_integrity)
}

#[test]
fn native_node_reader_preserves_typed_blob_errors_and_rollback_after_warm_reads() {
    use rusqlite::types::Value as SqlValue;
    let db = Connection::open_in_memory().unwrap();
    // An externally changed schema can also admit NULL. The original typed
    // loader must remain the reference for this malformed storage case.
    db.execute_batch("CREATE TABLE archive_nodes(id BLOB PRIMARY KEY,data BLOB)")
        .unwrap();
    let node = Node::account(
        [11; 32],
        Account {
            balance: 9,
            nonce: 4,
        },
    );
    let bytes = node.encode();
    db.execute(
        "INSERT INTO archive_nodes VALUES(?,?)",
        params![node.id.as_slice(), &bytes],
    )
    .unwrap();
    let cache = LiftCache::default();
    let mut reader = NodeReader::new(&db);
    assert_eq!(
        fields(reader.load(node.id, Some(&cache)).unwrap()),
        fields(node.clone())
    );
    let mut changed = bytes.clone();
    changed[40] ^= 0x80;
    for value in [
        SqlValue::Blob(changed),
        SqlValue::Blob(bytes[..bytes.len() - 1].to_vec()),
        SqlValue::Blob(vec![0; 164]),
        SqlValue::Blob(vec![0; 1024 * 1024]),
        SqlValue::Text("not-a-blob".into()),
        SqlValue::Integer(7),
        SqlValue::Real(1.5),
        SqlValue::Null,
    ] {
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        db.execute("UPDATE archive_nodes SET data=?", [value])
            .unwrap();
        let expected = archive::load_node(&db, node.id).map(fields);
        assert!(expected.is_err());
        assert_eq!(reader.load(node.id, Some(&cache)).map(fields), expected);
        assert_eq!(reader.load(node.id, None).map(fields), expected);
        db.execute_batch("ROLLBACK").unwrap();
        assert_eq!(
            fields(reader.load(node.id, Some(&cache)).unwrap()),
            fields(node.clone())
        );
    }
    db.execute("DELETE FROM archive_nodes", []).unwrap();
    assert_eq!(
        reader.load(node.id, Some(&cache)).map(fields),
        Err(ArchiveError::DataUnavailable)
    );
    assert_eq!(
        reader.load(node.id, None).map(fields),
        archive::load_node(&db, node.id).map(fields)
    );
}

#[derive(Clone, Copy, Debug)]
enum ForeignChange {
    DeleteLeaf,
    CorruptLeaf,
    TextLeaf,
    OversizeLeaf,
    AddColumn,
    RemoveTableName,
}

fn foreign_change_during_traversal(reference: bool, change: ForeignChange) -> (Verdict, usize) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nodes.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL").unwrap();
    let (state, root) = fixture(&db, 8);
    let cache = LiftCache::default();
    native_store::verify_with_lifts(&db, &root, &state, &mut || Ok(()), Some(&cache)).unwrap();
    let accounts = archive::accounts(&state).unwrap();
    let (&owner, &account) = accounts.first_key_value().unwrap();
    let leaf = Node::account(owner, account);
    let foreign = Connection::open(&path).unwrap();
    let mut visits = 0;
    let mut committed = false;
    let mut progress = || -> crate::Result<()> {
        visits += 1;
        if visits == 1 {
            // The root is loaded, but no leaf has been read. A retained active
            // WAL cursor would mask this committed change behind its snapshot.
            match change {
                ForeignChange::DeleteLeaf => {
                    assert_eq!(
                        foreign.execute(
                            "DELETE FROM archive_nodes WHERE id=?",
                            [leaf.id.as_slice()]
                        )?,
                        1
                    );
                }
                ForeignChange::CorruptLeaf => {
                    let mut bytes = leaf.encode();
                    bytes[40] ^= 0x80;
                    assert_eq!(
                        foreign.execute(
                            "UPDATE archive_nodes SET data=? WHERE id=?",
                            params![bytes, leaf.id.as_slice()]
                        )?,
                        1
                    );
                }
                ForeignChange::TextLeaf => {
                    assert_eq!(
                        foreign.execute(
                            "UPDATE archive_nodes SET data='not-a-blob' WHERE id=?",
                            [leaf.id.as_slice()]
                        )?,
                        1
                    );
                }
                ForeignChange::OversizeLeaf => {
                    assert_eq!(
                        foreign.execute(
                            "UPDATE archive_nodes SET data=zeroblob(1048576) WHERE id=?",
                            [leaf.id.as_slice()]
                        )?,
                        1
                    );
                }
                ForeignChange::AddColumn => {
                    foreign.execute_batch("ALTER TABLE archive_nodes ADD COLUMN extra INTEGER")?;
                }
                ForeignChange::RemoveTableName => {
                    foreign.execute_batch("ALTER TABLE archive_nodes RENAME TO removed_nodes")?;
                }
            }
            committed = foreign.is_autocommit();
        }
        Ok(())
    };
    let verify = if reference {
        reference_verify
    } else {
        native_store::verify_with_lifts
    };
    let result = verify(&db, &root, &state, &mut progress, Some(&cache));
    assert!(
        committed,
        "the independent SQL change must commit before traversal continues"
    );
    (verdict(result), visits)
}

#[test]
fn native_node_reader_observes_foreign_unread_leaf_and_schema_changes_inside_progress() {
    for change in [
        ForeignChange::DeleteLeaf,
        ForeignChange::CorruptLeaf,
        ForeignChange::TextLeaf,
        ForeignChange::OversizeLeaf,
        ForeignChange::AddColumn,
        ForeignChange::RemoveTableName,
    ] {
        let expected = foreign_change_during_traversal(true, change);
        let observed = foreign_change_during_traversal(false, change);
        assert_eq!(observed, expected, "{change:?}");
        if matches!(change, ForeignChange::AddColumn) {
            assert_eq!(observed, (Ok(()), 15));
        } else {
            assert_eq!(observed.0.unwrap_err().0, ErrorKind::LocalStructure);
        }
    }
}

#[test]
fn native_node_reader_preserves_cancel_precedence_and_empty_root_without_sql() {
    let db = Connection::open_in_memory().unwrap();
    let empty_root = Root {
        node: None,
        digest: native_store::empty_hashes()[0],
        count: 0,
        balance: 0,
    };
    let cache = LiftCache::default();
    for lifts in [None, Some(&cache)] {
        // No archive_nodes table exists: the original empty-root path performs
        // no query, and must not acquire a new schema or cursor prerequisite.
        native_store::verify_with_lifts(&db, &empty_root, &State::new(), &mut || Ok(()), lifts)
            .unwrap();
    }
    let (state, root) = fixture(&db, 8);
    native_store::verify_with_lifts(&db, &root, &state, &mut || Ok(()), Some(&cache)).unwrap();
    for stop in [1, 2, 7, 15] {
        let mut results = Vec::new();
        for reference in [true, false] {
            let mut visits = 0;
            let mut progress = || -> crate::Result<()> {
                visits += 1;
                if visits == stop {
                    // If the reader incorrectly continues after cancellation,
                    // the next SQL read would produce a competing storage error.
                    db.execute_batch("ALTER TABLE archive_nodes RENAME TO cancelled_nodes")?;
                    return Err(Error::new(ErrorCode::PublicRequestCancelled));
                }
                Ok(())
            };
            let verify = if reference {
                reference_verify
            } else {
                native_store::verify_with_lifts
            };
            let result = verify(&db, &root, &state, &mut progress, Some(&cache));
            results.push((verdict(result), visits));
            db.execute_batch("ALTER TABLE cancelled_nodes RENAME TO archive_nodes")
                .unwrap();
        }
        assert_eq!(results[0], results[1]);
        assert_eq!(results[0].1, stop);
        let error = results[0].0.as_ref().unwrap_err();
        assert_eq!(error.1, Some(ErrorCode::PublicRequestCancelled));
        assert_ne!(error.0, ErrorKind::LocalStructure);
        native_store::verify_with_lifts(&db, &root, &state, &mut || Ok(()), Some(&cache)).unwrap();
    }
}

#[cfg(unix)]
#[test]
#[ignore = "explicit paired SQL reader observation; not the public service acceptance gate"]
fn native_node_reader_paired_graph_cost_observation() {
    assert!(
        std::hint::black_box(!cfg!(debug_assertions)),
        "release comparison required"
    );
    let db = Connection::open_in_memory().unwrap();
    let (state, root) = fixture(&db, 512);
    let caches = [LiftCache::default(), LiftCache::default()];
    for (arm, cache) in caches.iter().enumerate() {
        let verify = if arm == 0 {
            reference_verify
        } else {
            native_store::verify_with_lifts
        };
        verify(&db, &root, &state, &mut || Ok(()), Some(cache)).unwrap();
    }
    let cpu = || -> Option<u64> {
        let stamp = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Known(
            rustix::time::ClockId::ThreadCPUTime,
        ))
        .ok()?;
        let nanos = u64::try_from(stamp.tv_nsec).ok()?;
        if nanos >= 1_000_000_000 {
            return None;
        }
        u64::try_from(stamp.tv_sec)
            .ok()?
            .checked_mul(1_000_000_000)?
            .checked_add(nanos)
    };
    for pair in 0..8 {
        for arm in if pair % 2 == 0 { [0, 1] } else { [1, 0] } {
            let verify = if arm == 0 {
                reference_verify
            } else {
                native_store::verify_with_lifts
            };
            let started = std::time::Instant::now();
            let cpu_before = cpu();
            let mut visits = 0;
            for _ in 0..16 {
                verify(
                    &db,
                    &root,
                    &state,
                    &mut || {
                        visits += 1;
                        Ok(())
                    },
                    Some(&caches[arm]),
                )
                .unwrap();
            }
            let thread_cpu_ns = cpu_before
                .zip(cpu())
                .and_then(|(before, after)| after.checked_sub(before));
            let elapsed_ns = started.elapsed().as_nanos();
            assert_eq!(visits, 16 * 1023);
            eprintln!(
                "pon_native_node_reader_pair_v1 {}",
                json!({
                    "pair":pair,"arm":if arm == 0 { "prior-cached-select-vec" } else { "traversal-prepared-borrowed-blob" },
                    "graphs":16,"accounts":512,"actual_node_reads":visits,
                    "elapsed_ns":elapsed_ns,"thread_cpu_ns":thread_cpu_ns,
                    "warm_exact_decode_cache":true,"database":"in-memory",
                    "scope":"same original complete graph checks; no paid-budget/refill work in this micro-observation",
                    "public_service_acceptance_qualified":false
                })
            );
        }
    }
}
