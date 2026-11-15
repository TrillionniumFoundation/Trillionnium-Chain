//! Real packets and SQL readback; counts here are not service throughput.
use super::*;
use crate::store::{canonical, continuity_v1, development_public, hash, WorkCheckedPacket};
use crate::{ErrorCode, Packet, Settings};
use rusqlite::{params, types::Value as SqlValue};
use std::cell::RefCell;
use std::error::Error as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::pon_executor::ExecutionProgress;
use trnm_protocol::pon_wire::Envelope;
use trnm_sqlite_io_boundary::TransactionScope;

const NOW: u64 = 100_000;

struct Fixture {
    node: Node,
    directory: tempfile::TempDir,
    ids: Vec<Hash>,
}

fn settings() -> Settings {
    Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap()
}

fn packet(node: &Node, parent: Hash, height: u64) -> Packet {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut command = Envelope {
        network: node.settings.network(),
        sender: development_public(0).unwrap(),
        nonce: height,
        expiry: 10_000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    command.signature = hex::decode(sign_hex(&key, &command.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    node.make_consensus_maintenance(
        parent,
        vec![command.encode().unwrap()],
        development_public(7 + height).unwrap(),
        1 + height * 10,
        4096,
    )
    .unwrap()
}

fn fixture(blocks: u64, accelerated: bool) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let cfg = settings();
    let mut node = Node::open(directory.path(), cfg.clone(), 1).unwrap();
    if !accelerated {
        node.legacy_admission_schema = None;
    }
    let mut ids = vec![cfg.genesis()];
    for height in 1..=blocks {
        let block = packet(&node, *ids.last().unwrap(), height);
        ids.push(node.admit(&block, NOW).unwrap());
    }
    assert_eq!(node.active().unwrap(), (cfg.genesis(), 0));
    Fixture {
        node,
        directory,
        ids,
    }
}

fn facts(db: &Connection) -> BTreeMap<String, Vec<Vec<SqlValue>>> {
    let tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            assert!(table
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
            let columns = db
                .prepare(&format!("SELECT * FROM {table}"))
                .unwrap()
                .column_count();
            let order = (1..=columns)
                .map(|column| column.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let mut statement = db
                .prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))
                .unwrap();
            let rows = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get::<_, SqlValue>(column))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            (table, rows)
        })
        .collect()
}

fn capture(node: &Node, child: Hash) -> native_authenticated::PostWriteReadback<'_> {
    let owner = TransactionScope::capture(&node.db).unwrap();
    native_authenticated::PostWriteReadback::new(
        &node.db,
        &node.settings,
        child,
        &owner,
        node.legacy_admission_readback_schema().unwrap(),
    )
    .unwrap()
    .unwrap()
}

fn original_pair(node: &Node, parent: Hash, child: Hash, expected: (&State, &State)) -> Result<()> {
    ensure(
        &node.state_at(parent)? == expected.0 && &node.state_at(child)? == expected.1,
        "STORAGE_WRITE",
    )
    .map_err(Error::local_integrity)
}

fn admit_counted(node: &mut Node, block: &Packet) -> usize {
    let callbacks = AtomicUsize::new(0);
    assert_eq!(
        node.admit_work_checked_with_progress(
            WorkCheckedPacket::verify(block.clone()).unwrap(),
            NOW,
            &|point| {
                if point == ExecutionProgress::BeforeDurableCommit {
                    callbacks.fetch_add(1, Ordering::SeqCst);
                }
                Ok(())
            },
        )
        .unwrap(),
        block.id().unwrap()
    );
    callbacks.load(Ordering::SeqCst)
}

#[test]
fn legacy_pair_matches_full_replays_snapshot_cadence_and_cold_publication() {
    let mut actual = fixture(0, true);
    let mut reference = fixture(0, false);
    let mut tip = actual.ids[0];
    let mut observed = Vec::new();
    for height in 1..=129 {
        let block = packet(&actual.node, tip, height);
        let accelerated = admit_counted(&mut actual.node, &block);
        let original = admit_counted(&mut reference.node, &block);
        let remainder = (height - 1) % 128;
        let saved = if height == 1 || height % 128 == 0 {
            0
        } else {
            5 * remainder as usize
        };
        assert_eq!(original - accelerated, saved, "height {height}");
        if matches!(height, 1 | 2 | 64 | 127 | 128 | 129) {
            observed.push((height, accelerated, original));
        }
        tip = block.id().unwrap();
    }
    let snapshots = |node: &Node| {
        node.db
            .prepare("SELECT blocks.height FROM snapshots JOIN blocks ON blocks.id=snapshots.block ORDER BY blocks.height")
            .unwrap()
            .query_map([], |row| row.get::<_, u64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };
    assert_eq!(snapshots(&actual.node), [0, 128]);
    assert_eq!(snapshots(&reference.node), [0, 128]);
    assert_eq!(facts(&actual.node.db), facts(&reference.node.db));
    assert_eq!(actual.node.active().unwrap(), (actual.ids[0], 0));
    assert_eq!(
        actual.node.state_at(tip).unwrap(),
        reference.node.state_at(tip).unwrap()
    );
    let cfg = actual.node.settings.clone();
    drop(actual.node);
    actual.node = Node::open(actual.directory.path(), cfg, 1).unwrap();
    // Node::open retains the original recover() contract: after complete
    // admission it activates the best stored chain in generation one.
    assert_eq!(actual.node.active().unwrap(), (tip, 1));
    for node in [&mut actual.node, &mut reference.node] {
        assert_eq!(node.activate_observed(tip, NOW).unwrap(), tip);
        assert_eq!(
            node.next_nonce(development_public(0).unwrap()).unwrap(),
            130
        );
    }
    let published = reference.node.read_active().unwrap();
    assert_eq!(actual.node.read_active().unwrap(), published);
    assert_eq!(facts(&actual.node.db), facts(&reference.node.db));
    let cfg = actual.node.settings.clone();
    drop(actual.node);
    let reopened = Node::open(actual.directory.path(), cfg, 1).unwrap();
    assert_eq!(reopened.read_active().unwrap(), published);
    assert_eq!(facts(&reopened.db), facts(&reference.node.db));
    println!("legacy_admission_before_durable_commit_callbacks={observed:?}");
}

#[test]
fn legacy_pair_rereads_snapshot_and_every_intermediate_delta_after_warm_use() {
    let f = fixture(4, true);
    let parent = f.ids[3];
    let child = f.ids[4];
    let expected = (
        f.node.state_at(parent).unwrap(),
        f.node.state_at(child).unwrap(),
    );
    // Each damage is installed before the current scope. A previously successful
    // replay or unchanged block id cannot conceal these actual SQL bytes.
    for damage in [
        "snapshot",
        "before",
        "after",
        "missing",
        "root",
        "untouched",
    ] {
        let tx = rusqlite::Transaction::new_unchecked(
            &f.node.db,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        let mut warm = capture(&f.node, child);
        f.node
            .check_legacy_admission_states(
                (parent, child),
                (&expected.0, &expected.1),
                &mut || Ok(()),
                &mut warm,
            )
            .unwrap();
        drop(warm);
        match damage {
            "snapshot" => {
                f.node
                    .db
                    .execute(
                        "UPDATE snapshots SET state=x'7b7d' WHERE block=?",
                        [f.ids[0].as_slice()],
                    )
                    .unwrap();
            }
            "before" => {
                f.node
                    .db
                    .execute(
                        "UPDATE deltas SET before=x'30' WHERE block=?",
                        [f.ids[2].as_slice()],
                    )
                    .unwrap();
            }
            "after" => {
                f.node
                    .db
                    .execute(
                        "UPDATE deltas SET after=x'30' WHERE block=?",
                        [f.ids[2].as_slice()],
                    )
                    .unwrap();
            }
            "missing" => {
                assert!(
                    f.node
                        .db
                        .execute("DELETE FROM deltas WHERE block=?", [f.ids[2].as_slice()])
                        .unwrap()
                        > 0
                );
            }
            "root" => {
                f.node
                    .db
                    .execute(
                        "UPDATE blocks SET state_root=zeroblob(32) WHERE id=?",
                        [f.ids[2].as_slice()],
                    )
                    .unwrap();
            }
            "untouched" => {
                assert!(f.node.db.execute(
                    "UPDATE deltas SET after=x'30' WHERE block=?1 AND key NOT IN (SELECT key FROM deltas WHERE block=?2)",
                    params![f.ids[2].as_slice(), child.as_slice()],
                ).unwrap() > 0);
            }
            _ => unreachable!(),
        }
        let original =
            original_pair(&f.node, parent, child, (&expected.0, &expected.1)).unwrap_err();
        let mut scope = capture(&f.node, child);
        let current = f
            .node
            .check_legacy_admission_states(
                (parent, child),
                (&expected.0, &expected.1),
                &mut || Ok(()),
                &mut scope,
            )
            .unwrap_err();
        assert_eq!(current.to_string(), original.to_string(), "{damage}");
        assert_eq!(current.kind(), original.kind(), "{damage}");
        assert!(current.requires_owner_stop(), "{damage}: {current}");
        drop(scope);
        tx.rollback().unwrap();
    }
}

#[test]
fn legacy_pair_child_snapshot_and_active_parent_keep_distinct_sql_sources() {
    let mut f = fixture(3, true);
    let parent = f.ids[2];
    let child = f.ids[3];
    let expected = (
        f.node.state_at(parent).unwrap(),
        f.node.state_at(child).unwrap(),
    );
    let tx =
        rusqlite::Transaction::new_unchecked(&f.node.db, rusqlite::TransactionBehavior::Immediate)
            .unwrap();
    // An actual snapshot is authoritative input even at a non-cadence height.
    // The reader must inspect it instead of inferring absence from height%128.
    f.node
        .db
        .execute(
            "INSERT INTO snapshots VALUES(?,?)",
            params![child.as_slice(), canonical(&expected.1).unwrap()],
        )
        .unwrap();
    let mut scope = capture(&f.node, child);
    f.node
        .check_legacy_admission_states(
            (parent, child),
            (&expected.0, &expected.1),
            &mut || Ok(()),
            &mut scope,
        )
        .unwrap();
    drop(scope);
    f.node
        .db
        .execute(
            "UPDATE snapshots SET state=x'7b7d' WHERE block=?",
            [child.as_slice()],
        )
        .unwrap();
    let original = original_pair(&f.node, parent, child, (&expected.0, &expected.1)).unwrap_err();
    let mut scope = capture(&f.node, child);
    let current = f
        .node
        .check_legacy_admission_states(
            (parent, child),
            (&expected.0, &expected.1),
            &mut || Ok(()),
            &mut scope,
        )
        .unwrap_err();
    assert_eq!(current.to_string(), original.to_string());
    assert!(current.requires_owner_stop());
    drop(scope);
    tx.rollback().unwrap();

    f.node.activate_observed(child, NOW).unwrap();
    let next = packet(&f.node, child, 4);
    let published = f.node.read_active().unwrap();
    f.node
        .db
        .execute(
            "UPDATE deltas SET after=x'30' WHERE block=?",
            [f.ids[2].as_slice()],
        )
        .unwrap();
    // Active KV remains intact. Only the child's ORIGINAL historical source
    // reads reveal the damage; an active-parent prefix would hide it.
    assert_eq!(f.node.read_active().unwrap(), published);
    let original_error = f.node.state_at(f.ids[2]).unwrap_err().to_string();
    let error = f.node.admit(&next, NOW).unwrap_err();
    assert_eq!(error.to_string(), original_error);
    assert!(error.requires_owner_stop());
    assert!(f.node.record(next.id().unwrap()).is_err());
    assert_eq!(f.node.read_active().unwrap(), published);
}

#[test]
fn legacy_pair_ineligible_schema_keeps_original_reads_and_refuses_bad_delta_writes() {
    let mut reference = fixture(3, false);
    let block = packet(&reference.node, reference.ids[3], 4);
    let original_callbacks = admit_counted(&mut reference.node, &block);
    for damage in [false, true] {
        let mut f = fixture(3, true);
        let sql = if damage {
            "CREATE TRIGGER prefix_trigger AFTER INSERT ON deltas BEGIN DELETE FROM deltas WHERE block=NEW.block AND key=NEW.key; END"
        } else {
            "CREATE TRIGGER prefix_trigger AFTER INSERT ON deltas BEGIN SELECT 1; END"
        };
        f.node.db.execute_batch(sql).unwrap();
        // Extra SQL graphs cannot qualify merely because their writes finished.
        let tx = rusqlite::Transaction::new_unchecked(
            &f.node.db,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        {
            let owner = TransactionScope::capture(&f.node.db).unwrap();
            assert!(native_authenticated::PostWriteReadback::new(
                &f.node.db,
                &f.node.settings,
                block.id().unwrap(),
                &owner,
                f.node.legacy_admission_readback_schema().unwrap(),
            )
            .unwrap()
            .is_none());
        }
        tx.rollback().unwrap();
        if damage {
            let before = facts(&f.node.db);
            let error = f.node.admit(&block, NOW).unwrap_err();
            assert_eq!(error.to_string(), "STORAGE_WRITE");
            assert!(error.requires_owner_stop());
            assert_eq!(facts(&f.node.db), before);
            assert!(f.node.record(block.id().unwrap()).is_err());
        } else {
            assert_eq!(admit_counted(&mut f.node, &block), original_callbacks);
            f.node
                .db
                .execute_batch("DROP TRIGGER prefix_trigger")
                .unwrap();
            assert_eq!(facts(&f.node.db), facts(&reference.node.db));
        }
    }
}

#[test]
fn legacy_pair_selection_excludes_authenticated_and_growth_state_relations() {
    let directory = tempfile::tempdir().unwrap();
    let classical = Node::open(&directory.path().join("legacy"), settings(), 1).unwrap();
    assert!(classical.legacy_admission_readback_schema().is_some());
    let authenticated =
        Node::open_with_authenticated_state(&directory.path().join("native"), settings(), 1)
            .unwrap();
    assert!(authenticated.legacy_admission_readback_schema().is_none());
    let growth = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        growth_profile_v2::PROFILE,
    )
    .unwrap();
    let mut growth = Node::open(&directory.path().join("growth"), growth, 1).unwrap();
    assert_eq!(growth.state_backend, StateBackend::Legacy);
    // Isolate the defensive profile condition even if source DDL were supplied.
    growth.legacy_admission_schema = Some(BTreeMap::new());
    assert!(growth.legacy_admission_readback_schema().is_none());
    growth.legacy_admission_schema = None;
    let v3 = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_protocol::qualified_work_task::lifecycle_v3::PROFILE,
    )
    .unwrap();
    let v3 = Node::open(&directory.path().join("v3"), v3, 1).unwrap();
    assert!(v3.legacy_admission_readback_schema().is_some());
}

#[test]
fn legacy_pair_cancellation_at_every_commit_callback_rolls_back_all_rows() {
    let mut measured = fixture(3, true);
    let block = packet(&measured.node, measured.ids[3], 4);
    let callbacks = admit_counted(&mut measured.node, &block);
    let mut cancelled = fixture(3, true);
    let before = facts(&cancelled.node.db);
    let active = cancelled.node.read_active().unwrap();
    assert!(callbacks > 20);
    for cut in 1..=callbacks {
        let current = AtomicUsize::new(0);
        let error = cancelled
            .node
            .admit_work_checked_with_progress(
                WorkCheckedPacket::verify(block.clone()).unwrap(),
                NOW,
                &|point| {
                    if point == ExecutionProgress::BeforeDurableCommit
                        && current.fetch_add(1, Ordering::SeqCst) + 1 == cut
                    {
                        return Err(Error::new(ErrorCode::PublicRequestCancelled));
                    }
                    Ok(())
                },
            )
            .unwrap_err();
        assert!(
            error.is(ErrorCode::PublicRequestCancelled),
            "{cut}: {error}"
        );
        assert!(!error.requires_owner_stop());
        assert_eq!(current.load(Ordering::SeqCst), cut);
        assert!(cancelled.node.db.is_autocommit());
        assert_eq!(facts(&cancelled.node.db), before, "cut {cut}");
        assert_eq!(cancelled.node.read_active().unwrap(), active);
    }
    assert_eq!(
        cancelled.node.admit(&block, NOW).unwrap(),
        block.id().unwrap()
    );
    assert_eq!(facts(&cancelled.node.db), facts(&measured.node.db));
}

// A test-only descriptor, never a second Connection or a production callback.
// The original persistence progress bridge supplies its actual borrowed DB and
// executes ordinary safe SQL on the owner thread. RAII clears the descriptor
// even when the test unwinds; parallel test/worker threads cannot consume it.
struct InjectedSql {
    cut: usize,
    seen: usize,
    sql: &'static str,
    cancel: bool,
}
std::thread_local! {
    static INJECTED_SQL: RefCell<Option<InjectedSql>> = const { RefCell::new(None) };
}
struct SqlFault;
impl SqlFault {
    fn install(cut: usize, sql: &'static str, cancel: bool) -> Self {
        INJECTED_SQL.with(|slot| {
            let mut slot = slot.borrow_mut();
            assert!(slot.is_none());
            *slot = Some(InjectedSql {
                cut,
                seen: 0,
                sql,
                cancel,
            });
        });
        Self
    }
    fn assert_fired(&self) {
        INJECTED_SQL.with(|slot| {
            let slot = slot.borrow();
            let fault = slot.as_ref().unwrap();
            assert!(fault.seen >= fault.cut);
        });
    }
}
impl Drop for SqlFault {
    fn drop(&mut self) {
        INJECTED_SQL.with(|slot| *slot.borrow_mut() = None);
    }
}
pub(super) fn progress(db: &Connection, point: ExecutionProgress) -> Result<()> {
    if point != ExecutionProgress::BeforeDurableCommit {
        return Ok(());
    }
    INJECTED_SQL.with(|slot| {
        let mut slot = slot.borrow_mut();
        if let Some(fault) = slot.as_mut() {
            fault.seen += 1;
            if fault.seen == fault.cut {
                db.execute_batch(fault.sql)?;
                if fault.cancel {
                    return Err(Error::new(ErrorCode::PublicRequestCancelled));
                }
            }
        }
        Ok(())
    })
}

#[test]
fn legacy_pair_rejects_writes_ddl_and_transaction_aba_through_last_callback() {
    let mut measured = fixture(3, true);
    let block = packet(&measured.node, measured.ids[3], 4);
    let callbacks = admit_counted(&mut measured.node, &block);
    for sql in [
        "UPDATE deltas SET after=after WHERE 0",
        "UPDATE blocks SET state_root=state_root",
        "CREATE TABLE prefix_probe(value); DROP TABLE prefix_probe",
        "SAVEPOINT prefix_probe; RELEASE prefix_probe",
        "ROLLBACK; BEGIN IMMEDIATE",
    ] {
        for cut in [1, callbacks / 2, callbacks] {
            let mut f = fixture(3, true);
            let before = facts(&f.node.db);
            let fault = SqlFault::install(cut, sql, false);
            let current = AtomicUsize::new(0);
            let error = f
                .node
                .admit_work_checked_with_progress(
                    WorkCheckedPacket::verify(block.clone()).unwrap(),
                    NOW,
                    &|point| {
                        if point == ExecutionProgress::BeforeDurableCommit {
                            current.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok(())
                    },
                )
                .unwrap_err();
            fault.assert_fired();
            drop(fault);
            assert!(error.requires_owner_stop(), "{cut} {sql:?}: {error}");
            assert!(
                error.to_string().starts_with("NATIVE_POST_WRITE_"),
                "{error}"
            );
            assert!(current.load(Ordering::SeqCst) >= cut);
            assert!(f.node.db.is_autocommit());
            assert_eq!(facts(&f.node.db), before);
        }
    }
    // A callback's own COMMIT cannot be undone by an observation fence. Preserve
    // the owner-stopping failure and its original cancellation source; never
    // report the externally committed rows as this admission's success.
    for cancel in [false, true] {
        let mut f = fixture(3, true);
        let fault = SqlFault::install(callbacks, "COMMIT; BEGIN IMMEDIATE", cancel);
        let current = AtomicUsize::new(0);
        let error = f
            .node
            .admit_work_checked_with_progress(
                WorkCheckedPacket::verify(block.clone()).unwrap(),
                NOW,
                &|point| {
                    if point == ExecutionProgress::BeforeDurableCommit {
                        current.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(())
                },
            )
            .unwrap_err();
        fault.assert_fired();
        drop(fault);
        assert!(error.to_string().starts_with("NATIVE_POST_WRITE_SCOPE"));
        assert!(error.requires_owner_stop());
        if cancel {
            assert!(error
                .source()
                .unwrap()
                .downcast_ref::<Error>()
                .unwrap()
                .is(ErrorCode::PublicRequestCancelled));
        }
        assert_eq!(f.node.active().unwrap(), (f.ids[0], 0));
        assert!(f.node.db.is_autocommit());
    }
}
