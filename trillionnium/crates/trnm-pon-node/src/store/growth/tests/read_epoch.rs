//! A read snapshot hides foreign WAL commits until its transaction ends.
//! Completed read facts cannot renew the original audited owner epoch.
use super::*;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
use std::sync::Arc;
use trnm_service_settlement::native_budget::{NativeFundingSourceV1, NativePaymentQueryV1};

fn data_version(node: &Node) -> u64 {
    node.db
        .query_row("PRAGMA data_version", [], |row| row.get(0))
        .unwrap()
}

fn commit_and_restore_generation(path: &Path) {
    let foreign = Connection::open(path).unwrap();
    assert_eq!(
        foreign
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "wal"
    );
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

#[derive(Default)]
struct EpochReadProbe {
    committed: AtomicBool,
    in_read: AtomicBool,
    read_block: AtomicBool,
    initial_checks: AtomicUsize,
    events: Mutex<Vec<&'static str>>,
}

impl EpochReadProbe {
    fn commit(&self, path: &Path, snapshot: bool) {
        assert!(self.initial_checks.load(Ordering::Relaxed) > 0);
        assert_eq!(self.in_read.load(Ordering::Relaxed), snapshot);
        if snapshot {
            assert!(self.read_block.load(Ordering::Relaxed));
        }
        assert!(!self.committed.swap(true, Ordering::Relaxed));
        // Both foreign transactions really commit, while the final semantic
        // rows remain identical. A restored generation cannot renew this epoch.
        commit_and_restore_generation(path);
        self.events.lock().unwrap().push("foreign-committed");
    }

    fn assert_snapshot_checks(&self) {
        assert!(self.committed.load(Ordering::Relaxed));
        let events = self.events.lock().unwrap();
        assert_eq!(events.first(), Some(&"foreign-committed"));
        let release = events
            .iter()
            .position(|&event| event == "snapshot-released")
            .expect("query did not release its original read snapshot");
        assert!(
            release > 1,
            "missing original in-snapshot guard: {events:?}"
        );
        assert!(events[1..release]
            .iter()
            .all(|&event| event == "snapshot-version-check"));
        assert_eq!(events[release + 1..], ["fresh-version-check"]);
    }
}

// A table hook injects after the API's entry guard. Snapshot tests select a
// later table, after the first blocks query has established the real read view.
// Progress tests supply no table and commit from ObservationReady instead.
fn install_epoch_probe(
    node: &mut Node,
    path: &Path,
    table: Option<&'static str>,
    snapshot: bool,
) -> Arc<EpochReadProbe> {
    let path = path.to_owned();
    let probe = Arc::new(EpochReadProbe::default());
    let trace = probe.clone();
    node.db
        .authorizer(Some(move |context: AuthContext<'_>| {
            match context.action {
                AuthAction::Transaction {
                    operation: TransactionOperation::Begin,
                } => trace.in_read.store(true, Ordering::Relaxed),
                AuthAction::Read {
                    table_name: "blocks",
                    ..
                } if trace.in_read.load(Ordering::Relaxed) => {
                    trace.read_block.store(true, Ordering::Relaxed);
                }
                AuthAction::Pragma {
                    pragma_name: "data_version",
                    ..
                } => {
                    if trace.committed.load(Ordering::Relaxed) {
                        trace.events.lock().unwrap().push(
                            if trace.in_read.load(Ordering::Relaxed) {
                                "snapshot-version-check"
                            } else {
                                "fresh-version-check"
                            },
                        );
                    } else {
                        trace.initial_checks.fetch_add(1, Ordering::Relaxed);
                    }
                }
                AuthAction::Transaction {
                    operation: TransactionOperation::Rollback,
                } => {
                    trace.in_read.store(false, Ordering::Relaxed);
                    trace.events.lock().unwrap().push("snapshot-released");
                }
                _ => (),
            }
            if let AuthAction::Read { table_name, .. } = context.action {
                if table == Some(table_name) && !trace.committed.load(Ordering::Relaxed) {
                    trace.commit(&path, snapshot);
                }
            }
            Authorization::Allow
        }))
        .unwrap();
    probe
}

fn remove_epoch_probe(node: &mut Node) {
    node.db
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .unwrap();
}

fn assert_epoch_error<T: std::fmt::Debug>(result: Result<T>) {
    let error = result.expect_err("query accepted an invalidated native owner epoch");
    assert_eq!(error.to_string(), "GROWTH_STORAGE_EPOCH_CHANGED");
    assert!(error.requires_owner_stop());
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
        let mut node =
            Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone())
                .unwrap();
        let expected = query(&node, kind).unwrap();
        let before = rows(&node.db);
        let changes = node.db.total_changes();
        let version = data_version(&node);
        let path = directory.path().join("native.sqlite");
        let probe = install_epoch_probe(&mut node, &path, Some("archive_nodes"), true);
        let result = query(&node, kind);
        remove_epoch_probe(&mut node);
        assert_epoch_error(result);
        probe.assert_snapshot_checks();
        let events = probe.events.lock().unwrap();
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

fn working_query(node: &Node, kind: u8) -> Result<serde_json::Value> {
    match kind {
        0 => {
            serde_json::to_value(node.growth_observe(node.settings.genesis())?).map_err(Into::into)
        }
        1 => {
            serde_json::to_value(node.growth_working(node.settings.genesis())?).map_err(Into::into)
        }
        2 => {
            let snapshot = node.growth_current_working()?;
            Ok(json!({
                "block": snapshot.block,
                "generation": snapshot.generation,
                "height": snapshot.height,
                "commitment": snapshot.commitment,
                "working": snapshot.working
            }))
        }
        _ => unreachable!(),
    }
}

#[test]
fn native_growth_v2_working_queries_refuse_foreign_commit_inside_read_snapshot() {
    for kind in 0..3 {
        let directory = tempfile::tempdir().unwrap();
        let settings = settings();
        let mut node =
            Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone())
                .unwrap();
        let expected = working_query(&node, kind).unwrap();
        let before = rows(&node.db);
        let changes = node.db.total_changes();
        let version = data_version(&node);
        let probe = install_epoch_probe(
            &mut node,
            &directory.path().join("native.sqlite"),
            Some("growth_states"),
            true,
        );
        let result = working_query(&node, kind);
        remove_epoch_probe(&mut node);
        assert_epoch_error(result);
        probe.assert_snapshot_checks();
        assert!(node.db.is_autocommit());
        assert_ne!(data_version(&node), version);
        assert_eq!(node.db.total_changes(), changes);
        assert_eq!(rows(&node.db), before);
        assert_epoch_error(working_query(&node, kind));
        drop(node);
        let reopened =
            Node::open_with_permanent_account_growth_v2(directory.path(), settings).unwrap();
        assert_eq!(working_query(&reopened, kind).unwrap(), expected);
        assert_eq!(rows(&reopened.db), before);
    }
}

fn progress_observation(
    node: &Node,
    packet: &GrowthPacket,
    kind: u8,
    progress: &(impl Fn(GrowthProgress) -> Result<()> + Sync),
) -> Result<serde_json::Value> {
    match kind {
        0 => node.growth_head_observation_with_progress(progress),
        1 => node.growth_exact_packet_observation_with_progress(packet, progress),
        _ => unreachable!(),
    }
}

#[test]
fn native_growth_v2_head_and_exact_observations_refuse_foreign_commit_at_ready() {
    for kind in 0..2 {
        let directory = tempfile::tempdir().unwrap();
        let settings = settings();
        let mut node =
            Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone())
                .unwrap();
        let packet = make(
            &node,
            settings.genesis(),
            vec![transfer(&settings, 0, 1, public(9), 1000)],
        );
        admit(&mut node, &packet);
        let expected = progress_observation(&node, &packet, kind, &|_| Ok(())).unwrap();
        if kind == 1 {
            assert_eq!(expected["stored_exact"], true);
            assert_eq!(expected["active_chain_member"], true);
        }
        let before = rows(&node.db);
        let changes = node.db.total_changes();
        let version = data_version(&node);
        let path = directory.path().join("native.sqlite");
        let probe = install_epoch_probe(&mut node, &path, None, true);
        let result = progress_observation(&node, &packet, kind, &|point| {
            if matches!(point, GrowthProgress::ObservationReady) {
                // Exact observation has completed real retained W1/M06/proof
                // replay and membership; head has read its actual active row.
                probe.commit(&path, true);
            }
            Ok(())
        });
        remove_epoch_probe(&mut node);
        assert_epoch_error(result);
        probe.assert_snapshot_checks();
        assert!(node.db.is_autocommit());
        assert_ne!(data_version(&node), version);
        assert_eq!(node.db.total_changes(), changes);
        assert_eq!(rows(&node.db), before);
        assert_epoch_error(progress_observation(&node, &packet, kind, &|_| Ok(())));
        drop(node);
        let reopened =
            Node::open_with_permanent_account_growth_v2(directory.path(), settings).unwrap();
        assert_eq!(
            progress_observation(&reopened, &packet, kind, &|_| Ok(())).unwrap(),
            expected
        );
        assert_eq!(rows(&reopened.db), before);
    }
}

fn autocommit_query(node: &Node, block: Hash, kind: u8) -> Result<serde_json::Value> {
    match kind {
        0 => Ok(json!(hex::encode(node.growth_packet(block)?.encode()?))),
        1 => Ok(json!(hex::encode(node.growth_expected_target(block)?))),
        _ => unreachable!(),
    }
}

#[test]
fn native_growth_v2_autocommit_queries_recheck_foreign_epoch_after_read() {
    for kind in 0..2 {
        let directory = tempfile::tempdir().unwrap();
        let settings = settings();
        let mut node =
            Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone())
                .unwrap();
        let packet = make(
            &node,
            settings.genesis(),
            vec![transfer(&settings, 0, 1, public(9), 1000)],
        );
        let block = admit(&mut node, &packet);
        let expected = autocommit_query(&node, block, kind).unwrap();
        let before = rows(&node.db);
        let changes = node.db.total_changes();
        let version = data_version(&node);
        let probe = install_epoch_probe(
            &mut node,
            &directory.path().join("native.sqlite"),
            Some("blocks"),
            false,
        );
        let result = autocommit_query(&node, block, kind);
        remove_epoch_probe(&mut node);
        assert_epoch_error(result);
        assert!(probe.committed.load(Ordering::Relaxed));
        assert_eq!(
            probe.events.lock().unwrap().as_slice(),
            ["foreign-committed", "fresh-version-check"]
        );
        assert!(node.db.is_autocommit());
        assert_ne!(data_version(&node), version);
        assert_eq!(node.db.total_changes(), changes);
        assert_eq!(rows(&node.db), before);
        assert_epoch_error(autocommit_query(&node, block, kind));
        drop(node);
        let reopened =
            Node::open_with_permanent_account_growth_v2(directory.path(), settings).unwrap();
        assert_eq!(autocommit_query(&reopened, block, kind).unwrap(), expected);
        assert_eq!(rows(&reopened.db), before);
    }
}

#[test]
fn native_growth_v2_successful_payment_rechecks_epoch_after_read_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone()).unwrap();
    let amount = 2_000u64;
    let deadline = 20u64;
    let task = hash(
        b"task-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &public(0),
            &1u64.to_le_bytes(),
            &public(1),
            &amount.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let mut reserve = task.to_vec();
    reserve.extend(public(1));
    reserve.extend(amount.to_le_bytes());
    reserve.extend(deadline.to_le_bytes());
    let first = make(
        &node,
        settings.genesis(),
        vec![signed(&settings, 0, 1, 2, reserve)],
    );
    let first_id = admit(&mut node, &first);
    let output = [71u8; 32];
    let mut payload = task.to_vec();
    payload.extend(output);
    let receipt = signed(&settings, 1, 1, 4, payload.clone());
    let settle = signed(&settings, 0, 2, 5, payload);
    let query = NativePaymentQueryV1 {
        source: NativeFundingSourceV1::Task(task),
        subject: output,
        beneficiary: public(1),
        operation: Envelope::decode(&settle).unwrap().id().unwrap(),
        maximum_gross_units: amount,
    };
    let second = make(&node, first_id, vec![receipt, settle]);
    let settled = admit(&mut node, &second);
    // This must be an actual successful signed escrow payment, not a fixture
    // that already returns NOT_CONFIRMED before the foreign write is injected.
    let expected = node.native_payment_observation(&query).unwrap();
    assert_eq!(expected.anchor.block, settled);
    assert_eq!(expected.gross_escrow_debit, amount);
    assert_eq!(expected.beneficiary_credit, amount);
    let before = rows(&node.db);
    let changes = node.db.total_changes();
    let version = data_version(&node);
    let probe = install_epoch_probe(
        &mut node,
        &directory.path().join("native.sqlite"),
        Some("growth_states"),
        true,
    );
    let result = node.native_payment_observation(&query);
    remove_epoch_probe(&mut node);
    assert_epoch_error(result);
    // Reaching the fresh check proves the original success path completed its
    // transition replay and explicit rollback, rather than an early error drop.
    probe.assert_snapshot_checks();
    assert!(node.db.is_autocommit());
    assert_ne!(data_version(&node), version);
    assert_eq!(node.db.total_changes(), changes);
    assert_eq!(rows(&node.db), before);
    assert_epoch_error(node.native_payment_observation(&query));
    drop(node);
    let reopened = Node::open_with_permanent_account_growth_v2(directory.path(), settings).unwrap();
    assert_eq!(
        reopened.native_payment_observation(&query).unwrap(),
        expected
    );
    assert_eq!(rows(&reopened.db), before);
}
