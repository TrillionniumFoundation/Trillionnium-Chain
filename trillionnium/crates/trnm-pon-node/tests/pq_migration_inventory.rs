//! Public Node inventory checks against real admitted blocks and SQLite files.
//!
//! The stricter same-connection unit suite remains in
//! src/store/pq_migration_inventory_tests.rs. This independent target does not
//! read Node's private connection counters or autocommit flag. It observes
//! committed logical rows and data_version through a separate read-only SQLite
//! connection; the production wrapper retains its own total_changes guard.
use rusqlite::{params, Connection, OpenFlags};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::pon_executor::pq_accounts_v2::migration_inventory_v1::{
    self, CheckpointInventory, SourcePins,
};
use trnm_pon_node::{development_public, Error, ErrorCode, Node, Packet, Settings};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

fn open(path: &Path, settings: Settings, authenticated: bool) -> Node {
    if authenticated {
        Node::open_with_authenticated_state(path, settings, 1).unwrap()
    } else {
        Node::open(path, settings, 1).unwrap()
    }
}

fn observer(directory: &Path) -> Connection {
    Connection::open_with_flags(
        directory.join("native.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
}

fn data_version(db: &Connection) -> u64 {
    db.query_row("PRAGMA data_version", [], |row| row.get(0))
        .unwrap()
}

fn logical_rows(db: &Connection) -> BTreeMap<String, Vec<Vec<String>>> {
    // Each observation has its own read snapshot. Never keep this transaction
    // across the Node call: doing so could hide a new commit from the observer.
    let tx = db.unchecked_transaction().unwrap();
    let tables: Vec<String> = tx
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|row| row.unwrap())
        .collect();
    let result = tables
        .into_iter()
        .map(|table| {
            assert!(table
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
            let mut statement = tx.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let columns = statement.column_count();
            let mut rows: Vec<Vec<String>> = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|index| {
                            row.get::<_, rusqlite::types::Value>(index)
                                .map(|value| format!("{value:?}"))
                        })
                        .collect()
                })
                .unwrap()
                .map(|row| row.unwrap())
                .collect();
            rows.sort();
            (table, rows)
        })
        .collect();
    tx.rollback().unwrap();
    result
}

fn pins(settings: &Settings, checkpoint: Hash) -> SourcePins {
    SourcePins {
        network: settings.network(),
        genesis: settings.genesis(),
        checkpoint,
    }
}

fn transfer(settings: &Settings) -> Vec<u8> {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(7_u64.to_le_bytes());
    let mut transaction = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce: 1,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    transaction.signature = hex::decode(sign_hex(&key, &transaction.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    transaction.encode().unwrap()
}

fn block(node: &Node, parent: Hash, transactions: Vec<Vec<u8>>, time: u64, miner: u64) -> Packet {
    node.make(
        parent,
        transactions,
        development_public(miner).unwrap(),
        time,
        4096,
    )
    .unwrap()
}

fn inspect_without_writes(node: &Node, db: &Connection, source: SourcePins) -> CheckpointInventory {
    let before = logical_rows(db);
    let active = node.active().unwrap();
    let version = data_version(db);
    let report = node.inspect_pq_migration_checkpoint(source).unwrap();
    assert_eq!(data_version(db), version);
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(logical_rows(db), before);
    report
}

fn refuse_without_writes(
    node: &Node,
    db: &Connection,
    source: SourcePins,
    expected: &str,
) -> Error {
    let before = logical_rows(db);
    let active = node.active().unwrap();
    let version = data_version(db);
    let error = node.inspect_pq_migration_checkpoint(source).unwrap_err();
    assert_eq!(error.to_string(), expected);
    assert_eq!(data_version(db), version);
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(logical_rows(db), before);
    error
}

#[test]
fn fixed_admitted_checkpoint_keeps_inventory_across_forks_reorg_and_cold_open() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(directory.path(), settings.clone(), authenticated);
        let db = observer(directory.path());
        let left = block(&node, settings.genesis(), vec![transfer(&settings)], 11, 7);
        let left_id = node.admit(&left, 1000).unwrap();
        node.activate(left_id).unwrap();
        let selected = pins(&settings, left_id);
        let report = inspect_without_writes(&node, &db, selected);
        let state = node.state_at(left_id).unwrap();
        let accounts: Vec<_> = state
            .iter()
            .filter(|(key, _)| key.starts_with("account:"))
            .map(|(_, value)| value)
            .collect();
        assert_eq!(report.source_network, hex::encode(settings.network()));
        assert_eq!(report.source_genesis, hex::encode(settings.genesis()));
        assert_eq!(report.checkpoint, hex::encode(left_id));
        assert_eq!(report.state_root, hex::encode(left.header.state));
        assert_eq!(report.source_height, 1);
        assert_eq!(report.source_timestamp, 11);
        assert_eq!(report.state_rows, state.len());
        assert_eq!(report.accounts.rows, accounts.len());
        assert_eq!(
            report.accounts.units,
            accounts
                .iter()
                .map(|row| row["balance"].as_u64().unwrap())
                .sum::<u64>()
        );
        assert_eq!(report.accounts_with_nonce_floor, 1);
        assert_eq!(report.greatest_nonce_floor, 1);
        assert_eq!(report.rewards.rows, 1);
        assert!(report.rewards.units > 0);
        assert_eq!(
            report.tasks.rows + report.quotas.rows + report.releases.rows,
            0
        );
        assert_eq!(
            report.issued_units,
            report.accounts.units + report.rewards.units
        );
        assert_eq!(
            report.disposition,
            migration_inventory_v1::LedgerDisposition::PreservationRequired
        );
        let original_report = serde_json::to_value(report).unwrap();

        // A different admitted child has no transfer. Its inventory must use
        // that branch's actual replay, not the current active KV or its nonce.
        let right = block(&node, settings.genesis(), vec![], 12, 8);
        let right_id = node.admit(&right, 1000).unwrap();
        assert_eq!(node.active().unwrap().0, left_id);
        let side_report = inspect_without_writes(&node, &db, pins(&settings, right_id));
        assert_eq!(side_report.checkpoint, hex::encode(right_id));
        assert_eq!(side_report.state_root, hex::encode(right.header.state));
        assert_eq!(side_report.accounts_with_nonce_floor, 0);
        assert_eq!(side_report.greatest_nonce_floor, 0);
        let original_side = serde_json::to_value(side_report).unwrap();
        let target = block(&node, right_id, vec![], 22, 8);
        let target_id = node.admit(&target, 1000).unwrap();
        assert_eq!(node.activate(target_id).unwrap(), target_id);
        assert_eq!(
            serde_json::to_value(inspect_without_writes(&node, &db, selected)).unwrap(),
            original_report
        );
        drop(db);
        drop(node);
        let node = open(directory.path(), settings.clone(), authenticated);
        let db = observer(directory.path());
        assert_eq!(node.active().unwrap().0, target_id);
        assert_eq!(
            serde_json::to_value(inspect_without_writes(&node, &db, selected)).unwrap(),
            original_report
        );
        assert_eq!(
            serde_json::to_value(inspect_without_writes(
                &node,
                &db,
                pins(&settings, right_id)
            ))
            .unwrap(),
            original_side
        );
    }
}

#[test]
fn inventory_requires_independent_source_pins_and_actual_admission() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = open(directory.path(), settings.clone(), true);
    let db = observer(directory.path());
    let packet = block(&node, settings.genesis(), vec![], 11, 7);
    let selected = pins(&settings, packet.id().unwrap());
    // A real locally produced work packet is still unknown until admission.
    refuse_without_writes(&node, &db, selected, "UNKNOWN_PARENT");
    let id = node.admit(&packet, 1000).unwrap();
    node.activate(id).unwrap();
    for wrong in [
        SourcePins {
            network: [9; 32],
            ..selected
        },
        SourcePins {
            genesis: [9; 32],
            ..selected
        },
        SourcePins {
            checkpoint: [0; 32],
            ..selected
        },
    ] {
        refuse_without_writes(&node, &db, wrong, "PQ_INVENTORY_CHECKPOINT");
    }
    refuse_without_writes(
        &node,
        &db,
        pins(&settings, settings.genesis()),
        "GENESIS_HAS_NO_PACKET",
    );
    refuse_without_writes(&node, &db, pins(&settings, [9; 32]), "UNKNOWN_PARENT");
    inspect_without_writes(&node, &db, selected);
}

#[test]
fn inventory_rechecks_actual_state_packet_and_storage_context_after_a_prior_success() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(directory.path(), settings.clone(), authenticated);
        let db = observer(directory.path());
        // Deliberate corruption of this test's owned database uses a separate
        // writer. No production mutation API or test-only success path exists.
        let writer = Connection::open_with_flags(
            directory.path().join("native.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
        )
        .unwrap();
        let packet = block(&node, settings.genesis(), vec![transfer(&settings)], 11, 7);
        let id = node.admit(&packet, 1000).unwrap();
        node.activate(id).unwrap();
        let selected = pins(&settings, id);
        let original = serde_json::to_value(inspect_without_writes(&node, &db, selected)).unwrap();
        let key = format!("account:{}", hex::encode(development_public(0).unwrap()));
        let slot: u64 = writer
            .query_row(
                "SELECT state_slot FROM active WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let original_account: Vec<u8> = writer
            .query_row(
                "SELECT value FROM kv WHERE slot=? AND key=?",
                params![slot, key],
                |row| row.get(0),
            )
            .unwrap();
        let mut changed: Value = serde_json::from_slice(&original_account).unwrap();
        changed["balance"] = json!(changed["balance"].as_u64().unwrap() - 1);
        writer
            .execute(
                "UPDATE kv SET value=? WHERE slot=? AND key=?",
                params![serde_json::to_vec(&changed).unwrap(), slot, key],
            )
            .unwrap();
        assert!(refuse_without_writes(&node, &db, selected, "ROOT").requires_owner_stop());
        writer
            .execute(
                "UPDATE kv SET value=? WHERE slot=? AND key=?",
                params![original_account, slot, key],
            )
            .unwrap();
        assert_eq!(
            serde_json::to_value(inspect_without_writes(&node, &db, selected)).unwrap(),
            original
        );

        let mut wrong_packet = packet.clone();
        wrong_packet.header.state[0] ^= 1;
        writer
            .execute(
                "UPDATE blocks SET packet=? WHERE id=?",
                params![wrong_packet.encode().unwrap(), id.as_slice()],
            )
            .unwrap();
        assert!(
            refuse_without_writes(&node, &db, selected, "STORAGE_PACKET").requires_owner_stop()
        );
        writer
            .execute(
                "UPDATE blocks SET packet=? WHERE id=?",
                params![packet.encode().unwrap(), id.as_slice()],
            )
            .unwrap();

        writer
            .execute(
                "UPDATE metadata SET value=? WHERE key='parameters'",
                [[9_u8; 32].as_slice()],
            )
            .unwrap();
        assert!(
            refuse_without_writes(&node, &db, selected, "STORAGE_CONTEXT").requires_owner_stop()
        );
        writer
            .execute(
                "UPDATE metadata SET value=? WHERE key='parameters'",
                [settings.parameters().as_slice()],
            )
            .unwrap();
        assert_eq!(
            serde_json::to_value(inspect_without_writes(&node, &db, selected)).unwrap(),
            original
        );
    }
}

#[test]
fn inventory_refuses_durable_pending_reorg_then_uses_recovered_snapshot() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(directory.path(), settings.clone(), authenticated);
        let db = observer(directory.path());
        let left = block(&node, settings.genesis(), vec![], 11, 7);
        let left_id = node.admit(&left, 1000).unwrap();
        node.activate(left_id).unwrap();
        let source = pins(&settings, left_id);
        let original = serde_json::to_value(inspect_without_writes(&node, &db, source)).unwrap();
        let right = block(&node, settings.genesis(), vec![], 12, 8);
        let right_id = node.admit(&right, 1000).unwrap();
        let target = block(&node, right_id, vec![], 22, 8);
        let target_id = node.admit(&target, 1000).unwrap();
        // A real durable intent has been committed. Simulate an owner fault,
        // rather than typed cancellation which intentionally ends staging.
        let error = node
            .activate_with_fault(
                target_id,
                Some(&mut |point| {
                    if point == "intent" {
                        Err(Error::new(ErrorCode::StoragePacket))
                    } else {
                        Ok(())
                    }
                }),
            )
            .unwrap_err();
        assert!(error.requires_owner_stop());
        assert_eq!(
            db.query_row::<u64, _, _>("SELECT done FROM reorg WHERE singleton=1", [], |row| row
                .get(0),)
                .unwrap(),
            0
        );
        refuse_without_writes(&node, &db, source, "REORG_IN_PROGRESS");
        refuse_without_writes(&node, &db, pins(&settings, target_id), "REORG_IN_PROGRESS");
        drop(db);
        drop(node);
        let node = open(directory.path(), settings, authenticated);
        let db = observer(directory.path());
        assert_eq!(node.active().unwrap().0, target_id);
        assert_eq!(
            serde_json::to_value(inspect_without_writes(&node, &db, source)).unwrap(),
            original
        );
    }
}

#[test]
fn inventory_does_not_substitute_growth_working_partition_for_complete_state() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap()
    .with_permanent_account_growth_v2("pq-migration-inventory-test")
    .unwrap();
    let node =
        Node::open_with_permanent_account_growth_v2(directory.path(), settings.clone()).unwrap();
    let db = observer(directory.path());
    refuse_without_writes(
        &node,
        &db,
        pins(&settings, [9; 32]),
        "GROWTH_COMPLETE_STATE_UNAVAILABLE",
    );
}
