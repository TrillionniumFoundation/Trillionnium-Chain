use super::*;
use crate::store::native_ancestry_commit_tests::{logical_rows, open};
use crate::{development_public, ErrorCode, Hash, Packet, Settings};
use rusqlite::params;
use serde_json::{json, Value};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::{hash, Envelope};

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

fn inspect_without_writes(node: &Node, source: SourcePins) -> CheckpointInventory {
    let before = logical_rows(&node.db);
    let active = node.active().unwrap();
    let changes = node.db.total_changes();
    assert!(node.db.is_autocommit());
    let report = node.inspect_pq_migration_checkpoint(source).unwrap();
    assert!(node.db.is_autocommit());
    assert_eq!(node.db.total_changes(), changes);
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(logical_rows(&node.db), before);
    report
}

fn refuse_without_writes(node: &Node, source: SourcePins, expected: &str) -> Error {
    let before = logical_rows(&node.db);
    let active = node.active().unwrap();
    let changes = node.db.total_changes();
    assert!(node.db.is_autocommit());
    let error = node.inspect_pq_migration_checkpoint(source).unwrap_err();
    assert_eq!(error.to_string(), expected);
    assert!(node.db.is_autocommit());
    assert_eq!(node.db.total_changes(), changes);
    assert_eq!(node.active().unwrap(), active);
    assert_eq!(logical_rows(&node.db), before);
    error
}

#[test]
fn fixed_admitted_checkpoint_keeps_inventory_across_forks_reorg_and_cold_open() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(directory.path(), settings.clone(), authenticated);
        let left = block(&node, settings.genesis(), vec![transfer(&settings)], 11, 7);
        let left_id = node.admit(&left, 1000).unwrap();
        node.activate(left_id).unwrap();
        let selected = pins(&settings, left_id);
        let report = inspect_without_writes(&node, selected);
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
        let side_report = inspect_without_writes(&node, pins(&settings, right_id));
        assert_eq!(side_report.checkpoint, hex::encode(right_id));
        assert_eq!(side_report.state_root, hex::encode(right.header.state));
        assert_eq!(side_report.accounts_with_nonce_floor, 0);
        assert_eq!(side_report.greatest_nonce_floor, 0);
        let original_side = serde_json::to_value(side_report).unwrap();
        let target = block(&node, right_id, vec![], 22, 8);
        let target_id = node.admit(&target, 1000).unwrap();
        assert_eq!(node.activate(target_id).unwrap(), target_id);
        assert_eq!(
            serde_json::to_value(inspect_without_writes(&node, selected)).unwrap(),
            original_report
        );
        drop(node);
        let node = open(directory.path(), settings.clone(), authenticated);
        assert_eq!(node.active().unwrap().0, target_id);
        assert_eq!(
            serde_json::to_value(inspect_without_writes(&node, selected)).unwrap(),
            original_report
        );
        assert_eq!(
            serde_json::to_value(inspect_without_writes(&node, pins(&settings, right_id))).unwrap(),
            original_side
        );
    }
}

#[test]
fn inventory_requires_independent_source_pins_and_actual_admission() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = open(directory.path(), settings.clone(), true);
    let packet = block(&node, settings.genesis(), vec![], 11, 7);
    let selected = pins(&settings, packet.id().unwrap());
    // A real locally produced work packet is still unknown until admission.
    refuse_without_writes(&node, selected, "UNKNOWN_PARENT");
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
        refuse_without_writes(&node, wrong, "PQ_INVENTORY_CHECKPOINT");
    }
    refuse_without_writes(
        &node,
        pins(&settings, settings.genesis()),
        "GENESIS_HAS_NO_PACKET",
    );
    refuse_without_writes(&node, pins(&settings, [9; 32]), "UNKNOWN_PARENT");
    inspect_without_writes(&node, selected);
}

#[test]
fn inventory_rechecks_actual_state_packet_and_storage_context_after_a_prior_success() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(directory.path(), settings.clone(), authenticated);
        let packet = block(&node, settings.genesis(), vec![transfer(&settings)], 11, 7);
        let id = node.admit(&packet, 1000).unwrap();
        node.activate(id).unwrap();
        let selected = pins(&settings, id);
        let original = serde_json::to_value(inspect_without_writes(&node, selected)).unwrap();
        let key = format!("account:{}", hex::encode(development_public(0).unwrap()));
        let slot = node.slot().unwrap();
        let original_account: Vec<u8> = node
            .db
            .query_row(
                "SELECT value FROM kv WHERE slot=? AND key=?",
                params![slot, key],
                |row| row.get(0),
            )
            .unwrap();
        let mut changed: Value = serde_json::from_slice(&original_account).unwrap();
        changed["balance"] = json!(changed["balance"].as_u64().unwrap() - 1);
        node.db
            .execute(
                "UPDATE kv SET value=? WHERE slot=? AND key=?",
                params![serde_json::to_vec(&changed).unwrap(), slot, key],
            )
            .unwrap();
        assert!(refuse_without_writes(&node, selected, "ROOT").requires_owner_stop());
        node.db
            .execute(
                "UPDATE kv SET value=? WHERE slot=? AND key=?",
                params![original_account, slot, key],
            )
            .unwrap();
        assert_eq!(
            serde_json::to_value(inspect_without_writes(&node, selected)).unwrap(),
            original
        );

        let mut wrong_packet = packet.clone();
        wrong_packet.header.state[0] ^= 1;
        node.db
            .execute(
                "UPDATE blocks SET packet=? WHERE id=?",
                params![wrong_packet.encode().unwrap(), id.as_slice()],
            )
            .unwrap();
        assert!(refuse_without_writes(&node, selected, "STORAGE_PACKET").requires_owner_stop());
        node.db
            .execute(
                "UPDATE blocks SET packet=? WHERE id=?",
                params![packet.encode().unwrap(), id.as_slice()],
            )
            .unwrap();

        node.db
            .execute(
                "UPDATE metadata SET value=? WHERE key='parameters'",
                [[9_u8; 32].as_slice()],
            )
            .unwrap();
        assert!(refuse_without_writes(&node, selected, "STORAGE_CONTEXT").requires_owner_stop());
        node.db
            .execute(
                "UPDATE metadata SET value=? WHERE key='parameters'",
                [settings.parameters().as_slice()],
            )
            .unwrap();
        assert_eq!(
            serde_json::to_value(inspect_without_writes(&node, selected)).unwrap(),
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
        let left = block(&node, settings.genesis(), vec![], 11, 7);
        let left_id = node.admit(&left, 1000).unwrap();
        node.activate(left_id).unwrap();
        let source = pins(&settings, left_id);
        let original = serde_json::to_value(inspect_without_writes(&node, source)).unwrap();
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
                        Err(Error::new(ErrorCode::StoragePacket).local_integrity())
                    } else {
                        Ok(())
                    }
                }),
            )
            .unwrap_err();
        assert!(error.requires_owner_stop());
        assert_eq!(
            node.db
                .query_row::<u64, _, _>("SELECT done FROM reorg WHERE singleton=1", [], |row| row
                    .get(0),)
                .unwrap(),
            0
        );
        refuse_without_writes(&node, source, "REORG_IN_PROGRESS");
        refuse_without_writes(&node, pins(&settings, target_id), "REORG_IN_PROGRESS");
        drop(node);
        let node = open(directory.path(), settings, authenticated);
        assert_eq!(node.active().unwrap().0, target_id);
        assert_eq!(
            serde_json::to_value(inspect_without_writes(&node, source)).unwrap(),
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
    refuse_without_writes(
        &node,
        pins(&settings, [9; 32]),
        "GROWTH_COMPLETE_STATE_UNAVAILABLE",
    );
}
