//! Actual wall-clock mining on a valid branch with future-dated ancestors.
//! No logical mining clock, difficulty change or proof shortcut is introduced.
use std::{
    sync::{atomic::AtomicBool, Arc, Mutex},
    time::Duration,
};
use trnm_crypto_primitives::{pon_work, sign_hex, signing_key_from_hex};
use trnm_pon_node::{
    development_public, ingress,
    mining::{run_pool_mining, MiningConfig, MiningMaterial},
    Node, PoolLimits, PoolState, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope};

fn setup(path: &std::path::Path, now: u64) -> (Node, Settings, MiningConfig) {
    let settings = Settings::development(Some(now - 100)).unwrap();
    let mut node = Node::open(path, settings.clone(), 2).unwrap();
    let miner = development_public(0).unwrap();
    node.enable_local_mempool(PoolLimits {
        max_records: 32,
        max_bytes: 65536,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 32,
        preview_miner: miner,
    })
    .unwrap();
    let config = MiningConfig {
        miner,
        material: MiningMaterial::LegacyDevelopment,
        max_transactions: 256,
        max_transaction_bytes: 524288,
        search_attempts: 4096,
        pace: Duration::from_secs(1),
        runtime: Duration::from_secs(2),
        max_blocks: 1,
    };
    (node, settings, config)
}

fn queued_transfer(settings: &Settings) -> Vec<u8> {
    let mut payload = development_public(1).unwrap().to_vec();
    payload.extend(7u64.to_le_bytes());
    let mut tx = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce: 1,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}

fn append(node: &mut Node, timestamp: u64, observed_now: u64) -> Vec<u8> {
    let packet = node
        .make(
            node.active().unwrap().0,
            Vec::new(),
            development_public(0).unwrap(),
            timestamp,
            4096,
        )
        .unwrap();
    // A target hit alone is not sufficient: both the full verifier and the
    // actual ordinary Node admission/activation execute for every ancestor.
    pon_work::verify(
        packet.header.challenge(),
        packet.header.work_task,
        packet.header.target,
        &packet.proof,
    )
    .unwrap();
    let id = node.admit(&packet, observed_now).unwrap();
    node.activate_observed(id, observed_now).unwrap();
    packet.encode().unwrap()
}

#[test]
fn valid_future_tip_does_not_suppress_real_wall_clock_successor() {
    let directory = tempfile::tempdir().unwrap();
    let wall = ingress::now().unwrap();
    let (mut node, settings, config) = setup(directory.path(), wall);
    let ancestors = [wall - 80, wall - 70, wall + 60]
        .map(|timestamp| hex::encode(append(&mut node, timestamp, wall)));
    let future_parent = node.active().unwrap();
    let raw = queued_transfer(&settings);
    node.pool_submit(raw.clone()).unwrap();
    let owner = Arc::new(Mutex::new(node));
    let mut events = Vec::new();
    let report = run_pool_mining(
        owner.clone(),
        config,
        Arc::new(AtomicBool::new(false)),
        |event| {
            events.push(serde_json::to_value(event)?);
            Ok(())
        },
    )
    .unwrap();
    let mut node = owner.lock().unwrap();
    let actual = node.active().unwrap();
    eprintln!(
        "PON_MINING_TIME_OBSERVATION {}",
        serde_json::json!({
            "schema":"pon-wall-clock-median-regression-v1",
            "case":"valid-future-tip", "wall_before":wall,
            "ancestor_packets_hex":ancestors, "queued_transfer_hex":hex::encode(&raw),
            "parent":hex::encode(future_parent.0), "active_after":hex::encode(actual.0),
            "active_packet_hex":hex::encode(node.packet(actual.0).unwrap().encode().unwrap()),
            "report":report, "events":events,
            "logical_mining_clock":false, "production_qualified":false
        })
    );
    assert_eq!(
        report.activated_blocks, 1,
        "an admissible real-wall child must be searched"
    );
    assert_eq!(report.included_transactions, 1);
    assert_eq!(report.stop_reason, "block-limit");
    let packet = node.packet(actual.0).unwrap();
    assert_eq!(packet.header.parent, future_parent.0);
    assert_eq!(packet.transactions, vec![raw]);
    assert_eq!(
        packet.header.timestamp,
        events[0]["observed_wall_seconds"].as_u64().unwrap()
    );
    assert!(packet.header.timestamp >= wall);
    assert!(packet.header.timestamp < wall + 60);
    assert!(packet.header.timestamp > wall - 70);
    pon_work::verify(
        packet.header.challenge(),
        packet.header.work_task,
        packet.header.target,
        &packet.proof,
    )
    .unwrap();
    let pool = node.pool_status().unwrap();
    assert_eq!(pool.retained_records, 1);
    assert_eq!(pool.groups[0].state, PoolState::SequenceConsumed);
    let encoded = packet.encode().unwrap();
    drop(node);
    drop(owner);
    let reopened = Node::open(directory.path(), settings, 2).unwrap();
    assert_eq!(reopened.active().unwrap(), actual);
    assert_eq!(
        reopened.packet(actual.0).unwrap().encode().unwrap(),
        encoded
    );
}

#[test]
fn future_median_still_waits_without_advancing_the_mining_clock() {
    let directory = tempfile::tempdir().unwrap();
    let wall = ingress::now().unwrap();
    let (mut node, settings, mut config) = setup(directory.path(), wall);
    let ancestors = [wall + 60, wall + 61, wall + 62]
        .map(|timestamp| hex::encode(append(&mut node, timestamp, wall)));
    let before = node.active().unwrap();
    node.pool_submit(queued_transfer(&settings)).unwrap();
    config.runtime = Duration::from_millis(150);
    let owner = Arc::new(Mutex::new(node));
    let report = run_pool_mining(
        owner.clone(),
        config,
        Arc::new(AtomicBool::new(false)),
        |_| panic!("future median cannot authorize a wall-clock search"),
    )
    .unwrap();
    eprintln!(
        "PON_MINING_TIME_OBSERVATION {}",
        serde_json::json!({
            "schema":"pon-wall-clock-median-regression-v1",
            "case":"future-median", "wall_before":wall,
            "ancestor_packets_hex":ancestors, "report":report,
            "logical_mining_clock":false, "production_qualified":false
        })
    );
    assert_eq!(report.activated_blocks, 0);
    assert_eq!(report.attempted_searches, 0);
    assert_eq!(report.observed_work_trials, 0);
    assert_eq!(report.stop_reason, "runtime");
    let mut node = owner.lock().unwrap();
    assert_eq!(node.active().unwrap(), before);
    let pool = node.pool_status().unwrap();
    assert_eq!(pool.retained_records, 1);
    assert_eq!(pool.groups[0].state, PoolState::Queued);
}
