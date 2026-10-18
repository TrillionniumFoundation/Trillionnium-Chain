//! Exact task settlement readback through real Node execution and the native CLI.
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_pon_node::{development_public, Node, Packet, Settings};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

const START: u64 = 1_800_000_000;
const CLOCK: u64 = START + 10_000;

fn signed(settings: &Settings, sender: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = Envelope {
        network: settings.network(), sender: development_public(sender).unwrap(), nonce,
        expiry: 100, fee_limit: 1_000_000, tag, payload, signature: [0; 64],
    };
    let key = signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&sender.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap())).unwrap().try_into().unwrap();
    tx.encode().unwrap()
}

fn task(settings: &Settings, owner_nonce: u64, provider_nonce: u64) -> (Hash, Hash, Vec<Vec<u8>>) {
    let owner = development_public(0).unwrap();
    let provider = development_public(2).unwrap();
    let budget = 1000_u64;
    let deadline = 100_u64;
    let id = hash(b"task-instance-v3", &[&settings.network(), &settings.parameters(), &owner,
        &owner_nonce.to_le_bytes(), &provider, &budget.to_le_bytes(), &deadline.to_le_bytes()]);
    // Stand-in bytes for one exact, externally constructed Hepta binding digest.
    // No score, evaluated model or installation claim is invented by this test.
    let output = hash(b"accepted-task-test-output", &[&id]);
    let mut reserve = id.to_vec();
    reserve.extend(provider);
    reserve.extend(budget.to_le_bytes());
    reserve.extend(deadline.to_le_bytes());
    let mut receipt = id.to_vec();
    receipt.extend(output);
    (id, output, vec![
        signed(settings, 0, owner_nonce, 2, reserve),
        signed(settings, 2, provider_nonce, 4, receipt.clone()),
        signed(settings, 0, owner_nonce + 1, 5, receipt),
    ])
}

fn open(path: &Path) -> Node {
    Node::open(path, Settings::development(None).unwrap(), 2).unwrap()
}

fn make(node: &mut Node, parent: Hash, height: u64, txs: Vec<Vec<u8>>, miner: u64) -> Packet {
    let packet = node.make(parent, txs, development_public(miner).unwrap(), START + height * 10, 4096).unwrap();
    node.admit(&packet, CLOCK).unwrap();
    packet
}

fn assert_no_authority(value: &Value) {
    for name in ["global_absence_authority", "confirmation_authority", "finality_authority",
        "execution_authority", "production_activation"] {
        assert_eq!(value[name], false, "{name}");
    }
}

#[test]
fn exact_acceptance_survives_restart_and_cli_readback_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let mut node = open(&store);
    let (id, output, transactions) = task(node.settings(), 1, 1);
    let accept_tx_id = hash(b"tx-id", &[&transactions[2]]);
    let genesis = node.settings().genesis();
    let packet = make(&mut node, genesis, 1, transactions, 0);
    assert_eq!(node.exact_packet_observation(&packet).unwrap()["accepted_task"], Value::Null);
    node.activate_observed(packet.id().unwrap(), CLOCK).unwrap();
    let before = node.stats().unwrap();
    let observed = node.exact_packet_observation(&packet).unwrap();
    let expected = json!({
        "schema_version": 1,
        "task_id": hex::encode(id),
        "owner": hex::encode(development_public(0).unwrap()),
        "provider": hex::encode(development_public(2).unwrap()),
        "output_sha256": hex::encode(output),
        "accept_tx_id": hex::encode(accept_tx_id),
        "accepted_in_exact_packet": true,
        "current_status": "settled",
    });
    assert_eq!(observed["accepted_task"], expected);
    assert_no_authority(&observed);
    assert_eq!(node.exact_packet_observation(&packet).unwrap(), observed);
    assert_eq!(node.stats().unwrap(), before);
    drop(node);
    let packet_path = dir.path().join("accepted.packet");
    fs::write(&packet_path, packet.encode().unwrap()).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
        .args(["packet-status", "--development", "--store"]).arg(&store)
        .arg("--packet").arg(&packet_path).output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let cli: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(cli["result"]["accepted_task"], expected);
    assert_no_authority(&cli["result"]);
    assert_eq!(open(&store).stats().unwrap(), before);
}

#[test]
fn settlement_in_another_packet_never_rescues_a_reorged_exact_packet() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = open(dir.path());
    let (_, _, transactions) = task(node.settings(), 1, 1);
    let genesis = node.settings().genesis();
    let original = make(&mut node, genesis, 1, transactions.clone(), 0);
    node.activate_observed(original.id().unwrap(), CLOCK).unwrap();
    let fork = make(&mut node, genesis, 1, vec![], 2);
    let fork_tip = make(&mut node, fork.id().unwrap(), 2, vec![], 2);
    node.activate_observed(fork_tip.id().unwrap(), CLOCK).unwrap();
    let removed = node.exact_packet_observation(&original).unwrap();
    assert_eq!(removed["stored_exact"], true);
    assert_eq!(removed["active_chain_member"], false);
    assert_eq!(removed["accepted_task"], Value::Null);
    let replacement = make(&mut node, fork_tip.id().unwrap(), 3, transactions, 2);
    node.activate_observed(replacement.id().unwrap(), CLOCK).unwrap();
    assert!(node.exact_packet_observation(&replacement).unwrap()["accepted_task"].is_object());
    assert_eq!(node.exact_packet_observation(&original).unwrap()["accepted_task"], Value::Null);
    drop(node);
    assert_eq!(open(dir.path()).exact_packet_observation(&original).unwrap()["accepted_task"], Value::Null);
}

#[test]
fn receipt_only_and_ambiguous_multi_accept_packets_have_no_upgrade_binding() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = open(dir.path());
    let (_, _, first) = task(node.settings(), 1, 1);
    let (_, _, second) = task(node.settings(), 3, 2);
    let genesis = node.settings().genesis();
    let receipt = make(&mut node, genesis, 1, first[..2].to_vec(), 0);
    node.activate_observed(receipt.id().unwrap(), CLOCK).unwrap();
    assert_eq!(node.exact_packet_observation(&receipt).unwrap()["accepted_task"], Value::Null);
    let mut accepts = vec![first[2].clone()];
    accepts.extend(second);
    let ambiguous = make(&mut node, receipt.id().unwrap(), 2, accepts, 0);
    node.activate_observed(ambiguous.id().unwrap(), CLOCK).unwrap();
    assert_eq!(node.exact_packet_observation(&ambiguous).unwrap()["accepted_task"], Value::Null);
}

#[test]
fn altered_current_task_bytes_cannot_become_a_settlement_observation() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = open(dir.path());
    let (task_id, _, transactions) = task(node.settings(), 1, 1);
    let genesis = node.settings().genesis();
    let packet = make(&mut node, genesis, 1, transactions, 0);
    node.activate_observed(packet.id().unwrap(), CLOCK).unwrap();
    assert!(node.exact_packet_observation(&packet).unwrap()["accepted_task"].is_object());
    let key = format!("task:{}", hex::encode(task_id));
    let mut forged = node.read_active().unwrap().2[&key].clone();
    forged["output"] = json!("ff".repeat(32));
    let db = rusqlite::Connection::open(dir.path().join("native.sqlite")).unwrap();
    assert!(db.execute("UPDATE kv SET value=? WHERE key=?",
        rusqlite::params![serde_json::to_vec(&forged).unwrap(), &key]).unwrap() > 0);
    assert!(node.exact_packet_observation(&packet).is_err());
}
