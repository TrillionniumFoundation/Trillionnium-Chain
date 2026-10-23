//! Independent native processes exchange actual PNP2 bytes in an explicitly
//! selected development namespace. Historical CLI/packet namespaces stay distinct.
use serde_json::{json, Value};
use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::continuity_v1;
use trnm_pon_node::{development_public, GrowthPacket, Settings};
use trnm_protocol::pon_wire::{hash, Envelope};

const NAMESPACE: &str = "native-growth-cli-v2";
fn command(name: &str, store: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    cmd.arg(name)
        .args([
            "--development",
            "--genesis-time",
            "1",
            "--growth-namespace",
            NAMESPACE,
        ])
        .arg("--store")
        .arg(store);
    cmd
}
fn accepted(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn rejected(output: Output, text: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(text),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn packet_status(store: &Path, packet: &[u8]) -> Output {
    let mut child = command("growth-packet-status", store)
        .arg("--packet-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(packet).unwrap();
    child.wait_with_output().unwrap()
}
fn signed_transfer() -> String {
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap()
    .with_permanent_account_growth_v2(NAMESPACE)
    .unwrap();
    let mut payload = development_public(9).unwrap().to_vec();
    payload.extend(10_000u64.to_le_bytes());
    let mut envelope = Envelope {
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
    envelope.signature = hex::decode(sign_hex(&key, &envelope.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    hex::encode(envelope.encode().unwrap())
}

#[test]
fn native_growth_v2_cli_signed_packet_remote_admission_and_cold_current_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let producer = dir.path().join("producer");
    let validator = dir.path().join("validator");
    let txs = dir.path().join("transactions.json");
    std::fs::write(&txs, serde_json::to_vec(&vec![signed_transfer()]).unwrap()).unwrap();
    let packet = dir.path().join("block.pnp2");
    let mined = accepted(
        command("growth-mine", &producer)
            .arg("--transactions")
            .arg(&txs)
            .args([
                "--timestamp",
                "11",
                "--logical-now",
                "1000",
                "--miner",
                &hex::encode(development_public(3).unwrap()),
            ])
            .arg("--output")
            .arg(&packet)
            .output()
            .unwrap(),
    );
    assert_eq!(mined["result"]["admitted"], true);
    assert_eq!(mined["result"]["state"]["height"], 1);
    assert_eq!(mined["result"]["state"]["permanent_accounts"], 5);
    assert_eq!(&std::fs::read(&packet).unwrap()[..4], b"PNP2");
    let received = accepted(
        command("growth-submit", &validator)
            .arg("--packet")
            .arg(&packet)
            .args(["--logical-now", "1000"])
            .output()
            .unwrap(),
    );
    assert_eq!(received["result"]["state"], mined["result"]["state"]);
    // Independent cold process lookup also handles a lost submit response;
    // the caller supplies the original bytes, never a retagged PNP1 receipt.
    let bytes = std::fs::read(&packet).unwrap();
    let observed = accepted(packet_status(&validator, &bytes));
    let observed = &observed["result"];
    assert_eq!(
        observed["schema"],
        "pon-native-exact-growth-packet-observation-v1"
    );
    assert_eq!(observed["packet_profile"], "PNP2");
    assert_eq!(
        observed["state_profile"],
        "permanent-account-growth-native-v2"
    );
    assert_eq!(observed["block"], mined["result"]["block"]);
    assert_eq!(observed["stored_exact"], true);
    assert_eq!(observed["active_chain_member"], true);
    assert_eq!(observed["active_depth"], 0);
    assert!(observed["accepted_task"].is_null());
    for field in ["network", "parameters", "genesis", "generation"] {
        assert_eq!(observed[field], received["result"]["state"][field]);
    }
    let mut changed = GrowthPacket::decode(&bytes).unwrap();
    changed.proof[0] ^= 1;
    rejected(
        packet_status(&validator, &changed.encode().unwrap()),
        "DUPLICATE_CONTENT",
    );
    let missing = dir.path().join("status-must-not-create");
    rejected(
        packet_status(&missing, &bytes),
        "GROWTH_PACKET_STATUS_EXISTING_STORE_REQUIRED",
    );
    assert!(!missing.exists());
    let mut wrong_context = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    rejected(
        wrong_context
            .args([
                "growth-packet-status",
                "--development",
                "--genesis-time",
                "1",
                "--growth-namespace",
                "foreign-growth-cli-v2",
            ])
            .arg("--store")
            .arg(&validator)
            .arg("--packet")
            .arg(&packet)
            .output()
            .unwrap(),
        "STORAGE_CONTEXT",
    );
    let current = accepted(command("growth-recover", &validator).output().unwrap());
    assert_eq!(current["result"], mined["result"]["state"]);
    let account = accepted(
        command("growth-account", &validator)
            .args(["--owner", &hex::encode(development_public(9).unwrap())])
            .output()
            .unwrap(),
    );
    assert_eq!(
        account["result"]["account"],
        json!({"balance":10_000,"nonce":0})
    );
    assert_eq!(account["result"]["authenticated_absence"], false);
    let working = accepted(
        command("growth-working", &validator)
            .args(["--key", "meta:issued"])
            .output()
            .unwrap(),
    );
    assert_eq!(
        working["result"]["state_root"],
        current["result"]["state_root"]
    );
    assert!(working["result"]["rows"]["row"].as_u64().unwrap() > 0);
    let owners = dir.path().join("owners.json");
    std::fs::write(
        &owners,
        serde_json::to_vec(&vec![
            hex::encode(development_public(9).unwrap()),
            hex::encode(development_public(999).unwrap()),
        ])
        .unwrap(),
    )
    .unwrap();
    let proof = accepted(
        command("growth-witness", &validator)
            .arg("--owners")
            .arg(&owners)
            .output()
            .unwrap(),
    );
    assert_eq!(
        proof["result"]["observation"]["expanded_witnesses_allocated"],
        0
    );
    let exported = dir.path().join("exported.pnp2");
    accepted(
        command("growth-export", &validator)
            .args(["--block", current["result"]["block"].as_str().unwrap()])
            .arg("--output")
            .arg(&exported)
            .output()
            .unwrap(),
    );
    assert_eq!(
        std::fs::read(exported).unwrap(),
        std::fs::read(packet).unwrap()
    );
}

#[test]
fn native_growth_v2_cli_rejects_ambiguous_or_malformed_inputs_before_creating_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("never-created");
    rejected(
        command("growth-status", &store)
            .args(["--state-backend", "legacy-v2"])
            .output()
            .unwrap(),
        "GROWTH_OPTION",
    );
    assert!(!store.exists());
    rejected(
        command("growth-packet-status", &store)
            .args(["--state-backend", "authenticated-v1"])
            .output()
            .unwrap(),
        "GROWTH_OPTION",
    );
    assert!(!store.exists());
    rejected(
        command("growth-account", &store)
            .args(["--owner", "invalid"])
            .output()
            .unwrap(),
        "HASH",
    );
    assert!(!store.exists());
    let bad = dir.path().join("bad.packet");
    std::fs::write(&bad, b"PNP1").unwrap();
    rejected(
        command("growth-submit", &store)
            .arg("--packet")
            .arg(bad)
            .output()
            .unwrap(),
        "PACKET_LIMIT",
    );
    assert!(!store.exists());
    let occupied = dir.path().join("occupied.packet");
    std::fs::write(&occupied, b"preserved").unwrap();
    rejected(
        command("growth-make", &store)
            .args([
                "--timestamp",
                "11",
                "--miner",
                &hex::encode(development_public(3).unwrap()),
            ])
            .arg("--output")
            .arg(&occupied)
            .output()
            .unwrap(),
        "GROWTH_OUTPUT_EXISTS",
    );
    assert!(!store.exists());
    assert_eq!(std::fs::read(occupied).unwrap(), b"preserved");
    let existing = dir.path().join("existing");
    let old = Settings::development(Some(1)).unwrap();
    drop(trnm_pon_node::Node::open(&existing, old, 1).unwrap());
    let before = std::fs::read(existing.join("native.sqlite")).unwrap();
    rejected(
        command("growth-status", &existing).output().unwrap(),
        "SCHEMA",
    );
    assert_eq!(
        before,
        std::fs::read(existing.join("native.sqlite")).unwrap()
    );
}

#[test]
fn capacity_observe_refuses_complete_state_reference_before_creating_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("never-created");
    let output = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"))
        .args([
            "capacity-observe",
            "--development",
            "--genesis-time",
            "1",
            "--evaluation-policy",
            "native-public-evaluation-dev-v1",
            "--task-profile",
            trnm_mvcc_fee::growth_profile_v2::PROFILE,
        ])
        .arg("--store")
        .arg(&store)
        .output()
        .unwrap();
    rejected(output, "CONTINUITY_PROFILE");
    assert!(!store.exists());
}
