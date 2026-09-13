use ed25519_dalek::SigningKey;
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::Path, process::Command};
use tempfile::TempDir;
use trnm_rpc::AccountState;
use trnm_types::TransferTx;

const ALICE_SK_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const BOB_SK_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn address_from_secret_hex(secret_hex: &str) -> String {
    let bytes = hex::decode(secret_hex).unwrap();
    let key_bytes: [u8; 32] = bytes.as_slice().try_into().unwrap();
    let sk = SigningKey::from_bytes(&key_bytes);
    TransferTx::derive_address_from_ed25519_pubkey(sk.verifying_key().as_bytes())
}

fn write_accounts(path: &Path, alice_balance: u128, alice_nonce: u64) {
    let alice = address_from_secret_hex(ALICE_SK_HEX);
    let bob = address_from_secret_hex(BOB_SK_HEX);

    let mut accounts = BTreeMap::new();
    accounts.insert(
        alice.clone(),
        AccountState {
            address: alice,
            balance: alice_balance,
            nonce: alice_nonce,
        },
    );
    accounts.insert(
        bob.clone(),
        AccountState {
            address: bob,
            balance: 0,
            nonce: 0,
        },
    );
    fs::write(path, serde_json::to_string_pretty(&accounts).unwrap()).unwrap();
}

fn run_rpc(temp: &TempDir, args: &[&str]) -> (bool, String, String) {
    let accounts_file = temp.path().join("accounts.json");
    let tx_file = temp.path().join("txs.json");

    let output = Command::new(env!("CARGO_BIN_EXE_trnm-rpc"))
        .args(args)
        .env("TRNM_RPC_DEVELOPMENT_ONLY", "1")
        .env("TRNM_RPC_ACCOUNTS_FILE", &accounts_file)
        .env("TRNM_RPC_TX_FILE", &tx_file)
        .output()
        .expect("run trnm-rpc");

    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn submit_ok(temp: &TempDir, nonce: u64) -> String {
    submit_with_amount_and_fee(temp, 10, 1, nonce)
}

fn submit_with_amount_and_fee(temp: &TempDir, amount: u128, fee: u128, nonce: u64) -> String {
    let alice = address_from_secret_hex(ALICE_SK_HEX);
    let bob = address_from_secret_hex(BOB_SK_HEX);
    let amount_s = amount.to_string();
    let fee_s = fee.to_string();
    let mut tx = TransferTx {
        from: alice.clone(),
        to: bob,
        amount,
        fee,
        nonce,
        signature: String::new(),
    };
    tx.signature = tx.sign_with_private_key_hex(ALICE_SK_HEX).unwrap();

    let (ok, out, err) = run_rpc(
        temp,
        &[
            "send-tx",
            "--from",
            &alice,
            "--to",
            &tx.to,
            "--amount",
            &amount_s,
            "--fee",
            &fee_s,
            "--nonce",
            &nonce.to_string(),
            "--signature",
            &tx.signature,
        ],
    );
    assert!(ok, "send-tx failed: {err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["status"], "pending");
    v["tx_hash"].as_str().unwrap().to_string()
}

#[test]
fn sendtx_gettx_happy_path_committed() {
    let temp = TempDir::new().unwrap();
    write_accounts(&temp.path().join("accounts.json"), 100, 0);

    let tx_hash = submit_ok(&temp, 0);

    let (ok, out, err) = run_rpc(&temp, &["get-tx", "--tx-hash", &tx_hash]);
    assert!(ok, "get-tx failed: {err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["tx_hash"], tx_hash);
    assert_eq!(v["status"], "committed");
    assert!(v["error"].is_null());
}

#[test]
fn sendtx_gettx_fail_insufficient_balance() {
    let temp = TempDir::new().unwrap();
    write_accounts(&temp.path().join("accounts.json"), 5, 0);

    let tx_hash = submit_ok(&temp, 0);

    let (ok, out, err) = run_rpc(&temp, &["get-tx", "--tx-hash", &tx_hash]);
    assert!(ok, "get-tx failed: {err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["status"], "fail");
    assert!(v["error"]
        .as_str()
        .unwrap()
        .contains("insufficient balance"));
}

#[test]
fn sendtx_gettx_fail_nonce_conflict() {
    let temp = TempDir::new().unwrap();
    write_accounts(&temp.path().join("accounts.json"), 100, 1);

    let tx_hash = submit_ok(&temp, 0);

    let (ok, out, err) = run_rpc(&temp, &["get-tx", "--tx-hash", &tx_hash]);
    assert!(ok, "get-tx failed: {err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["status"], "fail");
    assert!(v["error"]
        .as_str()
        .unwrap()
        .contains("nonce rollback/replay"));
}

#[test]
fn sendtx_gettx_commits_exact_amount_plus_fee_u128_boundary() {
    let temp = TempDir::new().unwrap();
    write_accounts(&temp.path().join("accounts.json"), u128::MAX, 0);

    let tx_hash = submit_with_amount_and_fee(&temp, u128::MAX - 1, 1, 0);

    let (ok, out, err) = run_rpc(&temp, &["get-tx", "--tx-hash", &tx_hash]);
    assert!(ok, "get-tx failed: {err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["tx_hash"], tx_hash);
    assert_eq!(v["status"], "committed");
    assert!(v["error"].is_null());
}

#[test]
fn gettx_accepts_case_and_whitespace_drift_in_hash() {
    let temp = TempDir::new().unwrap();
    write_accounts(&temp.path().join("accounts.json"), 100, 0);

    let tx_hash = submit_ok(&temp, 0);
    let drifted_hash = format!("  {}\n", tx_hash.to_uppercase());

    let (ok, out, err) = run_rpc(&temp, &["get-tx", "--tx-hash", &drifted_hash]);
    assert!(ok, "get-tx failed: {err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["tx_hash"], tx_hash);
    assert_eq!(v["status"], "committed");
}

#[test]
fn gettx_not_found() {
    let temp = TempDir::new().unwrap();
    write_accounts(&temp.path().join("accounts.json"), 100, 0);

    let (ok, _out, err) = run_rpc(&temp, &["get-tx", "--tx-hash", "0xdeadbeef"]);
    assert!(!ok);
    assert!(err.contains("TX_NOT_FOUND"), "stderr={err}");
}
