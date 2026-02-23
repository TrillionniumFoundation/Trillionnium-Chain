use serde_json::Value;
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

fn write_accounts(path: &Path) {
    fs::write(path, "{}\n").unwrap();
}

fn run_rpc(temp: &TempDir, args: &[&str], now_ms: u128) -> (bool, String, String) {
    let accounts_file = temp.path().join("accounts.json");
    let tx_file = temp.path().join("txs.json");
    let faucet_limits_file = temp.path().join("faucet_limits.json");

    let output = Command::new(env!("CARGO_BIN_EXE_trnm-rpc"))
        .args(args)
        .env("TRNM_RPC_ACCOUNTS_FILE", &accounts_file)
        .env("TRNM_RPC_TX_FILE", &tx_file)
        .env("TRNM_RPC_FAUCET_LIMITS_FILE", &faucet_limits_file)
        .env("TRNM_RPC_NOW_MS", now_ms.to_string())
        .output()
        .expect("run trnm-rpc");

    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn faucet_request_ok() {
    let temp = TempDir::new().unwrap();
    write_accounts(&temp.path().join("accounts.json"));
    let addr = format!("trnm1{}", "a".repeat(40));

    let (ok, out, err) = run_rpc(
        &temp,
        &["faucet-request", "--address", &addr, "--amount", "123"],
        1_000,
    );
    assert!(ok, "faucet-request failed: {err}");
    let v: Value = serde_json::from_str(&out).unwrap();

    assert_eq!(v["ok"], true);
    assert_eq!(v["code"], "OK");
    assert_eq!(v["address"], addr);
    assert_eq!(v["requested_amount"], 123);
    assert_eq!(v["granted_amount"], 123);
    assert_eq!(v["balance"], 123);
    assert_eq!(v["nonce"], 0);
    assert_eq!(v["version"], 1);
}

#[test]
fn faucet_request_rate_limited() {
    let temp = TempDir::new().unwrap();
    write_accounts(&temp.path().join("accounts.json"));
    let addr = format!("trnm1{}", "b".repeat(40));

    let (ok1, _out1, err1) = run_rpc(
        &temp,
        &["faucet-request", "--address", &addr, "--amount", "50"],
        5_000,
    );
    assert!(ok1, "first faucet-request failed: {err1}");

    let (ok2, out2, err2) = run_rpc(
        &temp,
        &["faucet-request", "--address", &addr, "--amount", "50"],
        5_100,
    );
    assert!(ok2, "second faucet-request failed: {err2}");
    let v: Value = serde_json::from_str(&out2).unwrap();

    assert_eq!(v["ok"], false);
    assert_eq!(v["code"], "RATE_LIMITED");
    assert_eq!(v["requested_amount"], 50);
    assert_eq!(v["granted_amount"], 0);
    assert_eq!(v["balance"], 50);
}

#[test]
fn faucet_request_invalid_address() {
    let temp = TempDir::new().unwrap();
    write_accounts(&temp.path().join("accounts.json"));

    let (ok, out, err) = run_rpc(
        &temp,
        &[
            "faucet-request",
            "--address",
            "invalid-address",
            "--amount",
            "88",
        ],
        9_000,
    );
    assert!(ok, "faucet-request failed: {err}");
    let v: Value = serde_json::from_str(&out).unwrap();

    assert_eq!(v["ok"], false);
    assert_eq!(v["code"], "INVALID_ADDRESS");
    assert_eq!(v["granted_amount"], 0);
    assert!(v["balance"].is_null());
}
