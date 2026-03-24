use super::*;

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
