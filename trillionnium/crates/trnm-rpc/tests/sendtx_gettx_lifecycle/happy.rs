use super::*;

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
