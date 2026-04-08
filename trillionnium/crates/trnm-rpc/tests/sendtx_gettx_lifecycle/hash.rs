use super::*;

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
