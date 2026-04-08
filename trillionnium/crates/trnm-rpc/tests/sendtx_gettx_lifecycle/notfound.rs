use super::*;

#[test]
fn gettx_not_found() {
    let temp = TempDir::new().unwrap();
    write_accounts(&temp.path().join("accounts.json"), 100, 0);

    let (ok, _out, err) = run_rpc(&temp, &["get-tx", "--tx-hash", "0xdeadbeef"]);
    assert!(!ok);
    assert!(err.contains("TX_NOT_FOUND"), "stderr={err}");
}
