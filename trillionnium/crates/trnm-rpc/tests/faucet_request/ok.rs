use super::*;

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
