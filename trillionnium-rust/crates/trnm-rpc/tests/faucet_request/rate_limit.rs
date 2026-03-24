use super::*;

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
