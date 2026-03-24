use super::*;

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
