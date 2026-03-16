use super::*;

#[test]
fn market_create_task_trims_creator_before_persisting() {
    let _ = fs::remove_dir_all("run/market");
    let _ = fs::remove_dir_all("run/market_test");

    let output = Command::new("cargo")
        .args([
            "run",
            "-p",
            "trnm-rpc",
            "--",
            "market.create_task",
            "--creator",
            "  alice  ",
            "--bounty",
            "100",
            "--description",
            "creator trim",
        ])
        .env("TRNM_RPC_ACCOUNTS_FILE", "run/market_test/accounts.json")
        .env("TRNM_RPC_TX_FILE", "run/market_test/txs.json")
        .output()
        .expect("failed to execute trnm-rpc");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"creator\": \"alice\""),
        "stdout: {stdout}"
    );
    assert!(
        !stdout.contains("\"creator\": \"  alice  \""),
        "stdout: {stdout}"
    );
}
