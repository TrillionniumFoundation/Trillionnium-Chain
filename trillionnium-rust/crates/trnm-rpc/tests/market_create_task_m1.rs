use std::fs;
use std::process::Command;

#[test]
fn market_create_task_m1_command_works() {
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
            "alice",
            "--bounty",
            "100",
            "--description",
            "m1 create task",
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
    assert!(stdout.contains("\"task_id\""));
    assert!(stdout.contains("\"creator\": \"alice\""));
    assert!(stdout.contains("\"status\": \"open\""));
}

#[test]
fn market_create_task_blank_creator_returns_structured_code() {
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
            "   ",
            "--bounty",
            "100",
            "--description",
            "invalid creator",
        ])
        .env("TRNM_RPC_ACCOUNTS_FILE", "run/market_test/accounts.json")
        .env("TRNM_RPC_TX_FILE", "run/market_test/txs.json")
        .output()
        .expect("failed to execute trnm-rpc");

    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"code\": \"task-creator-invalid\""),
        "stderr: {stderr}"
    );
}

#[test]
fn market_create_task_zero_bounty_returns_structured_code() {
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
            "alice",
            "--bounty",
            "0",
            "--description",
            "invalid bounty",
        ])
        .env("TRNM_RPC_ACCOUNTS_FILE", "run/market_test/accounts.json")
        .env("TRNM_RPC_TX_FILE", "run/market_test/txs.json")
        .output()
        .expect("failed to execute trnm-rpc");

    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"code\": \"task-bounty-invalid\""),
        "stderr: {stderr}"
    );
}

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

#[test]
fn market_create_task_unicode_whitespace_creator_returns_structured_code() {
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
            "\u{00a0}\u{3000}",
            "--bounty",
            "100",
            "--description",
            "invalid unicode creator",
        ])
        .env("TRNM_RPC_ACCOUNTS_FILE", "run/market_test/accounts.json")
        .env("TRNM_RPC_TX_FILE", "run/market_test/txs.json")
        .output()
        .expect("failed to execute trnm-rpc");

    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"code\": \"task-creator-invalid\""),
        "stderr: {stderr}"
    );
}

#[test]
fn market_create_task_visible_alias_works() {
    let _ = fs::remove_dir_all("run/market");
    let _ = fs::remove_dir_all("run/market_test");

    let output = Command::new("cargo")
        .args([
            "run",
            "-p",
            "trnm-rpc",
            "--",
            "market-create-task",
            "--creator",
            "alice",
            "--bounty",
            "100",
            "--description",
            "m1 create task alias",
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
    assert!(stdout.contains("\"task_id\""));
    assert!(stdout.contains("\"creator\": \"alice\""));
    assert!(stdout.contains("\"status\": \"open\""));
}
