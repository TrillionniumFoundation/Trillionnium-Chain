use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

fn unique_market_fixture_path(name: &str, ext: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("trnm_rpc_{}_{}.{}", name, ts, ext))
}

#[test]
fn market_match_waits_for_bids_lock_before_reading() {
    let tasks = unique_market_fixture_path("market_match_locking_tasks", "jsonl");
    let bids = unique_market_fixture_path("market_match_locking_bids", "jsonl");
    let _ = fs::remove_file(&tasks);
    let _ = fs::remove_file(&bids);

    let create_out = Command::new("cargo")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args([
            "market.create_task",
            "--creator",
            "creator-lock-test",
            "--bounty",
            "100",
            "--description",
            "lock regression",
        ])
        .env("TRNM_RPC_MARKET_TASKS_FILE", &tasks)
        .env("TRNM_RPC_MARKET_BIDS_FILE", &bids)
        .output()
        .expect("failed to run market.create_task");
    assert!(
        create_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&create_out.stderr)
    );

    let bid_out = Command::new("cargo")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args([
            "market.submit_bid",
            "--task-id",
            "20001",
            "--worker",
            "worker-lock-test",
            "--price",
            "90",
        ])
        .env("TRNM_RPC_MARKET_TASKS_FILE", &tasks)
        .env("TRNM_RPC_MARKET_BIDS_FILE", &bids)
        .output()
        .expect("failed to run market.submit_bid");
    assert!(
        bid_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&bid_out.stderr)
    );

    let bids_lock = bids.with_file_name(format!(
        "{}.lock",
        bids.file_name()
            .and_then(|v| v.to_str())
            .expect("bids filename")
    ));
    if let Some(parent) = bids_lock.parent() {
        fs::create_dir_all(parent).expect("create lock dir");
    }
    fs::write(&bids_lock, b"manual lock\n").expect("create bids lock");

    let release_lock = {
        let lock = bids_lock.clone();
        thread::spawn(move || {
            // Hold the lock long enough to dominate process startup jitter on busy CI nodes.
            // Keep this comfortably above warm `cargo run` startup so lock contention is exercised deterministically.
            thread::sleep(Duration::from_millis(2500));
            let _ = fs::remove_file(lock);
        })
    };

    let started = Instant::now();
    let match_out = Command::new("cargo")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args(["market.match_task", "--task-id", "20001"])
        .env("TRNM_RPC_MARKET_TASKS_FILE", &tasks)
        .env("TRNM_RPC_MARKET_BIDS_FILE", &bids)
        .env("TRNM_RPC_MARKET_LOCK_STALE_MS", "60000")
        .output()
        .expect("failed to run market.match_task");
    let elapsed = started.elapsed();

    let _ = release_lock.join();

    assert!(
        match_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&match_out.stderr)
    );
    assert!(
        elapsed >= Duration::from_millis(1200),
        "market.match_task should wait for bids lock; elapsed={elapsed:?}"
    );
}
