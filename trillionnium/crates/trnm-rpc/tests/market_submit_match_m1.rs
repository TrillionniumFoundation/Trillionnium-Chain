use serde_json::Value;
use std::fs;
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

fn test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock_test_guard<'a>() -> MutexGuard<'a, ()> {
    let guard = test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let root = fixture_root();
    let _ = fs::remove_file(root.join("tasks.jsonl"));
    let _ = fs::remove_file(root.join("tasks.jsonl.lock"));
    let _ = fs::remove_file(root.join("bids.jsonl"));
    let _ = fs::remove_file(root.join("bids.jsonl.lock"));
    let _ = fs::remove_file(root.join("reputation.json"));
    let _ = fs::remove_file(root.join("reputation.json.lock"));
    let _ = fs::remove_file(root.join("ingress.jsonl"));
    let _ = fs::remove_file(root.join("ingress.jsonl.lock"));
    guard
}

fn fixture_root() -> &'static std::path::Path {
    static ROOT: OnceLock<std::path::PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let dir = unique_market_fixture_path("market_submit_match_m1", "dir");
        fs::create_dir_all(&dir).expect("create market fixture dir");
        dir
    })
    .as_path()
}

fn market_reputation_fixture_path() -> std::path::PathBuf {
    fixture_root().join("reputation.json")
}

fn apply_market_env_baseline(cmd: &mut Command) {
    let root = fixture_root();
    cmd.env("TRNM_RPC_MARKET_TASKS_FILE", root.join("tasks.jsonl"));
    cmd.env("TRNM_RPC_MARKET_BIDS_FILE", root.join("bids.jsonl"));
    cmd.env(
        "TRNM_RPC_MARKET_REPUTATION_FILE",
        market_reputation_fixture_path(),
    );
    cmd.env("TRNM_RPC_INGRESS_FILE", root.join("ingress.jsonl"));
    cmd.env("TRNM_RPC_MARKET_LOCK_STALE_MS", "2000");
}

fn run_ok(args: &[&str]) -> String {
    let mut cmd = Command::new("cargo");
    cmd.env("TRNM_RPC_DEVELOPMENT_ONLY", "1");
    cmd.args(["run", "-p", "trnm-rpc", "--"]).args(args);
    apply_market_env_baseline(&mut cmd);
    let output = cmd.output().expect("failed to execute trnm-rpc");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn run_ok_with_env(args: &[&str], envs: &[(&str, &str)]) -> String {
    let mut command = Command::new("cargo");
    command.env("TRNM_RPC_DEVELOPMENT_ONLY", "1");
    command.args(["run", "-p", "trnm-rpc", "--"]).args(args);
    apply_market_env_baseline(&mut command);
    for (k, v) in envs {
        if *k == "TRNM_RPC_MARKET_REPUTATION_FILE" {
            command.env(k, market_reputation_fixture_path());
            continue;
        }
        command.env(k, v);
    }
    let output = command.output().expect("failed to execute trnm-rpc");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn unique_market_fixture_path(name: &str, ext: &str) -> std::path::PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("trnm_rpc_{}_{}.{}", name, ts, ext))
}

fn run_fail(args: &[&str]) -> String {
    let mut cmd = Command::new("cargo");
    cmd.env("TRNM_RPC_DEVELOPMENT_ONLY", "1");
    cmd.args(["run", "-p", "trnm-rpc", "--"]).args(args);
    apply_market_env_baseline(&mut cmd);
    let output = cmd.output().expect("failed to execute trnm-rpc");
    assert!(!output.status.success());
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[cfg(test)]
#[path = "market_submit_match_m1/submit.rs"]
mod market_submit_match_m1_submit;

#[cfg(test)]
#[path = "market_submit_match_m1/match.rs"]
mod market_submit_match_m1_match;

#[cfg(test)]
#[path = "market_submit_match_m1/report.rs"]
mod market_submit_match_m1_report;
