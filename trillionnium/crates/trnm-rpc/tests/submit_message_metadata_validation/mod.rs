use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn unique_fixture_path(name: &str, ext: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("trnm_rpc_{}_{}.{}", name, ts, ext))
}

fn run_submit_message(ingress: &PathBuf, text: &str, key: &str) -> std::process::Output {
    Command::new("cargo")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args([
            "submit-message",
            "--channel",
            "telegram",
            "--user-id",
            "u-meta",
            "--session-id",
            "s-meta",
            "--text",
            text,
            "--idempotency-key",
            key,
        ])
        .env("TRNM_RPC_INGRESS_FILE", ingress)
        .output()
        .expect("run submit-message")
}

#[path = "acceptance.rs"]
mod acceptance;
#[path = "payload_limit.rs"]
mod payload_limit;
#[path = "provenance.rs"]
mod provenance;
#[path = "timestamp.rs"]
mod timestamp;
