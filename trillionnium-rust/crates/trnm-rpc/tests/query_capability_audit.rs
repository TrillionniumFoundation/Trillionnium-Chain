use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::tempdir;
use trnm_types::{CapabilityScope, IdentityRegistry};

fn run_ok(args: &[&str], registry_path: &str) -> String {
    let output = Command::new("cargo")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args(args)
        .env("TRNM_RPC_IDENTITY_REGISTRY_FILE", registry_path)
        .output()
        .expect("failed to execute trnm-rpc");
    if !output.status.success() {
        panic!("RPC failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn run_fail(args: &[&str], registry_path: &str) -> String {
    let output = Command::new("cargo")
        .args(["run", "-p", "trnm-rpc", "--"])
        .args(args)
        .env("TRNM_RPC_IDENTITY_REGISTRY_FILE", registry_path)
        .output()
        .expect("failed to execute trnm-rpc");
    assert!(!output.status.success());
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[path = "query_capability_audit/errors.rs"]
mod errors;
#[path = "query_capability_audit/owner_history.rs"]
mod owner_history;
#[path = "query_capability_audit/path_env.rs"]
mod path_env;
#[path = "query_capability_audit/token_fields.rs"]
mod token_fields;
