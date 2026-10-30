//! Real CLI component controls; not the fixed-cgroup History campaign.
use serde_json::Value;
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};
use trnm_crypto_primitives::{public_key_hex, signing_key_from_hex};
use trnm_pon_node::{development_public, ingress, PoolLimits};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn command(operation: &str, genesis: u64) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    command.args([
        operation,
        "--development",
        "--genesis-time",
        &genesis.to_string(),
    ]);
    command
}

#[test]
fn explicit_zero_search_cli_round_trip_and_protected_client_refusal() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let genesis = ingress::now().unwrap() - 100;
    let server_key = hex::encode([121; 32]);
    let server_public = public_key_hex(&signing_key_from_hex(&server_key).unwrap());
    for (name, text) in [
        ("server.key", server_key),
        ("caller.key", hex::encode([122; 32])),
    ] {
        fs::write(root.join(name), text).unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let limits = PoolLimits {
        max_records: 32,
        max_bytes: 65536,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 32,
        preview_miner: development_public(3).unwrap(),
    };
    fs::write(root.join("pool.json"), serde_json::to_vec(&limits).unwrap()).unwrap();
    fs::set_permissions(root.join("pool.json"), fs::Permissions::from_mode(0o600)).unwrap();
    let mut serve = command("serve", genesis);
    serve
        .args([
            "--admission-profile",
            ingress::public_v3::PURE_HISTORY_RAW_PROFILE,
            "--public-development-network",
            "--listen",
            "127.0.0.1:0",
            "--seconds",
            "3",
        ])
        .arg("--store")
        .arg(root.join("receiver"))
        .arg("--pool-policy")
        .arg(root.join("pool.json"))
        .arg("--auth-secret")
        .arg(root.join("server.key"));
    let mut child = ChildGuard(
        serve
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (send, receive) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut stream = BufReader::new(stdout);
        let mut first = String::new();
        stream.read_line(&mut first).unwrap();
        let _ = send.send(first);
        let mut discarded = String::new();
        while stream.read_line(&mut discarded).unwrap() > 0 {
            discarded.clear();
        }
    });
    let ready: Value =
        serde_json::from_str(&receive.recv_timeout(Duration::from_secs(10)).unwrap()).unwrap();
    assert_eq!(
        ready["admission_profile"],
        ingress::public_v3::PURE_HISTORY_RAW_PROFILE
    );
    assert_eq!(ready["initial_paid_cpu_credit_ns"], 0);
    for (profile, bits, succeeds) in [
        (ingress::public_v3::PURE_HISTORY_RAW_PROFILE, "0", true),
        (ingress::public_v3::PROFILE, "8", false),
    ] {
        let mut head = command("head", genesis);
        head.args([
            "--admission-profile",
            profile,
            "--admission-bits",
            bits,
            "--peer",
            ready["address"].as_str().unwrap(),
            "--server-public",
            &server_public,
            "--client-observations",
        ])
        .arg("--auth-secret")
        .arg(root.join("caller.key"));
        let output = head.output().unwrap();
        assert_eq!(
            output.status.success(),
            succeeds,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if succeeds {
            let stderr = String::from_utf8(output.stderr).unwrap();
            let observed: Value =
                serde_json::from_str(stderr.lines().find(|line| line.starts_with('{')).unwrap())
                    .unwrap();
            assert_eq!(observed["observations"]["solution_trials"], 0);
            assert_eq!(observed["observations"]["solution_search_ns"], 0);
            assert_eq!(observed["pure_history_acknowledgement"]["search_budget"], 0);
            assert_eq!(
                observed["pure_history_acknowledgement"]["solution_nonce"],
                0
            );
        } else {
            assert!(String::from_utf8_lossy(&output.stderr).contains("PUBLIC_CHALLENGE_CONTEXT"));
        }
    }
    assert!(child.0.wait().unwrap().success());
    reader.join().unwrap();
}

#[test]
fn pure_cli_nonzero_override_is_rejected_before_store_or_network_io() {
    let directory = tempfile::tempdir().unwrap();
    let store = directory.path().join("must-not-exist");
    let output = command("serve", 1_750_000_000)
        .args([
            "--admission-profile",
            ingress::public_v3::PURE_HISTORY_RAW_PROFILE,
            "--admission-bits",
            "8",
            "--public-development-network",
        ])
        .arg("--store")
        .arg(&store)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("PUBLIC_PURE_HISTORY_RAW_PROFILE"));
    assert!(!store.exists());
}
