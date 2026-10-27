//! Actual CLI selects the explicit zero-search profile and the native W1 path.
use serde_json::Value;
use std::{
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    process::{Command, Output},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use trnm_pon_node::{
    development_public,
    ingress::{
        self,
        public_v3::{self, PublicPolicy, PublicServer},
    },
    Node, PoolLimits, Settings,
};

fn command(name: &str, genesis: u64) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    command.arg(name).args([
        "--development",
        "--genesis-time",
        &genesis.to_string(),
        "--evaluation-policy",
        "native-public-evaluation-dev-v1",
        "--task-profile",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    ]);
    command
}
fn accepted(out: Output) -> Value {
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice::<Value>(&out.stdout).unwrap()["result"].clone()
}
fn refused(out: Output, expected: &str) {
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(expected),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn explicit_pure_cli_fetch_mine_push_and_invalid_profile_have_no_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let genesis = ingress::now().unwrap() - 100;
    let settings = Settings::development_with_profiles(
        Some(genesis),
        "native-public-evaluation-dev-v1",
        trnm_mvcc_fee::continuity_v1::PROFILE,
    )
    .unwrap();
    let mut node = Node::open(&temp.path().join("receiver"), settings.clone(), 1).unwrap();
    node.enable_local_mempool(PoolLimits {
        max_records: 16,
        max_bytes: 32768,
        max_group_members: 16,
        critical_reserve: 0,
        max_removals: 32,
        preview_miner: development_public(0).unwrap(),
    })
    .unwrap();
    let owner = Arc::new(Mutex::new(node));
    let identity = ingress::DevelopmentIdentity::from_secret_hex(&hex::encode([113; 32])).unwrap();
    let pinned = identity.public_key().to_owned();
    let policy = PublicPolicy::pure_pon(Duration::from_secs(2)).unwrap();
    let server = PublicServer::new_process_cold(identity, policy).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let stop = Arc::new(AtomicBool::new(false));
    struct Stop(Arc<AtomicBool>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let secret = temp.path().join("guest.key");
    fs::write(&secret, hex::encode([114; 32])).unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
    let local = temp.path().join("local.json");
    let fetched = temp.path().join("fetched.json");
    let packet = temp.path().join("mined.packet");
    thread::scope(|scope| {
        let _guard = Stop(stop.clone());
        let server_stop = stop.clone();
        let server_owner = owner.clone();
        let worker = scope.spawn(move || {
            public_v3::serve_public_protected_v3(
                listener,
                server_owner,
                Duration::from_secs(30),
                server_stop,
                server,
            )
        });
        let exported = accepted(
            command("public-task-export", genesis)
                .arg("--output")
                .arg(&local)
                .output()
                .unwrap(),
        );
        assert_eq!(exported["transport_hash_trials"], 0);
        let fetch = accepted(
            command("public-task-fetch", genesis)
                .args([
                    "--peer",
                    &address,
                    "--server-public",
                    &pinned,
                    "--admission-profile",
                    public_v3::PURE_PON_PROFILE,
                ])
                .arg("--auth-secret")
                .arg(&secret)
                .arg("--output")
                .arg(&fetched)
                .output()
                .unwrap(),
        );
        assert_eq!(fetch["transport_hash_trials"], 0);
        assert_eq!(fetch["useful_output_credit"], 0);
        assert_eq!(fs::read(&local).unwrap(), fs::read(&fetched).unwrap());
        let mined = accepted(
            command("mine", genesis)
                .arg("--store")
                .arg(temp.path().join("miner"))
                .args(["--timestamp", &(genesis + 11).to_string()])
                .arg("--public-task-bundle")
                .arg(&fetched)
                .arg("--output")
                .arg(&packet)
                .output()
                .unwrap(),
        );
        assert_eq!(mined["admitted"], true);
        let pushed = accepted(
            command("push", genesis)
                .args([
                    "--peer",
                    &address,
                    "--server-public",
                    &pinned,
                    "--admission-profile",
                    public_v3::PURE_PON_PROFILE,
                ])
                .arg("--auth-secret")
                .arg(&secret)
                .arg("--packet")
                .arg(&packet)
                .output()
                .unwrap(),
        );
        assert_eq!(pushed["ok"], true);
        assert_eq!(pushed["solve_trials"], 0);
        let before = owner.lock().unwrap().read_active().unwrap();
        for (profile, bits) in [
            (public_v3::PROFILE, "0"),
            (public_v3::PURE_PON_PROFILE, "16"),
        ] {
            let output = temp.path().join(format!("refused-{bits}.json"));
            refused(
                command("public-task-fetch", genesis)
                    .args([
                        "--peer",
                        &address,
                        "--server-public",
                        &pinned,
                        "--admission-profile",
                        profile,
                        "--admission-bits",
                        bits,
                    ])
                    .arg("--auth-secret")
                    .arg(&secret)
                    .arg("--output")
                    .arg(&output)
                    .output()
                    .unwrap(),
                "PUBLIC_PURE_PON_PROFILE",
            );
            assert!(!output.exists());
        }
        assert_eq!(owner.lock().unwrap().read_active().unwrap(), before);
        stop.store(true, Ordering::Release);
        worker.join().unwrap().unwrap();
    });
}
