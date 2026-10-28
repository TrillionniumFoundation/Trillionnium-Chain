//! Actual CLI selects the explicit zero-search profile and the native W1 path.
use serde_json::Value;
use std::{
    fs,
    io::{BufRead, BufReader},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
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
    serde_json::from_slice::<Value>(&out.stdout).unwrap()
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
    exercise_pure_cli(public_v3::PURE_PON_PROFILE);
}

#[test]
fn explicit_pure_v2_cli_fetch_mine_push_and_invalid_profile_have_no_fallback() {
    exercise_pure_cli(public_v3::PURE_PON_V2_PROFILE);
}

fn exercise_pure_cli(profile: &str) {
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
    let server = if profile == public_v3::PURE_PON_V2_PROFILE {
        server.with_pure_admission_v2().unwrap()
    } else {
        server
    };
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
                    profile,
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
        assert_eq!(mined["result"]["admitted"], true);
        let pushed = accepted(
            command("push", genesis)
                .args([
                    "--peer",
                    &address,
                    "--server-public",
                    &pinned,
                    "--admission-profile",
                    profile,
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
        for (profile, bits) in [(public_v3::PROFILE, "0"), (profile, "16")] {
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

// Own only this test's actual CLI child. An assertion or readiness timeout must
// not leave a serving process, kernel process slot or temporary store in use.
struct CliService(Child);
impl Drop for CliService {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn object_keys(value: &Value) -> Vec<&str> {
    let mut keys: Vec<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

#[test]
fn actual_cli_serve_v2_host_observations_stay_unqualified_and_legacy_keys_stay_exact() {
    // Actual CLI service, not a library-server stand-in. No cgroup is provisioned
    // or selected: a loopback diagnostic must not invent a fixed-parent receipt.
    // Retain the existing CLI tests' six-second service and bounded startup/exit.
    for (profile, bits) in [
        (public_v3::PROFILE, 8),
        (public_v3::PURE_PON_PROFILE, 0),
        (public_v3::PURE_PON_V2_PROFILE, 0),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let genesis = ingress::now().unwrap() - 100;
        let settings = Settings::development_with_profiles(
            Some(genesis),
            "native-public-evaluation-dev-v1",
            trnm_mvcc_fee::continuity_v1::PROFILE,
        )
        .unwrap();
        let identity =
            ingress::DevelopmentIdentity::from_secret_hex(&hex::encode([115; 32])).unwrap();
        let caller =
            ingress::DevelopmentIdentity::from_secret_hex(&hex::encode([116; 32])).unwrap();
        let secret = temp.path().join("server.key");
        fs::write(&secret, hex::encode([115; 32])).unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        let pool = temp.path().join("pool.json");
        fs::write(
            &pool,
            serde_json::to_vec(&PoolLimits {
                max_records: 16,
                max_bytes: 32768,
                max_group_members: 16,
                critical_reserve: 0,
                max_removals: 32,
                preview_miner: development_public(0).unwrap(),
            })
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&pool, fs::Permissions::from_mode(0o600)).unwrap();
        let started = Instant::now();
        let mut service = CliService(
            command("serve", genesis)
                .arg("--store")
                .arg(temp.path().join("receiver"))
                .arg("--auth-secret")
                .arg(&secret)
                .arg("--pool-policy")
                .arg(&pool)
                .args([
                    "--admission-profile",
                    profile,
                    "--admission-bits",
                    &bits.to_string(),
                    "--public-development-network",
                    "--seconds",
                    "6",
                    "--listen",
                    "127.0.0.1:0",
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let stdout = service.0.stdout.take().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut lines = BufReader::new(stdout).lines();
            let first = lines.next().expect("CLI service readiness").unwrap();
            let _ = ready_tx.send(first);
            lines.collect::<std::io::Result<Vec<_>>>().unwrap()
        });
        let ready: Value =
            serde_json::from_str(&ready_rx.recv_timeout(Duration::from_secs(4)).unwrap()).unwrap();
        let policy = PublicPolicy::new(bits, Duration::from_secs(2)).unwrap();
        let v2 = profile == public_v3::PURE_PON_V2_PROFILE;
        assert_eq!(ready["event"], "listening");
        assert_eq!(ready["admission_profile"], profile);
        assert_eq!(ready["server_public"], identity.public_key());
        assert_eq!(
            ready["admission_profile_digest"],
            hex::encode(if v2 {
                policy.pure_admission_v2_id()
            } else {
                policy.id()
            })
        );
        assert_eq!(ready["initial_paid_cpu_credit_ns"], 0);
        assert_eq!(ready["root_kernel_parent_checked"], false);
        assert_eq!(
            ready.get("root_kernel_resources_before"),
            Some(&Value::Null)
        );
        assert_eq!(ready["public_network_ready"], false);
        assert_eq!(ready["production_activation"], false);
        let mut expected_ready = vec![
            "event",
            "address",
            "state",
            "server_public",
            "scope",
            "host_process_slot",
            "host_process_budget_scope",
            "root_kernel_parent_checked",
            "root_kernel_resources_before",
            "initial_paid_cpu_credit_ns",
            "admission_profile",
            "admission_profile_digest",
            "pool_context",
            "mining_enabled",
            "peer_polling_enabled",
            "peer_polling_context",
            "confidentiality",
            "identity_authority",
            "public_network_ready",
            "production_activation",
        ];
        if v2 {
            expected_ready.extend([
                "bound_host_resources_before",
                "mutation_cpu_is_whole_node_cpu",
            ]);
            assert_eq!(ready.get("bound_host_resources_before"), Some(&Value::Null));
            assert_eq!(ready["mutation_cpu_is_whole_node_cpu"], false);
        }
        expected_ready.sort_unstable();
        assert_eq!(object_keys(&ready), expected_ready);

        // Readiness alone is insufficient: authenticate a real Head response
        // from this child using its exact explicitly selected resource profile.
        let address = ready["address"]
            .as_str()
            .unwrap()
            .parse::<std::net::SocketAddr>()
            .unwrap();
        assert!(address.ip().is_loopback() && address.port() != 0);
        let call = if v2 {
            public_v3::call_public_pure_pon_v2
        } else {
            public_v3::call_public_protected_v3_with_deadline
        };
        let (reply, metrics) = call(
            address,
            &public_v3::Request::Head,
            &settings,
            identity.public_key(),
            &caller,
            policy,
            Some(Instant::now() + Duration::from_secs(2)),
        );
        assert!(reply.unwrap().ok);
        if bits == 0 {
            assert_eq!(metrics.solution_trials, 0);
        }
        let exit_deadline = started + Duration::from_secs(9);
        while service.0.try_wait().unwrap().is_none() && Instant::now() < exit_deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            service.0.try_wait().unwrap().is_some(),
            "bounded CLI service exit"
        );
        assert!(service.0.wait().unwrap().success());
        let final_lines = reader.join().unwrap();
        assert_eq!(final_lines.len(), 1, "one complete CLI service terminal");
        let result: Value = serde_json::from_str(&final_lines[0]).unwrap();
        assert_eq!(result["result"]["completed_read"], 1);
        assert_eq!(result["result"]["mutation_cpu_reservations"], 0);
        assert_eq!(
            result.get("host_kernel_resources_after"),
            Some(&Value::Null)
        );
        assert_eq!(result.get("host_kernel_cpu_delta"), Some(&Value::Null));
        assert_eq!(result["host_kernel_qualification"], false);
        assert_eq!(result["public_network_ready"], false);
        assert_eq!(result["production_activation"], false);
        let mut expected_final = vec![
            "host_kernel_cpu_delta",
            "host_kernel_qualification",
            "host_kernel_resources_after",
            "mining",
            "peer_polling",
            "production_activation",
            "public_network_ready",
            "result",
        ];
        if v2 {
            expected_final.extend([
                "bound_host_resources_before",
                "bound_host_resources_after",
                "bound_host_cpu_delta",
                "mutation_cpu_is_whole_node_cpu",
            ]);
            for field in [
                "bound_host_resources_before",
                "bound_host_resources_after",
                "bound_host_cpu_delta",
            ] {
                assert_eq!(result.get(field), Some(&Value::Null), "{field}");
            }
            assert_eq!(result["mutation_cpu_is_whole_node_cpu"], false);
        }
        expected_final.sort_unstable();
        assert_eq!(object_keys(&result), expected_final);
    }
}
