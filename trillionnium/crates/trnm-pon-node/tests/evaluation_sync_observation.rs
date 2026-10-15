//! Actual pinned public sync consumes a typed local round without a new RPC.
use serde_json::{json, Value};
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{pon_executor::Config, public_evaluation as evaluation};
use trnm_pon_node::{
    development_public,
    ingress::{self, public_v3, DevelopmentIdentity},
    Node, PoolLimits, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

static OBSERVED_CALLS: AtomicU64 = AtomicU64::new(0);
fn retain_output(output: &Output) {
    if let Some(directory) = std::env::var_os("EVALUATION_SYNC_OBSERVATION_EVIDENCE_DIR") {
        let directory = std::path::PathBuf::from(directory);
        fs::create_dir_all(&directory).unwrap();
        let ordinal = OBSERVED_CALLS.fetch_add(1, Ordering::Relaxed);
        let prefix = directory.join(format!("cli-{ordinal:03}"));
        // Command::output has already waited for this owned actual child.
        for (extension, bytes) in [
            ("stdout", output.stdout.as_slice()),
            ("stderr", output.stderr.as_slice()),
        ] {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(prefix.with_extension(extension))
                .unwrap();
            std::io::Write::write_all(&mut file, bytes).unwrap();
        }
        let receipt = json!({"actual_returncode":output.status.code(),
            "actual_child_wait_completed":true,"local_loopback_or_input_refusal_test":true,
            "public_ready":false});
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(prefix.with_extension("receipt.json"))
            .unwrap();
        std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(&receipt).unwrap())
            .unwrap();
    }
}

fn command(store: &Path, genesis: u64) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    c.args([
        "sync",
        "--development",
        "--genesis-time",
        &genesis.to_string(),
        "--evaluation-policy",
        evaluation::PROFILE,
    ])
    .arg("--store")
    .arg(store);
    c
}
#[track_caller]
fn refusal(output: Output, expected: &str) -> String {
    retain_output(&output);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains(expected), "{error}");
    error
}
#[track_caller]
fn success(c: &mut SyncCommand) -> Value {
    let output = c.output().unwrap();
    retain_output(&output);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn candidate(cfg: &Config, network: Hash) -> (Hash, Vec<u8>) {
    let owner = development_public(3).unwrap();
    let cid = hash(
        b"contribution-v3",
        &[
            &owner,
            &cfg.family,
            &[0; 32],
            &[7; 32],
            &[8; 32],
            &0_u64.to_le_bytes(),
        ],
    );
    let mut payload = Vec::new();
    for h in [cid, cfg.family, [0; 32], [7; 32]] {
        payload.extend(h);
    }
    payload.extend(1024_u64.to_le_bytes());
    payload.extend([8; 32]);
    payload.extend(0_u64.to_le_bytes());
    let mut tx = Envelope {
        network,
        sender: owner,
        nonce: 1,
        expiry: 128,
        fee_limit: 1_000_000,
        tag: 6,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&3_u64.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    (cid, tx.encode().unwrap())
}
fn append(
    node: &mut Node,
    parent: Hash,
    height: u64,
    genesis: u64,
    now: u64,
    txs: Vec<Vec<u8>>,
) -> Hash {
    let packet = node
        .make(
            parent,
            txs,
            development_public(3).unwrap(),
            genesis + height * 10,
            4096,
        )
        .unwrap();
    node.admit(&packet, now).unwrap()
}
struct Server {
    address: SocketAddr,
    public: String,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<trnm_pon_node::Result<public_v3::PublicMetrics>>>,
}
impl Server {
    fn start(node: Arc<Mutex<Node>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let identity = DevelopmentIdentity::from_secret_hex(&hex::encode([91; 32])).unwrap();
        let public = identity.public_key().to_owned();
        let policy = public_v3::PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let worker = thread::spawn(move || {
            public_v3::serve_public_protected_v3(
                listener,
                node,
                Duration::from_secs(120),
                signal,
                public_v3::PublicServer::new(identity, policy).unwrap(),
            )
        });
        Self {
            address,
            public,
            stop,
            worker: Some(worker),
        }
    }
    fn client(&self, store: &Path, genesis: u64, key: &Path, tip: Hash) -> Command {
        let mut c = command(store, genesis);
        c.args([
            "--admission-profile",
            public_v3::PROFILE,
            "--peer",
            &self.address.to_string(),
            "--server-public",
            &self.public,
            "--admission-bits",
            "8",
            "--tip",
            &hex::encode(tip),
        ])
        .arg("--auth-secret")
        .arg(key);
        c
    }
}
// Each command owns its listener, including its stop signal and joined worker.
// The 120-second lease is a watchdog for that network phase, never a budget for
// unrelated local recovery, assertions, or native fork/archive construction.
struct SyncCommand {
    phase: &'static str,
    server: Server,
    command: Command,
    started: Instant,
}
impl SyncCommand {
    fn args(&mut self, args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>) -> &mut Self {
        self.command.args(args);
        self
    }
    fn output(&mut self) -> std::io::Result<Output> {
        let output = self.command.output();
        let worker = self.server.worker.take().expect("one command per listener");
        let exited_before_stop = worker.is_finished();
        self.server.stop.store(true, Ordering::Release);
        let result = worker.join();
        eprintln!(
            "sync phase={} elapsed={:?} command={:?} address={} \
             server_exited_before_stop={} server_result={:?} child={:?}",
            self.phase,
            self.started.elapsed(),
            self.command,
            self.server.address,
            exited_before_stop,
            result,
            output.as_ref().map(|o| (
                o.status,
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ))
        );
        // A finite service may finish naturally after its final response while
        // the child is still validating local proofs. Record that timing, but
        // let the actual CLI outcome and state assertions decide its validity.
        let listener_ok = matches!(result, Ok(Ok(_)));
        if !listener_ok {
            if let Ok(output) = &output {
                // Preserve actual child failure evidence even when the service
                // lifecycle assertion fires before success/refusal validation.
                retain_output(output);
            }
        }
        assert!(
            listener_ok,
            "sync phase={} listener failed; see command/server diagnostics",
            self.phase
        );
        output
    }
}
fn sync_client(
    node: &Arc<Mutex<Node>>,
    phase: &'static str,
    store: &Path,
    genesis: u64,
    key: &Path,
    tip: Hash,
) -> SyncCommand {
    let started = Instant::now();
    let server = Server::start(node.clone());
    let command = server.client(store, genesis, key, tip);
    SyncCommand {
        phase,
        server,
        command,
        started,
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            // Normal execution checks the join result in SyncCommand::output.
            // Unwinding must still join without causing a second panic.
            let _ = worker.join();
        }
    }
}

#[test]
fn optional_sync_inputs_reject_before_open_without_changing_old_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = ingress::now().unwrap() - 2000;
    for (index, extra, expected) in [
        (0, vec!["--evaluation-candidate", "bad"], "HASH"),
        (
            1,
            vec![
                "--evaluation-candidate",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ],
            "HASH",
        ),
        (
            2,
            vec!["--evaluation-round-blocks", "1"],
            "EVALUATION_SYNC_CANDIDATE_REQUIRED",
        ),
        (
            3,
            vec![
                "--evaluation-candidate",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "--evaluation-round-blocks",
                "0",
            ],
            "EVALUATION_OBSERVATION_LIMIT",
        ),
        (
            4,
            vec![
                "--evaluation-candidate",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "--evaluation-round-blocks",
                "4097",
            ],
            "EVALUATION_OBSERVATION_LIMIT",
        ),
        (
            5,
            vec![
                "--evaluation-candidate",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ],
            "EVALUATION_SYNC_PUBLIC_PROFILE",
        ),
        (
            6,
            vec![
                "--evaluation-candidate",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "--admission-profile",
                public_v3::PROFILE,
                "--logical-now",
                "1",
            ],
            "NETWORK_USES_LOCAL_WALL_CLOCK",
        ),
    ] {
        let store = dir.path().join(index.to_string());
        refusal(
            command(&store, genesis).args(extra).output().unwrap(),
            expected,
        );
        assert!(!store.exists());
    }
}

#[test]
fn actual_public_full_sync_query_partial_refusals_reorg_and_retirement() {
    let dir = tempfile::tempdir().unwrap();
    let now = ingress::now().unwrap();
    let genesis = now - 5000;
    let settings =
        Settings::development_with_evaluation_policy(Some(genesis), evaluation::PROFILE).unwrap();
    let cfg = Config::installed_with_evaluation_policy(evaluation::PROFILE).unwrap();
    let source = dir.path().join("source");
    let receiver = dir.path().join("receiver");
    let mut node = Node::open(&source, settings.clone(), 2).unwrap();
    let (cid, raw) = candidate(&cfg, settings.network());
    let mut tip = node.settings().genesis();
    let root = tip;
    for height in 1..=64 {
        tip = append(
            &mut node,
            tip,
            height,
            genesis,
            now,
            if height == 1 {
                vec![raw.clone()]
            } else {
                vec![]
            },
        );
        node.activate_observed(tip, now).unwrap();
    }
    let source_observation =
        serde_json::to_value(node.evaluation_round_observation(cid, now, 64).unwrap()).unwrap();
    node.enable_local_mempool(PoolLimits {
        max_records: 8,
        max_bytes: 16384,
        max_group_members: 8,
        critical_reserve: 0,
        max_removals: 16,
        preview_miner: development_public(0).unwrap(),
    })
    .unwrap();
    let shared = Arc::new(Mutex::new(node));
    let key = dir.path().join("development-caller.key");
    fs::write(&key, hex::encode([92; 32])).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let mut c = sync_client(&shared, "full-sync", &receiver, genesis, &key, tip);
    c.args([
        "--evaluation-candidate",
        &hex::encode(cid),
        "--evaluation-round-blocks",
        "64",
    ]);
    let before_sync_clock = ingress::now().unwrap();
    let first = success(&mut c);
    let after_sync_clock = ingress::now().unwrap();
    let local = Node::open(&receiver, settings.clone(), 2).unwrap();
    let query_clock = first["result"]["evaluation_observation"]["observed_now"]
        .as_u64()
        .unwrap();
    assert!((before_sync_clock..=after_sync_clock).contains(&query_clock));
    let prior = local
        .evaluation_round_observation(cid, query_clock, 64)
        .unwrap();
    let local_expected = serde_json::to_value(&prior).unwrap();
    assert_eq!(first["result"]["evaluation_observation"], local_expected);
    assert_eq!(
        local_expected["active_generation"],
        local.active().unwrap().1
    );
    assert_eq!(source_observation["active_generation"], 64);
    assert_eq!(local_expected["active_generation"], 1);
    assert_eq!(
        local_expected["candidate_anchor"],
        source_observation["candidate_anchor"]
    );
    assert_eq!(
        local_expected["closed_result"],
        source_observation["closed_result"]
    );
    assert_eq!(
        local
            .check_evaluation_round_observation(&prior, genesis, 64)
            .unwrap_err()
            .to_string(),
        "TIME_DEFERRED"
    );
    let baseline = local.stats().unwrap();
    drop(local);
    assert_eq!(first["result"]["verified_tip"], hex::encode(tip));
    assert_eq!(
        first["result"]["evaluation_observation_scope"],
        json!({
        "schema":"native-sync-evaluation-observation-v1","same_exclusive_local_owner":true,
        "complete_native_sync":true,"unsigned_local_observation":true,
        "transport_phase_authority":false,"public_ready":false})
    );
    assert_eq!(
        first["result"]["evaluation_observation"]["closed_result"]["status"],
        "aborted"
    );
    let default = success(
        sync_client(&shared, "default-query", &receiver, genesis, &key, tip)
            .args(["--after", &hex::encode(tip)]),
    );
    let keys: Vec<_> = default["result"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        vec![
            "public_network_ready",
            "state",
            "transport_solve_trials",
            "verified_tip"
        ]
    );
    assert_eq!(default["result"]["state"], baseline);
    for (label, id, bound, error) in [
        ("unknown", [1; 32], 64, "STATE"),
        ("window", cid, 63, "EVALUATION_OBSERVATION_LIMIT"),
    ] {
        let error_text = refusal(
            sync_client(&shared, label, &receiver, genesis, &key, tip)
                .args([
                    "--after",
                    &hex::encode(tip),
                    "--evaluation-candidate",
                    &hex::encode(id),
                    "--evaluation-round-blocks",
                    &bound.to_string(),
                ])
                .output()
                .unwrap(),
            "SYNC_COMPLETED_EVALUATION_OBSERVATION_REFUSED",
        );
        assert!(error_text.contains(error), "{label}: {error_text}");
        let local = Node::open(&receiver, settings.clone(), 2).unwrap();
        assert_eq!(local.stats().unwrap(), baseline);
        drop(local);
    }
    let partial = dir.path().join("partial");
    refusal(
        sync_client(&shared, "partial", &partial, genesis, &key, tip)
            .args(["--pages", "1", "--evaluation-candidate", &hex::encode(cid)])
            .output()
            .unwrap(),
        "INCOMPLETE_HISTORY",
    );
    let local = Node::open(&partial, settings.clone(), 2).unwrap();
    // Normal reopen/recovery can activate the already verified partial prefix;
    // the failed sync still supplied no complete evaluation observation.
    let partial_tip = local.active().unwrap().0;
    let partial_height = local.packet(partial_tip).unwrap().header.height;
    assert!((1..64).contains(&partial_height));
    assert!(local
        .packet(shared.lock().unwrap().packet(tip).unwrap().header.parent)
        .is_err());
    drop(local);
    let wrong = dir.path().join("wrong-context");
    refusal(
        sync_client(&shared, "wrong-context", &wrong, genesis + 1, &key, tip)
            .args(["--evaluation-candidate", &hex::encode(cid)])
            .output()
            .unwrap(),
        "PUBLIC_CHALLENGE_CONTEXT",
    );
    let mut parent = root;
    {
        let mut owner = shared.lock().unwrap();
        for height in 1..=65 {
            parent = append(&mut owner, parent, height, genesis, now, vec![]);
        }
        owner.activate_observed(parent, now).unwrap();
    }
    let refused = refusal(
        sync_client(&shared, "reorganization", &receiver, genesis, &key, parent)
            .args(["--evaluation-candidate", &hex::encode(cid)])
            .output()
            .unwrap(),
        "SYNC_COMPLETED_EVALUATION_OBSERVATION_REFUSED",
    );
    assert!(refused.contains(":STATE"));
    let local = Node::open(&receiver, settings.clone(), 2).unwrap();
    assert_eq!(local.active().unwrap().0, parent);
    assert_eq!(
        local
            .check_evaluation_round_observation(&prior, now, 128)
            .unwrap_err()
            .to_string(),
        "STALE_VIEW"
    );
    drop(local);
    // Complete delivery of the known lighter candidate branch cannot replace
    // the receiver's heavier active fork or provide that old branch's phase.
    refusal(
        sync_client(&shared, "lighter-branch", &receiver, genesis, &key, tip)
            .args([
                "--after",
                &hex::encode(tip),
                "--evaluation-candidate",
                &hex::encode(cid),
            ])
            .output()
            .unwrap(),
        "SYNC_COMPLETED_EVALUATION_OBSERVATION_REFUSED",
    );
    let local = Node::open(&receiver, settings.clone(), 2).unwrap();
    assert_eq!(local.active().unwrap().0, parent);
    drop(local);
    // No listener survives a CLI command, so offline native construction cannot
    // consume the next command's finite service lease (including the fork above).
    // Extend the original candidate branch past actual native archive retention,
    // then select its heavier tip. No archive KV is fabricated or deleted here.
    let mut retired = tip;
    let mut retirement_branch = Vec::new();
    {
        let mut owner = shared.lock().unwrap();
        for height in 65..=305 {
            let previous = retired;
            retired = append(&mut owner, previous, height, genesis, now, vec![]);
            retirement_branch.push((retired, previous));
        }
        owner.activate_observed(retired, now).unwrap();
    }
    // Hosted job 110682210746 exhausted the unchanged 120-second lease after
    // 150 real history responses in one 241-successor retirement sync. Exercise
    // the explicit page-budget/resume contract instead: these are planned,
    // bounded commands, not retries of an arbitrary transport failure. This
    // test does not claim uninterrupted 241-block delivery within that lease.
    let mut after = tip;
    for (chunk, phase) in [
        "retirement-pages-1",
        "retirement-pages-2",
        "retirement-pages-3",
    ]
    .into_iter()
    .enumerate()
    {
        let error = refusal(
            sync_client(&shared, phase, &receiver, genesis, &key, retired)
                .args([
                    "--after",
                    &hex::encode(after),
                    "--pages",
                    "64",
                    "--evaluation-candidate",
                    &hex::encode(cid),
                ])
                .output()
                .unwrap(),
            "INCOMPLETE_HISTORY:page_budget:after=",
        );
        let cursor_text = error
            .strip_prefix("INCOMPLETE_HISTORY:page_budget:after=")
            .unwrap()
            .strip_suffix('\n')
            .unwrap();
        let cursor: Hash = hex::decode(cursor_text).unwrap().try_into().unwrap();
        assert_eq!(cursor_text, hex::encode(cursor));
        let start = chunk * 64;
        let end = start + 64;
        assert_eq!(cursor, retirement_branch[end - 1].0);
        assert_ne!(cursor, after);
        assert_ne!(cursor, retired);
        // Reopen only after the child's listener has stopped and joined. Every
        // advertised cursor and its preceding page packets must actually exist
        // in the durable receiver on the native source's expected ancestry.
        let local = Node::open(&receiver, settings.clone(), 2).unwrap();
        let mut previous = after;
        for (offset, &(id, source_parent)) in retirement_branch[start..end].iter().enumerate() {
            let packet = local.packet(id).unwrap();
            assert_eq!(packet.id().unwrap(), id);
            assert_eq!(packet.header.parent, source_parent);
            assert_eq!(packet.header.parent, previous);
            assert_eq!(packet.header.height, (65 + start + offset) as u64);
            previous = id;
        }
        assert_eq!(previous, cursor);
        assert!(local.packet(retirement_branch[end].0).is_err());
        assert!(local.packet(retired).is_err());
        drop(local);
        after = cursor;
    }
    let retired_error = refusal(
        sync_client(&shared, "retirement", &receiver, genesis, &key, retired)
            .args([
                "--after",
                &hex::encode(after),
                "--pages",
                "64",
                "--evaluation-candidate",
                &hex::encode(cid),
            ])
            .output()
            .unwrap(),
        "SYNC_COMPLETED_EVALUATION_OBSERVATION_REFUSED",
    );
    assert!(retired_error.starts_with(&format!(
        "SYNC_COMPLETED_EVALUATION_OBSERVATION_REFUSED:verified_tip={}:active_tip={}:generation=",
        hex::encode(retired),
        hex::encode(retired)
    )));
    assert!(retired_error.ends_with(":STATE\n"));
    let local = Node::open(&receiver, settings, 2).unwrap();
    assert_eq!(local.active().unwrap().0, retired);
    assert!(!local
        .read_active()
        .unwrap()
        .2
        .contains_key(&format!("evaluation-archive:{}", hex::encode(cid))));
    drop(local);
}
